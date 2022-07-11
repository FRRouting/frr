/*
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "stdlib.h"

#include "zebra.h"
#include "memory.h"
#include "hook.h"
#include "lib/northbound.h"
#include "lib/mpls.h"
#include "lib/log.h"
#include "lib/command.h"

#include "pathd/pathd.h"
#include "pathd/path_errors.h"
#include "pathd/path_bsid.h"
#include "pathd/path_zebra.h"

#include "pathd/path_bsid_clippy.c"


#define SRTE_BLOCK_SIZE 64

DEFINE_MTYPE_STATIC(PATHD, PATH_SRTE_BSID, "SRTE BSID Pool");

struct srte_label_block srte_bsid_pool;
struct debug path_debug_bsid;

static bool path_bsid_get_pool(void)
{
	if (CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE))
		return true;

	srte_bsid_pool.start = srte_bsid_pool.conf_lower_bound;
	srte_bsid_pool.end = srte_bsid_pool.conf_upper_bound;

	if (path_zebra_request_label_range(srte_bsid_pool.start,
					   srte_bsid_pool.end
						   - srte_bsid_pool.start + 1)
	    < 0) {
		UNSET_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE);
		zlog_warn("Allocation of mpls label chunk [%u/%u] failed",
			  srte_bsid_pool.start, srte_bsid_pool.end);
		return false;
	}

	srte_bsid_pool.current = 0;
	/* Compute the needed Used Mark number and allocate them */
	srte_bsid_pool.max_block =
		(srte_bsid_pool.end - srte_bsid_pool.start + 1)
		/ SRTE_BLOCK_SIZE;
	if (((srte_bsid_pool.end - srte_bsid_pool.start + 1) % SRTE_BLOCK_SIZE)
	    != 0)
		srte_bsid_pool.max_block++;
	srte_bsid_pool.used_mark =
		XCALLOC(MTYPE_PATH_SRTE_BSID,
			srte_bsid_pool.max_block * SRTE_BLOCK_SIZE);
	SET_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE);
	zlog_warn("Allocation of mpls label chunk [%u/%u] success",
		  srte_bsid_pool.start, srte_bsid_pool.end);
	return true;
}

static bool path_bsid_handle_labels_from_policies(bool allocate)
{
	bool policies_updated = false;
	mpls_label_t binding_sid = MPLS_LABEL_NONE;
	struct srte_policy *policy;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		if (!CHECK_FLAG(policy->flags, F_POLICY_DELETED)
		    && CHECK_FLAG(policy->flags, F_POLICY_TEMPLATE)) {
			if (allocate)
				binding_sid = path_bsid_request_label();
			if (policy->binding_sid != binding_sid) {
				policies_updated = true;
				if (binding_sid == MPLS_LABEL_NONE
				    && policy->best_candidate
				    && CHECK_FLAG(policy->best_candidate->flags,
						  F_CANDIDATE_TEMPLATE)) {
					path_zebra_delete_sr_policy(policy);
					/* XXX inform BGP that policy candidate changed */
				}
				if (policy->binding_sid != MPLS_LABEL_NONE)
					path_bsid_release_label(
						policy->binding_sid);
				policy->binding_sid = binding_sid;
				if (policy->best_candidate
				    && policy->binding_sid != MPLS_LABEL_NONE) {
					path_zebra_add_sr_policy(
						policy,
						policy->best_candidate->lsp
							->segment_list);
					/* XXX inform BGP that policy candidate changed */
				} else if (policy->binding_sid
					   != MPLS_LABEL_NONE) {
					srte_policy_apply_changes(policy);
				}
			}
		}
	}
	return policies_updated;
}

static void path_bsid_release_pool(void)
{
	int ret;

	if (CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE)) {
		ret = path_zebra_release_label_range(srte_bsid_pool.start,
						     srte_bsid_pool.end);
		/* Then reset pool structure */
		if (srte_bsid_pool.used_mark != NULL)
			XFREE(MTYPE_PATH_SRTE_BSID, srte_bsid_pool.used_mark);
		PATH_BSID_DEBUG("Releasing of mpls label chunk [%u/%u] %s",
				srte_bsid_pool.start, srte_bsid_pool.end,
				ret < 0 ? "failure" : "success");
		UNSET_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE);
	}
}

/* return true if allocation/deallocation needs a refresh of policies */
bool path_bsid_enable_pool(bool enable)
{
	bool ret = false;

	if ((enable
	     && CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_NEEDED))
	    || (!enable
		&& !CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_NEEDED)))
		return false;

	if (enable) {
		/* block can not be active at this point */
		SET_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_NEEDED);
		if (path_bsid_get_pool())
			ret = path_bsid_handle_labels_from_policies(true);
	} else {
		/* block can be active at this point */
		if (CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE)) {
			/* deallocate all policies templates */
			ret = path_bsid_handle_labels_from_policies(false);
			path_bsid_release_pool();
		}
		UNSET_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_NEEDED);
	}
	return ret;
}

bool path_bsid_configure_label_range(uint32_t lower_bound, uint32_t upper_bound)
{
	bool restart = false;

	if (srte_bsid_pool.conf_lower_bound == lower_bound
	    && srte_bsid_pool.conf_upper_bound == upper_bound)
		return false;

	PATH_BSID_DEBUG("Reconfigure mpls label chunk [%u/%u].", lower_bound,
			upper_bound);

	/* Label Manager is ready, start by releasing the old range.
	 * XXX current policies instantiated are not flushed
	 */
	if (CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_NEEDED)) {
		path_bsid_enable_pool(false);
		restart = true;
	}

	srte_bsid_pool.conf_lower_bound = lower_bound;
	srte_bsid_pool.conf_upper_bound = upper_bound;

	if (restart && path_bsid_enable_pool(true))
		return true;
	return false;
}


/**
 * Request a label from the Binding SID Local Pool
 *
 * @return	First available label on success or MPLS_INVALID_LABEL if the
 * 		block of labels is full
 */
mpls_label_t path_bsid_request_label(void)
{
	mpls_label_t label;
	uint32_t index;
	uint32_t pos;
	uint32_t size = srte_bsid_pool.end - srte_bsid_pool.start + 1;

	/* Check if label retrieval was ok */
	if (!CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE))
		return MPLS_LABEL_NONE;

	/* Check if we ran out of available labels */
	if (srte_bsid_pool.current >= size)
		return MPLS_LABEL_NONE;

	/* Get first available label and mark it used */
	label = srte_bsid_pool.current + srte_bsid_pool.start;
	index = srte_bsid_pool.current / SRTE_BLOCK_SIZE;
	pos = 1ULL << (srte_bsid_pool.current % SRTE_BLOCK_SIZE);
	srte_bsid_pool.used_mark[index] |= pos;

	/* Jump to the next free position */
	srte_bsid_pool.current++;
	pos = srte_bsid_pool.current % SRTE_BLOCK_SIZE;
	while (srte_bsid_pool.current < size) {
		if (pos == 0)
			index++;
		if (!((1ULL << pos) & srte_bsid_pool.used_mark[index]))
			break;
		else {
			srte_bsid_pool.current++;
			pos = srte_bsid_pool.current % SRTE_BLOCK_SIZE;
		}
	}

	if (srte_bsid_pool.current == size)
		zlog_warn(
			"SR: Warning, BSID pool is depleted and next label request will fail");

	return label;
}

/**
 * Release label from the binding SID local pool
 *
 * @param label	Label to be release
 *
 * @return	0 on success or -1 if label falls outside pool
 */
int path_bsid_release_label(mpls_label_t label)
{
	uint32_t index;
	uint32_t pos;

	if (label == MPLS_LABEL_NONE)
		return -1;

	if (!CHECK_FLAG(srte_bsid_pool.flags, SRTE_LABEL_BLOCK_ACTIVE))
		return -1;

	/* Check that label falls inside the pool */
	if ((label < srte_bsid_pool.start) || (label > srte_bsid_pool.end)) {
		flog_warn(
			EC_PATH_BSID_OVERFLOW,
			"%s: Returning label %u is outside mpls label chunk [%u/%u]",
			__func__, label, srte_bsid_pool.start,
			srte_bsid_pool.end);
		return -1;
	}

	index = (label - srte_bsid_pool.start) / SRTE_BLOCK_SIZE;
	pos = 1ULL << ((label - srte_bsid_pool.start) % SRTE_BLOCK_SIZE);
	srte_bsid_pool.used_mark[index] &= ~pos;
	/* Reset current to the first available position */
	for (index = 0; index < srte_bsid_pool.max_block; index++) {
		if (srte_bsid_pool.used_mark[index] != 0xFFFFFFFFFFFFFFFF) {
			for (pos = 0; pos < SRTE_BLOCK_SIZE; pos++)
				if (!((1ULL << pos)
				      & srte_bsid_pool.used_mark[index])) {
					srte_bsid_pool.current =
						index * SRTE_BLOCK_SIZE + pos;
					break;
				}
			break;
		}
	}

	return 0;
}

DEFPY(debug_path_bsid, debug_path_bsid_cmd, "[no] debug pathd bsid",
      NO_STR DEBUG_STR
      "path debugging\n"
      "BSID debugging\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);
	bool no_debug = (no != NULL);

	DEBUG_MODE_SET(&path_debug_bsid, mode, !no);
	DEBUG_FLAGS_SET(&path_debug_bsid, PATH_BSID_DEBUG_BASIC, !no_debug);
	return CMD_SUCCESS;
}

/*
 * Config Write functions
 */

extern void path_bsid_config_write(struct vty *vty)
{
	if (srte_bsid_pool.conf_lower_bound != SRTE_BSID_LOWER_BOUND
	    || srte_bsid_pool.conf_upper_bound != SRTE_BSID_UPPER_BOUND) {
		vty_out(vty, "  policy-label-blocks template %u %u\n",
			srte_bsid_pool.conf_lower_bound,
			srte_bsid_pool.conf_upper_bound);
	}
}

static int path_bsid_cli_debug_config_write(struct vty *vty)
{
	if (DEBUG_MODE_CHECK(&path_debug_bsid, DEBUG_MODE_CONF)) {
		if (DEBUG_FLAGS_CHECK(&path_debug_bsid, PATH_BSID_DEBUG_BASIC))
			vty_out(vty, "debug pathd bsid\n");
		return 1;
	}
	return 0;
}

static int path_bsid_cli_debug_set_all(uint32_t flags, bool set)
{
	DEBUG_FLAGS_SET(&path_debug_bsid, flags, set);

	/* If all modes have been turned off, don't preserve options. */
	if (!DEBUG_MODE_CHECK(&path_debug_bsid, DEBUG_MODE_ALL))
		DEBUG_CLEAR(&path_debug_bsid);

	return 0;
}

void path_bsid_show_debugging(struct vty *vty)
{
	if (DEBUG_FLAGS_CHECK(&path_debug_bsid, PATH_BSID_DEBUG_BASIC))
		vty_out(vty, "  Path bsid debugging is on\n");
}

/**
 * Initialize srte_bsid_pool
 *
 */
void path_bsid_init(void)
{
	memset(&srte_bsid_pool, 0, sizeof(struct srte_label_block));

	/* Initialize the BSID Range */
	srte_bsid_pool.conf_lower_bound = SRTE_BSID_LOWER_BOUND;
	srte_bsid_pool.conf_upper_bound = SRTE_BSID_UPPER_BOUND;

	install_element(CONFIG_NODE, &debug_path_bsid_cmd);
	install_element(ENABLE_NODE, &debug_path_bsid_cmd);

	hook_register(nb_client_debug_config_write,
		      path_bsid_cli_debug_config_write);
	hook_register(nb_client_debug_set_all, path_bsid_cli_debug_set_all);
}
