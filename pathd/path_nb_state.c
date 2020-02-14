/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sascha Kattelmann
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

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "northbound.h"
#include "libfrr.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"

/*
 * XPath: /frr-pathd:pathd/segment-list
 */
const void *pathd_te_segment_list_get_next(struct nb_cb_get_next_args *args)
{
	struct srte_segment_list *segment_list =
		(struct srte_segment_list *)args->list_entry;

	if (args->list_entry == NULL)
		segment_list =
			RB_MIN(srte_segment_list_head, &srte_segment_lists);
	else
		segment_list = RB_NEXT(srte_segment_list_head, segment_list);

	return segment_list;
}

int pathd_te_segment_list_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct srte_segment_list *segment_list =
		(struct srte_segment_list *)args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%s",
		 segment_list->name);

	return NB_OK;
}

const void *
pathd_te_segment_list_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return srte_segment_list_find(args->keys->key[0]);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy
 */
const void *pathd_te_sr_policy_get_next(struct nb_cb_get_next_args *args)
{
	struct srte_policy *policy = (struct srte_policy *)args->list_entry;

	if (args->list_entry == NULL)
		policy = RB_MIN(srte_policy_head, &srte_policies);
	else
		policy = RB_NEXT(srte_policy_head, policy);

	return policy;
}

int pathd_te_sr_policy_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct srte_policy *policy =
		(struct srte_policy *)args->list_entry;

	args->keys->num = 2;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 policy->color);
	(void)inet_ntop(AF_INET, &policy->endpoint, args->keys->key[1],
			sizeof(args->keys->key[1]));

	return NB_OK;
}

const void *pathd_te_sr_policy_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	uint32_t color;
	struct ipaddr endpoint;

	color = yang_str2uint32(args->keys->key[0]);
	yang_str2ip(args->keys->key[1], &endpoint);

	return srte_policy_find(color, &endpoint);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/is-operational
 */
struct yang_data *
pathd_te_sr_policy_is_operational_get_elem(struct nb_cb_get_elem_args *args)
{
	struct srte_policy *policy = (struct srte_policy *)args->list_entry;
	bool is_operational = false;

	if (policy->status == SRTE_POLICY_STATUS_UP)
		is_operational = true;

	return yang_data_new_bool(args->xpath, is_operational);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate-path
 */
const void *
pathd_te_sr_policy_candidate_path_get_next(struct nb_cb_get_next_args *args)
{
	struct srte_policy *policy =
		(struct srte_policy *)args->parent_list_entry;
	struct srte_candidate *candidate =
		(struct srte_candidate *)args->list_entry;

	if (args->list_entry == NULL)
		candidate =
			RB_MIN(srte_candidate_head, &policy->candidate_paths);
	else
		candidate = RB_NEXT(srte_candidate_head, candidate);

	return candidate;
}

int pathd_te_sr_policy_candidate_path_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct srte_candidate *candidate =
		(struct srte_candidate *)args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 candidate->preference);

	return NB_OK;
}

const void *pathd_te_sr_policy_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct srte_policy *policy =
		(struct srte_policy *)args->parent_list_entry;
	uint32_t preference;

	preference = yang_str2uint32(args->keys->key[0]);

	return srte_candidate_find(policy, preference);
}

/*
 * XPath: /frr-pathd:pathd/sr-policy/candidate_path/is-best-candidate-path
 */
struct yang_data *
pathd_te_sr_policy_candidate_path_is_best_candidate_path_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct srte_candidate *candidate =
		(struct srte_candidate *)args->list_entry;

	return yang_data_new_bool(args->xpath,
				  candidate->is_best_candidate_path);
}
