/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#include <northbound.h>
#include <yang.h>
#include <printfrr.h>
#include "pathd/pathd.h"
#include "pathd/path_pcep.h"
#include "pathd/path_pcep_nb.h"
#include "pathd/path_pcep_debug.h"

#define MAX_XPATH 256

typedef struct path_nb_list_path_cb_arg_t_ {
	void *arg;
	path_list_cb_t cb;
} path_nb_list_path_cb_arg_t;


static int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg);
static path_hop_t *path_nb_list_path_hops(struct te_segment_list *segment_list);

void path_nb_list_path(path_list_cb_t cb, void* arg)
{
	path_nb_list_path_cb_arg_t int_arg = { .arg = arg, .cb = cb};
	yang_dnode_iterate(path_nb_list_path_cb, &int_arg,
	                   running_config->dnode, "/frr-pathd:pathd/sr-policy");
}

int path_nb_list_path_cb(const struct lyd_node *dnode, void *int_arg)
{
	char *name;
	path_t *path;
	path_hop_t *hop;
	path_list_cb_t cb = ((path_nb_list_path_cb_arg_t*)int_arg)->cb;
	void *ext_arg = ((path_nb_list_path_cb_arg_t*)int_arg)->arg;
	struct te_sr_policy *policy;
	struct te_candidate_path *candidate;
	struct te_segment_list *segment_list, key;
	enum pcep_lsp_operational_status status;

	policy = nb_running_get_entry(dnode, NULL, true);
	PCEP_DEBUG("== POLICY: %s", policy->name);
	RB_FOREACH (candidate,
	            te_candidate_path_instance_head,
	            &policy->candidate_paths) {
		PCEP_DEBUG("== CANDIDATE: %s", candidate->name);
		key = (struct te_segment_list) {
			.name =  candidate->segment_list_name
		};
		segment_list = RB_FIND(te_segment_list_instance_head,
		                       &te_segment_list_instances,
		                       &key);
		assert(NULL != segment_list);
		PCEP_DEBUG("== SEGMENTS: %s", segment_list->name);
		hop = path_nb_list_path_hops(segment_list);
		path = XCALLOC(MTYPE_PCEP, sizeof(*path));
		name = asprintfrr(MTYPE_PCEP, "%s/%s",
		                  policy->name, candidate->name);
		//FIXME: operational status should come from the operational data
		if (candidate->is_best_candidate_path) {
			status = PCEP_LSP_OPERATIONAL_UP;
		} else {
			status = PCEP_LSP_OPERATIONAL_DOWN;
		}
		*path = (path_t) {
			.nbkey = (lsp_nb_key_t) {
				.color = policy->color,
				.endpoint = policy->endpoint,
				.preference = candidate->preference
			},
			.plsp_id = 0,
			.name = name,
			.srp_id = 0,
			.status = status,
			.do_remove = false,
			.go_active = false,
			.was_created = false,
			.was_removed = false,
			.is_synching = true,
			.is_delegated = false,
			.first = hop
		};
		if (!cb(path, ext_arg)) return 0;
	}

	// RB_FIND(bgp_adj_out_rb, &rn->adj_out, &lookup);

	// hop1 = XCALLOC(MTYPE_PCEP, sizeof(*hop1));
	// *hop1 = (path_hop_t) {
	// 	.next = NULL,
	// 	.is_loose = false,
	// 	.has_sid = true,
	// 	.is_mpls = true,
	// 	.has_attribs = false,
	// 	.sid = {
	// 		.mpls = {
	// 			.label = 16060,
	// 			.traffic_class = 0,
	// 			.is_bottom = true,
	// 			.ttl = 0
	// 		}
	// 	},
	// 	.has_nai = true,
	// 	.nai_type = PCEP_SR_SUBOBJ_NAI_IPV4_NODE,
	// 	.nai = { .ipv4_node = { .addr = addr_r6 } }
	// };
	// path = XCALLOC(MTYPE_PCEP, sizeof(*path));
	// *path = (path_t) {
	// 	.name = XSTRDUP(MTYPE_PCEP, "foob"),
	// 	.srp_id = 0,
	// 	.plsp_id = 42,
	// 	.status = PCEP_LSP_OPERATIONAL_UP,
	// 	.do_remove = false,
	// 	.go_active = false,
	// 	.was_created = false,
	// 	.was_removed = false,
	// 	.is_synching = true,
	// 	.is_delegated = true,
	// 	.first = hop1
	// };

	return 1;
}

path_hop_t *path_nb_list_path_hops(struct te_segment_list *segment_list)
{
	return NULL;
}