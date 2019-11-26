/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "memory.h"
#include "log.h"
#include "lib_errors.h"

#include "pathd/pathd.h"
#include "pathd/path_memory.h"

DEFINE_MTYPE_STATIC(PATHD, PATH_SEGMENT_LIST, "Segment List information")
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_POLICY, "SR Policy information")

/* Generate rb-tree of Segment List instances. */
static inline int
te_segment_list_instance_compare(const struct te_segment_list *a,
				 const struct te_segment_list *b)
{
	return strcmp(a->name, b->name);
}
RB_GENERATE(te_segment_list_instance_head, te_segment_list, entry,
	    te_segment_list_instance_compare)

struct te_segment_list_instance_head te_segment_list_instances =
	RB_INITIALIZER(&te_segment_list_instances);

/* Generate rb-tree of SR Policy instances. */
static inline int te_sr_policy_instance_compare(const struct te_sr_policy *a,
						const struct te_sr_policy *b)
{
	bool color_is_equal = !(a->color - b->color);
	bool endpoint_is_equal =
		(a->endpoint.ipaddr_v4.s_addr == b->endpoint.ipaddr_v4.s_addr);
	bool name_is_equal = !(strcmp(a->name, b->name));

	if ((color_is_equal && endpoint_is_equal) || name_is_equal)
		return 0;

	if (a->binding_sid && b->binding_sid)
		return (a->binding_sid - b->binding_sid);

	return -1;
}
RB_GENERATE(te_sr_policy_instance_head, te_sr_policy, entry,
	    te_sr_policy_instance_compare)

struct te_sr_policy_instance_head te_sr_policy_instances =
	RB_INITIALIZER(&te_sr_policy_instances);

/*----------------------------------------------------------------------------*/

struct te_segment_list *te_segment_list_create(char *name)
{
	struct te_segment_list *te_segment_list;
	mpls_label_t *labels;
	te_segment_list =
		XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*te_segment_list));
	labels = XCALLOC(MTYPE_PATH_SEGMENT_LIST,
			 MPLS_MAX_LABELS * sizeof(*labels));

	te_segment_list->name = name;
	te_segment_list->label_num = 0;
	te_segment_list->labels = labels;

	RB_INSERT(te_segment_list_instance_head, &te_segment_list_instances,
		  te_segment_list);

	return te_segment_list;
}

void te_segment_list_label_add(struct te_segment_list *te_segment_list,
			       mpls_label_t label)
{
	te_segment_list->labels[te_segment_list->label_num] = label;
	te_segment_list->label_num++;
}

void te_segment_list_del(struct te_segment_list *te_segment_list)
{
	free(te_segment_list->name);
	XFREE(MTYPE_PATH_SEGMENT_LIST, te_segment_list->labels);
	RB_REMOVE(te_segment_list_instance_head, &te_segment_list_instances,
		  te_segment_list);
}

struct te_sr_policy *te_sr_policy_create(char *name)
{
	struct te_sr_policy *te_sr_policy;
	struct te_candidate_path *candidate_paths;
	te_sr_policy = XCALLOC(MTYPE_PATH_SR_POLICY, sizeof(*te_sr_policy));
	candidate_paths = XCALLOC(MTYPE_PATH_SR_POLICY,
				  100 * sizeof(struct te_candidate_path));

	te_sr_policy->name = name;
	te_sr_policy->candidate_path_num = 0;
	te_sr_policy->candidate_paths = candidate_paths;

	RB_INSERT(te_sr_policy_instance_head, &te_sr_policy_instances,
		  te_sr_policy);

	return te_sr_policy;
}

void te_sr_policy_del(struct te_sr_policy *te_sr_policy)
{
	free(te_sr_policy->name);
	XFREE(MTYPE_PATH_SR_POLICY, te_sr_policy->candidate_paths);
	RB_REMOVE(te_sr_policy_instance_head, &te_sr_policy_instances,
		  te_sr_policy);
}

void te_sr_policy_color_add(struct te_sr_policy *te_sr_policy, uint32_t color)
{
	te_sr_policy->color = color;
}

void te_sr_policy_endpoint_add(struct te_sr_policy *te_sr_policy,
			       struct ipaddr *endpoint)
{
	te_sr_policy->endpoint = *endpoint;
}

void te_sr_policy_binding_sid_add(struct te_sr_policy *te_sr_policy,
				  mpls_label_t binding_sid)
{
	te_sr_policy->binding_sid = binding_sid;
}

void te_sr_policy_candidate_path_set_active(struct te_sr_policy *te_sr_policy)
{
	struct te_candidate_path active_candidate_path;
	active_candidate_path.preference = 0;

	if (te_sr_policy->candidate_path_num == 0) {
		/* delete the LSP from Zebra */
		path_zebra_delete_lsp(te_sr_policy->binding_sid);
		te_sr_policy->active_candidate_path = active_candidate_path;
		return;
	}

	int i;
	for (i = 0; i < te_sr_policy->candidate_path_num; i++) {
		if (te_sr_policy->candidate_paths[i].preference
		    > active_candidate_path.preference)
			active_candidate_path =
				te_sr_policy->candidate_paths[i];
	}
	te_sr_policy->active_candidate_path = active_candidate_path;

	struct te_segment_list *te_segment_list_found;
	struct te_segment_list te_segment_list_search;
	te_segment_list_search.name =
		te_sr_policy->active_candidate_path.segment_list_name;
	te_segment_list_found =
		RB_FIND(te_segment_list_instance_head,
			&te_segment_list_instances, &te_segment_list_search);

	/* send the new active LSP to Zebra */
	path_zebra_add_lsp(te_sr_policy->binding_sid, te_segment_list_found);
}

void te_sr_policy_candidate_path_add(struct te_sr_policy *te_sr_policy,
				     uint32_t preference,
				     char *segment_list_name,
				     enum te_protocol_origin protocol_origin,
				     struct ipaddr *originator,
				     bool dynamic_flag)
{
	struct te_candidate_path te_candidate_path;
	te_candidate_path.preference = preference;
	te_candidate_path.segment_list_name = segment_list_name;
	te_candidate_path.protocol_origin = protocol_origin;
	te_candidate_path.originator = *originator;
	te_candidate_path.dynamic_flag = dynamic_flag;

	int idx = te_sr_policy->candidate_path_num;
	te_sr_policy->candidate_paths[idx] = te_candidate_path;
	te_sr_policy->candidate_path_num++;

	te_sr_policy_candidate_path_set_active(te_sr_policy);
}

void te_sr_policy_candidate_path_delete(struct te_sr_policy *te_sr_policy,
					uint32_t preference)
{
	int i;
	int idx_last_element = te_sr_policy->candidate_path_num - 1;
	for (i = 0; i < te_sr_policy->candidate_path_num; i++) {
		if (te_sr_policy->candidate_paths[i].preference == preference) {
			free(te_sr_policy->candidate_paths[i]
				     .segment_list_name);
			if (te_sr_policy->candidate_path_num > 1
			    && i != idx_last_element) {
				/*
				 * If necessary move the last element in place
				 * of the deleted one
				 */
				te_sr_policy->candidate_paths[i] =
					te_sr_policy->candidate_paths
						[idx_last_element];
			}
			te_sr_policy->candidate_path_num--;
			break;
		}
	}
	te_sr_policy_candidate_path_set_active(te_sr_policy);
}

char *te_sr_policy_find(uint32_t color, struct ipaddr *endpoint)
{
	struct te_sr_policy te_sr_policy_search;
	struct te_sr_policy *te_sr_policy_found;

	te_sr_policy_search.color = color;
	te_sr_policy_search.endpoint = *endpoint;

	te_sr_policy_found =
		RB_FIND(te_sr_policy_instance_head, &te_sr_policy_instances,
			&te_sr_policy_search);

	return strdup(te_sr_policy_found->name);
}
