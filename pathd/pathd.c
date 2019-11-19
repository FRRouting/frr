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
	return strcmp(a->name, b->name);
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
	te_sr_policy->endpoint = endpoint;
}

void te_sr_policy_binding_sid_add(struct te_sr_policy *te_sr_policy,
				  mpls_label_t binding_sid)
{
	te_sr_policy->binding_sid = binding_sid;
}

void te_sr_policy_candidate_path_add(struct te_sr_policy *te_sr_policy,
				     uint32_t preference,
				     char *segment_list_name)
{
	struct te_candidate_path *te_candidate_path;
	te_candidate_path =
		XCALLOC(MTYPE_PATH_SR_POLICY, sizeof(struct te_candidate_path));
	te_candidate_path->preference = preference;
	te_candidate_path->segment_list_name = segment_list_name;
	int idx = te_sr_policy->candidate_path_num;
	memcpy(te_candidate_path, &(te_sr_policy->candidate_paths[idx]),
	       sizeof(struct te_candidate_path));
	te_sr_policy->candidate_path_num++;
	XFREE(MTYPE_PATH_SR_POLICY, te_candidate_path);
}
