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
DEFINE_MTYPE_STATIC(PATHD, PATH_SEGMENT_LIST_NAME, "Segment List name")
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_POLICY, "SR Policy information")
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_POLICY_NAME, "SR Policy name")
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_CANDIDATE_NAME,
		    "SR Policy candidate path name")
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_CANDIDATE_SL_NAME,
		    "SR Policy candidate path segment-list name")

/* Generate rb-tree of Segment List Segment instances. */
static inline int te_segment_list_segment_instance_compare(
	const struct te_segment_list_segment *a,
	const struct te_segment_list_segment *b)
{
	return (a->index < b->index ? -1 : a->index > b->index);
}
RB_GENERATE(te_segment_list_segment_instance_head, te_segment_list_segment,
	    entry, te_segment_list_segment_instance_compare)

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

/* Generate rb-tree of Candidate Path instances. */
static inline int
te_candidate_path_instance_compare(const struct te_candidate_path *a,
				   const struct te_candidate_path *b)
{
	return (a->preference < b->preference ? -1
					      : a->preference > b->preference);
}
RB_GENERATE(te_candidate_path_instance_head, te_candidate_path, entry,
	    te_candidate_path_instance_compare)

/* Generate rb-tree of SR Policy instances. */
static inline int te_sr_policy_instance_compare(const struct te_sr_policy *a,
						const struct te_sr_policy *b)
{
	if (a->color < b->color)
		return -1;

	if (a->color > b->color)
		return 1;

	if (a->endpoint.ipaddr_v4.s_addr < b->endpoint.ipaddr_v4.s_addr)
		return -1;

	if (a->endpoint.ipaddr_v4.s_addr > b->endpoint.ipaddr_v4.s_addr)
		return 1;

	return 0;
}
RB_GENERATE(te_sr_policy_instance_head, te_sr_policy, entry,
	    te_sr_policy_instance_compare)

struct te_sr_policy_instance_head te_sr_policy_instances =
	RB_INITIALIZER(&te_sr_policy_instances);

/*----------------------------------------------------------------------------*/

struct te_segment_list *te_segment_list_create(const char *name)
{
	struct te_segment_list *te_segment_list =
		XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*te_segment_list));

	te_segment_list->name = XSTRDUP(MTYPE_PATH_SEGMENT_LIST_NAME, name);
	RB_INIT(te_segment_list_segment_instance_head,
		&te_segment_list->segments);

	RB_INSERT(te_segment_list_instance_head, &te_segment_list_instances,
		  te_segment_list);

	return te_segment_list;
}

void te_segment_list_del(struct te_segment_list *te_segment_list)
{
	XFREE(MTYPE_PATH_SEGMENT_LIST_NAME, te_segment_list->name);
	RB_REMOVE(te_segment_list_instance_head, &te_segment_list_instances,
		  te_segment_list);
}

struct te_segment_list_segment *
te_segment_list_segment_add(struct te_segment_list *te_segment_list,
			    uint32_t index)
{
	struct te_segment_list_segment *te_segment_list_segment = XCALLOC(
		MTYPE_PATH_SEGMENT_LIST, sizeof(*te_segment_list_segment));

	te_segment_list_segment->index = index;

	RB_INSERT(te_segment_list_segment_instance_head,
		  &te_segment_list->segments, te_segment_list_segment);

	return te_segment_list_segment;
}

void te_segment_list_segment_del(
	struct te_segment_list *te_segment_list,
	struct te_segment_list_segment *te_segment_list_segment)
{
	RB_REMOVE(te_segment_list_segment_instance_head,
		  &te_segment_list->segments, te_segment_list_segment);
}

void te_segment_list_segment_sid_value_add(
	struct te_segment_list_segment *te_segment_list_segment,
	mpls_label_t sid_value)
{
	te_segment_list_segment->sid_value = sid_value;
}

struct te_sr_policy *te_sr_policy_create(uint32_t color,
					 struct ipaddr *endpoint)
{
	struct te_sr_policy *te_sr_policy;
	te_sr_policy = XCALLOC(MTYPE_PATH_SR_POLICY, sizeof(*te_sr_policy));

	struct te_candidate_path_instance_head te_candidate_path_instances =
		RB_INITIALIZER(&te_candidate_path_instances);

	te_sr_policy->color = color;
	te_sr_policy->endpoint = *endpoint;
	te_sr_policy->candidate_paths = te_candidate_path_instances;

	RB_INSERT(te_sr_policy_instance_head, &te_sr_policy_instances,
		  te_sr_policy);

	return te_sr_policy;
}

void te_sr_policy_del(struct te_sr_policy *te_sr_policy)
{
	path_zebra_delete_sr_policy(te_sr_policy);

	free(te_sr_policy->name);
	RB_REMOVE(te_sr_policy_instance_head, &te_sr_policy_instances,
		  te_sr_policy);
}

void te_sr_policy_name_set(struct te_sr_policy *te_sr_policy, const char *name)
{
	XFREE(MTYPE_PATH_SR_POLICY_NAME, te_sr_policy->name);
	te_sr_policy->name = XSTRDUP(MTYPE_PATH_SR_POLICY_NAME, name);
}

void te_sr_policy_name_unset(struct te_sr_policy *te_sr_policy)
{
	XFREE(MTYPE_PATH_SR_POLICY_NAME, te_sr_policy->name);
}

void te_sr_policy_binding_sid_add(struct te_sr_policy *te_sr_policy,
				  mpls_label_t binding_sid)
{
	te_sr_policy->binding_sid = binding_sid;
}

void te_sr_policy_candidate_path_set_active(struct te_sr_policy *te_sr_policy)
{
	struct te_candidate_path *best_candidate_path = NULL;
	struct te_candidate_path *candidate_path;
	RB_FOREACH_REVERSE (candidate_path, te_candidate_path_instance_head,
			    &te_sr_policy->candidate_paths) {
		/* search for highest preference with existing segment list name
		 */
		if (candidate_path->segment_list_name) {
			best_candidate_path = candidate_path;
			break;
		}
	}


	if (!best_candidate_path
	    || RB_EMPTY(te_candidate_path_instance_head,
			&te_sr_policy->candidate_paths)) {
		/* delete the LSP from Zebra */
		te_sr_policy->best_candidate_path_key = 0;
		path_zebra_delete_sr_policy(te_sr_policy);
		return;
	}

	struct te_candidate_path *former_best_candidate_path;
	if (te_sr_policy->best_candidate_path_key > 0) {
		former_best_candidate_path = find_candidate_path(
			te_sr_policy, te_sr_policy->best_candidate_path_key);
		if (former_best_candidate_path)
			former_best_candidate_path->is_best_candidate_path =
				false;
	}

	best_candidate_path->is_best_candidate_path = true;
	te_sr_policy->best_candidate_path_key = best_candidate_path->preference;

	struct te_segment_list *te_segment_list_found =
		te_segment_list_get(best_candidate_path->segment_list_name);

	/* send the new active LSP to Zebra */
	path_zebra_add_sr_policy(te_sr_policy, te_segment_list_found);
}

struct te_segment_list *te_segment_list_get(const char *name)
{
	struct te_segment_list te_segment_list_search;
	te_segment_list_search.name = (char *)name;
	return RB_FIND(te_segment_list_instance_head,
		       &te_segment_list_instances, &te_segment_list_search);
}

struct te_candidate_path *find_candidate_path(struct te_sr_policy *te_sr_policy,
					      uint32_t preference)
{
	struct te_candidate_path te_candidate_path_search;
	te_candidate_path_search.preference = preference;
	return RB_FIND(te_candidate_path_instance_head,
		       &te_sr_policy->candidate_paths,
		       &te_candidate_path_search);
}

struct te_candidate_path *
te_sr_policy_candidate_path_add(struct te_sr_policy *te_sr_policy,
				uint32_t preference)
{
	struct te_candidate_path *te_candidate_path =
		XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*te_candidate_path));
	te_candidate_path->preference = preference;
	te_candidate_path->sr_policy = te_sr_policy;

	RB_INSERT(te_candidate_path_instance_head,
		  &te_sr_policy->candidate_paths, te_candidate_path);

	return te_candidate_path;
}

void te_sr_policy_candidate_path_name_set(
	struct te_candidate_path *te_candidate_path, const char *name)
{
	XFREE(MTYPE_PATH_SR_CANDIDATE_NAME, te_candidate_path->name);
	te_candidate_path->name = XSTRDUP(MTYPE_PATH_SR_CANDIDATE_NAME, name);
}

void te_sr_policy_candidate_path_protocol_origin_add(
	struct te_candidate_path *te_candidate_path,
	enum te_protocol_origin protocol_origin)
{
	te_candidate_path->protocol_origin = protocol_origin;
}

void te_sr_policy_candidate_path_originator_add(
	struct te_candidate_path *te_candidate_path, struct ipaddr *originator)
{
	te_candidate_path->originator = *originator;
}

void te_sr_policy_candidate_path_discriminator_add(
	struct te_candidate_path *te_candidate_path, uint32_t discriminator)
{
	te_candidate_path->discriminator = discriminator;
}

void te_sr_policy_candidate_path_type_add(
	struct te_candidate_path *te_candidate_path,
	enum te_candidate_path_type type)
{
	te_candidate_path->type = type;
}

void te_sr_policy_candidate_path_segment_list_name_set(
	struct te_candidate_path *te_candidate_path,
	const char *segment_list_name)
{
	XFREE(MTYPE_PATH_SR_CANDIDATE_SL_NAME,
	      te_candidate_path->segment_list_name);
	te_candidate_path->segment_list_name =
		XSTRDUP(MTYPE_PATH_SR_CANDIDATE_SL_NAME, segment_list_name);
}

void te_sr_policy_candidate_path_delete(
	struct te_candidate_path *te_candidate_path)
{
	struct te_sr_policy *te_sr_policy = te_candidate_path->sr_policy;

	RB_REMOVE(te_candidate_path_instance_head,
		  &te_sr_policy->candidate_paths, te_candidate_path);
}

struct te_sr_policy *te_sr_policy_get(uint32_t color, struct ipaddr *endpoint)
{
	struct te_sr_policy te_sr_policy_search;
	struct te_sr_policy *te_sr_policy_found;

	te_sr_policy_search.color = color;
	te_sr_policy_search.endpoint = *endpoint;

	te_sr_policy_found =
		RB_FIND(te_sr_policy_instance_head, &te_sr_policy_instances,
			&te_sr_policy_search);

	return te_sr_policy_found;
}
