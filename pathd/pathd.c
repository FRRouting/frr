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
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_CANDIDATE,
		    "SR Policy candidate path information")

DEFINE_HOOK(pathd_candidate_created, (struct srte_candidate * candidate),
	    (candidate))
DEFINE_HOOK(pathd_candidate_updated, (struct srte_candidate * candidate),
	    (candidate))
DEFINE_HOOK(pathd_candidate_removed, (struct srte_candidate * candidate),
	    (candidate))

/* Generate rb-tree of Segment List Segment instances. */
static inline int srte_segment_entry_compare(const struct srte_segment_entry *a,
					     const struct srte_segment_entry *b)
{
	return a->index - b->index;
}
RB_GENERATE(srte_segment_entry_head, srte_segment_entry, entry,
	    srte_segment_entry_compare)

/* Generate rb-tree of Segment List instances. */
static inline int srte_segment_list_compare(const struct srte_segment_list *a,
					    const struct srte_segment_list *b)
{
	return strcmp(a->name, b->name);
}
RB_GENERATE(srte_segment_list_head, srte_segment_list, entry,
	    srte_segment_list_compare)

struct srte_segment_list_head srte_segment_lists =
	RB_INITIALIZER(&srte_segment_lists);

/* Generate rb-tree of Candidate Path instances. */
static inline int srte_candidate_compare(const struct srte_candidate *a,
					 const struct srte_candidate *b)
{
	return a->preference - b->preference;
}
RB_GENERATE(srte_candidate_head, srte_candidate, entry, srte_candidate_compare)

/* Generate rb-tree of SR Policy instances. */
static inline int srte_policy_compare(const struct srte_policy *a,
				      const struct srte_policy *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}
RB_GENERATE(srte_policy_head, srte_policy, entry, srte_policy_compare)

struct srte_policy_head srte_policies = RB_INITIALIZER(&srte_policies);

struct srte_segment_list *srte_segment_list_add(const char *name)
{
	struct srte_segment_list *segment_list;

	segment_list = XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*segment_list));
	strlcpy(segment_list->name, name, sizeof(segment_list->name));
	RB_INIT(srte_segment_entry_head, &segment_list->segments);
	RB_INSERT(srte_segment_list_head, &srte_segment_lists, segment_list);

	return segment_list;
}

void srte_segment_list_del(struct srte_segment_list *segment_list)
{
	RB_REMOVE(srte_segment_list_head, &srte_segment_lists, segment_list);
	XFREE(MTYPE_PATH_SEGMENT_LIST, segment_list);
}

struct srte_segment_list *srte_segment_list_find(const char *name)
{
	struct srte_segment_list search;

	strlcpy(search.name, name, sizeof(search.name));
	return RB_FIND(srte_segment_list_head, &srte_segment_lists, &search);
}

struct srte_segment_entry *
srte_segment_entry_add(struct srte_segment_list *segment_list, uint32_t index)
{
	struct srte_segment_entry *segment;

	segment = XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*segment));
	segment->index = index;
	RB_INSERT(srte_segment_entry_head, &segment_list->segments, segment);

	return segment;
}

void srte_segment_entry_del(struct srte_segment_list *segment_list,
			    struct srte_segment_entry *segment)
{
	RB_REMOVE(srte_segment_entry_head, &segment_list->segments, segment);
	XFREE(MTYPE_PATH_SEGMENT_LIST, segment);
}

struct srte_policy *srte_policy_add(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_policy *policy;

	policy = XCALLOC(MTYPE_PATH_SR_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = *endpoint;
	policy->binding_sid = MPLS_LABEL_NONE;
	RB_INIT(srte_candidate_head, &policy->candidate_paths);
	RB_INSERT(srte_policy_head, &srte_policies, policy);

	return policy;
}

void srte_policy_del(struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	path_zebra_delete_sr_policy(policy);

	while (!RB_EMPTY(srte_candidate_head, &policy->candidate_paths)) {
		candidate =
			RB_ROOT(srte_candidate_head, &policy->candidate_paths);
		srte_candidate_del(candidate);
	}

	RB_REMOVE(srte_policy_head, &srte_policies, policy);
	XFREE(MTYPE_PATH_SR_POLICY, policy);
}

struct srte_policy *srte_policy_find(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_policy search;

	search.color = color;
	search.endpoint = *endpoint;
	return RB_FIND(srte_policy_head, &srte_policies, &search);
}

void srte_policy_update_binding_sid(struct srte_policy *policy,
				    uint32_t binding_sid)
{
	if (policy->binding_sid != MPLS_LABEL_NONE)
		path_zebra_release_label(policy->binding_sid);

	policy->binding_sid = binding_sid;

	/* Reinstall the Binding-SID if necessary. */
	if (policy->best_candidate)
		path_zebra_add_sr_policy(policy,
					 policy->best_candidate->segment_list);
}

struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference)
{
	struct srte_candidate *candidate;

	candidate = XCALLOC(MTYPE_PATH_SR_CANDIDATE, sizeof(*candidate));
	candidate->preference = preference;
	candidate->policy = policy;
	candidate->created = true;
	RB_INSERT(srte_candidate_head, &policy->candidate_paths, candidate);

	return candidate;
}

void srte_candidate_del(struct srte_candidate *candidate)
{
	struct srte_policy *srte_policy = candidate->policy;

	hook_call(pathd_candidate_removed, candidate);
	RB_REMOVE(srte_candidate_head, &srte_policy->candidate_paths,
		  candidate);
	XFREE(MTYPE_PATH_SR_CANDIDATE, candidate);
}

struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference)
{
	struct srte_candidate search;

	search.preference = preference;
	return RB_FIND(srte_candidate_head, &policy->candidate_paths, &search);
}

void srte_candidate_set_active(struct srte_policy *policy,
			       struct srte_candidate *changed_candidate)
{
	bool was_deleted = false;
	struct srte_candidate *former_best_candidate = NULL;
	struct srte_candidate *best_candidate = NULL;
	struct srte_candidate *candidate = NULL;

	/* Figure out if the triggering candidate path was deleted,
	   because in this case, the hook has already been called */
	if (changed_candidate) {
		candidate = srte_candidate_find(policy,
						changed_candidate->preference);
		was_deleted =
			(NULL == candidate) || (candidate != changed_candidate);
	}

	RB_FOREACH_REVERSE (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
		/* search for highest preference with existing segment list */
		if (candidate->segment_list) {
			best_candidate = candidate;
			break;
		}
	}

	if (!best_candidate
	    || RB_EMPTY(srte_candidate_head, &policy->candidate_paths)) {
		/* Delete the LSP from Zebra */
		policy->best_candidate = NULL;
		path_zebra_delete_sr_policy(policy);
		/* We still want to notify the changed candidate path */
		if (changed_candidate && !was_deleted) {
			srte_candidate_updated(changed_candidate);
		}
		return;
	}

	if (policy->best_candidate)
		former_best_candidate = policy->best_candidate;

	if (former_best_candidate) {
		if (former_best_candidate == best_candidate) {
			if (changed_candidate
			    && (changed_candidate != best_candidate)) {
				/* If the elected candidate did not change,
				   and it is not the triggering candidate,
				   we only need to notify the triggering
				   candidate changes */
				if (was_deleted)
					return;
				srte_candidate_updated(changed_candidate);
				return;
			}
		} else {
			/* If the elected candidate changed, update the former
			   one state */
			former_best_candidate->is_best_candidate_path = false;
		}

		/* Delete the former candidate path LSP from Zebra */
		policy->best_candidate = NULL;
		path_zebra_delete_sr_policy(policy);
	}

	best_candidate->is_best_candidate_path = true;
	policy->best_candidate = best_candidate;

	/* send the new active LSP to Zebra */
	path_zebra_add_sr_policy(policy, best_candidate->segment_list);

	/* Notifies a single time all the candidates that changed */
	if (changed_candidate && !was_deleted
	    && (changed_candidate != former_best_candidate)
	    && (changed_candidate != best_candidate)) {
		srte_candidate_updated(changed_candidate);
	}
	if (former_best_candidate
	    && (former_best_candidate != best_candidate)) {
		srte_candidate_updated(former_best_candidate);
	}
	srte_candidate_updated(best_candidate);
}

void srte_candidate_updated(struct srte_candidate *candidate)
{
	if (true == candidate->created) {
		candidate->created = false;
		hook_call(pathd_candidate_created, candidate);
	} else {
		hook_call(pathd_candidate_updated, candidate);
	}
}

const char *srte_origin2str(enum srte_protocol_origin origin)
{
	switch (origin) {
	case SRTE_ORIGIN_PCEP:
		return "PCEP";
	case SRTE_ORIGIN_BGP:
		return "BGP";
	case SRTE_ORIGIN_LOCAL:
		return "Local";
	default:
		return "Unknown";
	}
}
