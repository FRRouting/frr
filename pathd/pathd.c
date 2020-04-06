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

static void trigger_pathd_candidate_created(struct srte_candidate *candidate);
static int trigger_pathd_candidate_created_event(struct thread *thread);
static void trigger_pathd_candidate_updated(struct srte_candidate *candidate);
static int trigger_pathd_candidate_updated_event(struct thread *thread);
static void trigger_pathd_candidate_removed(struct srte_candidate *candidate);
static int trigger_pathd_candidate_removed_event(struct thread *thread);
static const char *
srte_candidate_metric_name(enum srte_candidate_metric_type type);

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
	segment->segment_list = segment_list;
	segment->index = index;
	RB_INSERT(srte_segment_entry_head, &segment_list->segments, segment);

	return segment;
}

void srte_segment_entry_del(struct srte_segment_entry *segment)
{
	RB_REMOVE(srte_segment_entry_head, &segment->segment_list->segments,
		  segment);
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

	path_zebra_release_label(policy->binding_sid);

	while (!RB_EMPTY(srte_candidate_head, &policy->candidate_paths)) {
		candidate =
			RB_ROOT(srte_candidate_head, &policy->candidate_paths);
		trigger_pathd_candidate_removed(candidate);
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

static struct srte_candidate *
srte_policy_best_candidate(const struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH_REVERSE (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
		/* search for highest preference with existing segment list */
		if (!CHECK_FLAG(candidate->flags, F_CANDIDATE_DELETED)
		    && candidate->segment_list)
			return candidate;
	}

	return NULL;
}

void srte_apply_changes(void)
{
	struct srte_policy *policy, *safe_pol;
	struct srte_segment_list *segment_list, *safe_sl;

	RB_FOREACH_SAFE (policy, srte_policy_head, &srte_policies, safe_pol) {
		if (CHECK_FLAG(policy->flags, F_POLICY_DELETED)) {
			srte_policy_del(policy);
			continue;
		}
		srte_policy_apply_changes(policy);
		UNSET_FLAG(policy->flags, F_POLICY_NEW);
		UNSET_FLAG(policy->flags, F_POLICY_MODIFIED);
	}

	RB_FOREACH_SAFE (segment_list, srte_segment_list_head,
			 &srte_segment_lists, safe_sl) {
		if (CHECK_FLAG(segment_list->flags, F_SEGMENT_LIST_DELETED)) {
			srte_segment_list_del(segment_list);
			continue;
		}
		UNSET_FLAG(segment_list->flags, F_SEGMENT_LIST_NEW);
		UNSET_FLAG(segment_list->flags, F_SEGMENT_LIST_MODIFIED);
	}
}

void srte_policy_apply_changes(struct srte_policy *policy)
{
	struct srte_candidate *candidate, *safe;
	struct srte_candidate *old_best_candidate;
	struct srte_candidate *new_best_candidate;
	char endpoint[46];

	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));

	/* Get old and new best candidate path. */
	old_best_candidate = policy->best_candidate;
	new_best_candidate = srte_policy_best_candidate(policy);

	if (new_best_candidate != old_best_candidate) {
		/* TODO: add debug guard. */
		zlog_debug(
			"SR-TE(%s, %u): best candidate changed from %s to %s",
			endpoint, policy->color,
			old_best_candidate ? old_best_candidate->name : "none",
			new_best_candidate ? new_best_candidate->name : "none");

		if (old_best_candidate) {
			policy->best_candidate = NULL;
			UNSET_FLAG(old_best_candidate->flags, F_CANDIDATE_BEST);
			SET_FLAG(old_best_candidate->flags,
				 F_CANDIDATE_MODIFIED);

			/*
			 * Rely on replace semantics if there's a new best
			 * candidate.
			 */
			if (!new_best_candidate)
				path_zebra_delete_sr_policy(policy);
		}
		if (new_best_candidate) {
			policy->best_candidate = new_best_candidate;
			SET_FLAG(new_best_candidate->flags, F_CANDIDATE_BEST);
			SET_FLAG(new_best_candidate->flags,
				 F_CANDIDATE_MODIFIED);

			path_zebra_add_sr_policy(
				policy, new_best_candidate->segment_list);
		}
	} else if (new_best_candidate) {
		/* The best candidate path did not change, but some of its
		 * attributes or its segment list may have changed.
		 */

		bool candidate_changed = CHECK_FLAG(new_best_candidate->flags,
						    F_CANDIDATE_MODIFIED);
		bool segment_list_changed =
			new_best_candidate->segment_list
			&& CHECK_FLAG(new_best_candidate->segment_list->flags,
				      F_SEGMENT_LIST_MODIFIED);

		if (candidate_changed || segment_list_changed) {
			/* TODO: add debug guard. */
			zlog_debug("SR-TE(%s, %u): best candidate %s changed",
				   endpoint, policy->color,
				   new_best_candidate->name);

			path_zebra_add_sr_policy(
				policy, new_best_candidate->segment_list);
		}
	}

	RB_FOREACH_SAFE (candidate, srte_candidate_head,
			 &policy->candidate_paths, safe) {
		if (CHECK_FLAG(candidate->flags, F_CANDIDATE_DELETED)) {
			trigger_pathd_candidate_removed(candidate);
			srte_candidate_del(candidate);
			continue;
		} else if (CHECK_FLAG(candidate->flags, F_CANDIDATE_NEW)) {
			trigger_pathd_candidate_created(candidate);
		} else if (CHECK_FLAG(candidate->flags, F_CANDIDATE_MODIFIED)) {
			trigger_pathd_candidate_updated(candidate);
		} else if (candidate->segment_list
			   && CHECK_FLAG(candidate->segment_list->flags,
					 F_SEGMENT_LIST_MODIFIED)) {
			trigger_pathd_candidate_updated(candidate);
		}

		UNSET_FLAG(candidate->flags, F_CANDIDATE_NEW);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	}
}

struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference)
{
	struct srte_candidate *candidate;

	candidate = XCALLOC(MTYPE_PATH_SR_CANDIDATE, sizeof(*candidate));
	candidate->preference = preference;
	candidate->policy = policy;
	candidate->type = SRTE_CANDIDATE_TYPE_UNDEFINED;
	RB_INSERT(srte_candidate_head, &policy->candidate_paths, candidate);

	return candidate;
}

void srte_candidate_del(struct srte_candidate *candidate)
{
	struct srte_policy *srte_policy = candidate->policy;

	RB_REMOVE(srte_candidate_head, &srte_policy->candidate_paths,
		  candidate);
	XFREE(MTYPE_PATH_SR_CANDIDATE, candidate);
}

void srte_candidate_set_metric(struct srte_candidate *candidate,
			       enum srte_candidate_metric_type type,
			       float value, bool is_bound, bool is_computed)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug(
		"SR-TE(%s, %u): candidate %s metric %s (%u) set to %f (is-bound: %s; is_computed: %s)",
		endpoint, policy->color, candidate->name,
		srte_candidate_metric_name(type), type, value,
		is_bound ? "true" : "false", is_computed ? "true" : "false");
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		SET_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_ABC);
		COND_FLAG(candidate->flags, F_CANDIDATE_METRIC_ABC_BOUND,
			  is_bound);
		COND_FLAG(candidate->flags, F_CANDIDATE_METRIC_ABC_COMPUTED,
			  is_computed);
		candidate->metric_abc = value;
		break;
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		SET_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_TE);
		COND_FLAG(candidate->flags, F_CANDIDATE_METRIC_TE_BOUND,
			  is_bound);
		COND_FLAG(candidate->flags, F_CANDIDATE_METRIC_TE_COMPUTED,
			  is_computed);
		candidate->metric_te = value;
		break;
	default:
		break;
	}
}

void srte_candidate_unset_metric(struct srte_candidate *candidate,
				 enum srte_candidate_metric_type type)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s metric %s (%u) unset", endpoint,
		   policy->color, candidate->name,
		   srte_candidate_metric_name(type), type);
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		UNSET_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_ABC);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_METRIC_ABC_BOUND);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_METRIC_ABC_COMPUTED);
		candidate->metric_abc = 0;
		break;
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		UNSET_FLAG(candidate->flags, F_CANDIDATE_HAS_METRIC_TE);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_METRIC_TE_BOUND);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_METRIC_TE_COMPUTED);
		candidate->metric_te = 0;
		break;
	default:
		break;
	}
}

struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference)
{
	struct srte_candidate search;

	search.preference = preference;
	return RB_FIND(srte_candidate_head, &policy->candidate_paths, &search);
}

void srte_candidate_status_update(struct srte_policy *policy,
				  struct srte_candidate *candidate, int status)
{
	switch (status) {
	case ZEBRA_SR_POLICY_DOWN:
		switch (policy->status) {
		/* If the policy is GOING_UP, and zebra faild
		   to install it, we wait for zebra to retry */
		/* TODO: Add some timeout after which we would
			 get is back to DOWN and remove the
			 policy */
		case SRTE_POLICY_STATUS_GOING_UP:
		case SRTE_POLICY_STATUS_DOWN:
			return;
		default:
			policy->status = SRTE_POLICY_STATUS_DOWN;
			break;
		}
		break;
	case ZEBRA_SR_POLICY_UP:
		switch (policy->status) {
		case SRTE_POLICY_STATUS_UP:
			return;
		default:
			policy->status = SRTE_POLICY_STATUS_UP;
			break;
		}
		break;
	}

	trigger_pathd_candidate_updated(candidate);
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

void trigger_pathd_candidate_created(struct srte_candidate *candidate)
{
	thread_add_event(master, trigger_pathd_candidate_created_event,
			 (void *)candidate, 0, NULL);
}

int trigger_pathd_candidate_created_event(struct thread *thread)
{
	struct srte_candidate *candidate = THREAD_ARG(thread);
	return hook_call(pathd_candidate_created, candidate);
}

void trigger_pathd_candidate_updated(struct srte_candidate *candidate)
{
	thread_add_event(master, trigger_pathd_candidate_updated_event,
			 (void *)candidate, 0, NULL);
}

int trigger_pathd_candidate_updated_event(struct thread *thread)
{
	struct srte_candidate *candidate = THREAD_ARG(thread);
	return hook_call(pathd_candidate_updated, candidate);
}

void trigger_pathd_candidate_removed(struct srte_candidate *candidate)
{
	thread_add_event(master, trigger_pathd_candidate_removed_event,
			 (void *)candidate, 0, NULL);
}

int trigger_pathd_candidate_removed_event(struct thread *thread)
{
	struct srte_candidate *candidate = THREAD_ARG(thread);
	return hook_call(pathd_candidate_removed, candidate);
}

const char *srte_candidate_metric_name(enum srte_candidate_metric_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		return "ABC";
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		return "TE";
	default:
		return "UNKNOWN";
	}
}