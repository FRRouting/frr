/*
 * Copyright (C) 2020  NetDEF, Inc.
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
#include "network.h"

#include "pathd/pathd.h"
#include "pathd/path_zebra.h"
#include "pathd/path_debug.h"
#include "pathd/path_ted.h"

#define HOOK_DELAY 3

DEFINE_MGROUP(PATHD, "pathd");

DEFINE_MTYPE_STATIC(PATHD, PATH_SEGMENT_LIST, "Segment List");
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_POLICY, "SR Policy");
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_CANDIDATE, "SR Policy candidate path");

DEFINE_HOOK(pathd_candidate_created, (struct srte_candidate * candidate),
	    (candidate));
DEFINE_HOOK(pathd_candidate_updated, (struct srte_candidate * candidate),
	    (candidate));
DEFINE_HOOK(pathd_candidate_removed, (struct srte_candidate * candidate),
	    (candidate));

static void trigger_pathd_candidate_created(struct srte_candidate *candidate);
static int trigger_pathd_candidate_created_timer(struct thread *thread);
static void trigger_pathd_candidate_updated(struct srte_candidate *candidate);
static int trigger_pathd_candidate_updated_timer(struct thread *thread);
static void trigger_pathd_candidate_removed(struct srte_candidate *candidate);
static const char *
srte_candidate_metric_name(enum srte_candidate_metric_type type);

static void srte_set_metric(struct srte_metric *metric, float value,
			    bool required, bool is_bound, bool is_computed);
static void srte_unset_metric(struct srte_metric *metric);


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

/**
 * Adds a segment list to pathd.
 *
 * @param name The name of the segment list to add
 * @return The added segment list
 */
struct srte_segment_list *srte_segment_list_add(const char *name)
{
	struct srte_segment_list *segment_list;

	segment_list = XCALLOC(MTYPE_PATH_SEGMENT_LIST, sizeof(*segment_list));
	strlcpy(segment_list->name, name, sizeof(segment_list->name));
	RB_INIT(srte_segment_entry_head, &segment_list->segments);
	RB_INSERT(srte_segment_list_head, &srte_segment_lists, segment_list);

	return segment_list;
}

/**
 * Deletes a segment list from pathd.
 *
 * The given segment list structure will be freed and should not be used anymore
 * after calling this function.
 *
 * @param segment_list the segment list to remove from pathd.
 */
void srte_segment_list_del(struct srte_segment_list *segment_list)
{
	struct srte_segment_entry *segment, *safe_seg;
	RB_FOREACH_SAFE (segment, srte_segment_entry_head,
			 &segment_list->segments, safe_seg) {
		srte_segment_entry_del(segment);
	}
	RB_REMOVE(srte_segment_list_head, &srte_segment_lists, segment_list);
	XFREE(MTYPE_PATH_SEGMENT_LIST, segment_list);
}

/**
 * Search for a segment list by name.
 *
 * @param name The name of the segment list to look for
 * @return The segment list if found, NULL otherwise
 */
struct srte_segment_list *srte_segment_list_find(const char *name)
{
	struct srte_segment_list search;

	strlcpy(search.name, name, sizeof(search.name));
	return RB_FIND(srte_segment_list_head, &srte_segment_lists, &search);
}

/**
 * Adds a segment to a segment list.
 *
 * @param segment_list The segment list the segment should be added to
 * @param index	The index of the added segment in the segment list
 * @return The added segment
 */
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

/**
 * Deletes a segment from a segment list.
 *
 * @param segment The segment to be removed
 */
void srte_segment_entry_del(struct srte_segment_entry *segment)
{
	RB_REMOVE(srte_segment_entry_head, &segment->segment_list->segments,
		  segment);
	XFREE(MTYPE_PATH_SEGMENT_LIST, segment);
}

/**
 * Set the node or adjacency identifier of a segment.
 *
 * @param segment The segment for which the NAI should be set
 * @param type The type of the NAI
 * @param type The address of the node or the local address of the adjacency
 * @param type The local interface index of the unumbered adjacency
 * @param type The remote address of the adjacency
 * @param type The remote interface index of the unumbered adjacency
 */
void srte_segment_entry_set_nai(struct srte_segment_entry *segment,
				enum srte_segment_nai_type type,
				struct ipaddr *local_ip, uint32_t local_iface,
				struct ipaddr *remote_ip, uint32_t remote_iface)
{
	segment->nai_type = type;
	memcpy(&segment->nai_local_addr, local_ip, sizeof(struct ipaddr));

	switch (type) {
	case SRTE_SEGMENT_NAI_TYPE_IPV4_NODE:
	case SRTE_SEGMENT_NAI_TYPE_IPV6_NODE:
		break;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_ADJACENCY:
	case SRTE_SEGMENT_NAI_TYPE_IPV6_ADJACENCY:
		memcpy(&segment->nai_remote_addr, remote_ip,
		       sizeof(struct ipaddr));
		break;
	case SRTE_SEGMENT_NAI_TYPE_IPV4_UNNUMBERED_ADJACENCY:
		memcpy(&segment->nai_remote_addr, remote_ip,
		       sizeof(struct ipaddr));
		segment->nai_local_iface = local_iface;
		segment->nai_remote_iface = remote_iface;
		break;
	default:
		segment->nai_local_addr.ipa_type = IPADDR_NONE;
		segment->nai_local_iface = 0;
		segment->nai_remote_addr.ipa_type = IPADDR_NONE;
		segment->nai_remote_iface = 0;
	}
}

/**
 * Add a policy to pathd.
 *
 * WARNING: The color 0 is a special case as it is the no-color.
 *
 * @param color The color of the policy.
 * @param endpoint The IP address of the policy endpoint
 * @return The created policy
 */
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

/**
 * Delete a policy from pathd.
 *
 * The given policy structure will be freed and should never be used again
 * after calling this function.
 *
 * @param policy The policy to be removed
 */
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

/**
 * Search for a policy by color and endpoint.
 *
 * WARNING: The color 0 is a special case as it is the no-color.
 *
 * @param color The color of the policy to look for
 * @param endpoint The endpoint of the policy to look for
 * @return The policy if found, NULL otherwise
 */
struct srte_policy *srte_policy_find(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_policy search;

	search.color = color;
	search.endpoint = *endpoint;
	return RB_FIND(srte_policy_head, &srte_policies, &search);
}

/**
 * Update a policy binding SID.
 *
 * @param policy The policy for which the SID should be updated
 * @param binding_sid The new binding SID for the given policy
 */
void srte_policy_update_binding_sid(struct srte_policy *policy,
				    uint32_t binding_sid)
{
	if (policy->binding_sid != MPLS_LABEL_NONE)
		path_zebra_release_label(policy->binding_sid);

	policy->binding_sid = binding_sid;

	/* Reinstall the Binding-SID if necessary. */
	if (policy->best_candidate)
		path_zebra_add_sr_policy(
			policy, policy->best_candidate->lsp->segment_list);
}

/**
 * Gives the policy best candidate path.
 *
 * @param policy The policy we want the best candidate path from
 * @return The best candidate path
 */
static struct srte_candidate *
srte_policy_best_candidate(const struct srte_policy *policy)
{
	struct srte_candidate *candidate;

	RB_FOREACH_REVERSE (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
		/* search for highest preference with existing segment list */
		if (!CHECK_FLAG(candidate->flags, F_CANDIDATE_DELETED)
		    && candidate->lsp->segment_list)
			return candidate;
	}

	return NULL;
}

void srte_clean_zebra(void)
{
	struct srte_policy *policy, *safe_pol;

	RB_FOREACH_SAFE (policy, srte_policy_head, &srte_policies, safe_pol)
		srte_policy_del(policy);
}

/**
 * Apply changes defined by setting the policies, candidate paths
 * and segment lists modification flags NEW, MODIFIED and DELETED.
 *
 * This allows the northbound code to delay all the side effects of adding
 * modifying and deleting them to the end.
 *
 * Example of marking an object as modified:
 *   `SET_FLAG(obj->flags, F_XXX_MODIFIED)`
 */
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

/**
 * Apply changes defined by setting the given policy and its candidate paths
 * modification flags NEW, MODIFIED and DELETED.
 *
 * In moste cases `void srte_apply_changes(void)` should be used instead,
 * this function will not handle the changes of segment lists used by the
 * policy.
 *
 * @param policy The policy changes has to be applied to.
 */
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
				policy, new_best_candidate->lsp->segment_list);
		}
	} else if (new_best_candidate) {
		/* The best candidate path did not change, but some of its
		 * attributes or its segment list may have changed.
		 */

		bool candidate_changed = CHECK_FLAG(new_best_candidate->flags,
						    F_CANDIDATE_MODIFIED);
		bool segment_list_changed =
			new_best_candidate->lsp->segment_list
			&& CHECK_FLAG(
				   new_best_candidate->lsp->segment_list->flags,
				   F_SEGMENT_LIST_MODIFIED);

		if (candidate_changed || segment_list_changed) {
			/* TODO: add debug guard. */
			zlog_debug("SR-TE(%s, %u): best candidate %s changed",
				   endpoint, policy->color,
				   new_best_candidate->name);

			path_zebra_add_sr_policy(
				policy, new_best_candidate->lsp->segment_list);
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
		} else if (candidate->lsp->segment_list
			   && CHECK_FLAG(candidate->lsp->segment_list->flags,
					 F_SEGMENT_LIST_MODIFIED)) {
			trigger_pathd_candidate_updated(candidate);
		}

		UNSET_FLAG(candidate->flags, F_CANDIDATE_NEW);
		UNSET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	}
}

/**
 * Adds a candidate path to a policy.
 *
 * @param policy The policy the candidate path should be added to
 * @param preference The preference of the candidate path to be added
 * @return The added candidate path
 */
struct srte_candidate *srte_candidate_add(struct srte_policy *policy,
					  uint32_t preference)
{
	struct srte_candidate *candidate;
	struct srte_lsp *lsp;

	candidate = XCALLOC(MTYPE_PATH_SR_CANDIDATE, sizeof(*candidate));
	lsp = XCALLOC(MTYPE_PATH_SR_CANDIDATE, sizeof(*lsp));

	candidate->preference = preference;
	candidate->policy = policy;
	candidate->type = SRTE_CANDIDATE_TYPE_UNDEFINED;
	candidate->discriminator = frr_weak_random();

	lsp->candidate = candidate;
	candidate->lsp = lsp;

	RB_INSERT(srte_candidate_head, &policy->candidate_paths, candidate);

	return candidate;
}

/**
 * Deletes a candidate.
 *
 * The corresponding LSP will be removed alongside the candidate path.
 * The given candidate will be freed and shouldn't be used anymore after the
 * calling this function.
 *
 * @param candidate The candidate path to delete
 */
void srte_candidate_del(struct srte_candidate *candidate)
{
	struct srte_policy *srte_policy = candidate->policy;

	RB_REMOVE(srte_candidate_head, &srte_policy->candidate_paths,
		  candidate);

	XFREE(MTYPE_PATH_SR_CANDIDATE, candidate->lsp);
	XFREE(MTYPE_PATH_SR_CANDIDATE, candidate);
}

/**
 * Sets the bandwidth constraint of given candidate path.
 *
 * The corresponding LSP will be changed too.
 *
 * @param candidate The candidate path of which the bandwidth should be changed
 * @param bandwidth The Bandwidth constraint to set to the candidate path
 * @param required If the constraint is required (true) or only desired (false)
 */
void srte_candidate_set_bandwidth(struct srte_candidate *candidate,
				  float bandwidth, bool required)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug(
		"SR-TE(%s, %u): candidate %s %sconfig bandwidth set to %f B/s",
		endpoint, policy->color, candidate->name,
		required ? "required " : "", bandwidth);
	SET_FLAG(candidate->flags, F_CANDIDATE_HAS_BANDWIDTH);
	COND_FLAG(candidate->flags, F_CANDIDATE_REQUIRED_BANDWIDTH, required);
	candidate->bandwidth = bandwidth;

	srte_lsp_set_bandwidth(candidate->lsp, bandwidth, required);
}

/**
 * Sets the bandwidth constraint of the given LSP.
 *
 * The changes will not be shown as part of the running configuration.
 *
 * @param lsp The lsp of which the bandwidth should be changed
 * @param bandwidth The Bandwidth constraint to set to the candidate path
 * @param required If the constraint is required (true) or only desired (false)
 */
void srte_lsp_set_bandwidth(struct srte_lsp *lsp, float bandwidth,
			    bool required)
{
	struct srte_candidate *candidate = lsp->candidate;
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s %slsp bandwidth set to %f B/s",
		   endpoint, policy->color, candidate->name,
		   required ? "required" : "", bandwidth);
	SET_FLAG(lsp->flags, F_CANDIDATE_HAS_BANDWIDTH);
	COND_FLAG(lsp->flags, F_CANDIDATE_REQUIRED_BANDWIDTH, required);
	lsp->bandwidth = bandwidth;
}

/**
 * Remove a candidate path bandwidth constraint.
 *
 * The corresponding LSP will be changed too.
 *
 * @param candidate The candidate path of which the bandwidth should be removed
 */
void srte_candidate_unset_bandwidth(struct srte_candidate *candidate)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s config bandwidth unset",
		   endpoint, policy->color, candidate->name);
	UNSET_FLAG(candidate->flags, F_CANDIDATE_HAS_BANDWIDTH);
	UNSET_FLAG(candidate->flags, F_CANDIDATE_REQUIRED_BANDWIDTH);
	candidate->bandwidth = 0;
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	srte_lsp_unset_bandwidth(candidate->lsp);
}

/**
 * Remove an LSP bandwidth constraint.
 *
 * The changes will not be shown as part of the running configuration.
 *
 * @param lsp The lsp of which the bandwidth should be changed
 */
void srte_lsp_unset_bandwidth(struct srte_lsp *lsp)
{
	struct srte_candidate *candidate = lsp->candidate;
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s lsp bandwidth unset", endpoint,
		   policy->color, candidate->name);
	UNSET_FLAG(lsp->flags, F_CANDIDATE_HAS_BANDWIDTH);
	UNSET_FLAG(lsp->flags, F_CANDIDATE_REQUIRED_BANDWIDTH);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	lsp->bandwidth = 0;
}

/**
 * Sets a candidate path metric constraint.
 *
 * The corresponding LSP will be changed too.
 *
 * @param candidate The candidate path of which the metric should be changed
 * @param type The metric type
 * @param value The metric value
 * @param required If the constraint is required (true) or only desired (false)
 * @param is_bound If the metric is an indicative value or a strict upper bound
 * @param is_computed If the metric was computed or configured
 */
void srte_candidate_set_metric(struct srte_candidate *candidate,
			       enum srte_candidate_metric_type type,
			       float value, bool required, bool is_bound,
			       bool is_computed)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug(
		"SR-TE(%s, %u): candidate %s %sconfig metric %s (%u) set to %f (is-bound: %s; is_computed: %s)",
		endpoint, policy->color, candidate->name,
		required ? "required " : "", srte_candidate_metric_name(type),
		type, value, is_bound ? "true" : "false",
		is_computed ? "true" : "false");
	assert((type > 0) && (type <= MAX_METRIC_TYPE));
	srte_set_metric(&candidate->metrics[type - 1], value, required,
			is_bound, is_computed);
	srte_lsp_set_metric(candidate->lsp, type, value, required, is_bound,
			    is_computed);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
}

/**
 * Sets an LSP metric constraint.
 *
 * The changes will not be shown as part of the running configuration.
 *
 * @param lsp The LSP of which the metric should be changed
 * @param type The metric type
 * @param value The metric value
 * @param required If the constraint is required (true) or only desired (false)
 * @param is_bound If the metric is an indicative value or a strict upper bound
 * @param is_computed If the metric was computed or configured
 */
void srte_lsp_set_metric(struct srte_lsp *lsp,
			 enum srte_candidate_metric_type type, float value,
			 bool required, bool is_bound, bool is_computed)
{
	struct srte_candidate *candidate = lsp->candidate;
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug(
		"SR-TE(%s, %u): candidate %s %slsp metric %s (%u) set to %f (is-bound: %s; is_computed: %s)",
		endpoint, policy->color, candidate->name,
		required ? "required " : "", srte_candidate_metric_name(type),
		type, value, is_bound ? "true" : "false",
		is_computed ? "true" : "false");
	assert((type > 0) && (type <= MAX_METRIC_TYPE));
	srte_set_metric(&lsp->metrics[type - 1], value, required, is_bound,
			is_computed);
}

void srte_set_metric(struct srte_metric *metric, float value, bool required,
		     bool is_bound, bool is_computed)
{
	SET_FLAG(metric->flags, F_METRIC_IS_DEFINED);
	COND_FLAG(metric->flags, F_METRIC_IS_REQUIRED, required);
	COND_FLAG(metric->flags, F_METRIC_IS_BOUND, is_bound);
	COND_FLAG(metric->flags, F_METRIC_IS_COMPUTED, is_computed);
	metric->value = value;
}

/**
 * Removes a candidate path metric constraint.
 *
 * The corresponding LSP will be changed too.
 *
 * @param candidate The candidate path from which the metric should be removed
 * @param type The metric type
 */
void srte_candidate_unset_metric(struct srte_candidate *candidate,
				 enum srte_candidate_metric_type type)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s config metric %s (%u) unset",
		   endpoint, policy->color, candidate->name,
		   srte_candidate_metric_name(type), type);
	assert((type > 0) && (type <= MAX_METRIC_TYPE));
	srte_unset_metric(&candidate->metrics[type - 1]);
	srte_lsp_unset_metric(candidate->lsp, type);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
}

/**
 * Removes a candidate path metric constraint.
 *
 * The changes will not be shown as part of the running configuration.
 *
 * @param lsp The LSP from which the metric should be removed
 * @param type The metric type
 */
void srte_lsp_unset_metric(struct srte_lsp *lsp,
			   enum srte_candidate_metric_type type)
{
	struct srte_candidate *candidate = lsp->candidate;
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): candidate %s lsp metric %s (%u) unset",
		   endpoint, policy->color, candidate->name,
		   srte_candidate_metric_name(type), type);
	assert((type > 0) && (type <= MAX_METRIC_TYPE));
	srte_unset_metric(&lsp->metrics[type - 1]);
}

void srte_unset_metric(struct srte_metric *metric)
{
	UNSET_FLAG(metric->flags, F_METRIC_IS_DEFINED);
	UNSET_FLAG(metric->flags, F_METRIC_IS_BOUND);
	UNSET_FLAG(metric->flags, F_METRIC_IS_COMPUTED);
	metric->value = 0;
}

/**
 * Sets a candidate path objective function.
 *
 * @param candidate The candidate path of which the OF should be changed
 * @param required If the constraint is required (true) or only desired (false)
 * @param type The objective function type
 */
void srte_candidate_set_objfun(struct srte_candidate *candidate, bool required,
			       enum objfun_type type)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));

	candidate->objfun = type;
	SET_FLAG(candidate->flags, F_CANDIDATE_HAS_OBJFUN);
	COND_FLAG(candidate->flags, F_CANDIDATE_REQUIRED_OBJFUN, required);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	zlog_debug("SR-TE(%s, %u): candidate %s %sobjective function set to %s",
		   endpoint, policy->color, candidate->name,
		   required ? "required " : "", objfun_type_name(type));
}

/**
 * Removed the objective function constraint from a candidate path.
 *
 * @param candidate The candidate path from which the OF should be removed
 */
void srte_candidate_unset_objfun(struct srte_candidate *candidate)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));

	UNSET_FLAG(candidate->flags, F_CANDIDATE_HAS_OBJFUN);
	UNSET_FLAG(candidate->flags, F_CANDIDATE_REQUIRED_OBJFUN);
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	candidate->objfun = OBJFUN_UNDEFINED;
	zlog_debug(
		"SR-TE(%s, %u): candidate %s objective functions preferences unset",
		endpoint, policy->color, candidate->name);
}

static uint32_t filter_type_to_flag(enum affinity_filter_type type)
{
	switch (type) {
	case AFFINITY_FILTER_EXCLUDE_ANY:
		return F_CANDIDATE_HAS_EXCLUDE_ANY;
	case AFFINITY_FILTER_INCLUDE_ANY:
		return F_CANDIDATE_HAS_INCLUDE_ANY;
	case AFFINITY_FILTER_INCLUDE_ALL:
		return F_CANDIDATE_HAS_INCLUDE_ALL;
	default:
		return 0;
	}
}

static const char *filter_type_name(enum affinity_filter_type type)
{
	switch (type) {
	case AFFINITY_FILTER_EXCLUDE_ANY:
		return "exclude-any";
	case AFFINITY_FILTER_INCLUDE_ANY:
		return "include-any";
	case AFFINITY_FILTER_INCLUDE_ALL:
		return "include-all";
	default:
		return "unknown";
	}
}

/**
 * Sets a candidate path affinity filter constraint.
 *
 * @param candidate The candidate path of which the constraint should be changed
 * @param type The affinity constraint type to set
 * @param filter The bitmask filter of the constraint
 */
void srte_candidate_set_affinity_filter(struct srte_candidate *candidate,
					enum affinity_filter_type type,
					uint32_t filter)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));

	assert(type > AFFINITY_FILTER_UNDEFINED);
	assert(type <= MAX_AFFINITY_FILTER_TYPE);
	SET_FLAG(candidate->flags, filter_type_to_flag(type));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	candidate->affinity_filters[type - 1] = filter;
	zlog_debug(
		"SR-TE(%s, %u): candidate %s affinity filter %s set to 0x%08x",
		endpoint, policy->color, candidate->name,
		filter_type_name(type), filter);
}

/**
 * Removes a candidate path affinity filter constraint.
 *
 * @param candidate The candidate path from which the constraint should be
 * removed
 * @param type The affinity constraint type to remove
 */
void srte_candidate_unset_affinity_filter(struct srte_candidate *candidate,
					  enum affinity_filter_type type)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));

	assert(type > AFFINITY_FILTER_UNDEFINED);
	assert(type <= MAX_AFFINITY_FILTER_TYPE);
	UNSET_FLAG(candidate->flags, filter_type_to_flag(type));
	SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
	candidate->affinity_filters[type - 1] = 0;
	zlog_debug("SR-TE(%s, %u): candidate %s affinity filter %s unset",
		   endpoint, policy->color, candidate->name,
		   filter_type_name(type));
}

/**
 * Searches for a candidate path of the given policy.
 *
 * @param policy The policy to search for candidate path
 * @param preference The preference of the candidate path you are looking for
 * @return The candidate path if found, NULL otherwise
 */
struct srte_candidate *srte_candidate_find(struct srte_policy *policy,
					   uint32_t preference)
{
	struct srte_candidate search;

	search.preference = preference;
	return RB_FIND(srte_candidate_head, &policy->candidate_paths, &search);
}

/**
 * Searches for a an entry of a given segment list.
 *
 * @param segment_list The segment list to search for the entry
 * @param index The index of the entry you are looking for
 * @return The segment list entry if found, NULL otherwise.
 */
struct srte_segment_entry *
srte_segment_entry_find(struct srte_segment_list *segment_list, uint32_t index)
{
	struct srte_segment_entry search;

	search.index = index;
	return RB_FIND(srte_segment_entry_head, &segment_list->segments,
		       &search);
}

/**
 * Updates a candidate status.
 *
 * @param candidate The candidate of which the status should be updated
 * @param status The new candidate path status
 */
void srte_candidate_status_update(struct srte_candidate *candidate, int status)
{
	struct srte_policy *policy = candidate->policy;
	char endpoint[46];
	ipaddr2str(&policy->endpoint, endpoint, sizeof(endpoint));
	zlog_debug("SR-TE(%s, %u): zebra updated status to %d", endpoint,
		   policy->color, status);
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
			zlog_debug("SR-TE(%s, %u): policy is DOWN", endpoint,
				   policy->color);
			policy->status = SRTE_POLICY_STATUS_DOWN;
			break;
		}
		break;
	case ZEBRA_SR_POLICY_UP:
		switch (policy->status) {
		case SRTE_POLICY_STATUS_UP:
			return;
		default:
			zlog_debug("SR-TE(%s, %u): policy is UP", endpoint,
				   policy->color);
			policy->status = SRTE_POLICY_STATUS_UP;
			break;
		}
		break;
	}

	trigger_pathd_candidate_updated(candidate);
}

/**
 * Flags the segment lists from give originator for removal.
 *
 * The function srte_apply_changes must be called afterward for
 * the segment list to be removed.
 *
 * @param originator The originator tag of the segment list to be marked
 * @param force If the unset should be forced regardless of the originator
 */
void srte_candidate_unset_segment_list(const char *originator, bool force)
{
	if (originator == NULL) {
		zlog_warn(
			"Cannot unset segment list because originator is NULL");
		return;
	}

	zlog_debug("Unset segment lists for originator %s", originator);

	/* Iterate the policies, then iterate each policy's candidate path
	 * to check the candidate path's segment list originator */
	struct srte_policy *policy;
	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		zlog_debug("Unset segment lists checking policy %s",
			   policy->name);
		struct srte_candidate *candidate;
		RB_FOREACH (candidate, srte_candidate_head,
			    &policy->candidate_paths) {
			zlog_debug("Unset segment lists checking candidate %s",
				   candidate->name);
			if (candidate->lsp == NULL) {
				continue;
			}

			/* The candidate->lsp->segment_list is operational data,
			 * configured by the PCE. We dont want to modify the
			 * candidate->segment_list,
			 * which is configuration data. */
			struct srte_segment_list *segment_list =
				candidate->lsp->segment_list;
			if (segment_list == NULL) {
				continue;
			}

			if (segment_list->protocol_origin
			    == SRTE_ORIGIN_LOCAL) {
				zlog_warn(
					"Cannot unset segment list %s because it was created locally",
					segment_list->name);
				continue;
			}

			/* In the case of last pce,we force the unset
			 * because we don't have pce by prefix (TODO) is all
			 * 'global' */
			if (strncmp(segment_list->originator, originator,
				    sizeof(segment_list->originator))
				    == 0
			    || force) {
				zlog_debug("Unset segment list %s",
					   segment_list->name);
				SET_FLAG(segment_list->flags,
					 F_SEGMENT_LIST_DELETED);
				SET_FLAG(candidate->flags,
					 F_CANDIDATE_MODIFIED);
				candidate->lsp->segment_list = NULL;
			}
		}
	}
}

/**
 * Gives a string representation of given protocol origin enum.
 *
 * @param origin The enum you want a string representation of
 * @return The string representation of given enum
 */
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

void pathd_shutdown(void)
{
	path_ted_teardown();
	srte_clean_zebra();
}

void trigger_pathd_candidate_created(struct srte_candidate *candidate)
{
	/* The hook is called asynchronously to let the PCEP module
	time to send a response to the PCE before receiving any updates from
	pathd. In addition, a minimum amount of time need to pass before
	the hook is called to prevent the hook to be called multiple times
	from changing the candidate by hand with the console */
	if (candidate->hook_timer != NULL)
		return;
	thread_add_timer(master, trigger_pathd_candidate_created_timer,
			 (void *)candidate, HOOK_DELAY, &candidate->hook_timer);
}

int trigger_pathd_candidate_created_timer(struct thread *thread)
{
	struct srte_candidate *candidate = THREAD_ARG(thread);
	candidate->hook_timer = NULL;
	return hook_call(pathd_candidate_created, candidate);
}

void trigger_pathd_candidate_updated(struct srte_candidate *candidate)
{
	/* The hook is called asynchronously to let the PCEP module
	time to send a response to the PCE before receiving any updates from
	pathd. In addition, a minimum amount of time need to pass before
	the hook is called to prevent the hook to be called multiple times
	from changing the candidate by hand with the console */
	if (candidate->hook_timer != NULL)
		return;
	thread_add_timer(master, trigger_pathd_candidate_updated_timer,
			 (void *)candidate, HOOK_DELAY, &candidate->hook_timer);
}

int trigger_pathd_candidate_updated_timer(struct thread *thread)
{
	struct srte_candidate *candidate = THREAD_ARG(thread);
	candidate->hook_timer = NULL;
	return hook_call(pathd_candidate_updated, candidate);
}

void trigger_pathd_candidate_removed(struct srte_candidate *candidate)
{
	/* The hook needs to be call synchronously, otherwise the candidate
	path will be already deleted when the handler is called */
	if (candidate->hook_timer != NULL) {
		thread_cancel(&candidate->hook_timer);
		candidate->hook_timer = NULL;
	}
	hook_call(pathd_candidate_removed, candidate);
}

const char *srte_candidate_metric_name(enum srte_candidate_metric_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_METRIC_TYPE_IGP:
		return "IGP";
	case SRTE_CANDIDATE_METRIC_TYPE_TE:
		return "TE";
	case SRTE_CANDIDATE_METRIC_TYPE_HC:
		return "HC";
	case SRTE_CANDIDATE_METRIC_TYPE_ABC:
		return "ABC";
	case SRTE_CANDIDATE_METRIC_TYPE_LMLL:
		return "LMLL";
	case SRTE_CANDIDATE_METRIC_TYPE_CIGP:
		return "CIGP";
	case SRTE_CANDIDATE_METRIC_TYPE_CTE:
		return "CTE";
	case SRTE_CANDIDATE_METRIC_TYPE_PIGP:
		return "PIGP";
	case SRTE_CANDIDATE_METRIC_TYPE_PTE:
		return "PTE";
	case SRTE_CANDIDATE_METRIC_TYPE_PHC:
		return "PHC";
	case SRTE_CANDIDATE_METRIC_TYPE_MSD:
		return "MSD";
	case SRTE_CANDIDATE_METRIC_TYPE_PD:
		return "PD";
	case SRTE_CANDIDATE_METRIC_TYPE_PDV:
		return "PDV";
	case SRTE_CANDIDATE_METRIC_TYPE_PL:
		return "PL";
	case SRTE_CANDIDATE_METRIC_TYPE_PPD:
		return "PPD";
	case SRTE_CANDIDATE_METRIC_TYPE_PPDV:
		return "PPDV";
	case SRTE_CANDIDATE_METRIC_TYPE_PPL:
		return "PPL";
	case SRTE_CANDIDATE_METRIC_TYPE_NAP:
		return "NAP";
	case SRTE_CANDIDATE_METRIC_TYPE_NLP:
		return "NLP";
	case SRTE_CANDIDATE_METRIC_TYPE_DC:
		return "DC";
	case SRTE_CANDIDATE_METRIC_TYPE_BNC:
		return "BNC";
	default:
		return "UNKNOWN";
	}
}
