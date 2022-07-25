/* Pathd triggered SRTE handling
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"
#include "ipaddr.h"
#include "srte.h"

#include "pathd.h"
#include "path_zebra.h"
#include "path_triggered.h"
#include "path_template.h"
#include "path_tsrte.h"
#include "path_bsid.h"

bool path_triggered_enabled = false;

DEFINE_MTYPE_STATIC(PATHD, PATH_SR_TRIGGERED_POLICY, "SR Triggered Policy");

/* Generate rb-tree of SR Triggered Policy instances. */
static inline int
srte_triggered_policy_compare(const struct srte_triggered_policy *a,
			      const struct srte_triggered_policy *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}

RB_GENERATE(srte_triggered_policy_head, srte_triggered_policy, entry,
	    srte_triggered_policy_compare)
struct srte_triggered_policy_head srte_triggered_policies =
	RB_INITIALIZER(&srte_triggered_policies);

static struct srte_triggered_policy *
srte_triggered_policy_find(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_triggered_policy search;

	search.color = color;
	search.endpoint = *endpoint;
	return RB_FIND(srte_triggered_policy_head, &srte_triggered_policies,
		       &search);
}

/**
 * Create the Policy and Candidate path if needed
 *
 * @param bgp_policy: the srte bgp policy
 */
static void
srte_triggered_update_entry(struct srte_triggered_policy *bgp_policy)
{
	struct srte_policy_template *policy_template;
	struct srte_policy *policy;
	struct srte_candidate_template *candidate_template;
	struct srte_candidate *candidate;
	bool changed = false;
	char endpoint_str[ENDPOINT_STR_LENGTH];

	/* check there is a template available */
	policy_template = srte_policy_template_find(bgp_policy->color);
	if (!policy_template) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy template Color %u: not found",
			bgp_policy->color);
		return;
	}
	/* check there is a at least a candidate in the policy template */
	if (RB_EMPTY(srte_candidate_template_head,
		     &policy_template->candidate_paths)) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy template Color %u: no candidate paths",
			bgp_policy->color);
		return;
	}

	/* check if there is a policy available. if not create it */
	policy = srte_policy_find(bgp_policy->color, &bgp_policy->endpoint);
	ipaddr2str(&bgp_policy->endpoint, endpoint_str, sizeof(endpoint_str));
	if (!policy) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy Color %u Endpoint %s: created from template",
			bgp_policy->color, endpoint_str);
		policy = srte_policy_add(bgp_policy->color,
					 &bgp_policy->endpoint, SRTE_ORIGIN_BGP, NULL);
		policy->binding_sid = path_bsid_request_label();
		policy_template->counter++;
		snprintf(policy->name, sizeof(policy->name), "__%s__%u__",
			 policy_template->name, policy_template->counter);
		SET_FLAG(policy->flags, F_POLICY_NEW);
		SET_FLAG(policy->flags, F_POLICY_TEMPLATE);
		changed = true;
	} else {
		if (!CHECK_FLAG(policy->flags, F_POLICY_TEMPLATE)) {
			zlog_warn(
				"PATHD: policy Color %u Endpoint %s: template conflict with config, continue",
				bgp_policy->color, endpoint_str);
			SET_FLAG(policy->flags, F_POLICY_TEMPLATE);
			if (policy->binding_sid == MPLS_LABEL_NONE)
				policy->binding_sid = path_bsid_request_label();
			changed = true;
		}
	}

	/* check if the candidate paths are available. if not create it */
	RB_FOREACH (candidate_template, srte_candidate_template_head,
		    &policy_template->candidate_paths) {
		candidate = srte_candidate_find(policy,
						candidate_template->preference);
		if (!candidate) {
			candidate = srte_candidate_add(
				policy, candidate_template->preference, SRTE_ORIGIN_BGP, NULL);
			PATH_TEMPLATE_DEBUG(
				"PATHD: Candidate Color %u Endpoint %s Preference %u:  created from template",
				bgp_policy->color, endpoint_str,
				candidate_template->preference);
			SET_FLAG(candidate->flags, F_CANDIDATE_NEW);
			SET_FLAG(candidate->flags,
				 F_CANDIDATE_HAS_FLEX_ALGO_NUMBER);
			SET_FLAG(candidate->flags,
				 F_CANDIDATE_FLEX_ALGO_IGP_USE_DEFAULTS);
			SET_FLAG(candidate->flags, F_CANDIDATE_TEMPLATE);
		} else if (!CHECK_FLAG(candidate->flags,
				       F_CANDIDATE_TEMPLATE)) {
			zlog_warn(
				"PATHD: Candidate Color %u Endpoint %s Preference %u: conflict with config, not created !",
				bgp_policy->color, endpoint_str,
				candidate_template->preference);
			return;
		}
		strlcpy(candidate->name, candidate_template->name,
			sizeof(candidate_template->name));
		candidate->type = candidate_template->type;
		candidate->flex_algo_number =
			candidate_template->flex_algo_number;
		SET_FLAG(candidate->flags, F_CANDIDATE_MODIFIED);
		changed = true;
	}

	/* if changes, update srte changes */
	if (changed) {
		srte_policy_apply_changes(policy);
		UNSET_FLAG(policy->flags, F_POLICY_NEW);
		UNSET_FLAG(policy->flags, F_POLICY_MODIFIED);
	}
}

/**
 * Remove the Policy and Candidate path if needed
 *
 * @param bgp_policy: the srte triggered policy
 */
static void srte_triggered_policy_removing_specific(
	struct srte_triggered_policy *bgp_policy, bool specific_cpath,
	uint32_t preference)
{
	struct srte_policy *policy;
	struct srte_candidate *candidate;
	char endpoint_str[ENDPOINT_STR_LENGTH];
	bool policy_delete = true;

	ipaddr2str(&bgp_policy->endpoint, endpoint_str, sizeof(endpoint_str));

	/* check if there is a policy available. if not create it */
	policy = srte_policy_find(bgp_policy->color, &bgp_policy->endpoint);
	if (!policy) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy Color %u Endpoint %s: not found",
			bgp_policy->color, endpoint_str);
		return;
	}
	if (CHECK_FLAG(policy->flags, F_POLICY_CONFIG)) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy Color %u Endpoint %s: from config not suppressed",
			bgp_policy->color, endpoint_str);
	} else if (!CHECK_FLAG(policy->flags, F_POLICY_TEMPLATE)) {
		PATH_TEMPLATE_DEBUG(
			"PATHD: policy Color %u Endpoint %s: found but not derived from template",
			bgp_policy->color, endpoint_str);
		return;
	}

	/* check for the matching template candidate. */
	RB_FOREACH (candidate, srte_candidate_head, &policy->candidate_paths) {
		if (specific_cpath && candidate->preference != preference) {
			policy_delete = false;
			continue;
		}
		if (!CHECK_FLAG(candidate->flags, F_CANDIDATE_TEMPLATE)) {
			PATH_TEMPLATE_DEBUG(
				"PATHD: policy Color %u Endpoint %s: candidate paths preference %d origin %s not a template",
				bgp_policy->color, endpoint_str,
				candidate->preference,
				srte_origin2str(candidate->protocol_origin));
			policy_delete = false;
			continue;
		}
		SET_FLAG(candidate->flags, F_CANDIDATE_DELETED);
	}

	if (policy_delete) {
		SET_FLAG(policy->flags, F_POLICY_DELETED);
		srte_policy_del(policy);
	}
	srte_policy_apply_changes(policy);
	UNSET_FLAG(policy->flags, F_POLICY_NEW);
	UNSET_FLAG(policy->flags, F_POLICY_MODIFIED);
}

/**
 * Update protocol-origin for policies generated from templates
 *
 * @param enabled:
 *       if true, turn on srte_template_tsrte_enabled
 *       if false, turn off srte_template_tsrte_enabled only if no templates
 * configured
 */
void srte_triggered_update(void)
{
	bool protocol_bgp_enabled = false;

	if (!RB_EMPTY(srte_policy_template_head, &srte_policies_template))
		protocol_bgp_enabled = true;
	if (path_triggered_enabled != protocol_bgp_enabled) {
		path_triggered_enabled = protocol_bgp_enabled;
		zlog_info("configured for %saccepting BGP TE policies",
			  protocol_bgp_enabled ? "" : "not ");
		path_zebra_send_te_ready(srte_triggered_get_protocol_origin());
		if (path_bsid_enable_pool(protocol_bgp_enabled))
			srte_apply_changes();
	}
}

/**
 * Remove the Policy and Candidate path if needed
 *
 * @param bgp_policy: the srte triggered policy
 */
static void
srte_triggered_policy_removing(struct srte_triggered_policy *bgp_policy)
{
	srte_triggered_policy_removing_specific(bgp_policy, false, 0);
}

/**
 * Remove the Candidate path and policy if needed
 *
 * @param bgp_policy: the srte triggered policy
 * @param preference: the preference value
 */
static void srte_triggered_policy_candidate_removing(
	struct srte_triggered_policy *bgp_policy, uint32_t preference)
{
	srte_triggered_policy_removing_specific(bgp_policy, true, preference);
}

/**
 * Get protocol origin used for triggered srte
 *
 * @return : SRTE_ORIGIN_BGP if path_triggered_enabled is true
 *           SRTE_ORIGIN_LOCAL otherwise
 */
enum srte_protocol_origin srte_triggered_get_protocol_origin()
{
	if (path_triggered_enabled)
		return SRTE_ORIGIN_BGP;
	return SRTE_ORIGIN_LOCAL;
}

void srte_triggered_add(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_triggered_policy *policy;

	policy = srte_triggered_policy_find(color, endpoint);
	if (policy)
		return;

	policy = XCALLOC(MTYPE_PATH_SR_TRIGGERED_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = *endpoint;
	RB_INSERT(srte_triggered_policy_head, &srte_triggered_policies, policy);

	srte_triggered_update_entry(policy);
}

void srte_triggered_del(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_triggered_policy *policy;

	policy = srte_triggered_policy_find(color, endpoint);
	if (!policy)
		return;
	srte_triggered_policy_removing(policy);
	RB_REMOVE(srte_triggered_policy_head, &srte_triggered_policies, policy);
	XFREE(MTYPE_PATH_SR_TRIGGERED_POLICY, policy);
}

void srte_triggered_update_candidate_changed(uint32_t color)
{
	struct srte_triggered_policy *policy;

	RB_FOREACH (policy, srte_triggered_policy_head,
		    &srte_triggered_policies) {
		if (policy->color != color)
			continue;
		/* now that we have the policy to update, look if there are any
		 * bgp candidates to update
		 */
		srte_triggered_update_entry(policy);
	}
}

void srte_triggered_update_candidate_removing(uint32_t color,
					      uint32_t preference)
{
	struct srte_triggered_policy *policy;

	RB_FOREACH (policy, srte_triggered_policy_head,
		    &srte_triggered_policies) {
		if (policy->color != color)
			continue;
		/* now that we have the policy to update, look if there are any
		 * bgp candidates to update
		 */
		srte_triggered_policy_candidate_removing(policy, preference);
	}
}

void srte_triggered_clean_zebra(void)
{
	struct srte_triggered_policy *bgp_policy, *safe_bgp_pol;

	RB_FOREACH_SAFE (bgp_policy, srte_triggered_policy_head,
			 &srte_triggered_policies, safe_bgp_pol)
		srte_triggered_del(bgp_policy->color, &bgp_policy->endpoint);
}
