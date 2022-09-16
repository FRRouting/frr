/* Pathd template handling
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
#include "debug.h"

#include "pathd.h"
#include "path_template.h"

DEFINE_MTYPE_STATIC(PATHD, PATH_SR_POLICY_TEMPLATE, "SR Policy Template");
DEFINE_MTYPE_STATIC(PATHD, PATH_SR_CANDIDATE_TEMPLATE,
		    "SR Policy candidate template path");

struct debug path_template_debug;

/* Generate rb-tree of Candidate Path instances. */
static inline int
srte_candidate_template_compare(const struct srte_candidate_template *a,
				const struct srte_candidate_template *b)
{
	return a->preference - b->preference;
}

RB_GENERATE(srte_candidate_template_head, srte_candidate_template, entry,
	    srte_candidate_template_compare)

/* Generate rb-tree of SR Policy instances. */
static inline int
srte_policy_template_compare(const struct srte_policy_template *a,
			     const struct srte_policy_template *b)
{
	return sr_policy_template_compare(a->color, b->color);
}

RB_GENERATE(srte_policy_template_head, srte_policy_template, entry,
	    srte_policy_template_compare)

struct srte_policy_template_head srte_policies_template =
	RB_INITIALIZER(&srte_policies_template);

/**
 * Add a policy template to pathd.
 *
 * WARNING: There is no 0 color
 *
 * @param color The color of the policy.
 * @return The created policy
 */
struct srte_policy_template *srte_policy_template_add(uint32_t color)
{
	struct srte_policy_template *policy;

	policy = XCALLOC(MTYPE_PATH_SR_POLICY_TEMPLATE, sizeof(*policy));
	policy->color = color;
	RB_INIT(srte_candidate_template_head, &policy->candidate_paths);
	RB_INSERT(srte_policy_template_head, &srte_policies_template, policy);

	return policy;
}

/**
 * Delete a policy template from pathd.
 *
 * The given policy template structure will be freed and should never be
 * used again after calling this function.
 *
 * @param policy The policy template to be removed
 */
void srte_policy_template_del(struct srte_policy_template *policy)
{
	struct srte_candidate_template *candidate;

	/* XXX delete sr_policies derived from that policy template */

	while (!RB_EMPTY(srte_candidate_template_head,
			 &policy->candidate_paths)) {
		candidate = RB_ROOT(srte_candidate_template_head,
				    &policy->candidate_paths);
		srte_candidate_template_del(candidate);
	}


	RB_REMOVE(srte_policy_template_head, &srte_policies_template, policy);
	XFREE(MTYPE_PATH_SR_POLICY_TEMPLATE, policy);
}

/**
 * Search for a policy by color and endpoint.
 *
 * WARNING: The color 0 is a special case as it is the no-color.
 *
 * @param color The color of the policy to look for
 * @return The policy if found, NULL otherwise
 */
struct srte_policy_template *srte_policy_template_find(uint32_t color)
{
	struct srte_policy_template search;

	search.color = color;
	return RB_FIND(srte_policy_template_head, &srte_policies_template,
		       &search);
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
void srte_policy_template_apply_changes(struct srte_policy_template *policy)
{
	struct srte_candidate_template *candidate, *safe;

	RB_FOREACH_SAFE (candidate, srte_candidate_template_head,
			 &policy->candidate_paths, safe) {
		if (CHECK_FLAG(candidate->flags, F_CANDIDATE_DELETED)) {
			/* XXX trigger instantiated candidates templates */
			srte_candidate_template_del(candidate);
			continue;
		} else if (CHECK_FLAG(candidate->flags, F_CANDIDATE_NEW)) {
			/* XXX trigger new candidate */
		} else if (CHECK_FLAG(candidate->flags, F_CANDIDATE_MODIFIED)) {
			/* XXX trigger modified candidate */
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
struct srte_candidate_template *
srte_candidate_template_add(struct srte_policy_template *policy,
			    uint32_t preference)
{
	struct srte_candidate_template *candidate;

	candidate =
		XCALLOC(MTYPE_PATH_SR_CANDIDATE_TEMPLATE, sizeof(*candidate));

	candidate->preference = preference;
	candidate->policy = policy;
	candidate->type = SRTE_CANDIDATE_TYPE_UNDEFINED;

	RB_INSERT(srte_candidate_template_head, &policy->candidate_paths,
		  candidate);

	return candidate;
}

/**
 * Deletes a template candidate.
 *
 * The corresponding LSP will be removed alongside the candidate path.
 * The given candidate will be freed and shouldn't be used anymore after the
 * calling this function.
 *
 * @param candidate The candidate path to delete
 */
void srte_candidate_template_del(struct srte_candidate_template *candidate)
{
	struct srte_policy_template *srte_policy = candidate->policy;

	RB_REMOVE(srte_candidate_template_head, &srte_policy->candidate_paths,
		  candidate);

	XFREE(MTYPE_PATH_SR_CANDIDATE_TEMPLATE, candidate);
}

/**
 * Searches for a candidate path of the given policy template.
 * @param policy The policy template to search for candidate path
 * @param preference The preference of the candidate path you are looking for
 * @return The candidate path template if found, NULL otherwise
 */
struct srte_candidate_template *
srte_candidate_template_find(struct srte_policy_template *policy,
			     uint32_t preference)
{
	struct srte_candidate_template search;

	search.preference = preference;
	return RB_FIND(srte_candidate_template_head, &policy->candidate_paths,
		       &search);
}

void srte_template_clean_zebra(void)
{
	struct srte_policy_template *policy_tpl, *safe_pol_tpl;

	RB_FOREACH_SAFE (policy_tpl, srte_policy_template_head,
			 &srte_policies_template, safe_pol_tpl)
		srte_policy_template_del(policy_tpl);
}

void srte_template_apply_changes(void)
{
	struct srte_policy_template *policy_tpl, *safe_pol_tpl;

	RB_FOREACH_SAFE (policy_tpl, srte_policy_template_head,
			 &srte_policies_template, safe_pol_tpl) {
		if (CHECK_FLAG(policy_tpl->flags, F_POLICY_DELETED)) {
			srte_policy_template_del(policy_tpl);
			continue;
		}
		srte_policy_template_apply_changes(policy_tpl);
		UNSET_FLAG(policy_tpl->flags, F_POLICY_NEW);
		UNSET_FLAG(policy_tpl->flags, F_POLICY_MODIFIED);
	}
}

void srte_template_show_debugging(struct vty *vty)
{
	if (DEBUG_FLAGS_CHECK(&path_template_debug, PATH_TEMPLATE_DEBUG_BASIC))
		vty_out(vty, "  Path template debugging is on\n");
}
