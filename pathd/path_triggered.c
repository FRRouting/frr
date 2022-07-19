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

#include "path_zebra.h"
#include "path_triggered.h"
#include "path_template.h"
#include "path_tsrte.h"

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
	}
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

	/* XXX if policy template available, create policy
	 * and candidate path associated
	 */
}

void srte_triggered_del(uint32_t color, struct ipaddr *endpoint)
{
	struct srte_triggered_policy *policy;

	policy = srte_triggered_policy_find(color, endpoint);
	if (!policy)
		return;
	/* XXX if policy template available, delete policy
	 * and candidate path associated
	 */
	RB_REMOVE(srte_triggered_policy_head, &srte_triggered_policies, policy);
	XFREE(MTYPE_PATH_SR_TRIGGERED_POLICY, policy);
}
