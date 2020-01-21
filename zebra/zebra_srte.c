/* Zebra SR-TE code
 * Copyright (C) 2020  NetDEF, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "zebra/zebra_srte.h"
#include "lib/zclient.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_mpls.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR_POLICY, "SR Policy")

/* Generate rb-tree of SR Policy instances. */
static inline int
zebra_sr_policy_instance_compare(const struct zebra_sr_policy *a,
				 const struct zebra_sr_policy *b)
{
	if (a->color < b->color)
		return -1;

	if (a->color > b->color)
		return 1;

	if (a->endpoint.s_addr < b->endpoint.s_addr)
		return -1;

	if (a->endpoint.s_addr > b->endpoint.s_addr)
		return 1;

	return 0;
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

struct zebra_sr_policy *zebra_sr_policy_add(uint32_t color,
					    struct in_addr endpoint)
{
	struct zebra_sr_policy *policy;

	policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = endpoint;
	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);

	return policy;
}

void zebra_sr_policy_del(struct zebra_sr_policy *policy)
{
	zebra_sr_policy_uninstall(policy);
	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);
	XFREE(MTYPE_ZEBRA_SR_POLICY, policy);
}

struct zebra_sr_policy *zebra_sr_policy_find(uint32_t color,
					     struct in_addr endpoint)
{
	struct zebra_sr_policy policy = {};

	policy.color = color;
	policy.endpoint = endpoint;
	return RB_FIND(zebra_sr_policy_instance_head,
		       &zebra_sr_policy_instances, &policy);
}

void zebra_sr_policy_install(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->active_segment_list;
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *nhlfe;
	int ret;

	zebra_sr_policy_uninstall(policy);

	/* Try to resolve the Binding-SID nexthops. */
	lsp = mpls_lsp_find(policy->zvrf, zt->labels[0]);
	if (!lsp)
		return;

	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		ret = mpls_lsp_install(
			policy->zvrf, zt->type, zt->local_label, zt->label_num,
			zt->labels, nhlfe->nexthop->type, &nhlfe->nexthop->gate,
			nhlfe->nexthop->ifindex);
		if (ret) {
			zebra_sr_policy_uninstall(policy);
			return;
		}
	}

	policy->status = ZEBRA_SR_POLICY_UP;
}

void zebra_sr_policy_uninstall(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->active_segment_list;

	if (policy->status == ZEBRA_SR_POLICY_UP)
		return;

	mpls_lsp_uninstall_all_vrf(policy->zvrf, zt->type, zt->local_label);
	policy->status = ZEBRA_SR_POLICY_DOWN;
}

static int zebra_sr_policy_process_label_update(
	mpls_label_t label, enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy *policy;

	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		struct zapi_srte_tunnel *zt;
		mpls_label_t next_hop_label;

		zt = &policy->active_segment_list;
		next_hop_label = zt->labels[0];
		if (next_hop_label != label)
			continue;

		if (mode == ZEBRA_SR_POLICY_LABEL_CREATED
		    && policy->status == ZEBRA_SR_POLICY_DOWN) {
			zebra_sr_policy_install(policy);
		}
		if (mode == ZEBRA_SR_POLICY_LABEL_REMOVED
		    && policy->status == ZEBRA_SR_POLICY_UP) {
			zebra_sr_policy_uninstall(policy);
		}
	}

	return 0;
}

static int zebra_sr_policy_nexthop_label_removed(mpls_label_t label)
{
	return zebra_sr_policy_process_label_update(
		label, ZEBRA_SR_POLICY_LABEL_REMOVED);
}

static int zebra_sr_policy_nexthop_label_created(mpls_label_t label)
{
	return zebra_sr_policy_process_label_update(
		label, ZEBRA_SR_POLICY_LABEL_CREATED);
}

void zebra_srte_init(void)
{
	hook_register(zebra_mpls_label_created,
		      zebra_sr_policy_nexthop_label_created);
	hook_register(zebra_mpls_label_removed,
		      zebra_sr_policy_nexthop_label_removed);
}
