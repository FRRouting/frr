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
	bool color_is_equal = !(a->color - b->color);
	bool endpoint_is_equal = (a->endpoint.s_addr == b->endpoint.s_addr);

	if (color_is_equal && endpoint_is_equal)
		return 0;

	if (a->active_segment_list.local_label
	    && b->active_segment_list.local_label)
		return (a->active_segment_list.local_label
			- b->active_segment_list.local_label);

	return -1;
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

void zebra_sr_policy_set(struct zapi_sr_policy *zapi_sr_policy,
			 struct zebra_vrf *zvrf,
			 enum zebra_sr_policy_status status)
{
	struct zebra_sr_policy *zebra_sr_policy;

	zebra_sr_policy =
		XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(*zebra_sr_policy));
	zebra_sr_policy->color = zapi_sr_policy->color;
	memcpy(&zebra_sr_policy->endpoint, &zapi_sr_policy->endpoint,
	       sizeof(zapi_sr_policy->endpoint));
	strlcpy(zebra_sr_policy->name, zapi_sr_policy->name,
		sizeof(zebra_sr_policy->name));
	zebra_sr_policy->status = status;
	zebra_sr_policy->active_segment_list =
		zapi_sr_policy->active_segment_list;
	zebra_sr_policy->zvrf = zvrf;

	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  zebra_sr_policy);

	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  zebra_sr_policy);
}

void zebra_sr_policy_delete(struct zapi_sr_policy *zapi_sr_policy)
{
	struct zebra_sr_policy zebra_sr_policy;

	memset(&zebra_sr_policy, 0, sizeof(zebra_sr_policy));

	zebra_sr_policy.color = zapi_sr_policy->color;
	zebra_sr_policy.endpoint.s_addr = zapi_sr_policy->endpoint.s_addr;
	zebra_sr_policy.active_segment_list.local_label =
		zapi_sr_policy->active_segment_list.local_label;

	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  &zebra_sr_policy);
}

static int zebra_sr_policy_process_label_update(
	mpls_label_t label, enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy *sr_policy;
	struct zapi_srte_tunnel *zt;
	zebra_lsp_t *lsp;
	mpls_label_t next_hop_label;
	zebra_nhlfe_t *nhlfe;

	RB_FOREACH (sr_policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		zt = &sr_policy->active_segment_list;
		next_hop_label = zt->labels[0];
		if (next_hop_label == label) {
			if (mode == ZEBRA_SR_POLICY_LABEL_CREATED
			    && sr_policy->status == ZEBRA_SR_POLICY_DOWN) {
				lsp = mpls_lsp_find(sr_policy->zvrf,
						    next_hop_label);
				frr_each_safe(nhlfe_list, &lsp->nhlfe_list,
					      nhlfe) {
					mpls_lsp_install(
						sr_policy->zvrf, zt->type,
						zt->local_label, zt->label_num,
						zt->labels,
						nhlfe->nexthop->type,
						&nhlfe->nexthop->gate,
						nhlfe->nexthop->ifindex);
				}
				sr_policy->status = ZEBRA_SR_POLICY_UP;
			}
			if (mode == ZEBRA_SR_POLICY_LABEL_REMOVED
			    && sr_policy->status == ZEBRA_SR_POLICY_UP) {
				mpls_lsp_uninstall_all_vrf(sr_policy->zvrf,
							   zt->type,
							   zt->local_label);
				sr_policy->status = ZEBRA_SR_POLICY_DOWN;
			}
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
