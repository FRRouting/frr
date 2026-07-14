// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TIB (Tree Information Base) - just PIM <> IGMP/MLD glue for now
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>

#include "pim_tib.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_upstream.h"
#include "pim_oil.h"
#include "pim_nht.h"
#include "pim_dm.h"
#include "pim_routemap.h"
#if PIM_IPV == 6
#include "pim6_mld.h"
#endif

static struct channel_oil *
tib_sg_oil_setup(struct pim_instance *pim, pim_sgaddr sg, struct interface *oif)
{
	struct pim_interface *pim_oif = oif->info;
	int input_iface_vif_index = 0;
	pim_addr vif_source;
	struct prefix grp;
	struct pim_nexthop nexthop;
	struct pim_upstream *up = NULL;

	if (!pim_rp_set_upstream_addr(pim, &vif_source, sg.src, sg.grp)) {
		/* no PIM RP - create a dummy channel oil */
		return pim_channel_oil_add(pim, &sg, __func__);
	}

	pim_addr_to_prefix(&grp, sg.grp);

	up = pim_upstream_find(pim, &sg);
	if (up) {
		memcpy(&nexthop, &up->rpf.source_nexthop, sizeof(struct pim_nexthop));
		if (!pim_nht_lookup_ecmp(pim, &nexthop, vif_source, &grp, false, NULL))
			if (PIM_DEBUG_PIM_NHT_RP)
				zlog_debug("%s: Nexthop Lookup failed vif_src:%pPA, sg.src:%pPA, sg.grp:%pPA",
					   __func__, &vif_source, &sg.src, &sg.grp);

		if (nexthop.interface)
			input_iface_vif_index = pim_if_find_vifindex_by_ifindex(
				pim, nexthop.interface->ifindex);
	} else
		input_iface_vif_index = pim_nht_lookup_ecmp_if_vif_index(pim, vif_source, &grp);

	if (PIM_DEBUG_ZEBRA)
		zlog_debug("%s: NHT %pSG vif_source %pPAs vif_index:%d",
			   __func__, &sg, &vif_source, input_iface_vif_index);

	if (input_iface_vif_index < 1) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s %s: could not find vif index of interface with NH to RP for %pSG",
				   __FILE__, __func__, &sg);

		return pim_channel_oil_add(pim, &sg, __func__);
	}

	/*
	 * Non-DR must not create (S,G) state when the RPF interface for the
	 * source is the same as the IGMP oif (see TODO T22).  The DR still
	 * creates channel_oil here; looped OIF=IIF is blocked in
	 * pim_channel_add_oif().
	 */
	if ((input_iface_vif_index == pim_oif->mroute_vif_index) && !(PIM_I_am_DR(pim_oif))) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				"%s: ignoring request for looped MFC entry (S,G)=%pSG: oif=%s vif_index=%d",
				__func__, &sg, oif->name,
				input_iface_vif_index);

		return NULL;
	}

	return pim_channel_oil_add(pim, &sg, __func__);
}

/*
 * True when some interface other than leave_oif still has downstream interest
 * in sg that would be accepted by proxy_ifp's proxy route-map.  Used so a leave
 * on one downstream interface does not proxy-prune upstream while other
 * unfiltered downstream interfaces still have receivers for the same group.
 *
 * Remaining (*,G) interest covers a specific (S,G) leave: IGMPv2 / EXCLUDE
 * and group-only static/manual joins keep upstream flow for every source in G.
 *
 * Downstream interest that fails the proxy route-map (e.g. match
 * multicast-source-interface) must not keep the upstream proxy join: that
 * interface could not have created the join and must not block its prune.
 */
static bool tib_sg_interest_covers(pim_addr interest_src, pim_addr leave_src)
{
	if (!pim_addr_cmp(interest_src, leave_src))
		return true;

	/* Wildcard (*,G) covers any specific source leave. */
	return pim_addr_is_any(interest_src);
}

static bool tib_sg_ifp_has_downstream_interest(struct interface *ifp, pim_sgaddr sg)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct listnode *node;

	if (!pim_ifp)
		return false;

	/* Proxy interfaces are upstream outputs, not downstream sources. */
	if (pim_ifp->gm_proxy)
		return false;

#if PIM_IPV == 4
	if (pim_ifp->gm_group_list) {
		struct gm_group *group;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, node, group)) {
			struct listnode *srcnode;
			struct gm_source *src;

			if (pim_addr_cmp(group->group_addr, sg.grp))
				continue;

			/*
			 * IGMPv2 / IGMPv3 EXCLUDE {empty} is (*,G) interest.
			 * Steady-state usually has a forwarding * source from
			 * igmp_anysource_forward_start(), but that can fail or
			 * briefly be absent — still treat the group as joined.
			 */
			if (group->group_filtermode_isexcl &&
			    listcount(group->group_source_list) < 1)
				return true;

			for (ALL_LIST_ELEMENTS_RO(group->group_source_list, srcnode, src)) {
				if (!tib_sg_interest_covers(src->source_addr, sg.src))
					continue;
				if (IGMP_SOURCE_TEST_FORWARDING(src->source_flags))
					return true;
			}
		}
	}
#else
	if (pim_ifp->mld) {
		struct gm_sg *mlsg, ref = {};

		ref.sgaddr = sg;
		mlsg = gm_sgs_find(pim_ifp->mld->sgs, &ref);
		if (mlsg && mlsg->tib_joined)
			return true;

		/* (*,G) covers a specific (S,G) leave. */
		if (!pim_addr_is_any(sg.src)) {
			ref.sgaddr.src = PIMADDR_ANY;
			mlsg = gm_sgs_find(pim_ifp->mld->sgs, &ref);
			if (mlsg && mlsg->tib_joined)
				return true;
		}
	}
#endif

	if (pim_ifp->static_group_list) {
		struct static_group *stgrp;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->static_group_list, node, stgrp)) {
			if (!pim_addr_cmp(stgrp->group_addr, sg.grp) &&
			    tib_sg_interest_covers(stgrp->source_addr, sg.src))
				return true;
		}
	}

	if (pim_ifp->gm_join_list) {
		struct gm_join *ij;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_join_list, node, ij)) {
			if (ij->join_type == GM_JOIN_PROXY)
				continue;
			if (!pim_addr_cmp(ij->group_addr, sg.grp) &&
			    tib_sg_interest_covers(ij->source_addr, sg.src))
				return true;
		}
	}

	return false;
}

static bool tib_sg_downstream_receivers_remain(struct pim_instance *pim, pim_sgaddr sg,
					       struct interface *leave_oif,
					       struct interface *proxy_ifp)
{
	struct pim_interface *pim_proxy = proxy_ifp->info;
	struct prefix_sg pfx;
	struct interface *ifp;

	if (!pim_proxy)
		return false;

	pim_sg_to_prefix(&sg, &pfx);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (ifp == leave_oif || ifp == proxy_ifp)
			continue;
		if (!tib_sg_ifp_has_downstream_interest(ifp, sg))
			continue;
		/* Same filter path used when creating the proxy join. */
		if (!pim_filter_match(&pim_proxy->gm_proxy_filter, &pfx, proxy_ifp, ifp))
			continue;
		return true;
	}

	return false;
}

/*
 * After the last (*,G) proxy interest is pruned, drop any specific (S,G)
 * proxy joins for the same group that were only kept alive earlier because
 * tib_sg_interest_covers() treated remaining (*,G) as covering that (S,G).
 *
 * That mix is an ASM static-group edge case: join-group will not install
 * proxied (S,G) in ASM, but static-group can, alongside (*,G) interest.
 * Without this cleanup those (S,G) entries stay in gm_join_list until the
 * proxy interface is cycled.
 */
static void tib_sg_proxy_prune_uncovered_sources(struct pim_instance *pim, pim_addr group,
						 struct interface *leave_oif,
						 struct interface *proxy_ifp)
{
	struct pim_interface *pim_ifp = proxy_ifp->info;
	struct listnode *node, *nextnode;
	struct gm_join *ij;

	if (!pim_ifp || !pim_ifp->gm_join_list)
		return;

	for (ALL_LIST_ELEMENTS(pim_ifp->gm_join_list, node, nextnode, ij)) {
		pim_sgaddr check;

		if (ij->join_type != GM_JOIN_PROXY && ij->join_type != GM_JOIN_BOTH)
			continue;
		if (pim_addr_cmp(ij->group_addr, group))
			continue;
		/* Exact (*,G) was already handled by the caller. */
		if (pim_addr_is_any(ij->source_addr))
			continue;

		memset(&check, 0, sizeof(check));
		check.src = ij->source_addr;
		check.grp = group;

		if (tib_sg_downstream_receivers_remain(pim, check, leave_oif, proxy_ifp))
			continue;

		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: prune uncovered proxy %pSG on %s after (*,G) leave on %s",
				   __func__, &check, proxy_ifp->name, leave_oif->name);

		pim_if_gm_join_del(proxy_ifp, group, ij->source_addr, GM_JOIN_PROXY);
	}
}

void tib_sg_proxy_join_prune_check(struct pim_instance *pim, pim_sgaddr sg,
				   struct interface *oif, bool join)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (ifp == oif) /* skip the source interface */
			continue;

		if (pim_ifp->gm_enable && pim_ifp->gm_proxy) {
			struct prefix_sg pfx;

			pim_sg_to_prefix(&sg, &pfx);
			/*
			 * Apply the proxy route-map only to joins.  Prunes must
			 * always run so tightening the filter without cycling
			 * the proxy cannot strand proxy (*,G)/(S,G) state after
			 * the last host leaves.
			 *
			 * On leave, only skip the prune when another downstream
			 * interface still has interest that this proxy iface's
			 * route-map would accept.
			 */
			if (join) {
				if (!pim_filter_match(&pim_ifp->gm_proxy_filter, &pfx, ifp, oif)) {
					if (PIM_DEBUG_GM_TRACE)
						zlog_debug("%s: proxy join for SG%pPSG from %s to %s filtered due to route-map",
							   __func__, &pfx, oif->name, ifp->name);
					continue;
				}
				pim_if_gm_join_add(ifp, sg.grp, sg.src, GM_JOIN_PROXY);
			} else if (tib_sg_downstream_receivers_remain(pim, sg, oif, ifp)) {
				if (PIM_DEBUG_GM_TRACE)
					zlog_debug("%s: skip proxy prune for %pSG after leave on %s; other unfiltered receivers remain for %s",
						   __func__, &sg, oif->name, ifp->name);
			} else {
				pim_if_gm_join_del(ifp, sg.grp, sg.src, GM_JOIN_PROXY);
				/*
				 * (*,G) coverage can have deferred (S,G) proxy
				 * prunes; re-evaluate those when (*,G) itself
				 * finally leaves.
				 */
				if (pim_addr_is_any(sg.src))
					tib_sg_proxy_prune_uncovered_sources(pim, sg.grp, oif, ifp);
			}
		}
	} /* scan interfaces */
}

bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg,
		    struct interface *oif, struct channel_oil **oilp)
{
	struct pim_interface *pim_oif = oif->info;
	struct channel_oil *c_oil;

	if (!pim_oif) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: multicast not enabled on oif=%s?",
				   __func__, oif->name);
		return false;
	}

	if (!*oilp)
		*oilp = tib_sg_oil_setup(pim, sg, oif);
	if (!*oilp)
		return false;

	tib_sg_proxy_join_prune_check(pim, sg, oif, true);

	/* For dense mode, we know we have a new IGMP that we may need to forward
	 * We need to look for any existing pruned coil for this group and graft as needed
	 * Go over every interface, look for a pruned coil, and graft if found
	 */
	/* Only do dense on dense interfaces (and/or groups if SM-DM or have a prefix list)*/
	if (pim_iface_grp_dm(pim_oif, sg.grp)) {
		frr_each (rb_pim_oil, &(pim->channel_oil_head), c_oil) {
			/* TODO debug log of oil */
			if (PIM_DEBUG_GRAFT)
				zlog_debug("%s: Evaluating c_oil for DM graft", __func__);

			if (!pim_addr_cmp(sg.grp, *oil_mcastgrp(c_oil))) {
				if (c_oil->up && PIM_UPSTREAM_DM_TEST_PRUNE(c_oil->up->flags)) {
					struct interface *ifp =
						c_oil->up->rpf.source_nexthop.interface;
					if (ifp && ifp->info) {
						struct pim_interface *pim_ifp = ifp->info;
						if (HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
							PIM_UPSTREAM_DM_UNSET_PRUNE(
								c_oil->up->flags);
							event_cancel(&c_oil->up->t_prune_timer);
							pim_dm_graft_send(c_oil->up->rpf, c_oil->up);
							graft_timer_start(c_oil->up);
						}
					}
				}
			}
		}
	}

	if (PIM_I_am_DR(pim_oif) || PIM_I_am_DualActive(pim_oif)) {
		int result;

		result = pim_channel_add_oif(*oilp, oif, PIM_OIF_FLAG_PROTO_GM,
					     __func__);
		if (result) {
			if (PIM_DEBUG_MROUTE)
				zlog_warn("%s: add_oif() failed with return=%d",
					  __func__, result);
			return false;
		}
	} else {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				"%s: %pSG was received on %s interface but we are not DR for that interface",
				__func__, &sg, oif->name);

		return false;
	}
	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	if (!pim_ifchannel_local_membership_add(oif, &sg, false /*is_vxlan*/)) {
		if (PIM_DEBUG_MROUTE)
			zlog_warn(
				"%s: Failure to add local membership for %pSG",
				__func__, &sg);

		pim_channel_del_oif(*oilp, oif, PIM_OIF_FLAG_PROTO_GM,
				    __func__);
		return false;
	}

	return true;
}

void tib_sg_gm_prune(struct pim_instance *pim, pim_sgaddr sg,
		     struct interface *oif, struct channel_oil **oilp)
{
	int result;
	struct pim_interface *pim_oif = oif->info;
	struct channel_oil *live;

	tib_sg_proxy_join_prune_check(pim, sg, oif, false);

	/*
	 It appears that in certain circumstances that
	 igmp_source_forward_stop is called when IGMP forwarding
	 was not enabled in oif_flags for this outgoing interface.
	 Possibly because of multiple calls. When that happens, we
	 enter the below if statement and this function returns early
	 which in turn triggers the calling function to assert.
	 Making the call to pim_channel_del_oif and ignoring the return code
	 fixes the issue without ill effect, similar to
	 pim_forward_stop below.

	 Also on shutdown when the PIM upstream is removed the channel removal
	 may have already happened, so just return here instead of trying to
	 access an invalid pointer.
	*/
	if (pim->stopping)
		return;

	if (!*oilp)
		return;

	result = pim_channel_del_oif(*oilp, oif, PIM_OIF_FLAG_PROTO_GM,
				     __func__);
	if (result) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				"%s: pim_channel_del_oif() failed with return=%d",
				__func__, result);
		return;
	}

	/* dm: check if we need to send a prune message */
	if ((*oilp)->oil_size == 0) {
		/* Not forwarding to any other interfaces, prune it */
		/* Only if the upstream is dense and group is dense */
		if (pim_iface_grp_dm(pim_oif, sg.grp) && HAVE_DENSE_MODE(pim_oif->pim_mode)) {
			if ((*oilp)->up) {
				struct interface *ifp = (*oilp)->up->rpf.source_nexthop.interface;
				if (ifp && ifp->info) {
					struct pim_interface *pim_ifp = ifp->info;
					if (HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
						event_cancel(&(*oilp)->up->t_graft_timer);
						PIM_UPSTREAM_DM_SET_PRUNE((*oilp)->up->flags);
						pim_dm_prune_send((*oilp)->up->rpf, (*oilp)->up, 0);
						prune_timer_start((*oilp)->up);
					}
				}
			}
		}
	}

	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	pim_ifchannel_local_membership_del(oif, &sg);

	/*
	 * local_membership_del may delete the ifchannel and last upstream,
	 * which runs pim_channel_oil_upstream_deref() and frees the channel_oil.
	 * IGMP still holds *oilp in that case; a second pim_channel_oil_del()
	 * corrupts the RB tree (typed_rb_remove on freed / zeroed links).
	 */

	live = pim_find_channel_oil(pim, &sg);

	if (live == *oilp)
		*oilp = pim_channel_oil_del(live, __func__);
	else
		*oilp = NULL;
}
