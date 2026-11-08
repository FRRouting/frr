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
#include "pim_ssm.h"
#include "vrf.h"
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
		zlog_debug("%s: NHT (%s:%u:%u)%pSG vif_source %pPAs vif_index:%d", __func__,
			   PIM_DEBUG_VRF(pim->vrf), &sg, &vif_source, input_iface_vif_index);

	if (input_iface_vif_index < 1) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s %s: could not find vif index of interface with NH to RP for (%s:%u:%u)%pSG",
				   __FILE__, __func__, PIM_DEBUG_VRF(pim->vrf), &sg);

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
			zlog_debug("%s: ignoring request for looped MFC entry (S,G)=(%s:%u:%u)%pSG: oif=%s vif_index=%d",
				   __func__, PIM_DEBUG_VRF(pim->vrf), &sg, oif->name,
				   input_iface_vif_index);

		return NULL;
	}

	return pim_channel_oil_add(pim, &sg, __func__);
}

/*
 * True when some interface still has downstream interest in sg that would be
 * accepted by proxy_ifp's proxy route-map.  Used so a leave does not
 * proxy-prune upstream while other receivers for the same group remain,
 * on other interfaces or on the leaving one.
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

#if PIM_IPV == 4
/*
 * Is this IGMP source record a membership we would forward for?  Mirrors
 * igmp_source_forward_start() without depending on the FORWARDING flag,
 * which is only set once the oif was added, i.e. never on a non-DR.
 *
 * RFC 3376 6.3: forward while the source timer runs.  In EXCLUDE mode a
 * source with an expired timer is blocked.  The '*' source only exists for
 * EXCLUDE {empty}.  PIM state is (*,G) only in the ASM range and (S,G) only
 * in the SSM range.
 *
 * A membership that is going away already fails this test when its prune
 * runs (source unlinked, timer stopped, or group back to INCLUDE), so a
 * leave can count the rest of its own interface's interest.
 */
static bool tib_igmp_source_wanted(struct pim_interface *pim_ifp, struct gm_group *group,
				   struct gm_source *src)
{
	bool ssm = pim_is_grp_ssm(pim_ifp->pim, group->group_addr);

	if (pim_addr_is_any(src->source_addr))
		return group->group_filtermode_isexcl && !ssm;

	if (!ssm)
		return false;

	return event_is_scheduled(src->t_source_timer);
}
#endif

/*
 * Report every (S,G) this interface holds as real downstream interest:
 * IGMP/MLD membership, static groups and local joins.  This is the one
 * definition of downstream interest used both to add or keep proxy joins
 * and to decide whether a leave may prune them.
 *
 * Proxy interfaces are included: a membership learned on a proxy interface
 * is relayed out the other proxy interfaces.  GM_JOIN_PROXY entries are
 * skipped; those are joins we sent, not receivers.
 */
static void tib_ifp_interest_foreach(struct interface *ifp,
				     void (*cb)(struct interface *ifp, pim_sgaddr sg, void *arg),
				     void *arg)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct listnode *node;

	if (!pim_ifp || !cb)
		return;

#if PIM_IPV == 4
	if (pim_ifp->gm_group_list) {
		struct gm_group *group;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, node, group)) {
			struct listnode *srcnode;
			struct gm_source *src;
			pim_sgaddr sg = {};

			/*
			 * IGMPv2 / IGMPv3 EXCLUDE {empty} is (*,G) interest
			 * even when the '*' source has not been created yet.
			 */
			if (group->group_filtermode_isexcl &&
			    listcount(group->group_source_list) < 1 &&
			    !pim_is_grp_ssm(pim_ifp->pim, group->group_addr)) {
				sg.grp = group->group_addr;
				cb(ifp, sg, arg);
			}

			for (ALL_LIST_ELEMENTS_RO(group->group_source_list, srcnode, src)) {
				if (!tib_igmp_source_wanted(pim_ifp, group, src))
					continue;
				memset(&sg, 0, sizeof(sg));
				sg.src = src->source_addr;
				sg.grp = group->group_addr;
				cb(ifp, sg, arg);
			}
		}
	}
#else
	if (pim_ifp->mld) {
		struct gm_sg *mlsg;

		frr_each (gm_sgs, pim_ifp->mld->sgs, mlsg) {
			if (gm_sg_has_interest(mlsg))
				cb(ifp, mlsg->sgaddr, arg);
		}
	}
#endif

	if (pim_ifp->static_group_list) {
		struct static_group *stgrp;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->static_group_list, node, stgrp)) {
			pim_sgaddr sg = {};

			sg.src = stgrp->source_addr;
			sg.grp = stgrp->group_addr;
			cb(ifp, sg, arg);
		}
	}

	if (pim_ifp->gm_join_list) {
		struct gm_join *ij;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_join_list, node, ij)) {
			pim_sgaddr sg = {};

			if (ij->join_type == GM_JOIN_PROXY)
				continue;
			sg.src = ij->source_addr;
			sg.grp = ij->group_addr;
			cb(ifp, sg, arg);
		}
	}
}

struct interest_covers_arg {
	pim_sgaddr sg;
	bool found;
};

static void tib_sg_interest_covers_cb(struct interface *ifp, pim_sgaddr interest, void *arg)
{
	struct interest_covers_arg *ca = arg;

	if (!pim_addr_cmp(interest.grp, ca->sg.grp) &&
	    tib_sg_interest_covers(interest.src, ca->sg.src))
		ca->found = true;
}

static bool tib_sg_ifp_has_downstream_interest(struct interface *ifp, pim_sgaddr sg)
{
	struct interest_covers_arg ca = { .sg = sg };

	tib_ifp_interest_foreach(ifp, tib_sg_interest_covers_cb, &ca);
	return ca.found;
}

static bool tib_sg_downstream_receivers_remain(struct pim_instance *pim, pim_sgaddr sg,
					       struct interface *proxy_ifp)
{
	struct pim_interface *pim_proxy = proxy_ifp->info;
	struct prefix_sg pfx;
	struct interface *ifp;

	if (!pim_proxy)
		return false;

	pim_sg_to_prefix(&sg, &pfx);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		/*
		 * The leaving interface counts too: a static group or local
		 * join there may still need the join.  The membership that is
		 * leaving no longer counts by the time we get here.
		 */
		if (ifp == proxy_ifp)
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

		if (tib_sg_downstream_receivers_remain(pim, check, proxy_ifp))
			continue;

		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: prune uncovered proxy (%s:%u:%u)%pSG on %s after (*,G) leave on %s",
				   __func__, PIM_DEBUG_VRF(pim->vrf), &check, proxy_ifp->name,
				   leave_oif->name);

		pim_if_gm_join_del(proxy_ifp, group, ij->source_addr, GM_JOIN_PROXY);
	}
}

void tib_sg_downstream_ifaces_foreach(struct pim_instance *pim, pim_sgaddr sg,
				      struct interface *proxy_ifp, struct interface *skip_ifp,
				      void (*cb)(struct interface *ifp, void *arg), void *arg)
{
	struct pim_interface *pim_proxy;
	struct prefix_sg pfx;
	struct interface *ifp;

	if (!proxy_ifp || !proxy_ifp->info)
		return;

	pim_proxy = proxy_ifp->info;
	pim_sg_to_prefix(&sg, &pfx);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (ifp == skip_ifp || ifp == proxy_ifp)
			continue;
		if (!tib_sg_ifp_has_downstream_interest(ifp, sg))
			continue;
		if (!pim_filter_match(&pim_proxy->gm_proxy_filter, &pfx, proxy_ifp, ifp))
			continue;
		cb(ifp, arg);
	}
}

struct proxy_reeval_arg {
	struct interface *proxy_ifp;
};

struct proxy_keep_arg {
	struct interface *proxy_ifp;
	pim_sgaddr sg;
	bool keep;
};

/* True when this downstream interest is a reason to hold the proxy join for ka->sg. */
static void tib_sg_proxy_reeval_keep(struct interface *ds_ifp, pim_sgaddr interest, void *arg)
{
	struct proxy_keep_arg *ka = arg;
	struct pim_interface *pim_proxy;
	struct prefix_sg pfx;

	if (ka->keep || ds_ifp == ka->proxy_ifp)
		return;
	if (pim_addr_cmp(interest.grp, ka->sg.grp))
		return;
	if (!tib_sg_interest_covers(interest.src, ka->sg.src))
		return;

	pim_proxy = ka->proxy_ifp->info;
	pim_sg_to_prefix(&ka->sg, &pfx);
	if (!pim_filter_match(&pim_proxy->gm_proxy_filter, &pfx, ka->proxy_ifp, ds_ifp))
		return;

	ka->keep = true;
}

static void tib_sg_proxy_reeval_add(struct interface *ds_ifp, pim_sgaddr sg, void *arg)
{
	struct proxy_reeval_arg *ra = arg;
	struct pim_interface *pim_proxy = ra->proxy_ifp->info;
	struct prefix_sg pfx;

	/* Do not proxy a membership back out the interface it arrived on. */
	if (ds_ifp == ra->proxy_ifp)
		return;

	pim_sg_to_prefix(&sg, &pfx);
	if (!pim_filter_match(&pim_proxy->gm_proxy_filter, &pfx, ra->proxy_ifp, ds_ifp))
		return;

	pim_if_gm_join_add(ra->proxy_ifp, sg.grp, sg.src, GM_JOIN_PROXY);
}

void tib_sg_proxy_filter_reeval(struct pim_instance *pim, struct interface *proxy_ifp)
{
	struct pim_interface *pim_proxy;
	struct listnode *node, *nextnode;
	struct gm_join *ij;
	struct interface *ifp;
	struct proxy_reeval_arg arg;

	if (!pim || !proxy_ifp)
		return;

	pim_proxy = proxy_ifp->info;
	if (!pim_proxy || !pim_proxy->gm_enable || !pim_proxy->gm_proxy)
		return;

	if (pim_proxy->gm_join_list) {
		for (ALL_LIST_ELEMENTS(pim_proxy->gm_join_list, node, nextnode, ij)) {
			struct proxy_keep_arg keep = { .proxy_ifp = proxy_ifp };

			if (ij->join_type != GM_JOIN_PROXY && ij->join_type != GM_JOIN_BOTH)
				continue;

			keep.sg.src = ij->source_addr;
			keep.sg.grp = ij->group_addr;
			FOR_ALL_INTERFACES (pim->vrf, ifp) {
				if (ifp == proxy_ifp || keep.keep)
					continue;
				tib_ifp_interest_foreach(ifp, tib_sg_proxy_reeval_keep, &keep);
			}
			if (keep.keep)
				continue;

			pim_if_gm_join_del(proxy_ifp, keep.sg.grp, keep.sg.src, GM_JOIN_PROXY);
		}
	}

	arg.proxy_ifp = proxy_ifp;
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (ifp == proxy_ifp)
			continue;
		tib_ifp_interest_foreach(ifp, tib_sg_proxy_reeval_add, &arg);
	}
}

static struct event *gm_proxy_filter_event;

static void pim_gm_proxy_filter_update_all(struct event *event)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct pim_instance *pim = vrf->info;
		struct interface *ifp;

		if (!pim)
			continue;

		FOR_ALL_INTERFACES (vrf, ifp) {
			struct pim_interface *pim_ifp = ifp->info;

			if (!pim_ifp || !pim_ifp->gm_proxy || !pim_ifp->gm_proxy_filter.rmapname)
				continue;

			tib_sg_proxy_filter_reeval(pim, ifp);
		}
	}
}

/*
 * Route-map hooks run in the middle of an edit: the hook for a removed
 * 'match' or 'call' runs before the rule is gone, and a prefix-list entry
 * update unlinks the entry, notifies, then adds it back.  Evaluating right
 * away would apply the old route-map or flap the joins.  Re-evaluate once
 * the edits settle, coalescing a burst of changes into one pass.  All
 * filtered proxy interfaces are re-evaluated, since a change to one
 * route-map can affect any route-map that calls it.
 */
#define PIM_GM_PROXY_FILTER_DELAY_MSEC 200

void pim_gm_proxy_filter_update(const char *rmap_name)
{
	if (!rmap_name)
		return;

	/*
	 * pim6_terminate() frees the router before prefix_list_reset()
	 * notifies route-map dependencies. The PIM state is already gone
	 * and there is no event loop to run a deferred recompute.
	 */
	if (!router || !router->master) {
		event_cancel(&gm_proxy_filter_event);
		return;
	}

	event_cancel(&gm_proxy_filter_event);
	event_add_timer_msec(router->master, pim_gm_proxy_filter_update_all, NULL,
			     PIM_GM_PROXY_FILTER_DELAY_MSEC, &gm_proxy_filter_event);
}

void pim_gm_proxy_filter_terminate(void)
{
	event_cancel(&gm_proxy_filter_event);
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
			} else if (tib_sg_downstream_receivers_remain(pim, sg, ifp)) {
				if (PIM_DEBUG_GM_TRACE)
					zlog_debug("%s: skip proxy prune for (%s:%u:%u)%pSG after leave on %s; other unfiltered receivers remain for %s",
						   __func__, PIM_DEBUG_VRF(pim->vrf), &sg,
						   oif->name, ifp->name);
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

			if (!pim_addr_cmp(sg.grp, c_oil->group)) {
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
			zlog_debug("%s: (%s:%u:%u)%pSG was received on %s interface but we are not DR for that interface",
				   __func__, PIM_DEBUG_VRF(pim->vrf), &sg, oif->name);

		return false;
	}
	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	if (!pim_ifchannel_local_membership_add(oif, &sg, false /*is_vxlan*/)) {
		if (PIM_DEBUG_MROUTE)
			zlog_warn("%s: Failure to add local membership for (%s:%u:%u)%pSG",
				  __func__, PIM_DEBUG_VRF(pim->vrf), &sg);

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
	if (channel_oif_list_count(&(*oilp)->oif_list) == 0) {
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
