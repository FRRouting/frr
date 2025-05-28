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
		if (!pim_nht_lookup_ecmp(pim, &nexthop, vif_source, &grp, false))
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
			zlog_debug(
				"%s %s: could not find input interface for %pSG",
				__FILE__, __func__, &sg);

		return pim_channel_oil_add(pim, &sg, __func__);
	}

	/*
	 * Protect IGMP against adding looped MFC entries created by both
	 * source and receiver attached to the same interface. See TODO T22.
	 * Block only when the intf is non DR DR must create upstream.
	 */
	if ((input_iface_vif_index == pim_oif->mroute_vif_index) &&
	    !(PIM_I_am_DR(pim_oif))) {
		/* ignore request for looped MFC entry */
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				"%s: ignoring request for looped MFC entry (S,G)=%pSG: oif=%s vif_index=%d",
				__func__, &sg, oif->name,
				input_iface_vif_index);

		return NULL;
	}

	return pim_channel_oil_add(pim, &sg, __func__);
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
			if (join)
				pim_if_gm_join_add(ifp, sg.grp, sg.src,
						   GM_JOIN_PROXY);
			else
				pim_if_gm_join_del(ifp, sg.grp, sg.src,
						   GM_JOIN_PROXY);
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

	*oilp = pim_channel_oil_del(*oilp, __func__);
}
