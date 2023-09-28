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
		memcpy(&nexthop, &up->rpf.source_nexthop,
		       sizeof(struct pim_nexthop));
		(void)pim_ecmp_nexthop_lookup(pim, &nexthop, vif_source, &grp,
					      0);
		if (nexthop.interface)
			input_iface_vif_index = pim_if_find_vifindex_by_ifindex(
				pim, nexthop.interface->ifindex);
	} else
		input_iface_vif_index =
			pim_ecmp_fib_lookup_if_vif_index(pim, vif_source, &grp);

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

bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg,
		    struct interface *oif, struct channel_oil **oilp)
{
	struct pim_interface *pim_oif = oif->info;

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
	*/
	result = pim_channel_del_oif(*oilp, oif, PIM_OIF_FLAG_PROTO_GM,
				     __func__);
	if (result) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug(
				"%s: pim_channel_del_oif() failed with return=%d",
				__func__, result);
		return;
	}

	/*
	  Feed IGMPv3-gathered local membership information into PIM
	  per-interface (S,G) state.
	 */
	pim_ifchannel_local_membership_del(oif, &sg);

	pim_channel_oil_del(*oilp, __func__);
}
