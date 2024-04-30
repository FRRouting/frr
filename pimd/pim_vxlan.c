// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include <hash.h>
#include <jhash.h>
#include <log.h>
#include <prefix.h>
#include <vrf.h>

#include "pimd.h"
#include "pim_iface.h"
#include "pim_memory.h"
#include "pim_oil.h"
#include "pim_register.h"
#include "pim_str.h"
#include "pim_upstream.h"
#include "pim_ifchannel.h"
#include "pim_nht.h"
#include "pim_zebra.h"
#include "pim_vxlan.h"
#include "pim_mlag.h"

/* pim-vxlan global info */
struct pim_vxlan vxlan_info, *pim_vxlan_p = &vxlan_info;

static void pim_vxlan_work_timer_setup(bool start);
static void pim_vxlan_set_peerlink_rif(struct pim_instance *pim,
			struct interface *ifp);

#define PIM_VXLAN_STARTUP_NULL_REGISTERS 10

static void pim_vxlan_rp_send_null_register_startup(struct event *e)
{
	struct pim_vxlan_sg *vxlan_sg = EVENT_ARG(e);

	vxlan_sg->null_register_sent++;

	if (vxlan_sg->null_register_sent > PIM_VXLAN_STARTUP_NULL_REGISTERS) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("Null registering stopping for %s",
				   vxlan_sg->sg_str);
		return;
	}

	pim_null_register_send(vxlan_sg->up);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("Sent null register for %s", vxlan_sg->sg_str);

	event_add_timer(router->master, pim_vxlan_rp_send_null_register_startup,
			vxlan_sg, PIM_VXLAN_WORK_TIME, &vxlan_sg->null_register);
}

/*
 * The rp info has gone from no path to having a
 * path.  Let's immediately send out the null pim register
 * as that else we will be sitting for up to 60 seconds waiting
 * for it too pop.  Which is not cool.
 */
void pim_vxlan_rp_info_is_alive(struct pim_instance *pim,
				struct pim_rpf *rpg_changed)
{
	struct listnode *listnode;
	struct pim_vxlan_sg *vxlan_sg;
	struct pim_rpf *rpg;

	/*
	 * No vxlan here, move along, nothing to see
	 */
	if (!vxlan_info.work_list)
		return;

	for (listnode = vxlan_info.work_list->head; listnode;
	     listnode = listnode->next) {
		vxlan_sg = listgetdata(listnode);

		rpg = RP(pim, vxlan_sg->up->sg.grp);

		/*
		 * If the rp is the same we should send
		 */
		if (rpg == rpg_changed) {
			if (PIM_DEBUG_VXLAN)
				zlog_debug("VXLAN RP info for %s alive sending",
					   vxlan_sg->sg_str);
			vxlan_sg->null_register_sent = 0;
			event_add_event(router->master,
					pim_vxlan_rp_send_null_register_startup,
					vxlan_sg, 0, &vxlan_sg->null_register);
		}
	}
}

/*************************** vxlan work list **********************************
 * A work list is maintained for staggered generation of pim null register
 * messages for vxlan SG entries that are in a reg_join state.
 *
 * A max of 500 NULL registers are generated at one shot. If paused reg
 * generation continues on the next second and so on till all register
 * messages have been sent out. And the process is restarted every 60s.
 *
 * purpose of this null register generation is to setup the SPT and maintain
 * independent of the presence of overlay BUM traffic.
 ****************************************************************************/
static void pim_vxlan_do_reg_work(void)
{
	struct listnode *listnode;
	int work_cnt = 0;
	struct pim_vxlan_sg *vxlan_sg;
	static int sec_count;

	++sec_count;

	if (sec_count > PIM_VXLAN_NULL_REG_INTERVAL) {
		sec_count = 0;
		listnode = vxlan_info.next_work ?
					vxlan_info.next_work :
					vxlan_info.work_list->head;
		if (PIM_DEBUG_VXLAN && listnode)
			zlog_debug("vxlan SG work %s",
				vxlan_info.next_work ? "continues" : "starts");
	} else {
		listnode = vxlan_info.next_work;
	}

	for (; listnode; listnode = listnode->next) {
		vxlan_sg = (struct pim_vxlan_sg *)listnode->data;

		if (vxlan_sg->up && (vxlan_sg->up->reg_state == PIM_REG_JOIN)) {
			if (PIM_DEBUG_VXLAN)
				zlog_debug("vxlan SG %s periodic NULL register",
						vxlan_sg->sg_str);

			/*
			 * If we are on the work queue *and* the rpf
			 * has been lost on the vxlan_sg->up let's
			 * make sure that we don't send it.
			 */
			if (vxlan_sg->up->rpf.source_nexthop.interface) {
				pim_null_register_send(vxlan_sg->up);
				++work_cnt;
			}
		}

		if (work_cnt > vxlan_info.max_work_cnt) {
			vxlan_info.next_work = listnode->next;
			if (PIM_DEBUG_VXLAN)
				zlog_debug("vxlan SG %d work items proc and pause",
					work_cnt);
			return;
		}
	}

	if (work_cnt) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("vxlan SG %d work items proc", work_cnt);
	}
	vxlan_info.next_work = NULL;
}

/* Staggered work related info is initialized when the first work comes
 * along
 */
static void pim_vxlan_init_work(void)
{
	if (vxlan_info.flags & PIM_VXLANF_WORK_INITED)
		return;

	vxlan_info.max_work_cnt = PIM_VXLAN_WORK_MAX;
	vxlan_info.flags |= PIM_VXLANF_WORK_INITED;
	vxlan_info.work_list = list_new();
	pim_vxlan_work_timer_setup(true/* start */);
}

static void pim_vxlan_add_work(struct pim_vxlan_sg *vxlan_sg)
{
	if (vxlan_sg->flags & PIM_VXLAN_SGF_DEL_IN_PROG) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("vxlan SG %s skip work list; del-in-prog",
					vxlan_sg->sg_str);
		return;
	}

	pim_vxlan_init_work();

	/* already a part of the work list */
	if (vxlan_sg->work_node)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s work list add",
				vxlan_sg->sg_str);
	vxlan_sg->work_node = listnode_add(vxlan_info.work_list, vxlan_sg);
	/* XXX: adjust max_work_cnt if needed */
}

static void pim_vxlan_del_work(struct pim_vxlan_sg *vxlan_sg)
{
	if (!vxlan_sg->work_node)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s work list del",
				vxlan_sg->sg_str);

	if (vxlan_sg->work_node == vxlan_info.next_work)
		vxlan_info.next_work = vxlan_sg->work_node->next;

	list_delete_node(vxlan_info.work_list, vxlan_sg->work_node);
	vxlan_sg->work_node = NULL;
}

void pim_vxlan_update_sg_reg_state(struct pim_instance *pim,
		struct pim_upstream *up, bool reg_join)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, &up->sg);
	if (!vxlan_sg)
		return;

	/* add the vxlan sg entry to a work list for periodic reg joins.
	 * the entry will stay in the list as long as the register state is
	 * PIM_REG_JOIN
	 */
	if (reg_join)
		pim_vxlan_add_work(vxlan_sg);
	else {
		/*
		 * Stop the event that is sending NULL Registers on startup
		 * there is no need to keep spamming it
		 */
		if (PIM_DEBUG_VXLAN)
			zlog_debug("Received Register stop for %s",
				   vxlan_sg->sg_str);

		EVENT_OFF(vxlan_sg->null_register);
		pim_vxlan_del_work(vxlan_sg);
	}
}

static void pim_vxlan_work_timer_cb(struct event *t)
{
	pim_vxlan_do_reg_work();
	pim_vxlan_work_timer_setup(true /* start */);
}

/* global 1second timer used for periodic processing */
static void pim_vxlan_work_timer_setup(bool start)
{
	EVENT_OFF(vxlan_info.work_timer);
	if (start)
		event_add_timer(router->master, pim_vxlan_work_timer_cb, NULL,
				PIM_VXLAN_WORK_TIME, &vxlan_info.work_timer);
}

/**************************** vxlan origination mroutes ***********************
 * For every (local-vtep-ip, bum-mcast-grp) registered by evpn an origination
 * mroute is setup by pimd. The purpose of this mroute is to forward vxlan
 * encapsulated BUM (broadcast, unknown-unicast and unknown-multicast packets
 * over the underlay.)
 *
 * Sample mroute (single VTEP):
 * (27.0.0.7, 239.1.1.100)     Iif: lo      Oifs: uplink-1
 *
 * Sample mroute (anycast VTEP):
 * (36.0.0.9, 239.1.1.100)          Iif: peerlink-3.4094\
 *                                       Oifs: peerlink-3.4094 uplink-1
 ***************************************************************************/
static void pim_vxlan_orig_mr_up_del(struct pim_vxlan_sg *vxlan_sg)
{
	struct pim_upstream *up = vxlan_sg->up;

	if (!up)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig mroute-up del",
			vxlan_sg->sg_str);

	vxlan_sg->up = NULL;

	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG) {
		/* clear out all the vxlan properties */
		up->flags &= ~(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG |
			PIM_UPSTREAM_FLAG_MASK_STATIC_IIF |
			PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY |
			PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG |
			PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA |
			PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL);

		/* We bring things to a grinding halt by force expirying
		 * the kat. Doing this will also remove the reference we
		 * created as a "vxlan" source and delete the upstream entry
		 * if there are no other references.
		 */
		if (PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags)) {
			EVENT_OFF(up->t_ka_timer);
			up = pim_upstream_keep_alive_timer_proc(up);
		} else {
			/* this is really unexpected as we force vxlan
			 * origination mroutes active sources but just in
			 * case
			 */
			up = pim_upstream_del(vxlan_sg->pim, up, __func__);
		}
		/* if there are other references register the source
		 * for nht
		 */
		if (up) {
			enum pim_rpf_result r;

			r = pim_rpf_update(vxlan_sg->pim, up, NULL, __func__);
			if (r == PIM_RPF_FAILURE) {
				if (PIM_DEBUG_VXLAN)
					zlog_debug(
						"vxlan SG %s rpf_update failure",
						vxlan_sg->sg_str);
			}
		}
	}
}

static void pim_vxlan_orig_mr_up_iif_update(struct pim_vxlan_sg *vxlan_sg)
{
	/* update MFC with the new IIF */
	pim_upstream_fill_static_iif(vxlan_sg->up, vxlan_sg->iif);
	pim_upstream_mroute_iif_update(vxlan_sg->up->channel_oil, __func__);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig mroute-up updated with iif %s",
			vxlan_sg->sg_str,
			vxlan_sg->iif?vxlan_sg->iif->name:"-");

}

/* For every VxLAN BUM multicast group we setup a SG-up that has the following
 * "forced properties" -
 * 1. Directly connected on a DR interface i.e. we must act as an FHR
 * 2. We prime the pump i.e. no multicast data is needed to register this
 *    source with the FHR. To do that we send periodic null registers if
 *    the SG entry is in a register-join state. We also prevent expiry of
 *    KAT.
 * 3. As this SG is setup without data there is no need to register encapsulate
 *    data traffic. This encapsulation is explicitly skipped for the following
 *    reasons -
 *    a) Many levels of encapsulation are needed creating MTU disc challenges.
 *       Overlay BUM is encapsulated in a vxlan/UDP/IP header and then
 *       encapsulated again in a pim-register header.
 *    b) On a vxlan-aa setup both switches rx a copy of each BUM packet. if
 *       they both reg encapsulated traffic the RP will accept the duplicates
 *       as there are no RPF checks for this encapsulated data.
 *    a), b) can be workarounded if needed, but there is really no need because
 *    of (2) i.e. the pump is primed without data.
 */
static void pim_vxlan_orig_mr_up_add(struct pim_vxlan_sg *vxlan_sg)
{
	struct pim_upstream *up;
	struct pim_interface *term_ifp;
	int flags = 0;
	struct pim_instance *pim = vxlan_sg->pim;

	if (vxlan_sg->up) {
		/* nothing to do */
		return;
	}

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig mroute-up add with iif %s",
			vxlan_sg->sg_str,
			vxlan_sg->iif?vxlan_sg->iif->name:"-");

	PIM_UPSTREAM_FLAG_SET_SRC_VXLAN_ORIG(flags);
	/* pin the IIF to lo or peerlink-subinterface and disable NHT */
	PIM_UPSTREAM_FLAG_SET_STATIC_IIF(flags);
	/* Fake traffic by setting SRC_STREAM and starting KAT */
	/* We intentionally skip updating ref count for SRC_STREAM/FHR.
	 * Setting SRC_VXLAN should have already created a reference
	 * preventing the entry from being deleted
	 */
	PIM_UPSTREAM_FLAG_SET_FHR(flags);
	PIM_UPSTREAM_FLAG_SET_SRC_STREAM(flags);
	/* Force pimreg even if non-DR. This is needed on a MLAG setup for
	 * VxLAN AA
	 */
	PIM_UPSTREAM_FLAG_SET_FORCE_PIMREG(flags);
	/* prevent KAT expiry. we want the MDT setup even if there is no BUM
	 * traffic
	 */
	PIM_UPSTREAM_FLAG_SET_DISABLE_KAT_EXPIRY(flags);
	/* SPT for vxlan BUM groups is primed and maintained via NULL
	 * registers so there is no need to reg-encapsulate
	 * vxlan-encapsulated overlay data traffic
	 */
	PIM_UPSTREAM_FLAG_SET_NO_PIMREG_DATA(flags);
	/* On a MLAG setup we force a copy to the MLAG peer while also
	 * accepting traffic from the peer. To do this we set peerlink-rif as
	 * the IIF and also add it to the OIL
	 */
	PIM_UPSTREAM_FLAG_SET_ALLOW_IIF_IN_OIL(flags);

	/* XXX: todo: defer pim_upstream add if pim is not enabled on the iif */
	up = pim_upstream_find(vxlan_sg->pim, &vxlan_sg->sg);
	if (up) {
		/* if the iif is set to something other than the vxlan_sg->iif
		 * we must dereg the old nexthop and force to new "static"
		 * iif
		 */
		if (!PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags)) {
			pim_delete_tracked_nexthop(vxlan_sg->pim,
						   up->upstream_addr, up, NULL);
		}
		/* We are acting FHR; clear out use_rpt setting if any */
		pim_upstream_update_use_rpt(up, false /*update_mroute*/);
		pim_upstream_ref(up, flags, __func__);
		vxlan_sg->up = up;
		term_ifp = pim_vxlan_get_term_ifp(pim);
		/* mute termination device on origination mroutes */
		if (term_ifp)
			pim_channel_update_oif_mute(up->channel_oil,
					term_ifp);
		pim_vxlan_orig_mr_up_iif_update(vxlan_sg);
		/* mute pimreg on origination mroutes */
		if (pim->regiface)
			pim_channel_update_oif_mute(up->channel_oil,
					pim->regiface->info);
	} else {
		up = pim_upstream_add(vxlan_sg->pim, &vxlan_sg->sg,
				      vxlan_sg->iif, flags, __func__, NULL);
		vxlan_sg->up = up;
	}

	if (!up) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("vxlan SG %s orig mroute-up add failed",
					vxlan_sg->sg_str);
		return;
	}

	pim_upstream_keep_alive_timer_start(up, vxlan_sg->pim->keep_alive_time);

	/* register the source with the RP */
	switch (up->reg_state) {

	case PIM_REG_NOINFO:
		pim_register_join(up);
		pim_null_register_send(up);
		break;

	case PIM_REG_JOIN:
		/* if the pim upstream entry is already in reg-join state
		 * send null_register right away and add to the register
		 * worklist
		 */
		pim_null_register_send(up);
		pim_vxlan_update_sg_reg_state(pim, up, true);
		break;

	case PIM_REG_JOIN_PENDING:
	case PIM_REG_PRUNE:
		break;
	}

	/* update the inherited OIL */
	pim_upstream_inherited_olist(vxlan_sg->pim, up);
	if (!up->channel_oil->installed)
		pim_upstream_mroute_add(up->channel_oil, __func__);
}

static void pim_vxlan_orig_mr_oif_add(struct pim_vxlan_sg *vxlan_sg)
{
	if (!vxlan_sg->up || !vxlan_sg->orig_oif)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s oif %s add",
			vxlan_sg->sg_str, vxlan_sg->orig_oif->name);

	vxlan_sg->flags |= PIM_VXLAN_SGF_OIF_INSTALLED;
	pim_channel_add_oif(vxlan_sg->up->channel_oil,
		vxlan_sg->orig_oif, PIM_OIF_FLAG_PROTO_VXLAN,
		__func__);
}

static void pim_vxlan_orig_mr_oif_del(struct pim_vxlan_sg *vxlan_sg)
{
	struct interface *orig_oif;

	orig_oif = vxlan_sg->orig_oif;
	vxlan_sg->orig_oif = NULL;

	if (!(vxlan_sg->flags & PIM_VXLAN_SGF_OIF_INSTALLED))
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s oif %s del",
			vxlan_sg->sg_str, orig_oif->name);

	vxlan_sg->flags &= ~PIM_VXLAN_SGF_OIF_INSTALLED;
	pim_channel_del_oif(vxlan_sg->up->channel_oil,
			orig_oif, PIM_OIF_FLAG_PROTO_VXLAN, __func__);
}

static inline struct interface *pim_vxlan_orig_mr_oif_get(
		struct pim_instance *pim)
{
	return (vxlan_mlag.flags & PIM_VXLAN_MLAGF_ENABLED) ?
		pim->vxlan.peerlink_rif : NULL;
}

/* Single VTEPs: IIF for the vxlan-origination-mroutes is lo or vrf-dev (if
 * the mroute is in a non-default vrf).
 * Anycast VTEPs: IIF is the MLAG ISL/peerlink.
 */
static inline struct interface *pim_vxlan_orig_mr_iif_get(
		struct pim_instance *pim)
{
	return ((vxlan_mlag.flags & PIM_VXLAN_MLAGF_ENABLED) &&
			pim->vxlan.peerlink_rif) ?
		pim->vxlan.peerlink_rif : pim->vxlan.default_iif;
}

static bool pim_vxlan_orig_mr_add_is_ok(struct pim_vxlan_sg *vxlan_sg)
{
	struct pim_interface *pim_ifp;

	vxlan_sg->iif = pim_vxlan_orig_mr_iif_get(vxlan_sg->pim);
	if (!vxlan_sg->iif)
		return false;

	pim_ifp = (struct pim_interface *)vxlan_sg->iif->info;
	if (!pim_ifp || (pim_ifp->mroute_vif_index < 0))
		return false;

	return true;
}

static void pim_vxlan_orig_mr_install(struct pim_vxlan_sg *vxlan_sg)
{
	pim_vxlan_orig_mr_up_add(vxlan_sg);

	vxlan_sg->orig_oif = pim_vxlan_orig_mr_oif_get(vxlan_sg->pim);
	pim_vxlan_orig_mr_oif_add(vxlan_sg);
}

static void pim_vxlan_orig_mr_add(struct pim_vxlan_sg *vxlan_sg)
{
	if (!pim_vxlan_orig_mr_add_is_ok(vxlan_sg))
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig-mr add", vxlan_sg->sg_str);

	pim_vxlan_orig_mr_install(vxlan_sg);
}

static void pim_vxlan_orig_mr_del(struct pim_vxlan_sg *vxlan_sg)
{
	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig-mr del", vxlan_sg->sg_str);

	pim_vxlan_orig_mr_oif_del(vxlan_sg);
	pim_vxlan_orig_mr_up_del(vxlan_sg);
}

static void pim_vxlan_orig_mr_iif_update(struct hash_bucket *bucket, void *arg)
{
	struct interface *ifp;
	struct pim_vxlan_sg *vxlan_sg = (struct pim_vxlan_sg *)bucket->data;
	struct interface *old_iif = vxlan_sg->iif;

	if (!pim_vxlan_is_orig_mroute(vxlan_sg))
		return;

	ifp = pim_vxlan_orig_mr_iif_get(vxlan_sg->pim);
	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s iif changed from %s to %s",
				vxlan_sg->sg_str,
				old_iif ? old_iif->name : "-",
				ifp ? ifp->name : "-");

	if (pim_vxlan_orig_mr_add_is_ok(vxlan_sg)) {
		if (vxlan_sg->up) {
			/* upstream exists but iif changed */
			pim_vxlan_orig_mr_up_iif_update(vxlan_sg);
		} else {
			/* install mroute */
			pim_vxlan_orig_mr_install(vxlan_sg);
		}
	} else {
		pim_vxlan_orig_mr_del(vxlan_sg);
	}
}

/**************************** vxlan termination mroutes ***********************
 * For every bum-mcast-grp registered by evpn a *G termination
 * mroute is setup by pimd. The purpose of this mroute is to pull down vxlan
 * packets with the bum-mcast-grp dip from the underlay and terminate the
 * tunnel. This is done by including the vxlan termination device (ipmr-lo) in
 * its OIL. The vxlan de-capsulated packets are subject to subsequent overlay
 * bridging.
 *
 * Sample mroute:
 * (0.0.0.0, 239.1.1.100)     Iif: uplink-1      Oifs: ipmr-lo, uplink-1
 *****************************************************************************/
struct pim_interface *pim_vxlan_get_term_ifp(struct pim_instance *pim)
{
	return pim->vxlan.term_if ?
		(struct pim_interface *)pim->vxlan.term_if->info : NULL;
}

static void pim_vxlan_term_mr_oif_add(struct pim_vxlan_sg *vxlan_sg)
{
	if (vxlan_sg->flags & PIM_VXLAN_SGF_OIF_INSTALLED)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term-oif %s add",
			vxlan_sg->sg_str, vxlan_sg->term_oif->name);

	if (pim_ifchannel_local_membership_add(vxlan_sg->term_oif,
				&vxlan_sg->sg, true /*is_vxlan */)) {
		vxlan_sg->flags |= PIM_VXLAN_SGF_OIF_INSTALLED;
		/* update the inherited OIL */
		/* XXX - I don't see the inherited OIL updated when a local
		 * member is added. And that probably needs to be fixed. Till
		 * that happens we do a force update on the inherited OIL
		 * here.
		 */
		pim_upstream_inherited_olist(vxlan_sg->pim, vxlan_sg->up);
	} else {
		zlog_warn("vxlan SG %s term-oif %s add failed",
			vxlan_sg->sg_str, vxlan_sg->term_oif->name);
	}
}

static void pim_vxlan_term_mr_oif_del(struct pim_vxlan_sg *vxlan_sg)
{
	if (!(vxlan_sg->flags & PIM_VXLAN_SGF_OIF_INSTALLED))
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s oif %s del",
			vxlan_sg->sg_str, vxlan_sg->term_oif->name);

	vxlan_sg->flags &= ~PIM_VXLAN_SGF_OIF_INSTALLED;
	pim_ifchannel_local_membership_del(vxlan_sg->term_oif, &vxlan_sg->sg);
	/* update the inherited OIL */
	/* XXX - I don't see the inherited OIL updated when a local member
	 * is deleted. And that probably needs to be fixed. Till that happens
	 * we do a force update on the inherited OIL here.
	 */
	pim_upstream_inherited_olist(vxlan_sg->pim, vxlan_sg->up);
}

static void pim_vxlan_update_sg_entry_mlag(struct pim_instance *pim,
		struct pim_upstream *up, bool inherit)
{
	bool is_df = true;

	if (inherit && up->parent &&
			PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(up->parent->flags) &&
			PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->parent->flags))
		is_df = false;

	pim_mlag_up_df_role_update(pim, up, is_df, "inherit_xg_df");
}

/* We run MLAG DF election only on mroutes that have the termination
 * device ipmr-lo in the immediate OIL. This is only (*, G) entries at the
 * moment. For (S, G) entries that (with ipmr-lo in the inherited OIL) we
 * inherit the DF role from the (*, G) entry.
 */
void pim_vxlan_inherit_mlag_flags(struct pim_instance *pim,
		struct pim_upstream *up, bool inherit)
{
	struct listnode *listnode;
	struct pim_upstream *child;

	for (ALL_LIST_ELEMENTS_RO(up->sources, listnode,
				child)) {
		pim_vxlan_update_sg_entry_mlag(pim,
				child, true /* inherit */);
	}
}

static void pim_vxlan_term_mr_up_add(struct pim_vxlan_sg *vxlan_sg)
{
	struct pim_upstream *up;
	int flags = 0;

	if (vxlan_sg->up) {
		/* nothing to do */
		return;
	}

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term mroute-up add",
			vxlan_sg->sg_str);

	PIM_UPSTREAM_FLAG_SET_SRC_VXLAN_TERM(flags);
	/* enable MLAG designated-forwarder election on termination mroutes */
	PIM_UPSTREAM_FLAG_SET_MLAG_VXLAN(flags);

	up = pim_upstream_add(vxlan_sg->pim, &vxlan_sg->sg, NULL /* iif */,
			      flags, __func__, NULL);
	vxlan_sg->up = up;

	if (!up) {
		zlog_warn("vxlan SG %s term mroute-up add failed",
			vxlan_sg->sg_str);
		return;
	}

	/* update existing SG entries with the parent's MLAG flag */
	pim_vxlan_inherit_mlag_flags(vxlan_sg->pim, up, true /*enable*/);
}

static void pim_vxlan_term_mr_up_del(struct pim_vxlan_sg *vxlan_sg)
{
	struct pim_upstream *up = vxlan_sg->up;

	if (!up)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term mroute-up del",
			vxlan_sg->sg_str);
	vxlan_sg->up = NULL;
	if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM) {
		/* update SG entries that are inheriting from this XG entry */
		pim_vxlan_inherit_mlag_flags(vxlan_sg->pim, up,
				false /*enable*/);
		/* clear out all the vxlan related flags */
		up->flags &= ~(PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM |
			PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN);
		pim_mlag_up_local_del(vxlan_sg->pim, up);
		pim_upstream_del(vxlan_sg->pim, up, __func__);
	}
}

static void pim_vxlan_term_mr_add(struct pim_vxlan_sg *vxlan_sg)
{
	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term mroute add", vxlan_sg->sg_str);

	vxlan_sg->term_oif = vxlan_sg->pim->vxlan.term_if;
	if (!vxlan_sg->term_oif)
		/* defer termination mroute till we have a termination device */
		return;

	pim_vxlan_term_mr_up_add(vxlan_sg);
	/* set up local membership for the term-oif */
	pim_vxlan_term_mr_oif_add(vxlan_sg);
}

static void pim_vxlan_term_mr_del(struct pim_vxlan_sg *vxlan_sg)
{
	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term mroute del", vxlan_sg->sg_str);

	/* remove local membership associated with the term oif */
	pim_vxlan_term_mr_oif_del(vxlan_sg);
	/* remove references to the upstream entry */
	pim_vxlan_term_mr_up_del(vxlan_sg);
}

/************************** vxlan SG cache management ************************/
static unsigned int pim_vxlan_sg_hash_key_make(const void *p)
{
	const struct pim_vxlan_sg *vxlan_sg = p;

	return pim_sgaddr_hash(vxlan_sg->sg, 0);
}

static bool pim_vxlan_sg_hash_eq(const void *p1, const void *p2)
{
	const struct pim_vxlan_sg *sg1 = p1;
	const struct pim_vxlan_sg *sg2 = p2;

	return !pim_sgaddr_cmp(sg1->sg, sg2->sg);
}

static struct pim_vxlan_sg *pim_vxlan_sg_new(struct pim_instance *pim,
					     pim_sgaddr *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = XCALLOC(MTYPE_PIM_VXLAN_SG, sizeof(*vxlan_sg));

	vxlan_sg->pim = pim;
	vxlan_sg->sg = *sg;
	snprintfrr(vxlan_sg->sg_str, sizeof(vxlan_sg->sg_str), "%pSG", sg);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s alloc", vxlan_sg->sg_str);

	vxlan_sg = hash_get(pim->vxlan.sg_hash, vxlan_sg, hash_alloc_intern);

	/* we register with the MLAG daemon in the first VxLAN SG and never
	 * de-register during that life of the pimd
	 */
	if (pim->vxlan.sg_hash->count == 1) {
		vxlan_mlag.flags |= PIM_VXLAN_MLAGF_DO_REG;
		pim_mlag_register();
	}

	return vxlan_sg;
}

struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct pim_vxlan_sg lookup;

	lookup.sg = *sg;
	return hash_lookup(pim->vxlan.sg_hash, &lookup);
}

struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (vxlan_sg)
		return vxlan_sg;

	vxlan_sg = pim_vxlan_sg_new(pim, sg);

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		pim_vxlan_orig_mr_add(vxlan_sg);
	else
		pim_vxlan_term_mr_add(vxlan_sg);

	return vxlan_sg;
}

static void pim_vxlan_sg_del_item(struct pim_vxlan_sg *vxlan_sg)
{
	vxlan_sg->flags |= PIM_VXLAN_SGF_DEL_IN_PROG;

	EVENT_OFF(vxlan_sg->null_register);
	pim_vxlan_del_work(vxlan_sg);

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		pim_vxlan_orig_mr_del(vxlan_sg);
	else
		pim_vxlan_term_mr_del(vxlan_sg);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s free", vxlan_sg->sg_str);

	XFREE(MTYPE_PIM_VXLAN_SG, vxlan_sg);
}

void pim_vxlan_sg_del(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (!vxlan_sg)
		return;

	hash_release(pim->vxlan.sg_hash, vxlan_sg);
	pim_vxlan_sg_del_item(vxlan_sg);
}

/******************************* MLAG handling *******************************/
bool pim_vxlan_do_mlag_reg(void)
{
	return (vxlan_mlag.flags & PIM_VXLAN_MLAGF_DO_REG);
}

/* The peerlink sub-interface is added as an OIF to the origination-mroute.
 * This is done to send a copy of the multicast-vxlan encapsulated traffic
 * to the MLAG peer which may mroute it over the underlay if there are any
 * interested receivers.
 */
static void pim_vxlan_sg_peerlink_oif_update(struct hash_bucket *bucket,
					     void *arg)
{
	struct interface *new_oif = (struct interface *)arg;
	struct pim_vxlan_sg *vxlan_sg = (struct pim_vxlan_sg *)bucket->data;

	if (!pim_vxlan_is_orig_mroute(vxlan_sg))
		return;

	if (vxlan_sg->orig_oif == new_oif)
		return;

	pim_vxlan_orig_mr_oif_del(vxlan_sg);

	vxlan_sg->orig_oif = new_oif;
	pim_vxlan_orig_mr_oif_add(vxlan_sg);
}

/* In the case of anycast VTEPs the VTEP-PIP must be used as the
 * register source.
 */
bool pim_vxlan_get_register_src(struct pim_instance *pim,
		struct pim_upstream *up, struct in_addr *src_p)
{
	if (!(vxlan_mlag.flags & PIM_VXLAN_MLAGF_ENABLED))
		return true;

	/* if address is not available suppress the pim-register */
	if (vxlan_mlag.reg_addr.s_addr == INADDR_ANY)
		return false;

	*src_p = vxlan_mlag.reg_addr;
	return true;
}

void pim_vxlan_mlag_update(bool enable, bool peer_state, uint32_t role,
				struct interface *peerlink_rif,
				struct in_addr *reg_addr)
{
	struct pim_instance *pim;
	char addr_buf[INET_ADDRSTRLEN];
	struct pim_interface *pim_ifp = NULL;

	if (PIM_DEBUG_VXLAN) {
		inet_ntop(AF_INET, reg_addr,
				addr_buf, INET_ADDRSTRLEN);
		zlog_debug("vxlan MLAG update %s state %s role %d rif %s addr %s",
				enable ? "enable" : "disable",
				peer_state ? "up" : "down",
				role,
				peerlink_rif ? peerlink_rif->name : "-",
				addr_buf);
	}

	/* XXX: for now vxlan termination is only possible in the default VRF
	 * when that changes this will need to change to iterate all VRFs
	 */
	pim = pim_get_pim_instance(VRF_DEFAULT);

	if (!pim) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("%s: Unable to find pim instance", __func__);
		return;
	}

	if (enable)
		vxlan_mlag.flags |= PIM_VXLAN_MLAGF_ENABLED;
	else
		vxlan_mlag.flags &= ~PIM_VXLAN_MLAGF_ENABLED;

	if (vxlan_mlag.peerlink_rif != peerlink_rif)
		vxlan_mlag.peerlink_rif = peerlink_rif;

	vxlan_mlag.reg_addr = *reg_addr;
	vxlan_mlag.peer_state = peer_state;
	vxlan_mlag.role = role;

	/* process changes */
	if (vxlan_mlag.peerlink_rif)
		pim_ifp = (struct pim_interface *)vxlan_mlag.peerlink_rif->info;
	if ((vxlan_mlag.flags & PIM_VXLAN_MLAGF_ENABLED) &&
			pim_ifp && (pim_ifp->mroute_vif_index > 0))
		pim_vxlan_set_peerlink_rif(pim, peerlink_rif);
	else
		pim_vxlan_set_peerlink_rif(pim, NULL);
}

/****************************** misc callbacks *******************************/
static void pim_vxlan_set_default_iif(struct pim_instance *pim,
				struct interface *ifp)
{
	struct interface *old_iif;

	if (pim->vxlan.default_iif == ifp)
		return;

	old_iif = pim->vxlan.default_iif;
	if (PIM_DEBUG_VXLAN)
		zlog_debug("%s: vxlan default iif changed from %s to %s",
			   __func__, old_iif ? old_iif->name : "-",
			   ifp ? ifp->name : "-");

	old_iif = pim_vxlan_orig_mr_iif_get(pim);
	pim->vxlan.default_iif = ifp;
	ifp = pim_vxlan_orig_mr_iif_get(pim);
	if (old_iif == ifp)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("%s: vxlan orig iif changed from %s to %s", __func__,
			   old_iif ? old_iif->name : "-",
			   ifp ? ifp->name : "-");

	/* add/del upstream entries for the existing vxlan SG when the
	 * interface becomes available
	 */
	if (pim->vxlan.sg_hash)
		hash_iterate(pim->vxlan.sg_hash,
				pim_vxlan_orig_mr_iif_update, NULL);
}

static void pim_vxlan_up_cost_update(struct pim_instance *pim,
		struct pim_upstream *up,
		struct interface *old_peerlink_rif)
{
	if (!PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(up->flags))
		return;

	if (up->rpf.source_nexthop.interface &&
			((up->rpf.source_nexthop.interface ==
			  pim->vxlan.peerlink_rif) ||
			 (up->rpf.source_nexthop.interface ==
			  old_peerlink_rif))) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("RPF cost adjust for %s on peerlink-rif (old: %s, new: %s) change",
					up->sg_str,
					old_peerlink_rif ?
					old_peerlink_rif->name : "-",
					pim->vxlan.peerlink_rif ?
					pim->vxlan.peerlink_rif->name : "-");
		pim_mlag_up_local_add(pim, up);
	}
}

static void pim_vxlan_term_mr_cost_update(struct hash_bucket *bucket, void *arg)
{
	struct interface *old_peerlink_rif = (struct interface *)arg;
	struct pim_vxlan_sg *vxlan_sg = (struct pim_vxlan_sg *)bucket->data;
	struct pim_upstream *up;
	struct listnode *listnode;
	struct pim_upstream *child;

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		return;

	/* Lookup all XG and SG entries with RPF-interface peerlink_rif */
	up = vxlan_sg->up;
	if (!up)
		return;

	pim_vxlan_up_cost_update(vxlan_sg->pim, up,
			old_peerlink_rif);

	for (ALL_LIST_ELEMENTS_RO(up->sources, listnode,
				child))
		pim_vxlan_up_cost_update(vxlan_sg->pim, child,
				old_peerlink_rif);
}

static void pim_vxlan_sg_peerlink_rif_update(struct hash_bucket *bucket,
					     void *arg)
{
	pim_vxlan_orig_mr_iif_update(bucket, NULL);
	pim_vxlan_term_mr_cost_update(bucket, arg);
}

static void pim_vxlan_set_peerlink_rif(struct pim_instance *pim,
			struct interface *ifp)
{
	struct interface *old_iif;
	struct interface *new_iif;
	struct interface *old_oif;
	struct interface *new_oif;

	if (pim->vxlan.peerlink_rif == ifp)
		return;

	old_iif = pim->vxlan.peerlink_rif;
	if (PIM_DEBUG_VXLAN)
		zlog_debug("%s: vxlan peerlink_rif changed from %s to %s",
			   __func__, old_iif ? old_iif->name : "-",
			   ifp ? ifp->name : "-");

	old_iif = pim_vxlan_orig_mr_iif_get(pim);
	old_oif = pim_vxlan_orig_mr_oif_get(pim);
	pim->vxlan.peerlink_rif = ifp;

	new_iif = pim_vxlan_orig_mr_iif_get(pim);
	if (old_iif != new_iif) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("%s: vxlan orig iif changed from %s to %s",
				   __func__, old_iif ? old_iif->name : "-",
				   new_iif ? new_iif->name : "-");

		/* add/del upstream entries for the existing vxlan SG when the
		 * interface becomes available
		 */
		if (pim->vxlan.sg_hash)
			hash_iterate(pim->vxlan.sg_hash,
					pim_vxlan_sg_peerlink_rif_update,
					old_iif);
	}

	new_oif = pim_vxlan_orig_mr_oif_get(pim);
	if (old_oif != new_oif) {
		if (PIM_DEBUG_VXLAN)
			zlog_debug("%s: vxlan orig oif changed from %s to %s",
				   __func__, old_oif ? old_oif->name : "-",
				   new_oif ? new_oif->name : "-");
		if (pim->vxlan.sg_hash)
			hash_iterate(pim->vxlan.sg_hash,
					pim_vxlan_sg_peerlink_oif_update,
					new_oif);
	}
}

static void pim_vxlan_term_mr_oif_update(struct hash_bucket *bucket, void *arg)
{
	struct interface *ifp = (struct interface *)arg;
	struct pim_vxlan_sg *vxlan_sg = (struct pim_vxlan_sg *)bucket->data;

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		return;

	if (vxlan_sg->term_oif == ifp)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s term oif changed from %s to %s",
			vxlan_sg->sg_str,
			vxlan_sg->term_oif ? vxlan_sg->term_oif->name : "-",
			ifp ? ifp->name : "-");

	pim_vxlan_term_mr_del(vxlan_sg);
	vxlan_sg->term_oif = ifp;
	pim_vxlan_term_mr_add(vxlan_sg);
}

static void pim_vxlan_term_oif_update(struct pim_instance *pim,
		struct interface *ifp)
{
	if (pim->vxlan.term_if == ifp)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan term oif changed from %s to %s",
			pim->vxlan.term_if ? pim->vxlan.term_if->name : "-",
			ifp ? ifp->name : "-");

	pim->vxlan.term_if = ifp;
	if (pim->vxlan.sg_hash)
		hash_iterate(pim->vxlan.sg_hash,
				pim_vxlan_term_mr_oif_update, ifp);
}

void pim_vxlan_add_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;

	if (pim->vrf->vrf_id != VRF_DEFAULT)
		return;

	if (if_is_loopback(ifp))
		pim_vxlan_set_default_iif(pim, ifp);

	if (vxlan_mlag.flags & PIM_VXLAN_MLAGF_ENABLED &&
			(ifp == vxlan_mlag.peerlink_rif))
		pim_vxlan_set_peerlink_rif(pim, ifp);

	if (pim->vxlan.term_if_cfg == ifp)
		pim_vxlan_term_oif_update(pim, ifp);
}

void pim_vxlan_del_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;

	if (pim->vrf->vrf_id != VRF_DEFAULT)
		return;

	if (pim->vxlan.default_iif == ifp)
		pim_vxlan_set_default_iif(pim, NULL);

	if (pim->vxlan.peerlink_rif == ifp)
		pim_vxlan_set_peerlink_rif(pim, NULL);

	if (pim->vxlan.term_if == ifp)
		pim_vxlan_term_oif_update(pim, NULL);
}

/* enable pim implicitly on the termination device add */
void pim_vxlan_add_term_dev(struct pim_instance *pim,
		struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	if (pim->vxlan.term_if_cfg == ifp)
		return;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan term oif cfg changed from %s to %s",
			   pim->vxlan.term_if_cfg ?
			   pim->vxlan.term_if_cfg->name : "-",
			   ifp->name);

	pim->vxlan.term_if_cfg = ifp;

	/* enable pim on the term ifp */
	pim_ifp = (struct pim_interface *)ifp->info;
	if (pim_ifp) {
		pim_ifp->pim_enable = true;
		/* ifp is already oper up; activate it as a term dev */
		if (pim_ifp->mroute_vif_index >= 0)
			pim_vxlan_term_oif_update(pim, ifp);
	} else {
		/* ensure that pimreg exists before using the newly created
		 * vxlan termination device
		 */
		pim_if_create_pimreg(pim);
		(void)pim_if_new(ifp, false /*igmp*/, true /*pim*/,
				 false /*pimreg*/, true /*vxlan_term*/);
	}
}

/* disable pim implicitly, if needed, on the termination device deletion */
void pim_vxlan_del_term_dev(struct pim_instance *pim)
{
	struct interface *ifp = pim->vxlan.term_if_cfg;
	struct pim_interface *pim_ifp;

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan term oif cfg changed from %s to -",
				ifp->name);

	pim->vxlan.term_if_cfg = NULL;

	pim_ifp = (struct pim_interface *)ifp->info;
	if (pim_ifp) {
		pim_ifp->pim_enable = false;
		if (!pim_ifp->gm_enable)
			pim_if_delete(ifp);
	}
}

void pim_vxlan_init(struct pim_instance *pim)
{
	char hash_name[64];

	snprintf(hash_name, sizeof(hash_name),
		"PIM %s vxlan SG hash", pim->vrf->name);
	pim->vxlan.sg_hash = hash_create(pim_vxlan_sg_hash_key_make,
			pim_vxlan_sg_hash_eq, hash_name);
}

void pim_vxlan_exit(struct pim_instance *pim)
{
	hash_clean_and_free(&pim->vxlan.sg_hash,
			    (void (*)(void *))pim_vxlan_sg_del_item);

	if (vxlan_info.work_list)
		list_delete(&vxlan_info.work_list);
}

void pim_vxlan_terminate(void)
{
	pim_vxlan_work_timer_setup(false);
}
