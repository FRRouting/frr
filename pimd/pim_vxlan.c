/* PIM support for VxLAN BUM flooding
 *
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

/* pim-vxlan global info */
struct pim_vxlan vxlan_info, *pim_vxlan_p = &vxlan_info;

static void pim_vxlan_work_timer_setup(bool start);

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
			pim_null_register_send(vxlan_sg->up);
			++work_cnt;
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
	pim_vxlan_work_timer_setup(TRUE /* start */);
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
	else
		pim_vxlan_del_work(vxlan_sg);
}

static int pim_vxlan_work_timer_cb(struct thread *t)
{
	pim_vxlan_do_reg_work();
	pim_vxlan_work_timer_setup(true /* start */);
	return 0;
}

/* global 1second timer used for periodic processing */
static void pim_vxlan_work_timer_setup(bool start)
{
	THREAD_OFF(vxlan_info.work_timer);
	if (start)
		thread_add_timer(router->master, pim_vxlan_work_timer_cb, NULL,
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
			THREAD_OFF(up->t_ka_timer);
			up = pim_upstream_keep_alive_timer_proc(up);
		} else {
			/* this is really unexpected as we force vxlan
			 * origination mroutes active sources but just in
			 * case
			 */
			up = pim_upstream_del(vxlan_sg->pim, up,
				__PRETTY_FUNCTION__);
		}
		/* if there are other references register the source
		 * for nht
		 */
		if (up)
			pim_rpf_update(vxlan_sg->pim, up, NULL, 1 /* is_new */);
	}
}

static void pim_vxlan_orig_mr_up_iif_update(struct pim_vxlan_sg *vxlan_sg)
{
	int vif_index;

	/* update MFC with the new IIF */
	pim_upstream_fill_static_iif(vxlan_sg->up, vxlan_sg->iif);
	vif_index = pim_if_find_vifindex_by_ifindex(vxlan_sg->pim,
			vxlan_sg->iif->ifindex);
	if (vif_index > 0)
		pim_scan_individual_oil(vxlan_sg->up->channel_oil,
				vif_index);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s orig mroute-up updated with iif %s vifi %d",
			vxlan_sg->sg_str,
			vxlan_sg->iif?vxlan_sg->iif->name:"-", vif_index);

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
	int flags = 0;
	struct prefix nht_p;

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
			nht_p.family = AF_INET;
			nht_p.prefixlen = IPV4_MAX_BITLEN;
			nht_p.u.prefix4 = up->upstream_addr;
			pim_delete_tracked_nexthop(vxlan_sg->pim,
				&nht_p, up, NULL);
		}
		pim_upstream_ref(up, flags, __PRETTY_FUNCTION__);
		vxlan_sg->up = up;
		pim_vxlan_orig_mr_up_iif_update(vxlan_sg);
	} else {
		up = pim_upstream_add(vxlan_sg->pim, &vxlan_sg->sg,
				vxlan_sg->iif, flags,
				__PRETTY_FUNCTION__, NULL);
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
	if (up->reg_state == PIM_REG_NOINFO) {
		pim_register_join(up);
		pim_null_register_send(up);
	}

	/* update the inherited OIL */
	pim_upstream_inherited_olist(vxlan_sg->pim, up);
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
		vxlan_sg->orig_oif, PIM_OIF_FLAG_PROTO_VXLAN);
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
		orig_oif, PIM_OIF_FLAG_PROTO_VXLAN);
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

/************************** vxlan SG cache management ************************/
static unsigned int pim_vxlan_sg_hash_key_make(void *p)
{
	struct pim_vxlan_sg *vxlan_sg = p;

	return (jhash_2words(vxlan_sg->sg.src.s_addr,
				vxlan_sg->sg.grp.s_addr, 0));
}

static bool pim_vxlan_sg_hash_eq(const void *p1, const void *p2)
{
	const struct pim_vxlan_sg *sg1 = p1;
	const struct pim_vxlan_sg *sg2 = p2;

	return ((sg1->sg.src.s_addr == sg2->sg.src.s_addr)
			&& (sg1->sg.grp.s_addr == sg2->sg.grp.s_addr));
}

static struct pim_vxlan_sg *pim_vxlan_sg_new(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = XCALLOC(MTYPE_PIM_VXLAN_SG, sizeof(*vxlan_sg));

	vxlan_sg->pim = pim;
	vxlan_sg->sg = *sg;
	pim_str_sg_set(sg, vxlan_sg->sg_str);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s alloc", vxlan_sg->sg_str);

	vxlan_sg = hash_get(pim->vxlan.sg_hash, vxlan_sg, hash_alloc_intern);

	return vxlan_sg;
}

struct pim_vxlan_sg *pim_vxlan_sg_find(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg lookup;

	lookup.sg = *sg;
	return hash_lookup(pim->vxlan.sg_hash, &lookup);
}

struct pim_vxlan_sg *pim_vxlan_sg_add(struct pim_instance *pim,
		struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (vxlan_sg)
		return vxlan_sg;

	vxlan_sg = pim_vxlan_sg_new(pim, sg);

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		pim_vxlan_orig_mr_add(vxlan_sg);

	return vxlan_sg;
}

void pim_vxlan_sg_del(struct pim_instance *pim, struct prefix_sg *sg)
{
	struct pim_vxlan_sg *vxlan_sg;

	vxlan_sg = pim_vxlan_sg_find(pim, sg);
	if (!vxlan_sg)
		return;

	vxlan_sg->flags |= PIM_VXLAN_SGF_DEL_IN_PROG;

	pim_vxlan_del_work(vxlan_sg);

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		pim_vxlan_orig_mr_del(vxlan_sg);

	hash_release(vxlan_sg->pim->vxlan.sg_hash, vxlan_sg);

	if (PIM_DEBUG_VXLAN)
		zlog_debug("vxlan SG %s free", vxlan_sg->sg_str);

	XFREE(MTYPE_PIM_VXLAN_SG, vxlan_sg);
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
	if (pim->vxlan.sg_hash) {
		hash_clean(pim->vxlan.sg_hash, NULL);
		hash_free(pim->vxlan.sg_hash);
		pim->vxlan.sg_hash = NULL;
	}
}
