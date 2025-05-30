// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_dm.c: PIM Dense Mode
 *
 * Copyright (C) 2024 ATCorp
 * Jafar Al-Gharaibeh
 */

#include <zebra.h>

#include <lib/linklist.h>
#include <lib/prefix.h>
#include <lib/vty.h>
#include <lib/vrf.h>
#include <lib/plist.h>
#include <lib/lib_errors.h>

#include "pimd.h"
#include "pim_pim.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_dm.h"
#include "pim_igmp.h"
#include "pim_join.h"
#include "pim_util.h"

static void pim_dm_range_reevaluate(struct pim_instance *pim)
{
#if PIM_IPV == 4
	/* 1. Setup register state for (S,G) entries if G has changed from DM
	 * to
	 *    ASM.
	 * 2. check existing (*,G) IGMP registrations to see if they are
	 * still ASM. if they are now SSM delete them.
	 * 3. Allow channel setup for IGMP (*,G) members if G is now ASM
	 * 4. I could tear down all (*,G), (S,G,rpt) states. But that is an
	 * unnecessary sladge hammer and may not be particularly useful as it is
	 * likely the SPT switchover has already happened for flows along such
	 * RPTs.
	 * As for the RPT states it seems that the best thing to do is let them
	 * age
	 * out gracefully. As long as the FHR and LHR do the right thing RPTs
	 * will
	 * disappear in time for SSM groups.
	 */
	pim_upstream_register_reevaluate(pim);
	igmp_source_forward_reevaluate_all(pim);
#endif
}

void pim_dm_change_iif_mode(struct interface *ifp, enum pim_iface_mode mode)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct channel_oil *c_oil;

	if (!pim_ifp)
		return;

	if (HAVE_DENSE_MODE(mode) && !HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
		/* Enabling Dense Mode on the interface
		 * If it has no neighbors and no IGMP joins to a dense group, then nothing else to do.
		 * Otherwise, go through all installed multicast routes with dense groups and add this interface to the OIL.
		 * Also check if the route upstream is using a dense mode interface, or the group is joined somewhere, and it's set to prune
		 * then turn off the prune and instead send a graft
		 */
		pim_ifp->pim_mode = mode;
		if (listcount(pim_ifp->pim_neighbor_list) > 0 || pim_dm_check_gm_group_list(ifp)) {
			frr_each (rb_pim_oil, &pim_ifp->pim->channel_oil_head, c_oil) {
				if (pim_iface_grp_dm(pim_ifp, *oil_mcastgrp(c_oil)) &&
				    c_oil->installed) {
					oil_if_set(c_oil, pim_ifp->mroute_vif_index, 1);
					pim_upstream_mroute_update(c_oil, __func__);
					if (pim_upstream_up_connected(c_oil->up) &&
					    PIM_UPSTREAM_DM_TEST_PRUNE(c_oil->up->flags)) {
						PIM_UPSTREAM_DM_UNSET_PRUNE(c_oil->up->flags);
						if (c_oil->up->t_prune_timer)
							event_cancel(&c_oil->up->t_prune_timer);
						pim_dm_graft_send(c_oil->up->rpf, c_oil->up);
						graft_timer_start(c_oil->up);
					}
				}
			}
		}
	} else if (!HAVE_DENSE_MODE(mode) && HAVE_DENSE_MODE(pim_ifp->pim_mode)) {
		frr_each (rb_pim_oil, &pim_ifp->pim->channel_oil_head, c_oil) {
			if (pim_iface_grp_dm(pim_ifp, *oil_mcastgrp(c_oil)) && c_oil->installed) {
				oil_if_set(c_oil, pim_ifp->mroute_vif_index, 0);
				pim_upstream_mroute_update(c_oil, __func__);
				if (!pim_upstream_up_connected(c_oil->up)) {
					if (c_oil->up->t_graft_timer)
						event_cancel(&c_oil->up->t_graft_timer);
					PIM_UPSTREAM_DM_SET_PRUNE(c_oil->up->flags);
					pim_dm_prune_send(c_oil->up->rpf, c_oil->up, 0);
					prune_timer_start(c_oil->up);
				}
			}
		}
	}
	pim_ifp->pim_mode = mode;
}

void pim_dm_graft_send(struct pim_rpf rpf, struct pim_upstream *up)
{
	struct list groups, sources;
	struct pim_jp_agg_group jag;
	struct pim_jp_sources js;

	memset(&groups, 0, sizeof(groups));
	memset(&sources, 0, sizeof(sources));
	jag.sources = &sources;

	listnode_add(&groups, &jag);
	listnode_add(jag.sources, &js);

	jag.group = up->sg.grp;
	js.up = up;
	js.is_join = true;

	/*
	 * dm: rpf.rpf_addr is set to zero (anyaddr)
	 * set it to the address of the interface that send it!
	 */
	rpf.rpf_addr = rpf.source_nexthop.mrib_nexthop_addr;

	pim_graft_send(&rpf, &groups);

	list_delete_all_node(jag.sources);
	list_delete_all_node(&groups);
}

void pim_dm_prune_send(struct pim_rpf rpf, struct pim_upstream *up, bool is_join)
{
	struct list groups, sources;
	struct pim_jp_agg_group jag;
	struct pim_jp_sources js;

	memset(&groups, 0, sizeof(groups));
	memset(&sources, 0, sizeof(sources));
	jag.sources = &sources;

	listnode_add(&groups, &jag);
	listnode_add(jag.sources, &js);

	jag.group = up->sg.grp;
	js.up = up;
	js.is_join = is_join;

	/*
	 * dm:  rpf.rpf_addr is set to zero (anyaddr)
	 * set it to the address of the interface that send it!
	 */
	rpf.rpf_addr = rpf.source_nexthop.mrib_nexthop_addr;

	pim_joinprune_send(&rpf, &groups);

	list_delete_all_node(jag.sources);
	list_delete_all_node(&groups);
}

bool pim_dm_check_gm_group_list(struct interface *ifp)
{
	struct listnode *node;
	struct listnode *nextnode;
	struct gm_group *ij;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	if (!pim_ifp || !pim_ifp->gm_group_list)
		return false;
	for (ALL_LIST_ELEMENTS(pim_ifp->gm_group_list, node, nextnode, ij))
		if (pim_iface_grp_dm(pim_ifp, ij->group_addr))
			return true;

	return false;
}

/* Returns true if this interface has an IGMP for this group */
bool pim_dm_check_prune(struct interface *ifp, pim_addr group_addr)
{
	struct listnode *node;
	struct listnode *nextnode;
	struct gm_group *ij;
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	if (!pim_ifp->gm_group_list)
		return false;

	for (ALL_LIST_ELEMENTS(pim_ifp->gm_group_list, node, nextnode, ij))
		if (!pim_addr_cmp(group_addr, ij->group_addr))
			return true;

	return false;
}

void pim_dm_recv_graft(struct interface *ifp, pim_sgaddr *sg)
{
	struct pim_upstream *up;
	struct pim_interface *pim_ifp = ifp->info;
	pim_addr group_addr = sg->grp;
	struct pim_ifchannel *ch;

	if (!pim_ifp || !pim_ifp->pim_enable)
		return;

	++pim_ifp->pim_ifstat_graft_recv;

	if (!HAVE_DENSE_MODE(pim_ifp->pim_mode))
		return;

	up = pim_upstream_find(pim_ifp->pim, sg);

	if (!up)
		return;

	if (pim_iface_grp_dm(pim_ifp, group_addr) &&
	    !oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index)) {
		oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 1);
		pim_upstream_mroute_update(up->channel_oil, __func__);

		ch = pim_ifchannel_find(ifp, sg);

		if (ch) {
			PIM_UPSTREAM_DM_UNSET_PRUNE(ch->flags);
			if (ch->t_ifjoin_expiry_timer)
				event_cancel(&ch->t_ifjoin_expiry_timer);
			pim_ifchannel_delete(ch);
		}

		/* dm: forward graft message */
		if (PIM_UPSTREAM_DM_TEST_PRUNE(up->flags)) {
			PIM_UPSTREAM_DM_UNSET_PRUNE(up->flags);
			if (up->t_prune_timer)
				event_cancel(&up->t_prune_timer);
			pim_dm_graft_send(up->rpf, up);
			graft_timer_start(up);
		}
	}
}


void pim_dm_recv_prune(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		       pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags)
{
	struct pim_upstream *up;
	struct pim_interface *pim_ifp;
	pim_addr group_addr = sg->grp;
	struct pim_ifchannel *ch;

	struct interface *ifp2 = NULL;
	struct pim_interface *pim_ifp2;
	bool sg_connected;
	struct vrf *vrf;

	pim_ifp = ifp->info;
	if (!pim_ifp || !pim_ifp->pim_enable)
		return;

	if (!HAVE_DENSE_MODE(pim_ifp->pim_mode))
		return;

	up = pim_upstream_find(pim_ifp->pim, sg);

	if (!up)
		return;

	sg_connected = false;
	vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (pim_iface_grp_dm(pim_ifp, group_addr) &&
	    oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index)) {
		oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 0);
		pim_upstream_mroute_update(up->channel_oil, __func__);

		/* dm: we need to forward the prune upstream if needed */
		FOR_ALL_INTERFACES (vrf, ifp2) {
			pim_ifp2 = ifp2->info;

			if (!pim_ifp2)
				continue;
			if (HAVE_DENSE_MODE(pim_ifp2->pim_mode) && ifp2->ifindex != ifp->ifindex &&
			    oil_if_has(up->channel_oil, pim_ifp2->mroute_vif_index)) {
				sg_connected = true;
				break;
			}
			if (pim_dm_check_prune(ifp2, sg->grp)) {
				sg_connected = true;
				break;
			}
		}
		if (!sg_connected) {
			PIM_UPSTREAM_DM_SET_PRUNE(up->flags);
			pim_dm_prune_send(up->rpf, up, 0);
			prune_timer_start(up);
		}

		ch = pim_ifchannel_find(ifp, sg);
		if (!ch)
			ch = pim_ifchannel_add(ifp, sg, source_flags,
					       PIM_UPSTREAM_DM_FLAG_MASK_PRUNE);
		PIM_UPSTREAM_DM_SET_PRUNE(ch->flags);
		ch->prune_holdtime = holdtime;
		if (ch->t_ifjoin_expiry_timer)
			event_cancel(&ch->t_ifjoin_expiry_timer);
		event_add_timer(router->master, pim_dm_prune_iff_on_timer, ch, holdtime,
				&ch->t_ifjoin_expiry_timer);
	}
}

void pim_dm_prune_iff_on_timer(struct event *t)
{
	struct pim_ifchannel *ch;
	struct pim_upstream *up;
	struct interface *ifp;
	struct pim_interface *pim_ifp;

	ch = EVENT_ARG(t);

	ifp = ch->interface;
	pim_ifp = ifp->info;
	up = pim_upstream_find(pim_ifp->pim, &ch->sg);

	PIM_UPSTREAM_DM_UNSET_PRUNE(ch->flags);
	if (ch->flags == 0)
		pim_ifchannel_delete(ch);

	if (!up)
		return;
	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	if (up->channel_oil->installed) {
		oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 1);
		pim_upstream_mroute_update(up->channel_oil, __func__);
	}
}


void pim_dm_prefix_list_update(struct pim_instance *pim, struct prefix_list *plist)
{
	struct pim_dm *dm = pim->dm_info;

	if (!dm->plist_name || strcmp(dm->plist_name, prefix_list_name(plist))) {
		/* not ours */
		return;
	}

	pim_dm_range_reevaluate(pim);
}

bool pim_is_dm_prefix_filter(struct pim_instance *pim, pim_addr group_addr)
{
	struct pim_dm *dm;
	struct prefix group;
	struct prefix_list *plist;

	/* check if we have a dm prefix list confifgured  */
	dm = pim->dm_info;
	if (!dm)
		return true;
	plist = prefix_list_lookup(PIM_AFI, dm->plist_name);
	if (!plist)
		return true;

	pim_addr_to_prefix(&group, group_addr);

	return (prefix_list_apply_ext(plist, NULL, &group, true) == PREFIX_PERMIT);
}


int pim_is_grp_ssm(struct pim_instance *pim, pim_addr group_addr);

bool pim_is_grp_dm(struct pim_instance *pim, pim_addr group_addr)
{
	struct pim_rpf *rpg;

#if PIM_IPV == 4
	if (pim_is_group_224_0_0_0_24(group_addr))
		return false;
#else
	if (ipv6_mcast_reserved(&group_addr))
		return false;
#endif

	/* check if it is an SSM group */
	if (pim_is_grp_ssm(pim, group_addr))
		return false;

	/* check if it is an SM group */
	rpg = RP(pim, group_addr);
	if (rpg && !pim_rpf_addr_is_inaddr_any(rpg))
		return false;

	/* check if we have a dm prefix list filter  */
	return pim_is_dm_prefix_filter(pim, group_addr);
}


bool pim_iface_grp_dm(struct pim_interface *pim_ifp, pim_addr group_addr)
{
	struct pim_rpf *rpg;
	struct pim_instance *pim;

	if (!pim_ifp || !HAVE_DENSE_MODE(pim_ifp->pim_mode))
		return false;

#if PIM_IPV == 4
	if (pim_is_group_224_0_0_0_24(group_addr))
		return false;
#else
	if (ipv6_mcast_reserved(&group_addr))
		return false;
#endif

	pim = pim_ifp->pim;
	if (pim_is_grp_ssm(pim, group_addr))
		return false;

	if (pim_ifp->pim_mode == PIM_MODE_SPARSE_DENSE) {
		/*
		 * check if it is an SM group
		 * if we have an rp,
		 * and the rp is reachable (I.e, we have source_nexthop.interface)
		 */
		rpg = RP(pim, group_addr);
		if (rpg && rpg->source_nexthop.interface)
			return false;
	}

	/* check if we have a dm prefix list filter  */
	return pim_is_dm_prefix_filter(pim, group_addr);
}

int pim_dm_range_set(struct pim_instance *pim, const char *plist_name)
{
	struct pim_dm *dm = pim->dm_info;
	bool reeval = false;

	if (plist_name) {
		if (dm->plist_name) {
			if (strmatch(dm->plist_name, plist_name))
				return PIM_DM_ERR_DUP;
			XFREE(MTYPE_PIM_FILTER_NAME, dm->plist_name);
		}
		dm->plist_name = XSTRDUP(MTYPE_PIM_FILTER_NAME, plist_name);
		reeval = true;
	} else if (dm->plist_name) {
		reeval = true;
		XFREE(MTYPE_PIM_FILTER_NAME, dm->plist_name);
	}

	if (reeval)
		pim_dm_range_reevaluate(pim);

	return PIM_DM_ERR_NONE;
}

void pim_dm_init(struct pim_instance *pim)
{
	struct pim_dm *dm;

	dm = XCALLOC(MTYPE_PIM_DM_INFO, sizeof(*dm));
	pim->dm_info = dm;
}

void pim_dm_terminate(struct pim_instance *pim)
{
	if (pim->dm_info) {
		if (pim->dm_info->plist_name)
			XFREE(MTYPE_PIM_FILTER_NAME, pim->dm_info->plist_name);
		XFREE(MTYPE_PIM_DM_INFO, pim->dm_info);
	}
}
