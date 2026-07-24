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
#include "pim_ifchannel.h"
#include "pim_assert.h"
#include "pim_macro.h"
#include "if.h"

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
	pim_upstream_dense_reevaluate(pim);
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

static void pim_dm_assert_wrongif(struct interface *ifp, pim_sgaddr sg, struct pim_upstream *up)
{
	struct pim_ifchannel *ch, *throwaway;

	pim_ifchannel_find(ifp, &sg, &ch, &throwaway);
	if (!ch)
		ch = pim_ifchannel_add(ifp, &sg, 0, 0);

	if (ch->upstream != up) {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: (S,G)=%pSG ifchannel upstream mismatch on %s", __func__,
				   &sg, ifp->name);
		return;
	}

	pim_ifchannel_update_could_assert(ch);

	/* CouldAssert(S,G,I) must be true to initiate Assert (RFC 3973 4.6.4) */
	if (!PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: (S,G)=%s CouldAssert false on %s, skipping assert",
				   __func__, ch->sg_str, ifp->name);
		return;
	}

	if (ch->ifassert_state != PIM_IFASSERT_NOINFO) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: (S,G)=%s assert state %d on %s, skipping assert_action_a1",
				   __func__, ch->sg_str, ch->ifassert_state, ifp->name);
		return;
	}

	if (assert_action_a1(ch)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: (S,G)=%s assert_action_a1 failure on %s", __func__,
				   ch->sg_str, ifp->name);
	}
}

void pim_dm_wrongif(struct interface *ifp, pim_sgaddr sg, struct pim_upstream *up)
{
	if (!up || !up->rpf.source_nexthop.interface)
		return;

	if (up->rpf.source_nexthop.interface->ifindex == ifp->ifindex)
		return;

	if (if_is_pointopoint(ifp)) {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: Dense Mode WRONGVIF on P2P %s, immediate prune (S,G)=%pSG",
				   __func__, ifp->name, &sg);
		pim_dm_prune_wrongif(ifp, sg, up);
	} else if (PIM_UPSTREAM_FLAG_TEST_FHR(up->flags)) {
		/*
		 * The FHR injects on RPF_interface(S) only.  Reflected copies of
		 * the same flow on other LAN interfaces are not competing forwarders;
		 * Assert winner state there would keep stale OIFs and break prune.
		 */
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: Dense Mode WRONGVIF on LAN %s at FHR, immediate prune (S,G)=%pSG",
				   __func__, ifp->name, &sg);
		pim_dm_prune_wrongif(ifp, sg, up);
	} else {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: Dense Mode WRONGVIF on LAN %s, starting Assert (S,G)=%pSG",
				   __func__, ifp->name, &sg);
		pim_dm_assert_wrongif(ifp, sg, up);
	}
}

/* Send a prune immediately to all neighbors on an interface.
 * Used for wrong-interface traffic on P2P links and at the FHR.
 */
void pim_dm_prune_wrongif(struct interface *ifp, pim_sgaddr sg, struct pim_upstream *up)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (!up)
		return;

	if (should_limit_prune(up))
		return;

	/* Just in case, cancel any possible graft timer */
	event_cancel(&up->t_graft_timer);

	PIM_UPSTREAM_DM_SET_PRUNE(up->flags);

	/* Prune to each neighbor on the received interface */
	if (pim_ifp->pim_neighbor_list->count > 0) {
		struct listnode *neighnode;
		struct pim_neighbor *neigh;
		struct pim_rpf rpf;

		rpf.source_nexthop.interface = ifp;
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode, neigh)) {
			rpf.source_nexthop.mrib_nexthop_addr = neigh->source_addr;
			if (PIM_DEBUG_PIM_J_P)
				zlog_debug("%s: Sending immediate prune for (S,G)=%pSG to neighbor %pPA on interface %s",
					   __func__, &up->sg, &neigh->source_addr, ifp->name);
			pim_dm_prune_send(rpf, up, 0);
		}
		prune_limit_timer_start(up);
	}
}

/* React to an Assert state change on a dense-mode (S,G) interface.
 *
 * RFC 3973 4.6: the Assert loser must stop forwarding the duplicate onto the
 * shared LAN. If it also has no downstream receivers on that interface, it
 * prunes toward the Assert winner so the winner can drop the OIF and the tree
 * can converge. When the Assert is cancelled (back to NoInfo) the interface is
 * re-added so normal dense flooding resumes.
 */
void pim_dm_assert_state_changed(struct pim_ifchannel *ch, enum pim_ifassert_state new_state)
{
	struct interface *ifp = ch->interface;
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_upstream *up = ch->upstream;

	if (!pim_ifp || !up || !up->channel_oil)
		return;

	if (!pim_iface_grp_dm(pim_ifp, ch->sg.grp))
		return;

	/* Only downstream (non-RPF) interfaces are forwarding OIFs here. While
	 * RPF is unresolved (transiently NULL during reconvergence) we cannot
	 * tell whether ifp is the RPF interface, so skip the OIL update.
	 */
	if (!up->rpf.source_nexthop.interface || up->rpf.source_nexthop.interface == ifp)
		return;

	if (new_state == PIM_IFASSERT_I_AM_LOSER) {
		/* Defer to the Assert winner: stop forwarding the duplicate
		 * back onto this LAN.
		 */
		if (oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index)) {
			oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 0);
			pim_upstream_mroute_update(up->channel_oil, __func__);
		}

		/* With no local receivers on this interface, ask the winner to
		 * stop forwarding the duplicate to us so its OIF clears too.
		 */
		if (!pim_gm_has_igmp_join(ifp, ch->sg.grp)) {
			struct pim_rpf rpf;

			rpf.source_nexthop.interface = ifp;
			rpf.source_nexthop.mrib_nexthop_addr = ch->ifassert_winner;
			if (PIM_DEBUG_PIM_J_P)
				zlog_debug("%s: (S,G)=%s Assert loser on %s, pruning winner %pPA",
					   __func__, ch->sg_str, ifp->name, &ch->ifassert_winner);
			pim_dm_prune_send(rpf, up, 0);
		}
	} else if (new_state == PIM_IFASSERT_NOINFO) {
		/* Assert cancelled: resume dense flooding on this interface if
		 * it still has neighbors or local receivers and is not pruned,
		 * either on this interface (ch->flags) or for the whole (S,G)
		 * upstream (up->flags). Re-adding an OIF while the upstream is
		 * globally pruned would install an OIF that never sees traffic;
		 * mirror the up->flags guard used in pim_dm_prune_iff_on_timer().
		 */
		if ((pim_ifp->pim_neighbor_list->count || pim_gm_has_igmp_join(ifp, ch->sg.grp)) &&
		    !PIM_UPSTREAM_DM_TEST_PRUNE(ch->flags) &&
		    !PIM_UPSTREAM_DM_TEST_PRUNE(up->flags) &&
		    !oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index)) {
			oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 1);
			pim_upstream_mroute_update(up->channel_oil, __func__);
		}
	}
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
bool pim_gm_has_igmp_join(struct interface *ifp, pim_addr group_addr)
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

/*
 * Dense flood installs (S,G) OIFs with oil_if_set() (no PROTO_GM).  IGMP/MLD
 * leave only removes PROTO_GM from the (*,G)/(S,G) channel_oil that GM tracks,
 * so those DM-native OIFs would otherwise stick forever and block upstream
 * prune.  Clear the leave interface from matching dense (S,G) oils and prune
 * toward RPF when nothing downstream remains.
 *
 * While tib_sg_gm_prune runs, the leaving group is still on gm_group_list, so
 * pim_upstream_up_connected() would still see local membership on oif.  Skip
 * IGMP/MLD on the leave interface when deciding whether to prune.
 */
void pim_dm_gm_oif_del(struct pim_instance *pim, pim_sgaddr sg, struct interface *oif)
{
	struct channel_oil *c_oil;
	struct pim_interface *pim_oif = oif->info;

	if (!pim_oif || !pim_iface_grp_dm(pim_oif, sg.grp))
		return;

	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil) {
		struct pim_upstream *up = c_oil->up;
		struct interface *ifp;
		struct interface *rpf_ifp;
		struct pim_interface *pim_rpf;
		struct pim_ifchannel *ch, *throwaway;
		bool connected = false;

		if (pim_addr_cmp(sg.grp, *oil_mcastgrp(c_oil)))
			continue;
		/* Dense forwarding state is on (S,G); skip (*,G) oils. */
		if (pim_addr_is_any(*oil_origin(c_oil)))
			continue;
		if (!pim_addr_is_any(sg.src) && pim_addr_cmp(sg.src, *oil_origin(c_oil)))
			continue;
		if (!up || !up->channel_oil)
			continue;
		if (!oil_if_has(c_oil, pim_oif->mroute_vif_index))
			continue;

		oil_if_set(c_oil, pim_oif->mroute_vif_index, 0);
		pim_upstream_mroute_update(c_oil, __func__);

		FOR_ALL_INTERFACES (up->pim->vrf, ifp) {
			struct pim_interface *pim_ifp = ifp->info;

			if (!pim_ifp || !pim_ifp->pim_enable)
				continue;

			if (HAVE_DENSE_MODE(pim_ifp->pim_mode) &&
			    up->rpf.source_nexthop.interface &&
			    ifp->ifindex != up->rpf.source_nexthop.interface->ifindex &&
			    oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index)) {
				connected = true;
				break;
			}
			/* Leave interface still has the group on gm_group_list. */
			if (ifp != oif && pim_gm_has_igmp_join(ifp, up->sg.grp)) {
				connected = true;
				break;
			}
		}

		if (connected)
			continue;

		rpf_ifp = up->rpf.source_nexthop.interface;
		if (!rpf_ifp || !rpf_ifp->info)
			continue;

		pim_rpf = rpf_ifp->info;
		if (!HAVE_DENSE_MODE(pim_rpf->pim_mode))
			continue;

		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: (S,G)=%pSG leave on %s, pruning upstream on %s", __func__,
				   &up->sg, oif->name, rpf_ifp->name);

		event_cancel(&up->t_graft_timer);
		event_cancel(&up->t_join_timer);
		PIM_UPSTREAM_DM_SET_PRUNE(up->flags);
		if (up->join_state == PIM_UPSTREAM_JOINED)
			pim_upstream_switch(up->pim, up, PIM_UPSTREAM_NOTJOINED);
		/* Cancel any pending Join-override on the RPF LAN. */
		pim_ifchannel_find(rpf_ifp, &up->sg, &ch, &throwaway);
		if (ch)
			event_cancel(&ch->t_ifjoin_prune_pending_timer);
		pim_dm_prune_send(up->rpf, up, 0);
		prune_timer_start(up);
	}
}

void pim_dm_recv_graft(struct interface *ifp, pim_sgaddr *sg)
{
	struct pim_upstream *up;
	struct pim_interface *pim_ifp = ifp->info;
	pim_addr group_addr = sg->grp;
	struct pim_ifchannel *ch, *throwaway;

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

		pim_ifchannel_find(ifp, sg, &ch, &throwaway);

		if (ch) {
			PIM_UPSTREAM_DM_UNSET_PRUNE(ch->flags);
			event_cancel(&ch->t_ifjoin_expiry_timer);
			pim_ifchannel_delete(ch);
		}

		/* dm: forward graft message */
		if (PIM_UPSTREAM_DM_TEST_PRUNE(up->flags)) {
			PIM_UPSTREAM_DM_UNSET_PRUNE(up->flags);
			event_cancel(&up->t_prune_timer);
			pim_dm_graft_send(up->rpf, up);
			graft_timer_start(up);
		}
	}
}


/*
 * Apply a received dense prune on a forwarding OIF: clear the OIL, optionally
 * prune further upstream, and arm the prune-holdtime re-flood timer.
 */
static void pim_dm_apply_oif_prune(struct interface *ifp, struct pim_upstream *up,
				   uint16_t holdtime, uint8_t source_flags)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_ifchannel *ch, *throwaway;
	struct interface *ifp2;
	struct pim_interface *pim_ifp2;
	struct vrf *vrf;
	bool sg_connected = false;

	if (!oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index))
		return;

	oil_if_set(up->channel_oil, pim_ifp->mroute_vif_index, 0);
	pim_upstream_mroute_update(up->channel_oil, __func__);

	vrf = up->pim->vrf;
	FOR_ALL_INTERFACES (vrf, ifp2) {
		pim_ifp2 = ifp2->info;

		if (!pim_ifp2)
			continue;
		if (HAVE_DENSE_MODE(pim_ifp2->pim_mode) && ifp2->ifindex != ifp->ifindex &&
		    oil_if_has(up->channel_oil, pim_ifp2->mroute_vif_index)) {
			sg_connected = true;
			break;
		}
		if (pim_gm_has_igmp_join(ifp2, up->sg.grp)) {
			sg_connected = true;
			break;
		}
	}

	if (!sg_connected) {
		event_cancel(&up->t_graft_timer);
		event_cancel(&up->t_join_timer);
		PIM_UPSTREAM_DM_SET_PRUNE(up->flags);
		if (up->join_state == PIM_UPSTREAM_JOINED)
			pim_upstream_switch(up->pim, up, PIM_UPSTREAM_NOTJOINED);
		pim_dm_prune_send(up->rpf, up, 0);
		prune_timer_start(up);
	}

	pim_ifchannel_find(ifp, &up->sg, &ch, &throwaway);
	if (!ch)
		ch = pim_ifchannel_add(ifp, &up->sg, source_flags, PIM_UPSTREAM_DM_FLAG_MASK_PRUNE);
	PIM_UPSTREAM_DM_SET_PRUNE(ch->flags);
	ch->prune_holdtime = holdtime;
	event_cancel(&ch->t_ifjoin_expiry_timer);
	event_add_timer(router->master, pim_dm_prune_iff_on_timer, ch, holdtime,
			&ch->t_ifjoin_expiry_timer);
}

void pim_dm_prune_pending_on_timer(struct event *t)
{
	struct pim_ifchannel *ch = EVENT_ARG(t);
	struct interface *ifp = ch->interface;
	struct pim_upstream *up = ch->upstream;
	uint16_t holdtime = ch->prune_holdtime;

	if (PIM_DEBUG_PIM_J_P)
		zlog_debug("%s: (S,G)=%s LAN prune-pending expired on %s, applying prune",
			   __func__, ch->sg_str, ifp->name);

	if (!up)
		return;

	pim_dm_apply_oif_prune(ifp, up, holdtime, 0);
}

void pim_dm_join_override_on_timer(struct event *t)
{
	struct pim_ifchannel *ch = EVENT_ARG(t);
	struct pim_upstream *up = ch->upstream;
	struct interface *ifp = ch->interface;

	if (!up)
		return;

	if (PIM_UPSTREAM_DM_TEST_PRUNE(up->flags) || !pim_upstream_up_connected(up))
		return;

	if (PIM_DEBUG_PIM_J_P)
		zlog_debug("%s: (S,G)=%s sending LAN Join override on %s", __func__, ch->sg_str,
			   ifp->name);

	pim_dm_prune_send(up->rpf, up, true);
}

/*
 * Dense Join on a multi-access LAN: cancel a pending OIF prune (override),
 * cancel a pending Join override (suppression), or re-add an already-pruned
 * OIF like a Graft directed at this forwarder.
 */
void pim_dm_recv_join(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		      pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_upstream *up;
	struct pim_ifchannel *ch, *throwaway;
	bool directed_to_us;

	if (!pim_ifp || !pim_ifp->pim_enable)
		return;

	if (!HAVE_DENSE_MODE(pim_ifp->pim_mode) || !pim_iface_grp_dm(pim_ifp, sg->grp))
		return;

	up = pim_upstream_find(pim_ifp->pim, sg);
	if (!up)
		return;

	directed_to_us = !pim_addr_cmp(upstream, pim_ifp->primary_address);

	pim_ifchannel_find(ifp, sg, &ch, &throwaway);

	if (!directed_to_us) {
		/* Join suppression: another router already overrode the prune. */
		if (ch && event_is_scheduled(ch->t_ifjoin_prune_pending_timer) &&
		    up->rpf.source_nexthop.interface == ifp) {
			if (PIM_DEBUG_PIM_J_P)
				zlog_debug("%s: (S,G)=%pSG suppressing Join override on %s",
					   __func__, sg, ifp->name);
			event_cancel(&ch->t_ifjoin_prune_pending_timer);
		}
		return;
	}

	/* Directed to us (LAN forwarder). */
	if (ch && event_is_scheduled(ch->t_ifjoin_prune_pending_timer)) {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: (S,G)=%pSG Join override cancels prune-pending on %s",
				   __func__, sg, ifp->name);
		event_cancel(&ch->t_ifjoin_prune_pending_timer);
	}

	/*
	 * After the OIF is pruned, restoration is via Graft (pim_dm_recv_graft),
	 * not Join. Join only cancels prune-pending during the override window.
	 */
}

void pim_dm_recv_prune(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		       pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags)
{
	struct pim_upstream *up;
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch, *throwaway;
	int jp_override_interval_msec;

	pim_ifp = ifp->info;
	if (!pim_ifp || !pim_ifp->pim_enable)
		return;

	if (!HAVE_DENSE_MODE(pim_ifp->pim_mode))
		return;

	if (!pim_iface_grp_dm(pim_ifp, sg->grp))
		return;

	up = pim_upstream_find(pim_ifp->pim, sg);
	if (!up)
		return;

	/*
	 * Prune not directed to us: if this is our RPF interface and we still
	 * have downstream interest, schedule a Join override (RFC 3973).
	 */
	if (pim_addr_cmp(upstream, pim_ifp->primary_address)) {
		/*
		 * Overheard prune on our RPF LAN: Join-override only while we
		 * still want the stream.  Already-pruned upstreams must not
		 * keep canceling the forwarder's prune-pending.
		 */
		if (up->rpf.source_nexthop.interface == ifp &&
		    !PIM_UPSTREAM_DM_TEST_PRUNE(up->flags) && pim_upstream_up_connected(up)) {
			pim_ifchannel_find(ifp, sg, &ch, &throwaway);
			if (!ch)
				ch = pim_ifchannel_add(ifp, sg, source_flags, 0);
			if (!event_is_scheduled(ch->t_ifjoin_prune_pending_timer)) {
				int t_override_msec = pim_if_t_override_msec(ifp);

				if (PIM_DEBUG_PIM_J_P)
					zlog_debug("%s: (S,G)=%pSG scheduling Join override in %d msec on %s",
						   __func__, sg, t_override_msec, ifp->name);
				event_add_timer_msec(router->master, pim_dm_join_override_on_timer,
						     ch, t_override_msec,
						     &ch->t_ifjoin_prune_pending_timer);
			}
		}
		return;
	}

	/* Directed to us: we forward onto this interface. */
	if (!up->channel_oil || !oil_if_has(up->channel_oil, pim_ifp->mroute_vif_index))
		return;

	/*
	 * Multi-access LAN with other neighbors: delay OIF removal so a sibling
	 * with receivers can Join-override (RFC 3973). P2P or sole neighbor:
	 * prune immediately.
	 */
	if (!if_is_pointopoint(ifp) && listcount(pim_ifp->pim_neighbor_list) > 1) {
		jp_override_interval_msec = pim_if_jp_override_interval_msec(ifp);

		pim_ifchannel_find(ifp, sg, &ch, &throwaway);
		if (!ch)
			ch = pim_ifchannel_add(ifp, sg, source_flags, 0);
		ch->prune_holdtime = holdtime;
		ch->upstream = up;

		if (event_is_scheduled(ch->t_ifjoin_prune_pending_timer))
			return;

		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: (S,G)=%pSG LAN prune-pending %d msec on %s", __func__, sg,
				   jp_override_interval_msec, ifp->name);

		event_add_timer_msec(router->master, pim_dm_prune_pending_on_timer, ch,
				     jp_override_interval_msec, &ch->t_ifjoin_prune_pending_timer);
		return;
	}

	pim_dm_apply_oif_prune(ifp, up, holdtime, source_flags);
}

void pim_dm_prune_iff_on_timer(struct event *t)
{
	struct pim_ifchannel *ch;
	struct pim_upstream *up;
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	bool lost_assert;

	ch = EVENT_ARG(t);

	ifp = ch->interface;
	pim_ifp = ifp->info;
	up = pim_upstream_find(pim_ifp->pim, &ch->sg);

	/* Save assert state before pim_ifchannel_delete() may free ch. */
	lost_assert = pim_macro_ch_lost_assert(ch);

	PIM_UPSTREAM_DM_UNSET_PRUNE(ch->flags);
	if (ch->flags == 0)
		pim_ifchannel_delete(ch);

	if (!up)
		return;
	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	if (up->channel_oil && up->channel_oil->installed &&
	    !PIM_UPSTREAM_DM_TEST_PRUNE(up->flags) && !lost_assert) {
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

/* Determine if a group should be considered as a dense mode group for a specific interface.
 * A group is dense mode if it matches the following criteria:
 *   1. Is NOT in the reserved groups range (224.0.0.0/24)
 *   2. Is NOT in the SSM group range (default 232.0.0.0/8, or configured)
 *   3. If interface is in sparse-dense mode, group is NOT covered by an RP (even if unreachable)
 *   4. If a dense group filter list is configured, group is within the configured prefix list, if
 *      no filter list is configured, then group is dense mode.
 */
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
		/* If the interface is configured in sparse-dense mode, then the group is sparse if it has
		 * an RP discovered/configured, even if the RP is unreachable. Otherwise the group is a
		 * dense group.
		 */
		rpg = RP(pim, group_addr);
		if (rpg && !pim_rpf_addr_is_inaddr_any(rpg))
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
