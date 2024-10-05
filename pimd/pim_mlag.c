// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of PIM MLAG Functionality
 *
 * Module name: PIM MLAG
 *
 * Author: sathesh Kumar karra <sathk@cumulusnetworks.com>
 *
 * Copyright (C) 2019 Cumulus Networks http://www.cumulusnetworks.com
 */
#include <zebra.h>

#include "pimd.h"
#include "pim_mlag.h"
#include "pim_upstream.h"
#include "pim_vxlan.h"

extern struct zclient *zclient;

#define PIM_MLAG_METADATA_LEN 4

/*********************ACtual Data processing *****************************/
/* TBD: There can be duplicate updates to FIB***/
#define PIM_MLAG_ADD_OIF_TO_OIL(ch, ch_oil)                                    \
	do {                                                                   \
		if (PIM_DEBUG_MLAG)                                            \
			zlog_debug(                                            \
				"%s: add Dual-active Interface to %s "         \
				"to oil:%s",                                   \
				__func__, ch->interface->name, ch->sg_str);    \
		pim_channel_update_oif_mute(ch_oil, ch->interface->info);      \
	} while (0)

#define PIM_MLAG_DEL_OIF_TO_OIL(ch, ch_oil)                                    \
	do {                                                                   \
		if (PIM_DEBUG_MLAG)                                            \
			zlog_debug(                                            \
				"%s: del Dual-active Interface to %s "         \
				"to oil:%s",                                   \
				__func__, ch->interface->name, ch->sg_str);    \
		pim_channel_update_oif_mute(ch_oil, ch->interface->info);      \
	} while (0)


static void pim_mlag_calculate_df_for_ifchannels(struct pim_upstream *up,
						 bool is_df)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;
	struct pim_interface *pim_ifp = NULL;
	struct channel_oil *ch_oil = NULL;

	ch_oil = (up) ? up->channel_oil : NULL;

	if (!ch_oil)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Calculating DF for Dual active if-channel%s",
			   __func__, up->sg_str);

	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		pim_ifp = (ch->interface) ? ch->interface->info : NULL;
		if (!pim_ifp || !PIM_I_am_DualActive(pim_ifp))
			continue;

		if (is_df)
			PIM_MLAG_ADD_OIF_TO_OIL(ch, ch_oil);
		else
			PIM_MLAG_DEL_OIF_TO_OIL(ch, ch_oil);
	}
}

static void pim_mlag_inherit_mlag_flags(struct pim_upstream *up, bool is_df)
{
	struct listnode *listnode;
	struct pim_upstream *child;
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;
	struct pim_interface *pim_ifp = NULL;
	struct channel_oil *ch_oil = NULL;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Updating DF for uptream:%s children", __func__,
			   up->sg_str);


	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		pim_ifp = (ch->interface) ? ch->interface->info : NULL;
		if (!pim_ifp || !PIM_I_am_DualActive(pim_ifp))
			continue;

		for (ALL_LIST_ELEMENTS_RO(up->sources, listnode, child)) {
			if (PIM_DEBUG_MLAG)
				zlog_debug("%s: Updating DF for child:%s",
					   __func__, child->sg_str);
			ch_oil = (child) ? child->channel_oil : NULL;

			if (!ch_oil)
				continue;

			if (is_df)
				PIM_MLAG_ADD_OIF_TO_OIL(ch, ch_oil);
			else
				PIM_MLAG_DEL_OIF_TO_OIL(ch, ch_oil);
		}
	}
}

/******************************* pim upstream sync **************************/
/* Update DF role for the upstream entry and return true on role change */
bool pim_mlag_up_df_role_update(struct pim_instance *pim,
		struct pim_upstream *up, bool is_df, const char *reason)
{
	struct channel_oil *c_oil = up->channel_oil;
	bool old_is_df = !PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags);
	struct pim_interface *vxlan_ifp;

	if (is_df == old_is_df) {
		if (PIM_DEBUG_MLAG)
			zlog_debug(
				"%s: Ignoring Role update for %s, since no change",
				__func__, up->sg_str);
		return false;
	}

	if (PIM_DEBUG_MLAG)
		zlog_debug("local MLAG mroute %s role changed to %s based on %s",
				up->sg_str, is_df ? "df" : "non-df", reason);

	if (is_df)
		PIM_UPSTREAM_FLAG_UNSET_MLAG_NON_DF(up->flags);
	else
		PIM_UPSTREAM_FLAG_SET_MLAG_NON_DF(up->flags);


	/*
	 * This Upstream entry synced to peer Because of Dual-active
	 * Interface configuration
	 */
	if (PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(up->flags)) {
		pim_mlag_inherit_mlag_flags(up, is_df);
		pim_mlag_calculate_df_for_ifchannels(up, is_df);
	}

	/* If the DF role has changed check if ipmr-lo needs to be
	 * muted/un-muted. Active-Active devices and vxlan termination
	 * devices (ipmr-lo) are suppressed on the non-DF.
	 * This may leave the mroute with the empty OIL in which case the
	 * the forwarding entry's sole purpose is to just blackhole the flow
	 * headed to the switch.
	 */
	if (c_oil) {
		vxlan_ifp = pim_vxlan_get_term_ifp(pim);
		if (vxlan_ifp)
			pim_channel_update_oif_mute(c_oil, vxlan_ifp);
	}

	/* If DF role changed on a (*,G) termination mroute update the
	 * associated DF role on the inherited (S,G) entries
	 */
	if (pim_addr_is_any(up->sg.src) &&
	    PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(up->flags))
		pim_vxlan_inherit_mlag_flags(pim, up, true /* inherit */);

	return true;
}

/* Run per-upstream entry DF election and return true on role change */
static bool pim_mlag_up_df_role_elect(struct pim_instance *pim,
		struct pim_upstream *up)
{
	bool is_df;
	uint32_t peer_cost;
	uint32_t local_cost;
	bool rv;

	if (!pim_up_mlag_is_local(up))
		return false;

	/* We are yet to rx a status update from the local MLAG daemon so
	 * we will assume DF status.
	 */
	if (!(router->mlag_flags & PIM_MLAGF_STATUS_RXED))
		return pim_mlag_up_df_role_update(pim, up,
				true /*is_df*/, "mlagd-down");

	/* If not connected to peer assume DF role on the MLAG primary
	 * switch (and non-DF on the secondary switch.
	 */
	if (!(router->mlag_flags & PIM_MLAGF_PEER_CONN_UP)) {
		is_df = (router->mlag_role == MLAG_ROLE_PRIMARY) ? true : false;
		return pim_mlag_up_df_role_update(pim, up,
				is_df, "peer-down");
	}

	/* If MLAG peer session is up but zebra is down on the peer
	 * assume DF role.
	 */
	if (!(router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP))
		return pim_mlag_up_df_role_update(pim, up,
				true /*is_df*/, "zebra-down");

	/* If we are connected to peer switch but don't have a mroute
	 * from it we have to assume non-DF role to avoid duplicates.
	 * Note: When the peer connection comes up we wait for initial
	 * replay to complete before moving "strays" i.e. local-mlag-mroutes
	 * without a peer reference to non-df role.
	 */
	if (!PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(up->flags))
		return pim_mlag_up_df_role_update(pim, up,
				false /*is_df*/, "no-peer-mroute");

	/* switch with the lowest RPF cost wins. if both switches have the same
	 * cost MLAG role is used as a tie breaker (MLAG primary wins).
	 */
	peer_cost = up->mlag.peer_mrib_metric;
	local_cost = pim_up_mlag_local_cost(up);
	if (local_cost == peer_cost) {
		is_df = (router->mlag_role == MLAG_ROLE_PRIMARY) ? true : false;
		rv = pim_mlag_up_df_role_update(pim, up, is_df, "equal-cost");
	} else {
		is_df = (local_cost < peer_cost) ? true : false;
		rv = pim_mlag_up_df_role_update(pim, up, is_df, "cost");
	}

	return rv;
}

/* Handle upstream entry add from the peer MLAG switch -
 * - if a local entry doesn't exist one is created with reference
 *   _MLAG_PEER
 * - if a local entry exists and has a MLAG OIF DF election is run.
 *   the non-DF switch stop forwarding traffic to MLAG devices.
 */
static void pim_mlag_up_peer_add(struct mlag_mroute_add *msg)
{
	struct pim_upstream *up;
	struct pim_instance *pim;
	int flags = 0;
	pim_sgaddr sg;
	struct vrf *vrf;

	memset(&sg, 0, sizeof(sg));
	sg.src.s_addr = htonl(msg->source_ip);
	sg.grp.s_addr = htonl(msg->group_ip);

	if (PIM_DEBUG_MLAG)
		zlog_debug("peer MLAG mroute add %s:%pSG cost %d",
			   msg->vrf_name, &sg, msg->cost_to_rp);

	/* XXX - this is not correct. we MUST cache updates to avoid losing
	 * an entry because of race conditions with the peer switch.
	 */
	vrf = vrf_lookup_by_name(msg->vrf_name);
	if  (!vrf) {
		if (PIM_DEBUG_MLAG)
			zlog_debug(
				"peer MLAG mroute add failed %s:%pSG; no vrf",
				msg->vrf_name, &sg);
		return;
	}
	pim = vrf->info;

	up = pim_upstream_find(pim, &sg);
	if (up) {
		/* upstream already exists; create peer reference if it
		 * doesn't already exist.
		 */
		if (!PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(up->flags))
			pim_upstream_ref(up, PIM_UPSTREAM_FLAG_MASK_MLAG_PEER,
					 __func__);
	} else {
		PIM_UPSTREAM_FLAG_SET_MLAG_PEER(flags);
		up = pim_upstream_add(pim, &sg, NULL /*iif*/, flags, __func__,
				      NULL /*if_ch*/);

		if (!up) {
			if (PIM_DEBUG_MLAG)
				zlog_debug(
					"peer MLAG mroute add failed %s:%pSG",
					vrf->name, &sg);
			return;
		}
	}
	up->mlag.peer_mrib_metric = msg->cost_to_rp;
	pim_mlag_up_df_role_elect(pim, up);
}

/* Handle upstream entry del from the peer MLAG switch -
 * - peer reference is removed. this can result in the upstream
 *   being deleted altogether.
 * - if a local entry continues to exisy and has a MLAG OIF DF election
 *   is re-run (at the end of which the local entry will be the DF).
 */
static struct pim_upstream *pim_mlag_up_peer_deref(struct pim_instance *pim,
						   struct pim_upstream *up)
{
	if (!PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(up->flags))
		return up;

	PIM_UPSTREAM_FLAG_UNSET_MLAG_PEER(up->flags);
	up = pim_upstream_del(pim, up, __func__);
	if (up)
		pim_mlag_up_df_role_elect(pim, up);

	return up;
}

static void pim_mlag_up_peer_del(struct mlag_mroute_del *msg)
{
	struct pim_upstream *up;
	struct pim_instance *pim;
	pim_sgaddr sg;
	struct vrf *vrf;

	memset(&sg, 0, sizeof(sg));
	sg.src.s_addr = htonl(msg->source_ip);
	sg.grp.s_addr = htonl(msg->group_ip);

	if (PIM_DEBUG_MLAG)
		zlog_debug("peer MLAG mroute del %s:%pSG", msg->vrf_name, &sg);

	vrf = vrf_lookup_by_name(msg->vrf_name);
	if  (!vrf) {
		if (PIM_DEBUG_MLAG)
			zlog_debug(
				"peer MLAG mroute del skipped %s:%pSG; no vrf",
				msg->vrf_name, &sg);
		return;
	}
	pim = vrf->info;

	up = pim_upstream_find(pim, &sg);
	if  (!up) {
		if (PIM_DEBUG_MLAG)
			zlog_debug(
				"peer MLAG mroute del skipped %s:%pSG; no up",
				vrf->name, &sg);
		return;
	}

	(void)pim_mlag_up_peer_deref(pim, up);
}

/* When we lose connection to the local MLAG daemon we can drop all peer
 * references.
 */
static void pim_mlag_up_peer_del_all(void)
{
	struct list *temp = list_new();
	struct pim_upstream *up;
	struct vrf *vrf;
	struct pim_instance *pim;

	/*
	 * So why these gyrations?
	 * pim->upstream_head has the list of *,G and S,G
	 * that are in the system.  The problem of course
	 * is that it is an ordered list:
	 * (*,G1) -> (S1,G1) -> (S2,G2) -> (S3, G2) -> (*,G2) -> (S1,G2)
	 * And the *,G1 has pointers to S1,G1 and S2,G1
	 * if we delete *,G1 then we have a situation where
	 * S1,G1 and S2,G2 can be deleted as well.  Then a
	 * simple ALL_LIST_ELEMENTS will have the next listnode
	 * pointer become invalid and we crash.
	 * So let's grab the list of MLAG_PEER upstreams
	 * add a refcount put on another list and delete safely
	 */
	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			if (!PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(up->flags))
				continue;
			listnode_add(temp, up);
			/*
			 * Add a reference since we are adding to this
			 * list for deletion
			 */
			up->ref_count++;
		}

		while (temp->count) {
			up = listnode_head(temp);
			listnode_delete(temp, up);

			up = pim_mlag_up_peer_deref(pim, up);
			/*
			 * This is the deletion of the reference added
			 * above
			 */
			if (up)
				pim_upstream_del(pim, up, __func__);
		}
	}

	list_delete(&temp);
}

/* Send upstream entry to the local MLAG daemon (which will subsequently
 * send it to the peer MLAG switch).
 */
static void pim_mlag_up_local_add_send(struct pim_instance *pim,
		struct pim_upstream *up)
{
	struct stream *s = NULL;
	struct vrf *vrf = pim->vrf;

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP))
		return;

	s = stream_new(sizeof(struct mlag_mroute_add) + PIM_MLAG_METADATA_LEN);
	if (!s)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("local MLAG mroute add %s:%s",
				vrf->name, up->sg_str);

	++router->mlag_stats.msg.mroute_add_tx;

	stream_putl(s, MLAG_MROUTE_ADD);
	stream_put(s, vrf->name, VRF_NAMSIZ);
	stream_putl(s, ntohl(up->sg.src.s_addr));
	stream_putl(s, ntohl(up->sg.grp.s_addr));

	stream_putl(s, pim_up_mlag_local_cost(up));
	/* XXX - who is addding*/
	stream_putl(s, MLAG_OWNER_VXLAN);
	/* XXX - am_i_DR field should be removed */
	stream_putc(s, false);
	stream_putc(s, !(PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags)));
	stream_putl(s, vrf->vrf_id);
	/* XXX - this field is a No-op for VXLAN*/
	stream_put(s, NULL, IFNAMSIZ);

	stream_fifo_push_safe(router->mlag_fifo, s);
	pim_mlag_signal_zpthread();
}

static void pim_mlag_up_local_del_send(struct pim_instance *pim,
		struct pim_upstream *up)
{
	struct stream *s = NULL;
	struct vrf *vrf = pim->vrf;

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP))
		return;

	s = stream_new(sizeof(struct mlag_mroute_del) + PIM_MLAG_METADATA_LEN);
	if (!s)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("local MLAG mroute del %s:%s",
				vrf->name, up->sg_str);

	++router->mlag_stats.msg.mroute_del_tx;

	stream_putl(s, MLAG_MROUTE_DEL);
	stream_put(s, vrf->name, VRF_NAMSIZ);
	stream_putl(s, ntohl(up->sg.src.s_addr));
	stream_putl(s, ntohl(up->sg.grp.s_addr));
	/* XXX - who is adding */
	stream_putl(s, MLAG_OWNER_VXLAN);
	stream_putl(s, vrf->vrf_id);
	/* XXX - this field is a No-op for VXLAN */
	stream_put(s, NULL, IFNAMSIZ);

	/* XXX - is this the the most optimal way to do things */
	stream_fifo_push_safe(router->mlag_fifo, s);
	pim_mlag_signal_zpthread();
}


/* Called when a local upstream entry is created or if it's cost changes */
void pim_mlag_up_local_add(struct pim_instance *pim,
		struct pim_upstream *up)
{
	pim_mlag_up_df_role_elect(pim, up);
	/* XXX - need to add some dup checks here */
	pim_mlag_up_local_add_send(pim, up);
}

/* Called when local MLAG reference is removed from an upstream entry */
void pim_mlag_up_local_del(struct pim_instance *pim,
		struct pim_upstream *up)
{
	pim_mlag_up_df_role_elect(pim, up);
	pim_mlag_up_local_del_send(pim, up);
}

/* When connection to local MLAG daemon is established all the local
 * MLAG upstream entries are replayed to it.
 */
static void pim_mlag_up_local_replay(void)
{
	struct pim_upstream *up;
	struct vrf *vrf;
	struct pim_instance *pim;

	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			if (pim_up_mlag_is_local(up))
				pim_mlag_up_local_add_send(pim, up);
		}
	}
}

/* on local/peer mlag connection and role changes the DF status needs
 * to be re-evaluated
 */
static void pim_mlag_up_local_reeval(bool mlagd_send, const char *reason_code)
{
	struct pim_upstream *up;
	struct vrf *vrf;
	struct pim_instance *pim;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s re-run DF election because of %s",
				__func__, reason_code);
	RB_FOREACH(vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			if (!pim_up_mlag_is_local(up))
				continue;
			/* if role changes re-send to peer */
			if (pim_mlag_up_df_role_elect(pim, up) &&
					mlagd_send)
				pim_mlag_up_local_add_send(pim, up);
		}
	}
}

/*****************PIM Actions for MLAG state changes**********************/

/* notify the anycast VTEP component about state changes */
static inline void pim_mlag_vxlan_state_update(void)
{
	bool enable = !!(router->mlag_flags & PIM_MLAGF_STATUS_RXED);
	bool peer_state = !!(router->mlag_flags & PIM_MLAGF_PEER_CONN_UP);

	pim_vxlan_mlag_update(enable, peer_state, router->mlag_role,
			router->peerlink_rif_p, &router->local_vtep_ip);

}

/**************End of PIM Actions for MLAG State changes******************/


/********************API to process PIM MLAG Data ************************/

static void pim_mlag_process_mlagd_state_change(struct mlag_status msg)
{
	bool role_chg = false;
	bool state_chg = false;
	bool notify_vxlan = false;
	struct interface *peerlink_rif_p;
	char buf[MLAG_ROLE_STRSIZE];

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: msg dump: my_role: %s, peer_state: %s",
			   __func__,
			   mlag_role2str(msg.my_role, buf, sizeof(buf)),
			   (msg.peer_state == MLAG_STATE_RUNNING ? "RUNNING"
								 : "DOWN"));

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)) {
		if (PIM_DEBUG_MLAG)
			zlog_debug("%s: msg ignored mlagd process state down",
					__func__);
		return;
	}
	++router->mlag_stats.msg.mlag_status_updates;

	/* evaluate the changes first */
	if (router->mlag_role != msg.my_role) {
		role_chg = true;
		notify_vxlan = true;
		router->mlag_role = msg.my_role;
	}

	strlcpy(router->peerlink_rif, msg.peerlink_rif,
		sizeof(router->peerlink_rif));

	/* XXX - handle the case where we may rx the interface name from the
	 * MLAG daemon before we get the interface from zebra.
	 */
	peerlink_rif_p = if_lookup_by_name(router->peerlink_rif, VRF_DEFAULT);
	if (router->peerlink_rif_p != peerlink_rif_p) {
		router->peerlink_rif_p = peerlink_rif_p;
		notify_vxlan = true;
	}

	if (msg.peer_state == MLAG_STATE_RUNNING) {
		if (!(router->mlag_flags & PIM_MLAGF_PEER_CONN_UP)) {
			state_chg = true;
			notify_vxlan = true;
			router->mlag_flags |= PIM_MLAGF_PEER_CONN_UP;
		}
		router->connected_to_mlag = true;
	} else {
		if (router->mlag_flags & PIM_MLAGF_PEER_CONN_UP) {
			++router->mlag_stats.peer_session_downs;
			state_chg = true;
			notify_vxlan = true;
			router->mlag_flags &= ~PIM_MLAGF_PEER_CONN_UP;
		}
		router->connected_to_mlag = false;
	}

	/* apply the changes */
	/* when connection to mlagd comes up we hold send mroutes till we have
	 * rxed the status and had a chance to re-valuate DF state
	 */
	if (!(router->mlag_flags & PIM_MLAGF_STATUS_RXED)) {
		router->mlag_flags |= PIM_MLAGF_STATUS_RXED;
		pim_mlag_vxlan_state_update();
		/* on session up re-eval DF status */
		pim_mlag_up_local_reeval(false /*mlagd_send*/, "mlagd_up");
		/* replay all the upstream entries to the local MLAG daemon */
		pim_mlag_up_local_replay();
		return;
	}

	if (notify_vxlan)
		pim_mlag_vxlan_state_update();

	if (state_chg) {
		if (!(router->mlag_flags & PIM_MLAGF_PEER_CONN_UP))
			/* when a connection goes down the primary takes over
			 * DF role for all entries
			 */
			pim_mlag_up_local_reeval(true /*mlagd_send*/,
					"peer_down");
		else
			/* XXX - when session comes up we need to wait for
			 * PEER_REPLAY_DONE before running re-election on
			 * local-mlag entries that are missing peer reference
			 */
			pim_mlag_up_local_reeval(true /*mlagd_send*/,
					"peer_up");
	} else if (role_chg) {
		/* MLAG role changed without a state change */
		pim_mlag_up_local_reeval(true /*mlagd_send*/, "role_chg");
	}
}

static void pim_mlag_process_peer_frr_state_change(struct mlag_frr_status msg)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: msg dump: peer_frr_state: %s", __func__,
			(msg.frr_state == MLAG_FRR_STATE_UP ? "UP" : "DOWN"));

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)) {
		if (PIM_DEBUG_MLAG)
			zlog_debug("%s: msg ignored mlagd process state down",
					__func__);
		return;
	}
	++router->mlag_stats.msg.peer_zebra_status_updates;

	/* evaluate the changes first */
	if (msg.frr_state == MLAG_FRR_STATE_UP) {
		if (!(router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP)) {
			router->mlag_flags |= PIM_MLAGF_PEER_ZEBRA_UP;
			/* XXX - when peer zebra comes up we need to wait for
			 * for some time to let the peer setup MDTs before
			 * before relinquishing DF status
			 */
			pim_mlag_up_local_reeval(true /*mlagd_send*/,
					"zebra_up");
		}
	} else {
		if (router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP) {
			++router->mlag_stats.peer_zebra_downs;
			router->mlag_flags &= ~PIM_MLAGF_PEER_ZEBRA_UP;
			/* when a peer zebra goes down we assume DF role */
			pim_mlag_up_local_reeval(true /*mlagd_send*/,
					"zebra_down");
		}
	}
}

static void pim_mlag_process_vxlan_update(struct mlag_vxlan *msg)
{
	char addr_buf1[INET_ADDRSTRLEN];
	char addr_buf2[INET_ADDRSTRLEN];
	uint32_t local_ip;

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)) {
		if (PIM_DEBUG_MLAG)
			zlog_debug("%s: msg ignored mlagd process state down",
					__func__);
		return;
	}

	++router->mlag_stats.msg.vxlan_updates;
	router->anycast_vtep_ip.s_addr = htonl(msg->anycast_ip);
	local_ip = htonl(msg->local_ip);
	if (router->local_vtep_ip.s_addr != local_ip) {
		router->local_vtep_ip.s_addr = local_ip;
		pim_mlag_vxlan_state_update();
	}

	if (PIM_DEBUG_MLAG) {
		inet_ntop(AF_INET, &router->local_vtep_ip,
				addr_buf1, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &router->anycast_vtep_ip,
				addr_buf2, INET_ADDRSTRLEN);

		zlog_debug("%s: msg dump: local-ip:%s, anycast-ip:%s",
				__func__, addr_buf1, addr_buf2);
	}
}

static void pim_mlag_process_mroute_add(struct mlag_mroute_add msg)
{
	if (PIM_DEBUG_MLAG) {
		pim_sgaddr sg;

		sg.grp.s_addr = ntohl(msg.group_ip);
		sg.src.s_addr = ntohl(msg.source_ip);

		zlog_debug(
			"%s: msg dump: vrf_name: %s, s.ip: 0x%x, g.ip: 0x%x (%pSG) cost: %u",
			__func__, msg.vrf_name, msg.source_ip, msg.group_ip,
			&sg, msg.cost_to_rp);
		zlog_debug(
			"(%pSG)owner_id: %d, DR: %d, Dual active: %d, vrf_id: 0x%x intf_name: %s",
			&sg, msg.owner_id, msg.am_i_dr, msg.am_i_dual_active,
			msg.vrf_id, msg.intf_name);
	}

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)) {
		if (PIM_DEBUG_MLAG)
			zlog_debug("%s: msg ignored mlagd process state down",
					__func__);
		return;
	}

	++router->mlag_stats.msg.mroute_add_rx;

	pim_mlag_up_peer_add(&msg);
}

static void pim_mlag_process_mroute_del(struct mlag_mroute_del msg)
{
	if (PIM_DEBUG_MLAG) {
		pim_sgaddr sg;

		sg.grp.s_addr = ntohl(msg.group_ip);
		sg.src.s_addr = ntohl(msg.source_ip);
		zlog_debug(
			"%s: msg dump: vrf_name: %s, s.ip: 0x%x, g.ip: 0x%x(%pSG)",
			__func__, msg.vrf_name, msg.source_ip, msg.group_ip,
			&sg);
		zlog_debug("(%pSG)owner_id: %d, vrf_id: 0x%x intf_name: %s",
			   &sg, msg.owner_id, msg.vrf_id, msg.intf_name);
	}

	if (!(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)) {
		if (PIM_DEBUG_MLAG)
			zlog_debug("%s: msg ignored mlagd process state down",
					__func__);
		return;
	}

	++router->mlag_stats.msg.mroute_del_rx;

	pim_mlag_up_peer_del(&msg);
}

int pim_zebra_mlag_handle_msg(int cmd, struct zclient *zclient,
			      uint16_t zapi_length, vrf_id_t vrf_id)
{
	struct stream *s = zclient->ibuf;
	struct mlag_msg mlag_msg;
	char buf[80];
	int rc = 0;
	size_t length;

	rc = mlag_lib_decode_mlag_hdr(s, &mlag_msg, &length);
	if (rc)
		return (rc);

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received msg type: %s length: %d, bulk_cnt: %d",
			   __func__,
			   mlag_lib_msgid_to_str(mlag_msg.msg_type, buf,
						 sizeof(buf)),
			   mlag_msg.data_len, mlag_msg.msg_cnt);

	switch (mlag_msg.msg_type) {
	case MLAG_STATUS_UPDATE: {
		struct mlag_status msg;

		rc = mlag_lib_decode_mlag_status(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_mlagd_state_change(msg);
	} break;
	case MLAG_PEER_FRR_STATUS: {
		struct mlag_frr_status msg;

		rc = mlag_lib_decode_frr_status(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_peer_frr_state_change(msg);
	} break;
	case MLAG_VXLAN_UPDATE: {
		struct mlag_vxlan msg;

		rc = mlag_lib_decode_vxlan_update(s, &msg);
		if (rc)
			return rc;
		pim_mlag_process_vxlan_update(&msg);
	} break;
	case MLAG_MROUTE_ADD: {
		struct mlag_mroute_add msg;

		rc = mlag_lib_decode_mroute_add(s, &msg, &length);
		if (rc)
			return (rc);
		pim_mlag_process_mroute_add(msg);
	} break;
	case MLAG_MROUTE_DEL: {
		struct mlag_mroute_del msg;

		rc = mlag_lib_decode_mroute_del(s, &msg, &length);
		if (rc)
			return (rc);
		pim_mlag_process_mroute_del(msg);
	} break;
	case MLAG_MROUTE_ADD_BULK: {
		struct mlag_mroute_add msg;
		int i;

		for (i = 0; i < mlag_msg.msg_cnt; i++) {
			rc = mlag_lib_decode_mroute_add(s, &msg, &length);
			if (rc)
				return (rc);
			pim_mlag_process_mroute_add(msg);
		}
	} break;
	case MLAG_MROUTE_DEL_BULK: {
		struct mlag_mroute_del msg;
		int i;

		for (i = 0; i < mlag_msg.msg_cnt; i++) {
			rc = mlag_lib_decode_mroute_del(s, &msg, &length);
			if (rc)
				return (rc);
			pim_mlag_process_mroute_del(msg);
		}
	} break;
	case MLAG_MSG_NONE:
	case MLAG_REGISTER:
	case MLAG_DEREGISTER:
	case MLAG_DUMP:
	case MLAG_PIM_CFG_DUMP:
		break;
	}
	return 0;
}

/****************End of PIM Mesasge processing handler********************/

int pim_zebra_mlag_process_up(ZAPI_CALLBACK_ARGS)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received Process-Up from Mlag", __func__);

	/*
	 * Incase of local MLAG restart, PIM needs to replay all the data
	 * since MLAG is empty.
	 */
	router->connected_to_mlag = true;
	router->mlag_flags |= PIM_MLAGF_LOCAL_CONN_UP;
	return 0;
}

static void pim_mlag_param_reset(void)
{
	/* reset the cached params and stats */
	router->mlag_flags &= ~(PIM_MLAGF_STATUS_RXED |
			PIM_MLAGF_LOCAL_CONN_UP |
			PIM_MLAGF_PEER_CONN_UP |
			PIM_MLAGF_PEER_ZEBRA_UP);
	router->local_vtep_ip.s_addr = INADDR_ANY;
	router->anycast_vtep_ip.s_addr = INADDR_ANY;
	router->mlag_role = MLAG_ROLE_NONE;
	memset(&router->mlag_stats.msg, 0, sizeof(router->mlag_stats.msg));
	router->peerlink_rif[0] = '\0';
}

int pim_zebra_mlag_process_down(ZAPI_CALLBACK_ARGS)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received Process-Down from Mlag", __func__);

	/* Local CLAG is down, reset peer data and forward the traffic if
	 * we are DR
	 */
	if (router->mlag_flags & PIM_MLAGF_PEER_CONN_UP)
		++router->mlag_stats.peer_session_downs;
	if (router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP)
		++router->mlag_stats.peer_zebra_downs;
	router->connected_to_mlag = false;
	pim_mlag_param_reset();
	/* on mlagd session down re-eval DF status */
	pim_mlag_up_local_reeval(false /*mlagd_send*/, "mlagd_down");
	/* flush all peer references */
	pim_mlag_up_peer_del_all();
	/* notify the vxlan component */
	pim_mlag_vxlan_state_update();
	return 0;
}

static void pim_mlag_register_handler(struct event *thread)
{
	uint32_t bit_mask = 0;

	if (!zclient)
		return;

	SET_FLAG(bit_mask, (1 << MLAG_STATUS_UPDATE));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_ADD));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_DEL));
	SET_FLAG(bit_mask, (1 << MLAG_DUMP));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_ADD_BULK));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_DEL_BULK));
	SET_FLAG(bit_mask, (1 << MLAG_PIM_CFG_DUMP));
	SET_FLAG(bit_mask, (1 << MLAG_VXLAN_UPDATE));
	SET_FLAG(bit_mask, (1 << MLAG_PEER_FRR_STATUS));

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Posting Client Register to MLAG mask: 0x%x",
			   __func__, bit_mask);

	zclient_send_mlag_register(zclient, bit_mask);
}

void pim_mlag_register(void)
{
	if (router->mlag_process_register)
		return;

	router->mlag_process_register = true;

	event_add_event(router->master, pim_mlag_register_handler, NULL, 0,
			NULL);
}

static void pim_mlag_deregister_handler(struct event *thread)
{
	if (!zclient)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Posting Client De-Register to MLAG from PIM",
			   __func__);
	router->connected_to_mlag = false;
	zclient_send_mlag_deregister(zclient);
}

void pim_mlag_deregister(void)
{
	/* if somebody still interested in the MLAG channel skip de-reg */
	if (router->pim_mlag_intf_cnt || pim_vxlan_do_mlag_reg())
		return;

	/* not registered; nothing do */
	if (!router->mlag_process_register)
		return;

	router->mlag_process_register = false;

	event_add_event(router->master, pim_mlag_deregister_handler, NULL, 0,
			NULL);
}

void pim_if_configure_mlag_dualactive(struct pim_interface *pim_ifp)
{
	if (!pim_ifp || !pim_ifp->pim || pim_ifp->activeactive == true)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Configuring active-active on Interface: %s",
			   __func__, "NULL");

	pim_ifp->activeactive = true;
	if (pim_ifp->pim)
		pim_ifp->pim->inst_mlag_intf_cnt++;

	router->pim_mlag_intf_cnt++;
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Total MLAG configured Interfaces on router: %d, Inst: %d",
			__func__, router->pim_mlag_intf_cnt,
			pim_ifp->pim->inst_mlag_intf_cnt);

	if (router->pim_mlag_intf_cnt == 1) {
		/*
		 * at least one Interface is configured for MLAG, send register
		 * to Zebra for receiving MLAG Updates
		 */
		pim_mlag_register();
	}
}

void pim_if_unconfigure_mlag_dualactive(struct pim_interface *pim_ifp)
{
	if (!pim_ifp || !pim_ifp->pim || pim_ifp->activeactive == false)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: UnConfiguring active-active on Interface: %s",
			   __func__, "NULL");

	pim_ifp->activeactive = false;
	pim_ifp->pim->inst_mlag_intf_cnt--;

	router->pim_mlag_intf_cnt--;
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Total MLAG configured Interfaces on router: %d, Inst: %d",
			__func__, router->pim_mlag_intf_cnt,
			pim_ifp->pim->inst_mlag_intf_cnt);

	if (router->pim_mlag_intf_cnt == 0) {
		/*
		 * all the Interfaces are MLAG un-configured, post MLAG
		 * De-register to Zebra
		 */
		pim_mlag_deregister();
		pim_mlag_param_reset();
	}
}


void pim_instance_mlag_init(struct pim_instance *pim)
{
	if (!pim)
		return;

	pim->inst_mlag_intf_cnt = 0;
}


void pim_instance_mlag_terminate(struct pim_instance *pim)
{
	struct interface *ifp;

	if (!pim)
		return;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp || pim_ifp->activeactive == false)
			continue;

		pim_if_unconfigure_mlag_dualactive(pim_ifp);
	}
	pim->inst_mlag_intf_cnt = 0;
}

void pim_mlag_terminate(void)
{
	stream_free(router->mlag_stream);
	router->mlag_stream = NULL;
	stream_fifo_free(router->mlag_fifo);
	router->mlag_fifo = NULL;
}

void pim_mlag_init(void)
{
	pim_mlag_param_reset();
	router->pim_mlag_intf_cnt = 0;
	router->connected_to_mlag = false;
	router->mlag_fifo = stream_fifo_new();
	router->zpthread_mlag_write = NULL;
	router->mlag_stream = stream_new(MLAG_BUF_LIMIT);
}
