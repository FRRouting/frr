// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP-4 Finite State Machine
 * From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "sockunion.h"
#include "frrevent.h"
#include "log.h"
#include "stream.h"
#include "ringbuf.h"
#include "memory.h"
#include "plist.h"
#include "workqueue.h"
#include "queue.h"
#include "filter.h"
#include "command.h"
#include "lib_errors.h"
#include "zclient.h"
#include "lib/json.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"

DEFINE_HOOK(peer_backward_transition, (struct peer * peer), (peer));
DEFINE_HOOK(peer_status_changed, (struct peer * peer), (peer));

/* Definition of display strings corresponding to FSM events. This should be
 * kept consistent with the events defined in bgpd.h
 */
static const char *const bgp_event_str[] = {
	NULL,
	"BGP_Start",
	"BGP_Stop",
	"TCP_connection_open",
	"TCP_connection_open_w_delay",
	"TCP_connection_closed",
	"TCP_connection_open_failed",
	"TCP_fatal_error",
	"ConnectRetry_timer_expired",
	"Hold_Timer_expired",
	"KeepAlive_timer_expired",
	"DelayOpen_timer_expired",
	"Receive_OPEN_message",
	"Receive_KEEPALIVE_message",
	"Receive_UPDATE_message",
	"Receive_NOTIFICATION_message",
	"Clearing_Completed",
};

/* BGP FSM (finite state machine) has three types of functions.  Type
   one is thread functions.  Type two is event functions.  Type three
   is FSM functions.  Timer functions are set by bgp_timer_set
   function. */

/* BGP event function. */
void bgp_event(struct event *event);

/* BGP thread functions. */
static void bgp_start_timer(struct event *event);
static void bgp_connect_timer(struct event *event);
static void bgp_holdtime_timer(struct event *event);
static void bgp_delayopen_timer(struct event *event);

/* Register peer with NHT */
int bgp_peer_reg_with_nht(struct peer *peer)
{
	int connected = 0;

	if (peer->sort == BGP_PEER_EBGP && peer->ttl == BGP_DEFAULT_TTL
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	    && !CHECK_FLAG(peer->bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
		connected = 1;

	return bgp_find_or_add_nexthop(peer->bgp, peer->bgp,
				       family2afi(
					       peer->connection->su.sa.sa_family),
				       SAFI_UNICAST, NULL, peer, connected,
				       NULL);
}

static void peer_xfer_stats(struct peer *peer_dst, struct peer *peer_src)
{
	/* Copy stats over. These are only the pre-established state stats */
	peer_dst->open_in += peer_src->open_in;
	peer_dst->open_out += peer_src->open_out;
	peer_dst->keepalive_in += peer_src->keepalive_in;
	peer_dst->keepalive_out += peer_src->keepalive_out;
	peer_dst->notify_in += peer_src->notify_in;
	peer_dst->notify_out += peer_src->notify_out;
	peer_dst->dynamic_cap_in += peer_src->dynamic_cap_in;
	peer_dst->dynamic_cap_out += peer_src->dynamic_cap_out;
}

static struct peer *peer_xfer_conn(struct peer *from_peer)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	enum bgp_fsm_events last_evt, last_maj_evt;
	struct peer_connection *keeper, *going_away;

	assert(from_peer != NULL);

	/*
	 * Keeper is the connection that is staying around
	 */
	keeper = from_peer->connection;
	peer = from_peer->doppelganger;

	if (!peer || !CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
		return from_peer;

	/*
	 * from_peer is pointing at the non config node and
	 * at this point peer is pointing at the CONFIG node
	 * peer ( non incoming connection ).  The going_away pointer
	 * is the connection that is being placed on to
	 * the non Config node for deletion.
	 */
	going_away = peer->connection;

	/*
	 * Let's check that we are not going to loose known configuration
	 * state based upon doppelganger rules.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (from_peer->afc[afi][safi] != peer->afc[afi][safi]) {
			flog_err(
				EC_BGP_DOPPELGANGER_CONFIG,
				"from_peer->afc[%d][%d] is not the same as what we are overwriting",
				afi, safi);
			return NULL;
		}
	}

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s: peer transfer %p fd %d -> %p fd %d)",
			   from_peer->host, from_peer, from_peer->connection->fd,
			   peer, peer->connection->fd);

	bgp_writes_off(going_away);
	bgp_reads_off(going_away);
	bgp_writes_off(keeper);
	bgp_reads_off(keeper);

	/*
	 * Before exchanging FD remove doppelganger from
	 * keepalive peer hash. It could be possible conf peer
	 * fd is set to -1. If blocked on lock then keepalive
	 * thread can access peer pointer with fd -1.
	 */
	bgp_keepalives_off(keeper);

	EVENT_OFF(going_away->t_routeadv);
	EVENT_OFF(going_away->t_connect);
	EVENT_OFF(going_away->t_delayopen);
	EVENT_OFF(going_away->t_connect_check_r);
	EVENT_OFF(going_away->t_connect_check_w);
	EVENT_OFF(keeper->t_routeadv);
	EVENT_OFF(keeper->t_connect);
	EVENT_OFF(keeper->t_delayopen);
	EVENT_OFF(keeper->t_connect_check_r);
	EVENT_OFF(keeper->t_connect_check_w);
	EVENT_OFF(keeper->t_process_packet);

	/*
	 * At this point in time, it is possible that there are packets pending
	 * on various buffers. Those need to be transferred or dropped,
	 * otherwise we'll get spurious failures during session establishment.
	 */
	peer->connection = keeper;
	keeper->peer = peer;
	from_peer->connection = going_away;
	going_away->peer = from_peer;

	peer->as = from_peer->as;
	peer->v_holdtime = from_peer->v_holdtime;
	peer->v_keepalive = from_peer->v_keepalive;
	peer->v_routeadv = from_peer->v_routeadv;
	peer->v_delayopen = from_peer->v_delayopen;
	peer->v_gr_restart = from_peer->v_gr_restart;
	peer->cap = from_peer->cap;
	peer->remote_role = from_peer->remote_role;
	last_evt = peer->last_event;
	last_maj_evt = peer->last_major_event;
	peer->last_event = from_peer->last_event;
	peer->last_major_event = from_peer->last_major_event;
	from_peer->last_event = last_evt;
	from_peer->last_major_event = last_maj_evt;
	peer->remote_id = from_peer->remote_id;
	peer->last_reset = from_peer->last_reset;
	peer->max_packet_size = from_peer->max_packet_size;

	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp,
							  peer->bgp->peer);

	if (bgp_peer_gr_mode_get(peer) == PEER_DISABLE) {

		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			peer_nsf_stop(peer);
		}
	}

	if (peer->hostname) {
		XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
		peer->hostname = NULL;
	}
	if (from_peer->hostname != NULL) {
		peer->hostname = from_peer->hostname;
		from_peer->hostname = NULL;
	}

	if (peer->domainname) {
		XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);
		peer->domainname = NULL;
	}
	if (from_peer->domainname != NULL) {
		peer->domainname = from_peer->domainname;
		from_peer->domainname = NULL;
	}

	if (peer->soft_version) {
		XFREE(MTYPE_BGP_SOFT_VERSION, peer->soft_version);
		peer->soft_version = NULL;
	}
	if (from_peer->soft_version) {
		peer->soft_version = from_peer->soft_version;
		from_peer->soft_version = NULL;
	}

	FOREACH_AFI_SAFI (afi, safi) {
		peer->af_sflags[afi][safi] = from_peer->af_sflags[afi][safi];
		peer->af_cap[afi][safi] = from_peer->af_cap[afi][safi];
		peer->afc_nego[afi][safi] = from_peer->afc_nego[afi][safi];
		peer->afc_adv[afi][safi] = from_peer->afc_adv[afi][safi];
		peer->afc_recv[afi][safi] = from_peer->afc_recv[afi][safi];
		peer->orf_plist[afi][safi] = from_peer->orf_plist[afi][safi];
		peer->llgr[afi][safi] = from_peer->llgr[afi][safi];
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err(EC_LIB_SOCKET,
			 "%%bgp_getsockname() failed for %s peer %s fd %d (from_peer fd %d)",
			 (CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)
				  ? "accept"
				  : ""),
			 peer->host, going_away->fd, keeper->fd);
		BGP_EVENT_ADD(going_away, BGP_Stop);
		BGP_EVENT_ADD(keeper, BGP_Stop);
		return NULL;
	}
	if (going_away->status > Active) {
		if (bgp_getsockname(from_peer) < 0) {
			flog_err(EC_LIB_SOCKET,
				 "%%bgp_getsockname() failed for %s from_peer %s fd %d (peer fd %d)",

				 (CHECK_FLAG(from_peer->sflags,
					     PEER_STATUS_ACCEPT_PEER)
					  ? "accept"
					  : ""),
				 from_peer->host, going_away->fd, keeper->fd);
			bgp_stop(going_away);
			from_peer = NULL;
		}
	}


	// Note: peer_xfer_stats() must be called with I/O turned OFF
	if (from_peer)
		peer_xfer_stats(peer, from_peer);

	/* Register peer for NHT. This is to allow RAs to be enabled when
	 * needed, even on a passive connection.
	 */
	bgp_peer_reg_with_nht(peer);
	if (from_peer)
		bgp_replace_nexthop_by_peer(from_peer, peer);

	bgp_reads_on(keeper);
	bgp_writes_on(keeper);
	event_add_event(bm->master, bgp_process_packet, keeper, 0,
			&keeper->t_process_packet);

	return (peer);
}

/* Hook function called after bgp event is occered.  And vty's
   neighbor command invoke this function after making neighbor
   structure. */
void bgp_timer_set(struct peer_connection *connection)
{
	afi_t afi;
	safi_t safi;
	struct peer *peer = connection->peer;

	switch (connection->status) {
	case Idle:
		/* First entry point of peer's finite state machine.  In Idle
		   status start timer is on unless peer is shutdown or peer is
		   inactive.  All other timer must be turned off */
		if (BGP_PEER_START_SUPPRESSED(peer) || !peer_active(peer)
		    || peer->bgp->vrf_id == VRF_UNKNOWN) {
			EVENT_OFF(connection->t_start);
		} else {
			BGP_TIMER_ON(connection->t_start, bgp_start_timer,
				     peer->v_start);
		}
		EVENT_OFF(connection->t_connect);
		EVENT_OFF(connection->t_holdtime);
		bgp_keepalives_off(connection);
		EVENT_OFF(connection->t_routeadv);
		EVENT_OFF(connection->t_delayopen);
		break;

	case Connect:
		/* After start timer is expired, the peer moves to Connect
		   status.  Make sure start timer is off and connect timer is
		   on. */
		EVENT_OFF(connection->t_start);
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
			BGP_TIMER_ON(connection->t_connect, bgp_connect_timer,
				     (peer->v_delayopen + peer->v_connect));
		else
			BGP_TIMER_ON(connection->t_connect, bgp_connect_timer,
				     peer->v_connect);

		EVENT_OFF(connection->t_holdtime);
		bgp_keepalives_off(connection);
		EVENT_OFF(connection->t_routeadv);
		break;

	case Active:
		/* Active is waiting connection from remote peer.  And if
		   connect timer is expired, change status to Connect. */
		EVENT_OFF(connection->t_start);
		/* If peer is passive mode, do not set connect timer. */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSIVE)
		    || CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			EVENT_OFF(connection->t_connect);
		} else {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
				BGP_TIMER_ON(connection->t_connect,
					     bgp_connect_timer,
					     (peer->v_delayopen +
					      peer->v_connect));
			else
				BGP_TIMER_ON(connection->t_connect,
					     bgp_connect_timer, peer->v_connect);
		}
		EVENT_OFF(connection->t_holdtime);
		bgp_keepalives_off(connection);
		EVENT_OFF(connection->t_routeadv);
		break;

	case OpenSent:
		/* OpenSent status. */
		EVENT_OFF(connection->t_start);
		EVENT_OFF(connection->t_connect);
		if (peer->v_holdtime != 0) {
			BGP_TIMER_ON(connection->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
		} else {
			EVENT_OFF(connection->t_holdtime);
		}
		bgp_keepalives_off(connection);
		EVENT_OFF(connection->t_routeadv);
		EVENT_OFF(connection->t_delayopen);
		break;

	case OpenConfirm:
		/* OpenConfirm status. */
		EVENT_OFF(connection->t_start);
		EVENT_OFF(connection->t_connect);

		/*
		 * If the negotiated Hold Time value is zero, then the Hold Time
		 * timer and KeepAlive timers are not started.
		 * Additionally if a different hold timer has been negotiated
		 * than we must stop then start the timer again
		 */
		EVENT_OFF(connection->t_holdtime);
		if (peer->v_holdtime == 0)
			bgp_keepalives_off(connection);
		else {
			BGP_TIMER_ON(connection->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
			bgp_keepalives_on(connection);
		}
		EVENT_OFF(connection->t_routeadv);
		EVENT_OFF(connection->t_delayopen);
		break;

	case Established:
		/* In Established status start and connect timer is turned
		   off. */
		EVENT_OFF(connection->t_start);
		EVENT_OFF(connection->t_connect);
		EVENT_OFF(connection->t_delayopen);

		/*
		 * Same as OpenConfirm, if holdtime is zero then both holdtime
		 * and keepalive must be turned off.
		 * Additionally if a different hold timer has been negotiated
		 * then we must stop then start the timer again
		 */
		EVENT_OFF(connection->t_holdtime);
		if (peer->v_holdtime == 0)
			bgp_keepalives_off(connection);
		else {
			BGP_TIMER_ON(connection->t_holdtime, bgp_holdtime_timer,
				     peer->v_holdtime);
			bgp_keepalives_on(connection);
		}
		break;
	case Deleted:
		EVENT_OFF(peer->connection->t_gr_restart);
		EVENT_OFF(peer->connection->t_gr_stale);

		FOREACH_AFI_SAFI (afi, safi)
			EVENT_OFF(peer->t_llgr_stale[afi][safi]);

		EVENT_OFF(peer->connection->t_pmax_restart);
		EVENT_OFF(peer->t_refresh_stalepath);
		fallthrough;
	case Clearing:
		EVENT_OFF(connection->t_start);
		EVENT_OFF(connection->t_connect);
		EVENT_OFF(connection->t_holdtime);
		bgp_keepalives_off(connection);
		EVENT_OFF(connection->t_routeadv);
		EVENT_OFF(connection->t_delayopen);
		break;
	case BGP_STATUS_MAX:
		flog_err(EC_LIB_DEVELOPMENT,
			 "BGP_STATUS_MAX while a legal state is not valid state for the FSM");
		break;
	}
}

/* BGP start timer.  This function set BGP_Start event to thread value
   and process event. */
static void bgp_start_timer(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (start timer expire).", peer->host);

	EVENT_VAL(thread) = BGP_Start;
	bgp_event(thread); /* bgp_event unlocks peer */
}

/* BGP connect retry timer. */
static void bgp_connect_timer(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	/* stop the DelayOpenTimer if it is running */
	EVENT_OFF(connection->t_delayopen);

	assert(!connection->t_write);
	assert(!connection->t_read);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (connect timer expire)", peer->host);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
		bgp_stop(connection);
	else {
		EVENT_VAL(thread) = ConnectRetry_timer_expired;
		bgp_event(thread); /* bgp_event unlocks peer */
	}
}

/* BGP holdtime timer. */
static void bgp_holdtime_timer(struct event *thread)
{
	atomic_size_t inq_count;
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (holdtime timer expire)",
			   peer->host);

	/*
	 * Given that we do not have any expectation of ordering
	 * for handling packets from a peer -vs- handling
	 * the hold timer for a peer as that they are both
	 * events on the peer.  If we have incoming
	 * data on the peers inq, let's give the system a chance
	 * to handle that data.  This can be especially true
	 * for systems where we are heavily loaded for one
	 * reason or another.
	 */
	inq_count = atomic_load_explicit(&connection->ibuf->count,
					 memory_order_relaxed);
	if (inq_count)
		BGP_TIMER_ON(connection->t_holdtime, bgp_holdtime_timer,
			     peer->v_holdtime);

	EVENT_VAL(thread) = Hold_Timer_expired;
	bgp_event(thread); /* bgp_event unlocks peer */
}

void bgp_routeadv_timer(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (routeadv timer expire)", peer->host);

	peer->synctime = monotime(NULL);

	event_add_timer_msec(bm->master, bgp_generate_updgrp_packets, connection,
			     0, &connection->t_generate_updgrp_packets);

	/* MRAI timer will be started again when FIFO is built, no need to
	 * do it here.
	 */
}

/* RFC 4271 DelayOpenTimer */
void bgp_delayopen_timer(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Timer (DelayOpentimer expire)",
			   peer->host);

	EVENT_VAL(thread) = DelayOpen_timer_expired;
	bgp_event(thread); /* bgp_event unlocks peer */
}

/* BGP Peer Down Cause */
const char *const peer_down_str[] = {
	"",
	"Router ID changed",
	"Remote AS changed",
	"Local AS change",
	"Cluster ID changed",
	"Confederation identifier changed",
	"Confederation peer changed",
	"RR client config change",
	"RS client config change",
	"Update source change",
	"Address family activated",
	"Admin. shutdown",
	"User reset",
	"BGP Notification received",
	"BGP Notification send",
	"Peer closed the session",
	"Neighbor deleted",
	"Peer-group add member",
	"Peer-group delete member",
	"Capability changed",
	"Passive config change",
	"Multihop config change",
	"NSF peer closed the session",
	"Intf peering v6only config change",
	"BFD down received",
	"Interface down",
	"Neighbor address lost",
	"No path to specified Neighbor",
	"Waiting for Peer IPv6 LLA",
	"Waiting for VRF to be initialized",
	"No AFI/SAFI activated for peer",
	"AS Set config change",
	"Waiting for peer OPEN",
	"Reached received prefix count",
	"Socket Error",
	"Admin. shutdown (RTT)",
	"Suppress Fib Turned On or Off",
};

static void bgp_graceful_restart_timer_off(struct peer_connection *connection,
					   struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_LLGR_WAIT))
			return;

	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
	EVENT_OFF(connection->t_gr_stale);

	if (peer_dynamic_neighbor(peer) &&
	    !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
	}

	bgp_timer_set(connection);
}

static void bgp_llgr_stale_timer_expire(struct event *thread)
{
	struct peer_af *paf;
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	paf = EVENT_ARG(thread);

	peer = paf->peer;
	afi = paf->afi;
	safi = paf->safi;

	/* If the timer for the "Long-lived Stale Time" expires before the
	 * session is re-established, the helper MUST delete all the
	 * stale routes from the neighbor that it is retaining.
	 */
	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP Long-lived stale timer (%s) expired", peer,
			   get_afi_safi_str(afi, safi, false));

	UNSET_FLAG(peer->af_sflags[afi][safi], PEER_STATUS_LLGR_WAIT);

	bgp_clear_stale_route(peer, afi, safi);

	bgp_graceful_restart_timer_off(peer->connection, peer);
}

static void bgp_set_llgr_stale(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_table *table;
	struct attr attr;

	if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP || safi == SAFI_EVPN) {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest)) {
			struct bgp_dest *rm;

			table = bgp_dest_get_bgp_table_info(dest);
			if (!table)
				continue;

			for (rm = bgp_table_top(table); rm;
			     rm = bgp_route_next(rm))
				for (pi = bgp_dest_get_bgp_path_info(rm); pi;
				     pi = pi->next) {
					if (pi->peer != peer)
						continue;

					if (bgp_attr_get_community(pi->attr) &&
					    community_include(
						    bgp_attr_get_community(
							    pi->attr),
						    COMMUNITY_NO_LLGR))
						continue;

					if (bgp_debug_neighbor_events(peer))
						zlog_debug(
							"%pBP Long-lived set stale community (LLGR_STALE) for: %pFX",
							peer, &dest->rn->p);

					attr = *pi->attr;
					bgp_attr_add_llgr_community(&attr);
					pi->attr = bgp_attr_intern(&attr);
					bgp_recalculate_afi_safi_bestpaths(
						peer->bgp, afi, safi);

					break;
				}
		}
	} else {
		for (dest = bgp_table_top(peer->bgp->rib[afi][safi]); dest;
		     dest = bgp_route_next(dest))
			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				if (pi->peer != peer)
					continue;

				if (bgp_attr_get_community(pi->attr) &&
				    community_include(
					    bgp_attr_get_community(pi->attr),
					    COMMUNITY_NO_LLGR))
					continue;

				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%pBP Long-lived set stale community (LLGR_STALE) for: %pFX",
						peer, &dest->rn->p);

				attr = *pi->attr;
				bgp_attr_add_llgr_community(&attr);
				pi->attr = bgp_attr_intern(&attr);
				bgp_recalculate_afi_safi_bestpaths(peer->bgp,
								   afi, safi);

				break;
			}
	}
}

static void bgp_graceful_restart_timer_expire(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;
	struct peer *tmp_peer;
	struct listnode *node, *nnode;
	struct peer_af *paf;
	afi_t afi;
	safi_t safi;

	if (bgp_debug_neighbor_events(peer)) {
		zlog_debug("%pBP graceful restart timer expired", peer);
		zlog_debug("%pBP graceful restart stalepath timer stopped",
			   peer);
	}

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->nsf[afi][safi])
			continue;

		/* Once the "Restart Time" period ends, the LLGR period is
		 * said to have begun and the following procedures MUST be
		 * performed:
		 *
		 * The helper router MUST start a timer for the
		 * "Long-lived Stale Time".
		 *
		 * The helper router MUST attach the LLGR_STALE community
		 * for the stale routes being retained. Note that this
		 * requirement implies that the routes would need to be
		 * readvertised, to disseminate the modified community.
		 */
		if (peer->llgr[afi][safi].stale_time) {
			paf = peer_af_find(peer, afi, safi);
			if (!paf)
				continue;

			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP Long-lived stale timer (%s) started for %d sec",
					peer,
					get_afi_safi_str(afi, safi, false),
					peer->llgr[afi][safi].stale_time);

			SET_FLAG(peer->af_sflags[afi][safi],
				 PEER_STATUS_LLGR_WAIT);

			bgp_set_llgr_stale(peer, afi, safi);
			bgp_clear_stale_route(peer, afi, safi);

			event_add_timer(bm->master, bgp_llgr_stale_timer_expire,
					paf, peer->llgr[afi][safi].stale_time,
					&peer->t_llgr_stale[afi][safi]);

			for (ALL_LIST_ELEMENTS(peer->bgp->peer, node, nnode,
					       tmp_peer))
				bgp_announce_route(tmp_peer, afi, safi, false);
		} else {
			bgp_clear_stale_route(peer, afi, safi);
		}
	}

	bgp_graceful_restart_timer_off(connection, peer);
}

static void bgp_graceful_stale_timer_expire(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;
	afi_t afi;
	safi_t safi;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP graceful restart stalepath timer expired",
			   peer);

	/* NSF delete stale route */
	FOREACH_AFI_SAFI_NSF (afi, safi)
		if (peer->nsf[afi][safi])
			bgp_clear_stale_route(peer, afi, safi);
}

/* Selection deferral timer processing function */
static void bgp_graceful_deferral_timer_expire(struct event *thread)
{
	struct afi_safi_info *info;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;

	info = EVENT_ARG(thread);
	afi = info->afi;
	safi = info->safi;
	bgp = info->bgp;

	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug(
			"afi %d, safi %d : graceful restart deferral timer expired",
			afi, safi);

	bgp->gr_info[afi][safi].eor_required = 0;
	bgp->gr_info[afi][safi].eor_received = 0;
	XFREE(MTYPE_TMP, info);

	/* Best path selection */
	bgp_best_path_select_defer(bgp, afi, safi);
}

static bool bgp_update_delay_applicable(struct bgp *bgp)
{
	/* update_delay_over flag should be reset (set to 0) for any new
	   applicability of the update-delay during BGP process lifetime.
	   And it should be set after an occurence of the update-delay is
	   over)*/
	if (!bgp->update_delay_over)
		return true;
	return false;
}

bool bgp_update_delay_active(struct bgp *bgp)
{
	if (bgp->t_update_delay)
		return true;
	return false;
}

bool bgp_update_delay_configured(struct bgp *bgp)
{
	if (bgp->v_update_delay)
		return true;
	return false;
}

/* Do the post-processing needed when bgp comes out of the read-only mode
   on ending the update delay. */
void bgp_update_delay_end(struct bgp *bgp)
{
	EVENT_OFF(bgp->t_update_delay);
	EVENT_OFF(bgp->t_establish_wait);

	/* Reset update-delay related state */
	bgp->update_delay_over = 1;
	bgp->established = 0;
	bgp->restarted_peers = 0;
	bgp->implicit_eors = 0;
	bgp->explicit_eors = 0;

	frr_timestamp(3, bgp->update_delay_end_time,
		      sizeof(bgp->update_delay_end_time));

	/*
	 * Add an end-of-initial-update marker to the main process queues so
	 * that
	 * the route advertisement timer for the peers can be started. Also set
	 * the zebra and peer update hold flags. These flags are used to achieve
	 * three stages in the update-delay post processing:
	 *  1. Finish best-path selection for all the prefixes held on the
	 * queues.
	 *     (routes in BGP are updated, and peers sync queues are populated
	 * too)
	 *  2. As the eoiu mark is reached in the bgp process routine, ship all
	 * the
	 *     routes to zebra. With that zebra should see updates from BGP
	 * close
	 *     to each other.
	 *  3. Unblock the peer update writes. With that peer update packing
	 * with
	 *     the prefixes should be at its maximum.
	 */
	bgp_add_eoiu_mark(bgp);
	bgp->main_zebra_update_hold = 1;
	bgp->main_peers_update_hold = 1;

	/*
	 * Resume the queue processing. This should trigger the event that would
	 * take care of processing any work that was queued during the read-only
	 * mode.
	 */
	work_queue_unplug(bgp->process_queue);
}

/**
 * see bgp_fsm.h
 */
void bgp_start_routeadv(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	zlog_info("%s, update hold status %d", __func__,
		  bgp->main_peers_update_hold);

	if (bgp->main_peers_update_hold)
		return;

	frr_timestamp(3, bgp->update_delay_peers_resume_time,
		      sizeof(bgp->update_delay_peers_resume_time));

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		struct peer_connection *connection = peer->connection;

		if (!peer_established(connection))
			continue;

		EVENT_OFF(connection->t_routeadv);
		BGP_TIMER_ON(connection->t_routeadv, bgp_routeadv_timer, 0);
	}
}

/**
 * see bgp_fsm.h
 */
void bgp_adjust_routeadv(struct peer *peer)
{
	time_t nowtime = monotime(NULL);
	double diff;
	unsigned long remain;
	struct peer_connection *connection = peer->connection;

	/* Bypass checks for special case of MRAI being 0 */
	if (peer->v_routeadv == 0) {
		/* Stop existing timer, just in case it is running for a
		 * different
		 * duration and schedule write thread immediately.
		 */
		EVENT_OFF(connection->t_routeadv);

		peer->synctime = monotime(NULL);
		/* If suppress fib pending is enabled, route is advertised to
		 * peers when the status is received from the FIB. The delay
		 * is added to update group packet generate which will allow
		 * more routes to be sent in the update message
		 */
		BGP_UPDATE_GROUP_TIMER_ON(&connection->t_generate_updgrp_packets,
					  bgp_generate_updgrp_packets);
		return;
	}


	/*
	 * CASE I:
	 * If the last update was written more than MRAI back, expire the timer
	 * instantly so that we can send the update out sooner.
	 *
	 *                           <-------  MRAI --------->
	 *         |-----------------|-----------------------|
	 *         <------------- m ------------>
	 *         ^                 ^          ^
	 *         |                 |          |
	 *         |                 |     current time
	 *         |            timer start
	 *      last write
	 *
	 *                     m > MRAI
	 */
	diff = difftime(nowtime, peer->last_update);
	if (diff > (double)peer->v_routeadv) {
		EVENT_OFF(connection->t_routeadv);
		BGP_TIMER_ON(connection->t_routeadv, bgp_routeadv_timer, 0);
		return;
	}

	/*
	 * CASE II:
	 * - Find when to expire the MRAI timer.
	 *   If MRAI timer is not active, assume we can start it now.
	 *
	 *                      <-------  MRAI --------->
	 *         |------------|-----------------------|
	 *         <-------- m ----------><----- r ----->
	 *         ^            ^        ^
	 *         |            |        |
	 *         |            |   current time
	 *         |       timer start
	 *      last write
	 *
	 *                     (MRAI - m) < r
	 */
	if (connection->t_routeadv)
		remain = event_timer_remain_second(connection->t_routeadv);
	else
		remain = peer->v_routeadv;
	diff = peer->v_routeadv - diff;
	if (diff <= (double)remain) {
		EVENT_OFF(connection->t_routeadv);
		BGP_TIMER_ON(connection->t_routeadv, bgp_routeadv_timer, diff);
	}
}

static bool bgp_maxmed_onstartup_applicable(struct bgp *bgp)
{
	if (!bgp->maxmed_onstartup_over)
		return true;
	return false;
}

bool bgp_maxmed_onstartup_configured(struct bgp *bgp)
{
	if (bgp->v_maxmed_onstartup != BGP_MAXMED_ONSTARTUP_UNCONFIGURED)
		return true;
	return false;
}

bool bgp_maxmed_onstartup_active(struct bgp *bgp)
{
	if (bgp->t_maxmed_onstartup)
		return true;
	return false;
}

void bgp_maxmed_update(struct bgp *bgp)
{
	uint8_t maxmed_active;
	uint32_t maxmed_value;

	if (bgp->v_maxmed_admin) {
		maxmed_active = 1;
		maxmed_value = bgp->maxmed_admin_value;
	} else if (bgp->t_maxmed_onstartup) {
		maxmed_active = 1;
		maxmed_value = bgp->maxmed_onstartup_value;
	} else {
		maxmed_active = 0;
		maxmed_value = BGP_MAXMED_VALUE_DEFAULT;
	}

	if (bgp->maxmed_active != maxmed_active
	    || bgp->maxmed_value != maxmed_value) {
		bgp->maxmed_active = maxmed_active;
		bgp->maxmed_value = maxmed_value;

		update_group_announce(bgp);
	}
}

int bgp_fsm_error_subcode(int status)
{
	int fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_UNSPECIFIC;

	switch (status) {
	case OpenSent:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_OPENSENT;
		break;
	case OpenConfirm:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_OPENCONFIRM;
		break;
	case Established:
		fsm_err_subcode = BGP_NOTIFY_FSM_ERR_SUBCODE_ESTABLISHED;
		break;
	default:
		break;
	}

	return fsm_err_subcode;
}

/* The maxmed onstartup timer expiry callback. */
static void bgp_maxmed_onstartup_timer(struct event *thread)
{
	struct bgp *bgp;

	zlog_info("Max med on startup ended - timer expired.");

	bgp = EVENT_ARG(thread);
	EVENT_OFF(bgp->t_maxmed_onstartup);
	bgp->maxmed_onstartup_over = 1;

	bgp_maxmed_update(bgp);
}

static void bgp_maxmed_onstartup_begin(struct bgp *bgp)
{
	/* Applicable only once in the process lifetime on the startup */
	if (bgp->maxmed_onstartup_over)
		return;

	zlog_info("Begin maxmed onstartup mode - timer %d seconds",
		  bgp->v_maxmed_onstartup);

	event_add_timer(bm->master, bgp_maxmed_onstartup_timer, bgp,
			bgp->v_maxmed_onstartup, &bgp->t_maxmed_onstartup);

	if (!bgp->v_maxmed_admin) {
		bgp->maxmed_active = 1;
		bgp->maxmed_value = bgp->maxmed_onstartup_value;
	}

	/* Route announce to all peers should happen after this in
	 * bgp_establish() */
}

static void bgp_maxmed_onstartup_process_status_change(struct peer *peer)
{
	if (peer_established(peer->connection) && !peer->bgp->established) {
		bgp_maxmed_onstartup_begin(peer->bgp);
	}
}

/* The update delay timer expiry callback. */
static void bgp_update_delay_timer(struct event *thread)
{
	struct bgp *bgp;

	zlog_info("Update delay ended - timer expired.");

	bgp = EVENT_ARG(thread);
	EVENT_OFF(bgp->t_update_delay);
	bgp_update_delay_end(bgp);
}

/* The establish wait timer expiry callback. */
static void bgp_establish_wait_timer(struct event *thread)
{
	struct bgp *bgp;

	zlog_info("Establish wait - timer expired.");

	bgp = EVENT_ARG(thread);
	EVENT_OFF(bgp->t_establish_wait);
	bgp_check_update_delay(bgp);
}

/* Steps to begin the update delay:
     - initialize queues if needed
     - stop the queue processing
     - start the timer */
static void bgp_update_delay_begin(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	/* Stop the processing of queued work. Enqueue shall continue */
	work_queue_plug(bgp->process_queue);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		peer->update_delay_over = 0;

	/* Start the update-delay timer */
	event_add_timer(bm->master, bgp_update_delay_timer, bgp,
			bgp->v_update_delay, &bgp->t_update_delay);

	if (bgp->v_establish_wait != bgp->v_update_delay)
		event_add_timer(bm->master, bgp_establish_wait_timer, bgp,
				bgp->v_establish_wait, &bgp->t_establish_wait);

	frr_timestamp(3, bgp->update_delay_begin_time,
		      sizeof(bgp->update_delay_begin_time));
}

static void bgp_update_delay_process_status_change(struct peer *peer)
{
	if (peer_established(peer->connection)) {
		if (!peer->bgp->established++) {
			bgp_update_delay_begin(peer->bgp);
			zlog_info(
				"Begin read-only mode - update-delay timer %d seconds",
				peer->bgp->v_update_delay);
		}
		if (CHECK_FLAG(peer->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV))
			bgp_update_restarted_peers(peer);
	}
	if (peer->connection->ostatus == Established &&
	    bgp_update_delay_active(peer->bgp)) {
		/* Adjust the update-delay state to account for this flap.
		   NOTE: Intentionally skipping adjusting implicit_eors or
		   explicit_eors
		   counters. Extra sanity check in bgp_check_update_delay()
		   should
		   be enough to take care of any additive discrepancy in bgp eor
		   counters */
		peer->bgp->established--;
		peer->update_delay_over = 0;
	}
}

/* Called after event occurred, this function change status and reset
   read/write and timer thread. */
void bgp_fsm_change_status(struct peer_connection *connection,
			   enum bgp_fsm_status status)
{
	struct peer *peer = connection->peer;
	struct bgp *bgp = peer->bgp;
	uint32_t peer_count;

	peer_count = bgp->established_peers;

	if (status == Established)
		bgp->established_peers++;
	else if ((peer_established(connection)) && (status != Established))
		bgp->established_peers--;

	if (bgp_debug_neighbor_events(peer)) {
		struct vrf *vrf = vrf_lookup_by_id(bgp->vrf_id);

		zlog_debug("%s : vrf %s(%u), Status: %s established_peers %u", __func__,
			   vrf ? vrf->name : "Unknown", bgp->vrf_id,
			   lookup_msg(bgp_status_msg, status, NULL),
			   bgp->established_peers);
	}

	/* Set to router ID to the value provided by RIB if there are no peers
	 * in the established state and peer count did not change
	 */
	if ((peer_count != bgp->established_peers) &&
	    (bgp->established_peers == 0))
		bgp_router_id_zebra_bump(bgp->vrf_id, NULL);

	/* Transition into Clearing or Deleted must /always/ clear all routes..
	 * (and must do so before actually changing into Deleted..
	 */
	if (status >= Clearing) {
		bgp_clear_route_all(peer);

		/* If no route was queued for the clear-node processing,
		 * generate the
		 * completion event here. This is needed because if there are no
		 * routes
		 * to trigger the background clear-node thread, the event won't
		 * get
		 * generated and the peer would be stuck in Clearing. Note that
		 * this
		 * event is for the peer and helps the peer transition out of
		 * Clearing
		 * state; it should not be generated per (AFI,SAFI). The event
		 * is
		 * directly posted here without calling clear_node_complete() as
		 * we
		 * shouldn't do an extra unlock. This event will get processed
		 * after
		 * the state change that happens below, so peer will be in
		 * Clearing
		 * (or Deleted).
		 */
		if (!work_queue_is_scheduled(peer->clear_node_queue) &&
		    status != Deleted)
			BGP_EVENT_ADD(connection, Clearing_Completed);
	}

	/* Preserve old status and change into new status. */
	connection->ostatus = connection->status;
	connection->status = status;

	/* Reset received keepalives counter on every FSM change */
	peer->rtt_keepalive_rcv = 0;

	/* Fire backward transition hook if that's the case */
	if (connection->ostatus == Established &&
	    connection->status != Established)
		hook_call(peer_backward_transition, peer);

	/* Save event that caused status change. */
	peer->last_major_event = peer->cur_event;

	/* Operations after status change */
	hook_call(peer_status_changed, peer);

	if (status == Established)
		UNSET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);

	/* If max-med processing is applicable, do the necessary. */
	if (status == Established) {
		if (bgp_maxmed_onstartup_configured(peer->bgp)
		    && bgp_maxmed_onstartup_applicable(peer->bgp))
			bgp_maxmed_onstartup_process_status_change(peer);
		else
			peer->bgp->maxmed_onstartup_over = 1;
	}

	/* If update-delay processing is applicable, do the necessary. */
	if (bgp_update_delay_configured(peer->bgp)
	    && bgp_update_delay_applicable(peer->bgp))
		bgp_update_delay_process_status_change(peer);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s fd %d went from %s to %s", peer->host,
			   connection->fd,
			   lookup_msg(bgp_status_msg, connection->ostatus, NULL),
			   lookup_msg(bgp_status_msg, connection->status, NULL));
}

/* Flush the event queue and ensure the peer is shut down */
static enum bgp_fsm_state_progress
bgp_clearing_completed(struct peer_connection *connection)
{
	enum bgp_fsm_state_progress rc = bgp_stop(connection);

	if (rc >= BGP_FSM_SUCCESS)
		event_cancel_event_ready(bm->master, connection);

	return rc;
}

/* Administrative BGP peer stop event. */
/* May be called multiple times for the same peer */
enum bgp_fsm_state_progress bgp_stop(struct peer_connection *connection)
{
	afi_t afi;
	safi_t safi;
	char orf_name[BUFSIZ];
	enum bgp_fsm_state_progress ret = BGP_FSM_SUCCESS;
	struct peer *peer = connection->peer;
	struct bgp *bgp = peer->bgp;
	struct graceful_restart_info *gr_info = NULL;

	peer->nsf_af_count = 0;

	/* deregister peer */
	if (peer->bfd_config
	    && peer->last_reset == PEER_DOWN_UPDATE_SOURCE_CHANGE)
		bfd_sess_uninstall(peer->bfd_config->session);

	if (peer_dynamic_neighbor_no_nsf(peer) &&
	    !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return BGP_FSM_FAILURE_AND_DELETE;
	}

	/* Can't do this in Clearing; events are used for state transitions */
	if (connection->status != Clearing) {
		/* Delete all existing events of the peer */
		event_cancel_event_ready(bm->master, connection);
	}

	/* Increment Dropped count. */
	if (peer_established(connection)) {
		peer->dropped++;

		/* Notify BGP conditional advertisement process */
		peer->advmap_table_change = true;

		/* bgp log-neighbor-changes of neighbor Down */
		if (CHECK_FLAG(peer->bgp->flags,
			       BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
			struct vrf *vrf = vrf_lookup_by_id(peer->bgp->vrf_id);

			zlog_info(
				"%%ADJCHANGE: neighbor %pBP in vrf %s Down %s",
				peer,
				vrf ? ((vrf->vrf_id != VRF_DEFAULT)
					       ? vrf->name
					       : VRF_DEFAULT_NAME)
				    : "",
				peer_down_str[(int)peer->last_reset]);
		}

		/* graceful restart */
		if (connection->t_gr_stale) {
			EVENT_OFF(connection->t_gr_stale);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP graceful restart stalepath timer stopped",
					peer);
		}
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {
			if (bgp_debug_neighbor_events(peer)) {
				zlog_debug(
					"%pBP graceful restart timer started for %d sec",
					peer, peer->v_gr_restart);
				zlog_debug(
					"%pBP graceful restart stalepath timer started for %d sec",
					peer, peer->bgp->stalepath_time);
			}
			BGP_TIMER_ON(connection->t_gr_restart,
				     bgp_graceful_restart_timer_expire,
				     peer->v_gr_restart);
			BGP_TIMER_ON(connection->t_gr_stale,
				     bgp_graceful_stale_timer_expire,
				     peer->bgp->stalepath_time);
		} else {
			UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

			FOREACH_AFI_SAFI_NSF (afi, safi)
				peer->nsf[afi][safi] = 0;
		}

		/* Stop route-refresh stalepath timer */
		if (peer->t_refresh_stalepath) {
			EVENT_OFF(peer->t_refresh_stalepath);

			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP route-refresh restart stalepath timer stopped",
					peer);
		}

		/* If peer reset before receiving EOR, decrement EOR count and
		 * cancel the selection deferral timer if there are no
		 * pending EOR messages to be received
		 */
		if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (!peer->afc_nego[afi][safi]
				    || CHECK_FLAG(peer->af_sflags[afi][safi],
						  PEER_STATUS_EOR_RECEIVED))
					continue;

				gr_info = &bgp->gr_info[afi][safi];
				if (!gr_info)
					continue;

				if (gr_info->eor_required)
					gr_info->eor_required--;

				if (BGP_DEBUG(update, UPDATE_OUT))
					zlog_debug("peer %s, EOR_required %d",
						   peer->host,
						   gr_info->eor_required);

				/* There is no pending EOR message */
				if (gr_info->eor_required == 0) {
					if (gr_info->t_select_deferral) {
						void *info = EVENT_ARG(
							gr_info->t_select_deferral);
						XFREE(MTYPE_TMP, info);
					}
					EVENT_OFF(gr_info->t_select_deferral);
					gr_info->eor_received = 0;
				}
			}
		}

		/* set last reset time */
		peer->resettime = peer->uptime = monotime(NULL);

		if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
			zlog_debug("%s remove from all update group",
				   peer->host);
		update_group_remove_peer_afs(peer);

		/* Reset peer synctime */
		peer->synctime = 0;
	}

	/* stop keepalives */
	bgp_keepalives_off(connection);

	/* Stop read and write threads. */
	bgp_writes_off(connection);
	bgp_reads_off(connection);

	EVENT_OFF(connection->t_connect_check_r);
	EVENT_OFF(connection->t_connect_check_w);

	/* Stop all timers. */
	EVENT_OFF(connection->t_start);
	EVENT_OFF(connection->t_connect);
	EVENT_OFF(connection->t_holdtime);
	EVENT_OFF(connection->t_routeadv);
	EVENT_OFF(peer->connection->t_delayopen);

	/* Clear input and output buffer.  */
	frr_with_mutex (&connection->io_mtx) {
		if (connection->ibuf)
			stream_fifo_clean(connection->ibuf);
		if (connection->obuf)
			stream_fifo_clean(connection->obuf);

		if (connection->ibuf_work)
			ringbuf_wipe(connection->ibuf_work);

		if (peer->curr) {
			stream_free(peer->curr);
			peer->curr = NULL;
		}
	}

	/* Close of file descriptor. */
	if (connection->fd >= 0) {
		close(connection->fd);
		connection->fd = -1;
	}

	/* Reset capabilities. */
	peer->cap = 0;

	/* Resetting neighbor role to the default value */
	peer->remote_role = ROLE_UNDEFINED;

	FOREACH_AFI_SAFI (afi, safi) {
		/* Reset all negotiated variables */
		peer->afc_nego[afi][safi] = 0;
		peer->afc_adv[afi][safi] = 0;
		peer->afc_recv[afi][safi] = 0;

		/* peer address family capability flags*/
		peer->af_cap[afi][safi] = 0;

		/* peer address family status flags*/
		peer->af_sflags[afi][safi] = 0;

		/* Received ORF prefix-filter */
		peer->orf_plist[afi][safi] = NULL;

		if ((connection->status == OpenConfirm) ||
		    peer_established(connection)) {
			/* ORF received prefix-filter pnt */
			snprintf(orf_name, sizeof(orf_name), "%s.%d.%d",
				 peer->host, afi, safi);
			prefix_bgp_orf_remove_all(afi, orf_name);
		}
	}

	/* Reset keepalive and holdtime */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER)) {
		peer->v_keepalive = peer->keepalive;
		peer->v_holdtime = peer->holdtime;
	} else {
		peer->v_keepalive = peer->bgp->default_keepalive;
		peer->v_holdtime = peer->bgp->default_holdtime;
	}

	/* Reset DelayOpenTime */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
		peer->v_delayopen = peer->delayopen;
	else
		peer->v_delayopen = peer->bgp->default_delayopen;

	peer->update_time = 0;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE)
	    && !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE))) {
		peer_delete(peer);
		ret = BGP_FSM_FAILURE_AND_DELETE;
	} else {
		bgp_peer_conf_if_to_su_update(connection);
	}
	return ret;
}

/* BGP peer is stoped by the error. */
static enum bgp_fsm_state_progress
bgp_stop_with_error(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	/* Double start timer. */
	peer->v_start *= 2;

	/* Overflow check. */
	if (peer->v_start >= (60 * 2))
		peer->v_start = (60 * 2);

	if (peer_dynamic_neighbor_no_nsf(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return BGP_FSM_FAILURE;
	}

	return bgp_stop(connection);
}


/* something went wrong, send notify and tear down */
static enum bgp_fsm_state_progress
bgp_stop_with_notify(struct peer_connection *connection, uint8_t code,
		     uint8_t sub_code)
{
	struct peer *peer = connection->peer;

	/* Send notify to remote peer */
	bgp_notify_send(connection, code, sub_code);

	if (peer_dynamic_neighbor_no_nsf(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return BGP_FSM_FAILURE;
	}

	/* Clear start timer value to default. */
	peer->v_start = BGP_INIT_START_TIMER;

	return bgp_stop(connection);
}

/**
 * Determines whether a TCP session has successfully established for a peer and
 * events as appropriate.
 *
 * This function is called when setting up a new session. After connect() is
 * called on the peer's socket (in bgp_start()), the fd is passed to poll()
 * to wait for connection success or failure. When poll() returns, this
 * function is called to evaluate the result.
 *
 * Due to differences in behavior of poll() on Linux and BSD - specifically,
 * the value of .revents in the case of a closed connection - this function is
 * scheduled both for a read and a write event. The write event is triggered
 * when the connection is established. A read event is triggered when the
 * connection is closed. Thus we need to cancel whichever one did not occur.
 */
static void bgp_connect_check(struct event *thread)
{
	int status;
	socklen_t slen;
	int ret;
	struct peer_connection *connection = EVENT_ARG(thread);
	struct peer *peer = connection->peer;

	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_READS_ON));
	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!connection->t_read);
	assert(!connection->t_write);

	EVENT_OFF(connection->t_connect_check_r);
	EVENT_OFF(connection->t_connect_check_w);

	/* Check file descriptor. */
	slen = sizeof(status);
	ret = getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, (void *)&status,
			 &slen);

	/* If getsockopt is fail, this is fatal error. */
	if (ret < 0) {
		zlog_err("can't get sockopt for nonblocking connect: %d(%s)",
			  errno, safe_strerror(errno));
		BGP_EVENT_ADD(connection, TCP_fatal_error);
		return;
	}

	/* When status is 0 then TCP connection is established. */
	if (status == 0) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
			BGP_EVENT_ADD(connection,
				      TCP_connection_open_w_delay);
		else
			BGP_EVENT_ADD(connection, TCP_connection_open);
		return;
	} else {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [Event] Connect failed %d(%s)",
				   peer->host, status, safe_strerror(status));
		BGP_EVENT_ADD(connection, TCP_connection_open_failed);
		return;
	}
}

/* TCP connection open.  Next we send open message to remote peer. And
   add read thread for reading open message. */
static enum bgp_fsm_state_progress
bgp_connect_success(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (connection->fd < 0) {
		flog_err(EC_BGP_CONNECT, "%s peer's fd is negative value %d",
			 __func__, connection->fd);
		return bgp_stop(connection);
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: bgp_getsockname(): failed for peer %s, fd %d",
			     __func__, peer->host, connection->fd);
		bgp_notify_send(peer->connection, BGP_NOTIFY_FSM_ERR,
				bgp_fsm_error_subcode(connection->status));
		bgp_writes_on(connection);
		return BGP_FSM_FAILURE;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	bgp_reads_on(connection);

	if (bgp_debug_neighbor_events(peer)) {
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
			zlog_debug("%s open active, local address %pSU",
				   peer->host, peer->su_local);
		else
			zlog_debug("%s passive open", peer->host);
	}

	/* Send an open message */
	bgp_open_send(connection);

	return BGP_FSM_SUCCESS;
}

/* TCP connection open with RFC 4271 optional session attribute DelayOpen flag
 * set.
 */
static enum bgp_fsm_state_progress
bgp_connect_success_w_delayopen(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (connection->fd < 0) {
		flog_err(EC_BGP_CONNECT, "%s: peer's fd is negative value %d",
			 __func__, connection->fd);
		return bgp_stop(connection);
	}

	if (bgp_getsockname(peer) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: bgp_getsockname(): failed for peer %s, fd %d",
			     __func__, peer->host, connection->fd);
		bgp_notify_send(peer->connection, BGP_NOTIFY_FSM_ERR,
				bgp_fsm_error_subcode(connection->status));
		bgp_writes_on(connection);
		return BGP_FSM_FAILURE;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	bgp_reads_on(connection);

	if (bgp_debug_neighbor_events(peer)) {
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
			zlog_debug("%s open active, local address %pSU",
				   peer->host, peer->su_local);
		else
			zlog_debug("%s passive open", peer->host);
	}

	/* set the DelayOpenTime to the inital value */
	peer->v_delayopen = peer->delayopen;

	/* Start the DelayOpenTimer if it is not already running */
	if (!peer->connection->t_delayopen)
		BGP_TIMER_ON(peer->connection->t_delayopen, bgp_delayopen_timer,
			     peer->v_delayopen);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] BGP OPEN message delayed for %d seconds",
			   peer->host, peer->delayopen);

	return BGP_FSM_SUCCESS;
}

/* TCP connect fail */
static enum bgp_fsm_state_progress
bgp_connect_fail(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (peer_dynamic_neighbor(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s (dynamic neighbor) deleted (%s)",
				   peer->host, __func__);
		peer_delete(peer);
		return BGP_FSM_FAILURE_AND_DELETE;
	}

	/*
	 * If we are doing nht for a peer that ls v6 LL based
	 * massage the event system to make things happy
	 */
	bgp_nht_interface_events(peer);

	return bgp_stop(connection);
}

/* This function is the first starting point of all BGP connection. It
 * try to connect to remote peer with non-blocking IO.
 */
static enum bgp_fsm_state_progress bgp_start(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
	int status;

	bgp_peer_conf_if_to_su_update(connection);

	if (connection->su.sa.sa_family == AF_UNSPEC) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s [FSM] Unable to get neighbor's IP address, waiting...",
				peer->host);
		peer->last_reset = PEER_DOWN_NBR_ADDR;
		return BGP_FSM_FAILURE;
	}

	if (BGP_PEER_START_SUPPRESSED(peer)) {
		if (bgp_debug_neighbor_events(peer))
			flog_err(EC_BGP_FSM,
				 "%s [FSM] Trying to start suppressed peer - this is never supposed to happen!",
				 peer->host);
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_RTT_SHUTDOWN))
			peer->last_reset = PEER_DOWN_RTT_SHUTDOWN;
		else if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
			peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
		else if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHUTDOWN))
			peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
		else if (CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
			peer->last_reset = PEER_DOWN_PFX_COUNT;
		return BGP_FSM_FAILURE;
	}

	/* Clear remote router-id. */
	peer->remote_id.s_addr = INADDR_ANY;

	/* Clear peer capability flag. */
	peer->cap = 0;

	if (peer->bgp->vrf_id == VRF_UNKNOWN) {
		if (bgp_debug_neighbor_events(peer))
			flog_err(
				EC_BGP_FSM,
				"%s [FSM] In a VRF that is not initialised yet",
				peer->host);
		peer->last_reset = PEER_DOWN_VRF_UNINIT;
		return BGP_FSM_FAILURE;
	}

	/* Register peer for NHT. If next hop is already resolved, proceed
	 * with connection setup, else wait.
	 */
	if (!bgp_peer_reg_with_nht(peer)) {
		if (bgp_zebra_num_connects()) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s [FSM] Waiting for NHT, no path to neighbor present",
					peer->host);
			peer->last_reset = PEER_DOWN_WAITING_NHT;
			BGP_EVENT_ADD(connection, TCP_connection_open_failed);
			return BGP_FSM_SUCCESS;
		}
	}

	assert(!connection->t_write);
	assert(!connection->t_read);
	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_WRITES_ON));
	assert(!CHECK_FLAG(connection->thread_flags, PEER_THREAD_READS_ON));
	status = bgp_connect(connection);

	switch (status) {
	case connect_error:
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [FSM] Connect error", peer->host);
		BGP_EVENT_ADD(connection, TCP_connection_open_failed);
		break;
	case connect_success:
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [FSM] Connect immediately success, fd %d",
				   peer->host, connection->fd);

		BGP_EVENT_ADD(connection, TCP_connection_open);
		break;
	case connect_in_progress:
		/* To check nonblocking connect, we wait until socket is
		   readable or writable. */
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [FSM] Non blocking connect waiting result, fd %d",
				   peer->host, connection->fd);
		if (connection->fd < 0) {
			flog_err(EC_BGP_FSM, "%s peer's fd is negative value %d",
				 __func__, peer->connection->fd);
			return BGP_FSM_FAILURE;
		}
		/*
		 * - when the socket becomes ready, poll() will signify POLLOUT
		 * - if it fails to connect, poll() will signify POLLHUP
		 * - POLLHUP is handled as a 'read' event by thread.c
		 *
		 * therefore, we schedule both a read and a write event with
		 * bgp_connect_check() as the handler for each and cancel the
		 * unused event in that function.
		 */
		event_add_read(bm->master, bgp_connect_check, connection,
			       connection->fd, &connection->t_connect_check_r);
		event_add_write(bm->master, bgp_connect_check, connection,
				connection->fd, &connection->t_connect_check_w);
		break;
	}
	return BGP_FSM_SUCCESS;
}

/* Connect retry timer is expired when the peer status is Connect. */
static enum bgp_fsm_state_progress
bgp_reconnect(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
	enum bgp_fsm_state_progress ret;

	ret = bgp_stop(connection);
	if (ret < BGP_FSM_SUCCESS)
		return ret;

	/* Send graceful restart capabilty */
	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp,
							  peer->bgp->peer);

	return bgp_start(connection);
}

static enum bgp_fsm_state_progress
bgp_fsm_open(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	/* If DelayOpen is active, we may still need to send an open message */
	if ((connection->status == Connect) || (connection->status == Active))
		bgp_open_send(connection);

	/* Send keepalive and make keepalive timer */
	bgp_keepalive_send(peer);

	return BGP_FSM_SUCCESS;
}

/* FSM error, unexpected event.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static enum bgp_fsm_state_progress
bgp_fsm_event_error(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	flog_err(EC_BGP_FSM, "%s [FSM] unexpected packet received in state %s",
		 peer->host,
		 lookup_msg(bgp_status_msg, connection->status, NULL));

	return bgp_stop_with_notify(connection, BGP_NOTIFY_FSM_ERR,
				    bgp_fsm_error_subcode(connection->status));
}

/* Hold timer expire.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static enum bgp_fsm_state_progress
bgp_fsm_holdtime_expire(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s [FSM] Hold timer expire", peer->host);

	/* RFC8538 updates RFC 4724 by defining an extension that permits
	 * the Graceful Restart procedures to be performed when the BGP
	 * speaker receives a BGP NOTIFICATION message or the Hold Time expires.
	 */
	if (peer_established(connection) &&
	    bgp_has_graceful_restart_notification(peer))
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE))
			SET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);

	return bgp_stop_with_notify(connection, BGP_NOTIFY_HOLD_ERR, 0);
}

/* RFC 4271 DelayOpenTimer_Expires event */
static enum bgp_fsm_state_progress
bgp_fsm_delayopen_timer_expire(struct peer_connection *connection)
{
	/* Stop the DelayOpenTimer */
	EVENT_OFF(connection->t_delayopen);

	/* Send open message to peer */
	bgp_open_send(connection);

	/* Set the HoldTimer to a large value (4 minutes) */
	connection->peer->v_holdtime = 245;

	return BGP_FSM_SUCCESS;
}

/* Start the selection deferral timer thread for the specified AFI, SAFI */
static int bgp_start_deferral_timer(struct bgp *bgp, afi_t afi, safi_t safi,
				    struct graceful_restart_info *gr_info)
{
	struct afi_safi_info *thread_info;

	/* If the deferral timer is active, then increment eor count */
	if (gr_info->t_select_deferral) {
		gr_info->eor_required++;
		return 0;
	}

	/* Start the deferral timer when the first peer enabled for the graceful
	 * restart is established
	 */
	if (gr_info->eor_required == 0) {
		thread_info = XMALLOC(MTYPE_TMP, sizeof(struct afi_safi_info));

		thread_info->afi = afi;
		thread_info->safi = safi;
		thread_info->bgp = bgp;

		event_add_timer(bm->master, bgp_graceful_deferral_timer_expire,
				thread_info, bgp->select_defer_time,
				&gr_info->t_select_deferral);
	}
	gr_info->eor_required++;
	/* Send message to RIB indicating route update pending */
	if (gr_info->af_enabled[afi][safi] == false) {
		gr_info->af_enabled[afi][safi] = true;
		/* Send message to RIB */
		bgp_zebra_update(bgp, afi, safi,
				 ZEBRA_CLIENT_ROUTE_UPDATE_PENDING);
	}
	if (BGP_DEBUG(update, UPDATE_OUT))
		zlog_debug("Started the deferral timer for %s eor_required %d",
			   get_afi_safi_str(afi, safi, false),
			   gr_info->eor_required);
	return 0;
}

/* Update the graceful restart information for the specified AFI, SAFI */
static int bgp_update_gr_info(struct peer *peer, afi_t afi, safi_t safi)
{
	struct graceful_restart_info *gr_info;
	struct bgp *bgp = peer->bgp;
	int ret = 0;

	if ((afi < AFI_IP) || (afi >= AFI_MAX)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s : invalid afi %d", __func__, afi);
		return -1;
	}

	if ((safi < SAFI_UNICAST) || (safi > SAFI_MPLS_VPN)) {
		if (BGP_DEBUG(update, UPDATE_OUT))
			zlog_debug("%s : invalid safi %d", __func__, safi);
		return -1;
	}

	/* Restarting router */
	if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)
	    && BGP_PEER_RESTARTING_MODE(peer)) {
		/* Check if the forwarding state is preserved */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD)) {
			gr_info = &(bgp->gr_info[afi][safi]);
			ret = bgp_start_deferral_timer(bgp, afi, safi, gr_info);
		}
	}
	return ret;
}

/**
 * Transition to Established state.
 *
 * Convert peer from stub to full fledged peer, set some timers, and generate
 * initial updates.
 */
static enum bgp_fsm_state_progress
bgp_establish(struct peer_connection *connection)
{
	afi_t afi;
	safi_t safi;
	int nsf_af_count = 0;
	enum bgp_fsm_state_progress ret = BGP_FSM_SUCCESS;
	struct peer *other;
	int status;
	struct peer *peer = connection->peer;
	struct peer *orig = peer;

	other = peer->doppelganger;
	hash_release(peer->bgp->peerhash, peer);
	if (other)
		hash_release(peer->bgp->peerhash, other);

	peer = peer_xfer_conn(peer);
	if (!peer) {
		flog_err(EC_BGP_CONNECT, "%%Neighbor failed in xfer_conn");

		/*
		 * A failure of peer_xfer_conn but not putting the peers
		 * back in the hash ends up with a situation where incoming
		 * connections are rejected, as that the peer is not found
		 * when a lookup is done
		 */
		(void)hash_get(orig->bgp->peerhash, orig, hash_alloc_intern);
		if (other)
			(void)hash_get(other->bgp->peerhash, other,
				       hash_alloc_intern);
		return BGP_FSM_FAILURE;
	}
	/*
	 * At this point the connections have been possibly swapped
	 * let's reset it.
	 */
	connection = peer->connection;

	if (other == peer)
		ret = BGP_FSM_SUCCESS_STATE_TRANSFER;

	/* Reset capability open status flag. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN))
		SET_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

	/* Clear start timer value to default. */
	peer->v_start = BGP_INIT_START_TIMER;

	/* Increment established count. */
	peer->established++;
	bgp_fsm_change_status(connection, Established);

	/* bgp log-neighbor-changes of neighbor Up */
	if (CHECK_FLAG(peer->bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES)) {
		struct vrf *vrf = vrf_lookup_by_id(peer->bgp->vrf_id);
		zlog_info("%%ADJCHANGE: neighbor %pBP in vrf %s Up", peer,
			  vrf ? ((vrf->vrf_id != VRF_DEFAULT)
					 ? vrf->name
					 : VRF_DEFAULT_NAME)
			      : "");
	}
	/* assign update-group/subgroup */
	update_group_adjust_peer_afs(peer);

	/* graceful restart */
	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
	if (bgp_debug_neighbor_events(peer)) {
		if (BGP_PEER_RESTARTING_MODE(peer))
			zlog_debug("%pBP BGP_RESTARTING_MODE", peer);
		else if (BGP_PEER_HELPER_MODE(peer))
			zlog_debug("%pBP BGP_HELPER_MODE", peer);
	}

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (peer->afc_nego[afi][safi] &&
		    CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_RESTART_AF_RCV)) {
			if (peer->nsf[afi][safi] &&
			    !CHECK_FLAG(peer->af_cap[afi][safi],
					PEER_CAP_RESTART_AF_PRESERVE_RCV))
				bgp_clear_stale_route(peer, afi, safi);

			peer->nsf[afi][safi] = 1;
			nsf_af_count++;
		} else {
			if (peer->nsf[afi][safi])
				bgp_clear_stale_route(peer, afi, safi);
			peer->nsf[afi][safi] = 0;
		}
		/* Update the graceful restart information */
		if (peer->afc_nego[afi][safi]) {
			if (!BGP_SELECT_DEFER_DISABLE(peer->bgp)) {
				status = bgp_update_gr_info(peer, afi, safi);
				if (status < 0)
					zlog_err(
						"Error in updating graceful restart for %s",
						get_afi_safi_str(afi, safi,
								 false));
			} else {
				if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer) &&
				    BGP_PEER_RESTARTING_MODE(peer) &&
				    CHECK_FLAG(peer->bgp->flags,
					       BGP_FLAG_GR_PRESERVE_FWD))
					peer->bgp->gr_info[afi][safi]
						.eor_required++;
			}
		}
	}

	if (!CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {
		if ((bgp_peer_gr_mode_get(peer) == PEER_GR)
		    || ((bgp_peer_gr_mode_get(peer) == PEER_GLOBAL_INHERIT)
			&& (bgp_global_gr_mode_get(peer->bgp) == GLOBAL_GR))) {
			FOREACH_AFI_SAFI (afi, safi)
				/* Send route processing complete
				   message to RIB */
				bgp_zebra_update(
					peer->bgp, afi, safi,
					ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE);
		}
	} else {
		/* Peer sends R-bit. In this case, we need to send
		 * ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE to Zebra. */
		if (CHECK_FLAG(peer->cap,
			       PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV)) {
			FOREACH_AFI_SAFI (afi, safi)
				/* Send route processing complete
				   message to RIB */
				bgp_zebra_update(
					peer->bgp, afi, safi,
					ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE);
		}
	}

	peer->nsf_af_count = nsf_af_count;

	if (nsf_af_count)
		SET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);
	else {
		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);
		if (connection->t_gr_stale) {
			EVENT_OFF(connection->t_gr_stale);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP graceful restart stalepath timer stopped",
					peer);
		}
	}

	if (connection->t_gr_restart) {
		EVENT_OFF(connection->t_gr_restart);
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%pBP graceful restart timer stopped", peer);
	}

	/* Reset uptime, turn on keepalives, send current table. */
	if (!peer->v_holdtime)
		bgp_keepalives_on(connection);

	peer->uptime = monotime(NULL);

	/* Send route-refresh when ORF is enabled.
	 * Stop Long-lived Graceful Restart timers.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->t_llgr_stale[afi][safi]) {
			EVENT_OFF(peer->t_llgr_stale[afi][safi]);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%pBP Long-lived stale timer stopped for afi/safi: %d/%d",
					peer, afi, safi);
		}

		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV)) {
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_RM_RCV))
				bgp_route_refresh_send(
					peer, afi, safi, ORF_TYPE_PREFIX,
					REFRESH_IMMEDIATE, 0,
					BGP_ROUTE_REFRESH_NORMAL);
		}
	}

	/* First update is deferred until ORF or ROUTE-REFRESH is received */
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV))
			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_SM_RCV))
				SET_FLAG(peer->af_sflags[afi][safi],
					 PEER_STATUS_ORF_WAIT_REFRESH);
	}

	bgp_announce_peer(peer);

	/* Start the route advertisement timer to send updates to the peer - if
	 * BGP
	 * is not in read-only mode. If it is, the timer will be started at the
	 * end
	 * of read-only mode.
	 */
	if (!bgp_update_delay_active(peer->bgp)) {
		EVENT_OFF(peer->connection->t_routeadv);
		BGP_TIMER_ON(peer->connection->t_routeadv, bgp_routeadv_timer,
			     0);
	}

	if (peer->doppelganger &&
	    (peer->doppelganger->connection->status != Deleted)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"[Event] Deleting stub connection for peer %s",
				peer->host);

		if (peer->doppelganger->connection->status > Active)
			bgp_notify_send(peer->doppelganger->connection,
					BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
		else
			peer_delete(peer->doppelganger);
	}

	/*
	 * If we are replacing the old peer for a doppelganger
	 * then switch it around in the bgp->peerhash
	 * the doppelgangers su and this peer's su are the same
	 * so the hash_release is the same for either.
	 */
	(void)hash_get(peer->bgp->peerhash, peer, hash_alloc_intern);

	/* Start BFD peer if not already running. */
	if (peer->bfd_config)
		bgp_peer_bfd_update_source(peer);

	return ret;
}

/* Keepalive packet is received. */
static enum bgp_fsm_state_progress
bgp_fsm_keepalive(struct peer_connection *connection)
{
	EVENT_OFF(connection->t_holdtime);
	return BGP_FSM_SUCCESS;
}

/* Update packet is received. */
static enum bgp_fsm_state_progress
bgp_fsm_update(struct peer_connection *connection)
{
	EVENT_OFF(connection->t_holdtime);
	return BGP_FSM_SUCCESS;
}

/* This is empty event. */
static enum bgp_fsm_state_progress bgp_ignore(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	flog_err(EC_BGP_FSM,
		 "%s [FSM] Ignoring event %s in state %s, prior events %s, %s, fd %d",
		 peer->host, bgp_event_str[peer->cur_event],
		 lookup_msg(bgp_status_msg, connection->status, NULL),
		 bgp_event_str[peer->last_event],
		 bgp_event_str[peer->last_major_event], connection->fd);
	return BGP_FSM_SUCCESS;
}

/* This is to handle unexpected events.. */
static enum bgp_fsm_state_progress
bgp_fsm_exception(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	flog_err(EC_BGP_FSM,
		 "%s [FSM] Unexpected event %s in state %s, prior events %s, %s, fd %d",
		 peer->host, bgp_event_str[peer->cur_event],
		 lookup_msg(bgp_status_msg, connection->status, NULL),
		 bgp_event_str[peer->last_event],
		 bgp_event_str[peer->last_major_event], connection->fd);
	return bgp_stop(connection);
}

void bgp_fsm_nht_update(struct peer_connection *connection, struct peer *peer,
			bool has_valid_nexthops)
{
	if (!peer)
		return;

	switch (connection->status) {
	case Idle:
		if (has_valid_nexthops)
			BGP_EVENT_ADD(connection, BGP_Start);
		break;
	case Connect:
		if (!has_valid_nexthops) {
			EVENT_OFF(connection->t_connect);
			BGP_EVENT_ADD(connection, TCP_fatal_error);
		}
		break;
	case Active:
		if (has_valid_nexthops) {
			EVENT_OFF(connection->t_connect);
			BGP_EVENT_ADD(connection, ConnectRetry_timer_expired);
		}
		break;
	case OpenSent:
	case OpenConfirm:
	case Established:
		if (!has_valid_nexthops
		    && (peer->gtsm_hops == BGP_GTSM_HOPS_CONNECTED
			|| peer->bgp->fast_convergence))
			BGP_EVENT_ADD(connection, TCP_fatal_error);
		break;
	case Clearing:
	case Deleted:
	case BGP_STATUS_MAX:
		break;
	}
}

/* Finite State Machine structure */
static const struct {
	enum bgp_fsm_state_progress (*func)(struct peer_connection *);
	enum bgp_fsm_status next_state;
} FSM[BGP_STATUS_MAX - 1][BGP_EVENTS_MAX - 1] = {
	{
		/* Idle state: In Idle state, all events other than BGP_Start is
		   ignored.  With BGP_Start event, finite state machine calls
		   bgp_start(). */
		{bgp_start, Connect}, /* BGP_Start                    */
		{bgp_stop, Idle},     /* BGP_Stop                     */
		{bgp_stop, Idle},     /* TCP_connection_open          */
		{bgp_stop, Idle},     /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},     /* TCP_connection_closed        */
		{bgp_ignore, Idle},   /* TCP_connection_open_failed   */
		{bgp_stop, Idle},     /* TCP_fatal_error              */
		{bgp_ignore, Idle},   /* ConnectRetry_timer_expired   */
		{bgp_ignore, Idle},   /* Hold_Timer_expired           */
		{bgp_ignore, Idle},   /* KeepAlive_timer_expired      */
		{bgp_ignore, Idle},   /* DelayOpen_timer_expired */
		{bgp_ignore, Idle},   /* Receive_OPEN_message         */
		{bgp_ignore, Idle},   /* Receive_KEEPALIVE_message    */
		{bgp_ignore, Idle},   /* Receive_UPDATE_message       */
		{bgp_ignore, Idle},   /* Receive_NOTIFICATION_message */
		{bgp_ignore, Idle},   /* Clearing_Completed           */
	},
	{
		/* Connect */
		{bgp_ignore, Connect}, /* BGP_Start                    */
		{bgp_stop, Idle},      /* BGP_Stop                     */
		{bgp_connect_success, OpenSent}, /* TCP_connection_open */
		{bgp_connect_success_w_delayopen,
		 Connect},		    /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	    /* TCP_connection_closed        */
		{bgp_connect_fail, Active}, /* TCP_connection_open_failed   */
		{bgp_connect_fail, Idle},   /* TCP_fatal_error              */
		{bgp_reconnect, Connect},   /* ConnectRetry_timer_expired   */
		{bgp_fsm_exception, Idle},  /* Hold_Timer_expired           */
		{bgp_fsm_exception, Idle},  /* KeepAlive_timer_expired      */
		{bgp_fsm_delayopen_timer_expire,
		 OpenSent},		     /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_exception, Idle},   /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exception, Idle},   /* Receive_UPDATE_message       */
		{bgp_stop, Idle},	     /* Receive_NOTIFICATION_message */
		{bgp_fsm_exception, Idle},   /* Clearing_Completed           */
	},
	{
		/* Active, */
		{bgp_ignore, Active}, /* BGP_Start                    */
		{bgp_stop, Idle},     /* BGP_Stop                     */
		{bgp_connect_success, OpenSent}, /* TCP_connection_open */
		{bgp_connect_success_w_delayopen,
		 Active},		   /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	   /* TCP_connection_closed        */
		{bgp_ignore, Active},	   /* TCP_connection_open_failed   */
		{bgp_fsm_exception, Idle}, /* TCP_fatal_error              */
		{bgp_start, Connect},	   /* ConnectRetry_timer_expired   */
		{bgp_fsm_exception, Idle}, /* Hold_Timer_expired           */
		{bgp_fsm_exception, Idle}, /* KeepAlive_timer_expired      */
		{bgp_fsm_delayopen_timer_expire,
		 OpenSent},		     /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_exception, Idle},   /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exception, Idle},   /* Receive_UPDATE_message       */
		{bgp_fsm_exception, Idle},   /* Receive_NOTIFICATION_message */
		{bgp_fsm_exception, Idle},   /* Clearing_Completed           */
	},
	{
		/* OpenSent, */
		{bgp_ignore, OpenSent},	   /* BGP_Start                    */
		{bgp_stop, Idle},	   /* BGP_Stop                     */
		{bgp_stop, Active},	   /* TCP_connection_open          */
		{bgp_fsm_exception, Idle}, /* TCP_connection_open_w_delay */
		{bgp_stop, Active},	   /* TCP_connection_closed        */
		{bgp_stop, Active},	   /* TCP_connection_open_failed   */
		{bgp_stop, Active},	   /* TCP_fatal_error              */
		{bgp_fsm_exception, Idle}, /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Idle}, /* Hold_Timer_expired */
		{bgp_fsm_exception, Idle},   /* KeepAlive_timer_expired      */
		{bgp_fsm_exception, Idle},   /* DelayOpen_timer_expired */
		{bgp_fsm_open, OpenConfirm}, /* Receive_OPEN_message         */
		{bgp_fsm_event_error, Idle}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_event_error, Idle}, /* Receive_UPDATE_message       */
		{bgp_fsm_event_error, Idle}, /* Receive_NOTIFICATION_message */
		{bgp_fsm_exception, Idle},   /* Clearing_Completed           */
	},
	{
		/* OpenConfirm, */
		{bgp_ignore, OpenConfirm}, /* BGP_Start                    */
		{bgp_stop, Idle},	   /* BGP_Stop                     */
		{bgp_stop, Idle},	   /* TCP_connection_open          */
		{bgp_fsm_exception, Idle}, /* TCP_connection_open_w_delay */
		{bgp_stop, Idle},	   /* TCP_connection_closed        */
		{bgp_stop, Idle},	   /* TCP_connection_open_failed   */
		{bgp_stop, Idle},	   /* TCP_fatal_error              */
		{bgp_fsm_exception, Idle}, /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Idle}, /* Hold_Timer_expired */
		{bgp_ignore, OpenConfirm},    /* KeepAlive_timer_expired      */
		{bgp_fsm_exception, Idle},    /* DelayOpen_timer_expired */
		{bgp_fsm_exception, Idle},    /* Receive_OPEN_message         */
		{bgp_establish, Established}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_exception, Idle},    /* Receive_UPDATE_message       */
		{bgp_stop_with_error, Idle},  /* Receive_NOTIFICATION_message */
		{bgp_fsm_exception, Idle},    /* Clearing_Completed           */
	},
	{
		/* Established, */
		{bgp_ignore, Established}, /* BGP_Start                    */
		{bgp_stop, Clearing},	   /* BGP_Stop                     */
		{bgp_stop, Clearing},	   /* TCP_connection_open          */
		{bgp_fsm_exception, Idle}, /* TCP_connection_open_w_delay */
		{bgp_stop, Clearing},	   /* TCP_connection_closed        */
		{bgp_stop, Clearing},	   /* TCP_connection_open_failed   */
		{bgp_stop, Clearing},	   /* TCP_fatal_error              */
		{bgp_stop, Clearing},	   /* ConnectRetry_timer_expired   */
		{bgp_fsm_holdtime_expire, Clearing}, /* Hold_Timer_expired */
		{bgp_ignore, Established}, /* KeepAlive_timer_expired      */
		{bgp_fsm_exception, Idle}, /* DelayOpen_timer_expired */
		{bgp_stop, Clearing},	   /* Receive_OPEN_message         */
		{bgp_fsm_keepalive,
		 Established}, /* Receive_KEEPALIVE_message    */
		{bgp_fsm_update, Established}, /* Receive_UPDATE_message */
		{bgp_stop_with_error,
		 Clearing},		   /* Receive_NOTIFICATION_message */
		{bgp_fsm_exception, Idle}, /* Clearing_Completed           */
	},
	{
		/* Clearing, */
		{bgp_ignore, Clearing}, /* BGP_Start                    */
		{bgp_stop, Clearing},	/* BGP_Stop                     */
		{bgp_stop, Clearing},	/* TCP_connection_open          */
		{bgp_stop, Clearing},	/* TCP_connection_open_w_delay */
		{bgp_stop, Clearing},	/* TCP_connection_closed        */
		{bgp_stop, Clearing},	/* TCP_connection_open_failed   */
		{bgp_stop, Clearing},	/* TCP_fatal_error              */
		{bgp_stop, Clearing},	/* ConnectRetry_timer_expired   */
		{bgp_stop, Clearing},	/* Hold_Timer_expired           */
		{bgp_stop, Clearing},	/* KeepAlive_timer_expired      */
		{bgp_stop, Clearing},	/* DelayOpen_timer_expired */
		{bgp_stop, Clearing},	/* Receive_OPEN_message         */
		{bgp_stop, Clearing},	/* Receive_KEEPALIVE_message    */
		{bgp_stop, Clearing},	/* Receive_UPDATE_message       */
		{bgp_stop, Clearing},	/* Receive_NOTIFICATION_message */
		{bgp_clearing_completed, Idle}, /* Clearing_Completed */
	},
	{
		/* Deleted, */
		{bgp_ignore, Deleted}, /* BGP_Start                    */
		{bgp_ignore, Deleted}, /* BGP_Stop                     */
		{bgp_ignore, Deleted}, /* TCP_connection_open          */
		{bgp_ignore, Deleted}, /* TCP_connection_open_w_delay */
		{bgp_ignore, Deleted}, /* TCP_connection_closed        */
		{bgp_ignore, Deleted}, /* TCP_connection_open_failed   */
		{bgp_ignore, Deleted}, /* TCP_fatal_error              */
		{bgp_ignore, Deleted}, /* ConnectRetry_timer_expired   */
		{bgp_ignore, Deleted}, /* Hold_Timer_expired           */
		{bgp_ignore, Deleted}, /* KeepAlive_timer_expired      */
		{bgp_ignore, Deleted}, /* DelayOpen_timer_expired */
		{bgp_ignore, Deleted}, /* Receive_OPEN_message         */
		{bgp_ignore, Deleted}, /* Receive_KEEPALIVE_message    */
		{bgp_ignore, Deleted}, /* Receive_UPDATE_message       */
		{bgp_ignore, Deleted}, /* Receive_NOTIFICATION_message */
		{bgp_ignore, Deleted}, /* Clearing_Completed           */
	},
};

/* Execute event process. */
void bgp_event(struct event *thread)
{
	struct peer_connection *connection = EVENT_ARG(thread);
	enum bgp_fsm_events event;
	struct peer *peer = connection->peer;

	event = EVENT_VAL(thread);

	peer_lock(peer);
	bgp_event_update(connection, event);
	peer_unlock(peer);
}

int bgp_event_update(struct peer_connection *connection,
		     enum bgp_fsm_events event)
{
	enum bgp_fsm_status next;
	enum bgp_fsm_state_progress ret = 0;
	int fsm_result = FSM_PEER_NOOP;
	int passive_conn = 0;
	int dyn_nbr;
	struct peer *peer = connection->peer;

	passive_conn =
		(CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)) ? 1 : 0;
	dyn_nbr = peer_dynamic_neighbor(peer);

	/* Logging this event. */
	next = FSM[connection->status - 1][event - 1].next_state;

	if (bgp_debug_neighbor_events(peer) && connection->status != next)
		zlog_debug("%s [FSM] %s (%s->%s), fd %d", peer->host,
			   bgp_event_str[event],
			   lookup_msg(bgp_status_msg, connection->status, NULL),
			   lookup_msg(bgp_status_msg, next, NULL),
			   connection->fd);

	peer->last_event = peer->cur_event;
	peer->cur_event = event;

	/* Call function. */
	if (FSM[connection->status - 1][event - 1].func)
		ret = (*(FSM[connection->status - 1][event - 1].func))(
			connection);

	switch (ret) {
	case BGP_FSM_SUCCESS:
	case BGP_FSM_SUCCESS_STATE_TRANSFER:
		if (ret == BGP_FSM_SUCCESS_STATE_TRANSFER &&
		    next == Established) {
			/* The case when doppelganger swap accurred in
			   bgp_establish.
			   Update the peer pointer accordingly */
			fsm_result = FSM_PEER_TRANSFERRED;
		}

		/* If status is changed. */
		if (next != connection->status) {
			bgp_fsm_change_status(connection, next);

			/*
			 * If we're going to ESTABLISHED then we executed a
			 * peer transfer. In this case we can either return
			 * FSM_PEER_TRANSITIONED or FSM_PEER_TRANSFERRED.
			 * Opting for TRANSFERRED since transfer implies
			 * session establishment.
			 */
			if (fsm_result != FSM_PEER_TRANSFERRED)
				fsm_result = FSM_PEER_TRANSITIONED;
		}

		/* Make sure timer is set. */
		bgp_timer_set(connection);
		break;
	case BGP_FSM_FAILURE:
		/*
		 * If we got a return value of -1, that means there was an
		 * error, restart the FSM. Since bgp_stop() was called on the
		 * peer. only a few fields are safe to access here. In any case
		 * we need to indicate that the peer was stopped in the return
		 * code.
		 */
		if (!dyn_nbr && !passive_conn && peer->bgp &&
		    ret != BGP_FSM_FAILURE_AND_DELETE) {
			flog_err(EC_BGP_FSM,
				 "%s [FSM] Failure handling event %s in state %s, prior events %s, %s, fd %d, last reset: %s",
				 peer->host, bgp_event_str[peer->cur_event],
				 lookup_msg(bgp_status_msg, connection->status,
					    NULL),
				 bgp_event_str[peer->last_event],
				 bgp_event_str[peer->last_major_event],
				 connection->fd,
				 peer_down_str[peer->last_reset]);
			bgp_stop(connection);
			bgp_fsm_change_status(connection, Idle);
			bgp_timer_set(connection);
		}
		fsm_result = FSM_PEER_STOPPED;
		break;
	case BGP_FSM_FAILURE_AND_DELETE:
		fsm_result = FSM_PEER_STOPPED;
		break;
	}

	return fsm_result;
}
/* BGP GR Code */

int bgp_gr_lookup_n_update_all_peer(struct bgp *bgp,
				    enum global_mode global_new_state,
				    enum global_mode global_old_state)
{
	struct peer *peer = {0};
	struct listnode *node = {0};
	struct listnode *nnode = {0};
	enum peer_mode peer_old_state = PEER_INVALID;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug("%s [BGP_GR] Peer: (%s) :", __func__,
				   peer->host);

		peer_old_state = bgp_peer_gr_mode_get(peer);

		if (peer_old_state == PEER_GLOBAL_INHERIT) {

			/*
			 *Reset only these peers and send a
			 *new open message with the change capabilities.
			 *Considering the mode to be "global_new_state" and
			 *do all operation accordingly
			 */

			switch (global_new_state) {
			case GLOBAL_HELPER:
				BGP_PEER_GR_HELPER_ENABLE(peer);
				break;
			case GLOBAL_GR:
				BGP_PEER_GR_ENABLE(peer);
				break;
			case GLOBAL_DISABLE:
				BGP_PEER_GR_DISABLE(peer);
				break;
			case GLOBAL_INVALID:
				zlog_debug("%s [BGP_GR] GLOBAL_INVALID",
					   __func__);
				return BGP_ERR_GR_OPERATION_FAILED;
			}
		}
	}

	bgp->global_gr_present_state = global_new_state;

	return BGP_GR_SUCCESS;
}

int bgp_gr_update_all(struct bgp *bgp, enum global_gr_command global_gr_cmd)
{
	enum global_mode global_new_state = GLOBAL_INVALID;
	enum global_mode global_old_state = GLOBAL_INVALID;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s [BGP_GR]START: global_gr_cmd :%s:", __func__,
			   print_global_gr_cmd(global_gr_cmd));

	global_old_state = bgp_global_gr_mode_get(bgp);

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("[BGP_GR] global_old_gr_state :%s:",
			   print_global_gr_mode(global_old_state));

	if (global_old_state != GLOBAL_INVALID) {
		global_new_state =
			bgp->GLOBAL_GR_FSM[global_old_state][global_gr_cmd];

		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug("[BGP_GR] global_new_gr_state :%s:",
				   print_global_gr_mode(global_new_state));
	} else {
		zlog_err("%s [BGP_GR] global_old_state == GLOBAL_INVALID",
			 __func__);
		return BGP_ERR_GR_OPERATION_FAILED;
	}

	if (global_new_state == GLOBAL_INVALID) {
		zlog_err("%s [BGP_GR] global_new_state == GLOBAL_INVALID",
			 __func__);
		return BGP_ERR_GR_INVALID_CMD;
	}
	if (global_new_state == global_old_state) {
		/* Trace msg */
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"%s [BGP_GR] global_new_state == global_old_state :%s",
				__func__,
				print_global_gr_mode(global_new_state));
		return BGP_GR_NO_OPERATION;
	}

	return bgp_gr_lookup_n_update_all_peer(bgp, global_new_state,
					       global_old_state);
}

const char *print_peer_gr_mode(enum peer_mode pr_mode)
{
	const char *peer_gr_mode = NULL;

	switch (pr_mode) {
	case PEER_HELPER:
		peer_gr_mode = "PEER_HELPER";
		break;
	case PEER_GR:
		peer_gr_mode = "PEER_GR";
		break;
	case PEER_DISABLE:
		peer_gr_mode = "PEER_DISABLE";
		break;
	case PEER_INVALID:
		peer_gr_mode = "PEER_INVALID";
		break;
	case PEER_GLOBAL_INHERIT:
		peer_gr_mode = "PEER_GLOBAL_INHERIT";
		break;
	}

	return peer_gr_mode;
}

const char *print_peer_gr_cmd(enum peer_gr_command pr_gr_cmd)
{
	const char *peer_gr_cmd = NULL;

	switch (pr_gr_cmd) {
	case PEER_GR_CMD:
		peer_gr_cmd = "PEER_GR_CMD";
		break;
	case NO_PEER_GR_CMD:
		peer_gr_cmd = "NO_PEER_GR_CMD";
		break;
	case PEER_DISABLE_CMD:
		peer_gr_cmd = "PEER_DISABLE_GR_CMD";
		break;
	case NO_PEER_DISABLE_CMD:
		peer_gr_cmd = "NO_PEER_DISABLE_GR_CMD";
		break;
	case PEER_HELPER_CMD:
		peer_gr_cmd = "PEER_HELPER_CMD";
		break;
	case NO_PEER_HELPER_CMD:
		peer_gr_cmd = "NO_PEER_HELPER_CMD";
		break;
	}

	return peer_gr_cmd;
}

const char *print_global_gr_mode(enum global_mode gl_mode)
{
	const char *global_gr_mode = "???";

	switch (gl_mode) {
	case GLOBAL_HELPER:
		global_gr_mode = "GLOBAL_HELPER";
		break;
	case GLOBAL_GR:
		global_gr_mode = "GLOBAL_GR";
		break;
	case GLOBAL_DISABLE:
		global_gr_mode = "GLOBAL_DISABLE";
		break;
	case GLOBAL_INVALID:
		global_gr_mode = "GLOBAL_INVALID";
		break;
	}

	return global_gr_mode;
}

const char *print_global_gr_cmd(enum global_gr_command gl_gr_cmd)
{
	const char *global_gr_cmd = NULL;

	switch (gl_gr_cmd) {
	case GLOBAL_GR_CMD:
		global_gr_cmd = "GLOBAL_GR_CMD";
		break;
	case NO_GLOBAL_GR_CMD:
		global_gr_cmd = "NO_GLOBAL_GR_CMD";
		break;
	case GLOBAL_DISABLE_CMD:
		global_gr_cmd = "GLOBAL_DISABLE_CMD";
		break;
	case NO_GLOBAL_DISABLE_CMD:
		global_gr_cmd = "NO_GLOBAL_DISABLE_CMD";
		break;
	}

	return global_gr_cmd;
}

enum global_mode bgp_global_gr_mode_get(struct bgp *bgp)
{
	return bgp->global_gr_present_state;
}

enum peer_mode bgp_peer_gr_mode_get(struct peer *peer)
{
	return peer->peer_gr_present_state;
}

int bgp_neighbor_graceful_restart(struct peer *peer,
				  enum peer_gr_command peer_gr_cmd)
{
	enum peer_mode peer_new_state = PEER_INVALID;
	enum peer_mode peer_old_state = PEER_INVALID;
	struct bgp_peer_gr peer_state;
	int result = BGP_GR_FAILURE;

	/*
	 * fetch peer_old_state from peer structure also
	 * fetch global_old_state from bgp structure,
	 * peer had a back pointer to bgpo struct ;
	 */

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s [BGP_GR] START:Peer: (%s) : peer_gr_cmd :%s:",
			   __func__, peer->host,
			   print_peer_gr_cmd(peer_gr_cmd));

	peer_old_state = bgp_peer_gr_mode_get(peer);

	if (peer_old_state == PEER_INVALID) {
		zlog_debug("[BGP_GR] peer_old_state == Invalid state !");
		return BGP_ERR_GR_OPERATION_FAILED;
	}

	peer_state = peer->PEER_GR_FSM[peer_old_state][peer_gr_cmd];
	peer_new_state = peer_state.next_state;

	if (peer_new_state == PEER_INVALID) {
		zlog_debug(
			"[BGP_GR] Invalid bgp graceful restart command used !");
		return BGP_ERR_GR_INVALID_CMD;
	}

	if (peer_new_state != peer_old_state) {
		result = peer_state.action_fun(peer, peer_old_state,
					       peer_new_state);
	} else {
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"[BGP_GR] peer_old_state == peer_new_state !");
		return BGP_GR_NO_OPERATION;
	}

	if (result == BGP_GR_SUCCESS) {

		/* Update the mode i.e peer_new_state into the peer structure */
		peer->peer_gr_present_state = peer_new_state;
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug(
				"[BGP_GR] Successfully change the state of the peer to : %s : !",
				print_peer_gr_mode(peer_new_state));

		return BGP_GR_SUCCESS;
	}

	return result;
}

unsigned int bgp_peer_gr_action(struct peer *peer, enum peer_mode old_peer_state,
				enum peer_mode new_peer_state)
{
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"%s [BGP_GR] Move peer from old_peer_state :%s: to new_peer_state :%s: !!!!",
			__func__, print_peer_gr_mode(old_peer_state),
			print_peer_gr_mode(new_peer_state));

	enum global_mode bgp_gr_global_mode = GLOBAL_INVALID;
	unsigned int ret = BGP_GR_FAILURE;

	if (old_peer_state == new_peer_state) {
		/* Nothing to do over here as the present and old state is the
		 * same */
		return BGP_GR_NO_OPERATION;
	}
	if ((old_peer_state == PEER_INVALID)
	    || (new_peer_state == PEER_INVALID)) {
		/* something bad happend , print error message */
		return BGP_ERR_GR_INVALID_CMD;
	}

	bgp_gr_global_mode = bgp_global_gr_mode_get(peer->bgp);

	if ((old_peer_state == PEER_GLOBAL_INHERIT)
	    && (new_peer_state != PEER_GLOBAL_INHERIT)) {

		/* fetch the Mode running in the Global state machine
		 *from the bgp structure into a variable called
		 *bgp_gr_global_mode
		 */

		/* Here we are checking if the
		 *1. peer_new_state == global_mode == helper_mode
		 *2. peer_new_state == global_mode == GR_mode
		 *3. peer_new_state == global_mode == disabled_mode
		 */

		BGP_PEER_GR_GLOBAL_INHERIT_UNSET(peer);

		if ((int)new_peer_state == (int)bgp_gr_global_mode) {
			/* This is incremental updates i.e no tear down
			 * of the existing session
			 * as the peer is already working in the same mode.
			 */
			ret = BGP_GR_SUCCESS;
		} else {
			if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
				zlog_debug(
					"[BGP_GR] Peer state changed from :%s ",
					print_peer_gr_mode(old_peer_state));

			bgp_peer_move_to_gr_mode(peer, new_peer_state);

			ret = BGP_GR_SUCCESS;
		}
	}
	/* In the case below peer is going into Global inherit mode i.e.
	 * the peer would work as the mode configured at the global level
	 */
	else if ((new_peer_state == PEER_GLOBAL_INHERIT)
		 && (old_peer_state != PEER_GLOBAL_INHERIT)) {
		/* Here in this case it would be destructive
		 * in all the cases except one case when,
		 * Global GR is configured Disabled
		 * and present_peer_state is not disable
		 */

		BGP_PEER_GR_GLOBAL_INHERIT_SET(peer);

		if ((int)old_peer_state == (int)bgp_gr_global_mode) {
			/* This is incremental updates
			 *i.e no tear down of the existing session
			 *as the peer is already working in the same mode.
			 */
			ret = BGP_GR_SUCCESS;
		} else {
			/*  Destructive always */
			/*  Tear down the old session
			 *  and send the new capability
			 *  as per the bgp_gr_global_mode
			 */

			if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
				zlog_debug(
					"[BGP_GR] Peer state changed from :%s",
					print_peer_gr_mode(old_peer_state));

			bgp_peer_move_to_gr_mode(peer, bgp_gr_global_mode);

			ret = BGP_GR_SUCCESS;
		}
	} else {
		/*
		 *This else case, it include all the cases except -->
		 *(new_peer_state != Peer_Global) &&
		 *( old_peer_state != Peer_Global )
		 */
		if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
			zlog_debug("[BGP_GR] Peer state changed from :%s",
				   print_peer_gr_mode(old_peer_state));

		bgp_peer_move_to_gr_mode(peer, new_peer_state);

		ret = BGP_GR_SUCCESS;
	}

	return ret;
}

inline void bgp_peer_move_to_gr_mode(struct peer *peer, int new_state)

{
	int bgp_global_gr_mode = bgp_global_gr_mode_get(peer->bgp);

	switch (new_state) {
	case PEER_HELPER:
		BGP_PEER_GR_HELPER_ENABLE(peer);
		break;
	case PEER_GR:
		BGP_PEER_GR_ENABLE(peer);
		break;
	case PEER_DISABLE:
		BGP_PEER_GR_DISABLE(peer);
		break;
	case PEER_GLOBAL_INHERIT:
		BGP_PEER_GR_GLOBAL_INHERIT_SET(peer);

		if (bgp_global_gr_mode == GLOBAL_HELPER) {
			BGP_PEER_GR_HELPER_ENABLE(peer);
		} else if (bgp_global_gr_mode == GLOBAL_GR) {
			BGP_PEER_GR_ENABLE(peer);
		} else if (bgp_global_gr_mode == GLOBAL_DISABLE) {
			BGP_PEER_GR_DISABLE(peer);
		} else {
			zlog_err(
				"[BGP_GR] Default switch inherit mode ::: SOMETHING IS WRONG !!!");
		}
		break;
	default:
		zlog_err(
			"[BGP_GR] Default switch mode ::: SOMETHING IS WRONG !!!");
		break;
	}
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("[BGP_GR] Peer state changed  --to-->  : %d : !",
			   new_state);
}

void bgp_peer_gr_flags_update(struct peer *peer)
{
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s [BGP_GR] called !", __func__);
	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_HELPER))
		SET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER);
	else
		UNSET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER);
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"[BGP_GR] Peer %s Flag PEER_FLAG_GRACEFUL_RESTART_HELPER : %s : !",
			peer->host,
			(CHECK_FLAG(peer->flags,
				    PEER_FLAG_GRACEFUL_RESTART_HELPER)
				 ? "Set"
				 : "UnSet"));
	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_RESTART))
		SET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART);
	else
		UNSET_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART);
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"[BGP_GR] Peer %s Flag PEER_FLAG_GRACEFUL_RESTART : %s : !",
			peer->host,
			(CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART)
				 ? "Set"
				 : "UnSet"));
	if (CHECK_FLAG(peer->peer_gr_new_status_flag,
		       PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT))
		SET_FLAG(peer->flags,
			 PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT);
	else
		UNSET_FLAG(peer->flags,
			   PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT);
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug(
			"[BGP_GR] Peer %s Flag PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT : %s : !",
			peer->host,
			(CHECK_FLAG(peer->flags,
				    PEER_FLAG_GRACEFUL_RESTART_GLOBAL_INHERIT)
				 ? "Set"
				 : "UnSet"));

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART)
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART_HELPER)) {
		zlog_debug("[BGP_GR] Peer %s UNSET PEER_STATUS_NSF_MODE!",
			   peer->host);

		UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT)) {

			peer_nsf_stop(peer);
			zlog_debug(
				"[BGP_GR] Peer %s UNSET PEER_STATUS_NSF_WAIT!",
				peer->host);
		}
	}
}
