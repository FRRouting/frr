// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * bgp_bfd.c: BGP BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "frrevent.h"
#include "buffer.h"
#include "stream.h"
#include "vrf.h"
#include "zclient.h"
#include "bfd.h"
#include "lib/json.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgp_fsm.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_trace.h"
#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_bfd_clippy.c"
#endif

DEFINE_MTYPE_STATIC(BGPD, BFD_CONFIG, "BFD configuration data");

extern struct zclient *bgp_zclient;

/* BFD Strict mode Hold timer expire */
static void bgp_bfd_strict_holdtime_expire(struct event *event)
{
	struct peer *peer = EVENT_ARG(event);
	struct peer_connection *connection = peer->connection;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP BFD Strict mode Hold timer expire for %s", peer,
			   bgp_peer_get_connection_direction_string(connection));

	peer_set_last_reset(peer, PEER_DOWN_BFD_DOWN);
	SET_FLAG(peer->sflags, PEER_STATUS_BFD_STRICT_HOLD_TIME_EXPIRED);

	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_BFD_DOWN);

	BGP_EVENT_ADD(peer->connection, BGP_Stop);
}

bool bgp_bfd_strict_hold_start(struct peer *peer)
{
	struct peer_connection *connection = peer->connection;

	if (!peer->bfd_config || !CHECK_FLAG(peer->flags, PEER_FLAG_BFD_STRICT))
		return false;

	/* The session was installed when the peer was created, before the local
	 * address and the outgoing interface were known. Resolve them now:
	 * correcting them once the connection proceeds removes the session and
	 * installs a new one, and that new session starts down - tearing down
	 * the very peer this hold is waiting for.
	 */
	if (bgp_getsockname(connection) == 0)
		bgp_peer_bfd_update_source(peer);

	if (bfd_session_is_up(peer->bfd_config->session))
		return false;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP BFD strict mode, holding incoming connection until BFD is up for %s",
			   peer, bgp_peer_get_connection_direction_string(connection));

	SET_FLAG(peer->sflags, PEER_STATUS_BFD_STRICT_HOLD);

	event_cancel(&connection->t_connect);
	event_cancel(&peer->bfd_config->t_hold_timer);
	event_add_timer(bm->master, bgp_bfd_strict_holdtime_expire, peer,
			peer->bfd_config->hold_time, &peer->bfd_config->t_hold_timer);

	return true;
}

void bgp_bfd_strict_hold_release(struct peer *peer)
{
	struct peer_connection *connection = peer->connection;

	UNSET_FLAG(peer->sflags, PEER_STATUS_BFD_STRICT_HOLD);

	if (peer->bfd_config)
		event_cancel(&peer->bfd_config->t_hold_timer);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%pBP BFD is up, releasing connection held by BFD strict mode for %s",
			   peer, bgp_peer_get_connection_direction_string(connection));

	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER_DELAYOPEN))
		BGP_EVENT_ADD(connection, TCP_connection_open_w_delay);
	else
		BGP_EVENT_ADD(connection, TCP_connection_open);
}

static void bfd_session_status_update(struct bfd_session_params *bsp,
				      const struct bfd_session_status *bss,
				      void *arg)
{
	struct peer *peer = arg;
	bool local_cbit = bfd_sess_cbit(bsp);

	if (BGP_DEBUG(bfd, BFD_LIB))
		zlog_debug("%s: neighbor %s vrf %s(%u) bfd state %s -> %s",
			   __func__, peer->conf_if ? peer->conf_if : peer->host,
			   bfd_sess_vrf(bsp), bfd_sess_vrf_id(bsp),
			   bfd_get_status_str(bss->previous_state),
			   bfd_get_status_str(bss->state));

	frrtrace(6, frr_bgp, bfd_session_status_update,
		 peer->conf_if ? peer->conf_if : peer->host,
		 bfd_sess_vrf_id(bsp), bss->previous_state, bss->state,
		 local_cbit, bss->remote_cbit);

	/*
	 * Handle Admin Down from peer separately.
	 * When BFD receives Admin Down from peer, we should NOT tear down
	 * the BGP session. The peer is administratively shutting down BFD,
	 * but the BGP session should remain up.
	 */
	if (bss->state == BSS_ADMIN_DOWN && bss->previous_state == BSS_UP) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: BFD received Admin Down from peer %s - BGP session maintained",
				   __func__, peer->host);
		/* Don't tear down BGP session, just log the event */
		return;
	}

	if (bss->state == BSS_DOWN && bss->previous_state == BSS_UP) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE)
		    && local_cbit && !bss->remote_cbit) {
			if (BGP_DEBUG(bfd, BFD_LIB))
				zlog_debug(
					"%s BFD DOWN message ignored in the process of graceful restart when C bit is cleared",
					peer->host);
			return;
		}

		/* Once the BFD session is UP, and later BGP session is UP,
		 * BFD notices that peer->su_local changed, and BFD session goes down.
		 * We should trigger BGP session reset if BFD session is UP
		 * only when BGP session is UP already.
		 * Otherwise, we end up resetting BGP session when BFD session is UP,
		 * when the source address is changed, e.g. 0.0.0.0 -> 10.0.0.1.
		 */
		if (peer_established(peer->connection) && bss->last_event > peer->uptime) {
			if ((CHECK_FLAG(peer->flags, PEER_FLAG_TIMER) && !peer->holdtime) ||
			    !peer->bgp->default_holdtime) {
				event_add_timer(bm->master, bgp_bfd_strict_holdtime_expire, peer,
						peer->bfd_config->hold_time,
						&peer->bfd_config->t_hold_timer);
			} else {
				peer_set_last_reset(peer, PEER_DOWN_BFD_DOWN);
				/* rfc9384 */
				if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
					bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_BFD_DOWN);

				BGP_EVENT_ADD(peer->connection, BGP_Stop);
			}
		}
	}

	if (bss->state == BSS_UP && bss->previous_state != BSS_UP &&
	    !peer_established(peer->connection)) {
		if (!BGP_PEER_START_SUPPRESSED(peer)) {
			bgp_fsm_nht_update(peer->connection, peer, true);

			/* Held connections sit in Active, BGP_Start is ignored there. */
			if (CHECK_FLAG(peer->sflags, PEER_STATUS_BFD_STRICT_HOLD))
				bgp_bfd_strict_hold_release(peer);
			else
				BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
	}
}

/*
 * Egress interface of a single-hop peer.  It must come out the same before
 * and after TCP connects, or the session is re-keyed at connect: so it only
 * depends on configuration and connected routes, and p->nexthop.ifp (which
 * follows the TCP local address) is used only when nothing else resolves.
 */
static struct interface *bgp_peer_bfd_egress_ifp(struct peer *p)
{
	union sockunion *su = &p->connection->su;
	vrf_id_t vrf_id = p->bgp->vrf_id;
	struct interface *ifp = NULL;
	const char *ifname = p->conf_if ? p->conf_if : p->ifname;

	/* Link-local (or not yet learnt) peer: the local address is link-local. */
	if ((su->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr)) ||
	    (su->sa.sa_family != AF_INET && su->sa.sa_family != AF_INET6)) {
		if (ifname)
			ifp = if_lookup_by_name(ifname, vrf_id);
		else if (p->update_if)
			ifp = if_lookup_by_name(p->update_if, vrf_id);
	} else if (p->update_if)
		ifp = if_lookup_by_name(p->update_if, vrf_id);
	else if (ifname)
		ifp = if_lookup_by_name(ifname, vrf_id);
	else if (su->sa.sa_family == AF_INET)
		ifp = if_lookup_by_ipv4(&su->sin.sin_addr, vrf_id);
	else
		ifp = if_lookup_by_ipv6(&su->sin6.sin6_addr, 0, vrf_id);

	return ifp ? ifp : p->nexthop.ifp;
}

static bool bgp_peer_bfd_keyed(struct bfd_session_params *session)
{
	int family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src, dst;

	if (!bfd_sess_interface(session))
		return false;

	bfd_sess_addresses(session, &family, &src.v6, &dst.v6);
	if (family == AF_INET)
		return src.v4.s_addr != INADDR_ANY;

	return !IN6_IS_ADDR_UNSPECIFIED(&src.v6);
}

/*
 * bfdd keys single-hop sessions on the interface and local address, so
 * registering before either is known and filling them in at TCP connect
 * deletes the (possibly already Up) session and creates a new one; the
 * remote sees BFD Down and resets BGP.  Hold a single-hop install back until
 * both are known, except when nothing better can be learnt any more
 * (connection already up) or BGP itself waits for BFD (strict mode).
 */
static void bgp_peer_bfd_install(struct peer *p, uint8_t loc)
{
	struct bfd_session_params *session = p->bfd_config->session;

	if (!PEER_IS_MULTIHOP(p) && !bgp_peer_bfd_keyed(session) && !p->connection->su_local &&
	    !CHECK_FLAG(p->flags, PEER_FLAG_BFD_STRICT)) {
		if (BGP_DEBUG(bfd, BFD_LIB) && !p->bfd_config->install_pending)
			zlog_debug("%s: deferring BFD session for peer %pBP vrf %s(%u) until interface and source are known",
				   __func__, p, p->bgp->name_pretty, p->bgp->vrf_id);
		p->bfd_config->install_pending = true;
		return;
	}

	if (BGP_DEBUG(bfd, BFD_LIB))
		zlog_debug("%s: registering BFD session for peer %pBP vrf %s(%u)", __func__, p,
			   p->bgp->name_pretty, p->bgp->vrf_id);
	frrtrace(3, frr_bgp, bfd_session_register, p->host, p->bgp->vrf_id, loc);
	p->bfd_config->install_pending = false;
	bfd_sess_install(session);
}

static bool bgp_peer_bfd_sync(struct peer *p);

void bgp_peer_config_apply(struct peer *p, struct peer_group *pg)
{
	struct listnode *n;
	struct peer *pn;
	struct peer *gconfig;

	/* When called on a group, apply to all peers. */
	if (CHECK_FLAG(p->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS_RO(p->group->peer, n, pn)) {
			if (peergroup_flag_check(pn, PEER_FLAG_BFD_STRICT))
				peer_flag_set(pn, PEER_FLAG_BFD_STRICT);
			else
				peer_flag_unset(pn, PEER_FLAG_BFD_STRICT);
			bgp_peer_config_apply(pn, pg);
		}
		return;
	}

	/* No group, just use current configuration. */
	if (pg == NULL || pg->conf->bfd_config == NULL) {
		bfd_sess_set_timers(p->bfd_config->session,
				    p->bfd_config->detection_multiplier,
				    p->bfd_config->min_rx,
				    p->bfd_config->min_tx);
		bfd_sess_set_cbit(p->bfd_config->session, p->bfd_config->cbit);
		bfd_sess_set_profile(p->bfd_config->session,
				     p->bfd_config->profile);
		if (!PEER_IS_MULTIHOP(p))
			bgp_peer_bfd_sync(p);
		bgp_peer_bfd_install(p, 1);
		return;
	}

	/*
	 * Check if the group configuration was overwritten or apply group
	 * configuration.
	 */
	gconfig = pg->conf;

	if (!PEER_IS_MULTIHOP(p) || CHECK_FLAG(gconfig->flags, PEER_FLAG_UPDATE_SOURCE) ||
	    CHECK_FLAG(p->flags_override, PEER_FLAG_UPDATE_SOURCE))
		bgp_peer_bfd_sync(p);

	/*
	 * If using default control plane independent configuration,
	 * then prefer group's (e.g. it means it wasn't manually configured).
	 */
	if (!p->bfd_config->cbit)
		bfd_sess_set_cbit(p->bfd_config->session,
				  gconfig->bfd_config->cbit);
	else
		bfd_sess_set_cbit(p->bfd_config->session, p->bfd_config->cbit);

	/* If no hold time was specified in peer, then use the group one. */
	if (p->bfd_config->hold_time == BFD_DEF_STRICT_HOLD_TIME)
		p->bfd_config->hold_time = gconfig->bfd_config->hold_time;

	/* If no profile was specified in peer, then use the group profile. */
	if (p->bfd_config->profile[0] == 0)
		bfd_sess_set_profile(p->bfd_config->session,
				     gconfig->bfd_config->profile);
	else
		bfd_sess_set_profile(p->bfd_config->session,
				     p->bfd_config->profile);

	/* If no specific timers were configured, then use the group timers. */
	if (p->bfd_config->detection_multiplier == BFD_DEF_DETECT_MULT
	    || p->bfd_config->min_rx == BFD_DEF_MIN_RX
	    || p->bfd_config->min_tx == BFD_DEF_MIN_TX)
		bfd_sess_set_timers(p->bfd_config->session,
				    gconfig->bfd_config->detection_multiplier,
				    gconfig->bfd_config->min_rx,
				    gconfig->bfd_config->min_tx);
	else
		bfd_sess_set_timers(p->bfd_config->session,
				    p->bfd_config->detection_multiplier,
				    p->bfd_config->min_rx,
				    p->bfd_config->min_tx);

	bgp_peer_bfd_install(p, 2);
}

/*
 * Bring the session parameters in line with the peer; returns true if
 * anything changed and the session needs to be (re-)installed.
 */
static bool bgp_peer_bfd_sync(struct peer *p)
{
	struct bfd_session_params *session = p->bfd_config->session;
	const union sockunion *source = NULL;
	bool changed = false;
	int family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src, dst;
	struct interface *ifp;
	struct interface *egress_ifp;
	union sockunion addr;

	/* Figure out the correct source to use. */
	if (CHECK_FLAG(p->flags, PEER_FLAG_UPDATE_SOURCE)) {
		if (p->update_source) {
			source = p->update_source;
		} else if (p->update_if) {
			ifp = if_lookup_by_name(p->update_if, p->bgp->vrf_id);
			if (ifp) {
				sockunion_init(&addr);
				if (bgp_update_address(ifp, &p->connection->su, &addr)) {
					if (BGP_DEBUG(bfd, BFD_LIB))
						zlog_debug("%s: can't find the source address for interface %s",
							   __func__, p->update_if);
				}

				source = &addr;
			}
		}
	} else {
		source = p->connection->su_local;
	}

	egress_ifp = PEER_IS_MULTIHOP(p) ? p->nexthop.ifp : bgp_peer_bfd_egress_ifp(p);

	/*
	 * Without update-source the kernel picks the TCP source, so a guess can
	 * differ and rekey the session at connect: wait for su_local instead.
	 * Strict mode must install before TCP is up, so guess there.
	 */
	if (!source && !PEER_IS_MULTIHOP(p) && egress_ifp &&
	    CHECK_FLAG(p->flags, PEER_FLAG_BFD_STRICT)) {
		sockunion_init(&addr);
		if (!bgp_update_address(egress_ifp, &p->connection->su, &addr) &&
		    (addr.sa.sa_family != AF_INET6 || !IN6_IS_ADDR_LINKLOCAL(&addr.sin6.sin6_addr) ||
		     IN6_IS_ADDR_LINKLOCAL(&p->connection->su.sin6.sin6_addr)))
			source = &addr;
	}

	/* Update peer's source/destination addresses. */
	bfd_sess_addresses(session, &family, &src.v6, &dst.v6);
	if (family == AF_INET) {
		if ((source && source->sin.sin_addr.s_addr != src.v4.s_addr) ||
		    p->connection->su.sin.sin_addr.s_addr != dst.v4.s_addr) {
			if (BGP_DEBUG(bfd, BFD_LIB))
				zlog_debug("%s: address [%pI4->%pI4] to [%pI4->%pI4]",
					   __func__, &src.v4, &dst.v4,
					   source ? &source->sin.sin_addr
						  : &src.v4,
					   &p->connection->su.sin.sin_addr);

			bfd_sess_set_ipv4_addrs(session,
						source ? &source->sin.sin_addr
						       : NULL,
						&p->connection->su.sin.sin_addr);
			changed = true;
		}
	} else {
		if ((source && memcmp(&source->sin6, &src.v6, sizeof(src.v6))) ||
		    memcmp(&p->connection->su.sin6, &dst.v6, sizeof(dst.v6))) {
			if (BGP_DEBUG(bfd, BFD_LIB))
				zlog_debug("%s: address [%pI6->%pI6] to [%pI6->%pI6]",
					   __func__, &src.v6, &dst.v6,
					   source ? &source->sin6.sin6_addr
						  : &src.v6,
					   &p->connection->su.sin6.sin6_addr);

			bfd_sess_set_ipv6_addrs(session,
						source ? &source->sin6.sin6_addr
						       : NULL,
						&p->connection->su.sin6.sin6_addr);
			changed = true;
		}
	}

	/* Update interface. */
	if (egress_ifp && (!bfd_sess_interface(session) ||
			   !strmatch(bfd_sess_interface(session), egress_ifp->name))) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: interface %s to %s", __func__,
				   bfd_sess_interface(session) ? bfd_sess_interface(session)
							       : "none",
				   egress_ifp->name);

		bfd_sess_set_interface(session, egress_ifp->name);
		changed = true;
	}

	/*
	 * Update TTL.
	 *
	 * Two cases:
	 * - We detected that the peer is a hop away from us (remove multi hop).
	 *   (this happens when `p->shared_network` is set to `true`)
	 * - eBGP multi hop / TTL security changed.
	 */
	if (!PEER_IS_MULTIHOP(p) && bfd_sess_hop_count(session) > 1) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: TTL %d to 1", __func__,
				   bfd_sess_hop_count(session));

		bfd_sess_set_hop_count(session, 1);
		changed = true;
	}
	if (PEER_IS_MULTIHOP(p) && p->ttl != bfd_sess_hop_count(session)) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: TTL %d to %d", __func__,
				   bfd_sess_hop_count(session), p->ttl);

		bfd_sess_set_hop_count(session, p->ttl);
		changed = true;
	}

	/* Update VRF. */
	if (bfd_sess_vrf_id(session) != p->bgp->vrf_id) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug(
				"%s: VRF %s(%d) to %s(%d)", __func__,
				bfd_sess_vrf(session), bfd_sess_vrf_id(session),
				vrf_id_to_name(p->bgp->vrf_id), p->bgp->vrf_id);

		bfd_sess_set_vrf(session, p->bgp->vrf_id);
		changed = true;
	}

	return changed;
}

void bgp_peer_bfd_update_source(struct peer *p)
{
	if (!p->bfd_config)
		return;

	/* Nothing to do for groups. */
	if (CHECK_FLAG(p->sflags, PEER_STATUS_GROUP))
		return;

	if (bgp_peer_bfd_sync(p) || p->bfd_config->install_pending)
		bgp_peer_bfd_install(p, 3);
}

/**
 * Reset BFD configuration data structure to its defaults settings.
 */
static void bgp_peer_bfd_reset(struct peer *p)
{
	/* Set defaults. */
	p->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	p->bfd_config->min_rx = BFD_DEF_MIN_RX;
	p->bfd_config->min_tx = BFD_DEF_MIN_TX;
	p->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;
	p->bfd_config->cbit = false;
	p->bfd_config->profile[0] = 0;
}

void bgp_peer_configure_bfd(struct peer *p, bool manual)
{
	/* Groups should not call this. */
	assert(!CHECK_FLAG(p->sflags, PEER_STATUS_GROUP));

	/* Already configured, skip it. */
	if (p->bfd_config) {
		/* If manually active update flag. */
		if (!p->bfd_config->manual)
			p->bfd_config->manual = manual;

		return;
	}

	/* Allocate memory for configuration overrides. */
	p->bfd_config = XCALLOC(MTYPE_BFD_CONFIG, sizeof(*p->bfd_config));
	p->bfd_config->manual = manual;

	/* Create new session and assign callback. */
	p->bfd_config->session = bfd_sess_new(bfd_session_status_update, p);
	bgp_peer_bfd_reset(p);

	/* Configure session with basic BGP peer data. */
	if (p->connection->su.sa.sa_family == AF_INET)
		bfd_sess_set_ipv4_addrs(p->bfd_config->session,
					p->connection->su_local
						? &p->connection->su_local->sin.sin_addr
						: NULL,
					&p->connection->su.sin.sin_addr);
	else
		bfd_sess_set_ipv6_addrs(p->bfd_config->session,
					p->connection->su_local
						? &p->connection->su_local->sin6.sin6_addr
						: NULL,
					&p->connection->su.sin6.sin6_addr);

	bfd_sess_set_vrf(p->bfd_config->session, p->bgp->vrf_id);
	bfd_sess_set_hop_count(p->bfd_config->session,
			       PEER_IS_MULTIHOP(p) ? p->ttl : 1);

	if (p->nexthop.ifp)
		bfd_sess_set_interface(p->bfd_config->session,
				       p->nexthop.ifp->name);
}

static void bgp_peer_remove_bfd(struct peer *p)
{
	/* Groups should not call this. */
	assert(!CHECK_FLAG(p->sflags, PEER_STATUS_GROUP));

	if (!p->bfd_config)
		return;

	event_cancel(&p->bfd_config->t_hold_timer);

	/*
	 * Peer configuration was removed, however we must check if there
	 * is still a group configuration to keep this running.
	 */
	if (p->group && p->group->conf->bfd_config) {
		p->bfd_config->manual = false;
		bgp_peer_bfd_reset(p);
		bgp_peer_config_apply(p, p->group);
		return;
	}

	if (p->bfd_config) {
		if (BGP_DEBUG(bfd, BFD_LIB)) {
			if (p->bgp)
				zlog_debug("%s: deregistering BFD session for peer %pBP vrf %s(%u) (config removal)",
					   __func__, p, p->bgp->name_pretty, p->bgp->vrf_id);
			else
				zlog_debug("%s: deregistering BFD session for peer %pBP (config removal)",
					   __func__, p);
		}
		if (p->bgp)
			frrtrace(3, frr_bgp, bfd_session_deregister, p->host, p->bgp->vrf_id, 4);
		bfd_sess_free(&p->bfd_config->session);
	}

	XFREE(MTYPE_BFD_CONFIG, p->bfd_config);
}

static void bgp_group_configure_bfd(struct peer *p)
{
	struct listnode *n;
	struct peer *pn;

	/* Peers should not call this. */
	assert(CHECK_FLAG(p->sflags, PEER_STATUS_GROUP));

	/* Already allocated: do nothing. */
	if (p->bfd_config)
		return;

	p->bfd_config = XCALLOC(MTYPE_BFD_CONFIG, sizeof(*p->bfd_config));

	/* Set defaults. */
	p->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	p->bfd_config->min_rx = BFD_DEF_MIN_RX;
	p->bfd_config->min_tx = BFD_DEF_MIN_TX;
	p->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;

	for (ALL_LIST_ELEMENTS_RO(p->group->peer, n, pn))
		bgp_peer_configure_bfd(pn, false);
}

static void bgp_group_remove_bfd(struct peer *p)
{
	struct listnode *n;
	struct peer *pn;

	/* Peers should not call this. */
	assert(CHECK_FLAG(p->sflags, PEER_STATUS_GROUP));

	/* Already freed: do nothing. */
	if (p->bfd_config == NULL)
		return;

        if (p->bgp && p->group) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: removing BFD config from peer-group %s vrf %s(%u), will deregister sessions for %d peers",
				   __func__, p->group->name, p->bgp->name_pretty,
				   p->bgp->vrf_id,
				   p->group->peer ? (int)listcount(p->group->peer) : 0);

		frrtrace(3, frr_bgp, bfd_session_deregister, p->group->name, p->bgp->vrf_id, 5);

        }

	/* Free configuration and point to `NULL`. */
	XFREE(MTYPE_BFD_CONFIG, p->bfd_config);

	/* Now that it is `NULL` recalculate configuration for all peers. */
	for (ALL_LIST_ELEMENTS_RO(p->group->peer, n, pn)) {
		if (pn->bfd_config->manual)
			bgp_peer_config_apply(pn, NULL);
		else
			bgp_peer_remove_bfd(pn);
	}
}

void bgp_peer_remove_bfd_config(struct peer *p)
{
	if (CHECK_FLAG(p->sflags, PEER_STATUS_GROUP))
		bgp_group_remove_bfd(p);
	else
		bgp_peer_remove_bfd(p);
}

/*
 * bgp_bfd_peer_config_write - Write the peer BFD configuration.
 */
void bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer, const char *addr)
{
	/*
	 * Always show group BFD configuration, but peer only when explicitly
	 * configured.
	 */
	if ((!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)
	     && peer->bfd_config->manual)
	    || CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
#if HAVE_BFDD > 0
		vty_out(vty, " neighbor %s bfd\n", addr);
#else
		vty_out(vty, " neighbor %s bfd %d %d %d\n", addr,
			peer->bfd_config->detection_multiplier,
			peer->bfd_config->min_rx, peer->bfd_config->min_tx);
#endif /* HAVE_BFDD */
	}

	if (peer->bfd_config->profile[0])
		vty_out(vty, " neighbor %s bfd profile %s\n", addr,
			peer->bfd_config->profile);

	if (peer->bfd_config->cbit)
		vty_out(vty, " neighbor %s bfd check-control-plane-failure\n",
			addr);

	if (peergroup_flag_check(peer, PEER_FLAG_BFD_STRICT)) {
		if (peer->bfd_config->hold_time != BFD_DEF_STRICT_HOLD_TIME)
			vty_out(vty, " neighbor %s bfd strict hold-time %u\n", addr,
				peer->bfd_config->hold_time);
		else
			vty_out(vty, " neighbor %s bfd strict\n", addr);
	}
}

/*
 * bgp_bfd_show_info - Show the peer BFD information.
 */
void bgp_bfd_show_info(struct vty *vty, struct peer *peer, json_object *json_neigh)
{
	bfd_sess_show(vty, json_neigh, peer->bfd_config->session);
}

DEFUN (neighbor_bfd,
       neighbor_bfd_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}

#if HAVE_BFDD == 0
DEFUN(
       neighbor_bfd_param,
       neighbor_bfd_param_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd (2-255) (50-60000) (50-60000)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	int idx_peer = 1;
	int idx_number_1 = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	long detection_multiplier, min_rx, min_tx;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	detection_multiplier = strtol(argv[idx_number_1]->arg, NULL, 10);
	min_rx = strtol(argv[idx_number_2]->arg, NULL, 10);
	min_tx = strtol(argv[idx_number_3]->arg, NULL, 10);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	peer->bfd_config->detection_multiplier = detection_multiplier;
	peer->bfd_config->min_rx = min_rx;
	peer->bfd_config->min_tx = min_tx;
	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}
#endif

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
       neighbor_bfd_param,
       neighbor_bfd_param_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd (2-255) (50-60000) (50-60000)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	int idx_peer = 1;
	int idx_number_1 = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	long detection_multiplier, min_rx, min_tx;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	detection_multiplier = strtol(argv[idx_number_1]->arg, NULL, 10);
	min_rx = strtol(argv[idx_number_2]->arg, NULL, 10);
	min_tx = strtol(argv[idx_number_3]->arg, NULL, 10);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	peer->bfd_config->detection_multiplier = detection_multiplier;
	peer->bfd_config->min_rx = min_rx;
	peer->bfd_config->min_tx = min_tx;
	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}
#endif

DEFPY (neighbor_bfd_strict,
       neighbor_bfd_strict_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd strict",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BFD support\n"
       "Strict mode\n")
{
	struct peer *peer, *pn;
	struct listnode *n;
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		ret = peer_flag_unset(peer, PEER_FLAG_BFD_STRICT);
	else
		ret = peer_flag_set(peer, PEER_FLAG_BFD_STRICT);

	/* Strict mode needs the session installed for BGP to come up. */
	if (!no) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			for (ALL_LIST_ELEMENTS_RO(peer->group->peer, n, pn))
				bgp_peer_bfd_update_source(pn);
		} else
			bgp_peer_bfd_update_source(peer);
	}

	return ret;
}

DEFPY (neighbor_bfd_strict_hold_time,
       neighbor_bfd_strict_hold_time_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd strict hold-time ![(1-4294967295)$hold_time]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BFD support\n"
       "Strict mode\n"
       "BFD Hold time in seconds\n"
       "Seconds to wait before declaring BFD session down\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	event_cancel(&peer->bfd_config->t_hold_timer);

	if (no) {
		peer->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;
		peer_flag_unset(peer, PEER_FLAG_BFD_STRICT);
	} else {
		peer->bfd_config->hold_time = hold_time;
		peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	}

	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}

DEFUN (neighbor_bfd_check_controlplane_failure,
       neighbor_bfd_check_controlplane_failure_cmd,
       "[no] neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BFD support\n"
       "Link dataplane status with BGP controlplane\n")
{
	const char *no = strmatch(argv[0]->text, "no") ? "no" : NULL;
	int idx_peer = 0;
	struct peer *peer;

	if (no)
		idx_peer = 2;
	else
		idx_peer = 1;
	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	peer->bfd_config->cbit = no == NULL;
	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
 }

#if HAVE_BFDD > 0
DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n")
 {
	 int idx_peer = 2;
	 struct peer *peer;

	 peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	 if (!peer)
		 return CMD_WARNING_CONFIG_FAILED;

	 if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		 bgp_group_remove_bfd(peer);
	 else
		 bgp_peer_remove_bfd(peer);

	 return CMD_SUCCESS;
 }
#endif

#if HAVE_BFDD == 0
DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd [(2-255) (50-60000) (50-60000)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
 {
	 int idx_peer = 2;
	 struct peer *peer;

	 peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	 if (!peer)
		 return CMD_WARNING_CONFIG_FAILED;

	 if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		 bgp_group_remove_bfd(peer);
	 else
		 bgp_peer_remove_bfd(peer);

	 return CMD_SUCCESS;
}
#endif

#if HAVE_BFDD > 0
DEFUN(neighbor_bfd_profile, neighbor_bfd_profile_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "BFD integration\n"
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	int idx_peer = 1, idx_prof = 4;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	strlcpy(peer->bfd_config->profile, argv[idx_prof]->arg,
		sizeof(peer->bfd_config->profile));
	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}

DEFUN(no_neighbor_bfd_profile, no_neighbor_bfd_profile_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile [BFDPROF]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "BFD integration\n"
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!peer->bfd_config)
		return CMD_SUCCESS;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		bgp_group_configure_bfd(peer);
	else
		bgp_peer_configure_bfd(peer, true);

	peer->bfd_config->profile[0] = 0;
	bgp_peer_config_apply(peer, peer->group);

	return CMD_SUCCESS;
}
#endif /* HAVE_BFDD */

void bgp_bfd_init(struct event_loop *tm)
{
	/* Initialize BFD client functions */
	bfd_protocol_integration_init(bgp_zclient, tm);

	/* "neighbor bfd" commands. */
	install_element(BGP_NODE, &neighbor_bfd_cmd);
	install_element(BGP_NODE, &neighbor_bfd_param_cmd);
	install_element(BGP_NODE, &neighbor_bfd_check_controlplane_failure_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_hold_time_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_cmd);

#if HAVE_BFDD > 0
	install_element(BGP_NODE, &neighbor_bfd_profile_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_profile_cmd);
#endif /* HAVE_BFDD */
}
