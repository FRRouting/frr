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

DEFINE_MTYPE_STATIC(BGPD, BFD_CONFIG, "BFD configuration data");

extern struct zclient *zclient;

static void bfd_session_status_update(struct bfd_session_params *bsp,
				      const struct bfd_session_status *bss,
				      void *arg)
{
	struct peer *peer = arg;

	if (BGP_DEBUG(bfd, BFD_LIB))
		zlog_debug("%s: neighbor %s vrf %s(%u) bfd state %s -> %s",
			   __func__, peer->conf_if ? peer->conf_if : peer->host,
			   bfd_sess_vrf(bsp), bfd_sess_vrf_id(bsp),
			   bfd_get_status_str(bss->previous_state),
			   bfd_get_status_str(bss->state));

	if (bss->state == BSS_DOWN && bss->previous_state == BSS_UP) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE)
		    && bfd_sess_cbit(bsp) && !bss->remote_cbit) {
			if (BGP_DEBUG(bfd, BFD_LIB))
				zlog_debug(
					"%s BFD DOWN message ignored in the process of graceful restart when C bit is cleared",
					peer->host);
			return;
		}
		peer->last_reset = PEER_DOWN_BFD_DOWN;

		/* rfc9384 */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_BFD_DOWN);

		BGP_EVENT_ADD(peer->connection, BGP_Stop);
	}

	if (bss->state == BSS_UP && bss->previous_state != BSS_UP &&
	    !peer_established(peer->connection)) {
		if (!BGP_PEER_START_SUPPRESSED(peer)) {
			bgp_fsm_nht_update(peer->connection, peer, true);
			BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
	}
}

void bgp_peer_config_apply(struct peer *p, struct peer_group *pg)
{
	struct listnode *n;
	struct peer *pn;
	struct peer *gconfig;

	/* When called on a group, apply to all peers. */
	if (CHECK_FLAG(p->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS_RO(p->group->peer, n, pn))
			bgp_peer_config_apply(pn, pg);
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
		bfd_sess_install(p->bfd_config->session);
		return;
	}

	/*
	 * Check if the group configuration was overwritten or apply group
	 * configuration.
	 */
	gconfig = pg->conf;

	/*
	 * If using default control plane independent configuration,
	 * then prefer group's (e.g. it means it wasn't manually configured).
	 */
	if (!p->bfd_config->cbit)
		bfd_sess_set_cbit(p->bfd_config->session,
				  gconfig->bfd_config->cbit);
	else
		bfd_sess_set_cbit(p->bfd_config->session, p->bfd_config->cbit);

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

	bfd_sess_install(p->bfd_config->session);
}

void bgp_peer_bfd_update_source(struct peer *p)
{
	struct bfd_session_params *session = p->bfd_config->session;
	const union sockunion *source;
	bool changed = false;
	int family;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src, dst;

	/* Nothing to do for groups. */
	if (CHECK_FLAG(p->sflags, PEER_STATUS_GROUP))
		return;

	/* Figure out the correct source to use. */
	if (CHECK_FLAG(p->flags, PEER_FLAG_UPDATE_SOURCE) && p->update_source)
		source = p->update_source;
	else
		source = p->su_local;

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
	if (p->nexthop.ifp && bfd_sess_interface(session) == NULL) {
		if (BGP_DEBUG(bfd, BFD_LIB))
			zlog_debug("%s: interface none to %s", __func__,
				   p->nexthop.ifp->name);

		bfd_sess_set_interface(session, p->nexthop.ifp->name);
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

	if (changed)
		bfd_sess_install(session);
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
					p->su_local ? &p->su_local->sin.sin_addr
						    : NULL,
					&p->connection->su.sin.sin_addr);
	else
		bfd_sess_set_ipv6_addrs(p->bfd_config->session,
					p->su_local
						? &p->su_local->sin6.sin6_addr
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

	if (p->bfd_config)
		bfd_sess_free(&p->bfd_config->session);

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
void bgp_bfd_peer_config_write(struct vty *vty, const struct peer *peer,
			       const char *addr)
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
}

/*
 * bgp_bfd_show_info - Show the peer BFD information.
 */
void bgp_bfd_show_info(struct vty *vty, const struct peer *peer,
		       json_object *json_neigh)
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

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
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

DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
#if HAVE_BFDD > 0
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd",
#else
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd [(2-255) (50-60000) (50-60000)]",
#endif /* HAVE_BFDD */
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n"
#if HAVE_BFDD == 0
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
#endif /* !HAVE_BFDD */
)
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
	bfd_protocol_integration_init(zclient, tm);

	/* "neighbor bfd" commands. */
	install_element(BGP_NODE, &neighbor_bfd_cmd);
	install_element(BGP_NODE, &neighbor_bfd_param_cmd);
	install_element(BGP_NODE, &neighbor_bfd_check_controlplane_failure_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_cmd);

#if HAVE_BFDD > 0
	install_element(BGP_NODE, &neighbor_bfd_profile_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_profile_cmd);
#endif /* HAVE_BFDD */
}
