// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP-4, BGP-4+ daemon program
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "prefix.h"
#include "frrevent.h"
#include "buffer.h"
#include "stream.h"
#include "ringbuf.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
#include "filter.h"
#include "routemap.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "queue.h"
#include "zclient.h"
#include "bfd.h"
#include "hash.h"
#include "jhash.h"
#include "table.h"
#include "lib/json.h"
#include "lib/sockopt.h"
#include "frr_pthread.h"
#include "bitfield.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_mplsvpn.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi_backend.h"
#endif
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_nhg.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_labelpool.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_mac.h"
#include "bgp_trace.h"

DEFINE_MTYPE_STATIC(BGPD, PEER_TX_SHUTDOWN_MSG, "Peer shutdown message (TX)");
DEFINE_QOBJ_TYPE(bgp_master);
DEFINE_QOBJ_TYPE(bgp);
DEFINE_QOBJ_TYPE(peer);
DEFINE_HOOK(bgp_inst_delete, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_instance_state, (struct bgp *bgp), (bgp));

/* BGP process wide configuration.  */
static struct bgp_master bgp_master;

/* BGP process wide configuration pointer to export.  */
struct bgp_master *bm;

/* BGP community-list.  */
struct community_list_handler *bgp_clist;

unsigned int multipath_num = MULTIPATH_NUM;

/* Number of bgp instances configured for suppress fib config */
unsigned int bgp_suppress_fib_count;

static void bgp_if_finish(struct bgp *bgp);
static void peer_drop_dynamic_neighbor(struct peer *peer);

extern struct zclient *zclient;

/* handle main socket creation or deletion */
static int bgp_check_main_socket(bool create, struct bgp *bgp)
{
	static int bgp_server_main_created;
	struct listnode *node;
	char *address;

	if (create) {
		if (bgp_server_main_created)
			return 0;
		if (list_isempty(bm->addresses)) {
			if (bgp_socket(bgp, bm->port, NULL) < 0)
				return BGP_ERR_INVALID_VALUE;
		} else {
			for (ALL_LIST_ELEMENTS_RO(bm->addresses, node, address))
				if (bgp_socket(bgp, bm->port, address) < 0)
					return BGP_ERR_INVALID_VALUE;
		}
		bgp_server_main_created = 1;
		return 0;
	}
	if (!bgp_server_main_created)
		return 0;
	bgp_close();
	bgp_server_main_created = 0;
	return 0;
}

void bgp_session_reset(struct peer *peer)
{
	if (peer->doppelganger &&
	    (peer->doppelganger->connection->status != Deleted) &&
	    !(CHECK_FLAG(peer->doppelganger->flags, PEER_FLAG_CONFIG_NODE)))
		peer_delete(peer->doppelganger);

	BGP_EVENT_ADD(peer->connection, BGP_Stop);
}

/*
 * During session reset, we may delete the doppelganger peer, which would
 * be the next node to the current node. If the session reset was invoked
 * during walk of peer list, we would end up accessing the freed next
 * node. This function moves the next node along.
 */
void bgp_session_reset_safe(struct peer *peer, struct listnode **nnode)
{
	struct listnode *n;
	struct peer *npeer;

	n = (nnode) ? *nnode : NULL;
	npeer = (n) ? listgetdata(n) : NULL;

	if (peer->doppelganger &&
	    (peer->doppelganger->connection->status != Deleted) &&
	    !(CHECK_FLAG(peer->doppelganger->flags, PEER_FLAG_CONFIG_NODE))) {
		if (peer->doppelganger == npeer)
			/* nnode and *nnode are confirmed to be non-NULL here */
			*nnode = (*nnode)->next;
		peer_delete(peer->doppelganger);
	}

	BGP_EVENT_ADD(peer->connection, BGP_Stop);
}

/* BGP global flag manipulation.  */
int bgp_option_set(int flag)
{
	switch (flag) {
	case BGP_OPT_NO_FIB:
	case BGP_OPT_NO_LISTEN:
	case BGP_OPT_NO_ZEBRA:
		SET_FLAG(bm->options, flag);
		break;
	default:
		return BGP_ERR_INVALID_FLAG;
	}
	return 0;
}

int bgp_option_unset(int flag)
{
	switch (flag) {
	case BGP_OPT_NO_ZEBRA:
	case BGP_OPT_NO_FIB:
		UNSET_FLAG(bm->options, flag);
		break;
	default:
		return BGP_ERR_INVALID_FLAG;
	}
	return 0;
}

int bgp_option_check(int flag)
{
	return CHECK_FLAG(bm->options, flag);
}

/* set the bgp no-rib option during runtime and remove installed routes */
void bgp_option_norib_set_runtime(void)
{
	struct bgp *bgp;
	struct listnode *node;
	afi_t afi;
	safi_t safi;

	if (bgp_option_check(BGP_OPT_NO_FIB))
		return;

	bgp_option_set(BGP_OPT_NO_FIB);

	zlog_info("Disabled BGP route installation to RIB (Zebra)");

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		FOREACH_AFI_SAFI (afi, safi) {
			/*
			 * Stop a crash, more work is needed
			 * here to properly add/remove these types of
			 * routes from zebra.
			 */
			if (!bgp_fibupd_safi(safi))
				continue;

			bgp_zebra_withdraw_table_all_subtypes(bgp, afi, safi);
		}
	}

	zlog_info("All routes have been withdrawn from RIB (Zebra)");
}

/* unset the bgp no-rib option during runtime and announce routes to Zebra */
void bgp_option_norib_unset_runtime(void)
{
	struct bgp *bgp;
	struct listnode *node;
	afi_t afi;
	safi_t safi;

	if (!bgp_option_check(BGP_OPT_NO_FIB))
		return;

	bgp_option_unset(BGP_OPT_NO_FIB);

	zlog_info("Enabled BGP route installation to RIB (Zebra)");

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		FOREACH_AFI_SAFI (afi, safi) {
			/*
			 * Stop a crash, more work is needed
			 * here to properly add/remove these types
			 * of routes from zebra
			 */
			if (!bgp_fibupd_safi(safi))
				continue;

			bgp_zebra_announce_table_all_subtypes(bgp, afi, safi);
		}
	}

	zlog_info("All routes have been installed in RIB (Zebra)");
}

/* Internal function to set BGP structure configureation flag.  */
static void bgp_config_set(struct bgp *bgp, int config)
{
	SET_FLAG(bgp->config, config);
}

static void bgp_config_unset(struct bgp *bgp, int config)
{
	UNSET_FLAG(bgp->config, config);
}

static int bgp_config_check(struct bgp *bgp, int config)
{
	return CHECK_FLAG(bgp->config, config);
}

/* Set BGP router identifier; distinguish between explicit config and other
 * cases.
 */
static int bgp_router_id_set(struct bgp *bgp, const struct in_addr *id,
			     bool is_config)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (IPV4_ADDR_SAME(&bgp->router_id, id))
		return 0;

	/* EVPN uses router id in RD, withdraw them */
	if (is_evpn_enabled())
		bgp_evpn_handle_router_id_update(bgp, true);

	vpn_handle_router_id_update(bgp, true, is_config);

	IPV4_ADDR_COPY(&bgp->router_id, id);

	/* Set all peer's local identifier with this value. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		IPV4_ADDR_COPY(&peer->local_id, id);

		peer->last_reset = PEER_DOWN_RID_CHANGE;

		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}

	/* EVPN uses router id in RD, update them */
	if (is_evpn_enabled())
		bgp_evpn_handle_router_id_update(bgp, false);

	vpn_handle_router_id_update(bgp, false, is_config);

	return 0;
}

void bgp_router_id_zebra_bump(vrf_id_t vrf_id, const struct prefix *router_id)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct in_addr *addr = NULL;

	if (router_id != NULL)
		addr = (struct in_addr *)&(router_id->u.prefix4);

	if (vrf_id == VRF_DEFAULT) {
		/* Router-id change for default VRF has to also update all
		 * views. */
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
				continue;

			if (addr)
				bgp->router_id_zebra = *addr;
			else
				addr = &bgp->router_id_zebra;

			if (!bgp->router_id_static.s_addr) {
				/* Router ID is updated if there are no active
				 * peer sessions
				 */
				if (bgp->established_peers == 0) {
					if (BGP_DEBUG(zebra, ZEBRA))
						zlog_debug(
							"RID change : vrf %s(%u), RTR ID %pI4",
							bgp->name_pretty,
							bgp->vrf_id, addr);
					/*
					 * if old router-id was 0x0, set flag
					 * to use this new value
					 */
					bgp_router_id_set(bgp, addr,
							  (bgp->router_id.s_addr
							   == INADDR_ANY)
								  ? true
								  : false);
				}
			}
		}
	} else {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp) {
			if (addr)
				bgp->router_id_zebra = *addr;
			else
				addr = &bgp->router_id_zebra;

			if (!bgp->router_id_static.s_addr) {
				/* Router ID is updated if there are no active
				 * peer sessions
				 */
				if (bgp->established_peers == 0) {
					if (BGP_DEBUG(zebra, ZEBRA))
						zlog_debug(
							"RID change : vrf %s(%u), RTR ID %pI4",
							bgp->name_pretty,
							bgp->vrf_id, addr);
					/*
					 * if old router-id was 0x0, set flag
					 * to use this new value
					 */
					bgp_router_id_set(bgp, addr,
							  (bgp->router_id.s_addr
							   == INADDR_ANY)
								  ? true
								  : false);
				}
			}

		}
	}
}

void bgp_router_id_static_set(struct bgp *bgp, struct in_addr id)
{
	bgp->router_id_static = id;
	bgp_router_id_set(bgp,
			  id.s_addr != INADDR_ANY ? &id : &bgp->router_id_zebra,
			  true /* is config */);
}

void bm_wait_for_fib_set(bool set)
{
	bool send_msg = false;
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *next, *node;

	if (bm->wait_for_fib == set)
		return;

	bm->wait_for_fib = set;
	if (set) {
		if (bgp_suppress_fib_count == 0)
			send_msg = true;
		bgp_suppress_fib_count++;
	} else {
		bgp_suppress_fib_count--;
		if (bgp_suppress_fib_count == 0)
			send_msg = true;
	}

	if (send_msg && zclient)
		zebra_route_notify_send(ZEBRA_ROUTE_NOTIFY_REQUEST,
					zclient, set);

	/*
	 * If this is configed at a time when peers are already set
	 * FRR needs to reset the connection(s) as that some installs
	 * may have already happened in some shape fashion or form
	 * let's just start over
	 */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			peer->last_reset = PEER_DOWN_SUPPRESS_FIB_PENDING;

			if (!BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status))
				continue;

			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		}
	}
}

/* Set the suppress fib pending for the bgp configuration */
void bgp_suppress_fib_pending_set(struct bgp *bgp, bool set)
{
	bool send_msg = false;
	struct peer *peer;
	struct listnode *node;

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
		return;

	if (set) {
		SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING);
		/* Send msg to zebra for the first instance of bgp enabled
		 * with suppress fib
		 */
		if (bgp_suppress_fib_count == 0)
			send_msg = true;
		bgp_suppress_fib_count++;
	} else {
		UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING);
		bgp_suppress_fib_count--;

		/* Send msg to zebra if there are no instances enabled
		 * with suppress fib
		 */
		if (bgp_suppress_fib_count == 0)
			send_msg = true;
	}
	/* Send route notify request to RIB */
	if (send_msg) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Sending ZEBRA_ROUTE_NOTIFY_REQUEST");

		if (zclient)
			zebra_route_notify_send(ZEBRA_ROUTE_NOTIFY_REQUEST,
					zclient, set);
	}

	/*
	 * If this is configed at a time when peers are already set
	 * FRR needs to reset the connection as that some installs
	 * may have already happened in some shape fashion or form
	 * let's just start over
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		peer->last_reset = PEER_DOWN_SUPPRESS_FIB_PENDING;

		if (!BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			continue;

		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
				BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

/* BGP's cluster-id control. */
void bgp_cluster_id_set(struct bgp *bgp, struct in_addr *cluster_id)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (bgp_config_check(bgp, BGP_CONFIG_CLUSTER_ID)
	    && IPV4_ADDR_SAME(&bgp->cluster_id, cluster_id))
		return;

	IPV4_ADDR_COPY(&bgp->cluster_id, cluster_id);
	bgp_config_set(bgp, BGP_CONFIG_CLUSTER_ID);

	/* Clear all IBGP peer. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->sort != BGP_PEER_IBGP)
			continue;

		peer->last_reset = PEER_DOWN_CLID_CHANGE;

		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

void bgp_cluster_id_unset(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!bgp_config_check(bgp, BGP_CONFIG_CLUSTER_ID))
		return;

	bgp->cluster_id.s_addr = 0;
	bgp_config_unset(bgp, BGP_CONFIG_CLUSTER_ID);

	/* Clear all IBGP peer. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->sort != BGP_PEER_IBGP)
			continue;

		peer->last_reset = PEER_DOWN_CLID_CHANGE;

		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

/* BGP timer configuration.  */
void bgp_timers_set(struct vty *vty, struct bgp *bgp, uint32_t keepalive,
		    uint32_t holdtime, uint32_t connect_retry,
		    uint32_t delayopen)
{
	uint32_t default_keepalive = holdtime / 3;

	if (keepalive > default_keepalive) {
		if (vty)
			vty_out(vty,
				"%% keepalive value %u is larger than 1/3 of the holdtime, setting to %u\n",
				keepalive, default_keepalive);
	} else {
		default_keepalive = keepalive;
	}

	bgp->default_keepalive = default_keepalive;
	bgp->default_holdtime = holdtime;
	bgp->default_connect_retry = connect_retry;
	bgp->default_delayopen = delayopen;
}

/* mostly for completeness - CLI uses its own defaults */
void bgp_timers_unset(struct bgp *bgp)
{
	bgp->default_keepalive = BGP_DEFAULT_KEEPALIVE;
	bgp->default_holdtime = BGP_DEFAULT_HOLDTIME;
	bgp->default_connect_retry = BGP_DEFAULT_CONNECT_RETRY;
	bgp->default_delayopen = BGP_DEFAULT_DELAYOPEN;
}

void bgp_tcp_keepalive_set(struct bgp *bgp, uint16_t keepalive_idle,
			   uint16_t keepalive_intvl, uint16_t keepalive_probes)
{
	bgp->tcp_keepalive_idle = keepalive_idle;
	bgp->tcp_keepalive_intvl = keepalive_intvl;
	bgp->tcp_keepalive_probes = keepalive_probes;
}

void bgp_tcp_keepalive_unset(struct bgp *bgp)
{
	bgp->tcp_keepalive_idle = 0;
	bgp->tcp_keepalive_intvl = 0;
	bgp->tcp_keepalive_probes = 0;
}

/* BGP confederation configuration.  */
void bgp_confederation_id_set(struct bgp *bgp, as_t as, const char *as_str)
{
	struct peer *peer;
	struct listnode *node, *nnode;
	int already_confed;

	if (as == 0)
		return;

	/* Remember - were we doing confederation before? */
	already_confed = bgp_config_check(bgp, BGP_CONFIG_CONFEDERATION);
	bgp->confed_id = as;
	if (bgp->confed_id_pretty)
		XFREE(MTYPE_BGP_NAME, bgp->confed_id_pretty);
	bgp->confed_id_pretty = XSTRDUP(MTYPE_BGP_NAME, as_str);
	bgp_config_set(bgp, BGP_CONFIG_CONFEDERATION);

	/* If we were doing confederation already, this is just an external
	   AS change.  Just Reset EBGP sessions, not CONFED sessions.  If we
	   were not doing confederation before, reset all EBGP sessions.  */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		enum bgp_peer_sort ptype = peer_sort(peer);

		/* We're looking for peers who's AS is not local or part of our
		   confederation.  */
		if (already_confed) {
			if (ptype == BGP_PEER_EBGP) {
				peer->local_as = as;
				if (BGP_IS_VALID_STATE_FOR_NOTIF(
					    peer->connection->status)) {
					peer->last_reset =
						PEER_DOWN_CONFED_ID_CHANGE;
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_CONFIG_CHANGE);
				} else
					bgp_session_reset_safe(peer, &nnode);
			}
		} else {
			/* Not doign confederation before, so reset every
			   non-local
			   session */
			if (ptype != BGP_PEER_IBGP) {
				/* Reset the local_as to be our EBGP one */
				if (ptype == BGP_PEER_EBGP)
					peer->local_as = as;
				if (BGP_IS_VALID_STATE_FOR_NOTIF(
					    peer->connection->status)) {
					peer->last_reset =
						PEER_DOWN_CONFED_ID_CHANGE;
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_CONFIG_CHANGE);
				} else
					bgp_session_reset_safe(peer, &nnode);
			}
		}
	}
	return;
}

void bgp_confederation_id_unset(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	bgp->confed_id = 0;
	XFREE(MTYPE_BGP_NAME, bgp->confed_id_pretty);
	bgp_config_unset(bgp, BGP_CONFIG_CONFEDERATION);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		/* We're looking for peers who's AS is not local */
		if (peer_sort(peer) != BGP_PEER_IBGP) {
			peer->local_as = bgp->as;
			peer->last_reset = PEER_DOWN_CONFED_ID_CHANGE;
			if (BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status))
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_CONFIG_CHANGE);
			else
				bgp_session_reset_safe(peer, &nnode);
		}
	}
}

/* Is an AS part of the confed or not? */
bool bgp_confederation_peers_check(struct bgp *bgp, as_t as)
{
	int i;

	if (!bgp)
		return false;

	for (i = 0; i < bgp->confed_peers_cnt; i++)
		if (bgp->confed_peers[i].as == as)
			return true;

	return false;
}

/* Add an AS to the confederation set.  */
void bgp_confederation_peers_add(struct bgp *bgp, as_t as, const char *as_str)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!bgp)
		return;

	if (bgp_confederation_peers_check(bgp, as))
		return;

	bgp->confed_peers = XREALLOC(MTYPE_BGP_CONFED_LIST, bgp->confed_peers,
				     (bgp->confed_peers_cnt + 1) *
					     sizeof(struct as_confed));

	bgp->confed_peers[bgp->confed_peers_cnt].as = as;
	bgp->confed_peers[bgp->confed_peers_cnt].as_pretty =
		XSTRDUP(MTYPE_BGP_NAME, as_str);
	bgp->confed_peers_cnt++;

	if (bgp_config_check(bgp, BGP_CONFIG_CONFEDERATION)) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as == as) {
				peer->local_as = bgp->as;
				(void)peer_sort(peer);
				if (BGP_IS_VALID_STATE_FOR_NOTIF(
					    peer->connection->status)) {
					peer->last_reset =
						PEER_DOWN_CONFED_PEER_CHANGE;
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_CONFIG_CHANGE);
				} else
					bgp_session_reset_safe(peer, &nnode);
			}
		}
	}
}

/* Delete an AS from the confederation set.  */
void bgp_confederation_peers_remove(struct bgp *bgp, as_t as)
{
	int i;
	int j;
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!bgp)
		return;

	if (!bgp_confederation_peers_check(bgp, as))
		return;

	for (i = 0; i < bgp->confed_peers_cnt; i++)
		if (bgp->confed_peers[i].as == as) {
			XFREE(MTYPE_BGP_NAME, bgp->confed_peers[i].as_pretty);
			for (j = i + 1; j < bgp->confed_peers_cnt; j++) {
				bgp->confed_peers[j - 1].as =
					bgp->confed_peers[j].as;
				bgp->confed_peers[j - 1].as_pretty =
					bgp->confed_peers[j].as_pretty;
			}
		}

	bgp->confed_peers_cnt--;

	if (bgp->confed_peers_cnt == 0) {
		if (bgp->confed_peers)
			XFREE(MTYPE_BGP_CONFED_LIST, bgp->confed_peers);
		bgp->confed_peers = NULL;
	} else
		bgp->confed_peers = XREALLOC(
			MTYPE_BGP_CONFED_LIST, bgp->confed_peers,
			bgp->confed_peers_cnt * sizeof(struct as_confed));

	/* Now reset any peer who's remote AS has just been removed from the
	   CONFED */
	if (bgp_config_check(bgp, BGP_CONFIG_CONFEDERATION)) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as == as) {
				peer->local_as = bgp->confed_id;
				(void)peer_sort(peer);
				if (BGP_IS_VALID_STATE_FOR_NOTIF(
					    peer->connection->status)) {
					peer->last_reset =
						PEER_DOWN_CONFED_PEER_CHANGE;
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_CONFIG_CHANGE);
				} else
					bgp_session_reset_safe(peer, &nnode);
			}
		}
	}
}

/* Local preference configuration.  */
void bgp_default_local_preference_set(struct bgp *bgp, uint32_t local_pref)
{
	if (!bgp)
		return;

	bgp->default_local_pref = local_pref;
}

void bgp_default_local_preference_unset(struct bgp *bgp)
{
	if (!bgp)
		return;

	bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;
}

/* Local preference configuration.  */
void bgp_default_subgroup_pkt_queue_max_set(struct bgp *bgp,
					    uint32_t queue_size)
{
	if (!bgp)
		return;

	bgp->default_subgroup_pkt_queue_max = queue_size;
}

void bgp_default_subgroup_pkt_queue_max_unset(struct bgp *bgp)
{
	if (!bgp)
		return;
	bgp->default_subgroup_pkt_queue_max =
		BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX;
}

/* Listen limit configuration.  */
void bgp_listen_limit_set(struct bgp *bgp, int listen_limit)
{
	if (!bgp)
		return;

	bgp->dynamic_neighbors_limit = listen_limit;
}

void bgp_listen_limit_unset(struct bgp *bgp)
{
	if (!bgp)
		return;

	bgp->dynamic_neighbors_limit = BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT;
}

int bgp_map_afi_safi_iana2int(iana_afi_t pkt_afi, iana_safi_t pkt_safi,
			      afi_t *afi, safi_t *safi)
{
	/* Map from IANA values to internal values, return error if
	 * values are unrecognized.
	 */
	*afi = afi_iana2int(pkt_afi);
	*safi = safi_iana2int(pkt_safi);
	if (*afi == AFI_MAX || *safi == SAFI_MAX)
		return -1;

	return 0;
}

int bgp_map_afi_safi_int2iana(afi_t afi, safi_t safi, iana_afi_t *pkt_afi,
			      iana_safi_t *pkt_safi)
{
	/* Map from internal values to IANA values, return error if
	 * internal values are bad (unexpected).
	 */
	if (afi == AFI_MAX || safi == SAFI_MAX)
		return -1;
	*pkt_afi = afi_int2iana(afi);
	*pkt_safi = safi_int2iana(safi);
	return 0;
}

struct peer_af *peer_af_create(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer_af *af;
	int afid;
	struct bgp *bgp;

	if (!peer)
		return NULL;

	afid = afindex(afi, safi);
	if (afid >= BGP_AF_MAX)
		return NULL;

	bgp = peer->bgp;
	assert(peer->peer_af_array[afid] == NULL);

	/* Allocate new peer af */
	af = XCALLOC(MTYPE_BGP_PEER_AF, sizeof(struct peer_af));

	peer->peer_af_array[afid] = af;
	af->afi = afi;
	af->safi = safi;
	af->afid = afid;
	af->peer = peer;
	bgp->af_peer_count[afi][safi]++;

	return af;
}

struct peer_af *peer_af_find(struct peer *peer, afi_t afi, safi_t safi)
{
	int afid;

	if (!peer)
		return NULL;

	afid = afindex(afi, safi);
	if (afid >= BGP_AF_MAX)
		return NULL;

	return peer->peer_af_array[afid];
}

int peer_af_delete(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer_af *af;
	int afid;
	struct bgp *bgp;

	if (!peer)
		return -1;

	afid = afindex(afi, safi);
	if (afid >= BGP_AF_MAX)
		return -1;

	af = peer->peer_af_array[afid];
	if (!af)
		return -1;

	bgp = peer->bgp;
	bgp_soft_reconfig_table_task_cancel(bgp, bgp->rib[afi][safi], peer);

	bgp_stop_announce_route_timer(af);

	if (PAF_SUBGRP(af)) {
		if (BGP_DEBUG(update_groups, UPDATE_GROUPS))
			zlog_debug("u%" PRIu64 ":s%" PRIu64 " remove peer %s",
				   af->subgroup->update_group->id,
				   af->subgroup->id, peer->host);
	}


	update_subgroup_remove_peer(af->subgroup, af);

	if (bgp->af_peer_count[afi][safi])
		bgp->af_peer_count[afi][safi]--;

	peer->peer_af_array[afid] = NULL;
	XFREE(MTYPE_BGP_PEER_AF, af);
	return 0;
}

/* Peer comparison function for sorting.  */
int peer_cmp(struct peer *p1, struct peer *p2)
{
	if (p1->group && !p2->group)
		return -1;

	if (!p1->group && p2->group)
		return 1;

	if (p1->group == p2->group) {
		if (p1->conf_if && !p2->conf_if)
			return -1;

		if (!p1->conf_if && p2->conf_if)
			return 1;

		if (p1->conf_if && p2->conf_if)
			return if_cmp_name_func(p1->conf_if, p2->conf_if);
	} else
		return strcmp(p1->group->name, p2->group->name);

	return sockunion_cmp(&p1->connection->su, &p2->connection->su);
}

static unsigned int peer_hash_key_make(const void *p)
{
	const struct peer *peer = p;
	return sockunion_hash(&peer->connection->su);
}

static bool peer_hash_same(const void *p1, const void *p2)
{
	const struct peer *peer1 = p1;
	const struct peer *peer2 = p2;

	return (sockunion_same(&peer1->connection->su, &peer2->connection->su) &&
		CHECK_FLAG(peer1->flags, PEER_FLAG_CONFIG_NODE) ==
			CHECK_FLAG(peer2->flags, PEER_FLAG_CONFIG_NODE));
}

void peer_flag_inherit(struct peer *peer, uint64_t flag)
{
	bool group_val;

	/* Skip if peer is not a peer-group member. */
	if (!peer_group_active(peer))
		return;

	/* Unset override flag to signal inheritance from peer-group. */
	UNSET_FLAG(peer->flags_override, flag);

	/*
	 * Inherit flag state from peer-group. If the flag of the peer-group is
	 * not being inverted, the peer must inherit the inverse of the current
	 * peer-group flag state.
	 */
	group_val = CHECK_FLAG(peer->group->conf->flags, flag);
	if (!CHECK_FLAG(peer->group->conf->flags_invert, flag)
	    && CHECK_FLAG(peer->flags_invert, flag))
		COND_FLAG(peer->flags, flag, !group_val);
	else
		COND_FLAG(peer->flags, flag, group_val);
}

bool peer_af_flag_check(struct peer *peer, afi_t afi, safi_t safi,
			uint64_t flag)
{
	return !!CHECK_FLAG(peer->af_flags[afi][safi], flag);
}

void peer_af_flag_inherit(struct peer *peer, afi_t afi, safi_t safi,
			  uint64_t flag)
{
	bool group_val;

	/* Skip if peer is not a peer-group member. */
	if (!peer_group_active(peer))
		return;

	/* Unset override flag to signal inheritance from peer-group. */
	UNSET_FLAG(peer->af_flags_override[afi][safi], flag);

	/*
	 * Inherit flag state from peer-group. If the flag of the peer-group is
	 * not being inverted, the peer must inherit the inverse of the current
	 * peer-group flag state.
	 */
	group_val = CHECK_FLAG(peer->group->conf->af_flags[afi][safi], flag);
	if (!CHECK_FLAG(peer->group->conf->af_flags_invert[afi][safi], flag)
	    && CHECK_FLAG(peer->af_flags_invert[afi][safi], flag))
		COND_FLAG(peer->af_flags[afi][safi], flag, !group_val);
	else
		COND_FLAG(peer->af_flags[afi][safi], flag, group_val);
}

/* Check peer's AS number and determines if this peer is IBGP or EBGP */
static inline enum bgp_peer_sort peer_calc_sort(struct peer *peer)
{
	struct bgp *bgp;
	as_t local_as;

	bgp = peer->bgp;

	if (peer->change_local_as)
		local_as = peer->change_local_as;
	else
		local_as = peer->local_as;

	/* Peer-group */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (CHECK_FLAG(peer->as_type, AS_INTERNAL))
			return BGP_PEER_IBGP;

		if (CHECK_FLAG(peer->as_type, AS_EXTERNAL))
			return BGP_PEER_EBGP;

		else if (peer->as_type == AS_SPECIFIED && peer->as) {
			assert(bgp);
			return (local_as == peer->as ? BGP_PEER_IBGP
						     : BGP_PEER_EBGP);
		}

		else {
			struct peer *peer1;

			assert(peer->group);
			peer1 = listnode_head(peer->group->peer);

			if (peer1)
				return peer1->sort;
		}
		return BGP_PEER_INTERNAL;
	}

	/* Normal peer */
	if (bgp && CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		if (local_as == 0)
			return BGP_PEER_INTERNAL;

		if (local_as == peer->as) {
			if (bgp->as == bgp->confed_id) {
				if (local_as == bgp->as)
					return BGP_PEER_IBGP;
				else
					return BGP_PEER_EBGP;
			} else {
				if (local_as == bgp->confed_id)
					return BGP_PEER_EBGP;
				else
					return BGP_PEER_IBGP;
			}
		}

		if (bgp_confederation_peers_check(bgp, peer->as))
			return BGP_PEER_CONFED;

		return BGP_PEER_EBGP;
	} else {
		if (peer->as_type == AS_UNSPECIFIED) {
			/* check if in peer-group with AS information */
			if (peer->group
			    && (peer->group->conf->as_type != AS_UNSPECIFIED)) {
				if (peer->group->conf->as_type
				    == AS_SPECIFIED) {
					if (local_as == peer->group->conf->as)
						return BGP_PEER_IBGP;
					else
						return BGP_PEER_EBGP;
				} else if (CHECK_FLAG(peer->group->conf->as_type,
						      AS_INTERNAL))
					return BGP_PEER_IBGP;
				else
					return BGP_PEER_EBGP;
			}
			/* no AS information anywhere, let caller know */
			return BGP_PEER_UNSPECIFIED;
		} else if (peer->as_type != AS_SPECIFIED) {
			if (CHECK_FLAG(peer->as_type, AS_INTERNAL))
				return BGP_PEER_IBGP;
			else if (CHECK_FLAG(peer->as_type, AS_EXTERNAL))
				return BGP_PEER_EBGP;
		}

		return (local_as == 0 ? BGP_PEER_INTERNAL
				      : local_as == peer->as ? BGP_PEER_IBGP
							     : BGP_PEER_EBGP);
	}
}

/* Calculate and cache the peer "sort" */
enum bgp_peer_sort peer_sort(struct peer *peer)
{
	peer->sort = peer_calc_sort(peer);
	return peer->sort;
}

enum bgp_peer_sort peer_sort_lookup(struct peer *peer)
{
	return peer->sort;
}

/*
 * Mutex will be freed in peer_connection_free
 * this is a convenience function to reduce cut-n-paste
 */
void bgp_peer_connection_buffers_free(struct peer_connection *connection)
{
	frr_with_mutex (&connection->io_mtx) {
		if (connection->ibuf) {
			stream_fifo_free(connection->ibuf);
			connection->ibuf = NULL;
		}

		if (connection->obuf) {
			stream_fifo_free(connection->obuf);
			connection->obuf = NULL;
		}

		if (connection->ibuf_work) {
			ringbuf_del(connection->ibuf_work);
			connection->ibuf_work = NULL;
		}
	}
}

void bgp_peer_connection_free(struct peer_connection **connection)
{
	bgp_peer_connection_buffers_free(*connection);
	pthread_mutex_destroy(&(*connection)->io_mtx);

	memset(*connection, 0, sizeof(struct peer_connection));
	XFREE(MTYPE_BGP_PEER_CONNECTION, *connection);

	connection = NULL;
}

struct peer_connection *bgp_peer_connection_new(struct peer *peer)
{
	struct peer_connection *connection;

	connection = XCALLOC(MTYPE_BGP_PEER_CONNECTION,
			     sizeof(struct peer_connection));

	connection->peer = peer;
	connection->fd = -1;

	connection->ibuf = stream_fifo_new();
	connection->obuf = stream_fifo_new();
	pthread_mutex_init(&connection->io_mtx, NULL);

	/* We use a larger buffer for peer->obuf_work in the event that:
	 * - We RX a BGP_UPDATE where the attributes alone are just
	 *   under BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE.
	 * - The user configures an outbound route-map that does many as-path
	 *   prepends or adds many communities. At most they can have
	 *   CMD_ARGC_MAX args in a route-map so there is a finite limit on how
	 *   large they can make the attributes.
	 *
	 * Having a buffer with BGP_MAX_PACKET_SIZE_OVERFLOW allows us to avoid
	 * bounds checking for every single attribute as we construct an
	 * UPDATE.
	 */
	connection->ibuf_work =
		ringbuf_new(BGP_MAX_PACKET_SIZE * BGP_READ_PACKET_MAX);

	connection->status = Idle;
	connection->ostatus = Idle;

	return connection;
}

static void peer_free(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	assert(peer->connection->status == Deleted);

	QOBJ_UNREG(peer);

	/* this /ought/ to have been done already through bgp_stop earlier,
	 * but just to be sure..
	 */
	bgp_timer_set(peer->connection);
	bgp_reads_off(peer->connection);
	bgp_writes_off(peer->connection);
	event_cancel_event_ready(bm->master, peer->connection);
	FOREACH_AFI_SAFI (afi, safi)
		EVENT_OFF(peer->t_revalidate_all[afi][safi]);
	assert(!peer->connection->t_write);
	assert(!peer->connection->t_read);

	/* Free connected nexthop, if present */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE)
	    && !peer_dynamic_neighbor(peer))
		bgp_delete_connected_nexthop(family2afi(peer->connection->su.sa
								.sa_family),
					     peer);

	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->filter[afi][safi].advmap.aname)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      peer->filter[afi][safi].advmap.aname);
		if (peer->filter[afi][safi].advmap.cname)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      peer->filter[afi][safi].advmap.cname);
	}

	XFREE(MTYPE_PEER_TX_SHUTDOWN_MSG, peer->tx_shutdown_message);

	XFREE(MTYPE_PEER_DESC, peer->desc);
	XFREE(MTYPE_BGP_PEER_HOST, peer->host);
	XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
	XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);
	XFREE(MTYPE_BGP_PEER_IFNAME, peer->ifname);

	/* Update source configuration.  */
	if (peer->update_source) {
		sockunion_free(peer->update_source);
		peer->update_source = NULL;
	}

	XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);

	XFREE(MTYPE_BGP_NOTIFICATION, peer->notify.data);
	memset(&peer->notify, 0, sizeof(struct bgp_notify));

	if (peer->clear_node_queue)
		work_queue_free_and_null(&peer->clear_node_queue);

	XFREE(MTYPE_PEER_CONF_IF, peer->conf_if);

	XFREE(MTYPE_BGP_SOFT_VERSION, peer->soft_version);

	/* Remove BFD configuration. */
	if (peer->bfd_config)
		bgp_peer_remove_bfd_config(peer);

	FOREACH_AFI_SAFI (afi, safi)
		bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_NONE, 0);

	if (peer->change_local_as_pretty)
		XFREE(MTYPE_BGP_NAME, peer->change_local_as_pretty);
	if (peer->as_pretty)
		XFREE(MTYPE_BGP_NAME, peer->as_pretty);

	bgp_peer_connection_free(&peer->connection);

	bgp_unlock(peer->bgp);

	stream_free(peer->last_reset_cause);

	memset(peer, 0, sizeof(struct peer));

	XFREE(MTYPE_BGP_PEER, peer);
}

/* increase reference count on a struct peer */
struct peer *peer_lock_with_caller(const char *name, struct peer *peer)
{
	frrtrace(2, frr_bgp, bgp_peer_lock, peer, name);
	assert(peer && (peer->lock >= 0));

	peer->lock++;

	return peer;
}

/* decrease reference count on a struct peer
 * struct peer is freed and NULL returned if last reference
 */
struct peer *peer_unlock_with_caller(const char *name, struct peer *peer)
{
	frrtrace(2, frr_bgp, bgp_peer_unlock, peer, name);
	assert(peer && (peer->lock > 0));

	peer->lock--;

	if (peer->lock == 0) {
		peer_free(peer);
		return NULL;
	}

	return peer;
}
/* BGP GR changes */

int bgp_global_gr_init(struct bgp *bgp)
{
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s called ..", __func__);

	int local_GLOBAL_GR_FSM[BGP_GLOBAL_GR_MODE][BGP_GLOBAL_GR_EVENT_CMD] = {
		/* GLOBAL_HELPER Mode  */
		{
		/*Event -> */
		/*GLOBAL_GR_cmd*/  /*no_Global_GR_cmd*/
			GLOBAL_GR,      GLOBAL_INVALID,
		/*GLOBAL_DISABLE_cmd*/ /*no_Global_Disable_cmd*/
			GLOBAL_DISABLE, GLOBAL_INVALID
		},
		/* GLOBAL_GR Mode */
		{
		/*Event -> */
		/*GLOBAL_GR_cmd*/ /*no_Global_GR_cmd*/
			GLOBAL_GR,  GLOBAL_HELPER,
		/*GLOBAL_DISABLE_cmd*/ /*no_Global_Disable_cmd*/
			GLOBAL_DISABLE,  GLOBAL_INVALID
		},
		/* GLOBAL_DISABLE Mode  */
		{
		/*Event -> */
		/*GLOBAL_GR_cmd */	/*no_Global_GR_cmd*/
			GLOBAL_GR,      GLOBAL_INVALID,
		/*GLOBAL_DISABLE_cmd*//*no_Global_Disable_cmd*/
			GLOBAL_DISABLE,	GLOBAL_HELPER
		},
		/* GLOBAL_INVALID Mode  */
		{
		/*Event -> */
		/*GLOBAL_GR_cmd*/	/*no_Global_GR_cmd*/
			GLOBAL_INVALID, GLOBAL_INVALID,
		/*GLOBAL_DISABLE_cmd*/ /*no_Global_Disable_cmd*/
			GLOBAL_INVALID, GLOBAL_INVALID
		}
	};
	memcpy(bgp->GLOBAL_GR_FSM, local_GLOBAL_GR_FSM,
					sizeof(local_GLOBAL_GR_FSM));

	/* Inherit any BGP-wide configuration. */
	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER))
		bgp->global_gr_present_state = GLOBAL_GR;
	else if (CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED))
		bgp->global_gr_present_state = GLOBAL_DISABLE;
	else
		bgp->global_gr_present_state = GLOBAL_HELPER;

	if (bm->restart_time != BGP_DEFAULT_RESTART_TIME)
		bgp->restart_time = bm->restart_time;
	if (bm->stalepath_time != BGP_DEFAULT_STALEPATH_TIME)
		bgp->stalepath_time = bm->stalepath_time;
	if (bm->select_defer_time != BGP_DEFAULT_SELECT_DEFERRAL_TIME)
		bgp->select_defer_time = bm->select_defer_time;
	if (bm->rib_stale_time != BGP_DEFAULT_RIB_STALE_TIME)
		bgp->rib_stale_time = bm->rib_stale_time;
	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	if (CHECK_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA))
		SET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);

	bgp->present_zebra_gr_state = ZEBRA_GR_DISABLE;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s: Global GR state is %s", bgp->name_pretty,
			   print_global_gr_mode(bgp->global_gr_present_state));

	return BGP_GR_SUCCESS;
}

int bgp_peer_gr_init(struct peer *peer)
{
	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("%s called ..", __func__);

	struct bgp_peer_gr local_Peer_GR_FSM[BGP_PEER_GR_MODE]
					[BGP_PEER_GR_EVENT_CMD] = {
	{
	/*	PEER_HELPER Mode	*/
	/* Event-> */ /* PEER_GR_CMD */ /* NO_PEER_GR_CMD */
		{ PEER_GR, bgp_peer_gr_action }, {PEER_INVALID, NULL },
	/* Event-> */ /* PEER_DISABLE_CMD */ /* NO_PEER_DISABLE_CMD */
		{PEER_DISABLE, bgp_peer_gr_action }, {PEER_INVALID, NULL },
	/* Event-> */ /* PEER_HELPER_cmd */ /* NO_PEER_HELPER_CMD */
		{ PEER_HELPER, NULL }, {PEER_GLOBAL_INHERIT,
						bgp_peer_gr_action }
	},
	{
	/*	PEER_GR Mode	*/
	/* Event-> */ /* PEER_GR_CMD */ /* NO_PEER_GR_CMD */
		{ PEER_GR, NULL }, { PEER_GLOBAL_INHERIT,
						bgp_peer_gr_action },
	/* Event-> */ /* PEER_DISABLE_CMD */ /* NO_PEER_DISABLE_CMD */
		{PEER_DISABLE, bgp_peer_gr_action }, { PEER_INVALID, NULL },
	/* Event-> */ /* PEER_HELPER_cmd */ /* NO_PEER_HELPER_CMD */
		{ PEER_HELPER, bgp_peer_gr_action }, { PEER_INVALID, NULL }
	},
	{
	/*	PEER_DISABLE Mode	*/
	/* Event-> */ /* PEER_GR_CMD */ /* NO_PEER_GR_CMD */
		{ PEER_GR, bgp_peer_gr_action }, { PEER_INVALID, NULL },
	/* Event-> */ /* PEER_DISABLE_CMD */ /* NO_PEER_DISABLE_CMD */
		{ PEER_DISABLE, NULL }, { PEER_GLOBAL_INHERIT,
						bgp_peer_gr_action },
	/* Event-> */ /* PEER_HELPER_cmd */  /* NO_PEER_HELPER_CMD */
		{ PEER_HELPER, bgp_peer_gr_action }, { PEER_INVALID, NULL }
	},
	{
	/*	PEER_INVALID Mode	*/
	/* Event-> */ /* PEER_GR_CMD */  /* NO_PEER_GR_CMD */
		{ PEER_INVALID, NULL }, { PEER_INVALID, NULL },
	/* Event-> */ /* PEER_DISABLE_CMD */  /* NO_PEER_DISABLE_CMD */
		{ PEER_INVALID, NULL }, { PEER_INVALID, NULL },
	/* Event-> */ /* PEER_HELPER_cmd */  /* NO_PEER_HELPER_CMD */
		{ PEER_INVALID, NULL }, { PEER_INVALID, NULL },
	},
	{
	/*	PEER_GLOBAL_INHERIT Mode	*/
	/* Event-> */ /* PEER_GR_CMD */		/* NO_PEER_GR_CMD */
		{ PEER_GR, bgp_peer_gr_action }, { PEER_GLOBAL_INHERIT, NULL },
	/* Event-> */ /* PEER_DISABLE_CMD */     /* NO_PEER_DISABLE_CMD */
		{ PEER_DISABLE, bgp_peer_gr_action }, { PEER_GLOBAL_INHERIT, NULL },
	/* Event-> */ /* PEER_HELPER_cmd */     /* NO_PEER_HELPER_CMD */
		{ PEER_HELPER, bgp_peer_gr_action }, { PEER_GLOBAL_INHERIT, NULL }
	}
	};
	memcpy(&peer->PEER_GR_FSM, local_Peer_GR_FSM, sizeof(local_Peer_GR_FSM));
	bgp_peer_move_to_gr_mode(peer, PEER_GLOBAL_INHERIT);

	return BGP_GR_SUCCESS;
}

static void bgp_srv6_init(struct bgp *bgp)
{
	bgp->srv6_enabled = false;
	memset(bgp->srv6_locator_name, 0, sizeof(bgp->srv6_locator_name));
	bgp->srv6_locator_chunks = list_new();
	bgp->srv6_locator_chunks->del = srv6_locator_chunk_list_free;
	bgp->srv6_functions = list_new();
	bgp->srv6_functions->del = (void (*)(void *))srv6_function_free;
}

static void bgp_srv6_cleanup(struct bgp *bgp)
{
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		if (bgp->vpn_policy[afi].tovpn_sid_locator != NULL) {
			srv6_locator_free(
				bgp->vpn_policy[afi].tovpn_sid_locator);
			bgp->vpn_policy[afi].tovpn_sid_locator = NULL;
		}
		if (bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent != NULL)
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent);
		if (bgp->vpn_policy[afi].tovpn_sid != NULL) {
			sid_unregister(bgp, bgp->vpn_policy[afi].tovpn_sid);
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp->vpn_policy[afi].tovpn_sid);
		}
	}

	if (bgp->tovpn_sid_locator != NULL) {
		srv6_locator_free(bgp->tovpn_sid_locator);
		bgp->tovpn_sid_locator = NULL;
	}
	if (bgp->tovpn_zebra_vrf_sid_last_sent != NULL)
		XFREE(MTYPE_BGP_SRV6_SID, bgp->tovpn_zebra_vrf_sid_last_sent);
	if (bgp->tovpn_sid != NULL) {
		sid_unregister(bgp, bgp->tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->tovpn_sid);
	}

	if (bgp->srv6_locator_chunks)
		list_delete(&bgp->srv6_locator_chunks);
	if (bgp->srv6_functions)
		list_delete(&bgp->srv6_functions);

	srv6_locator_free(bgp->srv6_locator);
	bgp->srv6_locator = NULL;
}

/* Allocate new peer object, implicitely locked.  */
struct peer *peer_new(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct servent *sp;

	/* bgp argument is absolutely required */
	assert(bgp);

	/* Allocate new peer. */
	peer = XCALLOC(MTYPE_BGP_PEER, sizeof(struct peer));

	/* Create buffers. */
	peer->connection = bgp_peer_connection_new(peer);

	/* Set default value. */
	peer->v_start = BGP_INIT_START_TIMER;
	peer->v_connect = bgp->default_connect_retry;
	peer->cur_event = peer->last_event = peer->last_major_event = 0;
	peer->bgp = bgp_lock(bgp);
	peer = peer_lock(peer); /* initial reference */
	peer->local_role = ROLE_UNDEFINED;
	peer->remote_role = ROLE_UNDEFINED;
	peer->password = NULL;
	peer->max_packet_size = BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE;

	/* Set default flags. */
	FOREACH_AFI_SAFI (afi, safi) {
		SET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(peer->af_flags[afi][safi],
			 PEER_FLAG_SEND_EXT_COMMUNITY);
		SET_FLAG(peer->af_flags[afi][safi],
			 PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
		SET_FLAG(peer->af_flags[afi][safi],
			 PEER_FLAG_SEND_LARGE_COMMUNITY);

		SET_FLAG(peer->af_flags_invert[afi][safi],
			 PEER_FLAG_SEND_COMMUNITY);
		SET_FLAG(peer->af_flags_invert[afi][safi],
			 PEER_FLAG_SEND_EXT_COMMUNITY);
		SET_FLAG(peer->af_flags_invert[afi][safi],
			 PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
		SET_FLAG(peer->af_flags_invert[afi][safi],
			 PEER_FLAG_SEND_LARGE_COMMUNITY);
		peer->addpath_type[afi][safi] = BGP_ADDPATH_NONE;
		peer->addpath_best_selected[afi][safi] = 0;
		peer->addpath_paths_limit[afi][safi].receive = 0;
		peer->addpath_paths_limit[afi][safi].send = 0;
		peer->soo[afi][safi] = NULL;
	}

	/* set nexthop-unchanged for l2vpn evpn by default */
	SET_FLAG(peer->af_flags[AFI_L2VPN][SAFI_EVPN],
		 PEER_FLAG_NEXTHOP_UNCHANGED);

	SET_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
		peer_flag_set(peer, PEER_FLAG_ENFORCE_FIRST_AS);

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION);

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY))
		peer_flag_set(peer, PEER_FLAG_DYNAMIC_CAPABILITY);

	SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_FQDN);
	SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_FQDN);

	/* Initialize per peer bgp GR FSM */
	bgp_peer_gr_init(peer);

	/* Get service port number.  */
	sp = getservbyname("bgp", "tcp");
	peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);

	QOBJ_REG(peer, peer);
	return peer;
}

/*
 * This function is invoked when a duplicate peer structure associated with
 * a neighbor is being deleted. If this about-to-be-deleted structure is
 * the one with all the config, then we have to copy over the info.
 */
void peer_xfer_config(struct peer *peer_dst, struct peer *peer_src)
{
	struct peer_af *paf;
	afi_t afi;
	safi_t safi;
	int afidx;

	assert(peer_src);
	assert(peer_dst);

	/* The following function is used by both peer group config copy to
	 * individual peer and when we transfer config
	 */
	if (peer_src->change_local_as)
		peer_dst->change_local_as = peer_src->change_local_as;

	/* peer flags apply */
	peer_dst->flags = peer_src->flags;
	/*
	 * The doppelganger *must* not have a config node stored
	 */
	UNSET_FLAG(peer_dst->flags, PEER_FLAG_CONFIG_NODE);
	peer_dst->peer_gr_present_state = peer_src->peer_gr_present_state;
	peer_dst->peer_gr_new_status_flag = peer_src->peer_gr_new_status_flag;

	peer_dst->local_as = peer_src->local_as;
	peer_dst->port = peer_src->port;
	/* copy tcp_mss value */
	peer_dst->tcp_mss = peer_src->tcp_mss;
	(void)peer_sort(peer_dst);
	peer_dst->sub_sort = peer_src->sub_sort;
	peer_dst->rmap_type = peer_src->rmap_type;
	peer_dst->local_role = peer_src->local_role;

	peer_dst->max_packet_size = peer_src->max_packet_size;

	/* Timers */
	peer_dst->holdtime = peer_src->holdtime;
	peer_dst->keepalive = peer_src->keepalive;
	peer_dst->connect = peer_src->connect;
	peer_dst->delayopen = peer_src->delayopen;
	peer_dst->v_holdtime = peer_src->v_holdtime;
	peer_dst->v_keepalive = peer_src->v_keepalive;
	peer_dst->routeadv = peer_src->routeadv;
	peer_dst->v_routeadv = peer_src->v_routeadv;
	peer_dst->v_delayopen = peer_src->v_delayopen;

	/* password apply */
	if (peer_src->password) {
		XFREE(MTYPE_PEER_PASSWORD, peer_dst->password);
		peer_dst->password =
			XSTRDUP(MTYPE_PEER_PASSWORD, peer_src->password);
	}

	FOREACH_AFI_SAFI (afi, safi) {
		peer_dst->afc[afi][safi] = peer_src->afc[afi][safi];
		peer_dst->af_flags[afi][safi] = peer_src->af_flags[afi][safi];
		peer_dst->allowas_in[afi][safi] =
			peer_src->allowas_in[afi][safi];
		peer_dst->weight[afi][safi] = peer_src->weight[afi][safi];
		peer_dst->addpath_type[afi][safi] =
			peer_src->addpath_type[afi][safi];
		peer_dst->addpath_paths_limit[afi][safi] =
			peer_src->addpath_paths_limit[afi][safi];
	}

	for (afidx = BGP_AF_START; afidx < BGP_AF_MAX; afidx++) {
		paf = peer_src->peer_af_array[afidx];
		if (paf != NULL) {
			if (!peer_af_find(peer_dst, paf->afi, paf->safi))
				peer_af_create(peer_dst, paf->afi, paf->safi);
		}
	}

	/* update-source apply */
	if (peer_src->update_source) {
		if (peer_dst->update_source)
			sockunion_free(peer_dst->update_source);
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer_dst->update_if);
		peer_dst->update_source =
			sockunion_dup(peer_src->update_source);
	} else if (peer_src->update_if) {
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer_dst->update_if);
		if (peer_dst->update_source) {
			sockunion_free(peer_dst->update_source);
			peer_dst->update_source = NULL;
		}
		peer_dst->update_if =
			XSTRDUP(MTYPE_PEER_UPDATE_SOURCE, peer_src->update_if);
	}

	if (peer_src->ifname) {
		XFREE(MTYPE_BGP_PEER_IFNAME, peer_dst->ifname);

		peer_dst->ifname =
			XSTRDUP(MTYPE_BGP_PEER_IFNAME, peer_src->ifname);
	}
	peer_dst->ttl = peer_src->ttl;
	peer_dst->gtsm_hops = peer_src->gtsm_hops;
}

static int bgp_peer_conf_if_to_su_update_v4(struct peer_connection *connection,
					    struct interface *ifp)
{
	struct connected *ifc;
	struct prefix p;
	uint32_t addr;

	/* If our IPv4 address on the interface is /30 or /31, we can derive the
	 * IPv4 address of the other end.
	 */
	frr_each (if_connected, ifp->connected, ifc) {
		if (ifc->address && (ifc->address->family == AF_INET)) {
			prefix_copy(&p, CONNECTED_PREFIX(ifc));
			if (p.prefixlen == 30) {
				connection->su.sa.sa_family = AF_INET;
				addr = ntohl(p.u.prefix4.s_addr);
				if (addr % 4 == 1)
					connection->su.sin.sin_addr.s_addr =
						htonl(addr + 1);
				else if (addr % 4 == 2)
					connection->su.sin.sin_addr.s_addr =
						htonl(addr - 1);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
				connection->su.sin.sin_len =
					sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
				return 1;
			} else if (p.prefixlen == 31) {
				connection->su.sa.sa_family = AF_INET;
				addr = ntohl(p.u.prefix4.s_addr);
				if (addr % 2 == 0)
					connection->su.sin.sin_addr.s_addr =
						htonl(addr + 1);
				else
					connection->su.sin.sin_addr.s_addr =
						htonl(addr - 1);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
				connection->su.sin.sin_len =
					sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
				return 1;
			} else if (bgp_debug_neighbor_events(connection->peer))
				zlog_debug("%s: IPv4 interface address is not /30 or /31, v4 session not started",
					   connection->peer->conf_if);
		}
	}

	return 0;
}

static bool bgp_peer_conf_if_to_su_update_v6(struct peer_connection *connection,
					     struct interface *ifp)
{
	struct nbr_connected *ifc_nbr;

	/* Have we learnt the peer's IPv6 link-local address? */
	if (ifp->nbr_connected
	    && (ifc_nbr = listnode_head(ifp->nbr_connected))) {
		connection->su.sa.sa_family = AF_INET6;
		memcpy(&connection->su.sin6.sin6_addr,
		       &ifc_nbr->address->u.prefix, sizeof(struct in6_addr));
#ifdef SIN6_LEN
		connection->su.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		connection->su.sin6.sin6_scope_id = ifp->ifindex;
		return true;
	}

	return false;
}

/*
 * Set or reset the peer address socketunion structure based on the
 * learnt/derived peer address. If the address has changed, update the
 * password on the listen socket, if needed.
 */
void bgp_peer_conf_if_to_su_update(struct peer_connection *connection)
{
	struct interface *ifp;
	int prev_family;
	int peer_addr_updated = 0;
	struct listnode *node;
	union sockunion old_su;
	struct peer *peer = connection->peer;

	/*
	 * This function is only ever needed when FRR an interface
	 * based peering, so this simple test will tell us if
	 * we are in an interface based configuration or not
	 */
	if (!peer->conf_if)
		return;

	old_su = connection->su;

	prev_family = connection->su.sa.sa_family;
	if ((ifp = if_lookup_by_name(peer->conf_if, peer->bgp->vrf_id))) {
		peer->ifp = ifp;
		/* If BGP unnumbered is not "v6only", we first see if we can
		 * derive the
		 * peer's IPv4 address.
		 */
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
			peer_addr_updated =
				bgp_peer_conf_if_to_su_update_v4(connection,
								 ifp);

		/* If "v6only" or we can't derive peer's IPv4 address, see if
		 * we've
		 * learnt the peer's IPv6 link-local address. This is from the
		 * source
		 * IPv6 address in router advertisement.
		 */
		if (!peer_addr_updated)
			peer_addr_updated =
				bgp_peer_conf_if_to_su_update_v6(connection,
								 ifp);
	}
	/* If we could derive the peer address, we may need to install the
	 * password
	 * configured for the peer, if any, on the listen socket. Otherwise,
	 * mark
	 * that peer's address is not available and uninstall the password, if
	 * needed.
	 */
	if (peer_addr_updated) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD)
		    && prev_family == AF_UNSPEC)
			bgp_md5_set(connection);
	} else {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD)
		    && prev_family != AF_UNSPEC)
			bgp_md5_unset(connection);
		connection->su.sa.sa_family = AF_UNSPEC;
		memset(&connection->su.sin6.sin6_addr, 0,
		       sizeof(struct in6_addr));
	}

	/*
	 * If they are the same, nothing to do here, move along
	 */
	if (!sockunion_same(&old_su, &connection->su)) {
		union sockunion new_su = connection->su;
		struct bgp *bgp = peer->bgp;

		/*
		 * Our peer structure is stored in the bgp->peerhash
		 * release it before we modify anything in both the
		 * hash and the list.  But *only* if the peer
		 * is in the bgp->peerhash as that on deletion
		 * we call bgp_stop which calls this function :(
		 * so on deletion let's remove from the list first
		 * and then do the deletion preventing this from
		 * being added back on the list below when we
		 * fail to remove it up here.
		 */

		/*
		 * listnode_lookup just scans the list
		 * for the peer structure so it's safe
		 * to use without modifying the su
		 */
		node = listnode_lookup(bgp->peer, peer);
		if (node) {
			/*
			 * Let's reset the peer->su release and
			 * reset it and put it back.  We have to
			 * do this because hash_release will
			 * scan through looking for a matching
			 * su if needed.
			 */
			connection->su = old_su;
			hash_release(peer->bgp->peerhash, peer);
			listnode_delete(peer->bgp->peer, peer);

			connection->su = new_su;
			(void)hash_get(peer->bgp->peerhash, peer,
				       hash_alloc_intern);
			listnode_add_sort(peer->bgp->peer, peer);
		}
	}
}

void bgp_recalculate_afi_safi_bestpaths(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest, *ndest;
	struct bgp_path_info *pi, *next;
	struct bgp_table *table;

	for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		table = bgp_dest_get_bgp_table_info(dest);

		if (!table)
			continue;

		/* Special handling for 2-level routing
		 * tables. */
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			for (ndest = bgp_table_top(table); ndest;
			     ndest = bgp_route_next(ndest)) {
				for (pi = bgp_dest_get_bgp_path_info(ndest);
				     (pi != NULL) && (next = pi->next, 1);
				     pi = next)
					bgp_process(bgp, ndest, pi, afi, safi);
			}
		} else {
			for (pi = bgp_dest_get_bgp_path_info(dest);
			     (pi != NULL) && (next = pi->next, 1); pi = next)
				bgp_process(bgp, dest, pi, afi, safi);
		}
	}
}

/* Force a bestpath recalculation for all prefixes.  This is used
 * when 'bgp bestpath' commands are entered.
 */
void bgp_recalculate_all_bestpaths(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		bgp_recalculate_afi_safi_bestpaths(bgp, afi, safi);
	}
}

/*
 * Create new BGP peer.
 *
 * conf_if and su are mutually exclusive if configuring from the cli.
 * If we are handing a doppelganger, then we *must* pass in both
 * the original peer's su and conf_if, so that we can appropriately
 * track the bgp->peerhash( ie we don't want to remove the current
 * one from the config ).
 */
struct peer *peer_create(union sockunion *su, const char *conf_if,
			 struct bgp *bgp, as_t local_as, as_t remote_as,
			 enum peer_asn_type as_type, struct peer_group *group,
			 bool config_node, const char *as_str)
{
	int active;
	struct peer *peer;
	char buf[SU_ADDRSTRLEN];
	afi_t afi;
	safi_t safi;

	peer = peer_new(bgp);
	if (conf_if) {
		peer->conf_if = XSTRDUP(MTYPE_PEER_CONF_IF, conf_if);
		if (su)
			peer->connection->su = *su;
		else
			bgp_peer_conf_if_to_su_update(peer->connection);
		XFREE(MTYPE_BGP_PEER_HOST, peer->host);
		peer->host = XSTRDUP(MTYPE_BGP_PEER_HOST, conf_if);
	} else if (su) {
		peer->connection->su = *su;
		sockunion2str(su, buf, SU_ADDRSTRLEN);
		XFREE(MTYPE_BGP_PEER_HOST, peer->host);
		peer->host = XSTRDUP(MTYPE_BGP_PEER_HOST, buf);
	}
	peer->local_as = local_as;
	peer->as = remote_as;
	/* internal and external values do not use as_pretty */
	if (as_str && asn_str2asn(as_str, NULL))
		peer->as_pretty = XSTRDUP(MTYPE_BGP_NAME, as_str);
	peer->as_type = as_type;
	peer->local_id = bgp->router_id;
	peer->v_holdtime = bgp->default_holdtime;
	peer->v_keepalive = bgp->default_keepalive;
	peer->v_routeadv = (peer_sort(peer) == BGP_PEER_IBGP)
				   ? BGP_DEFAULT_IBGP_ROUTEADV
				   : BGP_DEFAULT_EBGP_ROUTEADV;
	if (bgp_config_inprocess())
		peer->shut_during_cfg = true;

	peer = peer_lock(peer); /* bgp peer list reference */
	peer->group = group;
	listnode_add_sort(bgp->peer, peer);

	if (config_node)
		SET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	(void)hash_get(bgp->peerhash, peer, hash_alloc_intern);

	/* Adjust update-group coalesce timer heuristics for # peers. */
	if (bgp->heuristic_coalesce) {
		long ct = BGP_DEFAULT_SUBGROUP_COALESCE_TIME
			  + (bgp->peer->count
			     * BGP_PEER_ADJUST_SUBGROUP_COALESCE_TIME);
		bgp->coalesce_time = MIN(BGP_MAX_SUBGROUP_COALESCE_TIME, ct);
	}

	active = peer_active(peer);
	if (!active) {
		if (peer->connection->su.sa.sa_family == AF_UNSPEC)
			peer->last_reset = PEER_DOWN_NBR_ADDR;
		else
			peer->last_reset = PEER_DOWN_NOAFI_ACTIVATED;
	}

	/* Last read and reset time set */
	peer->readtime = peer->resettime = monotime(NULL);

	/* Default TTL set. */
	peer->ttl = (peer->sort == BGP_PEER_IBGP) ? MAXTTL : BGP_DEFAULT_TTL;

	/* Default configured keepalives count for shutdown rtt command */
	peer->rtt_keepalive_conf = 1;

	/* If 'bgp default <afi>-<safi>' is configured, then activate the
	 * neighbor for the corresponding address family. IPv4 Unicast is
	 * the only address family enabled by default without expliict
	 * configuration.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->default_af[afi][safi]) {
			peer->afc[afi][safi] = 1;
			peer_af_create(peer, afi, safi);
		}
	}

	/* auto shutdown if configured */
	if (bgp->autoshutdown)
		peer_flag_set(peer, PEER_FLAG_SHUTDOWN);
	/* Set up peer's events and timers. */
	else if (!active && peer_active(peer))
		bgp_timer_set(peer->connection);

	bgp_peer_gr_flags_update(peer);
	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer);

	return peer;
}

/* Make accept BGP peer. This function is only called from the test code */
struct peer *peer_create_accept(struct bgp *bgp)
{
	struct peer *peer;

	peer = peer_new(bgp);

	peer = peer_lock(peer); /* bgp peer list reference */
	listnode_add_sort(bgp->peer, peer);
	(void)hash_get(bgp->peerhash, peer, hash_alloc_intern);

	return peer;
}

/*
 * Return true if we have a peer configured to use this afi/safi
 */
bool bgp_afi_safi_peer_exists(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct listnode *node;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (peer->afc[afi][safi])
			return true;
	}

	return false;
}

/* Change peer's AS number.  */
void peer_as_change(struct peer *peer, as_t as, enum peer_asn_type as_type,
		    const char *as_str)
{
	enum bgp_peer_sort origtype, newtype;

	/* Stop peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_REMOTE_AS_CHANGE;
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);
	}
	origtype = peer_sort_lookup(peer);
	peer->as = as;
	if (as_type == AS_SPECIFIED && as_str) {
		if (peer->as_pretty)
			XFREE(MTYPE_BGP_NAME, peer->as_pretty);
		peer->as_pretty = XSTRDUP(MTYPE_BGP_NAME, as_str);
	} else if (peer->as_type == AS_UNSPECIFIED && peer->as_pretty)
		XFREE(MTYPE_BGP_NAME, peer->as_pretty);
	peer->as_type = as_type;

	if (bgp_config_check(peer->bgp, BGP_CONFIG_CONFEDERATION)
	    && !bgp_confederation_peers_check(peer->bgp, as)
	    && peer->bgp->as != as)
		peer->local_as = peer->bgp->confed_id;
	else
		peer->local_as = peer->bgp->as;

	newtype = peer_sort(peer);
	/* Advertisement-interval reset */
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_ROUTEADV)) {
		peer->v_routeadv = (newtype == BGP_PEER_IBGP)
					   ? BGP_DEFAULT_IBGP_ROUTEADV
					   : BGP_DEFAULT_EBGP_ROUTEADV;
	}

	/* TTL reset */
	if (newtype == BGP_PEER_IBGP)
		peer->ttl = MAXTTL;
	else if (origtype == BGP_PEER_IBGP)
		peer->ttl = BGP_DEFAULT_TTL;

	/* reflector-client reset */
	if (newtype != BGP_PEER_IBGP) {
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_UNICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_MULTICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_LABELED_UNICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_MPLS_VPN],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_ENCAP],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP][SAFI_FLOWSPEC],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_UNICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_MULTICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_LABELED_UNICAST],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_MPLS_VPN],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_ENCAP],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_IP6][SAFI_FLOWSPEC],
			   PEER_FLAG_REFLECTOR_CLIENT);
		UNSET_FLAG(peer->af_flags[AFI_L2VPN][SAFI_EVPN],
			   PEER_FLAG_REFLECTOR_CLIENT);
	}
}

/* If peer does not exist, create new one.  If peer already exists,
   set AS number to the peer.  */
int peer_remote_as(struct bgp *bgp, union sockunion *su, const char *conf_if,
		   as_t *as, enum peer_asn_type as_type, const char *as_str)
{
	struct peer *peer;
	as_t local_as;

	if (conf_if)
		peer = peer_lookup_by_conf_if(bgp, conf_if);
	else
		peer = peer_lookup(bgp, su);

	if (peer) {
		/* Not allowed for a dynamic peer. */
		if (peer_dynamic_neighbor(peer)) {
			*as = peer->as;
			return BGP_ERR_INVALID_FOR_DYNAMIC_PEER;
		}

		/* When this peer is a member of peer-group.  */
		if (peer->group) {
			/* peer-group already has AS number/internal/external */
			if (peer->group->conf->as
			    || peer->group->conf->as_type) {
				/* Return peer group's AS number.  */
				*as = peer->group->conf->as;
				return BGP_ERR_PEER_GROUP_MEMBER;
			}

			enum bgp_peer_sort peer_sort_type =
				peer_sort(peer->group->conf);

			/* Explicit AS numbers used, compare AS numbers */
			if (as_type == AS_SPECIFIED) {
				if (((peer_sort_type == BGP_PEER_IBGP)
				    && (bgp->as != *as))
				    || ((peer_sort_type == BGP_PEER_EBGP)
				    && (bgp->as == *as))) {
					*as = peer->as;
					return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
				}
			} else {
				/* internal/external used, compare as-types */
				if (((peer_sort_type == BGP_PEER_IBGP) &&
				     !CHECK_FLAG(as_type, AS_INTERNAL)) ||
				    ((peer_sort_type == BGP_PEER_EBGP) &&
				     !CHECK_FLAG(as_type, AS_EXTERNAL))) {
					*as = peer->as;
					return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
				}
			}
		}

		/* Existing peer's AS number change. */
		if (((peer->as_type == AS_SPECIFIED) && peer->as != *as)
		    || (peer->as_type != as_type))
			peer_as_change(peer, *as, as_type, as_str);
	} else {
		if (conf_if)
			return BGP_ERR_NO_INTERFACE_CONFIG;

		/* If the peer is not part of our confederation, and its not an
		   iBGP peer then spoof the source AS */
		if (bgp_config_check(bgp, BGP_CONFIG_CONFEDERATION) &&
		    !bgp_confederation_peers_check(bgp, *as) && *as &&
		    bgp->as != *as)
			local_as = bgp->confed_id;
		else
			local_as = bgp->as;

		peer_create(su, conf_if, bgp, local_as, *as, as_type, NULL,
			    true, as_str);
	}

	return 0;
}

const char *bgp_get_name_by_role(uint8_t role)
{
	switch (role) {
	case ROLE_PROVIDER:
		return "provider";
	case ROLE_RS_SERVER:
		return "rs-server";
	case ROLE_RS_CLIENT:
		return "rs-client";
	case ROLE_CUSTOMER:
		return "customer";
	case ROLE_PEER:
		return "peer";
	case ROLE_UNDEFINED:
		return "undefined";
	}
	return "unknown";
}

enum asnotation_mode bgp_get_asnotation(struct bgp *bgp)
{
	if (!bgp)
		return ASNOTATION_PLAIN;
	return bgp->asnotation;
}

static void peer_group2peer_config_copy_af(struct peer_group *group,
					   struct peer *peer, afi_t afi,
					   safi_t safi)
{
	int in = FILTER_IN;
	int out = FILTER_OUT;
	uint64_t flags_tmp;
	uint64_t pflags_ovrd;
	uint8_t *pfilter_ovrd;
	struct peer *conf;

	conf = group->conf;
	pflags_ovrd = peer->af_flags_override[afi][safi];
	pfilter_ovrd = &peer->filter_override[afi][safi][in];

	/* peer af_flags apply */
	flags_tmp = conf->af_flags[afi][safi] & ~pflags_ovrd;
	flags_tmp ^= conf->af_flags_invert[afi][safi]
		     ^ peer->af_flags_invert[afi][safi];
	UNSET_FLAG(flags_tmp, pflags_ovrd);

	UNSET_FLAG(peer->af_flags[afi][safi], ~pflags_ovrd);
	SET_FLAG(peer->af_flags[afi][safi], flags_tmp);
	SET_FLAG(peer->af_flags_invert[afi][safi],
		 conf->af_flags_invert[afi][safi]);

	/* maximum-prefix */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_MAX_PREFIX)) {
		PEER_ATTR_INHERIT(peer, group, pmax[afi][safi]);
		PEER_ATTR_INHERIT(peer, group, pmax_threshold[afi][safi]);
		PEER_ATTR_INHERIT(peer, group, pmax_restart[afi][safi]);
	}

	/* maximum-prefix-out */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_MAX_PREFIX_OUT))
		PEER_ATTR_INHERIT(peer, group, pmax_out[afi][safi]);

	/* allowas-in */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_ALLOWAS_IN))
		PEER_ATTR_INHERIT(peer, group, allowas_in[afi][safi]);

	/* soo */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_SOO))
		PEER_ATTR_INHERIT(peer, group, soo[afi][safi]);

	/* weight */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_WEIGHT))
		PEER_ATTR_INHERIT(peer, group, weight[afi][safi]);

	/* default-originate route-map */
	if (!CHECK_FLAG(pflags_ovrd, PEER_FLAG_DEFAULT_ORIGINATE)) {
		PEER_STR_ATTR_INHERIT(peer, group, default_rmap[afi][safi].name,
				      MTYPE_ROUTE_MAP_NAME);
		PEER_ATTR_INHERIT(peer, group, default_rmap[afi][safi].map);
	}

	/* inbound filter apply */
	if (!CHECK_FLAG(pfilter_ovrd[in], PEER_FT_DISTRIBUTE_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].dlist[in].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].dlist[in].alist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[in], PEER_FT_PREFIX_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].plist[in].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].plist[in].plist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[in], PEER_FT_FILTER_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].aslist[in].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].aslist[in].aslist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[RMAP_IN], PEER_FT_ROUTE_MAP)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].map[in].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].map[RMAP_IN].map);
	}

	/* outbound filter apply */
	if (!CHECK_FLAG(pfilter_ovrd[out], PEER_FT_DISTRIBUTE_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].dlist[out].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].dlist[out].alist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[out], PEER_FT_PREFIX_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].plist[out].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].plist[out].plist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[out], PEER_FT_FILTER_LIST)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].aslist[out].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].aslist[out].aslist);
	}

	if (!CHECK_FLAG(pfilter_ovrd[RMAP_OUT], PEER_FT_ROUTE_MAP)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].map[RMAP_OUT].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].map[RMAP_OUT].map);
	}

	/* nondirectional filter apply */
	if (!CHECK_FLAG(pfilter_ovrd[0], PEER_FT_UNSUPPRESS_MAP)) {
		PEER_STR_ATTR_INHERIT(peer, group, filter[afi][safi].usmap.name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group, filter[afi][safi].usmap.map);
	}

	/* Conditional Advertisements */
	if (!CHECK_FLAG(pfilter_ovrd[RMAP_OUT], PEER_FT_ADVERTISE_MAP)) {
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].advmap.aname,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group, filter[afi][safi].advmap.amap);
		PEER_STR_ATTR_INHERIT(peer, group,
				      filter[afi][safi].advmap.cname,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, group, filter[afi][safi].advmap.cmap);
		PEER_ATTR_INHERIT(peer, group,
				  filter[afi][safi].advmap.condition);
	}

	if (peer->addpath_type[afi][safi] == BGP_ADDPATH_NONE) {
		peer->addpath_type[afi][safi] = conf->addpath_type[afi][safi];
		bgp_addpath_type_changed(conf->bgp);
	}
}

static int peer_activate_af(struct peer *peer, afi_t afi, safi_t safi)
{
	int active;
	struct peer *other;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		flog_err(EC_BGP_PEER_GROUP, "%s was called for peer-group %s",
			 __func__, peer->host);
		return 1;
	}

	/* Do not activate a peer for both SAFI_UNICAST and SAFI_LABELED_UNICAST
	 */
	if ((safi == SAFI_UNICAST && peer->afc[afi][SAFI_LABELED_UNICAST])
	    || (safi == SAFI_LABELED_UNICAST && peer->afc[afi][SAFI_UNICAST]))
		return BGP_ERR_PEER_SAFI_CONFLICT;

	/* Nothing to do if we've already activated this peer */
	if (peer->afc[afi][safi])
		return 0;

	if (peer_af_create(peer, afi, safi) == NULL)
		return 1;

	active = peer_active(peer);
	peer->afc[afi][safi] = 1;

	if (peer->group)
		peer_group2peer_config_copy_af(peer->group, peer, afi, safi);

	if (!active && peer_active(peer)) {
		bgp_timer_set(peer->connection);
	} else {
		peer->last_reset = PEER_DOWN_AF_ACTIVATE;

		if (peer_established(peer->connection)) {
			if (CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV)) {
				peer->afc_adv[afi][safi] = 1;
				bgp_capability_send(peer, afi, safi,
						    CAPABILITY_CODE_MP,
						    CAPABILITY_ACTION_SET);
				if (peer->afc_recv[afi][safi]) {
					peer->afc_nego[afi][safi] = 1;
					bgp_announce_route(peer, afi, safi,
							   false);
				}
			} else {
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_CONFIG_CHANGE);
			}
		}
		if (peer->connection->status == OpenSent ||
		    peer->connection->status == OpenConfirm)
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		/*
		 * If we are turning on a AFI/SAFI locally and we've
		 * started bringing a peer up, we need to tell
		 * the other peer to restart because we might loose
		 * configuration here because when the doppelganger
		 * gets to a established state due to how
		 * we resolve we could just overwrite the afi/safi
		 * activation.
		 */
		other = peer->doppelganger;
		if (other && (other->connection->status == OpenSent ||
			      other->connection->status == OpenConfirm))
			bgp_notify_send(other->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}

	return 0;
}

/* Activate the peer or peer group for specified AFI and SAFI.  */
int peer_activate(struct peer *peer, afi_t afi, safi_t safi)
{
	int ret = 0;
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct peer *tmp_peer;
	struct bgp *bgp;
	safi_t safi_check;

	/* Nothing to do if we've already activated this peer */
	if (peer->afc[afi][safi])
		return ret;

	bgp = peer->bgp;

	/* This is a peer-group so activate all of the members of the
	 * peer-group as well */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {

		/* Do not activate a peer for both SAFI_UNICAST and
		 * SAFI_LABELED_UNICAST */
		if ((safi == SAFI_UNICAST
		     && peer->afc[afi][SAFI_LABELED_UNICAST])
		    || (safi == SAFI_LABELED_UNICAST
			&& peer->afc[afi][SAFI_UNICAST]))
			return BGP_ERR_PEER_SAFI_CONFLICT;

		peer->afc[afi][safi] = 1;
		group = peer->group;

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, tmp_peer)) {
			SET_FLAG(ret, peer_activate_af(tmp_peer, afi, safi));
		}
	} else {
		SET_FLAG(ret, peer_activate_af(peer, afi, safi));
	}

	/* If this is the first peer to be activated for this
	 * afi/labeled-unicast or afi/mpls-vpn, recalc bestpaths to trigger
	 * label allocation */
	if (safi == SAFI_LABELED_UNICAST)
		safi_check = SAFI_UNICAST;
	else
		safi_check = safi;
	if (ret != BGP_ERR_PEER_SAFI_CONFLICT &&
	    (safi == SAFI_LABELED_UNICAST || safi == SAFI_MPLS_VPN) &&
	    !bgp->allocate_mpls_labels[afi][safi_check]) {

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"peer(s) are now active for %s, allocate MPLS labels",
				safi2str(safi));
		bgp->allocate_mpls_labels[afi][safi_check] = 1;
		bgp_recalculate_afi_safi_bestpaths(bgp, afi, safi_check);
	}

	if (safi == SAFI_FLOWSPEC) {
		/* connect to table manager */
		bgp_zebra_init_tm_connect(bgp);
	}
	return ret;
}

static bool non_peergroup_deactivate_af(struct peer *peer, afi_t afi,
					safi_t safi)
{
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		flog_err(EC_BGP_PEER_GROUP, "%s was called for peer-group %s",
			 __func__, peer->host);
		return true;
	}

	/* Nothing to do if we've already deactivated this peer */
	if (!peer->afc[afi][safi])
		return false;

	/* De-activate the address family configuration. */
	peer->afc[afi][safi] = 0;

	if (peer_af_delete(peer, afi, safi) != 0) {
		flog_err(EC_BGP_PEER_DELETE,
			 "couldn't delete af structure for peer %s(%s, %s)",
			 peer->host, afi2str(afi), safi2str(safi));
		return true;
	}

	if (peer_established(peer->connection)) {
		peer->last_reset = PEER_DOWN_NEIGHBOR_DELETE;

		if (CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV)) {
			peer->afc_adv[afi][safi] = 0;
			peer->afc_nego[afi][safi] = 0;

			if (peer_active_nego(peer)) {
				bgp_capability_send(peer, afi, safi,
						    CAPABILITY_CODE_MP,
						    CAPABILITY_ACTION_UNSET);
				bgp_clear_route(peer, afi, safi);
				peer->pcount[afi][safi] = 0;
			} else {
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_CONFIG_CHANGE);
			}
		} else {
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		}
	}

	return false;
}

int peer_deactivate(struct peer *peer, afi_t afi, safi_t safi)
{
	int ret = 0;
	struct peer_group *group;
	struct peer *tmp_peer;
	struct listnode *node, *nnode;
	struct bgp *bgp;
	safi_t safi_check;

	/* Nothing to do if we've already de-activated this peer */
	if (!peer->afc[afi][safi])
		return ret;

	/* This is a peer-group so de-activate all of the members of the
	 * peer-group as well */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->afc[afi][safi] = 0;
		group = peer->group;

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, tmp_peer)) {
			SET_FLAG(ret, non_peergroup_deactivate_af(tmp_peer, afi,
								  safi));
		}
	} else {
		SET_FLAG(ret, non_peergroup_deactivate_af(peer, afi, safi));
	}

	bgp = peer->bgp;

	/* If this is the last peer to be deactivated for this
	 * afi/labeled-unicast or afi/mpls-vpn, recalc bestpaths to trigger
	 * label deallocation */
	if (safi == SAFI_LABELED_UNICAST)
		safi_check = SAFI_UNICAST;
	else
		safi_check = safi;
	if ((safi == SAFI_LABELED_UNICAST || safi == SAFI_MPLS_VPN) &&
	    bgp->allocate_mpls_labels[afi][safi_check] &&
	    !bgp_afi_safi_peer_exists(bgp, afi, safi)) {

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"peer(s) are no longer active for %s, deallocate MPLS labels",
				safi2str(safi));
		bgp->allocate_mpls_labels[afi][safi_check] = 0;
		bgp_recalculate_afi_safi_bestpaths(bgp, afi, safi_check);
	}
	return ret;
}

void peer_nsf_stop(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
	UNSET_FLAG(peer->sflags, PEER_STATUS_NSF_MODE);

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		peer->nsf[afi][safi] = 0;
		EVENT_OFF(peer->t_llgr_stale[afi][safi]);
	}

	if (peer->connection->t_gr_restart) {
		EVENT_OFF(peer->connection->t_gr_restart);
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%pBP graceful restart timer stopped", peer);
	}
	if (peer->connection->t_gr_stale) {
		EVENT_OFF(peer->connection->t_gr_stale);
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%pBP graceful restart stalepath timer stopped",
				peer);
	}
	bgp_clear_route_all(peer);
}

/* Delete peer from confguration.
 *
 * The peer is moved to a dead-end "Deleted" neighbour-state, to allow
 * it to "cool off" and refcounts to hit 0, at which state it is freed.
 *
 * This function /should/ take care to be idempotent, to guard against
 * it being called multiple times through stray events that come in
 * that happen to result in this function being called again.  That
 * said, getting here for a "Deleted" peer is a bug in the neighbour
 * FSM.
 */
int peer_delete(struct peer *peer)
{
	int i;
	afi_t afi;
	safi_t safi;
	struct bgp *bgp;
	struct bgp_filter *filter;
	struct listnode *pn;
	int accept_peer;

	assert(peer->connection->status != Deleted);

	bgp = peer->bgp;
	accept_peer = CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);

	bgp_soft_reconfig_table_task_cancel(bgp, NULL, peer);

	bgp_keepalives_off(peer->connection);
	bgp_reads_off(peer->connection);
	bgp_writes_off(peer->connection);
	event_cancel_event_ready(bm->master, peer->connection);
	FOREACH_AFI_SAFI (afi, safi)
		EVENT_OFF(peer->t_revalidate_all[afi][safi]);
	assert(!CHECK_FLAG(peer->connection->thread_flags,
			   PEER_THREAD_WRITES_ON));
	assert(!CHECK_FLAG(peer->connection->thread_flags,
			   PEER_THREAD_READS_ON));
	assert(!CHECK_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON));

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT))
		peer_nsf_stop(peer);

	SET_FLAG(peer->flags, PEER_FLAG_DELETE);

	/* Remove BFD settings. */
	if (peer->bfd_config)
		bgp_peer_remove_bfd_config(peer);

	/* Delete peer route flap dampening configuration. This needs to happen
	 * before removing the peer from peer groups.
	 */
	FOREACH_AFI_SAFI (afi, safi)
		if (peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_CONFIG_DAMPENING))
			bgp_peer_damp_disable(peer, afi, safi);

	/* If this peer belongs to peer group, clear up the
	   relationship.  */
	if (peer->group) {
		if (peer_dynamic_neighbor(peer))
			peer_drop_dynamic_neighbor(peer);

		if ((pn = listnode_lookup(peer->group->peer, peer))) {
			peer = peer_unlock(
				peer); /* group->peer list reference */
			list_delete_node(peer->group->peer, pn);
		}
		peer->group = NULL;
	}

	/* Withdraw all information from routing table.  We can not use
	 * BGP_EVENT_ADD (peer, BGP_Stop) at here.  Because the event is
	 * executed after peer structure is deleted.
	 */
	peer->last_reset = PEER_DOWN_NEIGHBOR_DELETE;
	bgp_stop(peer->connection);
	UNSET_FLAG(peer->flags, PEER_FLAG_DELETE);

	if (peer->doppelganger) {
		peer->doppelganger->doppelganger = NULL;
		peer->doppelganger = NULL;
	}

	UNSET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);
	bgp_fsm_change_status(peer->connection, Deleted);

	/* Remove from NHT */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
		bgp_unlink_nexthop_by_peer(peer);

	/* Password configuration */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD)) {
		XFREE(MTYPE_PEER_PASSWORD, peer->password);
		if (!accept_peer &&
		    !BGP_CONNECTION_SU_UNSPEC(peer->connection) &&
		    !CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP) &&
		    !CHECK_FLAG(peer->flags, PEER_FLAG_DYNAMIC_NEIGHBOR))
			bgp_md5_unset(peer->connection);
	}

	bgp_timer_set(peer->connection); /* stops all timers for Deleted */

	/* Delete from all peer list. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)
	    && (pn = listnode_lookup(bgp->peer, peer))) {
		/*
		 * Removing from the list node first because
		 * peer_unlock *can* call peer_delete( I know,
		 * I know ).  So let's remove it and in
		 * the su recalculate function we'll ensure
		 * it's in there or not.
		 */
		list_delete_node(bgp->peer, pn);
		hash_release(bgp->peerhash, peer);
		peer_unlock(peer); /* bgp peer list reference */
	}

	/* Local and remote addresses. */
	if (peer->su_local) {
		sockunion_free(peer->su_local);
		peer->su_local = NULL;
	}

	if (peer->su_remote) {
		sockunion_free(peer->su_remote);
		peer->su_remote = NULL;
	}

	/* Free filter related memory.  */
	FOREACH_AFI_SAFI (afi, safi) {
		filter = &peer->filter[afi][safi];

		for (i = FILTER_IN; i < FILTER_MAX; i++) {
			XFREE(MTYPE_BGP_FILTER_NAME, filter->dlist[i].name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->plist[i].name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->aslist[i].name);
		}

		for (i = RMAP_IN; i < RMAP_MAX; i++) {
			XFREE(MTYPE_BGP_FILTER_NAME, filter->map[i].name);
		}

		XFREE(MTYPE_BGP_FILTER_NAME, filter->usmap.name);
		XFREE(MTYPE_ROUTE_MAP_NAME, peer->default_rmap[afi][safi].name);
		ecommunity_free(&peer->soo[afi][safi]);
	}

	FOREACH_AFI_SAFI (afi, safi)
		peer_af_delete(peer, afi, safi);

	XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
	XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);
	XFREE(MTYPE_BGP_SOFT_VERSION, peer->soft_version);

	peer_unlock(peer); /* initial reference */

	return 0;
}

static int peer_group_cmp(struct peer_group *g1, struct peer_group *g2)
{
	return strcmp(g1->name, g2->name);
}

/* Peer group cofiguration. */
static struct peer_group *peer_group_new(void)
{
	return XCALLOC(MTYPE_PEER_GROUP, sizeof(struct peer_group));
}

static void peer_group_free(struct peer_group *group)
{
	XFREE(MTYPE_PEER_GROUP, group);
}

struct peer_group *peer_group_lookup(struct bgp *bgp, const char *name)
{
	struct peer_group *group;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		if (strcmp(group->name, name) == 0)
			return group;
	}
	return NULL;
}

struct peer_group *peer_group_get(struct bgp *bgp, const char *name)
{
	struct peer_group *group;
	afi_t afi;
	safi_t safi;

	group = peer_group_lookup(bgp, name);
	if (group)
		return group;

	group = peer_group_new();
	group->bgp = bgp;
	XFREE(MTYPE_PEER_GROUP_HOST, group->name);
	group->name = XSTRDUP(MTYPE_PEER_GROUP_HOST, name);
	group->peer = list_new();
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		group->listen_range[afi] = list_new();
	group->conf = peer_new(bgp);
	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->default_af[afi][safi])
			group->conf->afc[afi][safi] = 1;
	}
	XFREE(MTYPE_BGP_PEER_HOST, group->conf->host);
	group->conf->host = XSTRDUP(MTYPE_BGP_PEER_HOST, name);
	group->conf->group = group;
	group->conf->as = 0;
	group->conf->ttl = BGP_DEFAULT_TTL;
	group->conf->gtsm_hops = BGP_GTSM_HOPS_DISABLED;
	group->conf->v_routeadv = BGP_DEFAULT_EBGP_ROUTEADV;
	SET_FLAG(group->conf->sflags, PEER_STATUS_GROUP);
	listnode_add_sort(bgp->group, group);

	return group;
}

static void peer_group2peer_config_copy(struct peer_group *group,
					struct peer *peer)
{
	uint64_t flags_tmp;
	struct peer *conf;
	bool config_node = !!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	conf = group->conf;

	/* remote-as */
	if (conf->as)
		peer->as = conf->as;

	/* local-as */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_LOCAL_AS))
		peer->change_local_as = conf->change_local_as;

	/* If peer-group has configured TTL then override it */
	if (conf->ttl != BGP_DEFAULT_TTL)
		peer->ttl = conf->ttl;

	/* GTSM hops */
	peer->gtsm_hops = conf->gtsm_hops;

	/* peer flags apply */
	flags_tmp = CHECK_FLAG(conf->flags, ~peer->flags_override);
	flags_tmp ^= conf->flags_invert ^ peer->flags_invert;
	UNSET_FLAG(flags_tmp, peer->flags_override);

	UNSET_FLAG(peer->flags, ~peer->flags_override);
	SET_FLAG(peer->flags, flags_tmp);
	SET_FLAG(peer->flags_invert, conf->flags_invert);

	if (config_node)
		SET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

	/* peer timers apply */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_TIMER)) {
		PEER_ATTR_INHERIT(peer, group, holdtime);
		PEER_ATTR_INHERIT(peer, group, keepalive);
	}

	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_TIMER_CONNECT)) {
		PEER_ATTR_INHERIT(peer, group, connect);
		if (CHECK_FLAG(conf->flags, PEER_FLAG_TIMER_CONNECT))
			peer->v_connect = conf->connect;
		else
			peer->v_connect = peer->bgp->default_connect_retry;
	}

	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_TIMER_DELAYOPEN)) {
		PEER_ATTR_INHERIT(peer, group, delayopen);
		if (CHECK_FLAG(conf->flags, PEER_FLAG_TIMER_DELAYOPEN))
			peer->v_delayopen = conf->delayopen;
		else
			peer->v_delayopen = peer->bgp->default_delayopen;
	}

	/* advertisement-interval apply */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_ROUTEADV)) {
		PEER_ATTR_INHERIT(peer, group, routeadv);
		if (CHECK_FLAG(conf->flags, PEER_FLAG_ROUTEADV))
			peer->v_routeadv = conf->routeadv;
		else
			peer->v_routeadv = (peer_sort(peer) == BGP_PEER_IBGP)
						   ? BGP_DEFAULT_IBGP_ROUTEADV
						   : BGP_DEFAULT_EBGP_ROUTEADV;
	}

	/* capability extended-nexthop apply */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE))
		if (CHECK_FLAG(conf->flags, PEER_FLAG_CAPABILITY_ENHE))
			SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);

	/* capability software-version apply */
	if (!CHECK_FLAG(peer->flags_override,
			PEER_FLAG_CAPABILITY_SOFT_VERSION))
		if (CHECK_FLAG(conf->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION))
			SET_FLAG(peer->flags,
				 PEER_FLAG_CAPABILITY_SOFT_VERSION);

	/* capability dynamic apply */
	if (!CHECK_FLAG(peer->flags_override,
			PEER_FLAG_DYNAMIC_CAPABILITY))
		if (CHECK_FLAG(conf->flags, PEER_FLAG_DYNAMIC_CAPABILITY))
			SET_FLAG(peer->flags,
				 PEER_FLAG_DYNAMIC_CAPABILITY);

	/* password apply */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_PASSWORD))
		PEER_STR_ATTR_INHERIT(peer, group, password,
				      MTYPE_PEER_PASSWORD);

	if (!BGP_CONNECTION_SU_UNSPEC(peer->connection))
		bgp_md5_set(peer->connection);

	/* update-source apply */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_UPDATE_SOURCE)) {
		if (conf->update_source) {
			XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
			PEER_SU_ATTR_INHERIT(peer, group, update_source);
		} else if (conf->update_if) {
			sockunion_free(peer->update_source);
			PEER_STR_ATTR_INHERIT(peer, group, update_if,
					      MTYPE_PEER_UPDATE_SOURCE);
		}
	}

	/* role */
	PEER_ATTR_INHERIT(peer, group, local_role);

	/* Update GR flags for the peer. */
	bgp_peer_gr_flags_update(peer);

	/* Apply BFD settings from group to peer if it exists. */
	if (conf->bfd_config) {
		bgp_peer_configure_bfd(peer, false);
		bgp_peer_config_apply(peer, group);
	}
}

/* Peer group's remote AS configuration.  */
int peer_group_remote_as(struct bgp *bgp, const char *group_name, as_t *as,
			 enum peer_asn_type as_type, const char *as_str)
{
	struct peer_group *group;
	struct peer *peer;
	struct listnode *node, *nnode;

	group = peer_group_lookup(bgp, group_name);
	if (!group)
		return -1;

	if ((as_type == group->conf->as_type) && (group->conf->as == *as))
		return 0;


	/* When we setup peer-group AS number all peer group member's AS
	   number must be updated to same number.  */
	peer_as_change(group->conf, *as, as_type, as_str);

	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		if (((peer->as_type == AS_SPECIFIED) && peer->as != *as) ||
		    (peer->as_type != as_type)) {
			peer_as_change(peer, *as, as_type, as_str);
			if (bgp_debug_neighbor_events(peer))
				zlog_debug("%s peer %s set to as_type %u curr status %s trigger BGP_Start",
					   __func__, peer->host, peer->as_type,
					   lookup_msg(bgp_status_msg,
						      peer->connection->status, NULL));
			/* Start Peer FSM to form neighbor using new as,
			 * NOTE: the connection is triggered upon start
			 * timer expiry.
			 */
			if (!BGP_PEER_START_SUPPRESSED(peer))
				BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
	}

	return 0;
}

void peer_notify_unconfig(struct peer *peer)
{
	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
				BGP_NOTIFY_CEASE_PEER_UNCONFIG);
}

static void peer_notify_shutdown(struct peer *peer)
{
	if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%pBP configured Graceful-Restart, skipping shutdown notification",
				peer);
		return;
	}

	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
				BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN);
}

void peer_group_notify_unconfig(struct peer_group *group)
{
	struct peer *peer, *other;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		other = peer->doppelganger;
		if (other && other->connection->status != Deleted) {
			other->group = NULL;
			peer_notify_unconfig(other);
		} else
			peer_notify_unconfig(peer);
	}
}

int peer_group_delete(struct peer_group *group)
{
	struct bgp *bgp;
	struct peer *peer;
	struct prefix *prefix;
	struct peer *other;
	struct listnode *node, *nnode;
	afi_t afi;

	bgp = group->bgp;

	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		other = peer->doppelganger;

		if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
			bgp_zebra_terminate_radv(bgp, peer);

		peer_delete(peer);
		if (other && other->connection->status != Deleted) {
			other->group = NULL;
			peer_delete(other);
		}
	}
	list_delete(&group->peer);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (ALL_LIST_ELEMENTS(group->listen_range[afi], node, nnode,
				       prefix)) {
			prefix_free(&prefix);
		}
		list_delete(&group->listen_range[afi]);
	}

	XFREE(MTYPE_PEER_GROUP_HOST, group->name);
	group->name = NULL;

	if (group->conf->bfd_config)
		bgp_peer_remove_bfd_config(group->conf);

	group->conf->group = NULL;
	peer_delete(group->conf);

	/* Delete from all peer_group list. */
	listnode_delete(bgp->group, group);

	peer_group_free(group);

	return 0;
}

int peer_group_remote_as_delete(struct peer_group *group)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if ((group->conf->as_type == AS_UNSPECIFIED)
	    || ((!group->conf->as) && (group->conf->as_type == AS_SPECIFIED)))
		return 0;

	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
			bgp_zebra_terminate_radv(peer->bgp, peer);

		/* reset existing peer connection */
		peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
	}

	group->conf->as = 0;
	group->conf->as_type = AS_UNSPECIFIED;

	return 0;
}

int peer_group_listen_range_add(struct peer_group *group, struct prefix *range)
{
	struct prefix *prefix;
	struct listnode *node, *nnode;
	afi_t afi;

	afi = family2afi(range->family);

	/* Group needs remote AS configured. */
	if (group->conf->as_type == AS_UNSPECIFIED)
		return BGP_ERR_PEER_GROUP_NO_REMOTE_AS;

	/* Ensure no duplicates. Currently we don't care about overlaps. */
	for (ALL_LIST_ELEMENTS(group->listen_range[afi], node, nnode, prefix)) {
		if (prefix_same(range, prefix))
			return 0;
	}

	prefix = prefix_new();
	prefix_copy(prefix, range);
	listnode_add(group->listen_range[afi], prefix);

	/* Update passwords for new ranges */
	if (group->conf->password)
		bgp_md5_set_prefix(group->bgp, prefix, group->conf->password);

	return 0;
}

int peer_group_listen_range_del(struct peer_group *group, struct prefix *range)
{
	struct prefix *prefix, prefix2;
	struct listnode *node, *nnode;
	struct peer *peer;
	afi_t afi;

	afi = family2afi(range->family);

	/* Identify the listen range. */
	for (ALL_LIST_ELEMENTS(group->listen_range[afi], node, nnode, prefix)) {
		if (prefix_same(range, prefix))
			break;
	}

	if (!prefix)
		return BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_NOT_FOUND;

	/* Dispose off any dynamic neighbors that exist due to this listen range
	 */
	for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
		if (!peer_dynamic_neighbor(peer))
			continue;

		if (sockunion2hostprefix(&peer->connection->su, &prefix2) &&
		    prefix_match(prefix, &prefix2)) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"Deleting dynamic neighbor %s group %s upon delete of listen range %pFX",
					peer->host, group->name, prefix);
			peer_delete(peer);
		}
	}

	/* Get rid of the listen range */
	listnode_delete(group->listen_range[afi], prefix);

	/* Remove passwords for deleted ranges */
	if (group->conf->password)
		bgp_md5_unset_prefix(group->bgp, prefix);

	return 0;
}

/* Bind specified peer to peer group.  */
int peer_group_bind(struct bgp *bgp, union sockunion *su, struct peer *peer,
		    struct peer_group *group, as_t *as)
{
	int first_member = 0;
	afi_t afi;
	safi_t safi;
	enum bgp_peer_sort ptype, gtype;

	/* Lookup the peer.  */
	if (!peer)
		peer = peer_lookup(bgp, su);

	/* The peer exist, bind it to the peer-group */
	if (peer) {
		/* When the peer already belongs to a peer-group, check the
		 * consistency.  */
		if (peer_group_active(peer)) {

			/* The peer is already bound to the peer-group,
			 * nothing to do
			 */
			if (strcmp(peer->group->name, group->name) == 0)
				return 0;
			else
				return BGP_ERR_PEER_GROUP_CANT_CHANGE;
		}

		/* The peer has not specified a remote-as, inherit it from the
		 * peer-group */
		if (peer->as_type == AS_UNSPECIFIED) {
			peer->as_type = group->conf->as_type;
			peer->as = group->conf->as;
			peer->sort = group->conf->sort;
			peer->sub_sort = group->conf->sub_sort;
		}

		ptype = peer_sort(peer);
		if (!group->conf->as && ptype != BGP_PEER_UNSPECIFIED) {
			gtype = peer_sort(group->conf);
			if ((gtype != BGP_PEER_INTERNAL) && (gtype != ptype)) {
				if (as)
					*as = peer->as;
				return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
			}

			if (gtype == BGP_PEER_INTERNAL)
				first_member = 1;
		}

		peer_group2peer_config_copy(group, peer);

		FOREACH_AFI_SAFI (afi, safi) {
			if (group->conf->afc[afi][safi]) {
				peer->afc[afi][safi] = 1;

				if (peer_af_find(peer, afi, safi)
				    || peer_af_create(peer, afi, safi)) {
					peer_group2peer_config_copy_af(
						group, peer, afi, safi);
				}
			} else if (peer->afc[afi][safi])
				peer_deactivate(peer, afi, safi);
		}

		if (peer->group) {
			assert(group && peer->group == group);
		} else {
			listnode_delete(bgp->peer, peer);

			peer->group = group;
			listnode_add_sort(bgp->peer, peer);

			peer = peer_lock(peer); /* group->peer list reference */
			listnode_add(group->peer, peer);
		}

		if (first_member) {
			gtype = peer_sort(group->conf);
			/* Advertisement-interval reset */
			if (!CHECK_FLAG(group->conf->flags,
					PEER_FLAG_ROUTEADV)) {
				group->conf->v_routeadv =
					(gtype == BGP_PEER_IBGP)
						? BGP_DEFAULT_IBGP_ROUTEADV
						: BGP_DEFAULT_EBGP_ROUTEADV;
			}

			/* ebgp-multihop reset */
			if (gtype == BGP_PEER_IBGP)
				group->conf->ttl = MAXTTL;
		}

		SET_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE);

		peer->last_reset = PEER_DOWN_RMAP_BIND;

		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);
	}

	/* Create a new peer. */
	else {
		if ((group->conf->as_type == AS_SPECIFIED)
		    && (!group->conf->as)) {
			return BGP_ERR_PEER_GROUP_NO_REMOTE_AS;
		}

		peer = peer_create(su, NULL, bgp, bgp->as, group->conf->as,
				   group->conf->as_type, group, true, NULL);

		peer = peer_lock(peer); /* group->peer list reference */
		listnode_add(group->peer, peer);

		peer_group2peer_config_copy(group, peer);

		/* If the peer-group is active for this afi/safi then activate
		 * for this peer */
		FOREACH_AFI_SAFI (afi, safi) {
			if (group->conf->afc[afi][safi]) {
				peer->afc[afi][safi] = 1;

				if (!peer_af_find(peer, afi, safi))
					peer_af_create(peer, afi, safi);

				peer_group2peer_config_copy_af(group, peer, afi,
							       safi);
			} else if (peer->afc[afi][safi])
				peer_deactivate(peer, afi, safi);
		}

		/* Set up peer's events and timers. */
		if (peer_active(peer))
			bgp_timer_set(peer->connection);
	}

	return 0;
}

static void bgp_startup_timer_expire(struct event *thread)
{
	struct bgp *bgp;

	bgp = EVENT_ARG(thread);
	bgp->t_startup = NULL;
}

/*
 * On shutdown we call the cleanup function which
 * does a free of the link list nodes,  free up
 * the data we are pointing at too.
 */
static void bgp_vrf_string_name_delete(void *data)
{
	char *vname = data;

	XFREE(MTYPE_TMP, vname);
}

/* BGP instance creation by `router bgp' commands. */
static struct bgp *bgp_create(as_t *as, const char *name,
			      enum bgp_instance_type inst_type,
			      const char *as_pretty,
			      enum asnotation_mode asnotation,
			      struct bgp *bgp_old, bool hidden)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (hidden) {
		bgp = bgp_old;
		goto peer_init;
	}

	bgp = XCALLOC(MTYPE_BGP, sizeof(struct bgp));
	bgp->as = *as;
	if (as_pretty)
		bgp->as_pretty = XSTRDUP(MTYPE_BGP_NAME, as_pretty);
	else
		bgp->as_pretty = XSTRDUP(MTYPE_BGP_NAME, asn_asn2asplain(*as));

	if (asnotation != ASNOTATION_UNDEFINED) {
		bgp->asnotation = asnotation;
		SET_FLAG(bgp->config, BGP_CONFIG_ASNOTATION);
	} else
		asn_str2asn_notation(bgp->as_pretty, NULL, &bgp->asnotation);

	if (BGP_DEBUG(zebra, ZEBRA)) {
		if (inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			zlog_debug("Creating Default VRF, AS %s",
				   bgp->as_pretty);
		else
			zlog_debug("Creating %s %s, AS %s",
				   (inst_type == BGP_INSTANCE_TYPE_VRF)
					   ? "VRF"
					   : "VIEW",
				   name, bgp->as_pretty);
	}

	/* Default the EVPN VRF to the default one */
	if (inst_type == BGP_INSTANCE_TYPE_DEFAULT && !bgp_master.bgp_evpn) {
		bgp_lock(bgp);
		bm->bgp_evpn = bgp;
	}

	bgp_lock(bgp);

	bgp->allow_martian = false;
	bgp_process_queue_init(bgp);
	bgp->heuristic_coalesce = true;
	bgp->inst_type = inst_type;
	bgp->vrf_id = (inst_type == BGP_INSTANCE_TYPE_DEFAULT) ? VRF_DEFAULT
							       : VRF_UNKNOWN;
	bgp->peer_self = peer_new(bgp);
	XFREE(MTYPE_BGP_PEER_HOST, bgp->peer_self->host);
	bgp->peer_self->host =
		XSTRDUP(MTYPE_BGP_PEER_HOST, "Static announcement");
	XFREE(MTYPE_BGP_PEER_HOST, bgp->peer_self->hostname);
	if (cmd_hostname_get())
		bgp->peer_self->hostname =
			XSTRDUP(MTYPE_BGP_PEER_HOST, cmd_hostname_get());

	XFREE(MTYPE_BGP_PEER_HOST, bgp->peer_self->domainname);
	if (cmd_domainname_get())
		bgp->peer_self->domainname =
			XSTRDUP(MTYPE_BGP_PEER_HOST, cmd_domainname_get());
	bgp->peer = list_new();

peer_init:
	bgp->peer->cmp = (int (*)(void *, void *))peer_cmp;
	bgp->peerhash = hash_create(peer_hash_key_make, peer_hash_same,
				    "BGP Peer Hash");
	bgp->peerhash->max_size = BGP_PEER_MAX_HASH_SIZE;

	if (!hidden)
		bgp->group = list_new();
	bgp->group->cmp = (int (*)(void *, void *))peer_group_cmp;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!hidden) {
			bgp->route[afi][safi] = bgp_table_init(bgp, afi, safi);
			bgp->aggregate[afi][safi] = bgp_table_init(bgp, afi,
								   safi);
			bgp->rib[afi][safi] = bgp_table_init(bgp, afi, safi);
		}

		/* Enable maximum-paths */
		bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_EBGP,
				      multipath_num, 0);
		bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_IBGP,
				      multipath_num, 0);
		/* Initialize graceful restart info */
		bgp->gr_info[afi][safi].eor_required = 0;
		bgp->gr_info[afi][safi].eor_received = 0;
		bgp->gr_info[afi][safi].t_select_deferral = NULL;
		bgp->gr_info[afi][safi].t_route_select = NULL;
		bgp->gr_info[afi][safi].gr_deferred = 0;
	}

	bgp->v_update_delay = bm->v_update_delay;
	bgp->v_establish_wait = bm->v_establish_wait;
	bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;
	bgp->default_subgroup_pkt_queue_max =
		BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX;
	bgp_tcp_keepalive_unset(bgp);
	if (!hidden)
		bgp_timers_unset(bgp);
	bgp->default_min_holdtime = 0;
	bgp->restart_time = BGP_DEFAULT_RESTART_TIME;
	bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	bgp->dynamic_neighbors_limit = BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT;
	bgp->dynamic_neighbors_count = 0;
	bgp->lb_ref_bw = BGP_LINK_BW_REF_BW;
	bgp->lb_handling = BGP_LINK_BW_ECMP;
	bgp->reject_as_sets = false;
	bgp->condition_check_period = DEFAULT_CONDITIONAL_ROUTES_POLL_TIME;
	bgp_addpath_init_bgp_data(&bgp->tx_addpath);
	bgp->fast_convergence = false;
	bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
	bgp->rmap_def_originate_eval_timer = 0;

#ifdef ENABLE_BGP_VNC
	if (inst_type != BGP_INSTANCE_TYPE_VRF && !hidden) {
		bgp->rfapi = bgp_rfapi_new(bgp);
		assert(bgp->rfapi);
		assert(bgp->rfapi_cfg);
	}
#endif /* ENABLE_BGP_VNC */

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		bgp->vpn_policy[afi].bgp = bgp;
		bgp->vpn_policy[afi].afi = afi;
		bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
		bgp->vpn_policy[afi].tovpn_zebra_vrf_label_last_sent =
			MPLS_LABEL_NONE;

		bgp->vpn_policy[afi].import_vrf = list_new();
		bgp->vpn_policy[afi].import_vrf->del =
			bgp_vrf_string_name_delete;
		if (!hidden) {
			bgp->vpn_policy[afi].export_vrf = list_new();
			bgp->vpn_policy[afi].export_vrf->del =
				bgp_vrf_string_name_delete;
		}
		SET_FLAG(bgp->af_flags[afi][SAFI_MPLS_VPN],
			 BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	}

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		bgp_label_per_nexthop_cache_init(
			&bgp->mpls_labels_per_nexthop[afi]);

	bgp_mplsvpn_nh_label_bind_cache_init(&bgp->mplsvpn_nh_label_bind);

	if (name)
		bgp->name = XSTRDUP(MTYPE_BGP_NAME, name);

	event_add_timer(bm->master, bgp_startup_timer_expire, bgp,
			bgp->restart_time, &bgp->t_startup);

	/* printable name we can use in debug messages */
	if (inst_type == BGP_INSTANCE_TYPE_DEFAULT && !hidden) {
		bgp->name_pretty = XSTRDUP(MTYPE_BGP_NAME, "VRF default");
	} else {
		const char *n;
		int len;

		if (bgp->name)
			n = bgp->name;
		else
			n = "?";

		len = 4 + 1 + strlen(n) + 1;	/* "view foo\0" */

		bgp->name_pretty = XCALLOC(MTYPE_BGP_NAME, len);
		snprintf(bgp->name_pretty, len, "%s %s",
			(bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
				? "VRF"
				: "VIEW",
			n);
	}

	atomic_store_explicit(&bgp->wpkt_quanta, BGP_WRITE_PACKET_MAX,
			      memory_order_relaxed);
	atomic_store_explicit(&bgp->rpkt_quanta, BGP_READ_PACKET_MAX,
			      memory_order_relaxed);
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	bgp->default_af[AFI_IP][SAFI_UNICAST] = true;

	if (!hidden)
		QOBJ_REG(bgp, bgp);

	update_bgp_group_init(bgp);

	if (!hidden) {
		/* assign a unique rd id for auto derivation of vrf's RD */
		bf_assign_index(bm->rd_idspace, bgp->vrf_rd_id);

		bgp_evpn_init(bgp);
		bgp_evpn_vrf_es_init(bgp);
		bgp_pbr_init(bgp);
		bgp_srv6_init(bgp);
	}

	/*initilize global GR FSM */
	bgp_global_gr_init(bgp);

	memset(&bgp->ebgprequirespolicywarning, 0,
	       sizeof(bgp->ebgprequirespolicywarning));

	return bgp;
}

/* Return the "default VRF" instance of BGP. */
struct bgp *bgp_get_default(void)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			return bgp;
	return NULL;
}

/* Lookup BGP entry. */
struct bgp *bgp_lookup(as_t as, const char *name)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		if (bgp->as == as
		    && ((bgp->name == NULL && name == NULL)
			|| (bgp->name && name && strcmp(bgp->name, name) == 0)))
			return bgp;
	return NULL;
}

/* Lookup BGP structure by view name. */
struct bgp *bgp_lookup_by_name(const char *name)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;
		if ((bgp->name == NULL && name == NULL)
		    || (bgp->name && name && strcmp(bgp->name, name) == 0))
			return bgp;
	}
	return NULL;
}

/* Lookup BGP instance based on VRF id. */
/* Note: Only to be used for incoming messages from Zebra. */
struct bgp *bgp_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	/* Lookup VRF (in tree) and follow link. */
	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;
	return (vrf->info) ? (struct bgp *)vrf->info : NULL;
}

/* Sets the BGP instance where EVPN is enabled */
void bgp_set_evpn(struct bgp *bgp)
{
	if (bm->bgp_evpn == bgp)
		return;

	/* First, release the reference count we hold on the instance */
	if (bm->bgp_evpn)
		bgp_unlock(bm->bgp_evpn);

	bm->bgp_evpn = bgp;

	/* Increase the reference count on this new VRF */
	if (bm->bgp_evpn)
		bgp_lock(bm->bgp_evpn);
}

/* Returns the BGP instance where EVPN is enabled, if any */
struct bgp *bgp_get_evpn(void)
{
	return bm->bgp_evpn;
}

/* handle socket creation or deletion, if necessary
 * this is called for all new BGP instances
 */
int bgp_handle_socket(struct bgp *bgp, struct vrf *vrf, vrf_id_t old_vrf_id,
		      bool create)
{
	struct listnode *node;
	char *address;

	/* Create BGP server socket, if listen mode not disabled */
	if (!bgp || bgp_option_check(BGP_OPT_NO_LISTEN))
		return 0;
	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		/*
		 * suppress vrf socket
		 */
		if (!create) {
			bgp_close_vrf_socket(bgp);
			return 0;
		}
		if (vrf == NULL)
			return BGP_ERR_INVALID_VALUE;
		/* do nothing
		 * if vrf_id did not change
		 */
		if (vrf->vrf_id == old_vrf_id)
			return 0;
		if (old_vrf_id != VRF_UNKNOWN) {
			/* look for old socket. close it. */
			bgp_close_vrf_socket(bgp);
		}
		/* if backend is not yet identified ( VRF_UNKNOWN) then
		 *   creation will be done later
		 */
		if (vrf->vrf_id == VRF_UNKNOWN)
			return 0;
		if (list_isempty(bm->addresses)) {
			if (bgp_socket(bgp, bm->port, NULL) < 0)
				return BGP_ERR_INVALID_VALUE;
		} else {
			for (ALL_LIST_ELEMENTS_RO(bm->addresses, node, address))
				if (bgp_socket(bgp, bm->port, address) < 0)
					return BGP_ERR_INVALID_VALUE;
		}
		return 0;
	} else
		return bgp_check_main_socket(create, bgp);
}

int bgp_lookup_by_as_name_type(struct bgp **bgp_val, as_t *as,
			       const char *as_pretty,
			       enum asnotation_mode asnotation, const char *name,
			       enum bgp_instance_type inst_type)
{
	struct bgp *bgp;
	struct peer *peer = NULL;
	struct listnode *node, *nnode;
	bool hidden = false;

	/* Multiple instance check. */
	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (bgp) {
		if (IS_BGP_INSTANCE_HIDDEN(bgp) && *as != AS_UNSPECIFIED)
			hidden = true;
		/* Handle AS number change */
		if (bgp->as != *as) {
			if (hidden || CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO)) {
				if (hidden) {
					bgp_create(as, name, inst_type,
						   as_pretty, asnotation, bgp,
						   hidden);
					UNSET_FLAG(bgp->flags,
						   BGP_FLAG_INSTANCE_HIDDEN);
				} else {
					bgp->as = *as;
					UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);
				}

				/* Set all peer's local AS with this ASN */
				for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode,
						       peer))
					peer->local_as = *as;
				*bgp_val = bgp;
				return BGP_INSTANCE_EXISTS;
			}

			*as = bgp->as;
			*bgp_val = bgp;
			return BGP_ERR_INSTANCE_MISMATCH;
		}
		if (bgp->inst_type != inst_type)
			return BGP_ERR_INSTANCE_MISMATCH;
		if (hidden)
			bgp_create(as, name, inst_type, as_pretty, asnotation,
				   bgp, hidden);
		*bgp_val = bgp;
		return BGP_INSTANCE_EXISTS;
	}
	*bgp_val = NULL;

	return BGP_SUCCESS;
}

/* Called from VTY commands. */
int bgp_get(struct bgp **bgp_val, as_t *as, const char *name,
	    enum bgp_instance_type inst_type, const char *as_pretty,
	    enum asnotation_mode asnotation)
{
	struct bgp *bgp;
	struct vrf *vrf = NULL;
	int ret = 0;

	ret = bgp_lookup_by_as_name_type(bgp_val, as, as_pretty, asnotation,
					 name, inst_type);
	if (ret || *bgp_val)
		return ret;

	bgp = bgp_create(as, name, inst_type, as_pretty, asnotation, NULL,
			 false);

	/*
	 * view instances will never work inside of a vrf
	 * as such they must always be in the VRF_DEFAULT
	 * Also we must set this to something useful because
	 * of the vrf socket code needing an actual useful
	 * default value to send to the underlying OS.
	 *
	 * This code is currently ignoring vrf based
	 * code using the -Z option( and that is probably
	 * best addressed elsewhere in the code )
	 */
	if (inst_type == BGP_INSTANCE_TYPE_VIEW)
		bgp->vrf_id = VRF_DEFAULT;

	bgp_router_id_set(bgp, &bgp->router_id_zebra, true);
	bgp_address_init(bgp);
	bgp_tip_hash_init(bgp);
	bgp_scan_init(bgp);
	*bgp_val = bgp;

	bgp->t_rmap_def_originate_eval = NULL;

	/* If Default instance or VRF, link to the VRF structure, if present. */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
	    || bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		vrf = bgp_vrf_lookup_by_instance_type(bgp);
		if (vrf)
			bgp_vrf_link(bgp, vrf);
	}
	/* BGP server socket already processed if BGP instance
	 * already part of the list
	 */
	bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, true);
	listnode_add(bm->bgp, bgp);

	if (IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Registering BGP instance %s to zebra",
				   __func__, bgp->name_pretty);
		bgp_zebra_instance_register(bgp);
	}

	return BGP_CREATED;
}

static void bgp_zclient_set_redist(afi_t afi, int type, unsigned short instance,
				   vrf_id_t vrf_id, bool set)
{
	if (instance) {
		if (set)
			redist_add_instance(&zclient->mi_redist[afi][type],
					    instance);
		else
			redist_del_instance(&zclient->mi_redist[afi][type],
					    instance);
	} else {
		if (set)
			vrf_bitmap_set(&zclient->redist[afi][type], vrf_id);
		else
			vrf_bitmap_unset(&zclient->redist[afi][type], vrf_id);
	}
}

static void bgp_set_redist_vrf_bitmaps(struct bgp *bgp, bool set)
{
	afi_t afi;
	int i;
	struct list *red_list;
	struct listnode *node;
	struct bgp_redist *red;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {

			red_list = bgp->redist[afi][i];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
				bgp_zclient_set_redist(afi, i, red->instance,
						       bgp->vrf_id, set);
		}
	}
}

/*
 * Make BGP instance "up". Applies only to VRFs (non-default) and
 * implies the VRF has been learnt from Zebra.
 */
void bgp_instance_up(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node, *next;

	/* notify BMP of instance state changed */
	hook_call(bgp_instance_state, bgp);

	bgp_set_redist_vrf_bitmaps(bgp, true);

	/* Register with zebra. */
	bgp_zebra_instance_register(bgp);

	/* Kick off any peers that may have been configured. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, next, peer)) {
		if (!BGP_PEER_START_SUPPRESSED(peer))
			BGP_EVENT_ADD(peer->connection, BGP_Start);
	}

	/* Process any networks that have been configured. */
	bgp_static_add(bgp);
}

/*
 * Make BGP instance "down". Applies only to VRFs (non-default) and
 * implies the VRF has been deleted by Zebra.
 */
void bgp_instance_down(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node;
	struct listnode *next;

	/* Cleanup evpn instance state */
	bgp_evpn_instance_down(bgp);

	/* notify BMP of instance state changed */
	hook_call(bgp_instance_state, bgp);

	/* Stop timers. */
	if (bgp->t_rmap_def_originate_eval)
		EVENT_OFF(bgp->t_rmap_def_originate_eval);

	/* Bring down peers, so corresponding routes are purged. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, next, peer)) {
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN);
		else
			bgp_session_reset(peer);
	}

	/* Purge network and redistributed routes. */
	bgp_purge_static_redist_routes(bgp);

	/* Cleanup registered nexthops (flags) */
	bgp_cleanup_nexthops(bgp);

	bgp_zebra_instance_deregister(bgp);

	bgp_set_redist_vrf_bitmaps(bgp, false);
}

/* Delete BGP instance. */
int bgp_delete(struct bgp *bgp)
{
	struct peer *peer;
	struct peer_group *group;
	struct listnode *node, *next;
	struct vrf *vrf;
	afi_t afi;
	safi_t safi;
	int i;
	struct bgp_dest *dest = NULL;
	struct bgp_dest *dest_next = NULL;
	struct bgp_table *dest_table = NULL;
	struct graceful_restart_info *gr_info;
	uint32_t cnt_before, cnt_after;

	assert(bgp);

	/*
	 * Iterate the pending dest list and remove all the dest pertaininig to
	 * the bgp under delete.
	 */
	cnt_before = zebra_announce_count(&bm->zebra_announce_head);
	for (dest = zebra_announce_first(&bm->zebra_announce_head); dest;
	     dest = dest_next) {
		dest_next = zebra_announce_next(&bm->zebra_announce_head, dest);
		dest_table = bgp_dest_table(dest);
		if (dest_table->bgp == bgp) {
			zebra_announce_del(&bm->zebra_announce_head, dest);
			bgp_path_info_unlock(dest->za_bgp_pi);
			bgp_dest_unlock_node(dest);
		}
	}

	cnt_after = zebra_announce_count(&bm->zebra_announce_head);
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Zebra Announce Fifo cleanup count before %u and after %u during BGP %s deletion",
			   cnt_before, cnt_after, bgp->name_pretty);

	bgp_soft_reconfig_table_task_cancel(bgp, NULL, NULL);

	/* make sure we withdraw any exported routes */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(),
			   bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(),
			   bgp);

	bgp_vpn_leak_unimport(bgp);

	hook_call(bgp_inst_delete, bgp);

	FOREACH_AFI_SAFI (afi, safi)
		EVENT_OFF(bgp->t_revalidate[afi][safi]);

	EVENT_OFF(bgp->t_condition_check);
	EVENT_OFF(bgp->t_startup);
	EVENT_OFF(bgp->t_maxmed_onstartup);
	EVENT_OFF(bgp->t_update_delay);
	EVENT_OFF(bgp->t_establish_wait);

	/* Set flag indicating bgp instance delete in progress */
	SET_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS);

	/* Delete the graceful restart info */
	FOREACH_AFI_SAFI (afi, safi) {
		struct event *t;

		gr_info = &bgp->gr_info[afi][safi];
		if (!gr_info)
			continue;
		t = gr_info->t_select_deferral;
		if (t) {
			void *info = EVENT_ARG(t);

			XFREE(MTYPE_TMP, info);
		}
		EVENT_OFF(gr_info->t_select_deferral);

		t = gr_info->t_route_select;
		if (t) {
			void *info = EVENT_ARG(t);

			XFREE(MTYPE_TMP, info);
		}
		EVENT_OFF(gr_info->t_route_select);
	}

	/* Delete route flap dampening configuration */
	FOREACH_AFI_SAFI (afi, safi) {
		bgp_damp_disable(bgp, afi, safi);
	}

	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT &&
	    (bgp_table_top(bgp->rib[AFI_IP][SAFI_MPLS_VPN]) ||
	     bgp_table_top(bgp->rib[AFI_IP6][SAFI_MPLS_VPN]))) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"Marking the deleting default bgp instance as hidden");
		SET_FLAG(bgp->flags, BGP_FLAG_INSTANCE_HIDDEN);
	}

	if (BGP_DEBUG(zebra, ZEBRA)) {
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			zlog_debug("Deleting Default VRF");
		else
			zlog_debug("Deleting %s %s",
				   (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
					   ? "VRF"
					   : "VIEW",
				   bgp->name);
	}

	/* unmap from RT list */
	if (!IS_BGP_INSTANCE_HIDDEN(bgp))
		bgp_evpn_vrf_delete(bgp);

	/* unmap bgp vrf label */
	vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP);
	vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP6);

	/* Stop timers. */
	if (bgp->t_rmap_def_originate_eval)
		EVENT_OFF(bgp->t_rmap_def_originate_eval);

	/* Inform peers we're going down. */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, next, peer))
		peer_notify_shutdown(peer);

	/* Delete static routes (networks). */
	bgp_static_delete(bgp);

	/* Unset redistribution. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (i != ZEBRA_ROUTE_BGP)
				bgp_redistribute_unset(bgp, afi, i, 0);

	/* Free peers and peer-groups. */
	for (ALL_LIST_ELEMENTS(bgp->group, node, next, group))
		peer_group_delete(group);

	while (listcount(bgp->peer)) {
		peer = listnode_head(bgp->peer);
		peer_delete(peer);
	}

	if (bgp->peer_self && !IS_BGP_INSTANCE_HIDDEN(bgp)) {
		peer_delete(bgp->peer_self);
		bgp->peer_self = NULL;
	}

	update_bgp_group_free(bgp);

/* TODO - Other memory may need to be freed - e.g., NHT */

#ifdef ENABLE_BGP_VNC
	if (!IS_BGP_INSTANCE_HIDDEN(bgp))
		rfapi_delete(bgp);
#endif

	/* Free memory allocated with aggregate address configuration. */
	FOREACH_AFI_SAFI (afi, safi) {
		struct bgp_aggregate *aggregate = NULL;

		for (struct bgp_dest *dest =
			     bgp_table_top(bgp->aggregate[afi][safi]);
		     dest; dest = bgp_route_next(dest)) {
			aggregate = bgp_dest_get_bgp_aggregate_info(dest);
			if (aggregate == NULL)
				continue;

			bgp_dest_set_bgp_aggregate_info(dest, NULL);
			bgp_free_aggregate_info(aggregate);
		}
	}

	bgp_cleanup_routes(bgp);

	for (afi = 0; afi < AFI_MAX; ++afi) {
		if (!bgp->vpn_policy[afi].import_redirect_rtlist)
			continue;
		ecommunity_free(
				&bgp->vpn_policy[afi]
				.import_redirect_rtlist);
		bgp->vpn_policy[afi].import_redirect_rtlist = NULL;
	}

	/* Free any memory allocated to holding routemap references */
	for (afi = 0; afi < AFI_MAX; ++afi) {
		for (enum vpn_policy_direction dir = 0;
		     dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
			if (bgp->vpn_policy[afi].rmap_name[dir])
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp->vpn_policy[afi].rmap_name[dir]);
			bgp->vpn_policy[afi].rmap[dir] = NULL;
		}
	}

	/* Deregister from Zebra, if needed */
	if (IS_BGP_INST_KNOWN_TO_ZEBRA(bgp) && !IS_BGP_INSTANCE_HIDDEN(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: deregistering this bgp %s instance from zebra",
				__func__, bgp->name);
		bgp_zebra_instance_deregister(bgp);
	}

	if (!IS_BGP_INSTANCE_HIDDEN(bgp)) {
		/* Remove visibility via the master list -
		 * there may however still be routes to be processed
		 * still referencing the struct bgp.
		 */
		listnode_delete(bm->bgp, bgp);
		/* Free interfaces in this instance. */
		bgp_if_finish(bgp);
	}

	vrf = bgp_vrf_lookup_by_instance_type(bgp);
	bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, false);
	if (vrf && !IS_BGP_INSTANCE_HIDDEN(bgp))
		bgp_vrf_unlink(bgp, vrf);

	/* Update EVPN VRF pointer */
	if (bm->bgp_evpn == bgp) {
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			bgp_set_evpn(NULL);
		else
			bgp_set_evpn(bgp_get_default());
	}

	if (bgp->process_queue)
		work_queue_free_and_null(&bgp->process_queue);

	if (!IS_BGP_INSTANCE_HIDDEN(bgp))
		bgp_unlock(bgp); /* initial reference */
	else {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			enum vpn_policy_direction dir;

			if (bgp->vpn_policy[afi].import_vrf)
				list_delete(&bgp->vpn_policy[afi].import_vrf);

			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			if (bgp->vpn_policy[afi].rtlist[dir])
				ecommunity_free(
					&bgp->vpn_policy[afi].rtlist[dir]);
		}
	}

	return 0;
}

void bgp_free(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_rmap *rmap;

	QOBJ_UNREG(bgp);

	list_delete(&bgp->group);
	list_delete(&bgp->peer);

	if (bgp->peerhash) {
		hash_free(bgp->peerhash);
		bgp->peerhash = NULL;
	}

	FOREACH_AFI_SAFI (afi, safi) {
		/* Special handling for 2-level routing tables. */
		if (safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP
		    || safi == SAFI_EVPN) {
			for (dest = bgp_table_top(bgp->rib[afi][safi]); dest;
			     dest = bgp_route_next(dest)) {
				table = bgp_dest_get_bgp_table_info(dest);
				bgp_table_finish(&table);
			}
		}
		if (bgp->route[afi][safi])
			bgp_table_finish(&bgp->route[afi][safi]);
		if (bgp->aggregate[afi][safi])
			bgp_table_finish(&bgp->aggregate[afi][safi]);
		if (bgp->rib[afi][safi])
			bgp_table_finish(&bgp->rib[afi][safi]);
		rmap = &bgp->table_map[afi][safi];
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
	}

	bgp_scan_finish(bgp);
	bgp_address_destroy(bgp);
	bgp_tip_hash_destroy(bgp);

	/* release the auto RD id */
	bf_release_index(bm->rd_idspace, bgp->vrf_rd_id);

	bgp_evpn_cleanup(bgp);
	bgp_pbr_cleanup(bgp);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		enum vpn_policy_direction dir;

		if (bgp->vpn_policy[afi].import_vrf)
			list_delete(&bgp->vpn_policy[afi].import_vrf);
		if (bgp->vpn_policy[afi].export_vrf)
			list_delete(&bgp->vpn_policy[afi].export_vrf);

		dir = BGP_VPN_POLICY_DIR_FROMVPN;
		if (bgp->vpn_policy[afi].rtlist[dir])
			ecommunity_free(&bgp->vpn_policy[afi].rtlist[dir]);
		dir = BGP_VPN_POLICY_DIR_TOVPN;
		if (bgp->vpn_policy[afi].rtlist[dir])
			ecommunity_free(&bgp->vpn_policy[afi].rtlist[dir]);
		if (bgp->vpn_policy[afi].tovpn_rd_pretty)
			XFREE(MTYPE_BGP_NAME,
			      bgp->vpn_policy[afi].tovpn_rd_pretty);
	}
	bgp_srv6_cleanup(bgp);
	bgp_confederation_id_unset(bgp);

	for (int i = 0; i < bgp->confed_peers_cnt; i++)
		XFREE(MTYPE_BGP_NAME, bgp->confed_peers[i].as_pretty);

	XFREE(MTYPE_BGP_NAME, bgp->as_pretty);
	XFREE(MTYPE_BGP_NAME, bgp->name);
	XFREE(MTYPE_BGP_NAME, bgp->name_pretty);
	XFREE(MTYPE_BGP_NAME, bgp->snmp_stats);
	XFREE(MTYPE_BGP_CONFED_LIST, bgp->confed_peers);

	XFREE(MTYPE_BGP, bgp);
}

struct peer *peer_lookup_by_conf_if(struct bgp *bgp, const char *conf_if)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!conf_if)
		return NULL;

	if (bgp != NULL) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			if (peer->conf_if && !strcmp(peer->conf_if, conf_if)
			    && !CHECK_FLAG(peer->sflags,
					   PEER_STATUS_ACCEPT_PEER))
				return peer;
	} else if (bm->bgp != NULL) {
		struct listnode *bgpnode, *nbgpnode;

		for (ALL_LIST_ELEMENTS(bm->bgp, bgpnode, nbgpnode, bgp))
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				if (peer->conf_if
				    && !strcmp(peer->conf_if, conf_if)
				    && !CHECK_FLAG(peer->sflags,
						   PEER_STATUS_ACCEPT_PEER))
					return peer;
	}
	return NULL;
}

struct peer *peer_lookup_by_hostname(struct bgp *bgp, const char *hostname)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	if (!hostname)
		return NULL;

	if (bgp != NULL) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			if (peer->hostname && !strcmp(peer->hostname, hostname)
			    && !CHECK_FLAG(peer->sflags,
					   PEER_STATUS_ACCEPT_PEER))
				return peer;
	} else if (bm->bgp != NULL) {
		struct listnode *bgpnode, *nbgpnode;

		for (ALL_LIST_ELEMENTS(bm->bgp, bgpnode, nbgpnode, bgp))
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				if (peer->hostname
				    && !strcmp(peer->hostname, hostname)
				    && !CHECK_FLAG(peer->sflags,
						   PEER_STATUS_ACCEPT_PEER))
					return peer;
	}
	return NULL;
}

struct peer *peer_lookup(struct bgp *bgp, union sockunion *su)
{
	struct peer *peer = NULL;
	struct peer tmp_peer;
	struct peer_connection connection;

	memset(&connection, 0, sizeof(struct peer_connection));
	memset(&tmp_peer, 0, sizeof(struct peer));
	tmp_peer.connection = &connection;

	/*
	 * We do not want to find the doppelganger peer so search for the peer
	 * in
	 * the hash that has PEER_FLAG_CONFIG_NODE
	 */
	SET_FLAG(tmp_peer.flags, PEER_FLAG_CONFIG_NODE);

	connection.su = *su;

	if (bgp != NULL) {
		peer = hash_lookup(bgp->peerhash, &tmp_peer);
	} else if (bm->bgp != NULL) {
		struct listnode *bgpnode, *nbgpnode;

		for (ALL_LIST_ELEMENTS(bm->bgp, bgpnode, nbgpnode, bgp)) {
			peer = hash_lookup(bgp->peerhash, &tmp_peer);
			if (peer)
				break;
		}
	}

	return peer;
}

struct peer *peer_create_bind_dynamic_neighbor(struct bgp *bgp,
					       union sockunion *su,
					       struct peer_group *group)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	/* Create peer first; we've already checked group config is valid. */
	peer = peer_create(su, NULL, bgp, bgp->as, group->conf->as,
			   group->conf->as_type, group, true, NULL);
	if (!peer)
		return NULL;

	/* Link to group */
	peer = peer_lock(peer);
	listnode_add(group->peer, peer);

	peer_group2peer_config_copy(group, peer);

	/*
	 * Bind peer for all AFs configured for the group. We don't call
	 * peer_group_bind as that is sub-optimal and does some stuff we don't
	 * want.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (!group->conf->afc[afi][safi])
			continue;
		peer->afc[afi][safi] = 1;

		if (!peer_af_find(peer, afi, safi))
			peer_af_create(peer, afi, safi);

		peer_group2peer_config_copy_af(group, peer, afi, safi);
	}

	/* Mark as dynamic, but also as a "config node" for other things to
	 * work. */
	SET_FLAG(peer->flags, PEER_FLAG_DYNAMIC_NEIGHBOR);

	return peer;
}

struct prefix *
peer_group_lookup_dynamic_neighbor_range(struct peer_group *group,
					 struct prefix *prefix)
{
	struct listnode *node, *nnode;
	struct prefix *range;
	afi_t afi;

	afi = family2afi(prefix->family);

	if (group->listen_range[afi])
		for (ALL_LIST_ELEMENTS(group->listen_range[afi], node, nnode,
				       range))
			if (prefix_match(range, prefix))
				return range;

	return NULL;
}

struct peer_group *
peer_group_lookup_dynamic_neighbor(struct bgp *bgp, struct prefix *prefix,
				   struct prefix **listen_range)
{
	struct prefix *range = NULL;
	struct peer_group *group = NULL;
	struct listnode *node, *nnode;

	*listen_range = NULL;
	if (bgp != NULL) {
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group))
			if ((range = peer_group_lookup_dynamic_neighbor_range(
				     group, prefix)))
				break;
	} else if (bm->bgp != NULL) {
		struct listnode *bgpnode, *nbgpnode;

		for (ALL_LIST_ELEMENTS(bm->bgp, bgpnode, nbgpnode, bgp))
			for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group))
				if ((range = peer_group_lookup_dynamic_neighbor_range(
					     group, prefix)))
					goto found_range;
	}

found_range:
	*listen_range = range;
	return (group && range) ? group : NULL;
}

struct peer *peer_lookup_dynamic_neighbor(struct bgp *bgp, union sockunion *su)
{
	struct peer_group *group;
	struct bgp *gbgp;
	struct peer *peer;
	struct prefix prefix;
	struct prefix *listen_range;
	int dncount;

	if (!sockunion2hostprefix(su, &prefix))
		return NULL;

	/* See if incoming connection matches a configured listen range. */
	group = peer_group_lookup_dynamic_neighbor(bgp, &prefix, &listen_range);

	if (!group)
		return NULL;


	gbgp = group->bgp;

	if (!gbgp)
		return NULL;

	if (bgp_debug_neighbor_events(NULL))
		zlog_debug(
			"Dynamic Neighbor %pFX matches group %s listen range %pFX",
			&prefix, group->name, listen_range);

	/* Are we within the listen limit? */
	dncount = gbgp->dynamic_neighbors_count;

	if (dncount >= gbgp->dynamic_neighbors_limit) {
		if (bgp_debug_neighbor_events(NULL))
			zlog_debug(
				"Dynamic Neighbor %pFX rejected - at limit %d",
				&prefix, gbgp->dynamic_neighbors_limit);
		return NULL;
	}

	/* Ensure group is not disabled. */
	if (CHECK_FLAG(group->conf->flags, PEER_FLAG_SHUTDOWN)) {
		if (bgp_debug_neighbor_events(NULL))
			zlog_debug(
				"Dynamic Neighbor %pFX rejected - group %s disabled",
				&prefix, group->name);
		return NULL;
	}

	/* Check that at least one AF is activated for the group. */
	if (!peer_group_af_configured(group)) {
		if (bgp_debug_neighbor_events(NULL))
			zlog_debug(
				"Dynamic Neighbor %pFX rejected - no AF activated for group %s",
				&prefix, group->name);
		return NULL;
	}

	/* Create dynamic peer and bind to associated group. */
	peer = peer_create_bind_dynamic_neighbor(gbgp, su, group);
	assert(peer);

	gbgp->dynamic_neighbors_count = ++dncount;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s Dynamic Neighbor added, group %s count %d",
			   peer->host, group->name, dncount);

	if (dncount == gbgp->dynamic_neighbors_limit) {
		zlog_warn("Dynamic Neighbor %s added as last connection. Peer-group %s reached maximum listen limit %d",
			  peer->host, group->name,
			  gbgp->dynamic_neighbors_limit);
	}
	return peer;
}

static void peer_drop_dynamic_neighbor(struct peer *peer)
{
	int dncount = -1;
	if (peer->group->bgp) {
		dncount = peer->group->bgp->dynamic_neighbors_count;
		if (dncount)
			peer->group->bgp->dynamic_neighbors_count = --dncount;
	}
	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s dropped from group %s, count %d", peer->host,
			   peer->group->name, dncount);
}

bool bgp_path_attribute_discard(struct peer *peer, char *buf, size_t size)
{
	if (!buf)
		return false;

	buf[0] = '\0';

	for (unsigned int i = 1; i <= BGP_ATTR_MAX; i++) {
		if (peer->discard_attrs[i])
			snprintf(buf + strlen(buf), size - strlen(buf), "%s%d",
				 (strlen(buf) > 0) ? " " : "", i);
	}

	if (strlen(buf) > 0)
		return true;

	return false;
}

bool bgp_path_attribute_treat_as_withdraw(struct peer *peer, char *buf,
					  size_t size)
{
	if (!buf)
		return false;

	buf[0] = '\0';

	for (unsigned int i = 1; i <= BGP_ATTR_MAX; i++) {
		if (peer->withdraw_attrs[i])
			snprintf(buf + strlen(buf), size - strlen(buf), "%s%d",
				 (strlen(buf) > 0) ? " " : "", i);
	}

	if (strlen(buf) > 0)
		return true;

	return false;
}

/* If peer is configured at least one address family return 1. */
bool peer_active(struct peer *peer)
{
	if (BGP_CONNECTION_SU_UNSPEC(peer->connection))
		return false;

	if (peer->bfd_config) {
		if (bfd_session_is_down(peer->bfd_config->session))
			return false;
	}

	if (peer->afc[AFI_IP][SAFI_UNICAST] || peer->afc[AFI_IP][SAFI_MULTICAST]
	    || peer->afc[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP][SAFI_MPLS_VPN] || peer->afc[AFI_IP][SAFI_ENCAP]
	    || peer->afc[AFI_IP][SAFI_FLOWSPEC]
	    || peer->afc[AFI_IP6][SAFI_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc[AFI_IP6][SAFI_ENCAP]
	    || peer->afc[AFI_IP6][SAFI_FLOWSPEC]
	    || peer->afc[AFI_L2VPN][SAFI_EVPN])
		return true;
	return false;
}

/* If peer is negotiated at least one address family return 1. */
bool peer_active_nego(struct peer *peer)
{
	if (peer->afc_nego[AFI_IP][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP][SAFI_ENCAP]
	    || peer->afc_nego[AFI_IP][SAFI_FLOWSPEC]
	    || peer->afc_nego[AFI_IP6][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP6][SAFI_ENCAP]
	    || peer->afc_nego[AFI_IP6][SAFI_FLOWSPEC]
	    || peer->afc_nego[AFI_L2VPN][SAFI_EVPN])
		return true;
	return false;
}

/* If peer received at least one address family MP, return true */
bool peer_afc_received(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		if (peer->afc_recv[afi][safi])
			return true;

	return false;
}

/* If peer advertised at least one address family MP, return true */
bool peer_afc_advertised(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		if (peer->afc_adv[afi][safi])
			return true;

	return false;
}

void peer_change_action(struct peer *peer, afi_t afi, safi_t safi,
			       enum peer_change_type type)
{
	struct peer_af *paf;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return;

	if (!peer_established(peer->connection))
		return;

	if (type == peer_change_reset) {
		/* If we're resetting session, we've to delete both peer struct
		 */
		if ((peer->doppelganger) &&
		    (peer->doppelganger->connection->status != Deleted) &&
		    (!CHECK_FLAG(peer->doppelganger->flags,
				 PEER_FLAG_CONFIG_NODE)))
			peer_delete(peer->doppelganger);

		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
				BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	} else if (type == peer_change_reset_in) {
		if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV))
			bgp_route_refresh_send(peer, afi, safi, 0, 0, 0,
					       BGP_ROUTE_REFRESH_NORMAL);
		else {
			if ((peer->doppelganger) &&
			    (peer->doppelganger->connection->status != Deleted) &&
			    (!CHECK_FLAG(peer->doppelganger->flags,
					 PEER_FLAG_CONFIG_NODE)))
				peer_delete(peer->doppelganger);

			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		}
	} else if (type == peer_change_reset_out) {
		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup)
			SET_FLAG(paf->subgroup->sflags,
				 SUBGRP_STATUS_FORCE_UPDATES);

		update_group_adjust_peer(paf);
		bgp_announce_route(peer, afi, safi, false);
	}
}

struct peer_flag_action {
	/* Peer's flag.  */
	uint64_t flag;

	/* This flag can be set for peer-group member.  */
	uint8_t not_for_member;

	/* Action when the flag is changed.  */
	enum peer_change_type type;
};

static const struct peer_flag_action peer_flag_action_list[] = {
	{PEER_FLAG_PASSIVE, 0, peer_change_reset},
	{PEER_FLAG_SHUTDOWN, 0, peer_change_reset},
	{PEER_FLAG_RTT_SHUTDOWN, 0, peer_change_none},
	{PEER_FLAG_DONT_CAPABILITY, 0, peer_change_none},
	{PEER_FLAG_OVERRIDE_CAPABILITY, 0, peer_change_none},
	{PEER_FLAG_STRICT_CAP_MATCH, 0, peer_change_none},
	{PEER_FLAG_DYNAMIC_CAPABILITY, 0, peer_change_none},
	{PEER_FLAG_DISABLE_CONNECTED_CHECK, 0, peer_change_reset},
	{PEER_FLAG_CAPABILITY_ENHE, 0, peer_change_reset},
	{PEER_FLAG_ENFORCE_FIRST_AS, 0, peer_change_reset_in},
	{PEER_FLAG_IFPEER_V6ONLY, 0, peer_change_reset},
	{PEER_FLAG_ROUTEADV, 0, peer_change_none},
	{PEER_FLAG_TIMER, 0, peer_change_none},
	{PEER_FLAG_TIMER_CONNECT, 0, peer_change_none},
	{PEER_FLAG_TIMER_DELAYOPEN, 0, peer_change_none},
	{PEER_FLAG_PASSWORD, 0, peer_change_none},
	{PEER_FLAG_LOCAL_AS, 0, peer_change_reset},
	{PEER_FLAG_LOCAL_AS_NO_PREPEND, 0, peer_change_reset},
	{PEER_FLAG_LOCAL_AS_REPLACE_AS, 0, peer_change_reset},
	{PEER_FLAG_DUAL_AS, 0, peer_change_reset},
	{PEER_FLAG_UPDATE_SOURCE, 0, peer_change_none},
	{PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE, 0, peer_change_none},
	{PEER_FLAG_EXTENDED_OPT_PARAMS, 0, peer_change_reset},
	{PEER_FLAG_ROLE_STRICT_MODE, 0, peer_change_none},
	{PEER_FLAG_ROLE, 0, peer_change_none},
	{PEER_FLAG_PORT, 0, peer_change_reset},
	{PEER_FLAG_AIGP, 0, peer_change_none},
	{PEER_FLAG_GRACEFUL_SHUTDOWN, 0, peer_change_none},
	{PEER_FLAG_CAPABILITY_SOFT_VERSION, 0, peer_change_none},
	{PEER_FLAG_CAPABILITY_FQDN, 0, peer_change_none},
	{PEER_FLAG_AS_LOOP_DETECTION, 0, peer_change_none},
	{PEER_FLAG_EXTENDED_LINK_BANDWIDTH, 0, peer_change_none},
	{PEER_FLAG_LONESOUL, 0, peer_change_reset_out},
	{0, 0, 0}};

static const struct peer_flag_action peer_af_flag_action_list[] = {
	{PEER_FLAG_SEND_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_SEND_EXT_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_SEND_LARGE_COMMUNITY, 1, peer_change_reset_out},
	{PEER_FLAG_NEXTHOP_SELF, 1, peer_change_reset_out},
	{PEER_FLAG_REFLECTOR_CLIENT, 1, peer_change_reset},
	{PEER_FLAG_RSERVER_CLIENT, 1, peer_change_reset},
	{PEER_FLAG_SOFT_RECONFIG, 0, peer_change_reset_in},
	{PEER_FLAG_AS_PATH_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_NEXTHOP_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_MED_UNCHANGED, 1, peer_change_reset_out},
	{PEER_FLAG_DEFAULT_ORIGINATE, 0, peer_change_none},
	{PEER_FLAG_REMOVE_PRIVATE_AS, 1, peer_change_reset_out},
	{PEER_FLAG_ALLOWAS_IN, 0, peer_change_reset_in},
	{PEER_FLAG_ALLOWAS_IN_ORIGIN, 0, peer_change_reset_in},
	{PEER_FLAG_ORF_PREFIX_SM, 1, peer_change_reset},
	{PEER_FLAG_ORF_PREFIX_RM, 1, peer_change_reset},
	{PEER_FLAG_MAX_PREFIX, 0, peer_change_none},
	{PEER_FLAG_MAX_PREFIX_WARNING, 0, peer_change_none},
	{PEER_FLAG_MAX_PREFIX_FORCE, 0, peer_change_none},
	{PEER_FLAG_MAX_PREFIX_OUT, 0, peer_change_none},
	{PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED, 0, peer_change_reset_out},
	{PEER_FLAG_FORCE_NEXTHOP_SELF, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_ALL, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE, 1, peer_change_reset_out},
	{PEER_FLAG_AS_OVERRIDE, 1, peer_change_reset_out},
	{PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE, 1, peer_change_reset_out},
	{PEER_FLAG_WEIGHT, 0, peer_change_reset_in},
	{PEER_FLAG_DISABLE_ADDPATH_RX, 0, peer_change_none},
	{PEER_FLAG_SOO, 0, peer_change_reset},
	{PEER_FLAG_ACCEPT_OWN, 0, peer_change_reset},
	{PEER_FLAG_SEND_EXT_COMMUNITY_RPKI, 1, peer_change_reset_out},
	{PEER_FLAG_ADDPATH_RX_PATHS_LIMIT, 0, peer_change_none},
	{0, 0, 0}};

/* Proper action set. */
static int peer_flag_action_set(const struct peer_flag_action *action_list,
				int size, struct peer_flag_action *action,
				uint64_t flag)
{
	int i;
	int found = 0;
	int reset_in = 0;
	int reset_out = 0;
	const struct peer_flag_action *match = NULL;

	/* Check peer's frag action.  */
	for (i = 0; i < size; i++) {
		match = &action_list[i];

		if (match->flag == 0)
			break;

		if (CHECK_FLAG(match->flag, flag)) {
			found = 1;

			if (match->type == peer_change_reset_in)
				reset_in = 1;
			if (match->type == peer_change_reset_out)
				reset_out = 1;
			if (match->type == peer_change_reset) {
				reset_in = 1;
				reset_out = 1;
			}
			if (match->not_for_member)
				action->not_for_member = 1;
		}
	}

	/* Set peer clear type.  */
	if (reset_in && reset_out)
		action->type = peer_change_reset;
	else if (reset_in)
		action->type = peer_change_reset_in;
	else if (reset_out)
		action->type = peer_change_reset_out;
	else
		action->type = peer_change_none;

	return found;
}

static void peer_flag_modify_action(struct peer *peer, uint64_t flag)
{
	if (flag == PEER_FLAG_DYNAMIC_CAPABILITY)
		peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
	else if (flag == PEER_FLAG_PASSIVE)
		peer->last_reset = PEER_DOWN_PASSIVE_CHANGE;
	else if (flag == PEER_FLAG_DISABLE_CONNECTED_CHECK)
		peer->last_reset = PEER_DOWN_MULTIHOP_CHANGE;

	if (flag == PEER_FLAG_SHUTDOWN) {
		if (CHECK_FLAG(peer->flags, flag)) {
			if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT))
				peer_nsf_stop(peer);

			UNSET_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);

			if (peer->connection->t_pmax_restart) {
				EVENT_OFF(peer->connection->t_pmax_restart);
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%pBP Maximum-prefix restart timer canceled",
						peer);
			}

			if (BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status)) {
				char *msg = peer->tx_shutdown_message;
				size_t msglen;
				uint8_t msgbuf[BGP_ADMIN_SHUTDOWN_MSG_LEN + 1];

				if (!msg && peer_group_active(peer))
					msg = peer->group->conf
						      ->tx_shutdown_message;
				msglen = msg ? strlen(msg) : 0;
				if (msglen > BGP_ADMIN_SHUTDOWN_MSG_LEN)
					msglen = BGP_ADMIN_SHUTDOWN_MSG_LEN;

				if (msglen) {
					msgbuf[0] = msglen;
					memcpy(msgbuf + 1, msg, msglen);

					bgp_notify_send_with_data(
						peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN,
						msgbuf, msglen + 1);
				} else
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN);
			} else
				bgp_session_reset(peer);
		} else {
			peer->v_start = BGP_INIT_START_TIMER;
			BGP_EVENT_ADD(peer->connection, BGP_Stop);
		}
	} else if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status)) {
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
				BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	} else
		bgp_session_reset(peer);
}

/* Enable global administrative shutdown of all peers of BGP instance */
void bgp_shutdown_enable(struct bgp *bgp, const char *msg)
{
	struct peer *peer;
	struct listnode *node;
	/* length(1) + message(N) */
	uint8_t data[BGP_ADMIN_SHUTDOWN_MSG_LEN + 1];

	/* do nothing if already shut down */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN))
		return;

	/* informational log message */
	zlog_info("Enabled administrative shutdown on BGP instance AS %u",
		  bgp->as);

	/* iterate through peers of BGP instance */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		peer->last_reset = PEER_DOWN_USER_SHUTDOWN;

		/* continue, if peer is already in administrative shutdown. */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN))
			continue;

		/* send a RFC 4486 notification message if necessary */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status)) {
			if (msg) {
				size_t datalen = strlen(msg);

				if (datalen > BGP_ADMIN_SHUTDOWN_MSG_LEN)
					datalen = BGP_ADMIN_SHUTDOWN_MSG_LEN;

				data[0] = datalen;
				memcpy(data + 1, msg, datalen);

				bgp_notify_send_with_data(peer->connection,
							  BGP_NOTIFY_CEASE,
							  BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN,
							  data, datalen + 1);
			} else {
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN);
			}
		}

		/* reset start timer to initial value */
		peer->v_start = BGP_INIT_START_TIMER;

		/* trigger a RFC 4271 ManualStop event */
		BGP_EVENT_ADD(peer->connection, BGP_Stop);
	}

	/* set the BGP instances shutdown flag */
	SET_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN);
}

/* Disable global administrative shutdown of all peers of BGP instance */
void bgp_shutdown_disable(struct bgp *bgp)
{
	const struct listnode *node;
	struct peer *peer;

	/* do nothing if not shut down. */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN))
		return;

	/* informational log message */
	zlog_info("Disabled administrative shutdown on BGP instance AS %u",
		  bgp->as);

	/* clear the BGP instances shutdown flag */
	UNSET_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN);

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		bgp_timer_set(peer->connection);
		peer->last_reset = PEER_DOWN_WAITING_OPEN;
	}
}

/* Change specified peer flag. */
static int peer_flag_modify(struct peer *peer, uint64_t flag, int set)
{
	int found;
	int size;
	bool invert, member_invert;
	struct peer *member;
	struct listnode *node, *nnode;
	struct peer_flag_action action;

	memset(&action, 0, sizeof(struct peer_flag_action));
	size = sizeof(peer_flag_action_list) / sizeof(struct peer_flag_action);

	invert = CHECK_FLAG(peer->flags_invert, flag);
	found = peer_flag_action_set(peer_flag_action_list, size, &action,
				     flag);

	/* Abort if no flag action exists. */
	if (!found)
		return BGP_ERR_INVALID_FLAG;

	/* Check for flag conflict: STRICT_CAP_MATCH && OVERRIDE_CAPABILITY */
	if (set && CHECK_FLAG(peer->flags | flag, PEER_FLAG_STRICT_CAP_MATCH)
	    && CHECK_FLAG(peer->flags | flag, PEER_FLAG_OVERRIDE_CAPABILITY))
		return BGP_ERR_PEER_FLAG_CONFLICT;

	/* Handle flag updates where desired state matches current state. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (set && CHECK_FLAG(peer->flags, flag)) {
			COND_FLAG(peer->flags_override, flag, !invert);
			return 0;
		}

		if (!set && !CHECK_FLAG(peer->flags, flag)) {
			COND_FLAG(peer->flags_override, flag, invert);
			return 0;
		}
	}

	/* Inherit from peer-group or set/unset flags accordingly. */
	if (peer_group_active(peer) && set == invert)
		peer_flag_inherit(peer, flag);
	else
		COND_FLAG(peer->flags, flag, set);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update flag override state accordingly. */
		COND_FLAG(peer->flags_override, flag, set != invert);

		/*
		 * For the extended next-hop encoding flag we need to turn RAs
		 * on if flag is being set, but only turn RAs off if the flag
		 * is being unset on this peer and if this peer is a member of a
		 * peer-group, the peer-group also doesn't have the flag set.
		 */
		if (flag == PEER_FLAG_CAPABILITY_ENHE) {
			if (set) {
				bgp_zebra_initiate_radv(peer->bgp, peer);
			} else if (peer_group_active(peer)) {
				if (!CHECK_FLAG(peer->group->conf->flags,
						flag) &&
				    !peer->conf_if)
					bgp_zebra_terminate_radv(peer->bgp,
								 peer);
			} else
				bgp_zebra_terminate_radv(peer->bgp, peer);
		}

		if (flag == PEER_FLAG_SHUTDOWN)
			peer->last_reset = set ? PEER_DOWN_USER_SHUTDOWN
					       : PEER_DOWN_WAITING_OPEN;

		/* Execute flag action on peer. */
		if (action.type == peer_change_reset)
			peer_flag_modify_action(peer, flag);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Update peer-group members, unless they are explicitly overriding
	 * peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, flag))
			continue;

		/* Check if only member without group is inverted. */
		member_invert =
			CHECK_FLAG(member->flags_invert, flag) && !invert;

		/* Skip peers with equivalent configuration. */
		if (set != member_invert && CHECK_FLAG(member->flags, flag))
			continue;

		if (set == member_invert && !CHECK_FLAG(member->flags, flag))
			continue;

		/* Update flag on peer-group member. */
		COND_FLAG(member->flags, flag, set != member_invert);

		if (flag == PEER_FLAG_CAPABILITY_ENHE && !member->conf_if)
			set ? bgp_zebra_initiate_radv(member->bgp, member)
			    : bgp_zebra_terminate_radv(member->bgp, member);

		if (flag == PEER_FLAG_SHUTDOWN)
			member->last_reset = set ? PEER_DOWN_USER_SHUTDOWN
						 : PEER_DOWN_WAITING_OPEN;

		/* Execute flag action on peer-group member. */
		if (action.type == peer_change_reset)
			peer_flag_modify_action(member, flag);
	}

	return 0;
}

int peer_flag_set(struct peer *peer, uint64_t flag)
{
	return peer_flag_modify(peer, flag, 1);
}

int peer_flag_unset(struct peer *peer, uint64_t flag)
{
	return peer_flag_modify(peer, flag, 0);
}

static int peer_af_flag_modify(struct peer *peer, afi_t afi, safi_t safi,
			       uint64_t flag, bool set)
{
	int found;
	int size;
	bool invert, member_invert;
	struct peer *member;
	struct listnode *node, *nnode;
	struct peer_flag_action action;
	enum bgp_peer_sort ptype;

	memset(&action, 0, sizeof(struct peer_flag_action));
	size = sizeof(peer_af_flag_action_list)
	       / sizeof(struct peer_flag_action);

	invert = CHECK_FLAG(peer->af_flags_invert[afi][safi], flag);
	found = peer_flag_action_set(peer_af_flag_action_list, size, &action,
				     flag);

	/* Abort if flag action exists. */
	if (!found)
		return BGP_ERR_INVALID_FLAG;

	ptype = peer_sort(peer);
	/* Special check for reflector client.  */
	if (CHECK_FLAG(flag, PEER_FLAG_REFLECTOR_CLIENT) &&
	    ptype != BGP_PEER_IBGP)
		return BGP_ERR_NOT_INTERNAL_PEER;

	/* Special check for remove-private-AS.  */
	if (CHECK_FLAG(flag, PEER_FLAG_REMOVE_PRIVATE_AS) &&
	    ptype == BGP_PEER_IBGP)
		return BGP_ERR_REMOVE_PRIVATE_AS;

	/* as-override is not allowed for IBGP peers */
	if (CHECK_FLAG(flag, PEER_FLAG_AS_OVERRIDE) && ptype == BGP_PEER_IBGP)
		return BGP_ERR_AS_OVERRIDE;

	/* Handle flag updates where desired state matches current state. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (set && CHECK_FLAG(peer->af_flags[afi][safi], flag)) {
			COND_FLAG(peer->af_flags_override[afi][safi], flag,
				  !invert);
			return 0;
		}

		if (!set && !CHECK_FLAG(peer->af_flags[afi][safi], flag)) {
			COND_FLAG(peer->af_flags_override[afi][safi], flag,
				  invert);
			return 0;
		}
	}

	/*
	 * For EVPN we implicitly set the NEXTHOP_UNCHANGED flag,
	 * if we are setting/unsetting flags which conflict with this flag
	 * handle accordingly
	 */
	if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
		if (set) {

			/*
			 * if we are setting NEXTHOP_SELF, we need to unset the
			 * NEXTHOP_UNCHANGED flag
			 */
			if (CHECK_FLAG(flag, PEER_FLAG_NEXTHOP_SELF) ||
			    CHECK_FLAG(flag, PEER_FLAG_FORCE_NEXTHOP_SELF))
				UNSET_FLAG(peer->af_flags[afi][safi],
					   PEER_FLAG_NEXTHOP_UNCHANGED);
		} else {

			/*
			 * if we are unsetting NEXTHOP_SELF, we need to set the
			 * NEXTHOP_UNCHANGED flag to reset the defaults for EVPN
			 */
			if (CHECK_FLAG(flag, PEER_FLAG_NEXTHOP_SELF) ||
			    CHECK_FLAG(flag, PEER_FLAG_FORCE_NEXTHOP_SELF))
				SET_FLAG(peer->af_flags[afi][safi],
					 PEER_FLAG_NEXTHOP_UNCHANGED);
		}
	}

	/*
	 * If the peer is a route server client let's not
	 * muck with the nexthop on the way out the door
	 */
	if (CHECK_FLAG(flag, PEER_FLAG_RSERVER_CLIENT)) {
		if (set)
			SET_FLAG(peer->af_flags[afi][safi],
				 PEER_FLAG_NEXTHOP_UNCHANGED);
		else
			UNSET_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_NEXTHOP_UNCHANGED);
	}

	/* Inherit from peer-group or set/unset flags accordingly. */
	if (peer_group_active(peer) && set == invert)
		peer_af_flag_inherit(peer, afi, safi, flag);
	else
		COND_FLAG(peer->af_flags[afi][safi], flag, set);

	/* Execute action when peer is established.  */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP) &&
	    peer_established(peer->connection)) {
		if (!set && flag == PEER_FLAG_SOFT_RECONFIG)
			bgp_clear_adj_in(peer, afi, safi);
		else {
			if (flag == PEER_FLAG_REFLECTOR_CLIENT)
				peer->last_reset = PEER_DOWN_RR_CLIENT_CHANGE;
			else if (flag == PEER_FLAG_RSERVER_CLIENT)
				peer->last_reset = PEER_DOWN_RS_CLIENT_CHANGE;
			else if (flag == PEER_FLAG_ORF_PREFIX_SM)
				peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;
			else if (flag == PEER_FLAG_ORF_PREFIX_RM)
				peer->last_reset = PEER_DOWN_CAPABILITY_CHANGE;

			/* We should not reset the session if
			 * dynamic capability is enabled and we
			 * are changing the ORF prefix flags.
			 */
			if ((CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) &&
			     CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV)) &&
			    (flag == PEER_FLAG_ORF_PREFIX_RM ||
			     flag == PEER_FLAG_ORF_PREFIX_SM))
				action.type = peer_change_none;

			peer_change_action(peer, afi, safi, action.type);
		}
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		COND_FLAG(peer->af_flags_override[afi][safi], flag,
			  set != invert);
	} else {
		/*
		 * Update peer-group members, unless they are explicitly
		 * overriding peer-group configuration.
		 */
		for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode,
				       member)) {
			/* Skip peers with overridden configuration. */
			if (CHECK_FLAG(member->af_flags_override[afi][safi],
				       flag))
				continue;

			/* Check if only member without group is inverted. */
			member_invert =
				CHECK_FLAG(member->af_flags_invert[afi][safi],
					   flag)
				&& !invert;

			/* Skip peers with equivalent configuration. */
			if (set != member_invert
			    && CHECK_FLAG(member->af_flags[afi][safi], flag))
				continue;

			if (set == member_invert
			    && !CHECK_FLAG(member->af_flags[afi][safi], flag))
				continue;

			/* Update flag on peer-group member. */
			COND_FLAG(member->af_flags[afi][safi], flag,
				  set != member_invert);

			/* Execute flag action on peer-group member. */
			if (peer_established(member->connection)) {
				if (!set && flag == PEER_FLAG_SOFT_RECONFIG)
					bgp_clear_adj_in(member, afi, safi);
				else {
					if (flag == PEER_FLAG_REFLECTOR_CLIENT)
						member->last_reset =
							PEER_DOWN_RR_CLIENT_CHANGE;
					else if (flag
						 == PEER_FLAG_RSERVER_CLIENT)
						member->last_reset =
							PEER_DOWN_RS_CLIENT_CHANGE;
					else if (flag
						 == PEER_FLAG_ORF_PREFIX_SM)
						member->last_reset =
							PEER_DOWN_CAPABILITY_CHANGE;
					else if (flag
						 == PEER_FLAG_ORF_PREFIX_RM)
						member->last_reset =
							PEER_DOWN_CAPABILITY_CHANGE;

					/* We should not reset the session if
					 * dynamic capability is enabled and we
					 * are changing the ORF prefix flags.
					 */
					if ((CHECK_FLAG(peer->cap,
							PEER_CAP_DYNAMIC_RCV) &&
					     CHECK_FLAG(peer->cap,
							PEER_CAP_DYNAMIC_ADV)) &&
					    (flag == PEER_FLAG_ORF_PREFIX_RM ||
					     flag == PEER_FLAG_ORF_PREFIX_SM))
						action.type = peer_change_none;

					peer_change_action(member, afi, safi,
							   action.type);
				}
			}
		}
	}

	return 0;
}

int peer_af_flag_set(struct peer *peer, afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify(peer, afi, safi, flag, 1);
}

int peer_af_flag_unset(struct peer *peer, afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify(peer, afi, safi, flag, 0);
}


void peer_tx_shutdown_message_set(struct peer *peer, const char *msg)
{
	XFREE(MTYPE_PEER_TX_SHUTDOWN_MSG, peer->tx_shutdown_message);
	peer->tx_shutdown_message =
		msg ? XSTRDUP(MTYPE_PEER_TX_SHUTDOWN_MSG, msg) : NULL;
}

void peer_tx_shutdown_message_unset(struct peer *peer)
{
	XFREE(MTYPE_PEER_TX_SHUTDOWN_MSG, peer->tx_shutdown_message);
}


/* EBGP multihop configuration. */
int peer_ebgp_multihop_set(struct peer *peer, int ttl)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct peer *peer1;

	if (peer->sort == BGP_PEER_IBGP || peer->conf_if)
		return 0;

	/* is there anything to do? */
	if (peer->ttl == ttl)
		return 0;

	/* see comment in peer_ttl_security_hops_set() */
	if (ttl != MAXTTL) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			group = peer->group;
			if (group->conf->gtsm_hops != BGP_GTSM_HOPS_DISABLED)
				return BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK;

			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       peer1)) {
				if (peer1->sort == BGP_PEER_IBGP)
					continue;

				if (peer1->gtsm_hops != BGP_GTSM_HOPS_DISABLED)
					return BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK;
			}
		} else {
			if (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED)
				return BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK;
		}
	}

	peer->ttl = ttl;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (peer->sort != BGP_PEER_IBGP) {
			if (BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status))
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_CONFIG_CHANGE);
			else
				bgp_session_reset(peer);

			/* Reconfigure BFD peer with new TTL. */
			if (peer->bfd_config)
				bgp_peer_bfd_update_source(peer);
		}
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_IBGP)
				continue;

			peer->ttl = group->conf->ttl;

			if (BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status))
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_CONFIG_CHANGE);
			else
				bgp_session_reset(peer);

			/* Reconfigure BFD peer with new TTL. */
			if (peer->bfd_config)
				bgp_peer_bfd_update_source(peer);
		}
	}
	return 0;
}

int peer_ebgp_multihop_unset(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int ttl;

	if (peer->sort == BGP_PEER_IBGP)
		return 0;

	if (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED && peer->ttl != MAXTTL)
		return BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK;

	if (peer_group_active(peer))
		ttl = peer->group->conf->ttl;
	else
		ttl = BGP_DEFAULT_TTL;

	if (ttl == peer->ttl)
		return 0;

	peer->ttl = ttl;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/* Reconfigure BFD peer with new TTL. */
		if (peer->bfd_config)
			bgp_peer_bfd_update_source(peer);
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_IBGP)
				continue;

			peer->ttl = BGP_DEFAULT_TTL;

			if (peer->connection->fd >= 0) {
				if (BGP_IS_VALID_STATE_FOR_NOTIF(
					    peer->connection->status))
					bgp_notify_send(peer->connection,
							BGP_NOTIFY_CEASE,
							BGP_NOTIFY_CEASE_CONFIG_CHANGE);
				else
					bgp_session_reset(peer);
			}

			/* Reconfigure BFD peer with new TTL. */
			if (peer->bfd_config)
				bgp_peer_bfd_update_source(peer);
		}
	}
	return 0;
}

/* Set Open Policy Role and check its correctness */
int peer_role_set(struct peer *peer, uint8_t role, bool strict_mode)
{
	struct peer *member;
	struct listnode *node, *nnode;

	peer_flag_set(peer, PEER_FLAG_ROLE);

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (peer->sort != BGP_PEER_EBGP)
			return BGP_ERR_INVALID_INTERNAL_ROLE;

		if (peer->local_role == role) {
			if (CHECK_FLAG(peer->flags,
				       PEER_FLAG_ROLE_STRICT_MODE) &&
			    !strict_mode)
				/* TODO: Is session restart needed if it was
				 * down?
				 */
				UNSET_FLAG(peer->flags,
					   PEER_FLAG_ROLE_STRICT_MODE);
			if (!CHECK_FLAG(peer->flags,
					PEER_FLAG_ROLE_STRICT_MODE) &&
			    strict_mode) {
				SET_FLAG(peer->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
				/* Restart session to throw Role Mismatch
				 * Notification
				 */
				if (peer->remote_role == ROLE_UNDEFINED)
					bgp_session_reset(peer);
			}
		} else {
			peer->local_role = role;
			if (strict_mode)
				SET_FLAG(peer->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
			else
				UNSET_FLAG(peer->flags,
					   PEER_FLAG_ROLE_STRICT_MODE);
		}

		return CMD_SUCCESS;
	}

	peer->local_role = role;
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		if (member->sort != BGP_PEER_EBGP)
			return BGP_ERR_INVALID_INTERNAL_ROLE;

		if (member->local_role == role) {
			if (CHECK_FLAG(member->flags,
				       PEER_FLAG_ROLE_STRICT_MODE) &&
			    !strict_mode)
				/* TODO: Is session restart needed if it was
				 * down?
				 */
				UNSET_FLAG(member->flags,
					   PEER_FLAG_ROLE_STRICT_MODE);
			if (!CHECK_FLAG(member->flags,
					PEER_FLAG_ROLE_STRICT_MODE) &&
			    strict_mode) {
				SET_FLAG(peer->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
				SET_FLAG(member->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
				/* Restart session to throw Role Mismatch
				 * Notification
				 */
				if (member->remote_role == ROLE_UNDEFINED)
					bgp_session_reset(member);
			}
		} else {
			member->local_role = role;

			if (strict_mode) {
				SET_FLAG(peer->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
				SET_FLAG(member->flags,
					 PEER_FLAG_ROLE_STRICT_MODE);
			} else {
				UNSET_FLAG(member->flags,
					   PEER_FLAG_ROLE_STRICT_MODE);
			}
		}
	}

	return CMD_SUCCESS;
}

int peer_role_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	peer_flag_unset(peer, PEER_FLAG_ROLE);

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return peer_role_set(peer, ROLE_UNDEFINED, 0);

	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member))
		peer_role_set(member, ROLE_UNDEFINED, 0);

	return CMD_SUCCESS;
}

/* Neighbor description. */
void peer_description_set(struct peer *peer, const char *desc)
{
	XFREE(MTYPE_PEER_DESC, peer->desc);

	peer->desc = XSTRDUP(MTYPE_PEER_DESC, desc);
}

void peer_description_unset(struct peer *peer)
{
	XFREE(MTYPE_PEER_DESC, peer->desc);
}

/* Neighbor update-source. */
int peer_update_source_if_set(struct peer *peer, const char *ifname)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_UPDATE_SOURCE);
	if (peer->update_if) {
		if (strcmp(peer->update_if, ifname) == 0)
			return 0;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
	}
	peer->update_if = XSTRDUP(MTYPE_PEER_UPDATE_SOURCE, ifname);
	sockunion_free(peer->update_source);
	peer->update_source = NULL;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/* Apply new source configuration to BFD session. */
		if (peer->bfd_config)
			bgp_peer_bfd_update_source(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (member->update_if) {
			if (strcmp(member->update_if, ifname) == 0)
				continue;
			XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);
		}

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		member->update_if = XSTRDUP(MTYPE_PEER_UPDATE_SOURCE, ifname);
		sockunion_free(member->update_source);
		member->update_source = NULL;
		member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;

		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);

		/* Apply new source configuration to BFD session. */
		if (member->bfd_config)
			bgp_peer_bfd_update_source(member);
	}

	return 0;
}

void peer_update_source_addr_set(struct peer *peer, const union sockunion *su)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_UPDATE_SOURCE);
	if (peer->update_source) {
		if (sockunion_cmp(peer->update_source, su) == 0)
			return;
		sockunion_free(peer->update_source);
	}
	peer->update_source = sockunion_dup(su);
	XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/* Apply new source configuration to BFD session. */
		if (peer->bfd_config)
			bgp_peer_bfd_update_source(peer);

		/* Skip peer-group mechanics for regular peers. */
		return;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (member->update_source) {
			if (sockunion_cmp(member->update_source, su) == 0)
				continue;
			sockunion_free(member->update_source);
		}

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		member->update_source = sockunion_dup(su);
		XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);
		member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;

		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);

		/* Apply new source configuration to BFD session. */
		if (member->bfd_config)
			bgp_peer_bfd_update_source(member);
	}
}

void peer_update_source_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;
	bool src_unchanged = false;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_UPDATE_SOURCE))
		return;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		/* Don't reset peer if the update_source we'll inherit from
		 * the peer-group matches the peer's existing update_source
		 */
		src_unchanged =
			(peer->update_source &&
			 peer->group->conf->update_source &&
			 sockunion_cmp(peer->update_source,
				       peer->group->conf->update_source) == 0);

		peer_flag_inherit(peer, PEER_FLAG_UPDATE_SOURCE);
		PEER_SU_ATTR_INHERIT(peer, peer->group, update_source);
		PEER_STR_ATTR_INHERIT(peer, peer->group, update_if,
				      MTYPE_PEER_UPDATE_SOURCE);

		if (src_unchanged)
			return;
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_UPDATE_SOURCE);
		sockunion_free(peer->update_source);
		peer->update_source = NULL;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/* Apply new source configuration to BFD session. */
		if (peer->bfd_config)
			bgp_peer_bfd_update_source(peer);

		/* Skip peer-group mechanics for regular peers. */
		return;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_UPDATE_SOURCE))
			continue;

		/* Skip peers with the same configuration. */
		if (!CHECK_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE)
		    && !member->update_source && !member->update_if)
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_UPDATE_SOURCE);
		sockunion_free(member->update_source);
		member->update_source = NULL;
		XFREE(MTYPE_PEER_UPDATE_SOURCE, member->update_if);
		member->last_reset = PEER_DOWN_UPDATE_SOURCE_CHANGE;

		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);

		/* Apply new source configuration to BFD session. */
		if (member->bfd_config)
			bgp_peer_bfd_update_source(member);
	}
}

int peer_default_originate_set(struct peer *peer, afi_t afi, safi_t safi,
			       const char *rmap, struct route_map *route_map)
{
	struct peer *member;
	struct listnode *node, *nnode;
	struct update_subgroup *subgrp;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_DEFAULT_ORIGINATE);

	subgrp = peer_subgroup(peer, afi, safi);

	if (rmap) {
		if (!peer->bgp->rmap_def_originate_eval_timer)
			peer->bgp->rmap_def_originate_eval_timer =
				RMAP_DEFAULT_ORIGINATE_EVAL_TIMER;

		if (!peer->default_rmap[afi][safi].name
		    || strcmp(rmap, peer->default_rmap[afi][safi].name) != 0) {
			struct route_map *map = NULL;

			if (peer->default_rmap[afi][safi].name) {
				map = route_map_lookup_by_name(
					peer->default_rmap[afi][safi].name);
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      peer->default_rmap[afi][safi].name);
			}

			/*
			 * When there is a change in route-map policy,
			 * this flow gets triggered. Since, the default
			 * route is already originated, the flag is set.
			 * The flag should be unset here,
			 * to trigger the flow of sending update message.
			 */
			if (subgrp)
				UNSET_FLAG(subgrp->sflags,
					   SUBGRP_STATUS_DEFAULT_ORIGINATE);

			route_map_counter_decrement(map);
			peer->default_rmap[afi][safi].name =
				XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			peer->default_rmap[afi][safi].map = route_map;
			route_map_counter_increment(route_map);
		}
	} else if (!rmap) {
		struct route_map *map = NULL;

		if (peer->default_rmap[afi][safi].name) {
			map = route_map_lookup_by_name(
				peer->default_rmap[afi][safi].name);
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      peer->default_rmap[afi][safi].name);
		}

		/*
		 * This is triggered in case of route-map deletion.
		 * The flag needs to be unset, to trigger the flow
		 * of sending an update message.
		 */
		if (subgrp)
			UNSET_FLAG(subgrp->sflags,
				   SUBGRP_STATUS_DEFAULT_ORIGINATE);

		route_map_counter_decrement(map);
		peer->default_rmap[afi][safi].name = NULL;
		peer->default_rmap[afi][safi].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		if (peer_established(peer->connection) &&
		    peer->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(peer, afi, safi));
			bgp_default_originate(peer, afi, safi, false);
			bgp_announce_route(peer, afi, safi, false);
		}

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi],
			 PEER_FLAG_DEFAULT_ORIGINATE);
		if (rmap) {
			struct route_map *map = NULL;

			if (!member->bgp->rmap_def_originate_eval_timer)
				member->bgp->rmap_def_originate_eval_timer =
					RMAP_DEFAULT_ORIGINATE_EVAL_TIMER;

			if (member->default_rmap[afi][safi].name) {
				map = route_map_lookup_by_name(
					member->default_rmap[afi][safi].name);
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      member->default_rmap[afi][safi].name);
			}

			route_map_counter_decrement(map);
			member->default_rmap[afi][safi].name =
				XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
			member->default_rmap[afi][safi].map = route_map;
			route_map_counter_increment(route_map);
		}

		/* Update peer route announcements. */
		if (peer_established(member->connection) &&
		    member->afc_nego[afi][safi]) {
			update_group_adjust_peer(
				peer_af_find(member, afi, safi));
			bgp_default_originate(member, afi, safi, false);
			bgp_announce_route(member, afi, safi, false);
		}
	}

	return 0;
}

int peer_default_originate_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_DEFAULT_ORIGINATE);
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      default_rmap[afi][safi].name,
				      MTYPE_ROUTE_MAP_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  default_rmap[afi][safi].map);
	} else {
		struct route_map *map = NULL;

		/* Otherwise remove flag and configuration from peer. */
		peer_af_flag_unset(peer, afi, safi,
				   PEER_FLAG_DEFAULT_ORIGINATE);
		if (peer->default_rmap[afi][safi].name) {
			map = route_map_lookup_by_name(
				peer->default_rmap[afi][safi].name);
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      peer->default_rmap[afi][safi].name);
		}
		route_map_counter_decrement(map);
		peer->default_rmap[afi][safi].name = NULL;
		peer->default_rmap[afi][safi].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		if (peer_established(peer->connection) &&
		    peer->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(peer, afi, safi));
			bgp_default_originate(peer, afi, safi, true);
			bgp_announce_route(peer, afi, safi, false);
		}

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		struct route_map *map;

		map = NULL;

		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi],
			   PEER_FLAG_DEFAULT_ORIGINATE);
		if (member->default_rmap[afi][safi].name) {
			map = route_map_lookup_by_name(
				member->default_rmap[afi][safi].name);
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      member->default_rmap[afi][safi].name);
		}
		route_map_counter_decrement(map);
		member->default_rmap[afi][safi].name = NULL;
		member->default_rmap[afi][safi].map = NULL;

		/* Update peer route announcements. */
		if (peer_established(member->connection) &&
		    member->afc_nego[afi][safi]) {
			update_group_adjust_peer(peer_af_find(member, afi, safi));
			bgp_default_originate(member, afi, safi, true);
			bgp_announce_route(member, afi, safi, false);
		}
	}

	return 0;
}

void peer_port_set(struct peer *peer, uint16_t port)
{
	peer->port = port;
	peer_flag_set(peer, PEER_FLAG_PORT);
}

void peer_port_unset(struct peer *peer)
{
	peer->port = BGP_PORT_DEFAULT;
	peer_flag_unset(peer, PEER_FLAG_PORT);
}

/* Set the TCP-MSS value in the peer structure,
 * This gets applied only after connection reset
 * So this value will be used in bgp_connect.
 */
void peer_tcp_mss_set(struct peer *peer, uint32_t tcp_mss)
{
	peer->tcp_mss = tcp_mss;
	SET_FLAG(peer->flags, PEER_FLAG_TCP_MSS);
	bgp_tcp_mss_set(peer);
}

/* Reset the TCP-MSS value in the peer structure,
 * This gets applied only after connection reset
 * So this value will be used in bgp_connect.
 */
void peer_tcp_mss_unset(struct peer *peer)
{
	UNSET_FLAG(peer->flags, PEER_FLAG_TCP_MSS);
	peer->tcp_mss = 0;
	bgp_tcp_mss_set(peer);
}

/*
 * Helper function that is called after the name of the policy
 * being used by a peer has changed (AF specific). Automatically
 * initiates inbound or outbound processing as needed.
 */
void peer_on_policy_change(struct peer *peer, afi_t afi, safi_t safi,
			   int outbound)
{
	if (outbound) {
		update_group_adjust_peer(peer_af_find(peer, afi, safi));
		if (peer_established(peer->connection))
			bgp_announce_route(peer, afi, safi, false);
	} else {
		if (!peer_established(peer->connection))
			return;

		if (bgp_soft_reconfig_in(peer, afi, safi))
			return;

		if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV))
			bgp_route_refresh_send(peer, afi, safi, 0, 0, 0,
					       BGP_ROUTE_REFRESH_NORMAL);
	}
}


/* neighbor weight. */
int peer_weight_set(struct peer *peer, afi_t afi, safi_t safi, uint16_t weight)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_WEIGHT);
	if (peer->weight[afi][safi] != weight) {
		peer->weight[afi][safi] = weight;
		peer_on_policy_change(peer, afi, safi, 0);
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_WEIGHT))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT);
		if (member->weight[afi][safi] != weight) {
			member->weight[afi][safi] = weight;
			peer_on_policy_change(member, afi, safi, 0);
		}
	}

	return 0;
}

int peer_weight_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_WEIGHT))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_WEIGHT);
		PEER_ATTR_INHERIT(peer, peer->group, weight[afi][safi]);

		peer_on_policy_change(peer, afi, safi, 0);
		return 0;
	}

	/* Remove flag and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_WEIGHT);
	peer->weight[afi][safi] = 0;
	peer_on_policy_change(peer, afi, safi, 0);

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_WEIGHT))
			continue;

		/* Skip peers where flag is already disabled. */
		if (!CHECK_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi], PEER_FLAG_WEIGHT);
		member->weight[afi][safi] = 0;
		peer_on_policy_change(member, afi, safi, 0);
	}

	return 0;
}

int peer_timers_set(struct peer *peer, uint32_t keepalive, uint32_t holdtime)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (keepalive > UINT16_MAX)
		return BGP_ERR_INVALID_VALUE;

	if (holdtime > UINT16_MAX)
		return BGP_ERR_INVALID_VALUE;

	if (holdtime < 3 && holdtime != 0)
		return BGP_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_TIMER);
	peer->holdtime = holdtime;
	peer->keepalive = (keepalive < holdtime / 3 ? keepalive : holdtime / 3);

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_TIMER);
		PEER_ATTR_INHERIT(member, peer->group, holdtime);
		PEER_ATTR_INHERIT(member, peer->group, keepalive);
	}

	return 0;
}

int peer_timers_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER);
		PEER_ATTR_INHERIT(peer, peer->group, holdtime);
		PEER_ATTR_INHERIT(peer, peer->group, keepalive);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_TIMER);
		peer->holdtime = 0;
		peer->keepalive = 0;
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER);
		member->holdtime = 0;
		member->keepalive = 0;
	}

	return 0;
}

int peer_timers_connect_set(struct peer *peer, uint32_t connect)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (connect > UINT16_MAX)
		return BGP_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_TIMER_CONNECT);
	peer->connect = connect;
	peer->v_connect = connect;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (!peer_established(peer->connection)) {
			if (peer_active(peer))
				BGP_EVENT_ADD(peer->connection, BGP_Stop);
			BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
		return 0;
	}
	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER_CONNECT))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_TIMER_CONNECT);
		member->connect = connect;
		member->v_connect = connect;

		if (!peer_established(member->connection)) {
			if (peer_active(member))
				BGP_EVENT_ADD(member->connection, BGP_Stop);
			BGP_EVENT_ADD(member->connection, BGP_Start);
		}
	}

	return 0;
}

int peer_timers_connect_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER_CONNECT);
		PEER_ATTR_INHERIT(peer, peer->group, connect);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_TIMER_CONNECT);
		peer->connect = 0;
	}

	/* Set timer with fallback to default value. */
	if (peer->connect)
		peer->v_connect = peer->connect;
	else
		peer->v_connect = peer->bgp->default_connect_retry;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (!peer_established(peer->connection)) {
			if (peer_active(peer))
				BGP_EVENT_ADD(peer->connection, BGP_Stop);
			BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
		return 0;
	}
	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_TIMER_CONNECT))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER_CONNECT);
		member->connect = 0;
		member->v_connect = peer->bgp->default_connect_retry;

		if (!peer_established(member->connection)) {
			if (peer_active(member))
				BGP_EVENT_ADD(member->connection, BGP_Stop);
			BGP_EVENT_ADD(member->connection, BGP_Start);
		}
	}

	return 0;
}

int peer_advertise_interval_set(struct peer *peer, uint32_t routeadv)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (routeadv > 600)
		return BGP_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_ROUTEADV);
	peer->routeadv = routeadv;
	peer->v_routeadv = routeadv;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		update_group_adjust_peer_afs(peer);
		if (peer_established(peer->connection))
			bgp_announce_route_all(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_ROUTEADV))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_ROUTEADV);
		member->routeadv = routeadv;
		member->v_routeadv = routeadv;

		/* Update peer route announcements. */
		update_group_adjust_peer_afs(member);
		if (peer_established(member->connection))
			bgp_announce_route_all(member);
	}

	return 0;
}

int peer_advertise_interval_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_ROUTEADV);
		PEER_ATTR_INHERIT(peer, peer->group, routeadv);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_ROUTEADV);
		peer->routeadv = 0;
	}

	/* Set timer with fallback to default value. */
	if (peer->routeadv)
		peer->v_routeadv = peer->routeadv;
	else
		peer->v_routeadv = (peer->sort == BGP_PEER_IBGP)
					   ? BGP_DEFAULT_IBGP_ROUTEADV
					   : BGP_DEFAULT_EBGP_ROUTEADV;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Update peer route announcements. */
		update_group_adjust_peer_afs(peer);
		if (peer_established(peer->connection))
			bgp_announce_route_all(peer);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_ROUTEADV))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_ROUTEADV);
		member->routeadv = 0;
		member->v_routeadv = (member->sort == BGP_PEER_IBGP)
					     ? BGP_DEFAULT_IBGP_ROUTEADV
					     : BGP_DEFAULT_EBGP_ROUTEADV;

		/* Update peer route announcements. */
		update_group_adjust_peer_afs(member);
		if (peer_established(member->connection))
			bgp_announce_route_all(member);
	}

	return 0;
}

/* set the peers RFC 4271 DelayOpen session attribute flag and DelayOpenTimer
 * interval
 */
int peer_timers_delayopen_set(struct peer *peer, uint32_t delayopen)
{
	struct peer *member;
	struct listnode *node;

	/* Set peers session attribute flag and timer interval. */
	peer_flag_set(peer, PEER_FLAG_TIMER_DELAYOPEN);
	peer->delayopen = delayopen;
	peer->v_delayopen = delayopen;

	/* Skip group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/* Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override,
			       PEER_FLAG_TIMER_DELAYOPEN))
			continue;

		/* Set session attribute flag and timer intervals on peer-group
		 * member.
		 */
		SET_FLAG(member->flags, PEER_FLAG_TIMER_DELAYOPEN);
		member->delayopen = delayopen;
		member->v_delayopen = delayopen;
	}

	return 0;
}

/* unset the peers RFC 4271 DelayOpen session attribute flag and reset the
 * DelayOpenTimer interval to the default value.
 */
int peer_timers_delayopen_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_TIMER_DELAYOPEN);
		PEER_ATTR_INHERIT(peer, peer->group, delayopen);
	} else {
		/* Otherwise remove session attribute flag and set timer
		 * interval to default value.
		 */
		peer_flag_unset(peer, PEER_FLAG_TIMER_DELAYOPEN);
		peer->delayopen = peer->bgp->default_delayopen;
	}

	/* Set timer value to zero */
	peer->v_delayopen = 0;

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/* Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override,
			       PEER_FLAG_TIMER_DELAYOPEN))
			continue;

		/* Remove session attribute flag, reset the timer interval to
		 * the default value and set the timer value to zero.
		 */
		UNSET_FLAG(member->flags, PEER_FLAG_TIMER_DELAYOPEN);
		member->delayopen = peer->bgp->default_delayopen;
		member->v_delayopen = 0;
	}

	return 0;
}

/* neighbor interface */
void peer_interface_set(struct peer *peer, const char *str)
{
	XFREE(MTYPE_BGP_PEER_IFNAME, peer->ifname);
	peer->ifname = XSTRDUP(MTYPE_BGP_PEER_IFNAME, str);
}

void peer_interface_unset(struct peer *peer)
{
	XFREE(MTYPE_BGP_PEER_IFNAME, peer->ifname);
}

/* Allow-as in.  */
int peer_allowas_in_set(struct peer *peer, afi_t afi, safi_t safi,
			int allow_num, int origin)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!origin && (allow_num < 1 || allow_num > 10))
		return BGP_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
	if (origin) {
		if (peer->allowas_in[afi][safi] != 0
		    || !CHECK_FLAG(peer->af_flags[afi][safi],
				   PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
			peer_af_flag_set(peer, afi, safi,
					 PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer->allowas_in[afi][safi] = 0;
			peer_on_policy_change(peer, afi, safi, 0);
		}
	} else {
		if (peer->allowas_in[afi][safi] != allow_num
		    || CHECK_FLAG(peer->af_flags[afi][safi],
				  PEER_FLAG_ALLOWAS_IN_ORIGIN)) {

			peer_af_flag_unset(peer, afi, safi,
					   PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer->allowas_in[afi][safi] = allow_num;
			peer_on_policy_change(peer, afi, safi, 0);
		}
	}

	/* Skip peer-group mechanics for regular peers. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_ALLOWAS_IN))
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN);
		if (origin) {
			if (member->allowas_in[afi][safi] != 0
			    || !CHECK_FLAG(member->af_flags[afi][safi],
					   PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
				SET_FLAG(member->af_flags[afi][safi],
					 PEER_FLAG_ALLOWAS_IN_ORIGIN);
				member->allowas_in[afi][safi] = 0;
				peer_on_policy_change(peer, afi, safi, 0);
			}
		} else {
			if (member->allowas_in[afi][safi] != allow_num
			    || CHECK_FLAG(member->af_flags[afi][safi],
					  PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
				UNSET_FLAG(member->af_flags[afi][safi],
					   PEER_FLAG_ALLOWAS_IN_ORIGIN);
				member->allowas_in[afi][safi] = allow_num;
				peer_on_policy_change(peer, afi, safi, 0);
			}
		}
	}

	return 0;
}

int peer_allowas_in_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Skip peer if flag is already disabled. */
	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_ALLOWAS_IN_ORIGIN);
		PEER_ATTR_INHERIT(peer, peer->group, allowas_in[afi][safi]);
		peer_on_policy_change(peer, afi, safi, 0);

		return 0;
	}

	/* Remove flag and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ALLOWAS_IN);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ALLOWAS_IN_ORIGIN);
	peer->allowas_in[afi][safi] = 0;
	peer_on_policy_change(peer, afi, safi, 0);

	/* Skip peer-group mechanics if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Remove flags and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_ALLOWAS_IN))
			continue;

		/* Remove flags and configuration on peer-group member. */
		UNSET_FLAG(member->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN);
		UNSET_FLAG(member->af_flags[afi][safi],
			   PEER_FLAG_ALLOWAS_IN_ORIGIN);
		member->allowas_in[afi][safi] = 0;
		peer_on_policy_change(member, afi, safi, 0);
	}

	return 0;
}

int peer_local_as_set(struct peer *peer, as_t as, bool no_prepend,
		      bool replace_as, bool dual_as, const char *as_str)
{
	bool old_no_prepend, old_replace_as, old_dual_as;
	struct bgp *bgp = peer->bgp;
	struct peer *member;
	struct listnode *node, *nnode;

	if (bgp->as == as)
		return BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS;

	/* Save previous flag states. */
	old_no_prepend =
		!!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND);
	old_replace_as =
		!!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS);
	old_dual_as = !!CHECK_FLAG(peer->flags, PEER_FLAG_DUAL_AS);

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_LOCAL_AS);
	peer_flag_modify(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND, no_prepend);
	peer_flag_modify(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS, replace_as);
	peer_flag_modify(peer, PEER_FLAG_DUAL_AS, dual_as);

	if (peer->change_local_as == as && old_no_prepend == no_prepend &&
	    old_replace_as == replace_as && old_dual_as == dual_as)
		return 0;
	peer->change_local_as = as;
	if (as_str) {
		if (peer->change_local_as_pretty)
			XFREE(MTYPE_BGP_NAME, peer->change_local_as_pretty);
		peer->change_local_as_pretty = XSTRDUP(MTYPE_BGP_NAME, as_str);
	}

	(void)peer_sort(peer);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		return 0;

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_LOCAL_AS))
			continue;

		/* Skip peers with the same configuration. */
		old_no_prepend = CHECK_FLAG(member->flags,
					    PEER_FLAG_LOCAL_AS_NO_PREPEND);
		old_replace_as = CHECK_FLAG(member->flags,
					    PEER_FLAG_LOCAL_AS_REPLACE_AS);
		old_dual_as = !!CHECK_FLAG(member->flags, PEER_FLAG_DUAL_AS);
		if (member->change_local_as == as &&
		    CHECK_FLAG(member->flags, PEER_FLAG_LOCAL_AS) &&
		    old_no_prepend == no_prepend &&
		    old_replace_as == replace_as && old_dual_as == dual_as)
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_LOCAL_AS);
		COND_FLAG(member->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND,
			  no_prepend);
		COND_FLAG(member->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS,
			  replace_as);
		COND_FLAG(member->flags, PEER_FLAG_DUAL_AS, dual_as);
		member->change_local_as = as;
		if (as_str)
			member->change_local_as_pretty = XSTRDUP(MTYPE_BGP_NAME,
								 as_str);
	}

	return 0;
}

int peer_local_as_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_LOCAL_AS))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS);
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		peer_flag_inherit(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		peer_flag_inherit(peer, PEER_FLAG_DUAL_AS);
		PEER_ATTR_INHERIT(peer, peer->group, change_local_as);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS);
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		peer_flag_unset(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		peer_flag_unset(peer, PEER_FLAG_DUAL_AS);
		peer->change_local_as = 0;
		XFREE(MTYPE_BGP_NAME, peer->change_local_as_pretty);
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;
		/* Send notification or stop peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			BGP_EVENT_ADD(peer->connection, BGP_Stop);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_LOCAL_AS))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS);
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND);
		UNSET_FLAG(member->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS);
		UNSET_FLAG(member->flags, PEER_FLAG_DUAL_AS);
		member->change_local_as = 0;
		XFREE(MTYPE_BGP_NAME, member->change_local_as_pretty);
		member->last_reset = PEER_DOWN_LOCAL_AS_CHANGE;

		/* Send notification or stop peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);
	}

	return 0;
}

/* Set password for authenticating with the peer. */
int peer_password_set(struct peer *peer, const char *password)
{
	struct peer *member;
	struct listnode *node, *nnode;
	int len = password ? strlen(password) : 0;
	int ret = BGP_SUCCESS;

	if ((len < PEER_PASSWORD_MINLEN) || (len > PEER_PASSWORD_MAXLEN))
		return BGP_ERR_INVALID_VALUE;

	/* Set flag and configuration on peer. */
	peer_flag_set(peer, PEER_FLAG_PASSWORD);
	if (peer->password && strcmp(peer->password, password) == 0)
		return 0;
	XFREE(MTYPE_PEER_PASSWORD, peer->password);
	peer->password = XSTRDUP(MTYPE_PEER_PASSWORD, password);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		peer->last_reset = PEER_DOWN_PASSWORD_CHANGE;
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/*
		 * Attempt to install password on socket and skip peer-group
		 * mechanics.
		 */
		if (BGP_CONNECTION_SU_UNSPEC(peer->connection))
			return BGP_SUCCESS;
		return (bgp_md5_set(peer->connection) >= 0)
			       ? BGP_SUCCESS
			       : BGP_ERR_TCPSIG_FAILED;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_PASSWORD))
			continue;

		/* Skip peers with the same password. */
		if (member->password && strcmp(member->password, password) == 0)
			continue;

		/* Set flag and configuration on peer-group member. */
		SET_FLAG(member->flags, PEER_FLAG_PASSWORD);
		if (member->password)
			XFREE(MTYPE_PEER_PASSWORD, member->password);
		member->password = XSTRDUP(MTYPE_PEER_PASSWORD, password);

		member->last_reset = PEER_DOWN_PASSWORD_CHANGE;
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);

		/* Attempt to install password on socket. */
		if (!BGP_CONNECTION_SU_UNSPEC(member->connection) &&
		    bgp_md5_set(member->connection) < 0)
			ret = BGP_ERR_TCPSIG_FAILED;
	}

	/* Set flag and configuration on all peer-group listen ranges */
	struct listnode *ln;
	struct prefix *lr;

	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP], ln, lr))
		bgp_md5_set_prefix(peer->bgp, lr, password);
	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP6], ln, lr))
		bgp_md5_set_prefix(peer->bgp, lr, password);

	return ret;
}

int peer_password_unset(struct peer *peer)
{
	struct peer *member;
	struct listnode *node, *nnode;

	if (!CHECK_FLAG(peer->flags, PEER_FLAG_PASSWORD))
		return 0;

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, PEER_FLAG_PASSWORD);
		PEER_STR_ATTR_INHERIT(peer, peer->group, password,
				      MTYPE_PEER_PASSWORD);
	} else {
		/* Otherwise remove flag and configuration from peer. */
		peer_flag_unset(peer, PEER_FLAG_PASSWORD);
		XFREE(MTYPE_PEER_PASSWORD, peer->password);
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);

		/* Attempt to uninstall password on socket. */
		if (!BGP_CONNECTION_SU_UNSPEC(peer->connection))
			bgp_md5_unset(peer->connection);
		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->flags_override, PEER_FLAG_PASSWORD))
			continue;

		/* Remove flag and configuration on peer-group member. */
		UNSET_FLAG(member->flags, PEER_FLAG_PASSWORD);
		XFREE(MTYPE_PEER_PASSWORD, member->password);

		/* Send notification or reset peer depending on state. */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(member->connection->status))
			bgp_notify_send(member->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(member);

		/* Attempt to uninstall password on socket. */
		if (!BGP_CONNECTION_SU_UNSPEC(member->connection))
			bgp_md5_unset(member->connection);
	}

	/* Set flag and configuration on all peer-group listen ranges */
	struct listnode *ln;
	struct prefix *lr;

	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP], ln, lr))
		bgp_md5_unset_prefix(peer->bgp, lr);
	for (ALL_LIST_ELEMENTS_RO(peer->group->listen_range[AFI_IP6], ln, lr))
		bgp_md5_unset_prefix(peer->bgp, lr);

	return 0;
}


/* Set distribute list to the peer. */
int peer_distribute_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
			const char *name)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->plist[direct].name)
		return BGP_ERR_PEER_FILTER_CONFLICT;
	if (filter->dlist[direct].name)
		XFREE(MTYPE_BGP_FILTER_NAME, filter->dlist[direct].name);
	filter->dlist[direct].name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
	filter->dlist[direct].alist = access_list_lookup(afi, name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_DISTRIBUTE_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, un less they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_DISTRIBUTE_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name =
			XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
		filter->dlist[direct].alist = access_list_lookup(afi, name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_distribute_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_DISTRIBUTE_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].dlist[direct].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].dlist[direct].alist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name = NULL;
		filter->dlist[direct].alist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_DISTRIBUTE_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->dlist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->dlist[direct].name);
		filter->dlist[direct].name = NULL;
		filter->dlist[direct].alist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

/* Update distribute list. */
static void peer_distribute_update(struct access_list *access)
{
	afi_t afi;
	safi_t safi;
	int direct;
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;
	struct peer_group *group;
	struct bgp_filter *filter;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (access->name)
			update_group_policy_update(bgp,
						   BGP_POLICY_DISTRIBUTE_LIST,
						   access->name, true, 0);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->dlist[direct].name)
						filter->dlist[direct]
							.alist = access_list_lookup(
							afi,
							filter->dlist[direct]
								.name);
					else
						filter->dlist[direct].alist =
							NULL;
				}
			}
		}
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->dlist[direct].name)
						filter->dlist[direct]
							.alist = access_list_lookup(
							afi,
							filter->dlist[direct]
								.name);
					else
						filter->dlist[direct].alist =
							NULL;
				}
			}
		}
#ifdef ENABLE_BGP_VNC
		vnc_prefix_list_update(bgp);
#endif
	}
}

/* Set prefix list to the peer. */
int peer_prefix_list_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
			 const char *name)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->dlist[direct].name)
		return BGP_ERR_PEER_FILTER_CONFLICT;
	if (filter->plist[direct].name)
		XFREE(MTYPE_BGP_FILTER_NAME, filter->plist[direct].name);
	filter->plist[direct].name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
	filter->plist[direct].plist = prefix_list_lookup(afi, name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_PREFIX_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_PREFIX_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name =
			XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
		filter->plist[direct].plist = prefix_list_lookup(afi, name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_prefix_list_unset(struct peer *peer, afi_t afi, safi_t safi,
			   int direct)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_PREFIX_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].plist[direct].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].plist[direct].plist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name = NULL;
		filter->plist[direct].plist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_PREFIX_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->plist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->plist[direct].name);
		filter->plist[direct].name = NULL;
		filter->plist[direct].plist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

/* Update prefix-list list. */
static void peer_prefix_list_update(struct prefix_list *plist)
{
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;
	struct peer_group *group;
	struct bgp_filter *filter;
	afi_t afi;
	safi_t safi;
	int direct;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		/*
		 * Update the prefix-list on update groups.
		 */
		update_group_policy_update(
			bgp, BGP_POLICY_PREFIX_LIST,
			plist ? prefix_list_name(plist) : NULL, true, 0);

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->plist[direct].name)
						filter->plist[direct]
							.plist = prefix_list_lookup(
							afi,
							filter->plist[direct]
								.name);
					else
						filter->plist[direct].plist =
							NULL;
				}

				/* If we touch prefix-list, we need to process
				 * new updates. This is important for ORF to
				 * work correctly.
				 */
				if (CHECK_FLAG(peer->af_cap[afi][safi],
					       PEER_CAP_ORF_PREFIX_SM_ADV) &&
				    CHECK_FLAG(peer->af_cap[afi][safi],
					       PEER_CAP_ORF_PREFIX_RM_RCV))
					peer_clear_soft(
						peer, afi, safi,
						BGP_CLEAR_SOFT_IN_ORF_PREFIX);
			}
		}
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->plist[direct].name)
						filter->plist[direct]
							.plist = prefix_list_lookup(
							afi,
							filter->plist[direct]
								.name);
					else
						filter->plist[direct].plist =
							NULL;
				}
			}
		}
	}
}

int peer_aslist_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
		    const char *name)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->aslist[direct].name)
		XFREE(MTYPE_BGP_FILTER_NAME, filter->aslist[direct].name);
	filter->aslist[direct].name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
	filter->aslist[direct].aslist = as_list_lookup(name);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_FILTER_LIST);
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_FILTER_LIST))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name =
			XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
		filter->aslist[direct].aslist = as_list_lookup(name);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

int peer_aslist_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != FILTER_IN && direct != FILTER_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct],
		   PEER_FT_FILTER_LIST);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].aslist[direct].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].aslist[direct].aslist);
	} else {
		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name = NULL;
		filter->aslist[direct].aslist = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_FILTER_LIST))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->aslist[direct].name)
			XFREE(MTYPE_BGP_FILTER_NAME,
			      filter->aslist[direct].name);
		filter->aslist[direct].name = NULL;
		filter->aslist[direct].aslist = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == FILTER_OUT) ? 1 : 0);
	}

	return 0;
}

static void peer_aslist_update(const char *aslist_name)
{
	afi_t afi;
	safi_t safi;
	int direct;
	struct listnode *mnode, *mnnode;
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;
	struct peer_group *group;
	struct bgp_filter *filter;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		update_group_policy_update(bgp, BGP_POLICY_FILTER_LIST,
					   aslist_name, true, 0);

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &peer->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->aslist[direct].name)
						filter->aslist[direct]
							.aslist = as_list_lookup(
							filter->aslist[direct]
								.name);
					else
						filter->aslist[direct].aslist =
							NULL;
				}
			}
		}
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			FOREACH_AFI_SAFI (afi, safi) {
				filter = &group->conf->filter[afi][safi];

				for (direct = FILTER_IN; direct < FILTER_MAX;
				     direct++) {
					if (filter->aslist[direct].name)
						filter->aslist[direct]
							.aslist = as_list_lookup(
							filter->aslist[direct]
								.name);
					else
						filter->aslist[direct].aslist =
							NULL;
				}
			}
		}
	}
}

static void peer_aslist_add(char *aslist_name)
{
	peer_aslist_update(aslist_name);
	route_map_notify_dependencies(aslist_name, RMAP_EVENT_ASLIST_ADDED);
}

static void peer_aslist_del(const char *aslist_name)
{
	peer_aslist_update(aslist_name);
	route_map_notify_dependencies(aslist_name, RMAP_EVENT_ASLIST_DELETED);
}


int peer_route_map_set(struct peer *peer, afi_t afi, safi_t safi, int direct,
		       const char *name, struct route_map *route_map)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;
	struct route_map *map = NULL;

	if (direct != RMAP_IN && direct != RMAP_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->map[direct].name) {
		/* If the neighbor is configured with the same route-map
		 * again then, ignore the duplicate configuration.
		 */
		if (strcmp(filter->map[direct].name, name) == 0)
			return 0;

		map = route_map_lookup_by_name(filter->map[direct].name);
		XFREE(MTYPE_BGP_FILTER_NAME, filter->map[direct].name);
	}
	route_map_counter_decrement(map);
	filter->map[direct].name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
	filter->map[direct].map = route_map;
	route_map_counter_increment(route_map);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][direct],
			 PEER_FT_ROUTE_MAP);
		peer_on_policy_change(peer, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		map = NULL;
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_ROUTE_MAP))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->map[direct].name) {
			map = route_map_lookup_by_name(filter->map[direct].name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->map[direct].name);
		}
		route_map_counter_decrement(map);
		filter->map[direct].name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
		filter->map[direct].map = route_map;
		route_map_counter_increment(route_map);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);
	}
	return 0;
}

/* Unset route-map from the peer. */
int peer_route_map_unset(struct peer *peer, afi_t afi, safi_t safi, int direct)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	if (direct != RMAP_IN && direct != RMAP_OUT)
		return BGP_ERR_INVALID_VALUE;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][direct], PEER_FT_ROUTE_MAP);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].map[direct].name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].map[direct].map);
	} else {
		struct route_map *map = NULL;

		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];

		if (filter->map[direct].name) {
			map = route_map_lookup_by_name(filter->map[direct].name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->map[direct].name);
		}
		route_map_counter_decrement(map);
		filter->map[direct].name = NULL;
		filter->map[direct].map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		struct route_map *map;

		map = NULL;

		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][direct],
			       PEER_FT_ROUTE_MAP))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->map[direct].name) {
			map = route_map_lookup_by_name(filter->map[direct].name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->map[direct].name);
		}
		route_map_counter_decrement(map);
		filter->map[direct].name = NULL;
		filter->map[direct].map = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi,
				      (direct == RMAP_OUT) ? 1 : 0);
	}

	return 0;
}

/* Set unsuppress-map to the peer. */
int peer_unsuppress_map_set(struct peer *peer, afi_t afi, safi_t safi,
			    const char *name, struct route_map *route_map)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	/* Set configuration on peer. */
	filter = &peer->filter[afi][safi];
	if (filter->usmap.name)
		XFREE(MTYPE_BGP_FILTER_NAME, filter->usmap.name);
	route_map_counter_decrement(filter->usmap.map);
	filter->usmap.name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
	filter->usmap.map = route_map;
	route_map_counter_increment(route_map);

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Set override-flag and process peer route updates. */
		SET_FLAG(peer->filter_override[afi][safi][0],
			 PEER_FT_UNSUPPRESS_MAP);
		peer_on_policy_change(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		struct route_map *map;

		map = NULL;

		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][0],
			       PEER_FT_UNSUPPRESS_MAP))
			continue;

		/* Set configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->usmap.name) {
			map = route_map_lookup_by_name(filter->usmap.name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->usmap.name);
		}
		route_map_counter_decrement(map);
		filter->usmap.name = XSTRDUP(MTYPE_BGP_FILTER_NAME, name);
		filter->usmap.map = route_map;
		route_map_counter_increment(route_map);

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi, 1);
	}

	return 0;
}

/* Unset route-map from the peer. */
int peer_unsuppress_map_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct bgp_filter *filter;
	struct listnode *node, *nnode;

	/* Unset override-flag unconditionally. */
	UNSET_FLAG(peer->filter_override[afi][safi][0], PEER_FT_UNSUPPRESS_MAP);

	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		PEER_STR_ATTR_INHERIT(peer, peer->group,
				      filter[afi][safi].usmap.name,
				      MTYPE_BGP_FILTER_NAME);
		PEER_ATTR_INHERIT(peer, peer->group,
				  filter[afi][safi].usmap.map);
	} else {
		struct route_map *map = NULL;

		/* Otherwise remove configuration from peer. */
		filter = &peer->filter[afi][safi];
		if (filter->usmap.name) {
			map = route_map_lookup_by_name(filter->usmap.name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->usmap.name);
		}
		route_map_counter_decrement(map);
		filter->usmap.name = NULL;
		filter->usmap.map = NULL;
	}

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Process peer route updates. */
		peer_on_policy_change(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Remove configuration on all peer-group members, unless they are
	 * explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		struct route_map *map;

		map = NULL;

		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->filter_override[afi][safi][0],
			       PEER_FT_UNSUPPRESS_MAP))
			continue;

		/* Remove configuration on peer-group member. */
		filter = &member->filter[afi][safi];
		if (filter->usmap.name) {
			map = route_map_lookup_by_name(filter->usmap.name);
			XFREE(MTYPE_BGP_FILTER_NAME, filter->usmap.name);
		}
		route_map_counter_decrement(map);
		filter->usmap.name = NULL;
		filter->usmap.map = NULL;

		/* Process peer route updates. */
		peer_on_policy_change(member, afi, safi, 1);
	}

	return 0;
}

static bool peer_maximum_prefix_clear_overflow(struct peer *peer)
{
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW))
		return false;

	UNSET_FLAG(peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
	if (peer->connection->t_pmax_restart) {
		EVENT_OFF(peer->connection->t_pmax_restart);
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%pBP Maximum-prefix restart timer cancelled",
				peer);
	}
	BGP_EVENT_ADD(peer->connection, BGP_Start);
	return true;
}

int peer_maximum_prefix_set(struct peer *peer, afi_t afi, safi_t safi,
			    uint32_t max, uint8_t threshold, int warning,
			    uint16_t restart, bool force)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flags and configuration on peer. */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX);

	if (force)
		peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);
	else
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);

	if (warning)
		peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
	else
		peer_af_flag_unset(peer, afi, safi,
				   PEER_FLAG_MAX_PREFIX_WARNING);

	peer->pmax[afi][safi] = max;
	peer->pmax_threshold[afi][safi] = threshold;
	peer->pmax_restart[afi][safi] = restart;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Re-check if peer violates maximum-prefix. */
		if ((peer_established(peer->connection)) &&
		    (peer->afc[afi][safi]))
			bgp_maximum_prefix_overflow(peer, afi, safi, 1);

		/* Skip peer-group mechanics for regular peers. */
		return 0;
	}

	/*
	 * Set flags and configuration on all peer-group members, unless they
	 * are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_MAX_PREFIX))
			continue;

		/* Set flag and configuration on peer-group member. */
		member->pmax[afi][safi] = max;
		member->pmax_threshold[afi][safi] = threshold;
		member->pmax_restart[afi][safi] = restart;

		if (force)
			SET_FLAG(member->af_flags[afi][safi],
				 PEER_FLAG_MAX_PREFIX_FORCE);
		else
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_FORCE);

		if (warning)
			SET_FLAG(member->af_flags[afi][safi],
				 PEER_FLAG_MAX_PREFIX_WARNING);
		else
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_WARNING);

		/* Re-check if peer violates maximum-prefix. */
		if ((peer_established(member->connection)) &&
		    (member->afc[afi][safi]))
			bgp_maximum_prefix_overflow(member, afi, safi, 1);
	}

	return 0;
}

int peer_maximum_prefix_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_MAX_PREFIX);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_MAX_PREFIX_FORCE);
		peer_af_flag_inherit(peer, afi, safi,
				     PEER_FLAG_MAX_PREFIX_WARNING);
		PEER_ATTR_INHERIT(peer, peer->group, pmax[afi][safi]);
		PEER_ATTR_INHERIT(peer, peer->group, pmax_threshold[afi][safi]);
		PEER_ATTR_INHERIT(peer, peer->group, pmax_restart[afi][safi]);

		return 0;
	}

	/* Remove flags and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_FORCE);
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_WARNING);
	peer->pmax[afi][safi] = 0;
	peer->pmax_threshold[afi][safi] = 0;
	peer->pmax_restart[afi][safi] = 0;

	/*
	 * Remove flags and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		struct peer *member;
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
			/* Skip peers with overridden configuration. */
			if (CHECK_FLAG(member->af_flags_override[afi][safi],
				       PEER_FLAG_MAX_PREFIX))
				continue;

			/* Remove flag and configuration on peer-group member.
			 */
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX);
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_FORCE);
			UNSET_FLAG(member->af_flags[afi][safi],
				   PEER_FLAG_MAX_PREFIX_WARNING);
			member->pmax[afi][safi] = 0;
			member->pmax_threshold[afi][safi] = 0;
			member->pmax_restart[afi][safi] = 0;

			peer_maximum_prefix_clear_overflow(member);
		}
	} else {
		peer_maximum_prefix_clear_overflow(peer);
	}

	return 0;
}

void peer_maximum_prefix_out_refresh_routes(struct peer *peer, afi_t afi,
					    safi_t safi)
{
	update_group_adjust_peer(peer_af_find(peer, afi, safi));

	if (peer_established(peer->connection))
		bgp_announce_route(peer, afi, safi, false);
}

int peer_maximum_prefix_out_set(struct peer *peer, afi_t afi, safi_t safi,
				uint32_t max)
{
	struct peer *member;
	struct listnode *node, *nnode;

	/* Set flag on peer and peer-group member if any */
	peer_af_flag_set(peer, afi, safi, PEER_FLAG_MAX_PREFIX_OUT);
	/* Set configuration on peer. */
	peer->pmax_out[afi][safi] = max;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Skip peer-group mechanics for regular peers. */
		peer_maximum_prefix_out_refresh_routes(peer, afi, safi);
		return 0;
	}

	/*
	 * Set flag and configuration on all peer-group members, unless they
	 * are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_MAX_PREFIX_OUT))
			continue;

		/* Set configuration on peer-group member. */
		member->pmax_out[afi][safi] = max;

		peer_maximum_prefix_out_refresh_routes(member, afi, safi);
	}
	return 0;
}

int peer_maximum_prefix_out_unset(struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *member;
	struct listnode *node;
	/* Inherit configuration from peer-group if peer is member. */
	if (peer_group_active(peer)) {
		peer_af_flag_inherit(peer, afi, safi, PEER_FLAG_MAX_PREFIX_OUT);
		PEER_ATTR_INHERIT(peer, peer->group, pmax_out[afi][safi]);

		peer_maximum_prefix_out_refresh_routes(peer, afi, safi);
		return 0;
	}

	/* Remove flag and configuration from peer. */
	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_MAX_PREFIX_OUT);
	peer->pmax_out[afi][safi] = 0;

	/* Check if handling a regular peer. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Skip peer-group mechanics for regular peers. */
		peer_maximum_prefix_out_refresh_routes(peer, afi, safi);
		return 0;
	}

	/*
	 * Remove flag and configuration from all peer-group members, unless
	 * they are explicitly overriding peer-group configuration.
	 */
	for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
		/* Skip peers with overridden configuration. */
		if (CHECK_FLAG(member->af_flags_override[afi][safi],
			       PEER_FLAG_MAX_PREFIX_OUT))
			continue;

		/* Remove flag and configuration on peer-group member.
		 */
		UNSET_FLAG(member->af_flags[afi][safi],
			   PEER_FLAG_MAX_PREFIX_OUT);
		member->pmax_out[afi][safi] = 0;

		peer_maximum_prefix_out_refresh_routes(member, afi, safi);
	}
	return 0;
}

int is_ebgp_multihop_configured(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct peer *peer1;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		if ((peer_sort(peer) != BGP_PEER_IBGP)
		    && (group->conf->ttl != BGP_DEFAULT_TTL))
			return 1;

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer1)) {
			if ((peer_sort(peer1) != BGP_PEER_IBGP)
			    && (peer1->ttl != BGP_DEFAULT_TTL))
				return 1;
		}
	} else {
		if ((peer_sort(peer) != BGP_PEER_IBGP)
		    && (peer->ttl != BGP_DEFAULT_TTL))
			return 1;
	}
	return 0;
}

/* Set # of hops between us and BGP peer. */
int peer_ttl_security_hops_set(struct peer *peer, int gtsm_hops)
{
	struct peer_group *group;
	struct peer *gpeer;
	struct listnode *node, *nnode;
	int ret;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s: set gtsm_hops to %d for %s", __func__,
			   gtsm_hops, peer->host);

	/* We cannot configure ttl-security hops when ebgp-multihop is already
	   set.  For non peer-groups, the check is simple.  For peer-groups,
	   it's
	   slightly messy, because we need to check both the peer-group
	   structure
	   and all peer-group members for any trace of ebgp-multihop
	   configuration
	   before actually applying the ttl-security rules.  Cisco really made a
	   mess of this configuration parameter, and OpenBGPD got it right.
	*/

	if ((peer->gtsm_hops == BGP_GTSM_HOPS_DISABLED)
	    && (peer->sort != BGP_PEER_IBGP)) {
		if (is_ebgp_multihop_configured(peer))
			return BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK;

		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			peer->gtsm_hops = gtsm_hops;

			/* Calling ebgp multihop also resets the session.
			 * On restart, NHT will get setup correctly as will the
			 * min & max ttls on the socket. The return value is
			 * irrelevant.
			 */
			ret = peer_ebgp_multihop_set(peer, MAXTTL);

			if (ret != 0)
				return ret;
		} else {
			group = peer->group;
			group->conf->gtsm_hops = gtsm_hops;
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       gpeer)) {
				gpeer->gtsm_hops = group->conf->gtsm_hops;

				/* Calling ebgp multihop also resets the
				 * session.
				 * On restart, NHT will get setup correctly as
				 * will the
				 * min & max ttls on the socket. The return
				 * value is
				 * irrelevant.
				 */
				peer_ebgp_multihop_set(gpeer, MAXTTL);
			}
		}
	} else {
		/* Post the first gtsm setup or if its ibgp, maxttl setting
		 * isn't
		 * necessary, just set the minttl.
		 */
		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			peer->gtsm_hops = gtsm_hops;

			if (peer->connection->fd >= 0)
				sockopt_minttl(peer->connection->su.sa.sa_family,
					       peer->connection->fd,
					       MAXTTL + 1 - gtsm_hops);
			if ((peer->connection->status < Established) &&
			    peer->doppelganger &&
			    (peer->doppelganger->connection->fd >= 0))
				sockopt_minttl(peer->connection->su.sa.sa_family,
					       peer->doppelganger->connection->fd,
					       MAXTTL + 1 - gtsm_hops);
		} else {
			group = peer->group;
			group->conf->gtsm_hops = gtsm_hops;
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       gpeer)) {
				struct peer_connection *connection =
					gpeer->connection;
				gpeer->gtsm_hops = group->conf->gtsm_hops;

				/* Change setting of existing peer
				 *   established then change value (may break
				 * connectivity)
				 *   not established yet (teardown session and
				 * restart)
				 *   no session then do nothing (will get
				 * handled by next connection)
				 */
				if (connection->fd >= 0 &&
				    gpeer->gtsm_hops != BGP_GTSM_HOPS_DISABLED)
					sockopt_minttl(connection->su.sa.sa_family,
						       connection->fd,
						       MAXTTL + 1 -
							       gpeer->gtsm_hops);
				if ((connection->status < Established) &&
				    gpeer->doppelganger &&
				    (gpeer->doppelganger->connection->fd >= 0))
					sockopt_minttl(connection->su.sa.sa_family,
						       gpeer->doppelganger
							       ->connection->fd,
						       MAXTTL + 1 - gtsm_hops);
			}
		}
	}

	return 0;
}

int peer_ttl_security_hops_unset(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int ret = 0;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s: set gtsm_hops to zero for %s", __func__,
			   peer->host);

	/* if a peer-group member, then reset to peer-group default rather than
	 * 0 */
	if (peer_group_active(peer))
		peer->gtsm_hops = peer->group->conf->gtsm_hops;
	else
		peer->gtsm_hops = BGP_GTSM_HOPS_DISABLED;

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		/* Invoking ebgp_multihop_set will set the TTL back to the
		 * original
		 * value as well as restting the NHT and such. The session is
		 * reset.
		 */
		if (peer->sort == BGP_PEER_EBGP)
			ret = peer_ebgp_multihop_unset(peer);
		else {
			if (peer->connection->fd >= 0)
				sockopt_minttl(peer->connection->su.sa.sa_family,
					       peer->connection->fd, 0);

			if ((peer->connection->status < Established) &&
			    peer->doppelganger &&
			    (peer->doppelganger->connection->fd >= 0))
				sockopt_minttl(peer->connection->su.sa.sa_family,
					       peer->doppelganger->connection->fd,
					       0);
		}
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			peer->gtsm_hops = BGP_GTSM_HOPS_DISABLED;
			if (peer->sort == BGP_PEER_EBGP)
				ret = peer_ebgp_multihop_unset(peer);
			else {
				if (peer->connection->fd >= 0)
					sockopt_minttl(peer->connection->su.sa
							       .sa_family,
						       peer->connection->fd, 0);

				if ((peer->connection->status < Established) &&
				    peer->doppelganger &&
				    (peer->doppelganger->connection->fd >= 0))
					sockopt_minttl(peer->connection->su.sa
							       .sa_family,
						       peer->doppelganger
							       ->connection->fd,
						       0);
			}
		}
	}

	return ret;
}

static void peer_reset_message_stats(struct peer *peer)
{
	if (peer) {
		atomic_store_explicit(&peer->open_in, 0, memory_order_relaxed);
		atomic_store_explicit(&peer->open_out, 0, memory_order_relaxed);
		atomic_store_explicit(&peer->update_in, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->update_out, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->keepalive_in, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->keepalive_out, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->notify_in, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->notify_out, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->refresh_in, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->refresh_out, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->dynamic_cap_in, 0,
				      memory_order_relaxed);
		atomic_store_explicit(&peer->dynamic_cap_out, 0,
				      memory_order_relaxed);
	}
}

/* Helper function to resend some BGP capabilities that are uncontrolled.
 * For instance, FQDN capability, that can't be turned off, but let's say
 * we changed the hostname, we need to resend it.
 */
static void peer_clear_capabilities(struct peer *peer, afi_t afi, safi_t safi)
{
	bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_FQDN,
			    CAPABILITY_ACTION_SET);
}

/*
 * If peer clear is invoked in a loop for all peers on the BGP instance,
 * it may end up freeing the doppelganger, and if this was the next node
 * to the current node, we would end up accessing the freed next node.
 * Pass along additional parameter which can be updated if next node
 * is freed; only required when walking the peer list on BGP instance.
 */
int peer_clear(struct peer *peer, struct listnode **nnode)
{
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
	    || !CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHUTDOWN)) {
		if (peer_maximum_prefix_clear_overflow(peer))
			return 0;

		peer->v_start = BGP_INIT_START_TIMER;
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_ADMIN_RESET);
		else
			bgp_session_reset_safe(peer, nnode);
	}
	return 0;
}

int peer_clear_soft(struct peer *peer, afi_t afi, safi_t safi,
		    enum bgp_clear_type stype)
{
	struct peer_af *paf;

	if (!peer_established(peer->connection))
		return 0;

	if (!peer->afc[afi][safi])
		return BGP_ERR_AF_UNCONFIGURED;

	peer->rtt = sockopt_tcp_rtt(peer->connection->fd);

	if (stype == BGP_CLEAR_SOFT_OUT || stype == BGP_CLEAR_SOFT_BOTH) {
		/* Clear the "neighbor x.x.x.x default-originate" flag */
		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup
		    && CHECK_FLAG(paf->subgroup->sflags,
				  SUBGRP_STATUS_DEFAULT_ORIGINATE))
			UNSET_FLAG(paf->subgroup->sflags,
				   SUBGRP_STATUS_DEFAULT_ORIGINATE);

		bgp_announce_route(peer, afi, safi, false);
	}

	if (stype == BGP_CLEAR_SOFT_IN_ORF_PREFIX) {
		if (CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV) &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_RCV)) {
			struct bgp_filter *filter = &peer->filter[afi][safi];
			uint8_t prefix_type;

			if (CHECK_FLAG(peer->af_cap[afi][safi],
				       PEER_CAP_ORF_PREFIX_RM_RCV))
				prefix_type = ORF_TYPE_PREFIX;

			if (filter->plist[FILTER_IN].plist) {
				if (CHECK_FLAG(peer->af_sflags[afi][safi],
					       PEER_STATUS_ORF_PREFIX_SEND))
					bgp_route_refresh_send(
						peer, afi, safi, prefix_type,
						REFRESH_DEFER, 1,
						BGP_ROUTE_REFRESH_NORMAL);
				bgp_route_refresh_send(
					peer, afi, safi, prefix_type,
					REFRESH_IMMEDIATE, 0,
					BGP_ROUTE_REFRESH_NORMAL);
			} else {
				if (CHECK_FLAG(peer->af_sflags[afi][safi],
					       PEER_STATUS_ORF_PREFIX_SEND))
					bgp_route_refresh_send(
						peer, afi, safi, prefix_type,
						REFRESH_IMMEDIATE, 1,
						BGP_ROUTE_REFRESH_NORMAL);
				else
					bgp_route_refresh_send(
						peer, afi, safi, 0, 0, 0,
						BGP_ROUTE_REFRESH_NORMAL);
			}
			return 0;
		}
	}

	if (stype == BGP_CLEAR_SOFT_IN || stype == BGP_CLEAR_SOFT_BOTH
	    || stype == BGP_CLEAR_SOFT_IN_ORF_PREFIX) {
		/* If neighbor has soft reconfiguration inbound flag.
		   Use Adj-RIB-In database. */
		if (!bgp_soft_reconfig_in(peer, afi, safi)) {
			/* If neighbor has route refresh capability, send route
			   refresh
			   message to the peer. */
			if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV))
				bgp_route_refresh_send(
					peer, afi, safi, 0, 0, 0,
					BGP_ROUTE_REFRESH_NORMAL);
			else
				return BGP_ERR_SOFT_RECONFIG_UNCONFIGURED;
		}
	}

	if (stype == BGP_CLEAR_MESSAGE_STATS)
		peer_reset_message_stats(peer);

	if (stype == BGP_CLEAR_CAPABILITIES)
		peer_clear_capabilities(peer, afi, safi);

	return 0;
}

/* Display peer uptime.*/
char *peer_uptime(time_t uptime2, char *buf, size_t len, bool use_json,
		  json_object *json)
{
	time_t uptime1, epoch_tbuf;
	struct tm tm;

	/* If there is no connection has been done before print `never'. */
	if (uptime2 == 0) {
		if (use_json) {
			json_object_string_add(json, "peerUptime", "never");
			json_object_int_add(json, "peerUptimeMsec", 0);
		} else
			snprintf(buf, len, "never");
		return buf;
	}

	/* Get current time. */
	uptime1 = monotime(NULL);
	uptime1 -= uptime2;
	gmtime_r(&uptime1, &tm);

	if (uptime1 < ONE_DAY_SECOND)
		snprintf(buf, len, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
			 tm.tm_sec);
	else if (uptime1 < ONE_WEEK_SECOND)
		snprintf(buf, len, "%dd%02dh%02dm", tm.tm_yday, tm.tm_hour,
			 tm.tm_min);
	else if (uptime1 < ONE_YEAR_SECOND)
		snprintf(buf, len, "%02dw%dd%02dh", tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7), tm.tm_hour);
	else
		snprintf(buf, len, "%02dy%02dw%dd", tm.tm_year - 70,
			 tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7));

	if (use_json) {
		epoch_tbuf = time(NULL) - uptime1;
		json_object_string_add(json, "peerUptime", buf);
		json_object_int_add(json, "peerUptimeMsec", uptime1 * 1000);
		json_object_int_add(json, "peerUptimeEstablishedEpoch",
				    epoch_tbuf);
	}

	return buf;
}

void bgp_master_init(struct event_loop *master, const int buffer_size,
		     struct list *addresses)
{
	qobj_init();

	memset(&bgp_master, 0, sizeof(bgp_master));

	bm = &bgp_master;

	zebra_announce_init(&bm->zebra_announce_head);
	bm->bgp = list_new();
	bm->listen_sockets = list_new();
	bm->port = BGP_PORT_DEFAULT;
	bm->addresses = addresses;
	bm->master = master;
	bm->start_time = monotime(NULL);
	bm->t_rmap_update = NULL;
	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;
	bm->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bm->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	bm->terminating = false;
	bm->socket_buffer = buffer_size;
	bm->wait_for_fib = false;
	bm->ip_tos = IPTOS_PREC_INTERNETCONTROL;
	bm->inq_limit = BM_DEFAULT_Q_LIMIT;
	bm->outq_limit = BM_DEFAULT_Q_LIMIT;
	bm->t_bgp_sync_label_manager = NULL;
	bm->t_bgp_start_label_manager = NULL;
	bm->t_bgp_zebra_route = NULL;
	bm->restart_time = BGP_DEFAULT_RESTART_TIME;
	bm->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	bm->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	bm->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;

	bgp_mac_init();
	/* init the rd id space.
	   assign 0th index in the bitfield,
	   so that we start with id 1
	 */
	bf_init(bm->rd_idspace, UINT16_MAX);
	bf_assign_zero_index(bm->rd_idspace);

	/* mpls label dynamic allocation pool */
	bgp_lp_init(bm->master, &bm->labelpool);

	bgp_nhg_init();
	bgp_evpn_mh_init();
	QOBJ_REG(bm, bgp_master);
}

/*
 * Free up connected routes and interfaces for a BGP instance. Invoked upon
 * instance delete (non-default only) or BGP exit.
 */
static void bgp_if_finish(struct bgp *bgp)
{
	struct vrf *vrf;
	struct interface *ifp;

	vrf = bgp_vrf_lookup_by_instance_type(bgp);

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW || !vrf)
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct connected *c;

		frr_each_safe (if_connected, ifp->connected, c)
			bgp_connected_delete(bgp, c);
	}
}

static void bgp_viewvrf_autocomplete(vector comps, struct cmd_token *token)
{
	struct vrf *vrf = NULL;
	struct listnode *next;
	struct bgp *bgp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, vrf->name));

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, bgp)) {
		if (bgp->inst_type != BGP_INSTANCE_TYPE_VIEW)
			continue;

		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, bgp->name));
	}
}

static void bgp_instasn_autocomplete(vector comps, struct cmd_token *token)
{
	struct listnode *next, *next2;
	struct bgp *bgp, *bgp2;
	char buf[ASN_STRING_MAX_SIZE];

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, bgp)) {
		/* deduplicate */
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, next2, bgp2)) {
			if (bgp2->as == bgp->as)
				break;
			if (bgp2 == bgp)
				break;
		}
		if (bgp2 != bgp)
			continue;

		snprintf(buf, sizeof(buf), "%s", bgp->as_pretty);
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, buf));
	}
}

static const struct cmd_variable_handler bgp_viewvrf_var_handlers[] = {
	{.tokenname = "VIEWVRFNAME", .completions = bgp_viewvrf_autocomplete},
	{.varname = "instasn", .completions = bgp_instasn_autocomplete},
	{.completions = NULL},
};

struct frr_pthread *bgp_pth_io;
struct frr_pthread *bgp_pth_ka;

static void bgp_pthreads_init(void)
{
	assert(!bgp_pth_io);
	assert(!bgp_pth_ka);

	struct frr_pthread_attr io = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};
	struct frr_pthread_attr ka = {
		.start = bgp_keepalives_start,
		.stop = bgp_keepalives_stop,
	};
	bgp_pth_io = frr_pthread_new(&io, "BGP I/O thread", "bgpd_io");
	bgp_pth_ka = frr_pthread_new(&ka, "BGP Keepalives thread", "bgpd_ka");
}

void bgp_pthreads_run(void)
{
	frr_pthread_run(bgp_pth_io, NULL);
	frr_pthread_run(bgp_pth_ka, NULL);

	/* Wait until threads are ready. */
	frr_pthread_wait_running(bgp_pth_io);
	frr_pthread_wait_running(bgp_pth_ka);
}

void bgp_pthreads_finish(void)
{
	frr_pthread_stop_all();
}

static int peer_unshut_after_cfg(struct bgp *bgp)
{
	struct listnode *node;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (!peer->shut_during_cfg)
			continue;

		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s: released from config-pending hold",
				   peer->host);

		peer->shut_during_cfg = false;
		if (peer_active(peer) &&
		    peer->connection->status != Established) {
			if (peer->connection->status != Idle)
				BGP_EVENT_ADD(peer->connection, BGP_Stop);
			BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
	}

	return 0;
}

void bgp_init(unsigned short instance)
{
	hook_register(bgp_config_end, peer_unshut_after_cfg);

	/* allocates some vital data structures used by peer commands in
	 * vty_init */

	/* pre-init pthreads */
	bgp_pthreads_init();

	/* Init zebra. */
	bgp_zebra_init(bm->master, instance);

#ifdef ENABLE_BGP_VNC
	vnc_zebra_init(bm->master);
#endif

	/* BGP VTY commands installation.  */
	bgp_vty_init();

	/* BGP inits. */
	bgp_attr_init();
	bgp_labels_init();
	bgp_debug_init();
	bgp_community_alias_init();
	bgp_dump_init();
	bgp_route_init();
	bgp_route_map_init();
	bgp_scan_vty_init();
	bgp_mplsvpn_init();
#ifdef ENABLE_BGP_VNC
	rfapi_init();
#endif
	bgp_ethernetvpn_init();
	bgp_flowspec_vty_init();

	/* Access list initialize. */
	access_list_init();
	access_list_add_hook(peer_distribute_update);
	access_list_delete_hook(peer_distribute_update);

	/* Filter list initialize. */
	bgp_filter_init();
	as_list_add_hook(peer_aslist_add);
	as_list_delete_hook(peer_aslist_del);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(peer_prefix_list_update);
	prefix_list_delete_hook(peer_prefix_list_update);

	/* Community list initialize. */
	bgp_clist = community_list_init();

	/* BFD init */
	bgp_bfd_init(bm->master);

	bgp_lp_vty_init();

	bgp_label_per_nexthop_init();
	bgp_mplsvpn_nexthop_init();

	cmd_variable_handler_register(bgp_viewvrf_var_handlers);
}

void bgp_terminate(void)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;

	QOBJ_UNREG(bm);

	/* Close the listener sockets first as this prevents peers from
	 * attempting
	 * to reconnect on receiving the peer unconfig message. In the presence
	 * of a large number of peers this will ensure that no peer is left with
	 * a dangling connection
	 */

	bgp_close();
	/* reverse bgp_master_init */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		bgp_close_vrf_socket(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (BGP_PEER_GRACEFUL_RESTART_CAPABLE(peer)) {
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%pBP configured Graceful-Restart, skipping unconfig notification",
						peer);
				continue;
			}
			if (BGP_IS_VALID_STATE_FOR_NOTIF(
				    peer->connection->status))
				bgp_notify_send(peer->connection,
						BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_PEER_UNCONFIG);
		}
	}

	if (bm->listen_sockets)
		list_delete(&bm->listen_sockets);

	EVENT_OFF(bm->t_rmap_update);
	EVENT_OFF(bm->t_bgp_sync_label_manager);
	EVENT_OFF(bm->t_bgp_start_label_manager);
	EVENT_OFF(bm->t_bgp_zebra_route);

	bgp_mac_finish();
}

struct peer *peer_lookup_in_view(struct vty *vty, struct bgp *bgp,
				 const char *ip_str, bool use_json)
{
	int ret;
	struct peer *peer;
	union sockunion su;
	struct peer_group *group;

	/* Get peer sockunion. */
	ret = str2sockunion(ip_str, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, ip_str);
		if (!peer) {
			peer = peer_lookup_by_hostname(bgp, ip_str);

			if (!peer) {
				group = peer_group_lookup(bgp, ip_str);
				if (group)
					peer = listnode_head(group->peer);
			}

			if (!peer) {
				if (use_json) {
					json_object *json_no = NULL;
					json_no = json_object_new_object();
					json_object_string_add(
						json_no,
						"malformedAddressOrName",
						ip_str);
					vty_json(vty, json_no);
				} else
					vty_out(vty,
						"%% Malformed address or name: %s\n",
						ip_str);
				return NULL;
			}
		}
		return peer;
	}

	/* Peer structure lookup. */
	peer = peer_lookup(bgp, &su);
	if (!peer) {
		if (use_json) {
			json_object *json_no = NULL;
			json_no = json_object_new_object();
			json_object_string_add(json_no, "warning",
					       "No such neighbor in this view/vrf");
			vty_json(vty, json_no);
		} else
			vty_out(vty, "No such neighbor in this view/vrf\n");
		return NULL;
	}

	return peer;
}

void bgp_gr_apply_running_config(void)
{
	struct peer *peer = NULL;
	struct bgp *bgp = NULL;
	struct listnode *node, *nnode;
	bool gr_router_detected = false;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("[BGP_GR] %s called !", __func__);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_peer_gr_flags_update(peer);
			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		}

		gr_router_detected = false;
	}
}

printfrr_ext_autoreg_p("BP", printfrr_bp);
static ssize_t printfrr_bp(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *ptr)
{
	const struct peer *peer = ptr;

	if (!peer)
		return bputs(buf, "(null)");

	if (!peer->host) {
		if (peer->conf_if)
			return bprintfrr(buf, "%s", peer->conf_if);
		return bprintfrr(buf, "%pSU", &peer->connection->su);
	}

	return bprintfrr(buf, "%s(%s)", peer->host,
			 peer->hostname ? peer->hostname : "Unknown");
}

const struct message bgp_martian_type_str[] = {
	{BGP_MARTIAN_IF_IP, "Self Interface IP"},
	{BGP_MARTIAN_TUN_IP, "Self Tunnel IP"},
	{BGP_MARTIAN_IF_MAC, "Self Interface MAC"},
	{BGP_MARTIAN_RMAC, "Self RMAC"},
	{BGP_MARTIAN_SOO, "Self Site-of-Origin"},
	{0}};

const char *bgp_martian_type2str(enum bgp_martian_type mt)
{
	return lookup_msg(bgp_martian_type_str, mt, "Unknown Martian Type");
}
