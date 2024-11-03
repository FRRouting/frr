// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra client
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 * Copyright (c) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"
#include "routemap.h"
#include "frrevent.h"
#include "queue.h"
#include "memory.h"
#include "lib/json.h"
#include "lib/bfd.h"
#include "lib/route_opaque.h"
#include "filter.h"
#include "mpls.h"
#include "vxlan.h"
#include "pbr.h"
#include "frrdistance.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_label.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#endif
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_labelpool.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_trace.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"

/* All information about zebra. */
struct zclient *zclient = NULL;
struct zclient *zclient_sync;
static bool bgp_zebra_label_manager_connect(void);

/* hook to indicate vrf status change for SNMP */
DEFINE_HOOK(bgp_vrf_status_changed, (struct bgp *bgp, struct interface *ifp),
	    (bgp, ifp));

DEFINE_MTYPE_STATIC(BGPD, BGP_IF_INFO, "BGP interface context");

/* Can we install into zebra? */
static inline bool bgp_install_info_to_zebra(struct bgp *bgp)
{
	if (zclient->sock <= 0)
		return false;

	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing information",
				__func__);
		return false;
	}

	return true;
}

int zclient_num_connects;

/* Router-id update message from zebra. */
static int bgp_router_id_update(ZAPI_CALLBACK_ARGS)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Router Id update VRF %u Id %pFX", vrf_id,
			   &router_id);

	bgp_router_id_zebra_bump(vrf_id, &router_id);
	return 0;
}

/* Set or clear interface on which unnumbered neighbor is configured. This
 * would in turn cause BGP to initiate or turn off IPv6 RAs on this
 * interface.
 */
static void bgp_update_interface_nbrs(struct bgp *bgp, struct interface *ifp,
				      struct interface *upd_ifp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->conf_if && (strcmp(peer->conf_if, ifp->name) == 0)) {
			if (upd_ifp) {
				peer->ifp = upd_ifp;
				bgp_zebra_initiate_radv(bgp, peer);
			} else {
				bgp_zebra_terminate_radv(bgp, peer);
				peer->ifp = upd_ifp;
			}
		}
	}
}

static int bgp_read_fec_update(ZAPI_CALLBACK_ARGS)
{
	bgp_parse_fec_update();
	return 0;
}

static void bgp_start_interface_nbrs(struct bgp *bgp, struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->conf_if && (strcmp(peer->conf_if, ifp->name) == 0) &&
		    !peer_established(peer->connection)) {
			if (peer_active(peer))
				BGP_EVENT_ADD(peer->connection, BGP_Stop);
			BGP_EVENT_ADD(peer->connection, BGP_Start);
		}
	}
}

static void bgp_nbr_connected_add(struct bgp *bgp, struct nbr_connected *ifc)
{
	struct connected *connected;
	struct interface *ifp;
	struct prefix *p;

	/* Kick-off the FSM for any relevant peers only if there is a
	 * valid local address on the interface.
	 */
	ifp = ifc->ifp;
	frr_each (if_connected, ifp->connected, connected) {
		p = connected->address;
		if (p->family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
			break;
	}
	if (!connected)
		return;

	bgp_start_interface_nbrs(bgp, ifp);
}

static void bgp_nbr_connected_delete(struct bgp *bgp, struct nbr_connected *ifc,
				     int del)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->conf_if
		    && (strcmp(peer->conf_if, ifc->ifp->name) == 0)) {
			peer->last_reset = PEER_DOWN_NBR_ADDR_DEL;
			BGP_EVENT_ADD(peer->connection, BGP_Stop);
		}
	}
	/* Free neighbor also, if we're asked to. */
	if (del) {
		ifp = ifc->ifp;
		listnode_delete(ifp->nbr_connected, ifc);
		nbr_connected_free(ifc);
	}
}

static int bgp_ifp_destroy(struct interface *ifp)
{
	struct bgp *bgp;

	bgp = ifp->vrf->info;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf del VRF %s IF %s", ifp->vrf->name,
			   ifp->name);

	if (bgp) {
		bgp_update_interface_nbrs(bgp, ifp, NULL);
		hook_call(bgp_vrf_status_changed, bgp, ifp);
	}

	bgp_mac_del_mac_entry(ifp);

	return 0;
}

static int bgp_ifp_up(struct interface *ifp)
{
	struct connected *c;
	struct nbr_connected *nc;
	struct listnode *node, *nnode;
	struct bgp *bgp;

	bgp = ifp->vrf->info;

	bgp_mac_add_mac_entry(ifp);

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf up VRF %s IF %s", ifp->vrf->name, ifp->name);

	if (!bgp)
		return 0;

	frr_each (if_connected, ifp->connected, c)
		bgp_connected_add(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_add(bgp, nc);

	hook_call(bgp_vrf_status_changed, bgp, ifp);
	bgp_nht_ifp_up(ifp);

	if (bgp_get_default() && if_is_vrf(ifp)) {
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP6);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP6);
		vpn_leak_postchange_all();
	}

	return 0;
}

static int bgp_ifp_down(struct interface *ifp)
{
	struct connected *c;
	struct nbr_connected *nc;
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;

	bgp = ifp->vrf->info;

	bgp_mac_del_mac_entry(ifp);

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf down VRF %s IF %s", ifp->vrf->name,
			   ifp->name);

	if (!bgp)
		return 0;

	frr_each (if_connected, ifp->connected, c)
		bgp_connected_delete(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_delete(bgp, nc, 1);

	/* Fast external-failover */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER)) {

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			/* Take down directly connected peers. */
			if ((peer->ttl != BGP_DEFAULT_TTL)
			    && (peer->gtsm_hops != BGP_GTSM_HOPS_CONNECTED))
				continue;

			if (ifp == peer->nexthop.ifp) {
				BGP_EVENT_ADD(peer->connection, BGP_Stop);
				peer->last_reset = PEER_DOWN_IF_DOWN;
			}
		}
	}

	hook_call(bgp_vrf_status_changed, bgp, ifp);
	bgp_nht_ifp_down(ifp);

	if (bgp_get_default() && if_is_vrf(ifp)) {
		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP6);
		vpn_leak_zebra_vrf_sid_withdraw(bgp, AFI_IP);
		vpn_leak_zebra_vrf_sid_withdraw(bgp, AFI_IP6);
		vpn_leak_postchange_all();
	}

	return 0;
}

static int bgp_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;
	struct bgp *bgp;
	struct peer *peer;
	struct prefix *addr;
	struct listnode *node, *nnode;
	afi_t afi;
	safi_t safi;

	bgp = bgp_lookup_by_vrf_id(vrf_id);

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address))
		zlog_debug("Rx Intf address add VRF %s IF %s addr %pFX",
			   ifc->ifp->vrf->name, ifc->ifp->name, ifc->address);

	if (!bgp)
		return 0;

	if (if_is_operative(ifc->ifp)) {
		bgp_connected_add(bgp, ifc);

		/* If we have learnt of any neighbors on this interface,
		 * check to kick off any BGP interface-based neighbors,
		 * but only if this is a link-local address.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && !list_isempty(ifc->ifp->nbr_connected))
			bgp_start_interface_nbrs(bgp, ifc->ifp);
		else {
			addr = ifc->address;

			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
				if (addr->family == AF_INET)
					continue;

				/*
				 * If the Peer's interface name matches the
				 * interface name for which BGP received the
				 * update and if the received interface address
				 * is a globalV6 and if the peer is currently
				 * using a v4-mapped-v6 addr or a link local
				 * address, then copy the Rxed global v6 addr
				 * into peer's v6_global and send updates out
				 * with new nexthop addr.
				 */
				if ((peer->conf_if &&
				     (strcmp(peer->conf_if, ifc->ifp->name) ==
				      0)) &&
				    !IN6_IS_ADDR_LINKLOCAL(&addr->u.prefix6) &&
				    ((IS_MAPPED_IPV6(
					     &peer->nexthop.v6_global)) ||
				     IN6_IS_ADDR_LINKLOCAL(
					     &peer->nexthop.v6_global))) {

					if (bgp_debug_zebra(ifc->address)) {
						zlog_debug(
							"Update peer %pBP's current intf addr %pI6 and send updates",
							peer,
							&peer->nexthop
								 .v6_global);
					}
					memcpy(&peer->nexthop.v6_global,
					       &addr->u.prefix6,
					       IPV6_MAX_BYTELEN);
					FOREACH_AFI_SAFI (afi, safi)
						bgp_announce_route(peer, afi,
								   safi, true);
				}
			}
		}
	}

	return 0;
}

static int bgp_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct listnode *node, *nnode;
	struct connected *ifc;
	struct peer *peer;
	struct bgp *bgp;
	struct prefix *addr;

	bgp = bgp_lookup_by_vrf_id(vrf_id);

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address))
		zlog_debug("Rx Intf address del VRF %s IF %s addr %pFX",
			   ifc->ifp->vrf->name, ifc->ifp->name, ifc->address);

	if (bgp && if_is_operative(ifc->ifp)) {
		bgp_connected_delete(bgp, ifc);
	}

	addr = ifc->address;

	if (bgp) {
		/*
		 * When we are using the v6 global as part of the peering
		 * nexthops and we are removing it, then we need to
		 * clear the peer data saved for that nexthop and
		 * cause a re-announcement of the route.  Since
		 * we do not want the peering to bounce.
		 */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			afi_t afi;
			safi_t safi;

			if (addr->family == AF_INET)
				continue;

			if (!IN6_IS_ADDR_LINKLOCAL(&addr->u.prefix6)
			    && memcmp(&peer->nexthop.v6_global,
				      &addr->u.prefix6, 16)
				       == 0) {
				memset(&peer->nexthop.v6_global, 0, 16);
				FOREACH_AFI_SAFI (afi, safi)
					bgp_announce_route(peer, afi, safi,
							   true);
			}
		}
	}

	connected_free(&ifc);

	return 0;
}

static int bgp_interface_nbr_address_add(ZAPI_CALLBACK_ARGS)
{
	struct nbr_connected *ifc = NULL;
	struct bgp *bgp;

	ifc = zebra_interface_nbr_address_read(cmd, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address))
		zlog_debug("Rx Intf neighbor add VRF %s IF %s addr %pFX",
			   ifc->ifp->vrf->name, ifc->ifp->name, ifc->address);

	if (if_is_operative(ifc->ifp)) {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp)
			bgp_nbr_connected_add(bgp, ifc);
	}

	return 0;
}

static int bgp_interface_nbr_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct nbr_connected *ifc = NULL;
	struct bgp *bgp;

	ifc = zebra_interface_nbr_address_read(cmd, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address))
		zlog_debug("Rx Intf neighbor del VRF %s IF %s addr %pFX",
			   ifc->ifp->vrf->name, ifc->ifp->name, ifc->address);

	if (if_is_operative(ifc->ifp)) {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp)
			bgp_nbr_connected_delete(bgp, ifc, 0);
	}

	nbr_connected_free(ifc);

	return 0;
}

/* Zebra route add and delete treatment. */
static int zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	enum nexthop_types_t nhtype;
	enum blackhole_type bhtype = BLACKHOLE_UNSPEC;
	struct zapi_route api;
	union g_addr nexthop = {};
	ifindex_t ifindex;
	int add, i;
	struct bgp *bgp;

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	/* ignore link-local address. */
	if (api.prefix.family == AF_INET6
	    && IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;

	ifindex = api.nexthops[0].ifindex;
	nhtype = api.nexthops[0].type;

	/* api_nh structure has union of gate and bh_type */
	if (nhtype == NEXTHOP_TYPE_BLACKHOLE) {
		/* bh_type is only applicable if NEXTHOP_TYPE_BLACKHOLE*/
		bhtype = api.nexthops[0].bh_type;
	} else
		nexthop = api.nexthops[0].gate;

	add = (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD);
	if (add) {
		/*
		 * The ADD message is actually an UPDATE and there is no
		 * explicit DEL
		 * for a prior redistributed route, if any. So, perform an
		 * implicit
		 * DEL processing for the same redistributed route from any
		 * other
		 * source type.
		 */
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			if (i != api.type)
				bgp_redistribute_delete(bgp, &api.prefix, i,
							api.instance);
		}

		/* Now perform the add/update. */
		bgp_redistribute_add(bgp, &api.prefix, &nexthop, ifindex,
				     nhtype, api.distance, bhtype, api.metric,
				     api.type, api.instance, api.tag);
	} else {
		bgp_redistribute_delete(bgp, &api.prefix, api.type,
					api.instance);
	}

	if (bgp_debug_zebra(&api.prefix)) {
		char buf[PREFIX_STRLEN];

		if (add) {
			inet_ntop(api.prefix.family, &nexthop, buf,
				  sizeof(buf));
			zlog_debug("Rx route ADD %s %s[%d] %pFX nexthop %s (type %d if %u) metric %u distance %u tag %" ROUTE_TAG_PRI,
				   bgp->name_pretty,
				   zebra_route_string(api.type), api.instance,
				   &api.prefix, buf, nhtype, ifindex,
				   api.metric, api.distance, api.tag);
		} else {
			zlog_debug("Rx route DEL %s %s[%d] %pFX",
				   bgp->name_pretty,
				   zebra_route_string(api.type), api.instance,
				   &api.prefix);
		}
	}

	return 0;
}

struct interface *if_lookup_by_ipv4(struct in_addr *addr, vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct connected *connected;
	struct prefix_ipv4 p;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	p.family = AF_INET;
	p.prefix = *addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			cp = connected->address;

			if (cp->family == AF_INET)
				if (prefix_match(cp, (struct prefix *)&p))
					return ifp;
		}
	}
	return NULL;
}

struct interface *if_lookup_by_ipv4_exact(struct in_addr *addr, vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct connected *connected;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			cp = connected->address;

			if (cp->family == AF_INET)
				if (IPV4_ADDR_SAME(&cp->u.prefix4, addr))
					return ifp;
		}
	}
	return NULL;
}

struct interface *if_lookup_by_ipv6(struct in6_addr *addr, ifindex_t ifindex,
				    vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct connected *connected;
	struct prefix_ipv6 p;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	p.family = AF_INET6;
	p.prefix = *addr;
	p.prefixlen = IPV6_MAX_BITLEN;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			cp = connected->address;

			if (cp->family == AF_INET6)
				if (prefix_match(cp, (struct prefix *)&p)) {
					if (IN6_IS_ADDR_LINKLOCAL(
						    &cp->u.prefix6)) {
						if (ifindex == ifp->ifindex)
							return ifp;
					} else
						return ifp;
				}
		}
	}
	return NULL;
}

struct interface *if_lookup_by_ipv6_exact(struct in6_addr *addr,
					  ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct connected *connected;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	FOR_ALL_INTERFACES (vrf, ifp) {
		frr_each (if_connected, ifp->connected, connected) {
			cp = connected->address;

			if (cp->family == AF_INET6)
				if (IPV6_ADDR_SAME(&cp->u.prefix6, addr)) {
					if (IN6_IS_ADDR_LINKLOCAL(
						    &cp->u.prefix6)) {
						if (ifindex == ifp->ifindex)
							return ifp;
					} else
						return ifp;
				}
		}
	}
	return NULL;
}

static int if_get_ipv6_global(struct interface *ifp, struct in6_addr *addr)
{
	struct connected *connected;
	struct prefix *cp;

	frr_each (if_connected, ifp->connected, connected) {
		cp = connected->address;

		if (cp->family == AF_INET6)
			if (!IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
				memcpy(addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
				return 1;
			}
	}
	return 0;
}

static bool if_get_ipv6_local(struct interface *ifp, struct in6_addr *addr)
{
	struct connected *connected;
	struct prefix *cp;

	frr_each (if_connected, ifp->connected, connected) {
		cp = connected->address;

		if (cp->family == AF_INET6)
			if (IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
				memcpy(addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
				return true;
			}
	}
	return false;
}

static int if_get_ipv4_address(struct interface *ifp, struct in_addr *addr)
{
	struct connected *connected;
	struct prefix *cp;

	frr_each (if_connected, ifp->connected, connected) {
		cp = connected->address;
		if ((cp->family == AF_INET)
		    && !ipv4_martian(&(cp->u.prefix4))) {
			*addr = cp->u.prefix4;
			return 1;
		}
	}
	return 0;
}


bool bgp_zebra_nexthop_set(union sockunion *local, union sockunion *remote,
			   struct bgp_nexthop *nexthop, struct peer *peer)
{
	int ret = 0;
	struct interface *ifp = NULL;
	bool v6_ll_avail = true;

	memset(nexthop, 0, sizeof(struct bgp_nexthop));

	if (!local)
		return false;
	if (!remote)
		return false;

	if (local->sa.sa_family == AF_INET) {
		nexthop->v4 = local->sin.sin_addr;
		if (peer->update_if)
			ifp = if_lookup_by_name(peer->update_if,
						peer->bgp->vrf_id);
		else
			ifp = if_lookup_by_ipv4_exact(&local->sin.sin_addr,
						      peer->bgp->vrf_id);
	}
	if (local->sa.sa_family == AF_INET6) {
		memcpy(&nexthop->v6_global, &local->sin6.sin6_addr, IPV6_MAX_BYTELEN);
		if (IN6_IS_ADDR_LINKLOCAL(&local->sin6.sin6_addr)) {
			if (peer->conf_if || peer->ifname)
				ifp = if_lookup_by_name(peer->conf_if
								? peer->conf_if
								: peer->ifname,
							peer->bgp->vrf_id);
			else if (peer->update_if)
				ifp = if_lookup_by_name(peer->update_if,
							peer->bgp->vrf_id);
		} else if (peer->update_if)
			ifp = if_lookup_by_name(peer->update_if,
						peer->bgp->vrf_id);
		else
			ifp = if_lookup_by_ipv6_exact(&local->sin6.sin6_addr,
						      local->sin6.sin6_scope_id,
						      peer->bgp->vrf_id);
	}

	/* Handle peerings via loopbacks. For instance, peer between
	 * 127.0.0.1 and 127.0.0.2. In short, allow peering with self
	 * via 127.0.0.0/8.
	 */
	if (!ifp && cmd_allow_reserved_ranges_get())
		ifp = if_get_vrf_loopback(peer->bgp->vrf_id);

	if (!ifp) {
		/*
		 * BGP views do not currently get proper data
		 * from zebra( when attached ) to be able to
		 * properly resolve nexthops, so give this
		 * instance type a pass.
		 */
		if (peer->bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
			return true;
		/*
		 * If we have no interface data but we have established
		 * some connection w/ zebra than something has gone
		 * terribly terribly wrong here, so say this failed
		 * If we do not any zebra connection then not
		 * having a ifp pointer is ok.
		 */
		return zclient_num_connects ? false : true;
	}

	nexthop->ifp = ifp;

	/* IPv4 connection, fetch and store IPv6 local address(es) if any. */
	if (local->sa.sa_family == AF_INET) {
		/* IPv6 nexthop*/
		ret = if_get_ipv6_global(ifp, &nexthop->v6_global);

		if (!ret) {
			/* There is no global nexthop. Use link-local address as
			 * both the
			 * global and link-local nexthop. In this scenario, the
			 * expectation
			 * for interop is that the network admin would use a
			 * route-map to
			 * specify the global IPv6 nexthop.
			 */
			v6_ll_avail =
				if_get_ipv6_local(ifp, &nexthop->v6_global);
			memcpy(&nexthop->v6_local, &nexthop->v6_global,
			       IPV6_MAX_BYTELEN);
		} else
			v6_ll_avail =
				if_get_ipv6_local(ifp, &nexthop->v6_local);

		/*
		 * If we are a v4 connection and we are not doing unnumbered
		 * not having a v6 LL address is ok
		 */
		if (!v6_ll_avail && !peer->conf_if)
			v6_ll_avail = true;
		if (if_lookup_by_ipv4(&remote->sin.sin_addr, peer->bgp->vrf_id))
			peer->shared_network = 1;
		else
			peer->shared_network = 0;
	}

	/* IPv6 connection, fetch and store IPv4 local address if any. */
	if (local->sa.sa_family == AF_INET6) {
		struct interface *direct = NULL;

		/* IPv4 nexthop. */
		ret = if_get_ipv4_address(ifp, &nexthop->v4);
		if (!ret && peer->local_id.s_addr != INADDR_ANY)
			nexthop->v4 = peer->local_id;

		/* Global address*/
		if (!IN6_IS_ADDR_LINKLOCAL(&local->sin6.sin6_addr)) {
			memcpy(&nexthop->v6_global, &local->sin6.sin6_addr,
			       IPV6_MAX_BYTELEN);

			/* If directly connected set link-local address. */
			direct = if_lookup_by_ipv6(&remote->sin6.sin6_addr,
						   remote->sin6.sin6_scope_id,
						   peer->bgp->vrf_id);
			if (direct)
				v6_ll_avail = if_get_ipv6_local(
					ifp, &nexthop->v6_local);
			/*
			 * It's fine to not have a v6 LL when using
			 * update-source loopback/vrf
			 */
			if (!v6_ll_avail && if_is_loopback(ifp))
				v6_ll_avail = true;
			else if (!v6_ll_avail) {
				flog_warn(
					EC_BGP_NO_LL_ADDRESS_AVAILABLE,
					"Interface: %s does not have a v6 LL address associated with it, waiting until one is created for it",
					ifp->name);
			}
		} else
		/* Link-local address. */
		{
			ret = if_get_ipv6_global(ifp, &nexthop->v6_global);

			/* If there is no global address.  Set link-local
			   address as
			   global.  I know this break RFC specification... */
			/* In this scenario, the expectation for interop is that
			 * the
			 * network admin would use a route-map to specify the
			 * global
			 * IPv6 nexthop.
			 */
			if (!ret)
				memcpy(&nexthop->v6_global,
				       &local->sin6.sin6_addr,
				       IPV6_MAX_BYTELEN);
			/* Always set the link-local address */
			memcpy(&nexthop->v6_local, &local->sin6.sin6_addr,
			       IPV6_MAX_BYTELEN);
		}

		if (IN6_IS_ADDR_LINKLOCAL(&local->sin6.sin6_addr)
		    || if_lookup_by_ipv6(&remote->sin6.sin6_addr,
					 remote->sin6.sin6_scope_id,
					 peer->bgp->vrf_id))
			peer->shared_network = 1;
		else
			peer->shared_network = 0;
	}

/* KAME stack specific treatment.  */
#ifdef KAME
	if (IN6_IS_ADDR_LINKLOCAL(&nexthop->v6_global)
	    && IN6_LINKLOCAL_IFINDEX(nexthop->v6_global)) {
		SET_IN6_LINKLOCAL_IFINDEX(nexthop->v6_global, 0);
	}
	if (IN6_IS_ADDR_LINKLOCAL(&nexthop->v6_local)
	    && IN6_LINKLOCAL_IFINDEX(nexthop->v6_local)) {
		SET_IN6_LINKLOCAL_IFINDEX(nexthop->v6_local, 0);
	}
#endif /* KAME */

	/* If we have identified the local interface, there is no error for now.
	 */
	return v6_ll_avail;
}

static struct in6_addr *
bgp_path_info_to_ipv6_nexthop(struct bgp_path_info *path, ifindex_t *ifindex)
{
	struct in6_addr *nexthop = NULL;

	/* Only global address nexthop exists. */
	if (path->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL
	    || path->attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL) {
		nexthop = &path->attr->mp_nexthop_global;
		if (IN6_IS_ADDR_LINKLOCAL(nexthop))
			*ifindex = path->attr->nh_ifindex;
	}

	/* If both global and link-local address present. */
	if (path->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
	    || path->attr->mp_nexthop_len
		       == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
		/* Check if route-map is set to prefer global over link-local */
		if (CHECK_FLAG(path->attr->nh_flags,
			       BGP_ATTR_NH_MP_PREFER_GLOBAL)) {
			nexthop = &path->attr->mp_nexthop_global;
			if (IN6_IS_ADDR_LINKLOCAL(nexthop))
				*ifindex = path->attr->nh_ifindex;
		} else {
			/* Workaround for Cisco's nexthop bug.  */
			if (IN6_IS_ADDR_UNSPECIFIED(
				    &path->attr->mp_nexthop_global)
			    && path->peer->su_remote
			    && path->peer->su_remote->sa.sa_family
				       == AF_INET6) {
				nexthop =
					&path->peer->su_remote->sin6.sin6_addr;
				if (IN6_IS_ADDR_LINKLOCAL(nexthop))
					*ifindex = path->peer->nexthop.ifp
							   ->ifindex;
			} else {
				nexthop = &path->attr->mp_nexthop_local;
				if (IN6_IS_ADDR_LINKLOCAL(nexthop))
					*ifindex = path->attr->nh_lla_ifindex;
			}
		}
	}

	return nexthop;
}

static bool bgp_table_map_apply(struct route_map *map, const struct prefix *p,
				struct bgp_path_info *path)
{
	route_map_result_t ret;

	ret = route_map_apply(map, p, path);
	bgp_attr_flush(path->attr);

	if (ret != RMAP_DENYMATCH)
		return true;

	if (bgp_debug_zebra(p)) {
		if (p->family == AF_INET) {
			zlog_debug(
				"Zebra rmap deny: IPv4 route %pFX nexthop %pI4",
				p, &path->attr->nexthop);
		}
		if (p->family == AF_INET6) {
			ifindex_t ifindex;
			struct in6_addr *nexthop;

			nexthop = bgp_path_info_to_ipv6_nexthop(path, &ifindex);
			zlog_debug(
				"Zebra rmap deny: IPv6 route %pFX nexthop %pI6",
				p, nexthop);
		}
	}
	return false;
}

static struct event *bgp_tm_thread_connect;
static bool bgp_tm_status_connected;
static bool bgp_tm_chunk_obtained;
#define BGP_FLOWSPEC_TABLE_CHUNK 100000
static uint32_t bgp_tm_min, bgp_tm_max, bgp_tm_chunk_size;
struct bgp *bgp_tm_bgp;

static void bgp_zebra_tm_connect(struct event *t)
{
	struct zclient *zclient;
	int delay = 10, ret = 0;

	zclient = EVENT_ARG(t);
	if (bgp_tm_status_connected && zclient->sock > 0)
		delay = 60;
	else {
		bgp_tm_status_connected = false;
		ret = tm_table_manager_connect(zclient);
	}
	if (ret < 0) {
		zlog_err("Error connecting to table manager!");
		bgp_tm_status_connected = false;
	} else {
		if (!bgp_tm_status_connected) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug(
					"Connecting to table manager. Success");
		}
		bgp_tm_status_connected = true;
		if (!bgp_tm_chunk_obtained) {
			if (bgp_zebra_get_table_range(zclient, bgp_tm_chunk_size,
						      &bgp_tm_min,
						      &bgp_tm_max) >= 0) {
				bgp_tm_chunk_obtained = true;
				/* parse non installed entries */
				bgp_zebra_announce_table(bgp_tm_bgp, AFI_IP, SAFI_FLOWSPEC);
			}
		}
	}
	event_add_timer(bm->master, bgp_zebra_tm_connect, zclient, delay,
			&bgp_tm_thread_connect);
}

bool bgp_zebra_tm_chunk_obtained(void)
{
	return bgp_tm_chunk_obtained;
}

uint32_t bgp_zebra_tm_get_id(void)
{
	static int table_id;

	if (!bgp_tm_chunk_obtained)
		return ++table_id;
	return bgp_tm_min++;
}

void bgp_zebra_init_tm_connect(struct bgp *bgp)
{
	int delay = 1;

	/* if already set, do nothing
	 */
	if (bgp_tm_thread_connect != NULL)
		return;
	bgp_tm_status_connected = false;
	bgp_tm_chunk_obtained = false;
	bgp_tm_min = bgp_tm_max = 0;
	bgp_tm_chunk_size = BGP_FLOWSPEC_TABLE_CHUNK;
	bgp_tm_bgp = bgp;
	event_add_timer(bm->master, bgp_zebra_tm_connect, zclient_sync, delay,
			&bgp_tm_thread_connect);
}

int bgp_zebra_get_table_range(struct zclient *zc, uint32_t chunk_size,
			      uint32_t *start, uint32_t *end)
{
	int ret;

	if (!bgp_tm_status_connected)
		return -1;
	ret = tm_get_table_chunk(zc, chunk_size, start, end);
	if (ret < 0) {
		flog_err(EC_BGP_TABLE_CHUNK,
			 "BGP: Error getting table chunk %u", chunk_size);
		return -1;
	}
	zlog_info("BGP: Table Manager returns range from chunk %u is [%u %u]",
		 chunk_size, *start, *end);
	return 0;
}

static bool update_ipv4nh_for_route_install(int nh_othervrf, struct bgp *nh_bgp,
					    struct in_addr *nexthop,
					    struct attr *attr, bool is_evpn,
					    struct zapi_nexthop *api_nh)
{
	struct bgp_route_evpn *bre = bgp_attr_get_evpn_overlay(attr);

	api_nh->gate.ipv4 = *nexthop;
	api_nh->vrf_id = nh_bgp->vrf_id;

	/* Need to set fields appropriately for EVPN routes imported into
	 * a VRF (which are programmed as onlink on l3-vni SVI) as well as
	 * connected routes leaked into a VRF.
	 */
	if (attr->nh_type == NEXTHOP_TYPE_BLACKHOLE) {
		api_nh->type = attr->nh_type;
		api_nh->bh_type = attr->bh_type;
	} else if (is_evpn) {
		/*
		 * If the nexthop is EVPN overlay index gateway IP,
		 * treat the nexthop as NEXTHOP_TYPE_IPV4
		 * Else, mark the nexthop as onlink.
		 */
		if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP)
			api_nh->type = NEXTHOP_TYPE_IPV4;
		else {
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN);
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
			api_nh->ifindex = nh_bgp->l3vni_svi_ifindex;
		}
	} else if (nh_othervrf && api_nh->gate.ipv4.s_addr == INADDR_ANY) {
		api_nh->type = NEXTHOP_TYPE_IFINDEX;
		api_nh->ifindex = attr->nh_ifindex;
	} else
		api_nh->type = NEXTHOP_TYPE_IPV4;

	return true;
}

static bool update_ipv6nh_for_route_install(int nh_othervrf, struct bgp *nh_bgp,
					    struct in6_addr *nexthop,
					    ifindex_t ifindex,
					    struct bgp_path_info *pi,
					    struct bgp_path_info *best_pi,
					    bool is_evpn,
					    struct zapi_nexthop *api_nh)
{
	struct attr *attr;
	struct bgp_route_evpn *bre;

	attr = pi->attr;
	api_nh->vrf_id = nh_bgp->vrf_id;
	bre = bgp_attr_get_evpn_overlay(attr);

	if (attr->nh_type == NEXTHOP_TYPE_BLACKHOLE) {
		api_nh->type = attr->nh_type;
		api_nh->bh_type = attr->bh_type;
	} else if (is_evpn) {
		/*
		 * If the nexthop is EVPN overlay index gateway IP,
		 * treat the nexthop as NEXTHOP_TYPE_IPV4
		 * Else, mark the nexthop as onlink.
		 */
		if (bre && bre->type == OVERLAY_INDEX_GATEWAY_IP)
			api_nh->type = NEXTHOP_TYPE_IPV6;
		else {
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN);
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
			api_nh->ifindex = nh_bgp->l3vni_svi_ifindex;
		}
	} else if (nh_othervrf) {
		if (IN6_IS_ADDR_UNSPECIFIED(nexthop)) {
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			api_nh->ifindex = attr->nh_ifindex;
		} else if (IN6_IS_ADDR_LINKLOCAL(nexthop)) {
			if (ifindex == 0)
				return false;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = ifindex;
		} else {
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->ifindex = 0;
		}
	} else {
		if (IN6_IS_ADDR_LINKLOCAL(nexthop)) {
			if (pi == best_pi
			    && attr->mp_nexthop_len
				       == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
				if (pi->peer->nexthop.ifp)
					ifindex =
						pi->peer->nexthop.ifp->ifindex;
			if (!ifindex) {
				if (pi->peer->conf_if)
					ifindex = pi->peer->ifp->ifindex;
				else if (pi->peer->ifname)
					ifindex = ifname2ifindex(
						pi->peer->ifname,
						pi->peer->bgp->vrf_id);
				else if (pi->peer->nexthop.ifp)
					ifindex =
						pi->peer->nexthop.ifp->ifindex;
			}

			if (ifindex == 0)
				return false;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = ifindex;
		} else {
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->ifindex = 0;
		}
	}
	/* api_nh structure has union of gate and bh_type */
	if (nexthop && api_nh->type != NEXTHOP_TYPE_BLACKHOLE)
		api_nh->gate.ipv6 = *nexthop;

	return true;
}

static bool bgp_zebra_use_nhop_weighted(struct bgp *bgp, struct attr *attr,
					uint64_t *nh_weight)
{
	/* zero link-bandwidth and link-bandwidth not present are treated
	 * as the same situation.
	 */
	if (!attr->link_bw) {
		/* the only situations should be if we're either told
		 * to skip or use default weight.
		 */
		if (bgp->lb_handling == BGP_LINK_BW_SKIP_MISSING)
			return false;
		*nh_weight = BGP_ZEBRA_DEFAULT_NHOP_WEIGHT;
	} else
		*nh_weight = attr->link_bw;

	return true;
}

static void bgp_zebra_announce_parse_nexthop(
	struct bgp_path_info *info, const struct prefix *p, struct bgp *bgp,
	struct zapi_route *api, unsigned int *valid_nh_count, afi_t afi,
	safi_t safi, uint32_t *nhg_id, uint32_t *metric, route_tag_t *tag,
	bool *allow_recursion)
{
	struct zapi_nexthop *api_nh;
	int nh_family;
	struct bgp_path_info *mpinfo;
	struct bgp *bgp_orig;
	struct attr local_attr;
	struct bgp_path_info local_info;
	struct bgp_path_info *mpinfo_cp = &local_info;
	mpls_label_t *labels;
	uint8_t num_labels = 0;
	mpls_label_t nh_label;
	int nh_othervrf = 0;
	bool nh_updated = false;
	bool do_wt_ecmp;
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;
	struct bgp_route_evpn *bre = NULL;

	/* Determine if we're doing weighted ECMP or not */
	do_wt_ecmp = bgp_path_info_mpath_chkwtd(bgp, info);

	/*
	 * vrf leaking support (will have only one nexthop)
	 */
	if (info->extra && info->extra->vrfleak &&
	    info->extra->vrfleak->bgp_orig)
		nh_othervrf = 1;

	/* EVPN MAC-IP routes are installed with a L3 NHG id */
	if (nhg_id && bgp_evpn_path_es_use_nhg(bgp, info, nhg_id)) {
		mpinfo = NULL;
		zapi_route_set_nhg_id(api, nhg_id);
	} else {
		mpinfo = info;
	}

	for (; mpinfo; mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		uint64_t nh_weight;
		bool is_evpn;
		bool is_parent_evpn;

		if (*valid_nh_count >= multipath_num)
			break;

		*mpinfo_cp = *mpinfo;
		nh_weight = 0;

		/* Get nexthop address-family */
		if (p->family == AF_INET &&
		    !BGP_ATTR_MP_NEXTHOP_LEN_IP6(mpinfo_cp->attr))
			nh_family = AF_INET;
		else if (p->family == AF_INET6 ||
			 (p->family == AF_INET &&
			  BGP_ATTR_MP_NEXTHOP_LEN_IP6(mpinfo_cp->attr)))
			nh_family = AF_INET6;
		else
			continue;

		/* If processing for weighted ECMP, determine the next hop's
		 * weight. Based on user setting, we may skip the next hop
		 * in some situations.
		 */
		if (do_wt_ecmp) {
			if (!bgp_zebra_use_nhop_weighted(bgp, mpinfo->attr,
							 &nh_weight))
				continue;
		}
		api_nh = &api->nexthops[*valid_nh_count];

		api_nh->srte_color = bgp_attr_get_color(info->attr);

		if (bgp_debug_zebra(&api->prefix)) {
			if (BGP_PATH_INFO_NUM_LABELS(mpinfo)) {
				zlog_debug("%s: p=%pFX, bgp_is_valid_label: %d",
					   __func__, p,
					   bgp_is_valid_label(
						   &mpinfo->extra->labels
							    ->label[0]));
			} else {
				zlog_debug("%s: p=%pFX, no label", __func__, p);
			}
		}

		if (bgp->table_map[afi][safi].name) {
			/* Copy info and attributes, so the route-map
			   apply doesn't modify the BGP route info. */
			local_attr = *mpinfo->attr;
			mpinfo_cp->attr = &local_attr;
			if (!bgp_table_map_apply(bgp->table_map[afi][safi].map,
						 p, mpinfo_cp))
				continue;

			/* metric/tag is only allowed to be
			 * overridden on 1st nexthop */
			if (mpinfo == info) {
				if (metric)
					*metric = mpinfo_cp->attr->med;
				if (tag)
					*tag = mpinfo_cp->attr->tag;
			}
		}

		BGP_ORIGINAL_UPDATE(bgp_orig, mpinfo, bgp);

		is_parent_evpn = is_route_parent_evpn(mpinfo);

		if (nh_family == AF_INET) {
			nh_updated = update_ipv4nh_for_route_install(
				nh_othervrf, bgp_orig,
				&mpinfo_cp->attr->nexthop, mpinfo_cp->attr,
				is_parent_evpn, api_nh);
		} else {
			ifindex_t ifindex = IFINDEX_INTERNAL;
			struct in6_addr *nexthop;

			nexthop = bgp_path_info_to_ipv6_nexthop(mpinfo_cp,
								&ifindex);

			if (!nexthop)
				nh_updated = update_ipv4nh_for_route_install(
					nh_othervrf, bgp_orig,
					&mpinfo_cp->attr->nexthop,
					mpinfo_cp->attr, is_parent_evpn,
					api_nh);
			else
				nh_updated = update_ipv6nh_for_route_install(
					nh_othervrf, bgp_orig, nexthop, ifindex,
					mpinfo, info, is_parent_evpn, api_nh);
		}

		is_evpn = !!CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN);
		bre = bgp_attr_get_evpn_overlay(mpinfo->attr);

		/* Did we get proper nexthop info to update zebra? */
		if (!nh_updated)
			continue;

		/* Allow recursion if it is a multipath group with both
		 * eBGP and iBGP paths.
		 */
		if (allow_recursion && !*allow_recursion &&
		    CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX) &&
		    (mpinfo->peer->sort == BGP_PEER_IBGP ||
		     mpinfo->peer->sort == BGP_PEER_CONFED))
			*allow_recursion = true;

		num_labels = BGP_PATH_INFO_NUM_LABELS(mpinfo);
		labels = num_labels ? mpinfo->extra->labels->label : NULL;

		if (num_labels && (is_evpn || bgp_is_valid_label(&labels[0]))) {
			enum lsp_types_t nh_label_type = ZEBRA_LSP_NONE;

			if (is_evpn) {
				nh_label = *bgp_evpn_path_info_labels_get_l3vni(
					labels, num_labels);
				nh_label_type = ZEBRA_LSP_EVPN;
			} else {
				mpls_lse_decode(labels[0], &nh_label, &ttl,
						&exp, &bos);
			}

			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
			api_nh->label_num = 1;
			api_nh->label_type = nh_label_type;
			api_nh->labels[0] = nh_label;
		}

		if (is_evpn && !(bre && bre->type == OVERLAY_INDEX_GATEWAY_IP))
			memcpy(&api_nh->rmac, &(mpinfo->attr->rmac),
			       sizeof(struct ethaddr));

		api_nh->weight = nh_weight;

		if (((mpinfo->attr->srv6_l3vpn &&
		      !sid_zero_ipv6(&mpinfo->attr->srv6_l3vpn->sid)) ||
		     (mpinfo->attr->srv6_vpn &&
		      !sid_zero_ipv6(&mpinfo->attr->srv6_vpn->sid))) &&
		    !is_evpn && bgp_is_valid_label(&labels[0])) {
			struct in6_addr *sid_tmp =
				mpinfo->attr->srv6_l3vpn
					? (&mpinfo->attr->srv6_l3vpn->sid)
					: (&mpinfo->attr->srv6_vpn->sid);

			memcpy(&api_nh->seg6_segs[0], sid_tmp,
			       sizeof(api_nh->seg6_segs[0]));

			if (mpinfo->attr->srv6_l3vpn &&
			    mpinfo->attr->srv6_l3vpn->transposition_len != 0) {
				mpls_lse_decode(labels[0], &nh_label, &ttl,
						&exp, &bos);

				if (nh_label < MPLS_LABEL_UNRESERVED_MIN) {
					if (bgp_debug_zebra(&api->prefix))
						zlog_debug(
							"skip invalid SRv6 routes: transposition scheme is used, but label is too small");
					continue;
				}

				transpose_sid(&api_nh->seg6_segs[0], nh_label,
					      mpinfo->attr->srv6_l3vpn
						      ->transposition_offset,
					      mpinfo->attr->srv6_l3vpn
						      ->transposition_len);
			}

			api_nh->seg_num = 1;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
		}

		(*valid_nh_count)++;
	}
}

static void bgp_debug_zebra_nh(struct zapi_route *api)
{
	int i;
	int nh_family;
	char nh_buf[INET6_ADDRSTRLEN];
	char eth_buf[ETHER_ADDR_STRLEN + 7] = { '\0' };
	char buf1[ETHER_ADDR_STRLEN];
	char label_buf[20];
	char sid_buf[20];
	char segs_buf[256];
	struct zapi_nexthop *api_nh;
	int count;

	count = api->nexthop_num;
	for (i = 0; i < count; i++) {
		api_nh = &api->nexthops[i];
		switch (api_nh->type) {
		case NEXTHOP_TYPE_IFINDEX:
			nh_buf[0] = '\0';
			break;
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			nh_family = AF_INET;
			inet_ntop(nh_family, &api_nh->gate, nh_buf,
				  sizeof(nh_buf));
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			nh_family = AF_INET6;
			inet_ntop(nh_family, &api_nh->gate, nh_buf,
				  sizeof(nh_buf));
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			strlcpy(nh_buf, "blackhole", sizeof(nh_buf));
			break;
		default:
			/* Note: add new nexthop case */
			assert(0);
			break;
		}

		label_buf[0] = '\0';
		eth_buf[0] = '\0';
		segs_buf[0] = '\0';
		if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL) &&
		    !CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN))
			snprintf(label_buf, sizeof(label_buf), "label %u",
				 api_nh->labels[0]);
		if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6) &&
		    !CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN)) {
			inet_ntop(AF_INET6, &api_nh->seg6_segs[0], sid_buf,
				  sizeof(sid_buf));
			snprintf(segs_buf, sizeof(segs_buf), "segs %s", sid_buf);
		}
		if (CHECK_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_EVPN) &&
		    !is_zero_mac(&api_nh->rmac))
			snprintf(eth_buf, sizeof(eth_buf), " RMAC %s",
				 prefix_mac2str(&api_nh->rmac, buf1,
						sizeof(buf1)));
		zlog_debug("  nhop [%d]: %s if %u VRF %u wt %" PRIu64
			   " %s %s %s",
			   i + 1, nh_buf, api_nh->ifindex, api_nh->vrf_id,
			   api_nh->weight, label_buf, segs_buf, eth_buf);
	}
}

static enum zclient_send_status
bgp_zebra_announce_actual(struct bgp_dest *dest, struct bgp_path_info *info,
			  struct bgp *bgp)
{
	struct bgp_path_info *bpi_ultimate;
	struct zapi_route api = { 0 };
	unsigned int valid_nh_count = 0;
	bool allow_recursion = false;
	uint8_t distance;
	struct peer *peer;
	uint32_t metric;
	route_tag_t tag;
	uint32_t nhg_id = 0;
	struct bgp_table *table = bgp_dest_table(dest);
	const struct prefix *p = bgp_dest_get_prefix(dest);

	if (table->safi == SAFI_FLOWSPEC) {
		bgp_pbr_update_entry(bgp, p, info, table->afi, table->safi,
				     true);
		return ZCLIENT_SEND_SUCCESS;
	}

	/* Make Zebra API structure. */
	api.vrf_id = bgp->vrf_id;
	api.type = ZEBRA_ROUTE_BGP;
	api.safi = table->safi;
	api.prefix = *p;
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	peer = info->peer;

	if (info->type == ZEBRA_ROUTE_BGP) {
		bpi_ultimate = bgp_get_imported_bpi_ultimate(info);
		peer = bpi_ultimate->peer;
	}

	tag = info->attr->tag;

	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED
	    || info->sub_type == BGP_ROUTE_AGGREGATE) {
		SET_FLAG(api.flags, ZEBRA_FLAG_IBGP);
		SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	}

	if ((peer->sort == BGP_PEER_EBGP && peer->ttl != BGP_DEFAULT_TTL)
	    || CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	    || CHECK_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))

		allow_recursion = true;

	if (info->attr->rmap_table_id) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = info->attr->rmap_table_id;
	}

	if (info->attr->srte_color)
		SET_FLAG(api.message, ZAPI_MESSAGE_SRTE);

	/* Metric is currently based on the best-path only */
	metric = info->attr->med;

	bgp_zebra_announce_parse_nexthop(info, p, bgp, &api, &valid_nh_count,
					 table->afi, table->safi, &nhg_id,
					 &metric, &tag, &allow_recursion);

	if (CHECK_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA)) {
		struct bgp_zebra_opaque bzo = {};
		const char *reason =
			bgp_path_selection_reason2str(dest->reason);

		strlcpy(bzo.aspath, info->attr->aspath->str,
			sizeof(bzo.aspath));

		if (info->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))
			strlcpy(bzo.community,
				bgp_attr_get_community(info->attr)->str,
				sizeof(bzo.community));

		if (info->attr->flag
		    & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))
			strlcpy(bzo.lcommunity,
				bgp_attr_get_lcommunity(info->attr)->str,
				sizeof(bzo.lcommunity));

		strlcpy(bzo.selection_reason, reason,
			sizeof(bzo.selection_reason));

		SET_FLAG(api.message, ZAPI_MESSAGE_OPAQUE);
		api.opaque.length = MIN(sizeof(struct bgp_zebra_opaque),
					ZAPI_MESSAGE_OPAQUE_LENGTH);
		memcpy(api.opaque.data, &bzo, api.opaque.length);
	}

	if (allow_recursion)
		SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);

	/*
	 * When we create an aggregate route we must also
	 * install a Null0 route in the RIB, so overwrite
	 * what was written into api with a blackhole route
	 */
	if (info->sub_type == BGP_ROUTE_AGGREGATE)
		zapi_route_set_blackhole(&api, BLACKHOLE_NULL);
	else
		api.nexthop_num = valid_nh_count;

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = metric;

	if (tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = tag;
	}

	distance = bgp_distance_apply(p, info, table->afi, table->safi, bgp);
	if (distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = distance;
	}

	if (bgp_debug_zebra(p)) {
		zlog_debug("Tx route add %s (table id %u) %pFX metric %u tag %" ROUTE_TAG_PRI
			   " count %d nhg %d",
			   bgp->name_pretty, api.tableid, &api.prefix,
			   api.metric, api.tag, api.nexthop_num, nhg_id);
		bgp_debug_zebra_nh(&api);

		zlog_debug("%s: %pFX: announcing to zebra (recursion %sset)",
			   __func__, p, (allow_recursion ? "" : "NOT "));
	}

	return zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}


/* Announce all routes of a table to zebra */
void bgp_zebra_announce_table(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	/* Don't try to install if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return;

	table = bgp->rib[afi][safi];
	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
			    (pi->type == ZEBRA_ROUTE_BGP
			     && (pi->sub_type == BGP_ROUTE_NORMAL
				 || pi->sub_type == BGP_ROUTE_IMPORTED)))
				bgp_zebra_route_install(dest, pi, bgp, true,
							NULL, false);
}

/* Announce routes of any bgp subtype of a table to zebra */
void bgp_zebra_announce_table_all_subtypes(struct bgp *bgp, afi_t afi,
					   safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	if (!bgp_install_info_to_zebra(bgp))
		return;

	table = bgp->rib[afi][safi];
	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
			    pi->type == ZEBRA_ROUTE_BGP)
				bgp_zebra_route_install(dest, pi, bgp, true,
							NULL, false);
}

enum zclient_send_status bgp_zebra_withdraw_actual(struct bgp_dest *dest,
						   struct bgp_path_info *info,
						   struct bgp *bgp)
{
	struct zapi_route api;
	struct peer *peer;
	struct bgp_table *table = bgp_dest_table(dest);
	const struct prefix *p = bgp_dest_get_prefix(dest);

	if (table->safi == SAFI_FLOWSPEC) {
		peer = info->peer;
		bgp_pbr_update_entry(peer->bgp, p, info, table->afi,
				     table->safi, false);
		return ZCLIENT_SEND_SUCCESS;
	}

	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.type = ZEBRA_ROUTE_BGP;
	api.safi = table->safi;
	api.prefix = *p;

	if (info->attr->rmap_table_id) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = info->attr->rmap_table_id;
	}

	if (bgp_debug_zebra(p))
		zlog_debug("Tx route delete %s (table id %u) %pFX",
			   bgp->name_pretty, api.tableid, &api.prefix);

	return zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

/*
 * Walk the new Fifo list one by one and invoke bgp_zebra_announce/withdraw
 * to install/withdraw the routes to zebra.
 *
 * If status = ZCLIENT_SEND_SUCCESS (Buffer empt)y i.e. Zebra is free to
 * receive more incoming data, then pick the next item on the list and
 * continue processing.
 *
 * If status = ZCLIENT_SEND_BUFFERED (Buffer pending) i.e. Zebra is busy,
 * break and bail out of the function because once at some point when zebra
 * is free, a callback is triggered which inturn call this same function and
 * continue processing items on list.
 */
#define ZEBRA_ANNOUNCEMENTS_LIMIT 1000
static void bgp_handle_route_announcements_to_zebra(struct event *e)
{
	bool is_evpn = false;
	uint32_t count = 0;
	struct bgp_dest *dest = NULL;
	struct bgp_table *table = NULL;
	enum zclient_send_status status = ZCLIENT_SEND_SUCCESS;
	bool install;
	const struct prefix_evpn *evp = NULL;

	while (count < ZEBRA_ANNOUNCEMENTS_LIMIT) {
		is_evpn = false;

		dest = zebra_announce_pop(&bm->zebra_announce_head);

		if (!dest)
			break;

		table = bgp_dest_table(dest);
		install = CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL);
		if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN) {
			is_evpn = true;
			evp = (const struct prefix_evpn *)bgp_dest_get_prefix(
				dest);
		}

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("BGP %s%s route %pBD(%s) with dest %p and flags 0x%x to zebra",
				   install ? "announcing" : "withdrawing",
				   is_evpn ? " evpn" : " ", dest,
				   table->bgp->name_pretty, dest, dest->flags);

		if (install) {
			if (is_evpn)
				status =
					evpn_zebra_install(table->bgp,
							   dest->za_vpn,
							   (const struct prefix_evpn
								    *)
								   bgp_dest_get_prefix(
									   dest),
							   dest->za_bgp_pi);
			else
				status = bgp_zebra_announce_actual(dest,
								   dest->za_bgp_pi,
								   table->bgp);
			UNSET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL);
		} else {
			if (is_evpn)
				status = evpn_zebra_uninstall(
					table->bgp, dest->za_vpn,
					(const struct prefix_evpn *)
						bgp_dest_get_prefix(dest),
					dest->za_bgp_pi, false);
			else
				status = bgp_zebra_withdraw_actual(dest,
								   dest->za_bgp_pi,
								   table->bgp);

			UNSET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE);
		}

		if (is_evpn && status == ZCLIENT_SEND_FAILURE)
			flog_err(EC_BGP_EVPN_FAIL,
				 "%s (%u): Failed to %s EVPN %pFX %s route in VNI %u",
				 vrf_id_to_name(table->bgp->vrf_id),
				 table->bgp->vrf_id,
				 install ? "install" : "uninstall", evp,
				 evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
					 ? "MACIP"
					 : "IMET",
				 dest->za_vpn->vni);

		bgp_path_info_unlock(dest->za_bgp_pi);
		dest->za_bgp_pi = NULL;
		dest->za_vpn = NULL;
		bgp_dest_unlock_node(dest);

		if (status == ZCLIENT_SEND_BUFFERED)
			break;

		count++;
	}

	if (status != ZCLIENT_SEND_BUFFERED &&
	    zebra_announce_count(&bm->zebra_announce_head))
		event_add_event(bm->master,
				bgp_handle_route_announcements_to_zebra, NULL,
				0, &bm->t_bgp_zebra_route);
}

/*
 * Callback function invoked when zclient_flush_data() receives a BUFFER_EMPTY
 * i.e. zebra is free to receive more incoming data.
 */
static void bgp_zebra_buffer_write_ready(void)
{
	bgp_handle_route_announcements_to_zebra(NULL);
}

/*
 * BGP is now keeping a list of dests with the dest having a pointer
 * to the bgp_path_info that it will be working on.
 * Here is the sequence of events that should happen:
 *
 *  Current State      New State       Action
 *  -------------      ---------       ------
 *      ----           Install         Place dest on list, save pi, mark
 *                                     as going to be installed
 *      ----           Withdrawal      Place dest on list, save pi, mark
 *                                     as going to be deleted
 *
 *    Install          Install         Leave dest on list, release old pi,
 *                                     save new pi, mark as going to be
 *                                     Installed
 *    Install          Withdrawal      Leave dest on list, release old pi,
 *                                     save new pi, mark as going to be
 *                                     withdrawan, remove install flag
 *
 *    Withdrawal       Install         Leave dest on list, release old pi,
 *                                     save new pi, mark as going to be
 *                                     installed.
 *    Withdrawal       Withdrawal      Leave dest on list, release old pi,
 *                                     save new pi, mark as going to be
 *                                     withdrawn.
 */
void bgp_zebra_route_install(struct bgp_dest *dest, struct bgp_path_info *info,
			     struct bgp *bgp, bool install, struct bgpevpn *vpn,
			     bool is_sync)
{
	bool is_evpn = false;
	struct bgp_table *table = NULL;

	table = bgp_dest_table(dest);
	if (table && table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;

	/*
	 * BGP is installing this route and bgp has been configured
	 * to suppress announcements until the route has been installed
	 * let's set the fact that we expect this route to be installed
	 */
	if (install) {
		if (BGP_SUPPRESS_FIB_ENABLED(bgp))
			SET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);

		if (bgp->main_zebra_update_hold && !is_evpn)
			return;
	} else {
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);
	}

	/*
	 * Don't try to install if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp) && !is_evpn)
		return;

	if (!CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL) &&
	    !CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE)) {
		zebra_announce_add_tail(&bm->zebra_announce_head, dest);
		/*
		 * If neither flag is set and za_bgp_pi is not set then it is a bug
		 */
		assert(!dest->za_bgp_pi);
		bgp_path_info_lock(info);
		bgp_dest_lock_node(dest);
		dest->za_bgp_pi = info;
	} else if (CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL)) {
		assert(dest->za_bgp_pi);
		bgp_path_info_unlock(dest->za_bgp_pi);
		bgp_path_info_lock(info);
		dest->za_bgp_pi = info;
	} else if (CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE)) {
		assert(dest->za_bgp_pi);
		bgp_path_info_unlock(dest->za_bgp_pi);
		bgp_path_info_lock(info);
		dest->za_bgp_pi = info;
	}

	if (is_evpn) {
		dest->za_vpn = vpn;
		dest->za_is_sync = is_sync;
	}

	if (install) {
		UNSET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE);
		SET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL);
	} else {
		UNSET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_INSTALL);
		SET_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE);
	}

	event_add_event(bm->master, bgp_handle_route_announcements_to_zebra,
			NULL, 0, &bm->t_bgp_zebra_route);
}

/* Withdraw all entries in a BGP instances RIB table from Zebra */
void bgp_zebra_withdraw_table_all_subtypes(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	if (!bgp_install_info_to_zebra(bgp))
		return;

	table = bgp->rib[afi][safi];
	if (!table)
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    && (pi->type == ZEBRA_ROUTE_BGP))
				bgp_zebra_route_install(dest, pi, bgp, false,
							NULL, false);
		}
	}
}

struct bgp_redist *bgp_redist_lookup(struct bgp *bgp, afi_t afi, uint8_t type,
				     unsigned short instance)
{
	struct list *red_list;
	struct listnode *node;
	struct bgp_redist *red;

	red_list = bgp->redist[afi][type];
	if (!red_list)
		return (NULL);

	for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
		if (red->instance == instance)
			return red;

	return NULL;
}

struct bgp_redist *bgp_redist_add(struct bgp *bgp, afi_t afi, uint8_t type,
				  unsigned short instance)
{
	struct list *red_list;
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (red)
		return red;

	if (!bgp->redist[afi][type])
		bgp->redist[afi][type] = list_new();

	red_list = bgp->redist[afi][type];
	red = XCALLOC(MTYPE_BGP_REDIST, sizeof(struct bgp_redist));
	red->instance = instance;

	listnode_add(red_list, red);

	return red;
}

static void bgp_redist_del(struct bgp *bgp, afi_t afi, uint8_t type,
			   unsigned short instance)
{
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);

	if (red) {
		listnode_delete(bgp->redist[afi][type], red);
		XFREE(MTYPE_BGP_REDIST, red);
		if (!bgp->redist[afi][type]->count)
			list_delete(&bgp->redist[afi][type]);
	}
}

/* Other routes redistribution into BGP. */
int bgp_redistribute_set(struct bgp *bgp, afi_t afi, int type,
			 unsigned short instance, bool changed)
{
	/* If redistribute options are changed call
	 * bgp_redistribute_unreg() to reset the option and withdraw
	 * the routes
	 */
	if (changed)
		bgp_redistribute_unreg(bgp, afi, type, instance);

	/* Return if already redistribute flag is set. */
	if (instance) {
		if (redist_check_instance(&zclient->mi_redist[afi][type],
					  instance))
			return CMD_WARNING;

		redist_add_instance(&zclient->mi_redist[afi][type], instance);
	} else {
		if (vrf_bitmap_check(&zclient->redist[afi][type], bgp->vrf_id))
			return CMD_WARNING;

#ifdef ENABLE_BGP_VNC
		if (EVPN_ENABLED(bgp) && type == ZEBRA_ROUTE_VNC_DIRECT) {
			vnc_export_bgp_enable(
				bgp, afi); /* only enables if mode bits cfg'd */
		}
#endif

		vrf_bitmap_set(&zclient->redist[afi][type], bgp->vrf_id);
	}

	/*
	 * Don't try to register if we're not connected to Zebra or Zebra
	 * doesn't know of this instance.
	 *
	 * When we come up later well resend if needed.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return CMD_SUCCESS;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Tx redistribute add %s afi %d %s %d",
			   bgp->name_pretty, afi, zebra_route_string(type),
			   instance);

	/* Send distribute add message to zebra. */
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				instance, bgp->vrf_id);

	return CMD_SUCCESS;
}

int bgp_redistribute_resend(struct bgp *bgp, afi_t afi, int type,
			    unsigned short instance)
{
	/* Don't try to send if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return -1;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Tx redistribute del/add %s afi %d %s %d",
			   bgp->name_pretty, afi, zebra_route_string(type),
			   instance);

	/* Send distribute add message to zebra. */
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi, type,
				instance, bgp->vrf_id);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				instance, bgp->vrf_id);

	return 0;
}

/* Redistribute with route-map specification.  */
bool bgp_redistribute_rmap_set(struct bgp_redist *red, const char *name,
			       struct route_map *route_map)
{
	if (red->rmap.name && (strcmp(red->rmap.name, name) == 0))
		return false;

	XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
	/* Decrement the count for existing routemap and
	 * increment the count for new route map.
	 */
	route_map_counter_decrement(red->rmap.map);
	red->rmap.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
	red->rmap.map = route_map;
	route_map_counter_increment(red->rmap.map);

	return true;
}

/* Redistribute with metric specification.  */
bool bgp_redistribute_metric_set(struct bgp *bgp, struct bgp_redist *red,
				 afi_t afi, int type, uint32_t metric)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (red->redist_metric_flag && red->redist_metric == metric)
		return false;

	red->redist_metric_flag = 1;
	red->redist_metric = metric;

	for (dest = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (pi->sub_type == BGP_ROUTE_REDISTRIBUTE
			    && pi->type == type
			    && pi->instance == red->instance) {
				struct attr *old_attr;
				struct attr new_attr;

				new_attr = *pi->attr;
				new_attr.med = red->redist_metric;
				old_attr = pi->attr;
				pi->attr = bgp_attr_intern(&new_attr);
				bgp_attr_unintern(&old_attr);

				bgp_path_info_set_flag(dest, pi,
						       BGP_PATH_ATTR_CHANGED);
				bgp_process(bgp, dest, pi, afi, SAFI_UNICAST);
			}
		}
	}

	return true;
}

/* Unset redistribution.  */
int bgp_redistribute_unreg(struct bgp *bgp, afi_t afi, int type,
			   unsigned short instance)
{
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return CMD_SUCCESS;

	/* Return if zebra connection is disabled. */
	if (instance) {
		if (!redist_check_instance(&zclient->mi_redist[afi][type],
					   instance))
			return CMD_WARNING;
		redist_del_instance(&zclient->mi_redist[afi][type], instance);
	} else {
		if (!vrf_bitmap_check(&zclient->redist[afi][type], bgp->vrf_id))
			return CMD_WARNING;
		vrf_bitmap_unset(&zclient->redist[afi][type], bgp->vrf_id);
	}

	if (bgp_install_info_to_zebra(bgp)) {
		/* Send distribute delete message to zebra. */
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Tx redistribute del %s afi %d %s %d",
				   bgp->name_pretty, afi,
				   zebra_route_string(type), instance);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
					type, instance, bgp->vrf_id);
	}

	/* Withdraw redistributed routes from current BGP's routing table. */
	bgp_redistribute_withdraw(bgp, afi, type, instance);

	return CMD_SUCCESS;
}

/* Unset redistribution.  */
static void _bgp_redistribute_unset(struct bgp *bgp, afi_t afi, int type,
				    unsigned short instance)
{
	struct bgp_redist *red;

/*
 * vnc and vpn->vrf checks must be before red check because
 * they operate within bgpd irrespective of zebra connection
 * status. red lookup fails if there is no zebra connection.
 */
#ifdef ENABLE_BGP_VNC
	if (EVPN_ENABLED(bgp) && type == ZEBRA_ROUTE_VNC_DIRECT) {
		vnc_export_bgp_disable(bgp, afi);
	}
#endif

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return;

	bgp_redistribute_unreg(bgp, afi, type, instance);

	/* Unset route-map. */
	XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
	route_map_counter_decrement(red->rmap.map);
	red->rmap.map = NULL;

	/* Unset metric. */
	red->redist_metric_flag = 0;
	red->redist_metric = 0;

	bgp_redist_del(bgp, afi, type, instance);
}

void bgp_redistribute_unset(struct bgp *bgp, afi_t afi, int type,
			    unsigned short instance)
{
	struct listnode *node, *nnode;
	struct bgp_redist *red;

	if ((type != ZEBRA_ROUTE_TABLE && type != ZEBRA_ROUTE_TABLE_DIRECT) ||
	    instance != 0)
		return _bgp_redistribute_unset(bgp, afi, type, instance);

	/* walk over instance */
	if (!bgp->redist[afi][type])
		return;

	for (ALL_LIST_ELEMENTS(bgp->redist[afi][type], node, nnode, red))
		_bgp_redistribute_unset(bgp, afi, type, red->instance);
}

void bgp_redistribute_redo(struct bgp *bgp)
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

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				bgp_redistribute_resend(bgp, afi, i,
							red->instance);
			}
		}
	}
}

void bgp_zclient_reset(void)
{
	zclient_reset(zclient);
}

/* Register this instance with Zebra. Invoked upon connect (for
 * default instance) and when other VRFs are learnt (or created and
 * already learnt).
 */
void bgp_zebra_instance_register(struct bgp *bgp)
{
	/* Don't try to register if we're not connected to Zebra */
	if (!zclient || zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Registering %s", bgp->name_pretty);

	/* Register for router-id, interfaces, redistributed routes. */
	zclient_send_reg_requests(zclient, bgp->vrf_id);

	/* For EVPN instance, register to learn about VNIs, if appropriate. */
	if (bgp->advertise_all_vni)
		bgp_zebra_advertise_all_vni(bgp, 1);

	bgp_nht_register_nexthops(bgp);
}

/* Deregister this instance with Zebra. Invoked upon the instance
 * being deleted (default or VRF) and it is already registered.
 */
void bgp_zebra_instance_deregister(struct bgp *bgp)
{
	/* Don't try to deregister if we're not connected to Zebra */
	if (zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Deregistering %s", bgp->name_pretty);

	/* For EVPN instance, unregister learning about VNIs, if appropriate. */
	if (bgp->advertise_all_vni)
		bgp_zebra_advertise_all_vni(bgp, 0);

	/* Deregister for router-id, interfaces, redistributed routes. */
	zclient_send_dereg_requests(zclient, bgp->vrf_id);
}

void bgp_zebra_initiate_radv(struct bgp *bgp, struct peer *peer)
{
	uint32_t ra_interval = BGP_UNNUM_DEFAULT_RA_INTERVAL;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA))
		return;

	/* Don't try to initiate if we're not connected to Zebra */
	if (zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%u: Initiating RA for peer %s", bgp->vrf_id,
			   peer->host);

	/*
	 * If unnumbered peer (peer->ifp) call thru zapi to start RAs.
	 * If we don't have an ifp pointer, call function to find the
	 * ifps for a numbered enhe peer to turn RAs on.
	 */
	peer->ifp ? zclient_send_interface_radv_req(zclient, bgp->vrf_id,
						    peer->ifp, 1, ra_interval)
		  : bgp_nht_reg_enhe_cap_intfs(peer);
}

void bgp_zebra_terminate_radv(struct bgp *bgp, struct peer *peer)
{
	/* Don't try to terminate if we're not connected to Zebra */
	if (zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%u: Terminating RA for peer %s", bgp->vrf_id,
			   peer->host);

	/*
	 * If unnumbered peer (peer->ifp) call thru zapi to stop RAs.
	 * If we don't have an ifp pointer, call function to find the
	 * ifps for a numbered enhe peer to turn RAs off.
	 */
	peer->ifp ? zclient_send_interface_radv_req(zclient, bgp->vrf_id,
						    peer->ifp, 0, 0)
		  : bgp_nht_dereg_enhe_cap_intfs(peer);
}

int bgp_zebra_advertise_subnet(struct bgp *bgp, int advertise, vni_t vni)
{
	struct stream *s = NULL;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, cannot advertise subnet",
				__func__);
		return 0;
	}

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ADVERTISE_SUBNET, bgp->vrf_id);
	stream_putc(s, advertise);
	stream_put3(s, vni);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int bgp_zebra_advertise_svi_macip(struct bgp *bgp, int advertise, vni_t vni)
{
	struct stream *s = NULL;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ADVERTISE_SVI_MACIP, bgp->vrf_id);
	stream_putc(s, advertise);
	stream_putl(s, vni);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int bgp_zebra_advertise_gw_macip(struct bgp *bgp, int advertise, vni_t vni)
{
	struct stream *s = NULL;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing gw_macip",
				__func__);
		return 0;
	}

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ADVERTISE_DEFAULT_GW, bgp->vrf_id);
	stream_putc(s, advertise);
	stream_putl(s, vni);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int bgp_zebra_vxlan_flood_control(struct bgp *bgp,
				  enum vxlan_flood_control flood_ctrl)
{
	struct stream *s;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing all vni",
				__func__);
		return 0;
	}

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VXLAN_FLOOD_CONTROL, bgp->vrf_id);
	stream_putc(s, flood_ctrl);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int bgp_zebra_advertise_all_vni(struct bgp *bgp, int advertise)
{
	struct stream *s;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_ADVERTISE_ALL_VNI, bgp->vrf_id);
	stream_putc(s, advertise);
	/* Also inform current BUM handling setting. This is really
	 * relevant only when 'advertise' is set.
	 */
	stream_putc(s, bgp->vxlan_flood_ctrl);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

int bgp_zebra_dup_addr_detection(struct bgp *bgp)
{
	struct stream *s;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("dup addr detect %s max_moves %u time %u freeze %s freeze_time %u",
			   bgp->evpn_info->dup_addr_detect ?
			   "enable" : "disable",
			   bgp->evpn_info->dad_max_moves,
			   bgp->evpn_info->dad_time,
			   bgp->evpn_info->dad_freeze ?
			   "enable" : "disable",
			   bgp->evpn_info->dad_freeze_time);

	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_DUPLICATE_ADDR_DETECTION,
			      bgp->vrf_id);
	stream_putl(s, bgp->evpn_info->dup_addr_detect);
	stream_putl(s, bgp->evpn_info->dad_time);
	stream_putl(s, bgp->evpn_info->dad_max_moves);
	stream_putl(s, bgp->evpn_info->dad_freeze);
	stream_putl(s, bgp->evpn_info->dad_freeze_time);
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

static int rule_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t seqno, priority, unique;
	enum zapi_rule_notify_owner note;
	struct bgp_pbr_action *bgp_pbra;
	struct bgp_pbr_rule *bgp_pbr = NULL;
	char ifname[IFNAMSIZ + 1];

	if (!zapi_rule_notify_decode(zclient->ibuf, &seqno, &priority, &unique,
				     ifname, &note))
		return -1;

	bgp_pbra = bgp_pbr_action_rule_lookup(vrf_id, unique);
	if (!bgp_pbra) {
		/* look in bgp pbr rule */
		bgp_pbr = bgp_pbr_rule_lookup(vrf_id, unique);
		if (!bgp_pbr && note != ZAPI_RULE_REMOVED) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("%s: Fail to look BGP rule (%u)",
					   __func__, unique);
			return 0;
		}
	}

	switch (note) {
	case ZAPI_RULE_FAIL_INSTALL:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received RULE_FAIL_INSTALL", __func__);
		if (bgp_pbra) {
			bgp_pbra->installed = false;
			bgp_pbra->install_in_progress = false;
		} else {
			bgp_pbr->installed = false;
			bgp_pbr->install_in_progress = false;
		}
		break;
	case ZAPI_RULE_INSTALLED:
		if (bgp_pbra) {
			bgp_pbra->installed = true;
			bgp_pbra->install_in_progress = false;
		} else {
			struct bgp_path_info *path;
			struct bgp_path_info_extra *extra;

			bgp_pbr->installed = true;
			bgp_pbr->install_in_progress = false;
			bgp_pbr->action->refcnt++;
			/* link bgp_info to bgp_pbr */
			path = (struct bgp_path_info *)bgp_pbr->path;
			extra = bgp_path_info_extra_get(path);
			if (!extra->flowspec) {
				extra->flowspec =
					XCALLOC(MTYPE_BGP_ROUTE_EXTRA_FS,
						sizeof(struct bgp_path_info_extra_fs));
				extra->flowspec->bgp_fs_iprule = NULL;
				extra->flowspec->bgp_fs_pbr = NULL;
			}
			listnode_add_force(&extra->flowspec->bgp_fs_iprule, bgp_pbr);
		}
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received RULE_INSTALLED", __func__);
		break;
	case ZAPI_RULE_FAIL_REMOVE:
	case ZAPI_RULE_REMOVED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received RULE REMOVED", __func__);
		break;
	}

	return 0;
}

static int ipset_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t unique;
	enum zapi_ipset_notify_owner note;
	struct bgp_pbr_match *bgp_pbim;

	if (!zapi_ipset_notify_decode(zclient->ibuf,
				      &unique,
				      &note))
		return -1;

	bgp_pbim = bgp_pbr_match_ipset_lookup(vrf_id, unique);
	if (!bgp_pbim) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Fail to look BGP match ( %u, ID %u)",
				   __func__, note, unique);
		return 0;
	}

	switch (note) {
	case ZAPI_IPSET_FAIL_INSTALL:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET_FAIL_INSTALL", __func__);
		bgp_pbim->installed = false;
		bgp_pbim->install_in_progress = false;
		break;
	case ZAPI_IPSET_INSTALLED:
		bgp_pbim->installed = true;
		bgp_pbim->install_in_progress = false;
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET_INSTALLED", __func__);
		break;
	case ZAPI_IPSET_FAIL_REMOVE:
	case ZAPI_IPSET_REMOVED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET REMOVED", __func__);
		break;
	}

	return 0;
}

static int ipset_entry_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t unique;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
	enum zapi_ipset_entry_notify_owner note;
	struct bgp_pbr_match_entry *bgp_pbime;

	if (!zapi_ipset_entry_notify_decode(
				zclient->ibuf,
				&unique,
				ipset_name,
				&note))
		return -1;
	bgp_pbime = bgp_pbr_match_ipset_entry_lookup(vrf_id,
						     ipset_name,
						     unique);
	if (!bgp_pbime) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: Fail to look BGP match entry (%u, ID %u)",
				__func__, note, unique);
		return 0;
	}

	switch (note) {
	case ZAPI_IPSET_ENTRY_FAIL_INSTALL:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET_ENTRY_FAIL_INSTALL",
				   __func__);
		bgp_pbime->installed = false;
		bgp_pbime->install_in_progress = false;
		break;
	case ZAPI_IPSET_ENTRY_INSTALLED:
		{
		struct bgp_path_info *path;
		struct bgp_path_info_extra *extra;

		bgp_pbime->installed = true;
		bgp_pbime->install_in_progress = false;
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET_ENTRY_INSTALLED",
				   __func__);
		/* link bgp_path_info to bpme */
		path = (struct bgp_path_info *)bgp_pbime->path;
		extra = bgp_path_info_extra_get(path);
		if (!extra->flowspec) {
			extra->flowspec =
				XCALLOC(MTYPE_BGP_ROUTE_EXTRA_FS,
					sizeof(struct bgp_path_info_extra_fs));
			extra->flowspec->bgp_fs_iprule = NULL;
			extra->flowspec->bgp_fs_pbr = NULL;
		}
		listnode_add_force(&extra->flowspec->bgp_fs_pbr, bgp_pbime);
		}
		break;
	case ZAPI_IPSET_ENTRY_FAIL_REMOVE:
	case ZAPI_IPSET_ENTRY_REMOVED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPSET_ENTRY_REMOVED",
				   __func__);
		break;
	}
	return 0;
}

static int iptable_notify_owner(ZAPI_CALLBACK_ARGS)
{
	uint32_t unique;
	enum zapi_iptable_notify_owner note;
	struct bgp_pbr_match *bgpm;

	if (!zapi_iptable_notify_decode(
					zclient->ibuf,
					&unique,
					&note))
		return -1;
	bgpm = bgp_pbr_match_iptable_lookup(vrf_id, unique);
	if (!bgpm) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Fail to look BGP iptable (%u %u)",
				   __func__, note, unique);
		return 0;
	}
	switch (note) {
	case ZAPI_IPTABLE_FAIL_INSTALL:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPTABLE_FAIL_INSTALL",
				   __func__);
		bgpm->installed_in_iptable = false;
		bgpm->install_iptable_in_progress = false;
		break;
	case ZAPI_IPTABLE_INSTALLED:
		bgpm->installed_in_iptable = true;
		bgpm->install_iptable_in_progress = false;
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPTABLE_INSTALLED", __func__);
		bgpm->action->refcnt++;
		break;
	case ZAPI_IPTABLE_FAIL_REMOVE:
	case ZAPI_IPTABLE_REMOVED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: Received IPTABLE REMOVED", __func__);
		break;
	}
	return 0;
}

/* Process route notification messages from RIB */
static int bgp_zebra_route_notify_owner(int command, struct zclient *zclient,
					zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct bgp_path_info *pi, *new_select;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note,
				      &afi, &safi)) {
		zlog_err("%s : error in msg decode", __func__);
		return -1;
	}

	/* Get the bgp instance */
	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE,
			 "%s : bgp instance not found vrf %d", __func__,
			 vrf_id);
		return -1;
	}

	/* Find the bgp route node */
	dest = bgp_safi_node_lookup(bgp->rib[afi][safi], safi, &p,
				    &bgp->vrf_prd);
	if (!dest) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %pFX does not exist in the BGP table, nothing to do for %u",
				   __func__, &p, note);
		return -1;
	}

	switch (note) {
	case ZAPI_ROUTE_INSTALLED:
		new_select = NULL;
		/* Clear the flags so that route can be processed */
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);
		SET_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED);
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("route %pBD : INSTALLED", dest);
		/* Find the best route */
		for (pi = dest->info; pi; pi = pi->next) {
			/* Process aggregate route */
			bgp_aggregate_increment(bgp, &p, pi, afi, safi);
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				new_select = pi;
		}
		/* Advertise the route */
		if (new_select)
			group_announce_route(bgp, afi, safi, dest, new_select);
		else {
			flog_err(EC_BGP_INVALID_ROUTE,
				 "selected route %pBD not found", dest);

			bgp_dest_unlock_node(dest);
			return -1;
		}
		break;
	case ZAPI_ROUTE_REMOVED:
		/* Route deleted from dataplane, reset the installed flag
		 * so that route can be reinstalled when client sends
		 * route add later
		 */
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED);
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("route %pBD: Removed from Fib", dest);
		break;
	case ZAPI_ROUTE_FAIL_INSTALL:
		new_select = NULL;
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("route: %pBD Failed to Install into Fib",
				   dest);
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED);
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				new_select = pi;
		}
		if (new_select)
			group_announce_route(bgp, afi, safi, dest, new_select);
		/* Error will be logged by zebra module */
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("route: %pBD removed due to better admin won",
				   dest);
		new_select = NULL;
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING);
		UNSET_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED);
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			bgp_aggregate_decrement(bgp, &p, pi, afi, safi);
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
				new_select = pi;
		}
		if (new_select)
			group_announce_route(bgp, afi, safi, dest, new_select);
		/* No action required */
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		zlog_warn("%s: Route %pBD failure to remove", __func__, dest);
		break;
	}

	bgp_dest_unlock_node(dest);
	return 0;
}

/* this function is used to forge ip rule,
 * - either for iptable/ipset using fwmark id
 * - or for sample ip rule cmd
 */
static void bgp_encode_pbr_rule_action(struct stream *s,
				       struct bgp_pbr_action *pbra,
				       struct bgp_pbr_rule *pbr)
{
	uint8_t fam = AF_INET;
	struct pbr_rule r;

	if (pbra->nh.type == NEXTHOP_TYPE_IPV6)
		fam = AF_INET6;

	/*
	 * Convert to canonical form
	 */
	memset(&r, 0, sizeof(r));
	/* r.seq unused */
	if (pbr)
		r.priority = pbr->priority;

	/* ruleno unused - priority change
	 * ruleno permits distinguishing various FS PBR entries
	 * - FS PBR entries based on ipset/iptables
	 * - FS PBR entries based on iprule
	 * the latter may contain default routing information injected by FS
	 */
	if (pbr)
		r.unique = pbr->unique;
	else
		r.unique = pbra->unique;

	r.family = fam;

	/* filter */

	if (pbr && pbr->flags & MATCH_IP_SRC_SET) {
		SET_FLAG(r.filter.filter_bm, PBR_FILTER_SRC_IP);
		r.filter.src_ip = pbr->src;
	} else {
		/* ??? */
		r.filter.src_ip.family = fam;
	}
	if (pbr && pbr->flags & MATCH_IP_DST_SET) {
		SET_FLAG(r.filter.filter_bm, PBR_FILTER_DST_IP);
		r.filter.dst_ip = pbr->dst;
	} else {
		/* ??? */
		r.filter.dst_ip.family = fam;
	}
	/* src_port, dst_port, pcp, dsfield not used */
	if (!pbr) {
		SET_FLAG(r.filter.filter_bm, PBR_FILTER_FWMARK);
		r.filter.fwmark = pbra->fwmark;
	}

	SET_FLAG(r.action.flags, PBR_ACTION_TABLE); /* always valid */
	r.action.table = pbra->table_id;

	zapi_pbr_rule_encode(s, &r);
}

static void bgp_encode_pbr_ipset_match(struct stream *s,
				  struct bgp_pbr_match *pbim)
{
	stream_putl(s, pbim->unique);
	stream_putl(s, pbim->type);
	stream_putc(s, pbim->family);
	stream_put(s, pbim->ipset_name,
		   ZEBRA_IPSET_NAME_SIZE);
}

static void bgp_encode_pbr_ipset_entry_match(struct stream *s,
				  struct bgp_pbr_match_entry *pbime)
{
	stream_putl(s, pbime->unique);
	/* check that back pointer is not null */
	stream_put(s, pbime->backpointer->ipset_name,
		   ZEBRA_IPSET_NAME_SIZE);

	stream_putc(s, pbime->src.family);
	stream_putc(s, pbime->src.prefixlen);
	stream_put(s, &pbime->src.u.prefix, prefix_blen(&pbime->src));

	stream_putc(s, pbime->dst.family);
	stream_putc(s, pbime->dst.prefixlen);
	stream_put(s, &pbime->dst.u.prefix, prefix_blen(&pbime->dst));

	stream_putw(s, pbime->src_port_min);
	stream_putw(s, pbime->src_port_max);
	stream_putw(s, pbime->dst_port_min);
	stream_putw(s, pbime->dst_port_max);
	stream_putc(s, pbime->proto);
}

static void bgp_encode_pbr_iptable_match(struct stream *s,
					 struct bgp_pbr_action *bpa,
					 struct bgp_pbr_match *pbm)
{
	stream_putl(s, pbm->unique2);

	stream_putl(s, pbm->type);

	stream_putl(s, pbm->flags);

	/* TODO: correlate with what is contained
	 * into bgp_pbr_action.
	 * currently only forward supported
	 */
	if (bpa->nh.type == NEXTHOP_TYPE_BLACKHOLE)
		stream_putl(s, ZEBRA_IPTABLES_DROP);
	else
		stream_putl(s, ZEBRA_IPTABLES_FORWARD);
	stream_putl(s, bpa->fwmark);
	stream_put(s, pbm->ipset_name,
		   ZEBRA_IPSET_NAME_SIZE);
	stream_putc(s, pbm->family);
	stream_putw(s, pbm->pkt_len_min);
	stream_putw(s, pbm->pkt_len_max);
	stream_putw(s, pbm->tcp_flags);
	stream_putw(s, pbm->tcp_mask_flags);
	stream_putc(s, pbm->dscp_value);
	stream_putc(s, pbm->fragment);
	stream_putc(s, pbm->protocol);
	stream_putw(s, pbm->flow_label);
}

/* BGP has established connection with Zebra. */
static void bgp_zebra_connected(struct zclient *zclient)
{
	struct bgp *bgp;

	zclient_num_connects++; /* increment even if not responding */

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);

	/* At this point, we may or may not have BGP instances configured, but
	 * we're only interested in the default VRF (others wouldn't have learnt
	 * the VRF from Zebra yet.)
	 */
	bgp = bgp_get_default();
	if (!bgp)
		return;

	bgp_zebra_instance_register(bgp);

	/* TODO - What if we have peers and networks configured, do we have to
	 * kick-start them?
	 */
	BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer);
}

static int bgp_zebra_process_local_es_add(ZAPI_CALLBACK_ARGS)
{
	esi_t esi;
	struct bgp *bgp = NULL;
	struct stream *s = NULL;
	char buf[ESI_STR_LEN];
	struct in_addr originator_ip;
	uint8_t active;
	uint8_t bypass;
	uint16_t df_pref;

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	s = zclient->ibuf;
	stream_get(&esi, s, sizeof(esi_t));
	originator_ip.s_addr = stream_get_ipv4(s);
	active = stream_getc(s);
	df_pref = stream_getw(s);
	bypass = stream_getc(s);

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug(
			"Rx add ESI %s originator-ip %pI4 active %u df_pref %u %s",
			esi_to_str(&esi, buf, sizeof(buf)), &originator_ip,
			active, df_pref, bypass ? "bypass" : "");

	frrtrace(5, frr_bgp, evpn_mh_local_es_add_zrecv, &esi, originator_ip,
		 active, bypass, df_pref);

	bgp_evpn_local_es_add(bgp, &esi, originator_ip, active, df_pref,
			      !!bypass);

	return 0;
}

static int bgp_zebra_process_local_es_del(ZAPI_CALLBACK_ARGS)
{
	esi_t esi;
	struct bgp *bgp = NULL;
	struct stream *s = NULL;
	char buf[ESI_STR_LEN];

	memset(&esi, 0, sizeof(esi_t));
	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	s = zclient->ibuf;
	stream_get(&esi, s, sizeof(esi_t));

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx del ESI %s",
				esi_to_str(&esi, buf, sizeof(buf)));

	frrtrace(1, frr_bgp, evpn_mh_local_es_del_zrecv, &esi);

	bgp_evpn_local_es_del(bgp, &esi);

	return 0;
}

static int bgp_zebra_process_local_es_evi(ZAPI_CALLBACK_ARGS)
{
	esi_t esi;
	vni_t vni;
	struct bgp *bgp;
	struct stream *s;
	char buf[ESI_STR_LEN];

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	s = zclient->ibuf;
	stream_get(&esi, s, sizeof(esi_t));
	vni = stream_getl(s);

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx %s ESI %s VNI %u",
			   (cmd == ZEBRA_VNI_ADD) ? "add" : "del",
			   esi_to_str(&esi, buf, sizeof(buf)), vni);

	if (cmd == ZEBRA_LOCAL_ES_EVI_ADD) {
		frrtrace(2, frr_bgp, evpn_mh_local_es_evi_add_zrecv, &esi, vni);

		bgp_evpn_local_es_evi_add(bgp, &esi, vni);
	} else {
		frrtrace(2, frr_bgp, evpn_mh_local_es_evi_del_zrecv, &esi, vni);

		bgp_evpn_local_es_evi_del(bgp, &esi, vni);
	}

	return 0;
}

static int bgp_zebra_process_local_l3vni(ZAPI_CALLBACK_ARGS)
{
	int filter = 0;
	vni_t l3vni = 0;
	struct ethaddr svi_rmac, vrr_rmac = {.octet = {0} };
	struct in_addr originator_ip;
	struct stream *s;
	ifindex_t svi_ifindex;
	bool is_anycast_mac = false;

	memset(&svi_rmac, 0, sizeof(svi_rmac));
	memset(&originator_ip, 0, sizeof(originator_ip));
	s = zclient->ibuf;
	l3vni = stream_getl(s);
	if (cmd == ZEBRA_L3VNI_ADD) {
		stream_get(&svi_rmac, s, sizeof(struct ethaddr));
		originator_ip.s_addr = stream_get_ipv4(s);
		stream_get(&filter, s, sizeof(int));
		svi_ifindex = stream_getl(s);
		stream_get(&vrr_rmac, s, sizeof(struct ethaddr));
		is_anycast_mac = stream_getl(s);

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Rx L3VNI ADD VRF %s VNI %u Originator-IP %pI4 RMAC svi-mac %pEA vrr-mac %pEA filter %s svi-if %u",
				   vrf_id_to_name(vrf_id), l3vni,
				   &originator_ip, &svi_rmac, &vrr_rmac,
				   filter ? "prefix-routes-only" : "none",
				   svi_ifindex);

		frrtrace(8, frr_bgp, evpn_local_l3vni_add_zrecv, l3vni, vrf_id,
			 &svi_rmac, &vrr_rmac, filter, originator_ip,
			 svi_ifindex, is_anycast_mac);

		bgp_evpn_local_l3vni_add(l3vni, vrf_id, &svi_rmac, &vrr_rmac,
					 originator_ip, filter, svi_ifindex,
					 is_anycast_mac);
	} else {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Rx L3VNI DEL VRF %s VNI %u",
				   vrf_id_to_name(vrf_id), l3vni);

		frrtrace(2, frr_bgp, evpn_local_l3vni_del_zrecv, l3vni, vrf_id);

		bgp_evpn_local_l3vni_del(l3vni, vrf_id);
	}

	return 0;
}

static int bgp_zebra_process_local_vni(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	vni_t vni;
	struct bgp *bgp;
	struct in_addr vtep_ip = {INADDR_ANY};
	vrf_id_t tenant_vrf_id = VRF_DEFAULT;
	struct in_addr mcast_grp = {INADDR_ANY};
	ifindex_t svi_ifindex = 0;

	s = zclient->ibuf;
	vni = stream_getl(s);
	if (cmd == ZEBRA_VNI_ADD) {
		vtep_ip.s_addr = stream_get_ipv4(s);
		stream_get(&tenant_vrf_id, s, sizeof(vrf_id_t));
		mcast_grp.s_addr = stream_get_ipv4(s);
		stream_get(&svi_ifindex, s, sizeof(ifindex_t));
	}

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug(
			"Rx VNI %s VRF %s VNI %u tenant-vrf %s SVI ifindex %u",
			(cmd == ZEBRA_VNI_ADD) ? "add" : "del",
			vrf_id_to_name(vrf_id), vni,
			vrf_id_to_name(tenant_vrf_id), svi_ifindex);

	if (cmd == ZEBRA_VNI_ADD) {
		frrtrace(4, frr_bgp, evpn_local_vni_add_zrecv, vni, vtep_ip,
			 tenant_vrf_id, mcast_grp);

		return bgp_evpn_local_vni_add(
			bgp, vni,
			vtep_ip.s_addr != INADDR_ANY ? vtep_ip : bgp->router_id,
			tenant_vrf_id, mcast_grp, svi_ifindex);
	} else {
		frrtrace(1, frr_bgp, evpn_local_vni_del_zrecv, vni);

		return bgp_evpn_local_vni_del(bgp, vni);
	}
}

static int bgp_zebra_process_local_macip(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	vni_t vni;
	struct bgp *bgp;
	struct ethaddr mac;
	struct ipaddr ip;
	int ipa_len;
	uint8_t flags = 0;
	uint32_t seqnum = 0;
	int state = 0;
	char buf2[ESI_STR_LEN];
	esi_t esi;

	memset(&ip, 0, sizeof(ip));
	s = zclient->ibuf;
	vni = stream_getl(s);
	stream_get(&mac.octet, s, ETH_ALEN);
	ipa_len = stream_getl(s);
	if (ipa_len != 0 && ipa_len != IPV4_MAX_BYTELEN
	    && ipa_len != IPV6_MAX_BYTELEN) {
		flog_err(EC_BGP_MACIP_LEN,
			 "%u:Recv MACIP %s with invalid IP addr length %d",
			 vrf_id, (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			 ipa_len);
		return -1;
	}

	if (ipa_len) {
		ip.ipa_type =
			(ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4 : IPADDR_V6;
		stream_get(&ip.ip.addr, s, ipa_len);
	}
	if (cmd == ZEBRA_MACIP_ADD) {
		flags = stream_getc(s);
		seqnum = stream_getl(s);
		stream_get(&esi, s, sizeof(esi_t));
	} else {
		state = stream_getl(s);
		memset(&esi, 0, sizeof(esi_t));
	}

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug(
			"%u:Recv MACIP %s f 0x%x MAC %pEA IP %pIA VNI %u seq %u state %d ESI %s",
			vrf_id, (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del", flags,
			&mac, &ip, vni, seqnum, state,
			esi_to_str(&esi, buf2, sizeof(buf2)));

	if (cmd == ZEBRA_MACIP_ADD) {
		frrtrace(6, frr_bgp, evpn_local_macip_add_zrecv, vni, &mac, &ip,
			 flags, seqnum, &esi);

		return bgp_evpn_local_macip_add(bgp, vni, &mac, &ip,
						flags, seqnum, &esi);
	} else {
		frrtrace(4, frr_bgp, evpn_local_macip_del_zrecv, vni, &mac, &ip,
			 state);

		return bgp_evpn_local_macip_del(bgp, vni, &mac, &ip, state);
	}
}

static int bgp_zebra_process_local_ip_prefix(ZAPI_CALLBACK_ARGS)
{
	struct stream *s = NULL;
	struct bgp *bgp_vrf = NULL;
	struct prefix p;

	memset(&p, 0, sizeof(p));
	s = zclient->ibuf;
	stream_get(&p, s, sizeof(struct prefix));

	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Recv prefix %pFX %s on vrf %s", &p,
			   (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD) ? "ADD" : "DEL",
			   vrf_id_to_name(vrf_id));

	if (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD) {

		if (p.family == AF_INET)
			bgp_evpn_advertise_type5_route(bgp_vrf, &p, NULL,
						       AFI_IP, SAFI_UNICAST);
		else
			bgp_evpn_advertise_type5_route(bgp_vrf, &p, NULL,
						       AFI_IP6, SAFI_UNICAST);

	} else {
		if (p.family == AF_INET)
			bgp_evpn_withdraw_type5_route(bgp_vrf, &p, AFI_IP,
						      SAFI_UNICAST);
		else
			bgp_evpn_withdraw_type5_route(bgp_vrf, &p, AFI_IP6,
						      SAFI_UNICAST);
	}
	return 0;
}

extern struct zebra_privs_t bgpd_privs;

static int bgp_ifp_create(struct interface *ifp)
{
	struct bgp *bgp;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf add VRF %s IF %s", ifp->vrf->name,
			   ifp->name);

	bgp = ifp->vrf->info;
	if (!bgp)
		return 0;

	bgp_mac_add_mac_entry(ifp);

	bgp_update_interface_nbrs(bgp, ifp, ifp);
	hook_call(bgp_vrf_status_changed, bgp, ifp);

	if (bgp_get_default() && if_is_loopback(ifp)) {
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP6);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP6);
		vpn_leak_postchange_all();
	}

	return 0;
}

static int bgp_zebra_process_srv6_locator_chunk(ZAPI_CALLBACK_ARGS)
{
	struct stream *s = NULL;
	struct bgp *bgp = bgp_get_default();
	struct listnode *node;
	struct srv6_locator_chunk *c;
	struct srv6_locator_chunk *chunk = srv6_locator_chunk_alloc();

	s = zclient->ibuf;
	zapi_srv6_locator_chunk_decode(s, chunk);

	if (strcmp(bgp->srv6_locator_name, chunk->locator_name) != 0) {
		zlog_err("%s: Locator name unmatch %s:%s", __func__,
			 bgp->srv6_locator_name, chunk->locator_name);
		srv6_locator_chunk_free(&chunk);
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_locator_chunks, node, c)) {
		if (!prefix_cmp(&c->prefix, &chunk->prefix)) {
			srv6_locator_chunk_free(&chunk);
			return 0;
		}
	}

	listnode_add(bgp->srv6_locator_chunks, chunk);
	vpn_leak_postchange_all();
	return 0;
}

/**
 * Internal function to process an SRv6 locator
 *
 * @param locator The locator to be processed
 */
static int bgp_zebra_process_srv6_locator_internal(struct srv6_locator *locator)
{
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->srv6_enabled || !locator)
		return -1;

	/*
	 * Check if the main BGP instance is configured to use the received
	 * locator
	 */
	if (strcmp(bgp->srv6_locator_name, locator->name) != 0) {
		zlog_err("%s: SRv6 Locator name unmatch %s:%s", __func__,
			 bgp->srv6_locator_name, locator->name);
		return 0;
	}

	zlog_info("%s: Received SRv6 locator %s %pFX, loc-block-len=%u, loc-node-len=%u func-len=%u, arg-len=%u",
		  __func__, locator->name, &locator->prefix,
		  locator->block_bits_length, locator->node_bits_length,
		  locator->function_bits_length, locator->argument_bits_length);

	/* Store the locator in the main BGP instance */
	bgp->srv6_locator = srv6_locator_alloc(locator->name);
	srv6_locator_copy(bgp->srv6_locator, locator);

	/*
	 * Process VPN-to-VRF and VRF-to-VPN leaks to advertise new locator
	 * and SIDs.
	 */
	vpn_leak_postchange_all();

	return 0;
}

static int bgp_zebra_srv6_sid_notify(ZAPI_CALLBACK_ARGS)
{
	struct bgp *bgp = bgp_get_default();
	struct srv6_locator *locator;
	struct srv6_sid_ctx ctx;
	struct in6_addr sid_addr;
	enum zapi_srv6_sid_notify note;
	struct bgp *bgp_vrf;
	struct vrf *vrf;
	struct listnode *node, *nnode;
	char buf[256];
	struct in6_addr *tovpn_sid;
	struct prefix_ipv6 tmp_prefix;
	uint32_t sid_func;
	bool found = false;

	if (!bgp || !bgp->srv6_enabled)
		return -1;

	if (!bgp->srv6_locator) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: ignoring SRv6 SID notify: locator not set",
				   __func__);
		return -1;
	}

	/* Decode the received notification message */
	if (!zapi_srv6_sid_notify_decode(zclient->ibuf, &ctx, &sid_addr,
					 &sid_func, NULL, &note, NULL)) {
		zlog_err("%s : error in msg decode", __func__);
		return -1;
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: received SRv6 SID notify: ctx %s sid_value %pI6 %s",
			   __func__, srv6_sid_ctx2str(buf, sizeof(buf), &ctx),
			   &sid_addr, zapi_srv6_sid_notify2str(note));

	/* Get the BGP instance for which the SID has been requested, if any */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp_vrf)) {
		vrf = vrf_lookup_by_id(bgp_vrf->vrf_id);
		if (!vrf)
			continue;

		if (vrf->vrf_id == ctx.vrf_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: ignoring SRv6 SID notify: No VRF suitable for received SID ctx %s sid_value %pI6",
				   __func__,
				   srv6_sid_ctx2str(buf, sizeof(buf), &ctx),
				   &sid_addr);
		return -1;
	}

	/* Handle notification */
	switch (note) {
	case ZAPI_SRV6_SID_ALLOCATED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("SRv6 SID %pI6 %s : ALLOCATED", &sid_addr,
				   srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Verify that the received SID belongs to the configured locator */
		tmp_prefix.family = AF_INET6;
		tmp_prefix.prefixlen = IPV6_MAX_BITLEN;
		tmp_prefix.prefix = sid_addr;

		if (!prefix_match((struct prefix *)&bgp->srv6_locator->prefix,
				  (struct prefix *)&tmp_prefix))
			return -1;

		/* Get label */
		uint8_t func_len = bgp->srv6_locator->function_bits_length;
		uint8_t shift_len = BGP_PREFIX_SID_SRV6_MAX_FUNCTION_LENGTH -
				    func_len;

		int label = sid_func << shift_len;

		/* Un-export VPN to VRF routes */
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp,
				   bgp_vrf);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp,
				   bgp_vrf);

		locator = srv6_locator_alloc(bgp->srv6_locator_name);
		srv6_locator_copy(locator, bgp->srv6_locator);

		/* Store SID, locator, and label */
		tovpn_sid = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		*tovpn_sid = sid_addr;
		if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT6) {
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);
			srv6_locator_free(
				bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator);
			sid_unregister(bgp,
				       bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);

			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid = tovpn_sid;
			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator = locator;
			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_transpose_label =
				label;
		} else if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT4) {
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);
			srv6_locator_free(
				bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator);
			sid_unregister(bgp,
				       bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);

			bgp_vrf->vpn_policy[AFI_IP].tovpn_sid = tovpn_sid;
			bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator = locator;
			bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_transpose_label =
				label;
		} else if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT46) {
			XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
			srv6_locator_free(bgp_vrf->tovpn_sid_locator);
			sid_unregister(bgp, bgp_vrf->tovpn_sid);

			bgp_vrf->tovpn_sid = tovpn_sid;
			bgp_vrf->tovpn_sid_locator = locator;
			bgp_vrf->tovpn_sid_transpose_label = label;
		} else {
			srv6_locator_free(locator);
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("Unsupported behavior. Not assigned SRv6 SID: %s %pI6",
					   srv6_sid_ctx2str(buf, sizeof(buf),
							    &ctx),
					   &sid_addr);
			return -1;
		}

		/* Register the new SID */
		sid_register(bgp, tovpn_sid, bgp->srv6_locator_name);

		/* Export VPN to VRF routes */
		vpn_leak_postchange_all();

		break;
	case ZAPI_SRV6_SID_RELEASED:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("SRv6 SID %pI6 %s: RELEASED", &sid_addr,
				   srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Un-export VPN to VRF routes */
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp,
				   bgp_vrf);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp,
				   bgp_vrf);

		/* Remove SID, locator, and label */
		if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT6) {
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);
			if (bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator) {
				srv6_locator_free(bgp->vpn_policy[AFI_IP6]
							  .tovpn_sid_locator);
				bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator =
					NULL;
			}
			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_transpose_label =
				0;

			/* Unregister the SID */
			sid_unregister(bgp,
				       bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);
		} else if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT4) {
			XFREE(MTYPE_BGP_SRV6_SID,
			      bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);
			if (bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator) {
				srv6_locator_free(bgp->vpn_policy[AFI_IP]
							  .tovpn_sid_locator);
				bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator =
					NULL;
			}
			bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_transpose_label =
				0;

			/* Unregister the SID */
			sid_unregister(bgp,
				       bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);
		} else if (ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_DT46) {
			XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
			if (bgp_vrf->tovpn_sid_locator) {
				srv6_locator_free(bgp_vrf->tovpn_sid_locator);
				bgp_vrf->tovpn_sid_locator = NULL;
			}
			bgp_vrf->tovpn_sid_transpose_label = 0;

			/* Unregister the SID */
			sid_unregister(bgp, bgp_vrf->tovpn_sid);
		} else {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("Unsupported behavior. Not assigned SRv6 SID: %s %pI6",
					   srv6_sid_ctx2str(buf, sizeof(buf),
							    &ctx),
					   &sid_addr);
			return -1;
		}

		/* Export VPN to VRF routes*/
		vpn_leak_postchange_all();
		break;
	case ZAPI_SRV6_SID_FAIL_ALLOC:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("SRv6 SID %pI6 %s: Failed to allocate",
				   &sid_addr,
				   srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	case ZAPI_SRV6_SID_FAIL_RELEASE:
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: SRv6 SID %pI6 %s failure to release",
				   __func__, &sid_addr,
				   srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	}

	return 0;
}

static int bgp_zebra_process_srv6_locator_add(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};
	struct bgp *bgp = bgp_get_default();

	if (!bgp || !bgp->srv6_enabled)
		return 0;

	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	return bgp_zebra_process_srv6_locator_internal(&loc);
}

static int bgp_zebra_process_srv6_locator_delete(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};
	struct bgp *bgp = bgp_get_default();
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct srv6_locator *tovpn_sid_locator;
	struct bgp_srv6_function *func;
	struct bgp *bgp_vrf;
	struct in6_addr *tovpn_sid;
	struct prefix_ipv6 tmp_prefi;

	if (!bgp)
		return 0;

	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	// clear SRv6 locator
	if (bgp->srv6_locator) {
		srv6_locator_free(bgp->srv6_locator);
		bgp->srv6_locator = NULL;
	}

	// refresh chunks
	for (ALL_LIST_ELEMENTS(bgp->srv6_locator_chunks, node, nnode, chunk))
		if (prefix_match((struct prefix *)&loc.prefix,
				 (struct prefix *)&chunk->prefix)) {
			listnode_delete(bgp->srv6_locator_chunks, chunk);
			srv6_locator_chunk_free(&chunk);
		}

	// refresh functions
	for (ALL_LIST_ELEMENTS(bgp->srv6_functions, node, nnode, func)) {
		tmp_prefi.family = AF_INET6;
		tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
		tmp_prefi.prefix = func->sid;
		if (prefix_match((struct prefix *)&loc.prefix,
				 (struct prefix *)&tmp_prefi)) {
			listnode_delete(bgp->srv6_functions, func);
			srv6_function_free(func);
		}
	}

	// refresh tovpn_sid
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		// refresh vpnv4 tovpn_sid
		tovpn_sid = bgp_vrf->vpn_policy[AFI_IP].tovpn_sid;
		if (tovpn_sid) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = *tovpn_sid;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi))
				XFREE(MTYPE_BGP_SRV6_SID,
				      bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);
		}

		// refresh vpnv6 tovpn_sid
		tovpn_sid = bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid;
		if (tovpn_sid) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = *tovpn_sid;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi))
				XFREE(MTYPE_BGP_SRV6_SID,
				      bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);
		}

		/* refresh per-vrf tovpn_sid */
		tovpn_sid = bgp_vrf->tovpn_sid;
		if (tovpn_sid) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = *tovpn_sid;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi))
				XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
		}
	}

	vpn_leak_postchange_all();

	/* refresh tovpn_sid_locator */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		/* refresh vpnv4 tovpn_sid_locator */
		tovpn_sid_locator =
			bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator;
		if (tovpn_sid_locator) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = tovpn_sid_locator->prefix.prefix;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi)) {
				srv6_locator_free(bgp_vrf->vpn_policy[AFI_IP]
							  .tovpn_sid_locator);
				bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator =
					NULL;
			}
		}

		/* refresh vpnv6 tovpn_sid_locator */
		tovpn_sid_locator =
			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator;
		if (tovpn_sid_locator) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = tovpn_sid_locator->prefix.prefix;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi)) {
				srv6_locator_free(bgp_vrf->vpn_policy[AFI_IP6]
							  .tovpn_sid_locator);
				bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator =
					NULL;
			}
		}

		/* refresh per-vrf tovpn_sid_locator */
		tovpn_sid_locator = bgp_vrf->tovpn_sid_locator;
		if (tovpn_sid_locator) {
			tmp_prefi.family = AF_INET6;
			tmp_prefi.prefixlen = IPV6_MAX_BITLEN;
			tmp_prefi.prefix = tovpn_sid_locator->prefix.prefix;
			if (prefix_match((struct prefix *)&loc.prefix,
					 (struct prefix *)&tmp_prefi)) {
				srv6_locator_free(bgp_vrf->tovpn_sid_locator);
				bgp_vrf->tovpn_sid_locator = NULL;
			}
		}
	}

	return 0;
}

static zclient_handler *const bgp_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = bgp_router_id_update,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = bgp_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = bgp_interface_address_delete,
	[ZEBRA_INTERFACE_NBR_ADDRESS_ADD] = bgp_interface_nbr_address_add,
	[ZEBRA_INTERFACE_NBR_ADDRESS_DELETE] = bgp_interface_nbr_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = zebra_read_route,
	[ZEBRA_FEC_UPDATE] = bgp_read_fec_update,
	[ZEBRA_LOCAL_ES_ADD] = bgp_zebra_process_local_es_add,
	[ZEBRA_LOCAL_ES_DEL] = bgp_zebra_process_local_es_del,
	[ZEBRA_VNI_ADD] = bgp_zebra_process_local_vni,
	[ZEBRA_LOCAL_ES_EVI_ADD] = bgp_zebra_process_local_es_evi,
	[ZEBRA_LOCAL_ES_EVI_DEL] = bgp_zebra_process_local_es_evi,
	[ZEBRA_VNI_DEL] = bgp_zebra_process_local_vni,
	[ZEBRA_MACIP_ADD] = bgp_zebra_process_local_macip,
	[ZEBRA_MACIP_DEL] = bgp_zebra_process_local_macip,
	[ZEBRA_L3VNI_ADD] = bgp_zebra_process_local_l3vni,
	[ZEBRA_L3VNI_DEL] = bgp_zebra_process_local_l3vni,
	[ZEBRA_IP_PREFIX_ROUTE_ADD] = bgp_zebra_process_local_ip_prefix,
	[ZEBRA_IP_PREFIX_ROUTE_DEL] = bgp_zebra_process_local_ip_prefix,
	[ZEBRA_RULE_NOTIFY_OWNER] = rule_notify_owner,
	[ZEBRA_IPSET_NOTIFY_OWNER] = ipset_notify_owner,
	[ZEBRA_IPSET_ENTRY_NOTIFY_OWNER] = ipset_entry_notify_owner,
	[ZEBRA_IPTABLE_NOTIFY_OWNER] = iptable_notify_owner,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = bgp_zebra_route_notify_owner,
	[ZEBRA_SRV6_LOCATOR_ADD] = bgp_zebra_process_srv6_locator_add,
	[ZEBRA_SRV6_LOCATOR_DELETE] = bgp_zebra_process_srv6_locator_delete,
	[ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK] =
		bgp_zebra_process_srv6_locator_chunk,
	[ZEBRA_SRV6_SID_NOTIFY] = bgp_zebra_srv6_sid_notify,
};

static int bgp_if_new_hook(struct interface *ifp)
{
	struct bgp_interface *iifp;

	if (ifp->info)
		return 0;
	iifp = XCALLOC(MTYPE_BGP_IF_INFO, sizeof(struct bgp_interface));
	ifp->info = iifp;

	return 0;
}

static int bgp_if_delete_hook(struct interface *ifp)
{
	XFREE(MTYPE_BGP_IF_INFO, ifp->info);
	return 0;
}

void bgp_if_init(void)
{
	/* Initialize Zebra interface data structure. */
	hook_register_prio(if_add, 0, bgp_if_new_hook);
	hook_register_prio(if_del, 0, bgp_if_delete_hook);
}

static bool bgp_zebra_label_manager_ready(void)
{
	return (zclient_sync->sock > 0);
}

static void bgp_start_label_manager(struct event *start)
{
	if (!bgp_zebra_label_manager_ready() &&
	    !bgp_zebra_label_manager_connect())
		event_add_timer(bm->master, bgp_start_label_manager, NULL, 1,
				&bm->t_bgp_start_label_manager);
}

static bool bgp_zebra_label_manager_connect(void)
{
	/* Connect to label manager. */
	if (zclient_socket_connect(zclient_sync) < 0) {
		zlog_warn("%s: failed connecting synchronous zclient!",
			  __func__);
		return false;
	}
	/* make socket non-blocking */
	set_nonblocking(zclient_sync->sock);

	/* Send hello to notify zebra this is a synchronous client */
	if (zclient_send_hello(zclient_sync) == ZCLIENT_SEND_FAILURE) {
		zlog_warn("%s: failed sending hello for synchronous zclient!",
			  __func__);
		close(zclient_sync->sock);
		zclient_sync->sock = -1;
		return false;
	}

	/* Connect to label manager */
	if (lm_label_manager_connect(zclient_sync, 0) != 0) {
		zlog_warn("%s: failed connecting to label manager!", __func__);
		if (zclient_sync->sock > 0) {
			close(zclient_sync->sock);
			zclient_sync->sock = -1;
		}
		return false;
	}

	/* tell label pool that zebra is connected */
	bgp_lp_event_zebra_up();

	/* tell BGP L3VPN that label manager is available */
	if (bgp_get_default())
		vpn_leak_postchange_all();
	return true;
}

static void bgp_zebra_capabilities(struct zclient_capabilities *cap)
{
	bm->v6_with_v4_nexthops = cap->v6_with_v4_nexthop;
}

void bgp_zebra_init(struct event_loop *master, unsigned short instance)
{
	zclient_num_connects = 0;

	hook_register_prio(if_real, 0, bgp_ifp_create);
	hook_register_prio(if_up, 0, bgp_ifp_up);
	hook_register_prio(if_down, 0, bgp_ifp_down);
	hook_register_prio(if_unreal, 0, bgp_ifp_destroy);

	/* Set default values. */
	zclient = zclient_new(master, &zclient_options_default, bgp_handlers,
			      array_size(bgp_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_BGP, 0, &bgpd_privs);
	zclient->zebra_buffer_write_ready = bgp_zebra_buffer_write_ready;
	zclient->zebra_connected = bgp_zebra_connected;
	zclient->zebra_capabilities = bgp_zebra_capabilities;
	zclient->nexthop_update = bgp_nexthop_update;
	zclient->instance = instance;

	/* Initialize special zclient for synchronous message exchanges. */
	zclient_sync = zclient_new(master, &zclient_options_sync, NULL, 0);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_BGP;
	zclient_sync->instance = instance;
	zclient_sync->session_id = 1;
	zclient_sync->privs = &bgpd_privs;

	if (!bgp_zebra_label_manager_ready())
		event_add_timer(master, bgp_start_label_manager, NULL, 1,
				&bm->t_bgp_start_label_manager);
}

void bgp_zebra_destroy(void)
{
	if (zclient == NULL)
		return;
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;

	if (zclient_sync == NULL)
		return;
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
	zclient_sync = NULL;
}

int bgp_zebra_num_connects(void)
{
	return zclient_num_connects;
}

void bgp_send_pbr_rule_action(struct bgp_pbr_action *pbra,
			      struct bgp_pbr_rule *pbr,
			      bool install)
{
	struct stream *s;

	if (pbra->install_in_progress && !pbr)
		return;
	if (pbr && pbr->install_in_progress)
		return;
	if (BGP_DEBUG(zebra, ZEBRA)) {
		if (pbr)
			zlog_debug("%s: table %d (ip rule) %d", __func__,
				   pbra->table_id, install);
		else
			zlog_debug("%s: table %d fwmark %d %d", __func__,
				   pbra->table_id, pbra->fwmark, install);
	}
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_RULE_ADD : ZEBRA_RULE_DELETE,
			      VRF_DEFAULT);

	bgp_encode_pbr_rule_action(s, pbra, pbr);

	if ((zclient_send_message(zclient) != ZCLIENT_SEND_FAILURE)
	    && install) {
		if (!pbr)
			pbra->install_in_progress = true;
		else
			pbr->install_in_progress = true;
	}
}

void bgp_send_pbr_ipset_match(struct bgp_pbr_match *pbrim, bool install)
{
	struct stream *s;

	if (pbrim->install_in_progress)
		return;
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: name %s type %d %d, ID %u", __func__,
			   pbrim->ipset_name, pbrim->type, install,
			   pbrim->unique);
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_IPSET_CREATE :
			      ZEBRA_IPSET_DESTROY,
			      VRF_DEFAULT);

	stream_putl(s, 1); /* send one pbr action */

	bgp_encode_pbr_ipset_match(s, pbrim);

	stream_putw_at(s, 0, stream_get_endp(s));
	if ((zclient_send_message(zclient) != ZCLIENT_SEND_FAILURE) && install)
		pbrim->install_in_progress = true;
}

void bgp_send_pbr_ipset_entry_match(struct bgp_pbr_match_entry *pbrime,
				    bool install)
{
	struct stream *s;

	if (pbrime->install_in_progress)
		return;
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: name %s %d %d, ID %u", __func__,
			   pbrime->backpointer->ipset_name, pbrime->unique,
			   install, pbrime->unique);
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_IPSET_ENTRY_ADD :
			      ZEBRA_IPSET_ENTRY_DELETE,
			      VRF_DEFAULT);

	stream_putl(s, 1); /* send one pbr action */

	bgp_encode_pbr_ipset_entry_match(s, pbrime);

	stream_putw_at(s, 0, stream_get_endp(s));
	if ((zclient_send_message(zclient) != ZCLIENT_SEND_FAILURE) && install)
		pbrime->install_in_progress = true;
}

static void bgp_encode_pbr_interface_list(struct bgp *bgp, struct stream *s,
					  uint8_t family)
{
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	struct bgp_pbr_interface *pbr_if;
	struct interface *ifp;

	if (!bgp_pbr_cfg)
		return;
	if (family == AF_INET)
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
	else
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv6);
	RB_FOREACH (pbr_if, bgp_pbr_interface_head, head) {
		ifp = if_lookup_by_name(pbr_if->name, bgp->vrf_id);
		if (ifp)
			stream_putl(s, ifp->ifindex);
	}
}

static int bgp_pbr_get_ifnumber(struct bgp *bgp, uint8_t family)
{
	struct bgp_pbr_config *bgp_pbr_cfg = bgp->bgp_pbr_cfg;
	struct bgp_pbr_interface_head *head;
	struct bgp_pbr_interface *pbr_if;
	int cnt = 0;

	if (!bgp_pbr_cfg)
		return 0;
	if (family == AF_INET)
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv4);
	else
		head = &(bgp_pbr_cfg->ifaces_by_name_ipv6);
	RB_FOREACH (pbr_if, bgp_pbr_interface_head, head) {
		if (if_lookup_by_name(pbr_if->name, bgp->vrf_id))
			cnt++;
	}
	return cnt;
}

void bgp_send_pbr_iptable(struct bgp_pbr_action *pba,
			  struct bgp_pbr_match *pbm,
			  bool install)
{
	struct stream *s;
	int ret = 0;
	int nb_interface;

	if (pbm->install_iptable_in_progress)
		return;
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: name %s type %d mark %d %d, ID %u", __func__,
			   pbm->ipset_name, pbm->type, pba->fwmark, install,
			   pbm->unique2);
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s,
			      install ? ZEBRA_IPTABLE_ADD :
			      ZEBRA_IPTABLE_DELETE,
			      VRF_DEFAULT);

	bgp_encode_pbr_iptable_match(s, pba, pbm);
	nb_interface = bgp_pbr_get_ifnumber(pba->bgp, pbm->family);
	stream_putl(s, nb_interface);
	if (nb_interface)
		bgp_encode_pbr_interface_list(pba->bgp, s, pbm->family);
	stream_putw_at(s, 0, stream_get_endp(s));
	ret = zclient_send_message(zclient);
	if (install) {
		if (ret != ZCLIENT_SEND_FAILURE)
			pba->refcnt++;
		else
			pbm->install_iptable_in_progress = true;
	}
}

/* inject in table <table_id> a default route to:
 * - if nexthop IP is present : to this nexthop
 * - if vrf is different from local : to the matching VRF
 */
void bgp_zebra_announce_default(struct bgp *bgp, struct nexthop *nh,
				afi_t afi, uint32_t table_id, bool announce)
{
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	struct prefix p;

	if (!nh || (nh->type != NEXTHOP_TYPE_IPV4
		    && nh->type != NEXTHOP_TYPE_IPV6)
	    || nh->vrf_id == VRF_UNKNOWN)
		return;

	/* in vrf-lite, no default route has to be announced
	 * the table id of vrf is directly used to divert traffic
	 */
	if (!vrf_is_backend_netns() && bgp->vrf_id != nh->vrf_id)
		return;

	memset(&p, 0, sizeof(p));
	if (afi != AFI_IP && afi != AFI_IP6)
		return;
	p.family = afi2family(afi);
	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.type = ZEBRA_ROUTE_BGP;
	api.safi = SAFI_UNICAST;
	api.prefix = p;
	api.tableid = table_id;
	api.nexthop_num = 1;
	SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api_nh = &api.nexthops[0];

	api.distance = ZEBRA_EBGP_DISTANCE_DEFAULT;
	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);

	api_nh->vrf_id = nh->vrf_id;

	if (BGP_DEBUG(zebra, ZEBRA)) {
		struct vrf *vrf;

		vrf = vrf_lookup_by_id(nh->vrf_id);
		zlog_debug("%s: %s default route to %pNHvv(%s) table %d",
			   bgp->name_pretty, announce ? "adding" : "withdrawing",
			   nh, VRF_LOGNAME(vrf), table_id);
	}

	/* redirect IP */
	if (afi == AFI_IP && nh->gate.ipv4.s_addr != INADDR_ANY) {
		api_nh->gate.ipv4 = nh->gate.ipv4;
		api_nh->type = NEXTHOP_TYPE_IPV4;
	} else if (afi == AFI_IP6 && memcmp(&nh->gate.ipv6, &in6addr_any,
					    sizeof(struct in6_addr))) {
		memcpy(&api_nh->gate.ipv6, &nh->gate.ipv6,
		       sizeof(struct in6_addr));
		api_nh->type = NEXTHOP_TYPE_IPV6;
	} else if (nh->vrf_id != bgp->vrf_id) {
		struct vrf *vrf;
		struct interface *ifp;

		vrf = vrf_lookup_by_id(nh->vrf_id);
		if (!vrf)
			return;
		/* create default route with interface <VRF>
		 * with nexthop-vrf <VRF>
		 */
		ifp = if_lookup_by_name_vrf(vrf->name, vrf);
		if (!ifp)
			return;
		api_nh->type = NEXTHOP_TYPE_IFINDEX;
		api_nh->ifindex = ifp->ifindex;
	}

	zclient_route_send(announce ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}

/* Send capabilities to RIB */
int bgp_zebra_send_capabilities(struct bgp *bgp, bool disable)
{
	struct zapi_cap api;
	int ret = BGP_GR_SUCCESS;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: Sending %sable for %s", __func__,
			   disable ? "dis" : "en", bgp->name_pretty);

	if (zclient == NULL) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s zclient invalid", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	/* Check if the client is connected */
	if ((zclient->sock < 0) || (zclient->t_connect)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s client not connected", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s(%d): Sending GR capability %s to zebra",
			   bgp->name_pretty, bgp->vrf_id,
			   disable ? "disabled" : "enabled");

	/* Check if capability is already sent. If the flag force is set
	 * send the capability since this can be initial bgp configuration
	 */
	memset(&api, 0, sizeof(api));
	if (disable) {
		api.cap = ZEBRA_CLIENT_GR_DISABLE;
		api.vrf_id = bgp->vrf_id;
	} else {
		api.cap = ZEBRA_CLIENT_GR_CAPABILITIES;
		api.stale_removal_time = bgp->rib_stale_time;
		api.vrf_id = bgp->vrf_id;
	}

	if (zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, zclient, &api)
	    == ZCLIENT_SEND_FAILURE) {
		zlog_err("%s(%d): Error sending GR capability to zebra",
			 bgp->name_pretty, bgp->vrf_id);
		ret = BGP_GR_FAILURE;
	} else {
		if (disable)
			bgp->present_zebra_gr_state = ZEBRA_GR_DISABLE;
		else
			bgp->present_zebra_gr_state = ZEBRA_GR_ENABLE;

		ret = BGP_GR_SUCCESS;
	}
	return ret;
}

/* Send route update pesding or completed status to RIB for the
 * specific AFI, SAFI
 */
int bgp_zebra_update(struct bgp *bgp, afi_t afi, safi_t safi,
		     enum zserv_client_capabilities type)
{
	struct zapi_cap api = {0};

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: %s afi: %u safi: %u Command %s", __func__,
			   bgp->name_pretty, afi, safi,
			   zserv_gr_client_cap_string(type));

	if (zclient == NULL) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s zclient == NULL, invalid", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	/* Check if the client is connected */
	if ((zclient->sock < 0) || (zclient->t_connect)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s client not connected", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	api.afi = afi;
	api.safi = safi;
	api.vrf_id = bgp->vrf_id;
	api.cap = type;

	if (zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, zclient, &api)
	    == ZCLIENT_SEND_FAILURE) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s error sending capability", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}
	return BGP_GR_SUCCESS;
}


/* Send RIB stale timer update */
int bgp_zebra_stale_timer_update(struct bgp *bgp)
{
	struct zapi_cap api;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%s: %s Timer Update to %u", __func__,
			   bgp->name_pretty, bgp->rib_stale_time);

	if (zclient == NULL) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("zclient invalid");
		return BGP_GR_FAILURE;
	}

	/* Check if the client is connected */
	if ((zclient->sock < 0) || (zclient->t_connect)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s client not connected", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	memset(&api, 0, sizeof(api));
	api.cap = ZEBRA_CLIENT_RIB_STALE_TIME;
	api.stale_removal_time = bgp->rib_stale_time;
	api.vrf_id = bgp->vrf_id;
	if (zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, zclient, &api)
	    == ZCLIENT_SEND_FAILURE) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("%s: %s error sending capability", __func__,
				   bgp->name_pretty);
		return BGP_GR_FAILURE;
	}

	return BGP_GR_SUCCESS;
}

int bgp_zebra_srv6_manager_get_locator_chunk(const char *name)
{
	return srv6_manager_get_locator_chunk(zclient, name);
}

int bgp_zebra_srv6_manager_release_locator_chunk(const char *name)
{
	return srv6_manager_release_locator_chunk(zclient, name);
}

/**
 * Ask the SRv6 Manager (zebra) about a specific locator
 *
 * @param name Locator name
 * @return 0 on success, -1 otherwise
 */
int bgp_zebra_srv6_manager_get_locator(const char *name)
{
	if (!name)
		return -1;

	/*
	 * Send the Get Locator request to the SRv6 Manager and return the
	 * result
	 */
	return srv6_manager_get_locator(zclient, name);
}

/**
 * Ask the SRv6 Manager (zebra) to allocate a SID.
 *
 * Optionally, it is possible to provide an IPv6 address (sid_value parameter).
 *
 * When sid_value is provided, the SRv6 Manager allocates the requested SID
 * address, if the request can be satisfied (explicit allocation).
 *
 * When sid_value is not provided, the SRv6 Manager allocates any available SID
 * from the provided locator (dynamic allocation).
 *
 * @param ctx Context to be associated with the request SID
 * @param sid_value IPv6 address to be associated with the requested SID (optional)
 * @param locator_name Name of the locator from which the SID must be allocated
 * @param sid_func SID Function allocated by the SRv6 Manager.
 */
bool bgp_zebra_request_srv6_sid(const struct srv6_sid_ctx *ctx,
				struct in6_addr *sid_value,
				const char *locator_name, uint32_t *sid_func)
{
	int ret;

	if (!ctx || !locator_name)
		return false;

	/*
	 * Send the Get SRv6 SID request to the SRv6 Manager and check the
	 * result
	 */
	ret = srv6_manager_get_sid(zclient, ctx, sid_value, locator_name,
				   sid_func);
	if (ret < 0) {
		zlog_warn("%s: error getting SRv6 SID!", __func__);
		return false;
	}

	return true;
}

/**
 * Ask the SRv6 Manager (zebra) to release a previously allocated SID.
 *
 * This function is used to tell the SRv6 Manager that BGP no longer intends
 * to use the SID.
 *
 * @param ctx Context to be associated with the SID to be released
 */
void bgp_zebra_release_srv6_sid(const struct srv6_sid_ctx *ctx)
{
	int ret;

	if (!ctx)
		return;

	/*
	 * Send the Release SRv6 SID request to the SRv6 Manager and check the
	 * result
	 */
	ret = srv6_manager_release_sid(zclient, ctx);
	if (ret < 0) {
		zlog_warn("%s: error releasing SRv6 SID!", __func__);
		return;
	}
}

void bgp_zebra_send_nexthop_label(int cmd, mpls_label_t label,
				  ifindex_t ifindex, vrf_id_t vrf_id,
				  enum lsp_types_t ltype, struct prefix *p,
				  uint8_t num_labels, mpls_label_t out_labels[])
{
	struct zapi_labels zl = {};
	struct zapi_nexthop *znh;
	int i = 0;

	zl.type = ltype;
	zl.local_label = label;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	if (p->family == AF_INET)
		IPV4_ADDR_COPY(&znh->gate.ipv4, &p->u.prefix4);
	else
		IPV6_ADDR_COPY(&znh->gate.ipv6, &p->u.prefix6);
	if (ifindex == IFINDEX_INTERNAL)
		znh->type = (p->family == AF_INET) ? NEXTHOP_TYPE_IPV4
						   : NEXTHOP_TYPE_IPV6;
	else
		znh->type = (p->family == AF_INET) ? NEXTHOP_TYPE_IPV4_IFINDEX
						   : NEXTHOP_TYPE_IPV6_IFINDEX;
	znh->ifindex = ifindex;
	znh->vrf_id = vrf_id;
	if (num_labels == 0)
		znh->label_num = 0;
	else {
		if (num_labels > MPLS_MAX_LABELS)
			znh->label_num = MPLS_MAX_LABELS;
		else
			znh->label_num = num_labels;
		for (i = 0; i < znh->label_num; i++)
			znh->labels[i] = out_labels[i];
	}
	/* vrf_id is DEFAULT_VRF */
	zebra_send_mpls_labels(zclient, cmd, &zl);
}

bool bgp_zebra_request_label_range(uint32_t base, uint32_t chunk_size,
				   bool label_auto)
{
	int ret;
	uint32_t start, end;

	if (!zclient_sync || !bgp_zebra_label_manager_ready())
		return false;

	ret = lm_get_label_chunk(zclient_sync, 0, base, chunk_size, &start,
				 &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label range!", __func__);
		return false;
	}

	if (start > end || start < MPLS_LABEL_UNRESERVED_MIN ||
	    end > MPLS_LABEL_UNRESERVED_MAX) {
		flog_err(EC_BGP_LM_ERROR, "%s: Invalid Label chunk: %u - %u",
			 __func__, start, end);
		return false;
	}

	if (label_auto)
		/* label automatic is serviced by the bgp label pool
		 * manager, which allocates label chunks in
		 * pre-pools, and which needs to be notified about
		 * new chunks availability
		 */
		bgp_lp_event_chunk(start, end);

	return true;
}

void bgp_zebra_release_label_range(uint32_t start, uint32_t end)
{
	int ret;

	if (!zclient_sync || !bgp_zebra_label_manager_ready())
		return;

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0)
		zlog_warn("%s: error releasing label range!", __func__);
}
