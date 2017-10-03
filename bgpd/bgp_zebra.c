/* zebra client
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "thread.h"
#include "queue.h"
#include "memory.h"
#include "lib/json.h"
#include "lib/bfd.h"
#include "filter.h"
#include "mpls.h"
#include "vxlan.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_label.h"
#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#endif
#include "bgpd/bgp_evpn.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Can we install into zebra? */
static inline int bgp_install_info_to_zebra(struct bgp *bgp)
{
	if (zclient->sock <= 0)
		return 0;

	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	return 1;
}

int zclient_num_connects;

/* Router-id update message from zebra. */
static int bgp_router_id_update(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (BGP_DEBUG(zebra, ZEBRA)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&router_id, buf, sizeof(buf));
		zlog_debug("Rx Router Id update VRF %u Id %s", vrf_id, buf);
	}

	bgp_router_id_zebra_bump(vrf_id, &router_id);
	return 0;
}

/* Nexthop update message from zebra. */
static int bgp_read_nexthop_update(int command, struct zclient *zclient,
				   zebra_size_t length, vrf_id_t vrf_id)
{
	bgp_parse_nexthop_update(command, vrf_id);
	return 0;
}

static int bgp_read_import_check_update(int command, struct zclient *zclient,
					zebra_size_t length, vrf_id_t vrf_id)
{
	bgp_parse_nexthop_update(command, vrf_id);
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

static int bgp_read_fec_update(int command, struct zclient *zclient,
			       zebra_size_t length)
{
	bgp_parse_fec_update();
	return 0;
}

static void bgp_start_interface_nbrs(struct bgp *bgp, struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peer->conf_if && (strcmp(peer->conf_if, ifp->name) == 0)
		    && peer->status != Established) {
			if (peer_active(peer))
				BGP_EVENT_ADD(peer, BGP_Stop);
			BGP_EVENT_ADD(peer, BGP_Start);
		}
	}
}

static void bgp_nbr_connected_add(struct bgp *bgp, struct nbr_connected *ifc)
{
	struct listnode *node;
	struct connected *connected;
	struct interface *ifp;
	struct prefix *p;

	/* Kick-off the FSM for any relevant peers only if there is a
	 * valid local address on the interface.
	 */
	ifp = ifc->ifp;
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
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
			BGP_EVENT_ADD(peer, BGP_Stop);
		}
	}
	/* Free neighbor also, if we're asked to. */
	if (del) {
		ifp = ifc->ifp;
		listnode_delete(ifp->nbr_connected, ifc);
		nbr_connected_free(ifc);
	}
}

/* Inteface addition message from zebra. */
static int bgp_interface_add(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct bgp *bgp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (!ifp) // unexpected
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA) && ifp)
		zlog_debug("Rx Intf add VRF %u IF %s", vrf_id, ifp->name);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	bgp_update_interface_nbrs(bgp, ifp, ifp);
	return 0;
}

static int bgp_interface_delete(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp;
	struct bgp *bgp;

	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);
	if (!ifp) /* This may happen if we've just unregistered for a VRF. */
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf del VRF %u IF %s", vrf_id, ifp->name);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	bgp_update_interface_nbrs(bgp, ifp, NULL);

	ifp->ifindex = IFINDEX_DELETED;
	return 0;
}

static int bgp_interface_up(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp;
	struct connected *c;
	struct nbr_connected *nc;
	struct listnode *node, *nnode;
	struct bgp *bgp;

	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);

	if (!ifp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf up VRF %u IF %s", vrf_id, ifp->name);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, c))
		bgp_connected_add(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_add(bgp, nc);

	return 0;
}

static int bgp_interface_down(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp;
	struct connected *c;
	struct nbr_connected *nc;
	struct listnode *node, *nnode;
	struct bgp *bgp;

	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);
	if (!ifp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx Intf down VRF %u IF %s", vrf_id, ifp->name);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, c))
		bgp_connected_delete(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_delete(bgp, nc, 1);

	/* Fast external-failover */
	{
		struct peer *peer;

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
			return 0;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
#if defined(HAVE_CUMULUS)
			/* Take down directly connected EBGP peers as well as
			 * 1-hop BFD
			 * tracked (directly connected) IBGP peers.
			 */
			if ((peer->ttl != 1) && (peer->gtsm_hops != 1)
			    && (!peer->bfd_info
				|| bgp_bfd_is_peer_multihop(peer)))
#else
			/* Take down directly connected EBGP peers */
			if ((peer->ttl != 1) && (peer->gtsm_hops != 1))
#endif
				continue;

			if (ifp == peer->nexthop.ifp) {
				BGP_EVENT_ADD(peer, BGP_Stop);
				peer->last_reset = PEER_DOWN_IF_DOWN;
			}
		}
	}

	return 0;
}

static int bgp_interface_address_add(int command, struct zclient *zclient,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(ifc->address, buf, sizeof(buf));
		zlog_debug("Rx Intf address add VRF %u IF %s addr %s", vrf_id,
			   ifc->ifp->name, buf);
	}

	if (if_is_operative(ifc->ifp)) {
		struct bgp *bgp;

		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (!bgp)
			return 0;

		bgp_connected_add(bgp, ifc);
		/* If we have learnt of any neighbors on this interface,
		 * check to kick off any BGP interface-based neighbors,
		 * but only if this is a link-local address.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)
		    && !list_isempty(ifc->ifp->nbr_connected))
			bgp_start_interface_nbrs(bgp, ifc->ifp);
	}

	return 0;
}

static int bgp_interface_address_delete(int command, struct zclient *zclient,
					zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;
	struct bgp *bgp;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(ifc->address, buf, sizeof(buf));
		zlog_debug("Rx Intf address del VRF %u IF %s addr %s", vrf_id,
			   ifc->ifp->name, buf);
	}

	if (if_is_operative(ifc->ifp)) {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp)
			bgp_connected_delete(bgp, ifc);
	}

	connected_free(ifc);

	return 0;
}

static int bgp_interface_nbr_address_add(int command, struct zclient *zclient,
					 zebra_size_t length, vrf_id_t vrf_id)
{
	struct nbr_connected *ifc = NULL;
	struct bgp *bgp;

	ifc = zebra_interface_nbr_address_read(command, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(ifc->address, buf, sizeof(buf));
		zlog_debug("Rx Intf neighbor add VRF %u IF %s addr %s", vrf_id,
			   ifc->ifp->name, buf);
	}

	if (if_is_operative(ifc->ifp)) {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp)
			bgp_nbr_connected_add(bgp, ifc);
	}

	return 0;
}

static int bgp_interface_nbr_address_delete(int command,
					    struct zclient *zclient,
					    zebra_size_t length,
					    vrf_id_t vrf_id)
{
	struct nbr_connected *ifc = NULL;
	struct bgp *bgp;

	ifc = zebra_interface_nbr_address_read(command, zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	if (bgp_debug_zebra(ifc->address)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(ifc->address, buf, sizeof(buf));
		zlog_debug("Rx Intf neighbor del VRF %u IF %s addr %s", vrf_id,
			   ifc->ifp->name, buf);
	}

	if (if_is_operative(ifc->ifp)) {
		bgp = bgp_lookup_by_vrf_id(vrf_id);
		if (bgp)
			bgp_nbr_connected_delete(bgp, ifc, 0);
	}

	nbr_connected_free(ifc);

	return 0;
}

/* VRF update for an interface. */
static int bgp_interface_vrf_update(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	vrf_id_t new_vrf_id;
	struct connected *c;
	struct nbr_connected *nc;
	struct listnode *node, *nnode;
	struct bgp *bgp;

	ifp = zebra_interface_vrf_update_read(zclient->ibuf, vrf_id,
					      &new_vrf_id);
	if (!ifp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA) && ifp)
		zlog_debug("Rx Intf VRF change VRF %u IF %s NewVRF %u", vrf_id,
			   ifp->name, new_vrf_id);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, c))
		bgp_connected_delete(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_delete(bgp, nc, 1);

	/* Fast external-failover */
	{
		struct peer *peer;

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
			return 0;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if ((peer->ttl != 1) && (peer->gtsm_hops != 1))
				continue;

			if (ifp == peer->nexthop.ifp)
				BGP_EVENT_ADD(peer, BGP_Stop);
		}
	}

	if_update_to_new_vrf(ifp, new_vrf_id);

	bgp = bgp_lookup_by_vrf_id(new_vrf_id);
	if (!bgp)
		return 0;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, c))
		bgp_connected_add(bgp, c);

	for (ALL_LIST_ELEMENTS(ifp->nbr_connected, node, nnode, nc))
		bgp_nbr_connected_add(bgp, nc);
	return 0;
}

/* Zebra route add and delete treatment. */
static int zebra_read_route(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	union g_addr nexthop;
	unsigned int ifindex;
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

	nexthop = api.nexthops[0].gate;
	ifindex = api.nexthops[0].ifindex;

	add = (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD);
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
				     api.metric, api.type, api.instance,
				     api.tag);
	} else {
		bgp_redistribute_delete(bgp, &api.prefix, api.type,
					api.instance);
	}

	if (bgp_debug_zebra(&api.prefix)) {
		char buf[2][PREFIX_STRLEN];

		prefix2str(&api.prefix, buf[0], sizeof(buf[0]));
		inet_ntop(api.prefix.family, &nexthop, buf[1], sizeof(buf[1]));
		zlog_debug(
			"Rx route %s VRF %u %s[%d] %s "
			"nexthop %s metric %u tag %" ROUTE_TAG_PRI,
			(add) ? "add" : "delete", vrf_id,
			zebra_route_string(api.type), api.instance, buf[0],
			buf[1], api.metric, api.tag);
	}

	return 0;
}

struct interface *if_lookup_by_ipv4(struct in_addr *addr, vrf_id_t vrf_id)
{
	struct vrf *vrf;
	struct listnode *cnode;
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

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
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
	struct listnode *cnode;
	struct interface *ifp;
	struct connected *connected;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
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
	struct listnode *cnode;
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

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
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
	struct listnode *cnode;
	struct interface *ifp;
	struct connected *connected;
	struct prefix *cp;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
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
	struct listnode *cnode;
	struct connected *connected;
	struct prefix *cp;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
		cp = connected->address;

		if (cp->family == AF_INET6)
			if (!IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
				memcpy(addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
				return 1;
			}
	}
	return 0;
}

static int if_get_ipv6_local(struct interface *ifp, struct in6_addr *addr)
{
	struct listnode *cnode;
	struct connected *connected;
	struct prefix *cp;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
		cp = connected->address;

		if (cp->family == AF_INET6)
			if (IN6_IS_ADDR_LINKLOCAL(&cp->u.prefix6)) {
				memcpy(addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
				return 1;
			}
	}
	return 0;
}

static int if_get_ipv4_address(struct interface *ifp, struct in_addr *addr)
{
	struct listnode *cnode;
	struct connected *connected;
	struct prefix *cp;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
		cp = connected->address;
		if ((cp->family == AF_INET)
		    && !ipv4_martian(&(cp->u.prefix4))) {
			*addr = cp->u.prefix4;
			return 1;
		}
	}
	return 0;
}

int bgp_nexthop_set(union sockunion *local, union sockunion *remote,
		    struct bgp_nexthop *nexthop, struct peer *peer)
{
	int ret = 0;
	struct interface *ifp = NULL;

	memset(nexthop, 0, sizeof(struct bgp_nexthop));

	if (!local)
		return -1;
	if (!remote)
		return -1;

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
		if (IN6_IS_ADDR_LINKLOCAL(&local->sin6.sin6_addr)) {
			if (peer->conf_if || peer->ifname)
				ifp = if_lookup_by_name(peer->conf_if
								? peer->conf_if
								: peer->ifname,
							peer->bgp->vrf_id);
		} else if (peer->update_if)
			ifp = if_lookup_by_name(peer->update_if,
						peer->bgp->vrf_id);
		else
			ifp = if_lookup_by_ipv6_exact(&local->sin6.sin6_addr,
						      local->sin6.sin6_scope_id,
						      peer->bgp->vrf_id);
	}

	if (!ifp)
		return -1;

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
			if_get_ipv6_local(ifp, &nexthop->v6_global);
			memcpy(&nexthop->v6_local, &nexthop->v6_global,
			       IPV6_MAX_BYTELEN);
		} else
			if_get_ipv6_local(ifp, &nexthop->v6_local);

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
		if (!ret && peer->local_id.s_addr)
			nexthop->v4 = peer->local_id;

		/* Global address*/
		if (!IN6_IS_ADDR_LINKLOCAL(&local->sin6.sin6_addr)) {
			memcpy(&nexthop->v6_global, &local->sin6.sin6_addr,
			       IPV6_MAX_BYTELEN);

			/* If directory connected set link-local address. */
			direct = if_lookup_by_ipv6(&remote->sin6.sin6_addr,
						   remote->sin6.sin6_scope_id,
						   peer->bgp->vrf_id);
			if (direct)
				if_get_ipv6_local(ifp, &nexthop->v6_local);
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
	return 0;
}

static struct in6_addr *bgp_info_to_ipv6_nexthop(struct bgp_info *info)
{
	struct in6_addr *nexthop = NULL;

	/* Only global address nexthop exists. */
	if (info->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL)
		nexthop = &info->attr->mp_nexthop_global;

	/* If both global and link-local address present. */
	if (info->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
		/* Check if route-map is set to prefer global over link-local */
		if (info->attr->mp_nexthop_prefer_global)
			nexthop = &info->attr->mp_nexthop_global;
		else {
			/* Workaround for Cisco's nexthop bug.  */
			if (IN6_IS_ADDR_UNSPECIFIED(
				    &info->attr->mp_nexthop_global)
			    && info->peer->su_remote->sa.sa_family == AF_INET6)
				nexthop =
					&info->peer->su_remote->sin6.sin6_addr;
			else
				nexthop = &info->attr->mp_nexthop_local;
		}
	}

	return nexthop;
}

static int bgp_table_map_apply(struct route_map *map, struct prefix *p,
			       struct bgp_info *info)
{
	route_map_result_t ret;

	ret = route_map_apply(map, p, RMAP_BGP, info);
	bgp_attr_flush(info->attr);

	if (ret != RMAP_DENYMATCH)
		return 1;

	if (bgp_debug_zebra(p)) {
		if (p->family == AF_INET) {
			char buf[2][INET_ADDRSTRLEN];
			zlog_debug(
				"Zebra rmap deny: IPv4 route %s/%d nexthop %s",
				inet_ntop(AF_INET, &p->u.prefix4, buf[0],
					  sizeof(buf[0])),
				p->prefixlen,
				inet_ntop(AF_INET, &info->attr->nexthop, buf[1],
					  sizeof(buf[1])));
		}
		if (p->family == AF_INET6) {
			char buf[2][INET6_ADDRSTRLEN];
			zlog_debug(
				"Zebra rmap deny: IPv6 route %s/%d nexthop %s",
				inet_ntop(AF_INET6, &p->u.prefix6, buf[0],
					  sizeof(buf[0])),
				p->prefixlen,
				inet_ntop(AF_INET6,
					  bgp_info_to_ipv6_nexthop(info),
					  buf[1], sizeof(buf[1])));
		}
	}
	return 0;
}

void bgp_zebra_announce(struct bgp_node *rn, struct prefix *p,
			struct bgp_info *info, struct bgp *bgp, afi_t afi,
			safi_t safi)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	int nh_family;
	unsigned int valid_nh_count = 0;
	int has_valid_label = 0;
	u_char distance;
	struct peer *peer;
	struct bgp_info *mpinfo;
	u_int32_t metric;
	struct attr local_attr;
	struct bgp_info local_info;
	struct bgp_info *mpinfo_cp = &local_info;
	route_tag_t tag;
	mpls_label_t label;

	/* Don't try to install if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return;

	if (bgp->main_zebra_update_hold)
		return;

	/* Make Zebra API structure. */
	memset(&api, 0, sizeof(api));
	api.vrf_id = bgp->vrf_id;
	api.type = ZEBRA_ROUTE_BGP;
	api.safi = safi;
	api.prefix = *p;
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	peer = info->peer;

	tag = info->attr->tag;

	/* When we create an aggregate route we must also install a Null0 route
	 * in
	 * the RIB */
	if (info->sub_type == BGP_ROUTE_AGGREGATE)
		zapi_route_set_blackhole(&api, BLACKHOLE_NULL);

	if (peer->sort == BGP_PEER_IBGP || peer->sort == BGP_PEER_CONFED
	    || info->sub_type == BGP_ROUTE_AGGREGATE) {
		SET_FLAG(api.flags, ZEBRA_FLAG_IBGP);
		SET_FLAG(api.flags, ZEBRA_FLAG_INTERNAL);
	}

	if ((peer->sort == BGP_PEER_EBGP && peer->ttl != 1)
	    || CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	    || bgp_flag_check(bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))

		SET_FLAG(api.flags, ZEBRA_FLAG_INTERNAL);

	/* Metric is currently based on the best-path only */
	metric = info->attr->med;
	for (mpinfo = info; mpinfo; mpinfo = bgp_info_mpath_next(mpinfo)) {
		if (valid_nh_count >= multipath_num)
			break;

		*mpinfo_cp = *mpinfo;

		/* Get nexthop address-family */
		if (p->family == AF_INET
		    && !BGP_ATTR_NEXTHOP_AFI_IP6(mpinfo_cp->attr))
			nh_family = AF_INET;
		else if (p->family == AF_INET6
			 || (p->family == AF_INET
			     && BGP_ATTR_NEXTHOP_AFI_IP6(mpinfo_cp->attr)))
			nh_family = AF_INET6;
		else
			continue;

		if (nh_family == AF_INET) {
			struct in_addr *nexthop;

			if (bgp->table_map[afi][safi].name) {
				/* Copy info and attributes, so the route-map
				   apply doesn't modify the BGP route info. */
				local_attr = *mpinfo->attr;
				mpinfo_cp->attr = &local_attr;

				if (!bgp_table_map_apply(
					    bgp->table_map[afi][safi].map, p,
					    mpinfo_cp))
					continue;

				/* metric/tag is only allowed to be
				 * overridden on 1st nexthop */
				if (mpinfo == info) {
					metric = mpinfo_cp->attr->med;
					tag = mpinfo_cp->attr->tag;
				}
			}

			nexthop = &mpinfo_cp->attr->nexthop;

			api_nh = &api.nexthops[valid_nh_count];
			api_nh->gate.ipv4 = *nexthop;
			api_nh->type = NEXTHOP_TYPE_IPV4;
		} else {
			ifindex_t ifindex;
			struct in6_addr *nexthop;

			ifindex = 0;

			if (bgp->table_map[afi][safi].name) {
				/* Copy info and attributes, so the route-map
				   apply doesn't modify the BGP route info. */
				local_attr = *mpinfo->attr;
				mpinfo_cp->attr = &local_attr;

				if (!bgp_table_map_apply(
					    bgp->table_map[afi][safi].map, p,
					    mpinfo_cp))
					continue;

				/* metric/tag is only allowed to be
				 * overridden on 1st nexthop */
				if (mpinfo == info) {
					metric = mpinfo_cp->attr->med;
					tag = mpinfo_cp->attr->tag;
				}
			}
			nexthop = bgp_info_to_ipv6_nexthop(mpinfo_cp);

			if ((mpinfo == info)
			    && mpinfo->attr->mp_nexthop_len
				       == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
				if (mpinfo->peer->nexthop.ifp)
					ifindex = mpinfo->peer->nexthop.ifp
							  ->ifindex;

			if (!ifindex) {
				if (mpinfo->peer->conf_if
				    || mpinfo->peer->ifname)
					ifindex = ifname2ifindex(
						mpinfo->peer->conf_if
							? mpinfo->peer->conf_if
							: mpinfo->peer->ifname,
						bgp->vrf_id);
				else if (mpinfo->peer->nexthop.ifp)
					ifindex = mpinfo->peer->nexthop.ifp
							  ->ifindex;
			}
			if (ifindex == 0)
				continue;

			api_nh = &api.nexthops[valid_nh_count];
			api_nh->gate.ipv6 = *nexthop;
			api_nh->ifindex = ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		}

		if (mpinfo->extra
		    && bgp_is_valid_label(&mpinfo->extra->label)) {
			has_valid_label = 1;
			label = label_pton(&mpinfo->extra->label);

			api_nh->label_num = 1;
			api_nh->labels[0] = label;
		}
		valid_nh_count++;
	}

	if (has_valid_label)
		SET_FLAG(api.message, ZAPI_MESSAGE_LABEL);

	if (info->sub_type != BGP_ROUTE_AGGREGATE)
		api.nexthop_num = valid_nh_count;

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = metric;

	if (tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = tag;
	}

	distance = bgp_distance_apply(p, info, afi, safi, bgp);
	if (distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = distance;
	}

	if (bgp_debug_zebra(p)) {
		char prefix_buf[PREFIX_STRLEN];
		char nh_buf[INET6_ADDRSTRLEN];
		char label_buf[20];
		int i;

		prefix2str(&api.prefix, prefix_buf, sizeof(prefix_buf));
		zlog_debug("Tx route %s VRF %u %s metric %u tag %" ROUTE_TAG_PRI
			   " count %d",
			   valid_nh_count ? "add" : "delete", bgp->vrf_id,
			   prefix_buf, api.metric, api.tag, api.nexthop_num);
		for (i = 0; i < api.nexthop_num; i++) {
			api_nh = &api.nexthops[i];

			if (api_nh->type == NEXTHOP_TYPE_IPV4)
				nh_family = AF_INET;
			else
				nh_family = AF_INET6;
			inet_ntop(nh_family, &api_nh->gate, nh_buf,
				  sizeof(nh_buf));

			label_buf[0] = '\0';
			if (has_valid_label)
				sprintf(label_buf, "label %u",
					api_nh->labels[0]);
			zlog_debug("  nhop [%d]: %s %s", i + 1, nh_buf,
				   label_buf);
		}
	}

	zclient_route_send(valid_nh_count ? ZEBRA_ROUTE_ADD
					  : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}

/* Announce all routes of a table to zebra */
void bgp_zebra_announce_table(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_node *rn;
	struct bgp_table *table;
	struct bgp_info *ri;

	/* Don't try to install if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return;

	table = bgp->rib[afi][safi];
	if (!table)
		return;

	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn))
		for (ri = rn->info; ri; ri = ri->next)
			if (CHECK_FLAG(ri->flags, BGP_INFO_SELECTED)
			    && ri->type == ZEBRA_ROUTE_BGP
			    && ri->sub_type == BGP_ROUTE_NORMAL)
				bgp_zebra_announce(rn, &rn->p, ri, bgp, afi,
						   safi);
}

void bgp_zebra_withdraw(struct prefix *p, struct bgp_info *info, safi_t safi)
{
	struct zapi_route api;
	struct peer *peer;

	peer = info->peer;
	assert(peer);

	/* Don't try to install if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(peer->bgp))
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = peer->bgp->vrf_id;
	api.type = ZEBRA_ROUTE_BGP;
	api.safi = safi;
	api.prefix = *p;

	if (peer->sort == BGP_PEER_IBGP) {
		SET_FLAG(api.flags, ZEBRA_FLAG_INTERNAL);
		SET_FLAG(api.flags, ZEBRA_FLAG_IBGP);
	}

	if ((peer->sort == BGP_PEER_EBGP && peer->ttl != 1)
	    || CHECK_FLAG(peer->flags, PEER_FLAG_DISABLE_CONNECTED_CHECK)
	    || bgp_flag_check(peer->bgp, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
		SET_FLAG(api.flags, ZEBRA_FLAG_INTERNAL);

	if (bgp_debug_zebra(p)) {
		char buf[PREFIX_STRLEN];

		prefix2str(&api.prefix, buf, sizeof(buf));
		zlog_debug("Tx route delete VRF %u %s", peer->bgp->vrf_id, buf);
	}

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
}

struct bgp_redist *bgp_redist_lookup(struct bgp *bgp, afi_t afi, u_char type,
				     u_short instance)
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

struct bgp_redist *bgp_redist_add(struct bgp *bgp, afi_t afi, u_char type,
				  u_short instance)
{
	struct list *red_list;
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (red)
		return red;

	if (!bgp->redist[afi][type])
		bgp->redist[afi][type] = list_new();

	red_list = bgp->redist[afi][type];
	red = (struct bgp_redist *)XCALLOC(MTYPE_BGP_REDIST,
					   sizeof(struct bgp_redist));
	red->instance = instance;

	listnode_add(red_list, red);

	return red;
}

static void bgp_redist_del(struct bgp *bgp, afi_t afi, u_char type,
			   u_short instance)
{
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);

	if (red) {
		listnode_delete(bgp->redist[afi][type], red);
		XFREE(MTYPE_BGP_REDIST, red);
		if (!bgp->redist[afi][type]->count)
			list_delete_and_null(&bgp->redist[afi][type]);
	}
}

/* Other routes redistribution into BGP. */
int bgp_redistribute_set(struct bgp *bgp, afi_t afi, int type, u_short instance)
{

	/* Return if already redistribute flag is set. */
	if (instance) {
		if (redist_check_instance(&zclient->mi_redist[afi][type],
					  instance))
			return CMD_WARNING;

		redist_add_instance(&zclient->mi_redist[afi][type], instance);
	} else {
		if (vrf_bitmap_check(zclient->redist[afi][type], bgp->vrf_id))
			return CMD_WARNING;

#if ENABLE_BGP_VNC
		if (bgp->vrf_id == VRF_DEFAULT
		    && type == ZEBRA_ROUTE_VNC_DIRECT) {
			vnc_export_bgp_enable(
				bgp, afi); /* only enables if mode bits cfg'd */
		}
#endif

		vrf_bitmap_set(zclient->redist[afi][type], bgp->vrf_id);
	}

	/* Don't try to register if we're not connected to Zebra or Zebra
	 * doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return CMD_WARNING_CONFIG_FAILED;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Tx redistribute add VRF %u afi %d %s %d",
			   bgp->vrf_id, afi, zebra_route_string(type),
			   instance);

	/* Send distribute add message to zebra. */
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				instance, bgp->vrf_id);

	return CMD_SUCCESS;
}

int bgp_redistribute_resend(struct bgp *bgp, afi_t afi, int type,
			    u_short instance)
{
	/* Don't try to send if we're not connected to Zebra or Zebra doesn't
	 * know of this instance.
	 */
	if (!bgp_install_info_to_zebra(bgp))
		return -1;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Tx redistribute del/add VRF %u afi %d %s %d",
			   bgp->vrf_id, afi, zebra_route_string(type),
			   instance);

	/* Send distribute add message to zebra. */
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi, type,
				instance, bgp->vrf_id);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				instance, bgp->vrf_id);

	return 0;
}

/* Redistribute with route-map specification.  */
int bgp_redistribute_rmap_set(struct bgp_redist *red, const char *name)
{
	if (red->rmap.name && (strcmp(red->rmap.name, name) == 0))
		return 0;

	if (red->rmap.name)
		XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
	red->rmap.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
	red->rmap.map = route_map_lookup_by_name(name);

	return 1;
}

/* Redistribute with metric specification.  */
int bgp_redistribute_metric_set(struct bgp *bgp, struct bgp_redist *red,
				afi_t afi, int type, u_int32_t metric)
{
	struct bgp_node *rn;
	struct bgp_info *ri;

	if (red->redist_metric_flag && red->redist_metric == metric)
		return 0;

	red->redist_metric_flag = 1;
	red->redist_metric = metric;

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); rn;
	     rn = bgp_route_next(rn)) {
		for (ri = rn->info; ri; ri = ri->next) {
			if (ri->sub_type == BGP_ROUTE_REDISTRIBUTE
			    && ri->type == type
			    && ri->instance == red->instance) {
				struct attr *old_attr;
				struct attr new_attr;

				bgp_attr_dup(&new_attr, ri->attr);
				new_attr.med = red->redist_metric;
				old_attr = ri->attr;
				ri->attr = bgp_attr_intern(&new_attr);
				bgp_attr_unintern(&old_attr);

				bgp_info_set_flag(rn, ri,
						  BGP_INFO_ATTR_CHANGED);
				bgp_process(bgp, rn, afi, SAFI_UNICAST);
			}
		}
	}

	return 1;
}

/* Unset redistribution.  */
int bgp_redistribute_unreg(struct bgp *bgp, afi_t afi, int type,
			   u_short instance)
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
		if (!vrf_bitmap_check(zclient->redist[afi][type], bgp->vrf_id))
			return CMD_WARNING;
		vrf_bitmap_unset(zclient->redist[afi][type], bgp->vrf_id);
	}

#if ENABLE_BGP_VNC
	if (bgp->vrf_id == VRF_DEFAULT && type == ZEBRA_ROUTE_VNC_DIRECT) {
		vnc_export_bgp_disable(bgp, afi);
	}
#endif

	if (bgp_install_info_to_zebra(bgp)) {
		/* Send distribute delete message to zebra. */
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Tx redistribute del VRF %u afi %d %s %d",
				   bgp->vrf_id, afi, zebra_route_string(type),
				   instance);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
					type, instance, bgp->vrf_id);
	}

	/* Withdraw redistributed routes from current BGP's routing table. */
	bgp_redistribute_withdraw(bgp, afi, type, instance);

	return CMD_SUCCESS;
}

/* Unset redistribution.  */
int bgp_redistribute_unset(struct bgp *bgp, afi_t afi, int type,
			   u_short instance)
{
	struct bgp_redist *red;

	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return CMD_SUCCESS;

	bgp_redistribute_unreg(bgp, afi, type, instance);

	/* Unset route-map. */
	if (red->rmap.name)
		XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
	red->rmap.name = NULL;
	red->rmap.map = NULL;

	/* Unset metric. */
	red->redist_metric_flag = 0;
	red->redist_metric = 0;

	bgp_redist_del(bgp, afi, type, instance);

	return CMD_SUCCESS;
}

/* Update redistribute vrf bitmap during triggers like
   restart networking or delete/add VRFs */
void bgp_update_redist_vrf_bitmaps(struct bgp *bgp, vrf_id_t old_vrf_id)
{
	int i;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (vrf_bitmap_check(zclient->redist[afi][i],
					     old_vrf_id)) {
				vrf_bitmap_unset(zclient->redist[afi][i],
						 old_vrf_id);
				vrf_bitmap_set(zclient->redist[afi][i],
					       bgp->vrf_id);
			}
	return;
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
		zlog_debug("Registering VRF %u", bgp->vrf_id);

	/* Register for router-id, interfaces, redistributed routes. */
	zclient_send_reg_requests(zclient, bgp->vrf_id);

	/* For default instance, register to learn about VNIs, if appropriate.
	 */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
	    && bgp->advertise_all_vni)
		bgp_zebra_advertise_all_vni(bgp, 1);
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
		zlog_debug("Deregistering VRF %u", bgp->vrf_id);

	/* For default instance, unregister learning about VNIs, if appropriate.
	 */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
	    && bgp->advertise_all_vni)
		bgp_zebra_advertise_all_vni(bgp, 0);

	/* Deregister for router-id, interfaces, redistributed routes. */
	zclient_send_dereg_requests(zclient, bgp->vrf_id);
}

void bgp_zebra_initiate_radv(struct bgp *bgp, struct peer *peer)
{
	int ra_interval = BGP_UNNUM_DEFAULT_RA_INTERVAL;

	/* Don't try to initiate if we're not connected to Zebra */
	if (zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%u: Initiating RA for peer %s", bgp->vrf_id,
			   peer->host);

	zclient_send_interface_radv_req(zclient, bgp->vrf_id, peer->ifp, 1,
					ra_interval);
}

void bgp_zebra_terminate_radv(struct bgp *bgp, struct peer *peer)
{
	/* Don't try to terminate if we're not connected to Zebra */
	if (zclient->sock < 0)
		return;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%u: Terminating RA for peer %s", bgp->vrf_id,
			   peer->host);

	zclient_send_interface_radv_req(zclient, bgp->vrf_id, peer->ifp, 0, 0);
}

int bgp_zebra_advertise_gw_macip(struct bgp *bgp, int advertise, vni_t vni)
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

	zclient_create_header(s, ZEBRA_ADVERTISE_DEFAULT_GW, bgp->vrf_id);
	stream_putc(s, advertise);
	stream_put3(s, vni);
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
	stream_putw_at(s, 0, stream_get_endp(s));

	return zclient_send_message(zclient);
}

/* BGP has established connection with Zebra. */
static void bgp_zebra_connected(struct zclient *zclient)
{
	struct bgp *bgp;

	zclient_num_connects++; /* increment even if not responding */

	/* At this point, we may or may not have BGP instances configured, but
	 * we're only interested in the default VRF (others wouldn't have learnt
	 * the VRF from Zebra yet.)
	 */
	bgp = bgp_get_default();
	if (!bgp)
		return;

	bgp_zebra_instance_register(bgp);

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);

	/* TODO - What if we have peers and networks configured, do we have to
	 * kick-start them?
	 */
}

static int bgp_zebra_process_local_vni(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	vni_t vni;
	struct bgp *bgp;
	struct in_addr vtep_ip;

	s = zclient->ibuf;
	vni = stream_getl(s);
	if (command == ZEBRA_VNI_ADD)
		vtep_ip.s_addr = stream_get_ipv4(s);
	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Rx VNI %s VRF %u VNI %u",
			   (command == ZEBRA_VNI_ADD) ? "add" : "del", vrf_id,
			   vni);

	if (command == ZEBRA_VNI_ADD)
		return bgp_evpn_local_vni_add(
			bgp, vni, vtep_ip.s_addr ? vtep_ip : bgp->router_id);
	else
		return bgp_evpn_local_vni_del(bgp, vni);
}

static int bgp_zebra_process_local_macip(int command, struct zclient *zclient,
					 zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	vni_t vni;
	struct bgp *bgp;
	struct ethaddr mac;
	struct ipaddr ip;
	int ipa_len;
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	u_char flags;

	memset(&ip, 0, sizeof(ip));
	s = zclient->ibuf;
	vni = stream_getl(s);
	stream_get(&mac.octet, s, ETH_ALEN);
	ipa_len = stream_getl(s);
	if (ipa_len != 0 && ipa_len != IPV4_MAX_BYTELEN
	    && ipa_len != IPV6_MAX_BYTELEN) {
		zlog_err("%u:Recv MACIP %s with invalid IP addr length %d",
			 vrf_id, (command == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			 ipa_len);
		return -1;
	}

	if (ipa_len) {
		ip.ipa_type =
			(ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4 : IPADDR_V6;
		stream_get(&ip.ip.addr, s, ipa_len);
	}
	flags = stream_getc(s);

	bgp = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("%u:Recv MACIP %s flags 0x%x MAC %s IP %s VNI %u",
			   vrf_id, (command == ZEBRA_MACIP_ADD) ? "Add" : "Del",
			   flags, prefix_mac2str(&mac, buf, sizeof(buf)),
			   ipaddr2str(&ip, buf1, sizeof(buf1)), vni);

	if (command == ZEBRA_MACIP_ADD)
		return bgp_evpn_local_macip_add(bgp, vni, &mac, &ip, flags);
	else
		return bgp_evpn_local_macip_del(bgp, vni, &mac, &ip);
}

void bgp_zebra_init(struct thread_master *master)
{
	zclient_num_connects = 0;

	/* Set default values. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_BGP, 0);
	zclient->zebra_connected = bgp_zebra_connected;
	zclient->router_id_update = bgp_router_id_update;
	zclient->interface_add = bgp_interface_add;
	zclient->interface_delete = bgp_interface_delete;
	zclient->interface_address_add = bgp_interface_address_add;
	zclient->interface_address_delete = bgp_interface_address_delete;
	zclient->interface_nbr_address_add = bgp_interface_nbr_address_add;
	zclient->interface_nbr_address_delete =
		bgp_interface_nbr_address_delete;
	zclient->interface_vrf_update = bgp_interface_vrf_update;
	zclient->redistribute_route_add = zebra_read_route;
	zclient->redistribute_route_del = zebra_read_route;
	zclient->interface_up = bgp_interface_up;
	zclient->interface_down = bgp_interface_down;
	zclient->nexthop_update = bgp_read_nexthop_update;
	zclient->import_check_update = bgp_read_import_check_update;
	zclient->fec_update = bgp_read_fec_update;
	zclient->local_vni_add = bgp_zebra_process_local_vni;
	zclient->local_vni_del = bgp_zebra_process_local_vni;
	zclient->local_macip_add = bgp_zebra_process_local_macip;
	zclient->local_macip_del = bgp_zebra_process_local_macip;
}

void bgp_zebra_destroy(void)
{
	if (zclient == NULL)
		return;
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}

int bgp_zebra_num_connects(void)
{
	return zclient_num_connects;
}
