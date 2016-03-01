/*
 * Copyright (C) 2016 by Open Source Routing.
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "prefix.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "command.h"
#include "network.h"
#include "linklist.h"

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"
#include "ldp_debug.h"

static void	 ifp2kif(struct interface *, struct kif *);
static void	 ifc2kaddr(struct interface *, struct connected *,
		    struct kaddr *);
static int	 ldp_router_id_update(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_add(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_delete(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_status_change(int command, struct zclient *,
		    zebra_size_t, vrf_id_t);
static int	 ldp_interface_address_add(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static int	 ldp_interface_address_delete(int, struct zclient *,
		    zebra_size_t, vrf_id_t);
static int	 ldp_zebra_read_route(int, struct zclient *, zebra_size_t,
		    vrf_id_t);
static void	 ldp_zebra_connected(struct zclient *);

static struct zclient	*zclient;

static void
ifp2kif(struct interface *ifp, struct kif *kif)
{
	memset(kif, 0, sizeof(*kif));
	strlcpy(kif->ifname, ifp->name, sizeof(kif->ifname));
	kif->ifindex = ifp->ifindex;
	kif->flags = ifp->flags;
}

static void
ifc2kaddr(struct interface *ifp, struct connected *ifc, struct kaddr *ka)
{
	memset(ka, 0, sizeof(*ka));
	ka->ifindex = ifp->ifindex;
	ka->af = ifc->address->family;
	ka->prefixlen = ifc->address->prefixlen;

	switch (ka->af) {
	case AF_INET:
		ka->addr.v4 = ifc->address->u.prefix4;
		if (ifc->destination)
			ka->dstbrd.v4 = ifc->destination->u.prefix4;
		break;
	case AF_INET6:
		ka->addr.v6 = ifc->address->u.prefix6;
		if (ifc->destination)
			ka->dstbrd.v6 = ifc->destination->u.prefix6;
		break;
	default:
		break;
	}
}

int
kr_change(struct kroute *kr)
{
	/* TODO */
	return (0);
}

int
kr_delete(struct kroute *kr)
{
	/* TODO */
	return (0);
}

int
kmpw_set(struct kpw *kpw)
{
	/* TODO */
	return (0);
}

int
kmpw_unset(struct kpw *kpw)
{
	/* TODO */
	return (0);
}

void
kif_redistribute(const char *ifname)
{
	struct listnode		*node, *cnode;
	struct interface	*ifp;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp)) {
		if (ifname && strcmp(ifname, ifp->name) != 0)
			continue;

		ifp2kif(ifp, &kif);
		main_imsg_compose_ldpe(IMSG_IFSTATUS, 0, &kif, sizeof(kif));

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	}
}

static int
ldp_router_id_update(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct prefix	 router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (bad_addr_v4(router_id.u.prefix4))
		return (0);

	debug_zebra_in("router-id update %s", inet_ntoa(router_id.u.prefix4));

	global.rtr_id.s_addr = router_id.u.prefix4.s_addr;
	main_imsg_compose_ldpe(IMSG_RTRID_UPDATE, 0, &global.rtr_id,
	    sizeof(global.rtr_id));

	return (0);
}

static int
ldp_interface_add(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct interface	*ifp;
	struct kif		 kif;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	debug_zebra_in("interface add %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	ifp2kif(ifp, &kif);
	main_imsg_compose_ldpe(IMSG_IFSTATUS, 0, &kif, sizeof(kif));

	return (0);
}

static int
ldp_interface_delete(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct interface	*ifp;

	/* zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return (0);

	debug_zebra_in("interface delete %s index %d mtu %d", ifp->name,
	    ifp->ifindex, ifp->mtu);

	/* To support pseudo interface do not free interface structure.  */
	/* if_delete(ifp); */
	ifp->ifindex = IFINDEX_INTERNAL;

	return (0);
}

static int
ldp_interface_status_change(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface	*ifp;
	struct listnode		*node;
	struct connected	*ifc;
	struct kif		 kif;
	struct kaddr		 ka;
	int			 link_new;

	/*
	 * zebra_interface_state_read() updates interface structure in
	 * iflist.
	 */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return (0);

	debug_zebra_in("interface %s state update", ifp->name);

	ifp2kif(ifp, &kif);
	main_imsg_compose_ldpe(IMSG_IFSTATUS, 0, &kif, sizeof(kif));

	link_new = (ifp->flags & IFF_UP) && (ifp->flags & IFF_RUNNING);
	if (link_new) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka,
			    sizeof(ka));
		}
	} else {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
			ifc2kaddr(ifp, ifc, &ka);
			main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka,
			    sizeof(ka));
		}
	}

	return (0);
}

static int
ldp_interface_address_add(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address add %s/%u", log_addr(ka.af, &ka.addr),
	    ka.prefixlen);

	/* notify ldpe about new address */
	main_imsg_compose_ldpe(IMSG_NEWADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_interface_address_delete(int command, struct zclient *zclient,
    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected	*ifc;
	struct interface	*ifp;
	struct kaddr		 ka;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return (0);

	ifp = ifc->ifp;
	ifc2kaddr(ifp, ifc, &ka);
	connected_free(ifc);

	/* Filter invalid addresses.  */
	if (bad_addr(ka.af, &ka.addr))
		return (0);

	debug_zebra_in("address delete %s/%u", log_addr(ka.af, &ka.addr),
	    ka.prefixlen);

	/* notify ldpe about removed address */
	main_imsg_compose_ldpe(IMSG_DELADDR, 0, &ka, sizeof(ka));

	return (0);
}

static int
ldp_zebra_read_route(int command, struct zclient *zclient, zebra_size_t length,
    vrf_id_t vrf_id)
{
	struct stream		*s;
	u_char			 type;
	u_char			 message_flags;
	struct kroute		 kr;
	int			 nhnum, nhlen;
	size_t			 nhmark;

	memset(&kr, 0, sizeof(kr));
	s = zclient->ibuf;

	type = stream_getc(s);
	if (type == ZEBRA_ROUTE_CONNECT)
		kr.flags |= F_CONNECTED;
	stream_getc(s); /* flags, unused */
	stream_getw(s); /* instance, unused */
	message_flags = stream_getc(s);
	if (!CHECK_FLAG(message_flags, ZAPI_MESSAGE_NEXTHOP))
		return (0);

	switch (command) {
	case ZEBRA_IPV4_ROUTE_ADD:
	case ZEBRA_REDISTRIBUTE_IPV4_ADD:
	case ZEBRA_IPV4_ROUTE_DELETE:
	case ZEBRA_REDISTRIBUTE_IPV4_DEL:
		kr.af = AF_INET;
		nhlen = sizeof(struct in_addr);
		break;
	case ZEBRA_IPV6_ROUTE_ADD:
	case ZEBRA_REDISTRIBUTE_IPV6_ADD:
	case ZEBRA_IPV6_ROUTE_DELETE:
	case ZEBRA_REDISTRIBUTE_IPV6_DEL:
		kr.af = AF_INET6;
		nhlen = sizeof(struct in6_addr);
		break;
	default:
		fatalx("ldp_zebra_read_route: unknown command");
	}
	kr.prefixlen = stream_getc(s);
	stream_get(&kr.prefix, s, PSIZE(kr.prefixlen));

	if (bad_addr(kr.af, &kr.prefix) ||
	    (kr.af == AF_INET6 && IN6_IS_SCOPE_EMBED(&kr.prefix.v6)))
		return (0);

	nhnum = stream_getc(s);
	nhmark = stream_get_getp(s);
	stream_set_getp(s, nhmark + nhnum * (nhlen + 5));

	if (CHECK_FLAG(message_flags, ZAPI_MESSAGE_DISTANCE))
		kr.priority = stream_getc(s);
	if (CHECK_FLAG(message_flags, ZAPI_MESSAGE_METRIC))
		stream_getl(s);	/* metric, not used */

	stream_set_getp(s, nhmark);

	/* loop through all the nexthops */
	for (; nhnum > 0; nhnum--) {
		switch (kr.af) {
		case AF_INET:
			kr.nexthop.v4.s_addr = stream_get_ipv4(s);
			break;
		case AF_INET6:
			stream_get(&kr.nexthop.v6, s, sizeof(kr.nexthop.v6));
			break;
		default:
			break;
		}
		stream_getc(s);	/* ifindex_num, unused. */
		kr.ifindex = stream_getl(s);

		switch (command) {
		case ZEBRA_IPV4_ROUTE_ADD:
		case ZEBRA_REDISTRIBUTE_IPV4_ADD:
		case ZEBRA_IPV6_ROUTE_ADD:
		case ZEBRA_REDISTRIBUTE_IPV6_ADD:
			debug_zebra_in("route add %s/%d nexthop %s (%s)",
			    log_addr(kr.af, &kr.prefix), kr.prefixlen,
			    log_addr(kr.af, &kr.nexthop),
			    zebra_route_string(type));
			main_imsg_compose_lde(IMSG_NETWORK_ADD, 0, &kr,
			    sizeof(kr));
			break;
		case ZEBRA_IPV4_ROUTE_DELETE:
		case ZEBRA_REDISTRIBUTE_IPV4_DEL:
		case ZEBRA_IPV6_ROUTE_DELETE:
		case ZEBRA_REDISTRIBUTE_IPV6_DEL:
			debug_zebra_in("route delete %s/%d nexthop %s (%s)",
			    log_addr(kr.af, &kr.prefix), kr.prefixlen,
			    log_addr(kr.af, &kr.nexthop),
			    zebra_route_string(type));
			main_imsg_compose_lde(IMSG_NETWORK_DEL, 0, &kr,
			    sizeof(kr));
			break;
		default:
			fatalx("ldp_zebra_read_route: unknown command");
		}
	}

	return (0);
}

static void
ldp_zebra_connected(struct zclient *zclient)
{
	int	i;

	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		switch (i) {
		case ZEBRA_ROUTE_KERNEL:
		case ZEBRA_ROUTE_CONNECT:
		case ZEBRA_ROUTE_STATIC:
		case ZEBRA_ROUTE_ISIS:
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
			    AFI_IP, i, 0, VRF_DEFAULT);
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
			    AFI_IP6, i, 0, VRF_DEFAULT);
			break;
		case ZEBRA_ROUTE_RIP:
		case ZEBRA_ROUTE_OSPF:
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
			    AFI_IP, i, 0, VRF_DEFAULT);
			break;
		case ZEBRA_ROUTE_RIPNG:
		case ZEBRA_ROUTE_OSPF6:
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
			    AFI_IP6, i, 0, VRF_DEFAULT);
			break;
		case ZEBRA_ROUTE_BGP:
			/* LDP should follow the IGP and ignore BGP routes */
		default:
			break;
		}
	}
}

void
ldp_zebra_init(struct thread_master *master)
{
	/* Set default values. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_LDP, 0);

	/* set callbacks */
	zclient->zebra_connected = ldp_zebra_connected;
	zclient->router_id_update = ldp_router_id_update;
	zclient->interface_add = ldp_interface_add;
	zclient->interface_delete = ldp_interface_delete;
	zclient->interface_up = ldp_interface_status_change;
	zclient->interface_down = ldp_interface_status_change;
	zclient->interface_address_add = ldp_interface_address_add;
	zclient->interface_address_delete = ldp_interface_address_delete;
	zclient->ipv4_route_add = ldp_zebra_read_route;
	zclient->ipv4_route_delete = ldp_zebra_read_route;
	zclient->redistribute_route_ipv4_add = ldp_zebra_read_route;
	zclient->redistribute_route_ipv4_del = ldp_zebra_read_route;
	zclient->ipv6_route_add = ldp_zebra_read_route;
	zclient->ipv6_route_delete = ldp_zebra_read_route;
	zclient->redistribute_route_ipv6_add = ldp_zebra_read_route;
	zclient->redistribute_route_ipv6_del = ldp_zebra_read_route;
}
