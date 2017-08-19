/* NHRP routing functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "nhrpd.h"
#include "table.h"
#include "memory.h"
#include "stream.h"
#include "log.h"
#include "zclient.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_ROUTE, "NHRP routing entry")

static struct zclient *zclient;
static struct route_table *zebra_rib[AFI_MAX];

struct route_info {
	union sockunion via;
	struct interface *ifp;
	struct interface *nhrp_ifp;
};

static struct route_node *nhrp_route_update_get(const struct prefix *p, int create)
{
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	if (!zebra_rib[afi])
		return NULL;

	if (create) {
		rn = route_node_get(zebra_rib[afi], p);
		if (!rn->info) {
			rn->info = XCALLOC(MTYPE_NHRP_ROUTE, sizeof(struct route_info));
			route_lock_node(rn);
		}
		return rn;
	} else {
		return route_node_lookup(zebra_rib[afi], p);
	}
}

static void nhrp_route_update_put(struct route_node *rn)
{
	struct route_info *ri = rn->info;

	if (!ri->ifp && !ri->nhrp_ifp && sockunion_family(&ri->via) == AF_UNSPEC) {
		XFREE(MTYPE_NHRP_ROUTE, rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
	}
	route_unlock_node(rn);
}

static void nhrp_route_update_zebra(const struct prefix *p, union sockunion *nexthop, struct interface *ifp)
{
	struct route_node *rn;
	struct route_info *ri;

	rn = nhrp_route_update_get(p, (sockunion_family(nexthop) != AF_UNSPEC) || ifp);
	if (rn) {
		ri = rn->info;
		ri->via = *nexthop;
		ri->ifp = ifp;
		nhrp_route_update_put(rn);
	}
}

void nhrp_route_update_nhrp(const struct prefix *p, struct interface *ifp)
{
	struct route_node *rn;
	struct route_info *ri;

	rn = nhrp_route_update_get(p, ifp != NULL);
	if (rn) {
		ri = rn->info;
		ri->nhrp_ifp = ifp;
		nhrp_route_update_put(rn);
	}
}

void nhrp_route_announce(int add, enum nhrp_cache_type type, const struct prefix *p, struct interface *ifp, const union sockunion *nexthop, uint32_t mtu)
{
	int flags = 0;

	if (zclient->sock < 0)
		return;

	switch (type) {
	case NHRP_CACHE_NEGATIVE:
		SET_FLAG(flags, ZEBRA_FLAG_REJECT);
		break;
	case NHRP_CACHE_DYNAMIC:
	case NHRP_CACHE_NHS:
	case NHRP_CACHE_STATIC:
		/* Regular route, so these are announced
		 * to other routing daemons */
		break;
	default:
		SET_FLAG(flags, ZEBRA_FLAG_FIB_OVERRIDE);
		break;
	}
	SET_FLAG(flags, ZEBRA_FLAG_INTERNAL);

	if (p->family == AF_INET) {
		struct in_addr *nexthop_ipv4;
		struct zapi_ipv4 api;

		memset(&api, 0, sizeof(api));
		api.flags = flags;
		api.type = ZEBRA_ROUTE_NHRP;
		api.safi = SAFI_UNICAST;

		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		if (nexthop) {
			nexthop_ipv4 = (struct in_addr *) sockunion_get_addr(nexthop);
			api.nexthop_num = 1;
			api.nexthop = &nexthop_ipv4;
		}
		if (ifp) {
			SET_FLAG(api.message, ZAPI_MESSAGE_IFINDEX);
			api.ifindex_num = 1;
			api.ifindex = &ifp->ifindex;
		}
		if (mtu) {
			SET_FLAG(api.message, ZAPI_MESSAGE_MTU);
			api.mtu = mtu;
		}

		if (unlikely(debug_flags & NHRP_DEBUG_ROUTE)) {
			char buf[2][INET_ADDRSTRLEN];
			zlog_debug("Zebra send: IPv4 route %s %s/%d nexthop %s metric %u"
				" count %d dev %s",
				add ? "add" : "del",
				inet_ntop(AF_INET, &p->u.prefix4, buf[0], sizeof(buf[0])),
				p->prefixlen,
				nexthop ? inet_ntop(AF_INET, api.nexthop[0], buf[1], sizeof(buf[1])) : "<onlink>",
				api.metric, api.nexthop_num, ifp->name);
		}

		zapi_ipv4_route(
			add ? ZEBRA_IPV4_ROUTE_ADD : ZEBRA_IPV4_ROUTE_DELETE,
			zclient, (struct prefix_ipv4 *) p, &api);
	} else if (p->family == AF_INET6) {
		struct in6_addr *nexthop_ipv6;
		struct zapi_ipv6 api;

		memset(&api, 0, sizeof(api));
		api.flags = flags;
		api.type = ZEBRA_ROUTE_NHRP;
		api.safi = SAFI_UNICAST;

		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		if (nexthop) {
			nexthop_ipv6 = (struct in6_addr *) sockunion_get_addr(nexthop);
			api.nexthop_num = 1;
			api.nexthop = &nexthop_ipv6;
		}
		if (ifp) {
			SET_FLAG(api.message, ZAPI_MESSAGE_IFINDEX);
			api.ifindex_num = 1;
			api.ifindex = &ifp->ifindex;
		}
		if (mtu) {
			SET_FLAG(api.message, ZAPI_MESSAGE_MTU);
			api.mtu = mtu;
		}

		if (unlikely(debug_flags & NHRP_DEBUG_ROUTE)) {
			char buf[2][INET6_ADDRSTRLEN];
			zlog_debug("Zebra send: IPv6 route %s %s/%d nexthop %s metric %u"
				" count %d dev %s",
				add ? "add" : "del",
				inet_ntop(AF_INET6, &p->u.prefix6, buf[0], sizeof(buf[0])),
				p->prefixlen,
				nexthop ? inet_ntop(AF_INET6, api.nexthop[0], buf[1], sizeof(buf[1])) : "<onlink>",
				api.metric, api.nexthop_num, ifp->name);
		}

		zapi_ipv6_route(
			add ? ZEBRA_IPV6_ROUTE_ADD : ZEBRA_IPV6_ROUTE_DELETE,
			zclient, (struct prefix_ipv6 *) p, NULL, &api);
	}
}

int nhrp_route_read(int cmd, struct zclient *zclient, zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct interface *ifp = NULL;
	struct prefix prefix;
	struct prefix_ipv6 src_p;
	union sockunion nexthop_addr;
	unsigned char message, nexthop_num, ifindex_num;
	unsigned ifindex;
	char buf[2][PREFIX_STRLEN];
	int i, afaddrlen, added;

	s = zclient->ibuf;
	memset(&prefix, 0, sizeof(prefix));
	sockunion_family(&nexthop_addr) = AF_UNSPEC;

	/* Type, flags, message. */
	/*type =*/ stream_getc(s);
	/*instance =*/ stream_getw(s);
	/*flags =*/ stream_getl(s);
	message = stream_getc(s);

	/* Prefix */
	switch (cmd) {
	case ZEBRA_REDISTRIBUTE_IPV4_ADD:
	case ZEBRA_REDISTRIBUTE_IPV4_DEL:
		prefix.family = AF_INET;
		prefix.prefixlen = MIN(IPV4_MAX_PREFIXLEN, stream_getc(s));
		break;
	case ZEBRA_REDISTRIBUTE_IPV6_ADD:
	case ZEBRA_REDISTRIBUTE_IPV6_DEL:
		prefix.family = AF_INET6;
		prefix.prefixlen = MIN(IPV6_MAX_PREFIXLEN, stream_getc(s));
		break;
	default:
		return -1;
	}
	afaddrlen = family2addrsize(prefix.family);
	stream_get(&prefix.u.val, s, PSIZE(prefix.prefixlen));

	memset(&src_p, 0, sizeof(src_p));
	if (prefix.family == AF_INET6 &&
	    CHECK_FLAG(message, ZAPI_MESSAGE_SRCPFX)) {
		src_p.family = AF_INET6;
		src_p.prefixlen = stream_getc(s);
		stream_get(&src_p.prefix, s, PSIZE(src_p.prefixlen));
	}
	if (src_p.prefixlen)
		/* we completely ignore srcdest routes for now. */
		return 0;

	/* Nexthop, ifindex, distance, metric. */
	if (CHECK_FLAG(message, ZAPI_MESSAGE_NEXTHOP|ZAPI_MESSAGE_IFINDEX)) {
		nexthop_num = stream_getc(s);
		for (i = 0; i < nexthop_num; i++) {
			stream_get(buf[0], s, afaddrlen);
			if (i == 0) sockunion_set(&nexthop_addr, prefix.family, (u_char*) buf[0], afaddrlen);
		}
		ifindex_num = stream_getc(s);
		for (i = 0; i < ifindex_num; i++) {
			ifindex = stream_getl(s);
			if (i == 0 && ifindex != IFINDEX_INTERNAL)
                          ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
		}
	}
	if (CHECK_FLAG(message, ZAPI_MESSAGE_DISTANCE))
		/*distance =*/ stream_getc(s);
	if (CHECK_FLAG(message, ZAPI_MESSAGE_METRIC))
		/*metric =*/ stream_getl(s);

	added = (cmd == ZEBRA_REDISTRIBUTE_IPV4_ADD || cmd == ZEBRA_REDISTRIBUTE_IPV6_ADD);
	debugf(NHRP_DEBUG_ROUTE, "if-route-%s: %s via %s dev %s",
		added ? "add" : "del",
		prefix2str(&prefix, buf[0], sizeof buf[0]),
		sockunion2str(&nexthop_addr, buf[1], sizeof buf[1]),
		ifp ? ifp->name : "(none)");

	nhrp_route_update_zebra(&prefix, &nexthop_addr, ifp);
	nhrp_shortcut_prefix_change(&prefix, !added);

	return 0;
}

int nhrp_route_get_nexthop(const union sockunion *addr, struct prefix *p, union sockunion *via, struct interface **ifp)
{
	struct route_node *rn;
	struct route_info *ri;
	struct prefix lookup;
	afi_t afi = family2afi(sockunion_family(addr));
	char buf[PREFIX_STRLEN];

	sockunion2hostprefix(addr, &lookup);

	rn = route_node_match(zebra_rib[afi], &lookup);
	if (!rn) return 0;

	ri = rn->info;
	if (ri->nhrp_ifp) {
		debugf(NHRP_DEBUG_ROUTE, "lookup %s: nhrp_if=%s",
			prefix2str(&lookup, buf, sizeof buf),
			ri->nhrp_ifp->name);

		if (via) sockunion_family(via) = AF_UNSPEC;
		if (ifp) *ifp = ri->nhrp_ifp;
	} else {
		debugf(NHRP_DEBUG_ROUTE, "lookup %s: zebra route dev %s",
			prefix2str(&lookup, buf, sizeof buf),
			ri->ifp ? ri->ifp->name : "(none)");

		if (via) *via = ri->via;
		if (ifp) *ifp = ri->ifp;
	}
	if (p) *p = rn->p;
	route_unlock_node(rn);
	return 1;
}

enum nhrp_route_type nhrp_route_address(struct interface *in_ifp, union sockunion *addr, struct prefix *p, struct nhrp_peer **peer)
{
	struct interface *ifp = in_ifp;
	struct nhrp_interface *nifp;
	struct nhrp_cache *c;
	union sockunion via[4];
	uint32_t network_id = 0;
	afi_t afi = family2afi(sockunion_family(addr));
	int i;

	if (ifp) {
		nifp = ifp->info;
		network_id = nifp->afi[afi].network_id;

		c = nhrp_cache_get(ifp, addr, 0);
		if (c && c->cur.type == NHRP_CACHE_LOCAL) {
			if (p) memset(p, 0, sizeof(*p));
			return NHRP_ROUTE_LOCAL;
		}
	}

	for (i = 0; i < 4; i++) {
		if (!nhrp_route_get_nexthop(addr, p, &via[i], &ifp))
			return NHRP_ROUTE_BLACKHOLE;
		if (ifp) {
			/* Departing from nbma network? */
			nifp = ifp->info;
			if (network_id && network_id != nifp->afi[afi].network_id)
				return NHRP_ROUTE_OFF_NBMA;
		}
		if (sockunion_family(&via[i]) == AF_UNSPEC)
			break;
		/* Resolve via node, but return the prefix of first match */
		addr = &via[i];
		p = NULL;
	}

	if (ifp) {
		c = nhrp_cache_get(ifp, addr, 0);
		if (c && c->cur.type >= NHRP_CACHE_DYNAMIC) {
			if (p) memset(p, 0, sizeof(*p));
			if (c->cur.type == NHRP_CACHE_LOCAL)
				return NHRP_ROUTE_LOCAL;
			if (peer) *peer = nhrp_peer_ref(c->cur.peer);
			return NHRP_ROUTE_NBMA_NEXTHOP;
		}
	}

	return NHRP_ROUTE_BLACKHOLE;
}

static void
nhrp_zebra_connected (struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6,
	    ZEBRA_ROUTE_ALL, 0, VRF_DEFAULT);
}

void nhrp_zebra_init(void)
{
	zebra_rib[AFI_IP] = route_table_init();
	zebra_rib[AFI_IP6] = route_table_init();

	zclient = zclient_new(master);
	zclient->zebra_connected = nhrp_zebra_connected;
	zclient->interface_add = nhrp_interface_add;
	zclient->interface_delete = nhrp_interface_delete;
	zclient->interface_up = nhrp_interface_up;
	zclient->interface_down = nhrp_interface_down;
	zclient->interface_address_add = nhrp_interface_address_add;
	zclient->interface_address_delete = nhrp_interface_address_delete;
	zclient->redistribute_route_ipv4_add = nhrp_route_read;
	zclient->redistribute_route_ipv4_del = nhrp_route_read;
	zclient->redistribute_route_ipv6_add = nhrp_route_read;
	zclient->redistribute_route_ipv6_del = nhrp_route_read;

	zclient_init(zclient, ZEBRA_ROUTE_NHRP, 0);
}

void nhrp_zebra_terminate(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
	route_table_finish(zebra_rib[AFI_IP]);
	route_table_finish(zebra_rib[AFI_IP6]);
}

