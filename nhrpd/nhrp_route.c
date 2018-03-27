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

static struct route_node *nhrp_route_update_get(const struct prefix *p,
						int create)
{
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	if (!zebra_rib[afi])
		return NULL;

	if (create) {
		rn = route_node_get(zebra_rib[afi], p);
		if (!rn->info) {
			rn->info = XCALLOC(MTYPE_NHRP_ROUTE,
					   sizeof(struct route_info));
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

	if (!ri->ifp && !ri->nhrp_ifp
	    && sockunion_family(&ri->via) == AF_UNSPEC) {
		XFREE(MTYPE_NHRP_ROUTE, rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
	}
	route_unlock_node(rn);
}

static void nhrp_route_update_zebra(const struct prefix *p,
				    union sockunion *nexthop,
				    struct interface *ifp)
{
	struct route_node *rn;
	struct route_info *ri;

	rn = nhrp_route_update_get(
		p, (sockunion_family(nexthop) != AF_UNSPEC) || ifp);
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

void nhrp_route_announce(int add, enum nhrp_cache_type type,
			 const struct prefix *p, struct interface *ifp,
			 const union sockunion *nexthop, uint32_t mtu)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;

	if (zclient->sock < 0)
		return;

	memset(&api, 0, sizeof(api));
	api.type = ZEBRA_ROUTE_NHRP;
	api.safi = SAFI_UNICAST;
	api.vrf_id = VRF_DEFAULT;
	api.prefix = *p;

	switch (type) {
	case NHRP_CACHE_NEGATIVE:
		zapi_route_set_blackhole(&api, BLACKHOLE_REJECT);
		ifp = NULL;
		nexthop = NULL;
		break;
	case NHRP_CACHE_DYNAMIC:
	case NHRP_CACHE_NHS:
	case NHRP_CACHE_STATIC:
		/* Regular route, so these are announced
		 * to other routing daemons */
		break;
	default:
		SET_FLAG(api.flags, ZEBRA_FLAG_FIB_OVERRIDE);
		break;
	}
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api.nexthop_num = 1;
	api_nh = &api.nexthops[0];
	api_nh->vrf_id = VRF_DEFAULT;

	switch (api.prefix.family) {
	case AF_INET:
		if (nexthop) {
			api_nh->gate.ipv4 = nexthop->sin.sin_addr;
			api_nh->type = NEXTHOP_TYPE_IPV4;
		}
		if (ifp) {
			api_nh->ifindex = ifp->ifindex;
			if (api_nh->type == NEXTHOP_TYPE_IPV4)
				api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			else
				api_nh->type = NEXTHOP_TYPE_IFINDEX;
		}
		break;
	case AF_INET6:
		if (nexthop) {
			api_nh->gate.ipv6 = nexthop->sin6.sin6_addr;
			api_nh->type = NEXTHOP_TYPE_IPV6;
		}
		if (ifp) {
			api_nh->ifindex = ifp->ifindex;
			if (api_nh->type == NEXTHOP_TYPE_IPV6)
				api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			else
				api_nh->type = NEXTHOP_TYPE_IFINDEX;
		}
		break;
	}
	if (mtu) {
		SET_FLAG(api.message, ZAPI_MESSAGE_MTU);
		api.mtu = mtu;
	}

	if (unlikely(debug_flags & NHRP_DEBUG_ROUTE)) {
		char buf[2][PREFIX_STRLEN];

		prefix2str(&api.prefix, buf[0], sizeof(buf[0]));
		zlog_debug(
			"Zebra send: route %s %s nexthop %s metric %u"
			" count %d dev %s",
			add ? "add" : "del", buf[0],
			nexthop ? inet_ntop(api.prefix.family, &api_nh->gate,
					    buf[1], sizeof(buf[1]))
				: "<onlink>",
			api.metric, api.nexthop_num, ifp ? ifp->name : "none");
	}

	zclient_route_send(add ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE, zclient,
			   &api);
}

int nhrp_route_read(int cmd, struct zclient *zclient, zebra_size_t length,
		    vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct interface *ifp = NULL;
	union sockunion nexthop_addr;
	char buf[2][PREFIX_STRLEN];
	int added;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	sockunion_family(&nexthop_addr) = AF_UNSPEC;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		api_nh = &api.nexthops[0];

		nexthop_addr.sa.sa_family = api.prefix.family;
		switch (nexthop_addr.sa.sa_family) {
		case AF_INET:
			nexthop_addr.sin.sin_addr = api_nh->gate.ipv4;
			break;
		case AF_INET6:
			nexthop_addr.sin6.sin6_addr = api_nh->gate.ipv6;
			break;
		}

		if (api_nh->ifindex != IFINDEX_INTERNAL)
			ifp = if_lookup_by_index(api_nh->ifindex, VRF_DEFAULT);
	}

	added = (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD);
	debugf(NHRP_DEBUG_ROUTE, "if-route-%s: %s via %s dev %s",
	       added ? "add" : "del",
	       prefix2str(&api.prefix, buf[0], sizeof buf[0]),
	       sockunion2str(&nexthop_addr, buf[1], sizeof buf[1]),
	       ifp ? ifp->name : "(none)");

	nhrp_route_update_zebra(&api.prefix, &nexthop_addr, ifp);
	nhrp_shortcut_prefix_change(&api.prefix, !added);

	return 0;
}

int nhrp_route_get_nexthop(const union sockunion *addr, struct prefix *p,
			   union sockunion *via, struct interface **ifp)
{
	struct route_node *rn;
	struct route_info *ri;
	struct prefix lookup;
	afi_t afi = family2afi(sockunion_family(addr));
	char buf[PREFIX_STRLEN];

	sockunion2hostprefix(addr, &lookup);

	rn = route_node_match(zebra_rib[afi], &lookup);
	if (!rn)
		return 0;

	ri = rn->info;
	if (ri->nhrp_ifp) {
		debugf(NHRP_DEBUG_ROUTE, "lookup %s: nhrp_if=%s",
		       prefix2str(&lookup, buf, sizeof buf),
		       ri->nhrp_ifp->name);

		if (via)
			sockunion_family(via) = AF_UNSPEC;
		if (ifp)
			*ifp = ri->nhrp_ifp;
	} else {
		debugf(NHRP_DEBUG_ROUTE, "lookup %s: zebra route dev %s",
		       prefix2str(&lookup, buf, sizeof buf),
		       ri->ifp ? ri->ifp->name : "(none)");

		if (via)
			*via = ri->via;
		if (ifp)
			*ifp = ri->ifp;
	}
	if (p)
		*p = rn->p;
	route_unlock_node(rn);
	return 1;
}

enum nhrp_route_type nhrp_route_address(struct interface *in_ifp,
					union sockunion *addr, struct prefix *p,
					struct nhrp_peer **peer)
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
			if (p)
				memset(p, 0, sizeof(*p));
			return NHRP_ROUTE_LOCAL;
		}
	}

	for (i = 0; i < 4; i++) {
		if (!nhrp_route_get_nexthop(addr, p, &via[i], &ifp))
			return NHRP_ROUTE_BLACKHOLE;
		if (ifp) {
			/* Departing from nbma network? */
			nifp = ifp->info;
			if (network_id
			    && network_id != nifp->afi[afi].network_id)
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
			if (p)
				memset(p, 0, sizeof(*p));
			if (c->cur.type == NHRP_CACHE_LOCAL)
				return NHRP_ROUTE_LOCAL;
			if (peer)
				*peer = nhrp_peer_ref(c->cur.peer);
			return NHRP_ROUTE_NBMA_NEXTHOP;
		}
	}

	return NHRP_ROUTE_BLACKHOLE;
}

static void nhrp_zebra_connected(struct zclient *zclient)
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

	zclient = zclient_new_notify(master, &zclient_options_default);
	zclient->zebra_connected = nhrp_zebra_connected;
	zclient->interface_add = nhrp_interface_add;
	zclient->interface_delete = nhrp_interface_delete;
	zclient->interface_up = nhrp_interface_up;
	zclient->interface_down = nhrp_interface_down;
	zclient->interface_address_add = nhrp_interface_address_add;
	zclient->interface_address_delete = nhrp_interface_address_delete;
	zclient->redistribute_route_add = nhrp_route_read;
	zclient->redistribute_route_del = nhrp_route_read;

	zclient_init(zclient, ZEBRA_ROUTE_NHRP, 0, &nhrpd_privs);
}

void nhrp_zebra_terminate(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
	route_table_finish(zebra_rib[AFI_IP]);
	route_table_finish(zebra_rib[AFI_IP6]);
}
