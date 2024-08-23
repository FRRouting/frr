// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP routing functions
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "nhrpd.h"
#include "table.h"
#include "memory.h"
#include "stream.h"
#include "log.h"
#include "zclient.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_ROUTE, "NHRP routing entry");

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
	    && sockunion_is_null(&ri->via)) {
		XFREE(MTYPE_NHRP_ROUTE, rn->info);
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

	rn = nhrp_route_update_get(p, !sockunion_is_null(nexthop) || ifp);
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
			 const union sockunion *nexthop_ref, uint32_t mtu)
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
		/* Fill in a blackhole nexthop */
		zapi_route_set_blackhole(&api, BLACKHOLE_REJECT);
		ifp = NULL;
		nexthop_ref = NULL;
		break;
	case NHRP_CACHE_DYNAMIC:
	case NHRP_CACHE_NHS:
	case NHRP_CACHE_STATIC:
		/* Regular route, so these are announced
		 * to other routing daemons */
		break;
	case NHRP_CACHE_INVALID:
	case NHRP_CACHE_INCOMPLETE:
		/*
		 * I cannot believe that we want to set a FIB_OVERRIDE
		 * for invalid state or incomplete.  But this matches
		 * the original code.  Someone will probably notice
		 * the problem eventually
		 */
	case NHRP_CACHE_CACHED:
	case NHRP_CACHE_LOCAL:
	case NHRP_CACHE_NUM_TYPES:
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
		if (api.prefix.prefixlen == IPV4_MAX_BITLEN &&
		    nexthop_ref &&
		    memcmp(&nexthop_ref->sin.sin_addr, &api.prefix.u.prefix4,
			   sizeof(struct in_addr)) == 0) {
			nexthop_ref = NULL;
		}
		if (nexthop_ref) {
			api_nh->gate.ipv4 = nexthop_ref->sin.sin_addr;
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
		if (api.prefix.prefixlen == IPV6_MAX_BITLEN &&
		    nexthop_ref &&
		    memcmp(&nexthop_ref->sin6.sin6_addr, &api.prefix.u.prefix6,
			   sizeof(struct in6_addr)) == 0) {
			nexthop_ref = NULL;
		}
		if (nexthop_ref) {
			api_nh->gate.ipv6 = nexthop_ref->sin6.sin6_addr;
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
		char buf[PREFIX_STRLEN];

		zlog_debug(
			"Zebra send: route %s %pFX nexthop %s metric %u count %d dev %s",
			add ? "add" : "del", &api.prefix,
			nexthop_ref ? inet_ntop(api.prefix.family,
						&api_nh->gate,
						buf, sizeof(buf))
				: "<onlink>",
			api.metric, api.nexthop_num, ifp ? ifp->name : "none");
	}

	zclient_route_send(add ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE, zclient,
			   &api);
}

int nhrp_route_read(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct interface *ifp = NULL;
	union sockunion nexthop_addr;
	int added;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	/* ignore our routes */
	if (api.type == ZEBRA_ROUTE_NHRP)
		return 0;

	/* ignore local routes */
	if (api.type == ZEBRA_ROUTE_LOCAL)
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
	debugf(NHRP_DEBUG_ROUTE, "if-route-%s: %pFX via %pSU dev %s",
	       added ? "add" : "del", &api.prefix, &nexthop_addr,
	       ifp ? ifp->name : "(none)");

	nhrp_route_update_zebra(&api.prefix, &nexthop_addr, added ? ifp : NULL);
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

	sockunion2hostprefix(addr, &lookup);

	rn = route_node_match(zebra_rib[afi], &lookup);
	if (!rn)
		return 0;

	ri = rn->info;
	if (ri->nhrp_ifp) {
		debugf(NHRP_DEBUG_ROUTE, "lookup %pFX: nhrp_if=%s", &lookup,
		       ri->nhrp_ifp->name);

		if (via)
			sockunion_family(via) = AF_UNSPEC;
		if (ifp)
			*ifp = ri->nhrp_ifp;
	} else {
		debugf(NHRP_DEBUG_ROUTE, "lookup %pFX: zebra route dev %s",
		       &lookup, ri->ifp ? ri->ifp->name : "(none)");

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
	zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP, true);
	zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP6, true);
}

static zclient_handler *const nhrp_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = nhrp_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = nhrp_interface_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = nhrp_route_read,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = nhrp_route_read,
	[ZEBRA_NEIGH_ADDED] = nhrp_neighbor_operation,
	[ZEBRA_NEIGH_REMOVED] = nhrp_neighbor_operation,
	[ZEBRA_NEIGH_GET] = nhrp_neighbor_operation,
	[ZEBRA_GRE_UPDATE] = nhrp_gre_update,
};

void nhrp_zebra_init(void)
{
	zebra_rib[AFI_IP] = route_table_init();
	zebra_rib[AFI_IP6] = route_table_init();

	zclient = zclient_new(master, &zclient_options_default, nhrp_handlers,
			      array_size(nhrp_handlers));
	zclient->zebra_connected = nhrp_zebra_connected;
	zclient_init(zclient, ZEBRA_ROUTE_NHRP, 0, &nhrpd_privs);
}

static void nhrp_table_node_cleanup(struct route_table *table,
				    struct route_node *node)
{
	if (!node->info)
		return;

	XFREE(MTYPE_NHRP_ROUTE, node->info);
}

void nhrp_send_zebra_configure_arp(struct interface *ifp, int family)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0) {
		debugf(NHRP_DEBUG_COMMON, "%s() : zclient not ready",
		       __func__);
		return;
	}
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_CONFIGURE_ARP, ifp->vrf->vrf_id);
	stream_putc(s, family);
	stream_putl(s, ifp->ifindex);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

void nhrp_send_zebra_gre_source_set(struct interface *ifp,
				    unsigned int link_idx,
				    vrf_id_t link_vrf_id)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0) {
		zlog_err("%s : zclient not ready", __func__);
		return;
	}
	if (link_idx == IFINDEX_INTERNAL || link_vrf_id == VRF_UNKNOWN) {
		/* silently ignore */
		return;
	}
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_GRE_SOURCE_SET, ifp->vrf->vrf_id);
	stream_putl(s, ifp->ifindex);
	stream_putl(s, link_idx);
	stream_putl(s, link_vrf_id);
	stream_putl(s, 0); /* mtu provisioning */
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

void nhrp_send_zebra_nbr(union sockunion *in,
			 union sockunion *out,
			 struct interface *ifp)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return;
	s = zclient->obuf;
	stream_reset(s);
	zclient_neigh_ip_encode(s, out ? ZEBRA_NEIGH_IP_ADD : ZEBRA_NEIGH_IP_DEL,
				in, out, ifp,
				out ? ZEBRA_NEIGH_STATE_REACHABLE
				    : ZEBRA_NEIGH_STATE_FAILED,
				0);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

int nhrp_send_zebra_gre_request(struct interface *ifp)
{
	return zclient_send_zebra_gre_request(zclient, ifp);
}

void nhrp_interface_update_arp(struct interface *ifp, bool arp_enable)
{
	zclient_interface_set_arp(zclient, ifp, arp_enable);
}


void nhrp_zebra_terminate(void)
{
	zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP, false);
	zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP6, false);
	zclient_stop(zclient);
	zclient_free(zclient);

	zebra_rib[AFI_IP]->cleanup = nhrp_table_node_cleanup;
	zebra_rib[AFI_IP6]->cleanup = nhrp_table_node_cleanup;
	route_table_finish(zebra_rib[AFI_IP]);
	route_table_finish(zebra_rib[AFI_IP6]);
}

int nhrp_gre_update(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct nhrp_gre_info gre_info, *val;
	struct interface *ifp;

	/* result */
	s = zclient->ibuf;
	if (vrf_id != VRF_DEFAULT)
		return 0;

	/* read GRE information */
	STREAM_GETL(s, gre_info.ifindex);
	STREAM_GETL(s, gre_info.ikey);
	STREAM_GETL(s, gre_info.okey);
	STREAM_GETL(s, gre_info.ifindex_link);
	STREAM_GETL(s, gre_info.vrfid_link);
	STREAM_GETL(s, gre_info.vtep_ip.s_addr);
	STREAM_GETL(s, gre_info.vtep_ip_remote.s_addr);
	if (gre_info.ifindex == IFINDEX_INTERNAL)
		val = NULL;
	else
		val = hash_lookup(nhrp_gre_list, &gre_info);
	if (val) {
		if (gre_info.vtep_ip.s_addr != val->vtep_ip.s_addr ||
		    gre_info.vrfid_link != val->vrfid_link ||
		    gre_info.ifindex_link != val->ifindex_link ||
		    gre_info.ikey != val->ikey ||
		    gre_info.okey != val->okey) {
			/* update */
			memcpy(val, &gre_info, sizeof(struct nhrp_gre_info));
		}
	} else {
		val = nhrp_gre_info_alloc(&gre_info);
	}
	ifp = if_lookup_by_index(gre_info.ifindex, vrf_id);
	debugf(NHRP_DEBUG_EVENT, "%s: gre interface %d vr %d obtained from system",
	       ifp ? ifp->name : "<none>", gre_info.ifindex, vrf_id);
	if (ifp)
		nhrp_interface_update_nbma(ifp, val);
	return 0;

stream_failure:
	zlog_err("%s(): error reading response ..", __func__);
	return -1;
}
