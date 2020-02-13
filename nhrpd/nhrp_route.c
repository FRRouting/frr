/* NHRP routing functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
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

struct route_info {
	union sockunion via;
	struct interface *ifp;
	struct interface *nhrp_ifp;
};

static struct route_node *nhrp_route_update_get(const struct prefix *p,
						int create,
						struct nhrp_vrf *nhrp_vrf)
{
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	if (!nhrp_vrf->zebra_rib[afi])
		return NULL;

	if (create) {
		rn = route_node_get(nhrp_vrf->zebra_rib[afi], p);
		if (!rn->info) {
			rn->info = XCALLOC(MTYPE_NHRP_ROUTE,
					   sizeof(struct route_info));
			route_lock_node(rn);
		}
		return rn;
	} else {
		return route_node_lookup(nhrp_vrf->zebra_rib[afi], p);
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
				    struct interface *ifp,
				    struct nhrp_vrf *nhrp_vrf)
{
	struct route_node *rn;
	struct route_info *ri;

	rn = nhrp_route_update_get(p, !sockunion_is_null(nexthop) || ifp,
				   nhrp_vrf);
	if (rn) {
		ri = rn->info;
		ri->via = *nexthop;
		ri->ifp = ifp;
		nhrp_route_update_put(rn);
	}
}

static void nhrp_zebra_register_neigh(vrf_id_t vrf_id, afi_t afi, bool reg)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, reg ? ZEBRA_NHRP_NEIGH_REGISTER :
			      ZEBRA_NHRP_NEIGH_UNREGISTER,
			      vrf_id);
	stream_putw(s, afi);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

void nhrp_route_update_nhrp(const struct prefix *p, struct interface *ifp,
			    struct nhrp_vrf *nhrp_vrf)
{
	struct route_node *rn;
	struct route_info *ri;

	rn = nhrp_route_update_get(p, ifp != NULL, nhrp_vrf);
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
	union sockunion *nexthop_ref = (union sockunion *)nexthop;

	if (zclient->sock < 0)
		return;

	memset(&api, 0, sizeof(api));
	api.type = ZEBRA_ROUTE_NHRP;
	api.safi = SAFI_UNICAST;
	if (ifp)
		api.vrf_id = ifp->vrf_id;
	else
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
	api_nh->vrf_id = api.vrf_id;

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
	struct nhrp_vrf *nhrp_vrf;


	nhrp_vrf  = find_nhrp_vrf_id(vrf_id);
	if (!nhrp_vrf) {
		zlog_err("%s(): nhrp_vrf not found", __func__);
		return -1;
	}
	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	/* ignore our routes */
	if (api.type == ZEBRA_ROUTE_NHRP)
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
			ifp = if_lookup_by_index(api_nh->ifindex, vrf_id);
	}

	added = (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD);
	debugf(NHRP_DEBUG_ROUTE, "%d: if-route-%s: %pFX via %pSU dev %s",
	       vrf_id, added ? "add" : "del", &api.prefix, &nexthop_addr,
	       ifp ? ifp->name : "(none)");

	nhrp_route_update_zebra(&api.prefix, &nexthop_addr, added ? ifp : NULL,
				nhrp_vrf);
	nhrp_shortcut_prefix_change(&api.prefix, !added, nhrp_vrf);

	return 0;
}

int nhrp_route_get_nexthop(const union sockunion *addr, struct prefix *p,
			   union sockunion *via, struct interface **ifp,
			   struct nhrp_vrf *nhrp_vrf)
{
	struct route_node *rn;
	struct route_info *ri;
	struct prefix lookup;
	afi_t afi = family2afi(sockunion_family(addr));

	sockunion2hostprefix(addr, &lookup);

	rn = route_node_match(nhrp_vrf->zebra_rib[afi], &lookup);
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
					struct nhrp_peer **peer,
					struct nhrp_vrf *nhrp_vrf)
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
		if (!nhrp_route_get_nexthop(addr, p, &via[i], &ifp, nhrp_vrf))
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
	nhrp_zebra_register_neigh(VRF_DEFAULT, AFI_IP, true);
	nhrp_zebra_register_neigh(VRF_DEFAULT, AFI_IP6, true);
}

void nhrp_route_init(struct nhrp_vrf *nhrp_vrf)
{
	nhrp_vrf->zebra_rib[AFI_IP] = route_table_init();
	nhrp_vrf->zebra_rib[AFI_IP6] = route_table_init();
}

void nhrp_zebra_register_log(vrf_id_t vrf_id, int group, bool reg)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0)
		return;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, reg ? ZEBRA_NFLOG_REGISTER :
			      ZEBRA_NFLOG_UNREGISTER,
			      vrf_id);
	stream_putl(s, group);

	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

static int nhrp_nflog_traffic_indication(int command, struct zclient *zclient,
					 uint16_t length, vrf_id_t vrf_id)
{
	ifindex_t idx;
	struct interface *ifp;
	uint16_t protocol_type;
	unsigned int len_payload;
	char buf[ZEBRA_MAX_PACKET_SIZ];

	STREAM_GETL(zclient->ibuf, idx);
	ifp = if_lookup_by_index(idx, vrf_id);
	if (!ifp) {
		debugf(NHRP_DEBUG_KERNEL,
		       "%s: Rx message. Interface not found ( index %u, vr %u)",
		       __func__, idx, vrf_id);
		return 0;
	}
	STREAM_GETW(zclient->ibuf, protocol_type);
	STREAM_GETL(zclient->ibuf, len_payload);
	if (len_payload == 0 || len_payload > ZEBRA_MAX_PACKET_SIZ) {
		debugf(NHRP_DEBUG_KERNEL,
		       "%s: Rx message (interface %s): Invalid payload length %u",
		       __func__, ifp->name, len_payload);
		return 0;
	}
	memset(buf, 0, sizeof(buf));
	STREAM_GET(buf, zclient->ibuf, len_payload);
	debugf(NHRP_DEBUG_KERNEL,
	       "%s: Rx message (interface %s): pkt len %d protocol type %d",
	       __func__, ifp->name, len_payload, protocol_type);
	nhrp_peer_send_indication(ifp, protocol_type, buf, len_payload);

 stream_failure:
	return 0;
}

void nhrp_zebra_init(void)
{

	zclient = zclient_new(master, &zclient_options_default);
	zclient->zebra_connected = nhrp_zebra_connected;
	zclient->interface_address_add = nhrp_interface_address_add;
	zclient->interface_address_delete = nhrp_interface_address_delete;
	zclient->redistribute_route_add = nhrp_route_read;
	zclient->redistribute_route_del = nhrp_route_read;
	zclient->neighbor_added = nhrp_neighbor_operation;
	zclient->neighbor_removed = nhrp_neighbor_operation;
	zclient->neighbor_get = nhrp_neighbor_operation;
	zclient->gre_update = nhrp_gre_update;
	zclient->nflog_traffic_indication = nhrp_nflog_traffic_indication;
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
	zclient_create_header(s,
			      ZEBRA_CONFIGURE_ARP,
			      ifp->vrf_id);
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
	zclient_create_header(s,
			      ZEBRA_GRE_SOURCE_SET,
			      ifp->vrf_id);
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
	zclient_neigh_ip_encode(s, out ? ZEBRA_NEIGH_IP_ADD :
				ZEBRA_NEIGH_IP_DEL, in, out,
				ifp);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

int nhrp_send_zebra_gre_request(struct interface *ifp)
{
	return zclient_send_zebra_gre_request(zclient, ifp);
}

void nhrp_send_zebra_interface_redirect(struct interface *ifp,
					int af)
{
	struct stream *s;

	if (!zclient || zclient->sock < 0) {
		zlog_err("%s : zclient not ready", __func__);
		return;
	}
	s = zclient->obuf;
	stream_reset(s);
	zclient_create_header(s,
			      ZEBRA_REDIRECT_INTERFACE,
			      ifp->vrf_id);
	stream_putl(s, ifp->ifindex);
	stream_putl(s, af);
	stream_putl(s, 0);
	stream_putw_at(s, 0, stream_get_endp(s));
	zclient_send_message(zclient);
}

void nhrp_zebra_terminate_zclient(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}

void nhrp_zebra_terminate(struct nhrp_vrf *nhrp_vrf)
{
	nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP, false);
	nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP6, false);

	nhrp_vrf->zebra_rib[AFI_IP]->cleanup = nhrp_table_node_cleanup;
	nhrp_vrf->zebra_rib[AFI_IP6]->cleanup = nhrp_table_node_cleanup;
	route_table_finish(nhrp_vrf->zebra_rib[AFI_IP]);
	route_table_finish(nhrp_vrf->zebra_rib[AFI_IP6]);
}

void nhrp_gre_update(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	struct nhrp_gre_info gre_info, *val;
	struct interface *ifp;
	struct nhrp_vrf *nhrp_vrf;

	/* result */
	s = zclient->ibuf;

	nhrp_vrf = find_nhrp_vrf_id(vrf_id);
	if (!nhrp_vrf) {
		zlog_err("%s() : nhrp vrf not found for vrf %u",
			 __func__, vrf_id);
		return;
	}

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
		val = hash_lookup(nhrp_vrf->nhrp_gre_list, &gre_info);
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
		val = nhrp_gre_info_alloc(&gre_info, nhrp_vrf);
	}
	ifp = if_lookup_by_index(gre_info.ifindex, vrf_id);
	debugf(NHRP_DEBUG_EVENT, "%s: gre interface %d vr %d obtained from system",
	       ifp ? ifp->name : "<none>", gre_info.ifindex, vrf_id);
	if (ifp)
		nhrp_interface_update_nbma(ifp, val);
	return;
stream_failure:
	zlog_err("%s(): error reading response ..", __func__);
}

void nhrp_instance_register(struct nhrp_vrf *nhrp_vrf, bool on)
{
	if (nhrp_vrf->vrf_id == VRF_UNKNOWN)
		return;
	if (on) {
		zclient_send_reg_requests(zclient, nhrp_vrf->vrf_id);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
					ZEBRA_ROUTE_ALL, 0, nhrp_vrf->vrf_id);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6,
					ZEBRA_ROUTE_ALL, 0, nhrp_vrf->vrf_id);
		nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP, true);
		nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP6, true);
	} else {
		nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP, false);
		nhrp_zebra_register_neigh(nhrp_vrf->vrf_id, AFI_IP6, false);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP,
					ZEBRA_ROUTE_ALL, 0, nhrp_vrf->vrf_id);
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP6,
					ZEBRA_ROUTE_ALL, 0, nhrp_vrf->vrf_id);
		zclient_send_dereg_requests(zclient, nhrp_vrf->vrf_id);
	}
}
