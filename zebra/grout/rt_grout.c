// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Grout routing tables
 *
 * Copyright (c) 2025 Maxime Leroy, Free Mobile
 */

#include "zebra/rib.h"
#include "zebra/table_manager.h"

#include "log_grout.h"
#include "zebra_dplane_grout.h"
#include "rt_grout.h"

static inline bool is_selfroute(gr_rt_origin_t origin)
{
	switch (origin) {
	case GR_RT_ORIGIN_ZEBRA:
	case GR_RT_ORIGIN_BABEL:
	case GR_RT_ORIGIN_BGP:
	case GR_RT_ORIGIN_ISIS:
	case GR_RT_ORIGIN_OSPF:
	case GR_RT_ORIGIN_RIP:
	case GR_RT_ORIGIN_RIPNG:
	case GR_RT_ORIGIN_NHRP:
	case GR_RT_ORIGIN_EIGRP:
	case GR_RT_ORIGIN_LDP:
	case GR_RT_ORIGIN_SHARP:
	case GR_RT_ORIGIN_PBR:
	case GR_RT_ORIGIN_ZSTATIC:
	case GR_RT_ORIGIN_OPENFABRIC:
	case GR_RT_ORIGIN_SRTE:
		return true;
	default:
		return false;
	}
}

gr_rt_origin_t zebra2origin(int proto)
{
	gr_rt_origin_t origin;

	switch (proto) {
	case ZEBRA_ROUTE_BABEL:
		origin = GR_RT_ORIGIN_BABEL;
		break;
	case ZEBRA_ROUTE_BGP:
		origin = GR_RT_ORIGIN_BGP;
		break;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		origin = GR_RT_ORIGIN_OSPF;
		break;
	case ZEBRA_ROUTE_STATIC:
		origin = GR_RT_ORIGIN_ZSTATIC;
		break;
	case ZEBRA_ROUTE_ISIS:
		origin = GR_RT_ORIGIN_ISIS;
		break;
	case ZEBRA_ROUTE_RIP:
		origin = GR_RT_ORIGIN_RIP;
		break;
	case ZEBRA_ROUTE_RIPNG:
		origin = GR_RT_ORIGIN_RIPNG;
		break;
	case ZEBRA_ROUTE_NHRP:
		origin = GR_RT_ORIGIN_NHRP;
		break;
	case ZEBRA_ROUTE_EIGRP:
		origin = GR_RT_ORIGIN_EIGRP;
		break;
	case ZEBRA_ROUTE_LDP:
		origin = GR_RT_ORIGIN_LDP;
		break;
	case ZEBRA_ROUTE_SHARP:
		origin = GR_RT_ORIGIN_SHARP;
		break;
	case ZEBRA_ROUTE_PBR:
		origin = GR_RT_ORIGIN_PBR;
		break;
	case ZEBRA_ROUTE_OPENFABRIC:
		origin = GR_RT_ORIGIN_OPENFABRIC;
		break;
	case ZEBRA_ROUTE_SRTE:
		origin = GR_RT_ORIGIN_SRTE;
		break;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		origin = GR_RT_ORIGIN_ZEBRA;
		break;
	case ZEBRA_ROUTE_CONNECT:
	case ZEBRA_ROUTE_LOCAL:
	case ZEBRA_ROUTE_KERNEL:
		origin = GR_RT_ORIGIN_LINK;
		break;
	default:
		/*
		 * When a user adds a new protocol this will show up
		 * to let them know to do something about it.  This
		 * is intentionally a warn because we should see
		 * this as part of development of a new protocol
		 */
		gr_log_debug("Please add this protocol(%d) to grout", proto);
		origin = GR_RT_ORIGIN_ZEBRA;
		break;
	}

	return origin;
}

static inline int origin2zebra(gr_rt_origin_t origin, int family, bool is_nexthop)
{
	int proto;

	switch (origin) {
	case GR_RT_ORIGIN_BABEL:
		proto = ZEBRA_ROUTE_BABEL;
		break;
	case GR_RT_ORIGIN_BGP:
		proto = ZEBRA_ROUTE_BGP;
		break;
	case GR_RT_ORIGIN_OSPF:
		proto = (family == AF_INET) ? ZEBRA_ROUTE_OSPF : ZEBRA_ROUTE_OSPF6;
		break;
	case GR_RT_ORIGIN_ISIS:
		proto = ZEBRA_ROUTE_ISIS;
		break;
	case GR_RT_ORIGIN_RIP:
		proto = ZEBRA_ROUTE_RIP;
		break;
	case GR_RT_ORIGIN_RIPNG:
		proto = ZEBRA_ROUTE_RIPNG;
		break;
	case GR_RT_ORIGIN_NHRP:
		proto = ZEBRA_ROUTE_NHRP;
		break;
	case GR_RT_ORIGIN_EIGRP:
		proto = ZEBRA_ROUTE_EIGRP;
		break;
	case GR_RT_ORIGIN_LDP:
		proto = ZEBRA_ROUTE_LDP;
		break;
	case GR_RT_ORIGIN_ZSTATIC:
		proto = ZEBRA_ROUTE_STATIC;
		break;
	case GR_RT_ORIGIN_SHARP:
		proto = ZEBRA_ROUTE_SHARP;
		break;
	case GR_RT_ORIGIN_PBR:
		proto = ZEBRA_ROUTE_PBR;
		break;
	case GR_RT_ORIGIN_OPENFABRIC:
		proto = ZEBRA_ROUTE_OPENFABRIC;
		break;
	case GR_RT_ORIGIN_SRTE:
		proto = ZEBRA_ROUTE_SRTE;
		break;
	case GR_RT_ORIGIN_USER:
	case GR_RT_ORIGIN_UNSPEC:
	case GR_RT_ORIGIN_REDIRECT:
	case GR_RT_ORIGIN_LINK:
	case GR_RT_ORIGIN_BOOT:
	case GR_RT_ORIGIN_GATED:
	case GR_RT_ORIGIN_RA:
	case GR_RT_ORIGIN_MRT:
	case GR_RT_ORIGIN_BIRD:
	case GR_RT_ORIGIN_DNROUTED:
	case GR_RT_ORIGIN_XORP:
	case GR_RT_ORIGIN_NTK:
	case GR_RT_ORIGIN_MROUTED:
	case GR_RT_ORIGIN_KEEPALIVED:
	case GR_RT_ORIGIN_OPENR:
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	case GR_RT_ORIGIN_ZEBRA:
		if (is_nexthop) {
			proto = ZEBRA_ROUTE_NHG;
			break;
		}
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	default:
		/*
		 * When a user adds a new protocol this will show up
		 * to let them know to do something about it.  This
		 * is intentionally a warn because we should see
		 * this as part of development of a new protocol
		 */
		gr_log_debug("Please add this protocol(%d) to grout", proto);
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
}

static void grout_route_change(bool new, uint16_t vrf_id, gr_rt_origin_t origin, uint16_t family,
			       void *nh_addr, void *dest_addr, uint8_t dest_prefixlen)
{
	int tableid = RT_TABLE_ID_MAIN; /* no table support for now */
	int proto = ZEBRA_ROUTE_KERNEL;
	struct nexthop nh = {};
	uint32_t flags = 0;
	struct prefix p;
	bool selfroute;
	int index = 0;
	size_t sz;
	afi_t afi;

	if (vrf_id != VRF_DEFAULT) {
		gr_log_debug("no vrf support for route, route not sync");
		return;
	}

	if (family == AF_INET)
		gr_log_debug("get notifcation '%s route %pI4/%u (origin %s)'", new ? "add" : "del",
			     dest_addr, dest_prefixlen, gr_rt_origin_name(origin));
	else
		gr_log_debug("get notifcation '%s route %pI6/%u (origin %s)'", new ? "add" : "del",
			     dest_addr, dest_prefixlen, gr_rt_origin_name(origin));

	if (new && is_selfroute(origin)) {
		gr_log_debug("'%s' route received that we think we have originated, ignoring",
			     gr_rt_origin_name(origin));
		return;
	}

	if (origin == GR_RT_ORIGIN_LINK) {
		gr_log_debug("'%s' route intentionally ignoring", gr_rt_origin_name(origin));
		return;
	}

	/* A method to ignore our own messages. selfroute ? */
	memset(&nh, 0, sizeof(nh));
	nh.vrf_id = VRF_DEFAULT;

	if (family == AF_INET) {
		afi = AFI_IP;
		p.family = AF_INET;
		sz = 4;

		memcpy(&p.u.prefix4, dest_addr, sz);
		p.prefixlen = dest_prefixlen;

		/* FIX IFINDEX CASE */
		nh.type = NEXTHOP_TYPE_IPV4;
		memcpy(&nh.gate.ipv4, nh_addr, sz);
	} else {
		afi = AFI_IP6;
		p.family = AF_INET6;
		sz = 16;

		memcpy(&p.u.prefix6, dest_addr, sz);
		p.prefixlen = dest_prefixlen;

		/* FIX IFINDEX CASE */
		nh.type = NEXTHOP_TYPE_IPV6;
		memcpy(&nh.gate.ipv6, nh_addr, sz);
	}

	proto = origin2zebra(origin, family, false);

	if (new)
		rib_add(afi, SAFI_UNICAST, VRF_DEFAULT, proto, 0, flags, &p, NULL, &nh, 0, tableid,
			0, 0, 0, 0, false);
	else
		rib_delete(afi, SAFI_UNICAST, VRF_DEFAULT, proto, 0, flags, &p, NULL, &nh, 0,
			   tableid, 0, 0, true);
}

void grout_route4_change(bool new, struct gr_ip4_route *gr_r4)
{
	grout_route_change(new, gr_r4->vrf_id, gr_r4->origin, AF_INET, (void *)&gr_r4->nh,
			   (void *)&gr_r4->dest.ip, gr_r4->dest.prefixlen);
}

void grout_route6_change(bool new, struct gr_ip6_route *gr_r6)
{
	grout_route_change(new, gr_r6->vrf_id, gr_r6->origin, AF_INET6, (void *)&gr_r6->nh,
			   (void *)&gr_r6->dest.ip, gr_r6->dest.prefixlen);
}

enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx)
{
	union {
		struct gr_ip4_route_add_req r4_add;
		struct gr_ip4_route_del_req r4_del;
		struct gr_ip6_route_add_req r6_add;
		struct gr_ip6_route_del_req r6_del;
	} req;
	const struct nexthop_group *ng;
	enum nexthop_types_t nt = 0;
	const struct prefix *p;
	gr_rt_origin_t origin;
	uint32_t req_type;
	size_t req_len;
	bool new;

	if (dplane_ctx_get_vrf(ctx) != 0) {
		gr_log_err("impossssible to add/del route on vrf %u (vrf not supported)",
			   dplane_ctx_get_vrf(ctx));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	p = dplane_ctx_get_dest(ctx);
	if (p->family != AF_INET && p->family != AF_INET6) {
		gr_log_err("impossssible to add/del route with family %u (not supported)",
			   p->family);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (dplane_ctx_get_src(ctx) != NULL) {
		gr_log_err("impossssible to add/del route with src (not supported)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	ng = dplane_ctx_get_ng(ctx);
	if (nexthop_group_nexthop_num(ng) > 1) {
		gr_log_err("impossssible to add/del route with several nexthop (not supported)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	if (nexthop_group_nexthop_num(ng) == 0) {
		gr_log_err("impossssible to add/del route with no nexthop (not supported)");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	nt = ng->nexthop->type;
	if (nt == NEXTHOP_TYPE_BLACKHOLE) {
		gr_log_err("impossssible to add/del route with nexthope type = %u (not supported)",
			   nt);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	/* TODO: other check for metric, distance, and so-on */

	origin = zebra2origin(dplane_ctx_get_type(ctx));
	new = dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE;
	if (p->family == AF_INET) {
		struct ip4_net *dest;

		if (nt == NEXTHOP_TYPE_IPV6 || nt == NEXTHOP_TYPE_IPV6_IFINDEX) {
			gr_log_err("impossssible to add/del ipv4 route with nexthope type = %u (not supported)",
				   nt);
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		if (new) {
			req.r4_add = (struct gr_ip4_route_add_req){ .exist_ok = true, .vrf_id = 0 };

			req_type = GR_IP4_ROUTE_ADD;
			req_len = sizeof(struct gr_ip4_route_add_req);

			if (nt == NEXTHOP_TYPE_IFINDEX || nt == NEXTHOP_TYPE_IPV4_IFINDEX)
				/* TOFIX with next API in grout */
				req.r4_add.nh = p->u.prefix4.s_addr;
			if (nt == NEXTHOP_TYPE_IPV4 || nt == NEXTHOP_TYPE_IPV4_IFINDEX)
				req.r4_add.nh = ng->nexthop->gate.ipv4.s_addr;
			req.r4_add.origin = origin;
			dest = &req.r4_add.dest;
		} else {
			req.r4_del = (struct gr_ip4_route_del_req){ .missing_ok = true,
								    .vrf_id = 0 };
			req_type = GR_IP4_ROUTE_DEL;
			req_len = sizeof(struct gr_ip4_route_del_req);

			dest = &req.r4_del.dest;
			new = false;
		}

		dest->ip = p->u.prefix4.s_addr;
		dest->prefixlen = p->prefixlen;

		gr_log_debug("%s route %pI4/%u (origin %s)", new ? "add" : "del", &dest->ip,
			     dest->prefixlen, gr_rt_origin_name(origin));
	} else {
		struct ip6_net *dest;

		if (nt == NEXTHOP_TYPE_IPV4 || nt == NEXTHOP_TYPE_IPV4_IFINDEX) {
			gr_log_err("impossssible to add/del ipv6 route with nexthope type = %u (not supported)",
				   nt);
			return ZEBRA_DPLANE_REQUEST_FAILURE;
		}

		if (new) {
			req.r6_add = (struct gr_ip6_route_add_req){ .exist_ok = true, .vrf_id = 0 };

			req_type = GR_IP6_ROUTE_ADD;
			req_len = sizeof(struct gr_ip6_route_add_req);

			if (nt == NEXTHOP_TYPE_IFINDEX || nt == NEXTHOP_TYPE_IPV6_IFINDEX)
				/* TOFIX with next API in grout */
				memcpy(req.r6_add.nh.a, p->u.prefix6.s6_addr,
				       sizeof(req.r6_add.nh));
			req.r4_add.nh = p->u.prefix4.s_addr;
			if (nt == NEXTHOP_TYPE_IPV6 || nt == NEXTHOP_TYPE_IPV6_IFINDEX)
				memcpy(req.r6_add.nh.a, ng->nexthop->gate.ipv6.s6_addr,
				       sizeof(req.r6_add.nh));
			req.r6_add.origin = origin;
			dest = &req.r6_add.dest;
		} else {
			req.r6_del = (struct gr_ip6_route_del_req){ .missing_ok = true,
								    .vrf_id = 0 };

			req_type = GR_IP6_ROUTE_ADD;
			req_len = sizeof(struct gr_ip6_route_add_req);

			dest = &req.r6_del.dest;
			new = false;
		}

		memcpy(dest->ip.a, p->u.prefix6.s6_addr, sizeof(dest->ip.a));
		dest->prefixlen = p->prefixlen;

		gr_log_debug("%s route %pI6/%u (origin %s)", new ? "add" : "del", &dest->ip,
			     dest->prefixlen, gr_rt_origin_name(origin));
	}

	if (!is_selfroute(origin)) {
		gr_log_debug("no frr route, skip it");
		return ZEBRA_DPLANE_REQUEST_SUCCESS;
	}

	if (grout_client_send_recv(req_type, req_len, &req, NULL) < 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}
