/* Kernel routing table updates using netlink over GNU/Linux system.
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

#ifdef HAVE_NETLINK

#include <net/if_arp.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "vty.h"
#include "mpls.h"
#include "vxlan.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_mpls.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mroute.h"
#include "zebra/zebra_vxlan.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif

static vlanid_t filter_vlan = 0;

struct gw_family_t {
	u_int16_t filler;
	u_int16_t family;
	union g_addr gate;
};

char ipv4_ll_buf[16] = "169.254.0.1";
struct in_addr ipv4_ll;

/*
 * The ipv4_ll data structure is used for all 5549
 * additions to the kernel.  Let's figure out the
 * correct value one time instead for every
 * install/remove of a 5549 type route
 */
void rt_netlink_init(void)
{
	inet_pton(AF_INET, ipv4_ll_buf, &ipv4_ll);
}

static inline int is_selfroute(int proto)
{
	if ((proto == RTPROT_BGP) || (proto == RTPROT_OSPF)
	    || (proto == RTPROT_STATIC) || (proto == RTPROT_ZEBRA)
	    || (proto == RTPROT_ISIS) || (proto == RTPROT_RIPNG)
	    || (proto == RTPROT_NHRP) || (proto == RTPROT_EIGRP)
	    || (proto == RTPROT_LDP) || (proto == RTPROT_BABEL)
	    || (proto == RTPROT_RIP) || (proto == RTPROT_SHARP)) {
		return 1;
	}

	return 0;
}

static inline int zebra2proto(int proto)
{
	switch (proto) {
	case ZEBRA_ROUTE_BABEL:
		proto = RTPROT_BABEL;
		break;
	case ZEBRA_ROUTE_BGP:
		proto = RTPROT_BGP;
		break;
	case ZEBRA_ROUTE_OSPF:
	case ZEBRA_ROUTE_OSPF6:
		proto = RTPROT_OSPF;
		break;
	case ZEBRA_ROUTE_STATIC:
		proto = RTPROT_STATIC;
		break;
	case ZEBRA_ROUTE_ISIS:
		proto = RTPROT_ISIS;
		break;
	case ZEBRA_ROUTE_RIP:
		proto = RTPROT_RIP;
		break;
	case ZEBRA_ROUTE_RIPNG:
		proto = RTPROT_RIPNG;
		break;
	case ZEBRA_ROUTE_NHRP:
		proto = RTPROT_NHRP;
		break;
	case ZEBRA_ROUTE_EIGRP:
		proto = RTPROT_EIGRP;
		break;
	case ZEBRA_ROUTE_LDP:
		proto = RTPROT_LDP;
		break;
	case ZEBRA_ROUTE_SHARP:
		proto = RTPROT_SHARP;
		break;
	default:
		proto = RTPROT_ZEBRA;
		break;
	}

	return proto;
}

static inline int proto2zebra(int proto, int family)
{
	switch (proto) {
	case RTPROT_BABEL:
		proto = ZEBRA_ROUTE_BABEL;
		break;
	case RTPROT_BGP:
		proto = ZEBRA_ROUTE_BGP;
		break;
	case RTPROT_OSPF:
		proto = (family == AFI_IP) ?
			ZEBRA_ROUTE_OSPF : ZEBRA_ROUTE_OSPF6;
		break;
	case RTPROT_ISIS:
		proto = ZEBRA_ROUTE_ISIS;
		break;
	case RTPROT_RIP:
		proto = ZEBRA_ROUTE_RIP;
		break;
	case RTPROT_RIPNG:
		proto = ZEBRA_ROUTE_RIPNG;
		break;
	case RTPROT_NHRP:
		proto = ZEBRA_ROUTE_NHRP;
		break;
	case RTPROT_EIGRP:
		proto = ZEBRA_ROUTE_EIGRP;
		break;
	case RTPROT_LDP:
		proto = ZEBRA_ROUTE_LDP;
		break;
	case RTPROT_STATIC:
		proto = ZEBRA_ROUTE_STATIC;
		break;
	default:
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
}

/*
Pending: create an efficient table_id (in a tree/hash) based lookup)
 */
static vrf_id_t vrf_lookup_by_table(u_int32_t table_id)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		if ((zvrf = vrf->info) == NULL || (zvrf->table_id != table_id))
			continue;

		return zvrf_id(zvrf);
	}

	return VRF_DEFAULT;
}

/* Looking up routing table by netlink interface. */
static int netlink_route_change_read_unicast(struct sockaddr_nl *snl,
					     struct nlmsghdr *h, ns_id_t ns_id,
					     int startup)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	u_char flags = 0;
	struct prefix p;
	struct prefix_ipv6 src_p = {};
	vrf_id_t vrf_id = VRF_DEFAULT;

	char anyaddr[16] = {0};

	int proto = ZEBRA_ROUTE_KERNEL;
	int index = 0;
	int table;
	int metric = 0;
	u_int32_t mtu = 0;
	uint8_t distance = 0;
	route_tag_t tag = 0;

	void *dest = NULL;
	void *gate = NULL;
	void *prefsrc = NULL; /* IPv4 preferred source host address */
	void *src = NULL;     /* IPv6 srcdest   source prefix */
	enum blackhole_type bh_type = BLACKHOLE_UNSPEC;

	rtm = NLMSG_DATA(h);

	if (startup && h->nlmsg_type != RTM_NEWROUTE)
		return 0;
	switch (rtm->rtm_type) {
	case RTN_UNICAST:
		break;
	case RTN_BLACKHOLE:
		bh_type = BLACKHOLE_NULL;
		break;
	case RTN_UNREACHABLE:
		bh_type = BLACKHOLE_REJECT;
		break;
	case RTN_PROHIBIT:
		bh_type = BLACKHOLE_ADMINPROHIB;
		break;
	default:
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0)
		return -1;

	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (rtm->rtm_flags & RTM_F_CLONED)
		return 0;
	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return 0;
	if (rtm->rtm_protocol == RTPROT_KERNEL)
		return 0;

	if (!startup && is_selfroute(rtm->rtm_protocol)
	    && h->nlmsg_type == RTM_NEWROUTE)
		return 0;

	/* We don't care about change notifications for the MPLS table. */
	/* TODO: Revisit this. */
	if (rtm->rtm_family == AF_MPLS)
		return 0;

	/* Table corresponding to route. */
	if (tb[RTA_TABLE])
		table = *(int *)RTA_DATA(tb[RTA_TABLE]);
	else
		table = rtm->rtm_table;

	/* Map to VRF */
	vrf_id = vrf_lookup_by_table(table);
	if (vrf_id == VRF_DEFAULT) {
		if (!is_zebra_valid_kernel_table(table)
		    && !is_zebra_main_routing_table(table))
			return 0;
	}

	/* Route which inserted by Zebra. */
	if (is_selfroute(rtm->rtm_protocol)) {
		flags |= ZEBRA_FLAG_SELFROUTE;
		proto = proto2zebra(rtm->rtm_protocol, rtm->rtm_family);
	}
	if (tb[RTA_OIF])
		index = *(int *)RTA_DATA(tb[RTA_OIF]);

	if (tb[RTA_DST])
		dest = RTA_DATA(tb[RTA_DST]);
	else
		dest = anyaddr;

	if (tb[RTA_SRC])
		src = RTA_DATA(tb[RTA_SRC]);
	else
		src = anyaddr;

	if (tb[RTA_PREFSRC])
		prefsrc = RTA_DATA(tb[RTA_PREFSRC]);

	if (tb[RTA_GATEWAY])
		gate = RTA_DATA(tb[RTA_GATEWAY]);

	if (tb[RTA_PRIORITY])
		metric = *(int *)RTA_DATA(tb[RTA_PRIORITY]);

#if defined(SUPPORT_REALMS)
	if (tb[RTA_FLOW])
		tag = *(uint32_t *)RTA_DATA(tb[RTA_FLOW]);
#endif

	if (tb[RTA_METRICS]) {
		struct rtattr *mxrta[RTAX_MAX + 1];

		memset(mxrta, 0, sizeof mxrta);
		netlink_parse_rtattr(mxrta, RTAX_MAX,
				     RTA_DATA(tb[RTA_METRICS]),
				     RTA_PAYLOAD(tb[RTA_METRICS]));

		if (mxrta[RTAX_MTU])
			mtu = *(u_int32_t *)RTA_DATA(mxrta[RTAX_MTU]);
	}

	if (rtm->rtm_family == AF_INET) {
		p.family = AF_INET;
		memcpy(&p.u.prefix4, dest, 4);
		p.prefixlen = rtm->rtm_dst_len;

		src_p.prefixlen =
			0; // Forces debug below to not display anything
	} else if (rtm->rtm_family == AF_INET6) {
		p.family = AF_INET6;
		memcpy(&p.u.prefix6, dest, 16);
		p.prefixlen = rtm->rtm_dst_len;

		src_p.family = AF_INET6;
		memcpy(&src_p.prefix, src, 16);
		src_p.prefixlen = rtm->rtm_src_len;
	}

	if (rtm->rtm_src_len != 0) {
		char buf[PREFIX_STRLEN];
		zlog_warn(
			"unsupported IPv[4|6] sourcedest route (dest %s vrf %u)",
			prefix2str(&p, buf, sizeof(buf)), vrf_id);
		return 0;
	}

	/*
	 * For ZEBRA_ROUTE_KERNEL types:
	 *
	 * The metric/priority of the route received from the kernel
	 * is a 32 bit number.  We are going to interpret the high
	 * order byte as the Admin Distance and the low order 3 bytes
	 * as the metric.
	 *
	 * This will allow us to do two things:
	 * 1) Allow the creation of kernel routes that can be
	 *    overridden by zebra.
	 * 2) Allow the old behavior for 'most' kernel route types
	 *    if a user enters 'ip route ...' v4 routes get a metric
	 *    of 0 and v6 routes get a metric of 1024.  Both of these
	 *    values will end up with a admin distance of 0, which
	 *    will cause them to win for the purposes of zebra.
	 */
	if (proto == ZEBRA_ROUTE_KERNEL) {
		distance = (metric >> 24) & 0xFF;
		metric   = (metric & 0x00FFFFFF);
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf[PREFIX_STRLEN];
		char buf2[PREFIX_STRLEN];
		zlog_debug(
			"%s %s%s%s vrf %u metric: %d Admin Distance: %d", nl_msg_type_to_str(h->nlmsg_type),
			prefix2str(&p, buf, sizeof(buf)),
			src_p.prefixlen ? " from " : "",
			src_p.prefixlen ? prefix2str(&src_p, buf2, sizeof(buf2))
					: "",
			vrf_id, metric, distance);
	}

	afi_t afi = AFI_IP;
	if (rtm->rtm_family == AF_INET6)
		afi = AFI_IP6;

	if (h->nlmsg_type == RTM_NEWROUTE) {
		struct interface *ifp;
		vrf_id_t nh_vrf_id = vrf_id;

		if (!tb[RTA_MULTIPATH]) {
			struct nexthop nh;
			size_t sz = (afi == AFI_IP) ? 4 : 16;

			memset(&nh, 0, sizeof(nh));

			if (bh_type == BLACKHOLE_UNSPEC) {
				if (index && !gate)
					nh.type = NEXTHOP_TYPE_IFINDEX;
				else if (index && gate)
					nh.type = (afi == AFI_IP)
						? NEXTHOP_TYPE_IPV4_IFINDEX
						: NEXTHOP_TYPE_IPV6_IFINDEX;
				else if (!index && gate)
					nh.type = (afi == AFI_IP)
							  ? NEXTHOP_TYPE_IPV4
							  : NEXTHOP_TYPE_IPV6;
				else {
					nh.type = NEXTHOP_TYPE_BLACKHOLE;
					nh.bh_type = bh_type;
				}
			} else {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = bh_type;
			}
			nh.ifindex = index;
			if (prefsrc)
				memcpy(&nh.src, prefsrc, sz);
			if (gate)
				memcpy(&nh.gate, gate, sz);

			if (index) {
				ifp = if_lookup_by_index(index,
							 VRF_UNKNOWN);
				if (ifp)
					nh_vrf_id = ifp->vrf_id;
			}

			rib_add(afi, SAFI_UNICAST, vrf_id, nh_vrf_id, proto,
				0, flags, &p, NULL, &nh, table, metric,
				mtu, distance, tag);
		} else {
			/* This is a multipath route */

			struct route_entry *re;
			struct rtnexthop *rtnh =
				(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);

			len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);

			re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
			re->type = proto;
			re->distance = distance;
			re->flags = flags;
			re->metric = metric;
			re->mtu = mtu;
			re->vrf_id = vrf_id;
			re->nh_vrf_id = vrf_id;
			re->table = table;
			re->nexthop_num = 0;
			re->uptime = time(NULL);
			re->tag = tag;

			for (;;) {
				if (len < (int)sizeof(*rtnh)
				    || rtnh->rtnh_len > len)
					break;

				index = rtnh->rtnh_ifindex;
				if (index) {
					/*
					 * Yes we are looking this up
					 * for every nexthop and just
					 * using the last one looked
					 * up right now
					 */
					ifp = if_lookup_by_index(index,
								 VRF_UNKNOWN);
					if (ifp)
						re->nh_vrf_id = ifp->vrf_id;
				}
				gate = 0;
				if (rtnh->rtnh_len > sizeof(*rtnh)) {
					memset(tb, 0, sizeof(tb));
					netlink_parse_rtattr(
						tb, RTA_MAX, RTNH_DATA(rtnh),
						rtnh->rtnh_len - sizeof(*rtnh));
					if (tb[RTA_GATEWAY])
						gate = RTA_DATA(
							tb[RTA_GATEWAY]);
				}

				if (gate) {
					if (rtm->rtm_family == AF_INET) {
						if (index)
							route_entry_nexthop_ipv4_ifindex_add(
								re, gate,
								prefsrc, index);
						else
							route_entry_nexthop_ipv4_add(
								re, gate,
								prefsrc);
					} else if (rtm->rtm_family
						   == AF_INET6) {
						if (index)
							route_entry_nexthop_ipv6_ifindex_add(
								re, gate,
								index);
						else
							route_entry_nexthop_ipv6_add(
								re, gate);
					}
				} else
					route_entry_nexthop_ifindex_add(re,
									index);

				len -= NLMSG_ALIGN(rtnh->rtnh_len);
				rtnh = RTNH_NEXT(rtnh);
			}

			zserv_nexthop_num_warn(__func__,
					       (const struct prefix *)&p,
					       re->nexthop_num);
			if (re->nexthop_num == 0)
				XFREE(MTYPE_RE, re);
			else
				rib_add_multipath(afi, SAFI_UNICAST, &p,
						  NULL, re);
		}
	} else {
		if (!tb[RTA_MULTIPATH]) {
			struct nexthop nh;
			size_t sz = (afi == AFI_IP) ? 4 : 16;

			memset(&nh, 0, sizeof(nh));
			if (bh_type == BLACKHOLE_UNSPEC) {
				if (index && !gate)
					nh.type = NEXTHOP_TYPE_IFINDEX;
				else if (index && gate)
					nh.type =
						(afi == AFI_IP)
							? NEXTHOP_TYPE_IPV4_IFINDEX
							: NEXTHOP_TYPE_IPV6_IFINDEX;
				else if (!index && gate)
					nh.type = (afi == AFI_IP)
							  ? NEXTHOP_TYPE_IPV4
							  : NEXTHOP_TYPE_IPV6;
				else {
					nh.type = NEXTHOP_TYPE_BLACKHOLE;
					nh.bh_type = BLACKHOLE_UNSPEC;
				}
			} else {
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = bh_type;
			}
			nh.ifindex = index;
			if (gate)
				memcpy(&nh.gate, gate, sz);
			rib_delete(afi, SAFI_UNICAST, vrf_id,
				   proto, 0, flags, &p, NULL, &nh,
				   table, metric, true, NULL);
		} else {
			/* XXX: need to compare the entire list of nexthops
			 * here for NLM_F_APPEND stupidity */
			rib_delete(afi, SAFI_UNICAST, vrf_id,
				   proto, 0, flags, &p, NULL, NULL,
				   table, metric, true, NULL);
		}
	}

	return 0;
}

static struct mcast_route_data *mroute = NULL;

static int netlink_route_change_read_multicast(struct sockaddr_nl *snl,
					       struct nlmsghdr *h,
					       ns_id_t ns_id, int startup)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	struct mcast_route_data *m;
	struct mcast_route_data mr;
	int iif = 0;
	int count;
	int oif[256];
	int oif_count = 0;
	char sbuf[40];
	char gbuf[40];
	char oif_list[256] = "\0";
	vrf_id_t vrf = ns_id;
	int table;

	if (mroute)
		m = mroute;
	else {
		memset(&mr, 0, sizeof(mr));
		m = &mr;
	}

	rtm = NLMSG_DATA(h);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (tb[RTA_TABLE])
		table = *(int *)RTA_DATA(tb[RTA_TABLE]);
	else
		table = rtm->rtm_table;

	vrf = vrf_lookup_by_table(table);

	if (tb[RTA_IIF])
		iif = *(int *)RTA_DATA(tb[RTA_IIF]);

	if (tb[RTA_SRC])
		m->sg.src = *(struct in_addr *)RTA_DATA(tb[RTA_SRC]);

	if (tb[RTA_DST])
		m->sg.grp = *(struct in_addr *)RTA_DATA(tb[RTA_DST]);

	if ((RTA_EXPIRES <= RTA_MAX) && tb[RTA_EXPIRES])
		m->lastused = *(unsigned long long *)RTA_DATA(tb[RTA_EXPIRES]);

	if (tb[RTA_MULTIPATH]) {
		struct rtnexthop *rtnh =
			(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);

		len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		for (;;) {
			if (len < (int)sizeof(*rtnh) || rtnh->rtnh_len > len)
				break;

			oif[oif_count] = rtnh->rtnh_ifindex;
			oif_count++;

			len -= NLMSG_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		struct interface *ifp;
		strlcpy(sbuf, inet_ntoa(m->sg.src), sizeof(sbuf));
		strlcpy(gbuf, inet_ntoa(m->sg.grp), sizeof(gbuf));
		for (count = 0; count < oif_count; count++) {
			ifp = if_lookup_by_index(oif[count], vrf);
			char temp[256];

			sprintf(temp, "%s ", ifp->name);
			strcat(oif_list, temp);
		}
		struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(vrf);
		ifp = if_lookup_by_index(iif, vrf);
		zlog_debug(
			"MCAST VRF: %s(%d) %s (%s,%s) IIF: %s OIF: %s jiffies: %lld",
			zvrf->vrf->name, vrf, nl_msg_type_to_str(h->nlmsg_type),
			sbuf, gbuf, ifp->name, oif_list, m->lastused);
	}
	return 0;
}

int netlink_route_change(struct sockaddr_nl *snl, struct nlmsghdr *h,
			 ns_id_t ns_id, int startup)
{
	int len;
	vrf_id_t vrf_id = ns_id;
	struct rtmsg *rtm;

	rtm = NLMSG_DATA(h);

	if (!(h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)) {
		/* If this is not route add/delete message print warning. */
		zlog_warn("Kernel message: %d vrf %u\n", h->nlmsg_type, vrf_id);
		return 0;
	}

	/* Connected route. */
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s %s %s proto %s vrf %u",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(rtm->rtm_family),
			   nl_rttype_to_str(rtm->rtm_type),
			   nl_rtproto_to_str(rtm->rtm_protocol), vrf_id);

	/* We don't care about change notifications for the MPLS table. */
	/* TODO: Revisit this. */
	if (rtm->rtm_family == AF_MPLS)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0)
		return -1;

	if (rtm->rtm_type == RTN_MULTICAST)
		netlink_route_change_read_multicast(snl, h, ns_id, startup);
	else
		netlink_route_change_read_unicast(snl, h, ns_id, startup);
	return 0;
}

/* Request for specific route information from the kernel */
static int netlink_request_route(struct zebra_ns *zns, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg rtm;
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.rtm.rtm_family = family;

	return netlink_request(&zns->netlink_cmd, &req.n);
}

/* Routing table read function using netlink interface.  Only called
   bootstrap time. */
int netlink_route_read(struct zebra_ns *zns)
{
	int ret;

	/* Get IPv4 routing table. */
	ret = netlink_request_route(zns, AF_INET, RTM_GETROUTE);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_route_change_read_unicast,
				 &zns->netlink_cmd, zns, 0, 1);
	if (ret < 0)
		return ret;

	/* Get IPv6 routing table. */
	ret = netlink_request_route(zns, AF_INET6, RTM_GETROUTE);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_route_change_read_unicast,
				 &zns->netlink_cmd, zns, 0, 1);
	if (ret < 0)
		return ret;

	return 0;
}

static void _netlink_route_nl_add_gateway_info(u_char route_family,
					       u_char gw_family,
					       struct nlmsghdr *nlmsg,
					       size_t req_size, int bytelen,
					       struct nexthop *nexthop)
{
	if (route_family == AF_MPLS) {
		struct gw_family_t gw_fam;

		gw_fam.family = gw_family;
		if (gw_family == AF_INET)
			memcpy(&gw_fam.gate.ipv4, &nexthop->gate.ipv4, bytelen);
		else
			memcpy(&gw_fam.gate.ipv6, &nexthop->gate.ipv6, bytelen);
		addattr_l(nlmsg, req_size, RTA_VIA, &gw_fam.family,
			  bytelen + 2);
	} else {
		if (gw_family == AF_INET)
			addattr_l(nlmsg, req_size, RTA_GATEWAY,
				  &nexthop->gate.ipv4, bytelen);
		else
			addattr_l(nlmsg, req_size, RTA_GATEWAY,
				  &nexthop->gate.ipv6, bytelen);
	}
}

static void _netlink_route_rta_add_gateway_info(u_char route_family,
						u_char gw_family,
						struct rtattr *rta,
						struct rtnexthop *rtnh,
						size_t req_size, int bytelen,
						struct nexthop *nexthop)
{
	if (route_family == AF_MPLS) {
		struct gw_family_t gw_fam;

		gw_fam.family = gw_family;
		if (gw_family == AF_INET)
			memcpy(&gw_fam.gate.ipv4, &nexthop->gate.ipv4, bytelen);
		else
			memcpy(&gw_fam.gate.ipv6, &nexthop->gate.ipv6, bytelen);
		rta_addattr_l(rta, req_size, RTA_VIA, &gw_fam.family,
			      bytelen + 2);
		rtnh->rtnh_len += RTA_LENGTH(bytelen + 2);
	} else {
		if (gw_family == AF_INET)
			rta_addattr_l(rta, req_size, RTA_GATEWAY,
				      &nexthop->gate.ipv4, bytelen);
		else
			rta_addattr_l(rta, req_size, RTA_GATEWAY,
				      &nexthop->gate.ipv6, bytelen);
		rtnh->rtnh_len += sizeof(struct rtattr) + bytelen;
	}
}

/* This function takes a nexthop as argument and adds
 * the appropriate netlink attributes to an existing
 * netlink message.
 *
 * @param routedesc: Human readable description of route type
 *                   (direct/recursive, single-/multipath)
 * @param bytelen: Length of addresses in bytes.
 * @param nexthop: Nexthop information
 * @param nlmsg: nlmsghdr structure to fill in.
 * @param req_size: The size allocated for the message.
 */
static void _netlink_route_build_singlepath(const char *routedesc, int bytelen,
					    struct nexthop *nexthop,
					    struct nlmsghdr *nlmsg,
					    struct rtmsg *rtmsg,
					    size_t req_size, int cmd)
{
	struct mpls_label_stack *nh_label;
	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];

	/*
	 * label_buf is *only* currently used within debugging.
	 * As such when we assign it we are guarding it inside
	 * a debug test.  If you want to change this make sure
	 * you fix this assumption
	 */
	label_buf[0] = '\0';
	/* outgoing label - either as NEWDST (in the case of LSR) or as ENCAP
	 * (in the case of LER)
	 */
	nh_label = nexthop->nh_label;
	if (rtmsg->rtm_family == AF_MPLS) {
		assert(nh_label);
		assert(nh_label->num_labels == 1);
	}

	if (nh_label && nh_label->num_labels) {
		int i, num_labels = 0;
		u_int32_t bos;
		char label_buf1[20];

		for (i = 0; i < nh_label->num_labels; i++) {
			if (nh_label->label[i] != MPLS_IMP_NULL_LABEL) {
				bos = ((i == (nh_label->num_labels - 1)) ? 1
									 : 0);
				out_lse[i] = mpls_lse_encode(nh_label->label[i],
							     0, 0, bos);
				if (IS_ZEBRA_DEBUG_KERNEL) {
					if (!num_labels)
						sprintf(label_buf, "label %u",
							nh_label->label[i]);
					else {
						sprintf(label_buf1, "/%u",
							nh_label->label[i]);
						strlcat(label_buf, label_buf1,
							sizeof(label_buf));
					}
				}
				num_labels++;
			}
		}
		if (num_labels) {
			if (rtmsg->rtm_family == AF_MPLS)
				addattr_l(nlmsg, req_size, RTA_NEWDST, &out_lse,
					  num_labels * sizeof(mpls_lse_t));
			else {
				struct rtattr *nest;
				u_int16_t encap = LWTUNNEL_ENCAP_MPLS;

				addattr_l(nlmsg, req_size, RTA_ENCAP_TYPE,
					  &encap, sizeof(u_int16_t));
				nest = addattr_nest(nlmsg, req_size, RTA_ENCAP);
				addattr_l(nlmsg, req_size, MPLS_IPTUNNEL_DST,
					  &out_lse,
					  num_labels * sizeof(mpls_lse_t));
				addattr_nest_end(nlmsg, nest);
			}
		}
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		rtmsg->rtm_flags |= RTNH_F_ONLINK;

	if (rtmsg->rtm_family == AF_INET
	    && (nexthop->type == NEXTHOP_TYPE_IPV6
		|| nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)) {
		rtmsg->rtm_flags |= RTNH_F_ONLINK;
		addattr_l(nlmsg, req_size, RTA_GATEWAY, &ipv4_ll, 4);
		addattr32(nlmsg, req_size, RTA_OIF, nexthop->ifindex);

		if (nexthop->rmap_src.ipv4.s_addr && (cmd == RTM_NEWROUTE))
			addattr_l(nlmsg, req_size, RTA_PREFSRC,
				  &nexthop->rmap_src.ipv4, bytelen);
		else if (nexthop->src.ipv4.s_addr && (cmd == RTM_NEWROUTE))
			addattr_l(nlmsg, req_size, RTA_PREFSRC,
				  &nexthop->src.ipv4, bytelen);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				" 5549: _netlink_route_build_singlepath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, ipv4_ll_buf, label_buf,
				nexthop->ifindex);
		return;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		/* Send deletes to the kernel without specifying the next-hop */
		if (cmd != RTM_DELROUTE)
			_netlink_route_nl_add_gateway_info(
				rtmsg->rtm_family, AF_INET, nlmsg, req_size,
				bytelen, nexthop);

		if (cmd == RTM_NEWROUTE) {
			if (nexthop->rmap_src.ipv4.s_addr)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv4, bytelen);
			else if (nexthop->src.ipv4.s_addr)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv4, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, inet_ntoa(nexthop->gate.ipv4),
				label_buf, nexthop->ifindex);
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV6
	    || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		_netlink_route_nl_add_gateway_info(rtmsg->rtm_family, AF_INET6,
						   nlmsg, req_size, bytelen,
						   nexthop);

		if (cmd == RTM_NEWROUTE) {
			if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv6, bytelen);
			else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv6, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, inet6_ntoa(nexthop->gate.ipv6),
				label_buf, nexthop->ifindex);
	}

	/*
	 * We have the ifindex so we should always send it
	 * This is especially useful if we are doing route
	 * leaking.
	 */
	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		addattr32(nlmsg, req_size, RTA_OIF, nexthop->ifindex);

	if (nexthop->type == NEXTHOP_TYPE_IFINDEX
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		if (cmd == RTM_NEWROUTE) {
			if (nexthop->rmap_src.ipv4.s_addr)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv4, bytelen);
			else if (nexthop->src.ipv4.s_addr)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv4, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via if %u",
				routedesc, nexthop->ifindex);
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		if (cmd == RTM_NEWROUTE) {
			if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv6, bytelen);
			else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv6, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via if %u",
				routedesc, nexthop->ifindex);
	}
}

/* This function takes a nexthop as argument and
 * appends to the given rtattr/rtnexthop pair the
 * representation of the nexthop. If the nexthop
 * defines a preferred source, the src parameter
 * will be modified to point to that src, otherwise
 * it will be kept unmodified.
 *
 * @param routedesc: Human readable description of route type
 *                   (direct/recursive, single-/multipath)
 * @param bytelen: Length of addresses in bytes.
 * @param nexthop: Nexthop information
 * @param rta: rtnetlink attribute structure
 * @param rtnh: pointer to an rtnetlink nexthop structure
 * @param src: pointer pointing to a location where
 *             the prefsrc should be stored.
 */
static void _netlink_route_build_multipath(const char *routedesc, int bytelen,
					   struct nexthop *nexthop,
					   struct rtattr *rta,
					   struct rtnexthop *rtnh,
					   struct rtmsg *rtmsg,
					   union g_addr **src)
{
	struct mpls_label_stack *nh_label;
	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];

	rtnh->rtnh_len = sizeof(*rtnh);
	rtnh->rtnh_flags = 0;
	rtnh->rtnh_hops = 0;
	rta->rta_len += rtnh->rtnh_len;

	/*
	 * label_buf is *only* currently used within debugging.
	 * As such when we assign it we are guarding it inside
	 * a debug test.  If you want to change this make sure
	 * you fix this assumption
	 */
	label_buf[0] = '\0';
	/* outgoing label - either as NEWDST (in the case of LSR) or as ENCAP
	 * (in the case of LER)
	 */
	nh_label = nexthop->nh_label;
	if (rtmsg->rtm_family == AF_MPLS) {
		assert(nh_label);
		assert(nh_label->num_labels == 1);
	}

	if (nh_label && nh_label->num_labels) {
		int i, num_labels = 0;
		u_int32_t bos;
		char label_buf1[20];

		for (i = 0; i < nh_label->num_labels; i++) {
			if (nh_label->label[i] != MPLS_IMP_NULL_LABEL) {
				bos = ((i == (nh_label->num_labels - 1)) ? 1
									 : 0);
				out_lse[i] = mpls_lse_encode(nh_label->label[i],
							     0, 0, bos);
				if (IS_ZEBRA_DEBUG_KERNEL) {
					if (!num_labels)
						sprintf(label_buf, "label %u",
							nh_label->label[i]);
					else {
						sprintf(label_buf1, "/%u",
							nh_label->label[i]);
						strlcat(label_buf, label_buf1,
							sizeof(label_buf));
					}
				}
				num_labels++;
			}
		}
		if (num_labels) {
			if (rtmsg->rtm_family == AF_MPLS) {
				rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_NEWDST,
					      &out_lse,
					      num_labels * sizeof(mpls_lse_t));
				rtnh->rtnh_len += RTA_LENGTH(
					num_labels * sizeof(mpls_lse_t));
			} else {
				struct rtattr *nest;
				u_int16_t encap = LWTUNNEL_ENCAP_MPLS;
				int len = rta->rta_len;

				rta_addattr_l(rta, NL_PKT_BUF_SIZE,
					      RTA_ENCAP_TYPE, &encap,
					      sizeof(u_int16_t));
				nest = rta_nest(rta, NL_PKT_BUF_SIZE,
						RTA_ENCAP);
				rta_addattr_l(rta, NL_PKT_BUF_SIZE,
					      MPLS_IPTUNNEL_DST, &out_lse,
					      num_labels * sizeof(mpls_lse_t));
				rta_nest_end(rta, nest);
				rtnh->rtnh_len += rta->rta_len - len;
			}
		}
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		rtnh->rtnh_flags |= RTNH_F_ONLINK;

	if (rtmsg->rtm_family == AF_INET
	    && (nexthop->type == NEXTHOP_TYPE_IPV6
		|| nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)) {
		bytelen = 4;
		rtnh->rtnh_flags |= RTNH_F_ONLINK;
		rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_GATEWAY, &ipv4_ll,
			      bytelen);
		rtnh->rtnh_len += sizeof(struct rtattr) + bytelen;
		rtnh->rtnh_ifindex = nexthop->ifindex;

		if (nexthop->rmap_src.ipv4.s_addr)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				" 5549: netlink_route_build_multipath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, ipv4_ll_buf, label_buf,
				nexthop->ifindex);
		return;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		_netlink_route_rta_add_gateway_info(rtmsg->rtm_family, AF_INET,
						    rta, rtnh, NL_PKT_BUF_SIZE,
						    bytelen, nexthop);
		if (nexthop->rmap_src.ipv4.s_addr)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, inet_ntoa(nexthop->gate.ipv4),
				label_buf, nexthop->ifindex);
	}
	if (nexthop->type == NEXTHOP_TYPE_IPV6
	    || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		_netlink_route_rta_add_gateway_info(rtmsg->rtm_family, AF_INET6,
						    rta, rtnh, NL_PKT_BUF_SIZE,
						    bytelen, nexthop);

		if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6))
			*src = &nexthop->rmap_src;
		else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6))
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via %s %s if %u",
				routedesc, inet6_ntoa(nexthop->gate.ipv6),
				label_buf, nexthop->ifindex);
	}

	/*
	 * We have figured out the ifindex so we should always send it
	 * This is especially useful if we are doing route
	 * leaking.
	 */
	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		rtnh->rtnh_ifindex = nexthop->ifindex;

	/* ifindex */
	if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX
	    || nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		if (nexthop->rmap_src.ipv4.s_addr)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via if %u",
				routedesc, nexthop->ifindex);
	} else if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath() (%s): "
				"nexthop via if %u",
				routedesc, nexthop->ifindex);
	} else {
		rtnh->rtnh_ifindex = 0;
	}
}

static inline void _netlink_mpls_build_singlepath(const char *routedesc,
						  zebra_nhlfe_t *nhlfe,
						  struct nlmsghdr *nlmsg,
						  struct rtmsg *rtmsg,
						  size_t req_size, int cmd)
{
	int bytelen;
	u_char family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	_netlink_route_build_singlepath(routedesc, bytelen, nhlfe->nexthop,
					nlmsg, rtmsg, req_size, cmd);
}


static inline void
_netlink_mpls_build_multipath(const char *routedesc, zebra_nhlfe_t *nhlfe,
			      struct rtattr *rta, struct rtnexthop *rtnh,
			      struct rtmsg *rtmsg, union g_addr **src)
{
	int bytelen;
	u_char family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	_netlink_route_build_multipath(routedesc, bytelen, nhlfe->nexthop, rta,
				       rtnh, rtmsg, src);
}


/* Log debug information for netlink_route_multipath
 * if debug logging is enabled.
 *
 * @param cmd: Netlink command which is to be processed
 * @param p: Prefix for which the change is due
 * @param nexthop: Nexthop which is currently processed
 * @param routedesc: Semantic annotation for nexthop
 *                     (recursive, multipath, etc.)
 * @param family: Address family which the change concerns
 */
static void _netlink_route_debug(int cmd, struct prefix *p,
				 struct nexthop *nexthop, const char *routedesc,
				 int family, struct zebra_vrf *zvrf)
{
	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf[PREFIX_STRLEN];
		zlog_debug(
			"netlink_route_multipath() (%s): %s %s vrf %u type %s",
			routedesc, nl_msg_type_to_str(cmd),
			prefix2str(p, buf, sizeof(buf)), zvrf_id(zvrf),
			(nexthop) ? nexthop_type_to_str(nexthop->type) : "UNK");
	}
}

static void _netlink_mpls_debug(int cmd, u_int32_t label, const char *routedesc)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("netlink_mpls_multipath() (%s): %s %u/20", routedesc,
			   nl_msg_type_to_str(cmd), label);
}

static int netlink_neigh_update(int cmd, int ifindex, uint32_t addr, char *lla,
				int llalen)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd; // RTM_NEWNEIGH or RTM_DELNEIGH
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req), NDA_DST, &addr, 4);
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

/* Routing table change via netlink interface. */
/* Update flag indicates whether this is a "replace" or not. */
static int netlink_route_multipath(int cmd, struct prefix *p,
				   struct prefix *src_p, struct route_entry *re,
				   int update)
{
	int bytelen;
	struct sockaddr_nl snl;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	int discard = 0;
	int family = PREFIX_FAMILY(p);
	const char *routedesc;
	int setsrc = 0;
	union g_addr src;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_vrf *zvrf = vrf_info_lookup(re->vrf_id);

	memset(&req, 0, sizeof req - NL_PKT_BUF_SIZE);

	bytelen = (family == AF_INET ? 4 : 16);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	if ((cmd == RTM_NEWROUTE) && update)
		req.n.nlmsg_flags |= NLM_F_REPLACE;
	req.n.nlmsg_type = cmd;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.r.rtm_family = family;
	req.r.rtm_dst_len = p->prefixlen;
	req.r.rtm_src_len = src_p ? src_p->prefixlen : 0;
	req.r.rtm_protocol = zebra2proto(re->type);
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof req, RTA_DST, &p->u.prefix, bytelen);
	if (src_p)
		addattr_l(&req.n, sizeof req, RTA_SRC, &src_p->u.prefix,
			  bytelen);

	/* Metric. */
	/* Hardcode the metric for all routes coming from zebra. Metric isn't
	 * used
	 * either by the kernel or by zebra. Its purely for calculating best
	 * path(s)
	 * by the routing protocol and for communicating with protocol peers.
	 */
	addattr32(&req.n, sizeof req, RTA_PRIORITY, NL_DEFAULT_ROUTE_METRIC);
#if defined(SUPPORT_REALMS)
	if (re->tag > 0 && re->tag <= 255)
		addattr32(&req.n, sizeof req, RTA_FLOW, re->tag);
#endif
	/* Table corresponding to this route. */
	if (re->table < 256)
		req.r.rtm_table = re->table;
	else {
		req.r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof req, RTA_TABLE, re->table);
	}

	if (discard)
		goto skip;

	if (re->mtu || re->nexthop_mtu) {
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		u_int32_t mtu = re->mtu;
		if (!mtu || (re->nexthop_mtu && re->nexthop_mtu < mtu))
			mtu = re->nexthop_mtu;
		rta->rta_type = RTA_METRICS;
		rta->rta_len = RTA_LENGTH(0);
		rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTAX_MTU, &mtu, sizeof mtu);
		addattr_l(&req.n, NL_PKT_BUF_SIZE, RTA_METRICS, RTA_DATA(rta),
			  RTA_PAYLOAD(rta));
	}

	/* Count overall nexthops so we can decide whether to use singlepath
	 * or multipath case. */
	nexthop_num = 0;
	for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;
		if (cmd == RTM_NEWROUTE
		    && !NEXTHOP_IS_ACTIVE(nexthop->flags))
			continue;
		if (cmd == RTM_DELROUTE
		    && !CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
			continue;

		nexthop_num++;
	}

	/* Singlepath case. */
	if (nexthop_num == 1 || multipath_num == 1) {
		nexthop_num = 0;
		for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
			/*
			 * So we want to cover 2 types of blackhole
			 * routes here:
			 * 1) A normal blackhole route( ala from a static
			 *    install.
			 * 2) A recursively resolved blackhole route
			 */
			if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
				switch (nexthop->bh_type) {
				case BLACKHOLE_ADMINPROHIB:
					req.r.rtm_type = RTN_PROHIBIT;
					break;
				case BLACKHOLE_REJECT:
					req.r.rtm_type = RTN_UNREACHABLE;
					break;
				default:
					req.r.rtm_type = RTN_BLACKHOLE;
					break;
				}
				goto skip;
			}
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {
				if (!setsrc) {
					if (family == AF_INET) {
						if (nexthop->rmap_src.ipv4
							    .s_addr
						    != 0) {
							src.ipv4 =
								nexthop->rmap_src
									.ipv4;
							setsrc = 1;
						} else if (nexthop->src.ipv4
								   .s_addr
							   != 0) {
							src.ipv4 =
								nexthop->src
									.ipv4;
							setsrc = 1;
						}
					} else if (family == AF_INET6) {
						if (!IN6_IS_ADDR_UNSPECIFIED(
							    &nexthop->rmap_src
								     .ipv6)) {
							src.ipv6 =
								nexthop->rmap_src
									.ipv6;
							setsrc = 1;
						} else if (
							!IN6_IS_ADDR_UNSPECIFIED(
								&nexthop->src
									 .ipv6)) {
							src.ipv6 =
								nexthop->src
									.ipv6;
							setsrc = 1;
						}
					}
				}
				continue;
			}

			if ((cmd == RTM_NEWROUTE
			     && NEXTHOP_IS_ACTIVE(nexthop->flags))
			    || (cmd == RTM_DELROUTE
				&& CHECK_FLAG(nexthop->flags,
					      NEXTHOP_FLAG_FIB))) {
				routedesc = nexthop->rparent
						    ? "recursive, single-path"
						    : "single-path";

				_netlink_route_debug(cmd, p, nexthop, routedesc,
						     family, zvrf);
				_netlink_route_build_singlepath(
					routedesc, bytelen, nexthop, &req.n,
					&req.r, sizeof req, cmd);
				nexthop_num++;
				break;
			}
		}
		if (setsrc && (cmd == RTM_NEWROUTE)) {
			if (family == AF_INET)
				addattr_l(&req.n, sizeof req, RTA_PREFSRC,
					  &src.ipv4, bytelen);
			else if (family == AF_INET6)
				addattr_l(&req.n, sizeof req, RTA_PREFSRC,
					  &src.ipv6, bytelen);
		}
	} else {
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		struct rtnexthop *rtnh;
		union g_addr *src1 = NULL;

		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

		nexthop_num = 0;
		for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
			if (nexthop_num >= multipath_num)
				break;

			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {
				/* This only works for IPv4 now */
				if (!setsrc) {
					if (family == AF_INET) {
						if (nexthop->rmap_src.ipv4
							    .s_addr
						    != 0) {
							src.ipv4 =
								nexthop->rmap_src
									.ipv4;
							setsrc = 1;
						} else if (nexthop->src.ipv4
								   .s_addr
							   != 0) {
							src.ipv4 =
								nexthop->src
									.ipv4;
							setsrc = 1;
						}
					} else if (family == AF_INET6) {
						if (!IN6_IS_ADDR_UNSPECIFIED(
							    &nexthop->rmap_src
								     .ipv6)) {
							src.ipv6 =
								nexthop->rmap_src
									.ipv6;
							setsrc = 1;
						} else if (
							!IN6_IS_ADDR_UNSPECIFIED(
								&nexthop->src
									 .ipv6)) {
							src.ipv6 =
								nexthop->src
									.ipv6;
							setsrc = 1;
						}
					}
				}
				continue;
			}

			if ((cmd == RTM_NEWROUTE
			     && NEXTHOP_IS_ACTIVE(nexthop->flags))
			    || (cmd == RTM_DELROUTE
				&& CHECK_FLAG(nexthop->flags,
					      NEXTHOP_FLAG_FIB))) {
				routedesc = nexthop->rparent
						    ? "recursive, multipath"
						    : "multipath";
				nexthop_num++;

				_netlink_route_debug(cmd, p, nexthop, routedesc,
						     family, zvrf);
				_netlink_route_build_multipath(
					routedesc, bytelen, nexthop, rta, rtnh,
					&req.r, &src1);
				rtnh = RTNH_NEXT(rtnh);

				if (!setsrc && src1) {
					if (family == AF_INET)
						src.ipv4 = src1->ipv4;
					else if (family == AF_INET6)
						src.ipv6 = src1->ipv6;

					setsrc = 1;
				}
			}
		}
		if (setsrc && (cmd == RTM_NEWROUTE)) {
			if (family == AF_INET)
				addattr_l(&req.n, sizeof req, RTA_PREFSRC,
					  &src.ipv4, bytelen);
			else if (family == AF_INET6)
				addattr_l(&req.n, sizeof req, RTA_PREFSRC,
					  &src.ipv6, bytelen);
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("Setting source");
		}

		if (rta->rta_len > RTA_LENGTH(0))
			addattr_l(&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH,
				  RTA_DATA(rta), RTA_PAYLOAD(rta));
	}

	/* If there is no useful nexthop then return. */
	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath(): No useful nexthop.");
		return 0;
	}

skip:

	/* Destination netlink address. */
	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	/* Talk to netlink socket. */
	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *in)
{
	int suc = 0;
	struct mcast_route_data *mr = (struct mcast_route_data *)in;
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	mroute = mr;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ndm.ndm_family = RTNL_FAMILY_IPMR;
	req.n.nlmsg_type = RTM_GETROUTE;

	addattr_l(&req.n, sizeof(req), RTA_IIF, &mroute->ifindex, 4);
	addattr_l(&req.n, sizeof(req), RTA_OIF, &mroute->ifindex, 4);
	addattr_l(&req.n, sizeof(req), RTA_SRC, &mroute->sg.src.s_addr, 4);
	addattr_l(&req.n, sizeof(req), RTA_DST, &mroute->sg.grp.s_addr, 4);
	addattr_l(&req.n, sizeof(req), RTA_TABLE, &zvrf->table_id, 4);

	suc = netlink_talk(netlink_route_change_read_multicast, &req.n,
			   &zns->netlink_cmd, zns, 0);

	mroute = NULL;
	return suc;
}

void kernel_route_rib(struct route_node *rn, struct prefix *p,
		      struct prefix *src_p, struct route_entry *old,
		      struct route_entry *new)
{
	int ret = 0;

	assert(old || new);

	if (new) {
		if (p->family == AF_INET)
			ret = netlink_route_multipath(RTM_NEWROUTE, p, src_p,
						      new, (old) ? 1 : 0);
		else {
			/*
			 * So v6 route replace semantics are not in
			 * the kernel at this point as I understand it.
			 * So let's do a delete than an add.
			 * In the future once v6 route replace semantics
			 * are in we can figure out what to do here to
			 * allow working with old and new kernels.
			 *
			 * I'm also intentionally ignoring the failure case
			 * of the route delete.  If that happens yeah we're
			 * screwed.
			 */
			if (old)
				netlink_route_multipath(RTM_DELROUTE, p,
							src_p, old, 0);
			ret = netlink_route_multipath(RTM_NEWROUTE, p,
						      src_p, new, 0);
		}
		kernel_route_rib_pass_fail(rn, p, new,
					   (!ret) ?
					   SOUTHBOUND_INSTALL_SUCCESS :
					   SOUTHBOUND_INSTALL_FAILURE);
		return;
	}

	if (old) {
		ret = netlink_route_multipath(RTM_DELROUTE, p, src_p, old, 0);

		kernel_route_rib_pass_fail(rn, p, old,
					   (!ret) ?
					   SOUTHBOUND_DELETE_SUCCESS :
					   SOUTHBOUND_DELETE_FAILURE);
	}
}

int kernel_neigh_update(int add, int ifindex, uint32_t addr, char *lla,
			int llalen)
{
	return netlink_neigh_update(add ? RTM_NEWNEIGH : RTM_DELNEIGH, ifindex,
				    addr, lla, llalen);
}

/*
 * Add remote VTEP to the flood list for this VxLAN interface (VNI). This
 * is done by adding an FDB entry with a MAC of 00:00:00:00:00:00.
 */
static int netlink_vxlan_flood_list_update(struct interface *ifp,
					   struct in_addr *vtep_ip, int cmd)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	u_char dst_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWNEIGH)
		req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_APPEND);
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = PF_BRIDGE;
	req.ndm.ndm_state = NUD_NOARP | NUD_PERMANENT;
	req.ndm.ndm_flags |= NTF_SELF; // Handle by "self", not "master"


	addattr_l(&req.n, sizeof(req), NDA_LLADDR, &dst_mac, 6);
	req.ndm.ndm_ifindex = ifp->ifindex;
	addattr_l(&req.n, sizeof(req), NDA_DST, &vtep_ip->s_addr, 4);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

/*
 * Add remote VTEP for this VxLAN interface (VNI). In Linux, this involves
 * adding
 * a "flood" MAC FDB entry.
 */
int kernel_add_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Install %s into flood list for VNI %u intf %s(%u)",
			   inet_ntoa(*vtep_ip), vni, ifp->name, ifp->ifindex);

	return netlink_vxlan_flood_list_update(ifp, vtep_ip, RTM_NEWNEIGH);
}

/*
 * Remove remote VTEP for this VxLAN interface (VNI). In Linux, this involves
 * deleting the "flood" MAC FDB entry.
 */
int kernel_del_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Uninstall %s from flood list for VNI %u intf %s(%u)",
			inet_ntoa(*vtep_ip), vni, ifp->name, ifp->ifindex);

	return netlink_vxlan_flood_list_update(ifp, vtep_ip, RTM_DELNEIGH);
}

#ifndef NDA_RTA
#define NDA_RTA(r)                                                             \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static int netlink_macfdb_change(struct sockaddr_nl *snl, struct nlmsghdr *h,
				 int len)
{
	struct ndmsg *ndm;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *tb[NDA_MAX + 1];
	struct interface *br_if;
	struct ethaddr mac;
	vlanid_t vid = 0;
	struct prefix vtep_ip;
	int vid_present = 0, dst_present = 0;
	char buf[ETHER_ADDR_STRLEN];
	char vid_buf[20];
	char dst_buf[30];
	u_char sticky = 0;

	ndm = NLMSG_DATA(h);

	/* We only process macfdb notifications if EVPN is enabled */
	if (!is_evpn_enabled())
		return 0;

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					ndm->ndm_ifindex);
	if (!ifp || !ifp->info)
		return 0;

	/* The interface should be something we're interested in. */
	if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
		return 0;

	/* Drop "permanent" entries. */
	if (ndm->ndm_state & NUD_PERMANENT)
		return 0;

	zif = (struct zebra_if *)ifp->info;
	if ((br_if = zif->brslave_info.br_if) == NULL) {
		zlog_warn("%s family %s IF %s(%u) brIF %u - no bridge master",
			  nl_msg_type_to_str(h->nlmsg_type),
			  nl_family_to_str(ndm->ndm_family), ifp->name,
			  ndm->ndm_ifindex, zif->brslave_info.bridge_ifindex);
		return 0;
	}

	/* Parse attributes and extract fields of interest. */
	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_LLADDR]) {
		zlog_warn("%s family %s IF %s(%u) brIF %u - no LLADDR",
			  nl_msg_type_to_str(h->nlmsg_type),
			  nl_family_to_str(ndm->ndm_family), ifp->name,
			  ndm->ndm_ifindex, zif->brslave_info.bridge_ifindex);
		return 0;
	}

	if (RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN) {
		zlog_warn(
			"%s family %s IF %s(%u) brIF %u - LLADDR is not MAC, len %lu",
			nl_msg_type_to_str(h->nlmsg_type),
			nl_family_to_str(ndm->ndm_family), ifp->name,
			ndm->ndm_ifindex, zif->brslave_info.bridge_ifindex,
			(unsigned long)RTA_PAYLOAD(tb[NDA_LLADDR]));
		return 0;
	}

	memcpy(&mac, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);

	if ((NDA_VLAN <= NDA_MAX) && tb[NDA_VLAN]) {
		vid_present = 1;
		vid = *(u_int16_t *)RTA_DATA(tb[NDA_VLAN]);
		sprintf(vid_buf, " VLAN %u", vid);
	}

	if (tb[NDA_DST]) {
		/* TODO: Only IPv4 supported now. */
		dst_present = 1;
		vtep_ip.family = AF_INET;
		vtep_ip.prefixlen = IPV4_MAX_BITLEN;
		memcpy(&(vtep_ip.u.prefix4.s_addr), RTA_DATA(tb[NDA_DST]),
		       IPV4_MAX_BYTELEN);
		sprintf(dst_buf, " dst %s", inet_ntoa(vtep_ip.u.prefix4));
	}

	sticky = (ndm->ndm_state & NUD_NOARP) ? 1 : 0;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s family %s IF %s(%u)%s %sMAC %s%s",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex, vid_present ? vid_buf : "",
			   sticky ? "sticky " : "",
			   prefix_mac2str(&mac, buf, sizeof(buf)),
			   dst_present ? dst_buf : "");

	if (filter_vlan && vid != filter_vlan)
		return 0;

	/* If add or update, do accordingly if learnt on a "local" interface; if
	 * the notification is over VxLAN, this has to be related to
	 * multi-homing,
	 * so perform an implicit delete of any local entry (if it exists).
	 */
	if (h->nlmsg_type == RTM_NEWNEIGH) {
		/* Drop "permanent" entries. */
		if (ndm->ndm_state & NUD_PERMANENT)
			return 0;

		if (IS_ZEBRA_IF_VXLAN(ifp))
			return zebra_vxlan_check_del_local_mac(ifp, br_if, &mac,
							       vid);

		return zebra_vxlan_local_mac_add_update(ifp, br_if, &mac, vid,
							sticky);
	}

	/* This is a delete notification.
	 *  1. For a MAC over VxLan, check if it needs to be refreshed(readded)
	 *  2. For a MAC over "local" interface, delete the mac
	 * Note: We will get notifications from both bridge driver and VxLAN
	 * driver.
	 * Ignore the notification from VxLan driver as it is also generated
	 * when mac moves from remote to local.
	 */
	if (dst_present)
		return 0;

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return zebra_vxlan_check_readd_remote_mac(ifp, br_if, &mac,
							  vid);

	return zebra_vxlan_local_mac_del(ifp, br_if, &mac, vid);
}

static int netlink_macfdb_table(struct sockaddr_nl *snl, struct nlmsghdr *h,
				ns_id_t ns_id, int startup)
{
	int len;
	struct ndmsg *ndm;

	if (h->nlmsg_type != RTM_NEWNEIGH)
		return 0;

	/* Length validity. */
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	if (len < 0)
		return -1;

	/* We are interested only in AF_BRIDGE notifications. */
	ndm = NLMSG_DATA(h);
	if (ndm->ndm_family != AF_BRIDGE)
		return 0;

	return netlink_macfdb_change(snl, h, len);
}

/* Request for MAC FDB information from the kernel */
static int netlink_request_macs(struct zebra_ns *zns, int family, int type,
				ifindex_t master_ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.ifm.ifi_family = family;
	if (master_ifindex)
		addattr32(&req.n, sizeof(req), IFLA_MASTER, master_ifindex);

	return netlink_request(&zns->netlink_cmd, &req.n);
}

/*
 * MAC forwarding database read using netlink interface. This is invoked
 * at startup.
 */
int netlink_macfdb_read(struct zebra_ns *zns)
{
	int ret;

	/* Get bridge FDB table. */
	ret = netlink_request_macs(zns, AF_BRIDGE, RTM_GETNEIGH, 0);
	if (ret < 0)
		return ret;
	/* We are reading entire table. */
	filter_vlan = 0;
	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd, zns,
				 0, 1);

	return ret;
}

/*
 * MAC forwarding database read using netlink interface. This is for a
 * specific bridge and matching specific access VLAN (if VLAN-aware bridge).
 */
int netlink_macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
				   struct interface *br_if)
{
	struct zebra_if *br_zif;
	struct zebra_if *zif;
	struct zebra_l2info_vxlan *vxl;
	int ret = 0;


	/* Save VLAN we're filtering on, if needed. */
	br_zif = (struct zebra_if *)br_if->info;
	zif = (struct zebra_if *)ifp->info;
	vxl = &zif->l2info.vxl;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		filter_vlan = vxl->access_vlan;

	/* Get bridge FDB table for specific bridge - we do the VLAN filtering.
	 */
	ret = netlink_request_macs(zns, AF_BRIDGE, RTM_GETNEIGH,
				   br_if->ifindex);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd, zns,
				 0, 0);

	/* Reset VLAN filter. */
	filter_vlan = 0;
	return ret;
}

static int netlink_macfdb_update(struct interface *ifp, vlanid_t vid,
				 struct ethaddr *mac, struct in_addr vtep_ip,
				 int local, int cmd, u_char sticky)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	int dst_alen;
	struct zebra_if *zif;
	struct interface *br_if;
	struct zebra_if *br_zif;
	char buf[ETHER_ADDR_STRLEN];
	int vid_present = 0, dst_present = 0;
	char vid_buf[20];
	char dst_buf[30];

	zif = ifp->info;
	if ((br_if = zif->brslave_info.br_if) == NULL) {
		zlog_warn("MAC %s on IF %s(%u) - no mapping to bridge",
			  (cmd == RTM_NEWNEIGH) ? "add" : "del", ifp->name,
			  ifp->ifindex);
		return -1;
	}

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWNEIGH)
		req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = AF_BRIDGE;
	req.ndm.ndm_flags |= NTF_SELF | NTF_MASTER;
	req.ndm.ndm_state = NUD_REACHABLE;

	if (sticky)
		req.ndm.ndm_state |= NUD_NOARP;
	else
		req.ndm.ndm_flags |= NTF_EXT_LEARNED;

	addattr_l(&req.n, sizeof(req), NDA_LLADDR, mac, 6);
	req.ndm.ndm_ifindex = ifp->ifindex;
	if (!local) {
		dst_alen = 4; // TODO: hardcoded
		addattr_l(&req.n, sizeof(req), NDA_DST, &vtep_ip, dst_alen);
		dst_present = 1;
		sprintf(dst_buf, " dst %s", inet_ntoa(vtep_ip));
	}
	br_zif = (struct zebra_if *)br_if->info;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif) && vid > 0) {
		addattr16(&req.n, sizeof(req), NDA_VLAN, vid);
		vid_present = 1;
		sprintf(vid_buf, " VLAN %u", vid);
	}
	addattr32(&req.n, sizeof(req), NDA_MASTER, br_if->ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Tx %s family %s IF %s(%u)%s %sMAC %s%s",
			   nl_msg_type_to_str(cmd),
			   nl_family_to_str(req.ndm.ndm_family), ifp->name,
			   ifp->ifindex, vid_present ? vid_buf : "",
			   sticky ? "sticky " : "",
			   prefix_mac2str(mac, buf, sizeof(buf)),
			   dst_present ? dst_buf : "");

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

#define NUD_VALID                                                              \
	(NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE     \
	 | NUD_DELAY)

static int netlink_ipneigh_change(struct sockaddr_nl *snl, struct nlmsghdr *h,
				  int len)
{
	struct ndmsg *ndm;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *tb[NDA_MAX + 1];
	struct interface *link_if;
	struct ethaddr mac;
	struct ipaddr ip;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	int mac_present = 0;
	u_char ext_learned;

	ndm = NLMSG_DATA(h);

	/* We only process neigh notifications if EVPN is enabled */
	if (!is_evpn_enabled())
		return 0;

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					ndm->ndm_ifindex);
	if (!ifp || !ifp->info)
		return 0;

	/* Drop "permanent" entries. */
	if (ndm->ndm_state & NUD_PERMANENT)
		return 0;

	zif = (struct zebra_if *)ifp->info;
	/* The neighbor is present on an SVI. From this, we locate the
	 * underlying
	 * bridge because we're only interested in neighbors on a VxLAN bridge.
	 * The bridge is located based on the nature of the SVI:
	 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN
	 * interface
	 * and is linked to the bridge
	 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge
	 * inteface
	 * itself
	 */
	if (IS_ZEBRA_IF_VLAN(ifp)) {
		link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
						    zif->link_ifindex);
		if (!link_if)
			return 0;
	} else if (IS_ZEBRA_IF_BRIDGE(ifp))
		link_if = ifp;
	else
		return 0;

	/* Parse attributes and extract fields of interest. */
	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_DST]) {
		zlog_warn("%s family %s IF %s(%u) - no DST",
			  nl_msg_type_to_str(h->nlmsg_type),
			  nl_family_to_str(ndm->ndm_family), ifp->name,
			  ndm->ndm_ifindex);
		return 0;
	}
	memset(&mac, 0, sizeof(struct ethaddr));
	memset(&ip, 0, sizeof(struct ipaddr));
	ip.ipa_type = (ndm->ndm_family == AF_INET) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ip.ip.addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));

	if (h->nlmsg_type == RTM_NEWNEIGH) {
		if (tb[NDA_LLADDR]) {
			if (RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN) {
				zlog_warn(
					"%s family %s IF %s(%u) - LLADDR is not MAC, len %lu",
					nl_msg_type_to_str(h->nlmsg_type),
					nl_family_to_str(ndm->ndm_family),
					ifp->name, ndm->ndm_ifindex,
					(unsigned long)RTA_PAYLOAD(tb[NDA_LLADDR]));
				return 0;
			}

			mac_present = 1;
			memcpy(&mac, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);
		}

		ext_learned = (ndm->ndm_flags & NTF_EXT_LEARNED) ? 1 : 0;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"Rx %s family %s IF %s(%u) IP %s MAC %s state 0x%x flags 0x%x",
				nl_msg_type_to_str(h->nlmsg_type),
				nl_family_to_str(ndm->ndm_family), ifp->name,
				ndm->ndm_ifindex,
				ipaddr2str(&ip, buf2, sizeof(buf2)),
				mac_present
					? prefix_mac2str(&mac, buf, sizeof(buf))
					: "",
				ndm->ndm_state, ndm->ndm_flags);

		/* If the neighbor state is valid for use, process as an add or
		 * update
		 * else process as a delete. Note that the delete handling may
		 * result
		 * in re-adding the neighbor if it is a valid "remote" neighbor.
		 */
		if (ndm->ndm_state & NUD_VALID)
			return zebra_vxlan_local_neigh_add_update(
				ifp, link_if, &ip, &mac, ndm->ndm_state,
				ext_learned);

		return zebra_vxlan_local_neigh_del(ifp, link_if, &ip);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s family %s IF %s(%u) IP %s",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex,
			   ipaddr2str(&ip, buf2, sizeof(buf2)));

	/* Process the delete - it may result in re-adding the neighbor if it is
	 * a valid "remote" neighbor.
	 */
	return zebra_vxlan_local_neigh_del(ifp, link_if, &ip);
}

static int netlink_neigh_table(struct sockaddr_nl *snl, struct nlmsghdr *h,
			       ns_id_t ns_id, int startup)
{
	int len;
	struct ndmsg *ndm;

	if (h->nlmsg_type != RTM_NEWNEIGH)
		return 0;

	/* Length validity. */
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	if (len < 0)
		return -1;

	/* We are interested only in AF_INET or AF_INET6 notifications. */
	ndm = NLMSG_DATA(h);
	if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6)
		return 0;

	return netlink_neigh_change(snl, h, len);
}

/* Request for IP neighbor information from the kernel */
static int netlink_request_neigh(struct zebra_ns *zns, int family, int type,
				 ifindex_t ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.ndm.ndm_family = family;
	if (ifindex)
		addattr32(&req.n, sizeof(req), NDA_IFINDEX, ifindex);

	return netlink_request(&zns->netlink_cmd, &req.n);
}

/*
 * IP Neighbor table read using netlink interface. This is invoked
 * at startup.
 */
int netlink_neigh_read(struct zebra_ns *zns)
{
	int ret;

	/* Get IP neighbor table. */
	ret = netlink_request_neigh(zns, AF_UNSPEC, RTM_GETNEIGH, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd, zns, 0,
				 1);

	return ret;
}

/*
 * IP Neighbor table read using netlink interface. This is for a specific
 * VLAN device.
 */
int netlink_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
	int ret = 0;

	ret = netlink_request_neigh(zns, AF_UNSPEC, RTM_GETNEIGH,
				    vlan_if->ifindex);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd, zns, 0,
				 0);

	return ret;
}

int netlink_neigh_change(struct sockaddr_nl *snl, struct nlmsghdr *h,
			 ns_id_t ns_id)
{
	int len;
	struct ndmsg *ndm;

	if (!(h->nlmsg_type == RTM_NEWNEIGH || h->nlmsg_type == RTM_DELNEIGH))
		return 0;

	/* Length validity. */
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	if (len < 0)
		return -1;

	/* Is this a notification for the MAC FDB or IP neighbor table? */
	ndm = NLMSG_DATA(h);
	if (ndm->ndm_family == AF_BRIDGE)
		return netlink_macfdb_change(snl, h, len);

	if (ndm->ndm_type != RTN_UNICAST)
		return 0;

	if (ndm->ndm_family == AF_INET || ndm->ndm_family == AF_INET6)
		return netlink_ipneigh_change(snl, h, len);

	return 0;
}

static int netlink_neigh_update2(struct interface *ifp, struct ipaddr *ip,
				 struct ethaddr *mac, u_int32_t flags, int cmd)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	int ipa_len;

	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	char buf[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];

	memset(&req.n, 0, sizeof(req.n));
	memset(&req.ndm, 0, sizeof(req.ndm));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWNEIGH)
		req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd; // RTM_NEWNEIGH or RTM_DELNEIGH
	req.ndm.ndm_family = IS_IPADDR_V4(ip) ? AF_INET : AF_INET6;
	req.ndm.ndm_state = flags;
	req.ndm.ndm_ifindex = ifp->ifindex;
	req.ndm.ndm_type = RTN_UNICAST;
	req.ndm.ndm_flags = NTF_EXT_LEARNED;


	ipa_len = IS_IPADDR_V4(ip) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	addattr_l(&req.n, sizeof(req), NDA_DST, &ip->ip.addr, ipa_len);
	if (mac)
		addattr_l(&req.n, sizeof(req), NDA_LLADDR, mac, 6);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Tx %s family %s IF %s(%u) Neigh %s MAC %s",
			   nl_msg_type_to_str(cmd),
			   nl_family_to_str(req.ndm.ndm_family), ifp->name,
			   ifp->ifindex, ipaddr2str(ip, buf, sizeof(buf)),
			   mac ? prefix_mac2str(mac, buf2, sizeof(buf2))
			       : "null");

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

int kernel_add_mac(struct interface *ifp, vlanid_t vid, struct ethaddr *mac,
		   struct in_addr vtep_ip, u_char sticky)
{
	return netlink_macfdb_update(ifp, vid, mac, vtep_ip, 0, RTM_NEWNEIGH,
				     sticky);
}

int kernel_del_mac(struct interface *ifp, vlanid_t vid, struct ethaddr *mac,
		   struct in_addr vtep_ip, int local)
{
	return netlink_macfdb_update(ifp, vid, mac, vtep_ip, local,
				     RTM_DELNEIGH, 0);
}

int kernel_add_neigh(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac)
{
	return netlink_neigh_update2(ifp, ip, mac, NUD_REACHABLE, RTM_NEWNEIGH);
}

int kernel_del_neigh(struct interface *ifp, struct ipaddr *ip)
{
	return netlink_neigh_update2(ifp, ip, NULL, 0, RTM_DELNEIGH);
}

/*
 * MPLS label forwarding table change via netlink interface.
 */
int netlink_mpls_multipath(int cmd, zebra_lsp_t *lsp)
{
	mpls_lse_t lse;
	zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	const char *routedesc;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	int route_type;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof req - NL_PKT_BUF_SIZE);

	/*
	 * Count # nexthops so we can decide whether to use singlepath
	 * or multipath case.
	 */
	nexthop_num = 0;
	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;
		if (cmd == RTM_NEWROUTE) {
			/* Count all selected NHLFEs */
			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				nexthop_num++;
		} else /* DEL */
		{
			/* Count all installed NHLFEs */
			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				nexthop_num++;
		}
	}

	if ((nexthop_num == 0) || (!lsp->best_nhlfe && (cmd != RTM_DELROUTE)))
		return 0;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.r.rtm_family = AF_MPLS;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_dst_len = MPLS_LABEL_LEN_BITS;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	if (cmd == RTM_NEWROUTE) {
		/* We do a replace to handle update. */
		req.n.nlmsg_flags |= NLM_F_REPLACE;

		/* set the protocol value if installing */
		route_type = re_type_from_lsp_type(lsp->best_nhlfe->type);
		req.r.rtm_protocol = zebra2proto(route_type);
	}

	/* Fill destination */
	lse = mpls_lse_encode(lsp->ile.in_label, 0, 0, 1);
	addattr_l(&req.n, sizeof req, RTA_DST, &lse, sizeof(mpls_lse_t));

	/* Fill nexthops (paths) based on single-path or multipath. The paths
	 * chosen depend on the operation.
	 */
	if (nexthop_num == 1 || multipath_num == 1) {
		routedesc = "single-path";
		_netlink_mpls_debug(cmd, lsp->ile.in_label, routedesc);

		nexthop_num = 0;
		for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
			nexthop = nhlfe->nexthop;
			if (!nexthop)
				continue;

			if ((cmd == RTM_NEWROUTE
			     && (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
				 && CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_ACTIVE)))
			    || (cmd == RTM_DELROUTE
				&& (CHECK_FLAG(nhlfe->flags,
					       NHLFE_FLAG_INSTALLED)
				    && CHECK_FLAG(nexthop->flags,
						  NEXTHOP_FLAG_FIB)))) {
				/* Add the gateway */
				_netlink_mpls_build_singlepath(routedesc, nhlfe,
							       &req.n, &req.r,
							       sizeof req, cmd);
				nexthop_num++;
				break;
			}
		}
	} else /* Multipath case */
	{
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		struct rtnexthop *rtnh;
		union g_addr *src1 = NULL;

		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

		routedesc = "multipath";
		_netlink_mpls_debug(cmd, lsp->ile.in_label, routedesc);

		nexthop_num = 0;
		for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
			nexthop = nhlfe->nexthop;
			if (!nexthop)
				continue;

			if (nexthop_num >= multipath_num)
				break;

			if ((cmd == RTM_NEWROUTE
			     && (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
				 && CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_ACTIVE)))
			    || (cmd == RTM_DELROUTE
				&& (CHECK_FLAG(nhlfe->flags,
					       NHLFE_FLAG_INSTALLED)
				    && CHECK_FLAG(nexthop->flags,
						  NEXTHOP_FLAG_FIB)))) {
				nexthop_num++;

				/* Build the multipath */
				_netlink_mpls_build_multipath(routedesc, nhlfe,
							      rta, rtnh, &req.r,
							      &src1);
				rtnh = RTNH_NEXT(rtnh);
			}
		}

		/* Add the multipath */
		if (rta->rta_len > RTA_LENGTH(0))
			addattr_l(&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH,
				  RTA_DATA(rta), RTA_PAYLOAD(rta));
	}

	/* Talk to netlink socket. */
	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}
#endif /* HAVE_NETLINK */
