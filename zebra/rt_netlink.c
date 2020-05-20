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
#include <linux/nexthop.h>

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
#include "printfrr.h"

#include "zebra/zapi_msg.h"
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
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_mroute.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_evpn_mh.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif

/* Re-defining as I am unable to include <linux/if_bridge.h> which has the
 * UAPI for MAC sync. */
#ifndef _UAPI_LINUX_IF_BRIDGE_H
/* FDB notification bits for NDA_NOTIFY:
 * - BR_FDB_NFY_STATIC - notify on activity/expire even for a static entry
 * - BR_FDB_NFY_INACTIVE - mark as inactive to avoid double notification,
 *                         used with BR_FDB_NFY_STATIC (kernel controlled)
 */
enum {
	BR_FDB_NFY_STATIC,
	BR_FDB_NFY_INACTIVE,
	BR_FDB_NFY_MAX
};
#endif

static vlanid_t filter_vlan = 0;

/* We capture whether the current kernel supports nexthop ids; by
 * default, we'll use them if possible. There's also a configuration
 * available to _disable_ use of kernel nexthops.
 */
static bool supports_nh;

struct gw_family_t {
	uint16_t filler;
	uint16_t family;
	union g_addr gate;
};

static const char ipv4_ll_buf[16] = "169.254.0.1";
static struct in_addr ipv4_ll;

/* Helper to control use of kernel-level nexthop ids */
static bool kernel_nexthops_supported(void)
{
	return (supports_nh && zebra_nhg_kernel_nexthops_enabled());
}

/*
 * Some people may only want to use NHGs created by protos and not
 * implicitly created by Zebra. This check accounts for that.
 */
static bool proto_nexthops_only(void)
{
	return zebra_nhg_proto_nexthops_only();
}

/* Is this a proto created NHG? */
static bool is_proto_nhg(uint32_t id, int type)
{
	/* If type is available, use it as the source of truth */
	if (type) {
		if (type != ZEBRA_ROUTE_NHG)
			return true;
		return false;
	}

	if (id >= ZEBRA_NHG_PROTO_LOWER)
		return true;

	return false;
}

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

/*
 * Mapping from dataplane neighbor flags to netlink flags
 */
static uint8_t neigh_flags_to_netlink(uint8_t dplane_flags)
{
	uint8_t flags = 0;

	if (dplane_flags & DPLANE_NTF_EXT_LEARNED)
		flags |= NTF_EXT_LEARNED;
	if (dplane_flags & DPLANE_NTF_ROUTER)
		flags |= NTF_ROUTER;

	return flags;
}

/*
 * Mapping from dataplane neighbor state to netlink state
 */
static uint16_t neigh_state_to_netlink(uint16_t dplane_state)
{
	uint16_t state = 0;

	if (dplane_state & DPLANE_NUD_REACHABLE)
		state |= NUD_REACHABLE;
	if (dplane_state & DPLANE_NUD_STALE)
		state |= NUD_STALE;
	if (dplane_state & DPLANE_NUD_NOARP)
		state |= NUD_NOARP;
	if (dplane_state & DPLANE_NUD_PROBE)
		state |= NUD_PROBE;

	return state;
}


static inline bool is_selfroute(int proto)
{
	if ((proto == RTPROT_BGP) || (proto == RTPROT_OSPF)
	    || (proto == RTPROT_ZSTATIC) || (proto == RTPROT_ZEBRA)
	    || (proto == RTPROT_ISIS) || (proto == RTPROT_RIPNG)
	    || (proto == RTPROT_NHRP) || (proto == RTPROT_EIGRP)
	    || (proto == RTPROT_LDP) || (proto == RTPROT_BABEL)
	    || (proto == RTPROT_RIP) || (proto == RTPROT_SHARP)
	    || (proto == RTPROT_PBR) || (proto == RTPROT_OPENFABRIC)) {
		return true;
	}

	return false;
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
		proto = RTPROT_ZSTATIC;
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
	case ZEBRA_ROUTE_PBR:
		proto = RTPROT_PBR;
		break;
	case ZEBRA_ROUTE_OPENFABRIC:
		proto = RTPROT_OPENFABRIC;
		break;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		proto = RTPROT_ZEBRA;
		break;
	default:
		/*
		 * When a user adds a new protocol this will show up
		 * to let them know to do something about it.  This
		 * is intentionally a warn because we should see
		 * this as part of development of a new protocol
		 */
		zlog_debug(
			"%s: Please add this protocol(%d) to proper rt_netlink.c handling",
			__func__, proto);
		proto = RTPROT_ZEBRA;
		break;
	}

	return proto;
}

static inline int proto2zebra(int proto, int family, bool is_nexthop)
{
	switch (proto) {
	case RTPROT_BABEL:
		proto = ZEBRA_ROUTE_BABEL;
		break;
	case RTPROT_BGP:
		proto = ZEBRA_ROUTE_BGP;
		break;
	case RTPROT_OSPF:
		proto = (family == AFI_IP) ? ZEBRA_ROUTE_OSPF
					   : ZEBRA_ROUTE_OSPF6;
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
	case RTPROT_ZSTATIC:
		proto = ZEBRA_ROUTE_STATIC;
		break;
	case RTPROT_SHARP:
		proto = ZEBRA_ROUTE_SHARP;
		break;
	case RTPROT_PBR:
		proto = ZEBRA_ROUTE_PBR;
		break;
	case RTPROT_OPENFABRIC:
		proto = ZEBRA_ROUTE_OPENFABRIC;
		break;
	case RTPROT_ZEBRA:
		if (is_nexthop) {
			proto = ZEBRA_ROUTE_NHG;
			break;
		}
		/* Intentional fall thru */
	default:
		/*
		 * When a user adds a new protocol this will show up
		 * to let them know to do something about it.  This
		 * is intentionally a warn because we should see
		 * this as part of development of a new protocol
		 */
		zlog_debug(
			"%s: Please add this protocol(%d) to proper rt_netlink.c handling",
			__func__, proto);
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
}

/*
Pending: create an efficient table_id (in a tree/hash) based lookup)
 */
static vrf_id_t vrf_lookup_by_table(uint32_t table_id, ns_id_t ns_id)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (zvrf == NULL)
			continue;
		/* case vrf with netns : match the netnsid */
		if (vrf_is_backend_netns()) {
			if (ns_id == zvrf_id(zvrf))
				return zvrf_id(zvrf);
		} else {
			/* VRF is VRF_BACKEND_VRF_LITE */
			if (zvrf->table_id != table_id)
				continue;
			return zvrf_id(zvrf);
		}
	}

	return VRF_DEFAULT;
}

/**
 * @parse_encap_mpls() - Parses encapsulated mpls attributes
 * @tb:         Pointer to rtattr to look for nested items in.
 * @labels:     Pointer to store labels in.
 *
 * Return:      Number of mpls labels found.
 */
static int parse_encap_mpls(struct rtattr *tb, mpls_label_t *labels)
{
	struct rtattr *tb_encap[MPLS_IPTUNNEL_MAX + 1] = {0};
	mpls_lse_t *lses = NULL;
	int num_labels = 0;
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;
	mpls_label_t label = 0;

	netlink_parse_rtattr_nested(tb_encap, MPLS_IPTUNNEL_MAX, tb);
	lses = (mpls_lse_t *)RTA_DATA(tb_encap[MPLS_IPTUNNEL_DST]);
	while (!bos && num_labels < MPLS_MAX_LABELS) {
		mpls_lse_decode(lses[num_labels], &label, &ttl, &exp, &bos);
		labels[num_labels++] = label;
	}

	return num_labels;
}

static struct nexthop
parse_nexthop_unicast(ns_id_t ns_id, struct rtmsg *rtm, struct rtattr **tb,
		      enum blackhole_type bh_type, int index, void *prefsrc,
		      void *gate, afi_t afi, vrf_id_t vrf_id)
{
	struct interface *ifp = NULL;
	struct nexthop nh = {0};
	mpls_label_t labels[MPLS_MAX_LABELS] = {0};
	int num_labels = 0;

	vrf_id_t nh_vrf_id = vrf_id;
	size_t sz = (afi == AFI_IP) ? 4 : 16;

	if (bh_type == BLACKHOLE_UNSPEC) {
		if (index && !gate)
			nh.type = NEXTHOP_TYPE_IFINDEX;
		else if (index && gate)
			nh.type = (afi == AFI_IP) ? NEXTHOP_TYPE_IPV4_IFINDEX
						  : NEXTHOP_TYPE_IPV6_IFINDEX;
		else if (!index && gate)
			nh.type = (afi == AFI_IP) ? NEXTHOP_TYPE_IPV4
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
		ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), index);
		if (ifp)
			nh_vrf_id = ifp->vrf_id;
	}
	nh.vrf_id = nh_vrf_id;

	if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE]
	    && *(uint16_t *)RTA_DATA(tb[RTA_ENCAP_TYPE])
		       == LWTUNNEL_ENCAP_MPLS) {
		num_labels = parse_encap_mpls(tb[RTA_ENCAP], labels);
	}

	if (rtm->rtm_flags & RTNH_F_ONLINK)
		SET_FLAG(nh.flags, NEXTHOP_FLAG_ONLINK);

	if (num_labels)
		nexthop_add_labels(&nh, ZEBRA_LSP_STATIC, num_labels, labels);

	return nh;
}

static uint8_t parse_multipath_nexthops_unicast(ns_id_t ns_id,
						struct nexthop_group *ng,
						struct rtmsg *rtm,
						struct rtnexthop *rtnh,
						struct rtattr **tb,
						void *prefsrc, vrf_id_t vrf_id)
{
	void *gate = NULL;
	struct interface *ifp = NULL;
	int index = 0;
	/* MPLS labels */
	mpls_label_t labels[MPLS_MAX_LABELS] = {0};
	int num_labels = 0;
	struct rtattr *rtnh_tb[RTA_MAX + 1] = {};

	int len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);
	vrf_id_t nh_vrf_id = vrf_id;

	for (;;) {
		struct nexthop *nh = NULL;

		if (len < (int)sizeof(*rtnh) || rtnh->rtnh_len > len)
			break;

		index = rtnh->rtnh_ifindex;
		if (index) {
			/*
			 * Yes we are looking this up
			 * for every nexthop and just
			 * using the last one looked
			 * up right now
			 */
			ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
							index);
			if (ifp)
				nh_vrf_id = ifp->vrf_id;
			else {
				flog_warn(
					EC_ZEBRA_UNKNOWN_INTERFACE,
					"%s: Unknown interface %u specified, defaulting to VRF_DEFAULT",
					__func__, index);
				nh_vrf_id = VRF_DEFAULT;
			}
		} else
			nh_vrf_id = vrf_id;

		if (rtnh->rtnh_len > sizeof(*rtnh)) {
			memset(rtnh_tb, 0, sizeof(rtnh_tb));

			netlink_parse_rtattr(rtnh_tb, RTA_MAX, RTNH_DATA(rtnh),
					     rtnh->rtnh_len - sizeof(*rtnh));
			if (rtnh_tb[RTA_GATEWAY])
				gate = RTA_DATA(rtnh_tb[RTA_GATEWAY]);
			if (rtnh_tb[RTA_ENCAP] && rtnh_tb[RTA_ENCAP_TYPE]
			    && *(uint16_t *)RTA_DATA(rtnh_tb[RTA_ENCAP_TYPE])
				       == LWTUNNEL_ENCAP_MPLS) {
				num_labels = parse_encap_mpls(
					rtnh_tb[RTA_ENCAP], labels);
			}
		}

		if (gate && rtm->rtm_family == AF_INET) {
			if (index)
				nh = nexthop_from_ipv4_ifindex(
					gate, prefsrc, index, nh_vrf_id);
			else
				nh = nexthop_from_ipv4(gate, prefsrc,
						       nh_vrf_id);
		} else if (gate && rtm->rtm_family == AF_INET6) {
			if (index)
				nh = nexthop_from_ipv6_ifindex(
					gate, index, nh_vrf_id);
			else
				nh = nexthop_from_ipv6(gate, nh_vrf_id);
		} else
			nh = nexthop_from_ifindex(index, nh_vrf_id);

		if (nh) {
			nh->weight = rtnh->rtnh_hops + 1;

			if (num_labels)
				nexthop_add_labels(nh, ZEBRA_LSP_STATIC,
						   num_labels, labels);

			if (rtnh->rtnh_flags & RTNH_F_ONLINK)
				SET_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK);

			/* Add to temporary list */
			nexthop_group_add_sorted(ng, nh);
		}

		if (rtnh->rtnh_len == 0)
			break;

		len -= NLMSG_ALIGN(rtnh->rtnh_len);
		rtnh = RTNH_NEXT(rtnh);
	}

	uint8_t nhop_num = nexthop_group_nexthop_num(ng);

	return nhop_num;
}

/* Looking up routing table by netlink interface. */
static int netlink_route_change_read_unicast(struct nlmsghdr *h, ns_id_t ns_id,
					     int startup)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	uint8_t flags = 0;
	struct prefix p;
	struct prefix_ipv6 src_p = {};
	vrf_id_t vrf_id;
	bool selfroute;

	char anyaddr[16] = {0};

	int proto = ZEBRA_ROUTE_KERNEL;
	int index = 0;
	int table;
	int metric = 0;
	uint32_t mtu = 0;
	uint8_t distance = 0;
	route_tag_t tag = 0;
	uint32_t nhe_id = 0;

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
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Route rtm_type: %s(%d) intentionally ignoring",
				   nl_rttype_to_str(rtm->rtm_type),
				   rtm->rtm_type);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct rtmsg)));
		return -1;
	}

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (rtm->rtm_flags & RTM_F_CLONED)
		return 0;
	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return 0;
	if (rtm->rtm_protocol == RTPROT_KERNEL)
		return 0;

	selfroute = is_selfroute(rtm->rtm_protocol);

	if (!startup && selfroute && h->nlmsg_type == RTM_NEWROUTE) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Route type: %d Received that we think we have originated, ignoring",
				   rtm->rtm_protocol);
		return 0;
	}

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
	vrf_id = vrf_lookup_by_table(table, ns_id);
	if (vrf_id == VRF_DEFAULT) {
		if (!is_zebra_valid_kernel_table(table)
		    && !is_zebra_main_routing_table(table))
			return 0;
	}

	/* Route which inserted by Zebra. */
	if (selfroute) {
		flags |= ZEBRA_FLAG_SELFROUTE;
		proto = proto2zebra(rtm->rtm_protocol, rtm->rtm_family, false);
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

	if (tb[RTA_NH_ID])
		nhe_id = *(uint32_t *)RTA_DATA(tb[RTA_NH_ID]);

	if (tb[RTA_PRIORITY])
		metric = *(int *)RTA_DATA(tb[RTA_PRIORITY]);

#if defined(SUPPORT_REALMS)
	if (tb[RTA_FLOW])
		tag = *(uint32_t *)RTA_DATA(tb[RTA_FLOW]);
#endif

	if (tb[RTA_METRICS]) {
		struct rtattr *mxrta[RTAX_MAX + 1];

		memset(mxrta, 0, sizeof(mxrta));
		netlink_parse_rtattr(mxrta, RTAX_MAX, RTA_DATA(tb[RTA_METRICS]),
				     RTA_PAYLOAD(tb[RTA_METRICS]));

		if (mxrta[RTAX_MTU])
			mtu = *(uint32_t *)RTA_DATA(mxrta[RTAX_MTU]);
	}

	if (rtm->rtm_family == AF_INET) {
		p.family = AF_INET;
		if (rtm->rtm_dst_len > IPV4_MAX_BITLEN) {
			zlog_err(
				"Invalid destination prefix length: %u received from kernel route change",
				rtm->rtm_dst_len);
			return -1;
		}
		memcpy(&p.u.prefix4, dest, 4);
		p.prefixlen = rtm->rtm_dst_len;

		if (rtm->rtm_src_len != 0) {
			char buf[PREFIX_STRLEN];
			flog_warn(
				EC_ZEBRA_UNSUPPORTED_V4_SRCDEST,
				"unsupported IPv4 sourcedest route (dest %s vrf %u)",
				prefix2str(&p, buf, sizeof(buf)), vrf_id);
			return 0;
		}

		/* Force debug below to not display anything for source */
		src_p.prefixlen = 0;
	} else if (rtm->rtm_family == AF_INET6) {
		p.family = AF_INET6;
		if (rtm->rtm_dst_len > IPV6_MAX_BITLEN) {
			zlog_err(
				"Invalid destination prefix length: %u received from kernel route change",
				rtm->rtm_dst_len);
			return -1;
		}
		memcpy(&p.u.prefix6, dest, 16);
		p.prefixlen = rtm->rtm_dst_len;

		src_p.family = AF_INET6;
		if (rtm->rtm_src_len > IPV6_MAX_BITLEN) {
			zlog_err(
				"Invalid source prefix length: %u received from kernel route change",
				rtm->rtm_src_len);
			return -1;
		}
		memcpy(&src_p.prefix, src, 16);
		src_p.prefixlen = rtm->rtm_src_len;
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
		metric = (metric & 0x00FFFFFF);
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf[PREFIX_STRLEN];
		char buf2[PREFIX_STRLEN];
		zlog_debug(
			"%s %s%s%s vrf %s(%u) table_id: %u metric: %d Admin Distance: %d",
			nl_msg_type_to_str(h->nlmsg_type),
			prefix2str(&p, buf, sizeof(buf)),
			src_p.prefixlen ? " from " : "",
			src_p.prefixlen ? prefix2str(&src_p, buf2, sizeof(buf2))
					: "",
			vrf_id_to_name(vrf_id), vrf_id, table, metric,
			distance);
	}

	afi_t afi = AFI_IP;
	if (rtm->rtm_family == AF_INET6)
		afi = AFI_IP6;

	if (h->nlmsg_type == RTM_NEWROUTE) {

		if (!tb[RTA_MULTIPATH]) {
			struct nexthop nh = {0};

			if (!nhe_id) {
				nh = parse_nexthop_unicast(
					ns_id, rtm, tb, bh_type, index, prefsrc,
					gate, afi, vrf_id);
			}
			rib_add(afi, SAFI_UNICAST, vrf_id, proto, 0, flags, &p,
				&src_p, &nh, nhe_id, table, metric, mtu,
				distance, tag);
		} else {
			/* This is a multipath route */
			struct route_entry *re;
			struct nexthop_group *ng = NULL;
			struct rtnexthop *rtnh =
				(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);

			re = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
			re->type = proto;
			re->distance = distance;
			re->flags = flags;
			re->metric = metric;
			re->mtu = mtu;
			re->vrf_id = vrf_id;
			re->table = table;
			re->uptime = monotime(NULL);
			re->tag = tag;
			re->nhe_id = nhe_id;

			if (!nhe_id) {
				uint8_t nhop_num;

				/* Use temporary list of nexthops; parse
				 * message payload's nexthops.
				 */
				ng = nexthop_group_new();
				nhop_num =
					parse_multipath_nexthops_unicast(
						ns_id, ng, rtm, rtnh, tb,
						prefsrc, vrf_id);

				zserv_nexthop_num_warn(
					__func__, (const struct prefix *)&p,
					nhop_num);

				if (nhop_num == 0) {
					nexthop_group_delete(&ng);
					ng = NULL;
				}
			}

			if (nhe_id || ng)
				rib_add_multipath(afi, SAFI_UNICAST, &p,
						  &src_p, re, ng);
			else
				XFREE(MTYPE_RE, re);
		}
	} else {
		if (nhe_id) {
			rib_delete(afi, SAFI_UNICAST, vrf_id, proto, 0, flags,
				   &p, &src_p, NULL, nhe_id, table, metric,
				   distance, true);
		} else {
			if (!tb[RTA_MULTIPATH]) {
				struct nexthop nh;

				nh = parse_nexthop_unicast(
					ns_id, rtm, tb, bh_type, index, prefsrc,
					gate, afi, vrf_id);
				rib_delete(afi, SAFI_UNICAST, vrf_id, proto, 0,
					   flags, &p, &src_p, &nh, 0, table,
					   metric, distance, true);
			} else {
				/* XXX: need to compare the entire list of
				 * nexthops here for NLM_F_APPEND stupidity */
				rib_delete(afi, SAFI_UNICAST, vrf_id, proto, 0,
					   flags, &p, &src_p, NULL, 0, table,
					   metric, distance, true);
			}
		}
	}

	return 0;
}

static struct mcast_route_data *mroute = NULL;

static int netlink_route_change_read_multicast(struct nlmsghdr *h,
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
	vrf_id_t vrf;
	int table;

	if (mroute)
		m = mroute;
	else {
		memset(&mr, 0, sizeof(mr));
		m = &mr;
	}

	rtm = NLMSG_DATA(h);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (tb[RTA_TABLE])
		table = *(int *)RTA_DATA(tb[RTA_TABLE]);
	else
		table = rtm->rtm_table;

	vrf = vrf_lookup_by_table(table, ns_id);

	if (tb[RTA_IIF])
		iif = *(int *)RTA_DATA(tb[RTA_IIF]);

	if (tb[RTA_SRC])
		m->sg.src = *(struct in_addr *)RTA_DATA(tb[RTA_SRC]);

	if (tb[RTA_DST])
		m->sg.grp = *(struct in_addr *)RTA_DATA(tb[RTA_DST]);

	if (tb[RTA_EXPIRES])
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

			if (rtnh->rtnh_len == 0)
				break;

			len -= NLMSG_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		struct interface *ifp = NULL;
		struct zebra_vrf *zvrf = NULL;

		strlcpy(sbuf, inet_ntoa(m->sg.src), sizeof(sbuf));
		strlcpy(gbuf, inet_ntoa(m->sg.grp), sizeof(gbuf));
		for (count = 0; count < oif_count; count++) {
			ifp = if_lookup_by_index(oif[count], vrf);
			char temp[256];

			sprintf(temp, "%s(%d) ", ifp ? ifp->name : "Unknown",
				oif[count]);
			strlcat(oif_list, temp, sizeof(oif_list));
		}
		zvrf = zebra_vrf_lookup_by_id(vrf);
		ifp = if_lookup_by_index(iif, vrf);
		zlog_debug(
			"MCAST VRF: %s(%d) %s (%s,%s) IIF: %s(%d) OIF: %s jiffies: %lld",
			zvrf_name(zvrf), vrf, nl_msg_type_to_str(h->nlmsg_type),
			sbuf, gbuf, ifp ? ifp->name : "Unknown", iif, oif_list,
			m->lastused);
	}
	return 0;
}

int netlink_route_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct rtmsg *rtm;

	rtm = NLMSG_DATA(h);

	if (!(h->nlmsg_type == RTM_NEWROUTE || h->nlmsg_type == RTM_DELROUTE)) {
		/* If this is not route add/delete message print warning. */
		zlog_debug("Kernel message: %s NS %u",
			   nl_msg_type_to_str(h->nlmsg_type), ns_id);
		return 0;
	}

	if (!(rtm->rtm_family == AF_INET ||
	      rtm->rtm_family == AF_INET6 ||
	      rtm->rtm_family == RTNL_FAMILY_IPMR )) {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel route change: %s",
			rtm->rtm_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	/* Connected route. */
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s %s %s proto %s NS %u",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(rtm->rtm_family),
			   nl_rttype_to_str(rtm->rtm_type),
			   nl_rtproto_to_str(rtm->rtm_protocol), ns_id);


	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size: %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct rtmsg)));
		return -1;
	}

	if (rtm->rtm_type == RTN_MULTICAST)
		netlink_route_change_read_multicast(h, ns_id, startup);
	else
		netlink_route_change_read_unicast(h, ns_id, startup);
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
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.rtm.rtm_family = family;

	return netlink_request(&zns->netlink_cmd, &req);
}

/* Routing table read function using netlink interface.  Only called
   bootstrap time. */
int netlink_route_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get IPv4 routing table. */
	ret = netlink_request_route(zns, AF_INET, RTM_GETROUTE);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_route_change_read_unicast,
				 &zns->netlink_cmd, &dp_info, 0, 1);
	if (ret < 0)
		return ret;

	/* Get IPv6 routing table. */
	ret = netlink_request_route(zns, AF_INET6, RTM_GETROUTE);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_route_change_read_unicast,
				 &zns->netlink_cmd, &dp_info, 0, 1);
	if (ret < 0)
		return ret;

	return 0;
}

static void _netlink_route_nl_add_gateway_info(uint8_t route_family,
					       uint8_t gw_family,
					       struct nlmsghdr *nlmsg,
					       size_t req_size, int bytelen,
					       const struct nexthop *nexthop)
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

static void _netlink_route_rta_add_gateway_info(uint8_t route_family,
						uint8_t gw_family,
						struct rtattr *rta,
						struct rtnexthop *rtnh,
						size_t req_size, int bytelen,
						const struct nexthop *nexthop)
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

static int build_label_stack(struct mpls_label_stack *nh_label,
			     mpls_lse_t *out_lse, char *label_buf,
			     size_t label_buf_size)
{
	char label_buf1[20];
	int num_labels = 0;

	for (int i = 0; nh_label && i < nh_label->num_labels; i++) {
		if (nh_label->label[i] == MPLS_LABEL_IMPLICIT_NULL)
			continue;

		if (IS_ZEBRA_DEBUG_KERNEL) {
			if (!num_labels)
				sprintf(label_buf, "label %u",
					nh_label->label[i]);
			else {
				sprintf(label_buf1, "/%u", nh_label->label[i]);
				strlcat(label_buf, label_buf1, label_buf_size);
			}
		}

		out_lse[num_labels] =
			mpls_lse_encode(nh_label->label[i], 0, 0, 0);
		num_labels++;
	}

	return num_labels;
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
static void _netlink_route_build_singlepath(const struct prefix *p,
					    const char *routedesc, int bytelen,
					    const struct nexthop *nexthop,
					    struct nlmsghdr *nlmsg,
					    struct rtmsg *rtmsg,
					    size_t req_size, int cmd)
{

	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];
	int num_labels = 0;
	struct vrf *vrf;
	char addrstr[INET6_ADDRSTRLEN];

	assert(nexthop);

	vrf = vrf_lookup_by_id(nexthop->vrf_id);

	/*
	 * label_buf is *only* currently used within debugging.
	 * As such when we assign it we are guarding it inside
	 * a debug test.  If you want to change this make sure
	 * you fix this assumption
	 */
	label_buf[0] = '\0';

	num_labels = build_label_stack(nexthop->nh_label, out_lse, label_buf,
				       sizeof(label_buf));

	if (num_labels) {
		/* Set the BoS bit */
		out_lse[num_labels - 1] |= htonl(1 << MPLS_LS_S_SHIFT);

		if (rtmsg->rtm_family == AF_MPLS)
			addattr_l(nlmsg, req_size, RTA_NEWDST, &out_lse,
				  num_labels * sizeof(mpls_lse_t));
		else {
			struct rtattr *nest;
			uint16_t encap = LWTUNNEL_ENCAP_MPLS;

			addattr_l(nlmsg, req_size, RTA_ENCAP_TYPE, &encap,
				  sizeof(uint16_t));
			nest = addattr_nest(nlmsg, req_size, RTA_ENCAP);
			addattr_l(nlmsg, req_size, MPLS_IPTUNNEL_DST, &out_lse,
				  num_labels * sizeof(mpls_lse_t));
			addattr_nest_end(nlmsg, nest);
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

		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY
		    && (cmd == RTM_NEWROUTE))
			addattr_l(nlmsg, req_size, RTA_PREFSRC,
				  &nexthop->rmap_src.ipv4, bytelen);
		else if (nexthop->src.ipv4.s_addr != INADDR_ANY
			 && (cmd == RTM_NEWROUTE))
			addattr_l(nlmsg, req_size, RTA_PREFSRC,
				  &nexthop->src.ipv4, bytelen);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: 5549 (%s): %pFX nexthop via %s %s if %u vrf %s(%u)",
				   __func__, routedesc, p, ipv4_ll_buf,
				   label_buf, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
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
			if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv4, bytelen);
			else if (nexthop->src.ipv4.s_addr != INADDR_ANY)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv4, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL) {
			inet_ntop(AF_INET, &nexthop->gate.ipv4, addrstr,
				  sizeof(addrstr));
			zlog_debug("%s: (%s): %pFX nexthop via %s %s if %u vrf %s(%u)",
				   __func__, routedesc, p, addrstr, label_buf,
				   nexthop->ifindex, VRF_LOGNAME(vrf),
				   nexthop->vrf_id);
		}
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

		if (IS_ZEBRA_DEBUG_KERNEL) {
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, addrstr,
				  sizeof(addrstr));
			zlog_debug("%s: (%s): %pFX nexthop via %s %s if %u vrf %s(%u)",
				   __func__, routedesc, p, addrstr, label_buf,
				   nexthop->ifindex, VRF_LOGNAME(vrf),
				   nexthop->vrf_id);
		}
	}

	/*
	 * We have the ifindex so we should always send it
	 * This is especially useful if we are doing route
	 * leaking.
	 */
	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		addattr32(nlmsg, req_size, RTA_OIF, nexthop->ifindex);

	if (nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		if (cmd == RTM_NEWROUTE) {
			if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->rmap_src.ipv4, bytelen);
			else if (nexthop->src.ipv4.s_addr != INADDR_ANY)
				addattr_l(nlmsg, req_size, RTA_PREFSRC,
					  &nexthop->src.ipv4, bytelen);
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: (%s): %pFX nexthop via if %u vrf %s(%u)",
				   __func__, routedesc, p, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
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
static void
_netlink_route_build_multipath(const struct prefix *p, const char *routedesc,
			       int bytelen, const struct nexthop *nexthop,
			       struct rtattr *rta, struct rtnexthop *rtnh,
			       struct rtmsg *rtmsg, const union g_addr **src)
{
	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];
	int num_labels = 0;
	struct vrf *vrf;

	rtnh->rtnh_len = sizeof(*rtnh);
	rtnh->rtnh_flags = 0;
	rtnh->rtnh_hops = 0;
	rta->rta_len += rtnh->rtnh_len;

	assert(nexthop);

	vrf = vrf_lookup_by_id(nexthop->vrf_id);

	/*
	 * label_buf is *only* currently used within debugging.
	 * As such when we assign it we are guarding it inside
	 * a debug test.  If you want to change this make sure
	 * you fix this assumption
	 */
	label_buf[0] = '\0';

	num_labels = build_label_stack(nexthop->nh_label, out_lse, label_buf,
				       sizeof(label_buf));

	if (num_labels) {
		/* Set the BoS bit */
		out_lse[num_labels - 1] |= htonl(1 << MPLS_LS_S_SHIFT);

		if (rtmsg->rtm_family == AF_MPLS) {
			rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_NEWDST,
				      &out_lse,
				      num_labels * sizeof(mpls_lse_t));
			rtnh->rtnh_len +=
				RTA_LENGTH(num_labels * sizeof(mpls_lse_t));
		} else {
			struct rtattr *nest;
			uint16_t encap = LWTUNNEL_ENCAP_MPLS;
			int len = rta->rta_len;

			rta_addattr_l(rta, NL_PKT_BUF_SIZE, RTA_ENCAP_TYPE,
				      &encap, sizeof(uint16_t));
			nest = rta_nest(rta, NL_PKT_BUF_SIZE, RTA_ENCAP);
			rta_addattr_l(rta, NL_PKT_BUF_SIZE, MPLS_IPTUNNEL_DST,
				      &out_lse,
				      num_labels * sizeof(mpls_lse_t));
			rta_nest_end(rta, nest);
			rtnh->rtnh_len += rta->rta_len - len;
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
		if (nexthop->weight)
			rtnh->rtnh_hops = nexthop->weight - 1;

		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: 5549 (%s): %pFX nexthop via %s %s if %u vrf %s(%u)",
				__func__, routedesc, p, ipv4_ll_buf, label_buf,
				nexthop->ifindex, VRF_LOGNAME(vrf),
				nexthop->vrf_id);
		return;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		_netlink_route_rta_add_gateway_info(rtmsg->rtm_family, AF_INET,
						    rta, rtnh, NL_PKT_BUF_SIZE,
						    bytelen, nexthop);
		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: (%s): %pFX nexthop via %pI4 %s if %u vrf %s(%u)",
				   __func__, routedesc, p, &nexthop->gate.ipv4,
				   label_buf, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
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
			zlog_debug("%s: (%s): %pFX nexthop via %pI6 %s if %u vrf %s(%u)",
				   __func__, routedesc, p, &nexthop->gate.ipv6,
				   label_buf, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
	}

	/*
	 * We have figured out the ifindex so we should always send it
	 * This is especially useful if we are doing route
	 * leaking.
	 */
	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		rtnh->rtnh_ifindex = nexthop->ifindex;

	/* ifindex */
	if (nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->rmap_src;
		else if (nexthop->src.ipv4.s_addr != INADDR_ANY)
			*src = &nexthop->src;

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: (%s): %pFX nexthop via if %u vrf %s(%u)",
				   __func__, routedesc, p, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
	}

	if (nexthop->weight)
		rtnh->rtnh_hops = nexthop->weight - 1;
}

static inline void _netlink_mpls_build_singlepath(const struct prefix *p,
						  const char *routedesc,
						  const zebra_nhlfe_t *nhlfe,
						  struct nlmsghdr *nlmsg,
						  struct rtmsg *rtmsg,
						  size_t req_size, int cmd)
{
	int bytelen;
	uint8_t family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	_netlink_route_build_singlepath(p, routedesc, bytelen, nhlfe->nexthop,
					nlmsg, rtmsg, req_size, cmd);
}


static inline void
_netlink_mpls_build_multipath(const struct prefix *p, const char *routedesc,
			      const zebra_nhlfe_t *nhlfe, struct rtattr *rta,
			      struct rtnexthop *rtnh, struct rtmsg *rtmsg,
			      const union g_addr **src)
{
	int bytelen;
	uint8_t family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	_netlink_route_build_multipath(p, routedesc, bytelen, nhlfe->nexthop,
				       rta, rtnh, rtmsg, src);
}

static void _netlink_mpls_debug(int cmd, uint32_t label, const char *routedesc)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("netlink_mpls_multipath() (%s): %s %u/20", routedesc,
			   nl_msg_type_to_str(cmd), label);
}

static int netlink_neigh_update(int cmd, int ifindex, uint32_t addr, char *lla,
				int llalen, ns_id_t ns_id)
{
	uint8_t protocol = RTPROT_ZEBRA;
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	struct zebra_ns *zns = zebra_ns_lookup(ns_id);

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd; // RTM_NEWNEIGH or RTM_DELNEIGH
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ndm.ndm_family = AF_INET;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;

	addattr_l(&req.n, sizeof(req),
		  NDA_PROTOCOL, &protocol, sizeof(protocol));
	addattr_l(&req.n, sizeof(req), NDA_DST, &addr, 4);
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

static bool nexthop_set_src(const struct nexthop *nexthop, int family,
			    union g_addr *src)
{
	if (family == AF_INET) {
		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY) {
			src->ipv4 = nexthop->rmap_src.ipv4;
			return true;
		} else if (nexthop->src.ipv4.s_addr != INADDR_ANY) {
			src->ipv4 = nexthop->src.ipv4;
			return true;
		}
	} else if (family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6)) {
			src->ipv6 = nexthop->rmap_src.ipv6;
			return true;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6)) {
			src->ipv6 = nexthop->src.ipv6;
			return true;
		}
	}

	return false;
}

static void netlink_route_nexthop_encap(struct nlmsghdr *n, size_t nlen,
					struct nexthop *nh)
{
	struct rtattr *nest;

	switch (nh->nh_encap_type) {
	case NET_VXLAN:
		addattr_l(n, nlen, RTA_ENCAP_TYPE, &nh->nh_encap_type,
			  sizeof(uint16_t));

		nest = addattr_nest(n, nlen, RTA_ENCAP);
		addattr32(n, nlen, 0 /* VXLAN_VNI */, nh->nh_encap.vni);
		addattr_nest_end(n, nest);
		break;
	}
}

/*
 * Routing table change via netlink interface, using a dataplane context object
 */
ssize_t netlink_route_multipath(int cmd, struct zebra_dplane_ctx *ctx,
				uint8_t *data, size_t datalen, bool fpm)
{
	int bytelen;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	const char *routedesc;
	bool setsrc = false;
	union g_addr src;
	const struct prefix *p, *src_p;
	uint32_t table_id;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	p = dplane_ctx_get_dest(ctx);
	src_p = dplane_ctx_get_src(ctx);

	memset(req, 0, sizeof(*req));

	bytelen = (p->family == AF_INET ? 4 : 16);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if ((cmd == RTM_NEWROUTE) &&
	    ((p->family == AF_INET) || v6_rr_semantics))
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = dplane_ctx_get_ns(ctx)->nls.snl.nl_pid;

	req->r.rtm_family = p->family;
	req->r.rtm_dst_len = p->prefixlen;
	req->r.rtm_src_len = src_p ? src_p->prefixlen : 0;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;

	if (cmd == RTM_DELROUTE)
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_old_type(ctx));
	else
		req->r.rtm_protocol = zebra2proto(dplane_ctx_get_type(ctx));

	/*
	 * blackhole routes are not RTN_UNICAST, they are
	 * RTN_ BLACKHOLE|UNREACHABLE|PROHIBIT
	 * so setting this value as a RTN_UNICAST would
	 * cause the route lookup of just the prefix
	 * to fail.  So no need to specify this for
	 * the RTM_DELROUTE case
	 */
	if (cmd != RTM_DELROUTE)
		req->r.rtm_type = RTN_UNICAST;

	addattr_l(&req->n, datalen, RTA_DST, &p->u.prefix, bytelen);
	if (src_p)
		addattr_l(&req->n, datalen, RTA_SRC, &src_p->u.prefix, bytelen);

	/* Metric. */
	/* Hardcode the metric for all routes coming from zebra. Metric isn't
	 * used
	 * either by the kernel or by zebra. Its purely for calculating best
	 * path(s)
	 * by the routing protocol and for communicating with protocol peers.
	 */
	addattr32(&req->n, datalen, RTA_PRIORITY, NL_DEFAULT_ROUTE_METRIC);

#if defined(SUPPORT_REALMS)
	{
		route_tag_t tag;

		if (cmd == RTM_DELROUTE)
			tag = dplane_ctx_get_old_tag(ctx);
		else
			tag = dplane_ctx_get_tag(ctx);

		if (tag > 0 && tag <= 255)
			addattr32(&req->n, datalen, RTA_FLOW, tag);
	}
#endif
	/* Table corresponding to this route. */
	table_id = dplane_ctx_get_table(ctx);
	if (table_id < 256)
		req->r.rtm_table = table_id;
	else {
		req->r.rtm_table = RT_TABLE_UNSPEC;
		addattr32(&req->n, datalen, RTA_TABLE, table_id);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"%s: %s %pFX vrf %u(%u)", __func__,
			nl_msg_type_to_str(cmd), p, dplane_ctx_get_vrf(ctx),
			table_id);

	/*
	 * If we are not updating the route and we have received
	 * a route delete, then all we need to fill in is the
	 * prefix information to tell the kernel to schwack
	 * it.
	 */
	if (cmd == RTM_DELROUTE)
		return req->n.nlmsg_len;

	if (dplane_ctx_get_mtu(ctx) || dplane_ctx_get_nh_mtu(ctx)) {
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		uint32_t mtu = dplane_ctx_get_mtu(ctx);
		uint32_t nexthop_mtu = dplane_ctx_get_nh_mtu(ctx);

		if (!mtu || (nexthop_mtu && nexthop_mtu < mtu))
			mtu = nexthop_mtu;
		rta->rta_type = RTA_METRICS;
		rta->rta_len = RTA_LENGTH(0);
		rta_addattr_l(rta, NL_PKT_BUF_SIZE,
			      RTAX_MTU, &mtu, sizeof(mtu));
		addattr_l(&req->n, datalen, RTA_METRICS, RTA_DATA(rta),
			  RTA_PAYLOAD(rta));
	}

	if (kernel_nexthops_supported()
	    && (!proto_nexthops_only()
		|| is_proto_nhg(dplane_ctx_get_nhe_id(ctx), 0))) {
		/* Kernel supports nexthop objects */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"netlink_route_multipath(): %pFX nhg_id is %u",
				p, dplane_ctx_get_nhe_id(ctx));

		addattr32(&req->n, datalen, RTA_NH_ID,
			  dplane_ctx_get_nhe_id(ctx));

		/* Have to determine src still */
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (setsrc)
				break;

			setsrc = nexthop_set_src(nexthop, p->family, &src);
		}

		if (setsrc) {
			if (p->family == AF_INET)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv4, bytelen);
			else if (p->family == AF_INET6)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv6, bytelen);
		}

		return req->n.nlmsg_len;
	}

	/* Count overall nexthops so we can decide whether to use singlepath
	 * or multipath case.
	 */
	nexthop_num = 0;
	for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;
		if (!NEXTHOP_IS_ACTIVE(nexthop->flags))
			continue;

		nexthop_num++;
	}

	/* Singlepath case. */
	if (nexthop_num == 1) {
		nexthop_num = 0;
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
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
					req->r.rtm_type = RTN_PROHIBIT;
					break;
				case BLACKHOLE_REJECT:
					req->r.rtm_type = RTN_UNREACHABLE;
					break;
				default:
					req->r.rtm_type = RTN_BLACKHOLE;
					break;
				}
				return req->n.nlmsg_len;
			}
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {

				if (setsrc)
					continue;

				setsrc = nexthop_set_src(nexthop, p->family,
							 &src);
				continue;
			}

			if (NEXTHOP_IS_ACTIVE(nexthop->flags)) {
				routedesc = nexthop->rparent
						    ? "recursive, single-path"
						    : "single-path";

				_netlink_route_build_singlepath(
					p, routedesc, bytelen, nexthop, &req->n,
					&req->r, datalen, cmd);
				nexthop_num++;
				break;
			}

			/*
			 * Add encapsulation information when installing via
			 * FPM.
			 */
			if (fpm)
				netlink_route_nexthop_encap(&req->n, datalen,
							    nexthop);
		}

		if (setsrc) {
			if (p->family == AF_INET)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv4, bytelen);
			else if (p->family == AF_INET6)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv6, bytelen);
		}
	} else {    /* Multipath case */
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		struct rtnexthop *rtnh;
		const union g_addr *src1 = NULL;

		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

		nexthop_num = 0;
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {
				/* This only works for IPv4 now */
				if (setsrc)
					continue;

				setsrc = nexthop_set_src(nexthop, p->family,
							 &src);
				continue;
			}

			if (NEXTHOP_IS_ACTIVE(nexthop->flags)) {
				routedesc = nexthop->rparent
						    ? "recursive, multipath"
						    : "multipath";
				nexthop_num++;

				_netlink_route_build_multipath(
					p, routedesc, bytelen, nexthop, rta,
					rtnh, &req->r, &src1);
				rtnh = RTNH_NEXT(rtnh);

				if (!setsrc && src1) {
					if (p->family == AF_INET)
						src.ipv4 = src1->ipv4;
					else if (p->family == AF_INET6)
						src.ipv6 = src1->ipv6;

					setsrc = 1;
				}
			}

			/*
			 * Add encapsulation information when installing via
			 * FPM.
			 */
			if (fpm)
				netlink_route_nexthop_encap(&req->n, datalen,
							    nexthop);
		}

		if (setsrc) {
			if (p->family == AF_INET)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv4, bytelen);
			else if (p->family == AF_INET6)
				addattr_l(&req->n, datalen, RTA_PREFSRC,
					  &src.ipv6, bytelen);
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("Setting source");
		}

		if (rta->rta_len > RTA_LENGTH(0))
			addattr_l(&req->n, datalen, RTA_MULTIPATH,
				  RTA_DATA(rta), RTA_PAYLOAD(rta));
	}

	/* If there is no useful nexthop then return. */
	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: No useful nexthop.", __func__);
	}

	return req->n.nlmsg_len;
}

int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *in)
{
	uint32_t actual_table;
	int suc = 0;
	struct mcast_route_data *mr = (struct mcast_route_data *)in;
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	mroute = mr;
	struct zebra_ns *zns;

	zns = zvrf->zns;
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ndm.ndm_family = RTNL_FAMILY_IPMR;
	req.n.nlmsg_type = RTM_GETROUTE;

	addattr_l(&req.n, sizeof(req), RTA_IIF, &mroute->ifindex, 4);
	addattr_l(&req.n, sizeof(req), RTA_OIF, &mroute->ifindex, 4);
	addattr_l(&req.n, sizeof(req), RTA_SRC, &mroute->sg.src.s_addr, 4);
	addattr_l(&req.n, sizeof(req), RTA_DST, &mroute->sg.grp.s_addr, 4);
	/*
	 * What?
	 *
	 * So during the namespace cleanup we started storing
	 * the zvrf table_id for the default table as RT_TABLE_MAIN
	 * which is what the normal routing table for ip routing is.
	 * This change caused this to break our lookups of sg data
	 * because prior to this change the zvrf->table_id was 0
	 * and when the pim multicast kernel code saw a 0,
	 * it was auto-translated to RT_TABLE_DEFAULT.  But since
	 * we are now passing in RT_TABLE_MAIN there is no auto-translation
	 * and the kernel goes screw you and the delicious cookies you
	 * are trying to give me.  So now we have this little hack.
	 */
	actual_table = (zvrf->table_id == RT_TABLE_MAIN) ? RT_TABLE_DEFAULT :
		zvrf->table_id;
	addattr_l(&req.n, sizeof(req), RTA_TABLE, &actual_table, 4);

	suc = netlink_talk(netlink_route_change_read_multicast, &req.n,
			   &zns->netlink_cmd, zns, 0);

	mroute = NULL;
	return suc;
}

/* Char length to debug ID with */
#define ID_LENGTH 10

static void _netlink_nexthop_build_group(struct nlmsghdr *n, size_t req_size,
					 uint32_t id,
					 const struct nh_grp *z_grp,
					 const uint8_t count)
{
	struct nexthop_grp grp[count];
	/* Need space for max group size, "/", and null term */
	char buf[(MULTIPATH_NUM * (ID_LENGTH + 1)) + 1];
	char buf1[ID_LENGTH + 2];

	buf[0] = '\0';

	memset(grp, 0, sizeof(grp));

	if (count) {
		for (int i = 0; i < count; i++) {
			grp[i].id = z_grp[i].id;
			grp[i].weight = z_grp[i].weight - 1;

			if (IS_ZEBRA_DEBUG_KERNEL) {
				if (i == 0)
					snprintf(buf, sizeof(buf1), "group %u",
						 grp[i].id);
				else {
					snprintf(buf1, sizeof(buf1), "/%u",
						 grp[i].id);
					strlcat(buf, buf1, sizeof(buf));
				}
			}
		}
		addattr_l(n, req_size, NHA_GROUP, grp, count * sizeof(*grp));
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: ID (%u): %s", __func__, id, buf);
}

/**
 * netlink_nexthop() - Nexthop change via the netlink interface
 *
 * @ctx:	Dataplane ctx
 *
 * Return:	Result status
 */
static int netlink_nexthop(int cmd, struct zebra_dplane_ctx *ctx)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];
	int num_labels = 0;
	size_t req_size = sizeof(req);
	uint32_t id = dplane_ctx_get_nhe_id(ctx);
	int type = dplane_ctx_get_nhe_type(ctx);

	if (!id) {
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Failed trying to update a nexthop group in the kernel that does not have an ID");
		return -1;
	}

	/*
	 * Nothing to do if the kernel doesn't support nexthop objects or
	 * we dont want to install this type of NHG
	 */
	if (!kernel_nexthops_supported()) {
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): kernel nexthops not supported, ignoring",
				__func__, id, zebra_route_string(type));
		return 0;
	}

	if (proto_nexthops_only() && !is_proto_nhg(id, type)) {
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: nhg_id %u (%s): proto-based nexthops only, ignoring",
				__func__, id, zebra_route_string(type));
		return 0;
	}

	label_buf[0] = '\0';

	memset(&req, 0, req_size);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (cmd == RTM_NEWNEXTHOP)
		req.n.nlmsg_flags |= NLM_F_REPLACE;

	req.n.nlmsg_type = cmd;
	req.n.nlmsg_pid = dplane_ctx_get_ns(ctx)->nls.snl.nl_pid;

	req.nhm.nh_family = AF_UNSPEC;
	/* TODO: Scope? */

	addattr32(&req.n, req_size, NHA_ID, id);

	if (cmd == RTM_NEWNEXTHOP) {
		/*
		 * We distinguish between a "group", which is a collection
		 * of ids, and a singleton nexthop with an id. The
		 * group is installed as an id that just refers to a list of
		 * other ids.
		 */
		if (dplane_ctx_get_nhe_nh_grp_count(ctx))
			_netlink_nexthop_build_group(
				&req.n, req_size, id,
				dplane_ctx_get_nhe_nh_grp(ctx),
				dplane_ctx_get_nhe_nh_grp_count(ctx));
		else {
			const struct nexthop *nh =
				dplane_ctx_get_nhe_ng(ctx)->nexthop;
			afi_t afi = dplane_ctx_get_nhe_afi(ctx);

			if (afi == AFI_IP)
				req.nhm.nh_family = AF_INET;
			else if (afi == AFI_IP6)
				req.nhm.nh_family = AF_INET6;

			switch (nh->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				addattr_l(&req.n, req_size, NHA_GATEWAY,
					  &nh->gate.ipv4, IPV4_MAX_BYTELEN);
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				addattr_l(&req.n, req_size, NHA_GATEWAY,
					  &nh->gate.ipv6, IPV6_MAX_BYTELEN);
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				addattr_l(&req.n, req_size, NHA_BLACKHOLE, NULL,
					  0);
				/* Blackhole shouldn't have anymore attributes
				 */
				goto nexthop_done;
			case NEXTHOP_TYPE_IFINDEX:
				/* Don't need anymore info for this */
				break;
			}

			if (!nh->ifindex) {
				flog_err(
					EC_ZEBRA_NHG_FIB_UPDATE,
					"Context received for kernel nexthop update without an interface");
				return -1;
			}

			addattr32(&req.n, req_size, NHA_OIF, nh->ifindex);

			if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK))
				req.nhm.nh_flags |= RTNH_F_ONLINK;

			num_labels =
				build_label_stack(nh->nh_label, out_lse,
						  label_buf, sizeof(label_buf));

			if (num_labels) {
				/* Set the BoS bit */
				out_lse[num_labels - 1] |=
					htonl(1 << MPLS_LS_S_SHIFT);

				/*
				 * TODO: MPLS unsupported for now in kernel.
				 */
				if (req.nhm.nh_family == AF_MPLS)
					goto nexthop_done;
#if 0
					addattr_l(&req.n, req_size, NHA_NEWDST,
						  &out_lse,
						  num_labels
							  * sizeof(mpls_lse_t));
#endif
				else {
					struct rtattr *nest;
					uint16_t encap = LWTUNNEL_ENCAP_MPLS;

					addattr_l(&req.n, req_size,
						  NHA_ENCAP_TYPE, &encap,
						  sizeof(uint16_t));
					nest = addattr_nest(&req.n, req_size,
							    NHA_ENCAP);
					addattr_l(&req.n, req_size,
						  MPLS_IPTUNNEL_DST, &out_lse,
						  num_labels
							  * sizeof(mpls_lse_t));
					addattr_nest_end(&req.n, nest);
				}
			}

nexthop_done:

			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: ID (%u): %pNHv vrf %s(%u) %s ",
					   __func__, id, nh,
					   vrf_id_to_name(nh->vrf_id),
					   nh->vrf_id, label_buf);
		}

		req.nhm.nh_protocol = zebra2proto(type);

	} else if (cmd != RTM_DELNEXTHOP) {
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Nexthop group kernel update command (%d) does not exist",
			cmd);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s, id=%u", __func__, nl_msg_type_to_str(cmd),
			   id);

	return netlink_talk_info(netlink_talk_filter, &req.n,
				 dplane_ctx_get_ns(ctx), 0);
}

/**
 * kernel_nexthop_update() - Update/delete a nexthop from the kernel
 *
 * @ctx:	Dataplane context
 *
 * Return:	Dataplane result flag
 */
enum zebra_dplane_result kernel_nexthop_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	int cmd = 0;
	int ret = 0;

	op = dplane_ctx_get_op(ctx);
	if (op == DPLANE_OP_NH_INSTALL || op == DPLANE_OP_NH_UPDATE)
		cmd = RTM_NEWNEXTHOP;
	else if (op == DPLANE_OP_NH_DELETE)
		cmd = RTM_DELNEXTHOP;
	else {
		flog_err(EC_ZEBRA_NHG_FIB_UPDATE,
			 "Context received for kernel nexthop update with incorrect OP code (%u)",
			 op);
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	ret = netlink_nexthop(cmd, ctx);

	return (ret == 0 ? ZEBRA_DPLANE_REQUEST_SUCCESS
			 : ZEBRA_DPLANE_REQUEST_FAILURE);
}

/*
 * Update or delete a prefix from the kernel,
 * using info from a dataplane context.
 */
enum zebra_dplane_result kernel_route_update(struct zebra_dplane_ctx *ctx)
{
	int cmd, ret;
	const struct prefix *p = dplane_ctx_get_dest(ctx);
	struct nexthop *nexthop;
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_DELETE) {
		cmd = RTM_DELROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_INSTALL) {
		cmd = RTM_NEWROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_UPDATE) {

		if (p->family == AF_INET || v6_rr_semantics) {
			/* Single 'replace' operation */
			cmd = RTM_NEWROUTE;

			/*
			 * With route replace semantics in place
			 * for v4 routes and the new route is a system
			 * route we do not install anything.
			 * The problem here is that the new system
			 * route should cause us to withdraw from
			 * the kernel the old non-system route
			 */
			if (RSYSTEM_ROUTE(dplane_ctx_get_type(ctx)) &&
			    !RSYSTEM_ROUTE(dplane_ctx_get_old_type(ctx))) {
				netlink_route_multipath(RTM_DELROUTE, ctx,
							nl_pkt, sizeof(nl_pkt),
							false);
				netlink_talk_info(netlink_talk_filter,
						  (struct nlmsghdr *)nl_pkt,
						  dplane_ctx_get_ns(ctx), 0);
			}
		} else {
			/*
			 * So v6 route replace semantics are not in
			 * the kernel at this point as I understand it.
			 * so let's do a delete then an add.
			 * In the future once v6 route replace semantics
			 * are in we can figure out what to do here to
			 * allow working with old and new kernels.
			 *
			 * I'm also intentionally ignoring the failure case
			 * of the route delete.  If that happens yeah we're
			 * screwed.
			 */
			if (!RSYSTEM_ROUTE(dplane_ctx_get_old_type(ctx))) {
				netlink_route_multipath(RTM_DELROUTE, ctx,
							nl_pkt, sizeof(nl_pkt),
							false);
				netlink_talk_info(netlink_talk_filter,
						  (struct nlmsghdr *)nl_pkt,
						  dplane_ctx_get_ns(ctx), 0);
			}
			cmd = RTM_NEWROUTE;
		}

	} else {
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (!RSYSTEM_ROUTE(dplane_ctx_get_type(ctx))) {
		netlink_route_multipath(cmd, ctx, nl_pkt, sizeof(nl_pkt),
					false);
		ret = netlink_talk_info(netlink_talk_filter,
					(struct nlmsghdr *)nl_pkt,
					dplane_ctx_get_ns(ctx), 0);
	} else
		ret = 0;
	if ((cmd == RTM_NEWROUTE) && (ret == 0)) {
		/* Update installed nexthops to signal which have been
		 * installed.
		 */
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			}
		}
	}

	return (ret == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

/**
 * netlink_nexthop_process_nh() - Parse the gatway/if info from a new nexthop
 *
 * @tb:		Netlink RTA data
 * @family:	Address family in the nhmsg
 * @ifp:	Interface connected - this should be NULL, we fill it in
 * @ns_id:	Namspace id
 *
 * Return:	New nexthop
 */
static struct nexthop netlink_nexthop_process_nh(struct rtattr **tb,
						 unsigned char family,
						 struct interface **ifp,
						 ns_id_t ns_id)
{
	struct nexthop nh = {};
	void *gate = NULL;
	enum nexthop_types_t type = 0;
	int if_index = 0;
	size_t sz = 0;
	struct interface *ifp_lookup;

	if_index = *(int *)RTA_DATA(tb[NHA_OIF]);


	if (tb[NHA_GATEWAY]) {
		switch (family) {
		case AF_INET:
			type = NEXTHOP_TYPE_IPV4_IFINDEX;
			sz = 4;
			break;
		case AF_INET6:
			type = NEXTHOP_TYPE_IPV6_IFINDEX;
			sz = 16;
			break;
		default:
			flog_warn(
				EC_ZEBRA_BAD_NHG_MESSAGE,
				"Nexthop gateway with bad address family (%d) received from kernel",
				family);
			return nh;
		}
		gate = RTA_DATA(tb[NHA_GATEWAY]);
	} else
		type = NEXTHOP_TYPE_IFINDEX;

	if (type)
		nh.type = type;

	if (gate)
		memcpy(&(nh.gate), gate, sz);

	if (if_index)
		nh.ifindex = if_index;

	ifp_lookup =
		if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), nh.ifindex);

	if (ifp)
		*ifp = ifp_lookup;
	if (ifp_lookup)
		nh.vrf_id = ifp_lookup->vrf_id;
	else {
		flog_warn(
			EC_ZEBRA_UNKNOWN_INTERFACE,
			"%s: Unknown nexthop interface %u received, defaulting to VRF_DEFAULT",
			__func__, nh.ifindex);

		nh.vrf_id = VRF_DEFAULT;
	}

	if (tb[NHA_ENCAP] && tb[NHA_ENCAP_TYPE]) {
		uint16_t encap_type = *(uint16_t *)RTA_DATA(tb[NHA_ENCAP_TYPE]);
		int num_labels = 0;

		mpls_label_t labels[MPLS_MAX_LABELS] = {0};

		if (encap_type == LWTUNNEL_ENCAP_MPLS)
			num_labels = parse_encap_mpls(tb[NHA_ENCAP], labels);

		if (num_labels)
			nexthop_add_labels(&nh, ZEBRA_LSP_STATIC, num_labels,
					   labels);
	}

	return nh;
}

static int netlink_nexthop_process_group(struct rtattr **tb,
					 struct nh_grp *z_grp, int z_grp_size)
{
	uint8_t count = 0;
	/* linux/nexthop.h group struct */
	struct nexthop_grp *n_grp = NULL;

	n_grp = (struct nexthop_grp *)RTA_DATA(tb[NHA_GROUP]);
	count = (RTA_PAYLOAD(tb[NHA_GROUP]) / sizeof(*n_grp));

	if (!count || (count * sizeof(*n_grp)) != RTA_PAYLOAD(tb[NHA_GROUP])) {
		flog_warn(EC_ZEBRA_BAD_NHG_MESSAGE,
			  "Invalid nexthop group received from the kernel");
		return count;
	}

#if 0
	// TODO: Need type for something?
	zlog_debug("Nexthop group type: %d",
		   *((uint16_t *)RTA_DATA(tb[NHA_GROUP_TYPE])));

#endif

	for (int i = 0; ((i < count) && (i < z_grp_size)); i++) {
		z_grp[i].id = n_grp[i].id;
		z_grp[i].weight = n_grp[i].weight + 1;
	}
	return count;
}

/**
 * netlink_nexthop_change() - Read in change about nexthops from the kernel
 *
 * @h:		Netlink message header
 * @ns_id:	Namspace id
 * @startup:	Are we reading under startup conditions?
 *
 * Return:	Result status
 */
int netlink_nexthop_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	/* nexthop group id */
	uint32_t id;
	unsigned char family;
	int type;
	afi_t afi = AFI_UNSPEC;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct interface *ifp = NULL;
	struct nhmsg *nhm = NULL;
	struct nexthop nh = {};
	struct nh_grp grp[MULTIPATH_NUM] = {};
	/* Count of nexthops in group array */
	uint8_t grp_count = 0;
	struct rtattr *tb[NHA_MAX + 1] = {};

	nhm = NLMSG_DATA(h);

	if (ns_id)
		vrf_id = ns_id;

	if (startup && h->nlmsg_type != RTM_NEWNEXTHOP)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct nhmsg));
	if (len < 0) {
		zlog_warn(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct nhmsg)));
		return -1;
	}

	netlink_parse_rtattr(tb, NHA_MAX, RTM_NHA(nhm), len);


	if (!tb[NHA_ID]) {
		flog_warn(
			EC_ZEBRA_BAD_NHG_MESSAGE,
			"Nexthop group without an ID received from the kernel");
		return -1;
	}

	/* We use the ID key'd nhg table for kernel updates */
	id = *((uint32_t *)RTA_DATA(tb[NHA_ID]));

	if (zebra_evpn_mh_is_fdb_nh(id)) {
		/* If this is a L2 NH just ignore it */
		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
			zlog_debug("Ignore kernel update (%u) for fdb-nh 0x%x",
					h->nlmsg_type, id);
		}
		return 0;
	}

	family = nhm->nh_family;
	afi = family2afi(family);

	type = proto2zebra(nhm->nh_protocol, 0, true);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s ID (%u) %s NS %u",
			   nl_msg_type_to_str(h->nlmsg_type), id,
			   nl_family_to_str(family), ns_id);


	if (h->nlmsg_type == RTM_NEWNEXTHOP) {
		if (tb[NHA_GROUP]) {
			/**
			 * If this is a group message its only going to have
			 * an array of nexthop IDs associated with it
			 */
			grp_count = netlink_nexthop_process_group(
				tb, grp, array_size(grp));
		} else {
			if (tb[NHA_BLACKHOLE]) {
				/**
				 * This nexthop is just for blackhole-ing
				 * traffic, it should not have an OIF, GATEWAY,
				 * or ENCAP
				 */
				nh.type = NEXTHOP_TYPE_BLACKHOLE;
				nh.bh_type = BLACKHOLE_UNSPEC;
			} else if (tb[NHA_OIF])
				/**
				 * This is a true new nexthop, so we need
				 * to parse the gateway and device info
				 */
				nh = netlink_nexthop_process_nh(tb, family,
								&ifp, ns_id);
			else {

				flog_warn(
					EC_ZEBRA_BAD_NHG_MESSAGE,
					"Invalid Nexthop message received from the kernel with ID (%u)",
					id);
				return -1;
			}
			SET_FLAG(nh.flags, NEXTHOP_FLAG_ACTIVE);
			if (nhm->nh_flags & RTNH_F_ONLINK)
				SET_FLAG(nh.flags, NEXTHOP_FLAG_ONLINK);
			vrf_id = nh.vrf_id;
		}

		if (zebra_nhg_kernel_find(id, &nh, grp, grp_count, vrf_id, afi,
					  type, startup))
			return -1;

	} else if (h->nlmsg_type == RTM_DELNEXTHOP)
		zebra_nhg_kernel_del(id, vrf_id);

	return 0;
}

/**
 * netlink_request_nexthop() - Request nextop information from the kernel
 * @zns:	Zebra namespace
 * @family:	AF_* netlink family
 * @type:	RTM_* route type
 *
 * Return:	Result status
 */
static int netlink_request_nexthop(struct zebra_ns *zns, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.nhm.nh_family = family;

	return netlink_request(&zns->netlink_cmd, &req);
}


/**
 * netlink_nexthop_read() - Nexthop read function using netlink interface
 *
 * @zns:	Zebra name space
 *
 * Return:	Result status
 * Only called at bootstrap time.
 */
int netlink_nexthop_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get nexthop objects */
	ret = netlink_request_nexthop(zns, AF_UNSPEC, RTM_GETNEXTHOP);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_nexthop_change, &zns->netlink_cmd,
				 &dp_info, 0, 1);

	if (!ret)
		/* If we succesfully read in nexthop objects,
		 * this kernel must support them.
		 */
		supports_nh = true;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
		zlog_debug("Nexthop objects %ssupported on this kernel",
			   supports_nh ? "" : "not ");

	return ret;
}


int kernel_neigh_update(int add, int ifindex, uint32_t addr, char *lla,
			int llalen, ns_id_t ns_id)
{
	return netlink_neigh_update(add ? RTM_NEWNEIGH : RTM_DELNEIGH, ifindex,
				    addr, lla, llalen, ns_id);
}

/**
 * netlink_update_neigh_ctx_internal() - Common helper api for evpn
 * neighbor updates using dataplane context object.
 * @ctx:		Dataplane context
 * @cmd:		Netlink command (RTM_NEWNEIGH or RTM_DELNEIGH)
 * @mac:		A neighbor cache link layer address
 * @ip:		A neighbor cache n/w layer destination address
 * @replace_obj:	Whether NEW request should replace existing object or
 *			add to the end of the list
 * @family:		AF_* netlink family
 * @type:		RTN_* route type
 * @flags:		NTF_* flags
 * @state:		NUD_* states
 * @data:		data buffer pointer
 * @datalen:		total amount of data buffer space
 *
 * Return:		Result status
 */
static ssize_t
netlink_update_neigh_ctx_internal(const struct zebra_dplane_ctx *ctx,
				  int cmd, const struct ethaddr *mac,
				  const struct ipaddr *ip, bool replace_obj,
				  uint8_t family, uint8_t type, uint8_t flags,
				  uint16_t state, uint32_t nhg_id,
				  bool nfy, uint8_t nfy_flags,
				  bool ext, uint32_t ext_flags,
				  void *data, size_t datalen)
{
	uint8_t protocol = RTPROT_ZEBRA;
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[];
	} *req = data;
	int ipa_len;
	enum dplane_op_e op;

	memset(req, 0, datalen);

	op = dplane_ctx_get_op(ctx);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;
	if (cmd == RTM_NEWNEIGH)
		req->n.nlmsg_flags |=
			NLM_F_CREATE
			| (replace_obj ? NLM_F_REPLACE : NLM_F_APPEND);
	req->n.nlmsg_type = cmd;
	req->ndm.ndm_family = family;
	req->ndm.ndm_type = type;
	req->ndm.ndm_state = state;
	req->ndm.ndm_flags = flags;
	req->ndm.ndm_ifindex = dplane_ctx_get_ifindex(ctx);

	addattr_l(&req->n, datalen,
		  NDA_PROTOCOL, &protocol, sizeof(protocol));
	if (mac)
		addattr_l(&req->n, datalen, NDA_LLADDR, mac, 6);
	if (nfy)
		addattr_l(&req->n, datalen, NDA_NOTIFY,
				&nfy_flags, sizeof(nfy_flags));
	if (ext)
		addattr_l(&req->n, datalen, NDA_EXT_FLAGS,
				&ext_flags, sizeof(ext_flags));

	if (nhg_id) {
		addattr32(&req->n, datalen, NDA_NH_ID, nhg_id);
	} else {
		ipa_len = IS_IPADDR_V4(ip) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		addattr_l(&req->n, datalen, NDA_DST, &ip->ip.addr, ipa_len);
	}

	if (op == DPLANE_OP_MAC_INSTALL || op == DPLANE_OP_MAC_DELETE) {
		vlanid_t vid = dplane_ctx_mac_get_vlan(ctx);

		if (vid > 0)
			addattr16(&req->n, datalen, NDA_VLAN, vid);

		addattr32(&req->n, datalen, NDA_MASTER,
			  dplane_ctx_mac_get_br_ifindex(ctx));
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Add remote VTEP to the flood list for this VxLAN interface (VNI). This
 * is done by adding an FDB entry with a MAC of 00:00:00:00:00:00.
 */
static int netlink_vxlan_flood_update_ctx(const struct zebra_dplane_ctx *ctx,
					  int cmd)
{
	struct ethaddr dst_mac = {.octet = {0}};
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];

	 netlink_update_neigh_ctx_internal(
		ctx, cmd, &dst_mac, dplane_ctx_neigh_get_ipaddr(ctx), false,
		PF_BRIDGE, 0, NTF_SELF, (NUD_NOARP | NUD_PERMANENT), 0,
		false /*nfy*/, 0 /*nfy_flags*/,
		false /*ext*/, 0 /*ext_flags*/,
		nl_pkt, sizeof(nl_pkt));

	return netlink_talk_info(netlink_talk_filter,
				 (struct nlmsghdr *)nl_pkt,
				 dplane_ctx_get_ns(ctx), 0);
}

#ifndef NDA_RTA
#define NDA_RTA(r)                                                             \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static int netlink_macfdb_change(struct nlmsghdr *h, int len, ns_id_t ns_id)
{
	struct ndmsg *ndm;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *tb[NDA_MAX + 1];
	struct interface *br_if;
	struct ethaddr mac;
	vlanid_t vid = 0;
	struct in_addr vtep_ip;
	int vid_present = 0, dst_present = 0;
	char buf[ETHER_ADDR_STRLEN];
	char vid_buf[20];
	char dst_buf[30];
	bool sticky;
	bool local_inactive = false;
	bool dp_static = false;
	uint32_t nhg_id = 0;

	ndm = NLMSG_DATA(h);

	/* We only process macfdb notifications if EVPN is enabled */
	if (!is_evpn_enabled())
		return 0;

	/* Parse attributes and extract fields of interest. Do basic
	 * validation of the fields.
	 */
	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_LLADDR]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s AF_BRIDGE IF %u - no LLADDR",
				   nl_msg_type_to_str(h->nlmsg_type),
				   ndm->ndm_ifindex);
		return 0;
	}

	if (RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s AF_BRIDGE IF %u - LLADDR is not MAC, len %lu",
				nl_msg_type_to_str(h->nlmsg_type), ndm->ndm_ifindex,
				(unsigned long)RTA_PAYLOAD(tb[NDA_LLADDR]));
		return 0;
	}

	memcpy(&mac, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);

	if ((NDA_VLAN <= NDA_MAX) && tb[NDA_VLAN]) {
		vid_present = 1;
		vid = *(uint16_t *)RTA_DATA(tb[NDA_VLAN]);
		sprintf(vid_buf, " VLAN %u", vid);
	}

	if (tb[NDA_DST]) {
		/* TODO: Only IPv4 supported now. */
		dst_present = 1;
		memcpy(&vtep_ip.s_addr, RTA_DATA(tb[NDA_DST]),
		       IPV4_MAX_BYTELEN);
		sprintf(dst_buf, " dst %s", inet_ntoa(vtep_ip));
	}

	if (tb[NDA_NH_ID])
		nhg_id = *(uint32_t *)RTA_DATA(tb[NDA_NH_ID]);

	if (ndm->ndm_state & NUD_STALE)
		local_inactive = true;

	if (tb[NDA_NOTIFY]) {
		uint8_t nfy_flags;

		dp_static = true;
		nfy_flags = *(uint8_t *)RTA_DATA(tb[NDA_NOTIFY]);
		/* local activity has not been detected on the entry */
		if (nfy_flags & (1 << BR_FDB_NFY_INACTIVE))
			local_inactive = true;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s AF_BRIDGE IF %u%s st 0x%x fl 0x%x MAC %s%s nhg %d",
			   nl_msg_type_to_str(h->nlmsg_type),
			   ndm->ndm_ifindex, vid_present ? vid_buf : "",
			   ndm->ndm_state, ndm->ndm_flags,
			   prefix_mac2str(&mac, buf, sizeof(buf)),
			   dst_present ? dst_buf : "", nhg_id);

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
					ndm->ndm_ifindex);
	if (!ifp || !ifp->info)
		return 0;

	/* The interface should be something we're interested in. */
	if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
		return 0;

	zif = (struct zebra_if *)ifp->info;
	if ((br_if = zif->brslave_info.br_if) == NULL) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s AF_BRIDGE IF %s(%u) brIF %u - no bridge master",
				nl_msg_type_to_str(h->nlmsg_type), ifp->name,
				ndm->ndm_ifindex,
				zif->brslave_info.bridge_ifindex);
		return 0;
	}

	sticky = !!(ndm->ndm_flags & NTF_STICKY);

	if (filter_vlan && vid != filter_vlan) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("        Filtered due to filter vlan: %d",
				   filter_vlan);
		return 0;
	}

	/* If add or update, do accordingly if learnt on a "local" interface; if
	 * the notification is over VxLAN, this has to be related to
	 * multi-homing,
	 * so perform an implicit delete of any local entry (if it exists).
	 */
	if (h->nlmsg_type == RTM_NEWNEIGH) {
                /* Drop "permanent" entries. */
                if (ndm->ndm_state & NUD_PERMANENT) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"        Dropping entry because of NUD_PERMANENT");
			return 0;
		}

		if (IS_ZEBRA_IF_VXLAN(ifp))
			return zebra_vxlan_dp_network_mac_add(ifp, br_if, &mac,
					vid, nhg_id, sticky,
					!!(ndm->ndm_flags & NTF_EXT_LEARNED));

		return zebra_vxlan_local_mac_add_update(ifp, br_if, &mac, vid,
				sticky, local_inactive, dp_static);
	}

	/* This is a delete notification.
	 * Ignore the notification with IP dest as it may just signify that the
	 * MAC has moved from remote to local. The exception is the special
	 * all-zeros MAC that represents the BUM flooding entry; we may have
	 * to readd it. Otherwise,
	 *  1. For a MAC over VxLan, check if it needs to be refreshed(readded)
	 *  2. For a MAC over "local" interface, delete the mac
	 * Note: We will get notifications from both bridge driver and VxLAN
	 * driver.
	 */
	if (nhg_id)
		return 0;

	if (dst_present) {
		u_char zero_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

		if (!memcmp(zero_mac, mac.octet, ETH_ALEN))
			return zebra_vxlan_check_readd_vtep(ifp, vtep_ip);
		return 0;
	}

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return zebra_vxlan_dp_network_mac_del(ifp, br_if, &mac,
							  vid);

	return zebra_vxlan_local_mac_del(ifp, br_if, &mac, vid);
}

static int netlink_macfdb_table(struct nlmsghdr *h, ns_id_t ns_id, int startup)
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

	return netlink_macfdb_change(h, len, ns_id);
}

/* Request for MAC FDB information from the kernel */
static int netlink_request_macs(struct nlsock *netlink_cmd, int family,
				int type, ifindex_t master_ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.ifm.ifi_family = family;
	if (master_ifindex)
		addattr32(&req.n, sizeof(req), IFLA_MASTER, master_ifindex);

	return netlink_request(netlink_cmd, &req);
}

/*
 * MAC forwarding database read using netlink interface. This is invoked
 * at startup.
 */
int netlink_macfdb_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get bridge FDB table. */
	ret = netlink_request_macs(&zns->netlink_cmd, AF_BRIDGE, RTM_GETNEIGH,
				   0);
	if (ret < 0)
		return ret;
	/* We are reading entire table. */
	filter_vlan = 0;
	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 0, 1);

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
	struct zebra_dplane_info dp_info;
	int ret = 0;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Save VLAN we're filtering on, if needed. */
	br_zif = (struct zebra_if *)br_if->info;
	zif = (struct zebra_if *)ifp->info;
	vxl = &zif->l2info.vxl;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		filter_vlan = vxl->access_vlan;

	/* Get bridge FDB table for specific bridge - we do the VLAN filtering.
	 */
	ret = netlink_request_macs(&zns->netlink_cmd, AF_BRIDGE, RTM_GETNEIGH,
				   br_if->ifindex);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 0, 0);

	/* Reset VLAN filter. */
	filter_vlan = 0;
	return ret;
}


/* Request for MAC FDB for a specific MAC address in VLAN from the kernel */
static int netlink_request_specific_mac_in_bridge(struct zebra_ns *zns,
						  int family,
						  int type,
						  struct interface *br_if,
						  struct ethaddr *mac,
						  vlanid_t vid)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	struct zebra_if *br_zif;
	char buf[ETHER_ADDR_STRLEN];

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_type = type;	/* RTM_GETNEIGH */
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.ndm.ndm_family = family;	/* AF_BRIDGE */
	/* req.ndm.ndm_state = NUD_REACHABLE; */

	addattr_l(&req.n, sizeof(req), NDA_LLADDR, mac, 6);

	br_zif = (struct zebra_if *)br_if->info;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif) && vid > 0)
		addattr16(&req.n, sizeof(req), NDA_VLAN, vid);

	addattr32(&req.n, sizeof(req), NDA_MASTER, br_if->ifindex);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"%s: Tx family %s IF %s(%u) vrf %s(%u) MAC %s vid %u",
			__func__, nl_family_to_str(req.ndm.ndm_family),
			br_if->name, br_if->ifindex,
			vrf_id_to_name(br_if->vrf_id), br_if->vrf_id,
			prefix_mac2str(mac, buf, sizeof(buf)), vid);

	return netlink_request(&zns->netlink_cmd, &req);
}

int netlink_macfdb_read_specific_mac(struct zebra_ns *zns,
				     struct interface *br_if,
				     struct ethaddr *mac, vlanid_t vid)
{
	int ret = 0;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get bridge FDB table for specific bridge - we do the VLAN filtering.
	 */
	ret = netlink_request_specific_mac_in_bridge(zns, AF_BRIDGE,
						     RTM_GETNEIGH,
						     br_if, mac, vid);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 1, 0);

	return ret;
}

/*
 * Netlink-specific handler for MAC updates using dataplane context object.
 */
ssize_t
netlink_macfdb_update_ctx(struct zebra_dplane_ctx *ctx, uint8_t *data,
			  size_t datalen)
{
	struct ipaddr vtep_ip;
	vlanid_t vid;
	ssize_t total;
	int cmd;
	uint8_t flags;
	uint16_t state;
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];
	uint32_t nhg_id;
	uint32_t update_flags;
	bool nfy = false;
	uint8_t nfy_flags = 0;

	cmd = dplane_ctx_get_op(ctx) == DPLANE_OP_MAC_INSTALL
			  ? RTM_NEWNEIGH : RTM_DELNEIGH;

	flags = NTF_MASTER;
	state = NUD_REACHABLE;

	update_flags = dplane_ctx_mac_get_update_flags(ctx);
	if (update_flags & DPLANE_MAC_REMOTE) {
		flags |= NTF_SELF;
		if (dplane_ctx_mac_is_sticky(ctx)) {
			/* NUD_NOARP prevents the entry from expiring */
			state |= NUD_NOARP;
			/* sticky the entry from moving */
			flags |= NTF_STICKY;
		} else {
			flags |= NTF_EXT_LEARNED;
		}
		/* if it was static-local previously we need to clear the
		 * notify flags on replace with remote
		 */
		if (update_flags & DPLANE_MAC_WAS_STATIC)
			nfy = true;
	} else {
		/* local mac */
		if (update_flags & DPLANE_MAC_SET_STATIC) {
			nfy_flags |= (1 << BR_FDB_NFY_STATIC);
			state |= NUD_NOARP;
		}

		if (update_flags & DPLANE_MAC_SET_INACTIVE)
			nfy_flags |= (1 << BR_FDB_NFY_INACTIVE);

		nfy = true;
	}

	nhg_id = dplane_ctx_mac_get_nhg_id(ctx);
	vtep_ip.ipaddr_v4 = *(dplane_ctx_mac_get_vtep_ip(ctx));
	SET_IPADDR_V4(&vtep_ip);

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char ipbuf[PREFIX_STRLEN];
		char buf[ETHER_ADDR_STRLEN];
		char vid_buf[20];
		const struct ethaddr *mac = dplane_ctx_mac_get_addr(ctx);

		vid = dplane_ctx_mac_get_vlan(ctx);
		if (vid > 0)
			snprintf(vid_buf, sizeof(vid_buf), " VLAN %u", vid);
		else
			vid_buf[0] = '\0';

		zlog_debug("Tx %s family %s IF %s(%u)%s %sMAC %s dst %s nhg %u%s%s%s%s%s",
			   nl_msg_type_to_str(cmd), nl_family_to_str(AF_BRIDGE),
			   dplane_ctx_get_ifname(ctx),
			   dplane_ctx_get_ifindex(ctx), vid_buf,
			   dplane_ctx_mac_is_sticky(ctx) ? "sticky " : "",
			   prefix_mac2str(mac, buf, sizeof(buf)),
			   ipaddr2str(&vtep_ip, ipbuf, sizeof(ipbuf)),
			   nhg_id,
			   (update_flags &
				DPLANE_MAC_REMOTE) ? " rem" : "",
			   (update_flags &
				DPLANE_MAC_WAS_STATIC) ? " clr_sync" : "",
			   (state & NUD_NOARP) ? " static" : "",
			   (update_flags &
				DPLANE_MAC_SET_INACTIVE) ? " inactive" : "",
			   nfy ? " nfy" : "");
	}

	total = netlink_update_neigh_ctx_internal(
			ctx, cmd, dplane_ctx_mac_get_addr(ctx),
			dplane_ctx_neigh_get_ipaddr(ctx), true, AF_BRIDGE, 0,
			flags, state, nhg_id, nfy, nfy_flags,
			false /*ext*/, 0 /*ext_flags*/,
			nl_pkt, sizeof(nl_pkt));

	return total;
}

/*
 * In the event the kernel deletes ipv4 link-local neighbor entries created for
 * 5549 support, re-install them.
 */
static void netlink_handle_5549(struct ndmsg *ndm, struct zebra_if *zif,
				struct interface *ifp, struct ipaddr *ip,
				bool handle_failed)
{
	if (ndm->ndm_family != AF_INET)
		return;

	if (!zif->v6_2_v4_ll_neigh_entry)
		return;

	if (ipv4_ll.s_addr != ip->ip._v4_addr.s_addr)
		return;

	if (handle_failed && ndm->ndm_state & NUD_FAILED) {
		zlog_info("Neighbor Entry for %s has entered a failed state, not reinstalling",
			  ifp->name);
		return;
	}

	if_nbr_ipv6ll_to_ipv4ll_neigh_update(ifp, &zif->v6_2_v4_ll_addr6, true);
}

#define NUD_VALID                                                              \
	(NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE     \
	 | NUD_DELAY)
#define NUD_LOCAL_ACTIVE                                                 \
	(NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE)

static int netlink_ipneigh_change(struct nlmsghdr *h, int len, ns_id_t ns_id)
{
	struct ndmsg *ndm;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *tb[NDA_MAX + 1];
	struct interface *link_if;
	struct ethaddr mac;
	struct ipaddr ip;
	struct vrf *vrf;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	int mac_present = 0;
	bool is_ext;
	bool is_router;
	bool local_inactive;

	ndm = NLMSG_DATA(h);

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
					ndm->ndm_ifindex);
	if (!ifp || !ifp->info)
		return 0;

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	zif = (struct zebra_if *)ifp->info;

	/* Parse attributes and extract fields of interest. */
	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_DST]) {
		zlog_debug("%s family %s IF %s(%u) vrf %s(%u) - no DST",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex, VRF_LOGNAME(vrf), ifp->vrf_id);
		return 0;
	}

	memset(&ip, 0, sizeof(struct ipaddr));
	ip.ipa_type = (ndm->ndm_family == AF_INET) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ip.ip.addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));

	/* if kernel deletes our rfc5549 neighbor entry, re-install it */
	if (h->nlmsg_type == RTM_DELNEIGH && (ndm->ndm_state & NUD_PERMANENT)) {
		netlink_handle_5549(ndm, zif, ifp, &ip, false);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"\tNeighbor Entry Received is a 5549 entry, finished");
		return 0;
	}

	/* if kernel marks our rfc5549 neighbor entry invalid, re-install it */
	if (h->nlmsg_type == RTM_NEWNEIGH && !(ndm->ndm_state & NUD_VALID))
		netlink_handle_5549(ndm, zif, ifp, &ip, true);

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
		link_if = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
						    zif->link_ifindex);
		if (!link_if)
			return 0;
	} else if (IS_ZEBRA_IF_BRIDGE(ifp))
		link_if = ifp;
	else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"\tNeighbor Entry received is not on a VLAN or a BRIDGE, ignoring");
		return 0;
	}

	memset(&mac, 0, sizeof(struct ethaddr));
	if (h->nlmsg_type == RTM_NEWNEIGH) {
		if (tb[NDA_LLADDR]) {
			if (RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN) {
				if (IS_ZEBRA_DEBUG_KERNEL)
					zlog_debug(
						"%s family %s IF %s(%u) vrf %s(%u) - LLADDR is not MAC, len %lu",
						nl_msg_type_to_str(
							h->nlmsg_type),
						nl_family_to_str(
							ndm->ndm_family),
						ifp->name, ndm->ndm_ifindex,
						VRF_LOGNAME(vrf), ifp->vrf_id,
						(unsigned long)RTA_PAYLOAD(
							tb[NDA_LLADDR]));
				return 0;
			}

			mac_present = 1;
			memcpy(&mac, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);
		}

		is_ext = !!(ndm->ndm_flags & NTF_EXT_LEARNED);
		is_router = !!(ndm->ndm_flags & NTF_ROUTER);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"Rx %s family %s IF %s(%u) vrf %s(%u) IP %s MAC %s state 0x%x flags 0x%x",
				nl_msg_type_to_str(h->nlmsg_type),
				nl_family_to_str(ndm->ndm_family), ifp->name,
				ndm->ndm_ifindex, VRF_LOGNAME(vrf), ifp->vrf_id,
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
		if (ndm->ndm_state & NUD_VALID) {
			local_inactive = !(ndm->ndm_state & NUD_LOCAL_ACTIVE);

			/* XXX - populate dp-static based on the sync flags
			 * in the kernel
			 */
			return zebra_vxlan_handle_kernel_neigh_update(
				ifp, link_if, &ip, &mac, ndm->ndm_state,
				is_ext, is_router, local_inactive,
				false /* dp_static */);
		}

		return zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s family %s IF %s(%u) vrf %s(%u) IP %s",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex, VRF_LOGNAME(vrf), ifp->vrf_id,
			   ipaddr2str(&ip, buf2, sizeof(buf2)));

	/* Process the delete - it may result in re-adding the neighbor if it is
	 * a valid "remote" neighbor.
	 */
	return zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
}

static int netlink_neigh_table(struct nlmsghdr *h, ns_id_t ns_id, int startup)
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

	return netlink_neigh_change(h, len);
}

/* Request for IP neighbor information from the kernel */
static int netlink_request_neigh(struct nlsock *netlink_cmd, int family,
				 int type, ifindex_t ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.ndm.ndm_family = family;
	if (ifindex)
		addattr32(&req.n, sizeof(req), NDA_IFINDEX, ifindex);

	return netlink_request(netlink_cmd, &req);
}

/*
 * IP Neighbor table read using netlink interface. This is invoked
 * at startup.
 */
int netlink_neigh_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get IP neighbor table. */
	ret = netlink_request_neigh(&zns->netlink_cmd, AF_UNSPEC, RTM_GETNEIGH,
				    0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd,
				 &dp_info, 0, 1);

	return ret;
}

/*
 * IP Neighbor table read using netlink interface. This is for a specific
 * VLAN device.
 */
int netlink_neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
	int ret = 0;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	ret = netlink_request_neigh(&zns->netlink_cmd, AF_UNSPEC, RTM_GETNEIGH,
				    vlan_if->ifindex);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd,
				 &dp_info, 0, 0);

	return ret;
}

/*
 * Request for a specific IP in VLAN (SVI) device from IP Neighbor table,
 * read using netlink interface.
 */
static int netlink_request_specific_neigh_in_vlan(struct zebra_ns *zns,
						  int type, struct ipaddr *ip,
						  ifindex_t ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	int ipa_len;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = type; /* RTM_GETNEIGH */
	req.ndm.ndm_ifindex = ifindex;

	if (IS_IPADDR_V4(ip)) {
		ipa_len = IPV4_MAX_BYTELEN;
		req.ndm.ndm_family = AF_INET;

	} else {
		ipa_len = IPV6_MAX_BYTELEN;
		req.ndm.ndm_family = AF_INET6;
	}

	addattr_l(&req.n, sizeof(req), NDA_DST, &ip->ip.addr, ipa_len);

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf[INET6_ADDRSTRLEN];

		zlog_debug("%s: Tx %s family %s IF %u IP %s flags 0x%x",
			   __func__, nl_msg_type_to_str(type),
			   nl_family_to_str(req.ndm.ndm_family), ifindex,
			   ipaddr2str(ip, buf, sizeof(buf)), req.n.nlmsg_flags);
	}

	return netlink_request(&zns->netlink_cmd, &req);
}

int netlink_neigh_read_specific_ip(struct ipaddr *ip,
				  struct interface *vlan_if)
{
	int ret = 0;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(vlan_if->vrf_id);
	char buf[INET6_ADDRSTRLEN];
	struct zebra_dplane_info dp_info;

	zns = zvrf->zns;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: neigh request IF %s(%u) IP %s vrf %s(%u)",
			   __func__, vlan_if->name, vlan_if->ifindex,
			   ipaddr2str(ip, buf, sizeof(buf)),
			   vrf_id_to_name(vlan_if->vrf_id), vlan_if->vrf_id);

	ret = netlink_request_specific_neigh_in_vlan(zns, RTM_GETNEIGH, ip,
					    vlan_if->ifindex);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd,
				 &dp_info, 1, 0);

	return ret;
}

int netlink_neigh_change(struct nlmsghdr *h, ns_id_t ns_id)
{
	int len;
	struct ndmsg *ndm;

	if (!(h->nlmsg_type == RTM_NEWNEIGH || h->nlmsg_type == RTM_DELNEIGH))
		return 0;

	/* Length validity. */
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ndmsg)));
		return -1;
	}

	/* Is this a notification for the MAC FDB or IP neighbor table? */
	ndm = NLMSG_DATA(h);
	if (ndm->ndm_family == AF_BRIDGE)
		return netlink_macfdb_change(h, len, ns_id);

	if (ndm->ndm_type != RTN_UNICAST)
		return 0;

	if (ndm->ndm_family == AF_INET || ndm->ndm_family == AF_INET6)
		return netlink_ipneigh_change(h, len, ns_id);
	else {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel neighbor change: %s",
			ndm->ndm_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	return 0;
}

/*
 * Utility neighbor-update function, using info from dplane context.
 */
static int netlink_neigh_update_ctx(const struct zebra_dplane_ctx *ctx,
				    int cmd)
{
	const struct ipaddr *ip;
	const struct ethaddr *mac;
	uint8_t flags;
	uint16_t state;
	uint8_t family;
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];
	uint32_t update_flags;
	uint32_t ext_flags = 0;
	bool ext = false;

	ip = dplane_ctx_neigh_get_ipaddr(ctx);
	mac = dplane_ctx_neigh_get_mac(ctx);
	if (is_zero_mac(mac))
		mac = NULL;

	update_flags = dplane_ctx_neigh_get_update_flags(ctx);
	flags = neigh_flags_to_netlink(dplane_ctx_neigh_get_flags(ctx));
	state = neigh_state_to_netlink(dplane_ctx_neigh_get_state(ctx));

	family = IS_IPADDR_V4(ip) ? AF_INET : AF_INET6;

	if (update_flags & DPLANE_NEIGH_REMOTE) {
		flags |= NTF_EXT_LEARNED;
		/* if it was static-local previously we need to clear the
		 * ext flags on replace with remote
		 */
		if (update_flags & DPLANE_NEIGH_WAS_STATIC)
			ext = true;
	} else {
		ext = true;
		/* local neigh */
		if (update_flags & DPLANE_NEIGH_SET_STATIC)
			ext_flags |= NTF_E_MH_PEER_SYNC;

		/* the ndm_state set for local entries can be REACHABLE or
		 * STALE. if the dataplane has already establish reachability
		 * (in the meantime) FRR must not over-write it with STALE.
		 * this accidental race/over-write is avoided by using the
		 * WEAK_OVERRIDE_STATE
		 */
		ext_flags |= NTF_E_WEAK_OVERRIDE_STATE;
	}
	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf[INET6_ADDRSTRLEN];
		char buf2[ETHER_ADDR_STRLEN];

		zlog_debug(
			"Tx %s family %s IF %s(%u) Neigh %s MAC %s flags 0x%x state 0x%x",
			nl_msg_type_to_str(cmd), nl_family_to_str(family),
			dplane_ctx_get_ifname(ctx), dplane_ctx_get_ifindex(ctx),
			ipaddr2str(ip, buf, sizeof(buf)),
			mac ? prefix_mac2str(mac, buf2, sizeof(buf2)) : "null",
			flags, state);
	}

	netlink_update_neigh_ctx_internal(
			ctx, cmd, mac, ip, true, family, RTN_UNICAST, flags,
			state, 0 /*nhg*/, false /*nfy*/, 0 /*nfy_flags*/,
			ext, ext_flags, nl_pkt, sizeof(nl_pkt));

	return netlink_talk_info(netlink_talk_filter, (struct nlmsghdr *)nl_pkt,
				 dplane_ctx_get_ns(ctx), 0);
}

/*
 * Update MAC, using dataplane context object.
 */
enum zebra_dplane_result kernel_mac_update_ctx(struct zebra_dplane_ctx *ctx)
{
	uint8_t nl_pkt[NL_PKT_BUF_SIZE];
	ssize_t rv;

	rv = netlink_macfdb_update_ctx(ctx, nl_pkt, sizeof(nl_pkt));
	if (rv <= 0)
		return ZEBRA_DPLANE_REQUEST_FAILURE;

	rv = netlink_talk_info(netlink_talk_filter, (struct nlmsghdr *)nl_pkt,
			       dplane_ctx_get_ns(ctx), 0);

	return rv == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE;
}

enum zebra_dplane_result kernel_neigh_update_ctx(struct zebra_dplane_ctx *ctx)
{
	int ret = -1;

	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
		ret = netlink_neigh_update_ctx(ctx, RTM_NEWNEIGH);
		break;
	case DPLANE_OP_NEIGH_DELETE:
		ret = netlink_neigh_update_ctx(ctx, RTM_DELNEIGH);
		break;
	case DPLANE_OP_VTEP_ADD:
		ret = netlink_vxlan_flood_update_ctx(ctx, RTM_NEWNEIGH);
		break;
	case DPLANE_OP_VTEP_DELETE:
		ret = netlink_vxlan_flood_update_ctx(ctx, RTM_DELNEIGH);
		break;
	default:
		break;
	}

	return (ret == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

/*
 * MPLS label forwarding table change via netlink interface, using dataplane
 * context information.
 */
int netlink_mpls_multipath(int cmd, struct zebra_dplane_ctx *ctx)
{
	mpls_lse_t lse;
	const zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	const char *routedesc;
	int route_type;
	struct prefix p = {0};

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);

	/*
	 * Count # nexthops so we can decide whether to use singlepath
	 * or multipath case.
	 */
	nexthop_num = 0;
	for (nhlfe = dplane_ctx_get_nhlfe(ctx); nhlfe; nhlfe = nhlfe->next) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;
		if (cmd == RTM_NEWROUTE) {
			/* Count all selected NHLFEs */
			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
				nexthop_num++;
		} else { /* DEL */
			/* Count all installed NHLFEs */
			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
				nexthop_num++;
		}
	}

	if ((nexthop_num == 0) ||
	    (!dplane_ctx_get_best_nhlfe(ctx) && (cmd != RTM_DELROUTE)))
		return 0;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.n.nlmsg_pid = dplane_ctx_get_ns(ctx)->nls.snl.nl_pid;

	req.r.rtm_family = AF_MPLS;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_dst_len = MPLS_LABEL_LEN_BITS;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;

	if (cmd == RTM_NEWROUTE) {
		/* We do a replace to handle update. */
		req.n.nlmsg_flags |= NLM_F_REPLACE;

		/* set the protocol value if installing */
		route_type = re_type_from_lsp_type(
			dplane_ctx_get_best_nhlfe(ctx)->type);
		req.r.rtm_protocol = zebra2proto(route_type);
	}

	/* Fill destination */
	lse = mpls_lse_encode(dplane_ctx_get_in_label(ctx), 0, 0, 1);
	addattr_l(&req.n, sizeof(req), RTA_DST, &lse, sizeof(mpls_lse_t));

	/* Fill nexthops (paths) based on single-path or multipath. The paths
	 * chosen depend on the operation.
	 */
	if (nexthop_num == 1) {
		routedesc = "single-path";
		_netlink_mpls_debug(cmd, dplane_ctx_get_in_label(ctx),
				    routedesc);

		nexthop_num = 0;
		for (nhlfe = dplane_ctx_get_nhlfe(ctx);
		     nhlfe; nhlfe = nhlfe->next) {
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
				_netlink_mpls_build_singlepath(
					&p, routedesc, nhlfe, &req.n, &req.r,
					sizeof(req), cmd);

				nexthop_num++;
				break;
			}
		}
	} else { /* Multipath case */
		char buf[NL_PKT_BUF_SIZE];
		struct rtattr *rta = (void *)buf;
		struct rtnexthop *rtnh;
		const union g_addr *src1 = NULL;

		rta->rta_type = RTA_MULTIPATH;
		rta->rta_len = RTA_LENGTH(0);
		rtnh = RTA_DATA(rta);

		routedesc = "multipath";
		_netlink_mpls_debug(cmd, dplane_ctx_get_in_label(ctx),
				    routedesc);

		nexthop_num = 0;
		for (nhlfe = dplane_ctx_get_nhlfe(ctx);
		     nhlfe; nhlfe = nhlfe->next) {
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
				nexthop_num++;

				/* Build the multipath */
				_netlink_mpls_build_multipath(&p, routedesc,
							      nhlfe, rta, rtnh,
							      &req.r, &src1);
				rtnh = RTNH_NEXT(rtnh);
			}
		}

		/* Add the multipath */
		if (rta->rta_len > RTA_LENGTH(0))
			addattr_l(&req.n, NL_PKT_BUF_SIZE, RTA_MULTIPATH,
				  RTA_DATA(rta), RTA_PAYLOAD(rta));
	}

	/* Talk to netlink socket. */
	return netlink_talk_info(netlink_talk_filter, &req.n,
				 dplane_ctx_get_ns(ctx), 0);
}

/****************************************************************************
* This code was developed in a branch that didn't have dplane APIs for
* MAC updates. Hence the use of the legacy style. Needs to be moved to
* the new dplane style XXX
*/
static int netlink_fdb_nh_update(uint32_t nh_id, struct in_addr vtep_ip)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[256];
	} req;
	int cmd = RTM_NEWNEXTHOP;
	struct zebra_vrf *zvrf;
	struct zebra_ns *zns;

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return -1;
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_INET;

	addattr32(&req.n, sizeof(req), NHA_ID, nh_id);
	addattr_l(&req.n, sizeof(req), NHA_FDB, NULL, 0);
	addattr_l(&req.n, sizeof(req), NHA_GATEWAY,
			&vtep_ip, IPV4_MAX_BYTELEN);

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		zlog_debug("Tx %s fdb-nh 0x%x %s",
			   nl_msg_type_to_str(cmd), nh_id, inet_ntoa(vtep_ip));
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

static int netlink_fdb_nh_del(uint32_t nh_id)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[256];
	} req;
	int cmd = RTM_DELNEXTHOP;
	struct zebra_vrf *zvrf;
	struct zebra_ns *zns;

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return -1;
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_UNSPEC;

	addattr32(&req.n, sizeof(req), NHA_ID, nh_id);

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		zlog_debug("Tx %s fdb-nh 0x%x",
			   nl_msg_type_to_str(cmd), nh_id);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

static int netlink_fdb_nhg_update(uint32_t nhg_id, uint32_t nh_cnt,
		struct nh_grp *nh_ids)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[256];
	} req;
	int cmd = RTM_NEWNEXTHOP;
	struct zebra_vrf *zvrf;
	struct zebra_ns *zns;
	struct nexthop_grp grp[nh_cnt];
	uint32_t i;

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return -1;
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_UNSPEC;

	addattr32(&req.n, sizeof(req), NHA_ID, nhg_id);
	addattr_l(&req.n, sizeof(req), NHA_FDB, NULL, 0);
	memset(&grp, 0, sizeof(grp));
	for (i = 0; i < nh_cnt; ++i) {
		grp[i].id = nh_ids[i].id;
		grp[i].weight = nh_ids[i].weight;
	}
	addattr_l(&req.n, sizeof(req), NHA_GROUP,
			grp, nh_cnt * sizeof(struct nexthop_grp));


	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		char vtep_str[ES_VTEP_LIST_STR_SZ];

		vtep_str[0] = '\0';
		for (i = 0; i < nh_cnt; ++i) {
			sprintf(vtep_str + strlen(vtep_str), "0x%x ",
					grp[i].id);
		}

		zlog_debug("Tx %s fdb-nhg 0x%x %s",
			   nl_msg_type_to_str(cmd), nhg_id, vtep_str);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    0);
}

static int netlink_fdb_nhg_del(uint32_t nhg_id)
{
	return netlink_fdb_nh_del(nhg_id);
}

int kernel_upd_mac_nh(uint32_t nh_id, struct in_addr vtep_ip)
{
	return netlink_fdb_nh_update(nh_id, vtep_ip);
}

int kernel_del_mac_nh(uint32_t nh_id)
{
	return netlink_fdb_nh_del(nh_id);
}

int kernel_upd_mac_nhg(uint32_t nhg_id, uint32_t nh_cnt,
		struct nh_grp *nh_ids)
{
	return netlink_fdb_nhg_update(nhg_id, nh_cnt, nh_ids);
}

int kernel_del_mac_nhg(uint32_t nhg_id)
{
	return netlink_fdb_nhg_del(nhg_id);
}

#endif /* HAVE_NETLINK */
