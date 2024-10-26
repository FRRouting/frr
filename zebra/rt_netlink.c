// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H

#include <net/if_arp.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>
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
#include "plist.h"
#include "plist_int.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "rib.h"
#include "frrevent.h"
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
#include "zebra/zebra_trace.h"
#include "zebra/zebra_neigh.h"
#include "lib/srv6.h"

#ifndef AF_MPLS
#define AF_MPLS 28
#endif

/* Re-defining as I am unable to include <linux/if_bridge.h> which has the
 * UAPI for MAC sync. */
#ifndef _UAPI_LINUX_IF_BRIDGE_H
#define BR_SPH_LIST_SIZE 10
#endif

DEFINE_MTYPE_STATIC(LIB, NH_SRV6, "Nexthop srv6");

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

/* Is this a ipv4 over ipv6 route? */
static bool is_route_v4_over_v6(unsigned char rtm_family,
				enum nexthop_types_t nexthop_type)
{
	if (rtm_family == AF_INET
	    && (nexthop_type == NEXTHOP_TYPE_IPV6
		|| nexthop_type == NEXTHOP_TYPE_IPV6_IFINDEX))
		return true;

	return false;
}

/* Helper to control use of kernel-level nexthop ids */
static bool kernel_nexthops_supported(void)
{
	return (supports_nh && !vrf_is_backend_netns()
		&& zebra_nhg_kernel_nexthops_enabled());
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

/* Is vni mcast group */
static bool is_mac_vni_mcast_group(struct ethaddr *mac, vni_t vni,
				   struct in_addr grp_addr)
{
	if (!vni)
		return false;

	if (!is_zero_mac(mac))
		return false;

	if (!IN_MULTICAST(ntohl(grp_addr.s_addr)))
		return false;

	return true;
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
	if (dplane_flags & DPLANE_NTF_USE)
		flags |= NTF_USE;

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
	if (dplane_state & DPLANE_NUD_INCOMPLETE)
		state |= NUD_INCOMPLETE;
	if (dplane_state & DPLANE_NUD_PERMANENT)
		state |= NUD_PERMANENT;
	if (dplane_state & DPLANE_NUD_FAILED)
		state |= NUD_FAILED;

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
	    || (proto == RTPROT_PBR) || (proto == RTPROT_OPENFABRIC)
	    || (proto == RTPROT_SRTE)) {
		return true;
	}

	return false;
}

int zebra2proto(int proto)
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
	case ZEBRA_ROUTE_SRTE:
		proto = RTPROT_SRTE;
		break;
	case ZEBRA_ROUTE_TABLE:
	case ZEBRA_ROUTE_NHG:
		proto = RTPROT_ZEBRA;
		break;
	case ZEBRA_ROUTE_CONNECT:
	case ZEBRA_ROUTE_LOCAL:
	case ZEBRA_ROUTE_KERNEL:
		proto = RTPROT_KERNEL;
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
		proto = (family == AF_INET) ? ZEBRA_ROUTE_OSPF
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
	case RTPROT_SRTE:
		proto = ZEBRA_ROUTE_SRTE;
		break;
	case RTPROT_UNSPEC:
	case RTPROT_REDIRECT:
	case RTPROT_KERNEL:
	case RTPROT_BOOT:
	case RTPROT_GATED:
	case RTPROT_RA:
	case RTPROT_MRT:
	case RTPROT_BIRD:
	case RTPROT_DNROUTED:
	case RTPROT_XORP:
	case RTPROT_NTK:
	case RTPROT_MROUTED:
	case RTPROT_KEEPALIVED:
	case RTPROT_OPENR:
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	case RTPROT_ZEBRA:
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
		zlog_debug(
			"%s: Please add this protocol(%d) to proper rt_netlink.c handling",
			__func__, proto);
		proto = ZEBRA_ROUTE_KERNEL;
		break;
	}
	return proto;
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

/**
 * @parse_encap_seg6local_flavors() - Parses encapsulated SRv6 flavors
 * attributes
 * @tb:         Pointer to rtattr to look for nested items in.
 * @flv:        Pointer to store SRv6 flavors info in.
 *
 * Return:      0 on success, non-zero on error
 */
static int parse_encap_seg6local_flavors(struct rtattr *tb,
					 struct seg6local_flavors_info *flv)
{
	struct rtattr *tb_encap[SEG6_LOCAL_FLV_MAX + 1] = {};

	netlink_parse_rtattr_nested(tb_encap, SEG6_LOCAL_FLV_MAX, tb);

	if (tb_encap[SEG6_LOCAL_FLV_OPERATION])
		flv->flv_ops = *(uint32_t *)RTA_DATA(
			tb_encap[SEG6_LOCAL_FLV_OPERATION]);

	if (tb_encap[SEG6_LOCAL_FLV_LCBLOCK_BITS])
		flv->lcblock_len = *(uint8_t *)RTA_DATA(
			tb_encap[SEG6_LOCAL_FLV_LCBLOCK_BITS]);

	if (tb_encap[SEG6_LOCAL_FLV_LCNODE_FN_BITS])
		flv->lcnode_func_len = *(uint8_t *)RTA_DATA(
			tb_encap[SEG6_LOCAL_FLV_LCNODE_FN_BITS]);

	return 0;
}

static enum seg6local_action_t
parse_encap_seg6local(struct rtattr *tb,
		      struct seg6local_context *ctx)
{
	struct rtattr *tb_encap[SEG6_LOCAL_MAX + 1] = {};
	enum seg6local_action_t act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;

	netlink_parse_rtattr_nested(tb_encap, SEG6_LOCAL_MAX, tb);

	if (tb_encap[SEG6_LOCAL_ACTION])
		act = *(uint32_t *)RTA_DATA(tb_encap[SEG6_LOCAL_ACTION]);

	if (tb_encap[SEG6_LOCAL_NH4])
		ctx->nh4 = *(struct in_addr *)RTA_DATA(
				tb_encap[SEG6_LOCAL_NH4]);

	if (tb_encap[SEG6_LOCAL_NH6])
		ctx->nh6 = *(struct in6_addr *)RTA_DATA(
				tb_encap[SEG6_LOCAL_NH6]);

	if (tb_encap[SEG6_LOCAL_TABLE])
		ctx->table = *(uint32_t *)RTA_DATA(tb_encap[SEG6_LOCAL_TABLE]);

	if (tb_encap[SEG6_LOCAL_VRFTABLE])
		ctx->table =
			*(uint32_t *)RTA_DATA(tb_encap[SEG6_LOCAL_VRFTABLE]);

	if (tb_encap[SEG6_LOCAL_FLAVORS]) {
		parse_encap_seg6local_flavors(tb_encap[SEG6_LOCAL_FLAVORS],
					      &ctx->flv);
	}

	return act;
}

static int parse_encap_seg6(struct rtattr *tb, struct in6_addr *segs)
{
	struct rtattr *tb_encap[SEG6_IPTUNNEL_MAX + 1] = {};
	struct seg6_iptunnel_encap *ipt = NULL;
	int i;

	netlink_parse_rtattr_nested(tb_encap, SEG6_IPTUNNEL_MAX, tb);

	if (tb_encap[SEG6_IPTUNNEL_SRH]) {
		ipt = (struct seg6_iptunnel_encap *)
			RTA_DATA(tb_encap[SEG6_IPTUNNEL_SRH]);

		for (i = ipt->srh[0].first_segment; i >= 0; i--)
			memcpy(&segs[i], &ipt->srh[0].segments[i],
			       sizeof(struct in6_addr));

		return ipt->srh[0].first_segment + 1;
	}

	return 0;
}


static struct nexthop
parse_nexthop_unicast(ns_id_t ns_id, struct rtmsg *rtm, struct rtattr **tb,
		      enum blackhole_type bh_type, int index, void *prefsrc,
		      void *gate, afi_t afi, vrf_id_t vrf_id)
{
	struct interface *ifp = NULL;
	struct nexthop nh = {.weight = 1};
	mpls_label_t labels[MPLS_MAX_LABELS] = {0};
	int num_labels = 0;
	enum seg6local_action_t seg6l_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct seg6local_context seg6l_ctx = {};
	struct in6_addr segs[SRV6_MAX_SIDS] = {};
	int num_segs = 0;

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
			nh_vrf_id = ifp->vrf->vrf_id;
	}
	nh.vrf_id = nh_vrf_id;

	if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE]
	    && *(uint16_t *)RTA_DATA(tb[RTA_ENCAP_TYPE])
		       == LWTUNNEL_ENCAP_MPLS) {
		num_labels = parse_encap_mpls(tb[RTA_ENCAP], labels);
	}
	if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE]
	    && *(uint16_t *)RTA_DATA(tb[RTA_ENCAP_TYPE])
		       == LWTUNNEL_ENCAP_SEG6_LOCAL) {
		seg6l_act = parse_encap_seg6local(tb[RTA_ENCAP], &seg6l_ctx);
	}
	if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE]
	    && *(uint16_t *)RTA_DATA(tb[RTA_ENCAP_TYPE])
		       == LWTUNNEL_ENCAP_SEG6) {
		num_segs = parse_encap_seg6(tb[RTA_ENCAP], segs);
	}

	if (rtm->rtm_flags & RTNH_F_ONLINK)
		SET_FLAG(nh.flags, NEXTHOP_FLAG_ONLINK);

	if (rtm->rtm_flags & RTNH_F_LINKDOWN)
		SET_FLAG(nh.flags, NEXTHOP_FLAG_LINKDOWN);

	if (num_labels)
		nexthop_add_labels(&nh, ZEBRA_LSP_STATIC, num_labels, labels);

	/* Resolve default values for SRv6 flavors */
	if (seg6l_ctx.flv.flv_ops != ZEBRA_SEG6_LOCAL_FLV_OP_UNSPEC) {
		if (seg6l_ctx.flv.lcblock_len == 0)
			seg6l_ctx.flv.lcblock_len =
				ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCBLOCK_LEN;
		if (seg6l_ctx.flv.lcnode_func_len == 0)
			seg6l_ctx.flv.lcnode_func_len =
				ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN;
	}

	if (seg6l_act != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		nexthop_add_srv6_seg6local(&nh, seg6l_act, &seg6l_ctx);

	if (num_segs)
		nexthop_add_srv6_seg6(&nh, segs, num_segs);

	return nh;
}

static uint16_t parse_multipath_nexthops_unicast(ns_id_t ns_id, struct nexthop_group *ng,
						 struct rtmsg *rtm, struct rtnexthop *rtnh,
						 struct rtattr **tb, void *prefsrc, vrf_id_t vrf_id)
{
	void *gate = NULL;
	struct interface *ifp = NULL;
	int index = 0;
	/* MPLS labels */
	mpls_label_t labels[MPLS_MAX_LABELS] = {0};
	int num_labels = 0;
	enum seg6local_action_t seg6l_act = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct seg6local_context seg6l_ctx = {};
	struct in6_addr segs[SRV6_MAX_SIDS] = {};
	int num_segs = 0;
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
				nh_vrf_id = ifp->vrf->vrf_id;
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
			if (rtnh_tb[RTA_ENCAP] && rtnh_tb[RTA_ENCAP_TYPE]
			    && *(uint16_t *)RTA_DATA(rtnh_tb[RTA_ENCAP_TYPE])
				       == LWTUNNEL_ENCAP_SEG6_LOCAL) {
				seg6l_act = parse_encap_seg6local(
					rtnh_tb[RTA_ENCAP], &seg6l_ctx);
			}
			if (rtnh_tb[RTA_ENCAP] && rtnh_tb[RTA_ENCAP_TYPE]
			    && *(uint16_t *)RTA_DATA(rtnh_tb[RTA_ENCAP_TYPE])
				       == LWTUNNEL_ENCAP_SEG6) {
				num_segs = parse_encap_seg6(rtnh_tb[RTA_ENCAP],
							    segs);
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

			/* Resolve default values for SRv6 flavors */
			if (seg6l_ctx.flv.flv_ops !=
			    ZEBRA_SEG6_LOCAL_FLV_OP_UNSPEC) {
				if (seg6l_ctx.flv.lcblock_len == 0)
					seg6l_ctx.flv.lcblock_len =
						ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCBLOCK_LEN;
				if (seg6l_ctx.flv.lcnode_func_len == 0)
					seg6l_ctx.flv.lcnode_func_len =
						ZEBRA_DEFAULT_SEG6_LOCAL_FLV_LCNODE_FN_LEN;
			}

			if (seg6l_act != ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
				nexthop_add_srv6_seg6local(nh, seg6l_act,
							   &seg6l_ctx);

			if (num_segs)
				nexthop_add_srv6_seg6(nh, segs, num_segs);

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

	uint16_t nhop_num = nexthop_group_nexthop_num(ng);

	return nhop_num;
}

/* Looking up routing table by netlink interface. */
int netlink_route_change_read_unicast_internal(struct nlmsghdr *h,
					       ns_id_t ns_id, int startup,
					       struct zebra_dplane_ctx *ctx)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	uint32_t flags = 0;
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

	frrtrace(3, frr_zebra, netlink_route_change_read_unicast, h, ns_id,
		 startup);

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

	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (rtm->rtm_flags & RTM_F_CLONED)
		return 0;
	if (rtm->rtm_protocol == RTPROT_REDIRECT)
		return 0;

	selfroute = is_selfroute(rtm->rtm_protocol);

	if (!startup && selfroute && h->nlmsg_type == RTM_NEWROUTE &&
	    !zrouter.asic_offloaded && !ctx) {
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
	vrf_id = zebra_vrf_lookup_by_table(table, ns_id);
	if (vrf_id == VRF_DEFAULT) {
		if (!is_zebra_valid_kernel_table(table)
		    && !is_zebra_main_routing_table(table))
			return 0;
	}

	if (rtm->rtm_flags & RTM_F_TRAP)
		flags |= ZEBRA_FLAG_TRAPPED;
	if (rtm->rtm_flags & RTM_F_OFFLOAD)
		flags |= ZEBRA_FLAG_OFFLOADED;
	if (rtm->rtm_flags & RTM_F_OFFLOAD_FAILED)
		flags |= ZEBRA_FLAG_OFFLOAD_FAILED;

	if (h->nlmsg_flags & NLM_F_APPEND)
		flags |= ZEBRA_FLAG_OUTOFSYNC;

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
			flog_warn(
				EC_ZEBRA_UNSUPPORTED_V4_SRCDEST,
				"unsupported IPv4 sourcedest route (dest %pFX vrf %u)",
				&p, vrf_id);
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
	} else {
		/* We only handle the AFs we handle... */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: unknown address-family %u", __func__,
				   rtm->rtm_family);
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
		metric = (metric & 0x00FFFFFF);
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char buf2[PREFIX_STRLEN];

		zlog_debug(
			"%s %pFX%s%s vrf %s(%u) table_id: %u metric: %d Admin Distance: %d",
			nl_msg_type_to_str(h->nlmsg_type), &p,
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
		struct route_entry *re;
		struct nexthop_group *ng = NULL;

		re = zebra_rib_route_entry_new(vrf_id, proto, 0, flags, nhe_id,
					       table, metric, mtu, distance,
					       tag);
		if (!nhe_id)
			ng = nexthop_group_new();

		if (!tb[RTA_MULTIPATH]) {
			struct nexthop *nexthop, nh;

			if (!nhe_id) {
				nh = parse_nexthop_unicast(
					ns_id, rtm, tb, bh_type, index, prefsrc,
					gate, afi, vrf_id);

				nexthop = nexthop_new();
				*nexthop = nh;
				nexthop_group_add_sorted(ng, nexthop);
			}
		} else {
			/* This is a multipath route */
			struct rtnexthop *rtnh =
				(struct rtnexthop *)RTA_DATA(tb[RTA_MULTIPATH]);

			if (!nhe_id) {
				uint16_t nhop_num;

				/* Use temporary list of nexthops; parse
				 * message payload's nexthops.
				 */
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
		}
		if (nhe_id || ng) {
			dplane_rib_add_multipath(afi, SAFI_UNICAST, &p, &src_p,
						 re, ng, startup, ctx);
			if (ng)
				nexthop_group_delete(&ng);
			if (ctx)
				zebra_rib_route_entry_free(re);
		} else {
			/*
			 * I really don't see how this is possible
			 * but since we are testing for it let's
			 * let the end user know why the route
			 * that was just received was swallowed
			 * up and forgotten
			 */
			zlog_err(
				"%s: %pFX multipath RTM_NEWROUTE has a invalid nexthop group from the kernel",
				__func__, &p);
			zebra_rib_route_entry_free(re);
		}
	} else {
		if (ctx) {
			zlog_err(
				"%s: %pFX RTM_DELROUTE received but received a context as well",
				__func__, &p);
			return 0;
		}

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

	return 1;
}

static int netlink_route_change_read_unicast(struct nlmsghdr *h, ns_id_t ns_id,
					     int startup)
{
	return netlink_route_change_read_unicast_internal(h, ns_id, startup,
							  NULL);
}

static struct mcast_route_data *mroute = NULL;

static int netlink_route_change_read_multicast(struct nlmsghdr *h,
					       ns_id_t ns_id, int startup)
{
	int len;
	struct rtmsg *rtm;
	struct rtattr *tb[RTA_MAX + 1];
	struct mcast_route_data *m;
	int iif = 0;
	int count;
	int oif[256];
	int oif_count = 0;
	char oif_list[256] = "\0";
	vrf_id_t vrf;
	int table;

	assert(mroute);
	m = mroute;

	rtm = NLMSG_DATA(h);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

	netlink_parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), len);

	if (tb[RTA_TABLE])
		table = *(int *)RTA_DATA(tb[RTA_TABLE]);
	else
		table = rtm->rtm_table;

	vrf = zebra_vrf_lookup_by_table(table, ns_id);

	if (tb[RTA_IIF])
		iif = *(int *)RTA_DATA(tb[RTA_IIF]);

	if (tb[RTA_SRC]) {
		if (rtm->rtm_family == RTNL_FAMILY_IPMR)
			m->src.ipaddr_v4 =
				*(struct in_addr *)RTA_DATA(tb[RTA_SRC]);
		else
			m->src.ipaddr_v6 =
				*(struct in6_addr *)RTA_DATA(tb[RTA_SRC]);
	}

	if (tb[RTA_DST]) {
		if (rtm->rtm_family == RTNL_FAMILY_IPMR)
			m->grp.ipaddr_v4 =
				*(struct in_addr *)RTA_DATA(tb[RTA_DST]);
		else
			m->grp.ipaddr_v6 =
				*(struct in6_addr *)RTA_DATA(tb[RTA_DST]);
	}

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

	if (rtm->rtm_family == RTNL_FAMILY_IPMR) {
		SET_IPADDR_V4(&m->src);
		SET_IPADDR_V4(&m->grp);
	} else if (rtm->rtm_family == RTNL_FAMILY_IP6MR) {
		SET_IPADDR_V6(&m->src);
		SET_IPADDR_V6(&m->grp);
	} else {
		zlog_warn("%s: Invalid rtm_family received", __func__);
		return 0;
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		struct interface *ifp = NULL;
		struct zebra_vrf *zvrf = NULL;

		for (count = 0; count < oif_count; count++) {
			ifp = if_lookup_by_index(oif[count], vrf);
			char temp[256];

			snprintf(temp, sizeof(temp), "%s(%d) ",
				 ifp ? ifp->name : "Unknown", oif[count]);
			strlcat(oif_list, temp, sizeof(oif_list));
		}
		zvrf = zebra_vrf_lookup_by_id(vrf);
		ifp = if_lookup_by_index(iif, vrf);
		zlog_debug(
			"MCAST VRF: %s(%d) %s (%pIA,%pIA) IIF: %s(%d) OIF: %s jiffies: %lld",
			zvrf_name(zvrf), vrf, nl_msg_type_to_str(h->nlmsg_type),
			&m->src, &m->grp, ifp ? ifp->name : "Unknown", iif,
			oif_list, m->lastused);
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

	switch (rtm->rtm_family) {
	case AF_INET:
	case AF_INET6:
		break;

	case RTNL_FAMILY_IPMR:
	case RTNL_FAMILY_IP6MR:
		/* notifications on IPMR are irrelevant to zebra, we only care
		 * about responses to RTM_GETROUTE requests we sent.
		 */
		return 0;

	default:
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

	/* these are "magic" kernel-managed *unicast* routes used for
	 * outputting locally generated multicast traffic (which uses unicast
	 * handling on Linux because ~reasons~.
	 */
	if (rtm->rtm_type == RTN_MULTICAST)
		return 0;

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
				 &zns->netlink_cmd, &dp_info, 0, true);
	if (ret < 0)
		return ret;

	/* Get IPv6 routing table. */
	ret = netlink_request_route(zns, AF_INET6, RTM_GETROUTE);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_route_change_read_unicast,
				 &zns->netlink_cmd, &dp_info, 0, true);
	if (ret < 0)
		return ret;

	return 0;
}

/*
 * The function returns true if the gateway info could be added
 * to the message, otherwise false is returned.
 */
static bool _netlink_route_add_gateway_info(uint8_t route_family,
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
		if (!nl_attr_put(nlmsg, req_size, RTA_VIA, &gw_fam.family,
				 bytelen + 2))
			return false;
	} else {
		if (!(nexthop->rparent
		      && IS_MAPPED_IPV6(&nexthop->rparent->gate.ipv6))) {
			if (gw_family == AF_INET) {
				if (!nl_attr_put(nlmsg, req_size, RTA_GATEWAY,
						 &nexthop->gate.ipv4, bytelen))
					return false;
			} else {
				if (!nl_attr_put(nlmsg, req_size, RTA_GATEWAY,
						 &nexthop->gate.ipv6, bytelen))
					return false;
			}
		}
	}

	return true;
}

static int build_label_stack(struct mpls_label_stack *nh_label,
			     enum lsp_types_t nh_label_type,
			     mpls_lse_t *out_lse, char *label_buf,
			     size_t label_buf_size)
{
	char label_buf1[20];
	int num_labels = 0;

	for (int i = 0; nh_label && i < nh_label->num_labels; i++) {
		if (nh_label_type != ZEBRA_LSP_EVPN &&
		    nh_label->label[i] == MPLS_LABEL_IMPLICIT_NULL)
			continue;

		if (IS_ZEBRA_DEBUG_KERNEL) {
			if (!num_labels)
				snprintf(label_buf, label_buf_size, "label %u",
					 nh_label->label[i]);
			else {
				snprintf(label_buf1, sizeof(label_buf1), "/%u",
					 nh_label->label[i]);
				strlcat(label_buf, label_buf1, label_buf_size);
			}
		}

		if (nh_label_type == ZEBRA_LSP_EVPN)
			out_lse[num_labels] = label2vni(&nh_label->label[i]);
		else
			out_lse[num_labels] =
				mpls_lse_encode(nh_label->label[i], 0, 0, 0);
		num_labels++;
	}

	return num_labels;
}

static bool _netlink_nexthop_encode_dvni_label(const struct nexthop *nexthop,
					       struct nlmsghdr *nlmsg,
					       mpls_lse_t *out_lse,
					       size_t buflen, char *label_buf)
{
	struct in_addr ipv4;

	if (!nl_attr_put64(nlmsg, buflen, LWTUNNEL_IP_ID,
			   htonll((uint64_t)out_lse[0])))
		return false;

	if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		if (!nl_attr_put(nlmsg, buflen, LWTUNNEL_IP_DST,
				 &nexthop->gate.ipv4, 4))
			return false;

	} else if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		if (IS_MAPPED_IPV6(&nexthop->gate.ipv6)) {
			ipv4_mapped_ipv6_to_ipv4(&nexthop->gate.ipv6, &ipv4);
			if (!nl_attr_put(nlmsg, buflen, LWTUNNEL_IP_DST, &ipv4,
					 4))
				return false;

		} else {
			if (!nl_attr_put(nlmsg, buflen, LWTUNNEL_IP_DST,
					 &nexthop->gate.ipv6, 16))
				return false;
		}
	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: nexthop %pNHv %s must NEXTHOP_TYPE_IPV*_IFINDEX to be vxlan encapped",
				__func__, nexthop, label_buf);

		return false;
	}

	return true;
}

static bool _netlink_route_encode_label_info(const struct nexthop *nexthop,
					     struct nlmsghdr *nlmsg,
					     size_t buflen, struct rtmsg *rtmsg,
					     char *label_buf,
					     size_t label_buf_size)
{
	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	int num_labels;
	struct rtattr *nest;
	struct mpls_label_stack *nh_label;
	enum lsp_types_t nh_label_type;

	nh_label = nexthop->nh_label;
	nh_label_type = nexthop->nh_label_type;

	/*
	 * label_buf is *only* currently used within debugging.
	 * As such when we assign it we are guarding it inside
	 * a debug test.  If you want to change this make sure
	 * you fix this assumption
	 */
	label_buf[0] = '\0';

	num_labels = build_label_stack(nh_label, nh_label_type, out_lse,
				       label_buf, label_buf_size);

	if (num_labels && nh_label_type == ZEBRA_LSP_EVPN) {
		if (!nl_attr_put16(nlmsg, buflen, RTA_ENCAP_TYPE,
				   LWTUNNEL_ENCAP_IP))
			return false;

		nest = nl_attr_nest(nlmsg, buflen, RTA_ENCAP);
		if (!nest)
			return false;

		if (_netlink_nexthop_encode_dvni_label(nexthop, nlmsg, out_lse,
						       buflen,
						       label_buf) == false)
			return false;

		nl_attr_nest_end(nlmsg, nest);

	} else if (num_labels) {
		/* Set the BoS bit */
		out_lse[num_labels - 1] |= htonl(1 << MPLS_LS_S_SHIFT);

		if (rtmsg->rtm_family == AF_MPLS) {
			if (!nl_attr_put(nlmsg, buflen, RTA_NEWDST, &out_lse,
					 num_labels * sizeof(mpls_lse_t)))
				return false;
		} else {
			if (!nl_attr_put16(nlmsg, buflen, RTA_ENCAP_TYPE,
					   LWTUNNEL_ENCAP_MPLS))
				return false;

			nest = nl_attr_nest(nlmsg, buflen, RTA_ENCAP);
			if (!nest)
				return false;

			if (!nl_attr_put(nlmsg, buflen, MPLS_IPTUNNEL_DST,
					 &out_lse,
					 num_labels * sizeof(mpls_lse_t)))
				return false;
			nl_attr_nest_end(nlmsg, nest);
		}
	}

	return true;
}

static bool _netlink_route_encode_nexthop_src(const struct nexthop *nexthop,
					      int family,
					      struct nlmsghdr *nlmsg,
					      size_t buflen, int bytelen)
{
	if (family == AF_INET) {
		if (nexthop->rmap_src.ipv4.s_addr != INADDR_ANY) {
			if (!nl_attr_put(nlmsg, buflen, RTA_PREFSRC,
					 &nexthop->rmap_src.ipv4, bytelen))
				return false;
		} else if (nexthop->src.ipv4.s_addr != INADDR_ANY) {
			if (!nl_attr_put(nlmsg, buflen, RTA_PREFSRC,
					 &nexthop->src.ipv4, bytelen))
				return false;
		}
	} else if (family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->rmap_src.ipv6)) {
			if (!nl_attr_put(nlmsg, buflen, RTA_PREFSRC,
					 &nexthop->rmap_src.ipv6, bytelen))
				return false;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&nexthop->src.ipv6)) {
			if (!nl_attr_put(nlmsg, buflen, RTA_PREFSRC,
					 &nexthop->src.ipv6, bytelen))
				return false;
		}
	}

	return true;
}

static ssize_t fill_seg6ipt_encap(char *buffer, size_t buflen,
				  struct seg6_seg_stack *segs)
{
	struct seg6_iptunnel_encap *ipt;
	struct ipv6_sr_hdr *srh;
	size_t srhlen;
	int i;

	if (segs->num_segs > SRV6_MAX_SEGS) {
		/* Exceeding maximum supported SIDs */
		return -1;
	}

	srhlen = SRH_BASE_HEADER_LENGTH + SRH_SEGMENT_LENGTH * segs->num_segs;

	if (buflen < (sizeof(struct seg6_iptunnel_encap) + srhlen))
		return -1;

	memset(buffer, 0, buflen);

	ipt = (struct seg6_iptunnel_encap *)buffer;
	ipt->mode = SEG6_IPTUN_MODE_ENCAP;

	srh = (struct ipv6_sr_hdr *)&ipt->srh;
	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = segs->num_segs - 1;
	srh->first_segment = segs->num_segs - 1;

	for (i = 0; i < segs->num_segs; i++) {
		memcpy(&srh->segments[segs->num_segs - i - 1], &segs->seg[i],
		       sizeof(struct in6_addr));
	}

	return sizeof(struct seg6_iptunnel_encap) + srhlen;
}

static bool
_netlink_nexthop_encode_seg6local_flavor(const struct nexthop *nexthop,
					 struct nlmsghdr *nlmsg, size_t buflen)
{
	struct rtattr *nest;
	struct seg6local_flavors_info *flv;

	assert(nexthop);

	if (!nexthop->nh_srv6)
		return false;

	flv = &nexthop->nh_srv6->seg6local_ctx.flv;

	if (flv->flv_ops == ZEBRA_SEG6_LOCAL_FLV_OP_UNSPEC)
		return true;

	nest = nl_attr_nest(nlmsg, buflen, SEG6_LOCAL_FLAVORS);
	if (!nest)
		return false;

	if (!nl_attr_put32(nlmsg, buflen, SEG6_LOCAL_FLV_OPERATION,
			   flv->flv_ops))
		return false;

	if (flv->lcblock_len)
		if (!nl_attr_put8(nlmsg, buflen, SEG6_LOCAL_FLV_LCBLOCK_BITS,
				  flv->lcblock_len))
			return false;

	if (flv->lcnode_func_len)
		if (!nl_attr_put8(nlmsg, buflen, SEG6_LOCAL_FLV_LCNODE_FN_BITS,
				  flv->lcnode_func_len))
			return false;

	nl_attr_nest_end(nlmsg, nest);

	return true;
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
 *
 * The function returns true if the nexthop could be added
 * to the message, otherwise false is returned.
 */
static bool _netlink_route_build_singlepath(const struct prefix *p,
					    const char *routedesc, int bytelen,
					    const struct nexthop *nexthop,
					    struct nlmsghdr *nlmsg,
					    struct rtmsg *rtmsg,
					    size_t req_size, int cmd)
{

	char label_buf[256];
	struct vrf *vrf;
	char addrstr[INET6_ADDRSTRLEN];

	assert(nexthop);

	vrf = vrf_lookup_by_id(nexthop->vrf_id);

	if (!_netlink_route_encode_label_info(nexthop, nlmsg, req_size, rtmsg,
					      label_buf, sizeof(label_buf)))
		return false;

	if (nexthop->nh_srv6) {
		if (nexthop->nh_srv6->seg6local_action !=
		    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			struct rtattr *nest;
			const struct seg6local_context *ctx;

			ctx = &nexthop->nh_srv6->seg6local_ctx;
			if (!nl_attr_put16(nlmsg, req_size, RTA_ENCAP_TYPE,
					   LWTUNNEL_ENCAP_SEG6_LOCAL))
				return false;

			nest = nl_attr_nest(nlmsg, req_size, RTA_ENCAP);
			if (!nest)
				return false;

			switch (nexthop->nh_srv6->seg6local_action) {
			case ZEBRA_SEG6_LOCAL_ACTION_END:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_X:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_X))
					return false;
				if (!nl_attr_put(nlmsg, req_size,
						 SEG6_LOCAL_NH6, &ctx->nh6,
						 sizeof(struct in6_addr)))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_T:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_T))
					return false;
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_TABLE,
						   ctx->table))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DX4:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_DX4))
					return false;
				if (!nl_attr_put(nlmsg, req_size,
						 SEG6_LOCAL_NH4, &ctx->nh4,
						 sizeof(struct in_addr)))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DX6:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_DX6))
					return false;
				if (!nl_attr_put(nlmsg, req_size,
						 SEG6_LOCAL_NH6, &ctx->nh6,
						 sizeof(struct in6_addr)))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DT6:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_DT6))
					return false;
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_TABLE,
						   ctx->table))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DT4:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_DT4))
					return false;
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_VRFTABLE,
						   ctx->table))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DT46:
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_ACTION,
						   SEG6_LOCAL_ACTION_END_DT46))
					return false;
				if (!nl_attr_put32(nlmsg, req_size,
						   SEG6_LOCAL_VRFTABLE,
						   ctx->table))
					return false;
				break;
			case ZEBRA_SEG6_LOCAL_ACTION_END_DX2:
			case ZEBRA_SEG6_LOCAL_ACTION_END_B6:
			case ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP:
			case ZEBRA_SEG6_LOCAL_ACTION_END_BM:
			case ZEBRA_SEG6_LOCAL_ACTION_END_S:
			case ZEBRA_SEG6_LOCAL_ACTION_END_AS:
			case ZEBRA_SEG6_LOCAL_ACTION_END_AM:
			case ZEBRA_SEG6_LOCAL_ACTION_END_BPF:
			case ZEBRA_SEG6_LOCAL_ACTION_UNSPEC:
				zlog_err("%s: unsupport seg6local behaviour action=%u",
					 __func__,
					 nexthop->nh_srv6->seg6local_action);
				return false;
			}

			if (!_netlink_nexthop_encode_seg6local_flavor(
				    nexthop, nlmsg, req_size))
				return false;

			nl_attr_nest_end(nlmsg, nest);
		}

		if (nexthop->nh_srv6->seg6_segs &&
		    nexthop->nh_srv6->seg6_segs->num_segs &&
		    !sid_zero(nexthop->nh_srv6->seg6_segs)) {
			char tun_buf[4096];
			ssize_t tun_len;
			struct rtattr *nest;

			if (!nl_attr_put16(nlmsg, req_size, RTA_ENCAP_TYPE,
					  LWTUNNEL_ENCAP_SEG6))
				return false;
			nest = nl_attr_nest(nlmsg, req_size, RTA_ENCAP);
			if (!nest)
				return false;
			tun_len =
				fill_seg6ipt_encap(tun_buf, sizeof(tun_buf),
						   nexthop->nh_srv6->seg6_segs);
			if (tun_len < 0)
				return false;
			if (!nl_attr_put(nlmsg, req_size, SEG6_IPTUNNEL_SRH,
					 tun_buf, tun_len))
				return false;
			nl_attr_nest_end(nlmsg, nest);
		}
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		rtmsg->rtm_flags |= RTNH_F_ONLINK;

	if (is_route_v4_over_v6(rtmsg->rtm_family, nexthop->type)) {
		rtmsg->rtm_flags |= RTNH_F_ONLINK;
		if (!nl_attr_put(nlmsg, req_size, RTA_GATEWAY, &ipv4_ll, 4))
			return false;
		if (!nl_attr_put32(nlmsg, req_size, RTA_OIF, nexthop->ifindex))
			return false;

		if (cmd == RTM_NEWROUTE) {
			if (!_netlink_route_encode_nexthop_src(
				    nexthop, AF_INET, nlmsg, req_size, bytelen))
				return false;
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: 5549 (%s): %pFX nexthop via %s %s if %u vrf %s(%u)",
				   __func__, routedesc, p, ipv4_ll_buf,
				   label_buf, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
		return true;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		/* Send deletes to the kernel without specifying the next-hop */
		if (cmd != RTM_DELROUTE) {
			if (!_netlink_route_add_gateway_info(
				    rtmsg->rtm_family, AF_INET, nlmsg, req_size,
				    bytelen, nexthop))
				return false;
		}

		if (cmd == RTM_NEWROUTE) {
			if (!_netlink_route_encode_nexthop_src(
				    nexthop, AF_INET, nlmsg, req_size, bytelen))
				return false;
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
		if (!_netlink_route_add_gateway_info(rtmsg->rtm_family,
						     AF_INET6, nlmsg, req_size,
						     bytelen, nexthop))
			return false;

		if (cmd == RTM_NEWROUTE) {
			if (!_netlink_route_encode_nexthop_src(
				    nexthop, AF_INET6, nlmsg, req_size,
				    bytelen))
				return false;
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
	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE) {
		if (!nl_attr_put32(nlmsg, req_size, RTA_OIF, nexthop->ifindex))
			return false;
	}

	if (nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		if (cmd == RTM_NEWROUTE) {
			if (!_netlink_route_encode_nexthop_src(
				    nexthop, AF_INET, nlmsg, req_size, bytelen))
				return false;
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: (%s): %pFX nexthop via if %u vrf %s(%u)",
				   __func__, routedesc, p, nexthop->ifindex,
				   VRF_LOGNAME(vrf), nexthop->vrf_id);
	}

	return true;
}

/* This function appends tag value as rtnl flow attribute
 * to the given netlink msg only if value is less than 256.
 * Used only if SUPPORT_REALMS enabled.
 *
 * @param nlmsg: nlmsghdr structure to fill in.
 * @param maxlen: The size allocated for the message.
 * @param tag: The route tag.
 *
 * The function returns true if the flow attribute could
 * be added to the message, otherwise false is returned.
 */
static inline bool _netlink_set_tag(struct nlmsghdr *n, unsigned int maxlen,
				    route_tag_t tag)
{
	if (tag > 0 && tag <= 255) {
		if (!nl_attr_put32(n, maxlen, RTA_FLOW, tag))
			return false;
	}
	return true;
}

/*
 * The function returns true if the attribute could be added
 * to the message, otherwise false is returned.
 */
static int netlink_route_nexthop_encap(bool fpm, struct nlmsghdr *n,
				       size_t nlen, const struct nexthop *nh)
{
	struct rtattr *nest;

	if (!fpm)
		return true;

	switch (nh->nh_encap_type) {
	case NET_VXLAN:
		if (!nl_attr_put16(n, nlen, RTA_ENCAP_TYPE, nh->nh_encap_type))
			return false;

		nest = nl_attr_nest(n, nlen, RTA_ENCAP);
		if (!nest)
			return false;

		if (!nl_attr_put32(n, nlen, 0 /* VXLAN_VNI */, nh->nh_encap.vni))
			return false;
		nl_attr_nest_end(n, nest);
		break;
	}

	return true;
}

/* This function takes a nexthop as argument and
 * appends to the given netlink msg. If the nexthop
 * defines a preferred source, the src parameter
 * will be modified to point to that src, otherwise
 * it will be kept unmodified.
 *
 * @param routedesc: Human readable description of route type
 *                   (direct/recursive, single-/multipath)
 * @param bytelen: Length of addresses in bytes.
 * @param nexthop: Nexthop information
 * @param nlmsg: nlmsghdr structure to fill in.
 * @param req_size: The size allocated for the message.
 * @param src: pointer pointing to a location where
 *             the prefsrc should be stored.
 *
 * The function returns true if the nexthop could be added
 * to the message, otherwise false is returned.
 */
static bool _netlink_route_build_multipath(const struct prefix *p,
					   const char *routedesc, int bytelen,
					   const struct nexthop *nexthop,
					   struct nlmsghdr *nlmsg,
					   size_t req_size, struct rtmsg *rtmsg,
					   const union g_addr **src,
					   route_tag_t tag, bool fpm)
{
	char label_buf[256];
	struct vrf *vrf;
	struct rtnexthop *rtnh;

	rtnh = nl_attr_rtnh(nlmsg, req_size);
	if (rtnh == NULL)
		return false;

	assert(nexthop);

	vrf = vrf_lookup_by_id(nexthop->vrf_id);

	if (!_netlink_route_encode_label_info(nexthop, nlmsg, req_size, rtmsg,
					      label_buf, sizeof(label_buf)))
		return false;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		rtnh->rtnh_flags |= RTNH_F_ONLINK;

	if (is_route_v4_over_v6(rtmsg->rtm_family, nexthop->type)) {
		rtnh->rtnh_flags |= RTNH_F_ONLINK;
		if (!nl_attr_put(nlmsg, req_size, RTA_GATEWAY, &ipv4_ll, 4))
			return false;
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
		nl_attr_rtnh_end(nlmsg, rtnh);
		return true;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		if (!_netlink_route_add_gateway_info(rtmsg->rtm_family, AF_INET,
						     nlmsg, req_size, bytelen,
						     nexthop))
			return false;

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
		if (!_netlink_route_add_gateway_info(rtmsg->rtm_family,
						     AF_INET6, nlmsg, req_size,
						     bytelen, nexthop))
			return false;

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

	if (!_netlink_set_tag(nlmsg, req_size, tag))
		return false;

	/*
	 * Add encapsulation information when installing via
	 * FPM.
	 */
	if (!netlink_route_nexthop_encap(fpm, nlmsg, req_size, nexthop))
		return false;

	nl_attr_rtnh_end(nlmsg, rtnh);
	return true;
}

static inline bool
_netlink_mpls_build_singlepath(const struct prefix *p, const char *routedesc,
			       const struct zebra_nhlfe *nhlfe,
			       struct nlmsghdr *nlmsg, struct rtmsg *rtmsg,
			       size_t req_size, int cmd)
{
	int bytelen;
	uint8_t family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	return _netlink_route_build_singlepath(p, routedesc, bytelen,
					       nhlfe->nexthop, nlmsg, rtmsg,
					       req_size, cmd);
}


static inline bool
_netlink_mpls_build_multipath(const struct prefix *p, const char *routedesc,
			      const struct zebra_nhlfe *nhlfe,
			      struct nlmsghdr *nlmsg, size_t req_size,
			      struct rtmsg *rtmsg, const union g_addr **src)
{
	int bytelen;
	uint8_t family;

	family = NHLFE_FAMILY(nhlfe);
	bytelen = (family == AF_INET ? 4 : 16);
	return _netlink_route_build_multipath(p, routedesc, bytelen,
					      nhlfe->nexthop, nlmsg, req_size,
					      rtmsg, src, 0, false);
}

static void _netlink_mpls_debug(int cmd, uint32_t label, const char *routedesc)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("netlink_mpls_multipath_msg_encode() (%s): %s %u/20",
			   routedesc, nl_msg_type_to_str(cmd), label);
}

static int netlink_neigh_update(int cmd, int ifindex, void *addr, char *lla,
				int llalen, ns_id_t ns_id, uint8_t family,
				bool permanent, uint8_t protocol)
{
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

	req.ndm.ndm_family = family;
	req.ndm.ndm_ifindex = ifindex;
	req.ndm.ndm_type = RTN_UNICAST;
	if (cmd == RTM_NEWNEIGH) {
		if (!permanent)
			req.ndm.ndm_state = NUD_REACHABLE;
		else
			req.ndm.ndm_state = NUD_PERMANENT;
	} else
		req.ndm.ndm_state = NUD_FAILED;

	nl_attr_put(&req.n, sizeof(req), NDA_PROTOCOL, &protocol,
		    sizeof(protocol));
	req.ndm.ndm_type = RTN_UNICAST;
	nl_attr_put(&req.n, sizeof(req), NDA_DST, addr,
		    family2addrsize(family));
	if (lla)
		nl_attr_put(&req.n, sizeof(req), NDA_LLADDR, lla, llalen);

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char ip_str[INET6_ADDRSTRLEN + 8];
		struct interface *ifp = if_lookup_by_index_per_ns(
			zebra_ns_lookup(ns_id), ifindex);
		if (ifp) {
			if (family == AF_INET6)
				snprintfrr(ip_str, sizeof(ip_str), "ipv6 %pI6",
					   (struct in6_addr *)addr);
			else
				snprintfrr(ip_str, sizeof(ip_str), "ipv4 %pI4",
					   (in_addr_t *)addr);
			zlog_debug(
				"%s: %s ifname %s ifindex %u addr %s mac %pEA vrf %s(%u)",
				__func__, nl_msg_type_to_str(cmd), ifp->name,
				ifindex, ip_str, (struct ethaddr *)lla,
				vrf_id_to_name(ifp->vrf->vrf_id),
				ifp->vrf->vrf_id);
		}
	}
	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    false);
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

/*
 * Routing table change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
ssize_t netlink_route_multipath_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					   uint8_t *data, size_t datalen,
					   bool fpm, bool force_nhg,
					   bool force_rr)
{
	int bytelen;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	const char *routedesc;
	bool setsrc = false;
	union g_addr src;
	const struct prefix *p, *src_p;
	uint32_t table_id;
	struct nlsock *nl;
	route_tag_t tag = 0;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[];
	} *req = (void *)data;

	p = dplane_ctx_get_dest(ctx);
	src_p = dplane_ctx_get_src(ctx);

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	bytelen = (p->family == AF_INET ? 4 : 16);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (((cmd == RTM_NEWROUTE) &&
	     ((p->family == AF_INET) || kernel_nexthops_supported() ||
	      zrouter.v6_rr_semantics)) ||
	    force_rr)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

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

	if (!nl_attr_put(&req->n, datalen, RTA_DST, &p->u.prefix, bytelen))
		return 0;
	if (src_p) {
		if (!nl_attr_put(&req->n, datalen, RTA_SRC, &src_p->u.prefix,
				 bytelen))
			return 0;
	}

	/* Metric. */
	/* Hardcode the metric for all routes coming from zebra. Metric isn't
	 * used
	 * either by the kernel or by zebra. Its purely for calculating best
	 * path(s)
	 * by the routing protocol and for communicating with protocol peers.
	 */
	if (!nl_attr_put32(&req->n, datalen, RTA_PRIORITY,
			   ROUTE_INSTALLATION_METRIC))
		return 0;

#if defined(SUPPORT_REALMS)
	if (cmd == RTM_DELROUTE)
		tag = dplane_ctx_get_old_tag(ctx);
	else
		tag = dplane_ctx_get_tag(ctx);
#endif

	/* Table corresponding to this route. */
	table_id = dplane_ctx_get_table(ctx);
	if (table_id < 256)
		req->r.rtm_table = table_id;
	else {
		req->r.rtm_table = RT_TABLE_UNSPEC;
		if (!nl_attr_put32(&req->n, datalen, RTA_TABLE, table_id))
			return 0;
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
	if (cmd == RTM_DELROUTE) {
		if (!_netlink_set_tag(&req->n, datalen, tag))
			return 0;
		return NLMSG_ALIGN(req->n.nlmsg_len);
	}

	if (dplane_ctx_get_mtu(ctx) || dplane_ctx_get_nh_mtu(ctx)) {
		struct rtattr *nest;
		uint32_t mtu = dplane_ctx_get_mtu(ctx);
		uint32_t nexthop_mtu = dplane_ctx_get_nh_mtu(ctx);

		if (!mtu || (nexthop_mtu && nexthop_mtu < mtu))
			mtu = nexthop_mtu;

		nest = nl_attr_nest(&req->n, datalen, RTA_METRICS);
		if (nest == NULL)
			return 0;

		if (!nl_attr_put(&req->n, datalen, RTAX_MTU, &mtu, sizeof(mtu)))
			return 0;
		nl_attr_nest_end(&req->n, nest);
	}

	/*
	 * Always install blackhole routes without using nexthops, because of
	 * the following kernel problems:
	 * 1. Kernel nexthops don't suport unreachable/prohibit route types.
	 * 2. Blackhole kernel nexthops are deleted when loopback is down.
	 */
	nexthop = dplane_ctx_get_ng(ctx)->nexthop;
	if (nexthop) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			nexthop = nexthop->resolved;

		if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
			switch (nexthop->bh_type) {
			case BLACKHOLE_ADMINPROHIB:
				req->r.rtm_type = RTN_PROHIBIT;
				break;
			case BLACKHOLE_REJECT:
				req->r.rtm_type = RTN_UNREACHABLE;
				break;
			case BLACKHOLE_UNSPEC:
			case BLACKHOLE_NULL:
				req->r.rtm_type = RTN_BLACKHOLE;
				break;
			}
			return NLMSG_ALIGN(req->n.nlmsg_len);
		}
	}

	if ((!fpm && kernel_nexthops_supported()
	     && (!proto_nexthops_only()
		 || is_proto_nhg(dplane_ctx_get_nhe_id(ctx), 0)))
	    || (fpm && force_nhg)) {
		/* Kernel supports nexthop objects */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %pFX nhg_id is %u", __func__, p,
				   dplane_ctx_get_nhe_id(ctx));

		if (!nl_attr_put32(&req->n, datalen, RTA_NH_ID,
				   dplane_ctx_get_nhe_id(ctx)))
			return 0;

		/* Have to determine src still */
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (setsrc)
				break;

			setsrc = nexthop_set_src(nexthop, p->family, &src);
			if (setsrc && IS_ZEBRA_DEBUG_KERNEL) {
				if (p->family == AF_INET)
					zlog_debug("%s: %pFX set src %pI4",
						   __func__, p, &src.ipv4);
				else if (p->family == AF_INET6)
					zlog_debug("%s: %pFX set src %pI6",
						   __func__, p, &src.ipv6);
			}
		}

		if (setsrc) {
			if (p->family == AF_INET) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv4, bytelen))
					return 0;
			} else if (p->family == AF_INET6) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv6, bytelen))
					return 0;
			}
		}

		return NLMSG_ALIGN(req->n.nlmsg_len);
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
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {

				if (setsrc)
					continue;

				setsrc = nexthop_set_src(nexthop, p->family,
							 &src);
				if (setsrc && IS_ZEBRA_DEBUG_KERNEL) {
					if (p->family == AF_INET)
						zlog_debug("%s: %pFX set src %pI4",
							   __func__, p,
							   &src.ipv4);
					else if (p->family == AF_INET6)
						zlog_debug("%s: %pFX set src %pI6",
							   __func__, p,
							   &src.ipv6);
				}
				continue;
			}

			if (NEXTHOP_IS_ACTIVE(nexthop->flags)) {
				routedesc = nexthop->rparent
						    ? "recursive, single-path"
						    : "single-path";

				if (!_netlink_set_tag(&req->n, datalen, tag))
					return 0;

				if (!_netlink_route_build_singlepath(
					    p, routedesc, bytelen, nexthop,
					    &req->n, &req->r, datalen, cmd))
					return 0;

				/*
				 * Add encapsulation information when
				 * installing via FPM.
				 */
				if (!netlink_route_nexthop_encap(fpm, &req->n,
								 datalen,
								 nexthop))
					return 0;

				nexthop_num++;
				break;
			}
		}

		if (setsrc) {
			if (p->family == AF_INET) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv4, bytelen))
					return 0;
			} else if (p->family == AF_INET6) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv6, bytelen))
					return 0;
			}
		}
	} else {    /* Multipath case */
		struct rtattr *nest;
		const union g_addr *src1 = NULL;

		nest = nl_attr_nest(&req->n, datalen, RTA_MULTIPATH);
		if (nest == NULL)
			return 0;

		nexthop_num = 0;
		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags,
				       NEXTHOP_FLAG_RECURSIVE)) {
				/* This only works for IPv4 now */
				if (setsrc)
					continue;

				setsrc = nexthop_set_src(nexthop, p->family,
							 &src);
				if (setsrc && IS_ZEBRA_DEBUG_KERNEL) {
					if (p->family == AF_INET)
						zlog_debug("%s: %pFX set src %pI4",
							   __func__, p,
							   &src.ipv4);
					else if (p->family == AF_INET6)
						zlog_debug("%s: %pFX set src %pI6",
							   __func__, p,
							   &src.ipv6);
				}
				continue;
			}

			if (NEXTHOP_IS_ACTIVE(nexthop->flags)) {
				routedesc = nexthop->rparent
						    ? "recursive, multipath"
						    : "multipath";
				nexthop_num++;

				if (!_netlink_route_build_multipath(p, routedesc,
								    bytelen,
								    nexthop,
								    &req->n,
								    datalen,
								    &req->r,
								    &src1, tag,
								    fpm))
					return 0;

				if (!setsrc && src1) {
					if (p->family == AF_INET)
						src.ipv4 = src1->ipv4;
					else if (p->family == AF_INET6)
						src.ipv6 = src1->ipv6;

					setsrc = 1;
				}
			}
		}

		nl_attr_nest_end(&req->n, nest);

		if (setsrc) {
			if (p->family == AF_INET) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv4, bytelen))
					return 0;
			} else if (p->family == AF_INET6) {
				if (!nl_attr_put(&req->n, datalen, RTA_PREFSRC,
						 &src.ipv6, bytelen))
					return 0;
			}
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("Setting source");
		}
	}

	/* If there is no useful nexthop then return. */
	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: No useful nexthop.", __func__);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *in)
{
	uint32_t actual_table;
	int suc = 0;
	struct mcast_route_data *mr = (struct mcast_route_data *)in;
	struct {
		struct nlmsghdr n;
		struct rtmsg rtm;
		char buf[256];
	} req;

	mroute = mr;
	struct zebra_ns *zns;

	zns = zvrf->zns;
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.n.nlmsg_type = RTM_GETROUTE;

	if (mroute->family == AF_INET) {
		req.rtm.rtm_family = RTNL_FAMILY_IPMR;
		req.rtm.rtm_dst_len = IPV4_MAX_BITLEN;
		req.rtm.rtm_src_len = IPV4_MAX_BITLEN;

		nl_attr_put(&req.n, sizeof(req), RTA_SRC,
			    &mroute->src.ipaddr_v4,
			    sizeof(mroute->src.ipaddr_v4));
		nl_attr_put(&req.n, sizeof(req), RTA_DST,
			    &mroute->grp.ipaddr_v4,
			    sizeof(mroute->grp.ipaddr_v4));
	} else {
		req.rtm.rtm_family = RTNL_FAMILY_IP6MR;
		req.rtm.rtm_dst_len = IPV6_MAX_BITLEN;
		req.rtm.rtm_src_len = IPV6_MAX_BITLEN;

		nl_attr_put(&req.n, sizeof(req), RTA_SRC,
			    &mroute->src.ipaddr_v6,
			    sizeof(mroute->src.ipaddr_v6));
		nl_attr_put(&req.n, sizeof(req), RTA_DST,
			    &mroute->grp.ipaddr_v6,
			    sizeof(mroute->grp.ipaddr_v6));
	}

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
	if (mroute->family == AF_INET)
		actual_table = (zvrf->table_id == rt_table_main_id)
				       ? RT_TABLE_DEFAULT
				       : zvrf->table_id;
	else
		actual_table = zvrf->table_id;

	nl_attr_put32(&req.n, sizeof(req), RTA_TABLE, actual_table);

	suc = netlink_talk(netlink_route_change_read_multicast, &req.n,
			   &zns->netlink_cmd, zns, false);

	mroute = NULL;
	return suc;
}

/* Char length to debug ID with */
#define ID_LENGTH 10

static bool _netlink_nexthop_build_group(struct nlmsghdr *n, size_t req_size, uint32_t id,
					 const struct nh_grp *z_grp, const uint16_t count,
					 bool resilient, const struct nhg_resilience *nhgr)
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
					snprintf(buf, sizeof(buf), "group %u",
						 grp[i].id);
				else {
					snprintf(buf1, sizeof(buf1), "/%u",
						 grp[i].id);
					strlcat(buf, buf1, sizeof(buf));
				}
			}
		}
		if (!nl_attr_put(n, req_size, NHA_GROUP, grp,
				 count * sizeof(*grp)))
			return false;

		if (resilient) {
			struct rtattr *nest;

			nest = nl_attr_nest(n, req_size, NHA_RES_GROUP);

			nl_attr_put16(n, req_size, NHA_RES_GROUP_BUCKETS,
				      nhgr->buckets);
			nl_attr_put32(n, req_size, NHA_RES_GROUP_IDLE_TIMER,
				      nhgr->idle_timer * 1000);
			nl_attr_put32(n, req_size,
				      NHA_RES_GROUP_UNBALANCED_TIMER,
				      nhgr->unbalanced_timer * 1000);
			nl_attr_nest_end(n, nest);

			nl_attr_put16(n, req_size, NHA_GROUP_TYPE,
				      NEXTHOP_GRP_TYPE_RES);
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: ID (%u): %s", __func__, id, buf);

	return true;
}

/**
 * Next hop packet encoding helper function.
 *
 * \param[in] cmd netlink command.
 * \param[in] ctx dataplane context (information snapshot).
 * \param[out] buf buffer to hold the packet.
 * \param[in] buflen amount of buffer bytes.
 *
 * \returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
ssize_t netlink_nexthop_msg_encode(uint16_t cmd,
				   const struct zebra_dplane_ctx *ctx,
				   void *buf, size_t buflen, bool fpm)
{
	struct {
		struct nlmsghdr n;
		struct nhmsg nhm;
		char buf[];
	} *req = buf;

	mpls_lse_t out_lse[MPLS_MAX_LABELS];
	char label_buf[256];
	int num_labels = 0;
	uint32_t id = dplane_ctx_get_nhe_id(ctx);
	int type = dplane_ctx_get_nhe_type(ctx);
	struct rtattr *nest;
	uint16_t encap;
	struct nlsock *nl =
		kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	if (!id) {
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Failed trying to update a nexthop group in the kernel that does not have an ID");
		return -1;
	}

	/*
	 * Nothing to do if the kernel doesn't support nexthop objects or
	 * we dont want to install this type of NHG, but FPM may possible to
	 * handle this.
	 */
	if (!fpm && !kernel_nexthops_supported()) {
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

	if (buflen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (cmd == RTM_NEWNEXTHOP)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;
	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->nhm.nh_family = AF_UNSPEC;
	/* TODO: Scope? */

	if (!nl_attr_put32(&req->n, buflen, NHA_ID, id))
		return 0;

	if (cmd == RTM_NEWNEXTHOP) {
		/*
		 * We distinguish between a "group", which is a collection
		 * of ids, and a singleton nexthop with an id. The
		 * group is installed as an id that just refers to a list of
		 * other ids.
		 */
		if (dplane_ctx_get_nhe_nh_grp_count(ctx)) {
			const struct nexthop_group *nhg;
			const struct nhg_resilience *nhgr;

			nhg = dplane_ctx_get_nhe_ng(ctx);
			nhgr = &nhg->nhgr;
			if (!_netlink_nexthop_build_group(
				    &req->n, buflen, id,
				    dplane_ctx_get_nhe_nh_grp(ctx),
				    dplane_ctx_get_nhe_nh_grp_count(ctx),
				    !!nhgr->buckets, nhgr))
				return 0;
		} else {
			const struct nexthop *nh =
				dplane_ctx_get_nhe_ng(ctx)->nexthop;
			afi_t afi = dplane_ctx_get_nhe_afi(ctx);

			if (afi == AFI_IP)
				req->nhm.nh_family = AF_INET;
			else if (afi == AFI_IP6)
				req->nhm.nh_family = AF_INET6;

			switch (nh->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				if (!nl_attr_put(&req->n, buflen, NHA_GATEWAY,
						 &nh->gate.ipv4,
						 IPV4_MAX_BYTELEN))
					return 0;
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				if (!nl_attr_put(&req->n, buflen, NHA_GATEWAY,
						 &nh->gate.ipv6,
						 IPV6_MAX_BYTELEN))
					return 0;
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				if (!nl_attr_put(&req->n, buflen, NHA_BLACKHOLE,
						 NULL, 0))
					return 0;
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

			if (!nl_attr_put32(&req->n, buflen, NHA_OIF,
					   nh->ifindex))
				return 0;

			if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ONLINK))
				req->nhm.nh_flags |= RTNH_F_ONLINK;

			num_labels = build_label_stack(
				nh->nh_label, nh->nh_label_type, out_lse,
				label_buf, sizeof(label_buf));

			if (num_labels && nh->nh_label_type == ZEBRA_LSP_EVPN) {
				if (!nl_attr_put16(&req->n, buflen,
						   NHA_ENCAP_TYPE,
						   LWTUNNEL_ENCAP_IP))
					return 0;

				nest = nl_attr_nest(&req->n, buflen, NHA_ENCAP);
				if (!nest)
					return 0;

				if (_netlink_nexthop_encode_dvni_label(
					    nh, &req->n, out_lse, buflen,
					    label_buf) == false)
					return 0;

				nl_attr_nest_end(&req->n, nest);

			} else if (num_labels) {
				/* Set the BoS bit */
				out_lse[num_labels - 1] |=
					htonl(1 << MPLS_LS_S_SHIFT);

				/*
				 * TODO: MPLS unsupported for now in kernel.
				 */
				if (req->nhm.nh_family == AF_MPLS)
					goto nexthop_done;

				encap = LWTUNNEL_ENCAP_MPLS;
				if (!nl_attr_put16(&req->n, buflen,
						   NHA_ENCAP_TYPE, encap))
					return 0;
				nest = nl_attr_nest(&req->n, buflen, NHA_ENCAP);
				if (!nest)
					return 0;
				if (!nl_attr_put(
					    &req->n, buflen, MPLS_IPTUNNEL_DST,
					    &out_lse,
					    num_labels * sizeof(mpls_lse_t)))
					return 0;

				nl_attr_nest_end(&req->n, nest);
			}

			if (nh->nh_srv6) {
				if (nh->nh_srv6->seg6local_action !=
				    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
					uint32_t action;
					uint16_t encap;
					struct rtattr *nest;
					const struct seg6local_context *ctx;

					req->nhm.nh_family = AF_INET6;
					action = nh->nh_srv6->seg6local_action;
					ctx = &nh->nh_srv6->seg6local_ctx;
					encap = LWTUNNEL_ENCAP_SEG6_LOCAL;
					if (!nl_attr_put(&req->n, buflen,
							 NHA_ENCAP_TYPE,
							 &encap,
							 sizeof(uint16_t)))
						return 0;

					nest = nl_attr_nest(&req->n, buflen,
						NHA_ENCAP | NLA_F_NESTED);
					if (!nest)
						return 0;

					switch (action) {
					case SEG6_LOCAL_ACTION_END:
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_ACTION,
						    SEG6_LOCAL_ACTION_END))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_X:
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_ACTION,
						    SEG6_LOCAL_ACTION_END_X))
							return 0;
						if (!nl_attr_put(
						    &req->n, buflen,
						    SEG6_LOCAL_NH6, &ctx->nh6,
						    sizeof(struct in6_addr)))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_T:
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_ACTION,
						    SEG6_LOCAL_ACTION_END_T))
							return 0;
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_TABLE,
						    ctx->table))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_DX4:
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_ACTION,
						    SEG6_LOCAL_ACTION_END_DX4))
							return 0;
						if (!nl_attr_put(
						    &req->n, buflen,
						    SEG6_LOCAL_NH4, &ctx->nh4,
						    sizeof(struct in_addr)))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_DX6:
						if (!nl_attr_put32(&req->n,
								   buflen,
								   SEG6_LOCAL_ACTION,
								   SEG6_LOCAL_ACTION_END_DX6))
							return 0;
						if (!nl_attr_put(&req->n, buflen,
								 SEG6_LOCAL_NH6,
								 &ctx->nh6,
								 sizeof(struct in6_addr)))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_DT6:
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_ACTION,
						    SEG6_LOCAL_ACTION_END_DT6))
							return 0;
						if (!nl_attr_put32(
						    &req->n, buflen,
						    SEG6_LOCAL_TABLE,
						    ctx->table))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_DT4:
						if (!nl_attr_put32(
							    &req->n, buflen,
							    SEG6_LOCAL_ACTION,
							    SEG6_LOCAL_ACTION_END_DT4))
							return 0;
						if (!nl_attr_put32(
							    &req->n, buflen,
							    SEG6_LOCAL_VRFTABLE,
							    ctx->table))
							return 0;
						break;
					case SEG6_LOCAL_ACTION_END_DT46:
						if (!nl_attr_put32(
							    &req->n, buflen,
							    SEG6_LOCAL_ACTION,
							    SEG6_LOCAL_ACTION_END_DT46))
							return 0;
						if (!nl_attr_put32(
							    &req->n, buflen,
							    SEG6_LOCAL_VRFTABLE,
							    ctx->table))
							return 0;
						break;
					default:
						zlog_err("%s: unsupport seg6local behaviour action=%u",
							 __func__, action);
						return 0;
					}

					if (!_netlink_nexthop_encode_seg6local_flavor(
						    nh, &req->n, buflen))
						return false;

					nl_attr_nest_end(&req->n, nest);
				}

				if (nh->nh_srv6->seg6_segs &&
				    nh->nh_srv6->seg6_segs->num_segs &&
				    !sid_zero(nh->nh_srv6->seg6_segs)) {
					char tun_buf[4096];
					ssize_t tun_len;
					struct rtattr *nest;

					if (!nl_attr_put16(&req->n, buflen,
					    NHA_ENCAP_TYPE,
					    LWTUNNEL_ENCAP_SEG6))
						return 0;
					nest = nl_attr_nest(&req->n, buflen,
					    NHA_ENCAP | NLA_F_NESTED);
					if (!nest)
						return 0;
					tun_len = fill_seg6ipt_encap(
						tun_buf, sizeof(tun_buf),
						nh->nh_srv6->seg6_segs);
					if (tun_len < 0)
						return 0;
					if (!nl_attr_put(&req->n, buflen,
							 SEG6_IPTUNNEL_SRH,
							 tun_buf, tun_len))
						return 0;
					nl_attr_nest_end(&req->n, nest);
				}
			}

nexthop_done:

			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: ID (%u): %pNHv(%d) vrf %s(%u) %s ",
					   __func__, id, nh, nh->ifindex,
					   vrf_id_to_name(nh->vrf_id),
					   nh->vrf_id, label_buf);
		}

		req->nhm.nh_protocol = zebra2proto(type);

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

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_nexthop_msg_encoder(struct zebra_dplane_ctx *ctx,
					   void *buf, size_t buflen)
{
	enum dplane_op_e op;
	int cmd = 0;

	op = dplane_ctx_get_op(ctx);
	if (op == DPLANE_OP_NH_INSTALL || op == DPLANE_OP_NH_UPDATE)
		cmd = RTM_NEWNEXTHOP;
	else if (op == DPLANE_OP_NH_DELETE)
		cmd = RTM_DELNEXTHOP;
	else {
		flog_err(EC_ZEBRA_NHG_FIB_UPDATE,
			 "Context received for kernel nexthop update with incorrect OP code (%u)",
			 op);
		return -1;
	}

	return netlink_nexthop_msg_encode(cmd, ctx, buf, buflen, false);
}

enum netlink_msg_status
netlink_put_nexthop_update_msg(struct nl_batch *bth,
			       struct zebra_dplane_ctx *ctx)
{
	/* Nothing to do if the kernel doesn't support nexthop objects */
	if (!kernel_nexthops_supported())
		return FRR_NETLINK_SUCCESS;

	return netlink_batch_add_msg(bth, ctx, netlink_nexthop_msg_encoder,
				     false);
}

static ssize_t netlink_newroute_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_route_multipath_msg_encode(RTM_NEWROUTE, ctx, buf,
						  buflen, false, false, false);
}

static ssize_t netlink_delroute_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_route_multipath_msg_encode(RTM_DELROUTE, ctx, buf,
						  buflen, false, false, false);
}

enum netlink_msg_status
netlink_put_route_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	int cmd;
	const struct prefix *p = dplane_ctx_get_dest(ctx);

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_DELETE) {
		cmd = RTM_DELROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_INSTALL) {
		cmd = RTM_NEWROUTE;
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_UPDATE) {
		if (p->family == AF_INET || kernel_nexthops_supported() ||
		    zrouter.v6_rr_semantics) {
			/* Single 'replace' operation */

			/*
			 * With route replace semantics in place
			 * for v4 routes and the new route is a system
			 * route we do not install anything.
			 * The problem here is that the new system
			 * route should cause us to withdraw from
			 * the kernel the old non-system route
			 */
			if (RSYSTEM_ROUTE(dplane_ctx_get_type(ctx))
			    && !RSYSTEM_ROUTE(dplane_ctx_get_old_type(ctx)))
				return netlink_batch_add_msg(
					bth, ctx, netlink_delroute_msg_encoder,
					true);
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
			if (!RSYSTEM_ROUTE(dplane_ctx_get_old_type(ctx)))
				netlink_batch_add_msg(
					bth, ctx, netlink_delroute_msg_encoder,
					true);
		}

		cmd = RTM_NEWROUTE;
	} else
		return FRR_NETLINK_ERROR;

	if (dplane_ctx_get_safi(ctx) == SAFI_MULTICAST)
		return FRR_NETLINK_SUCCESS;

	if (RSYSTEM_ROUTE(dplane_ctx_get_type(ctx)))
		return FRR_NETLINK_SUCCESS;

	return netlink_batch_add_msg(bth, ctx,
				     cmd == RTM_NEWROUTE
					     ? netlink_newroute_msg_encoder
					     : netlink_delroute_msg_encoder,
				     false);
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
	struct nexthop nh = {.weight = 1};
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
		nh.vrf_id = ifp_lookup->vrf->vrf_id;
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
					 struct nh_grp *z_grp, int z_grp_size,
					 struct nhg_resilience *nhgr)
{
	uint16_t count = 0;
	/* linux/nexthop.h group struct */
	struct nexthop_grp *n_grp = NULL;

	n_grp = (struct nexthop_grp *)RTA_DATA(tb[NHA_GROUP]);
	count = (RTA_PAYLOAD(tb[NHA_GROUP]) / sizeof(*n_grp));

	if (!count || (count * sizeof(*n_grp)) != RTA_PAYLOAD(tb[NHA_GROUP])) {
		flog_warn(EC_ZEBRA_BAD_NHG_MESSAGE,
			  "Invalid nexthop group received from the kernel");
		return count;
	}

	for (int i = 0; ((i < count) && (i < z_grp_size)); i++) {
		z_grp[i].id = n_grp[i].id;
		z_grp[i].weight = n_grp[i].weight + 1;
	}

	memset(nhgr, 0, sizeof(*nhgr));
	if (tb[NHA_RES_GROUP]) {
		struct rtattr *tbn[NHA_RES_GROUP_MAX + 1];
		struct rtattr *rta;
		struct rtattr *res_group = tb[NHA_RES_GROUP];

		netlink_parse_rtattr_nested(tbn, NHA_RES_GROUP_MAX, res_group);

		if (tbn[NHA_RES_GROUP_BUCKETS]) {
			rta = tbn[NHA_RES_GROUP_BUCKETS];
			nhgr->buckets = *(uint16_t *)RTA_DATA(rta);
		}

		if (tbn[NHA_RES_GROUP_IDLE_TIMER]) {
			rta = tbn[NHA_RES_GROUP_IDLE_TIMER];
			nhgr->idle_timer = *(uint32_t *)RTA_DATA(rta);
		}

		if (tbn[NHA_RES_GROUP_UNBALANCED_TIMER]) {
			rta = tbn[NHA_RES_GROUP_UNBALANCED_TIMER];
			nhgr->unbalanced_timer = *(uint32_t *)RTA_DATA(rta);
		}

		if (tbn[NHA_RES_GROUP_UNBALANCED_TIME]) {
			rta = tbn[NHA_RES_GROUP_UNBALANCED_TIME];
			nhgr->unbalanced_time = *(uint64_t *)RTA_DATA(rta);
		}
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
	struct nexthop nh = {.weight = 1};
	struct nh_grp grp[MULTIPATH_NUM] = {};
	/* Count of nexthops in group array */
	uint16_t grp_count = 0;
	struct rtattr *tb[NHA_MAX + 1] = {};

	frrtrace(3, frr_zebra, netlink_nexthop_change, h, ns_id, startup);

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

	netlink_parse_rtattr_flags(tb, NHA_MAX, RTM_NHA(nhm), len,
				   NLA_F_NESTED);


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
		struct nhg_resilience nhgr = {};

		if (tb[NHA_GROUP]) {
			/**
			 * If this is a group message its only going to have
			 * an array of nexthop IDs associated with it
			 */
			grp_count = netlink_nexthop_process_group(
				tb, grp, array_size(grp), &nhgr);
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
					  type, startup, &nhgr))
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
				 &dp_info, 0, true);

	if (!ret)
		/* If we succesfully read in nexthop objects,
		 * this kernel must support them.
		 */
		supports_nh = true;
	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_NHG)
		zlog_debug("Nexthop objects %ssupported on this kernel",
			   supports_nh ? "" : "not ");

	zebra_router_set_supports_nhgs(supports_nh);

	return ret;
}


int kernel_neigh_update(int add, int ifindex, void *addr, char *lla, int llalen,
			ns_id_t ns_id, uint8_t family, bool permanent)
{
	return netlink_neigh_update(add ? RTM_NEWNEIGH : RTM_DELNEIGH, ifindex,
				    addr, lla, llalen, ns_id, family, permanent,
				    RTPROT_ZEBRA);
}

/**
 * netlink_neigh_update_msg_encode() - Common helper api for encoding
 * evpn neighbor update as netlink messages using dataplane context object.
 * Here, a neighbor refers to a bridge forwarding database entry for
 * either unicast forwarding or head-end replication or an IP neighbor
 * entry.
 * @ctx:		Dataplane context
 * @cmd:		Netlink command (RTM_NEWNEIGH or RTM_DELNEIGH)
 * @lla:		A pointer to neighbor cache link layer address
 * @llalen:		Length of the pointer to neighbor cache link layer
 * address
 * @ip:		A neighbor cache n/w layer destination address
 *			In the case of bridge FDB, this represnts the remote
 *			VTEP IP.
 * @replace_obj:	Whether NEW request should replace existing object or
 *			add to the end of the list
 * @family:		AF_* netlink family
 * @type:		RTN_* route type
 * @flags:		NTF_* flags
 * @state:		NUD_* states
 * @data:		data buffer pointer
 * @datalen:		total amount of data buffer space
 * @protocol:		protocol information
 *
 * Return:		0 when the msg doesn't fit entirely in the buffer
 *				otherwise the number of bytes written to buf.
 */
static ssize_t netlink_neigh_update_msg_encode(
	const struct zebra_dplane_ctx *ctx, int cmd, const void *lla,
	int llalen, const struct ipaddr *ip, bool replace_obj, uint8_t family,
	uint8_t type, uint8_t flags, uint16_t state, uint32_t nhg_id, bool nfy,
	uint8_t nfy_flags, bool ext, uint32_t ext_flags, void *data,
	size_t datalen, uint8_t protocol)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[];
	} *req = data;
	int ipa_len;
	enum dplane_op_e op;

	if (datalen < sizeof(*req))
		return 0;
	memset(req, 0, sizeof(*req));

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

	if (!nl_attr_put(&req->n, datalen, NDA_PROTOCOL, &protocol,
			 sizeof(protocol)))
		return 0;

	if (lla) {
		if (!nl_attr_put(&req->n, datalen, NDA_LLADDR, lla, llalen))
			return 0;
	}

	if (nfy) {
		struct rtattr *nest;

		nest = nl_attr_nest(&req->n, datalen,
				    NDA_FDB_EXT_ATTRS | NLA_F_NESTED);
		if (!nest)
			return 0;

		if (!nl_attr_put(&req->n, datalen, NFEA_ACTIVITY_NOTIFY,
				 &nfy_flags, sizeof(nfy_flags)))
			return 0;
		if (!nl_attr_put(&req->n, datalen, NFEA_DONT_REFRESH, NULL, 0))
			return 0;

		nl_attr_nest_end(&req->n, nest);
	}


	if (ext) {
		if (!nl_attr_put(&req->n, datalen, NDA_EXT_FLAGS, &ext_flags,
				 sizeof(ext_flags)))
			return 0;
	}

	if (nhg_id) {
		if (!nl_attr_put32(&req->n, datalen, NDA_NH_ID, nhg_id))
			return 0;
	} else {
		ipa_len =
			IS_IPADDR_V4(ip) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		if (!nl_attr_put(&req->n, datalen, NDA_DST, &ip->ip.addr,
				 ipa_len))
			return 0;
	}

	if (op == DPLANE_OP_MAC_INSTALL || op == DPLANE_OP_MAC_DELETE) {
		vlanid_t vid = dplane_ctx_mac_get_vlan(ctx);
		vni_t vni = dplane_ctx_mac_get_vni(ctx);

		if (vid > 0) {
			if (!nl_attr_put16(&req->n, datalen, NDA_VLAN, vid))
				return 0;
		}

		if (vni > 0) {
			if (!nl_attr_put32(&req->n, datalen, NDA_SRC_VNI, vni))
				return 0;
		}

		if (!nl_attr_put32(&req->n, datalen, NDA_MASTER,
				   dplane_ctx_mac_get_br_ifindex(ctx)))
			return 0;
	}

	if (op == DPLANE_OP_VTEP_ADD || op == DPLANE_OP_VTEP_DELETE) {
		vni_t vni = dplane_ctx_neigh_get_vni(ctx);

		if (vni > 0) {
			if (!nl_attr_put32(&req->n, datalen, NDA_SRC_VNI, vni))
				return 0;
		}
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Add remote VTEP to the flood list for this VxLAN interface (VNI). This
 * is done by adding an FDB entry with a MAC of 00:00:00:00:00:00.
 */
static ssize_t
netlink_vxlan_flood_update_ctx(const struct zebra_dplane_ctx *ctx, int cmd,
			       void *buf, size_t buflen)
{
	struct ethaddr dst_mac = {.octet = {0}};
	int proto = RTPROT_ZEBRA;

	if (dplane_ctx_get_type(ctx) != 0)
		proto = zebra2proto(dplane_ctx_get_type(ctx));

	return netlink_neigh_update_msg_encode(
		ctx, cmd, (const void *)&dst_mac, ETH_ALEN,
		dplane_ctx_neigh_get_ipaddr(ctx), false, PF_BRIDGE, 0, NTF_SELF,
		(NUD_NOARP | NUD_PERMANENT), 0 /*nhg*/, false /*nfy*/,
		0 /*nfy_flags*/, false /*ext*/, 0 /*ext_flags*/, buf, buflen,
		proto);
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
	char vid_buf[20];
	char dst_buf[30];
	bool sticky;
	bool local_inactive = false;
	bool dp_static = false;
	vni_t vni = 0;
	uint32_t nhg_id = 0;
	bool vni_mcast_grp = false;

	ndm = NLMSG_DATA(h);

	/* We only process macfdb notifications if EVPN is enabled */
	if (!is_evpn_enabled())
		return 0;

	/* Parse attributes and extract fields of interest. Do basic
	 * validation of the fields.
	 */
	netlink_parse_rtattr_flags(tb, NDA_MAX, NDA_RTA(ndm), len,
				   NLA_F_NESTED);

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

	if (tb[NDA_VLAN]) {
		vid_present = 1;
		vid = *(uint16_t *)RTA_DATA(tb[NDA_VLAN]);
		snprintf(vid_buf, sizeof(vid_buf), " VLAN %u", vid);
	}

	if (tb[NDA_DST]) {
		/* TODO: Only IPv4 supported now. */
		dst_present = 1;
		memcpy(&vtep_ip.s_addr, RTA_DATA(tb[NDA_DST]),
		       IPV4_MAX_BYTELEN);
		snprintfrr(dst_buf, sizeof(dst_buf), " dst %pI4",
			   &vtep_ip);
	} else
		memset(&vtep_ip, 0, sizeof(vtep_ip));

	if (tb[NDA_NH_ID])
		nhg_id = *(uint32_t *)RTA_DATA(tb[NDA_NH_ID]);

	if (ndm->ndm_state & NUD_STALE)
		local_inactive = true;

	if (tb[NDA_FDB_EXT_ATTRS]) {
		struct rtattr *attr = tb[NDA_FDB_EXT_ATTRS];
		struct rtattr *nfea_tb[NFEA_MAX + 1] = {0};

		netlink_parse_rtattr_nested(nfea_tb, NFEA_MAX, attr);
		if (nfea_tb[NFEA_ACTIVITY_NOTIFY]) {
			uint8_t nfy_flags;

			nfy_flags = *(uint8_t *)RTA_DATA(
				nfea_tb[NFEA_ACTIVITY_NOTIFY]);
			if (nfy_flags & FDB_NOTIFY_BIT)
				dp_static = true;
			if (nfy_flags & FDB_NOTIFY_INACTIVE_BIT)
				local_inactive = true;
		}
	}

	if (tb[NDA_SRC_VNI])
		vni = *(vni_t *)RTA_DATA(tb[NDA_SRC_VNI]);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Rx %s AF_BRIDGE IF %u%s st 0x%x fl 0x%x MAC %pEA%s nhg %d vni %d",
			nl_msg_type_to_str(h->nlmsg_type), ndm->ndm_ifindex,
			vid_present ? vid_buf : "", ndm->ndm_state,
			ndm->ndm_flags, &mac, dst_present ? dst_buf : "",
			nhg_id, vni);

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

	/* For per vni device, vni comes from device itself */
	if (IS_ZEBRA_IF_VXLAN(ifp) && IS_ZEBRA_VXLAN_IF_VNI(zif)) {
		struct zebra_vxlan_vni *vnip;

		vnip = zebra_vxlan_if_vni_find(zif, 0);
		vni = vnip->vni;
	}

	sticky = !!(ndm->ndm_flags & NTF_STICKY);

	if (filter_vlan && vid != filter_vlan) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("        Filtered due to filter vlan: %d",
				   filter_vlan);
		return 0;
	}

	/*
	 * Check if this is a mcast group update (svd case)
	 */
	vni_mcast_grp = is_mac_vni_mcast_group(&mac, vni, vtep_ip);

	/* If add or update, do accordingly if learnt on a "local" interface; if
	 * the notification is over VxLAN, this has to be related to
	 * multi-homing,
	 * so perform an implicit delete of any local entry (if it exists).
	 */
	if (h->nlmsg_type == RTM_NEWNEIGH) {
                /* Drop "permanent" entries. */
		if (!vni_mcast_grp && (ndm->ndm_state & NUD_PERMANENT)) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"        Dropping entry because of NUD_PERMANENT");
			return 0;
		}

		if (IS_ZEBRA_IF_VXLAN(ifp)) {
			if (!dst_present)
				return 0;

			if (vni_mcast_grp)
				return zebra_vxlan_if_vni_mcast_group_add_update(
					ifp, vni, &vtep_ip);

			return zebra_vxlan_dp_network_mac_add(
				ifp, br_if, &mac, vid, vni, nhg_id, sticky,
				!!(ndm->ndm_flags & NTF_EXT_LEARNED));
		}

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
		if (vni_mcast_grp)
			return zebra_vxlan_if_vni_mcast_group_del(ifp, vni,
								  &vtep_ip);

		if (is_zero_mac(&mac) && vni)
			return zebra_vxlan_check_readd_vtep(ifp, vni, vtep_ip);

		return 0;
	}

	if (IS_ZEBRA_IF_VXLAN(ifp))
		return 0;

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
		nl_attr_put32(&req.n, sizeof(req), IFLA_MASTER, master_ifindex);

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
				 &dp_info, 0, true);

	return ret;
}

/*
 * MAC forwarding database read using netlink interface. This is for a
 * specific bridge and matching specific access VLAN (if VLAN-aware bridge).
 */
int netlink_macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
				   struct interface *br_if, vlanid_t vid)
{
	struct zebra_if *br_zif;
	struct zebra_dplane_info dp_info;
	int ret = 0;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Save VLAN we're filtering on, if needed. */
	br_zif = (struct zebra_if *)br_if->info;
	if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif))
		filter_vlan = vid;

	/* Get bridge FDB table for specific bridge - we do the VLAN filtering.
	 */
	ret = netlink_request_macs(&zns->netlink_cmd, AF_BRIDGE, RTM_GETNEIGH,
				   br_if->ifindex);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 0, false);

	/* Reset VLAN filter. */
	filter_vlan = 0;
	return ret;
}


/* Request for MAC FDB for a specific MAC address in VLAN from the kernel */
static int netlink_request_specific_mac(struct zebra_ns *zns, int family,
					int type, struct interface *ifp,
					const struct ethaddr *mac, vlanid_t vid,
					vni_t vni, uint8_t flags)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req;
	struct zebra_if *zif;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_type = type;	/* RTM_GETNEIGH */
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.ndm.ndm_family = family;	/* AF_BRIDGE */
	req.ndm.ndm_flags = flags;
	/* req.ndm.ndm_state = NUD_REACHABLE; */

	nl_attr_put(&req.n, sizeof(req), NDA_LLADDR, mac, 6);

	zif = (struct zebra_if *)ifp->info;
	/* Is this a read on a VXLAN interface? */
	if (IS_ZEBRA_IF_VXLAN(ifp)) {
		nl_attr_put32(&req.n, sizeof(req), NDA_VNI, vni);
		/* TBD: Why is ifindex not filled in the non-vxlan case? */
		req.ndm.ndm_ifindex = ifp->ifindex;
	} else {
		if (IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(zif) && vid > 0)
			nl_attr_put16(&req.n, sizeof(req), NDA_VLAN, vid);
		nl_attr_put32(&req.n, sizeof(req), NDA_MASTER, ifp->ifindex);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Tx %s %s IF %s(%u) MAC %pEA vid %u vni %u",
			   nl_msg_type_to_str(type),
			   nl_family_to_str(req.ndm.ndm_family), ifp->name,
			   ifp->ifindex, mac, vid, vni);

	return netlink_request(&zns->netlink_cmd, &req);
}

int netlink_macfdb_read_specific_mac(struct zebra_ns *zns,
				     struct interface *br_if,
				     const struct ethaddr *mac, vlanid_t vid)
{
	int ret = 0;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get bridge FDB table for specific bridge - we do the VLAN filtering.
	 */
	ret = netlink_request_specific_mac(zns, AF_BRIDGE, RTM_GETNEIGH, br_if,
					   mac, vid, 0, 0);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 1, 0);

	return ret;
}

int netlink_macfdb_read_mcast_for_vni(struct zebra_ns *zns,
				      struct interface *ifp, vni_t vni)
{
	struct zebra_if *zif;
	struct ethaddr mac = {.octet = {0}};
	struct zebra_dplane_info dp_info;
	int ret = 0;

	zif = ifp->info;
	if (IS_ZEBRA_VXLAN_IF_VNI(zif))
		return 0;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get specific FDB entry for BUM handling, if any */
	ret = netlink_request_specific_mac(zns, AF_BRIDGE, RTM_GETNEIGH, ifp,
					   &mac, 0, vni, NTF_SELF);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_macfdb_table, &zns->netlink_cmd,
				 &dp_info, 1, false);

	return ret;
}

/*
 * Netlink-specific handler for MAC updates using dataplane context object.
 */
ssize_t netlink_macfdb_update_ctx(struct zebra_dplane_ctx *ctx, void *data,
				  size_t datalen)
{
	struct ipaddr vtep_ip;
	vlanid_t vid;
	ssize_t total;
	int cmd;
	uint8_t flags;
	uint16_t state;
	uint32_t nhg_id;
	uint32_t update_flags;
	bool nfy = false;
	uint8_t nfy_flags = 0;
	int proto = RTPROT_ZEBRA;

	if (dplane_ctx_get_type(ctx) != 0)
		proto = zebra2proto(dplane_ctx_get_type(ctx));

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
			nfy_flags |= FDB_NOTIFY_BIT;
			state |= NUD_NOARP;
		}

		if (update_flags & DPLANE_MAC_SET_INACTIVE)
			nfy_flags |= FDB_NOTIFY_INACTIVE_BIT;

		nfy = true;
	}

	nhg_id = dplane_ctx_mac_get_nhg_id(ctx);
	vtep_ip.ipaddr_v4 = *(dplane_ctx_mac_get_vtep_ip(ctx));
	SET_IPADDR_V4(&vtep_ip);

	if (IS_ZEBRA_DEBUG_KERNEL) {
		char vid_buf[20];
		const struct ethaddr *mac = dplane_ctx_mac_get_addr(ctx);

		vid = dplane_ctx_mac_get_vlan(ctx);
		if (vid > 0)
			snprintf(vid_buf, sizeof(vid_buf), " VLAN %u", vid);
		else
			vid_buf[0] = '\0';

		zlog_debug(
			"Tx %s family %s IF %s(%u)%s %sMAC %pEA dst %pIA nhg %u%s%s%s%s%s",
			nl_msg_type_to_str(cmd), nl_family_to_str(AF_BRIDGE),
			dplane_ctx_get_ifname(ctx), dplane_ctx_get_ifindex(ctx),
			vid_buf, dplane_ctx_mac_is_sticky(ctx) ? "sticky " : "",
			mac, &vtep_ip, nhg_id,
			(update_flags & DPLANE_MAC_REMOTE) ? " rem" : "",
			(update_flags & DPLANE_MAC_WAS_STATIC) ? " clr_sync"
							       : "",
			(update_flags & DPLANE_MAC_SET_STATIC) ? " static" : "",
			(update_flags & DPLANE_MAC_SET_INACTIVE) ? " inactive"
								 : "",
			nfy ? " nfy" : "");
	}

	total = netlink_neigh_update_msg_encode(
		ctx, cmd, (const void *)dplane_ctx_mac_get_addr(ctx), ETH_ALEN,
		&vtep_ip, true, AF_BRIDGE, 0, flags, state, nhg_id, nfy,
		nfy_flags, false /*ext*/, 0 /*ext_flags*/, data, datalen,
		proto);

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

static int netlink_nbr_entry_state_to_zclient(int nbr_state)
{
	/* an exact match is done between
	 * - netlink neighbor state values: NDM_XXX (see in linux/neighbour.h)
	 * - zclient neighbor state values: ZEBRA_NEIGH_STATE_XXX
	 *  (see in lib/zclient.h)
	 */
	return nbr_state;
}
static int netlink_ipneigh_change(struct nlmsghdr *h, int len, ns_id_t ns_id)
{
	struct ndmsg *ndm;
	struct interface *ifp;
	struct zebra_if *zif;
	struct rtattr *tb[NDA_MAX + 1];
	struct interface *link_if;
	struct ethaddr mac;
	struct ipaddr ip;
	char buf[ETHER_ADDR_STRLEN];
	int mac_present = 0;
	bool is_ext;
	bool is_router;
	bool local_inactive;
	uint32_t ext_flags = 0;
	bool dp_static = false;
	int l2_len = 0;
	int cmd;

	ndm = NLMSG_DATA(h);

	/* The interface should exist. */
	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id),
					ndm->ndm_ifindex);
	if (!ifp || !ifp->info)
		return 0;

	zif = (struct zebra_if *)ifp->info;

	/* Parse attributes and extract fields of interest. */
	netlink_parse_rtattr(tb, NDA_MAX, NDA_RTA(ndm), len);

	if (!tb[NDA_DST]) {
		zlog_debug("%s family %s IF %s(%u) vrf %s(%u) - no DST",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex, ifp->vrf->name, ifp->vrf->vrf_id);
		return 0;
	}

	memset(&ip, 0, sizeof(ip));
	ip.ipa_type = (ndm->ndm_family == AF_INET) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ip.ip.addr, RTA_DATA(tb[NDA_DST]), RTA_PAYLOAD(tb[NDA_DST]));

	/* if kernel deletes our rfc5549 neighbor entry, re-install it */
	if (h->nlmsg_type == RTM_DELNEIGH && (ndm->ndm_state & NUD_PERMANENT)) {
		netlink_handle_5549(ndm, zif, ifp, &ip, false);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry Received is a 5549 entry, finished");
		return 0;
	}

	/* if kernel marks our rfc5549 neighbor entry invalid, re-install it */
	if (h->nlmsg_type == RTM_NEWNEIGH && !(ndm->ndm_state & NUD_VALID))
		netlink_handle_5549(ndm, zif, ifp, &ip, true);

	/* we send link layer information to client:
	 * - nlmsg_type = RTM_DELNEIGH|NEWNEIGH|GETNEIGH
	 * - struct ipaddr ( for DEL and GET)
	 * - struct ethaddr mac; (for NEW)
	 */
	if (h->nlmsg_type == RTM_NEWNEIGH)
		cmd = ZEBRA_NEIGH_ADDED;
	else if (h->nlmsg_type == RTM_GETNEIGH)
		cmd = ZEBRA_NEIGH_GET;
	else if (h->nlmsg_type == RTM_DELNEIGH)
		cmd = ZEBRA_NEIGH_REMOVED;
	else {
		zlog_debug("%s(): unknown nlmsg type %u", __func__,
			   h->nlmsg_type);
		return 0;
	}
	if (tb[NDA_LLADDR]) {
		/* copy LLADDR information */
		l2_len = RTA_PAYLOAD(tb[NDA_LLADDR]);
	}

	union sockunion link_layer_ipv4;

	if (l2_len) {
		sockunion_family(&link_layer_ipv4) = AF_INET;
		memcpy((void *)sockunion_get_addr(&link_layer_ipv4),
		       RTA_DATA(tb[NDA_LLADDR]), l2_len);
	} else
		sockunion_family(&link_layer_ipv4) = AF_UNSPEC;
	zsend_neighbor_notify(cmd, ifp, &ip,
			      netlink_nbr_entry_state_to_zclient(ndm->ndm_state),
			      &link_layer_ipv4, l2_len);

	if (h->nlmsg_type == RTM_GETNEIGH)
		return 0;

	/* The neighbor is present on an SVI. From this, we locate the
	 * underlying
	 * bridge because we're only interested in neighbors on a VxLAN bridge.
	 * The bridge is located based on the nature of the SVI:
	 * (a) In the case of a VLAN-aware bridge, the SVI is a L3 VLAN
	 * interface
	 * and is linked to the bridge
	 * (b) In the case of a VLAN-unaware bridge, the SVI is the bridge
	 * interface
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
		link_if = NULL;
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"    Neighbor Entry received is not on a VLAN or a BRIDGE, ignoring");
	}

	memset(&mac, 0, sizeof(mac));
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
						ifp->vrf->name,
						ifp->vrf->vrf_id,
						(unsigned long)RTA_PAYLOAD(
							tb[NDA_LLADDR]));
				return 0;
			}

			mac_present = 1;
			memcpy(&mac, RTA_DATA(tb[NDA_LLADDR]), ETH_ALEN);
		}

		is_ext = !!(ndm->ndm_flags & NTF_EXT_LEARNED);
		is_router = !!(ndm->ndm_flags & NTF_ROUTER);

		if (tb[NDA_EXT_FLAGS]) {
			ext_flags = *(uint32_t *)RTA_DATA(tb[NDA_EXT_FLAGS]);
			if (ext_flags & NTF_E_MH_PEER_SYNC)
				dp_static = true;
		}

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"Rx %s family %s IF %s(%u) vrf %s(%u) IP %pIA MAC %s state 0x%x flags 0x%x ext_flags 0x%x",
				nl_msg_type_to_str(h->nlmsg_type),
				nl_family_to_str(ndm->ndm_family), ifp->name,
				ndm->ndm_ifindex, ifp->vrf->name,
				ifp->vrf->vrf_id, &ip,
				mac_present
					? prefix_mac2str(&mac, buf, sizeof(buf))
					: "",
				ndm->ndm_state, ndm->ndm_flags, ext_flags);

		/* If the neighbor state is valid for use, process as an add or
		 * update
		 * else process as a delete. Note that the delete handling may
		 * result
		 * in re-adding the neighbor if it is a valid "remote" neighbor.
		 */
		if (ndm->ndm_state & NUD_VALID) {
			if (zebra_evpn_mh_do_adv_reachable_neigh_only())
				local_inactive =
					!(ndm->ndm_state & NUD_LOCAL_ACTIVE);
			else
				/* If EVPN-MH is not enabled we treat STALE
				 * neighbors as locally-active and advertise
				 * them
				 */
				local_inactive = false;

			/* Add local neighbors to the l3 interface database */
			if (is_ext)
				zebra_neigh_del(ifp, &ip);
			else
				zebra_neigh_add(ifp, &ip, &mac);

			if (link_if)
				zebra_vxlan_handle_kernel_neigh_update(
					ifp, link_if, &ip, &mac, ndm->ndm_state,
					is_ext, is_router, local_inactive,
					dp_static);
			return 0;
		}


		zebra_neigh_del(ifp, &ip);
		if (link_if)
			zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);
		return 0;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Rx %s family %s IF %s(%u) vrf %s(%u) IP %pIA",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(ndm->ndm_family), ifp->name,
			   ndm->ndm_ifindex, ifp->vrf->name, ifp->vrf->vrf_id,
			   &ip);

	/* Process the delete - it may result in re-adding the neighbor if it is
	 * a valid "remote" neighbor.
	 */
	zebra_neigh_del(ifp, &ip);
	if (link_if)
		zebra_vxlan_handle_kernel_neigh_del(ifp, link_if, &ip);

	return 0;
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
		nl_attr_put32(&req.n, sizeof(req), NDA_IFINDEX, ifindex);

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
				 &dp_info, 0, true);

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
				 &dp_info, 0, false);

	return ret;
}

/*
 * Request for a specific IP in VLAN (SVI) device from IP Neighbor table,
 * read using netlink interface.
 */
static int netlink_request_specific_neigh_in_vlan(struct zebra_ns *zns,
						  int type,
						  const struct ipaddr *ip,
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

	nl_attr_put(&req.n, sizeof(req), NDA_DST, &ip->ip.addr, ipa_len);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: Tx %s family %s IF %u IP %pIA flags 0x%x",
			   __func__, nl_msg_type_to_str(type),
			   nl_family_to_str(req.ndm.ndm_family), ifindex, ip,
			   req.n.nlmsg_flags);

	return netlink_request(&zns->netlink_cmd, &req);
}

int netlink_neigh_read_specific_ip(const struct ipaddr *ip,
				   struct interface *vlan_if)
{
	int ret = 0;
	struct zebra_ns *zns;
	struct zebra_vrf *zvrf = vlan_if->vrf->info;
	struct zebra_dplane_info dp_info;

	zns = zvrf->zns;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: neigh request IF %s(%u) IP %pIA vrf %s(%u)",
			   __func__, vlan_if->name, vlan_if->ifindex, ip,
			   vlan_if->vrf->name, vlan_if->vrf->vrf_id);

	ret = netlink_request_specific_neigh_in_vlan(zns, RTM_GETNEIGH, ip,
					    vlan_if->ifindex);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_neigh_table, &zns->netlink_cmd,
				 &dp_info, 1, false);

	return ret;
}

int netlink_neigh_change(struct nlmsghdr *h, ns_id_t ns_id)
{
	int len;
	struct ndmsg *ndm;

	if (!(h->nlmsg_type == RTM_NEWNEIGH || h->nlmsg_type == RTM_DELNEIGH
	      || h->nlmsg_type == RTM_GETNEIGH))
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
static ssize_t netlink_neigh_update_ctx(const struct zebra_dplane_ctx *ctx,
					int cmd, void *buf, size_t buflen)
{
	const struct ipaddr *ip;
	const struct ethaddr *mac = NULL;
	const struct ipaddr *link_ip = NULL;
	const void *link_ptr = NULL;
	char buf2[ETHER_ADDR_STRLEN];

	int llalen;
	uint8_t flags;
	uint16_t state;
	uint8_t family;
	uint32_t update_flags;
	uint32_t ext_flags = 0;
	bool ext = false;
	int proto = RTPROT_ZEBRA;

	if (dplane_ctx_get_type(ctx) != 0)
		proto = zebra2proto(dplane_ctx_get_type(ctx));

	ip = dplane_ctx_neigh_get_ipaddr(ctx);

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_NEIGH_IP_INSTALL
	    || dplane_ctx_get_op(ctx) == DPLANE_OP_NEIGH_IP_DELETE) {
		link_ip = dplane_ctx_neigh_get_link_ip(ctx);
		llalen = IPADDRSZ(link_ip);
		link_ptr = (const void *)&(link_ip->ip.addr);
		ipaddr2str(link_ip, buf2, sizeof(buf2));
	} else {
		mac = dplane_ctx_neigh_get_mac(ctx);
		llalen = ETH_ALEN;
		link_ptr = (const void *)mac;
		if (is_zero_mac(mac))
			mac = NULL;
		if (mac)
			prefix_mac2str(mac, buf2, sizeof(buf2));
		else
			snprintf(buf2, sizeof(buf2), "null");
	}
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
	} else if (!(update_flags & DPLANE_NEIGH_NO_EXTENSION)) {
		ext = true;
		/* local neigh */
		if (update_flags & DPLANE_NEIGH_SET_STATIC)
			ext_flags |= NTF_E_MH_PEER_SYNC;
	}
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Tx %s family %s IF %s(%u) Neigh %pIA %s %s flags 0x%x state 0x%x %sext_flags 0x%x",
			nl_msg_type_to_str(cmd), nl_family_to_str(family),
			dplane_ctx_get_ifname(ctx), dplane_ctx_get_ifindex(ctx),
			ip, link_ip ? "Link" : "MAC", buf2, flags, state,
			ext ? "ext " : "", ext_flags);

	return netlink_neigh_update_msg_encode(
		ctx, cmd, link_ptr, llalen, ip, true, family, RTN_UNICAST,
		flags, state, 0 /*nhg*/, false /*nfy*/, 0 /*nfy_flags*/, ext,
		ext_flags, buf, buflen, proto);
}

static int netlink_neigh_table_update_ctx(const struct zebra_dplane_ctx *ctx,
					  void *data, size_t datalen)
{
	struct {
		struct nlmsghdr n;
		struct ndtmsg ndtm;
		char buf[];
	} *req = data;
	struct rtattr *nest;
	uint8_t family;
	ifindex_t idx;
	uint32_t val;

	if (datalen < sizeof(*req))
		return 0;
	memset(req, 0, sizeof(*req));
	family = dplane_ctx_neightable_get_family(ctx);
	idx = dplane_ctx_get_ifindex(ctx);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndtmsg));
	req->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;
	req->n.nlmsg_type = RTM_SETNEIGHTBL;
	req->ndtm.ndtm_family = family;

	nl_attr_put(&req->n, datalen, NDTA_NAME,
		    family == AF_INET ? "arp_cache" : "ndisc_cache", 10);
	nest = nl_attr_nest(&req->n, datalen, NDTA_PARMS);
	if (nest == NULL)
		return 0;
	if (!nl_attr_put(&req->n, datalen, NDTPA_IFINDEX, &idx, sizeof(idx)))
		return 0;
	val = dplane_ctx_neightable_get_app_probes(ctx);
	if (!nl_attr_put(&req->n, datalen, NDTPA_APP_PROBES, &val, sizeof(val)))
		return 0;
	val = dplane_ctx_neightable_get_mcast_probes(ctx);
	if (!nl_attr_put(&req->n, datalen, NDTPA_MCAST_PROBES, &val,
			 sizeof(val)))
		return 0;
	val = dplane_ctx_neightable_get_ucast_probes(ctx);
	if (!nl_attr_put(&req->n, datalen, NDTPA_UCAST_PROBES, &val,
			 sizeof(val)))
		return 0;
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_neigh_msg_encoder(struct zebra_dplane_ctx *ctx,
					 void *buf, size_t buflen)
{
	ssize_t ret = 0;
	enum dplane_op_e op;

	op = dplane_ctx_get_op(ctx);
	if (op == DPLANE_OP_NEIGH_INSTALL || op == DPLANE_OP_NEIGH_UPDATE ||
	    op == DPLANE_OP_NEIGH_DISCOVER || op == DPLANE_OP_NEIGH_IP_INSTALL)
		ret = netlink_neigh_update_ctx(ctx, RTM_NEWNEIGH, buf, buflen);
	else if (op == DPLANE_OP_NEIGH_DELETE || op == DPLANE_OP_NEIGH_IP_DELETE)
		ret = netlink_neigh_update_ctx(ctx, RTM_DELNEIGH, buf, buflen);
	else if (op == DPLANE_OP_VTEP_ADD)
		ret = netlink_vxlan_flood_update_ctx(ctx, RTM_NEWNEIGH, buf,
						     buflen);
	else if (op == DPLANE_OP_VTEP_DELETE)
		ret = netlink_vxlan_flood_update_ctx(ctx, RTM_DELNEIGH, buf,
						     buflen);
	else if (op == DPLANE_OP_NEIGH_TABLE_UPDATE)
		ret = netlink_neigh_table_update_ctx(ctx, buf, buflen);
	else
		ret = -1;

	return ret;
}

/*
 * Update MAC, using dataplane context object.
 */

enum netlink_msg_status netlink_put_mac_update_msg(struct nl_batch *bth,
						   struct zebra_dplane_ctx *ctx)
{
	return netlink_batch_add_msg(bth, ctx, netlink_macfdb_update_ctx,
				     false);
}

enum netlink_msg_status
netlink_put_neigh_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	return netlink_batch_add_msg(bth, ctx, netlink_neigh_msg_encoder,
				     false);
}

/*
 * MPLS label forwarding table change via netlink interface, using dataplane
 * context information.
 */
ssize_t netlink_mpls_multipath_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					  void *buf, size_t buflen)
{
	mpls_lse_t lse;
	const struct nhlfe_list_head *head;
	const struct zebra_nhlfe *nhlfe;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num;
	const char *routedesc;
	int route_type;
	struct prefix p = {0};
	struct nlsock *nl =
		kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[0];
	} *req = buf;

	if (buflen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	/*
	 * Count # nexthops so we can decide whether to use singlepath
	 * or multipath case.
	 */
	nexthop_num = 0;
	head = dplane_ctx_get_nhlfe_list(ctx);
	frr_each(nhlfe_list_const, head, nhlfe) {
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

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req->n.nlmsg_type = cmd;
	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->r.rtm_family = AF_MPLS;
	req->r.rtm_table = rt_table_main_id;
	req->r.rtm_dst_len = MPLS_LABEL_LEN_BITS;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;
	req->r.rtm_type = RTN_UNICAST;

	if (cmd == RTM_NEWROUTE) {
		/* We do a replace to handle update. */
		req->n.nlmsg_flags |= NLM_F_REPLACE;

		/* set the protocol value if installing */
		route_type = re_type_from_lsp_type(
			dplane_ctx_get_best_nhlfe(ctx)->type);
		req->r.rtm_protocol = zebra2proto(route_type);
	}

	/* Fill destination */
	lse = mpls_lse_encode(dplane_ctx_get_in_label(ctx), 0, 0, 1);
	if (!nl_attr_put(&req->n, buflen, RTA_DST, &lse, sizeof(mpls_lse_t)))
		return 0;

	/* Fill nexthops (paths) based on single-path or multipath. The paths
	 * chosen depend on the operation.
	 */
	if (nexthop_num == 1) {
		routedesc = "single-path";
		_netlink_mpls_debug(cmd, dplane_ctx_get_in_label(ctx),
				    routedesc);

		nexthop_num = 0;
		frr_each(nhlfe_list_const, head, nhlfe) {
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
				if (!_netlink_mpls_build_singlepath(
					    &p, routedesc, nhlfe, &req->n,
					    &req->r, buflen, cmd))
					return false;

				nexthop_num++;
				break;
			}
		}
	} else { /* Multipath case */
		struct rtattr *nest;
		const union g_addr *src1 = NULL;

		nest = nl_attr_nest(&req->n, buflen, RTA_MULTIPATH);
		if (!nest)
			return 0;

		routedesc = "multipath";
		_netlink_mpls_debug(cmd, dplane_ctx_get_in_label(ctx),
				    routedesc);

		nexthop_num = 0;
		frr_each(nhlfe_list_const, head, nhlfe) {
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
				if (!_netlink_mpls_build_multipath(
					    &p, routedesc, nhlfe, &req->n,
					    buflen, &req->r, &src1))
					return 0;
			}
		}

		/* Add the multipath */
		nl_attr_nest_end(&req->n, nest);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/****************************************************************************
* This code was developed in a branch that didn't have dplane APIs for
* MAC updates. Hence the use of the legacy style. It will be moved to
* the new dplane style pre-merge to master. XXX
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
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_INET;

	if (!nl_attr_put32(&req.n, sizeof(req), NHA_ID, nh_id))
		return -1;
	if (!nl_attr_put(&req.n, sizeof(req), NHA_FDB, NULL, 0))
		return -1;
	if (!nl_attr_put(&req.n, sizeof(req), NHA_GATEWAY,
			&vtep_ip, IPV4_MAX_BYTELEN))
		return -1;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		zlog_debug("Tx %s fdb-nh 0x%x %pI4",
			   nl_msg_type_to_str(cmd), nh_id, &vtep_ip);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    false);
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
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_UNSPEC;

	if (!nl_attr_put32(&req.n, sizeof(req), NHA_ID, nh_id))
		return -1;

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		zlog_debug("Tx %s fdb-nh 0x%x",
			   nl_msg_type_to_str(cmd), nh_id);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    false);
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
	zns = zvrf->zns;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nhmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);
	req.n.nlmsg_type = cmd;
	req.nhm.nh_family = AF_UNSPEC;

	if (!nl_attr_put32(&req.n, sizeof(req), NHA_ID, nhg_id))
		return -1;
	if (!nl_attr_put(&req.n, sizeof(req), NHA_FDB, NULL, 0))
		return -1;
	memset(&grp, 0, sizeof(grp));
	for (i = 0; i < nh_cnt; ++i) {
		grp[i].id = nh_ids[i].id;
		grp[i].weight = nh_ids[i].weight;
	}
	if (!nl_attr_put(&req.n, sizeof(req), NHA_GROUP,
			grp, nh_cnt * sizeof(struct nexthop_grp)))
		return -1;


	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		char vtep_str[ES_VTEP_LIST_STR_SZ];
		char nh_buf[16];

		vtep_str[0] = '\0';
		for (i = 0; i < nh_cnt; ++i) {
			snprintf(nh_buf, sizeof(nh_buf), "%u ",
					grp[i].id);
			strlcat(vtep_str, nh_buf, sizeof(vtep_str));
		}

		zlog_debug("Tx %s fdb-nhg 0x%x %s",
			   nl_msg_type_to_str(cmd), nhg_id, vtep_str);
	}

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    false);
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
