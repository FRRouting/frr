// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Code for encoding/decoding FPM messages that are in netlink format.
 *
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#include "log.h"
#include "rib.h"
#include "vty.h"
#include "prefix.h"

#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "nexthop.h"

#include "zebra/zebra_fpm_private.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/interface.h"

/*
 * af_addr_size
 *
 * The size of an address in a given address family.
 */
static size_t af_addr_size(uint8_t af)
{
	switch (af) {

	case AF_INET:
		return 4;
	case AF_INET6:
		return 16;
	default:
		assert(0);
		return 16;
	}
}

/*
 * We plan to use RTA_ENCAP_TYPE attribute for VxLAN encap as well.
 * Currently, values 0 to 8 for this attribute are used by lwtunnel_encap_types
 * So, we cannot use these values for VxLAN encap.
 */
enum fpm_nh_encap_type_t {
	FPM_NH_ENCAP_NONE = 0,
	FPM_NH_ENCAP_VXLAN = 100,
	FPM_NH_ENCAP_MAX,
};

/*
 * fpm_nh_encap_type_to_str
 */
static const char *fpm_nh_encap_type_to_str(enum fpm_nh_encap_type_t encap_type)
{
	switch (encap_type) {
	case FPM_NH_ENCAP_NONE:
		return "none";

	case FPM_NH_ENCAP_VXLAN:
		return "VxLAN";

	case FPM_NH_ENCAP_MAX:
		return "invalid";
	}

	return "invalid";
}

struct vxlan_encap_info_t {
	vni_t vni;
};

enum vxlan_encap_info_type_t {
	VXLAN_VNI = 0,
};

struct fpm_nh_encap_info_t {
	enum fpm_nh_encap_type_t encap_type;
	union {
		struct vxlan_encap_info_t vxlan_encap;
	};
};

/*
 * netlink_nh_info
 *
 * Holds information about a single nexthop for netlink. These info
 * structures are transient and may contain pointers into rib
 * data structures for convenience.
 */
struct netlink_nh_info {
	/* Weight of the nexthop ( for unequal cost ECMP ) */
	uint8_t weight;
	uint32_t if_index;
	union g_addr *gateway;

	/*
	 * Information from the struct nexthop from which this nh was
	 * derived. For debug purposes only.
	 */
	int recursive;
	enum nexthop_types_t type;
	struct fpm_nh_encap_info_t encap_info;
};

/*
 * netlink_route_info
 *
 * A structure for holding information for a netlink route message.
 */
struct netlink_route_info {
	uint32_t nlmsg_pid;
	uint16_t nlmsg_type;
	uint8_t rtm_type;
	uint32_t rtm_table;
	uint8_t rtm_protocol;
	uint8_t af;
	struct prefix *prefix;
	uint32_t *metric;
	unsigned int num_nhs;

	/*
	 * Nexthop structures
	 */
	struct netlink_nh_info nhs[MULTIPATH_NUM];
	union g_addr *pref_src;
};

/*
 * netlink_route_info_add_nh
 *
 * Add information about the given nexthop to the given route info
 * structure.
 *
 * Returns true if a nexthop was added, false otherwise.
 */
static int netlink_route_info_add_nh(struct netlink_route_info *ri,
				     struct nexthop *nexthop,
				     struct route_entry *re)
{
	struct netlink_nh_info nhi;
	union g_addr *src;
	struct zebra_vrf *zvrf = NULL;
	struct interface *ifp = NULL, *link_if = NULL;
	struct zebra_if *zif = NULL;
	vni_t vni = 0;

	memset(&nhi, 0, sizeof(nhi));
	src = NULL;

	if (ri->num_nhs >= (int)array_size(ri->nhs))
		return 0;

	nhi.recursive = nexthop->rparent ? 1 : 0;
	nhi.type = nexthop->type;
	nhi.if_index = nexthop->ifindex;
	nhi.weight = nexthop->weight;

	if (nexthop->type == NEXTHOP_TYPE_IPV4
	    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
		nhi.gateway = &nexthop->gate;
		if (nexthop->src.ipv4.s_addr != INADDR_ANY)
			src = &nexthop->src;
	}

	if (nexthop->type == NEXTHOP_TYPE_IPV6
	    || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
		/* Special handling for IPv4 route with IPv6 Link Local next hop
		 */
		if (ri->af == AF_INET)
			nhi.gateway = &ipv4ll_gateway;
		else
			nhi.gateway = &nexthop->gate;
	}

	if (nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		if (nexthop->src.ipv4.s_addr != INADDR_ANY)
			src = &nexthop->src;
	}

	if (!nhi.gateway && nhi.if_index == 0)
		return 0;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_EVPN)) {
		nhi.encap_info.encap_type = FPM_NH_ENCAP_VXLAN;

		/* Extract VNI id for the nexthop SVI interface */
		zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
		if (zvrf) {
			ifp = if_lookup_by_index_per_ns(zvrf->zns,
							nexthop->ifindex);
			if (ifp) {
				zif = (struct zebra_if *)ifp->info;
				if (zif) {
					if (IS_ZEBRA_IF_BRIDGE(ifp))
						link_if = ifp;
					else if (IS_ZEBRA_IF_VLAN(ifp))
						link_if =
						if_lookup_by_index_per_ns(
							zvrf->zns,
							zif->link_ifindex);
					if (link_if)
						vni = vni_id_from_svi(ifp,
								      link_if);
				}
			}
		}

		nhi.encap_info.vxlan_encap.vni = vni;
	}

	/*
	 * We have a valid nhi. Copy the structure over to the route_info.
	 */
	ri->nhs[ri->num_nhs] = nhi;
	ri->num_nhs++;

	if (src && !ri->pref_src)
		ri->pref_src = src;

	return 1;
}

/*
 * netlink_proto_from_route_type
 */
static uint8_t netlink_proto_from_route_type(int type)
{
	return zebra2proto(type);
}

/*
 * netlink_route_info_fill
 *
 * Fill out the route information object from the given route.
 *
 * Returns true on success and false on failure.
 */
static int netlink_route_info_fill(struct netlink_route_info *ri, int cmd,
				   rib_dest_t *dest, struct route_entry *re)
{
	struct nexthop *nexthop;

	memset(ri, 0, sizeof(*ri));

	ri->prefix = rib_dest_prefix(dest);
	ri->af = rib_dest_af(dest);

	ri->nlmsg_pid = pid;

	ri->nlmsg_type = cmd;
	ri->rtm_protocol = RTPROT_UNSPEC;

	/*
	 * An RTM_DELROUTE need not be accompanied by any nexthops,
	 * particularly in our communication with the FPM.
	 */
	if (cmd == RTM_DELROUTE && !re)
		return 1;

	if (!re) {
		zfpm_debug("%s: Expected non-NULL re pointer", __func__);
		return 0;
	}

	ri->rtm_table = re->table;

	ri->rtm_protocol = netlink_proto_from_route_type(re->type);
	ri->rtm_type = RTN_UNICAST;
	ri->metric = &re->metric;

	for (ALL_NEXTHOPS(re->nhe->nhg, nexthop)) {
		if (ri->num_nhs >= zrouter.multipath_num)
			break;

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
			continue;

		if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
			switch (nexthop->bh_type) {
			case BLACKHOLE_ADMINPROHIB:
				ri->rtm_type = RTN_PROHIBIT;
				break;
			case BLACKHOLE_REJECT:
				ri->rtm_type = RTN_UNREACHABLE;
				break;
			case BLACKHOLE_NULL:
			case BLACKHOLE_UNSPEC:
				ri->rtm_type = RTN_BLACKHOLE;
				break;
			}
		}

		if ((cmd == RTM_NEWROUTE
		     && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		    || (cmd == RTM_DELROUTE
			&& CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))) {
			netlink_route_info_add_nh(ri, nexthop, re);
		}
	}

	if (ri->num_nhs == 0) {
		switch (ri->rtm_type) {
		case RTN_PROHIBIT:
		case RTN_UNREACHABLE:
		case RTN_BLACKHOLE:
			break;
		default:
			/* If there is no useful nexthop then return. */
			zfpm_debug(
				"netlink_encode_route(): No useful nexthop.");
			return 0;
		}
	}

	return 1;
}

/*
 * netlink_route_info_encode
 *
 * Returns the number of bytes written to the buffer. 0 or a negative
 * value indicates an error.
 */
static int netlink_route_info_encode(struct netlink_route_info *ri,
				     char *in_buf, size_t in_buf_len)
{
	size_t bytelen;
	unsigned int nexthop_num = 0;
	size_t buf_offset;
	struct netlink_nh_info *nhi;
	enum fpm_nh_encap_type_t encap;
	struct rtattr *nest, *inner_nest;
	struct rtnexthop *rtnh;
	struct vxlan_encap_info_t *vxlan;
	struct in6_addr ipv6;

	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1];
	} * req;

	req = (void *)in_buf;

	buf_offset = ((char *)req->buf) - ((char *)req);

	if (in_buf_len < buf_offset) {
		assert(0);
		return 0;
	}

	memset(req, 0, buf_offset);

	bytelen = af_addr_size(ri->af);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req->n.nlmsg_pid = ri->nlmsg_pid;
	req->n.nlmsg_type = ri->nlmsg_type;
	req->r.rtm_family = ri->af;

	/*
	 * rtm_table field is a uchar field which can accommodate table_id less
	 * than 256.
	 * To support table id greater than 255, if the table_id is greater than
	 * 255, set rtm_table to RT_TABLE_UNSPEC and add RTA_TABLE attribute
	 * with 32 bit value as the table_id.
	 */
	if (ri->rtm_table < 256)
		req->r.rtm_table = ri->rtm_table;
	else {
		req->r.rtm_table = RT_TABLE_UNSPEC;
		nl_attr_put32(&req->n, in_buf_len, RTA_TABLE, ri->rtm_table);
	}

	req->r.rtm_dst_len = ri->prefix->prefixlen;
	req->r.rtm_protocol = ri->rtm_protocol;
	req->r.rtm_scope = RT_SCOPE_UNIVERSE;

	nl_attr_put(&req->n, in_buf_len, RTA_DST, &ri->prefix->u.prefix,
		    bytelen);

	req->r.rtm_type = ri->rtm_type;

	/* Metric. */
	if (ri->metric)
		nl_attr_put32(&req->n, in_buf_len, RTA_PRIORITY, *ri->metric);

	if (ri->num_nhs == 0)
		goto done;

	if (ri->num_nhs == 1) {
		nhi = &ri->nhs[0];

		if (nhi->gateway) {
			if (nhi->type == NEXTHOP_TYPE_IPV4_IFINDEX
			    && ri->af == AF_INET6) {
				ipv4_to_ipv4_mapped_ipv6(&ipv6,
							 nhi->gateway->ipv4);
				nl_attr_put(&req->n, in_buf_len, RTA_GATEWAY,
					    &ipv6, bytelen);
			} else
				nl_attr_put(&req->n, in_buf_len, RTA_GATEWAY,
					    nhi->gateway, bytelen);
		}

		if (nhi->if_index) {
			nl_attr_put32(&req->n, in_buf_len, RTA_OIF,
				      nhi->if_index);
		}

		encap = nhi->encap_info.encap_type;
		switch (encap) {
		case FPM_NH_ENCAP_NONE:
		case FPM_NH_ENCAP_MAX:
			break;
		case FPM_NH_ENCAP_VXLAN:
			nl_attr_put16(&req->n, in_buf_len, RTA_ENCAP_TYPE,
				      encap);
			vxlan = &nhi->encap_info.vxlan_encap;
			nest = nl_attr_nest(&req->n, in_buf_len, RTA_ENCAP);
			nl_attr_put32(&req->n, in_buf_len, VXLAN_VNI,
				      vxlan->vni);
			nl_attr_nest_end(&req->n, nest);
			break;
		}

		goto done;
	}

	/*
	 * Multipath case.
	 */
	nest = nl_attr_nest(&req->n, in_buf_len, RTA_MULTIPATH);

	for (nexthop_num = 0; nexthop_num < ri->num_nhs; nexthop_num++) {
		rtnh = nl_attr_rtnh(&req->n, in_buf_len);
		nhi = &ri->nhs[nexthop_num];

		if (nhi->gateway)
			nl_attr_put(&req->n, in_buf_len, RTA_GATEWAY,
				    nhi->gateway, bytelen);

		if (nhi->if_index) {
			rtnh->rtnh_ifindex = nhi->if_index;
		}

		rtnh->rtnh_hops = nhi->weight;

		encap = nhi->encap_info.encap_type;
		switch (encap) {
		case FPM_NH_ENCAP_NONE:
		case FPM_NH_ENCAP_MAX:
			break;
		case FPM_NH_ENCAP_VXLAN:
			nl_attr_put16(&req->n, in_buf_len, RTA_ENCAP_TYPE,
				      encap);
			vxlan = &nhi->encap_info.vxlan_encap;
			inner_nest =
				nl_attr_nest(&req->n, in_buf_len, RTA_ENCAP);
			nl_attr_put32(&req->n, in_buf_len, VXLAN_VNI,
				      vxlan->vni);
			nl_attr_nest_end(&req->n, inner_nest);
			break;
		}

		nl_attr_rtnh_end(&req->n, rtnh);
	}

	nl_attr_nest_end(&req->n, nest);
	assert(nest->rta_len > RTA_LENGTH(0));

done:

	if (ri->pref_src) {
		nl_attr_put(&req->n, in_buf_len, RTA_PREFSRC, ri->pref_src,
			    bytelen);
	}

	assert(req->n.nlmsg_len < in_buf_len);
	return req->n.nlmsg_len;
}

/*
 * zfpm_log_route_info
 *
 * Helper function to log the information in a route_info structure.
 */
static void zfpm_log_route_info(struct netlink_route_info *ri,
				const char *label)
{
	struct netlink_nh_info *nhi;
	unsigned int i;
	char buf[PREFIX_STRLEN];

	zfpm_debug("%s : %s %pFX, Proto: %s, Metric: %u", label,
		   nl_msg_type_to_str(ri->nlmsg_type), ri->prefix,
		   nl_rtproto_to_str(ri->rtm_protocol),
		   ri->metric ? *ri->metric : 0);

	for (i = 0; i < ri->num_nhs; i++) {
		nhi = &ri->nhs[i];

		if (nhi->gateway) {
			if (ri->af == AF_INET)
				inet_ntop(AF_INET, nhi->gateway, buf,
					  sizeof(buf));
			else
				inet_ntop(AF_INET6, nhi->gateway, buf,
					  sizeof(buf));
		} else
			strlcpy(buf, "none", sizeof(buf));

		zfpm_debug("  Intf: %u, Gateway: %s, Recursive: %s, Type: %s, Encap type: %s",
			   nhi->if_index, buf, nhi->recursive ? "yes" : "no",
			   nexthop_type_to_str(nhi->type),
			   fpm_nh_encap_type_to_str(nhi->encap_info.encap_type)
			   );
	}
}

/*
 * zfpm_netlink_encode_route
 *
 * Create a netlink message corresponding to the given route in the
 * given buffer space.
 *
 * Returns the number of bytes written to the buffer. 0 or a negative
 * value indicates an error.
 */
int zfpm_netlink_encode_route(int cmd, rib_dest_t *dest, struct route_entry *re,
			      char *in_buf, size_t in_buf_len)
{
	struct netlink_route_info ri_space, *ri;

	ri = &ri_space;

	if (!netlink_route_info_fill(ri, cmd, dest, re))
		return 0;

	zfpm_log_route_info(ri, __func__);

	return netlink_route_info_encode(ri, in_buf, in_buf_len);
}

/*
 * zfpm_netlink_encode_mac
 *
 * Create a netlink message corresponding to the given MAC.
 *
 * Returns the number of bytes written to the buffer. 0 or a negative
 * value indicates an error.
 */
int zfpm_netlink_encode_mac(struct fpm_mac_info_t *mac, char *in_buf,
			    size_t in_buf_len)
{
	size_t buf_offset;

	struct macmsg {
		struct nlmsghdr hdr;
		struct ndmsg ndm;
		char buf[0];
	} *req;
	req = (void *)in_buf;

	buf_offset = offsetof(struct macmsg, buf);
	if (in_buf_len < buf_offset)
		return 0;
	memset(req, 0, buf_offset);

	/* Construct nlmsg header */
	req->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req->hdr.nlmsg_type = CHECK_FLAG(mac->fpm_flags, ZEBRA_MAC_DELETE_FPM) ?
				RTM_DELNEIGH : RTM_NEWNEIGH;
	req->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (req->hdr.nlmsg_type == RTM_NEWNEIGH)
		req->hdr.nlmsg_flags |= (NLM_F_CREATE | NLM_F_REPLACE);

	/* Construct ndmsg */
	req->ndm.ndm_family = AF_BRIDGE;
	req->ndm.ndm_ifindex = mac->vxlan_if;

	req->ndm.ndm_state = NUD_REACHABLE;
	req->ndm.ndm_flags |= NTF_SELF | NTF_MASTER;
	if (CHECK_FLAG(mac->zebra_flags,
		(ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW)))
		req->ndm.ndm_state |= NUD_NOARP;
	else
		req->ndm.ndm_flags |= NTF_EXT_LEARNED;

	/* Add attributes */
	nl_attr_put(&req->hdr, in_buf_len, NDA_LLADDR, &mac->macaddr, 6);
	nl_attr_put(&req->hdr, in_buf_len, NDA_DST, &mac->r_vtep_ip, 4);
	nl_attr_put32(&req->hdr, in_buf_len, NDA_MASTER, mac->svi_if);
	nl_attr_put32(&req->hdr, in_buf_len, NDA_VNI, mac->vni);

	assert(req->hdr.nlmsg_len < in_buf_len);

	zfpm_debug("Tx %s family %s ifindex %u MAC %pEA DEST %pI4",
		   nl_msg_type_to_str(req->hdr.nlmsg_type),
		   nl_family_to_str(req->ndm.ndm_family), req->ndm.ndm_ifindex,
		   &mac->macaddr, &mac->r_vtep_ip);

	return req->hdr.nlmsg_len;
}

#endif /* HAVE_NETLINK */
