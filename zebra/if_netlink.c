// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface looking up by netlink.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H
#define _LINUX_IF_H
#define _LINUX_IP_H

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <linux/if_bridge.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "rib.h"
#include "frrevent.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "vrf_int.h"
#include "mpls.h"
#include "lib_errors.h"

#include "vty.h"
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
#include "zebra/if_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_l2.h"
#include "zebra/netconf_netlink.h"
#include "zebra/zebra_trace.h"

extern struct zebra_privs_t zserv_privs;

/* Utility function to parse hardware link-layer address and update ifp */
static void netlink_interface_update_hw_addr(struct rtattr **tb,
					     struct zebra_dplane_ctx *ctx)
{
	if (tb[IFLA_ADDRESS]) {
		int hw_addr_len;

		hw_addr_len = RTA_PAYLOAD(tb[IFLA_ADDRESS]);

		if (hw_addr_len > INTERFACE_HWADDR_MAX)
			zlog_warn("Hardware address is too large: %d",
				  hw_addr_len);
		else
			dplane_ctx_set_ifp_hw_addr(ctx, hw_addr_len,
						   RTA_DATA(tb[IFLA_ADDRESS]));
	}
}

static enum zebra_link_type netlink_to_zebra_link_type(unsigned int hwt)
{
	switch (hwt) {
	case ARPHRD_ETHER:
		return ZEBRA_LLT_ETHER;
	case ARPHRD_EETHER:
		return ZEBRA_LLT_EETHER;
	case ARPHRD_AX25:
		return ZEBRA_LLT_AX25;
	case ARPHRD_PRONET:
		return ZEBRA_LLT_PRONET;
	case ARPHRD_IEEE802:
		return ZEBRA_LLT_IEEE802;
	case ARPHRD_ARCNET:
		return ZEBRA_LLT_ARCNET;
	case ARPHRD_APPLETLK:
		return ZEBRA_LLT_APPLETLK;
	case ARPHRD_DLCI:
		return ZEBRA_LLT_DLCI;
	case ARPHRD_ATM:
		return ZEBRA_LLT_ATM;
	case ARPHRD_METRICOM:
		return ZEBRA_LLT_METRICOM;
	case ARPHRD_IEEE1394:
		return ZEBRA_LLT_IEEE1394;
	case ARPHRD_EUI64:
		return ZEBRA_LLT_EUI64;
	case ARPHRD_INFINIBAND:
		return ZEBRA_LLT_INFINIBAND;
	case ARPHRD_SLIP:
		return ZEBRA_LLT_SLIP;
	case ARPHRD_CSLIP:
		return ZEBRA_LLT_CSLIP;
	case ARPHRD_SLIP6:
		return ZEBRA_LLT_SLIP6;
	case ARPHRD_CSLIP6:
		return ZEBRA_LLT_CSLIP6;
	case ARPHRD_RSRVD:
		return ZEBRA_LLT_RSRVD;
	case ARPHRD_ADAPT:
		return ZEBRA_LLT_ADAPT;
	case ARPHRD_ROSE:
		return ZEBRA_LLT_ROSE;
	case ARPHRD_X25:
		return ZEBRA_LLT_X25;
	case ARPHRD_PPP:
		return ZEBRA_LLT_PPP;
	case ARPHRD_CISCO:
		return ZEBRA_LLT_CHDLC;
	case ARPHRD_LAPB:
		return ZEBRA_LLT_LAPB;
	case ARPHRD_RAWHDLC:
		return ZEBRA_LLT_RAWHDLC;
	case ARPHRD_TUNNEL:
		return ZEBRA_LLT_IPIP;
	case ARPHRD_TUNNEL6:
		return ZEBRA_LLT_IPIP6;
	case ARPHRD_FRAD:
		return ZEBRA_LLT_FRAD;
	case ARPHRD_SKIP:
		return ZEBRA_LLT_SKIP;
	case ARPHRD_LOOPBACK:
		return ZEBRA_LLT_LOOPBACK;
	case ARPHRD_LOCALTLK:
		return ZEBRA_LLT_LOCALTLK;
	case ARPHRD_FDDI:
		return ZEBRA_LLT_FDDI;
	case ARPHRD_SIT:
		return ZEBRA_LLT_SIT;
	case ARPHRD_IPDDP:
		return ZEBRA_LLT_IPDDP;
	case ARPHRD_IPGRE:
		return ZEBRA_LLT_IPGRE;
	case ARPHRD_PIMREG:
		return ZEBRA_LLT_PIMREG;
	case ARPHRD_HIPPI:
		return ZEBRA_LLT_HIPPI;
	case ARPHRD_ECONET:
		return ZEBRA_LLT_ECONET;
	case ARPHRD_IRDA:
		return ZEBRA_LLT_IRDA;
	case ARPHRD_FCPP:
		return ZEBRA_LLT_FCPP;
	case ARPHRD_FCAL:
		return ZEBRA_LLT_FCAL;
	case ARPHRD_FCPL:
		return ZEBRA_LLT_FCPL;
	case ARPHRD_FCFABRIC:
		return ZEBRA_LLT_FCFABRIC;
	case ARPHRD_IEEE802_TR:
		return ZEBRA_LLT_IEEE802_TR;
	case ARPHRD_IEEE80211:
		return ZEBRA_LLT_IEEE80211;
#ifdef ARPHRD_IEEE802154
	case ARPHRD_IEEE802154:
		return ZEBRA_LLT_IEEE802154;
#endif
#ifdef ARPHRD_IP6GRE
	case ARPHRD_IP6GRE:
		return ZEBRA_LLT_IP6GRE;
#endif
#ifdef ARPHRD_IEEE802154_PHY
	case ARPHRD_IEEE802154_PHY:
		return ZEBRA_LLT_IEEE802154_PHY;
#endif

	default:
		return ZEBRA_LLT_UNKNOWN;
	}
}

static void netlink_determine_zebra_iftype(const char *kind,
					   enum zebra_iftype *zif_type)
{
	*zif_type = ZEBRA_IF_OTHER;

	if (!kind)
		return;

	if (strcmp(kind, "vrf") == 0)
		*zif_type = ZEBRA_IF_VRF;
	else if (strcmp(kind, "bridge") == 0)
		*zif_type = ZEBRA_IF_BRIDGE;
	else if (strcmp(kind, "vlan") == 0)
		*zif_type = ZEBRA_IF_VLAN;
	else if (strcmp(kind, "vxlan") == 0)
		*zif_type = ZEBRA_IF_VXLAN;
	else if (strcmp(kind, "macvlan") == 0)
		*zif_type = ZEBRA_IF_MACVLAN;
	else if (strcmp(kind, "veth") == 0)
		*zif_type = ZEBRA_IF_VETH;
	else if (strcmp(kind, "bond") == 0)
		*zif_type = ZEBRA_IF_BOND;
	else if (strcmp(kind, "team") == 0)
		*zif_type = ZEBRA_IF_BOND;
	else if (strcmp(kind, "gre") == 0)
		*zif_type = ZEBRA_IF_GRE;
}

static void netlink_vrf_change(struct nlmsghdr *h, struct rtattr *tb,
			       uint32_t ns_id, const char *name,
			       struct zebra_dplane_ctx *ctx)
{
	struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
	struct rtattr *attr[IFLA_VRF_MAX + 1];

	netlink_parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

	if (!linkinfo[IFLA_INFO_DATA]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: IFLA_INFO_DATA missing from VRF message: %s",
				__func__, name);
		return;
	}

	netlink_parse_rtattr_nested(attr, IFLA_VRF_MAX,
				    linkinfo[IFLA_INFO_DATA]);
	if (!attr[IFLA_VRF_TABLE]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: IFLA_VRF_TABLE missing from VRF message: %s",
				__func__, name);
		return;
	}

	dplane_ctx_set_ifp_table_id(
		ctx, *(uint32_t *)RTA_DATA(attr[IFLA_VRF_TABLE]));
}

static uint32_t get_iflink_speed(struct interface *interface, int *error)
{
	struct ifreq ifdata;
	struct ethtool_cmd ecmd;
	int sd;
	int rc;
	const char *ifname = interface->name;
	uint32_t ret;

	if (error)
		*error = 0;
	/* initialize struct */
	memset(&ifdata, 0, sizeof(ifdata));

	/* set interface name */
	strlcpy(ifdata.ifr_name, ifname, sizeof(ifdata.ifr_name));

	/* initialize ethtool interface */
	memset(&ecmd, 0, sizeof(ecmd));
	ecmd.cmd = ETHTOOL_GSET; /* ETHTOOL_GLINK */
	ifdata.ifr_data = (caddr_t)&ecmd;

	/* use ioctl to get speed of an interface */
	frr_with_privs(&zserv_privs) {
		sd = vrf_socket(PF_INET, SOCK_DGRAM, IPPROTO_IP,
				interface->vrf->vrf_id, NULL);
		if (sd < 0) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("Failure to read interface %s speed: %d %s",
					   ifname, errno, safe_strerror(errno));
			/* no vrf socket creation may probably mean vrf issue */
			if (error)
				*error = INTERFACE_SPEED_ERROR_READ;
			return 0;
		}
		/* Get the current link state for the interface */
		rc = vrf_ioctl(interface->vrf->vrf_id, sd, SIOCETHTOOL,
			       (char *)&ifdata);
	}
	if (rc < 0) {
		if (errno != EOPNOTSUPP && IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IOCTL failure to read interface %s speed: %d %s",
				ifname, errno, safe_strerror(errno));
		/* no device means interface unreachable */
		if (errno == ENODEV && error)
			*error = INTERFACE_SPEED_ERROR_READ;
		ecmd.speed_hi = 0;
		ecmd.speed = 0;
	}

	close(sd);

	ret = ((uint32_t)ecmd.speed_hi << 16) | ecmd.speed;
	if (ret == UINT32_MAX) {
		if (error)
			*error = INTERFACE_SPEED_ERROR_UNKNOWN;
		ret = 0;
	}
	return ret;
}

uint32_t kernel_get_speed(struct interface *ifp, int *error)
{
	return get_iflink_speed(ifp, error);
}

static ssize_t
netlink_gre_set_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
			    size_t buflen)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[];
	} *req = buf;
	uint32_t link_idx;
	unsigned int mtu;
	struct rtattr *rta_info, *rta_data;
	const struct zebra_l2info_gre *gre_info;

	if (buflen < sizeof(*req))
		return 0;
	memset(req, 0, sizeof(*req));

	req->n.nlmsg_type =  RTM_NEWLINK;
	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;

	req->ifi.ifi_index = dplane_ctx_get_ifindex(ctx);

	gre_info = dplane_ctx_gre_get_info(ctx);
	if (!gre_info)
		return 0;

	req->ifi.ifi_change = 0xFFFFFFFF;
	link_idx = dplane_ctx_gre_get_link_ifindex(ctx);
	mtu = dplane_ctx_gre_get_mtu(ctx);

	if (mtu && !nl_attr_put32(&req->n, buflen, IFLA_MTU, mtu))
		return 0;

	rta_info = nl_attr_nest(&req->n, buflen, IFLA_LINKINFO);
	if (!rta_info)
		return 0;

	if (!nl_attr_put(&req->n, buflen, IFLA_INFO_KIND, "gre", 3))
		return 0;

	rta_data = nl_attr_nest(&req->n, buflen, IFLA_INFO_DATA);
	if (!rta_data)
		return 0;

	if (!nl_attr_put32(&req->n, buflen, IFLA_GRE_LINK, link_idx))
		return 0;

	if (gre_info->vtep_ip.s_addr &&
	    !nl_attr_put32(&req->n, buflen, IFLA_GRE_LOCAL,
			   gre_info->vtep_ip.s_addr))
		return 0;

	if (gre_info->vtep_ip_remote.s_addr &&
	    !nl_attr_put32(&req->n, buflen, IFLA_GRE_REMOTE,
			   gre_info->vtep_ip_remote.s_addr))
		return 0;

	if (gre_info->ikey &&
	    !nl_attr_put32(&req->n, buflen, IFLA_GRE_IKEY,
			   gre_info->ikey))
		return 0;
	if (gre_info->okey &&
	    !nl_attr_put32(&req->n, buflen, IFLA_GRE_IKEY,
			   gre_info->okey))
		return 0;

	nl_attr_nest_end(&req->n, rta_data);
	nl_attr_nest_end(&req->n, rta_info);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static int netlink_extract_bridge_info(struct rtattr *link_data,
				       struct zebra_l2info_bridge *bridge_info)
{
	struct rtattr *attr[IFLA_BR_MAX + 1];

	memset(bridge_info, 0, sizeof(*bridge_info));
	netlink_parse_rtattr_nested(attr, IFLA_BR_MAX, link_data);
	if (attr[IFLA_BR_VLAN_FILTERING])
		bridge_info->bridge.vlan_aware =
			*(uint8_t *)RTA_DATA(attr[IFLA_BR_VLAN_FILTERING]);
	return 0;
}

static int netlink_extract_vlan_info(struct rtattr *link_data,
				     struct zebra_l2info_vlan *vlan_info)
{
	struct rtattr *attr[IFLA_VLAN_MAX + 1];
	vlanid_t vid_in_msg;

	memset(vlan_info, 0, sizeof(*vlan_info));
	netlink_parse_rtattr_nested(attr, IFLA_VLAN_MAX, link_data);
	if (!attr[IFLA_VLAN_ID]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_VLAN_ID missing from VLAN IF message");
		return -1;
	}

	vid_in_msg = *(vlanid_t *)RTA_DATA(attr[IFLA_VLAN_ID]);
	vlan_info->vid = vid_in_msg;
	return 0;
}

static int netlink_extract_gre_info(struct rtattr *link_data,
				    struct zebra_l2info_gre *gre_info)
{
	struct rtattr *attr[IFLA_GRE_MAX + 1];

	memset(gre_info, 0, sizeof(*gre_info));
	memset(attr, 0, sizeof(attr));
	netlink_parse_rtattr_nested(attr, IFLA_GRE_MAX, link_data);

	if (!attr[IFLA_GRE_LOCAL]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_GRE_LOCAL missing from GRE IF message");
	} else
		gre_info->vtep_ip =
			*(struct in_addr *)RTA_DATA(attr[IFLA_GRE_LOCAL]);
	if (!attr[IFLA_GRE_REMOTE]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_GRE_REMOTE missing from GRE IF message");
	} else
		gre_info->vtep_ip_remote =
			*(struct in_addr *)RTA_DATA(attr[IFLA_GRE_REMOTE]);

	if (!attr[IFLA_GRE_LINK]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_GRE_LINK missing from GRE IF message");
	} else {
		gre_info->ifindex_link =
			*(ifindex_t *)RTA_DATA(attr[IFLA_GRE_LINK]);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_GRE_LINK obtained is %u",
				   gre_info->ifindex_link);
	}
	if (attr[IFLA_GRE_IKEY])
		gre_info->ikey = *(uint32_t *)RTA_DATA(attr[IFLA_GRE_IKEY]);
	if (attr[IFLA_GRE_OKEY])
		gre_info->okey = *(uint32_t *)RTA_DATA(attr[IFLA_GRE_OKEY]);
	return 0;
}

static int netlink_extract_vxlan_info(struct rtattr *link_data,
				      struct zebra_l2info_vxlan *vxl_info)
{
	uint8_t svd = 0;
	struct rtattr *attr[IFLA_VXLAN_MAX + 1];
	vni_t vni_in_msg;
	struct in_addr vtep_ip_in_msg;
	ifindex_t ifindex_link;

	memset(vxl_info, 0, sizeof(*vxl_info));
	netlink_parse_rtattr_nested(attr, IFLA_VXLAN_MAX, link_data);
	if (attr[IFLA_VXLAN_COLLECT_METADATA]) {
		svd = *(uint8_t *)RTA_DATA(attr[IFLA_VXLAN_COLLECT_METADATA]);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_VXLAN_COLLECT_METADATA=%u in VXLAN IF message",
				svd);
	}

	if (!svd) {
		/*
		 * In case of svd we will not get vni info directly from the
		 * device
		 */
		if (!attr[IFLA_VXLAN_ID]) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"IFLA_VXLAN_ID missing from VXLAN IF message");
			return -1;
		}

		vxl_info->vni_info.iftype = ZEBRA_VXLAN_IF_VNI;
		vni_in_msg = *(vni_t *)RTA_DATA(attr[IFLA_VXLAN_ID]);
		vxl_info->vni_info.vni.vni = vni_in_msg;
	} else {
		vxl_info->vni_info.iftype = ZEBRA_VXLAN_IF_SVD;
	}

	if (!attr[IFLA_VXLAN_LOCAL]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"IFLA_VXLAN_LOCAL missing from VXLAN IF message");
	} else {
		vtep_ip_in_msg =
			*(struct in_addr *)RTA_DATA(attr[IFLA_VXLAN_LOCAL]);
		vxl_info->vtep_ip = vtep_ip_in_msg;
	}

	if (attr[IFLA_VXLAN_GROUP]) {
		if (!svd)
			vxl_info->vni_info.vni.mcast_grp =
				*(struct in_addr *)RTA_DATA(
					attr[IFLA_VXLAN_GROUP]);
	}

	if (!attr[IFLA_VXLAN_LINK]) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("IFLA_VXLAN_LINK missing from VXLAN IF message");
	} else {
		ifindex_link =
			*(ifindex_t *)RTA_DATA(attr[IFLA_VXLAN_LINK]);
		vxl_info->ifindex_link = ifindex_link;
	}
	return 0;
}

/*
 * Extract and save L2 params (of interest) for an interface. When a
 * bridge interface is added or updated, take further actions to map
 * its members. Likewise, for VxLAN interface.
 */
static void netlink_interface_update_l2info(struct zebra_dplane_ctx *ctx,
					    enum zebra_iftype zif_type,
					    struct rtattr *link_data, int add,
					    ns_id_t link_nsid)
{
	struct zebra_l2info_bridge bridge_info;
	struct zebra_l2info_vlan vlan_info;
	struct zebra_l2info_vxlan vxlan_info;
	struct zebra_l2info_gre gre_info;

	if (!link_data)
		return;

	switch (zif_type) {
	case ZEBRA_IF_BRIDGE:
		netlink_extract_bridge_info(link_data, &bridge_info);
		dplane_ctx_set_ifp_bridge_info(ctx, &bridge_info);
		break;
	case ZEBRA_IF_VLAN:
		netlink_extract_vlan_info(link_data, &vlan_info);
		dplane_ctx_set_ifp_vlan_info(ctx, &vlan_info);
		break;
	case ZEBRA_IF_VXLAN:
		netlink_extract_vxlan_info(link_data, &vxlan_info);
		vxlan_info.link_nsid = link_nsid;
		dplane_ctx_set_ifp_vxlan_info(ctx, &vxlan_info);
		break;
	case ZEBRA_IF_GRE:
		netlink_extract_gre_info(link_data, &gre_info);
		gre_info.link_nsid = link_nsid;
		dplane_ctx_set_ifp_gre_info(ctx, &gre_info);
		break;
	case ZEBRA_IF_OTHER:
	case ZEBRA_IF_VRF:
	case ZEBRA_IF_MACVLAN:
	case ZEBRA_IF_VETH:
	case ZEBRA_IF_BOND:
		break;
	}
}

static int
netlink_bridge_vxlan_vlan_vni_map_update(struct zebra_dplane_ctx *ctx,
					 struct rtattr *af_spec)
{
	int rem;
	uint16_t flags;
	struct rtattr *i;
	struct zebra_vxlan_vni_array *vniarray = NULL;
	struct zebra_vxlan_vni vni_end;
	struct zebra_vxlan_vni vni_start;
	struct rtattr *aftb[IFLA_BRIDGE_VLAN_TUNNEL_MAX + 1];
	int32_t count = 0;

	memset(&vni_start, 0, sizeof(vni_start));
	memset(&vni_end, 0, sizeof(vni_end));

	for (i = RTA_DATA(af_spec), rem = RTA_PAYLOAD(af_spec); RTA_OK(i, rem);
	     i = RTA_NEXT(i, rem)) {

		if (i->rta_type != IFLA_BRIDGE_VLAN_TUNNEL_INFO)
			continue;

		memset(aftb, 0, sizeof(aftb));
		netlink_parse_rtattr_nested(aftb, IFLA_BRIDGE_VLAN_TUNNEL_MAX,
					    i);
		if (!aftb[IFLA_BRIDGE_VLAN_TUNNEL_ID] ||
		    !aftb[IFLA_BRIDGE_VLAN_TUNNEL_VID])
			/* vlan-vni info missing */
			return 0;

		count++;
		flags = 0;
		vniarray = XREALLOC(
			MTYPE_TMP, vniarray,
			sizeof(struct zebra_vxlan_vni_array) +
				count * sizeof(struct zebra_vxlan_vni));

		memset(&vniarray->vnis[count - 1], 0,
		       sizeof(struct zebra_vxlan_vni));

		vniarray->vnis[count - 1].vni =
			*(vni_t *)RTA_DATA(aftb[IFLA_BRIDGE_VLAN_TUNNEL_ID]);
		vniarray->vnis[count - 1].access_vlan = *(vlanid_t *)RTA_DATA(
			aftb[IFLA_BRIDGE_VLAN_TUNNEL_VID]);

		if (aftb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS])
			flags = *(uint16_t *)RTA_DATA(
				aftb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS]);

		vniarray->vnis[count - 1].flags = flags;
	}

	if (count) {
		vniarray->count = count;
		dplane_ctx_set_ifp_vxlan_vni_array(ctx, vniarray);
	}
	return 0;
}

static int netlink_bridge_vxlan_update(struct zebra_dplane_ctx *ctx,
				       struct rtattr *af_spec)
{
	struct rtattr *aftb[IFLA_BRIDGE_MAX + 1];
	struct bridge_vlan_info *vinfo;
	struct zebra_dplane_bridge_vlan_info bvinfo;

	if (!af_spec) {
		dplane_ctx_set_ifp_no_afspec(ctx);
		return 0;
	}

	netlink_bridge_vxlan_vlan_vni_map_update(ctx, af_spec);

	/* There is a 1-to-1 mapping of VLAN to VxLAN - hence
	 * only 1 access VLAN is accepted.
	 */
	netlink_parse_rtattr_nested(aftb, IFLA_BRIDGE_MAX, af_spec);
	if (!aftb[IFLA_BRIDGE_VLAN_INFO]) {
		dplane_ctx_set_ifp_no_bridge_vlan_info(ctx);
		return 0;
	}

	vinfo = RTA_DATA(aftb[IFLA_BRIDGE_VLAN_INFO]);
	bvinfo.flags = vinfo->flags;
	bvinfo.vid = vinfo->vid;

	dplane_ctx_set_ifp_bridge_vlan_info(ctx, &bvinfo);
	return 0;
}

static void netlink_bridge_vlan_update(struct zebra_dplane_ctx *ctx,
				       struct rtattr *af_spec)
{
	struct rtattr *i;
	int rem;
	struct bridge_vlan_info *vinfo;
	struct zebra_dplane_bridge_vlan_info_array *bvarray = NULL;
	int32_t count = 0;

	if (af_spec) {
		for (i = RTA_DATA(af_spec), rem = RTA_PAYLOAD(af_spec);
		     RTA_OK(i, rem); i = RTA_NEXT(i, rem)) {
			if (i->rta_type != IFLA_BRIDGE_VLAN_INFO)
				continue;

			count++;
			bvarray = XREALLOC(
				MTYPE_TMP, bvarray,
				sizeof(struct
				       zebra_dplane_bridge_vlan_info_array) +
					count * sizeof(struct
						       zebra_dplane_bridge_vlan_info));

			vinfo = RTA_DATA(i);
			bvarray->array[count - 1].flags = vinfo->flags;
			bvarray->array[count - 1].vid = vinfo->vid;
		}
	}

	if (count) {
		bvarray->count = count;
		dplane_ctx_set_ifp_bridge_vlan_info_array(ctx, bvarray);
	}
}

static int netlink_bridge_interface(struct zebra_dplane_ctx *ctx,
				    struct rtattr *af_spec, int startup)
{

	netlink_bridge_vxlan_update(ctx, af_spec);

	/* build vlan bitmap associated with this interface if that
	 * device type is interested in the vlans
	 */
	netlink_bridge_vlan_update(ctx, af_spec);

	dplane_provider_enqueue_to_zebra(ctx);
	return 0;
}

/*
 * Process interface protodown dplane update.
 *
 * If the interface is an es bond member then it must follow EVPN's
 * protodown setting.
 */
static void netlink_proc_dplane_if_protodown(struct zebra_dplane_ctx *ctx,
					     struct rtattr **tb)
{
	bool protodown;
	uint32_t rc_bitfield = 0;
	struct rtattr *pd_reason_info[IFLA_MAX + 1];

	protodown = !!*(uint8_t *)RTA_DATA(tb[IFLA_PROTO_DOWN]);

	if (tb[IFLA_PROTO_DOWN_REASON]) {
		netlink_parse_rtattr_nested(pd_reason_info, IFLA_INFO_MAX,
					    tb[IFLA_PROTO_DOWN_REASON]);

		if (pd_reason_info[IFLA_PROTO_DOWN_REASON_VALUE])
			rc_bitfield = *(uint32_t *)RTA_DATA(
				pd_reason_info[IFLA_PROTO_DOWN_REASON_VALUE]);
	}

	dplane_ctx_set_ifp_rc_bitfield(ctx, rc_bitfield);
	dplane_ctx_set_ifp_protodown(ctx, protodown);
	dplane_ctx_set_ifp_protodown_set(ctx, true);
}

static uint8_t netlink_parse_lacp_bypass(struct rtattr **linkinfo)
{
	uint8_t bypass = 0;
	struct rtattr *mbrinfo[IFLA_BOND_SLAVE_MAX + 1];

	netlink_parse_rtattr_nested(mbrinfo, IFLA_BOND_SLAVE_MAX,
				    linkinfo[IFLA_INFO_SLAVE_DATA]);
	if (mbrinfo[IFLA_BOND_SLAVE_AD_RX_BYPASS])
		bypass = *(uint8_t *)RTA_DATA(
			mbrinfo[IFLA_BOND_SLAVE_AD_RX_BYPASS]);

	return bypass;
}

/* Request for specific interface or address information from the kernel */
static int netlink_request_intf_addr(struct nlsock *netlink_cmd, int family,
				     int type, uint32_t filter_mask)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifm;
		char buf[256];
	} req;

	frrtrace(4, frr_zebra, netlink_request_intf_addr, netlink_cmd, family,
		 type, filter_mask);

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.ifm.ifi_family = family;

	/* Include filter, if specified. */
	if (filter_mask)
		nl_attr_put32(&req.n, sizeof(req), IFLA_EXT_MASK, filter_mask);

	return netlink_request(netlink_cmd, &req);
}

enum netlink_msg_status
netlink_put_gre_set_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);
	assert(op == DPLANE_OP_GRE_SET);

	ret = netlink_batch_add_msg(bth, ctx, netlink_gre_set_msg_encoder, false);

	return ret;
}

/* Interface lookup by netlink socket. */
int interface_lookup_netlink(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;
	struct nlsock *netlink_cmd = &zns->netlink_dplane_out;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get interface information. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_PACKET, RTM_GETLINK, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_link_change, netlink_cmd, &dp_info, 0,
				 true);
	if (ret < 0)
		return ret;

	/* Get interface information - for bridge interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_BRIDGE, RTM_GETLINK,
					RTEXT_FILTER_BRVLAN);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_link_change, netlink_cmd, &dp_info, 0,
				 true);
	if (ret < 0)
		return ret;

	return ret;
}

void interface_list_tunneldump(struct zebra_ns *zns)
{
	int ret;

	/*
	 * So netlink_tunneldump_read will initiate a request
	 * per tunnel to get data.  If we are on a kernel that
	 * does not support this then we will get X error messages
	 * (one per tunnel request )back which netlink_parse_info will
	 * stop after the first one.  So we need to read equivalent
	 * error messages per tunnel then we can continue.
	 * if we do not gather all the read failures then
	 * later requests will not work right.
	 */
	ret = netlink_tunneldump_read(zns);
	if (ret < 0)
		return;

	zebra_dplane_startup_stage(zns, ZEBRA_DPLANE_TUNNELS_READ);
}


/**
 * interface_addr_lookup_netlink() - Look up interface addresses
 *
 * @zns:	Zebra netlink socket
 * Return:	Result status
 */
static int interface_addr_lookup_netlink(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;
	struct nlsock *netlink_cmd = &zns->netlink_cmd;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get IPv4 address of the interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_INET, RTM_GETADDR, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface_addr_dplane, netlink_cmd,
				 &dp_info, 0, true);
	if (ret < 0)
		return ret;

	/* Get IPv6 address of the interfaces. */
	ret = netlink_request_intf_addr(netlink_cmd, AF_INET6, RTM_GETADDR, 0);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_interface_addr_dplane, netlink_cmd,
				 &dp_info, 0, true);
	if (ret < 0)
		return ret;

	return 0;
}

int kernel_interface_set_master(struct interface *master,
				struct interface *slave)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_SETLINK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.ifa.ifi_index = slave->ifindex;

	nl_attr_put32(&req.n, sizeof(req), IFLA_MASTER, master->ifindex);
	nl_attr_put32(&req.n, sizeof(req), IFLA_LINK, slave->ifindex);

	return netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns,
			    false);
}

/* Interface address modification. */
static ssize_t netlink_address_msg_encoder(struct zebra_dplane_ctx *ctx,
					   void *buf, size_t buflen)
{
	int bytelen;
	const struct prefix *p;
	int cmd;
	const char *label;

	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[0];
	} *req = buf;

	if (buflen < sizeof(*req))
		return 0;

	p = dplane_ctx_get_intf_addr(ctx);
	memset(req, 0, sizeof(*req));

	bytelen = (p->family == AF_INET ? 4 : 16);

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL)
		cmd = RTM_NEWADDR;
	else
		cmd = RTM_DELADDR;

	req->n.nlmsg_type = cmd;
	req->ifa.ifa_family = p->family;

	req->ifa.ifa_index = dplane_ctx_get_ifindex(ctx);

	if (!nl_attr_put(&req->n, buflen, IFA_LOCAL, &p->u.prefix, bytelen))
		return 0;

	if (p->family == AF_INET) {
		if (dplane_ctx_intf_is_connected(ctx)) {
			p = dplane_ctx_get_intf_dest(ctx);
			if (!nl_attr_put(&req->n, buflen, IFA_ADDRESS,
					 &p->u.prefix, bytelen))
				return 0;
		} else if (cmd == RTM_NEWADDR) {
			struct in_addr broad = {
				.s_addr = ipv4_broadcast_addr(p->u.prefix4.s_addr,
							p->prefixlen)
			};
			if (!nl_attr_put(&req->n, buflen, IFA_BROADCAST, &broad,
					 bytelen))
				return 0;
		}
	}

	/* p is now either address or destination/bcast addr */
	req->ifa.ifa_prefixlen = p->prefixlen;

	if (dplane_ctx_intf_is_secondary(ctx))
		SET_FLAG(req->ifa.ifa_flags, IFA_F_SECONDARY);

	if (dplane_ctx_intf_has_label(ctx)) {
		label = dplane_ctx_get_intf_label(ctx);
		if (!nl_attr_put(&req->n, buflen, IFA_LABEL, label,
				 strlen(label) + 1))
			return 0;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

enum netlink_msg_status
netlink_put_address_update_msg(struct nl_batch *bth,
			       struct zebra_dplane_ctx *ctx)
{
	return netlink_batch_add_msg(bth, ctx, netlink_address_msg_encoder,
				     false);
}

static ssize_t netlink_intf_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
					size_t buflen)
{
	enum dplane_op_e op;
	int cmd = 0;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_INTF_UPDATE)
		cmd = RTM_SETLINK;
	else if (op == DPLANE_OP_INTF_INSTALL)
		cmd = RTM_NEWLINK;
	else if (op == DPLANE_OP_INTF_DELETE)
		cmd = RTM_DELLINK;
	else {
		flog_err(
			EC_ZEBRA_NHG_FIB_UPDATE,
			"Context received for kernel interface update with incorrect OP code (%u)",
			op);
		return -1;
	}

	return netlink_intf_msg_encode(cmd, ctx, buf, buflen);
}

enum netlink_msg_status
netlink_put_intf_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	return netlink_batch_add_msg(bth, ctx, netlink_intf_msg_encoder, false);
}

int netlink_interface_addr(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	struct interface *ifp;
	void *addr;
	void *broad;
	uint8_t flags = 0;
	char *label = NULL;
	struct zebra_ns *zns;
	uint32_t metric = METRIC_MAX;
	uint32_t kernel_flags = 0;

	frrtrace(3, frr_zebra, netlink_interface_addr, h, ns_id, startup);

	zns = zebra_ns_lookup(ns_id);
	ifa = NLMSG_DATA(h);

	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6) {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel interface addr change: %s",
			ifa->ifa_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size: %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ifaddrmsg)));
		return -1;
	}

	netlink_parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	ifp = if_lookup_by_index_per_ns(zns, ifa->ifa_index);
	if (ifp == NULL) {
		if (startup) {
			/* During startup, failure to lookup the referenced
			 * interface should not be an error, so we have
			 * downgraded this condition to warning, and we permit
			 * the startup interface state retrieval to continue.
			 */
			flog_warn(EC_LIB_INTERFACE,
				  "%s: can't find interface by index %d",
				  __func__, ifa->ifa_index);
			return 0;
		} else {
			flog_err(EC_LIB_INTERFACE,
				 "%s: can't find interface by index %d",
				 __func__, ifa->ifa_index);
			return -1;
		}
	}

	/* Flags passed through */
	if (tb[IFA_FLAGS])
		kernel_flags = *(int *)RTA_DATA(tb[IFA_FLAGS]);
	else
		kernel_flags = ifa->ifa_flags;

	if (IS_ZEBRA_DEBUG_KERNEL) /* remove this line to see initial ifcfg */
	{
		char buf[BUFSIZ];
		zlog_debug("%s %s %s flags 0x%x:", __func__,
			   nl_msg_type_to_str(h->nlmsg_type), ifp->name,
			   kernel_flags);
		if (tb[IFA_LOCAL])
			zlog_debug("  IFA_LOCAL     %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_LOCAL]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_ADDRESS])
			zlog_debug("  IFA_ADDRESS   %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_ADDRESS]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_BROADCAST])
			zlog_debug("  IFA_BROADCAST %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_BROADCAST]), buf,
					     BUFSIZ),
				   ifa->ifa_prefixlen);
		if (tb[IFA_LABEL] && strcmp(ifp->name, RTA_DATA(tb[IFA_LABEL])))
			zlog_debug("  IFA_LABEL     %s",
				   (char *)RTA_DATA(tb[IFA_LABEL]));

		if (tb[IFA_CACHEINFO]) {
			struct ifa_cacheinfo *ci = RTA_DATA(tb[IFA_CACHEINFO]);
			zlog_debug("  IFA_CACHEINFO pref %d, valid %d",
				   ci->ifa_prefered, ci->ifa_valid);
		}
	}

	/* logic copied from iproute2/ip/ipaddress.c:print_addrinfo() */
	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	/* is there a peer address? */
	if (tb[IFA_ADDRESS]
	    && memcmp(RTA_DATA(tb[IFA_ADDRESS]), RTA_DATA(tb[IFA_LOCAL]),
		      RTA_PAYLOAD(tb[IFA_ADDRESS]))) {
		broad = RTA_DATA(tb[IFA_ADDRESS]);
		SET_FLAG(flags, ZEBRA_IFA_PEER);
	} else
		/* seeking a broadcast address */
		broad = (tb[IFA_BROADCAST] ? RTA_DATA(tb[IFA_BROADCAST])
					   : NULL);

	/* addr is primary key, SOL if we don't have one */
	if (addr == NULL) {
		zlog_debug("%s: Local Interface Address is NULL for %s",
			   __func__, ifp->name);
		return -1;
	}

	/* Flags. */
	if (kernel_flags & IFA_F_SECONDARY)
		SET_FLAG(flags, ZEBRA_IFA_SECONDARY);

	/* Label */
	if (tb[IFA_LABEL])
		label = (char *)RTA_DATA(tb[IFA_LABEL]);

	if (label && strcmp(ifp->name, label) == 0)
		label = NULL;

	if (tb[IFA_RT_PRIORITY])
		metric = *(uint32_t *)RTA_DATA(tb[IFA_RT_PRIORITY]);

	/* Register interface address to the interface. */
	if (ifa->ifa_family == AF_INET) {
		if (ifa->ifa_prefixlen > IPV4_MAX_BITLEN) {
			zlog_err(
				"Invalid prefix length: %u received from kernel interface addr change: %s",
				ifa->ifa_prefixlen,
				nl_msg_type_to_str(h->nlmsg_type));
			return -1;
		}

		if (h->nlmsg_type == RTM_NEWADDR)
			connected_add_ipv4(ifp, flags, (struct in_addr *)addr,
					   ifa->ifa_prefixlen,
					   (struct in_addr *)broad, label,
					   metric);
		else if (CHECK_FLAG(flags, ZEBRA_IFA_PEER)) {
			/* Delete with a peer address */
			connected_delete_ipv4(
				ifp, flags, (struct in_addr *)addr,
				ifa->ifa_prefixlen, broad);
		} else
			connected_delete_ipv4(
				ifp, flags, (struct in_addr *)addr,
				ifa->ifa_prefixlen, NULL);
	}

	if (ifa->ifa_family == AF_INET6) {
		if (ifa->ifa_prefixlen > IPV6_MAX_BITLEN) {
			zlog_err(
				"Invalid prefix length: %u received from kernel interface addr change: %s",
				ifa->ifa_prefixlen,
				nl_msg_type_to_str(h->nlmsg_type));
			return -1;
		}
		if (h->nlmsg_type == RTM_NEWADDR) {
			/* Only consider valid addresses; we'll not get a
			 * notification from
			 * the kernel till IPv6 DAD has completed, but at init
			 * time, Quagga
			 * does query for and will receive all addresses.
			 */
			if (!(kernel_flags
			      & (IFA_F_DADFAILED | IFA_F_TENTATIVE)))
				connected_add_ipv6(ifp, flags,
						   (struct in6_addr *)addr,
						   (struct in6_addr *)broad,
						   ifa->ifa_prefixlen, label,
						   metric);
		} else
			connected_delete_ipv6(ifp, (struct in6_addr *)addr,
					      NULL, ifa->ifa_prefixlen);
	}

	/*
	 * Linux kernel does not send route delete on interface down/addr del
	 * so we have to re-process routes it owns (i.e. kernel routes)
	 */
	if (h->nlmsg_type != RTM_NEWADDR)
		rib_update(RIB_UPDATE_KERNEL);

	return 0;
}

/*
 * Parse and validate an incoming interface address change message,
 * generating a dplane context object.
 * This runs in the dplane pthread; the context is enqueued to the
 * main pthread for processing.
 */
int netlink_interface_addr_dplane(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup /*ignored*/)
{
	int len;
	struct ifaddrmsg *ifa;
	struct rtattr *tb[IFA_MAX + 1];
	void *addr;
	void *broad;
	char *label = NULL;
	uint32_t metric = METRIC_MAX;
	uint32_t kernel_flags = 0;
	struct zebra_dplane_ctx *ctx;
	struct prefix p;

	ifa = NLMSG_DATA(h);

	/* Validate message types */
	if (h->nlmsg_type != RTM_NEWADDR && h->nlmsg_type != RTM_DELADDR)
		return 0;

	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s: Invalid address family: %u",
				   __func__, nl_msg_type_to_str(h->nlmsg_type),
				   ifa->ifa_family);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	if (len < 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s: netlink msg bad size: %d %zu",
				   __func__, nl_msg_type_to_str(h->nlmsg_type),
				   h->nlmsg_len,
				   (size_t)NLMSG_LENGTH(
					   sizeof(struct ifaddrmsg)));
		return -1;
	}

	netlink_parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);

	/* Flags passed through */
	if (tb[IFA_FLAGS])
		kernel_flags = *(int *)RTA_DATA(tb[IFA_FLAGS]);
	else
		kernel_flags = ifa->ifa_flags;

	if (IS_ZEBRA_DEBUG_KERNEL) { /* remove this line to see initial ifcfg */
		char buf[PREFIX_STRLEN];

		zlog_debug("%s: %s nsid %u ifindex %u flags 0x%x:", __func__,
			   nl_msg_type_to_str(h->nlmsg_type), ns_id,
			   ifa->ifa_index, kernel_flags);
		if (tb[IFA_LOCAL])
			zlog_debug("  IFA_LOCAL     %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_LOCAL]), buf,
					     sizeof(buf)),
				   ifa->ifa_prefixlen);
		if (tb[IFA_ADDRESS])
			zlog_debug("  IFA_ADDRESS   %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_ADDRESS]), buf,
					     sizeof(buf)),
				   ifa->ifa_prefixlen);
		if (tb[IFA_BROADCAST])
			zlog_debug("  IFA_BROADCAST %s/%d",
				   inet_ntop(ifa->ifa_family,
					     RTA_DATA(tb[IFA_BROADCAST]), buf,
					     sizeof(buf)),
				   ifa->ifa_prefixlen);
		if (tb[IFA_LABEL])
			zlog_debug("  IFA_LABEL     %s",
				   (const char *)RTA_DATA(tb[IFA_LABEL]));

		if (tb[IFA_CACHEINFO]) {
			struct ifa_cacheinfo *ci = RTA_DATA(tb[IFA_CACHEINFO]);

			zlog_debug("  IFA_CACHEINFO pref %d, valid %d",
				   ci->ifa_prefered, ci->ifa_valid);
		}
	}

	/* Validate prefix length */

	if (ifa->ifa_family == AF_INET
	    && ifa->ifa_prefixlen > IPV4_MAX_BITLEN) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s: Invalid prefix length: %u",
				   __func__, nl_msg_type_to_str(h->nlmsg_type),
				   ifa->ifa_prefixlen);
		return -1;
	}

	if (ifa->ifa_family == AF_INET6) {
		if (ifa->ifa_prefixlen > IPV6_MAX_BITLEN) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: Invalid prefix length: %u",
					   __func__,
					   nl_msg_type_to_str(h->nlmsg_type),
					   ifa->ifa_prefixlen);
			return -1;
		}

		/* Only consider valid addresses; we'll not get a kernel
		 * notification till IPv6 DAD has completed, but at init
		 * time, FRR does query for and will receive all addresses.
		 */
		if (h->nlmsg_type == RTM_NEWADDR
		    && (kernel_flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE))) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: Invalid/tentative addr",
					   __func__,
					   nl_msg_type_to_str(h->nlmsg_type));
			return 0;
		}
	}

	/* logic copied from iproute2/ip/ipaddress.c:print_addrinfo() */
	if (tb[IFA_LOCAL] == NULL)
		tb[IFA_LOCAL] = tb[IFA_ADDRESS];
	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	/* local interface address */
	addr = (tb[IFA_LOCAL] ? RTA_DATA(tb[IFA_LOCAL]) : NULL);

	/* addr is primary key, SOL if we don't have one */
	if (addr == NULL) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s: No local interface address",
				   __func__, nl_msg_type_to_str(h->nlmsg_type));
		return -1;
	}

	/* Allocate a context object, now that validation is done. */
	ctx = dplane_ctx_alloc();
	if (h->nlmsg_type == RTM_NEWADDR)
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_ADD);
	else
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_ADDR_DEL);

	dplane_ctx_set_ifindex(ctx, ifa->ifa_index);
	dplane_ctx_set_ns_id(ctx, ns_id);

	/* Convert addr to prefix */
	memset(&p, 0, sizeof(p));
	p.family = ifa->ifa_family;
	p.prefixlen = ifa->ifa_prefixlen;
	if (p.family == AF_INET)
		p.u.prefix4 = *(struct in_addr *)addr;
	else
		p.u.prefix6 = *(struct in6_addr *)addr;

	dplane_ctx_set_intf_addr(ctx, &p);

	/* is there a peer address? */
	if (tb[IFA_ADDRESS]
	    && memcmp(RTA_DATA(tb[IFA_ADDRESS]), RTA_DATA(tb[IFA_LOCAL]),
		      RTA_PAYLOAD(tb[IFA_ADDRESS]))) {
		broad = RTA_DATA(tb[IFA_ADDRESS]);
		dplane_ctx_intf_set_connected(ctx);
	} else if (tb[IFA_BROADCAST]) {
		/* seeking a broadcast address */
		broad = RTA_DATA(tb[IFA_BROADCAST]);
		dplane_ctx_intf_set_broadcast(ctx);
	} else
		broad = NULL;

	if (broad) {
		/* Convert addr to prefix */
		memset(&p, 0, sizeof(p));
		p.family = ifa->ifa_family;
		p.prefixlen = ifa->ifa_prefixlen;
		if (p.family == AF_INET)
			p.u.prefix4 = *(struct in_addr *)broad;
		else
			p.u.prefix6 = *(struct in6_addr *)broad;

		dplane_ctx_set_intf_dest(ctx, &p);
	}

	/* Flags. */
	if (kernel_flags & IFA_F_SECONDARY)
		dplane_ctx_intf_set_secondary(ctx);

	if (kernel_flags & IFA_F_NOPREFIXROUTE)
		dplane_ctx_intf_set_noprefixroute(ctx);

	/* Label */
	if (tb[IFA_LABEL]) {
		label = (char *)RTA_DATA(tb[IFA_LABEL]);
		dplane_ctx_set_intf_label(ctx, label);
	}

	if (tb[IFA_RT_PRIORITY])
		metric = *(uint32_t *)RTA_DATA(tb[IFA_RT_PRIORITY]);

	dplane_ctx_set_intf_metric(ctx, metric);

	/* Enqueue ctx for main pthread to process */
	dplane_provider_enqueue_to_zebra(ctx);
	return 0;
}

int netlink_link_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *linkinfo[IFLA_MAX + 1];
	char *name = NULL;
	char *kind = NULL;
	char *slave_kind = NULL;
	vrf_id_t vrf_id = VRF_DEFAULT;
	enum zebra_iftype zif_type = ZEBRA_IF_OTHER;
	enum zebra_slave_iftype zif_slave_type = ZEBRA_IF_SLAVE_NONE;
	ifindex_t bridge_ifindex = IFINDEX_INTERNAL;
	ifindex_t bond_ifindex = IFINDEX_INTERNAL;
	ifindex_t link_ifindex = IFINDEX_INTERNAL;
	ns_id_t link_nsid = ns_id;
	ifindex_t master_infindex = IFINDEX_INTERNAL;
	uint8_t bypass = 0;
	uint32_t txqlen = 0;

	frrtrace(3, frr_zebra, netlink_interface, h, ns_id, startup);

	ifi = NLMSG_DATA(h);

	if (!(h->nlmsg_type == RTM_NEWLINK || h->nlmsg_type == RTM_DELLINK)) {
		/* If this is not link add/delete message so print warning. */
		zlog_debug("%s: wrong kernel message %s", __func__,
			   nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	if (!(ifi->ifi_family == AF_UNSPEC || ifi->ifi_family == AF_BRIDGE
	      || ifi->ifi_family == AF_INET6)) {
		flog_warn(
			EC_ZEBRA_UNKNOWN_FAMILY,
			"Invalid address family: %u received from kernel link change: %s",
			ifi->ifi_family, nl_msg_type_to_str(h->nlmsg_type));
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct ifinfomsg)));
		return -1;
	}

	/* Looking up interface name. */
	memset(linkinfo, 0, sizeof(linkinfo));
	netlink_parse_rtattr_flags(tb, IFLA_MAX, IFLA_RTA(ifi), len,
				   NLA_F_NESTED);

	/* check for wireless messages to ignore */
	if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: ignoring IFLA_WIRELESS message",
				   __func__);
		return 0;
	}

	if (tb[IFLA_IFNAME] == NULL)
		return -1;
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	/* Must be valid string. */
	len = RTA_PAYLOAD(tb[IFLA_IFNAME]);
	if (len < 2 || name[len - 1] != '\0') {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: invalid intf name", __func__);
		return -1;
	}

	if (tb[IFLA_LINKINFO]) {
		netlink_parse_rtattr_nested(linkinfo, IFLA_INFO_MAX,
					    tb[IFLA_LINKINFO]);

		if (linkinfo[IFLA_INFO_KIND])
			kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);

		if (linkinfo[IFLA_INFO_SLAVE_KIND])
			slave_kind = RTA_DATA(linkinfo[IFLA_INFO_SLAVE_KIND]);

		netlink_determine_zebra_iftype(kind, &zif_type);
	}

	/* If linking to another interface, note it. */
	if (tb[IFLA_LINK])
		link_ifindex = *(ifindex_t *)RTA_DATA(tb[IFLA_LINK]);

	if (tb[IFLA_LINK_NETNSID]) {
		link_nsid = *(ns_id_t *)RTA_DATA(tb[IFLA_LINK_NETNSID]);
		link_nsid = ns_id_get_absolute(ns_id, link_nsid);
	}

	if (tb[IFLA_TXQLEN])
		txqlen = *(uint32_t *)RTA_DATA(tb[IFLA_TXQLEN]);

	struct zebra_dplane_ctx *ctx = dplane_ctx_alloc();
	dplane_ctx_set_ns_id(ctx, ns_id);
	dplane_ctx_set_ifp_link_nsid(ctx, link_nsid);
	dplane_ctx_set_ifp_zif_type(ctx, zif_type);
	dplane_ctx_set_ifindex(ctx, ifi->ifi_index);
	dplane_ctx_set_ifname(ctx, name);
	dplane_ctx_set_ifp_startup(ctx, startup);
	dplane_ctx_set_ifp_family(ctx, ifi->ifi_family);
	dplane_ctx_set_intf_txqlen(ctx, txqlen);

	/* We are interested in some AF_BRIDGE notifications. */
#ifndef AF_BRIDGE
#define AF_BRIDGE 7
#endif
	if (ifi->ifi_family == AF_BRIDGE) {
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_INSTALL);
		return netlink_bridge_interface(ctx, tb[IFLA_AF_SPEC], startup);
	}

	if (h->nlmsg_type == RTM_NEWLINK) {
		dplane_ctx_set_ifp_link_ifindex(ctx, link_ifindex);
		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_INSTALL);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
		if (tb[IFLA_IFALIAS]) {
			dplane_ctx_set_ifp_desc(ctx,
						RTA_DATA(tb[IFLA_IFALIAS]));
		}
		if (!tb[IFLA_MTU]) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"RTM_NEWLINK for interface %s(%u) without MTU set",
					name, ifi->ifi_index);
			dplane_ctx_fini(&ctx);
			return 0;
		}
		dplane_ctx_set_ifp_mtu(ctx, *(int *)RTA_DATA(tb[IFLA_MTU]));

		/* If VRF, create or update the VRF structure itself. */
		if (zif_type == ZEBRA_IF_VRF && !vrf_is_backend_netns()) {
			netlink_vrf_change(h, tb[IFLA_LINKINFO], ns_id, name,
					   ctx);
			vrf_id = ifi->ifi_index;
		}

		if (tb[IFLA_MASTER]) {
			if (slave_kind && (strcmp(slave_kind, "vrf") == 0)
			    && !vrf_is_backend_netns()) {
				zif_slave_type = ZEBRA_IF_SLAVE_VRF;
				master_infindex = vrf_id =
					*(uint32_t *)RTA_DATA(tb[IFLA_MASTER]);
			} else if (slave_kind
				   && (strcmp(slave_kind, "bridge") == 0)) {
				zif_slave_type = ZEBRA_IF_SLAVE_BRIDGE;
				master_infindex = bridge_ifindex =
					*(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
			} else if (slave_kind
				   && (strcmp(slave_kind, "bond") == 0)) {
				zif_slave_type = ZEBRA_IF_SLAVE_BOND;
				master_infindex = bond_ifindex =
					*(ifindex_t *)RTA_DATA(tb[IFLA_MASTER]);
				bypass = netlink_parse_lacp_bypass(linkinfo);
			} else
				zif_slave_type = ZEBRA_IF_SLAVE_OTHER;
		}
		dplane_ctx_set_ifp_zif_slave_type(ctx, zif_slave_type);
		dplane_ctx_set_ifp_vrf_id(ctx, vrf_id);
		dplane_ctx_set_ifp_master_ifindex(ctx, master_infindex);
		dplane_ctx_set_ifp_bridge_ifindex(ctx, bridge_ifindex);
		dplane_ctx_set_ifp_bond_ifindex(ctx, bond_ifindex);
		dplane_ctx_set_ifp_bypass(ctx, bypass);
		dplane_ctx_set_ifp_zltype(
			ctx, netlink_to_zebra_link_type(ifi->ifi_type));

		if (vrf_is_backend_netns())
			dplane_ctx_set_ifp_vrf_id(ctx, ns_id);

		dplane_ctx_set_ifp_flags(ctx, ifi->ifi_flags & 0x0000fffff);

		if (tb[IFLA_PROTO_DOWN]) {
			dplane_ctx_set_ifp_protodown_set(ctx, true);
			netlink_proc_dplane_if_protodown(ctx, tb);
		} else
			dplane_ctx_set_ifp_protodown_set(ctx, false);

		netlink_interface_update_hw_addr(tb, ctx);

		/* Extract and save L2 interface information, take
		 * additional actions. */
		netlink_interface_update_l2info(
			ctx, zif_type, linkinfo[IFLA_INFO_DATA], 1, link_nsid);
	} else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("RTM_DELLINK for %s(%u), enqueuing to zebra",
				   name, ifi->ifi_index);

		dplane_ctx_set_op(ctx, DPLANE_OP_INTF_DELETE);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);

		dplane_ctx_set_ifp_bond_ifindex(ctx, bond_ifindex);
	}

	dplane_provider_enqueue_to_zebra(ctx);

	return 0;
}

/**
 * Interface encoding helper function.
 *
 * \param[in] cmd netlink command.
 * \param[in] ctx dataplane context (information snapshot).
 * \param[out] buf buffer to hold the packet.
 * \param[in] buflen amount of buffer bytes.
 */

ssize_t netlink_intf_msg_encode(uint16_t cmd,
				const struct zebra_dplane_ctx *ctx, void *buf,
				size_t buflen)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifa;
		char buf[];
	} *req = buf;

	struct rtattr *nest_protodown_reason;
	ifindex_t ifindex = dplane_ctx_get_ifindex(ctx);
	bool down = dplane_ctx_intf_is_protodown(ctx);
	bool pd_reason_val = dplane_ctx_get_intf_pd_reason_val(ctx);
	struct nlsock *nl =
		kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	if (buflen < sizeof(*req))
		return 0;

	memset(req, 0, sizeof(*req));

	if (cmd != RTM_SETLINK)
		flog_err(
			EC_ZEBRA_INTF_UPDATE_FAILURE,
			"Only RTM_SETLINK message type currently supported in dplane pthread");

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;
	req->n.nlmsg_type = cmd;
	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->ifa.ifi_index = ifindex;

	nl_attr_put8(&req->n, buflen, IFLA_PROTO_DOWN, down);
	nl_attr_put32(&req->n, buflen, IFLA_LINK, ifindex);

	/* Reason info nest */
	nest_protodown_reason =
		nl_attr_nest(&req->n, buflen, IFLA_PROTO_DOWN_REASON);

	if (!nest_protodown_reason)
		return -1;

	nl_attr_put32(&req->n, buflen, IFLA_PROTO_DOWN_REASON_MASK,
		      (1 << if_netlink_get_frr_protodown_r_bit()));
	nl_attr_put32(&req->n, buflen, IFLA_PROTO_DOWN_REASON_VALUE,
		      ((int)pd_reason_val)
			      << if_netlink_get_frr_protodown_r_bit());

	nl_attr_nest_end(&req->n, nest_protodown_reason);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: %s, protodown=%d reason_val=%d ifindex=%u",
			   __func__, nl_msg_type_to_str(cmd), down,
			   pd_reason_val, ifindex);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/* Interface information read by netlink. */
void interface_list(struct zebra_ns *zns)
{
	interface_lookup_netlink(zns);

	zebra_dplane_startup_stage(zns, ZEBRA_DPLANE_INTERFACES_READ);
}

void interface_list_second(struct zebra_ns *zns)
{
	zebra_if_update_all_links(zns);
	/* We add routes for interface address,
	 * so we need to get the nexthop info
	 * from the kernel before we can do that
	 */
	netlink_nexthop_read(zns);

	interface_addr_lookup_netlink(zns);

	zebra_dplane_startup_stage(zns, ZEBRA_DPLANE_ADDRESSES_READ);
}

/**
 * netlink_request_tunneldump() - Request all tunnels from the linux kernel
 *
 * @zns:	Zebra namespace
 * @family:	AF_* netlink family
 * @type:	RTM_* (RTM_GETTUNNEL) route type
 *
 * Return:	Result status
 */
static int netlink_request_tunneldump(struct zebra_ns *zns, int family,
				      int ifindex)
{
	struct {
		struct nlmsghdr n;
		struct tunnel_msg tmsg;
		char buf[256];
	} req;

	/* Form the request */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tunnel_msg));
	req.n.nlmsg_type = RTM_GETTUNNEL;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.tmsg.family = family;
	req.tmsg.ifindex = ifindex;

	return netlink_request(&zns->netlink_cmd, &req);
}

/*
 * Currently we only ask for vxlan l3svd vni information.
 * In the future this can be expanded.
 */
int netlink_tunneldump_read(struct zebra_ns *zns)
{
	int ret = 0;
	struct zebra_dplane_info dp_info;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct nlsock *netlink_cmd = &zns->netlink_cmd;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;

		ret = netlink_request_tunneldump(zns, PF_BRIDGE,
						 tmp_if->ifindex);
		if (ret < 0)
			return ret;

		ret = netlink_parse_info(netlink_link_change, netlink_cmd,
					 &dp_info, 0, true);

		if (ret < 0)
			return ret;
	}

	return 0;
}

static const char *port_state2str(uint8_t state)
{
	switch (state) {
	case BR_STATE_DISABLED:
		return "DISABLED";
	case BR_STATE_LISTENING:
		return "LISTENING";
	case BR_STATE_LEARNING:
		return "LEARNING";
	case BR_STATE_FORWARDING:
		return "FORWARDING";
	case BR_STATE_BLOCKING:
		return "BLOCKING";
	}

	return "UNKNOWN";
}

static void vxlan_vni_state_change(struct zebra_if *zif, uint16_t id,
				   uint8_t state)
{
	struct zebra_vxlan_vni *vnip;

	vnip = zebra_vxlan_if_vlanid_vni_find(zif, id);

	if (!vnip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Cannot find VNI for VID (%u) IF %s for vlan state update",
				id, zif->ifp->name);

		return;
	}

	switch (state) {
	case BR_STATE_FORWARDING:
		zebra_vxlan_if_vni_up(zif->ifp, vnip);
		break;
	case BR_STATE_BLOCKING:
		zebra_vxlan_if_vni_down(zif->ifp, vnip);
		break;
	case BR_STATE_DISABLED:
	case BR_STATE_LISTENING:
	case BR_STATE_LEARNING:
	default:
		/* Not used for anything at the moment */
		break;
	}
}

static void vlan_id_range_state_change(struct interface *ifp, uint16_t id_start,
				       uint16_t id_end, uint8_t state)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;

	if (!zif)
		return;

	for (uint16_t i = id_start; i <= id_end; i++)
		vxlan_vni_state_change(zif, i, state);
}

/**
 * netlink_vlan_change() - Read in change about vlans from the kernel
 *
 * @h:		Netlink message header
 * @ns_id:	Namspace id
 * @startup:	Are we reading under startup conditions?
 *
 * Return:	Result status
 */
int netlink_vlan_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len, rem;
	struct interface *ifp;
	struct br_vlan_msg *bvm;
	struct bridge_vlan_info *vinfo;
	struct rtattr *vtb[BRIDGE_VLANDB_ENTRY_MAX + 1] = {};
	struct rtattr *attr;
	uint8_t state;
	uint32_t vrange;
	int type;

	/* We only care about state changes for now */
	if (!(h->nlmsg_type == RTM_NEWVLAN))
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct br_vlan_msg));
	if (len < 0) {
		zlog_warn(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct br_vlan_msg)));
		return -1;
	}

	bvm = NLMSG_DATA(h);

	if (bvm->family != AF_BRIDGE)
		return 0;

	ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(ns_id), bvm->ifindex);
	if (!ifp) {
		zlog_debug("Cannot find bridge-vlan IF (%u) for vlan update",
			   bvm->ifindex);
		return 0;
	}

	if (!IS_ZEBRA_IF_VXLAN(ifp)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Ignoring non-vxlan IF (%s) for vlan update",
				   ifp->name);

		return 0;
	}

	if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s %s IF %s NS %u",
			   nl_msg_type_to_str(h->nlmsg_type),
			   nl_family_to_str(bvm->family), ifp->name, ns_id);

	/* Loop over "ALL" BRIDGE_VLANDB_ENTRY */
	rem = len;
	for (attr = BRVLAN_RTA(bvm); RTA_OK(attr, rem);
	     attr = RTA_NEXT(attr, rem)) {
		vinfo = NULL;
		vrange = 0;

		type = attr->rta_type & NLA_TYPE_MASK;

		if (type != BRIDGE_VLANDB_ENTRY)
			continue;

		/* Parse nested entry data */
		netlink_parse_rtattr_nested(vtb, BRIDGE_VLANDB_ENTRY_MAX, attr);

		/* It must have info for the ID */
		if (!vtb[BRIDGE_VLANDB_ENTRY_INFO])
			continue;

		vinfo = (struct bridge_vlan_info *)RTA_DATA(
			vtb[BRIDGE_VLANDB_ENTRY_INFO]);

		/*
		 * We only care about state info, if there is none, just ignore
		 * it.
		 */
		if (!vtb[BRIDGE_VLANDB_ENTRY_STATE])
			continue;

		state = *(uint8_t *)RTA_DATA(vtb[BRIDGE_VLANDB_ENTRY_STATE]);

		if (vtb[BRIDGE_VLANDB_ENTRY_RANGE])
			vrange = *(uint32_t *)RTA_DATA(
				vtb[BRIDGE_VLANDB_ENTRY_RANGE]);

		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_VXLAN) {
			if (vrange)
				zlog_debug("VLANDB_ENTRY: VID (%u-%u) state=%s",
					   vinfo->vid, vrange,
					   port_state2str(state));
			else
				zlog_debug("VLANDB_ENTRY: VID (%u) state=%s",
					   vinfo->vid, port_state2str(state));
		}

		vlan_id_range_state_change(
			ifp, vinfo->vid, (vrange ? vrange : vinfo->vid), state);
	}

	return 0;
}

/**
 * netlink_request_vlan() - Request vlan information from the kernel
 * @zns:	Zebra namespace
 * @family:	AF_* netlink family
 * @type:	RTM_* type
 *
 * Return:	Result status
 */
static int netlink_request_vlan(struct zebra_ns *zns, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct br_vlan_msg bvm;
		char buf[256];
	} req;

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct br_vlan_msg));
	req.bvm.family = family;

	nl_attr_put32(&req.n, sizeof(req), BRIDGE_VLANDB_DUMP_FLAGS,
		      BRIDGE_VLANDB_DUMPF_STATS);

	return netlink_request(&zns->netlink_cmd, &req);
}

/**
 * netlink_vlan_read() - Vlan read function using netlink interface
 *
 * @zns:	Zebra name space
 *
 * Return:	Result status
 * Only called at bootstrap time.
 */
int netlink_vlan_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true /*is_cmd*/);

	/* Get bridg vlan info */
	ret = netlink_request_vlan(zns, PF_BRIDGE, RTM_GETVLAN);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_vlan_change, &zns->netlink_cmd,
				 &dp_info, 0, 1);

	return ret;
}

#endif /* GNU_LINUX */
