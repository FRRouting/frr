// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */

#include <zebra.h>

#include <linux/rtnetlink.h>

#include <zebra/zebra_kernel_capabilities.h>

#ifdef HAVE_NETLINK

#define _LINUX_IN6_H
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>

#include <lib/ns.h>

#include <zebra/table_manager.h>
#include <zebra/rt.h>
#include <zebra/zebra_dplane.h>
#include <zebra/rt_netlink.h>
#include <zebra/kernel_netlink.h>

#define LOG_UNSUPPORTED_SRV6_SEG6LOCAL_DT6_VRFTABLE()                                              \
	zlog_err("%s: SEG6LOCAL DT6 routes with VRFTABLE is NOT supported", __func__)
#define LOG_SUPPORTED_SRV6_SEG6LOCAL_DT6_VRFTABLE()                                                \
	zlog_info("%s: SEG6LOCAL DT6 routes with VRFTABLE is supported", __func__)
#define CHECK_SRV6_ATTR_L3VRF_TABLE	9999999
#define CHECK_SRV6_ATTR_L3VRF_INTERFACE "6wsrv6l3vrf"
#define CHECK_SRV6_ATTR_PREFIX_STR	"2001:db8:efff::"
#define CHECK_SRV6_DUMMY_INTERFACE	"6wsrv6dummy"

static bool check_srv6_seg6local_dt6_vrftable_attr_supported_in_progress;
static bool check_srv6_seg6local_dt6_vrftable_attr_supported;

static bool configure_fake_l3vrf(struct zebra_ns *zns, bool add_l3vrf)
{
	int buflen = NL_PKT_BUF_SIZE;
	struct rtattr *rta_info, *rta_vrf;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};

	/* create a temp L3VRF device */
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	if (add_l3vrf) {
		req.n.nlmsg_type = RTM_NEWLINK;
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

		req.ifi.ifi_change = IFF_UP;
		req.ifi.ifi_flags = IFF_UP;
	} else {
		req.n.nlmsg_type = RTM_DELLINK;
	}

	if (!nl_attr_put(&req.n, buflen, IFLA_IFNAME, CHECK_SRV6_ATTR_L3VRF_INTERFACE,
			 strlen(CHECK_SRV6_ATTR_L3VRF_INTERFACE) + 1))
		goto configure_fake_vrf_error;

	if (!add_l3vrf) {
		if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
			goto configure_fake_vrf_error;
		return true;
	}

	rta_info = nl_attr_nest(&req.n, buflen, IFLA_LINKINFO);
	if (!rta_info)
		goto configure_fake_vrf_error;

	if (!nl_attr_put(&req.n, buflen, IFLA_INFO_KIND, "vrf", 4))
		goto configure_fake_vrf_error;

	rta_vrf = nl_attr_nest(&req.n, buflen, IFLA_INFO_DATA);
	if (!rta_vrf)
		goto configure_fake_vrf_error;

	if (!nl_attr_put32(&req.n, buflen, IFLA_VRF_TABLE, CHECK_SRV6_ATTR_L3VRF_TABLE))
		goto configure_fake_vrf_error;

	nl_attr_nest_end(&req.n, rta_vrf);

	nl_attr_nest_end(&req.n, rta_info);

	if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
		goto configure_fake_vrf_error;

	check_srv6_seg6local_dt6_vrftable_attr_supported_in_progress = true;

	return true;

configure_fake_vrf_error:
	return false;
}

static int check_srv6_attr_netlink_talk_func(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct rtmsg *rtm;
	struct rtattr *rta, *rta_encap = NULL;
	size_t plen;
	size_t msglen;
	size_t rta_encap_len = 0;
	struct in6_addr *p, in6_p;
	uint16_t tunnel_type = LWTUNNEL_ENCAP_NONE;

	if (h->nlmsg_type != RTM_NEWROUTE)
		return 0;
	rtm = NLMSG_DATA(h);
	msglen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
	rta = RTM_RTA(rtm);
next_rta_for_rta_encap:
	if (RTA_OK(rta, msglen) == 0)
		return 0;

	plen = RTA_PAYLOAD(rta);
	if (((rta->rta_type & NLA_TYPE_MASK) != RTA_ENCAP) &&
	    ((rta->rta_type & NLA_TYPE_MASK) != RTA_ENCAP_TYPE) &&
	    ((rta->rta_type & NLA_TYPE_MASK) != RTA_DST)) {
		rta = RTA_NEXT(rta, msglen);
		goto next_rta_for_rta_encap;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_DST) {
		p = RTA_DATA(rta);
		inet_pton(AF_INET6, CHECK_SRV6_ATTR_PREFIX_STR, &in6_p);
		if (!IPV6_ADDR_SAME(p, &in6_p))
			return 0;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_ENCAP_TYPE) {
		tunnel_type = *(uint16_t *)RTA_DATA(rta);
		if (tunnel_type != LWTUNNEL_ENCAP_SEG6_LOCAL)
			return 0;
	}
	if ((rta->rta_type & NLA_TYPE_MASK) == RTA_ENCAP) {
		rta_encap_len = plen;
		rta_encap = RTA_DATA(rta);
	}
	if (rta_encap == NULL || tunnel_type == LWTUNNEL_ENCAP_NONE) {
		rta = RTA_NEXT(rta, msglen);
		goto next_rta_for_rta_encap;
	}

next_rta_encap_inspection:
	if (RTA_OK(rta_encap, rta_encap_len) == 0)
		return 0;
	if ((rta_encap->rta_type & NLA_TYPE_MASK) == SEG6_LOCAL_ACTION) {
		check_srv6_seg6local_dt6_vrftable_attr_supported = true;
		return 0;
	}
	rta_encap = RTA_NEXT(rta_encap, rta_encap_len);
	goto next_rta_encap_inspection;

	return 0;
}

static bool handle_fake_srv6_seg6local_route(struct zebra_ns *zns, int type, struct interface *ifp)
{
	int datalen = NL_PKT_BUF_SIZE;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};
	struct prefix p = {};
	struct rtattr *rta_encap;

	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	inet_pton(p.family, CHECK_SRV6_ATTR_PREFIX_STR, &p.u.prefix6);

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = type;
	if (type == RTM_NEWROUTE)
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;

	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.r.rtm_family = p.family;
	req.r.rtm_dst_len = p.prefixlen;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_table = RT_TABLE_MAIN;

	if (!nl_attr_put(&req.n, datalen, RTA_DST, &p.u.prefix6, sizeof(struct in6_addr)))
		goto error_fake_srv6_seg6local_route;

	if (type == RTM_DELROUTE) {
		if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
			goto error_fake_srv6_seg6local_route;
		return true;
	}

	req.r.rtm_type = RTN_UNICAST;
	req.r.rtm_protocol = RTPROT_ZEBRA;

	if (!nl_attr_put32(&req.n, datalen, RTA_OIF, ifp->ifindex))
		goto error_fake_srv6_seg6local_route;

	if (type == RTM_GETROUTE) {
		/* the passed function will check for SEG6_LOCAL_ACTION netlink_attr parameter */
		if (netlink_talk(check_srv6_attr_netlink_talk_func, &req.n, &zns->netlink_cmd, zns,
				 0))
			goto error_fake_srv6_seg6local_route;
		return true;
	}

	if (!nl_attr_put32(&req.n, datalen, RTA_OIF, ifp->ifindex))
		goto error_fake_srv6_seg6local_route;

	if (type == RTM_GETROUTE) {
		/* the passed function will check the below parameters:
		 * LWTUNNEL_ENCAP_SEG6_LOCAL and SEG6_LOCAL_ACTION
		 */
		if (netlink_talk(check_srv6_attr_netlink_talk_func, &req.n, &zns->netlink_cmd, zns,
				 0))
			goto error_fake_srv6_seg6local_route;
		return true;
	}

	if (!nl_attr_put16(&req.n, datalen, RTA_ENCAP_TYPE, LWTUNNEL_ENCAP_SEG6_LOCAL))
		goto error_fake_srv6_seg6local_route;

	rta_encap = nl_attr_nest(&req.n, datalen, RTA_ENCAP);
	if (!rta_encap)
		goto error_fake_srv6_seg6local_route;

	if (!nl_attr_put32(&req.n, datalen, SEG6_LOCAL_ACTION, SEG6_LOCAL_ACTION_END_DT6))
		goto error_fake_srv6_seg6local_route;

	if (!nl_attr_put32(&req.n, datalen, SEG6_LOCAL_VRFTABLE, CHECK_SRV6_ATTR_L3VRF_TABLE))
		goto error_fake_srv6_seg6local_route;

	nl_attr_nest_end(&req.n, rta_encap);

	if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
		goto error_fake_srv6_seg6local_route;

	check_srv6_seg6local_dt6_vrftable_attr_supported = true;
	return true;

error_fake_srv6_seg6local_route:
	return false;
}

static bool check_srv6_interfaces_configured(bool create)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	if (!zns || zns->netlink_cmd.sock == -1)
		return false;

	if (!zebra_kernel_capabilities_configure_interface(zns, CHECK_SRV6_DUMMY_INTERFACE, create))
		return false;

	if (!configure_fake_l3vrf(zns, true)) {
		zebra_kernel_capabilities_configure_interface(zns, CHECK_SRV6_DUMMY_INTERFACE,
							      false);
		return false;
	}
	return true;
}

bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname,
						   bool add_iface)
{
	int buflen = NL_PKT_BUF_SIZE;
	struct rtattr *rta_info;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;
	if (add_iface) {
		req.n.nlmsg_type = RTM_NEWLINK;
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		req.ifi.ifi_change = IFF_UP;
		req.ifi.ifi_flags = IFF_UP;
	} else {
		req.n.nlmsg_type = RTM_DELLINK;
	}

	if (!nl_attr_put(&req.n, buflen, IFLA_IFNAME, ifname, strlen(ifname) + 1))
		return false;

	if (!add_iface) {
		if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
			return false;
		return true;
	}

	rta_info = nl_attr_nest(&req.n, buflen, IFLA_LINKINFO);
	if (!rta_info)
		return false;

	if (!nl_attr_put(&req.n, buflen, IFLA_INFO_KIND, "dummy", 6))
		return false;

	nl_attr_nest_end(&req.n, rta_info);

	if (netlink_talk(netlink_talk_filter, &req.n, &zns->netlink_cmd, zns, 0))
		return false;

	return true;
}

void zebra_kernel_capabilities_init(void)
{
	check_srv6_seg6local_dt6_vrftable_attr_supported_in_progress = false;
	check_srv6_seg6local_dt6_vrftable_attr_supported = false;

	/* create the necessary interfaces to start the probing
	 * for srv6 capabilities check
	 */
	if (!check_srv6_interfaces_configured(true))
		LOG_UNSUPPORTED_SRV6_SEG6LOCAL_DT6_VRFTABLE();
}

/*
 * called upon interface creation
 * check that probe l3vrf interface CHECK_SRV6_ATTR_L3VRF_INTERFACE is created
 */
void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp)
{
	struct zebra_ns *zns;
	struct interface *ifp_dummy;
	static bool supported_func_done = false;

	/* no need to check for dummy interface creation; only the last interface created is enough */
	if (strncmp(ifp->name, CHECK_SRV6_ATTR_L3VRF_INTERFACE,
		    strlen(CHECK_SRV6_ATTR_L3VRF_INTERFACE) + 1))
		return;

	if (supported_func_done)
		/* avoid multiple events from the same interface if probing is over */
		return;

	zns = zebra_ns_lookup(NS_DEFAULT);
	if (!zns || zns->netlink_cmd.sock == -1)
		goto netlink_error;

	ifp_dummy = if_lookup_by_name(CHECK_SRV6_DUMMY_INTERFACE, VRF_DEFAULT);
	if (!ifp_dummy)
		goto netlink_error;

	if (!check_srv6_seg6local_dt6_vrftable_attr_supported_in_progress)
		return;

	if (check_srv6_seg6local_dt6_vrftable_attr_supported)
		return;

	check_srv6_seg6local_dt6_vrftable_attr_supported_in_progress = false;

	if (!handle_fake_srv6_seg6local_route(zns, RTM_NEWROUTE, ifp_dummy))
		goto netlink_error;

	if (!handle_fake_srv6_seg6local_route(zns, RTM_GETROUTE, ifp_dummy))
		goto netlink_error;

	if (check_srv6_seg6local_dt6_vrftable_attr_supported)
		LOG_SUPPORTED_SRV6_SEG6LOCAL_DT6_VRFTABLE();
	else
		LOG_UNSUPPORTED_SRV6_SEG6LOCAL_DT6_VRFTABLE();

	handle_fake_srv6_seg6local_route(zns, RTM_DELROUTE, NULL);

netlink_error:
	supported_func_done = true;
	check_srv6_interfaces_configured(false);
}

bool zebra_kernel_capabilities_is_srv6_seg6local_dt6_vrftable_attr_supported(void)
{
	return check_srv6_seg6local_dt6_vrftable_attr_supported;
}

#else

bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname,
						   bool add_iface)
{
	return false;
}

void zebra_kernel_capabilities_init(void)
{
}

void zebra_kernel_capabilities_interface_created_cb(struct interface *ifp)
{
}

bool zebra_kernel_capabilities_is_srv6_seg6local_dt6_vrftable_attr_supported(void)
{
	return false;
}

#endif /* HAVE_NETLINK */
