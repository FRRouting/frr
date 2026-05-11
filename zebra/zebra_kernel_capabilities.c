// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */

#include <zebra.h>

#include <linux/rtnetlink.h>

#include <zebra/zebra_kernel_capabilities.h>

#ifdef HAVE_NETLINK

#include <lib/ns.h>
#include <zebra/zebra_dplane.h>
#include <zebra/kernel_netlink.h>

bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname)
{
	int buflen = NL_PKT_BUF_SIZE;
	struct rtattr *rta_info;
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
		char buf[NL_PKT_BUF_SIZE];
	} req = {};

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.ifi.ifi_change = IFF_UP;
	req.ifi.ifi_flags = IFF_UP;

	if (!nl_attr_put(&req.n, buflen, IFLA_IFNAME, ifname, strlen(ifname) + 1))
		return false;

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

#else

bool zebra_kernel_capabilities_configure_interface(struct zebra_ns *zns, const char *ifname)
{
	return false;
}

#endif /* HAVE_NETLINK */
