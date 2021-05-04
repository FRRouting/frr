/*
 * netconf_netlink.c - netconf interaction with the kernel using
 * netlink
 * Copyright (C) 2021  Nvidia, Inc.
 *                     Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#ifdef HAVE_NETLINK /* Netlink OSes only */

#include <ns.h>

#include "linux/netconf.h"

#include "zebra/zebra_ns.h"
#include "zebra/zebra_dplane.h"
#include "zebra/kernel_netlink.h"
#include "zebra/netconf_netlink.h"
#include "zebra/debug.h"

static struct rtattr *netconf_rta(struct netconfmsg *ncm)
{
	return (struct rtattr *)((char *)ncm
				 + NLMSG_ALIGN(sizeof(struct netconfmsg)));
}

int netlink_netconf_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct netconfmsg *ncm;
	struct rtattr *tb[NETCONFA_MAX + 1] = {};
	int len;
	ifindex_t ifindex;
	bool mpls_on = false;
	bool mc_on = false;

	if (h->nlmsg_type != RTM_NEWNETCONF && h->nlmsg_type != RTM_DELNETCONF)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct netconfmsg));
	if (len < 0) {
		zlog_err("%s: Message received from netlink is of a broken size: %d %zu",
			 __func__, h->nlmsg_len,
			 (size_t)NLMSG_LENGTH(sizeof(struct netconfmsg)));
		return -1;
	}

	ncm = NLMSG_DATA(h);

	netlink_parse_rtattr(tb, NETCONFA_MAX, netconf_rta(ncm), len);

	if (!tb[NETCONFA_IFINDEX]) {
		zlog_err("%s: Message received from netlink that we expected to receive an interface on",
			__func__);
		return 0;
	}

	ifindex = *(ifindex_t *)RTA_DATA(tb[NETCONFA_IFINDEX]);

	switch (ifindex) {
	case NETCONFA_IFINDEX_ALL:
	case NETCONFA_IFINDEX_DEFAULT:
		/*
		 * We need the ability to handle netlink messages intended
		 * for all and default interfaces.  I am not 100% sure
		 * what that is yet, or where we would store it.
		 */
		return 0;
	default:
		break;
	}
	if (tb[NETCONFA_INPUT]) {
		mpls_on = *(bool *)RTA_DATA(tb[NETCONFA_INPUT]);
		/* Create a context and pass it up for processing */
	}

	if (tb[NETCONFA_MC_FORWARDING]) {
		mc_on = *(bool *)RTA_DATA(tb[NETCONFA_MC_FORWARDING]);
		/* Create a context and pass it up for processing */
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("Interface %u is mpls on: %d multicast on: %d",
			   ifindex, mpls_on, mc_on);

	return 0;
}

static int netlink_request_netconf(struct nlsock *netlink_cmd)
{
	struct {
		struct nlmsghdr n;
		struct netconfmsg ncm;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct netconfmsg));
	req.n.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETNETCONF;
	req.ncm.ncm_family = AF_UNSPEC;

	return netlink_request(netlink_cmd, &req);
}

int netconf_lookup_netlink(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;
	struct nlsock *netlink_cmd = &zns->netlink_cmd;

	zebra_dplane_info_from_zns(&dp_info, zns, true);

	ret = netlink_request_netconf(netlink_cmd);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_netconf_change, netlink_cmd, &dp_info,
				 0, 1);
	return ret;
}

#endif	/* HAVE_NETLINK */
