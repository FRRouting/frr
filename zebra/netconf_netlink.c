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
	return (struct rtattr *)((char *)ncm +
				 NLMSG_ALIGN(sizeof(struct netconfmsg)));
}

/*
 * Handle netconf update about a single interface: create dplane
 * context, and enqueue for processing in the main zebra pthread.
 */
static int netlink_netconf_dplane_update(ns_id_t ns_id, ifindex_t ifindex,
					 enum dplane_netconf_status_e mpls_on,
					 enum dplane_netconf_status_e mcast_on)
{
	struct zebra_dplane_ctx *ctx;

	ctx = dplane_ctx_alloc();
	dplane_ctx_set_op(ctx, DPLANE_OP_INTF_NETCONFIG);
	dplane_ctx_set_netconf_ns_id(ctx, ns_id);
	dplane_ctx_set_netconf_ifindex(ctx, ifindex);

	dplane_ctx_set_netconf_mpls(ctx, mpls_on);
	dplane_ctx_set_netconf_mcast(ctx, mcast_on);

	/* Enqueue ctx for main pthread to process */
	dplane_provider_enqueue_to_zebra(ctx);

	return 0;
}

/*
 * Parse and process an incoming netlink netconf update.
 */
int netlink_netconf_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct netconfmsg *ncm;
	struct rtattr *tb[NETCONFA_MAX + 1] = {};
	int len;
	ifindex_t ifindex;
	uint32_t ival;
	enum dplane_netconf_status_e mpls_on = DPLANE_NETCONF_STATUS_UNKNOWN;
	enum dplane_netconf_status_e mcast_on = DPLANE_NETCONF_STATUS_UNKNOWN;

	if (h->nlmsg_type != RTM_NEWNETCONF && h->nlmsg_type != RTM_DELNETCONF)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct netconfmsg));
	if (len < 0) {
		zlog_err("%s: Message received from netlink is of a broken size: %d, min %zu",
			 __func__, h->nlmsg_len,
			 (size_t)NLMSG_LENGTH(sizeof(struct netconfmsg)));
		return -1;
	}

	ncm = NLMSG_DATA(h);

	netlink_parse_rtattr(tb, NETCONFA_MAX, netconf_rta(ncm), len);

	if (!tb[NETCONFA_IFINDEX]) {
		zlog_err("NETCONF message received from netlink without an ifindex");
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
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: Ignoring global ifindex %d",
				   __func__, ifindex);

		return 0;
	default:
		break;
	}

	if (tb[NETCONFA_INPUT]) {
		ival = *(uint32_t *)RTA_DATA(tb[NETCONFA_INPUT]);
		if (ival != 0)
			mpls_on = DPLANE_NETCONF_STATUS_ENABLED;
		else
			mpls_on = DPLANE_NETCONF_STATUS_DISABLED;
	}

	if (tb[NETCONFA_MC_FORWARDING]) {
		ival = *(uint32_t *)RTA_DATA(tb[NETCONFA_MC_FORWARDING]);
		if (ival != 0)
			mcast_on = DPLANE_NETCONF_STATUS_ENABLED;
		else
			mcast_on = DPLANE_NETCONF_STATUS_DISABLED;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: interface %u is mpls on: %d multicast on: %d",
			   __func__, ifindex, mpls_on, mcast_on);

	/* Create a dplane context and pass it along for processing */
	netlink_netconf_dplane_update(ns_id, ifindex, mpls_on, mcast_on);

	return 0;
}

/*
 * Request info from the host OS. This only sends the request; any replies
 * are processed asynchronously.
 */
int netlink_request_netconf(int sockfd)
{
	struct nlsock *nls;
	struct {
		struct nlmsghdr n;
		struct netconfmsg ncm;
		char buf[1024];
	} req = {};

	nls = kernel_netlink_nlsock_lookup(sockfd);

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: nlsock %s", __func__, nls ? nls->name : "NULL");

	if (nls == NULL)
		return -1;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct netconfmsg));
	req.n.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETNETCONF;
	req.ncm.ncm_family = AF_UNSPEC;

	return netlink_request(nls, &req);
}

#endif	/* HAVE_NETLINK */
