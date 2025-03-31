// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * netconf_netlink.c - netconf interaction with the kernel using
 * netlink
 * Copyright (C) 2021  Nvidia, Inc.
 *                     Donald Sharp
 */
#include <zebra.h>
#include <fcntl.h>

#ifdef HAVE_NETLINK /* Netlink OSes only */

#include <ns.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "linux/netconf.h"

#include "lib/lib_errors.h"
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
static int
netlink_netconf_dplane_update(ns_id_t ns_id, afi_t afi, ifindex_t ifindex,
			      enum dplane_netconf_status_e mpls_on,
			      enum dplane_netconf_status_e mcast_on,
			      enum dplane_netconf_status_e linkdown_on)
{
	struct zebra_dplane_ctx *ctx;

	ctx = dplane_ctx_alloc();
	dplane_ctx_set_op(ctx, DPLANE_OP_INTF_NETCONFIG);
	dplane_ctx_set_ns_id(ctx, ns_id);
	dplane_ctx_set_afi(ctx, afi);
	dplane_ctx_set_ifindex(ctx, ifindex);

	dplane_ctx_set_netconf_mpls(ctx, mpls_on);
	dplane_ctx_set_netconf_mcast(ctx, mcast_on);
	dplane_ctx_set_netconf_linkdown(ctx, linkdown_on);

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
	afi_t afi;
	enum dplane_netconf_status_e mpls_on = DPLANE_NETCONF_STATUS_UNKNOWN;
	enum dplane_netconf_status_e mcast_on = DPLANE_NETCONF_STATUS_UNKNOWN;
	enum dplane_netconf_status_e linkdown_on =
		DPLANE_NETCONF_STATUS_UNKNOWN;

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

	/*
	 * FRR does not have an internal representation of afi_t for
	 * the MPLS Address Family that the kernel has.  So let's
	 * just call it v4.  This is ok because the kernel appears
	 * to do a good job of not sending data that is mixed/matched
	 * across families
	 */
#ifdef AF_MPLS
	if (ncm->ncm_family == AF_MPLS)
		afi = AFI_IP;
	else
#endif /* AF_MPLS */
		afi = family2afi(ncm->ncm_family);

	netlink_parse_rtattr(tb, NETCONFA_MAX, netconf_rta(ncm), len);

	if (!tb[NETCONFA_IFINDEX]) {
		zlog_err("NETCONF message received from netlink without an ifindex");
		return 0;
	}

	ifindex = *(ifindex_t *)RTA_DATA(tb[NETCONFA_IFINDEX]);

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

	if (tb[NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN]) {
		ival = *(uint32_t *)RTA_DATA(
			tb[NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN]);
		if (ival != 0)
			linkdown_on = DPLANE_NETCONF_STATUS_ENABLED;
		else
			linkdown_on = DPLANE_NETCONF_STATUS_DISABLED;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"%s: interface %u is mpls on: %d multicast on: %d linkdown: %d",
			__func__, ifindex, mpls_on, mcast_on, linkdown_on);

	/* Create a dplane context and pass it along for processing */
	netlink_netconf_dplane_update(ns_id, afi, ifindex, mpls_on, mcast_on,
				      linkdown_on);

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

extern struct zebra_privs_t zserv_privs;
/*
 * Currently netconf has no ability to set from netlink.
 * So we've received a request to do this work in the data plane.
 * as such we need to set the value via the /proc system
 */
enum netlink_msg_status netlink_put_intf_netconfig(struct nl_batch *bth,
						   struct zebra_dplane_ctx *ctx)
{
	const char *ifname = dplane_ctx_get_ifname(ctx);
	enum dplane_netconf_status_e mpls_on = dplane_ctx_get_netconf_mpls(ctx);
	char set[64];
	char mpls_proc[PATH_MAX];
	int fd, ret = FRR_NETLINK_ERROR;

	snprintf(mpls_proc, sizeof(mpls_proc),
		 "/proc/sys/net/mpls/conf/%s/input", ifname);

	if (mpls_on == DPLANE_NETCONF_STATUS_ENABLED)
		snprintf(set, sizeof(set), "1\n");
	else if (mpls_on == DPLANE_NETCONF_STATUS_DISABLED)
		snprintf(set, sizeof(set), "0\n");
	else {
		flog_err_sys(
			EC_LIB_DEVELOPMENT,
			"%s: Expected interface %s to be set to ENABLED or DISABLED was %d",
			__func__, ifname, mpls_on);
		return ret;
	}

	frr_with_privs (&zserv_privs) {
		fd = open(mpls_proc, O_WRONLY);
		if (fd < 0) {
			flog_err_sys(
				EC_LIB_SOCKET,
				"%s: Unable to open %s for writing: %s(%d)",
				__func__, mpls_proc, safe_strerror(errno),
				errno);
			return ret;
		}
		if (write(fd, set, 2) == 2)
			ret = FRR_NETLINK_SUCCESS;
		else
			flog_err_sys(EC_LIB_SOCKET,
				     "%s: Unsuccessful write to %s: %s(%d)",
				     __func__, mpls_proc, safe_strerror(errno),
				     errno);
		close(fd);
	}
	return ret;
}

#endif	/* HAVE_NETLINK */
