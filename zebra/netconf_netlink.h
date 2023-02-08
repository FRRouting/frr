// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * netconf_netlink.h - netconf interaction with the kernel using
 * netlink
 * Copyright (C) 2021  Nvidia, Inc.
 *                     Donald Sharp
 */
#ifndef __NETCONF_NETLINK_H__
#define __NETCONF_NETLINK_H__

#ifdef HAVE_NETLINK /* Netlink-only module */

#include "zebra/zebra_ns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse and handle a NETCONF message. */
extern int netlink_netconf_change(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);
/* Request info from the host OS. */
int netlink_request_netconf(int sockfd);

struct nl_batch;

extern enum netlink_msg_status
netlink_put_intf_netconfig(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif	/* HAVE_NETLINK */

#endif	/* NETCONF_NETLINK_H */
