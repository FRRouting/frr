/*
 * netconf_netlink.h - netconf interaction with the kernel using
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
