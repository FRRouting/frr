// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Header file exported by ge_netlink.c to zebra.
 * Copyright (C) 2022, Carmine Scarpitta
 */

#ifndef _ZEBRA_GE_NETLINK_H
#define _ZEBRA_GE_NETLINK_H

#include "zebra_dplane.h"

#ifdef HAVE_NETLINK

#include <linux/genetlink.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic Netlink request message */
struct genl_request {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[1024];
};

extern int genl_resolve_family(const char *family);
extern ssize_t netlink_sr_tunsrc_set_msg_encode(int cmd,
						struct zebra_dplane_ctx *ctx,
						void *buf, size_t buflen);
extern ssize_t netlink_sr_tunsrc_set_msg_encoder(struct zebra_dplane_ctx *ctx,
						 void *buf, size_t buflen);
struct nl_batch;
extern enum netlink_msg_status
netlink_put_sr_tunsrc_set_msg(struct nl_batch *bth,
			      struct zebra_dplane_ctx *ctx);

int netlink_sr_tunsrc_reply_read(struct nlmsghdr *h, ns_id_t ns_id, int startup);
int netlink_sr_tunsrc_read(struct zebra_ns *zns);

extern void ge_netlink_init(struct zebra_ns *zns);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_GE_NETLINK_H */
