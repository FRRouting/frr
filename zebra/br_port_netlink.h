// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#ifndef _ZEBRA_BR_PORT_NETLINK_H
#define _ZEBRA_BR_PORT_NETLINK_H

#include "lib/if.h"
#include "lib/prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_dplane_ctx;
struct nl_batch;

int zebra_br_port_test_func(void);
extern enum netlink_msg_status
netlink_put_br_port_msg(struct nl_batch *bth,
			      struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_BR_PORT_NETLINK_H */
