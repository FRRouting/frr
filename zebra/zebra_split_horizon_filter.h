// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Split Horizon Filter implementation
 * Copyright (c) 2026 VyOS Inc
 * Kyrylo Yatsenko
 */

#ifndef _ZEBRA_SPLIT_HORIZON_FILTER_H
#define _ZEBRA_SPLIT_HORIZON_FILTER_H

#include "lib/if.h"
#include "lib/prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_dplane_ctx;
struct nl_batch;

extern enum netlink_msg_status
sph_process_br_port_msg(struct nl_batch *bth,
		       struct zebra_dplane_ctx *ctx);

extern enum netlink_msg_status
sph_process_uplink_add_msg(struct nl_batch *bth,
			   struct zebra_dplane_ctx *ctx);

extern enum netlink_msg_status
sph_process_uplink_delete_msg(struct nl_batch *bth,
				 struct zebra_dplane_ctx *ctx);

extern enum netlink_msg_status
sph_process_es_delete_msg(struct nl_batch *bth,
			     struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SPLIT_HORIZON_FILTER_H */
