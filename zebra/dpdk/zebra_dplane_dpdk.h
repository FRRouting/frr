// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 */

#ifndef _ZEBRA_DPLANE_DPDK_H
#define _ZEBRA_DPLANE_DPDK_H

#include <zebra.h>


#define ZD_DPDK_INVALID_PORT 0xffff

extern void zd_dpdk_pbr_flows_show(struct vty *vty);
extern void zd_dpdk_port_show(struct vty *vty, uint16_t port_id, bool uj,
			      int detail);
extern void zd_dpdk_stat_show(struct vty *vty);
extern void zd_dpdk_vty_init(void);

extern struct zebra_privs_t zserv_privs;

#endif
