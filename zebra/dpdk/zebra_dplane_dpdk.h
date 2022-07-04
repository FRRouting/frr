/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

#endif
