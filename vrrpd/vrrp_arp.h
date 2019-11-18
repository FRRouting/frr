/*
 * VRRP ARP handling.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __VRRP_ARP_H__
#define __VRRP_ARP_H__

#include <zebra.h>

#include "vrrp.h"

/* FIXME: Use the kernel define for this */
#define HWTYPE_ETHER 1

extern void vrrp_garp_init(void);
extern void vrrp_garp_fini(void);
extern bool vrrp_garp_is_init(void);
extern void vrrp_garp_send(struct vrrp_router *vr, struct in_addr *v4);
extern void vrrp_garp_send_all(struct vrrp_router *vr);

#endif /* __VRRP_ARP_H__ */
