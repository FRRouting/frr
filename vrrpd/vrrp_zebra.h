/*
 * VRRP Zebra interfacing.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __VRRP_ZEBRA_H__
#define __VRRP_ZEBRA_H__

#include <zebra.h>

#include "lib/if.h"

extern void vrrp_zebra_init(void);
extern void vrrp_zebra_radv_set(struct vrrp_router *r, bool enable);
extern int vrrp_zclient_send_interface_protodown(struct interface *ifp,
						 bool down);

extern int vrrp_ifp_create(struct interface *ifp);
extern int vrrp_ifp_up(struct interface *ifp);
extern int vrrp_ifp_down(struct interface *ifp);
extern int vrrp_ifp_destroy(struct interface *ifp);

#endif /* __VRRP_ZEBRA_H__ */
