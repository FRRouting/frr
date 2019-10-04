/*
 * Zebra connect library for staticd
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
 */
#ifndef __STATIC_ZEBRA_H__
#define __STATIC_ZEBRA_H__

extern struct thread_master *master;

extern void static_zebra_nht_register(struct route_node *rn,
				      struct static_route *si, bool reg);

extern void static_zebra_route_add(struct route_node *rn,
				   struct static_route *si_changed,
				   vrf_id_t vrf_id, safi_t safi, bool install);
extern void static_zebra_init(void);
extern void static_zebra_vrf_register(struct vrf *vrf);
extern void static_zebra_vrf_unregister(struct vrf *vrf);

#endif
