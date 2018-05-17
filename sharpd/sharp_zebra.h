/*
 * Zebra connect library for SHARP
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __SHARP_ZEBRA_H__
#define __SHARP_ZEBRA_H__

extern void sharp_zebra_init(void);

extern void vrf_label_add(vrf_id_t vrf_id, afi_t afi, mpls_label_t label);
extern void route_add(struct prefix *p, uint8_t instance, struct nexthop *nh);
extern void route_delete(struct prefix *p, uint8_t instance);
extern void sharp_zebra_nexthop_watch(struct prefix *p, bool watch);
#endif
