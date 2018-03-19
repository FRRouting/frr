/*
 * Zebra connect library for PBR
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#ifndef __PBR_ZEBRA_H__
#define __PBR_ZEBRA_H__

struct pbr_interface {
	char mapname[100];
};

extern struct thread_master *master;

extern void pbr_zebra_init(void);

extern void route_add(struct pbr_nexthop_group_cache *pnhgc,
		      struct nexthop_group nhg, afi_t install_afi);
extern void route_delete(struct pbr_nexthop_group_cache *pnhgc,
			 afi_t install_afi);

extern void pbr_send_rnh(struct nexthop *nhop, bool reg);

extern void pbr_send_pbr_map(struct pbr_map_sequence *pbrms,
			     struct pbr_map_interface *pmi, bool install);

extern struct pbr_interface *pbr_if_new(struct interface *ifp);
#endif
