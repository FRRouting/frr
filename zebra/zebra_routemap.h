/*
 * Zebra routemap header
 * Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __ZEBRA_ROUTEMAP_H__
#define __ZEBRA_ROUTEMAP_H__

#include "lib/routemap.h"

extern void zebra_route_map_init(void);
extern void zebra_routemap_config_write_protocol(struct vty *vty);
extern char *zebra_get_import_table_route_map(afi_t afi, uint32_t table);
extern void zebra_add_import_table_route_map(afi_t afi, const char *rmap_name,
					     uint32_t table);
extern void zebra_del_import_table_route_map(afi_t afi, uint32_t table);

extern void zebra_route_map_write_delay_timer(struct vty *);

extern route_map_result_t
zebra_import_table_route_map_check(int family, int rib_type, uint8_t instance,
				   struct prefix *p, struct nexthop *nexthop,
				   vrf_id_t vrf_id, route_tag_t tag,
				   const char *rmap_name);
extern route_map_result_t
zebra_route_map_check(int family, int rib_type, uint8_t instance,
		      struct prefix *p, struct nexthop *nexthop,
		      vrf_id_t vrf_id, route_tag_t tag);
extern route_map_result_t
zebra_nht_route_map_check(int family, int client_proto, struct prefix *p,
			  struct route_entry *, struct nexthop *nexthop);


#endif
