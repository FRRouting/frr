/*
 * IS-IS Rout(e)ing protocol               - isis_route.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _ZEBRA_ISIS_ROUTE_H
#define _ZEBRA_ISIS_ROUTE_H

#include "lib/nexthop.h"

struct isis_nexthop {
	ifindex_t ifindex;
	int family;
	union g_addr ip;
	unsigned int lock;
};

struct isis_route_info {
#define ISIS_ROUTE_FLAG_ACTIVE       0x01  /* active route for the prefix */
#define ISIS_ROUTE_FLAG_ZEBRA_SYNCED 0x02  /* set when route synced to zebra */
#define ISIS_ROUTE_FLAG_ZEBRA_RESYNC 0x04  /* set when route needs to sync */
	uint8_t flag;
	uint32_t cost;
	uint32_t depth;
	struct list *nexthops;
};

struct isis_route_info *isis_route_create(struct prefix *prefix,
					  struct prefix_ipv6 *src_p,
					  uint32_t cost,
					  uint32_t depth,
					  struct list *adjacencies,
					  struct isis_area *area,
					  struct route_table *table);

/* Walk the given table and install new routes to zebra and remove old ones.
 * route status is tracked using ISIS_ROUTE_FLAG_ACTIVE */
void isis_route_verify_table(struct isis_area *area,
			     struct route_table *table);

/* Same as isis_route_verify_table, but merge L1 and L2 routes before */
void isis_route_verify_merge(struct isis_area *area,
			     struct route_table *level1_table,
			     struct route_table *level2_table);

/* Unset ISIS_ROUTE_FLAG_ACTIVE on all routes. Used before running spf. */
void isis_route_invalidate_table(struct isis_area *area,
				 struct route_table *table);

#endif /* _ZEBRA_ISIS_ROUTE_H */
