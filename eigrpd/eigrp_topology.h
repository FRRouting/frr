/*
 * EIGRP Topology Table.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
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

#ifndef _ZEBRA_EIGRP_TOPOLOGY_H
#define _ZEBRA_EIGRP_TOPOLOGY_H

#include "memory.h"

DECLARE_MTYPE(EIGRP_PREFIX_DESCRIPTOR);

/* EIGRP Topology table related functions. */
extern struct route_table *eigrp_topology_new(void);
extern void eigrp_topology_init(struct route_table *table);
extern struct eigrp_prefix_descriptor *eigrp_prefix_descriptor_new(void);
extern struct eigrp_route_descriptor *eigrp_route_descriptor_new(void);
extern void eigrp_topology_free(struct eigrp *eigrp, struct route_table *table);
extern void eigrp_prefix_descriptor_add(struct route_table *table,
					struct eigrp_prefix_descriptor *pe);
extern void eigrp_route_descriptor_add(struct eigrp *eigrp,
				       struct eigrp_prefix_descriptor *pe,
				       struct eigrp_route_descriptor *ne);
extern void eigrp_prefix_descriptor_delete(struct eigrp *eigrp,
					   struct route_table *table,
					   struct eigrp_prefix_descriptor *pe);
extern void eigrp_route_descriptor_delete(struct eigrp *eigrp,
					  struct eigrp_prefix_descriptor *pe,
					  struct eigrp_route_descriptor *ne);
extern void eigrp_topology_delete_all(struct eigrp *eigrp,
				      struct route_table *table);
extern struct eigrp_prefix_descriptor *
eigrp_topology_table_lookup_ipv4(struct route_table *table, struct prefix *p);
extern struct list *
eigrp_topology_get_successor(struct eigrp_prefix_descriptor *pe);
extern struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_descriptor *pe,
				 unsigned int maxpaths);
extern struct eigrp_route_descriptor *
eigrp_route_descriptor_lookup(struct list *entries,
			      struct eigrp_neighbor *neigh);
extern struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *eigrp,
						   struct eigrp_neighbor *n);
extern void eigrp_topology_update_all_node_flags(struct eigrp *eigrp);
extern void
eigrp_topology_update_node_flags(struct eigrp *eigrp,
				 struct eigrp_prefix_descriptor *pe);
extern enum metric_change
eigrp_topology_update_distance(struct eigrp_fsm_action_message *msg);
extern void eigrp_update_routing_table(struct eigrp *eigrp,
				       struct eigrp_prefix_descriptor *pe);
extern void eigrp_topology_neighbor_down(struct eigrp *eigrp,
					 struct eigrp_neighbor *neigh);
extern void
eigrp_update_topology_table_prefix(struct eigrp *eigrp,
				   struct route_table *table,
				   struct eigrp_prefix_descriptor *pe);

#endif
