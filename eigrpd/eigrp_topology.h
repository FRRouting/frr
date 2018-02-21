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

/* EIGRP Topology table related functions. */
extern struct route_table *eigrp_topology_new(void);
extern void eigrp_topology_init(struct route_table *table);
extern struct eigrp_prefix_entry *eigrp_prefix_entry_new(void);
extern struct eigrp_nexthop_entry *eigrp_nexthop_entry_new(void);
extern void eigrp_topology_free(struct route_table *table);
extern void eigrp_topology_cleanup(struct route_table *table);
extern void eigrp_prefix_entry_add(struct route_table *table,
				   struct eigrp_prefix_entry *pe);
extern void eigrp_nexthop_entry_add(struct eigrp_prefix_entry *,
				    struct eigrp_nexthop_entry *);
extern void eigrp_prefix_entry_delete(struct route_table *table,
				      struct eigrp_prefix_entry *pe);
extern void eigrp_nexthop_entry_delete(struct eigrp_prefix_entry *,
				       struct eigrp_nexthop_entry *);
extern void eigrp_topology_delete_all(struct route_table *table);
extern unsigned int eigrp_topology_table_isempty(struct list *);
extern struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4(struct route_table *table, struct prefix *p);
extern struct list *eigrp_topology_get_successor(struct eigrp_prefix_entry *);
extern struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_entry *pe,
				 unsigned int maxpaths);
extern struct eigrp_nexthop_entry *
eigrp_prefix_entry_lookup(struct list *, struct eigrp_neighbor *);
extern struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *,
						   struct eigrp_neighbor *);
extern void eigrp_topology_update_all_node_flags(struct eigrp *);
extern void eigrp_topology_update_node_flags(struct eigrp_prefix_entry *);
extern enum metric_change
eigrp_topology_update_distance(struct eigrp_fsm_action_message *);
extern void eigrp_update_routing_table(struct eigrp_prefix_entry *);
extern void eigrp_topology_neighbor_down(struct eigrp *,
					 struct eigrp_neighbor *);
extern void eigrp_update_topology_table_prefix(struct route_table *table,
					       struct eigrp_prefix_entry *pe);

#endif
