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

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "vty.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_memory.h"

static int eigrp_route_descriptor_cmp(struct eigrp_route_descriptor *,
				   struct eigrp_route_descriptor *);

/*
 * Returns linkedlist used as topology table
 * cmp - assigned function for comparing topology nodes
 * del - assigned function executed before deleting topology node by list
 * function
 */
struct route_table *eigrp_topology_new()
{
	return route_table_init();
}

/*
 * Returns new created toplogy node
 * cmp - assigned function for comparing topology entry
 */
struct eigrp_prefix_descriptor *eigrp_prefix_descriptor_new()
{
	struct eigrp_prefix_descriptor *new;
	new = XCALLOC(MTYPE_EIGRP_PREFIX_DESCRIPTOR,
		      sizeof(struct eigrp_prefix_descriptor));
	new->entries = list_new();
	new->rij = list_new();
	new->entries->cmp = (int (*)(void *, void *))eigrp_route_descriptor_cmp;
	new->distance = new->fdistance = new->rdistance = EIGRP_MAX_METRIC;
	new->destination = NULL;

	return new;
}

/*
 * Topology entry comparison
 */
static int eigrp_route_descriptor_cmp(struct eigrp_route_descriptor *route1,
				   struct eigrp_route_descriptor *route2)
{
	if (route1->distance < route2->distance)
		return -1;
	if (route1->distance > route2->distance)
		return 1;

	return 0;
}

/*
 * Returns new topology entry
 */

struct eigrp_route_descriptor *eigrp_route_descriptor_new()
{
	struct eigrp_route_descriptor *new;

	new = XCALLOC(MTYPE_EIGRP_ROUTE_DESCRIPTOR,
		      sizeof(struct eigrp_route_descriptor));
	new->reported_distance = EIGRP_MAX_METRIC;
	new->distance = EIGRP_MAX_METRIC;

	return new;
}

/*
 * Freeing topology table list
 */
void eigrp_topology_free(struct route_table *table)
{
	route_table_finish(table);
}

/*
 * Deleting all topology nodes in table
 */
void eigrp_topology_cleanup(struct route_table *table)
{
	eigrp_topology_delete_all(table);
}

/*
 * Adding topology node to topology table
 */
void eigrp_prefix_descriptor_add(struct route_table *topology,
			    struct eigrp_prefix_descriptor *pe)
{
	struct route_node *rn;

	rn = route_node_get(topology, pe->destination);
	if (rn->info) {
		if (IS_DEBUG_EIGRP_EVENT) {
			char buf[PREFIX_STRLEN];

			zlog_debug(
				"%s: %s Should we have found this entry in the topo table?",
				__PRETTY_FUNCTION__,
				prefix2str(pe->destination, buf, sizeof(buf)));
		}
	}

	rn->info = pe;
	route_lock_node(rn);
}

/*
 * Adding topology entry to topology node
 */
void eigrp_route_descriptor_add(struct eigrp_prefix_descriptor *node,
			     struct eigrp_route_descriptor *route)
{
	struct list *l = list_new();

	listnode_add(l, route);

	if (listnode_lookup(node->entries, route) == NULL) {
		listnode_add_sort(node->entries, route);
		route->prefix = node;

		eigrp_zebra_route_add(node->destination, l);
	}

	list_delete_and_null(&l);
}

/*
 * Deleting topology node from topology table
 */
void eigrp_prefix_descriptor_delete(struct route_table *table,
			       struct eigrp_prefix_descriptor *pe)
{
	struct eigrp *eigrp = eigrp_lookup();
	struct route_node *rn;

	if (!eigrp)
		return;

	rn = route_node_lookup(table, pe->destination);
	if (!rn)
		return;

	/*
	 * Emergency removal of the node from this list.
	 * Whatever it is.
	 */
	listnode_delete(eigrp->topology_changes_internalIPV4, pe);

	list_delete_and_null(&pe->entries);
	list_delete_and_null(&pe->rij);
	eigrp_zebra_route_delete(pe->destination);

	rn->info = NULL;
	route_unlock_node(rn); // Lookup above
	route_unlock_node(rn); // Initial creation
	XFREE(MTYPE_EIGRP_PREFIX_DESCRIPTOR, pe);
}

/*
 * Deleting topology entry from topology node
 */
void eigrp_route_descriptor_delete(struct eigrp_prefix_descriptor *node,
				struct eigrp_route_descriptor *route)
{
	if (listnode_lookup(node->entries, route) != NULL) {
		listnode_delete(node->entries, route);
		eigrp_zebra_route_delete(node->destination);
		XFREE(MTYPE_EIGRP_ROUTE_DESCRIPTOR, route);
	}
}

/*
 * Deleting all nodes from topology table
 */
void eigrp_topology_delete_all(struct route_table *topology)
{
	struct route_node *rn;
	struct eigrp_prefix_descriptor *pe;

	for (rn = route_top(topology); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_prefix_descriptor_delete(topology, pe);
	}
}

/*
 * Return 0 if topology is not empty
 * otherwise return 1
 */
unsigned int eigrp_topology_table_isempty(struct list *topology)
{
	if (topology->count)
		return 1;
	else
		return 0;
}

struct eigrp_prefix_descriptor *
eigrp_topology_table_lookup_ipv4(struct route_table *table,
				 struct prefix *address)
{
	struct eigrp_prefix_descriptor *pe;
	struct route_node *rn;

	rn = route_node_lookup(table, address);
	if (!rn)
		return NULL;

	pe = rn->info;

	route_unlock_node(rn);

	return pe;
}

/*
 * For a future optimization, put the successor list into it's
 * own separate list from the full list?
 *
 * That way we can clean up all the list_new and list_delete's
 * that we are doing.  DBS
 */
struct list *eigrp_topology_get_successor(struct eigrp_prefix_descriptor *table_node)
{
	struct list *successors = list_new();
	struct eigrp_route_descriptor *data;
	struct listnode *node1, *node2;

	for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
		if (data->flags & EIGRP_ROUTE_SUCCESSOR_FLAG) {
			listnode_add(successors, data);
		}
	}

	/*
	 * If we have no successors return NULL
	 */
	if (!successors->count) {
		list_delete_and_null(&successors);
		successors = NULL;
	}

	return successors;
}

struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_descriptor *table_node,
				 unsigned int maxpaths)
{
	struct list *successors = eigrp_topology_get_successor(table_node);

	if (successors && successors->count > maxpaths) {
		do {
			struct listnode *node = listtail(successors);

			list_delete_node(successors, node);

		} while (successors->count > maxpaths);
	}

	return successors;
}

struct eigrp_route_descriptor *
eigrp_prefix_descriptor_lookup(struct list *entries, struct eigrp_neighbor *nbr)
{
	struct eigrp_route_descriptor *data;
	struct listnode *node, *nnode;
	for (ALL_LIST_ELEMENTS(entries, node, nnode, data)) {
		if (data->adv_router == nbr) {
			return data;
		}
	}

	return NULL;
}

/* Lookup all prefixes from specified neighbor */
struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *eigrp,
					    struct eigrp_neighbor *nbr)
{
	struct listnode *node2, *node22;
	struct eigrp_route_descriptor *route;
	struct eigrp_prefix_descriptor *pe;
	struct route_node *rn;

	/* create new empty list for prefixes storage */
	struct list *prefixes = list_new();

	/* iterate over all prefixes in topology table */
	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		pe = rn->info;
		/* iterate over all neighbor entry in prefix */
		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, route)) {
			/* if route is from specified neighbor, add to list */
			if (route->adv_router == nbr) {
				listnode_add(prefixes, pe);
			}
		}
	}

	/* return list of prefixes from specified neighbor */
	return prefixes;
}

enum metric_change
eigrp_topology_update_distance(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_descriptor *prefix = msg->prefix;
	struct eigrp_route_descriptor *route = msg->route;
	enum metric_change change = METRIC_SAME;
	uint32_t new_reported_distance;

	assert(route);

	switch (msg->data_type) {
	case EIGRP_CONNECTED:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED)
			return change;

		change = METRIC_DECREASE;
		break;
	case EIGRP_INT:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED) {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		if (eigrp_metrics_is_same(msg->metrics,
					  route->reported_metric)) {
			return change; // No change
		}

		new_reported_distance =
			eigrp_calculate_metrics(eigrp, msg->metrics);

		if (route->reported_distance < new_reported_distance) {
			change = METRIC_INCREASE;
			goto distance_done;
		} else
			change = METRIC_DECREASE;

		route->reported_metric = msg->metrics;
		route->reported_distance = new_reported_distance;
		eigrp_calculate_metrics(eigrp, msg->metrics);
		route->distance = eigrp_calculate_total_metrics(eigrp, route);
		break;
	case EIGRP_EXT:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL) {
			if (eigrp_metrics_is_same(msg->metrics,
						  route->reported_metric))
				return change;
		} else {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		break;
	default:
		zlog_err("%s: Please implement handler", __PRETTY_FUNCTION__);
		break;
	}
distance_done:
	/*
	 * Move to correct position in list according to new distance
	 */
	listnode_delete(prefix->entries, route);
	listnode_add_sort(prefix->entries, route);

	return change;
}

void eigrp_topology_update_all_node_flags(struct eigrp *eigrp)
{
	struct eigrp_prefix_descriptor *pe;
	struct route_node *rn;

	if (!eigrp)
		return;

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_topology_update_node_flags(pe);
	}
}

void eigrp_topology_update_node_flags(struct eigrp_prefix_descriptor *dest)
{
	struct listnode *node;
	struct eigrp_route_descriptor *route;
	struct eigrp *eigrp = eigrp_lookup();

	assert(eigrp);

	for (ALL_LIST_ELEMENTS_RO(dest->entries, node, route)) {
		if (route->reported_distance < dest->fdistance) {
			// is feasible successor, can be successor
			if (((uint64_t)route->distance
			     <= (uint64_t)dest->distance
					* (uint64_t)eigrp->variance)
			    && route->distance != EIGRP_MAX_METRIC) {
				// is successor
				route->flags |=
					EIGRP_ROUTE_SUCCESSOR_FLAG;
				route->flags &=
					~EIGRP_ROUTE_FSUCCESSOR_FLAG;
			} else {
				// is feasible successor only
				route->flags |=
					EIGRP_ROUTE_FSUCCESSOR_FLAG;
				route->flags &=
					~EIGRP_ROUTE_SUCCESSOR_FLAG;
			}
		} else {
			route->flags &= ~EIGRP_ROUTE_FSUCCESSOR_FLAG;
			route->flags &= ~EIGRP_ROUTE_SUCCESSOR_FLAG;
		}
	}
}

void eigrp_update_routing_table(struct eigrp_prefix_descriptor *prefix)
{
	struct eigrp *eigrp = eigrp_lookup();
	struct list *successors;
	struct listnode *node;
	struct eigrp_route_descriptor *route;

	if (!eigrp)
		return;

	successors = eigrp_topology_get_successor_max(prefix, eigrp->max_paths);

	if (successors) {
		eigrp_zebra_route_add(prefix->destination, successors);
		for (ALL_LIST_ELEMENTS_RO(successors, node, route))
			route->flags |= EIGRP_ROUTE_INTABLE_FLAG;

		list_delete_and_null(&successors);
	} else {
		eigrp_zebra_route_delete(prefix->destination);
		for (ALL_LIST_ELEMENTS_RO(prefix->entries, node, route))
			route->flags &= ~EIGRP_ROUTE_INTABLE_FLAG;
	}
}

void eigrp_topology_neighbor_down(struct eigrp *eigrp,
				  struct eigrp_neighbor *nbr)
{
	struct listnode *node2, *node22;
	struct eigrp_prefix_descriptor *pe;
	struct eigrp_route_descriptor *route;
	struct route_node *rn;

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, route)) {
			struct eigrp_fsm_action_message msg;

			if (route->adv_router != nbr)
				continue;

			msg.metrics.delay = EIGRP_MAX_METRIC;
			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.route = route;
			msg.prefix = pe;
			eigrp_fsm_event(&msg);
		}
	}

	eigrp_query_send_all(eigrp);
	eigrp_update_send_all(eigrp, nbr->ei);
}

void eigrp_update_topology_table_prefix(struct route_table *table,
					struct eigrp_prefix_descriptor *prefix)
{
	struct listnode *node1, *node2;

	struct eigrp_route_descriptor *route;
	for (ALL_LIST_ELEMENTS(prefix->entries, node1, node2, route)) {
		if (route->distance == EIGRP_MAX_METRIC) {
			eigrp_route_descriptor_delete(prefix, route);
		}
	}
	if (prefix->distance == EIGRP_MAX_METRIC
	    && prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
		eigrp_prefix_descriptor_delete(table, prefix);
	}
}
