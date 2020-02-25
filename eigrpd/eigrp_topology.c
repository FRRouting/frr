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
#include "lib_errors.h"

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

static int eigrp_nexthop_entry_cmp(struct eigrp_nexthop_entry *,
				   struct eigrp_nexthop_entry *);

/*
 * Returns linkedlist used as topology table
 * cmp - assigned function for comparing topology nodes
 * del - assigned function executed before deleting topology node by list
 * function
 */
struct route_table *eigrp_topology_new(void)
{
	return route_table_init();
}

/*
 * Returns new created toplogy node
 * cmp - assigned function for comparing topology entry
 */
struct eigrp_prefix_entry *eigrp_prefix_entry_new(void)
{
	struct eigrp_prefix_entry *new;
	new = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
		      sizeof(struct eigrp_prefix_entry));
	new->entries = list_new();
	new->rij = list_new();
	new->entries->cmp = (int (*)(void *, void *))eigrp_nexthop_entry_cmp;
	new->distance = new->fdistance = new->rdistance = EIGRP_MAX_METRIC;
	new->destination = NULL;

	return new;
}

/*
 * Topology entry comparison
 */
static int eigrp_nexthop_entry_cmp(struct eigrp_nexthop_entry *entry1,
				   struct eigrp_nexthop_entry *entry2)
{
	if (entry1->distance < entry2->distance)
		return -1;
	if (entry1->distance > entry2->distance)
		return 1;

	return 0;
}

/*
 * Returns new topology entry
 */

struct eigrp_nexthop_entry *eigrp_nexthop_entry_new(void)
{
	struct eigrp_nexthop_entry *new;

	new = XCALLOC(MTYPE_EIGRP_NEXTHOP_ENTRY,
		      sizeof(struct eigrp_nexthop_entry));
	new->reported_distance = EIGRP_MAX_METRIC;
	new->distance = EIGRP_MAX_METRIC;

	return new;
}

/*
 * Freeing topology table list
 */
void eigrp_topology_free(struct eigrp *eigrp, struct route_table *table)
{
	eigrp_topology_delete_all(eigrp, table);
	route_table_finish(table);
}

/*
 * Adding topology node to topology table
 */
void eigrp_prefix_entry_add(struct route_table *topology,
			    struct eigrp_prefix_entry *pe)
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
		route_unlock_node(rn);
	}

	rn->info = pe;
}

/*
 * Adding topology entry to topology node
 */
void eigrp_nexthop_entry_add(struct eigrp *eigrp,
			     struct eigrp_prefix_entry *node,
			     struct eigrp_nexthop_entry *entry)
{
	struct list *l = list_new();

	listnode_add(l, entry);

	if (listnode_lookup(node->entries, entry) == NULL) {
		listnode_add_sort(node->entries, entry);
		entry->prefix = node;

		eigrp_zebra_route_add(eigrp, node->destination,
				      l, node->fdistance);
	}

	list_delete(&l);
}

/*
 * Deleting topology node from topology table
 */
void eigrp_prefix_entry_delete(struct eigrp *eigrp, struct route_table *table,
			       struct eigrp_prefix_entry *pe)
{
	struct eigrp_nexthop_entry *ne;
	struct listnode *node, *nnode;
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

	for (ALL_LIST_ELEMENTS(pe->entries, node, nnode, ne))
		eigrp_nexthop_entry_delete(eigrp, pe, ne);
	list_delete(&pe->entries);
	list_delete(&pe->rij);
	eigrp_zebra_route_delete(eigrp, pe->destination);
	prefix_free(&pe->destination);

	rn->info = NULL;
	route_unlock_node(rn); // Lookup above
	route_unlock_node(rn); // Initial creation
	XFREE(MTYPE_EIGRP_PREFIX_ENTRY, pe);
}

/*
 * Deleting topology entry from topology node
 */
void eigrp_nexthop_entry_delete(struct eigrp *eigrp,
				struct eigrp_prefix_entry *node,
				struct eigrp_nexthop_entry *entry)
{
	if (listnode_lookup(node->entries, entry) != NULL) {
		listnode_delete(node->entries, entry);
		eigrp_zebra_route_delete(eigrp, node->destination);
		XFREE(MTYPE_EIGRP_NEXTHOP_ENTRY, entry);
	}
}

/*
 * Deleting all nodes from topology table
 */
void eigrp_topology_delete_all(struct eigrp *eigrp,
			       struct route_table *topology)
{
	struct route_node *rn;
	struct eigrp_prefix_entry *pe;

	for (rn = route_top(topology); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_prefix_entry_delete(eigrp, topology, pe);
	}
}

struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4(struct route_table *table,
				 struct prefix *address)
{
	struct eigrp_prefix_entry *pe;
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
struct list *eigrp_topology_get_successor(struct eigrp_prefix_entry *table_node)
{
	struct list *successors = list_new();
	struct eigrp_nexthop_entry *data;
	struct listnode *node1, *node2;

	for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
		if (data->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG) {
			listnode_add(successors, data);
		}
	}

	/*
	 * If we have no successors return NULL
	 */
	if (!successors->count) {
		list_delete(&successors);
		successors = NULL;
	}

	return successors;
}

struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_entry *table_node,
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

struct eigrp_nexthop_entry *
eigrp_prefix_entry_lookup(struct list *entries, struct eigrp_neighbor *nbr)
{
	struct eigrp_nexthop_entry *data;
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
	struct eigrp_nexthop_entry *entry;
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	/* create new empty list for prefixes storage */
	struct list *prefixes = list_new();

	/* iterate over all prefixes in topology table */
	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		pe = rn->info;
		/* iterate over all neighbor entry in prefix */
		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, entry)) {
			/* if entry is from specified neighbor, add to list */
			if (entry->adv_router == nbr) {
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
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *entry = msg->entry;
	enum metric_change change = METRIC_SAME;
	uint32_t new_reported_distance;

	assert(entry);

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
					  entry->reported_metric)) {
			return change; // No change
		}

		new_reported_distance =
			eigrp_calculate_metrics(eigrp, msg->metrics);

		if (entry->reported_distance < new_reported_distance) {
			change = METRIC_INCREASE;
			goto distance_done;
		} else
			change = METRIC_DECREASE;

		entry->reported_metric = msg->metrics;
		entry->reported_distance = new_reported_distance;
		eigrp_calculate_metrics(eigrp, msg->metrics);
		entry->distance = eigrp_calculate_total_metrics(eigrp, entry);
		break;
	case EIGRP_EXT:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL) {
			if (eigrp_metrics_is_same(msg->metrics,
						  entry->reported_metric))
				return change;
		} else {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: Please implement handler",
			 __PRETTY_FUNCTION__);
		break;
	}
distance_done:
	/*
	 * Move to correct position in list according to new distance
	 */
	listnode_delete(prefix->entries, entry);
	listnode_add_sort(prefix->entries, entry);

	return change;
}

void eigrp_topology_update_all_node_flags(struct eigrp *eigrp)
{
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	if (!eigrp)
		return;

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_topology_update_node_flags(eigrp, pe);
	}
}

void eigrp_topology_update_node_flags(struct eigrp *eigrp,
				      struct eigrp_prefix_entry *dest)
{
	struct listnode *node;
	struct eigrp_nexthop_entry *entry;

	for (ALL_LIST_ELEMENTS_RO(dest->entries, node, entry)) {
		if (entry->reported_distance < dest->fdistance) {
			// is feasible successor, can be successor
			if (((uint64_t)entry->distance
			     <= (uint64_t)dest->distance
					* (uint64_t)eigrp->variance)
			    && entry->distance != EIGRP_MAX_METRIC) {
				// is successor
				entry->flags |=
					EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
				entry->flags &=
					~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			} else {
				// is feasible successor only
				entry->flags |=
					EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
				entry->flags &=
					~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
			}
		} else {
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
		}
	}
}

void eigrp_update_routing_table(struct eigrp *eigrp,
				struct eigrp_prefix_entry *prefix)
{
	struct list *successors;
	struct listnode *node;
	struct eigrp_nexthop_entry *entry;

	successors = eigrp_topology_get_successor_max(prefix, eigrp->max_paths);

	if (successors) {
		eigrp_zebra_route_add(eigrp, prefix->destination, successors,
				      prefix->fdistance);
		for (ALL_LIST_ELEMENTS_RO(successors, node, entry))
			entry->flags |= EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;

		list_delete(&successors);
	} else {
		eigrp_zebra_route_delete(eigrp, prefix->destination);
		for (ALL_LIST_ELEMENTS_RO(prefix->entries, node, entry))
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
	}
}

void eigrp_topology_neighbor_down(struct eigrp *eigrp,
				  struct eigrp_neighbor *nbr)
{
	struct listnode *node2, *node22;
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *entry;
	struct route_node *rn;

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, entry)) {
			struct eigrp_fsm_action_message msg;

			if (entry->adv_router != nbr)
				continue;

			msg.metrics.delay = EIGRP_MAX_METRIC;
			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.entry = entry;
			msg.prefix = pe;
			eigrp_fsm_event(&msg);
		}
	}

	eigrp_query_send_all(eigrp);
	eigrp_update_send_all(eigrp, nbr->ei);
}

void eigrp_update_topology_table_prefix(struct eigrp *eigrp,
					struct route_table *table,
					struct eigrp_prefix_entry *prefix)
{
	struct listnode *node1, *node2;

	struct eigrp_nexthop_entry *entry;
	for (ALL_LIST_ELEMENTS(prefix->entries, node1, node2, entry)) {
		if (entry->distance == EIGRP_MAX_METRIC) {
			eigrp_nexthop_entry_delete(eigrp, prefix, entry);
		}
	}
	if (prefix->distance == EIGRP_MAX_METRIC
	    && prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
		eigrp_prefix_entry_delete(eigrp, table, prefix);
	}
}
