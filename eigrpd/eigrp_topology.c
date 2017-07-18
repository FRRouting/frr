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

static int eigrp_prefix_entry_cmp(struct eigrp_prefix_entry *,
				  struct eigrp_prefix_entry *);
static void eigrp_prefix_entry_del(struct eigrp_prefix_entry *);
static int eigrp_neighbor_entry_cmp(struct eigrp_neighbor_entry *,
				    struct eigrp_neighbor_entry *);

/*
 * Returns linkedlist used as topology table
 * cmp - assigned function for comparing topology nodes
 * del - assigned function executed before deleting topology node by list
 * function
 */
struct list *eigrp_topology_new()
{
	struct list *new = list_new();
	new->cmp = (int (*)(void *, void *))eigrp_prefix_entry_cmp;
	new->del = (void (*)(void *))eigrp_prefix_entry_del;

	return new;
}

/*
 * Topology node comparison
 */

static int eigrp_prefix_entry_cmp(struct eigrp_prefix_entry *node1,
				  struct eigrp_prefix_entry *node2)
{
	if (node1->af == AF_INET) {
		if (node2->af == AF_INET) {
			if (node1->destination_ipv4->prefix.s_addr
			    < node2->destination_ipv4->prefix.s_addr) {
				return -1; // if it belong above node2
			} else {
				if (node1->destination_ipv4->prefix.s_addr
				    > node2->destination_ipv4->prefix.s_addr) {
					return 1; // if it belongs under node2
				} else {
					return 0; // same value... ERROR...in
						  // case of adding same prefix
						  // again
				}
			}
		} else {
			return 1;
		}
	} else {	  // TODO check if the prefix dont exists
		return 1; // add to end
	}
}

/*
 * Topology node delete
 */

static void eigrp_prefix_entry_del(struct eigrp_prefix_entry *node)
{
	list_delete_all_node(node->entries);
	list_free(node->entries);
}

/*
 * Returns new created toplogy node
 * cmp - assigned function for comparing topology entry
 */
struct eigrp_prefix_entry *eigrp_prefix_entry_new()
{
	struct eigrp_prefix_entry *new;
	new = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
		      sizeof(struct eigrp_prefix_entry));
	new->entries = list_new();
	new->rij = list_new();
	new->entries->cmp = (int (*)(void *, void *))eigrp_neighbor_entry_cmp;
	new->distance = new->fdistance = new->rdistance = EIGRP_MAX_METRIC;
	new->destination_ipv4 = NULL;
	new->destination_ipv6 = NULL;

	return new;
}

/*
 * Topology entry comparison
 */
static int eigrp_neighbor_entry_cmp(struct eigrp_neighbor_entry *entry1,
				    struct eigrp_neighbor_entry *entry2)
{
	if (entry1->distance
	    < entry2->distance) // parameter used in list_add_sort ()
		return -1;      // actually set to sort by distance
	if (entry1->distance > entry2->distance)
		return 1;

	return 0;
}

/*
 * Returns new topology entry
 */

struct eigrp_neighbor_entry *eigrp_neighbor_entry_new()
{
	struct eigrp_neighbor_entry *new;

	new = XCALLOC(MTYPE_EIGRP_NEIGHBOR_ENTRY,
		      sizeof(struct eigrp_neighbor_entry));
	new->reported_distance = EIGRP_MAX_METRIC;
	new->distance = EIGRP_MAX_METRIC;

	return new;
}

/*
 * Freeing topology table list
 */
void eigrp_topology_free(struct list *list)
{
	list_free(list);
}

/*
 * Deleting all topology nodes in table
 */
void eigrp_topology_cleanup(struct list *topology)
{
	assert(topology);

	eigrp_topology_delete_all(topology);
}

/*
 * Adding topology node to topology table
 */
void eigrp_prefix_entry_add(struct list *topology,
			    struct eigrp_prefix_entry *node)
{
	if (listnode_lookup(topology, node) == NULL) {
		listnode_add_sort(topology, node);
	}
}

/*
 * Adding topology entry to topology node
 */
void eigrp_neighbor_entry_add(struct eigrp_prefix_entry *node,
			      struct eigrp_neighbor_entry *entry)
{
	struct list *l = list_new();

	listnode_add(l, entry);

	if (listnode_lookup(node->entries, entry) == NULL) {
		listnode_add_sort(node->entries, entry);
		entry->prefix = node;

		eigrp_zebra_route_add(node->destination_ipv4, l);
	}

	list_delete(l);
}

/*
 * Deleting topology node from topology table
 */
void eigrp_prefix_entry_delete(struct list *topology,
			       struct eigrp_prefix_entry *node)
{
	struct eigrp *eigrp = eigrp_lookup();

	/*
	 * Emergency removal of the node from this list.
	 * Whatever it is.
	 */
	listnode_delete(eigrp->topology_changes_internalIPV4, node);

	if (listnode_lookup(topology, node) != NULL) {
		list_delete_all_node(node->entries);
		list_free(node->entries);
		list_free(node->rij);
		listnode_delete(topology, node);
		eigrp_zebra_route_delete(node->destination_ipv4);
		XFREE(MTYPE_EIGRP_PREFIX_ENTRY, node);
	}
}

/*
 * Deleting topology entry from topology node
 */
void eigrp_neighbor_entry_delete(struct eigrp_prefix_entry *node,
				 struct eigrp_neighbor_entry *entry)
{
	if (listnode_lookup(node->entries, entry) != NULL) {
		listnode_delete(node->entries, entry);
		eigrp_zebra_route_delete(node->destination_ipv4);
		XFREE(MTYPE_EIGRP_NEIGHBOR_ENTRY, entry);
	}
}

/*
 * Deleting all nodes from topology table
 */
void eigrp_topology_delete_all(struct list *topology)
{
	list_delete_all_node(topology);
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

struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4(struct list *topology_table,
				 struct prefix_ipv4 *address)
{
	struct eigrp_prefix_entry *data;
	struct listnode *node;
	for (ALL_LIST_ELEMENTS_RO(topology_table, node, data)) {
		if ((data->af == AF_INET)
		    && (data->destination_ipv4->prefix.s_addr
			== address->prefix.s_addr)
		    && (data->destination_ipv4->prefixlen
			== address->prefixlen))
			return data;
	}

	return NULL;
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
	struct eigrp_neighbor_entry *data;
	struct listnode *node1, *node2;

	for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
		if (data->flags & EIGRP_NEIGHBOR_ENTRY_SUCCESSOR_FLAG) {
			listnode_add(successors, data);
		}
	}

	/*
	 * If we have no successors return NULL
	 */
	if (!successors->count) {
		list_delete(successors);
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

struct eigrp_neighbor_entry *
eigrp_prefix_entry_lookup(struct list *entries, struct eigrp_neighbor *nbr)
{
	struct eigrp_neighbor_entry *data;
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
	struct listnode *node1, *node11, *node2, *node22;
	struct eigrp_prefix_entry *prefix;
	struct eigrp_neighbor_entry *entry;

	/* create new empty list for prefixes storage */
	struct list *prefixes = list_new();

	/* iterate over all prefixes in topology table */
	for (ALL_LIST_ELEMENTS(eigrp->topology_table, node1, node11, prefix)) {
		/* iterate over all neighbor entry in prefix */
		for (ALL_LIST_ELEMENTS(prefix->entries, node2, node22, entry)) {
			/* if entry is from specified neighbor, add to list */
			if (entry->adv_router == nbr) {
				listnode_add(prefixes, prefix);
			}
		}
	}

	/* return list of prefixes from specified neighbor */
	return prefixes;
}

int eigrp_topology_update_distance(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_neighbor_entry *entry = msg->entry;
	int change = 0;
	assert(entry);

	struct TLV_IPv4_External_type *ext_data = NULL;
	struct TLV_IPv4_Internal_type *int_data = NULL;
	if (msg->data_type == EIGRP_TLV_IPv4_INT) {
		int_data = msg->data.ipv4_int_type;
		if (eigrp_metrics_is_same(int_data->metric,
					  entry->reported_metric)) {
			return 0; // No change
		}
		change = entry->reported_distance
					 < eigrp_calculate_metrics(
						   eigrp, int_data->metric)
				 ? 1
				 : entry->reported_distance
						   > eigrp_calculate_metrics(
							     eigrp,
							     int_data->metric)
					   ? 2
					   : 3; // Increase : Decrease : No
						// change
		entry->reported_metric = int_data->metric;
		entry->reported_distance =
			eigrp_calculate_metrics(eigrp, int_data->metric);
		entry->distance = eigrp_calculate_total_metrics(eigrp, entry);
	} else {
		ext_data = msg->data.ipv4_ext_data;
		if (eigrp_metrics_is_same(ext_data->metric,
					  entry->reported_metric))
			return 0;
	}
	/*
	 * Move to correct position in list according to new distance
	 */
	listnode_delete(prefix->entries, entry);
	listnode_add_sort(prefix->entries, entry);

	return change;
}

void eigrp_topology_update_all_node_flags(struct eigrp *eigrp)
{
	struct list *table = eigrp->topology_table;
	struct eigrp_prefix_entry *data;
	struct listnode *node, *nnode;
	for (ALL_LIST_ELEMENTS(table, node, nnode, data)) {
		eigrp_topology_update_node_flags(data);
	}
}

void eigrp_topology_update_node_flags(struct eigrp_prefix_entry *dest)
{
	struct listnode *node;
	struct eigrp_neighbor_entry *entry;
	struct eigrp *eigrp = eigrp_lookup();

	for (ALL_LIST_ELEMENTS_RO(dest->entries, node, entry)) {
		if (((uint64_t)entry->distance
		     <= (uint64_t)(dest->distance * eigrp->variance))
		    && entry->distance != EIGRP_MAX_METRIC) // is successor
		{
			entry->flags |= EIGRP_NEIGHBOR_ENTRY_SUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEIGHBOR_ENTRY_FSUCCESSOR_FLAG;
		} else if (entry->reported_distance
			   < dest->fdistance) // is feasible successor
		{
			entry->flags |= EIGRP_NEIGHBOR_ENTRY_FSUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEIGHBOR_ENTRY_SUCCESSOR_FLAG;
		} else {
			entry->flags &= ~EIGRP_NEIGHBOR_ENTRY_FSUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEIGHBOR_ENTRY_SUCCESSOR_FLAG;
		}
	}
}

void eigrp_update_routing_table(struct eigrp_prefix_entry *prefix)
{
	struct eigrp *eigrp = eigrp_lookup();
	struct list *successors =
		eigrp_topology_get_successor_max(prefix, eigrp->max_paths);
	struct listnode *node;
	struct eigrp_neighbor_entry *entry;

	if (successors) {
		eigrp_zebra_route_add(prefix->destination_ipv4, successors);
		for (ALL_LIST_ELEMENTS_RO(successors, node, entry))
			entry->flags |= EIGRP_NEIGHBOR_ENTRY_INTABLE_FLAG;

		list_delete(successors);
	} else {
		eigrp_zebra_route_delete(prefix->destination_ipv4);
		for (ALL_LIST_ELEMENTS_RO(prefix->entries, node, entry))
			entry->flags &= ~EIGRP_NEIGHBOR_ENTRY_INTABLE_FLAG;
	}
}

void eigrp_topology_neighbor_down(struct eigrp *eigrp,
				  struct eigrp_neighbor *nbr)
{
	struct listnode *node1, *node11, *node2, *node22;
	struct eigrp_prefix_entry *prefix;
	struct eigrp_neighbor_entry *entry;

	for (ALL_LIST_ELEMENTS(eigrp->topology_table, node1, node11, prefix)) {
		for (ALL_LIST_ELEMENTS(prefix->entries, node2, node22, entry)) {
			if (entry->adv_router == nbr) {
				struct eigrp_fsm_action_message *msg;
				msg = XCALLOC(MTYPE_EIGRP_FSM_MSG,
					      sizeof(struct
						     eigrp_fsm_action_message));
				struct TLV_IPv4_Internal_type *tlv =
					eigrp_IPv4_InternalTLV_new();
				tlv->metric.delay = EIGRP_MAX_METRIC;
				msg->packet_type = EIGRP_OPC_UPDATE;
				msg->eigrp = eigrp;
				msg->data_type = EIGRP_TLV_IPv4_INT;
				msg->adv_router = nbr;
				msg->data.ipv4_int_type = tlv;
				msg->entry = entry;
				msg->prefix = prefix;
				int event = eigrp_get_fsm_event(msg);
				eigrp_fsm_event(msg, event);
			}
		}
	}

	eigrp_query_send_all(eigrp);
	eigrp_update_send_all(eigrp, nbr->ei);
}

void eigrp_update_topology_table_prefix(struct list *table,
					struct eigrp_prefix_entry *prefix)
{
	struct listnode *node1, *node2;

	struct eigrp_neighbor_entry *entry;
	for (ALL_LIST_ELEMENTS(prefix->entries, node1, node2, entry)) {
		if (entry->distance == EIGRP_MAX_METRIC) {
			eigrp_neighbor_entry_delete(prefix, entry);
		}
	}
	if (prefix->distance == EIGRP_MAX_METRIC
	    && prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
		eigrp_prefix_entry_delete(table, prefix);
	}
}
