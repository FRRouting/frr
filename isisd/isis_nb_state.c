/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "northbound.h"
#include "linklist.h"

#include "isisd/isisd.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency
 */
const void *
lib_interface_isis_adjacencies_adjacency_get_next(const void *parent_list_entry,
						  const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj, *adj_next = NULL;
	struct list *list;
	struct listnode *node, *node_next;

	/* Get first adjacency. */
	if (list_entry == NULL) {
		ifp = (struct interface *)parent_list_entry;
		if (!ifp)
			return NULL;

		circuit = circuit_scan_by_ifp(ifp);
		if (!circuit)
			return NULL;

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++) {
				adj = listnode_head(
					circuit->u.bc.adjdb[level - 1]);
				if (adj)
					break;
			}
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			break;
		default:
			adj = NULL;
			break;
		}

		return adj;
	}

	/* Get next adjacency. */
	adj = (struct isis_adjacency *)list_entry;
	circuit = adj->circuit;
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		list = circuit->u.bc.adjdb[adj->level - 1];
		node = listnode_lookup(list, adj);
		node_next = listnextnode(node);
		if (node_next)
			adj_next = listgetdata(node_next);
		else if (adj->level == ISIS_LEVEL1) {
			/*
			 * Once we finish the L1 adjacencies, move to the L2
			 * adjacencies list.
			 */
			list = circuit->u.bc.adjdb[ISIS_LEVEL2 - 1];
			adj_next = listnode_head(list);
		}
		break;
	case CIRCUIT_T_P2P:
		/* P2P circuits have at most one adjacency. */
	default:
		break;
	}

	return adj_next;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-sys-type
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_sys_type_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_enum(xpath, adj->level);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-sysid
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_sysid_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_string(xpath, sysid_print(adj->sysid));
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-extended-circuit-id
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_uint32(xpath, adj->circuit->circuit_id);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-snpa
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_snpa_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_string(xpath, snpa_print(adj->snpa));
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/hold-timer
 */
struct yang_data *lib_interface_isis_adjacencies_adjacency_hold_timer_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_uint16(xpath, adj->hold_time);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/neighbor-priority
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_priority_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_uint8(xpath, adj->prio[adj->level - 1]);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/adjacencies/adjacency/state
 */
struct yang_data *
lib_interface_isis_adjacencies_adjacency_state_get_elem(const char *xpath,
							const void *list_entry)
{
	const struct isis_adjacency *adj = list_entry;

	return yang_data_new_string(xpath, isis_adj_yang_state(adj->adj_state));
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-changes
 */
struct yang_data *lib_interface_isis_event_counters_adjacency_changes_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->adj_state_changes);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-number
 */
struct yang_data *lib_interface_isis_event_counters_adjacency_number_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *node;
	uint32_t total = 0;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	/*
	 * TODO: keep track of the number of adjacencies instead of calculating
	 * it on demand.
	 */
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			for (ALL_LIST_ELEMENTS_RO(
				     circuit->u.bc.adjdb[level - 1], node, adj))
				total++;
		}
		break;
	case CIRCUIT_T_P2P:
		adj = circuit->u.p2p.neighbor;
		if (adj)
			total = 1;
		break;
	default:
		break;
	}

	return yang_data_new_uint32(xpath, total);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/event-counters/init-fails
 */
struct yang_data *
lib_interface_isis_event_counters_init_fails_get_elem(const char *xpath,
						      const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->init_failures);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/adjacency-rejects
 */
struct yang_data *lib_interface_isis_event_counters_adjacency_rejects_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->rej_adjacencies);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/id-len-mismatch
 */
struct yang_data *lib_interface_isis_event_counters_id_len_mismatch_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->id_len_mismatches);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/max-area-addresses-mismatch
 */
struct yang_data *
lib_interface_isis_event_counters_max_area_addresses_mismatch_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->max_area_addr_mismatches);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/authentication-type-fails
 */
struct yang_data *
lib_interface_isis_event_counters_authentication_type_fails_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->auth_type_failures);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/event-counters/authentication-fails
 */
struct yang_data *
lib_interface_isis_event_counters_authentication_fails_get_elem(
	const char *xpath, const void *list_entry)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(xpath, circuit->auth_failures);
}
