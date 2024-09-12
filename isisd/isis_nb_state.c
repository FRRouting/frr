// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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
 * XPath: /frr-interface:lib/interface/state/frr-isisd:isis
 */
struct yang_data *
lib_interface_state_isis_get_elem(struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit || !circuit->area)
		return NULL;

	return yang_data_new(args->xpath, NULL);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency
 */
const void *lib_interface_state_isis_adjacencies_adjacency_get_next(
	struct nb_cb_get_next_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj = NULL, *adj_next = NULL;
	struct list *list;
	struct listnode *node, *node_next;

	/* Get first adjacency. */
	if (args->list_entry == NULL) {
		ifp = (struct interface *)args->parent_list_entry;
		if (!ifp)
			return NULL;

		circuit = circuit_scan_by_ifp(ifp);
		if (!circuit)
			return NULL;

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++) {
				struct list *adjdb;

				adjdb = circuit->u.bc.adjdb[level - 1];
				if (adjdb) {
					adj = listnode_head(adjdb);
					if (adj)
						break;
				}
			}
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			break;
		default:
			break;
		}

		return adj;
	}

	/* Get next adjacency. */
	adj = (struct isis_adjacency *)args->list_entry;
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
			if (!list)
				break;
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
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-sys-type
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_sys_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;

	return yang_data_new_enum(args->xpath, adj->level);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-sysid
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_sysid_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;
	char xpath_value[ISO_SYSID_STRLEN];

	snprintfrr(xpath_value, ISO_SYSID_STRLEN, "%pSY", adj->sysid);

	return yang_data_new_string(args->xpath, xpath_value);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-extended-circuit-id
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;

	return yang_data_new_uint32(args->xpath, adj->circuit->circuit_id);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-snpa
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_snpa_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;
	char xpath_value[ISO_SYSID_STRLEN];

	snprintfrr(xpath_value, ISO_SYSID_STRLEN, "%pSY", adj->snpa);

	return yang_data_new_string(args->xpath, xpath_value);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/hold-timer
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_hold_timer_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;

	return yang_data_new_uint16(args->xpath, adj->hold_time);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-priority
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_priority_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;

	return yang_data_new_uint8(args->xpath, adj->prio[adj->level - 1]);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/state
 */
struct yang_data *lib_interface_state_isis_adjacencies_adjacency_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct isis_adjacency *adj = args->list_entry;

	return yang_data_new_string(args->xpath,
				    isis_adj_yang_state(adj->adj_state));
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid
 */
const void *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct isis_adjacency *adj = args->parent_list_entry;
	const struct sr_adjacency *sra = args->list_entry, *sra_next = NULL;
	struct listnode *node, *node_next;

	if (args->list_entry == NULL)
		sra_next = listnode_head(adj->adj_sids);
	else {
		node = listnode_lookup(adj->adj_sids, sra);
		node_next = listnextnode(node);
		if (node_next)
			sra_next = listgetdata(node_next);
	}

	return sra_next;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/af
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_af_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Adjacency SID is not published with circuit type Broadcast */
		return NULL;
	case CIRCUIT_T_P2P:
		return yang_data_new_uint8(args->xpath, sra->u.adj_sid->family);
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/value
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_value_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Adjacency SID is not published with circuit type Broadcast */
		return NULL;
	case CIRCUIT_T_P2P:
		return yang_data_new_uint32(args->xpath, sra->u.adj_sid->sid);
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/weight
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_weight_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Adjacency SID is not published with circuit type Broadcast */
		return NULL;
	case CIRCUIT_T_P2P:
		return yang_data_new_uint8(args->xpath, sra->u.adj_sid->weight);
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/protection-requested
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_protection_requested_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Adjacency SID is not published with circuit type Broadcast */
		return NULL;
	case CIRCUIT_T_P2P:
		return yang_data_new_bool(args->xpath,
					  sra->u.adj_sid->flags &
						  EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid
 */
const void *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct isis_adjacency *adj = args->parent_list_entry;
	const struct sr_adjacency *sra = args->list_entry, *sra_next = NULL;
	struct listnode *node, *node_next;

	if (args->list_entry == NULL)
		sra_next = listnode_head(adj->adj_sids);
	else {
		node = listnode_lookup(adj->adj_sids, sra);
		node_next = listnextnode(node);
		if (node_next)
			sra_next = listgetdata(node_next);
	}

	return sra_next;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/af
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_af_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		return yang_data_new_uint8(args->xpath,
					   sra->u.ladj_sid->family);
	case CIRCUIT_T_P2P:
		/* LAN adjacency SID is not published with circuit type P2P */
		return NULL;
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/value
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_value_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		return yang_data_new_uint32(args->xpath, sra->u.ladj_sid->sid);
	case CIRCUIT_T_P2P:
		/* LAN adjacency SID is not published with circuit type P2P */
		return NULL;
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/weight
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_weight_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		return yang_data_new_uint8(args->xpath,
					   sra->u.ladj_sid->weight);
	case CIRCUIT_T_P2P:
		/* LAN adjacency SID is not published with circuit type P2P */
		return NULL;
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/protection-requested
 */
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_protection_requested_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct sr_adjacency *sra = args->list_entry;

	switch (sra->adj->circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		return yang_data_new_bool(args->xpath,
					  sra->u.ladj_sid->flags &
						  EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	case CIRCUIT_T_P2P:
		/* LAN adjacency SID is not published with circuit type P2P */
		return NULL;
	}

	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-changes
 */
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_changes_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->adj_state_changes);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-number
 */
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_number_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *node;
	uint32_t total = 0;

	ifp = (struct interface *)args->list_entry;
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

	return yang_data_new_uint32(args->xpath, total);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/init-fails
 */
struct yang_data *lib_interface_state_isis_event_counters_init_fails_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->init_failures);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-rejects
 */
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_rejects_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->rej_adjacencies);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/id-len-mismatch
 */
struct yang_data *
lib_interface_state_isis_event_counters_id_len_mismatch_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->id_len_mismatches);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/max-area-addresses-mismatch
 */
struct yang_data *
lib_interface_state_isis_event_counters_max_area_addresses_mismatch_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    circuit->max_area_addr_mismatches);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/authentication-type-fails
 */
struct yang_data *
lib_interface_state_isis_event_counters_authentication_type_fails_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->auth_type_failures);
}

/*
 * XPath:
 * /frr-interface:lib/interface/state/frr-isisd:isis/event-counters/authentication-fails
 */
struct yang_data *
lib_interface_state_isis_event_counters_authentication_fails_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct interface *ifp;
	struct isis_circuit *circuit;

	ifp = (struct interface *)args->list_entry;
	if (!ifp)
		return NULL;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return NULL;

	return yang_data_new_uint32(args->xpath, circuit->auth_failures);
}
