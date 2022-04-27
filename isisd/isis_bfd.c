// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#include <zebra.h>

#include "zclient.h"
#include "nexthop.h"
#include "bfd.h"
#include "lib_errors.h"

#include "isisd/isis_bfd.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_mt.h"
#include "isisd/isisd.h"
#include "isisd/fabricd.h"

DEFINE_MTYPE_STATIC(ISISD, BFD_SESSION, "ISIS BFD Session");
DEFINE_MTYPE_STATIC(ISISD, BFD_LOCAL_MTID_NLPID, "ISIS BFD local MTID/NLPID");
DEFINE_MTYPE_STATIC(ISISD, BFD_LOCAL_MTID, "ISIS BFD local MTID");


static void isis_bfd_update_rfc6213(struct isis_adjacency *adj);
static void isis_bfd_update_status_rfc6213(struct isis_adjacency *adj,
					   uint8_t family);

static bool isis_bfd_session_is_admin_down(struct isis_adjacency *adj,
					   struct bfd_session_params *bfd_session,
					   bool debug_on)
{
	if (bfd_session &&
	    bfd_sess_status(bfd_session) == BFD_STATUS_ADMIN_DOWN) {
		if (IS_DEBUG_BFD && debug_on)
			zlog_debug("ISIS-BFD: keep L%u adjacency %s to %s, as BFD detected ADMIN_DOWN.",
				   adj->level, isis_adj_name(adj),
				   adj_state2string(adj->adj_state));
		return true;
	}
	return false;
}

/* Check if an adjacency is up and bfd required just went up
 * This function identifies disruptive situations that should be avoided
 * Returns true if identified, false otherwise
 * - Used to not trigger alarm, when identified
 */
static bool isis_bfd_is_required_changed_up(struct isis_adjacency *adj,
					    bool debug_on)
{
	if (adj->adj_state == ISIS_ADJ_UP && adj->circuit &&
	    adj->bfd_rfc6213.bfd_required_is_transition_up) {
		/* RFC6213, 4.
		 * some amount of time should be allowed before bringing down an "UP"
		 * adjacency on a BFD enabled interface when the value of
		 * "ISIS_BFD_REQUIRED" becomes "TRUE" as a result of the introduction of
		 * the BFD TLV or the modification (by adding a new supported MTID/
		 * NLPID) of an existing BFD TLV in a neighbor's IIH
		 *
		 * solution: return true, by not updating the IIH holdtime
		 */
		if (IS_DEBUG_BFD && debug_on)
			zlog_debug("ISIS-BFD: keep L%u adjacency %s to %s, as BFD required just went true",
				   adj->level, isis_adj_name(adj),
				   adj_state2string(adj->adj_state));
		return true;
	}
	return false;
}

/* Check if an adjacency is up and neighbor is not useable
 * This function identifies disruptive situations that should be avoided
 * Returns true if identified, false otherwise
 * - Used to not update the adjacency hold time, when identified
 */
static bool isis_bfd_is_neighbor_not_useable(struct isis_adjacency *adj,
					     bool debug_on)
{
	if (adj->adj_state == ISIS_ADJ_UP && adj->circuit &&
	    adj->circuit->bfd_config.enabled &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config) &&
	    adj->bfd_rfc6213.bfd_required &&
	    !adj->bfd_rfc6213.neighbor_useable) {
		/* RFC6213, 4.
		 * To avoid disruptive transition to the use of BFD, do
		 * not update the adjacency hold time when receiving
		 * an IIH from a neighbor with whom we have an "UP" adjacency until
		 * "ISIS_NEIGHBOR_USEABLE" becomes "TRUE"
		 */
		if (IS_DEBUG_BFD && debug_on)
			zlog_debug("ISIS-BFD: keep L%u adjacency %s to %s, as neighbor is not useable",
				   adj->level, isis_adj_name(adj),
				   adj_state2string(adj->adj_state));
		return true;
	}
	return false;
}

static void isis_bfd_transition_bfd_required(struct isis_adjacency *adj,
					     bool val, const char *reason)
{
	if (IS_DEBUG_BFD &&
	    ((adj->bfd_rfc6213.bfd_required_is_transition_up && !val) ||
	     (!adj->bfd_rfc6213.bfd_required_is_transition_up && val)))
		zlog_debug("ISIS-BFD: L%u adjacency %s, bfd required transition to up changes to %s (%s)",
			   adj->level, isis_adj_name(adj),
			   val ? "True" : "False", reason);
	adj->bfd_rfc6213.bfd_required_is_transition_up = val;
}

static void adj_bfd_cb(struct bfd_session_params *bsp,
		       const struct bfd_session_status *bss, void *arg)
{
	struct isis_adjacency *adj = arg;
	bool neighbor_useable_last;

	if (IS_DEBUG_BFD)
		zlog_debug("ISIS-BFD: BFD changed status for L%u adjacency %s old %s new %s",
			   adj->level, isis_adj_name(adj),
			   bfd_get_status_str(bss->previous_state),
			   bfd_get_status_str(bss->state));

	neighbor_useable_last = adj->bfd_rfc6213.neighbor_useable;
	if (bss->state != bss->previous_state) {
		isis_bfd_update_rfc6213(adj);
		if (isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config) &&
		    bss->state == BFD_STATUS_DOWN &&
		    isis_bfd_is_required_changed_up(adj, true))
			return;
	}
	if (bss->state == BFD_STATUS_UP)
		isis_bfd_transition_bfd_required(adj, false, "BFD is up");

	/* RFC6213, 4.
	 * If a BFD session is administratively shut down [RFC5880] and the BFD
	 * session state change impacts the value of "ISIS_NEIGHBOR_USEABLE",
	 * then IS-IS SHOULD allow time for the corresponding MTID/NLPID to be
	 * removed from the neighbor's BFD TLV by not updating the adjacency
	 * hold time until "ISIS_BFD_REQUIRED" becomes "FALSE".
	 */
	if (isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config) &&
	    (neighbor_useable_last != adj->bfd_rfc6213.neighbor_useable) &&
	    !adj->bfd_rfc6213.neighbor_useable &&
	    isis_bfd_session_is_admin_down(adj, bsp, true))
		return;

	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		adj->circuit->area->bfd_signalled_down = true;
		isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
				      "bfd session went down");
	}
}

void bfd_handle_adj_down(struct isis_adjacency *adj, uint8_t family,
			 const char *reason)
{
	if (adj->bfd_session_ipv4 && (family == AF_INET || family == AF_UNSPEC)) {
		if (reason && IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: Turn off IPv4 BFD session: %s",
				   reason);
		bfd_sess_free(&adj->bfd_session_ipv4);
		adj->bfd_session_ipv4 = NULL;
		UNSET_FLAG(adj->bfd_rfc6213.flags, BFD_ADJ_STOP_IPV4);
	}
	if (adj->bfd_session_ipv6 &&
	    (family == AF_INET6 || family == AF_UNSPEC)) {
		if (reason && IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: Turn off IPv6 BFD session: %s",
				   reason);
		bfd_sess_free(&adj->bfd_session_ipv6);
		adj->bfd_session_ipv6 = NULL;
		UNSET_FLAG(adj->bfd_rfc6213.flags, BFD_ADJ_STOP_IPV6);
	}
}


static int bfd_handle_delete(struct isis_adjacency *adj)
{
	struct listnode *node, *nnode;
	struct bfd_local_mtnlpid *bfd_local_pair;
	struct bfd_local_mtid *bfd_local_topo;

	if (IS_DEBUG_BFD &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config))
		zlog_debug("ISIS-BFD: L%u adjacency %s becomes down. Cleaning RFC6213 structures.",
			   adj->level, isis_adj_name(adj));

	if (adj->bfd_rfc6213.local_mtnlpid_lst) {
		for (ALL_LIST_ELEMENTS(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				       nnode, bfd_local_pair)) {
			listnode_delete(adj->bfd_rfc6213.local_mtnlpid_lst,
					bfd_local_pair);
			XFREE(MTYPE_BFD_LOCAL_MTID_NLPID, bfd_local_pair);
		}
		list_delete(&adj->bfd_rfc6213.local_mtnlpid_lst);
	}


	if (adj->bfd_rfc6213.local_mtid_lst) {
		for (ALL_LIST_ELEMENTS(adj->bfd_rfc6213.local_mtid_lst, node,
				       nnode, bfd_local_topo)) {
			listnode_delete(adj->bfd_rfc6213.local_mtid_lst,
					bfd_local_topo);
			XFREE(MTYPE_BFD_LOCAL_MTID, bfd_local_topo);
		}
		list_delete(&adj->bfd_rfc6213.local_mtid_lst);
	}

	memset(&adj->bfd_rfc6213, 0, sizeof(struct bfd_rfc6213_params));
	bfd_handle_adj_down(adj, AF_UNSPEC, NULL);

	return 0;
}

static void bfd_handle_run_bfd_session(struct isis_adjacency *adj,
				       uint8_t family, union g_addr *src_ip,
				       union g_addr *dst_ip)
{
	struct bfd_session_params *bfd_session = NULL;

	if (family == AF_INET) {
		if (adj->bfd_session_ipv4 == NULL)
			adj->bfd_session_ipv4 = bfd_sess_new(adj_bfd_cb, adj);
		bfd_session = adj->bfd_session_ipv4;
	} else if (family == AF_INET6) {
		if (adj->bfd_session_ipv6 == NULL)
			adj->bfd_session_ipv6 = bfd_sess_new(adj_bfd_cb, adj);
		bfd_session = adj->bfd_session_ipv6;
	} else if (family == AF_UNSPEC)
		return;

	bfd_sess_set_timers(bfd_session, BFD_DEF_DETECT_MULT, BFD_DEF_MIN_RX,
			    BFD_DEF_MIN_TX);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(bfd_session, &src_ip->ipv4,
					&dst_ip->ipv4);
	else
		bfd_sess_set_ipv6_addrs(bfd_session, &src_ip->ipv6,
					&dst_ip->ipv6);
	bfd_sess_set_interface(bfd_session, adj->circuit->interface->name);
	bfd_sess_set_vrf(bfd_session, adj->circuit->interface->vrf->vrf_id);
	bfd_sess_set_profile(bfd_session, adj->circuit->bfd_config.profile);
	bfd_sess_install(bfd_session);
}

/* family parameter : AF_INET or AF_INET6 in case rfc6213 is enabled
 * else AF_UNSPEC
 */
static void bfd_handle_run_bfd(struct isis_adjacency *adj, uint8_t family)
{
	struct isis_circuit *circuit = adj->circuit;
	struct bfd_session_params *bfd_session;
	union g_addr dst_ip;
	uint8_t selected_family = AF_UNSPEC;
	union g_addr src_ip;
	struct list *local_ips;
	struct prefix *local_ip;

	if (isis_bfd_config_rfc6213_enabled(&circuit->bfd_config) &&
	    ((family == AF_INET && !adj->bfd_rfc6213.bfd_ipv4_required) ||
	     (family == AF_INET6 && !adj->bfd_rfc6213.bfd_ipv6_required))) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: skipping BFD initialization on L%u adjacency %s because BFD_REQUIRED %s is false.",
				   adj->level, isis_adj_name(adj),
				   family2str(family));
		return;
	}

	/* If IS-IS IPv6 is configured wait for IPv6 address to be programmed
	 * before starting up BFD
	 */
	if ((family == AF_UNSPEC || family == AF_INET6) &&
	    circuit->ipv6_router &&
	    (listcount(circuit->ipv6_link) == 0 || adj->ll_ipv6_count == 0)) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: skipping BFD initialization on L%u adjacency %s because IPv6 is enabled but not ready",
				   adj->level, isis_adj_name(adj));
		return bfd_handle_adj_down(adj, AF_INET6, NULL);
	}

	/*
	 * If IS-IS is enabled for both IPv4 and IPv6 on the circuit, prefer
	 * creating a BFD session over IPv6.
	 */
	if ((family == AF_INET6 || family == AF_UNSPEC) &&
	    circuit->ipv6_router && adj->ll_ipv6_count) {
		selected_family = AF_INET6;
		dst_ip.ipv6 = adj->ll_ipv6_addrs[0];
		local_ips = circuit->ipv6_link;
		if (list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv6 enabled and no local IPv6 addresses");
			return bfd_handle_adj_down(adj, selected_family, NULL);
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv6 = local_ip->u.prefix6;
	} else if ((family == AF_INET || family == AF_UNSPEC) &&
		   circuit->ip_router && adj->ipv4_address_count) {
		selected_family = AF_INET;
		dst_ip.ipv4 = adj->ipv4_addresses[0];
		local_ips = fabricd_ip_addrs(adj->circuit);
		if (!local_ips || list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv4 enabled and no local IPv4 addresses");
			return bfd_handle_adj_down(adj, selected_family, NULL);
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv4 = local_ip->u.prefix4;
	} else
		return bfd_handle_adj_down(adj, selected_family, NULL);

	bfd_handle_run_bfd_session(adj, selected_family, &src_ip, &dst_ip);

	if (selected_family == AF_INET)
		bfd_session = adj->bfd_session_ipv4;
	else
		bfd_session = adj->bfd_session_ipv6;

	bfd_sess_set_timers(bfd_session, BFD_DEF_DETECT_MULT, BFD_DEF_MIN_RX,
			    BFD_DEF_MIN_TX);

	if (selected_family == AF_INET)
		bfd_sess_set_ipv4_addrs(adj->bfd_session_ipv4, &src_ip.ipv4,
					&dst_ip.ipv4);
	else
		bfd_sess_set_ipv6_addrs(adj->bfd_session_ipv6, &src_ip.ipv6,
					&dst_ip.ipv6);

	bfd_sess_set_interface(bfd_session, adj->circuit->interface->name);
	bfd_sess_set_vrf(bfd_session, adj->circuit->interface->vrf->vrf_id);
	bfd_sess_set_profile(bfd_session, circuit->bfd_config.profile);
	bfd_sess_install(bfd_session);

	/* if rfc6213 is not enabled, keep only one bfd session */
	if (!isis_bfd_config_rfc6213_enabled(&circuit->bfd_config))
		bfd_handle_adj_down(
			adj, selected_family == AF_INET ? AF_INET6 : AF_INET,
			"RFC6213 is disabled. Only one BFD session is supported.");
}

static void bfd_handle_adj_up(struct isis_adjacency *adj, uint8_t family)
{
	struct isis_circuit *circuit = adj->circuit;

	if (!circuit->bfd_config.enabled) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: skipping BFD initialization on L%u adjacency %s because BFD is not enabled for the circuit",
				   adj->level, isis_adj_name(adj));
		goto out;
	}

	if (isis_bfd_config_rfc6213_enabled(&circuit->bfd_config)) {
		isis_bfd_update_rfc6213(adj);
		if (family == AF_UNSPEC) {
			isis_bfd_update_status_rfc6213(adj, AF_INET);
			isis_bfd_update_status_rfc6213(adj, AF_INET6);
		} else
			isis_bfd_update_status_rfc6213(adj, family);
	}

	/* RFC6213, 3.2
	 * When the IS-IS adjacency is "UP" and "ISIS_NEIGHBOR_USEABLE"
	 * becomes "FALSE", the IS-IS adjacency MUST transition to "DOWN".
	 */
	if (isis_bfd_config_rfc6213_enabled(&circuit->bfd_config) &&
	    adj->adj_state == ISIS_ADJ_UP && adj->bfd_rfc6213.bfd_required &&
	    !adj->bfd_rfc6213.neighbor_useable) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: neighbor is not useable for L%u adjacency %s",
				   adj->level, isis_adj_name(adj));
		isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
				      "BFD-TLV, neighbor is not useable");
		goto out;
	}

	if (!isis_bfd_config_rfc6213_enabled(&circuit->bfd_config))
		bfd_handle_run_bfd(adj, AF_UNSPEC);
	return;
out:
	if (adj)
		bfd_handle_adj_down(adj, family, NULL);
}

void isis_bfd_init_adjacency(struct isis_adjacency *adj)
{
	if (IS_DEBUG_BFD &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config))
		zlog_debug("ISIS-BFD: L%u adjacency %s becomes up. Initializing RFC6213 structures.",
			   adj->level, isis_adj_name(adj));

	adj->bfd_rfc6213.local_mtnlpid_lst = list_new();
	adj->bfd_rfc6213.local_mtid_lst = list_new();
	adj->bfd_rfc6213.config_rfc6213_ipv4_last =
		adj->circuit->bfd_config.rfc6213_ipv4;
	adj->bfd_rfc6213.config_rfc6213_ipv6_last =
		adj->circuit->bfd_config.rfc6213_ipv6;
}


static int bfd_handle_adj_state_change(struct isis_adjacency *adj)
{
	if (adj->adj_state == ISIS_ADJ_UP)
		bfd_handle_adj_up(adj, AF_UNSPEC);
	else
		bfd_handle_adj_down(adj, AF_UNSPEC, NULL);
	return 0;
}

static void bfd_adj_cmd(struct isis_adjacency *adj)
{
	bool changed = false;
	uint8_t family = AF_UNSPEC;

	/* case 'isis bfd' command changed */
	if (adj->circuit->bfd_config.enabled !=
	    adj->bfd_rfc6213.config_enabled_last) {
		adj->bfd_rfc6213.config_enabled_last =
			adj->circuit->bfd_config.enabled;
		if (!adj->circuit->bfd_config.enabled) {
			SET_FLAG(adj->bfd_rfc6213.flags,
				 BFD_ADJ_STOP_IPV4 | BFD_ADJ_STOP_IPV6);
			return;
		}
		changed = true;
		UNSET_FLAG(adj->bfd_rfc6213.flags,
			   BFD_ADJ_STOP_IPV4 | BFD_ADJ_STOP_IPV6);
	}
	adj->bfd_rfc6213.config_enabled_last = adj->circuit->bfd_config.enabled;
	/* case 'isis bfd use-tlv-ipv[4,6] changed */
	if (isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config)) {
		if (changed)
			family = AF_UNSPEC;
		if (adj->bfd_rfc6213.config_rfc6213_ipv4_last !=
		    adj->circuit->bfd_config.rfc6213_ipv4) {
			if (adj->circuit->bfd_config.rfc6213_ipv4)
				UNSET_FLAG(adj->bfd_rfc6213.flags,
					   BFD_ADJ_STOP_IPV4);
			else
				SET_FLAG(adj->bfd_rfc6213.flags,
					 BFD_ADJ_STOP_IPV4);
			changed = true;
			family = AF_INET;
		}
		if (adj->bfd_rfc6213.config_rfc6213_ipv6_last !=
		    adj->circuit->bfd_config.rfc6213_ipv6) {
			if (adj->circuit->bfd_config.rfc6213_ipv6)
				UNSET_FLAG(adj->bfd_rfc6213.flags,
					   BFD_ADJ_STOP_IPV6);
			else
				SET_FLAG(adj->bfd_rfc6213.flags,
					 BFD_ADJ_STOP_IPV6);
			changed = true;
			family = AF_INET6;
		}
		if (!changed)
			return;
		adj->bfd_rfc6213.config_rfc6213_ipv4_last =
			adj->circuit->bfd_config.rfc6213_ipv4;
		adj->bfd_rfc6213.config_rfc6213_ipv6_last =
			adj->circuit->bfd_config.rfc6213_ipv6;

		/* try to start bfd */
		isis_bfd_update_rfc6213(adj);
		if (family == AF_UNSPEC) {
			isis_bfd_update_status_rfc6213(adj, AF_INET);
			isis_bfd_update_status_rfc6213(adj, AF_INET6);
		} else
			isis_bfd_update_status_rfc6213(adj, family);
	} else if (adj->adj_state == ISIS_ADJ_UP)
		bfd_handle_adj_up(adj, AF_UNSPEC);
}

void isis_bfd_circuit_cmd(struct isis_circuit *circuit)
{
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			struct list *adjdb = circuit->u.bc.adjdb[level - 1];

			struct listnode *node;
			struct isis_adjacency *adj;

			if (!adjdb)
				continue;
			for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj))
				bfd_adj_cmd(adj);
		}
		break;
	case CIRCUIT_T_P2P:
		if (circuit->u.p2p.neighbor)
			bfd_adj_cmd(circuit->u.p2p.neighbor);
		break;
	default:
		break;
	}
}

static int bfd_handle_adj_ip_enabled(struct isis_adjacency *adj, int family,
				     bool global)
{

	if (family != AF_INET6 || global)
		return 0;

	if ((family == AF_INET && adj->bfd_session_ipv4) ||
	    (family == AF_INET6 && adj->bfd_session_ipv6))
		return 0;

	if (adj->adj_state != ISIS_ADJ_UP)
		return 0;

	bfd_handle_adj_up(adj, (uint8_t)family);

	return 0;
}

static int bfd_handle_circuit_add_addr(struct isis_circuit *circuit,
				       uint8_t family)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	if (circuit->area == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(circuit->area->adjacency_list, node, adj)) {
		if (family == AF_INET && adj->bfd_session_ipv4)
			continue;

		if (family == AF_INET6 && adj->bfd_session_ipv6)
			continue;

		if (adj->adj_state != ISIS_ADJ_UP)
			continue;

		bfd_handle_adj_up(adj, family);
	}

	return 0;
}

void isis_bfd_init(struct event_loop *tm)
{
	bfd_protocol_integration_init(zclient, tm);

	hook_register(isis_adj_state_change_hook, bfd_handle_adj_state_change);
	hook_register(isis_adj_delete_hook, bfd_handle_delete);
	hook_register(isis_adj_ip_enabled_hook, bfd_handle_adj_ip_enabled);
	hook_register(isis_circuit_add_addr_hook, bfd_handle_circuit_add_addr);
}

static uint8_t isis_bfd_mtpid_nlpid2mtnplid(uint16_t mtid, uint8_t nlpid)
{
	if (mtid == ISIS_MT_STANDARD && nlpid == NLPID_IP)
		return ISIS_BFD_MT_STANDARD_NLP_IPV4;
	else if (mtid == ISIS_MT_STANDARD && nlpid == NLPID_IPV6)
		return ISIS_BFD_MT_STANDARD_NLP_IPV6;
	else if (mtid == ISIS_MT_IPV6_UNICAST && nlpid == NLPID_IPV6)
		return ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6;

	return ISIS_BFD_MT_NLP_UNDEFINED;
}

static bool isis_bfd_mtnlpid_enabled(uint8_t mtid_nlpid, uint16_t mtid,
				     uint8_t nlpid)
{
	uint8_t check_mtid_nlpid = isis_bfd_mtpid_nlpid2mtnplid(mtid, nlpid);

	return CHECK_FLAG(mtid_nlpid, check_mtid_nlpid);
}

static uint16_t isis_bfd_mtnplid2mtpid(uint8_t mtid_nlpid)
{
	if (mtid_nlpid == ISIS_BFD_MT_STANDARD_NLP_IPV4 ||
	    mtid_nlpid == ISIS_BFD_MT_STANDARD_NLP_IPV6)
		return ISIS_MT_STANDARD;

	if (mtid_nlpid == ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6)
		return ISIS_MT_IPV6_UNICAST;

	return ISIS_MT_DISABLE;
}

static uint8_t isis_bfd_mtnplid2nlpid(uint8_t mtid_nlpid)
{
	if (mtid_nlpid == ISIS_BFD_MT_STANDARD_NLP_IPV4)
		return NLPID_IP;

	if (mtid_nlpid == ISIS_BFD_MT_STANDARD_NLP_IPV6 ||
	    mtid_nlpid == ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6)
		return NLPID_IPV6;

	return NLPID_NULL;
}

static void isis_bfd_update_adj_bfd_debug(struct isis_adjacency *adj,
					  uint8_t prev_mtid_nlpid,
					  uint8_t mtid_nlpid,
					  uint8_t mtid_nlpid_flag)
{
	bool flag;

	flag = CHECK_FLAG(prev_mtid_nlpid, mtid_nlpid_flag) !=
	       CHECK_FLAG(mtid_nlpid, mtid_nlpid_flag);
	if (!flag)
		return;

	flag = !CHECK_FLAG(prev_mtid_nlpid, mtid_nlpid_flag) &&
	       CHECK_FLAG(mtid_nlpid, mtid_nlpid_flag);

	zlog_debug("ISIS-BFD: peer MT %s NLPID %s %s L%u adjacency %s",
		   isis_mtid2str(isis_bfd_mtnplid2mtpid(mtid_nlpid_flag)),
		   nlpid2str(isis_bfd_mtnplid2nlpid(mtid_nlpid_flag)),
		   flag ? "added to" : "removed from", adj->level,
		   isis_adj_name(adj));
}

void isis_bfd_update_adj_bfd(struct isis_bfd_enabled *head,
			     struct isis_adjacency *adj, bool *changed)
{
	uint8_t prev_mtid_nlpid, *mtid_nlpid, mtid_nlpid_flag;
	struct isis_bfd_enabled *niter;
	bool bfd_tlv_changed;

	mtid_nlpid = &adj->bfd_rfc6213.neighbor_mtid_nlpid;
	prev_mtid_nlpid = *mtid_nlpid;
	*mtid_nlpid = 0;

	/* add new TLVs in MTID NLPID list */
	for (niter = head; niter; niter = niter->next) {
		if (niter->mtid == ISIS_MT_STANDARD && niter->nlpid == NLPID_IP)
			SET_FLAG(*mtid_nlpid, ISIS_BFD_MT_STANDARD_NLP_IPV4);
		else if (niter->mtid == ISIS_MT_STANDARD &&
			 niter->nlpid == NLPID_IPV6)
			SET_FLAG(*mtid_nlpid, ISIS_BFD_MT_STANDARD_NLP_IPV6);
		else if (niter->mtid == ISIS_MT_IPV6_UNICAST &&
			 niter->nlpid == NLPID_IPV6)
			SET_FLAG(*mtid_nlpid, ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6);
		else if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: received unsupported MTID %s NLPID %s from L%u adjacency %s",
				   isis_mtid2str(niter->mtid),
				   nlpid2str(niter->nlpid), adj->level,
				   isis_adj_name(adj));
	}

	bfd_tlv_changed = prev_mtid_nlpid != *mtid_nlpid;

	if (IS_DEBUG_BFD && bfd_tlv_changed &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config)) {
		for (unsigned int i = 0; i < sizeof(mtid_nlpid_flag) * 8; i++) {
			mtid_nlpid_flag = 0x1 << i;
			if (CHECK_FLAG(*mtid_nlpid, mtid_nlpid_flag))
				isis_bfd_update_adj_bfd_debug(adj,
							      prev_mtid_nlpid,
							      *mtid_nlpid,
							      mtid_nlpid_flag);
		}
	}

	if (bfd_tlv_changed &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config)) {
		isis_bfd_update_rfc6213(adj);
		isis_bfd_update_status_rfc6213(adj, AF_INET);
		isis_bfd_update_status_rfc6213(adj, AF_INET6);
		*changed = true;
	}
}

void isis_bfd_circuit_update_rfc6213(struct isis_circuit *circuit)
{
	struct isis_area_mt_setting **area_settings;
	unsigned int mt_count = 0, i;
	bool rfc6213_ipv4 = false;
	bool rfc6213_ipv6 = false;
	uint8_t cnt;
	uint16_t mtid;

	/* Update the locally supported MTID/NLPID pairs. */
	if (circuit->bfd_config.rfc6213_ipv4 && circuit->bfd_config.enabled &&
	    circuit->ip_router && fabricd_ip_addrs(circuit)) {
		for (cnt = 0; cnt < circuit->nlpids.count; cnt++) {
			if (circuit->nlpids.nlpids[cnt] == NLPID_IP) {
				rfc6213_ipv4 = true;
				break;
			}
		}
	}

	if (rfc6213_ipv4)
		SET_FLAG(circuit->bfd_config.mtid_nlpid,
			 ISIS_BFD_MT_STANDARD_NLP_IPV4);
	else
		UNSET_FLAG(circuit->bfd_config.mtid_nlpid,
			   ISIS_BFD_MT_STANDARD_NLP_IPV4);

	if (circuit->bfd_config.rfc6213_ipv6 && circuit->bfd_config.enabled &&
	    circuit->ipv6_router &&
	    (listcount(circuit->ipv6_link) > 0 ||
	     listcount(circuit->ipv6_non_link) > 0)) {
		for (cnt = 0; cnt < circuit->nlpids.count; cnt++) {
			if (circuit->nlpids.nlpids[cnt] == NLPID_IPV6) {
				rfc6213_ipv6 = true;
				break;
			}
		}
	}

	if (rfc6213_ipv6) {
		area_settings = area_mt_settings(circuit->area, &mt_count);

		/* MTID ISIS_MT_STANDARD is always enabled
		 * ISIS_MT_IPV6_UNICAST is enabled only if
		 * "topology ipv6-unicast" is configured.
		 */
		mtid = ISIS_MT_STANDARD;
		for (i = 0; i < mt_count; i++) {
			if (area_settings[i]->mtid == ISIS_MT_IPV6_UNICAST) {
				mtid = ISIS_MT_IPV6_UNICAST;
				break;
			}
		}
		if (mtid == ISIS_MT_STANDARD) {
			SET_FLAG(circuit->bfd_config.mtid_nlpid,
				 ISIS_BFD_MT_STANDARD_NLP_IPV6);
			UNSET_FLAG(circuit->bfd_config.mtid_nlpid,
				   ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6);
		} else {
			SET_FLAG(circuit->bfd_config.mtid_nlpid,
				 ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6);
			UNSET_FLAG(circuit->bfd_config.mtid_nlpid,
				   ISIS_BFD_MT_STANDARD_NLP_IPV6);
		}
	} else {
		UNSET_FLAG(circuit->bfd_config.mtid_nlpid,
			   ISIS_BFD_MT_STANDARD_NLP_IPV6);
		UNSET_FLAG(circuit->bfd_config.mtid_nlpid,
			   ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6);
	}
}


static struct bfd_local_mtnlpid *
isis_bfd_local_mtnlpid_get(struct isis_adjacency *adj, uint16_t mtid,
			   uint8_t nlpid)
{
	struct bfd_local_mtnlpid *bfd_pair;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_pair)) {
		if (bfd_pair->mtid == mtid && bfd_pair->nlpid == nlpid)
			return bfd_pair;
	}

	return NULL;
}

static struct bfd_local_mtnlpid *
isis_bfd_local_mtnlpid_add(struct isis_adjacency *adj, uint16_t mtid,
			   uint8_t nlpid)
{
	struct bfd_local_mtnlpid *bfd_pair;

	bfd_pair = isis_bfd_local_mtnlpid_get(adj, mtid, nlpid);
	if (bfd_pair)
		return bfd_pair;

	bfd_pair = XCALLOC(MTYPE_BFD_LOCAL_MTID_NLPID,
			   sizeof(struct bfd_local_mtnlpid));
	bfd_pair->mtid = mtid;
	bfd_pair->nlpid = nlpid;
	listnode_add(adj->bfd_rfc6213.local_mtnlpid_lst, bfd_pair);

	if (IS_DEBUG_BFD)
		zlog_debug("ISIS-BFD: local MT %s NLPID %s added to L%u adjacency %s",
			   isis_mtid2str(mtid), nlpid2str(nlpid), adj->level,
			   isis_adj_name(adj));

	return bfd_pair;
}

static void isis_bfd_local_mtnlpid_del(struct isis_adjacency *adj,
				       uint16_t mtid, uint8_t nlpid)
{
	struct bfd_local_mtnlpid *bfd_pair;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(adj->bfd_rfc6213.local_mtnlpid_lst, node, nnode,
			       bfd_pair)) {
		if (bfd_pair->mtid == mtid && bfd_pair->nlpid == nlpid) {
			listnode_delete(adj->bfd_rfc6213.local_mtnlpid_lst,
					bfd_pair);
			XFREE(MTYPE_BFD_LOCAL_MTID_NLPID, bfd_pair);
			if (IS_DEBUG_BFD)
				zlog_debug("ISIS-BFD: local MT %s NLPID %s removed from L%u adjacency %s",
					   isis_mtid2str(mtid), nlpid2str(nlpid),
					   adj->level, isis_adj_name(adj));
			return;
		}
	}
}

static struct bfd_local_mtid *isis_bfd_local_mtid_get(struct isis_adjacency *adj,
						      uint16_t mtid)
{
	struct bfd_local_mtid *bfd_topo;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst, node,
				  bfd_topo)) {
		if (bfd_topo->mtid == mtid)
			return bfd_topo;
	}
	return NULL;
}

static struct bfd_local_mtid *isis_bfd_local_mtid_add(struct isis_adjacency *adj,
						      uint16_t mtid)
{
	struct bfd_local_mtid *bfd_topo;

	bfd_topo = isis_bfd_local_mtid_get(adj, mtid);
	if (bfd_topo)
		return bfd_topo;

	bfd_topo = XCALLOC(MTYPE_BFD_LOCAL_MTID, sizeof(struct bfd_local_mtid));
	bfd_topo->mtid = mtid;
	listnode_add(adj->bfd_rfc6213.local_mtid_lst, bfd_topo);

	if (IS_DEBUG_BFD)
		zlog_debug("ISIS-BFD: local MT %s added to L%u adjacency %s",
			   isis_mtid2str(mtid), adj->level, isis_adj_name(adj));

	return bfd_topo;
}

static void
isis_bfd_adjacency_update_rfc6213_local_params(struct isis_adjacency *adj)
{
	struct listnode *node, *mtnode, *nmtnode;
	struct bfd_local_mtnlpid *bfd_local_pair;
	struct bfd_local_mtid *bfd_local_topo;
	struct bfd_conf *bfd_conf;
	bool found;

	bfd_conf = &adj->circuit->bfd_config;

	if (IS_DEBUG_BFD && isis_bfd_config_rfc6213_enabled(bfd_conf))
		zlog_debug("ISIS-BFD: updating RFC6213 local variables for L%u adjacency %s",
			   adj->level, isis_adj_name(adj));

	isis_bfd_circuit_update_rfc6213(adj->circuit);

	/* Update the locally supported MTID/NLPID pairs. */
	if (CHECK_FLAG(bfd_conf->mtid_nlpid, ISIS_BFD_MT_STANDARD_NLP_IPV4))
		/* MTID ISIS_MT_STANDARD is always enabled */
		isis_bfd_local_mtnlpid_add(adj, ISIS_MT_STANDARD, NLPID_IP);
	else
		isis_bfd_local_mtnlpid_del(adj, ISIS_MT_STANDARD, NLPID_IP);

	if (CHECK_FLAG(bfd_conf->mtid_nlpid, ISIS_BFD_MT_STANDARD_NLP_IPV6))
		/* MTID ISIS_MT_STANDARD is always enabled */
		isis_bfd_local_mtnlpid_add(adj, ISIS_MT_STANDARD, NLPID_IPV6);
	else
		isis_bfd_local_mtnlpid_del(adj, ISIS_MT_STANDARD, NLPID_IPV6);

	if (CHECK_FLAG(bfd_conf->mtid_nlpid, ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6))
		/* MTID ISIS_MT_IPV6_UNICAST is enabled topology ipv6 is set*/
		isis_bfd_local_mtnlpid_add(adj, ISIS_MT_IPV6_UNICAST,
					   NLPID_IPV6);
	else
		isis_bfd_local_mtnlpid_del(adj, ISIS_MT_IPV6_UNICAST,
					   NLPID_IPV6);

	/* Update the locally supported topology (MTID). */
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		isis_bfd_local_mtid_add(adj, bfd_local_pair->mtid);
	}

	for (ALL_LIST_ELEMENTS(adj->bfd_rfc6213.local_mtid_lst, mtnode, nmtnode,
			       bfd_local_topo)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst,
					  node, bfd_local_pair)) {
			if (bfd_local_topo->mtid == bfd_local_pair->mtid) {
				found = true;
				break;
			}
		}
		if (!found) {
			listnode_delete(adj->bfd_rfc6213.local_mtid_lst,
					bfd_local_topo);
			if (IS_DEBUG_BFD)
				zlog_debug("ISIS-BFD: local MT %s removed from L%u adjacency %s",
					   isis_mtid2str(bfd_local_topo->mtid),
					   adj->level, isis_adj_name(adj));
			XFREE(MTYPE_BFD_LOCAL_MTID, bfd_local_topo);
		}
	}
}

static bool isis_bfd_get_bfd_nlpid_state(struct isis_adjacency *adj,
					 uint8_t family)
{
	enum bfd_session_state state = BFD_STATUS_UNKNOWN;

	if (family == AF_INET && adj->bfd_session_ipv4)
		state = bfd_sess_status(adj->bfd_session_ipv4);
	if (family == AF_INET6 && adj->bfd_session_ipv6)
		state = bfd_sess_status(adj->bfd_session_ipv6);
	if (state == BFD_STATUS_ADMIN_DOWN || state == BFD_STATUS_DOWN)
		return false;
	return true;
}

static void isis_bfd_update_rfc6213(struct isis_adjacency *adj)
{
	struct listnode *node, *mtnode;
	struct bfd_local_mtnlpid *bfd_local_pair;
	struct bfd_local_mtid *bfd_local_topo;
	bool old_value, debug;

	debug = IS_DEBUG_BFD &&
		isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config);

	if (debug)
		zlog_debug("ISIS-BFD: %s RFC6213 variables for L%u adjacency %s",
			   adj->bfd_rfc6213.inited ? "updating" : "initializing",
			   adj->level, isis_adj_name(adj));

	isis_bfd_adjacency_update_rfc6213_local_params(adj);

	/* RFC6213, 3.1. ISIS_TOPO_NLPID_BFD_REQUIRED
	 * For each locally supported MTID/NLPID pair, an
	 * "ISIS_TOPO_NLPID_BFD_REQUIRED" variable is assigned.  If BFD is
	 * supported by both the local system and the neighbor of the MTID/
	 * NLPID, this variable is set to "TRUE".  Otherwise, the variable is
	 * set to "FALSE".
	 */

	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		old_value = bfd_local_pair->topo_nlpid_bfd_required;
		if (isis_bfd_mtnlpid_enabled(adj->bfd_rfc6213.neighbor_mtid_nlpid,
					     bfd_local_pair->mtid,
					     bfd_local_pair->nlpid))
			bfd_local_pair->topo_nlpid_bfd_required = true;
		else
			bfd_local_pair->topo_nlpid_bfd_required = false;

		/* TO DO: to be moved somewhere else */
		if (old_value == false &&
		    bfd_local_pair->topo_nlpid_bfd_required)
			isis_bfd_transition_bfd_required(
				adj, true, "local MTNLPID changed to required");

		if (old_value == true &&
		    bfd_local_pair->topo_nlpid_bfd_required == false) {
			if (bfd_local_pair->nlpid == NLPID_IP)
				SET_FLAG(adj->bfd_rfc6213.flags,
					 BFD_ADJ_STOP_IPV4);
			else if (bfd_local_pair->nlpid == NLPID_IPV6)
				SET_FLAG(adj->bfd_rfc6213.flags,
					 BFD_ADJ_STOP_IPV6);
		}

		if (debug &&
		    (!bfd_local_pair->inited ||
		     old_value != bfd_local_pair->topo_nlpid_bfd_required)) {
			zlog_debug("ISIS-BFD: local MT %s NLPID %s BFD is %srequired on L%u adjacency %s",
				   isis_mtid2str(bfd_local_pair->mtid),
				   nlpid2str(bfd_local_pair->nlpid),
				   bfd_local_pair->topo_nlpid_bfd_required
					   ? ""
					   : "not ",
				   adj->level, isis_adj_name(adj));
		}
	}

	/* RFC6213, 3.1. ISIS_TOPO_NLPID_STATE
	 * If "ISIS_TOPO_NLPID_BFD_REQUIRED" is "TRUE", "NLPID_STATE"
	 * follows the BFD session state for that MTID/NLPID ("UP == TRUE").
	 * Otherwise, the variable is set to "TRUE".
	 */

	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		old_value = bfd_local_pair->topo_nlpid_state;
		if (bfd_local_pair->topo_nlpid_bfd_required)
			bfd_local_pair->topo_nlpid_state =
				isis_bfd_get_bfd_nlpid_state(adj,
							     bfd_local_pair->nlpid ==
									     NLPID_IP
								     ? AF_INET
								     : AF_INET6);
		else
			bfd_local_pair->topo_nlpid_state = true;
		if (debug && (!bfd_local_pair->inited ||
			      old_value != bfd_local_pair->topo_nlpid_state))
			zlog_debug("ISIS-BFD: local MT %s NLPID %s BFD state is %s on L%u adjacency %s",
				   isis_mtid2str(bfd_local_pair->mtid),
				   nlpid2str(bfd_local_pair->nlpid),
				   bfd_local_pair->topo_nlpid_state ? "True"
								    : "False",
				   adj->level, isis_adj_name(adj));
	}

	/* RFC6213, 3.1. ISIS_TOPO_USEABLE
	 * For each locally supported topology (MTID), an "ISIS_TOPO_USEABLE"
	 * variable is set to the logical "AND" of the set of
	 * "ISIS_TOPO_NLPID_STATE" variables associated with that MTID.
	 */
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst, mtnode,
				  bfd_local_topo)) {
		old_value = bfd_local_topo->topo_useable;
		bfd_local_topo->topo_useable = true;
		for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst,
					  node, bfd_local_pair)) {
			if (bfd_local_topo->mtid == bfd_local_pair->mtid)
				bfd_local_topo->topo_useable &=
					bfd_local_pair->topo_nlpid_state;
		}
		if (debug && (!bfd_local_topo->inited ||
			      old_value != bfd_local_topo->topo_useable))
			zlog_debug("ISIS-BFD: local MT %s is %suseable on L%u adjacency %s",
				   isis_mtid2str(bfd_local_topo->mtid),
				   bfd_local_topo->topo_useable ? "" : "not ",
				   adj->level, isis_adj_name(adj));
	}

	/* Internal:
	 * Set if BFD IPv4/IPv6 local config is required
	 * and useable with local NLPID.
	 */

	old_value = adj->bfd_rfc6213.bfd_ipv4_required;
	adj->bfd_rfc6213.bfd_ipv4_required = false;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		if (bfd_local_pair->nlpid == NLPID_IP &&
		    bfd_local_pair->topo_nlpid_bfd_required) {
			adj->bfd_rfc6213.bfd_ipv4_required = true;
			break;
		}
	}
	if (debug && (!adj->bfd_rfc6213.inited ||
		      old_value != adj->bfd_rfc6213.bfd_ipv4_required))
		zlog_debug("ISIS-BFD: bfd_ipv4_required is %s on L%u adjacency %s",
			   adj->bfd_rfc6213.bfd_ipv4_required ? "True" : "False",
			   adj->level, isis_adj_name(adj));
	if (old_value != adj->bfd_rfc6213.bfd_ipv4_required &&
	    adj->bfd_rfc6213.bfd_ipv4_required)
		isis_bfd_transition_bfd_required(adj, true,
						 "bfd_ipv4_required is True");

	old_value = adj->bfd_rfc6213.bfd_ipv6_required;
	adj->bfd_rfc6213.bfd_ipv6_required = false;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		if (bfd_local_pair->nlpid == NLPID_IPV6 &&
		    bfd_local_pair->topo_nlpid_bfd_required) {
			adj->bfd_rfc6213.bfd_ipv6_required = true;
			break;
		}
	}
	if (debug && (!adj->bfd_rfc6213.inited ||
		      old_value != adj->bfd_rfc6213.bfd_ipv6_required))
		zlog_debug("ISIS-BFD: bfd_ipv6_required is %s on L%u adjacency %s",
			   adj->bfd_rfc6213.bfd_ipv6_required ? "True" : "False",
			   adj->level, isis_adj_name(adj));
	if (old_value != adj->bfd_rfc6213.bfd_ipv6_required &&
	    adj->bfd_rfc6213.bfd_ipv6_required)
		isis_bfd_transition_bfd_required(adj, true,
						 "bfd_ipv6_required is True");

	/* RFC6213, 3.1. ISIS_TOPO_BFD_REQUIRED
	 * For each locally supported MTID, an "ISIS_TOPO_BFD_REQUIRED" variable
	 * is set to the logical "OR" of all "ISIS_TOPO_NLPID_BFD_REQUIRED"
	 * variables associated with that MTID.
	 */
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst, mtnode,
				  bfd_local_topo)) {
		old_value = bfd_local_topo->topo_bfd_required;
		bfd_local_topo->topo_bfd_required = false;
		for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst,
					  node, bfd_local_pair)) {
			if (bfd_local_topo->mtid == bfd_local_pair->mtid)
				bfd_local_topo->topo_bfd_required |=
					bfd_local_pair->topo_nlpid_bfd_required;
		}
		if (debug && (!bfd_local_topo->inited ||
			      old_value != bfd_local_topo->topo_bfd_required))
			zlog_debug("ISIS-BFD: local MT %s BFD is %srequired on L%u adjacency %s",
				   isis_mtid2str(bfd_local_topo->mtid),
				   bfd_local_topo->topo_bfd_required ? ""
								     : "not ",
				   adj->level, isis_adj_name(adj));
	}

	/* RFC6213, 3.1. ISIS_BFD_REQUIRED
	 * An "ISIS_BFD_REQUIRED" variable is set to the logical "AND" of all
	 * "ISIS_TOPO_BFD_REQUIRED" variables.
	 */
	adj->bfd_rfc6213.bfd_required_last = adj->bfd_rfc6213.bfd_required;
	if (list_isempty(adj->bfd_rfc6213.local_mtid_lst))
		adj->bfd_rfc6213.bfd_required = false;
	else {
		adj->bfd_rfc6213.bfd_required = true;
		for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst,
					  mtnode, bfd_local_topo)) {
			adj->bfd_rfc6213.bfd_required &=
				bfd_local_topo->topo_bfd_required;
		}
	}

	if (IS_DEBUG_BFD &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config) &&
	    adj->bfd_rfc6213.bfd_required_last != adj->bfd_rfc6213.bfd_required) {
		zlog_debug("ISIS-BFD: BFD is %srequired for L%u adjacency %s",
			   adj->bfd_rfc6213.bfd_required ? "" : "not ",
			   adj->level, isis_adj_name(adj));
	}
	if (adj->bfd_rfc6213.bfd_required_last != adj->bfd_rfc6213.bfd_required) {
		if (!adj->bfd_rfc6213.bfd_required)
			isis_bfd_transition_bfd_required(adj, false,
							 "BFD required is FALSE");
	}

	if (debug &&
	    (!adj->bfd_rfc6213.inited || adj->bfd_rfc6213.bfd_required_last !=
						 adj->bfd_rfc6213.bfd_required))
		zlog_debug("ISIS-BFD: local BFD is %srequired on L%u adjacency %s",
			   adj->bfd_rfc6213.bfd_required ? "" : "not ",
			   adj->level, isis_adj_name(adj));

	/* RFC6213, 3.1. ISIS_NEIGHBOR_USEABLE
	 * An "ISIS_NEIGHBOR_USEABLE" variable is set to the logical "OR" of all
	 * "ISIS_TOPO_USEABLE" variables.
	 */
	old_value = adj->bfd_rfc6213.neighbor_useable;
	adj->bfd_rfc6213.neighbor_useable = false;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst, mtnode,
				  bfd_local_topo)) {
		adj->bfd_rfc6213.neighbor_useable |=
			bfd_local_topo->topo_useable;
	}

	if (debug && (!adj->bfd_rfc6213.inited ||
		      old_value != adj->bfd_rfc6213.neighbor_useable))
		zlog_debug("ISIS-BFD: neighbor is %suseable on L%u adjacency %s",
			   adj->bfd_rfc6213.neighbor_useable ? "" : "not ",
			   adj->level, isis_adj_name(adj));

	/* set inited value to true in order to not display debug logs
	 * next time unless a value has changed.
	 */
	adj->bfd_rfc6213.inited = true;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair))
		bfd_local_pair->inited = true;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtid_lst, mtnode,
				  bfd_local_topo))
		bfd_local_topo->inited = true;
}

/* RFC6213, 3.1.
 * family parameter is either AF_INET or AF_INET6
 */
static void isis_bfd_update_status_rfc6213(struct isis_adjacency *adj,
					   uint8_t family)
{
	struct listnode *node;
	struct bfd_local_mtnlpid *bfd_local_pair;
	bool found;
	char buf[BUFSIZ];

	if (family != AF_INET && family != AF_INET6)
		return;

	if ((family == AF_INET &&
	     CHECK_FLAG(adj->bfd_rfc6213.flags, BFD_ADJ_STOP_IPV4)) ||
	    (family == AF_INET6 &&
	     CHECK_FLAG(adj->bfd_rfc6213.flags, BFD_ADJ_STOP_IPV6))) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: L%u adjacency %s BFD_ADJ_STOP_IPV%d is set. Nothing to do.",
				   adj->level, isis_adj_name(adj),
				   family == AF_INET ? 4 : 6);
		return;
	}

	if (!adj->circuit ||
	    !isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config)) {
		if (IS_DEBUG_BFD)
			zlog_debug("ISIS-BFD: L%u adjacency %s IPv%d RFC6213 is disabled.",
				   adj->level, isis_adj_name(adj),
				   family == AF_INET ? 4 : 6);
		return;
	}

	/* internal.
	 * If no nlpid is supported in receiving TLV
	 * or if BFD is not required by local configuration
	 * then BFD session establishment is no longer required
	 */
	if ((family == AF_INET && !adj->bfd_rfc6213.bfd_ipv4_required) ||
	    (family == AF_INET6 && !adj->bfd_rfc6213.bfd_ipv6_required)) {
		snprintf(buf, sizeof(buf),
			 "L%u adjacency %s, address family not required.",
			 adj->level, isis_adj_name(adj));
		bfd_handle_adj_down(adj, family, buf);
		return;
	}

	/* RFC6213, 4.
	 * If the value of "ISIS_BFD_REQUIRED" becomes "FALSE"
	 * then BFD session establishment is no longer required
	 * other case : at startup, BFD required is "FALSE"
	 */
	if (adj->bfd_rfc6213.bfd_required_last &&
	    ((family == AF_INET && !adj->bfd_rfc6213.bfd_ipv4_required) ||
	     (family == AF_INET6 && !adj->bfd_rfc6213.bfd_ipv6_required))) {
		snprintf(buf, sizeof(buf),
			 "L%u adjacency %s, ISIS_BFD_REQUIRED %s becomes false.",
			 adj->level, isis_adj_name(adj), family2str(family));
		bfd_handle_adj_down(adj, family, buf);
		return;
	}

	found = false;
	for (ALL_LIST_ELEMENTS_RO(adj->bfd_rfc6213.local_mtnlpid_lst, node,
				  bfd_local_pair)) {
		if (bfd_local_pair->nlpid == NLPID_IP && family != AF_INET)
			continue;
		if (bfd_local_pair->nlpid == NLPID_IPV6 && family != AF_INET6)
			continue;

		found = true;
		if (bfd_local_pair->topo_nlpid_bfd_required) {
			if (family == AF_INET &&
			    (!adj->bfd_session_ipv4 ||
			     bfd_sess_status(adj->bfd_session_ipv4) !=
				     BFD_STATUS_UP)) {
				if (IS_DEBUG_BFD)
					zlog_debug("ISIS-BFD: L%u adjacency %s IPv%d: initializing BFD.",
						   adj->level,
						   isis_adj_name(adj),
						   family == AF_INET ? 4 : 6);
				bfd_handle_run_bfd(adj, family);
			}
			if (family == AF_INET6 &&
			    (!adj->bfd_session_ipv6 ||
			     bfd_sess_status(adj->bfd_session_ipv6) !=
				     BFD_STATUS_UP)) {
				if (IS_DEBUG_BFD)
					zlog_debug("ISIS-BFD: L%u adjacency %s IPv%d: initializing BFD.",
						   adj->level,
						   isis_adj_name(adj),
						   family == AF_INET ? 4 : 6);
				bfd_handle_run_bfd(adj, family);
			}
		} else {
			snprintf(buf, sizeof(buf),
				 "L%u adjacency %s, ISIS_TOPO_NLPID_BFD_REQUIRED is false.",
				 adj->level, isis_adj_name(adj));
			bfd_handle_adj_down(adj, family, buf);
		}
	}
	if (!found) {
		snprintf(buf, sizeof(buf),
			 "L%u adjacency %s, local NLPID not found.", adj->level,
			 isis_adj_name(adj));
		bfd_handle_adj_down(adj, family, buf);
	}
}

bool isis_bfd_config_rfc6213_enabled(struct bfd_conf *config)
{
	if (config->rfc6213_ipv4 || config->rfc6213_ipv6)
		return true;
	return false;
}

static void isis_bfd_show_mtid_nlpid(struct vty *vty, uint8_t mtid_nlpid)
{
	uint8_t mtid_nlpid_flag, nlpid, i;
	bool first = true;
	uint16_t mtid;

	if (!mtid_nlpid) {
		vty_out(vty, "null\n");
		return;
	}

	for (i = 0; i < sizeof(mtid_nlpid_flag) * 8; i++) {
		mtid_nlpid_flag = 0x1 << i;
		if (!CHECK_FLAG(mtid_nlpid, mtid_nlpid_flag))
			continue;

		mtid = isis_bfd_mtnplid2mtpid(mtid_nlpid_flag);
		nlpid = isis_bfd_mtnplid2nlpid(mtid_nlpid_flag);
		vty_out(vty, "%s(%s,%s)", first ? "" : ", ",
			isis_mtid2str(mtid), nlpid2str(nlpid));
		first = false;
	}
	vty_out(vty, "\n");
}

void isis_bfd_show_adjacency(struct vty *vty, struct isis_adjacency *adj)
{
	if (!adj->bfd_rfc6213.neighbor_mtid_nlpid)
		return;
	vty_out(vty, "    RFC6213 (MTID,NLPID):\n");
	vty_out(vty, "        Local   : ");
	isis_bfd_show_mtid_nlpid(vty, adj->circuit->bfd_config.mtid_nlpid);
	vty_out(vty, "        Neighbor: ");
	isis_bfd_show_mtid_nlpid(vty, adj->bfd_rfc6213.neighbor_mtid_nlpid);
}

/* RFC6213, 4.
 * Check if adjacency hold-timer must be updated
 * - returns true when a BFD admin down is detected in one of the bfd sessions.
 * - returns true if adjacency is up and "ISIS_NEIGHBOR_USEABLE" is "FALSE"
 * - returns false otherwise
 */
bool isis_bfd_dont_update_adjacency_holdtime(struct isis_adjacency *adj)
{
	bool ipv4 = false;
	bool ipv6 = false;
	bool state = false;

	if (adj->circuit->bfd_config.rfc6213_ipv4)
		ipv4 = isis_bfd_session_is_admin_down(adj, adj->bfd_session_ipv4,
						      false);

	if (adj->circuit->bfd_config.rfc6213_ipv6)
		ipv6 = isis_bfd_session_is_admin_down(adj, adj->bfd_session_ipv6,
						      false);

	state = isis_bfd_is_neighbor_not_useable(adj, false);

	if (adj->circuit->bfd_config.rfc6213_ipv4 &&
	    !adj->circuit->bfd_config.rfc6213_ipv6)
		return ipv4 || state;

	if (adj->circuit->bfd_config.rfc6213_ipv6 &&
	    !adj->circuit->bfd_config.rfc6213_ipv4)
		return ipv6 || state;

	return ipv4 || ipv6 || state;
}
