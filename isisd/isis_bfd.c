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


static void adj_bfd_cb(struct bfd_session_params *bsp,
		       const struct bfd_session_status *bss, void *arg)
{
	struct isis_adjacency *adj = arg;

	if (IS_DEBUG_BFD)
		zlog_debug(
			"ISIS-BFD: BFD changed status for adjacency %s old %s new %s",
			isis_adj_name(adj),
			bfd_get_status_str(bss->previous_state),
			bfd_get_status_str(bss->state));

	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		adj->circuit->area->bfd_signalled_down = true;
		isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
				      "bfd session went down");
	}
}

static void bfd_handle_adj_down(struct isis_adjacency *adj)
{
	bfd_sess_free(&adj->bfd_session);
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

	bfd_handle_adj_down(adj);
	return 0;
}

static void bfd_handle_adj_up(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;
	int family;
	union g_addr dst_ip;
	union g_addr src_ip;
	struct list *local_ips;
	struct prefix *local_ip;

	if (!circuit->bfd_config.enabled) {
		if (IS_DEBUG_BFD)
			zlog_debug(
				"ISIS-BFD: skipping BFD initialization on adjacency with %s because BFD is not enabled for the circuit",
				isis_adj_name(adj));
		goto out;
	}

	/* If IS-IS IPv6 is configured wait for IPv6 address to be programmed
	 * before starting up BFD
	 */
	if (circuit->ipv6_router
	    && (listcount(circuit->ipv6_link) == 0
		|| adj->ll_ipv6_count == 0)) {
		if (IS_DEBUG_BFD)
			zlog_debug(
				"ISIS-BFD: skipping BFD initialization on adjacency with %s because IPv6 is enabled but not ready",
				isis_adj_name(adj));
		return;
	}

	/*
	 * If IS-IS is enabled for both IPv4 and IPv6 on the circuit, prefer
	 * creating a BFD session over IPv6.
	 */
	if (circuit->ipv6_router && adj->ll_ipv6_count) {
		family = AF_INET6;
		dst_ip.ipv6 = adj->ll_ipv6_addrs[0];
		local_ips = circuit->ipv6_link;
		if (list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv6 enabled and no local IPv6 addresses");
			goto out;
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv6 = local_ip->u.prefix6;
	} else if (circuit->ip_router && adj->ipv4_address_count) {
		family = AF_INET;
		dst_ip.ipv4 = adj->ipv4_addresses[0];
		local_ips = fabricd_ip_addrs(adj->circuit);
		if (!local_ips || list_isempty(local_ips)) {
			if (IS_DEBUG_BFD)
				zlog_debug(
					"ISIS-BFD: skipping BFD initialization: IPv4 enabled and no local IPv4 addresses");
			goto out;
		}
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv4 = local_ip->u.prefix4;
	} else
		goto out;

	if (adj->bfd_session == NULL)
		adj->bfd_session = bfd_sess_new(adj_bfd_cb, adj);

	bfd_sess_set_timers(adj->bfd_session, BFD_DEF_DETECT_MULT,
			    BFD_DEF_MIN_RX, BFD_DEF_MIN_TX);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(adj->bfd_session, &src_ip.ipv4,
					&dst_ip.ipv4);
	else
		bfd_sess_set_ipv6_addrs(adj->bfd_session, &src_ip.ipv6,
					&dst_ip.ipv6);
	bfd_sess_set_interface(adj->bfd_session, adj->circuit->interface->name);
	bfd_sess_set_vrf(adj->bfd_session,
			 adj->circuit->interface->vrf->vrf_id);
	bfd_sess_set_profile(adj->bfd_session, circuit->bfd_config.profile);
	bfd_sess_install(adj->bfd_session);
	return;
out:
	bfd_handle_adj_down(adj);
}

void isis_bfd_init_adjacency(struct isis_adjacency *adj)
{
	if (IS_DEBUG_BFD &&
	    isis_bfd_config_rfc6213_enabled(&adj->circuit->bfd_config))
		zlog_debug("ISIS-BFD: L%u adjacency %s becomes up. Initializing RFC6213 structures.",
			   adj->level, isis_adj_name(adj));

	adj->bfd_rfc6213.local_mtnlpid_lst = list_new();
	adj->bfd_rfc6213.local_mtid_lst = list_new();
}


static int bfd_handle_adj_state_change(struct isis_adjacency *adj)
{
	if (adj->adj_state == ISIS_ADJ_UP)
		bfd_handle_adj_up(adj);
	else
		bfd_handle_adj_down(adj);
	return 0;
}

static void bfd_adj_cmd(struct isis_adjacency *adj)
{
	if (adj->adj_state == ISIS_ADJ_UP && adj->circuit->bfd_config.enabled)
		bfd_handle_adj_up(adj);
	else
		bfd_handle_adj_down(adj);
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

	if (adj->bfd_session)
		return 0;

	if (adj->adj_state != ISIS_ADJ_UP)
		return 0;

	bfd_handle_adj_up(adj);

	return 0;
}

static int bfd_handle_circuit_add_addr(struct isis_circuit *circuit)
{
	struct isis_adjacency *adj;
	struct listnode *node;

	if (circuit->area == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(circuit->area->adjacency_list, node, adj)) {
		if (adj->bfd_session)
			continue;

		if (adj->adj_state != ISIS_ADJ_UP)
			continue;

		bfd_handle_adj_up(adj);
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

void isis_bfd_adjacency_update_rfc6213_local_params(struct isis_adjacency *adj)
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

bool isis_bfd_config_rfc6213_enabled(struct bfd_conf *config)
{
	if (config->rfc6213_ipv4 || config->rfc6213_ipv6)
		return true;
	return false;
}
