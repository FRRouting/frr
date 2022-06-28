/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
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
#include "isisd/isisd.h"
#include "isisd/fabricd.h"

DEFINE_MTYPE_STATIC(ISISD, BFD_SESSION, "ISIS BFD Session");

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

void isis_bfd_init(struct thread_master *tm)
{
	bfd_protocol_integration_init(zclient, tm);

	hook_register(isis_adj_state_change_hook, bfd_handle_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, bfd_handle_adj_ip_enabled);
	hook_register(isis_circuit_add_addr_hook, bfd_handle_circuit_add_addr);
}
