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

DEFINE_MTYPE_STATIC(ISISD, BFD_SESSION, "ISIS BFD Session")

struct bfd_session {
	int family;
	union g_addr dst_ip;
	union g_addr src_ip;
	int status;
};

static struct bfd_session *bfd_session_new(int family, union g_addr *dst_ip,
					   union g_addr *src_ip)
{
	struct bfd_session *rv;

	rv = XCALLOC(MTYPE_BFD_SESSION, sizeof(*rv));
	rv->family = family;
	rv->dst_ip = *dst_ip;
	rv->src_ip = *src_ip;
	return rv;
}

static void bfd_session_free(struct bfd_session **session)
{
	if (!*session)
		return;

	XFREE(MTYPE_BFD_SESSION, *session);
	*session = NULL;
}

static bool bfd_session_same(const struct bfd_session *session, int family,
			     const union g_addr *src, const union g_addr *dst)
{
	if (session->family != family)
		return false;

	switch (session->family) {
	case AF_INET:
		if (!IPV4_ADDR_SAME(&session->dst_ip.ipv4, &dst->ipv4))
			return false;
		if (!IPV4_ADDR_SAME(&session->src_ip.ipv4, &src->ipv4))
			return false;
		break;
	case AF_INET6:
		if (!IPV6_ADDR_SAME(&session->dst_ip.ipv6, &dst->ipv6))
			return false;
		if (!IPV6_ADDR_SAME(&session->src_ip.ipv6, &src->ipv6))
			return false;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown address-family: %u",
			 __func__, session->family);
		exit(1);
	}

	return true;
}

static void bfd_adj_event(struct isis_adjacency *adj, struct prefix *dst,
			  int new_status)
{
	if (!adj->bfd_session)
		return;

	if (adj->bfd_session->family != dst->family)
		return;

	switch (adj->bfd_session->family) {
	case AF_INET:
		if (!IPV4_ADDR_SAME(&adj->bfd_session->dst_ip.ipv4,
				    &dst->u.prefix4))
			return;
		break;
	case AF_INET6:
		if (!IPV6_ADDR_SAME(&adj->bfd_session->dst_ip.ipv6,
				    &dst->u.prefix6))
			return;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown address-family: %u",
			 __func__, adj->bfd_session->family);
		exit(1);
	}

	int old_status = adj->bfd_session->status;

	BFD_SET_CLIENT_STATUS(adj->bfd_session->status, new_status);

	if (old_status == new_status)
		return;

	if (isis->debugs & DEBUG_BFD) {
		char dst_str[INET6_ADDRSTRLEN];

		inet_ntop(adj->bfd_session->family, &adj->bfd_session->dst_ip,
			  dst_str, sizeof(dst_str));
		zlog_debug("ISIS-BFD: Peer %s on %s changed from %s to %s",
			   dst_str, adj->circuit->interface->name,
			   bfd_get_status_str(old_status),
			   bfd_get_status_str(new_status));
	}

	if (old_status != BFD_STATUS_UP
	    || new_status != BFD_STATUS_DOWN) {
		return;
	}

	isis_adj_state_change(adj, ISIS_ADJ_DOWN, "bfd session went down");
}

static int isis_bfd_interface_dest_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct prefix dst_ip;
	int status;

	ifp = bfd_get_peer_info(zclient->ibuf, &dst_ip, NULL, &status,
				NULL, vrf_id);
	if (!ifp || (dst_ip.family != AF_INET && dst_ip.family != AF_INET6))
		return 0;

	if (isis->debugs & DEBUG_BFD) {
		char dst_buf[INET6_ADDRSTRLEN];

		inet_ntop(dst_ip.family, &dst_ip.u.prefix, dst_buf,
			  sizeof(dst_buf));

		zlog_debug("ISIS-BFD: Received update for %s on %s: Changed state to %s",
			   dst_buf, ifp->name, bfd_get_status_str(status));
	}

	struct isis_circuit *circuit = circuit_scan_by_ifp(ifp);

	if (!circuit)
		return 0;

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			struct list *adjdb = circuit->u.bc.adjdb[level - 1];

			struct listnode *node, *nnode;
			struct isis_adjacency *adj;

			for (ALL_LIST_ELEMENTS(adjdb, node, nnode, adj))
				bfd_adj_event(adj, &dst_ip, status);
		}
	} else if (circuit->circ_type == CIRCUIT_T_P2P) {
		if (circuit->u.p2p.neighbor) {
			bfd_adj_event(circuit->u.p2p.neighbor,
				      &dst_ip, status);
		}
	}

	return 0;
}

static int isis_bfd_nbr_replay(ZAPI_CALLBACK_ARGS)
{
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

	struct listnode *anode;
	struct isis_area *area;

	if (isis->debugs & DEBUG_BFD)
		zlog_debug("ISIS-BFD: Got neighbor replay request, resending neighbors.");

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		struct listnode *cnode;
		struct isis_circuit *circuit;

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			isis_bfd_circuit_cmd(circuit, ZEBRA_BFD_DEST_UPDATE);
	}

	if (isis->debugs & DEBUG_BFD)
		zlog_debug("ISIS-BFD: Done with replay.");

	return 0;
}

static void (*orig_zebra_connected)(struct zclient *);
static void isis_bfd_zebra_connected(struct zclient *zclient)
{
	if (orig_zebra_connected)
		orig_zebra_connected(zclient);

	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);
}

static void bfd_debug(int family, union g_addr *dst, union g_addr *src,
		      const char *interface, int command)
{
	if (!(isis->debugs & DEBUG_BFD))
		return;

	char dst_str[INET6_ADDRSTRLEN];
	char src_str[INET6_ADDRSTRLEN];

	inet_ntop(family, dst, dst_str, sizeof(dst_str));
	inet_ntop(family, src, src_str, sizeof(src_str));

	const char *command_str;

	switch (command) {
	case ZEBRA_BFD_DEST_REGISTER:
		command_str = "Register";
		break;
	case ZEBRA_BFD_DEST_DEREGISTER:
		command_str = "Deregister";
		break;
	case ZEBRA_BFD_DEST_UPDATE:
		command_str = "Update";
		break;
	default:
		command_str = "Unknown-Cmd";
		break;
	}

	zlog_debug("ISIS-BFD: %s peer %s on %s (src %s)",
		   command_str, dst_str, interface, src_str);
}

static void bfd_handle_adj_down(struct isis_adjacency *adj)
{
	if (!adj->bfd_session)
		return;

	bfd_debug(adj->bfd_session->family, &adj->bfd_session->dst_ip,
		  &adj->bfd_session->src_ip, adj->circuit->interface->name,
		  ZEBRA_BFD_DEST_DEREGISTER);

	bfd_peer_sendmsg(zclient, NULL, adj->bfd_session->family,
			 &adj->bfd_session->dst_ip,
			 &adj->bfd_session->src_ip,
			 adj->circuit->interface->name,
			 0, /* ttl */
			 0, /* multihop */
			 1, /* control plane independent bit is on */
			 ZEBRA_BFD_DEST_DEREGISTER,
			 0, /* set_flag */
			 VRF_DEFAULT);
	bfd_session_free(&adj->bfd_session);
}

static void bfd_handle_adj_up(struct isis_adjacency *adj, int command)
{
	struct isis_circuit *circuit = adj->circuit;
	int family;
	union g_addr dst_ip;
	union g_addr src_ip;
	struct list *local_ips;
	struct prefix *local_ip;

	if (!circuit->bfd_info)
		goto out;

	/*
	 * If IS-IS is enabled for both IPv4 and IPv6 on the circuit, prefer
	 * creating a BFD session over IPv6.
	 */
	if (circuit->ipv6_router && adj->ipv6_address_count) {
		family = AF_INET6;
		dst_ip.ipv6 = adj->ipv6_addresses[0];
		local_ips = circuit->ipv6_link;
		if (!local_ips || list_isempty(local_ips))
			goto out;
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv6 = local_ip->u.prefix6;
	} else if (circuit->ip_router && adj->ipv4_address_count) {
		family = AF_INET;
		dst_ip.ipv4 = adj->ipv4_addresses[0];
		local_ips = fabricd_ip_addrs(adj->circuit);
		if (!local_ips || list_isempty(local_ips))
			goto out;
		local_ip = listgetdata(listhead(local_ips));
		src_ip.ipv4 = local_ip->u.prefix4;
	} else
		goto out;

	if (adj->bfd_session) {
		if (bfd_session_same(adj->bfd_session, family, &src_ip,
				     &dst_ip))
			bfd_handle_adj_down(adj);
	}

	if (!adj->bfd_session)
		adj->bfd_session = bfd_session_new(family, &dst_ip, &src_ip);

	bfd_debug(adj->bfd_session->family, &adj->bfd_session->dst_ip,
		  &adj->bfd_session->src_ip, circuit->interface->name, command);
	bfd_peer_sendmsg(zclient, circuit->bfd_info, adj->bfd_session->family,
			 &adj->bfd_session->dst_ip,
			 &adj->bfd_session->src_ip,
			 circuit->interface->name,
			 0, /* ttl */
			 0, /* multihop */
			 1, /* control plane independent bit is on */
			 command,
			 0, /* set flag */
			 VRF_DEFAULT);
	return;
out:
	bfd_handle_adj_down(adj);
}

static int bfd_handle_adj_state_change(struct isis_adjacency *adj)
{
	if (adj->adj_state == ISIS_ADJ_UP)
		bfd_handle_adj_up(adj, ZEBRA_BFD_DEST_REGISTER);
	else
		bfd_handle_adj_down(adj);
	return 0;
}

static void bfd_adj_cmd(struct isis_adjacency *adj, int command)
{
	if (adj->adj_state == ISIS_ADJ_UP
	    && command != ZEBRA_BFD_DEST_DEREGISTER) {
		bfd_handle_adj_up(adj, command);
	} else {
		bfd_handle_adj_down(adj);
	}
}

void isis_bfd_circuit_cmd(struct isis_circuit *circuit, int command)
{
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			struct list *adjdb = circuit->u.bc.adjdb[level - 1];

			struct listnode *node;
			struct isis_adjacency *adj;

			for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj))
				bfd_adj_cmd(adj, command);
		}
		break;
	case CIRCUIT_T_P2P:
		if (circuit->u.p2p.neighbor)
			bfd_adj_cmd(circuit->u.p2p.neighbor, command);
		break;
	default:
		break;
	}
}

void isis_bfd_circuit_param_set(struct isis_circuit *circuit,
				uint32_t min_rx, uint32_t min_tx,
				uint32_t detect_mult, int defaults)
{
	int command = 0;

	bfd_set_param(&circuit->bfd_info, min_rx,
		      min_tx, detect_mult, defaults, &command);

	if (command)
		isis_bfd_circuit_cmd(circuit, command);
}

static int bfd_circuit_write_settings(struct isis_circuit *circuit,
				      struct vty *vty)
{
	struct bfd_info *bfd_info = circuit->bfd_info;

	if (!bfd_info)
		return 0;

	vty_out(vty, " %s bfd\n", PROTO_NAME);
	return 1;
}

void isis_bfd_init(void)
{
	bfd_gbl_init();

	orig_zebra_connected = zclient->zebra_connected;
	zclient->zebra_connected = isis_bfd_zebra_connected;
	zclient->interface_bfd_dest_update = isis_bfd_interface_dest_update;
	zclient->bfd_dest_replay = isis_bfd_nbr_replay;
	hook_register(isis_adj_state_change_hook,
		      bfd_handle_adj_state_change);
	hook_register(isis_circuit_config_write,
		      bfd_circuit_write_settings);
}
