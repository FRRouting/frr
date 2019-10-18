/*
 * EIGRP Interface Functions.
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

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "keychain.h"
#include "vrf.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_dump.h"

struct eigrp_interface *eigrp_if_new(struct eigrp *eigrp, struct interface *ifp,
				     struct prefix *p)
{
	struct eigrp_interface *ei = ifp->info;
	int i;

	if (ei)
		return ei;

	ei = XCALLOC(MTYPE_EIGRP_IF, sizeof(struct eigrp_interface));

	/* Set zebra interface pointer. */
	ei->ifp = ifp;
	prefix_copy(&ei->address, p);

	ifp->info = ei;
	listnode_add(eigrp->eiflist, ei);

	ei->type = EIGRP_IFTYPE_BROADCAST;

	/* Initialize neighbor list. */
	ei->nbrs = list_new();

	ei->crypt_seqnum = time(NULL);

	/* Initialize lists */
	for (i = 0; i < EIGRP_FILTER_MAX; i++) {
		ei->list[i] = NULL;
		ei->prefix[i] = NULL;
		ei->routemap[i] = NULL;
	}

	ei->eigrp = eigrp;

	ei->params.v_hello = EIGRP_HELLO_INTERVAL_DEFAULT;
	ei->params.v_wait = EIGRP_HOLD_INTERVAL_DEFAULT;
	ei->params.bandwidth = EIGRP_BANDWIDTH_DEFAULT;
	ei->params.delay = EIGRP_DELAY_DEFAULT;
	ei->params.reliability = EIGRP_RELIABILITY_DEFAULT;
	ei->params.load = EIGRP_LOAD_DEFAULT;
	ei->params.auth_type = EIGRP_AUTH_TYPE_NONE;
	ei->params.auth_keychain = NULL;

	return ei;
}

int eigrp_if_delete_hook(struct interface *ifp)
{
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	if (!ei)
		return 0;

	list_delete(&ei->nbrs);

	eigrp = ei->eigrp;
	listnode_delete(eigrp->eiflist, ei);

	eigrp_fifo_free(ei->obuf);

	XFREE(MTYPE_EIGRP_IF_INFO, ifp->info);
	ifp->info = NULL;

	return 0;
}

static int eigrp_ifp_create(struct interface *ifp)
{
	struct eigrp_interface *ei = ifp->info;

	if (!ei)
		return 0;

	ei->params.type = eigrp_default_iftype(ifp);

	eigrp_if_update(ifp);

	return 0;
}

static int eigrp_ifp_up(struct interface *ifp)
{
	/* Interface is already up. */
	if (if_is_operative(ifp)) {
		/* Temporarily keep ifp values. */
		struct interface if_tmp;
		memcpy(&if_tmp, ifp, sizeof(struct interface));

		if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
			zlog_debug("Zebra: Interface[%s] state update.",
				   ifp->name);

		if (if_tmp.bandwidth != ifp->bandwidth) {
			if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
				zlog_debug(
					"Zebra: Interface[%s] bandwidth change %d -> %d.",
					ifp->name, if_tmp.bandwidth,
					ifp->bandwidth);

			//          eigrp_if_recalculate_output_cost (ifp);
		}

		if (if_tmp.mtu != ifp->mtu) {
			if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
				zlog_debug(
					"Zebra: Interface[%s] MTU change %u -> %u.",
					ifp->name, if_tmp.mtu, ifp->mtu);

			/* Must reset the interface (simulate down/up) when MTU
			 * changes. */
			eigrp_if_reset(ifp);
		}
		return 0;
	}

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to up.",
			   ifp->name);

	if (ifp->info)
		eigrp_if_up(ifp->info);

	return 0;
}

static int eigrp_ifp_down(struct interface *ifp)
{
	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to down.",
			   ifp->name);

	if (ifp->info)
		eigrp_if_down(ifp->info);

	return 0;
}

static int eigrp_ifp_destroy(struct interface *ifp)
{
	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface delete %s index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	if (ifp->info)
		eigrp_if_free(ifp->info, INTERFACE_DOWN_BY_ZEBRA);

	return 0;
}

struct list *eigrp_iflist;

void eigrp_if_init(void)
{
	if_zapi_callbacks(eigrp_ifp_create, eigrp_ifp_up,
			  eigrp_ifp_down, eigrp_ifp_destroy);
	/* Initialize Zebra interface data structure. */
	// hook_register_prio(if_add, 0, eigrp_if_new);
	hook_register_prio(if_del, 0, eigrp_if_delete_hook);
}


void eigrp_del_if_params(struct eigrp_if_params *eip)
{
	if (eip->auth_keychain)
		free(eip->auth_keychain);
}

int eigrp_if_up(struct eigrp_interface *ei)
{
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_metrics metric;
	struct eigrp_interface *ei2;
	struct listnode *node, *nnode;
	struct eigrp *eigrp;

	if (ei == NULL)
		return 0;

	eigrp = ei->eigrp;
	eigrp_adjust_sndbuflen(eigrp, ei->ifp->mtu);

	eigrp_if_stream_set(ei);

	/* Set multicast memberships appropriately for new state. */
	eigrp_if_set_multicast(ei);

	thread_add_event(master, eigrp_hello_timer, ei, (1), NULL);

	/*Prepare metrics*/
	metric.bandwidth = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
	metric.delay = eigrp_delay_to_scaled(ei->params.delay);
	metric.load = ei->params.load;
	metric.reliability = ei->params.reliability;
	metric.mtu[0] = 0xDC;
	metric.mtu[1] = 0x05;
	metric.mtu[2] = 0x00;
	metric.hop_count = 0;
	metric.flags = 0;
	metric.tag = 0;

	/*Add connected entry to topology table*/

	ne = eigrp_nexthop_entry_new();
	ne->ei = ei;
	ne->reported_metric = metric;
	ne->total_metric = metric;
	ne->distance = eigrp_calculate_metrics(eigrp, metric);
	ne->reported_distance = 0;
	ne->adv_router = eigrp->neighbor_self;
	ne->flags = EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;

	struct prefix dest_addr;

	dest_addr = ei->address;
	apply_mask(&dest_addr);
	pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
					      &dest_addr);

	if (pe == NULL) {
		pe = eigrp_prefix_entry_new();
		pe->serno = eigrp->serno;
		pe->destination = (struct prefix *)prefix_ipv4_new();
		prefix_copy(pe->destination, &dest_addr);
		pe->af = AF_INET;
		pe->nt = EIGRP_TOPOLOGY_TYPE_CONNECTED;

		ne->prefix = pe;
		pe->reported_metric = metric;
		pe->state = EIGRP_FSM_STATE_PASSIVE;
		pe->fdistance = eigrp_calculate_metrics(eigrp, metric);
		pe->req_action |= EIGRP_FSM_NEED_UPDATE;
		eigrp_prefix_entry_add(eigrp->topology_table, pe);
		listnode_add(eigrp->topology_changes_internalIPV4, pe);

		eigrp_nexthop_entry_add(eigrp, pe, ne);

		for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei2)) {
			eigrp_update_send(ei2);
		}

		pe->req_action &= ~EIGRP_FSM_NEED_UPDATE;
		listnode_delete(eigrp->topology_changes_internalIPV4, pe);
	} else {
		struct eigrp_fsm_action_message msg;

		ne->prefix = pe;
		eigrp_nexthop_entry_add(eigrp, pe, ne);

		msg.packet_type = EIGRP_OPC_UPDATE;
		msg.eigrp = eigrp;
		msg.data_type = EIGRP_CONNECTED;
		msg.adv_router = NULL;
		msg.entry = ne;
		msg.prefix = pe;

		eigrp_fsm_event(&msg);
	}

	return 1;
}

int eigrp_if_down(struct eigrp_interface *ei)
{
	struct listnode *node, *nnode;
	struct eigrp_neighbor *nbr;

	if (ei == NULL)
		return 0;

	/* Shutdown packet reception and sending */
	if (ei->t_hello)
		THREAD_OFF(ei->t_hello);

	eigrp_if_stream_unset(ei);

	/*Set infinite metrics to routes learned by this interface and start
	 * query process*/
	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		eigrp_nbr_delete(nbr);
	}

	return 1;
}

void eigrp_if_stream_set(struct eigrp_interface *ei)
{
	/* set output fifo queue. */
	if (ei->obuf == NULL)
		ei->obuf = eigrp_fifo_new();
}

void eigrp_if_stream_unset(struct eigrp_interface *ei)
{
	struct eigrp *eigrp = ei->eigrp;

	if (ei->on_write_q) {
		listnode_delete(eigrp->oi_write_q, ei);
		if (list_isempty(eigrp->oi_write_q))
			thread_cancel(eigrp->t_write);
		ei->on_write_q = 0;
	}
}

bool eigrp_if_is_passive(struct eigrp_interface *ei)
{
	if (ei->params.passive_interface == EIGRP_IF_ACTIVE)
		return false;

	if (ei->eigrp->passive_interface_default == EIGRP_IF_ACTIVE)
		return false;

	return true;
}

void eigrp_if_set_multicast(struct eigrp_interface *ei)
{
	if (!eigrp_if_is_passive(ei)) {
		/* The interface should belong to the EIGRP-all-routers group.
		 */
		if (!ei->member_allrouters
		    && (eigrp_if_add_allspfrouters(ei->eigrp, &ei->address,
						   ei->ifp->ifindex)
			>= 0))
			/* Set the flag only if the system call to join
			 * succeeded. */
			ei->member_allrouters = true;
	} else {
		/* The interface should NOT belong to the EIGRP-all-routers
		 * group. */
		if (ei->member_allrouters) {
			/* Only actually drop if this is the last reference */
			eigrp_if_drop_allspfrouters(ei->eigrp, &ei->address,
						    ei->ifp->ifindex);
			/* Unset the flag regardless of whether the system call
			   to leave
			   the group succeeded, since it's much safer to assume
			   that
			   we are not a member. */
			ei->member_allrouters = false;
		}
	}
}

uint8_t eigrp_default_iftype(struct interface *ifp)
{
	if (if_is_pointopoint(ifp))
		return EIGRP_IFTYPE_POINTOPOINT;
	else if (if_is_loopback(ifp))
		return EIGRP_IFTYPE_LOOPBACK;
	else
		return EIGRP_IFTYPE_BROADCAST;
}

void eigrp_if_free(struct eigrp_interface *ei, int source)
{
	struct prefix dest_addr;
	struct eigrp_prefix_entry *pe;
	struct eigrp *eigrp = ei->eigrp;

	if (source == INTERFACE_DOWN_BY_VTY) {
		THREAD_OFF(ei->t_hello);
		eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
	}

	dest_addr = ei->address;
	apply_mask(&dest_addr);
	pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
					      &dest_addr);
	if (pe)
		eigrp_prefix_entry_delete(eigrp, eigrp->topology_table, pe);

	eigrp_if_down(ei);

	listnode_delete(ei->eigrp->eiflist, ei);
}

/* Simulate down/up on the interface.  This is needed, for example, when
   the MTU changes. */
void eigrp_if_reset(struct interface *ifp)
{
	struct eigrp_interface *ei = ifp->info;

	if (!ei)
		return;

	eigrp_if_down(ei);
	eigrp_if_up(ei);
}

struct eigrp_interface *eigrp_if_lookup_by_local_addr(struct eigrp *eigrp,
						      struct interface *ifp,
						      struct in_addr address)
{
	struct listnode *node;
	struct eigrp_interface *ei;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (ifp && ei->ifp != ifp)
			continue;

		if (IPV4_ADDR_SAME(&address, &ei->address.u.prefix4))
			return ei;
	}

	return NULL;
}

/**
 * @fn eigrp_if_lookup_by_name
 *
 * @param[in]		eigrp		EIGRP process
 * @param[in]		if_name 	Name of the interface
 *
 * @return struct eigrp_interface *
 *
 * @par
 * Function is used for lookup interface by name.
 */
struct eigrp_interface *eigrp_if_lookup_by_name(struct eigrp *eigrp,
						const char *if_name)
{
	struct eigrp_interface *ei;
	struct listnode *node;

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* compare int name with eigrp interface's name */
		if (strcmp(ei->ifp->name, if_name) == 0) {
			return ei;
		}
	}

	return NULL;
}

uint32_t eigrp_bandwidth_to_scaled(uint32_t bandwidth)
{
	uint64_t temp_bandwidth = (256ull * 10000000) / bandwidth;

	temp_bandwidth = temp_bandwidth < EIGRP_MAX_METRIC ? temp_bandwidth
							   : EIGRP_MAX_METRIC;

	return (uint32_t)temp_bandwidth;
}

uint32_t eigrp_scaled_to_bandwidth(uint32_t scaled)
{
	uint64_t temp_scaled = scaled * (256ull * 10000000);

	temp_scaled =
		temp_scaled < EIGRP_MAX_METRIC ? temp_scaled : EIGRP_MAX_METRIC;

	return (uint32_t)temp_scaled;
}

uint32_t eigrp_delay_to_scaled(uint32_t delay)
{
	return delay * 256;
}

uint32_t eigrp_scaled_to_delay(uint32_t scaled)
{
	return scaled / 256;
}
