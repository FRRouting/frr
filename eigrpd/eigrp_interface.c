// SPDX-License-Identifier: GPL-2.0-or-later
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
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "network.h"
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
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_types.h"
#include "eigrpd/eigrp_metric.h"

DEFINE_MTYPE_STATIC(EIGRPD, EIGRP_IF, "EIGRP interface");
DEFINE_MTYPE_STATIC(EIGRPD, EIGRP_CONNECTED, "EIGRP connected prefix");
DEFINE_MTYPE_STATIC(EIGRPD, EIGRP_IF_INFO, "EIGRP interface info");
DEFINE_MTYPE_STATIC(EIGRPD, EIGRP_IF_PARAMS, "EIGRP interface parameters");

struct eigrp_if_params *eigrp_new_if_params(void)
{
	struct eigrp_if_params *eip;

	eip = XCALLOC(MTYPE_EIGRP_IF_PARAMS, sizeof(struct eigrp_if_params));

	eip->v_hello = EIGRP_HELLO_INTERVAL_DEFAULT;
	eip->v_wait = EIGRP_HOLD_INTERVAL_DEFAULT;
	eip->bandwidth = EIGRP_BANDWIDTH_DEFAULT;
	eip->delay = EIGRP_DELAY_DEFAULT;
	eip->reliability = EIGRP_RELIABILITY_DEFAULT;
	eip->load = EIGRP_LOAD_DEFAULT;
	eip->auth_type = EIGRP_AUTH_TYPE_NONE;
	eip->auth_keychain = NULL;

	return eip;
}

/*
 * Allocate the per-interface EIGRP data on demand.
 *
 * Called both from the interface-creation hook and from the northbound
 * configuration callbacks, so that configuration entered before EIGRP is
 * running has somewhere to live (issue #11301).
 */
struct eigrp_if_info *eigrp_if_info_get(struct interface *ifp)
{
	struct eigrp_if_info *eii = ifp->info;

	if (eii)
		return eii;

	eii = XCALLOC(MTYPE_EIGRP_IF_INFO, sizeof(struct eigrp_if_info));
	eii->def_params = eigrp_new_if_params();
	eii->def_params->type = eigrp_default_iftype(ifp);
	eii->eis = list_new();

	ifp->info = eii;

	return eii;
}

void eigrp_if_info_free(struct interface *ifp)
{
	struct eigrp_if_info *eii = ifp->info;

	if (!eii)
		return;

	list_delete(&eii->eis);

	eigrp_del_if_params(eii->def_params);
	XFREE(MTYPE_EIGRP_IF_PARAMS, eii->def_params);

	XFREE(MTYPE_EIGRP_IF_INFO, ifp->info);
}

struct eigrp_connected *eigrp_connected_lookup(struct eigrp_interface *ei,
					      const struct prefix *address)
{
	struct eigrp_connected *ec;
	struct listnode *node;
	struct prefix subnet;

	prefix_copy(&subnet, address);
	apply_mask(&subnet);

	for (ALL_LIST_ELEMENTS_RO(ei->connected, node, ec))
		if (prefix_same(&ec->address, &subnet))
			return ec;

	return NULL;
}

struct eigrp_connected *eigrp_connected_add(struct eigrp_interface *ei,
					    const struct prefix *address)
{
	struct eigrp_connected *ec;

	ec = eigrp_connected_lookup(ei, address);
	if (ec)
		return ec;

	ec = XCALLOC(MTYPE_EIGRP_CONNECTED, sizeof(struct eigrp_connected));
	ec->ei = ei;
	prefix_copy(&ec->address, address);
	apply_mask(&ec->address);

	listnode_add(ei->connected, ec);

	return ec;
}

/*
 * Stop advertising a connected subnet.
 *
 * This keeps master's behaviour of dropping the whole prefix descriptor
 * rather than just this instance's contribution; narrowing that is a
 * separate concern from where the subnet list lives.
 */
void eigrp_connected_withdraw(struct eigrp_connected *ec)
{
	struct eigrp *eigrp = ec->ei->eigrp;
	struct eigrp_prefix_descriptor *pe;

	pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
					      &ec->address);
	if (pe)
		eigrp_prefix_descriptor_delete(eigrp, eigrp->topology_table,
					       pe);
}

void eigrp_connected_delete(struct eigrp_connected *ec)
{
	listnode_delete(ec->ei->connected, ec);
	XFREE(MTYPE_EIGRP_CONNECTED, ec);
}

struct eigrp_interface *eigrp_if_lookup(struct eigrp *eigrp, struct interface *ifp)
{
	struct eigrp_interface *ei;
	struct listnode *node;

	if (!ifp->info)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(EIGRP_IF_EIS(ifp), node, ei))
		if (ei->eigrp == eigrp)
			return ei;

	return NULL;
}

struct eigrp_interface *eigrp_if_lookup_by_ifp(struct interface *ifp)
{
	if (!ifp->info || list_isempty(EIGRP_IF_EIS(ifp)))
		return NULL;

	return listnode_head(EIGRP_IF_EIS(ifp));
}

int eigrp_interface_cmp(const struct eigrp_interface *a, const struct eigrp_interface *b)
{
	return if_cmp_func(a->ifp, b->ifp);
}

uint32_t eigrp_interface_hash(const struct eigrp_interface *ei)
{
	return ei->ifp->ifindex;
}

struct eigrp_interface *eigrp_if_new(struct eigrp *eigrp, struct interface *ifp,
				     struct prefix *p)
{
	struct eigrp_if_info *eii = eigrp_if_info_get(ifp);
	struct eigrp_interface *ei;
	int i;

	/*
	 * One instance per EIGRP process per interface.  A second `network`
	 * statement in the same process matching another connected prefix
	 * reuses this instance rather than making a new one; which prefixes
	 * it advertises is tracked separately.
	 */
	ei = eigrp_if_lookup(eigrp, ifp);
	if (ei)
		return ei;

	ei = XCALLOC(MTYPE_EIGRP_IF, sizeof(struct eigrp_interface));

	/* Set zebra interface pointer. */
	ei->ifp = ifp;
	prefix_copy(&ei->address, p);

	listnode_add(eii->eis, ei);
	eigrp_interface_hash_add(&eigrp->eifs, ei);

	ei->type = EIGRP_IFTYPE_BROADCAST;

	/* Initialize neighbor list. */
	eigrp_nbr_hash_init(&ei->nbr_hash_head);

	ei->connected = list_new();

	ei->crypt_seqnum = frr_sequence32_next();

	/* Initialize lists */
	for (i = 0; i < EIGRP_FILTER_MAX; i++) {
		ei->list[i] = NULL;
		ei->prefix[i] = NULL;
		ei->routemap[i] = NULL;
	}

	ei->eigrp = eigrp;

	/*
	 * Configuration is owned by the interface, not by this object, so
	 * anything set before EIGRP started is picked up here rather than
	 * being reset to defaults.
	 */
	ei->params = eii->def_params;

	ei->curr_bandwidth = ifp->bandwidth;
	ei->curr_mtu = ifp->mtu;

	return ei;
}

static void eigrp_if_delete_one(struct eigrp_interface *ei)
{
	struct eigrp *eigrp = ei->eigrp;

	eigrp_nbr_hash_fini(&ei->nbr_hash_head);
	eigrp_interface_hash_del(&eigrp->eifs, ei);

	while (!list_isempty(ei->connected))
		eigrp_connected_delete(listnode_head(ei->connected));
	list_delete(&ei->connected);
	eigrp_fifo_free(ei->obuf);

	XFREE(MTYPE_EIGRP_IF, ei);
}

/*
 * Detach one running instance from its interface and free it, leaving the
 * interface's configuration alone.
 *
 * Without this, stopping EIGRP on an interface would leave the instance in
 * the interface's table and in the process-wide hash, so the interface would
 * still look like it was running and could never be reactivated.
 */
static void eigrp_if_remove(struct eigrp_interface *ei)
{
	struct interface *ifp = ei->ifp;

	listnode_delete(EIGRP_IF_EIS(ifp), ei);

	eigrp_if_delete_one(ei);
}

/*
 * Tear down every running instance on an interface, but keep the interface's
 * configuration.
 *
 * This is the path taken when an EIGRP instance goes away or a `network`
 * statement is removed: the protocol stops, but the interface and everything
 * configured on it remain.  Previously this freed ifp->info outright, which
 * is why interface configuration could not outlive the protocol.
 */
/*
 * Drop the instances an interface runs, optionally narrowed to one process.
 *
 * An interface carries one instance per EIGRP process, so a process going
 * away must take only its own: freeing the rest would tear down another
 * autonomous system's adjacency and leave its topology descriptors pointing
 * at freed interfaces.  The interface itself going away takes all of them.
 */
static void eigrp_if_free_instances(struct eigrp *eigrp, struct interface *ifp)
{
	struct eigrp_interface *ei;
	struct listnode *node, *nnode;

	if (!ifp->info)
		return;

	for (ALL_LIST_ELEMENTS(EIGRP_IF_EIS(ifp), node, nnode, ei)) {
		if (eigrp && ei->eigrp != eigrp)
			continue;

		list_delete_node(EIGRP_IF_EIS(ifp), node);
		eigrp_if_delete_one(ei);
	}
}

void eigrp_if_free_process(struct eigrp *eigrp, struct interface *ifp)
{
	eigrp_if_free_instances(eigrp, ifp);
}

void eigrp_if_free_all(struct interface *ifp)
{
	eigrp_if_free_instances(NULL, ifp);
}

/* The interface itself is going away, so the configuration goes with it. */
int eigrp_if_delete_hook(struct interface *ifp)
{
	if (!ifp->info)
		return 0;

	eigrp_if_free_all(ifp);
	eigrp_if_info_free(ifp);

	return 0;
}

static int eigrp_ifp_create(struct interface *ifp)
{
	/*
	 * Allocate the interface data as soon as the interface exists rather
	 * than waiting for a `network` statement to match.  This is what lets
	 * configuration be applied to an interface EIGRP is not running on.
	 */
	struct eigrp_if_info *eii = eigrp_if_info_get(ifp);

	eii->def_params->type = eigrp_default_iftype(ifp);

	eigrp_if_update(ifp);

	return 0;
}

static int eigrp_ifp_up(struct interface *ifp)
{
	struct eigrp_interface *ei = eigrp_if_lookup_by_ifp(ifp);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to up.",
			   ifp->name);

	if (!ei)
		return 0;

	if (ei->curr_bandwidth != ifp->bandwidth) {
		if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
			zlog_debug(
				"Zebra: Interface[%s] bandwidth change %d -> %d.",
				ifp->name, ei->curr_bandwidth,
				ifp->bandwidth);

		ei->curr_bandwidth = ifp->bandwidth;
		// eigrp_if_recalculate_output_cost (ifp);
	}

	if (ei->curr_mtu != ifp->mtu) {
		if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
			zlog_debug(
				"Zebra: Interface[%s] MTU change %u -> %u.",
				ifp->name, ei->curr_mtu, ifp->mtu);

		ei->curr_mtu = ifp->mtu;
		/* Must reset the interface (simulate down/up) when MTU
		 * changes. */
		eigrp_if_reset(ifp);
		return 0;
	}

	eigrp_if_up(ei);

	return 0;
}

static int eigrp_ifp_down(struct interface *ifp)
{
	struct eigrp_interface *ei = eigrp_if_lookup_by_ifp(ifp);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to down.",
			   ifp->name);

	if (ei)
		eigrp_if_down(ei);

	return 0;
}

static int eigrp_ifp_destroy(struct interface *ifp)
{
	struct eigrp_interface *ei;

	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface delete %s index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	ei = eigrp_if_lookup_by_ifp(ifp);
	if (ei)
		eigrp_if_free(ei, INTERFACE_DOWN_BY_ZEBRA);

	return 0;
}

struct list *eigrp_iflist;

void eigrp_if_init(void)
{
	hook_register_prio(if_real, 0, eigrp_ifp_create);
	hook_register_prio(if_up, 0, eigrp_ifp_up);
	hook_register_prio(if_down, 0, eigrp_ifp_down);
	hook_register_prio(if_unreal, 0, eigrp_ifp_destroy);
	/* Initialize Zebra interface data structure. */
	/*
	 * eigrp_ifp_create() allocates the interface data, so there is no
	 * longer a disabled if_add hook trying to build a prefix-derived
	 * struct eigrp_interface before one can exist.  Configuration that
	 * arrives before the interface is known to zebra is handled by the
	 * northbound callbacks calling eigrp_if_info_get() on demand.
	 */
	hook_register_prio(if_del, 0, eigrp_if_delete_hook);
}


void eigrp_del_if_params(struct eigrp_if_params *eip)
{
	if (eip->auth_keychain)
		free(eip->auth_keychain);
}

/*
 * Set the network byte order of the 3 bytes we send
 * of the mtu of the link.
 */
static void eigrp_mtu_convert(struct eigrp_metrics *metric, uint32_t host_mtu)
{
	uint32_t network_mtu = htonl(host_mtu);
	uint8_t *nm = (uint8_t *)&network_mtu;

	metric->mtu[0] = nm[1];
	metric->mtu[1] = nm[2];
	metric->mtu[2] = nm[3];
}

/*
 * Contribute one connected subnet to the topology table.
 *
 * This runs again every time the interface is brought back up, and
 * eigrp_if_reset() does exactly that on a bandwidth, delay or MTU change
 * while eigrp_if_down() deliberately leaves the descriptor in place.  So an
 * existing descriptor from this instance is refreshed with the new metric
 * rather than duplicated -- skipping it instead would silently drop the very
 * change that triggered the reset.
 */
static void eigrp_connected_advertise(struct eigrp_connected *ec,
				      struct eigrp_metrics metric)
{
	struct eigrp_interface *ei = ec->ei;
	struct eigrp *eigrp = ei->eigrp;
	struct eigrp_prefix_descriptor *pe;
	struct eigrp_route_descriptor *ne;
	struct eigrp_fsm_action_message msg;
	struct eigrp_interface *ei2;

	pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
					      &ec->address);

	if (pe == NULL) {
		ne = eigrp_route_descriptor_new();
		ne->ei = ei;
		ne->reported_metric = metric;
		ne->total_metric = metric;
		ne->distance = eigrp_calculate_metrics(eigrp, metric);
		ne->reported_distance = 0;
		ne->adv_router = eigrp->neighbor_self;
		ne->flags = EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG;

		pe = eigrp_prefix_descriptor_new();
		pe->serno = eigrp->serno;
		prefix_copy(&pe->destination, &ec->address);
		pe->af = AF_INET;
		pe->nt = EIGRP_TOPOLOGY_TYPE_CONNECTED;

		ne->prefix = pe;
		pe->reported_metric = metric;
		pe->state = EIGRP_FSM_STATE_PASSIVE;
		pe->fdistance = eigrp_calculate_metrics(eigrp, metric);
		pe->req_action |= EIGRP_FSM_NEED_UPDATE;
		eigrp_prefix_descriptor_add(eigrp->topology_table, pe);
		listnode_add(eigrp->topology_changes_internalIPV4, pe);

		eigrp_route_descriptor_add(eigrp, pe, ne);

		frr_each (eigrp_interface_hash, &eigrp->eifs, ei2)
			eigrp_update_send(ei2);

		pe->req_action &= ~EIGRP_FSM_NEED_UPDATE;
		listnode_delete(eigrp->topology_changes_internalIPV4, pe);

		return;
	}

	ne = eigrp_route_descriptor_lookup_ei(pe, eigrp->neighbor_self, ei);
	if (ne == NULL) {
		ne = eigrp_route_descriptor_new();
		ne->ei = ei;
		ne->reported_distance = 0;
		ne->adv_router = eigrp->neighbor_self;
		ne->flags = EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG;
		ne->prefix = pe;
		ne->reported_metric = metric;
		ne->total_metric = metric;
		ne->distance = eigrp_calculate_metrics(eigrp, metric);

		eigrp_route_descriptor_add(eigrp, pe, ne);
	} else {
		/* Already advertising it -- take the new metric. */
		ne->reported_metric = metric;
		ne->total_metric = metric;
		ne->distance = eigrp_calculate_metrics(eigrp, metric);
	}

	msg.packet_type = EIGRP_OPC_UPDATE;
	msg.eigrp = eigrp;
	msg.data_type = EIGRP_CONNECTED;
	msg.adv_router = NULL;
	msg.entry = ne;
	msg.prefix = pe;

	eigrp_fsm_event(&msg);
}

int eigrp_if_up(struct eigrp_interface *ei)
{
	struct eigrp_metrics metric;
	struct eigrp_connected *ec;
	struct listnode *node;
	struct eigrp *eigrp;

	if (ei == NULL)
		return 0;

	eigrp = ei->eigrp;
	eigrp_adjust_sndbuflen(eigrp, ei->ifp->mtu);

	eigrp_if_stream_set(ei);

	/* Set multicast memberships appropriately for new state. */
	eigrp_if_set_multicast(ei);

	event_add_event(master, eigrp_hello_timer, ei, (1), &ei->t_hello);

	/*Prepare metrics*/
	metric.bandwidth = eigrp_bandwidth_to_scaled(ei->params->bandwidth);
	metric.delay = eigrp_delay_to_scaled(ei->params->delay);
	metric.load = ei->params->load;
	metric.reliability = ei->params->reliability;
	eigrp_mtu_convert(&metric, ei->ifp->mtu);
	metric.hop_count = 0;
	metric.flags = 0;
	metric.tag = 0;

	/* Advertise every connected subnet this instance speaks for. */
	for (ALL_LIST_ELEMENTS_RO(ei->connected, node, ec))
		eigrp_connected_advertise(ec, metric);

	return 1;
}

int eigrp_if_down(struct eigrp_interface *ei)
{
	if (ei == NULL)
		return 0;

	/* Shutdown packet reception and sending */
	event_cancel(&ei->t_hello);

	eigrp_if_stream_unset(ei);

	/*Set infinite metrics to routes learned by this interface and start
	 * query process*/
	while (eigrp_nbr_hash_count(&ei->nbr_hash_head) > 0)
		eigrp_nbr_delete(eigrp_nbr_hash_first(&ei->nbr_hash_head));


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
			event_cancel(&(eigrp->t_write));
		ei->on_write_q = 0;
	}
}

bool eigrp_if_is_passive(struct eigrp_interface *ei)
{
	if (ei->params->passive_interface == EIGRP_IF_ACTIVE)
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
	struct eigrp_connected *ec;
	struct listnode *node;

	if (source == INTERFACE_DOWN_BY_VTY) {
		event_cancel(&ei->t_hello);
		eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
	}

	for (ALL_LIST_ELEMENTS_RO(ei->connected, node, ec))
		eigrp_connected_withdraw(ec);

	eigrp_if_down(ei);

	/*
	 * Drop the instance rather than leaving it behind stopped: a later
	 * `network` statement covering this interface must be able to create
	 * a fresh one.  The interface configuration is untouched.
	 */
	eigrp_if_remove(ei);
}

/* Simulate down/up on the interface.  This is needed, for example, when
   the MTU changes. */
void eigrp_if_reset(struct interface *ifp)
{
	struct eigrp_interface *ei = eigrp_if_lookup_by_ifp(ifp);

	if (!ei)
		return;

	eigrp_if_down(ei);
	eigrp_if_up(ei);
}

struct eigrp_interface *eigrp_if_lookup_by_local_addr(struct eigrp *eigrp,
						      struct interface *ifp,
						      struct in_addr address)
{
	struct eigrp_interface *ei;

	frr_each (eigrp_interface_hash, &eigrp->eifs, ei) {
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

	/* iterate over all eigrp interfaces */
	// XXX
	frr_each (eigrp_interface_hash, &eigrp->eifs, ei) {
		/* compare int name with eigrp interface's name */
		if (strcmp(ei->ifp->name, if_name) == 0) {
			return ei;
		}
	}

	return NULL;
}
