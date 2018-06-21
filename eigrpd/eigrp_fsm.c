/*
 * EIGRPd Finite State Machine (DUAL).
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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
 *
 * This file contains functions for executing logic of finite state machine
 *
 *                                +------------ +
 *                                |     (7)     |
 *                                |             v
 *                    +=====================================+
 *                    |                                     |
 *                    |              Passive                |
 *                    |                                     |
 *                    +=====================================+
 *                        ^     |     ^     ^     ^    |
 *                     (3)|     |  (1)|     |  (1)|    |
 *                        |  (0)|     |  (3)|     | (2)|
 *                        |     |     |     |     |    +---------------+
 *                        |     |     |     |     |                     \
 *              +--------+      |     |     |     +-----------------+    \
 *            /                /     /      |                        \    \
 *          /                /     /        +----+                    \    \
 *         |                |     |               |                    |    |
 *         |                v     |               |                    |    v
 *    +===========+   (6)  +===========+       +===========+   (6) +===========+
 *    |           |------->|           |  (5)  |           |-------->| |
 *    |           |   (4)  |           |------>|           |   (4)   | |
 *    | ACTIVE 0  |<-------| ACTIVE 1  |       | ACTIVE 2  |<--------| ACTIVE 3
 * |
 * +--|           |     +--|           |    +--|           |      +--| |
 * |  +===========+     |  +===========+    |  +===========+      |
 * +===========+
 * |       ^  |(5)      |      ^            |    ^    ^           |         ^
 * |       |  +---------|------|------------|----+    |           |         |
 * +-------+            +------+            +---------+           +---------+
 *    (7)                 (7)                  (7)                   (7)
 *
 * 0- input event other than query from successor, FC not satisfied
 * 1- last reply, FD is reset
 * 2- query from successor, FC not satisfied
 * 3- last reply, FC satisfied with current value of FDij
 * 4- distance increase while in active state
 * 5- query from successor while in active state
 * 6- last reply, FC not satisfied with current value of FDij
 * 7- state not changed, usually by receiving not last reply
 */

#include <thread.h>
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

/*
 * Prototypes
 */
int eigrp_fsm_event_keep_state(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_dinc(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcs(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_qact(struct eigrp_fsm_action_message *);

//---------------------------------------------------------------------

/*
 * NSM - field of fields of struct containing one function each.
 * Which function is used depends on actual state of FSM and occurred
 * event(arrow in diagram). Usage:
 * NSM[actual/starting state][occurred event].func
 * Functions are should be executed within separate thread.
 */
struct {
	int (*func)(struct eigrp_fsm_action_message *);
} NSM[EIGRP_FSM_STATE_MAX][EIGRP_FSM_EVENT_MAX] = {
	{
		// PASSIVE STATE
		{eigrp_fsm_event_nq_fcn},     /* Event 0 */
		{eigrp_fsm_event_keep_state}, /* Event 1 */
		{eigrp_fsm_event_q_fcn},      /* Event 2 */
		{eigrp_fsm_event_keep_state}, /* Event 3 */
		{eigrp_fsm_event_keep_state}, /* Event 4 */
		{eigrp_fsm_event_keep_state}, /* Event 5 */
		{eigrp_fsm_event_keep_state}, /* Event 6 */
		{eigrp_fsm_event_keep_state}, /* Event 7 */
	},
	{
		// Active 0 state
		{eigrp_fsm_event_keep_state}, /* Event 0 */
		{eigrp_fsm_event_keep_state}, /* Event 1 */
		{eigrp_fsm_event_keep_state}, /* Event 2 */
		{eigrp_fsm_event_lr_fcs},     /* Event 3 */
		{eigrp_fsm_event_keep_state}, /* Event 4 */
		{eigrp_fsm_event_qact},       /* Event 5 */
		{eigrp_fsm_event_lr_fcn},     /* Event 6 */
		{eigrp_fsm_event_keep_state}, /* Event 7 */
	},
	{
		// Active 1 state
		{eigrp_fsm_event_keep_state}, /* Event 0 */
		{eigrp_fsm_event_lr},	 /* Event 1 */
		{eigrp_fsm_event_keep_state}, /* Event 2 */
		{eigrp_fsm_event_keep_state}, /* Event 3 */
		{eigrp_fsm_event_dinc},       /* Event 4 */
		{eigrp_fsm_event_qact},       /* Event 5 */
		{eigrp_fsm_event_keep_state}, /* Event 6 */
		{eigrp_fsm_event_keep_state}, /* Event 7 */
	},
	{
		// Active 2 state
		{eigrp_fsm_event_keep_state}, /* Event 0 */
		{eigrp_fsm_event_keep_state}, /* Event 1 */
		{eigrp_fsm_event_keep_state}, /* Event 2 */
		{eigrp_fsm_event_lr_fcs},     /* Event 3 */
		{eigrp_fsm_event_keep_state}, /* Event 4 */
		{eigrp_fsm_event_keep_state}, /* Event 5 */
		{eigrp_fsm_event_lr_fcn},     /* Event 6 */
		{eigrp_fsm_event_keep_state}, /* Event 7 */
	},
	{
		// Active 3 state
		{eigrp_fsm_event_keep_state}, /* Event 0 */
		{eigrp_fsm_event_lr},	 /* Event 1 */
		{eigrp_fsm_event_keep_state}, /* Event 2 */
		{eigrp_fsm_event_keep_state}, /* Event 3 */
		{eigrp_fsm_event_dinc},       /* Event 4 */
		{eigrp_fsm_event_keep_state}, /* Event 5 */
		{eigrp_fsm_event_keep_state}, /* Event 6 */
		{eigrp_fsm_event_keep_state}, /* Event 7 */
	},
};

static const char *packet_type2str(uint8_t packet_type)
{
	if (packet_type == EIGRP_OPC_UPDATE)
		return "Update";
	if (packet_type == EIGRP_OPC_REQUEST)
		return "Request";
	if (packet_type == EIGRP_OPC_QUERY)
		return "Query";
	if (packet_type == EIGRP_OPC_REPLY)
		return "Reply";
	if (packet_type == EIGRP_OPC_HELLO)
		return "Hello";
	if (packet_type == EIGRP_OPC_IPXSAP)
		return "IPXSAP";
	if (packet_type == EIGRP_OPC_ACK)
		return "Ack";
	if (packet_type == EIGRP_OPC_SIAQUERY)
		return "SIA Query";
	if (packet_type == EIGRP_OPC_SIAREPLY)
		return "SIA Reply";

	return "Unknown";
}

static const char *prefix_state2str(enum eigrp_fsm_states state)
{
	switch (state) {
	case EIGRP_FSM_STATE_PASSIVE:
		return "Passive";
	case EIGRP_FSM_STATE_ACTIVE_0:
		return "Active oij0";
	case EIGRP_FSM_STATE_ACTIVE_1:
		return "Active oij1";
	case EIGRP_FSM_STATE_ACTIVE_2:
		return "Active oij2";
	case EIGRP_FSM_STATE_ACTIVE_3:
		return "Active oij3";
	}

	return "Unknown";
}

static const char *fsm_state2str(enum eigrp_fsm_events event)
{
	switch (event) {
	case EIGRP_FSM_KEEP_STATE:
		return "Keep State Event";
	case EIGRP_FSM_EVENT_NQ_FCN:
		return "Non Query Event Feasability not satisfied";
	case EIGRP_FSM_EVENT_LR:
		return "Last Reply Event";
	case EIGRP_FSM_EVENT_Q_FCN:
		return "Query Event Feasability not satisified";
	case EIGRP_FSM_EVENT_LR_FCS:
		return "Last Reply Event Feasability satisified";
	case EIGRP_FSM_EVENT_DINC:
		return "Distance Increase Event";
	case EIGRP_FSM_EVENT_QACT:
		return "Query from Successor while in active state";
	case EIGRP_FSM_EVENT_LR_FCN:
		return "Last Reply Event, Feasibility not satisfied";
	};

	return "Unknown";
}

static const char *change2str(enum metric_change change)
{
	switch (change) {
	case METRIC_DECREASE:
		return "Decrease";
	case METRIC_SAME:
		return "Same";
	case METRIC_INCREASE:
		return "Increase";
	}

	return "Unknown";
}
/*
 * Main function in which are make decisions which event occurred.
 * msg - argument of type struct eigrp_fsm_action_message contain
 * details about what happen
 *
 * Return number of occurred event (arrow in diagram).
 *
 */
static enum eigrp_fsm_events
eigrp_get_fsm_event(struct eigrp_fsm_action_message *msg)
{
	// Loading base information from message
	// struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *entry = msg->entry;
	uint8_t actual_state = prefix->state;
	enum metric_change change;

	if (entry == NULL) {
		entry = eigrp_nexthop_entry_new();
		entry->adv_router = msg->adv_router;
		entry->ei = msg->adv_router->ei;
		entry->prefix = prefix;
		msg->entry = entry;
	}

	/*
	 * Calculate resultant metrics and insert to correct position
	 * in entries list
	 */
	change = eigrp_topology_update_distance(msg);

	/* Store for display later */
	msg->change = change;

	switch (actual_state) {
	case EIGRP_FSM_STATE_PASSIVE: {
		struct eigrp_nexthop_entry *head =
			listnode_head(prefix->entries);

		if (head->reported_distance < prefix->fdistance) {
			return EIGRP_FSM_KEEP_STATE;
		}
		/*
		 * if best entry doesn't satisfy feasibility condition it means
		 * move to active state
		 * dependently if it was query from successor
		 */
		if (msg->packet_type == EIGRP_OPC_QUERY) {
			return EIGRP_FSM_EVENT_Q_FCN;
		} else {
			return EIGRP_FSM_EVENT_NQ_FCN;
		}

		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_0: {
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct eigrp_nexthop_entry *head =
				listnode_head(prefix->entries);

			listnode_delete(prefix->rij, entry->adv_router);
			if (prefix->rij->count)
				return EIGRP_FSM_KEEP_STATE;

			zlog_info("All reply received\n");
			if (head->reported_distance < prefix->fdistance) {
				return EIGRP_FSM_EVENT_LR_FCS;
			}

			return EIGRP_FSM_EVENT_LR_FCN;
		} else if (msg->packet_type == EIGRP_OPC_QUERY
			   && (entry->flags
			       & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			return EIGRP_FSM_EVENT_QACT;
		}

		return EIGRP_FSM_KEEP_STATE;

		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_1: {
		if (msg->packet_type == EIGRP_OPC_QUERY
		    && (entry->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			return EIGRP_FSM_EVENT_QACT;
		} else if (msg->packet_type == EIGRP_OPC_REPLY) {
			listnode_delete(prefix->rij, entry->adv_router);

			if (change == METRIC_INCREASE
			    && (entry->flags
				& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
				return EIGRP_FSM_EVENT_DINC;
			} else if (prefix->rij->count) {
				return EIGRP_FSM_KEEP_STATE;
			} else {
				zlog_info("All reply received\n");
				return EIGRP_FSM_EVENT_LR;
			}
		} else if (msg->packet_type == EIGRP_OPC_UPDATE
			   && change == METRIC_INCREASE
			   && (entry->flags
			       & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			return EIGRP_FSM_EVENT_DINC;
		}
		return EIGRP_FSM_KEEP_STATE;

		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_2: {
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct eigrp_nexthop_entry *head =
				listnode_head(prefix->entries);

			listnode_delete(prefix->rij, entry->adv_router);
			if (prefix->rij->count) {
				return EIGRP_FSM_KEEP_STATE;
			} else {
				zlog_info("All reply received\n");
				if (head->reported_distance
				    < prefix->fdistance) {
					return EIGRP_FSM_EVENT_LR_FCS;
				}

				return EIGRP_FSM_EVENT_LR_FCN;
			}
		}
		return EIGRP_FSM_KEEP_STATE;

		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_3: {
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			listnode_delete(prefix->rij, entry->adv_router);

			if (change == METRIC_INCREASE
			    && (entry->flags
				& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
				return EIGRP_FSM_EVENT_DINC;
			} else if (prefix->rij->count) {
				return EIGRP_FSM_KEEP_STATE;
			} else {
				zlog_info("All reply received\n");
				return EIGRP_FSM_EVENT_LR;
			}
		} else if (msg->packet_type == EIGRP_OPC_UPDATE
			   && change == METRIC_INCREASE
			   && (entry->flags
			       & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			return EIGRP_FSM_EVENT_DINC;
		}
		return EIGRP_FSM_KEEP_STATE;

		break;
	}
	}

	return EIGRP_FSM_KEEP_STATE;
}

/*
 * Function made to execute in separate thread.
 * Load argument from thread and execute proper NSM function
 */
int eigrp_fsm_event(struct eigrp_fsm_action_message *msg)
{
	enum eigrp_fsm_events event = eigrp_get_fsm_event(msg);

	zlog_info(
		"EIGRP AS: %d State: %s Event: %s Network: %s Packet Type: %s Reply RIJ Count: %d change: %s",
		msg->eigrp->AS, prefix_state2str(msg->prefix->state),
		fsm_state2str(event), eigrp_topology_ip_string(msg->prefix),
		packet_type2str(msg->packet_type), msg->prefix->rij->count,
		change2str(msg->change));
	(*(NSM[msg->prefix->state][event].func))(msg);

	return 1;
}

/*
 * Function of event 0.
 *
 */
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct list *successors = eigrp_topology_get_successor(prefix);
	struct eigrp_nexthop_entry *ne;

	assert(successors); // If this is NULL we have shit the bed, fun huh?

	ne = listnode_head(successors);
	prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
	prefix->rdistance = prefix->distance = prefix->fdistance = ne->distance;
	prefix->reported_metric = ne->total_metric;

	if (eigrp_nbr_count_get()) {
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more
					 // neighbors left
	}

	list_delete_and_null(&successors);

	return 1;
}

int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct list *successors = eigrp_topology_get_successor(prefix);
	struct eigrp_nexthop_entry *ne;

	assert(successors); // If this is NULL somebody poked us in the eye.

	ne = listnode_head(successors);
	prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
	prefix->rdistance = prefix->distance = prefix->fdistance = ne->distance;
	prefix->reported_metric = ne->total_metric;
	if (eigrp_nbr_count_get()) {
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more
					 // neighbors left
	}

	list_delete_and_null(&successors);

	return 1;
}

int eigrp_fsm_event_keep_state(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *ne = listnode_head(prefix->entries);

	if (prefix->state == EIGRP_FSM_STATE_PASSIVE) {
		if (!eigrp_metrics_is_same(prefix->reported_metric,
					   ne->total_metric)) {
			prefix->rdistance = prefix->fdistance =
				prefix->distance = ne->distance;
			prefix->reported_metric = ne->total_metric;
			if (msg->packet_type == EIGRP_OPC_QUERY)
				eigrp_send_reply(msg->adv_router, prefix);
			prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
			eigrp = eigrp_lookup();
			assert(eigrp);
			listnode_add(eigrp->topology_changes_internalIPV4,
				     prefix);
		}
		eigrp_topology_update_node_flags(prefix);
		eigrp_update_routing_table(prefix);
	}

	if (msg->packet_type == EIGRP_OPC_QUERY)
		eigrp_send_reply(msg->adv_router, prefix);

	return 1;
}

int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *ne = listnode_head(prefix->entries);

	prefix->fdistance = prefix->distance = prefix->rdistance = ne->distance;
	prefix->reported_metric = ne->total_metric;

	if (prefix->state == EIGRP_FSM_STATE_ACTIVE_3) {
		struct list *successors = eigrp_topology_get_successor(prefix);

		assert(successors); // It's like Napolean and Waterloo

		ne = listnode_head(successors);
		eigrp_send_reply(ne->adv_router, prefix);
		list_delete_and_null(&successors);
	}

	prefix->state = EIGRP_FSM_STATE_PASSIVE;
	prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
	listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	eigrp_topology_update_node_flags(prefix);
	eigrp_update_routing_table(prefix);
	eigrp_update_topology_table_prefix(eigrp->topology_table, prefix);

	return 1;
}

int eigrp_fsm_event_dinc(struct eigrp_fsm_action_message *msg)
{
	struct list *successors = eigrp_topology_get_successor(msg->prefix);
	struct eigrp_nexthop_entry *ne;

	assert(successors); // Trump and his big hands

	ne = listnode_head(successors);
	msg->prefix->state = msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_1
				     ? EIGRP_FSM_STATE_ACTIVE_0
				     : EIGRP_FSM_STATE_ACTIVE_2;
	msg->prefix->distance = ne->distance;
	if (!msg->prefix->rij->count)
		(*(NSM[msg->prefix->state][eigrp_get_fsm_event(msg)].func))(
			msg);


	list_delete_and_null(&successors);
	return 1;
}

int eigrp_fsm_event_lr_fcs(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *ne = listnode_head(prefix->entries);

	prefix->state = EIGRP_FSM_STATE_PASSIVE;
	prefix->distance = prefix->rdistance = ne->distance;
	prefix->reported_metric = ne->total_metric;
	prefix->fdistance = prefix->fdistance > prefix->distance
				    ? prefix->distance
				    : prefix->fdistance;
	if (prefix->state == EIGRP_FSM_STATE_ACTIVE_2) {
		struct list *successors = eigrp_topology_get_successor(prefix);

		assert(successors); // Having a spoon and all you need is a
				    // knife
		ne = listnode_head(successors);
		eigrp_send_reply(ne->adv_router, prefix);

		list_delete_and_null(&successors);
	}
	prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
	listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	eigrp_topology_update_node_flags(prefix);
	eigrp_update_routing_table(prefix);
	eigrp_update_topology_table_prefix(eigrp->topology_table, prefix);

	return 1;
}

int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *best_successor;
	struct list *successors = eigrp_topology_get_successor(prefix);

	assert(successors); // Routing without a stack

	prefix->state = prefix->state == EIGRP_FSM_STATE_ACTIVE_0
				? EIGRP_FSM_STATE_ACTIVE_1
				: EIGRP_FSM_STATE_ACTIVE_3;

	best_successor = listnode_head(successors);
	prefix->rdistance = prefix->distance = best_successor->distance;
	prefix->reported_metric = best_successor->total_metric;

	if (eigrp_nbr_count_get()) {
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more
					 // neighbors left
	}

	list_delete_and_null(&successors);

	return 1;
}

int eigrp_fsm_event_qact(struct eigrp_fsm_action_message *msg)
{
	struct list *successors = eigrp_topology_get_successor(msg->prefix);
	struct eigrp_nexthop_entry *ne;

	assert(successors); // Cats and no Dogs

	ne = listnode_head(successors);
	msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
	msg->prefix->distance = ne->distance;

	list_delete_and_null(&successors);
	return 1;
}
