/*
 * EIGRP Neighbor Handling.
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

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "thread.h"
#include "stream.h"
#include "table.h"
#include "log.h"
#include "keychain.h"
#include "vty.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_memory.h"

struct eigrp_neighbor *eigrp_nbr_new(struct eigrp_interface *ei)
{
	struct eigrp_neighbor *nbr;

	/* Allcate new neighbor. */
	nbr = XCALLOC(MTYPE_EIGRP_NEIGHBOR, sizeof(struct eigrp_neighbor));

	/* Relate neighbor to the interface. */
	nbr->ei = ei;

	/* Set default values. */
	eigrp_nbr_state_set(nbr, EIGRP_NEIGHBOR_DOWN);

	return nbr;
}

/**
 *@fn void dissect_eigrp_sw_version (tvbuff_t *tvb, proto_tree *tree,
 *                                   proto_item *ti)
 *
 * @par
 * Create a new neighbor structure and initalize it.
 */
static struct eigrp_neighbor *eigrp_nbr_add(struct eigrp_interface *ei,
					    struct eigrp_header *eigrph,
					    struct ip *iph)
{
	struct eigrp_neighbor *nbr;

	nbr = eigrp_nbr_new(ei);
	nbr->src = iph->ip_src;

	//  if (IS_DEBUG_EIGRP_EVENT)
	//    zlog_debug("NSM[%s:%s]: start", IF_NAME (nbr->oi),
	//               inet_ntoa (nbr->router_id));

	return nbr;
}

struct eigrp_neighbor *eigrp_nbr_get(struct eigrp_interface *ei,
				     struct eigrp_header *eigrph,
				     struct ip *iph)
{
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		if (iph->ip_src.s_addr == nbr->src.s_addr) {
			return nbr;
		}
	}

	nbr = eigrp_nbr_add(ei, eigrph, iph);
	listnode_add(ei->nbrs, nbr);

	return nbr;
}

/**
 * @fn eigrp_nbr_lookup_by_addr
 *
 * @param[in]		ei			EIGRP interface
 * @param[in]		nbr_addr 	Address of neighbor
 *
 * @return void
 *
 * @par
 * Function is used for neighbor lookup by address
 * in specified interface.
 */
struct eigrp_neighbor *eigrp_nbr_lookup_by_addr(struct eigrp_interface *ei,
						struct in_addr *addr)
{
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		if (addr->s_addr == nbr->src.s_addr) {
			return nbr;
		}
	}

	return NULL;
}

/**
 * @fn eigrp_nbr_lookup_by_addr_process
 *
 * @param[in]    eigrp          EIGRP process
 * @param[in]    nbr_addr       Address of neighbor
 *
 * @return void
 *
 * @par
 * Function is used for neighbor lookup by address
 * in whole EIGRP process.
 */
struct eigrp_neighbor *eigrp_nbr_lookup_by_addr_process(struct eigrp *eigrp,
							struct in_addr nbr_addr)
{
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* iterate over all neighbors on eigrp interface */
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			/* compare if neighbor address is same as arg address */
			if (nbr->src.s_addr == nbr_addr.s_addr) {
				return nbr;
			}
		}
	}

	return NULL;
}


/* Delete specified EIGRP neighbor from interface. */
void eigrp_nbr_delete(struct eigrp_neighbor *nbr)
{
	eigrp_nbr_state_set(nbr, EIGRP_NEIGHBOR_DOWN);
	if (nbr->ei)
		eigrp_topology_neighbor_down(nbr->ei->eigrp, nbr);

	/* Cancel all events. */ /* Thread lookup cost would be negligible. */
	thread_cancel_event(master, nbr);
	eigrp_fifo_free(nbr->multicast_queue);
	eigrp_fifo_free(nbr->retrans_queue);
	THREAD_OFF(nbr->t_holddown);

	if (nbr->ei)
		listnode_delete(nbr->ei->nbrs, nbr);
	XFREE(MTYPE_EIGRP_NEIGHBOR, nbr);
}

int holddown_timer_expired(struct thread *thread)
{
	struct eigrp_neighbor *nbr;

	nbr = THREAD_ARG(thread);

	zlog_info("Neighbor %s (%s) is down: holding time expired",
		  inet_ntoa(nbr->src),
		  ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	nbr->state = EIGRP_NEIGHBOR_DOWN;
	eigrp_nbr_delete(nbr);

	return 0;
}

uint8_t eigrp_nbr_state_get(struct eigrp_neighbor *nbr)
{
	return (nbr->state);
}

void eigrp_nbr_state_set(struct eigrp_neighbor *nbr, uint8_t state)
{
	nbr->state = state;

	if (eigrp_nbr_state_get(nbr) == EIGRP_NEIGHBOR_DOWN) {
		// reset all the seq/ack counters
		nbr->recv_sequence_number = 0;
		nbr->init_sequence_number = 0;
		nbr->retrans_counter = 0;

		// Kvalues
		nbr->K1 = EIGRP_K1_DEFAULT;
		nbr->K2 = EIGRP_K2_DEFAULT;
		nbr->K3 = EIGRP_K3_DEFAULT;
		nbr->K4 = EIGRP_K4_DEFAULT;
		nbr->K5 = EIGRP_K5_DEFAULT;
		nbr->K6 = EIGRP_K6_DEFAULT;

		// hold time..
		nbr->v_holddown = EIGRP_HOLD_INTERVAL_DEFAULT;
		THREAD_OFF(nbr->t_holddown);

		/* out with the old */
		if (nbr->multicast_queue)
			eigrp_fifo_free(nbr->multicast_queue);
		if (nbr->retrans_queue)
			eigrp_fifo_free(nbr->retrans_queue);

		/* in with the new */
		nbr->retrans_queue = eigrp_fifo_new();
		nbr->multicast_queue = eigrp_fifo_new();

		nbr->crypt_seqnum = 0;
	}
}

const char *eigrp_nbr_state_str(struct eigrp_neighbor *nbr)
{
	const char *state;
	switch (nbr->state) {
	case EIGRP_NEIGHBOR_DOWN:
		state = "Down";
		break;
	case EIGRP_NEIGHBOR_PENDING:
		state = "Waiting for Init";
		break;
	case EIGRP_NEIGHBOR_UP:
		state = "Up";
		break;
	default:
		state = "Unknown";
		break;
	}

	return (state);
}

void eigrp_nbr_state_update(struct eigrp_neighbor *nbr)
{
	switch (nbr->state) {
	case EIGRP_NEIGHBOR_DOWN: {
		/*Start Hold Down Timer for neighbor*/
		//     THREAD_OFF(nbr->t_holddown);
		//     THREAD_TIMER_ON(master, nbr->t_holddown,
		//     holddown_timer_expired,
		//     nbr, nbr->v_holddown);
		break;
	}
	case EIGRP_NEIGHBOR_PENDING: {
		/*Reset Hold Down Timer for neighbor*/
		THREAD_OFF(nbr->t_holddown);
		thread_add_timer(master, holddown_timer_expired, nbr,
				 nbr->v_holddown, &nbr->t_holddown);
		break;
	}
	case EIGRP_NEIGHBOR_UP: {
		/*Reset Hold Down Timer for neighbor*/
		THREAD_OFF(nbr->t_holddown);
		thread_add_timer(master, holddown_timer_expired, nbr,
				 nbr->v_holddown, &nbr->t_holddown);
		break;
	}
	}
}

int eigrp_nbr_count_get(void)
{
	struct eigrp_interface *iface;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;
	struct eigrp *eigrp = eigrp_lookup();
	uint32_t counter;

	if (eigrp == NULL) {
		zlog_debug("EIGRP Routing Process not enabled");
		return 0;
	}

	counter = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, iface)) {
		for (ALL_LIST_ELEMENTS(iface->nbrs, node2, nnode2, nbr)) {
			if (nbr->state == EIGRP_NEIGHBOR_UP) {
				counter++;
			}
		}
	}
	return counter;
}

/**
 * @fn eigrp_nbr_hard_restart
 *
 * @param[in]		nbr	Neighbor who would receive hard restart
 * @param[in]		vty Virtual terminal for log output
 * @return void
 *
 * @par
 * Function used for executing hard restart for neighbor:
 * Send Hello packet with Peer Termination TLV with
 * neighbor's address, set it's state to DOWN and delete the neighbor
 */
void eigrp_nbr_hard_restart(struct eigrp_neighbor *nbr, struct vty *vty)
{
	if (nbr == NULL) {
		zlog_err("Nbr Hard restart: Neighbor not specified.");
		return;
	}

	zlog_debug("Neighbor %s (%s) is down: manually cleared",
		   inet_ntoa(nbr->src),
		   ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	if (vty != NULL) {
		vty_time_print(vty, 0);
		vty_out(vty, "Neighbor %s (%s) is down: manually cleared\n",
			inet_ntoa(nbr->src),
			ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	}

	/* send Hello with Peer Termination TLV */
	eigrp_hello_send(nbr->ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN_NBR,
			 &(nbr->src));
	/* set neighbor to DOWN */
	nbr->state = EIGRP_NEIGHBOR_DOWN;
	/* delete neighbor */
	eigrp_nbr_delete(nbr);
}

int eigrp_nbr_split_horizon_check(struct eigrp_nexthop_entry *ne,
				  struct eigrp_interface *ei)
{
	if (ne->distance == EIGRP_MAX_METRIC)
		return 0;

	return (ne->ei == ei);
}
