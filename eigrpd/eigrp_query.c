/*
 * EIGRP Sending and Receiving EIGRP Query Packets.
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
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"
#include "checksum.h"
#include "md5.h"
#include "vty.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_macros.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_memory.h"

u_int32_t eigrp_query_send_all(struct eigrp *eigrp)
{
	struct eigrp_interface *iface;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_prefix_entry *pe;
	u_int32_t counter;

	if (eigrp == NULL) {
		zlog_debug("EIGRP Routing Process not enabled");
		return 0;
	}

	counter = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, iface)) {
		eigrp_send_query(iface);
		counter++;
	}

	for (ALL_LIST_ELEMENTS(eigrp->topology_changes_internalIPV4, node2,
			       nnode2, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_QUERY) {
			pe->req_action &= ~EIGRP_FSM_NEED_QUERY;
			listnode_delete(eigrp->topology_changes_internalIPV4,
					pe);
		}
	}

	return counter;
}

/*EIGRP QUERY read function*/
void eigrp_query_receive(struct eigrp *eigrp, struct ip *iph,
			 struct eigrp_header *eigrph, struct stream *s,
			 struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
	struct TLV_IPv4_Internal_type *tlv;

	u_int16_t type;

	/* increment statistics. */
	ei->query_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

	nbr->recv_sequence_number = ntohl(eigrph->sequence);

	while (s->endp > s->getp) {
		type = stream_getw(s);
		if (type == EIGRP_TLV_IPv4_INT) {
			struct prefix_ipv4 dest_addr;

			stream_set_getp(s, s->getp - sizeof(u_int16_t));

			tlv = eigrp_read_ipv4_tlv(s);

			dest_addr.family = AF_INET;
			dest_addr.prefix = tlv->destination;
			dest_addr.prefixlen = tlv->prefix_length;
			struct eigrp_prefix_entry *dest =
				eigrp_topology_table_lookup_ipv4(
					eigrp->topology_table, &dest_addr);

			/* If the destination exists (it should, but one never
			 * know)*/
			if (dest != NULL) {
				struct eigrp_fsm_action_message *msg;
				msg = XCALLOC(MTYPE_EIGRP_FSM_MSG,
					      sizeof(struct
						     eigrp_fsm_action_message));
				struct eigrp_neighbor_entry *entry =
					eigrp_prefix_entry_lookup(dest->entries,
								  nbr);
				msg->packet_type = EIGRP_OPC_QUERY;
				msg->eigrp = eigrp;
				msg->data_type = EIGRP_TLV_IPv4_INT;
				msg->adv_router = nbr;
				msg->data.ipv4_int_type = tlv;
				msg->entry = entry;
				msg->prefix = dest;
				int event = eigrp_get_fsm_event(msg);
				eigrp_fsm_event(msg, event);
			}
			eigrp_IPv4_InternalTLV_free(tlv);
		}
	}
	eigrp_hello_send_ack(nbr);
	eigrp_query_send_all(eigrp);
	eigrp_update_send_all(eigrp, nbr->ei);
}

void eigrp_send_query(struct eigrp_interface *ei)
{
	struct eigrp_packet *ep;
	u_int16_t length = EIGRP_HEADER_LEN;
	struct listnode *node, *nnode, *node2, *nnode2;
	struct eigrp_neighbor *nbr;
	struct eigrp_prefix_entry *pe;
	char has_tlv;
	bool ep_saved = false;

	ep = eigrp_packet_new(ei->ifp->mtu);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_QUERY, ei, ep->s, 0,
				 ei->eigrp->sequence_number, 0);

	// encode Authentication TLV, if needed
	if ((IF_DEF_PARAMS(ei->ifp)->auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (IF_DEF_PARAMS(ei->ifp)->auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
	}

	has_tlv = 0;
	for (ALL_LIST_ELEMENTS(ei->eigrp->topology_changes_internalIPV4, node,
			       nnode, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_QUERY) {
			length += eigrp_add_internalTLV_to_stream(ep->s, pe);
			for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
				if (nbr->state == EIGRP_NEIGHBOR_UP) {
					listnode_add(pe->rij, nbr);
					has_tlv = 1;
				}
			}
		}
	}

	if (!has_tlv) {
		eigrp_packet_free(ep);
		return;
	}

	if ((IF_DEF_PARAMS(ei->ifp)->auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (IF_DEF_PARAMS(ei->ifp)->auth_keychain != NULL)) {
		eigrp_make_md5_digest(ei, ep->s, EIGRP_AUTH_UPDATE_FLAG);
	}

	/* EIGRP Checksum */
	eigrp_packet_checksum(ei, ep->s, length);

	ep->length = length;
	ep->dst.s_addr = htonl(EIGRP_MULTICAST_ADDRESS);

	/*This ack number we await from neighbor*/
	ep->sequence_number = ei->eigrp->sequence_number;

	for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
		if (nbr->state == EIGRP_NEIGHBOR_UP) {
			/*Put packet to retransmission queue*/
			eigrp_fifo_push_head(nbr->retrans_queue, ep);
			ep_saved = true;

			if (nbr->retrans_queue->count == 1) {
				eigrp_send_packet_reliably(nbr);
			}
		}
	}

	if (!ep_saved)
		eigrp_packet_free(ep);
}
