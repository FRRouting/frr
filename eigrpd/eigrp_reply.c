/*
 * EIGRP Sending and Receiving EIGRP Reply Packets.
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
#include "keychain.h"
#include "plist.h"

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

void eigrp_send_reply(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *pe)
{
	struct eigrp_packet *ep;
	u_int16_t length = EIGRP_HEADER_LEN;

	struct access_list *alist;
	struct prefix_list *plist;
	struct access_list *alist_i;
	struct prefix_list *plist_i;
	struct eigrp *e;
	struct eigrp_prefix_entry *pe2;

	// TODO: Work in progress
	/* Filtering */
	/* get list from eigrp process */
	e = eigrp_lookup();
	pe2 = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
		      sizeof(struct eigrp_prefix_entry));
	memcpy(pe2, pe, sizeof(struct eigrp_prefix_entry));
	/* Get access-lists and prefix-lists from process and interface */
	alist = e->list[EIGRP_FILTER_OUT];
	plist = e->prefix[EIGRP_FILTER_OUT];
	alist_i = nbr->ei->list[EIGRP_FILTER_OUT];
	plist_i = nbr->ei->prefix[EIGRP_FILTER_OUT];
	zlog_info("REPLY Send: Filtering");

	zlog_info("REPLY SEND Prefix: %s", inet_ntoa(nbr->src));
	/* Check if any list fits */
	if ((alist
	     && access_list_apply(alist, (struct prefix *)pe2->destination_ipv4)
			== FILTER_DENY)
	    || (plist
		&& prefix_list_apply(plist,
				     (struct prefix *)pe2->destination_ipv4)
			   == PREFIX_DENY)
	    || (alist_i
		&& access_list_apply(alist_i,
				     (struct prefix *)pe2->destination_ipv4)
			   == FILTER_DENY)
	    || (plist_i
		&& prefix_list_apply(plist_i,
				     (struct prefix *)pe2->destination_ipv4)
			   == PREFIX_DENY)) {
		zlog_info("REPLY SEND: Setting Metric to max");
		pe2->reported_metric.delay = EIGRP_MAX_METRIC;

	} else {
		zlog_info("REPLY SEND: Not setting metric");
	}

	/*
	 * End of filtering
	 */

	ep = eigrp_packet_new(nbr->ei->ifp->mtu);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_REPLY, nbr->ei, ep->s, 0,
				 nbr->ei->eigrp->sequence_number, 0);

	// encode Authentication TLV, if needed
	if ((IF_DEF_PARAMS(nbr->ei->ifp)->auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (IF_DEF_PARAMS(nbr->ei->ifp)->auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, nbr->ei);
	}


	length += eigrp_add_internalTLV_to_stream(ep->s, pe2);

	if ((IF_DEF_PARAMS(nbr->ei->ifp)->auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (IF_DEF_PARAMS(nbr->ei->ifp)->auth_keychain != NULL)) {
		eigrp_make_md5_digest(nbr->ei, ep->s, EIGRP_AUTH_UPDATE_FLAG);
	}

	/* EIGRP Checksum */
	eigrp_packet_checksum(nbr->ei, ep->s, length);

	ep->length = length;
	ep->dst.s_addr = nbr->src.s_addr;

	/*This ack number we await from neighbor*/
	ep->sequence_number = nbr->ei->eigrp->sequence_number;

	/*Put packet to retransmission queue*/
	eigrp_fifo_push_head(nbr->retrans_queue, ep);

	if (nbr->retrans_queue->count == 1) {
		eigrp_send_packet_reliably(nbr);
	}

	XFREE(MTYPE_EIGRP_PREFIX_ENTRY, pe2);
}

/*EIGRP REPLY read function*/
void eigrp_reply_receive(struct eigrp *eigrp, struct ip *iph,
			 struct eigrp_header *eigrph, struct stream *s,
			 struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
	struct TLV_IPv4_Internal_type *tlv;

	struct access_list *alist;
	struct prefix_list *plist;
	struct access_list *alist_i;
	struct prefix_list *plist_i;
	struct eigrp *e;

	u_int16_t type;

	/* increment statistics. */
	ei->reply_in++;

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
			/*
			 * Destination must exists
			 */
			assert(dest);

			struct eigrp_fsm_action_message *msg;
			msg = XCALLOC(MTYPE_EIGRP_FSM_MSG,
				      sizeof(struct eigrp_fsm_action_message));
			struct eigrp_neighbor_entry *entry =
				eigrp_prefix_entry_lookup(dest->entries, nbr);

			/*
			 * Filtering
			 */
			// TODO: Work in progress
			/* get list from eigrp process */
			e = eigrp_lookup();
			/* Get access-lists and prefix-lists from process and
			 * interface */
			alist = e->list[EIGRP_FILTER_IN];
			plist = e->prefix[EIGRP_FILTER_IN];
			alist_i = ei->list[EIGRP_FILTER_IN];
			plist_i = ei->prefix[EIGRP_FILTER_IN];
			/* Check if any list fits */
			if ((alist
			     && access_list_apply(alist,
						  (struct prefix *)&dest_addr)
					== FILTER_DENY)
			    || (plist
				&& prefix_list_apply(
					   plist, (struct prefix *)&dest_addr)
					   == PREFIX_DENY)
			    || (alist_i
				&& access_list_apply(
					   alist_i, (struct prefix *)&dest_addr)
					   == FILTER_DENY)
			    || (plist_i
				&& prefix_list_apply(
					   plist_i, (struct prefix *)&dest_addr)
					   == PREFIX_DENY)) {
				tlv->metric.delay = EIGRP_MAX_METRIC;
			}
			/*
			 * End of filtering
			 */

			msg->packet_type = EIGRP_OPC_REPLY;
			msg->eigrp = eigrp;
			msg->data_type = EIGRP_TLV_IPv4_INT;
			msg->adv_router = nbr;
			msg->data.ipv4_int_type = tlv;
			msg->entry = entry;
			msg->prefix = dest;
			int event = eigrp_get_fsm_event(msg);
			eigrp_fsm_event(msg, event);


			eigrp_IPv4_InternalTLV_free(tlv);
		}
	}
	eigrp_hello_send_ack(nbr);
}
