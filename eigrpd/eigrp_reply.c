/*
 * Eigrp Sending and Receiving EIGRP Reply Packets.
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
	uint16_t length = EIGRP_HEADER_LEN;
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp *eigrp = ei->eigrp;
	struct eigrp_prefix_entry *pe2;

	// TODO: Work in progress
	/* Filtering */
	/* get list from eigrp process */
	pe2 = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
		      sizeof(struct eigrp_prefix_entry));
	memcpy(pe2, pe, sizeof(struct eigrp_prefix_entry));

	if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_OUT,
				      pe2->destination)) {
		zlog_info("REPLY SEND: Setting Metric to max");
		pe2->reported_metric.delay = EIGRP_MAX_METRIC;
	}

	/*
	 * End of filtering
	 */

	ep = eigrp_packet_new(EIGRP_PACKET_MTU(ei->ifp->mtu), nbr);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_REPLY, eigrp, ep->s, 0,
				 eigrp->sequence_number, 0);

	// encode Authentication TLV, if needed
	if (ei->params.auth_type == EIGRP_AUTH_TYPE_MD5
	    && (ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
	}


	length += eigrp_add_internalTLV_to_stream(ep->s, pe2);

	if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (ei->params.auth_keychain != NULL)) {
		eigrp_make_md5_digest(ei, ep->s, EIGRP_AUTH_UPDATE_FLAG);
	}

	/* EIGRP Checksum */
	eigrp_packet_checksum(ei, ep->s, length);

	ep->length = length;
	ep->dst.s_addr = nbr->src.s_addr;

	/*This ack number we await from neighbor*/
	ep->sequence_number = eigrp->sequence_number;

	/*Put packet to retransmission queue*/
	eigrp_fifo_push(nbr->retrans_queue, ep);

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

	uint16_t type;

	/* increment statistics. */
	ei->reply_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

	nbr->recv_sequence_number = ntohl(eigrph->sequence);

	while (s->endp > s->getp) {
		type = stream_getw(s);

		if (type != EIGRP_TLV_IPv4_INT)
			continue;

		struct prefix dest_addr;

		stream_set_getp(s, s->getp - sizeof(uint16_t));

		tlv = eigrp_read_ipv4_tlv(s);

		dest_addr.family = AF_INET;
		dest_addr.u.prefix4 = tlv->destination;
		dest_addr.prefixlen = tlv->prefix_length;
		struct eigrp_prefix_entry *dest =
			eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
							 &dest_addr);
		/*
		 * Destination must exists
		 */
		if (!dest) {
			char buf[PREFIX_STRLEN];

			zlog_err(
				"%s: Received prefix %s which we do not know about",
				__PRETTY_FUNCTION__,
				prefix2str(&dest_addr, buf, sizeof(buf)));
			eigrp_IPv4_InternalTLV_free(tlv);
			continue;
		}

		struct eigrp_fsm_action_message msg;
		struct eigrp_nexthop_entry *entry =
			eigrp_prefix_entry_lookup(dest->entries, nbr);

		if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_IN,
					      &dest_addr)) {
			tlv->metric.delay = EIGRP_MAX_METRIC;
		}
		/*
		 * End of filtering
		 */

		msg.packet_type = EIGRP_OPC_REPLY;
		msg.eigrp = eigrp;
		msg.data_type = EIGRP_INT;
		msg.adv_router = nbr;
		msg.metrics = tlv->metric;
		msg.entry = entry;
		msg.prefix = dest;
		eigrp_fsm_event(&msg);

		eigrp_IPv4_InternalTLV_free(tlv);
	}
	eigrp_hello_send_ack(nbr);
}
