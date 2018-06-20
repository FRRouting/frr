/* BGP packet management routine.
 * Contains utility functions for constructing and consuming BGP messages.
 * Copyright (C) 2017 Cumulus Networks
 * Copyright (C) 1999 Kunihiro Ishiguro
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
#include <sys/time.h>

#include "thread.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h" /* for inet_ntop () */
#include "sockopt.h"
#include "linklist.h"
#include "plist.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_flowspec.h"

/**
 * Sets marker and type fields for a BGP message.
 *
 * @param s the stream containing the packet
 * @param type the packet type
 * @return the size of the stream
 */
int bgp_packet_set_marker(struct stream *s, uint8_t type)
{
	int i;

	/* Fill in marker. */
	for (i = 0; i < BGP_MARKER_SIZE; i++)
		stream_putc(s, 0xff);

	/* Dummy total length. This field is should be filled in later on. */
	stream_putw(s, 0);

	/* BGP packet type. */
	stream_putc(s, type);

	/* Return current stream size. */
	return stream_get_endp(s);
}

/**
 * Sets size field for a BGP message.
 *
 * Size field is set to the size of the stream passed.
 *
 * @param s the stream containing the packet
 * @return the size of the stream
 */
int bgp_packet_set_size(struct stream *s)
{
	int cp;

	/* Preserve current pointer. */
	cp = stream_get_endp(s);
	stream_putw_at(s, BGP_MARKER_SIZE, cp);

	return cp;
}

/*
 * Push a packet onto the beginning of the peer's output queue.
 * This function acquires the peer's write mutex before proceeding.
 */
static void bgp_packet_add(struct peer *peer, struct stream *s)
{
	pthread_mutex_lock(&peer->io_mtx);
	stream_fifo_push(peer->obuf, s);
	pthread_mutex_unlock(&peer->io_mtx);
}

static struct stream *bgp_update_packet_eor(struct peer *peer, afi_t afi,
					    safi_t safi)
{
	struct stream *s;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	if (DISABLE_BGP_ANNOUNCE)
		return NULL;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("send End-of-RIB for %s to %s",
			   afi_safi_print(afi, safi), peer->host);

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make BGP update packet. */
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* Unfeasible Routes Length */
	stream_putw(s, 0);

	if (afi == AFI_IP && safi == SAFI_UNICAST) {
		/* Total Path Attribute Length */
		stream_putw(s, 0);
	} else {
		/* Convert AFI, SAFI to values for packet. */
		bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

		/* Total Path Attribute Length */
		stream_putw(s, 6);
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MP_UNREACH_NLRI);
		stream_putc(s, 3);
		stream_putw(s, pkt_afi);
		stream_putc(s, pkt_safi);
	}

	bgp_packet_set_size(s);
	return s;
}

/* Called when there is a change in the EOR(implicit or explicit) status of a
 * peer. Ends the update-delay if all expected peers are done with EORs. */
void bgp_check_update_delay(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct peer *peer = NULL;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("Checking update delay, T: %d R: %d I:%d E: %d",
			   bgp->established, bgp->restarted_peers,
			   bgp->implicit_eors, bgp->explicit_eors);

	if (bgp->established
	    <= bgp->restarted_peers + bgp->implicit_eors + bgp->explicit_eors) {
		/*
		 * This is an extra sanity check to make sure we wait for all
		 * the eligible configured peers. This check is performed if
		 * establish wait timer is on, or establish wait option is not
		 * given with the update-delay command
		 */
		if (bgp->t_establish_wait
		    || (bgp->v_establish_wait == bgp->v_update_delay))
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
				if (CHECK_FLAG(peer->flags,
					       PEER_FLAG_CONFIG_NODE)
				    && !CHECK_FLAG(peer->flags,
						   PEER_FLAG_SHUTDOWN)
				    && !peer->update_delay_over) {
					if (bgp_debug_neighbor_events(peer))
						zlog_debug(
							" Peer %s pending, continuing read-only mode",
							peer->host);
					return;
				}
			}

		zlog_info(
			"Update delay ended, restarted: %d, EORs implicit: %d, explicit: %d",
			bgp->restarted_peers, bgp->implicit_eors,
			bgp->explicit_eors);
		bgp_update_delay_end(bgp);
	}
}

/*
 * Called if peer is known to have restarted. The restart-state bit in
 * Graceful-Restart capability is used for that
 */
void bgp_update_restarted_peers(struct peer *peer)
{
	if (!bgp_update_delay_active(peer->bgp))
		return; /* BGP update delay has ended */
	if (peer->update_delay_over)
		return; /* This peer has already been considered */

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("Peer %s: Checking restarted", peer->host);

	if (peer->status == Established) {
		peer->update_delay_over = 1;
		peer->bgp->restarted_peers++;
		bgp_check_update_delay(peer->bgp);
	}
}

/*
 * Called as peer receives a keep-alive. Determines if this occurence can be
 * taken as an implicit EOR for this peer.
 * NOTE: The very first keep-alive after the Established state of a peer is
 * considered implicit EOR for the update-delay purposes
 */
void bgp_update_implicit_eors(struct peer *peer)
{
	if (!bgp_update_delay_active(peer->bgp))
		return; /* BGP update delay has ended */
	if (peer->update_delay_over)
		return; /* This peer has already been considered */

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("Peer %s: Checking implicit EORs", peer->host);

	if (peer->status == Established) {
		peer->update_delay_over = 1;
		peer->bgp->implicit_eors++;
		bgp_check_update_delay(peer->bgp);
	}
}

/*
 * Should be called only when there is a change in the EOR_RECEIVED status
 * for any afi/safi on a peer.
 */
static void bgp_update_explicit_eors(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	if (!bgp_update_delay_active(peer->bgp))
		return; /* BGP update delay has ended */
	if (peer->update_delay_over)
		return; /* This peer has already been considered */

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("Peer %s: Checking explicit EORs", peer->host);

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			if (peer->afc_nego[afi][safi]
			    && !CHECK_FLAG(peer->af_sflags[afi][safi],
					   PEER_STATUS_EOR_RECEIVED)) {
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"   afi %d safi %d didnt receive EOR",
						afi, safi);
				return;
			}
		}

	peer->update_delay_over = 1;
	peer->bgp->explicit_eors++;
	bgp_check_update_delay(peer->bgp);
}

/**
 * Frontend for NLRI parsing, to fan-out to AFI/SAFI specific parsers.
 *
 * mp_withdraw, if set, is used to nullify attr structure on most of the
 * calling safi function and for evpn, passed as parameter
 */
int bgp_nlri_parse(struct peer *peer, struct attr *attr,
		   struct bgp_nlri *packet, int mp_withdraw)
{
	switch (packet->safi) {
	case SAFI_UNICAST:
	case SAFI_MULTICAST:
		return bgp_nlri_parse_ip(peer, mp_withdraw ? NULL : attr,
					 packet);
	case SAFI_LABELED_UNICAST:
		return bgp_nlri_parse_label(peer, mp_withdraw ? NULL : attr,
					    packet);
	case SAFI_MPLS_VPN:
		return bgp_nlri_parse_vpn(peer, mp_withdraw ? NULL : attr,
					  packet);
	case SAFI_EVPN:
		return bgp_nlri_parse_evpn(peer, attr, packet, mp_withdraw);
	case SAFI_FLOWSPEC:
		return bgp_nlri_parse_flowspec(peer, attr, packet, mp_withdraw);
	}
	return -1;
}

/*
 * Checks a variety of conditions to determine whether the peer needs to be
 * rescheduled for packet generation again, and does so if necessary.
 *
 * @param peer to check for rescheduling
 */
static void bgp_write_proceed_actions(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct peer_af *paf;
	struct bpacket *next_pkt;
	struct update_subgroup *subgrp;

	FOREACH_AFI_SAFI (afi, safi) {
		paf = peer_af_find(peer, afi, safi);
		if (!paf)
			continue;
		subgrp = paf->subgroup;
		if (!subgrp)
			continue;

		next_pkt = paf->next_pkt_to_send;
		if (next_pkt && next_pkt->buffer) {
			BGP_TIMER_ON(peer->t_generate_updgrp_packets,
				     bgp_generate_updgrp_packets, 0);
			return;
		}

		/* No packets readily available for AFI/SAFI, are there
		 * subgroup packets
		 * that need to be generated? */
		if (bpacket_queue_is_full(SUBGRP_INST(subgrp),
					  SUBGRP_PKTQ(subgrp))
		    || subgroup_packets_to_build(subgrp)) {
			BGP_TIMER_ON(peer->t_generate_updgrp_packets,
				     bgp_generate_updgrp_packets, 0);
			return;
		}

		/* No packets to send, see if EOR is pending */
		if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {
			if (!subgrp->t_coalesce && peer->afc_nego[afi][safi]
			    && peer->synctime
			    && !CHECK_FLAG(peer->af_sflags[afi][safi],
					   PEER_STATUS_EOR_SEND)
			    && safi != SAFI_MPLS_VPN) {
				BGP_TIMER_ON(peer->t_generate_updgrp_packets,
					     bgp_generate_updgrp_packets, 0);
				return;
			}
		}
	}
}

/*
 * Generate advertisement information (withdraws, updates, EOR) from each
 * update group a peer belongs to, encode this information into packets, and
 * enqueue the packets onto the peer's output buffer.
 */
int bgp_generate_updgrp_packets(struct thread *thread)
{
	struct peer *peer = THREAD_ARG(thread);

	struct stream *s;
	struct peer_af *paf;
	struct bpacket *next_pkt;
	uint32_t wpq;
	uint32_t generated = 0;
	afi_t afi;
	safi_t safi;

	wpq = atomic_load_explicit(&peer->bgp->wpkt_quanta,
				   memory_order_relaxed);

	/*
	 * The code beyond this part deals with update packets, proceed only
	 * if peer is Established and updates are not on hold (as part of
	 * update-delay post processing).
	 */
	if (peer->status != Established)
		return 0;

	if (peer->bgp->main_peers_update_hold)
		return 0;

	do {
		s = NULL;
		FOREACH_AFI_SAFI (afi, safi) {
			paf = peer_af_find(peer, afi, safi);
			if (!paf || !PAF_SUBGRP(paf))
				continue;
			next_pkt = paf->next_pkt_to_send;

			/*
			 * Try to generate a packet for the peer if we are at
			 * the end of the list. Always try to push out
			 * WITHDRAWs first.
			 */
			if (!next_pkt || !next_pkt->buffer) {
				next_pkt = subgroup_withdraw_packet(
					PAF_SUBGRP(paf));
				if (!next_pkt || !next_pkt->buffer)
					subgroup_update_packet(PAF_SUBGRP(paf));
				next_pkt = paf->next_pkt_to_send;
			}

			/*
			 * If we still don't have a packet to send to the peer,
			 * then try to find out out if we have to send eor or
			 * if not, skip to the next AFI, SAFI. Don't send the
			 * EOR prematurely; if the subgroup's coalesce timer is
			 * running, the adjacency-out structure is not created
			 * yet.
			 */
			if (!next_pkt || !next_pkt->buffer) {
				if (CHECK_FLAG(peer->cap,
					       PEER_CAP_RESTART_RCV)) {
					if (!(PAF_SUBGRP(paf))->t_coalesce
					    && peer->afc_nego[afi][safi]
					    && peer->synctime
					    && !CHECK_FLAG(
						       peer->af_sflags[afi]
								      [safi],
						       PEER_STATUS_EOR_SEND)) {
						SET_FLAG(peer->af_sflags[afi]
									[safi],
							 PEER_STATUS_EOR_SEND);

						if ((s = bgp_update_packet_eor(
							     peer, afi,
							     safi))) {
							bgp_packet_add(peer, s);
						}
					}
				}
				continue;
			}


			/* Found a packet template to send, overwrite
			 * packet with appropriate attributes from peer
			 * and advance peer */
			s = bpacket_reformat_for_peer(next_pkt, paf);
			bgp_packet_add(peer, s);
			bpacket_queue_advance_peer(paf);
		}
	} while (s && (++generated < wpq));

	if (generated)
		bgp_writes_on(peer);

	bgp_write_proceed_actions(peer);

	return 0;
}

/*
 * Creates a BGP Keepalive packet and appends it to the peer's output queue.
 */
void bgp_keepalive_send(struct peer *peer)
{
	struct stream *s;

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make keepalive packet. */
	bgp_packet_set_marker(s, BGP_MSG_KEEPALIVE);

	/* Set packet size. */
	(void)bgp_packet_set_size(s);

	/* Dump packet if debug option is set. */
	/* bgp_packet_dump (s); */

	if (bgp_debug_keepalive(peer))
		zlog_debug("%s sending KEEPALIVE", peer->host);

	/* Add packet to the peer. */
	bgp_packet_add(peer, s);

	bgp_writes_on(peer);
}

/*
 * Creates a BGP Open packet and appends it to the peer's output queue.
 * Sets capabilities as necessary.
 */
void bgp_open_send(struct peer *peer)
{
	struct stream *s;
	uint16_t send_holdtime;
	as_t local_as;

	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
		send_holdtime = peer->holdtime;
	else
		send_holdtime = peer->bgp->default_holdtime;

	/* local-as Change */
	if (peer->change_local_as)
		local_as = peer->change_local_as;
	else
		local_as = peer->local_as;

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make open packet. */
	bgp_packet_set_marker(s, BGP_MSG_OPEN);

	/* Set open packet values. */
	stream_putc(s, BGP_VERSION_4); /* BGP version */
	stream_putw(s, (local_as <= BGP_AS_MAX) ? (uint16_t)local_as
						: BGP_AS_TRANS);
	stream_putw(s, send_holdtime);		/* Hold Time */
	stream_put_in_addr(s, &peer->local_id); /* BGP Identifier */

	/* Set capability code. */
	bgp_open_capability(s, peer);

	/* Set BGP packet length. */
	(void)bgp_packet_set_size(s);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug(
			"%s sending OPEN, version %d, my as %u, holdtime %d, id %s",
			peer->host, BGP_VERSION_4, local_as, send_holdtime,
			inet_ntoa(peer->local_id));

	/* Dump packet if debug option is set. */
	/* bgp_packet_dump (s); */

	/* Add packet to the peer. */
	bgp_packet_add(peer, s);

	bgp_writes_on(peer);
}

/*
 * Writes NOTIFICATION message directly to a peer socket without waiting for
 * the I/O thread.
 *
 * There must be exactly one stream on the peer->obuf FIFO, and the data within
 * this stream must match the format of a BGP NOTIFICATION message.
 * Transmission is best-effort.
 *
 * @requires peer->io_mtx
 * @param peer
 * @return 0
 */
static int bgp_write_notify(struct peer *peer)
{
	int ret, val;
	uint8_t type;
	struct stream *s;

	/* There should be at least one packet. */
	s = stream_fifo_pop(peer->obuf);

	if (!s)
		return 0;

	assert(stream_get_endp(s) >= BGP_HEADER_SIZE);

	/* Stop collecting data within the socket */
	sockopt_cork(peer->fd, 0);

	/*
	 * socket is in nonblocking mode, if we can't deliver the NOTIFY, well,
	 * we only care about getting a clean shutdown at this point.
	 */
	ret = write(peer->fd, STREAM_DATA(s), stream_get_endp(s));

	/*
	 * only connection reset/close gets counted as TCP_fatal_error, failure
	 * to write the entire NOTIFY doesn't get different FSM treatment
	 */
	if (ret <= 0) {
		stream_free(s);
		BGP_EVENT_ADD(peer, TCP_fatal_error);
		return 0;
	}

	/* Disable Nagle, make NOTIFY packet go out right away */
	val = 1;
	(void)setsockopt(peer->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val,
			 sizeof(val));

	/* Retrieve BGP packet type. */
	stream_set_getp(s, BGP_MARKER_SIZE + 2);
	type = stream_getc(s);

	assert(type == BGP_MSG_NOTIFY);

	/* Type should be notify. */
	atomic_fetch_add_explicit(&peer->notify_out, 1, memory_order_relaxed);
	peer->notify_out++;

	/* Double start timer. */
	peer->v_start *= 2;

	/* Overflow check. */
	if (peer->v_start >= (60 * 2))
		peer->v_start = (60 * 2);

	/*
	 * Handle Graceful Restart case where the state changes to
	 * Connect instead of Idle
	 */
	BGP_EVENT_ADD(peer, BGP_Stop);

	stream_free(s);

	return 0;
}

/*
 * Creates a BGP Notify and appends it to the peer's output queue.
 *
 * This function attempts to write the packet from the thread it is called
 * from, to ensure the packet gets out ASAP.
 *
 * This function may be called from multiple threads. Since the function
 * modifies I/O buffer(s) in the peer, these are locked for the duration of the
 * call to prevent tampering from other threads.
 *
 * Delivery of the NOTIFICATION is attempted once and is best-effort. After
 * return, the peer structure *must* be reset; no assumptions about session
 * state are valid.
 *
 * @param peer
 * @param code      BGP error code
 * @param sub_code  BGP error subcode
 * @param data      Data portion
 * @param datalen   length of data portion
 */
void bgp_notify_send_with_data(struct peer *peer, uint8_t code,
			       uint8_t sub_code, uint8_t *data, size_t datalen)
{
	struct stream *s;

	/* Lock I/O mutex to prevent other threads from pushing packets */
	pthread_mutex_lock(&peer->io_mtx);
	/* ============================================== */

	/* Allocate new stream. */
	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make notify packet. */
	bgp_packet_set_marker(s, BGP_MSG_NOTIFY);

	/* Set notify packet values. */
	stream_putc(s, code);     /* BGP notify code */
	stream_putc(s, sub_code); /* BGP notify sub_code */

	/* If notify data is present. */
	if (data)
		stream_write(s, data, datalen);

	/* Set BGP packet length. */
	bgp_packet_set_size(s);

	/* wipe output buffer */
	stream_fifo_clean(peer->obuf);

	/*
	 * If possible, store last packet for debugging purposes. This check is
	 * in place because we are sometimes called with a doppelganger peer,
	 * who tends to have a plethora of fields nulled out.
	 */
	if (peer->curr && peer->last_reset_cause_size) {
		size_t packetsize = stream_get_endp(peer->curr);
		assert(packetsize <= peer->last_reset_cause_size);
		memcpy(peer->last_reset_cause, peer->curr->data, packetsize);
		peer->last_reset_cause_size = packetsize;
	}

	/* For debug */
	{
		struct bgp_notify bgp_notify;
		int first = 0;
		int i;
		char c[4];

		bgp_notify.code = code;
		bgp_notify.subcode = sub_code;
		bgp_notify.data = NULL;
		bgp_notify.length = datalen;
		bgp_notify.raw_data = data;

		peer->notify.code = bgp_notify.code;
		peer->notify.subcode = bgp_notify.subcode;

		if (bgp_notify.length && data) {
			bgp_notify.data =
				XMALLOC(MTYPE_TMP, bgp_notify.length * 3);
			for (i = 0; i < bgp_notify.length; i++)
				if (first) {
					sprintf(c, " %02x", data[i]);
					strcat(bgp_notify.data, c);
				} else {
					first = 1;
					sprintf(c, "%02x", data[i]);
					strcpy(bgp_notify.data, c);
				}
		}
		bgp_notify_print(peer, &bgp_notify, "sending");

		if (bgp_notify.data) {
			XFREE(MTYPE_TMP, bgp_notify.data);
			bgp_notify.data = NULL;
			bgp_notify.length = 0;
		}
	}

	/* peer reset cause */
	if (code == BGP_NOTIFY_CEASE) {
		if (sub_code == BGP_NOTIFY_CEASE_ADMIN_RESET)
			peer->last_reset = PEER_DOWN_USER_RESET;
		else if (sub_code == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN)
			peer->last_reset = PEER_DOWN_USER_SHUTDOWN;
		else
			peer->last_reset = PEER_DOWN_NOTIFY_SEND;
	} else
		peer->last_reset = PEER_DOWN_NOTIFY_SEND;

	/* Add packet to peer's output queue */
	stream_fifo_push(peer->obuf, s);

	bgp_write_notify(peer);

	/* ============================================== */
	pthread_mutex_unlock(&peer->io_mtx);
}

/*
 * Creates a BGP Notify and appends it to the peer's output queue.
 *
 * This function attempts to write the packet from the thread it is called
 * from, to ensure the packet gets out ASAP.
 *
 * @param peer
 * @param code      BGP error code
 * @param sub_code  BGP error subcode
 */
void bgp_notify_send(struct peer *peer, uint8_t code, uint8_t sub_code)
{
	bgp_notify_send_with_data(peer, code, sub_code, NULL, 0);
}

/*
 * Creates BGP Route Refresh packet and appends it to the peer's output queue.
 *
 * @param peer
 * @param afi               Address Family Identifier
 * @param safi              Subsequent Address Family Identifier
 * @param orf_type          Outbound Route Filtering type
 * @param when_to_refresh   Whether to refresh immediately or defer
 * @param remove            Whether to remove ORF for specified AFI/SAFI
 */
void bgp_route_refresh_send(struct peer *peer, afi_t afi, safi_t safi,
			    uint8_t orf_type, uint8_t when_to_refresh,
			    int remove)
{
	struct stream *s;
	struct bgp_filter *filter;
	int orf_refresh = 0;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	if (DISABLE_BGP_ANNOUNCE)
		return;

	filter = &peer->filter[afi][safi];

	/* Convert AFI, SAFI to values for packet. */
	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make BGP update packet. */
	if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_NEW_RCV))
		bgp_packet_set_marker(s, BGP_MSG_ROUTE_REFRESH_NEW);
	else
		bgp_packet_set_marker(s, BGP_MSG_ROUTE_REFRESH_OLD);

	/* Encode Route Refresh message. */
	stream_putw(s, pkt_afi);
	stream_putc(s, 0);
	stream_putc(s, pkt_safi);

	if (orf_type == ORF_TYPE_PREFIX || orf_type == ORF_TYPE_PREFIX_OLD)
		if (remove || filter->plist[FILTER_IN].plist) {
			uint16_t orf_len;
			unsigned long orfp;

			orf_refresh = 1;
			stream_putc(s, when_to_refresh);
			stream_putc(s, orf_type);
			orfp = stream_get_endp(s);
			stream_putw(s, 0);

			if (remove) {
				UNSET_FLAG(peer->af_sflags[afi][safi],
					   PEER_STATUS_ORF_PREFIX_SEND);
				stream_putc(s, ORF_COMMON_PART_REMOVE_ALL);
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%s sending REFRESH_REQ to remove ORF(%d) (%s) for afi/safi: %d/%d",
						peer->host, orf_type,
						(when_to_refresh == REFRESH_DEFER
							 ? "defer"
							 : "immediate"),
						pkt_afi, pkt_safi);
			} else {
				SET_FLAG(peer->af_sflags[afi][safi],
					 PEER_STATUS_ORF_PREFIX_SEND);
				prefix_bgp_orf_entry(
					s, filter->plist[FILTER_IN].plist,
					ORF_COMMON_PART_ADD,
					ORF_COMMON_PART_PERMIT,
					ORF_COMMON_PART_DENY);
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%s sending REFRESH_REQ with pfxlist ORF(%d) (%s) for afi/safi: %d/%d",
						peer->host, orf_type,
						(when_to_refresh == REFRESH_DEFER
							 ? "defer"
							 : "immediate"),
						pkt_afi, pkt_safi);
			}

			/* Total ORF Entry Len. */
			orf_len = stream_get_endp(s) - orfp - 2;
			stream_putw_at(s, orfp, orf_len);
		}

	/* Set packet size. */
	(void)bgp_packet_set_size(s);

	if (bgp_debug_neighbor_events(peer)) {
		if (!orf_refresh)
			zlog_debug("%s sending REFRESH_REQ for afi/safi: %d/%d",
				   peer->host, pkt_afi, pkt_safi);
	}

	/* Add packet to the peer. */
	bgp_packet_add(peer, s);

	bgp_writes_on(peer);
}

/*
 * Create a BGP Capability packet and append it to the peer's output queue.
 *
 * @param peer
 * @param afi              Address Family Identifier
 * @param safi             Subsequent Address Family Identifier
 * @param capability_code  BGP Capability Code
 * @param action           Set or Remove capability
 */
void bgp_capability_send(struct peer *peer, afi_t afi, safi_t safi,
			 int capability_code, int action)
{
	struct stream *s;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	/* Convert AFI, SAFI to values for packet. */
	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make BGP update packet. */
	bgp_packet_set_marker(s, BGP_MSG_CAPABILITY);

	/* Encode MP_EXT capability. */
	if (capability_code == CAPABILITY_CODE_MP) {
		stream_putc(s, action);
		stream_putc(s, CAPABILITY_CODE_MP);
		stream_putc(s, CAPABILITY_CODE_MP_LEN);
		stream_putw(s, pkt_afi);
		stream_putc(s, 0);
		stream_putc(s, pkt_safi);

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s sending CAPABILITY has %s MP_EXT CAP for afi/safi: %d/%d",
				peer->host,
				action == CAPABILITY_ACTION_SET ? "Advertising"
								: "Removing",
				pkt_afi, pkt_safi);
	}

	/* Set packet size. */
	(void)bgp_packet_set_size(s);

	/* Add packet to the peer. */
	bgp_packet_add(peer, s);

	bgp_writes_on(peer);
}

/* RFC1771 6.8 Connection collision detection. */
static int bgp_collision_detect(struct peer *new, struct in_addr remote_id)
{
	struct peer *peer;

	/* Upon receipt of an OPEN message, the local system must examine
	   all of its connections that are in the OpenConfirm state.  A BGP
	   speaker may also examine connections in an OpenSent state if it
	   knows the BGP Identifier of the peer by means outside of the
	   protocol.  If among these connections there is a connection to a
	   remote BGP speaker whose BGP Identifier equals the one in the
	   OPEN message, then the local system performs the following
	   collision resolution procedure: */

	if ((peer = new->doppelganger) != NULL) {
		/* Do not accept the new connection in Established or Clearing
		 * states.
		 * Note that a peer GR is handled by closing the existing
		 * connection
		 * upon receipt of new one.
		 */
		if (peer->status == Established || peer->status == Clearing) {
			bgp_notify_send(new, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
			return (-1);
		} else if ((peer->status == OpenConfirm)
			   || (peer->status == OpenSent)) {
			/* 1. The BGP Identifier of the local system is compared
			   to
			   the BGP Identifier of the remote system (as specified
			   in
			   the OPEN message). */

			if (ntohl(peer->local_id.s_addr)
			    < ntohl(remote_id.s_addr))
				if (!CHECK_FLAG(peer->sflags,
						PEER_STATUS_ACCEPT_PEER)) {
					/* 2. If the value of the local BGP
					   Identifier is less
					   than the remote one, the local system
					   closes BGP
					   connection that already exists (the
					   one that is
					   already in the OpenConfirm state),
					   and accepts BGP
					   connection initiated by the remote
					   system. */
					bgp_notify_send(
						peer, BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
					return 1;
				} else {
					bgp_notify_send(
						new, BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
					return -1;
				}
			else {
				/* 3. Otherwise, the local system closes newly
				   created
				   BGP connection (the one associated with the
				   newly
				   received OPEN message), and continues to use
				   the
				   existing one (the one that is already in the
				   OpenConfirm state). */
				if (CHECK_FLAG(peer->sflags,
					       PEER_STATUS_ACCEPT_PEER)) {
					bgp_notify_send(
						peer, BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
					return 1;
				} else {
					bgp_notify_send(
						new, BGP_NOTIFY_CEASE,
						BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
					return -1;
				}
			}
		}
	}
	return 0;
}

/* Packet processing routines ---------------------------------------------- */
/*
 * This is a family of functions designed to be called from
 * bgp_process_packet(). These functions all share similar behavior and should
 * adhere to the following invariants and restrictions:
 *
 * Return codes
 * ------------
 * The return code of any one of those functions should be one of the FSM event
 * codes specified in bgpd.h. If a NOTIFY was sent, this event code MUST be
 * BGP_Stop. Otherwise, the code SHOULD correspond to the function's expected
 * packet type. For example, bgp_open_receive() should return BGP_Stop upon
 * error and Receive_OPEN_message otherwise.
 *
 * If no action is necessary, the correct return code is BGP_PACKET_NOOP as
 * defined below.
 *
 * Side effects
 * ------------
 * - May send NOTIFY messages
 * - May not modify peer->status
 * - May not call bgp_event_update()
 */

#define BGP_PACKET_NOOP 0

/**
 * Process BGP OPEN message for peer.
 *
 * If any errors are encountered in the OPEN message, immediately sends NOTIFY
 * and returns BGP_Stop.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_open_receive(struct peer *peer, bgp_size_t size)
{
	int ret;
	uint8_t version;
	uint8_t optlen;
	uint16_t holdtime;
	uint16_t send_holdtime;
	as_t remote_as;
	as_t as4 = 0;
	struct in_addr remote_id;
	int mp_capability;
	uint8_t notify_data_remote_as[2];
	uint8_t notify_data_remote_as4[4];
	uint8_t notify_data_remote_id[4];
	uint16_t *holdtime_ptr;

	/* Parse open packet. */
	version = stream_getc(peer->curr);
	memcpy(notify_data_remote_as, stream_pnt(peer->curr), 2);
	remote_as = stream_getw(peer->curr);
	holdtime_ptr = (uint16_t *)stream_pnt(peer->curr);
	holdtime = stream_getw(peer->curr);
	memcpy(notify_data_remote_id, stream_pnt(peer->curr), 4);
	remote_id.s_addr = stream_get_ipv4(peer->curr);

	/* Receive OPEN message log  */
	if (bgp_debug_neighbor_events(peer))
		zlog_debug(
			"%s rcv OPEN, version %d, remote-as (in open) %u,"
			" holdtime %d, id %s",
			peer->host, version, remote_as, holdtime,
			inet_ntoa(remote_id));

	/* BEGIN to read the capability here, but dont do it yet */
	mp_capability = 0;
	optlen = stream_getc(peer->curr);

	if (optlen != 0) {
		/* If not enough bytes, it is an error. */
		if (STREAM_READABLE(peer->curr) < optlen) {
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return BGP_Stop;
		}

		/* We need the as4 capability value *right now* because
		 * if it is there, we have not got the remote_as yet, and
		 * without
		 * that we do not know which peer is connecting to us now.
		 */
		as4 = peek_for_as4_capability(peer, optlen);
		memcpy(notify_data_remote_as4, &as4, 4);
	}

	/* Just in case we have a silly peer who sends AS4 capability set to 0
	 */
	if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV) && !as4) {
		zlog_err("%s bad OPEN, got AS4 capability, but AS4 set to 0",
			 peer->host);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_BAD_PEER_AS,
					  notify_data_remote_as4, 4);
		return BGP_Stop;
	}

	if (remote_as == BGP_AS_TRANS) {
		/* Take the AS4 from the capability.  We must have received the
		 * capability now!  Otherwise we have a asn16 peer who uses
		 * BGP_AS_TRANS, for some unknown reason.
		 */
		if (as4 == BGP_AS_TRANS) {
			zlog_err(
				"%s [AS4] NEW speaker using AS_TRANS for AS4, not allowed",
				peer->host);
			bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
						  BGP_NOTIFY_OPEN_BAD_PEER_AS,
						  notify_data_remote_as4, 4);
			return BGP_Stop;
		}

		if (!as4 && BGP_DEBUG(as4, AS4))
			zlog_debug(
				"%s [AS4] OPEN remote_as is AS_TRANS, but no AS4."
				" Odd, but proceeding.",
				peer->host);
		else if (as4 < BGP_AS_MAX && BGP_DEBUG(as4, AS4))
			zlog_debug(
				"%s [AS4] OPEN remote_as is AS_TRANS, but AS4 (%u) fits "
				"in 2-bytes, very odd peer.",
				peer->host, as4);
		if (as4)
			remote_as = as4;
	} else {
		/* We may have a partner with AS4 who has an asno < BGP_AS_MAX
		 */
		/* If we have got the capability, peer->as4cap must match
		 * remote_as */
		if (CHECK_FLAG(peer->cap, PEER_CAP_AS4_RCV)
		    && as4 != remote_as) {
			/* raise error, log this, close session */
			zlog_err(
				"%s bad OPEN, got AS4 capability, but remote_as %u"
				" mismatch with 16bit 'myasn' %u in open",
				peer->host, as4, remote_as);
			bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
						  BGP_NOTIFY_OPEN_BAD_PEER_AS,
						  notify_data_remote_as4, 4);
			return BGP_Stop;
		}
	}

	/* remote router-id check. */
	if (remote_id.s_addr == 0 || IPV4_CLASS_DE(ntohl(remote_id.s_addr))
	    || ntohl(peer->local_id.s_addr) == ntohl(remote_id.s_addr)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s bad OPEN, wrong router identifier %s",
				   peer->host, inet_ntoa(remote_id));
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_BAD_BGP_IDENT,
					  notify_data_remote_id, 4);
		return BGP_Stop;
	}

	/* Set remote router-id */
	peer->remote_id = remote_id;

	/* Peer BGP version check. */
	if (version != BGP_VERSION_4) {
		uint16_t maxver = htons(BGP_VERSION_4);
		/* XXX this reply may not be correct if version < 4  XXX */
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s bad protocol version, remote requested %d, local request %d",
				peer->host, version, BGP_VERSION_4);
		/* Data must be in network byte order here */
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_UNSUP_VERSION,
					  (uint8_t *)&maxver, 2);
		return BGP_Stop;
	}

	/* Check neighbor as number. */
	if (peer->as_type == AS_UNSPECIFIED) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s bad OPEN, remote AS is unspecified currently",
				peer->host);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_BAD_PEER_AS,
					  notify_data_remote_as, 2);
		return BGP_Stop;
	} else if (peer->as_type == AS_INTERNAL) {
		if (remote_as != peer->bgp->as) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s bad OPEN, remote AS is %u, internal specified",
					peer->host, remote_as);
			bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
						  BGP_NOTIFY_OPEN_BAD_PEER_AS,
						  notify_data_remote_as, 2);
			return BGP_Stop;
		}
		peer->as = peer->local_as;
	} else if (peer->as_type == AS_EXTERNAL) {
		if (remote_as == peer->bgp->as) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s bad OPEN, remote AS is %u, external specified",
					peer->host, remote_as);
			bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
						  BGP_NOTIFY_OPEN_BAD_PEER_AS,
						  notify_data_remote_as, 2);
			return BGP_Stop;
		}
		peer->as = remote_as;
	} else if ((peer->as_type == AS_SPECIFIED) && (remote_as != peer->as)) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s bad OPEN, remote AS is %u, expected %u",
				   peer->host, remote_as, peer->as);
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_BAD_PEER_AS,
					  notify_data_remote_as, 2);
		return BGP_Stop;
	}

	/* From the rfc: Upon receipt of an OPEN message, a BGP speaker MUST
	   calculate the value of the Hold Timer by using the smaller of its
	   configured Hold Time and the Hold Time received in the OPEN message.
	   The Hold Time MUST be either zero or at least three seconds.  An
	   implementation may reject connections on the basis of the Hold Time.
	   */

	if (holdtime < 3 && holdtime != 0) {
		bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
					  BGP_NOTIFY_OPEN_UNACEP_HOLDTIME,
					  (uint8_t *)holdtime_ptr, 2);
		return BGP_Stop;
	}

	/* From the rfc: A reasonable maximum time between KEEPALIVE messages
	   would be one third of the Hold Time interval.  KEEPALIVE messages
	   MUST NOT be sent more frequently than one per second.  An
	   implementation MAY adjust the rate at which it sends KEEPALIVE
	   messages as a function of the Hold Time interval. */

	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
		send_holdtime = peer->holdtime;
	else
		send_holdtime = peer->bgp->default_holdtime;

	if (holdtime < send_holdtime)
		peer->v_holdtime = holdtime;
	else
		peer->v_holdtime = send_holdtime;

	if ((CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
	    && (peer->keepalive < peer->v_holdtime / 3))
		peer->v_keepalive = peer->keepalive;
	else
		peer->v_keepalive = peer->v_holdtime / 3;

	/* Open option part parse. */
	if (optlen != 0) {
		if ((ret = bgp_open_option_parse(peer, optlen, &mp_capability))
		    < 0)
			return BGP_Stop;
	} else {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s rcvd OPEN w/ OPTION parameter len: 0",
				   peer->host);
	}

	/*
	 * Assume that the peer supports the locally configured set of
	 * AFI/SAFIs if the peer did not send us any Mulitiprotocol
	 * capabilities, or if 'override-capability' is configured.
	 */
	if (!mp_capability
	    || CHECK_FLAG(peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY)) {
		peer->afc_nego[AFI_IP][SAFI_UNICAST] =
			peer->afc[AFI_IP][SAFI_UNICAST];
		peer->afc_nego[AFI_IP][SAFI_MULTICAST] =
			peer->afc[AFI_IP][SAFI_MULTICAST];
		peer->afc_nego[AFI_IP][SAFI_LABELED_UNICAST] =
			peer->afc[AFI_IP][SAFI_LABELED_UNICAST];
		peer->afc_nego[AFI_IP][SAFI_FLOWSPEC] =
			peer->afc[AFI_IP][SAFI_FLOWSPEC];
		peer->afc_nego[AFI_IP6][SAFI_UNICAST] =
			peer->afc[AFI_IP6][SAFI_UNICAST];
		peer->afc_nego[AFI_IP6][SAFI_MULTICAST] =
			peer->afc[AFI_IP6][SAFI_MULTICAST];
		peer->afc_nego[AFI_IP6][SAFI_LABELED_UNICAST] =
			peer->afc[AFI_IP6][SAFI_LABELED_UNICAST];
		peer->afc_nego[AFI_L2VPN][SAFI_EVPN] =
			peer->afc[AFI_L2VPN][SAFI_EVPN];
		peer->afc_nego[AFI_IP6][SAFI_FLOWSPEC] =
			peer->afc[AFI_IP6][SAFI_FLOWSPEC];
	}

	/* When collision is detected and this peer is closed.  Retrun
	   immidiately. */
	ret = bgp_collision_detect(peer, remote_id);
	if (ret < 0)
		return BGP_Stop;

	/* Get sockname. */
	if ((ret = bgp_getsockname(peer)) < 0) {
		zlog_err("%s: bgp_getsockname() failed for peer: %s",
			 __FUNCTION__, peer->host);
		return BGP_Stop;
	}

	/* Verify valid local address present based on negotiated
	 * address-families. */
	if (peer->afc_nego[AFI_IP][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP][SAFI_ENCAP]) {
		if (!peer->nexthop.v4.s_addr) {
#if defined(HAVE_CUMULUS)
			zlog_err(
				"%s: No local IPv4 addr resetting connection, fd %d",
				peer->host, peer->fd);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_SUBCODE_UNSPECIFIC);
			return BGP_Stop;
#endif
		}
	}
	if (peer->afc_nego[AFI_IP6][SAFI_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_LABELED_UNICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MULTICAST]
	    || peer->afc_nego[AFI_IP6][SAFI_MPLS_VPN]
	    || peer->afc_nego[AFI_IP6][SAFI_ENCAP]) {
		if (IN6_IS_ADDR_UNSPECIFIED(&peer->nexthop.v6_global)) {
#if defined(HAVE_CUMULUS)
			zlog_err(
				"%s: No local IPv6 addr resetting connection, fd %d",
				peer->host, peer->fd);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_SUBCODE_UNSPECIFIC);
			return BGP_Stop;
#endif
		}
	}
	peer->rtt = sockopt_tcp_rtt(peer->fd);

	return Receive_OPEN_message;
}

/**
 * Process BGP KEEPALIVE message for peer.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_keepalive_receive(struct peer *peer, bgp_size_t size)
{
	if (bgp_debug_keepalive(peer))
		zlog_debug("%s KEEPALIVE rcvd", peer->host);

	bgp_update_implicit_eors(peer);

	return Receive_KEEPALIVE_message;
}


/**
 * Process BGP UPDATE message for peer.
 *
 * Parses UPDATE and creates attribute object.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_update_receive(struct peer *peer, bgp_size_t size)
{
	int ret, nlri_ret;
	uint8_t *end;
	struct stream *s;
	struct attr attr;
	bgp_size_t attribute_len;
	bgp_size_t update_len;
	bgp_size_t withdraw_len;

	enum NLRI_TYPES {
		NLRI_UPDATE,
		NLRI_WITHDRAW,
		NLRI_MP_UPDATE,
		NLRI_MP_WITHDRAW,
		NLRI_TYPE_MAX
	};
	struct bgp_nlri nlris[NLRI_TYPE_MAX];

	/* Status must be Established. */
	if (peer->status != Established) {
		zlog_err("%s [FSM] Update packet received under status %s",
			 peer->host,
			 lookup_msg(bgp_status_msg, peer->status, NULL));
		bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR, 0);
		return BGP_Stop;
	}

	/* Set initial values. */
	memset(&attr, 0, sizeof(struct attr));
	attr.label_index = BGP_INVALID_LABEL_INDEX;
	attr.label = MPLS_INVALID_LABEL;
	memset(&nlris, 0, sizeof(nlris));
	memset(peer->rcvd_attr_str, 0, BUFSIZ);
	peer->rcvd_attr_printed = 0;

	s = peer->curr;
	end = stream_pnt(s) + size;

	/* RFC1771 6.3 If the Unfeasible Routes Length or Total Attribute
	   Length is too large (i.e., if Unfeasible Routes Length + Total
	   Attribute Length + 23 exceeds the message Length), then the Error
	   Subcode is set to Malformed Attribute List.  */
	if (stream_pnt(s) + 2 > end) {
		zlog_err(
			"%s [Error] Update packet error"
			" (packet length is short for unfeasible length)",
			peer->host);
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		return BGP_Stop;
	}

	/* Unfeasible Route Length. */
	withdraw_len = stream_getw(s);

	/* Unfeasible Route Length check. */
	if (stream_pnt(s) + withdraw_len > end) {
		zlog_err(
			"%s [Error] Update packet error"
			" (packet unfeasible length overflow %d)",
			peer->host, withdraw_len);
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		return BGP_Stop;
	}

	/* Unfeasible Route packet format check. */
	if (withdraw_len > 0) {
		nlris[NLRI_WITHDRAW].afi = AFI_IP;
		nlris[NLRI_WITHDRAW].safi = SAFI_UNICAST;
		nlris[NLRI_WITHDRAW].nlri = stream_pnt(s);
		nlris[NLRI_WITHDRAW].length = withdraw_len;
		stream_forward_getp(s, withdraw_len);
	}

	/* Attribute total length check. */
	if (stream_pnt(s) + 2 > end) {
		zlog_warn(
			"%s [Error] Packet Error"
			" (update packet is short for attribute length)",
			peer->host);
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		return BGP_Stop;
	}

	/* Fetch attribute total length. */
	attribute_len = stream_getw(s);

	/* Attribute length check. */
	if (stream_pnt(s) + attribute_len > end) {
		zlog_warn(
			"%s [Error] Packet Error"
			" (update packet attribute length overflow %d)",
			peer->host, attribute_len);
		bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
				BGP_NOTIFY_UPDATE_MAL_ATTR);
		return BGP_Stop;
	}

	/* Certain attribute parsing errors should not be considered bad enough
	 * to reset the session for, most particularly any partial/optional
	 * attributes that have 'tunneled' over speakers that don't understand
	 * them. Instead we withdraw only the prefix concerned.
	 *
	 * Complicates the flow a little though..
	 */
	bgp_attr_parse_ret_t attr_parse_ret = BGP_ATTR_PARSE_PROCEED;
/* This define morphs the update case into a withdraw when lower levels
 * have signalled an error condition where this is best.
 */
#define NLRI_ATTR_ARG (attr_parse_ret != BGP_ATTR_PARSE_WITHDRAW ? &attr : NULL)

	/* Parse attribute when it exists. */
	if (attribute_len) {
		attr_parse_ret = bgp_attr_parse(peer, &attr, attribute_len,
						&nlris[NLRI_MP_UPDATE],
						&nlris[NLRI_MP_WITHDRAW]);
		if (attr_parse_ret == BGP_ATTR_PARSE_ERROR) {
			bgp_attr_unintern_sub(&attr);
			return BGP_Stop;
		}
	}

	/* Logging the attribute. */
	if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW
	    || BGP_DEBUG(update, UPDATE_IN)
	    || BGP_DEBUG(update, UPDATE_PREFIX)) {
		ret = bgp_dump_attr(&attr, peer->rcvd_attr_str, BUFSIZ);

		if (attr_parse_ret == BGP_ATTR_PARSE_WITHDRAW)
			zlog_err(
				"%s rcvd UPDATE with errors in attr(s)!! Withdrawing route.",
				peer->host);

		if (ret && bgp_debug_update(peer, NULL, NULL, 1)) {
			zlog_debug("%s rcvd UPDATE w/ attr: %s", peer->host,
				   peer->rcvd_attr_str);
			peer->rcvd_attr_printed = 1;
		}
	}

	/* Network Layer Reachability Information. */
	update_len = end - stream_pnt(s);

	if (update_len) {
		/* Set NLRI portion to structure. */
		nlris[NLRI_UPDATE].afi = AFI_IP;
		nlris[NLRI_UPDATE].safi = SAFI_UNICAST;
		nlris[NLRI_UPDATE].nlri = stream_pnt(s);
		nlris[NLRI_UPDATE].length = update_len;
		stream_forward_getp(s, update_len);
	}

	if (BGP_DEBUG(update, UPDATE_IN))
		zlog_debug("%s rcvd UPDATE wlen %d attrlen %d alen %d",
			   peer->host, withdraw_len, attribute_len, update_len);

	/* Parse any given NLRIs */
	for (int i = NLRI_UPDATE; i < NLRI_TYPE_MAX; i++) {
		if (!nlris[i].nlri)
			continue;

		/* NLRI is processed iff the peer if configured for the specific
		 * afi/safi */
		if (!peer->afc[nlris[i].afi][nlris[i].safi]) {
			zlog_info(
				"%s [Info] UPDATE for non-enabled AFI/SAFI %u/%u",
				peer->host, nlris[i].afi, nlris[i].safi);
			continue;
		}

		/* EoR handled later */
		if (nlris[i].length == 0)
			continue;

		switch (i) {
		case NLRI_UPDATE:
		case NLRI_MP_UPDATE:
			nlri_ret = bgp_nlri_parse(peer, NLRI_ATTR_ARG,
						  &nlris[i], 0);
			break;
		case NLRI_WITHDRAW:
		case NLRI_MP_WITHDRAW:
			nlri_ret = bgp_nlri_parse(peer, &attr, &nlris[i], 1);
			break;
		default:
			nlri_ret = -1;
		}

		if (nlri_ret < 0) {
			zlog_err("%s [Error] Error parsing NLRI", peer->host);
			if (peer->status == Established)
				bgp_notify_send(
					peer, BGP_NOTIFY_UPDATE_ERR,
					i <= NLRI_WITHDRAW
						? BGP_NOTIFY_UPDATE_INVAL_NETWORK
						: BGP_NOTIFY_UPDATE_OPT_ATTR_ERR);
			bgp_attr_unintern_sub(&attr);
			return BGP_Stop;
		}
	}

	/* EoR checks
	 *
	 * Non-MP IPv4/Unicast EoR is a completely empty UPDATE
	 * and MP EoR should have only an empty MP_UNREACH
	 */
	if ((!update_len && !withdraw_len && nlris[NLRI_MP_UPDATE].length == 0)
	    || (attr_parse_ret == BGP_ATTR_PARSE_EOR)) {
		afi_t afi = 0;
		safi_t safi;

		/* Non-MP IPv4/Unicast is a completely emtpy UPDATE - already
		 * checked
		 * update and withdraw NLRI lengths are 0.
		 */
		if (!attribute_len) {
			afi = AFI_IP;
			safi = SAFI_UNICAST;
		} else if (attr.flag & ATTR_FLAG_BIT(BGP_ATTR_MP_UNREACH_NLRI)
			   && nlris[NLRI_MP_WITHDRAW].length == 0) {
			afi = nlris[NLRI_MP_WITHDRAW].afi;
			safi = nlris[NLRI_MP_WITHDRAW].safi;
		} else if (attr_parse_ret == BGP_ATTR_PARSE_EOR) {
			afi = nlris[NLRI_MP_UPDATE].afi;
			safi = nlris[NLRI_MP_UPDATE].safi;
		}

		if (afi && peer->afc[afi][safi]) {
			/* End-of-RIB received */
			if (!CHECK_FLAG(peer->af_sflags[afi][safi],
					PEER_STATUS_EOR_RECEIVED)) {
				SET_FLAG(peer->af_sflags[afi][safi],
					 PEER_STATUS_EOR_RECEIVED);
				bgp_update_explicit_eors(peer);
			}

			/* NSF delete stale route */
			if (peer->nsf[afi][safi])
				bgp_clear_stale_route(peer, afi, safi);

			if (bgp_debug_neighbor_events(peer)) {
				zlog_debug("rcvd End-of-RIB for %s from %s",
					   afi_safi_print(afi, safi),
					   peer->host);
			}
		}
	}

	/* Everything is done.  We unintern temporary structures which
	   interned in bgp_attr_parse(). */
	bgp_attr_unintern_sub(&attr);

	peer->update_time = bgp_clock();

	/* Rearm holdtime timer */
	BGP_TIMER_OFF(peer->t_holdtime);
	bgp_timer_set(peer);

	return Receive_UPDATE_message;
}

/**
 * Process BGP NOTIFY message for peer.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_notify_receive(struct peer *peer, bgp_size_t size)
{
	struct bgp_notify bgp_notify;

	if (peer->notify.data) {
		XFREE(MTYPE_TMP, peer->notify.data);
		peer->notify.data = NULL;
		peer->notify.length = 0;
	}

	bgp_notify.code = stream_getc(peer->curr);
	bgp_notify.subcode = stream_getc(peer->curr);
	bgp_notify.length = size - 2;
	bgp_notify.data = NULL;

	/* Preserv notify code and sub code. */
	peer->notify.code = bgp_notify.code;
	peer->notify.subcode = bgp_notify.subcode;
	/* For further diagnostic record returned Data. */
	if (bgp_notify.length) {
		peer->notify.length = size - 2;
		peer->notify.data = XMALLOC(MTYPE_TMP, size - 2);
		memcpy(peer->notify.data, stream_pnt(peer->curr), size - 2);
	}

	/* For debug */
	{
		int i;
		int first = 0;
		char c[4];

		if (bgp_notify.length) {
			bgp_notify.data =
				XMALLOC(MTYPE_TMP, bgp_notify.length * 3);
			for (i = 0; i < bgp_notify.length; i++)
				if (first) {
					sprintf(c, " %02x",
						stream_getc(peer->curr));
					strcat(bgp_notify.data, c);
				} else {
					first = 1;
					sprintf(c, "%02x",
						stream_getc(peer->curr));
					strcpy(bgp_notify.data, c);
				}
			bgp_notify.raw_data = (uint8_t *)peer->notify.data;
		}

		bgp_notify_print(peer, &bgp_notify, "received");
		if (bgp_notify.data) {
			XFREE(MTYPE_TMP, bgp_notify.data);
			bgp_notify.data = NULL;
			bgp_notify.length = 0;
		}
	}

	/* peer count update */
	atomic_fetch_add_explicit(&peer->notify_in, 1, memory_order_relaxed);

	peer->last_reset = PEER_DOWN_NOTIFY_RECEIVED;

	/* We have to check for Notify with Unsupported Optional Parameter.
	   in that case we fallback to open without the capability option.
	   But this done in bgp_stop. We just mark it here to avoid changing
	   the fsm tables.  */
	if (bgp_notify.code == BGP_NOTIFY_OPEN_ERR
	    && bgp_notify.subcode == BGP_NOTIFY_OPEN_UNSUP_PARAM)
		UNSET_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

	return Receive_NOTIFICATION_message;
}

/**
 * Process BGP ROUTEREFRESH message for peer.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_route_refresh_receive(struct peer *peer, bgp_size_t size)
{
	iana_afi_t pkt_afi;
	afi_t afi;
	iana_safi_t pkt_safi;
	safi_t safi;
	struct stream *s;
	struct peer_af *paf;
	struct update_group *updgrp;
	struct peer *updgrp_peer;

	/* If peer does not have the capability, send notification. */
	if (!CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_ADV)) {
		zlog_err("%s [Error] BGP route refresh is not enabled",
			 peer->host);
		bgp_notify_send(peer, BGP_NOTIFY_HEADER_ERR,
				BGP_NOTIFY_HEADER_BAD_MESTYPE);
		return BGP_Stop;
	}

	/* Status must be Established. */
	if (peer->status != Established) {
		zlog_err(
			"%s [Error] Route refresh packet received under status %s",
			peer->host,
			lookup_msg(bgp_status_msg, peer->status, NULL));
		bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR, 0);
		return BGP_Stop;
	}

	s = peer->curr;

	/* Parse packet. */
	pkt_afi = stream_getw(s);
	(void)stream_getc(s);
	pkt_safi = stream_getc(s);

	if (bgp_debug_update(peer, NULL, NULL, 0))
		zlog_debug("%s rcvd REFRESH_REQ for afi/safi: %d/%d",
			   peer->host, pkt_afi, pkt_safi);

	/* Convert AFI, SAFI to internal values and check. */
	if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
		zlog_info(
			"%s REFRESH_REQ for unrecognized afi/safi: %d/%d - ignored",
			peer->host, pkt_afi, pkt_safi);
		return BGP_PACKET_NOOP;
	}

	if (size != BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE) {
		uint8_t *end;
		uint8_t when_to_refresh;
		uint8_t orf_type;
		uint16_t orf_len;

		if (size - (BGP_MSG_ROUTE_REFRESH_MIN_SIZE - BGP_HEADER_SIZE)
		    < 5) {
			zlog_info("%s ORF route refresh length error",
				  peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE, 0);
			return BGP_Stop;
		}

		when_to_refresh = stream_getc(s);
		end = stream_pnt(s) + (size - 5);

		while ((stream_pnt(s) + 2) < end) {
			orf_type = stream_getc(s);
			orf_len = stream_getw(s);

			/* orf_len in bounds? */
			if ((stream_pnt(s) + orf_len) > end)
				break; /* XXX: Notify instead?? */
			if (orf_type == ORF_TYPE_PREFIX
			    || orf_type == ORF_TYPE_PREFIX_OLD) {
				uint8_t *p_pnt = stream_pnt(s);
				uint8_t *p_end = stream_pnt(s) + orf_len;
				struct orf_prefix orfp;
				uint8_t common = 0;
				uint32_t seq;
				int psize;
				char name[BUFSIZ];
				int ret = CMD_SUCCESS;

				if (bgp_debug_neighbor_events(peer)) {
					zlog_debug(
						"%s rcvd Prefixlist ORF(%d) length %d",
						peer->host, orf_type, orf_len);
				}

				/* we're going to read at least 1 byte of common
				 * ORF header,
				 * and 7 bytes of ORF Address-filter entry from
				 * the stream
				 */
				if (orf_len < 7)
					break;

				/* ORF prefix-list name */
				sprintf(name, "%s.%d.%d", peer->host, afi,
					safi);

				while (p_pnt < p_end) {
					/* If the ORF entry is malformed, want
					 * to read as much of it
					 * as possible without going beyond the
					 * bounds of the entry,
					 * to maximise debug information.
					 */
					int ok;
					memset(&orfp, 0,
					       sizeof(struct orf_prefix));
					common = *p_pnt++;
					/* after ++: p_pnt <= p_end */
					if (common
					    & ORF_COMMON_PART_REMOVE_ALL) {
						if (bgp_debug_neighbor_events(
							    peer))
							zlog_debug(
								"%s rcvd Remove-All pfxlist ORF request",
								peer->host);
						prefix_bgp_orf_remove_all(afi,
									  name);
						break;
					}
					ok = ((uint32_t)(p_end - p_pnt)
					      >= sizeof(uint32_t));
					if (ok) {
						memcpy(&seq, p_pnt,
						       sizeof(uint32_t));
						p_pnt += sizeof(uint32_t);
						orfp.seq = ntohl(seq);
					} else
						p_pnt = p_end;

					if ((ok = (p_pnt < p_end)))
						orfp.ge =
							*p_pnt++; /* value
								     checked in
								     prefix_bgp_orf_set()
								     */
					if ((ok = (p_pnt < p_end)))
						orfp.le =
							*p_pnt++; /* value
								     checked in
								     prefix_bgp_orf_set()
								     */
					if ((ok = (p_pnt < p_end)))
						orfp.p.prefixlen = *p_pnt++;
					orfp.p.family = afi2family(
						afi); /* afi checked already  */

					psize = PSIZE(
						orfp.p.prefixlen); /* 0 if not
								      ok */
					if (psize
					    > prefix_blen(
						      &orfp.p)) /* valid for
								   family ?   */
					{
						ok = 0;
						psize = prefix_blen(&orfp.p);
					}
					if (psize
					    > (p_end - p_pnt)) /* valid for
								  packet ?   */
					{
						ok = 0;
						psize = p_end - p_pnt;
					}

					if (psize > 0)
						memcpy(&orfp.p.u.prefix, p_pnt,
						       psize);
					p_pnt += psize;

					if (bgp_debug_neighbor_events(peer)) {
						char buf[INET6_BUFSIZ];

						zlog_debug(
							"%s rcvd %s %s seq %u %s/%d ge %d le %d%s",
							peer->host,
							(common & ORF_COMMON_PART_REMOVE
								 ? "Remove"
								 : "Add"),
							(common & ORF_COMMON_PART_DENY
								 ? "deny"
								 : "permit"),
							orfp.seq,
							inet_ntop(
								orfp.p.family,
								&orfp.p.u.prefix,
								buf,
								INET6_BUFSIZ),
							orfp.p.prefixlen,
							orfp.ge, orfp.le,
							ok ? "" : " MALFORMED");
					}

					if (ok)
						ret = prefix_bgp_orf_set(
							name, afi, &orfp,
							(common & ORF_COMMON_PART_DENY
								 ? 0
								 : 1),
							(common & ORF_COMMON_PART_REMOVE
								 ? 0
								 : 1));

					if (!ok || (ok && ret != CMD_SUCCESS)) {
						zlog_info(
							"%s Received misformatted prefixlist ORF."
							" Remove All pfxlist",
							peer->host);
						prefix_bgp_orf_remove_all(afi,
									  name);
						break;
					}
				}

				peer->orf_plist[afi][safi] =
					prefix_bgp_orf_lookup(afi, name);
			}
			stream_forward_getp(s, orf_len);
		}
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s rcvd Refresh %s ORF request", peer->host,
				   when_to_refresh == REFRESH_DEFER
					   ? "Defer"
					   : "Immediate");
		if (when_to_refresh == REFRESH_DEFER)
			return BGP_PACKET_NOOP;
	}

	/* First update is deferred until ORF or ROUTE-REFRESH is received */
	if (CHECK_FLAG(peer->af_sflags[afi][safi],
		       PEER_STATUS_ORF_WAIT_REFRESH))
		UNSET_FLAG(peer->af_sflags[afi][safi],
			   PEER_STATUS_ORF_WAIT_REFRESH);

	paf = peer_af_find(peer, afi, safi);
	if (paf && paf->subgroup) {
		if (peer->orf_plist[afi][safi]) {
			updgrp = PAF_UPDGRP(paf);
			updgrp_peer = UPDGRP_PEER(updgrp);
			updgrp_peer->orf_plist[afi][safi] =
				peer->orf_plist[afi][safi];
		}

		/* If the peer is configured for default-originate clear the
		 * SUBGRP_STATUS_DEFAULT_ORIGINATE flag so that we will
		 * re-advertise the
		 * default
		 */
		if (CHECK_FLAG(paf->subgroup->sflags,
			       SUBGRP_STATUS_DEFAULT_ORIGINATE))
			UNSET_FLAG(paf->subgroup->sflags,
				   SUBGRP_STATUS_DEFAULT_ORIGINATE);
	}

	/* Perform route refreshment to the peer */
	bgp_announce_route(peer, afi, safi);

	/* No FSM action necessary */
	return BGP_PACKET_NOOP;
}

/**
 * Parse BGP CAPABILITY message for peer.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
static int bgp_capability_msg_parse(struct peer *peer, uint8_t *pnt,
				    bgp_size_t length)
{
	uint8_t *end;
	struct capability_mp_data mpc;
	struct capability_header *hdr;
	uint8_t action;
	iana_afi_t pkt_afi;
	afi_t afi;
	iana_safi_t pkt_safi;
	safi_t safi;

	end = pnt + length;

	while (pnt < end) {
		/* We need at least action, capability code and capability
		 * length. */
		if (pnt + 3 > end) {
			zlog_info("%s Capability length error", peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE, 0);
			return BGP_Stop;
		}
		action = *pnt;
		hdr = (struct capability_header *)(pnt + 1);

		/* Action value check.  */
		if (action != CAPABILITY_ACTION_SET
		    && action != CAPABILITY_ACTION_UNSET) {
			zlog_info("%s Capability Action Value error %d",
				  peer->host, action);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE, 0);
			return BGP_Stop;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s CAPABILITY has action: %d, code: %u, length %u",
				peer->host, action, hdr->code, hdr->length);

		/* Capability length check. */
		if ((pnt + hdr->length + 3) > end) {
			zlog_info("%s Capability length error", peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_CEASE, 0);
			return BGP_Stop;
		}

		/* Fetch structure to the byte stream. */
		memcpy(&mpc, pnt + 3, sizeof(struct capability_mp_data));
		pnt += hdr->length + 3;

		/* We know MP Capability Code. */
		if (hdr->code == CAPABILITY_CODE_MP) {
			pkt_afi = ntohs(mpc.afi);
			pkt_safi = mpc.safi;

			/* Ignore capability when override-capability is set. */
			if (CHECK_FLAG(peer->flags,
				       PEER_FLAG_OVERRIDE_CAPABILITY))
				continue;

			/* Convert AFI, SAFI to internal values. */
			if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi,
						      &safi)) {
				if (bgp_debug_neighbor_events(peer))
					zlog_debug(
						"%s Dynamic Capability MP_EXT afi/safi invalid "
						"(%u/%u)",
						peer->host, pkt_afi, pkt_safi);
				continue;
			}

			/* Address family check.  */
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s CAPABILITY has %s MP_EXT CAP for afi/safi: %u/%u",
					peer->host,
					action == CAPABILITY_ACTION_SET
						? "Advertising"
						: "Removing",
					pkt_afi, pkt_safi);

			if (action == CAPABILITY_ACTION_SET) {
				peer->afc_recv[afi][safi] = 1;
				if (peer->afc[afi][safi]) {
					peer->afc_nego[afi][safi] = 1;
					bgp_announce_route(peer, afi, safi);
				}
			} else {
				peer->afc_recv[afi][safi] = 0;
				peer->afc_nego[afi][safi] = 0;

				if (peer_active_nego(peer))
					bgp_clear_route(peer, afi, safi);
				else
					return BGP_Stop;
			}
		} else {
			zlog_warn(
				"%s unrecognized capability code: %d - ignored",
				peer->host, hdr->code);
		}
	}

	/* No FSM action necessary */
	return BGP_PACKET_NOOP;
}

/**
 * Parse BGP CAPABILITY message for peer.
 *
 * Exported for unit testing.
 *
 * @param peer
 * @param size size of the packet
 * @return as in summary
 */
int bgp_capability_receive(struct peer *peer, bgp_size_t size)
{
	uint8_t *pnt;

	/* Fetch pointer. */
	pnt = stream_pnt(peer->curr);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s rcv CAPABILITY", peer->host);

	/* If peer does not have the capability, send notification. */
	if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV)) {
		zlog_err("%s [Error] BGP dynamic capability is not enabled",
			 peer->host);
		bgp_notify_send(peer, BGP_NOTIFY_HEADER_ERR,
				BGP_NOTIFY_HEADER_BAD_MESTYPE);
		return BGP_Stop;
	}

	/* Status must be Established. */
	if (peer->status != Established) {
		zlog_err(
			"%s [Error] Dynamic capability packet received under status %s",
			peer->host,
			lookup_msg(bgp_status_msg, peer->status, NULL));
		bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR, 0);
		return BGP_Stop;
	}

	/* Parse packet. */
	return bgp_capability_msg_parse(peer, pnt, size);
}

/**
 * Processes a peer's input buffer.
 *
 * This function sidesteps the event loop and directly calls bgp_event_update()
 * after processing each BGP message. This is necessary to ensure proper
 * ordering of FSM events and unifies the behavior that was present previously,
 * whereby some of the packet handling functions would update the FSM and some
 * would not, making event flow difficult to understand. Please think twice
 * before hacking this.
 *
 * Thread type: THREAD_EVENT
 * @param thread
 * @return 0
 */
int bgp_process_packet(struct thread *thread)
{
	/* Yes first of all get peer pointer. */
	struct peer *peer;	// peer
	uint32_t rpkt_quanta_old; // how many packets to read
	int fsm_update_result;    // return code of bgp_event_update()
	int mprc;		  // message processing return code

	peer = THREAD_ARG(thread);
	rpkt_quanta_old = atomic_load_explicit(&peer->bgp->rpkt_quanta,
					       memory_order_relaxed);
	fsm_update_result = 0;

	/* Guard against scheduled events that occur after peer deletion. */
	if (peer->status == Deleted || peer->status == Clearing)
		return 0;

	unsigned int processed = 0;

	while (processed < rpkt_quanta_old) {
		uint8_t type = 0;
		bgp_size_t size;
		char notify_data_length[2];

		pthread_mutex_lock(&peer->io_mtx);
		{
			peer->curr = stream_fifo_pop(peer->ibuf);
		}
		pthread_mutex_unlock(&peer->io_mtx);

		if (peer->curr == NULL) // no packets to process, hmm...
			return 0;

		/* skip the marker and copy the packet length */
		stream_forward_getp(peer->curr, BGP_MARKER_SIZE);
		memcpy(notify_data_length, stream_pnt(peer->curr), 2);

		/* read in the packet length and type */
		size = stream_getw(peer->curr);
		type = stream_getc(peer->curr);

		/* BGP packet dump function. */
		bgp_dump_packet(peer, type, peer->curr);

		/* adjust size to exclude the marker + length + type */
		size -= BGP_HEADER_SIZE;

		/* Read rest of the packet and call each sort of packet routine
		 */
		switch (type) {
		case BGP_MSG_OPEN:
			atomic_fetch_add_explicit(&peer->open_in, 1,
						  memory_order_relaxed);
			mprc = bgp_open_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP OPEN receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		case BGP_MSG_UPDATE:
			atomic_fetch_add_explicit(&peer->update_in, 1,
						  memory_order_relaxed);
			peer->readtime = monotime(NULL);
			mprc = bgp_update_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP UPDATE receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		case BGP_MSG_NOTIFY:
			atomic_fetch_add_explicit(&peer->notify_in, 1,
						  memory_order_relaxed);
			mprc = bgp_notify_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP NOTIFY receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		case BGP_MSG_KEEPALIVE:
			peer->readtime = monotime(NULL);
			atomic_fetch_add_explicit(&peer->keepalive_in, 1,
						  memory_order_relaxed);
			mprc = bgp_keepalive_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP KEEPALIVE receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		case BGP_MSG_ROUTE_REFRESH_NEW:
		case BGP_MSG_ROUTE_REFRESH_OLD:
			atomic_fetch_add_explicit(&peer->refresh_in, 1,
						  memory_order_relaxed);
			mprc = bgp_route_refresh_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP ROUTEREFRESH receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		case BGP_MSG_CAPABILITY:
			atomic_fetch_add_explicit(&peer->dynamic_cap_in, 1,
						  memory_order_relaxed);
			mprc = bgp_capability_receive(peer, size);
			if (mprc == BGP_Stop)
				zlog_err(
					"%s: BGP CAPABILITY receipt failed for peer: %s",
					__FUNCTION__, peer->host);
			break;
		default:
			/*
			 * The message type should have been sanitized before
			 * we ever got here. Receipt of a message with an
			 * invalid header at this point is indicative of a
			 * security issue.
			 */
			assert (!"Message of invalid type received during input processing");
		}

		/* delete processed packet */
		stream_free(peer->curr);
		peer->curr = NULL;
		processed++;

		/* Update FSM */
		if (mprc != BGP_PACKET_NOOP)
			fsm_update_result = bgp_event_update(peer, mprc);
		else
			continue;

		/*
		 * If peer was deleted, do not process any more packets. This
		 * is usually due to executing BGP_Stop or a stub deletion.
		 */
		if (fsm_update_result == FSM_PEER_TRANSFERRED
		    || fsm_update_result == FSM_PEER_STOPPED)
			break;
	}

	if (fsm_update_result != FSM_PEER_TRANSFERRED
	    && fsm_update_result != FSM_PEER_STOPPED) {
		pthread_mutex_lock(&peer->io_mtx);
		{
			// more work to do, come back later
			if (peer->ibuf->count > 0)
				thread_add_timer_msec(
					bm->master, bgp_process_packet, peer, 0,
					&peer->t_process_packet);
		}
		pthread_mutex_unlock(&peer->io_mtx);
	}

	return 0;
}
