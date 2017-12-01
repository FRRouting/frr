/* BGP I/O.
 * Implements packet I/O in a pthread.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

/* clang-format off */
#include <zebra.h>
#include <pthread.h>		// for pthread_mutex_unlock, pthread_mutex_lock

#include "frr_pthread.h"	// for frr_pthread_get, frr_pthread
#include "linklist.h"		// for list_delete, list_delete_all_node, lis...
#include "log.h"		// for zlog_debug, safe_strerror, zlog_err
#include "memory.h"		// for MTYPE_TMP, XCALLOC, XFREE
#include "network.h"		// for ERRNO_IO_RETRY
#include "stream.h"		// for stream_get_endp, stream_getw_from, str...
#include "thread.h"		// for THREAD_OFF, THREAD_ARG, thread, thread...
#include "zassert.h"		// for assert

#include "bgpd/bgp_io.h"
#include "bgpd/bgp_debug.h"	// for bgp_debug_neighbor_events, bgp_type_str
#include "bgpd/bgp_fsm.h"	// for BGP_EVENT_ADD, bgp_event
#include "bgpd/bgp_packet.h"	// for bgp_notify_send_with_data, bgp_notify...
#include "bgpd/bgpd.h"		// for peer, BGP_MARKER_SIZE, bgp_master, bm
/* clang-format on */

/* forward declarations */
static uint16_t bgp_write(struct peer *);
static uint16_t bgp_read(struct peer *);
static int bgp_process_writes(struct thread *);
static int bgp_process_reads(struct thread *);
static bool validate_header(struct peer *);

/* generic i/o status codes */
#define BGP_IO_TRANS_ERR (1 << 0) // EAGAIN or similar occurred
#define BGP_IO_FATAL_ERR (1 << 1) // some kind of fatal TCP error

/* Start and stop routines for I/O pthread + control variables
 * ------------------------------------------------------------------------ */
_Atomic bool bgp_io_thread_run;
_Atomic bool bgp_io_thread_started;

void bgp_io_init()
{
	bgp_io_thread_run = false;
	bgp_io_thread_started = false;
}

/* Unused callback for thread_add_read() */
static int bgp_io_dummy(struct thread *thread) { return 0; }

void *bgp_io_start(void *arg)
{
	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);
	fpt->master->owner = pthread_self();

	// fd so we can sleep in poll()
	int sleeper[2];
	pipe(sleeper);
	thread_add_read(fpt->master, &bgp_io_dummy, NULL, sleeper[0], NULL);

	// we definitely don't want to handle signals
	fpt->master->handle_signals = false;

	struct thread task;

	atomic_store_explicit(&bgp_io_thread_run, true, memory_order_seq_cst);
	atomic_store_explicit(&bgp_io_thread_started, true,
			      memory_order_seq_cst);

	while (bgp_io_thread_run) {
		if (thread_fetch(fpt->master, &task)) {
			thread_call(&task);
		}
	}

	close(sleeper[1]);
	close(sleeper[0]);

	return NULL;
}

static int bgp_io_finish(struct thread *thread)
{
	atomic_store_explicit(&bgp_io_thread_run, false, memory_order_seq_cst);
	return 0;
}

int bgp_io_stop(void **result, struct frr_pthread *fpt)
{
	thread_add_event(fpt->master, &bgp_io_finish, NULL, 0, NULL);
	pthread_join(fpt->thread, result);
	return 0;
}

/* Extern API -------------------------------------------------------------- */

void bgp_writes_on(struct peer *peer)
{
	while (
	    !atomic_load_explicit(&bgp_io_thread_started, memory_order_seq_cst))
		;

	assert(peer->status != Deleted);
	assert(peer->obuf);
	assert(peer->ibuf);
	assert(peer->ibuf_work);
	assert(!peer->t_connect_check_r);
	assert(!peer->t_connect_check_w);
	assert(peer->fd);

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	thread_add_write(fpt->master, bgp_process_writes, peer, peer->fd,
			 &peer->t_write);
	SET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_writes_off(struct peer *peer)
{
	while (
	    !atomic_load_explicit(&bgp_io_thread_started, memory_order_seq_cst))
		;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	thread_cancel_async(fpt->master, &peer->t_write, NULL);
	THREAD_OFF(peer->t_generate_updgrp_packets);

	UNSET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_reads_on(struct peer *peer)
{
	while (
	    !atomic_load_explicit(&bgp_io_thread_started, memory_order_seq_cst))
		;

	assert(peer->status != Deleted);
	assert(peer->ibuf);
	assert(peer->fd);
	assert(peer->ibuf_work);
	assert(peer->obuf);
	assert(!peer->t_connect_check_r);
	assert(!peer->t_connect_check_w);
	assert(peer->fd);

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	thread_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
			&peer->t_read);

	SET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
}

void bgp_reads_off(struct peer *peer)
{
	while (
	    !atomic_load_explicit(&bgp_io_thread_started, memory_order_seq_cst))
		;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	thread_cancel_async(fpt->master, &peer->t_read, NULL);
	THREAD_OFF(peer->t_process_packet);

	UNSET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
}

/* Internal functions ------------------------------------------------------- */

/**
 * Called from I/O pthread when a file descriptor has become ready for writing.
 */
static int bgp_process_writes(struct thread *thread)
{
	static struct peer *peer;
	peer = THREAD_ARG(thread);
	uint16_t status;
	bool reschedule;
	bool fatal = false;

	if (peer->fd < 0)
		return -1;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	pthread_mutex_lock(&peer->io_mtx);
	{
		status = bgp_write(peer);
		reschedule = (stream_fifo_head(peer->obuf) != NULL);
	}
	pthread_mutex_unlock(&peer->io_mtx);

	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) { /* no problem */
	}

	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR)) {
		reschedule = false; /* problem */
		fatal = true;
	}

	if (reschedule) {
		thread_add_write(fpt->master, bgp_process_writes, peer,
				 peer->fd, &peer->t_write);
	} else if (!fatal) {
		BGP_TIMER_ON(peer->t_generate_updgrp_packets,
			     bgp_generate_updgrp_packets, 0);
	}

	return 0;
}

/**
 * Called from I/O pthread when a file descriptor has become ready for reading,
 * or has hung up.
 *
 * We read as much data as possible, process as many packets as we can and
 * place them on peer->ibuf for secondary processing by the main thread.
 */
static int bgp_process_reads(struct thread *thread)
{
	/* clang-format off */
	static struct peer *peer;	// peer to read from
	uint16_t status;		// bgp_read status code
	bool more = true;		// whether we got more data
	bool fatal = false;		// whether fatal error occurred
	bool added_pkt = false;		// whether we pushed onto ->ibuf
	bool header_valid = true;	// whether header is valid
	/* clang-format on */

	peer = THREAD_ARG(thread);

	if (peer->fd < 0)
		return -1;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_IO);

	pthread_mutex_lock(&peer->io_mtx);
	{
		status = bgp_read(peer);
	}
	pthread_mutex_unlock(&peer->io_mtx);

	/* error checking phase */
	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) {
		/* no problem; just don't process packets */
		more = false;
	}

	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR)) {
		/* problem; tear down session */
		more = false;
		fatal = true;
	}

	while (more) {
		/* static buffer for transferring packets */
		static unsigned char pktbuf[BGP_MAX_PACKET_SIZE];
		/* shorter alias to peer's input buffer */
		struct stream *ibw = peer->ibuf_work;
		/* offset of start of current packet */
		size_t offset = stream_get_getp(ibw);
		/* packet size as given by header */
		u_int16_t pktsize = 0;

		/* check that we have enough data for a header */
		if (STREAM_READABLE(ibw) < BGP_HEADER_SIZE)
			break;

		/* validate header */
		header_valid = validate_header(peer);

		if (!header_valid) {
			fatal = true;
			break;
		}

		/* header is valid; retrieve packet size */
		pktsize = stream_getw_from(ibw, offset + BGP_MARKER_SIZE);

		/* if this fails we are seriously screwed */
		assert(pktsize <= BGP_MAX_PACKET_SIZE);

		/* If we have that much data, chuck it into its own
		 * stream and append to input queue for processing. */
		if (STREAM_READABLE(ibw) >= pktsize) {
			struct stream *pkt = stream_new(pktsize);
			stream_get(pktbuf, ibw, pktsize);
			stream_put(pkt, pktbuf, pktsize);

			pthread_mutex_lock(&peer->io_mtx);
			{
				stream_fifo_push(peer->ibuf, pkt);
			}
			pthread_mutex_unlock(&peer->io_mtx);

			added_pkt = true;
		} else
			break;
	}

	/*
	 * After reading:
	 * 1. Move unread data to stream start to make room for more.
	 * 2. Reschedule and return when we have additional data.
	 *
	 * XXX: Heavy abuse of stream API. This needs a ring buffer.
	 */
	if (more && STREAM_WRITEABLE(peer->ibuf_work) < BGP_MAX_PACKET_SIZE) {
		void *from = stream_pnt(peer->ibuf_work);
		void *to = peer->ibuf_work->data;
		size_t siz = STREAM_READABLE(peer->ibuf_work);
		memmove(to, from, siz);
		stream_set_getp(peer->ibuf_work, 0);
		stream_set_endp(peer->ibuf_work, siz);
	}

	assert(STREAM_WRITEABLE(peer->ibuf_work) >= BGP_MAX_PACKET_SIZE);

	/* handle invalid header */
	if (fatal) {
		/* wipe buffer just in case someone screwed up */
		stream_reset(peer->ibuf_work);
	} else {
		thread_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
				&peer->t_read);
		if (added_pkt)
			thread_add_timer_msec(bm->master, bgp_process_packet,
					      peer, 0, &peer->t_process_packet);
	}

	return 0;
}

/**
 * Flush peer output buffer.
 *
 * This function pops packets off of peer->obuf and writes them to peer->fd.
 * The amount of packets written is equal to the minimum of peer->wpkt_quanta
 * and the number of packets on the output buffer, unless an error occurs.
 *
 * If write() returns an error, the appropriate FSM event is generated.
 *
 * The return value is equal to the number of packets written
 * (which may be zero).
 */
static uint16_t bgp_write(struct peer *peer)
{
	u_char type;
	struct stream *s;
	int num;
	int update_last_write = 0;
	unsigned int count = 0;
	uint32_t oc;
	uint32_t uo;
	uint16_t status = 0;
	uint32_t wpkt_quanta_old;

	// save current # updates sent
	oc = atomic_load_explicit(&peer->update_out, memory_order_relaxed);

	// cache current write quanta
	wpkt_quanta_old =
	    atomic_load_explicit(&peer->bgp->wpkt_quanta, memory_order_relaxed);

	while (count < wpkt_quanta_old && (s = stream_fifo_head(peer->obuf))) {
		int writenum;
		do {
			writenum = stream_get_endp(s) - stream_get_getp(s);
			num = write(peer->fd, STREAM_PNT(s), writenum);

			if (num < 0) {
				if (!ERRNO_IO_RETRY(errno)) {
					BGP_EVENT_ADD(peer, TCP_fatal_error);
					SET_FLAG(status, BGP_IO_FATAL_ERR);
				} else {
					SET_FLAG(status, BGP_IO_TRANS_ERR);
				}

				goto done;
			} else if (num != writenum) // incomplete write
				stream_forward_getp(s, num);

		} while (num != writenum);

		/* Retrieve BGP packet type. */
		stream_set_getp(s, BGP_MARKER_SIZE + 2);
		type = stream_getc(s);

		switch (type) {
		case BGP_MSG_OPEN:
			atomic_fetch_add_explicit(&peer->open_out, 1,
						  memory_order_relaxed);
			break;
		case BGP_MSG_UPDATE:
			atomic_fetch_add_explicit(&peer->update_out, 1,
						  memory_order_relaxed);
			break;
		case BGP_MSG_NOTIFY:
			atomic_fetch_add_explicit(&peer->notify_out, 1,
						  memory_order_relaxed);
			/* Double start timer. */
			peer->v_start *= 2;

			/* Overflow check. */
			if (peer->v_start >= (60 * 2))
				peer->v_start = (60 * 2);

			/* Handle Graceful Restart case where the state changes
			 * to Connect instead of Idle */
			BGP_EVENT_ADD(peer, BGP_Stop);
			goto done;

		case BGP_MSG_KEEPALIVE:
			atomic_fetch_add_explicit(&peer->keepalive_out, 1,
						  memory_order_relaxed);
			break;
		case BGP_MSG_ROUTE_REFRESH_NEW:
		case BGP_MSG_ROUTE_REFRESH_OLD:
			atomic_fetch_add_explicit(&peer->refresh_out, 1,
						  memory_order_relaxed);
			break;
		case BGP_MSG_CAPABILITY:
			atomic_fetch_add_explicit(&peer->dynamic_cap_out, 1,
						  memory_order_relaxed);
			break;
		}

		count++;

		stream_free(stream_fifo_pop(peer->obuf));
		update_last_write = 1;
	}

done : {
	/* Update last_update if UPDATEs were written. */
	uo = atomic_load_explicit(&peer->update_out, memory_order_relaxed);
	if (uo > oc)
		atomic_store_explicit(&peer->last_update, bgp_clock(),
				      memory_order_relaxed);

	/* If we TXed any flavor of packet */
	if (update_last_write)
		atomic_store_explicit(&peer->last_write, bgp_clock(),
				      memory_order_relaxed);
}

	return status;
}

/**
 * Reads a chunk of data from peer->fd into peer->ibuf_work.
 *
 * @return status flag (see top-of-file)
 */
static uint16_t bgp_read(struct peer *peer)
{
	size_t readsize; // how many bytes we want to read
	ssize_t nbytes;  // how many bytes we actually read
	uint16_t status = 0;

	readsize = STREAM_WRITEABLE(peer->ibuf_work);

	nbytes = stream_read_try(peer->ibuf_work, peer->fd, readsize);

	switch (nbytes) {
	/* Fatal error; tear down session */
	case -1:
		zlog_err("%s [Error] bgp_read_packet error: %s", peer->host,
			 safe_strerror(errno));

		if (peer->status == Established) {
			if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE)) {
				peer->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
				SET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
			} else
				peer->last_reset = PEER_DOWN_CLOSE_SESSION;
		}

		BGP_EVENT_ADD(peer, TCP_fatal_error);
		SET_FLAG(status, BGP_IO_FATAL_ERR);
		break;

	/* Received EOF / TCP session closed */
	case 0:
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [Event] BGP connection closed fd %d",
				   peer->host, peer->fd);

		if (peer->status == Established) {
			if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE)) {
				peer->last_reset = PEER_DOWN_NSF_CLOSE_SESSION;
				SET_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT);
			} else
				peer->last_reset = PEER_DOWN_CLOSE_SESSION;
		}

		BGP_EVENT_ADD(peer, TCP_connection_closed);
		SET_FLAG(status, BGP_IO_FATAL_ERR);
		break;

	/* EAGAIN or EWOULDBLOCK; come back later */
	case -2:
		SET_FLAG(status, BGP_IO_TRANS_ERR);
		break;
	default:
		break;
	}

	return status;
}

/*
 * Called after we have read a BGP packet header. Validates marker, message
 * type and packet length. If any of these aren't correct, sends a notify.
 */
static bool validate_header(struct peer *peer)
{
	uint16_t size;
	uint8_t type;
	struct stream *pkt = peer->ibuf_work;
	size_t getp = stream_get_getp(pkt);

	static uint8_t marker[BGP_MARKER_SIZE] = {
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (memcmp(marker, stream_pnt(pkt), BGP_MARKER_SIZE) != 0) {
		bgp_notify_send(peer, BGP_NOTIFY_HEADER_ERR,
				BGP_NOTIFY_HEADER_NOT_SYNC);
		return false;
	}

	/* Get size and type in host byte order. */
	size = stream_getw_from(pkt, getp + BGP_MARKER_SIZE);
	type = stream_getc_from(pkt, getp + BGP_MARKER_SIZE + 2);

	/* BGP type check. */
	if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE
	    && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE
	    && type != BGP_MSG_ROUTE_REFRESH_NEW
	    && type != BGP_MSG_ROUTE_REFRESH_OLD
	    && type != BGP_MSG_CAPABILITY) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s unknown message type 0x%02x", peer->host,
				   type);

		bgp_notify_send_with_data(peer, BGP_NOTIFY_HEADER_ERR,
					  BGP_NOTIFY_HEADER_BAD_MESTYPE,
					  &type, 1);
		return false;
	}

	/* Minimum packet length check. */
	if ((size < BGP_HEADER_SIZE) || (size > BGP_MAX_PACKET_SIZE)
	    || (type == BGP_MSG_OPEN && size < BGP_MSG_OPEN_MIN_SIZE)
	    || (type == BGP_MSG_UPDATE && size < BGP_MSG_UPDATE_MIN_SIZE)
	    || (type == BGP_MSG_NOTIFY && size < BGP_MSG_NOTIFY_MIN_SIZE)
	    || (type == BGP_MSG_KEEPALIVE && size != BGP_MSG_KEEPALIVE_MIN_SIZE)
	    || (type == BGP_MSG_ROUTE_REFRESH_NEW
		&& size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
	    || (type == BGP_MSG_ROUTE_REFRESH_OLD
		&& size < BGP_MSG_ROUTE_REFRESH_MIN_SIZE)
	    || (type == BGP_MSG_CAPABILITY
		&& size < BGP_MSG_CAPABILITY_MIN_SIZE)) {
		if (bgp_debug_neighbor_events(peer)) {
			zlog_debug("%s bad message length - %d for %s",
				   peer->host, size,
				   type == 128 ? "ROUTE-REFRESH"
					       : bgp_type_str[(int) type]);
		}

		uint16_t nsize = htons(size);

		bgp_notify_send_with_data(peer, BGP_NOTIFY_HEADER_ERR,
					  BGP_NOTIFY_HEADER_BAD_MESLEN,
					  (unsigned char *) &nsize, 2);
		return false;
	}

	return true;
}
