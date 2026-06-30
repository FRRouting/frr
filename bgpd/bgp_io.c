// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP I/O.
 * Implements packet I/O in a pthread.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
 */

/* clang-format off */
#include <zebra.h>
#include <pthread.h>		// for pthread_mutex_unlock, pthread_mutex_lock
#include <sys/uio.h>		// for writev

#include "frr_pthread.h"
#include "linklist.h"		// for list_delete, list_delete_all_node, lis...
#include "log.h"		// for zlog_debug, safe_strerror, zlog_err
#include "memory.h"		// for MTYPE_TMP, XCALLOC, XFREE
#include "network.h"		// for ERRNO_IO_RETRY
#include "stream.h"		// for stream_get_endp, stream_getw_from, str...
#include "frrevent.h"		// for event, EVENT_ARG, thread...

#include "bgpd/bgp_io.h"
#include "bgpd/bgp_debug.h"	// for bgp_debug_neighbor_events, bgp_type_str
#include "bgpd/bgp_errors.h"	// for expanded error reference information
#include "bgpd/bgp_fsm.h"	// for BGP_EVENT_ADD, bgp_event
#include "bgpd/bgp_packet.h"	// for bgp_notify_io_invalid...
#include "bgpd/bgp_trace.h"	// for frrtraces
#include "bgpd/bgpd.h"		// for peer, BGP_MARKER_SIZE, bgp_master, bm
/* clang-format on */

/* forward declarations */
static uint16_t bgp_write(struct peer_connection *connection);
static uint16_t bgp_read(struct peer_connection *connection, int *code_p, ssize_t *nread_p);
static void bgp_process_writes(struct event *event);
static void bgp_process_reads(struct event *event);
static bool validate_header_from_buf(struct peer_connection *connection, const uint8_t *buf);

/* Global scratch buffer for socket read - defined near bgp_read() */
static uint8_t ibuf_scratch[BGP_IBUF_WORK_SIZE];

/* generic i/o status codes */
#define BGP_IO_TRANS_ERR (1 << 0) /* EAGAIN or similar occurred */
#define BGP_IO_FATAL_ERR (1 << 1) /* some kind of fatal TCP error */

/* extract message length from BGP header */
#define BGP_MSG_LEN(buf) ((uint16_t)(((buf)[BGP_MARKER_SIZE] << 8) + (buf)[BGP_MARKER_SIZE + 1]))

/* Thread external API ----------------------------------------------------- */

void bgp_writes_on(struct peer_connection *connection)
{
	struct frr_pthread *fpt = bgp_pth_io;

	assert(fpt->running);

	assert(connection->status != Deleted);
	assert(connection->obuf);
	assert(connection->ibuf);
	assert(!connection->t_connect_check_r);
	assert(!connection->t_connect_check_w);
	assert(connection->fd);

	event_add_write(fpt->master, bgp_process_writes, connection,
			connection->fd, &connection->t_write);

	SET_FLAG(connection->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_writes_off(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
	struct frr_pthread *fpt = bgp_pth_io;
	struct stream *s;

	assert(fpt->running);

	UNSET_FLAG(peer->connection->thread_flags, PEER_THREAD_WRITES_ON);

	/* Clear out the write fifo */
	frr_with_mutex (&connection->io_mtx) {
		if (connection->obuf != NULL) {
			while ((s = stream_fifo_pop(connection->obuf)) != NULL)
				stream_free(s);
		}
	}

	event_cancel_async(fpt->master, &connection->t_write, NULL);
	event_cancel(&connection->t_generate_updgrp_packets);
}

void bgp_reads_on(struct peer_connection *connection)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

	assert(connection->status != Deleted);
	assert(connection->ibuf);
	assert(connection->fd);
	assert(connection->obuf);
	assert(!connection->t_connect_check_r);
	assert(!connection->t_connect_check_w);
	assert(connection->fd);

	event_add_read(fpt->master, bgp_process_reads, connection,
		       connection->fd, &connection->t_read);

	SET_FLAG(connection->thread_flags, PEER_THREAD_READS_ON);
}

void bgp_reads_off(struct peer_connection *connection)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

	event_cancel_async(fpt->master, &connection->t_read, NULL);

	frr_with_mutex (&bm->peer_connection_mtx) {
		if (peer_connection_fifo_member(&bm->connection_fifo, connection))
			peer_connection_fifo_del(&bm->connection_fifo, connection);
	}

	UNSET_FLAG(connection->thread_flags, PEER_THREAD_READS_ON);
}

/* Thread internal functions ----------------------------------------------- */

/*
 * Called from I/O pthread when a file descriptor has become ready for writing.
 */
static void bgp_process_writes(struct event *event)
{
	static struct peer *peer;
	struct peer_connection *connection = EVENT_ARG(event);
	uint16_t status;
	bool reschedule = false;
	bool fatal = false;
	struct frr_pthread *fpt = bgp_pth_io;

	peer = connection->peer;

	if (connection->fd < 0)
		return;

	/* Anticipate rescheduling */
	event_add_write(fpt->master, bgp_process_writes, connection, connection->fd,
			&connection->t_write);

	frr_with_mutex (&connection->io_mtx) {
		status = bgp_write(connection);
		reschedule = (stream_fifo_head(connection->obuf) != NULL);
	}

	/* no problem */
	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) {
	}

	/* problem */
	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR)) {
		reschedule = false;
		fatal = true;
	}

	/* If suppress fib pending is enabled, route is advertised to peers when
	 * the status is received from the FIB. The delay is added
	 * to update group packet generate which will allow more routes to be
	 * sent in the update message
	 */
	if (!reschedule) {
		event_cancel(&connection->t_write);

		if (!fatal)
			BGP_UPDATE_GROUP_TIMER_ON(&connection->t_generate_updgrp_packets,
						  bgp_generate_updgrp_packets);
	}
}

/*
 * Process packets from a buffer with in-place parsing.
 *
 * Parses complete BGP packets from buf, pushes them to connection->ibuf.
 *
 * added_pkt_p: set to true if at least one packet was added
 * remaining_p: set to number of unprocessed bytes at end of buffer
 *
 * Returns:
 *   0: success (check *remaining_p for partial data)
 *   -EBADMSG: invalid header
 */
static int parse_buffer(struct peer_connection *connection, const uint8_t *buf, size_t len,
			bool *added_pkt_p, size_t *remaining_p)
{
	size_t offset = 0;
	uint16_t pktsize;
	struct stream *pkt;

	*remaining_p = 0;

	while (offset < len) {
		/* need at least a header */
		if (len - offset < BGP_HEADER_SIZE) {
			*remaining_p = len - offset;
			return 0;
		}

		/* validate header */
		if (!validate_header_from_buf(connection, buf + offset))
			return -EBADMSG;

		/* get packet size from header (already validated) */
		pktsize = BGP_MSG_LEN(buf + offset);

		/* need complete packet */
		if (len - offset < pktsize) {
			*remaining_p = len - offset;
			return 0;
		}

		/* create stream and copy packet */
		pkt = stream_new(pktsize);
		memcpy(pkt->data, buf + offset, pktsize);
		stream_set_endp(pkt, pktsize);

		frrtrace(2, frr_bgp, packet_read, connection, pkt);
		frr_with_mutex (&connection->io_mtx) {
			stream_fifo_push(connection->ibuf, pkt);
		}

		*added_pkt_p = true;
		offset += pktsize;
	}

	return 0;
}

/*
 * Called from I/O pthread when a file descriptor has become ready for reading,
 * or has hung up.
 *
 * We read as much data as possible, process as many packets as we can and
 * place them on peer->connection.ibuf for secondary processing by the main
 * thread.
 */
static void bgp_process_reads(struct event *event)
{
	/* clang-format off */
	struct peer_connection *connection = EVENT_ARG(event);
	static struct peer *peer;       /* peer to read from */
	uint16_t status;                /* bgp_read status code */
	bool fatal = false;             /* whether fatal error occurred */
	bool added_pkt = false;         /* whether we pushed onto ->connection.ibuf */
	int code = 0;                   /* FSM code if error occurred */
	static bool ibuf_full_logged;   /* Have we logged full already */
	int ret = 0;
	ssize_t nread = 0;
	size_t remaining = 0;
	size_t total_len;
	/* clang-format on */

	peer = connection->peer;

	if (bm->terminating || connection->fd < 0)
		return;

	struct frr_pthread *fpt = bgp_pth_io;

	/*
	 * Soft limit: check queue before reading, not during parsing.
	 * This allows a single read to exceed the limit (multiple messages
	 * in one read are all processed), keeping ibuf_work for partial
	 * packets only. The limit governs when we stop reading, not parsing.
	 */
	frr_with_mutex (&connection->io_mtx) {
		if (connection->ibuf->count >= bm->inq_limit) {
			if (!ibuf_full_logged) {
				if (bgp_debug_neighbor_events(peer))
					zlog_debug("%s [Event] Peer Input-Queue is full: limit (%u)",
						   peer->host, bm->inq_limit);
				ibuf_full_logged = true;
			}
			return;
		}
		ibuf_full_logged = false;
	}

	frr_with_mutex (&connection->io_mtx) {
		status = bgp_read(connection, &code, &nread);
	}

	/* error checking phase */
	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR)) {
		/* problem; tear down session */
		fatal = true;

		/* Handle the error in the main pthread, include the
		 * specific state change from 'bgp_read'.
		 */
		bgp_enqueue_conn_err(peer->bgp, connection, code);
		goto done;
	}

	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) {
		/* EAGAIN - no data read; ibuf_work (if any) unchanged */
		goto done;
	}

	/*
	 * Parse from ibuf_scratch. Prior partial data was copied there by
	 * bgp_read().
	 */
	total_len = connection->ibuf_data_len + nread;
	if (total_len > 0)
		ret = parse_buffer(connection, ibuf_scratch, total_len, &added_pkt, &remaining);

	if (remaining > 0) {
		/* partial packet remains - save to ibuf_work */
		if (!connection->ibuf_work)
			connection->ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK, BGP_IBUF_WORK_SIZE);
		memcpy(connection->ibuf_work, ibuf_scratch + total_len - remaining, remaining);
	} else if (connection->ibuf_work) {
		/* no partial data - free ibuf_work */
		XFREE(MTYPE_BGP_IBUF_WORK, connection->ibuf_work);
	}
	connection->ibuf_data_len = remaining;

	if (ret == -EBADMSG)
		fatal = true;

done:
	/* handle invalid header */
	if (fatal) {
		/* wipe buffer just in case someone screwed up */
		if (connection->ibuf_work) {
			XFREE(MTYPE_BGP_IBUF_WORK, connection->ibuf_work);
			connection->ibuf_data_len = 0;
		}
		return;
	}

	event_add_read(fpt->master, bgp_process_reads, connection, connection->fd,
		       &connection->t_read);
	if (added_pkt) {
		frr_with_mutex (&bm->peer_connection_mtx) {
			if (!peer_connection_fifo_member(&bm->connection_fifo, connection))
				peer_connection_fifo_add_tail(&bm->connection_fifo, connection);
		}
		event_add_event(bm->master, bgp_process_packet, NULL, 0, &bm->e_process_packet);
	}
}

/*
 * Flush peer output buffer.
 *
 * This function pops packets off of peer->connection.obuf and writes them to
 * peer->connection.fd. The amount of packets written is equal to the minimum of
 * peer->wpkt_quanta and the number of packets on the output buffer, unless an
 * error occurs.
 *
 * If write() returns an error, the appropriate FSM event is generated.
 *
 * The return value is equal to the number of packets written
 * (which may be zero).
 */
static uint16_t bgp_write(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
	uint8_t type;
	struct stream *s;
	int update_last_write = 0;
	unsigned int count;
	uint32_t uo = 0;
	uint16_t status = 0;
	uint32_t wpkt_quanta_old;

	int writenum = 0;
	int num;
	unsigned int iovsz;
	unsigned int strmsz;
	unsigned int total_written;
	time_t now;

	wpkt_quanta_old = atomic_load_explicit(&peer->bgp->wpkt_quanta,
					       memory_order_relaxed);
	struct stream *ostreams[wpkt_quanta_old];
	struct stream **streams = ostreams;
	struct iovec iov[wpkt_quanta_old];

	s = stream_fifo_head(connection->obuf);

	if (!s)
		goto done;

	count = iovsz = 0;
	while (count < wpkt_quanta_old && iovsz < array_size(iov) && s) {
		ostreams[iovsz] = s;
		iov[iovsz].iov_base = stream_pnt(s);
		iov[iovsz].iov_len = STREAM_READABLE(s);
		writenum += STREAM_READABLE(s);
		s = s->next;
		++iovsz;
		++count;
	}

	strmsz = iovsz;
	total_written = 0;

	do {
		num = writev(connection->fd, iov, iovsz);

		if (num < 0) {
			if (!ERRNO_IO_RETRY(errno)) {
				BGP_EVENT_ADD(connection, TCP_fatal_error);
				SET_FLAG(status, BGP_IO_FATAL_ERR);
			} else {
				SET_FLAG(status, BGP_IO_TRANS_ERR);
			}

			break;
		} else if (num != writenum) {
			unsigned int msg_written = 0;
			unsigned int ic = iovsz;

			for (unsigned int i = 0; i < ic; i++) {
				size_t ss = iov[i].iov_len;

				if (ss > (unsigned int) num)
					break;

				msg_written++;
				iovsz--;
				writenum -= ss;
				num -= ss;
			}

			total_written += msg_written;

			assert(total_written < count);

			memmove(&iov, &iov[msg_written],
				sizeof(iov[0]) * iovsz);
			streams = &streams[msg_written];
			stream_forward_getp(streams[0], num);
			iov[0].iov_base = stream_pnt(streams[0]);
			iov[0].iov_len = STREAM_READABLE(streams[0]);

			writenum -= num;
			num = 0;
			assert(writenum > 0);
		} else {
			total_written = strmsz;
		}

	} while (num != writenum);

	/* Handle statistics */
	for (unsigned int i = 0; i < total_written; i++) {
		s = stream_fifo_pop(connection->obuf);

		assert(s == ostreams[i]);

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
			uo++;
			break;
		case BGP_MSG_NOTIFY:
			atomic_fetch_add_explicit(&peer->notify_out, 1,
						  memory_order_relaxed);
			/* Double start timer. */
			peer->v_start *= 2;

			/* Overflow check. */
			if (peer->v_start >= (60 * 2))
				peer->v_start = (60 * 2);

			/*
			 * Handle Graceful Restart case where the state changes
			 * to Connect instead of Idle.
			 */
			BGP_EVENT_ADD(connection, BGP_Stop);
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

		stream_free(s);
		ostreams[i] = NULL;
		update_last_write = 1;
	}

done : {
	now = monotime(NULL);
	/*
	 * Update last_update if UPDATEs were written.
	 * Note: that these are only updated at end,
	 *       not per message (i.e., per loop)
	 */
	if (uo)
		atomic_store_explicit(&peer->last_update, now,
				      memory_order_relaxed);

	/* If we TXed any flavor of packet */
	if (update_last_write) {
		atomic_store_explicit(&peer->last_write, now,
				      memory_order_relaxed);
		atomic_store_explicit(&connection->last_sendq_ok, now, memory_order_relaxed);
	}
}

	return status;
}

/*
 * Reads a chunk of data from peer->connection.fd into ibuf_scratch.
 *
 * If ibuf_work has partial data, copies it to ibuf_scratch first,
 * then reads new data after it.
 *
 * code_p
 *    Pointer to location to store FSM event code in case of fatal error.
 * nread_p
 *    Pointer to store number of bytes read.
 *
 * @return status flag (see top-of-file)
 *
 * PLEASE NOTE:  If we ever transform the bgp_read to be a pthread
 * per peer then we need to rethink the global ibuf_scratch
 * data structure above.
 */
static uint16_t bgp_read(struct peer_connection *connection, int *code_p, ssize_t *nread_p)
{
	size_t readsize; /* how many bytes we want to read */
	ssize_t nbytes;  /* how many bytes we actually read */
	uint8_t *readbuf;
	uint16_t status = 0;

	if (nread_p)
		*nread_p = 0;

	/*
	 * Always read into ibuf_scratch. If ibuf_work has partial data,
	 * copy it to ibuf_scratch first so new data lands right after it.
	 * This wastes a memcpy on EAGAIN but avoids memmove when data arrives.
	 */
	if (connection->ibuf_work && connection->ibuf_data_len > 0) {
		memcpy(ibuf_scratch, connection->ibuf_work, connection->ibuf_data_len);
		readbuf = ibuf_scratch + connection->ibuf_data_len;
		readsize = sizeof(ibuf_scratch) - connection->ibuf_data_len;
	} else {
		readbuf = ibuf_scratch;
		readsize = sizeof(ibuf_scratch);
	}

	/* ibuf_data_len < BGP_IBUF_WORK_SIZE, so readsize > 0 */
	assert(readsize > 0);

#ifdef __clang_analyzer__
	/* clang-SA doesn't want you to call read() while holding a mutex */
	(void)readbuf;
	(void)readsize;
	nbytes = 0;
#else
	nbytes = read(connection->fd, readbuf, readsize);
#endif

	/* EAGAIN or EWOULDBLOCK; come back later */
	if (nbytes < 0 && ERRNO_IO_RETRY(errno)) {
		SET_FLAG(status, BGP_IO_TRANS_ERR);
	} else if (nbytes < 0) {
		/* Fatal error; tear down session */
		flog_err(EC_BGP_UPDATE_RCV,
			 "%s [Error] bgp_read_packet error: %s",
			 connection->peer->host, safe_strerror(errno));

		/* Handle the error in the main pthread. */
		if (code_p)
			*code_p = TCP_fatal_error;

		SET_FLAG(status, BGP_IO_FATAL_ERR);

	} else if (nbytes == 0) {
		/* Received EOF / TCP session closed */
		if (bgp_debug_neighbor_events(connection->peer))
			zlog_debug("%s [Event] BGP connection closed fd %d",
				   connection->peer->host, connection->fd);

		/* Handle the error in the main pthread. */
		if (code_p)
			*code_p = TCP_connection_closed;

		SET_FLAG(status, BGP_IO_FATAL_ERR);
	} else {
		if (nread_p)
			*nread_p = nbytes;
	}

	return status;
}

/*
 * Validate BGP packet header from a buffer.
 *
 * Assumes buf has at least BGP_HEADER_SIZE bytes.
 */
static bool validate_header_from_buf(struct peer_connection *connection, const uint8_t *buf)
{
	struct peer *peer = connection->peer;
	uint16_t size;
	uint8_t type;

	static const uint8_t m_correct[BGP_MARKER_SIZE] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (memcmp(m_correct, buf, BGP_MARKER_SIZE) != 0) {
		bgp_notify_io_invalid(connection, BGP_NOTIFY_HEADER_ERR,
				      BGP_NOTIFY_HEADER_NOT_SYNC, NULL, 0);
		return false;
	}

	/* Get size and type */
	size = BGP_MSG_LEN(buf);
	type = buf[BGP_MARKER_SIZE + 2];

	/* BGP type check. */
	if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE
	    && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE
	    && type != BGP_MSG_ROUTE_REFRESH_NEW
	    && type != BGP_MSG_ROUTE_REFRESH_OLD
	    && type != BGP_MSG_CAPABILITY) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s unknown message type 0x%02x", peer->host,
				   type);

		bgp_notify_io_invalid(connection, BGP_NOTIFY_HEADER_ERR,
				      BGP_NOTIFY_HEADER_BAD_MESTYPE, &type, 1);
		return false;
	}

	/* Minimum packet length check. */
	if ((size < BGP_HEADER_SIZE) || (size > peer->max_packet_size)
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
					       : bgp_type_str[(int)type]);
		}

		uint16_t nsize = htons(size);

		bgp_notify_io_invalid(connection, BGP_NOTIFY_HEADER_ERR,
				      BGP_NOTIFY_HEADER_BAD_MESLEN, (unsigned char *)&nsize, 2);
		return false;
	}

	return true;
}
