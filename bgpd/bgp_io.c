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
#include "ringbuf.h"		// for ringbuf_remain, ringbuf_peek, ringbuf_...
#include "frrevent.h"		// for EVENT_OFF, EVENT_ARG, thread...

#include "bgpd/bgp_io.h"
#include "bgpd/bgp_debug.h"	// for bgp_debug_neighbor_events, bgp_type_str
#include "bgpd/bgp_errors.h"	// for expanded error reference information
#include "bgpd/bgp_fsm.h"	// for BGP_EVENT_ADD, bgp_event
#include "bgpd/bgp_packet.h"	// for bgp_notify_io_invalid...
#include "bgpd/bgp_trace.h"	// for frrtraces
#include "bgpd/bgpd.h"		// for peer, BGP_MARKER_SIZE, bgp_master, bm
/* clang-format on */

/* forward declarations */
<<<<<<< HEAD
static uint16_t bgp_write(struct peer *);
static uint16_t bgp_read(struct peer *peer, int *code_p);
static void bgp_process_writes(struct event *event);
static void bgp_process_reads(struct event *event);
static bool validate_header(struct peer *);
=======
static uint16_t bgp_write(struct peer_connection *connection);
static uint16_t bgp_read(struct peer_connection *connection, int *code_p);
static void bgp_process_writes(struct event *event);
static void bgp_process_reads(struct event *event);
static bool validate_header(struct peer_connection *connection);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

/* generic i/o status codes */
#define BGP_IO_TRANS_ERR (1 << 0) /* EAGAIN or similar occurred */
#define BGP_IO_FATAL_ERR (1 << 1) /* some kind of fatal TCP error */
#define BGP_IO_WORK_FULL_ERR (1 << 2) /* No room in work buffer */

/* Thread external API ----------------------------------------------------- */

<<<<<<< HEAD
void bgp_writes_on(struct peer *peer)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

	assert(peer->status != Deleted);
	assert(peer->obuf);
	assert(peer->ibuf);
	assert(peer->ibuf_work);
	assert(!peer->t_connect_check_r);
	assert(!peer->t_connect_check_w);
	assert(peer->fd);

	event_add_write(fpt->master, bgp_process_writes, peer, peer->fd,
			&peer->t_write);
	SET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_writes_off(struct peer *peer)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

	event_cancel_async(fpt->master, &peer->t_write, NULL);
	EVENT_OFF(peer->t_generate_updgrp_packets);

	UNSET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_reads_on(struct peer *peer)
=======
void bgp_writes_on(struct peer_connection *connection)
{
	struct frr_pthread *fpt = bgp_pth_io;

	assert(fpt->running);

	assert(connection->status != Deleted);
	assert(connection->obuf);
	assert(connection->ibuf);
	assert(connection->ibuf_work);
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
	assert(fpt->running);

	event_cancel_async(fpt->master, &connection->t_write, NULL);
	EVENT_OFF(connection->t_generate_updgrp_packets);

	UNSET_FLAG(peer->connection->thread_flags, PEER_THREAD_WRITES_ON);
}

void bgp_reads_on(struct peer_connection *connection)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

<<<<<<< HEAD
	assert(peer->status != Deleted);
	assert(peer->ibuf);
	assert(peer->fd);
	assert(peer->ibuf_work);
	assert(peer->obuf);
	assert(!peer->t_connect_check_r);
	assert(!peer->t_connect_check_w);
	assert(peer->fd);

	event_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
		       &peer->t_read);

	SET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
}

void bgp_reads_off(struct peer *peer)
=======
	assert(connection->status != Deleted);
	assert(connection->ibuf);
	assert(connection->fd);
	assert(connection->ibuf_work);
	assert(connection->obuf);
	assert(!connection->t_connect_check_r);
	assert(!connection->t_connect_check_w);
	assert(connection->fd);

	event_add_read(fpt->master, bgp_process_reads, connection,
		       connection->fd, &connection->t_read);

	SET_FLAG(connection->thread_flags, PEER_THREAD_READS_ON);
}

void bgp_reads_off(struct peer_connection *connection)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	struct frr_pthread *fpt = bgp_pth_io;
	assert(fpt->running);

<<<<<<< HEAD
	event_cancel_async(fpt->master, &peer->t_read, NULL);
	EVENT_OFF(peer->t_process_packet);
	EVENT_OFF(peer->t_process_packet_error);

	UNSET_FLAG(peer->thread_flags, PEER_THREAD_READS_ON);
=======
	event_cancel_async(fpt->master, &connection->t_read, NULL);
	EVENT_OFF(connection->t_process_packet);
	EVENT_OFF(connection->t_process_packet_error);

	UNSET_FLAG(connection->thread_flags, PEER_THREAD_READS_ON);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
}

/* Thread internal functions ----------------------------------------------- */

/*
 * Called from I/O pthread when a file descriptor has become ready for writing.
 */
static void bgp_process_writes(struct event *thread)
{
	static struct peer *peer;
<<<<<<< HEAD
	peer = EVENT_ARG(thread);
=======
	struct peer_connection *connection = EVENT_ARG(thread);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	uint16_t status;
	bool reschedule;
	bool fatal = false;

<<<<<<< HEAD
	if (peer->fd < 0)
=======
	peer = connection->peer;

	if (connection->fd < 0)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return;

	struct frr_pthread *fpt = bgp_pth_io;

<<<<<<< HEAD
	frr_with_mutex (&peer->io_mtx) {
		status = bgp_write(peer);
		reschedule = (stream_fifo_head(peer->obuf) != NULL);
=======
	frr_with_mutex (&connection->io_mtx) {
		status = bgp_write(connection);
		reschedule = (stream_fifo_head(connection->obuf) != NULL);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
	if (reschedule) {
<<<<<<< HEAD
		event_add_write(fpt->master, bgp_process_writes, peer, peer->fd,
				&peer->t_write);
	} else if (!fatal) {
		BGP_UPDATE_GROUP_TIMER_ON(&peer->t_generate_updgrp_packets,
=======
		event_add_write(fpt->master, bgp_process_writes, connection,
				connection->fd, &connection->t_write);
	} else if (!fatal) {
		BGP_UPDATE_GROUP_TIMER_ON(&connection->t_generate_updgrp_packets,
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
					  bgp_generate_updgrp_packets);
	}
}

<<<<<<< HEAD
static int read_ibuf_work(struct peer *peer)
{
	/* static buffer for transferring packets */
	/* shorter alias to peer's input buffer */
	struct ringbuf *ibw = peer->ibuf_work;
=======
static int read_ibuf_work(struct peer_connection *connection)
{
	/* static buffer for transferring packets */
	/* shorter alias to peer's input buffer */
	struct ringbuf *ibw = connection->ibuf_work;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	/* packet size as given by header */
	uint16_t pktsize = 0;
	struct stream *pkt;

	/* ============================================== */
<<<<<<< HEAD
	frr_with_mutex (&peer->io_mtx) {
		if (peer->ibuf->count >= bm->inq_limit)
=======
	frr_with_mutex (&connection->io_mtx) {
		if (connection->ibuf->count >= bm->inq_limit)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
			return -ENOMEM;
	}

	/* check that we have enough data for a header */
	if (ringbuf_remain(ibw) < BGP_HEADER_SIZE)
		return 0;

	/* check that header is valid */
<<<<<<< HEAD
	if (!validate_header(peer))
=======
	if (!validate_header(connection))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return -EBADMSG;

	/* header is valid; retrieve packet size */
	ringbuf_peek(ibw, BGP_MARKER_SIZE, &pktsize, sizeof(pktsize));

	pktsize = ntohs(pktsize);

	/* if this fails we are seriously screwed */
<<<<<<< HEAD
	assert(pktsize <= peer->max_packet_size);
=======
	assert(pktsize <= connection->peer->max_packet_size);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	/*
	 * If we have that much data, chuck it into its own
	 * stream and append to input queue for processing.
	 *
	 * Otherwise, come back later.
	 */
	if (ringbuf_remain(ibw) < pktsize)
		return 0;

	pkt = stream_new(pktsize);
	assert(STREAM_WRITEABLE(pkt) == pktsize);
	assert(ringbuf_get(ibw, pkt->data, pktsize) == pktsize);
	stream_set_endp(pkt, pktsize);

<<<<<<< HEAD
	frrtrace(2, frr_bgp, packet_read, peer, pkt);
	frr_with_mutex (&peer->io_mtx) {
		stream_fifo_push(peer->ibuf, pkt);
=======
	frrtrace(2, frr_bgp, packet_read, connection->peer, pkt);
	frr_with_mutex (&connection->io_mtx) {
		stream_fifo_push(connection->ibuf, pkt);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	return pktsize;
}

/*
 * Called from I/O pthread when a file descriptor has become ready for reading,
 * or has hung up.
 *
 * We read as much data as possible, process as many packets as we can and
<<<<<<< HEAD
 * place them on peer->ibuf for secondary processing by the main thread.
=======
 * place them on peer->connection.ibuf for secondary processing by the main
 * thread.
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
 */
static void bgp_process_reads(struct event *thread)
{
	/* clang-format off */
<<<<<<< HEAD
	static struct peer *peer;       /* peer to read from */
	uint16_t status;                /* bgp_read status code */
	bool fatal = false;             /* whether fatal error occurred */
	bool added_pkt = false;         /* whether we pushed onto ->ibuf */
=======
	struct peer_connection *connection = EVENT_ARG(thread);
	static struct peer *peer;       /* peer to read from */
	uint16_t status;                /* bgp_read status code */
	bool fatal = false;             /* whether fatal error occurred */
	bool added_pkt = false;         /* whether we pushed onto ->connection.ibuf */
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	int code = 0;                   /* FSM code if error occurred */
	static bool ibuf_full_logged;   /* Have we logged full already */
	int ret = 1;
	/* clang-format on */

<<<<<<< HEAD
	peer = EVENT_ARG(thread);

	if (bm->terminating || peer->fd < 0)
=======
	peer = connection->peer;

	if (bm->terminating || connection->fd < 0)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		return;

	struct frr_pthread *fpt = bgp_pth_io;

<<<<<<< HEAD
	frr_with_mutex (&peer->io_mtx) {
		status = bgp_read(peer, &code);
=======
	frr_with_mutex (&connection->io_mtx) {
		status = bgp_read(connection, &code);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	/* error checking phase */
	if (CHECK_FLAG(status, BGP_IO_TRANS_ERR)) {
		/* no problem; just don't process packets */
		goto done;
	}

	if (CHECK_FLAG(status, BGP_IO_FATAL_ERR)) {
		/* problem; tear down session */
		fatal = true;

		/* Handle the error in the main pthread, include the
		 * specific state change from 'bgp_read'.
		 */
<<<<<<< HEAD
		event_add_event(bm->master, bgp_packet_process_error, peer,
				code, &peer->t_process_packet_error);
=======
		event_add_event(bm->master, bgp_packet_process_error, connection,
				code, &connection->t_process_packet_error);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		goto done;
	}

	while (true) {
<<<<<<< HEAD
		ret = read_ibuf_work(peer);
=======
		ret = read_ibuf_work(connection);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		if (ret <= 0)
			break;

		added_pkt = true;
	}

	switch (ret) {
	case -EBADMSG:
		fatal = true;
		break;
	case -ENOMEM:
		if (!ibuf_full_logged) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s [Event] Peer Input-Queue is full: limit (%u)",
					peer->host, bm->inq_limit);

			ibuf_full_logged = true;
		}
		break;
	default:
		ibuf_full_logged = false;
		break;
	}

done:
	/* handle invalid header */
	if (fatal) {
		/* wipe buffer just in case someone screwed up */
<<<<<<< HEAD
		ringbuf_wipe(peer->ibuf_work);
		return;
	}

	event_add_read(fpt->master, bgp_process_reads, peer, peer->fd,
		       &peer->t_read);
	if (added_pkt)
		event_add_event(bm->master, bgp_process_packet, peer, 0,
				&peer->t_process_packet);
=======
		ringbuf_wipe(connection->ibuf_work);
		return;
	}

	event_add_read(fpt->master, bgp_process_reads, connection,
		       connection->fd, &connection->t_read);
	if (added_pkt)
		event_add_event(bm->master, bgp_process_packet, connection, 0,
				&connection->t_process_packet);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
}

/*
 * Flush peer output buffer.
 *
<<<<<<< HEAD
 * This function pops packets off of peer->obuf and writes them to peer->fd.
 * The amount of packets written is equal to the minimum of peer->wpkt_quanta
 * and the number of packets on the output buffer, unless an error occurs.
=======
 * This function pops packets off of peer->connection.obuf and writes them to
 * peer->connection.fd. The amount of packets written is equal to the minimum of
 * peer->wpkt_quanta and the number of packets on the output buffer, unless an
 * error occurs.
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
 *
 * If write() returns an error, the appropriate FSM event is generated.
 *
 * The return value is equal to the number of packets written
 * (which may be zero).
 */
<<<<<<< HEAD
static uint16_t bgp_write(struct peer *peer)
{
=======
static uint16_t bgp_write(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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

<<<<<<< HEAD
	s = stream_fifo_head(peer->obuf);
=======
	s = stream_fifo_head(connection->obuf);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

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
<<<<<<< HEAD
		num = writev(peer->fd, iov, iovsz);

		if (num < 0) {
			if (!ERRNO_IO_RETRY(errno)) {
				BGP_EVENT_ADD(peer, TCP_fatal_error);
=======
		num = writev(connection->fd, iov, iovsz);

		if (num < 0) {
			if (!ERRNO_IO_RETRY(errno)) {
				BGP_EVENT_ADD(connection, TCP_fatal_error);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
<<<<<<< HEAD
		s = stream_fifo_pop(peer->obuf);
=======
		s = stream_fifo_pop(connection->obuf);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

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
<<<<<<< HEAD
			BGP_EVENT_ADD(peer, BGP_Stop);
=======
			BGP_EVENT_ADD(connection, BGP_Stop);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
		peer->last_sendq_ok = now;
	}
}

	return status;
}

uint8_t ibuf_scratch[BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE * BGP_READ_PACKET_MAX];
/*
<<<<<<< HEAD
 * Reads a chunk of data from peer->fd into peer->ibuf_work.
=======
 * Reads a chunk of data from peer->connection.fd into
 * peer->connection.ibuf_work.
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
 *
 * code_p
 *    Pointer to location to store FSM event code in case of fatal error.
 *
 * @return status flag (see top-of-file)
 *
 * PLEASE NOTE:  If we ever transform the bgp_read to be a pthread
 * per peer then we need to rethink the global ibuf_scratch
 * data structure above.
 */
<<<<<<< HEAD
static uint16_t bgp_read(struct peer *peer, int *code_p)
=======
static uint16_t bgp_read(struct peer_connection *connection, int *code_p)
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
{
	size_t readsize; /* how many bytes we want to read */
	ssize_t nbytes;  /* how many bytes we actually read */
	size_t ibuf_work_space; /* space we can read into the work buf */
	uint16_t status = 0;

<<<<<<< HEAD
	ibuf_work_space = ringbuf_space(peer->ibuf_work);
=======
	ibuf_work_space = ringbuf_space(connection->ibuf_work);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	if (ibuf_work_space == 0) {
		SET_FLAG(status, BGP_IO_WORK_FULL_ERR);
		return status;
	}

	readsize = MIN(ibuf_work_space, sizeof(ibuf_scratch));

<<<<<<< HEAD
	nbytes = read(peer->fd, ibuf_scratch, readsize);
=======
#ifdef __clang_analyzer__
	/* clang-SA doesn't want you to call read() while holding a mutex */
	(void)readsize;
	nbytes = 0;
#else
	nbytes = read(connection->fd, ibuf_scratch, readsize);
#endif
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	/* EAGAIN or EWOULDBLOCK; come back later */
	if (nbytes < 0 && ERRNO_IO_RETRY(errno)) {
		SET_FLAG(status, BGP_IO_TRANS_ERR);
	} else if (nbytes < 0) {
		/* Fatal error; tear down session */
		flog_err(EC_BGP_UPDATE_RCV,
<<<<<<< HEAD
			 "%s [Error] bgp_read_packet error: %s", peer->host,
			 safe_strerror(errno));
=======
			 "%s [Error] bgp_read_packet error: %s",
			 connection->peer->host, safe_strerror(errno));
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

		/* Handle the error in the main pthread. */
		if (code_p)
			*code_p = TCP_fatal_error;

		SET_FLAG(status, BGP_IO_FATAL_ERR);

	} else if (nbytes == 0) {
		/* Received EOF / TCP session closed */
<<<<<<< HEAD
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s [Event] BGP connection closed fd %d",
				   peer->host, peer->fd);
=======
		if (bgp_debug_neighbor_events(connection->peer))
			zlog_debug("%s [Event] BGP connection closed fd %d",
				   connection->peer->host, connection->fd);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

		/* Handle the error in the main pthread. */
		if (code_p)
			*code_p = TCP_connection_closed;

		SET_FLAG(status, BGP_IO_FATAL_ERR);
	} else {
<<<<<<< HEAD
		assert(ringbuf_put(peer->ibuf_work, ibuf_scratch, nbytes) ==
		       (size_t)nbytes);
=======
		assert(ringbuf_put(connection->ibuf_work, ibuf_scratch,
				   nbytes) == (size_t)nbytes);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	}

	return status;
}

/*
 * Called after we have read a BGP packet header. Validates marker, message
 * type and packet length. If any of these aren't correct, sends a notify.
 *
 * Assumes that there are at least BGP_HEADER_SIZE readable bytes in the input
 * buffer.
 */
<<<<<<< HEAD
static bool validate_header(struct peer *peer)
{
	uint16_t size;
	uint8_t type;
	struct ringbuf *pkt = peer->ibuf_work;
=======
static bool validate_header(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;
	uint16_t size;
	uint8_t type;
	struct ringbuf *pkt = connection->ibuf_work;
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	static const uint8_t m_correct[BGP_MARKER_SIZE] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t m_rx[BGP_MARKER_SIZE] = {0x00};

	if (ringbuf_peek(pkt, 0, m_rx, BGP_MARKER_SIZE) != BGP_MARKER_SIZE)
		return false;

	if (memcmp(m_correct, m_rx, BGP_MARKER_SIZE) != 0) {
		bgp_notify_io_invalid(peer, BGP_NOTIFY_HEADER_ERR,
				      BGP_NOTIFY_HEADER_NOT_SYNC, NULL, 0);
		return false;
	}

	/* Get size and type in network byte order. */
	ringbuf_peek(pkt, BGP_MARKER_SIZE, &size, sizeof(size));
	ringbuf_peek(pkt, BGP_MARKER_SIZE + 2, &type, sizeof(type));

	size = ntohs(size);

	/* BGP type check. */
	if (type != BGP_MSG_OPEN && type != BGP_MSG_UPDATE
	    && type != BGP_MSG_NOTIFY && type != BGP_MSG_KEEPALIVE
	    && type != BGP_MSG_ROUTE_REFRESH_NEW
	    && type != BGP_MSG_ROUTE_REFRESH_OLD
	    && type != BGP_MSG_CAPABILITY) {
		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s unknown message type 0x%02x", peer->host,
				   type);

		bgp_notify_io_invalid(peer, BGP_NOTIFY_HEADER_ERR,
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

		bgp_notify_io_invalid(peer, BGP_NOTIFY_HEADER_ERR,
				      BGP_NOTIFY_HEADER_BAD_MESLEN,
				      (unsigned char *)&nsize, 2);
		return false;
	}

	return true;
}
