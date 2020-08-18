/*
 * BFD data plane implementation (distributed BFD).
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif /* __FreeBSD__ */

#include <errno.h>
#include <time.h>

#include "lib/hook.h"
#include "lib/printfrr.h"
#include "lib/stream.h"
#include "lib/thread.h"

#include "bfd.h"
#include "bfddp_packet.h"

#include "lib/openbsd-queue.h"

DEFINE_MTYPE_STATIC(BFDD, BFDD_DPLANE_CTX, "Data plane client allocated memory")

/** Data plane client socket buffer size. */
#define BFD_DPLANE_CLIENT_BUF_SIZE 8192

struct bfd_dplane_ctx {
	/** Client file descriptor. */
	int sock;
	/** Data plane current last used ID. */
	uint16_t last_id;

	/** Input buffer data. */
	struct stream *inbuf;
	/** Output buffer data. */
	struct stream *outbuf;
	/** Input event data. */
	struct thread *inbufev;
	/** Output event data. */
	struct thread *outbufev;

	/** Amount of bytes read. */
	uint64_t in_bytes;
	/** Amount of bytes read peak. */
	uint64_t in_bytes_peak;
	/** Amount of bytes written. */
	uint64_t out_bytes;
	/** Amount of bytes written peak. */
	uint64_t out_bytes_peak;
	/** Amount of output buffer full events (`bfd_dplane_enqueue` failed).
	 */
	uint64_t out_fullev;

	/** Amount of messages read (full messages). */
	uint64_t in_msgs;
	/** Amount of messages enqueued (maybe written). */
	uint64_t out_msgs;

	TAILQ_ENTRY(bfd_dplane_ctx) entry;
};

/**
 * Callback type for `bfd_dplane_expect`. \see bfd_dplane_expect.
 */
typedef void (*bfd_dplane_expect_cb)(struct bfddp_message *msg, void *arg);

static void bfd_dplane_ctx_free(struct bfd_dplane_ctx *bdc);

/*
 * BFD data plane helper functions.
 */
static const char *bfd_dplane_messagetype2str(enum bfddp_message_type bmt)
{
	switch (bmt) {
	case ECHO_REQUEST:
		return "ECHO_REQUEST";
	case ECHO_REPLY:
		return "ECHO_REPLY";
	case DP_ADD_SESSION:
		return "DP_ADD_SESSION";
	case DP_DELETE_SESSION:
		return "DP_DELETE_SESSION";
	case BFD_STATE_CHANGE:
		return "BFD_STATE_CHANGE";
	case DP_REQUEST_SESSION_COUNTERS:
		return "DP_REQUEST_SESSION_COUNTERS";
	case BFD_SESSION_COUNTERS:
		return "BFD_SESSION_COUNTERS";
	default:
		return "UNKNOWN";
	}
}

static void bfd_dplane_debug_message(const struct bfddp_message *msg)
{
	enum bfddp_message_type bmt;
	char buf[256], addrs[256];
	uint32_t flags;
	int rv;

	if (!bglobal.debug_dplane)
		return;

	bmt = ntohs(msg->header.type);
	zlog_debug("dplane-packet: [version=%d length=%d type=%s (%d)]",
		   msg->header.version, ntohs(msg->header.length),
		   bfd_dplane_messagetype2str(bmt), bmt);

	switch (bmt) {
	case ECHO_REPLY:
	case ECHO_REQUEST:
		zlog_debug("  [dp_time=%" PRIu64 " bfdd_time=%" PRIu64 "]",
			   (uint64_t)be64toh(msg->data.echo.dp_time),
			   (uint64_t)be64toh(msg->data.echo.bfdd_time));
		break;

	case DP_ADD_SESSION:
	case DP_DELETE_SESSION:
		flags = ntohl(msg->data.session.flags);
		if (flags & SESSION_IPV6)
			snprintfrr(addrs, sizeof(addrs), "src=%pI6 dst=%pI6",
				   &msg->data.session.src,
				   &msg->data.session.dst);
		else
			snprintfrr(addrs, sizeof(addrs), "src=%pI4 dst=%pI4",
				   &msg->data.session.src,
				   &msg->data.session.dst);

		buf[0] = 0;
		if (flags & SESSION_CBIT)
			strlcat(buf, "cpi ", sizeof(buf));
		if (flags & SESSION_ECHO)
			strlcat(buf, "echo ", sizeof(buf));
		if (flags & SESSION_IPV6)
			strlcat(buf, "ipv6 ", sizeof(buf));
		if (flags & SESSION_DEMAND)
			strlcat(buf, "demand ", sizeof(buf));
		if (flags & SESSION_PASSIVE)
			strlcat(buf, "passive ", sizeof(buf));
		if (flags & SESSION_MULTIHOP)
			strlcat(buf, "multihop ", sizeof(buf));
		if (flags & SESSION_SHUTDOWN)
			strlcat(buf, "shutdown ", sizeof(buf));

		/* Remove the last space to make things prettier. */
		rv = (int)strlen(buf);
		if (rv > 0)
			buf[rv - 1] = 0;

		zlog_debug(
			"  [flags=0x%08x{%s} %s ttl=%d detect_mult=%d "
			"ifindex=%d ifname=%s]",
			flags, buf, addrs, msg->data.session.ttl,
			msg->data.session.detect_mult,
			ntohl(msg->data.session.ifindex),
			msg->data.session.ifname);
		break;

	case BFD_STATE_CHANGE:
		buf[0] = 0;
		flags = ntohl(msg->data.state.remote_flags);
		if (flags & RBIT_CPI)
			strlcat(buf, "cbit ", sizeof(buf));
		if (flags & RBIT_DEMAND)
			strlcat(buf, "demand ", sizeof(buf));
		if (flags & RBIT_MP)
			strlcat(buf, "mp ", sizeof(buf));

		/* Remove the last space to make things prettier. */
		rv = (int)strlen(buf);
		if (rv > 0)
			buf[rv - 1] = 0;

		zlog_debug(
			"  [lid=%u rid=%u flags=0x%02x{%s} state=%s "
			"diagnostics=%s mult=%d tx=%u rx=%u erx=%u]",
			ntohl(msg->data.state.lid), ntohl(msg->data.state.rid),
			flags, buf, state_list[msg->data.state.state].str,
			diag2str(msg->data.state.diagnostics),
			msg->data.state.detection_multiplier,
			ntohl(msg->data.state.desired_tx),
			ntohl(msg->data.state.required_rx),
			ntohl(msg->data.state.required_echo_rx));
		break;

	case DP_REQUEST_SESSION_COUNTERS:
		zlog_debug("  [lid=%u]", ntohl(msg->data.counters_req.lid));
		break;

	case BFD_SESSION_COUNTERS:
		zlog_debug(
			"  [lid=%u "
			"control{in %" PRIu64 " bytes (%" PRIu64
			" packets), "
			"out %" PRIu64 " bytes (%" PRIu64
			" packets)} "
			"echo{in %" PRIu64 " bytes (%" PRIu64
			" packets), "
			"out %" PRIu64 " bytes (%" PRIu64 " packets)}]",
			ntohl(msg->data.session_counters.lid),
			(uint64_t)be64toh(
				msg->data.session_counters.control_input_bytes),
			(uint64_t)be64toh(msg->data.session_counters
					   .control_input_packets),
			(uint64_t)be64toh(msg->data.session_counters
					   .control_output_bytes),
			(uint64_t)be64toh(msg->data.session_counters
					   .control_output_packets),
			(uint64_t)be64toh(msg->data.session_counters.echo_input_bytes),
			(uint64_t)be64toh(
				msg->data.session_counters.echo_input_packets),
			(uint64_t)be64toh(
				msg->data.session_counters.echo_output_bytes),
			(uint64_t)be64toh(msg->data.session_counters
					   .echo_output_packets));
		break;
	}
}

static ssize_t bfd_dplane_flush(struct bfd_dplane_ctx *bdc)
{
	ssize_t total = 0;
	int rv;

	while (STREAM_READABLE(bdc->outbuf)) {
		/* Flush buffer contents to socket. */
		rv = stream_flush(bdc->outbuf, bdc->sock);
		if (rv == -1) {
			/* Interruption: try again. */
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				continue;

			zlog_warn("%s: socket failed: %s", __func__,
				  strerror(errno));
			bfd_dplane_ctx_free(bdc);
			return 0;
		}
		if (rv == 0) {
			if (bglobal.debug_dplane)
				zlog_info("%s: connection closed", __func__);

			bfd_dplane_ctx_free(bdc);
			return 0;
		}

		/* Account total written. */
		total += rv;

		/* Account output bytes. */
		bdc->out_bytes += (uint64_t)rv;

		/* Forward pointer. */
		stream_forward_getp(bdc->outbuf, (size_t)rv);
	}

	/* Make more space for new data. */
	stream_pulldown(bdc->outbuf);

	/* Disable write ready events. */
	THREAD_OFF(bdc->outbufev);

	return total;
}

static int bfd_dplane_write(struct thread *t)
{
	bfd_dplane_flush(THREAD_ARG(t));
	return 0;
}

static void
bfd_dplane_session_state_change(struct bfd_dplane_ctx *bdc,
				const struct bfddp_state_change *state)
{
	struct bfd_session *bs;
	uint32_t flags;
	int old_state;

	/* Look up session. */
	bs = bfd_id_lookup(ntohl(state->lid));
	if (bs == NULL) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: failed to find session to update",
				   __func__);
		return;
	}

	flags = ntohl(state->remote_flags);
	old_state = bs->ses_state;

	/* Update session state. */
	bs->ses_state = state->state;
	bs->remote_diag = state->diagnostics;
	bs->discrs.remote_discr = ntohl(state->rid);
	bs->remote_cbit = !!(flags & RBIT_CPI);
	bs->remote_detect_mult = state->detection_multiplier;
	bs->remote_timers.desired_min_tx = ntohl(state->desired_tx);
	bs->remote_timers.required_min_rx = ntohl(state->required_rx);
	bs->remote_timers.required_min_echo = ntohl(state->required_echo_rx);

	/* Notify and update counters. */
	control_notify(bs, bs->ses_state);

	/* No state change. */
	if (old_state == bs->ses_state)
		return;

	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
	case PTM_BFD_DOWN:
		/* Both states mean down. */
		if (old_state == PTM_BFD_ADM_DOWN || old_state == PTM_BFD_DOWN)
			break;

		monotime(&bs->downtime);
		bs->stats.session_down++;
		break;
	case PTM_BFD_UP:
		monotime(&bs->uptime);
		bs->stats.session_up++;
		break;
	case PTM_BFD_INIT:
		/* NOTHING */
		break;

	default:
		zlog_warn("%s: unhandled new state %d", __func__,
			  bs->ses_state);
		break;
	}

	if (bglobal.debug_peer_event)
		zlog_debug("state-change: [data plane: %s] %s -> %s",
			   bs_to_string(bs), state_list[old_state].str,
			   state_list[bs->ses_state].str);
}

/**
 * Enqueue message in output buffer.
 *
 * \param[in,out] bdc data plane client context.
 * \param[in] buf the message to buffer.
 * \param[in] buflen the amount of bytes to buffer.
 *
 * \returns `-1` on failure (buffer full) or `0` on success.
 */
static int bfd_dplane_enqueue(struct bfd_dplane_ctx *bdc, const void *buf,
			      size_t buflen)
{
	size_t rlen;

	/* Not enough space. */
	if (buflen > STREAM_WRITEABLE(bdc->outbuf)) {
		bdc->out_fullev++;
		return -1;
	}

	/* Show debug message if active. */
	bfd_dplane_debug_message((struct bfddp_message *)buf);

	/* Buffer the message. */
	stream_write(bdc->outbuf, buf, buflen);

	/* Account message as sent. */
	bdc->out_msgs++;
	/* Register peak buffered bytes. */
	rlen = STREAM_READABLE(bdc->outbuf);
	if (bdc->out_bytes_peak < rlen)
		bdc->out_bytes_peak = rlen;

	/* Schedule if it is not yet. */
	if (bdc->outbufev == NULL)
		thread_add_write(master, bfd_dplane_write, bdc, bdc->sock,
				 &bdc->outbufev);

	return 0;
}

static void bfd_dplane_echo_request_handle(struct bfd_dplane_ctx *bdc,
					   const struct bfddp_message *bm)
{
	struct bfddp_message msg = {};
	uint16_t msglen = sizeof(msg.header) + sizeof(msg.data.echo);
	struct timeval tv;

	gettimeofday(&tv, NULL);

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.type = htons(ECHO_REPLY);
	msg.header.length = htons(msglen);

	/* Prepare payload. */
	msg.data.echo.dp_time = bm->data.echo.dp_time;
	msg.data.echo.bfdd_time =
		htobe64((uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec));

	/* Enqueue for output. */
	bfd_dplane_enqueue(bdc, &msg, msglen);
}

static void bfd_dplane_handle_message(struct bfddp_message *msg, void *arg)
{
	enum bfddp_message_type bmt;
	struct bfd_dplane_ctx *bdc = arg;

	/* Call the appropriated handler. */
	bmt = ntohs(msg->header.type);
	switch (bmt) {
	case ECHO_REQUEST:
		bfd_dplane_echo_request_handle(bdc, msg);
		break;
	case BFD_STATE_CHANGE:
		bfd_dplane_session_state_change(bdc, &msg->data.state);
		break;
	case ECHO_REPLY:
		/* NOTHING: we don't do anything with this information. */
		break;
	case DP_ADD_SESSION:
	case DP_DELETE_SESSION:
	case DP_REQUEST_SESSION_COUNTERS:
		/* NOTHING: we are not supposed to receive this. */
		break;
	case BFD_SESSION_COUNTERS:
		/*
		 * NOTHING: caller of DP_REQUEST_SESSION_COUNTERS should
		 * handle this with `bfd_dplane_expect`.
		 */
		break;

	default:
		zlog_debug("%s: unhandled message type %d", __func__, bmt);
		break;
	}
}

/**
 * Reads the socket immediately to receive data plane answer to query.
 *
 * \param bdc the data plane context.
 * \param id the message ID waiting response.
 * \param cb the callback to call when ready.
 * \param arg the callback argument.
 *
 * \return
 * `-2` on unavailability (try again), `-1` on failure or `0` on success.
 */
static int bfd_dplane_expect(struct bfd_dplane_ctx *bdc, uint16_t id,
			     bfd_dplane_expect_cb cb, void *arg)
{
	struct bfddp_message_header *bh;
	size_t rlen = 0, reads = 0;
	ssize_t rv;

	/*
	 * Don't attempt to read if buffer is full, otherwise we'll get a
	 * bogus 'connection closed' signal (rv == 0).
	 */
	if (bdc->inbuf->endp == bdc->inbuf->size)
		goto skip_read;

read_again:
	/* Attempt to read message from client. */
	rv = stream_read_try(bdc->inbuf, bdc->sock,
			     STREAM_WRITEABLE(bdc->inbuf));
	if (rv == 0) {
		if (bglobal.debug_dplane)
			zlog_info("%s: socket closed", __func__);

		bfd_dplane_ctx_free(bdc);
		return -1;
	}
	if (rv == -1) {
		zlog_warn("%s: socket failed: %s", __func__, strerror(errno));
		bfd_dplane_ctx_free(bdc);
		return -1;
	}

	/* We got interrupted, reschedule read. */
	if (rv == -2)
		return -2;

	/* Account read bytes. */
	bdc->in_bytes += (uint64_t)rv;
	/* Register peak buffered bytes. */
	rlen = STREAM_READABLE(bdc->inbuf);
	if (bdc->in_bytes_peak < rlen)
		bdc->in_bytes_peak = rlen;

skip_read:
	while (rlen > 0) {
		bh = (struct bfddp_message_header *)stream_pnt(bdc->inbuf);
		/* Not enough data read. */
		if (ntohs(bh->length) > rlen)
			goto read_again;

		/* Account full message read. */
		bdc->in_msgs++;

		/* Account this message as whole read for buffer reorganize. */
		reads++;

		/* Check for bad version. */
		if (bh->version != BFD_DP_VERSION) {
			zlog_err("%s: bad data plane client version: %d",
				 __func__, bh->version);
			return -1;
		}

		/* Show debug message if active. */
		bfd_dplane_debug_message((struct bfddp_message *)bh);

		/*
		 * Handle incoming message with callback if the ID matches,
		 * otherwise fallback to default handler.
		 */
		if (id && ntohs(bh->id) == id)
			cb((struct bfddp_message *)bh, arg);
		else
			bfd_dplane_handle_message((struct bfddp_message *)bh,
						  bdc);

		/* Advance current read pointer. */
		stream_forward_getp(bdc->inbuf, ntohs(bh->length));

		/* Reduce the buffer available bytes. */
		rlen -= ntohs(bh->length);

		/* Reorganize buffer to handle more bytes read. */
		if (reads >= 3) {
			stream_pulldown(bdc->inbuf);
			reads = 0;
		}

		/* We found the message, return to caller. */
		if (id && ntohs(bh->id) == id)
			break;
	}

	return 0;
}

static int bfd_dplane_read(struct thread *t)
{
	struct bfd_dplane_ctx *bdc = THREAD_ARG(t);
	int rv;

	rv = bfd_dplane_expect(bdc, 0, bfd_dplane_handle_message, NULL);
	if (rv == -1)
		return 0;

	stream_pulldown(bdc->inbuf);
	thread_add_read(master, bfd_dplane_read, bdc, bdc->sock, &bdc->inbufev);
	return 0;
}

static struct bfd_dplane_ctx *bfd_dplane_ctx_new(int sock)
{
	struct bfd_dplane_ctx *bdc;

	bdc = XCALLOC(MTYPE_BFDD_DPLANE_CTX, sizeof(*bdc));
	if (bdc == NULL)
		return NULL;

	bdc->sock = sock;
	bdc->inbuf = stream_new(BFD_DPLANE_CLIENT_BUF_SIZE);
	bdc->outbuf = stream_new(BFD_DPLANE_CLIENT_BUF_SIZE);
	thread_add_read(master, bfd_dplane_read, bdc, sock, &bdc->inbufev);

	return bdc;
}

static void _bfd_session_unregister_dplane(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;
	struct bfd_dplane_ctx *bdc = arg;

	if (bs->bdc != bdc)
		return;

	bs->bdc = NULL;
}

static void bfd_dplane_ctx_free(struct bfd_dplane_ctx *bdc)
{
	if (bglobal.debug_dplane)
		zlog_debug("%s: terminating data plane client %d", __func__,
			   bdc->sock);

	/* Remove from the list of attached data planes. */
	TAILQ_REMOVE(&bglobal.bg_dplaneq, bdc, entry);

	/* Detach all associated sessions. */
	if (bglobal.bg_shutdown == false)
		bfd_key_iterate(_bfd_session_unregister_dplane, bdc);

	/* Free resources. */
	socket_close(&bdc->sock);
	stream_free(bdc->inbuf);
	stream_free(bdc->outbuf);
	THREAD_OFF(bdc->inbufev);
	THREAD_OFF(bdc->outbufev);
	XFREE(MTYPE_BFDD_DPLANE_CTX, bdc);
}

/*
 * Data plane listening socket.
 */
static int bfd_dplane_accept(struct thread *t)
{
	struct bfd_global *bg = THREAD_ARG(t);
	struct bfd_dplane_ctx *bdc;
	int sock;

	/* Accept new connection. */
	sock = accept(bg->bg_dplane_sock, NULL, 0);
	if (sock == -1) {
		zlog_warn("%s: accept failed: %s", __func__, strerror(errno));
		goto reschedule_and_return;
	}

	/* Create and handle new connection. */
	bdc = bfd_dplane_ctx_new(sock);
	TAILQ_INSERT_TAIL(&bglobal.bg_dplaneq, bdc, entry);

	if (bglobal.debug_dplane)
		zlog_debug("%s: new data plane client connected", __func__);

reschedule_and_return:
	thread_add_read(master, bfd_dplane_accept, bg, bg->bg_dplane_sock,
			&bglobal.bg_dplane_sockev);
	return 0;
}

/**
 * Termination phase of the distributed BFD infrastructure: free all allocated
 * resources.
 */
static int bfd_dplane_finish_late(void)
{
	struct bfd_dplane_ctx *bdc;

	if (bglobal.debug_dplane)
		zlog_debug("%s: terminating distributed BFD", __func__);

	/* Free all data plane client contexts. */
	while ((bdc = TAILQ_FIRST(&bglobal.bg_dplaneq)) != NULL)
		bfd_dplane_ctx_free(bdc);

	/* Cancel accept thread and close socket. */
	THREAD_OFF(bglobal.bg_dplane_sockev);
	close(bglobal.bg_dplane_sock);

	return 0;
}

/*
 * Data plane exported functions.
 */
void bfd_dplane_init(const struct sockaddr *sa, socklen_t salen)
{
	int sock;

	zlog_info("initializing distributed BFD");

	/*
	 * Data plane socket creation:
	 * - Set REUSEADDR option for taking over previously open socket.
	 * - Bind to address requested (maybe IPv4, IPv6, UNIX etc...).
	 * - Listen on that address for new connections.
	 * - Ask to be waken up when a new connection comes.
	 */
	sock = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_warn("%s: failed to initialize socket: %s", __func__,
			  strerror(errno));
		return;
	}

	if (sockopt_reuseaddr(sock) == -1) {
		zlog_warn("%s: failed to set reuseaddr: %s", __func__,
			  strerror(errno));
		close(sock);
		return;
	}

	/* Handle UNIX socket: delete previous socket if any. */
	if (sa->sa_family == AF_UNIX)
		unlink(((struct sockaddr_un *)sa)->sun_path);

	if (bind(sock, sa, salen) == -1) {
		zlog_warn("%s: failed to bind socket: %s", __func__,
			  strerror(errno));
		close(sock);
		return;
	}

	if (listen(sock, SOMAXCONN) == -1) {
		zlog_warn("%s: failed to put socket on listen: %s", __func__,
			  strerror(errno));
		close(sock);
		return;
	}

	bglobal.bg_dplane_sock = sock;
	thread_add_read(master, bfd_dplane_accept, &bglobal, sock,
			&bglobal.bg_dplane_sockev);

	/* Initialize queue header. */
	TAILQ_INIT(&bglobal.bg_dplaneq);

	/* Observe shutdown events. */
	hook_register(frr_fini, bfd_dplane_finish_late);
}
