// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD data plane implementation (distributed BFD).
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include "lib/network.h"
#include "lib/printfrr.h"
#include "lib/stream.h"
#include "lib/frrevent.h"

#include "bfd.h"
#include "bfddp_packet.h"

#include "lib/openbsd-queue.h"

DEFINE_MTYPE_STATIC(BFDD, BFDD_DPLANE_CTX,
		    "Data plane client allocated memory");

/** Data plane client socket buffer size. */
#define BFD_DPLANE_CLIENT_BUF_SIZE 8192

struct bfd_dplane_ctx {
	/** Client file descriptor. */
	int sock;
	/** Is this a connected or accepted? */
	bool client;
	/** Is the socket still connecting? */
	bool connecting;
	/** Client/server address. */
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
	} addr;
	/** Address length. */
	socklen_t addrlen;
	/** Data plane current last used ID. */
	uint16_t last_id;

	/** Input buffer data. */
	struct stream *inbuf;
	/** Output buffer data. */
	struct stream *outbuf;
	/** Input event data. */
	struct event *inbufev;
	/** Output event data. */
	struct event *outbufev;
	/** Connection event. */
	struct event *connectev;

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

static void bfd_dplane_client_connect(struct event *t);
static bool bfd_dplane_client_connecting(struct bfd_dplane_ctx *bdc);
static void bfd_dplane_ctx_free(struct bfd_dplane_ctx *bdc);
static int _bfd_dplane_add_session(struct bfd_dplane_ctx *bdc,
				   struct bfd_session *bs);

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
			   be64toh(msg->data.echo.dp_time),
			   be64toh(msg->data.echo.bfdd_time));
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
				   (struct in_addr *)&msg->data.session.src,
				   (struct in_addr *)&msg->data.session.dst);

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
			be64toh(msg->data.session_counters.control_input_bytes),
			be64toh(msg->data.session_counters
				.control_input_packets),
			be64toh(msg->data.session_counters
				.control_output_bytes),
			be64toh(msg->data.session_counters
				.control_output_packets),
			be64toh(msg->data.session_counters.echo_input_bytes),
			be64toh(msg->data.session_counters.echo_input_packets),
			be64toh(msg->data.session_counters.echo_output_bytes),
			be64toh(msg->data.session_counters
				.echo_output_packets));
		break;
	}
}

/**
 * Gets the next unused non zero identification.
 *
 * \param bdc the data plane context.
 *
 * \returns next usable id.
 */
static uint16_t bfd_dplane_next_id(struct bfd_dplane_ctx *bdc)
{
	bdc->last_id++;

	/* Don't use reserved id `0`. */
	if (bdc->last_id == 0)
		bdc->last_id = 1;

	return bdc->last_id;
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
	EVENT_OFF(bdc->outbufev);

	return total;
}

static void bfd_dplane_write(struct event *t)
{
	struct bfd_dplane_ctx *bdc = EVENT_ARG(t);

	/* Handle connection stage. */
	if (bdc->connecting && bfd_dplane_client_connecting(bdc))
		return;

	bfd_dplane_flush(bdc);
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
	ptm_bfd_notify(bs, bs->ses_state);

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

	/* Handle not connected yet client. */
	if (bdc->client && bdc->sock == -1)
		return -1;

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
		event_add_write(master, bfd_dplane_write, bdc, bdc->sock,
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

static void bfd_dplane_read(struct event *t)
{
	struct bfd_dplane_ctx *bdc = EVENT_ARG(t);
	int rv;

	rv = bfd_dplane_expect(bdc, 0, bfd_dplane_handle_message, NULL);
	if (rv == -1)
		return;

	stream_pulldown(bdc->inbuf);
	event_add_read(master, bfd_dplane_read, bdc, bdc->sock, &bdc->inbufev);
}

static void _bfd_session_register_dplane(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;
	struct bfd_dplane_ctx *bdc = arg;

	if (bs->bdc != NULL)
		return;

	/* Disable software session. */
	bfd_session_disable(bs);

	/* Move session to data plane. */
	_bfd_dplane_add_session(bdc, bs);
}

static struct bfd_dplane_ctx *bfd_dplane_ctx_new(int sock)
{
	struct bfd_dplane_ctx *bdc;

	bdc = XCALLOC(MTYPE_BFDD_DPLANE_CTX, sizeof(*bdc));

	bdc->sock = sock;
	bdc->inbuf = stream_new(BFD_DPLANE_CLIENT_BUF_SIZE);
	bdc->outbuf = stream_new(BFD_DPLANE_CLIENT_BUF_SIZE);

	/* If not socket ready, skip read and session registration. */
	if (sock == -1)
		return bdc;

	event_add_read(master, bfd_dplane_read, bdc, sock, &bdc->inbufev);

	/* Register all unattached sessions. */
	bfd_key_iterate(_bfd_session_register_dplane, bdc);

	return bdc;
}

static void _bfd_session_unregister_dplane(struct hash_bucket *hb, void *arg)
{
	struct bfd_session *bs = hb->data;
	struct bfd_dplane_ctx *bdc = arg;

	if (bs->bdc != bdc)
		return;

	bs->bdc = NULL;

	/* Fallback to software. */
	bfd_session_enable(bs);
}

static void bfd_dplane_ctx_free(struct bfd_dplane_ctx *bdc)
{
	if (bglobal.debug_dplane)
		zlog_debug("%s: terminating data plane client %d", __func__,
			   bdc->sock);

	/* Client mode has special treatment. */
	if (bdc->client) {
		/* Disable connection event if any. */
		EVENT_OFF(bdc->connectev);

		/* Normal treatment on shutdown. */
		if (bglobal.bg_shutdown)
			goto free_resources;

		/* Attempt reconnection. */
		socket_close(&bdc->sock);
		EVENT_OFF(bdc->inbufev);
		EVENT_OFF(bdc->outbufev);
		event_add_timer(master, bfd_dplane_client_connect, bdc, 3,
				&bdc->connectev);
		return;
	}

free_resources:
	/* Remove from the list of attached data planes. */
	TAILQ_REMOVE(&bglobal.bg_dplaneq, bdc, entry);

	/* Detach all associated sessions. */
	if (bglobal.bg_shutdown == false)
		bfd_key_iterate(_bfd_session_unregister_dplane, bdc);

	/* Free resources. */
	socket_close(&bdc->sock);
	stream_free(bdc->inbuf);
	stream_free(bdc->outbuf);
	EVENT_OFF(bdc->inbufev);
	EVENT_OFF(bdc->outbufev);
	XFREE(MTYPE_BFDD_DPLANE_CTX, bdc);
}

static void _bfd_dplane_session_fill(const struct bfd_session *bs,
				     struct bfddp_message *msg)
{
	uint16_t msglen = sizeof(msg->header) + sizeof(msg->data.session);

	/* Message header. */
	msg->header.version = BFD_DP_VERSION;
	msg->header.length = ntohs(msglen);
	msg->header.type = ntohs(DP_ADD_SESSION);

	/* Message payload. */
	msg->data.session.dst = bs->key.peer;
	msg->data.session.src = bs->key.local;
	msg->data.session.detect_mult = bs->detect_mult;

	if (bs->ifp) {
		msg->data.session.ifindex = htonl(bs->ifp->ifindex);
		strlcpy(msg->data.session.ifname, bs->ifp->name,
			sizeof(msg->data.session.ifname));
	}
	if (bs->flags & BFD_SESS_FLAG_MH) {
		msg->data.session.flags |= SESSION_MULTIHOP;
		msg->data.session.ttl = bs->mh_ttl;
	} else
		msg->data.session.ttl = BFD_TTL_VAL;

	if (bs->flags & BFD_SESS_FLAG_IPV6)
		msg->data.session.flags |= SESSION_IPV6;
	if (bs->flags & BFD_SESS_FLAG_ECHO)
		msg->data.session.flags |= SESSION_ECHO;
	if (bs->flags & BFD_SESS_FLAG_CBIT)
		msg->data.session.flags |= SESSION_CBIT;
	if (bs->flags & BFD_SESS_FLAG_PASSIVE)
		msg->data.session.flags |= SESSION_PASSIVE;
	if (bs->flags & BFD_SESS_FLAG_SHUTDOWN)
		msg->data.session.flags |= SESSION_SHUTDOWN;

	msg->data.session.flags = htonl(msg->data.session.flags);
	msg->data.session.lid = htonl(bs->discrs.my_discr);
	msg->data.session.min_tx = htonl(bs->timers.desired_min_tx);
	msg->data.session.min_rx = htonl(bs->timers.required_min_rx);
	msg->data.session.min_echo_tx = htonl(bs->timers.desired_min_echo_tx);
	msg->data.session.min_echo_rx = htonl(bs->timers.required_min_echo_rx);
}

static int _bfd_dplane_add_session(struct bfd_dplane_ctx *bdc,
				   struct bfd_session *bs)
{
	int rv;

	/* Associate session. */
	bs->bdc = bdc;

	/* Reset previous state. */
	bs->remote_diag = 0;
	bs->local_diag = 0;
	bs->ses_state = PTM_BFD_DOWN;

	/* Enqueue message to data plane client. */
	rv = bfd_dplane_update_session(bs);
	if (rv != 0)
		bs->bdc = NULL;

	return rv;
}

static void _bfd_dplane_update_session_counters(struct bfddp_message *msg,
						void *arg)
{
	struct bfd_session *bs = arg;

	bs->stats.rx_ctrl_pkt =
		be64toh(msg->data.session_counters.control_input_packets);
	bs->stats.tx_ctrl_pkt =
		be64toh(msg->data.session_counters.control_output_packets);
	bs->stats.rx_echo_pkt =
		be64toh(msg->data.session_counters.echo_input_packets);
	bs->stats.tx_echo_pkt =
		be64toh(msg->data.session_counters.echo_output_bytes);
}

/**
 * Send message to data plane requesting the session counters.
 *
 * \param bs the BFD session.
 *
 * \returns `0` on failure or the request id.
 */
static uint16_t bfd_dplane_request_counters(const struct bfd_session *bs)
{
	struct bfddp_message msg = {};
	size_t msglen = sizeof(msg.header) + sizeof(msg.data.counters_req);

	/* Fill header information. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(msglen);
	msg.header.type = htons(DP_REQUEST_SESSION_COUNTERS);
	msg.header.id = htons(bfd_dplane_next_id(bs->bdc));

	/* Session to get counters. */
	msg.data.counters_req.lid = htonl(bs->discrs.my_discr);

	/* If enqueue failed, let caller know. */
	if (bfd_dplane_enqueue(bs->bdc, &msg, msglen) == -1)
		return 0;

	/* Flush socket. */
	bfd_dplane_flush(bs->bdc);

	return ntohs(msg.header.id);
}

/*
 * Data plane listening socket.
 */
static void bfd_dplane_accept(struct event *t)
{
	struct bfd_global *bg = EVENT_ARG(t);
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
	event_add_read(master, bfd_dplane_accept, bg, bg->bg_dplane_sock,
		       &bglobal.bg_dplane_sockev);
}

/*
 * Data plane connecting socket.
 */
static void _bfd_dplane_client_bootstrap(struct bfd_dplane_ctx *bdc)
{
	bdc->connecting = false;

	/* Clean up buffers. */
	stream_reset(bdc->inbuf);
	stream_reset(bdc->outbuf);

	/* Ask for read notifications. */
	event_add_read(master, bfd_dplane_read, bdc, bdc->sock, &bdc->inbufev);

	/* Remove all sessions then register again to send them all. */
	bfd_key_iterate(_bfd_session_unregister_dplane, bdc);
	bfd_key_iterate(_bfd_session_register_dplane, bdc);
}

static bool bfd_dplane_client_connecting(struct bfd_dplane_ctx *bdc)
{
	int rv;
	socklen_t rvlen = sizeof(rv);

	/* Make sure `errno` is reset, then test `getsockopt` success. */
	errno = 0;
	if (getsockopt(bdc->sock, SOL_SOCKET, SO_ERROR, &rv, &rvlen) == -1)
		rv = -1;

	/* Connection successful. */
	if (rv == 0) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: connected to server: %d", __func__,
				   bdc->sock);

		_bfd_dplane_client_bootstrap(bdc);
		return false;
	}

	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* non error, wait more. */
		return true;

	default:
		zlog_warn("%s: connection failed: %s", __func__,
			  strerror(errno));
		bfd_dplane_ctx_free(bdc);
		return true;
	}
}

static void bfd_dplane_client_connect(struct event *t)
{
	struct bfd_dplane_ctx *bdc = EVENT_ARG(t);
	int rv, sock;
	socklen_t rvlen = sizeof(rv);

	/* Allocate new socket. */
	sock = socket(bdc->addr.sa.sa_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_warn("%s: failed to initialize socket: %s", __func__,
			  strerror(errno));
		goto reschedule_connect;
	}

	/* Set non blocking socket. */
	set_nonblocking(sock);

	/* Set 'no delay' (disables nagle algorithm) for IPv4/IPv6. */
	rv = 1;
	if (bdc->addr.sa.sa_family != AF_UNIX
	    && setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &rv, rvlen) == -1)
		zlog_warn("%s: TCP_NODELAY: %s", __func__, strerror(errno));

	/* Attempt to connect. */
	rv = connect(sock, &bdc->addr.sa, bdc->addrlen);
	if (rv == -1 && (errno != EINPROGRESS && errno != EAGAIN)) {
		zlog_warn("%s: data plane connection failed: %s", __func__,
			  strerror(errno));
		goto reschedule_connect;
	}

	bdc->sock = sock;
	if (rv == -1) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: server connection in progress: %d",
				   __func__, sock);

		/* If we are not connected yet, ask for write notifications. */
		bdc->connecting = true;
		event_add_write(master, bfd_dplane_write, bdc, bdc->sock,
				&bdc->outbufev);
	} else {
		if (bglobal.debug_dplane)
			zlog_debug("%s: server connection: %d", __func__, sock);

		/* Otherwise just start accepting data. */
		_bfd_dplane_client_bootstrap(bdc);
	}

reschedule_connect:
	EVENT_OFF(bdc->inbufev);
	EVENT_OFF(bdc->outbufev);
	socket_close(&sock);
	event_add_timer(master, bfd_dplane_client_connect, bdc, 3,
			&bdc->connectev);
}

static void bfd_dplane_client_init(const struct sockaddr *sa, socklen_t salen)
{
	struct bfd_dplane_ctx *bdc;

	/* Allocate context and copy address for reconnection. */
	bdc = bfd_dplane_ctx_new(-1);
	if (salen <= sizeof(bdc->addr)) {
		memcpy(&bdc->addr, sa, salen);
		bdc->addrlen = sizeof(bdc->addr);
	} else {
		memcpy(&bdc->addr, sa, sizeof(bdc->addr));
		bdc->addrlen = sizeof(bdc->addr);
		zlog_warn("%s: server address truncated (from %d to %d)",
			  __func__, salen, bdc->addrlen);
	}

	bdc->client = true;

	event_add_timer(master, bfd_dplane_client_connect, bdc, 0,
			&bdc->connectev);

	/* Insert into data plane lists. */
	TAILQ_INSERT_TAIL(&bglobal.bg_dplaneq, bdc, entry);
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
	EVENT_OFF(bglobal.bg_dplane_sockev);
	close(bglobal.bg_dplane_sock);

	return 0;
}

/*
 * Data plane exported functions.
 */
void bfd_dplane_init(const struct sockaddr *sa, socklen_t salen, bool client)
{
	int sock;

	zlog_info("initializing distributed BFD");

	/* Initialize queue header. */
	TAILQ_INIT(&bglobal.bg_dplaneq);

	/* Initialize listening socket. */
	bglobal.bg_dplane_sock = -1;

	/* Observe shutdown events. */
	hook_register(frr_fini, bfd_dplane_finish_late);

	/* Handle client mode. */
	if (client) {
		bfd_dplane_client_init(sa, salen);
		return;
	}

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
	event_add_read(master, bfd_dplane_accept, &bglobal, sock,
		       &bglobal.bg_dplane_sockev);
}

int bfd_dplane_add_session(struct bfd_session *bs)
{
	struct bfd_dplane_ctx *bdc;

	/* Select a data plane client to install session. */
	TAILQ_FOREACH (bdc, &bglobal.bg_dplaneq, entry) {
		if (_bfd_dplane_add_session(bdc, bs) == 0)
			return 0;
	}

	return -1;
}

int bfd_dplane_update_session(const struct bfd_session *bs)
{
	struct bfddp_message msg = {};

	if (bs->bdc == NULL)
		return 0;

	_bfd_dplane_session_fill(bs, &msg);

	/* Enqueue message to data plane client. */
	return bfd_dplane_enqueue(bs->bdc, &msg, ntohs(msg.header.length));
}

int bfd_dplane_delete_session(struct bfd_session *bs)
{
	struct bfddp_message msg = {};
	int rv;

	/* Not using data plane, just return success. */
	if (bs->bdc == NULL)
		return 0;

	/* Fill most of the common fields. */
	_bfd_dplane_session_fill(bs, &msg);

	/* Change the message type. */
	msg.header.type = ntohs(DP_DELETE_SESSION);

	/* Enqueue message to data plane client. */
	rv = bfd_dplane_enqueue(bs->bdc, &msg, ntohs(msg.header.length));

	/* Remove association. */
	bs->bdc = NULL;

	return rv;
}

/*
 * Data plane CLI.
 */
void bfd_dplane_show_counters(struct vty *vty)
{
	struct bfd_dplane_ctx *bdc;

#define SHOW_COUNTER(label, counter, formatter)                                \
	vty_out(vty, "%28s: %" formatter "\n", (label), (counter))

	vty_out(vty, "%28s\n%28s\n", "Data plane", "==========");
	TAILQ_FOREACH (bdc, &bglobal.bg_dplaneq, entry) {
		SHOW_COUNTER("File descriptor", bdc->sock, "d");
		SHOW_COUNTER("Input bytes", bdc->in_bytes, PRIu64);
		SHOW_COUNTER("Input bytes peak", bdc->in_bytes_peak, PRIu64);
		SHOW_COUNTER("Input messages", bdc->in_msgs, PRIu64);
		SHOW_COUNTER("Input current usage", STREAM_READABLE(bdc->inbuf),
			     "zu");
		SHOW_COUNTER("Output bytes", bdc->out_bytes, PRIu64);
		SHOW_COUNTER("Output bytes peak", bdc->out_bytes_peak, PRIu64);
		SHOW_COUNTER("Output messages", bdc->out_msgs, PRIu64);
		SHOW_COUNTER("Output full events", bdc->out_fullev, PRIu64);
		SHOW_COUNTER("Output current usage",
			     STREAM_READABLE(bdc->inbuf), "zu");
		vty_out(vty, "\n");
	}
#undef SHOW_COUNTER
}

int bfd_dplane_update_session_counters(struct bfd_session *bs)
{
	uint16_t id;
	int rv;

	/* If session is not using data plane, then just return success. */
	if (bs->bdc == NULL)
		return 0;

	/* Make the request. */
	id = bfd_dplane_request_counters(bs);
	if (id == 0) {
		zlog_debug("%s: counters request failed", __func__);
		return -1;
	}

	/* Handle interruptions. */
	do {
		rv = bfd_dplane_expect(bs->bdc, id,
				       _bfd_dplane_update_session_counters, bs);
	} while (rv == -2);

	return rv;
}
