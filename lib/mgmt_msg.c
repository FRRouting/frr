// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * March 6 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */
#include <zebra.h>
#include "debug.h"
#include "network.h"
#include "sockopt.h"
#include "stream.h"
#include "frrevent.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"


#define MGMT_MSG_DBG(dbgtag, fmt, ...)                                         \
	do {                                                                   \
		if (dbgtag)                                                    \
			zlog_debug("%s: %s: " fmt, dbgtag, __func__,           \
				   ##__VA_ARGS__);                             \
	} while (0)

#define MGMT_MSG_ERR(ms, fmt, ...)                                             \
	zlog_err("%s: %s: " fmt, (ms)->idtag, __func__, ##__VA_ARGS__)

DEFINE_MTYPE(LIB, MSG_CONN, "msg connection state");

/**
 * Read data from a socket into streams containing 1 or more full msgs headed by
 * mgmt_msg_hdr which contain API messages (currently protobuf).
 *
 * Args:
 *	ms: mgmt_msg_state for this process.
 *	fd: socket/file to read data from.
 *	debug: true to enable debug logging.
 *
 * Returns:
 *	MPP_DISCONNECT - socket should be closed and connect retried.
 *	MSV_SCHED_STREAM - this call should be rescheduled to run.
 *	MPP_SCHED_BOTH - this call and the procmsg buf should be scheduled to
 *run.
 */
enum mgmt_msg_rsched mgmt_msg_read(struct mgmt_msg_state *ms, int fd,
				   bool debug)
{
	const char *dbgtag = debug ? ms->idtag : NULL;
	size_t avail = STREAM_WRITEABLE(ms->ins);
	struct mgmt_msg_hdr *mhdr = NULL;
	size_t total = 0;
	size_t mcount = 0;
	ssize_t n, left;

	assert(ms && fd != -1);

	/*
	 * Read as much as we can into the stream.
	 */
	while (avail > sizeof(struct mgmt_msg_hdr)) {
		n = stream_read_try(ms->ins, fd, avail);

		/* -2 is normal nothing read, and to retry */
		if (n == -2) {
			MGMT_MSG_DBG(dbgtag, "nothing more to read");
			break;
		}
		if (n <= 0) {
			if (n == 0)
				MGMT_MSG_ERR(ms, "got EOF/disconnect");
			else
				MGMT_MSG_ERR(ms,
					     "got error while reading: '%s'",
					     safe_strerror(errno));
			return MSR_DISCONNECT;
		}
		MGMT_MSG_DBG(dbgtag, "read %zd bytes", n);
		ms->nrxb += n;
		avail -= n;
	}

	/*
	 * Check if we have read a complete messages or not.
	 */
	assert(stream_get_getp(ms->ins) == 0);
	left = stream_get_endp(ms->ins);
	while (left > (ssize_t)sizeof(struct mgmt_msg_hdr)) {
		mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(ms->ins) + total);
		if (!MGMT_MSG_IS_MARKER(mhdr->marker)) {
			MGMT_MSG_DBG(dbgtag, "recv corrupt buffer, disconnect");
			return MSR_DISCONNECT;
		}
		if ((ssize_t)mhdr->len > left)
			break;

		MGMT_MSG_DBG(dbgtag, "read full message len %u", mhdr->len);
		total += mhdr->len;
		left -= mhdr->len;
		mcount++;
	}

	if (!mcount) {
		/* Didn't manage to read a full message */
		if (mhdr && avail == 0) {
			struct stream *news;
			/*
			 * Message was longer than what was left and we have no
			 * available space to read more in. B/c mcount == 0 the
			 * message starts at the beginning of the stream so
			 * therefor the stream is too small to fit the message..
			 * Resize the stream to fit.
			 */
			news = stream_new(mhdr->len);
			stream_put(news, mhdr, left);
			stream_set_endp(news, left);
			stream_free(ms->ins);
			ms->ins = news;
		}
		return MSR_SCHED_STREAM;
	}

	/*
	 * We have read at least one message into the stream, queue it up.
	 */
	mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(ms->ins) + total);
	stream_set_endp(ms->ins, total);
	stream_fifo_push(&ms->inq, ms->ins);
	if (left < (ssize_t)sizeof(struct mgmt_msg_hdr))
		ms->ins = stream_new(ms->max_msg_sz);
	else
		/* handle case where message is greater than max */
		ms->ins = stream_new(MAX(ms->max_msg_sz, mhdr->len));
	if (left) {
		stream_put(ms->ins, mhdr, left);
		stream_set_endp(ms->ins, left);
	}

	return MSR_SCHED_BOTH;
}

/**
 * Process streams containing whole messages that have been pushed onto the
 * FIFO. This should be called from an event/timer handler and should be
 * reschedulable.
 *
 * Args:
 *	ms: mgmt_msg_state for this process.
 *	handle_mgs: function to call for each received message.
 *	user: opaque value passed through to handle_msg.
 *	debug: true to enable debug logging.
 *
 * Returns:
 *	true if more to process (so reschedule) else false
 */
bool mgmt_msg_procbufs(struct mgmt_msg_state *ms,
		       void (*handle_msg)(uint8_t version, uint8_t *msg,
					  size_t msglen, void *user),
		       void *user, bool debug)
{
	const char *dbgtag = debug ? ms->idtag : NULL;
	struct mgmt_msg_hdr *mhdr;
	struct stream *work;
	uint8_t *data;
	size_t left, nproc;

	MGMT_MSG_DBG(dbgtag, "Have %zu streams to process", ms->inq.count);

	nproc = 0;
	while (nproc < ms->max_read_buf) {
		work = stream_fifo_pop(&ms->inq);
		if (!work)
			break;

		data = STREAM_DATA(work);
		left = stream_get_endp(work);
		MGMT_MSG_DBG(dbgtag, "Processing stream of len %zu", left);

		for (; left > sizeof(struct mgmt_msg_hdr);
		     left -= mhdr->len, data += mhdr->len) {
			mhdr = (struct mgmt_msg_hdr *)data;

			assert(MGMT_MSG_IS_MARKER(mhdr->marker));
			assert(left >= mhdr->len);

			handle_msg(MGMT_MSG_MARKER_VERSION(mhdr->marker),
				   (uint8_t *)(mhdr + 1),
				   mhdr->len - sizeof(struct mgmt_msg_hdr),
				   user);
			ms->nrxm++;
			nproc++;
		}

		if (work != ms->ins)
			stream_free(work); /* Free it up */
		else
			stream_reset(work); /* Reset stream for next read */
	}

	/* return true if should reschedule b/c more to process. */
	return stream_fifo_head(&ms->inq) != NULL;
}

/**
 * Write data from a onto the socket, using streams that have been queued for
 * sending by mgmt_msg_send_msg. This function should be reschedulable.
 *
 * Args:
 *	ms: mgmt_msg_state for this process.
 *	fd: socket/file to read data from.
 *	debug: true to enable debug logging.
 *
 * Returns:
 *	MSW_SCHED_NONE - do not reschedule anything.
 *	MSW_SCHED_STREAM - this call should be rescheduled to run again.
 *	MSW_SCHED_WRITES_OFF - writes should be disabled with a timer to
 *	    re-enable them a short time later
 *	MSW_DISCONNECT - socket should be closed and reconnect retried.
 *run.
 */
enum mgmt_msg_wsched mgmt_msg_write(struct mgmt_msg_state *ms, int fd,
				    bool debug)
{
	const char *dbgtag = debug ? ms->idtag : NULL;
	struct stream *s;
	size_t nproc = 0;
	ssize_t left;
	ssize_t n;

	if (ms->outs) {
		MGMT_MSG_DBG(dbgtag,
			     "found unqueued stream with %zu bytes, queueing",
			     stream_get_endp(ms->outs));
		stream_fifo_push(&ms->outq, ms->outs);
		ms->outs = NULL;
	}

	for (s = stream_fifo_head(&ms->outq); s && nproc < ms->max_write_buf;
	     s = stream_fifo_head(&ms->outq)) {
		left = STREAM_READABLE(s);
		assert(left);

		n = stream_flush(s, fd);
		if (n <= 0) {
			if (n == 0)
				MGMT_MSG_ERR(ms,
					     "connection closed while writing");
			else if (ERRNO_IO_RETRY(errno)) {
				MGMT_MSG_DBG(
					dbgtag,
					"retry error while writing %zd bytes: %s (%d)",
					left, safe_strerror(errno), errno);
				return MSW_SCHED_STREAM;
			} else
				MGMT_MSG_ERR(
					ms,
					"error while writing %zd bytes: %s (%d)",
					left, safe_strerror(errno), errno);

			n = mgmt_msg_reset_writes(ms);
			MGMT_MSG_DBG(dbgtag, "drop and freed %zd streams", n);

			return MSW_DISCONNECT;
		}

		ms->ntxb += n;
		if (n != left) {
			MGMT_MSG_DBG(dbgtag, "short stream write %zd of %zd", n,
				     left);
			stream_forward_getp(s, n);
			return MSW_SCHED_STREAM;
		}

		stream_free(stream_fifo_pop(&ms->outq));
		MGMT_MSG_DBG(dbgtag, "wrote stream of %zd bytes", n);
		nproc++;
	}
	if (s) {
		MGMT_MSG_DBG(
			dbgtag,
			"reached %zu buffer writes, pausing with %zu streams left",
			ms->max_write_buf, ms->outq.count);
		return MSW_SCHED_STREAM;
	}
	MGMT_MSG_DBG(dbgtag, "flushed all streams from output q");
	return MSW_SCHED_NONE;
}


/**
 * Send a message by enqueueing it to be written over the socket by
 * mgmt_msg_write.
 *
 * Args:
 *	ms: mgmt_msg_state for this process.
 *	version: version of this message, will be given to receiving side.
 *	msg: the message to be sent.
 *	len: the length of the message.
 *	packf: a function to pack the message.
 *	debug: true to enable debug logging.
 *
 * Returns:
 *      0 on success, otherwise -1 on failure. The only failure mode is if a
 *      the message exceeds the maximum message size configured on init.
 */
int mgmt_msg_send_msg(struct mgmt_msg_state *ms, uint8_t version, void *msg,
		      size_t len, size_t (*packf)(void *msg, void *buf),
		      bool debug)
{
	const char *dbgtag = debug ? ms->idtag : NULL;
	struct mgmt_msg_hdr *mhdr;
	struct stream *s;
	uint8_t *dstbuf;
	size_t endp, n;
	size_t mlen = len + sizeof(*mhdr);

	if (mlen > ms->max_msg_sz)
		MGMT_MSG_DBG(dbgtag, "Sending large msg size %zu > max size %zu",
			     mlen, ms->max_msg_sz);

	if (!ms->outs) {
		MGMT_MSG_DBG(dbgtag, "creating new stream for msg len %zu", mlen);
		ms->outs = stream_new(MAX(ms->max_msg_sz, mlen));
	} else if (mlen > ms->max_msg_sz && ms->outs->endp == 0) {
		/* msg is larger than stream max size get a fit-to-size stream */
		MGMT_MSG_DBG(dbgtag,
			     "replacing old stream with fit-to-size for msg len %zu",
			     mlen);
		stream_free(ms->outs);
		ms->outs = stream_new(mlen);
	} else if (STREAM_WRITEABLE(ms->outs) < mlen) {
		MGMT_MSG_DBG(dbgtag,
			     "enq existing stream len %zu and creating new stream for msg len %zu",
			     STREAM_WRITEABLE(ms->outs), mlen);
		stream_fifo_push(&ms->outq, ms->outs);
		ms->outs = stream_new(MAX(ms->max_msg_sz, mlen));
	} else {
		MGMT_MSG_DBG(
			dbgtag,
			"using existing stream with avail %zu for msg len %zu",
			STREAM_WRITEABLE(ms->outs), mlen);
	}
	s = ms->outs;

	if (dbgtag && version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *native_msg = msg;

		MGMT_MSG_DBG(
			dbgtag,
			"Sending native msg sess/txn-id %"PRIu64" req-id %"PRIu64" code %u",
			native_msg->refer_id, native_msg->req_id, native_msg->code);

	}

	/* We have a stream with space, pack the message into it. */
	mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(s) + s->endp);
	mhdr->marker = MGMT_MSG_MARKER(version);
	mhdr->len = mlen;
	stream_forward_endp(s, sizeof(*mhdr));
	endp = stream_get_endp(s);
	dstbuf = STREAM_DATA(s) + endp;
	if (packf)
		n = packf(msg, dstbuf);
	else {
		memcpy(dstbuf, msg, len);
		n = len;
	}
	stream_set_endp(s, endp + n);
	ms->ntxm++;

	return 0;
}

/**
 * Create and open a unix domain stream socket on the given path
 * setting non-blocking and send and receive buffer sizes.
 *
 * Args:
 *	path: path of unix domain socket to connect to.
 *	sendbuf: size of socket send buffer.
 *	recvbuf: size of socket receive buffer.
 *	dbgtag: if non-NULL enable log debug, and use this tag.
 *
 * Returns:
 *	socket fd or -1 on error.
 */
int mgmt_msg_connect(const char *path, size_t sendbuf, size_t recvbuf,
		     const char *dbgtag)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	MGMT_MSG_DBG(dbgtag, "connecting to server on %s", path);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		MGMT_MSG_DBG(dbgtag, "socket failed: %s", safe_strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		MGMT_MSG_DBG(dbgtag, "failed to connect on %s: %s", path,
			     safe_strerror(errno));
		close(sock);
		return -1;
	}

	MGMT_MSG_DBG(dbgtag, "connected to server on %s", path);
	set_nonblocking(sock);
	setsockopt_so_sendbuf(sock, sendbuf);
	setsockopt_so_recvbuf(sock, recvbuf);
	return sock;
}

/**
 * Reset the sending queue, by dequeueing all streams and freeing them. Return
 * the number of streams freed.
 *
 * Args:
 *	ms: mgmt_msg_state for this process.
 *
 * Returns:
 *      Number of streams that were freed.
 *
 */
size_t mgmt_msg_reset_writes(struct mgmt_msg_state *ms)
{
	struct stream *s;
	size_t nproc = 0;

	for (s = stream_fifo_pop(&ms->outq); s;
	     s = stream_fifo_pop(&ms->outq), nproc++)
		stream_free(s);

	return nproc;
}


void mgmt_msg_init(struct mgmt_msg_state *ms, size_t max_read_buf,
		   size_t max_write_buf, size_t max_msg_sz, const char *idtag)
{
	memset(ms, 0, sizeof(*ms));
	ms->ins = stream_new(max_msg_sz);
	stream_fifo_init(&ms->inq);
	stream_fifo_init(&ms->outq);
	ms->max_read_buf = max_write_buf;
	ms->max_write_buf = max_read_buf;
	ms->max_msg_sz = max_msg_sz;
	ms->idtag = strdup(idtag);
}

void mgmt_msg_destroy(struct mgmt_msg_state *ms)
{
	mgmt_msg_reset_writes(ms);
	if (ms->ins)
		stream_free(ms->ins);
	if (ms->outs)
		stream_free(ms->outs);
	free(ms->idtag);
}

/*
 * Connections
 */

#define MSG_CONN_DEFAULT_CONN_RETRY_MSEC 250
#define MSG_CONN_SEND_BUF_SIZE (1u << 16)
#define MSG_CONN_RECV_BUF_SIZE (1u << 16)

static void msg_client_sched_connect(struct msg_client *client,
				     unsigned long msec);

static void msg_conn_sched_proc_msgs(struct msg_conn *conn);
static void msg_conn_sched_read(struct msg_conn *conn);
static void msg_conn_sched_write(struct msg_conn *conn);

static void msg_conn_write(struct event *thread)
{
	struct msg_conn *conn = EVENT_ARG(thread);
	enum mgmt_msg_wsched rv;

	rv = mgmt_msg_write(&conn->mstate, conn->fd, conn->debug);
	if (rv == MSW_SCHED_STREAM)
		msg_conn_sched_write(conn);
	else if (rv == MSW_DISCONNECT)
		msg_conn_disconnect(conn, conn->is_client);
	else
		assert(rv == MSW_SCHED_NONE);
}

static void msg_conn_read(struct event *thread)
{
	struct msg_conn *conn = EVENT_ARG(thread);
	enum mgmt_msg_rsched rv;

	rv = mgmt_msg_read(&conn->mstate, conn->fd, conn->debug);
	if (rv == MSR_DISCONNECT) {
		msg_conn_disconnect(conn, conn->is_client);
		return;
	}
	if (rv == MSR_SCHED_BOTH)
		msg_conn_sched_proc_msgs(conn);
	msg_conn_sched_read(conn);
}

/* collapse this into mgmt_msg_procbufs */
static void msg_conn_proc_msgs(struct event *thread)
{
	struct msg_conn *conn = EVENT_ARG(thread);

	if (mgmt_msg_procbufs(&conn->mstate,
			      (void (*)(uint8_t, uint8_t *, size_t,
					void *))conn->handle_msg,
			      conn, conn->debug))
		/* there's more, schedule handling more */
		msg_conn_sched_proc_msgs(conn);
}

static void msg_conn_sched_read(struct msg_conn *conn)
{
	event_add_read(conn->loop, msg_conn_read, conn, conn->fd,
		       &conn->read_ev);
}

static void msg_conn_sched_write(struct msg_conn *conn)
{
	event_add_write(conn->loop, msg_conn_write, conn, conn->fd,
			&conn->write_ev);
}

static void msg_conn_sched_proc_msgs(struct msg_conn *conn)
{
	event_add_event(conn->loop, msg_conn_proc_msgs, conn, 0,
			&conn->proc_msg_ev);
}


void msg_conn_disconnect(struct msg_conn *conn, bool reconnect)
{

	/* disconnect short-circuit if present */
	if (conn->remote_conn) {
		conn->remote_conn->remote_conn = NULL;
		conn->remote_conn = NULL;
	}

	if (conn->fd != -1) {
		close(conn->fd);
		conn->fd = -1;

		/* Notify client through registered callback (if any) */
		if (conn->notify_disconnect)
			(void)(*conn->notify_disconnect)(conn);
	}

	if (reconnect) {
		assert(conn->is_client);
		msg_client_sched_connect(
			container_of(conn, struct msg_client, conn),
			MSG_CONN_DEFAULT_CONN_RETRY_MSEC);
	}
}

int msg_conn_send_msg(struct msg_conn *conn, uint8_t version, void *msg,
		      size_t mlen, size_t (*packf)(void *, void *),
		      bool short_circuit_ok)
{
	const char *dbgtag = conn->debug ? conn->mstate.idtag : NULL;

	if (conn->fd == -1) {
		MGMT_MSG_ERR(&conn->mstate,
			     "can't send message on closed connection");
		return -1;
	}

	/* immediately handle the message if short-circuit is present */
	if (conn->remote_conn && short_circuit_ok) {
		uint8_t *buf = msg;
		size_t n = mlen;
		bool old;

		if (packf) {
			buf = XMALLOC(MTYPE_TMP, mlen);
			n = packf(msg, buf);
		}

		++conn->short_circuit_depth;
		MGMT_MSG_DBG(dbgtag, "SC send: depth %u msg: %p",
			     conn->short_circuit_depth, msg);

		old = conn->remote_conn->is_short_circuit;
		conn->remote_conn->is_short_circuit = true;
		conn->remote_conn->handle_msg(version, buf, n,
					      conn->remote_conn);
		conn->remote_conn->is_short_circuit = old;

		--conn->short_circuit_depth;
		MGMT_MSG_DBG(dbgtag, "SC return from depth: %u msg: %p",
			     conn->short_circuit_depth, msg);

		if (packf)
			XFREE(MTYPE_TMP, buf);
		return 0;
	}

	int rv = mgmt_msg_send_msg(&conn->mstate, version, msg, mlen, packf,
				   conn->debug);

	msg_conn_sched_write(conn);

	return rv;
}

void msg_conn_cleanup(struct msg_conn *conn)
{
	struct mgmt_msg_state *ms = &conn->mstate;

	/* disconnect short-circuit if present */
	if (conn->remote_conn) {
		conn->remote_conn->remote_conn = NULL;
		conn->remote_conn = NULL;
	}

	if (conn->fd != -1) {
		close(conn->fd);
		conn->fd = -1;
	}

	EVENT_OFF(conn->read_ev);
	EVENT_OFF(conn->write_ev);
	EVENT_OFF(conn->proc_msg_ev);

	mgmt_msg_destroy(ms);
}

/*
 * Client Connections
 */

DECLARE_LIST(msg_server_list, struct msg_server, link);

static struct msg_server_list_head msg_servers;

static void msg_client_connect(struct msg_client *conn);

static void msg_client_connect_timer(struct event *thread)
{
	msg_client_connect(EVENT_ARG(thread));
}

static void msg_client_sched_connect(struct msg_client *client,
				     unsigned long msec)
{
	struct msg_conn *conn = &client->conn;
	const char *dbgtag = conn->debug ? conn->mstate.idtag : NULL;

	MGMT_MSG_DBG(dbgtag, "connection retry in %lu msec", msec);
	if (msec)
		event_add_timer_msec(conn->loop, msg_client_connect_timer,
				     client, msec, &client->conn_retry_tmr);
	else
		event_add_event(conn->loop, msg_client_connect_timer, client, 0,
				&client->conn_retry_tmr);
}

static int msg_client_connect_short_circuit(struct msg_client *client)
{
	struct msg_conn *server_conn;
	struct msg_server *server;
	const char *dbgtag =
		client->conn.debug ? client->conn.mstate.idtag : NULL;
	union sockunion su = {0};
	int sockets[2];

	frr_each (msg_server_list, &msg_servers, server)
		if (!strcmp(server->sopath, client->sopath))
			break;
	if (!server) {
		MGMT_MSG_DBG(dbgtag,
			     "no short-circuit server available yet for %s",
			     client->sopath);
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
		MGMT_MSG_ERR(
			&client->conn.mstate,
			"socketpair failed trying to short-circuit connection on %s: %s",
			client->sopath, safe_strerror(errno));
		return -1;
	}

	/* client side */
	client->conn.fd = sockets[0];
	set_nonblocking(sockets[0]);
	setsockopt_so_sendbuf(sockets[0], client->conn.mstate.max_write_buf);
	setsockopt_so_recvbuf(sockets[0], client->conn.mstate.max_read_buf);

	/* server side */
	memset(&su, 0, sizeof(union sockunion));
	server_conn = server->create(sockets[1], &su);
	server_conn->debug = DEBUG_MODE_CHECK(server->debug, DEBUG_MODE_ALL)
				     ? true
				     : false;

	client->conn.remote_conn = server_conn;
	server_conn->remote_conn = &client->conn;

	MGMT_MSG_DBG(
		dbgtag,
		"short-circuit connection on %s server %s:%d to client %s:%d",
		client->sopath, server_conn->mstate.idtag, server_conn->fd,
		client->conn.mstate.idtag, client->conn.fd);

	MGMT_MSG_DBG(
		server_conn->debug ? server_conn->mstate.idtag : NULL,
		"short-circuit connection on %s client %s:%d to server %s:%d",
		client->sopath, client->conn.mstate.idtag, client->conn.fd,
		server_conn->mstate.idtag, server_conn->fd);

	return 0;
}


/* Connect and start reading from the socket */
static void msg_client_connect(struct msg_client *client)
{
	struct msg_conn *conn = &client->conn;
	const char *dbgtag = conn->debug ? conn->mstate.idtag : NULL;

	if (!client->short_circuit_ok)
		conn->fd =
			mgmt_msg_connect(client->sopath, MSG_CONN_SEND_BUF_SIZE,
					 MSG_CONN_RECV_BUF_SIZE, dbgtag);
	else if (msg_client_connect_short_circuit(client))
		conn->fd = -1;

	if (conn->fd == -1)
		/* retry the connection */
		msg_client_sched_connect(client,
					 MSG_CONN_DEFAULT_CONN_RETRY_MSEC);
	else if (client->notify_connect && client->notify_connect(client))
		/* client connect notify failed */
		msg_conn_disconnect(conn, true);
	else
		/* start reading */
		msg_conn_sched_read(conn);
}

void msg_client_init(struct msg_client *client, struct event_loop *tm,
		     const char *sopath,
		     int (*notify_connect)(struct msg_client *client),
		     int (*notify_disconnect)(struct msg_conn *client),
		     void (*handle_msg)(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *client),
		     size_t max_read_buf, size_t max_write_buf,
		     size_t max_msg_sz, bool short_circuit_ok,
		     const char *idtag, bool debug)
{
	struct msg_conn *conn = &client->conn;
	memset(client, 0, sizeof(*client));

	conn->loop = tm;
	conn->fd = -1;
	conn->handle_msg = handle_msg;
	conn->notify_disconnect = notify_disconnect;
	conn->is_client = true;
	conn->debug = debug;
	client->short_circuit_ok = short_circuit_ok;
	client->sopath = strdup(sopath);
	client->notify_connect = notify_connect;

	mgmt_msg_init(&conn->mstate, max_read_buf, max_write_buf, max_msg_sz,
		      idtag);

	/* Start trying to connect to server */
	msg_client_sched_connect(client, 0);
}

void msg_client_cleanup(struct msg_client *client)
{
	assert(client->conn.is_client);

	EVENT_OFF(client->conn_retry_tmr);
	free(client->sopath);

	msg_conn_cleanup(&client->conn);
}


/*
 * Server-side connections
 */

static void msg_server_accept(struct event *event)
{
	struct msg_server *server = EVENT_ARG(event);
	struct msg_conn *conn;
	union sockunion su;
	int fd;

	if (server->fd < 0)
		return;

	/* We continue hearing server listen socket. */
	event_add_read(server->loop, msg_server_accept, server, server->fd,
		       &server->listen_ev);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	fd = sockunion_accept(server->fd, &su);
	if (fd < 0) {
		zlog_err("Failed to accept %s client connection: %s",
			 server->idtag, safe_strerror(errno));
		return;
	}
	set_nonblocking(fd);
	set_cloexec(fd);

	DEBUGD(server->debug, "Accepted new %s connection", server->idtag);

	conn = server->create(fd, &su);
	if (conn)
		conn->debug = DEBUG_MODE_CHECK(server->debug, DEBUG_MODE_ALL)
				      ? true
				      : false;
}

int msg_server_init(struct msg_server *server, const char *sopath,
		    struct event_loop *loop,
		    struct msg_conn *(*create)(int fd, union sockunion *su),
		    const char *idtag, struct debug *debug)
{
	int ret;
	int sock;
	struct sockaddr_un addr;
	mode_t old_mask;

	memset(server, 0, sizeof(*server));
	server->fd = -1;

	sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sock < 0) {
		zlog_err("Failed to create %s server socket: %s", server->idtag,
			 safe_strerror(errno));
		goto fail;
	}

	addr.sun_family = AF_UNIX,
	strlcpy(addr.sun_path, sopath, sizeof(addr.sun_path));
	unlink(addr.sun_path);
	old_mask = umask(0077);
	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		zlog_err("Failed to bind %s server socket to '%s': %s",
			 server->idtag, addr.sun_path, safe_strerror(errno));
		umask(old_mask);
		goto fail;
	}
	umask(old_mask);

	ret = listen(sock, MGMTD_MAX_CONN);
	if (ret < 0) {
		zlog_err("Failed to listen on %s server socket: %s",
			 server->idtag, safe_strerror(errno));
		goto fail;
	}

	server->fd = sock;
	server->loop = loop;
	server->sopath = strdup(sopath);
	server->idtag = strdup(idtag);
	server->create = create;
	server->debug = debug;

	msg_server_list_add_head(&msg_servers, server);

	event_add_read(server->loop, msg_server_accept, server, server->fd,
		       &server->listen_ev);


	DEBUGD(debug, "Started %s server, listening on %s", idtag, sopath);
	return 0;

fail:
	if (sock >= 0)
		close(sock);
	server->fd = -1;
	return -1;
}

void msg_server_cleanup(struct msg_server *server)
{
	DEBUGD(server->debug, "Closing %s server", server->idtag);

	if (server->listen_ev)
		EVENT_OFF(server->listen_ev);

	msg_server_list_del(&msg_servers, server);

	if (server->fd >= 0)
		close(server->fd);
	free((char *)server->sopath);
	free((char *)server->idtag);

	memset(server, 0, sizeof(*server));
	server->fd = -1;
}

/*
 * Initialize and start reading from the accepted socket
 *
 *     notify_connect - only called for disconnect i.e., connected == false
 */
void msg_conn_accept_init(struct msg_conn *conn, struct event_loop *tm, int fd,
			  int (*notify_disconnect)(struct msg_conn *conn),
			  void (*handle_msg)(uint8_t version, uint8_t *data,
					     size_t len, struct msg_conn *conn),
			  size_t max_read, size_t max_write, size_t max_size,
			  const char *idtag)
{
	conn->loop = tm;
	conn->fd = fd;
	conn->notify_disconnect = notify_disconnect;
	conn->handle_msg = handle_msg;
	conn->is_client = false;

	mgmt_msg_init(&conn->mstate, max_read, max_write, max_size, idtag);

	/* start reading */
	msg_conn_sched_read(conn);

	/* Make socket non-blocking.  */
	set_nonblocking(conn->fd);
	setsockopt_so_sendbuf(conn->fd, MSG_CONN_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(conn->fd, MSG_CONN_RECV_BUF_SIZE);
}

struct msg_conn *
msg_server_conn_create(struct event_loop *tm, int fd,
		       int (*notify_disconnect)(struct msg_conn *conn),
		       void (*handle_msg)(uint8_t version, uint8_t *data,
					  size_t len, struct msg_conn *conn),
		       size_t max_read, size_t max_write, size_t max_size,
		       void *user, const char *idtag)
{
	struct msg_conn *conn = XMALLOC(MTYPE_MSG_CONN, sizeof(*conn));
	memset(conn, 0, sizeof(*conn));
	msg_conn_accept_init(conn, tm, fd, notify_disconnect, handle_msg,
			     max_read, max_write, max_size, idtag);
	conn->user = user;
	return conn;
}

void msg_server_conn_delete(struct msg_conn *conn)
{
	if (!conn)
		return;
	msg_conn_cleanup(conn);
	XFREE(MTYPE_MSG_CONN, conn);
}
