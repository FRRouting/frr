// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * March 6 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */
#include <zebra.h>
#include "network.h"
#include "sockopt.h"
#include "stream.h"
#include "thread.h"
#include "mgmt_msg.h"


#define MGMT_MSG_DBG(dbgtag, fmt, ...)                                         \
	do {                                                                   \
		if (dbgtag)                                                    \
			zlog_debug("%s: %s: " fmt, dbgtag, __func__,           \
				   ##__VA_ARGS__);                             \
	} while (0)

#define MGMT_MSG_ERR(ms, fmt, ...)                                             \
	zlog_err("%s: %s: " fmt, ms->idtag, __func__, ##__VA_ARGS__)

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
		MGMT_MSG_DBG(dbgtag, "got %ld bytes", n);

		/* -2 is normal nothing read, and to retry */
		if (n == -2)
			break;
		if (n <= 0) {
			if (n == 0)
				MGMT_MSG_ERR(ms, "got EOF/disconnect");
			else
				MGMT_MSG_ERR(ms,
					     "got error while reading: '%s'",
					     safe_strerror(errno));
			return MSR_DISCONNECT;
		}
		ms->nrxb += n;
		avail -= n;
	}

	/*
	 * Check if we have read a complete messages or not.
	 */
	assert(stream_get_getp(ms->ins) == 0);
	left = stream_get_endp(ms->ins);
	while (left > (long)sizeof(struct mgmt_msg_hdr)) {
		mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(ms->ins) + total);
		if (mhdr->marker != MGMT_MSG_MARKER) {
			MGMT_MSG_DBG(dbgtag, "recv corrupt buffer, disconnect");
			return MSR_DISCONNECT;
		}
		if (mhdr->len > left)
			break;

		MGMT_MSG_DBG(dbgtag, "read full message len %u", mhdr->len);
		total += mhdr->len;
		left -= mhdr->len;
		mcount++;
	}

	if (!mcount)
		return MSR_SCHED_STREAM;

	/*
	 * We have read at least one message into the stream, queue it up.
	 */
	mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(ms->ins) + total);
	stream_set_endp(ms->ins, total);
	stream_fifo_push(&ms->inq, ms->ins);
	ms->ins = stream_new(ms->max_msg_sz);
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
		       void (*handle_msg)(void *user, uint8_t *msg,
					  size_t msglen),
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

			assert(mhdr->marker == MGMT_MSG_MARKER);
			assert(left >= mhdr->len);

			handle_msg(user, (uint8_t *)(mhdr + 1),
				   mhdr->len - sizeof(struct mgmt_msg_hdr));
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
		return MSW_SCHED_WRITES_OFF;
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
 *	fd: socket/file to read data from.
 *	debug: true to enable debug logging.
 *
 * Returns:
 *      0 on success, otherwise -1 on failure. The only failure mode is if a
 *      the message exceeds the maximum message size configured on init.
 */
int mgmt_msg_send_msg(struct mgmt_msg_state *ms, void *msg, size_t len,
		      mgmt_msg_packf packf, bool debug)
{
	const char *dbgtag = debug ? ms->idtag : NULL;
	struct mgmt_msg_hdr *mhdr;
	struct stream *s;
	uint8_t *dstbuf;
	size_t endp, n;
	size_t mlen = len + sizeof(*mhdr);

	if (mlen > ms->max_msg_sz) {
		MGMT_MSG_ERR(ms, "Message %zu > max size %zu, dropping", mlen,
			     ms->max_msg_sz);
		return -1;
	}

	if (!ms->outs) {
		MGMT_MSG_DBG(dbgtag, "creating new stream for msg len %zu",
			     len);
		ms->outs = stream_new(ms->max_msg_sz);
	} else if (STREAM_WRITEABLE(ms->outs) < mlen) {
		MGMT_MSG_DBG(
			dbgtag,
			"enq existing stream len %zu and creating new stream for msg len %zu",
			STREAM_WRITEABLE(ms->outs), mlen);
		stream_fifo_push(&ms->outq, ms->outs);
		ms->outs = stream_new(ms->max_msg_sz);
	} else {
		MGMT_MSG_DBG(
			dbgtag,
			"using existing stream with avail %zu for msg len %zu",
			STREAM_WRITEABLE(ms->outs), mlen);
	}
	s = ms->outs;

	/* We have a stream with space, pack the message into it. */
	mhdr = (struct mgmt_msg_hdr *)(STREAM_DATA(s) + s->endp);
	mhdr->marker = MGMT_MSG_MARKER;
	mhdr->len = mlen;
	stream_forward_endp(s, sizeof(*mhdr));
	endp = stream_get_endp(s);
	dstbuf = STREAM_DATA(s) + endp;
	n = packf(msg, dstbuf);
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
	free(ms->idtag);
}
