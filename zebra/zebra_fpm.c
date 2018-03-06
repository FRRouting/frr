/*
 * Main implementation file for interface to Forwarding Plane Manager.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
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

#include "log.h"
#include "libfrr.h"
#include "stream.h"
#include "thread.h"
#include "network.h"
#include "command.h"
#include "version.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"

#include "fpm/fpm.h"
#include "zebra_fpm_private.h"

/*
 * Interval at which we attempt to connect to the FPM.
 */
#define ZFPM_CONNECT_RETRY_IVL   5

/*
 * Sizes of outgoing and incoming stream buffers for writing/reading
 * FPM messages.
 */
#define ZFPM_OBUF_SIZE (2 * FPM_MAX_MSG_LEN)
#define ZFPM_IBUF_SIZE (FPM_MAX_MSG_LEN)

/*
 * The maximum number of times the FPM socket write callback can call
 * 'write' before it yields.
 */
#define ZFPM_MAX_WRITES_PER_RUN 10

/*
 * Interval over which we collect statistics.
 */
#define ZFPM_STATS_IVL_SECS        10

/*
 * Structure that holds state for iterating over all route_node
 * structures that are candidates for being communicated to the FPM.
 */
typedef struct zfpm_rnodes_iter_t_ {
	rib_tables_iter_t tables_iter;
	route_table_iter_t iter;
} zfpm_rnodes_iter_t;

/*
 * Statistics.
 */
typedef struct zfpm_stats_t_ {
	unsigned long connect_calls;
	unsigned long connect_no_sock;

	unsigned long read_cb_calls;

	unsigned long write_cb_calls;
	unsigned long write_calls;
	unsigned long partial_writes;
	unsigned long max_writes_hit;
	unsigned long t_write_yields;

	unsigned long nop_deletes_skipped;
	unsigned long route_adds;
	unsigned long route_dels;

	unsigned long updates_triggered;
	unsigned long redundant_triggers;

	unsigned long dests_del_after_update;

	unsigned long t_conn_down_starts;
	unsigned long t_conn_down_dests_processed;
	unsigned long t_conn_down_yields;
	unsigned long t_conn_down_finishes;

	unsigned long t_conn_up_starts;
	unsigned long t_conn_up_dests_processed;
	unsigned long t_conn_up_yields;
	unsigned long t_conn_up_aborts;
	unsigned long t_conn_up_finishes;

} zfpm_stats_t;

/*
 * States for the FPM state machine.
 */
typedef enum {

	/*
	 * In this state we are not yet ready to connect to the FPM. This
	 * can happen when this module is disabled, or if we're cleaning up
	 * after a connection has gone down.
	 */
	ZFPM_STATE_IDLE,

	/*
	 * Ready to talk to the FPM and periodically trying to connect to
	 * it.
	 */
	ZFPM_STATE_ACTIVE,

	/*
	 * In the middle of bringing up a TCP connection. Specifically,
	 * waiting for a connect() call to complete asynchronously.
	 */
	ZFPM_STATE_CONNECTING,

	/*
	 * TCP connection to the FPM is up.
	 */
	ZFPM_STATE_ESTABLISHED

} zfpm_state_t;

/*
 * Message format to be used to communicate with the FPM.
 */
typedef enum {
	ZFPM_MSG_FORMAT_NONE,
	ZFPM_MSG_FORMAT_NETLINK,
	ZFPM_MSG_FORMAT_PROTOBUF,
} zfpm_msg_format_e;
/*
 * Globals.
 */
typedef struct zfpm_glob_t_ {

	/*
	 * True if the FPM module has been enabled.
	 */
	int enabled;

	/*
	 * Message format to be used to communicate with the fpm.
	 */
	zfpm_msg_format_e message_format;

	struct thread_master *master;

	zfpm_state_t state;

	in_addr_t fpm_server;
	/*
	 * Port on which the FPM is running.
	 */
	int fpm_port;

	/*
	 * List of rib_dest_t structures to be processed
	 */
	TAILQ_HEAD(zfpm_dest_q, rib_dest_t_) dest_q;

	/*
	 * Stream socket to the FPM.
	 */
	int sock;

	/*
	 * Buffers for messages to/from the FPM.
	 */
	struct stream *obuf;
	struct stream *ibuf;

	/*
	 * Threads for I/O.
	 */
	struct thread *t_connect;
	struct thread *t_write;
	struct thread *t_read;

	/*
	 * Thread to clean up after the TCP connection to the FPM goes down
	 * and the state that belongs to it.
	 */
	struct thread *t_conn_down;

	struct {
		zfpm_rnodes_iter_t iter;
	} t_conn_down_state;

	/*
	 * Thread to take actions once the TCP conn to the FPM comes up, and
	 * the state that belongs to it.
	 */
	struct thread *t_conn_up;

	struct {
		zfpm_rnodes_iter_t iter;
	} t_conn_up_state;

	unsigned long connect_calls;
	time_t last_connect_call_time;

	/*
	 * Stats from the start of the current statistics interval up to
	 * now. These are the counters we typically update in the code.
	 */
	zfpm_stats_t stats;

	/*
	 * Statistics that were gathered in the last collection interval.
	 */
	zfpm_stats_t last_ivl_stats;

	/*
	 * Cumulative stats from the last clear to the start of the current
	 * statistics interval.
	 */
	zfpm_stats_t cumulative_stats;

	/*
	 * Stats interval timer.
	 */
	struct thread *t_stats;

	/*
	 * If non-zero, the last time when statistics were cleared.
	 */
	time_t last_stats_clear_time;

} zfpm_glob_t;

static zfpm_glob_t zfpm_glob_space;
static zfpm_glob_t *zfpm_g = &zfpm_glob_space;

static int zfpm_trigger_update(struct route_node *rn, const char *reason);

static int zfpm_read_cb(struct thread *thread);
static int zfpm_write_cb(struct thread *thread);

static void zfpm_set_state(zfpm_state_t state, const char *reason);
static void zfpm_start_connect_timer(const char *reason);
static void zfpm_start_stats_timer(void);

/*
 * zfpm_thread_should_yield
 */
static inline int zfpm_thread_should_yield(struct thread *t)
{
	return thread_should_yield(t);
}

/*
 * zfpm_state_to_str
 */
static const char *zfpm_state_to_str(zfpm_state_t state)
{
	switch (state) {

	case ZFPM_STATE_IDLE:
		return "idle";

	case ZFPM_STATE_ACTIVE:
		return "active";

	case ZFPM_STATE_CONNECTING:
		return "connecting";

	case ZFPM_STATE_ESTABLISHED:
		return "established";

	default:
		return "unknown";
	}
}

/*
 * zfpm_get_elapsed_time
 *
 * Returns the time elapsed (in seconds) since the given time.
 */
static time_t zfpm_get_elapsed_time(time_t reference)
{
	time_t now;

	now = monotime(NULL);

	if (now < reference) {
		assert(0);
		return 0;
	}

	return now - reference;
}

/*
 * zfpm_rnodes_iter_init
 */
static inline void zfpm_rnodes_iter_init(zfpm_rnodes_iter_t *iter)
{
	memset(iter, 0, sizeof(*iter));
	rib_tables_iter_init(&iter->tables_iter);

	/*
	 * This is a hack, but it makes implementing 'next' easier by
	 * ensuring that route_table_iter_next() will return NULL the first
	 * time we call it.
	 */
	route_table_iter_init(&iter->iter, NULL);
	route_table_iter_cleanup(&iter->iter);
}

/*
 * zfpm_rnodes_iter_next
 */
static inline struct route_node *zfpm_rnodes_iter_next(zfpm_rnodes_iter_t *iter)
{
	struct route_node *rn;
	struct route_table *table;

	while (1) {
		rn = route_table_iter_next(&iter->iter);
		if (rn)
			return rn;

		/*
		 * We've made our way through this table, go to the next one.
		 */
		route_table_iter_cleanup(&iter->iter);

		table = rib_tables_iter_next(&iter->tables_iter);

		if (!table)
			return NULL;

		route_table_iter_init(&iter->iter, table);
	}

	return NULL;
}

/*
 * zfpm_rnodes_iter_pause
 */
static inline void zfpm_rnodes_iter_pause(zfpm_rnodes_iter_t *iter)
{
	route_table_iter_pause(&iter->iter);
}

/*
 * zfpm_rnodes_iter_cleanup
 */
static inline void zfpm_rnodes_iter_cleanup(zfpm_rnodes_iter_t *iter)
{
	route_table_iter_cleanup(&iter->iter);
	rib_tables_iter_cleanup(&iter->tables_iter);
}

/*
 * zfpm_stats_init
 *
 * Initialize a statistics block.
 */
static inline void zfpm_stats_init(zfpm_stats_t *stats)
{
	memset(stats, 0, sizeof(*stats));
}

/*
 * zfpm_stats_reset
 */
static inline void zfpm_stats_reset(zfpm_stats_t *stats)
{
	zfpm_stats_init(stats);
}

/*
 * zfpm_stats_copy
 */
static inline void zfpm_stats_copy(const zfpm_stats_t *src, zfpm_stats_t *dest)
{
	memcpy(dest, src, sizeof(*dest));
}

/*
 * zfpm_stats_compose
 *
 * Total up the statistics in two stats structures ('s1 and 's2') and
 * return the result in the third argument, 'result'. Note that the
 * pointer 'result' may be the same as 's1' or 's2'.
 *
 * For simplicity, the implementation below assumes that the stats
 * structure is composed entirely of counters. This can easily be
 * changed when necessary.
 */
static void zfpm_stats_compose(const zfpm_stats_t *s1, const zfpm_stats_t *s2,
			       zfpm_stats_t *result)
{
	const unsigned long *p1, *p2;
	unsigned long *result_p;
	int i, num_counters;

	p1 = (const unsigned long *)s1;
	p2 = (const unsigned long *)s2;
	result_p = (unsigned long *)result;

	num_counters = (sizeof(zfpm_stats_t) / sizeof(unsigned long));

	for (i = 0; i < num_counters; i++) {
		result_p[i] = p1[i] + p2[i];
	}
}

/*
 * zfpm_read_on
 */
static inline void zfpm_read_on(void)
{
	assert(!zfpm_g->t_read);
	assert(zfpm_g->sock >= 0);

	thread_add_read(zfpm_g->master, zfpm_read_cb, 0, zfpm_g->sock,
			&zfpm_g->t_read);
}

/*
 * zfpm_write_on
 */
static inline void zfpm_write_on(void)
{
	assert(!zfpm_g->t_write);
	assert(zfpm_g->sock >= 0);

	thread_add_write(zfpm_g->master, zfpm_write_cb, 0, zfpm_g->sock,
			 &zfpm_g->t_write);
}

/*
 * zfpm_read_off
 */
static inline void zfpm_read_off(void)
{
	THREAD_READ_OFF(zfpm_g->t_read);
}

/*
 * zfpm_write_off
 */
static inline void zfpm_write_off(void)
{
	THREAD_WRITE_OFF(zfpm_g->t_write);
}

/*
 * zfpm_conn_up_thread_cb
 *
 * Callback for actions to be taken when the connection to the FPM
 * comes up.
 */
static int zfpm_conn_up_thread_cb(struct thread *thread)
{
	struct route_node *rnode;
	zfpm_rnodes_iter_t *iter;
	rib_dest_t *dest;

	zfpm_g->t_conn_up = NULL;

	iter = &zfpm_g->t_conn_up_state.iter;

	if (zfpm_g->state != ZFPM_STATE_ESTABLISHED) {
		zfpm_debug(
			"Connection not up anymore, conn_up thread aborting");
		zfpm_g->stats.t_conn_up_aborts++;
		goto done;
	}

	while ((rnode = zfpm_rnodes_iter_next(iter))) {
		dest = rib_dest_from_rnode(rnode);

		if (dest) {
			zfpm_g->stats.t_conn_up_dests_processed++;
			zfpm_trigger_update(rnode, NULL);
		}

		/*
		 * Yield if need be.
		 */
		if (!zfpm_thread_should_yield(thread))
			continue;

		zfpm_g->stats.t_conn_up_yields++;
		zfpm_rnodes_iter_pause(iter);
		zfpm_g->t_conn_up = NULL;
		thread_add_timer_msec(zfpm_g->master, zfpm_conn_up_thread_cb,
				      NULL, 0, &zfpm_g->t_conn_up);
		return 0;
	}

	zfpm_g->stats.t_conn_up_finishes++;

done:
	zfpm_rnodes_iter_cleanup(iter);
	return 0;
}

/*
 * zfpm_connection_up
 *
 * Called when the connection to the FPM comes up.
 */
static void zfpm_connection_up(const char *detail)
{
	assert(zfpm_g->sock >= 0);
	zfpm_read_on();
	zfpm_write_on();
	zfpm_set_state(ZFPM_STATE_ESTABLISHED, detail);

	/*
	 * Start thread to push existing routes to the FPM.
	 */
	assert(!zfpm_g->t_conn_up);

	zfpm_rnodes_iter_init(&zfpm_g->t_conn_up_state.iter);

	zfpm_debug("Starting conn_up thread");
	zfpm_g->t_conn_up = NULL;
	thread_add_timer_msec(zfpm_g->master, zfpm_conn_up_thread_cb, NULL, 0,
			      &zfpm_g->t_conn_up);
	zfpm_g->stats.t_conn_up_starts++;
}

/*
 * zfpm_connect_check
 *
 * Check if an asynchronous connect() to the FPM is complete.
 */
static void zfpm_connect_check(void)
{
	int status;
	socklen_t slen;
	int ret;

	zfpm_read_off();
	zfpm_write_off();

	slen = sizeof(status);
	ret = getsockopt(zfpm_g->sock, SOL_SOCKET, SO_ERROR, (void *)&status,
			 &slen);

	if (ret >= 0 && status == 0) {
		zfpm_connection_up("async connect complete");
		return;
	}

	/*
	 * getsockopt() failed or indicated an error on the socket.
	 */
	close(zfpm_g->sock);
	zfpm_g->sock = -1;

	zfpm_start_connect_timer("getsockopt() after async connect failed");
	return;
}

/*
 * zfpm_conn_down_thread_cb
 *
 * Callback that is invoked to clean up state after the TCP connection
 * to the FPM goes down.
 */
static int zfpm_conn_down_thread_cb(struct thread *thread)
{
	struct route_node *rnode;
	zfpm_rnodes_iter_t *iter;
	rib_dest_t *dest;

	assert(zfpm_g->state == ZFPM_STATE_IDLE);

	zfpm_g->t_conn_down = NULL;

	iter = &zfpm_g->t_conn_down_state.iter;

	while ((rnode = zfpm_rnodes_iter_next(iter))) {
		dest = rib_dest_from_rnode(rnode);

		if (dest) {
			if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)) {
				TAILQ_REMOVE(&zfpm_g->dest_q, dest,
					     fpm_q_entries);
			}

			UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
			UNSET_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM);

			zfpm_g->stats.t_conn_down_dests_processed++;

			/*
			 * Check if the dest should be deleted.
			 */
			rib_gc_dest(rnode);
		}

		/*
		 * Yield if need be.
		 */
		if (!zfpm_thread_should_yield(thread))
			continue;

		zfpm_g->stats.t_conn_down_yields++;
		zfpm_rnodes_iter_pause(iter);
		zfpm_g->t_conn_down = NULL;
		thread_add_timer_msec(zfpm_g->master, zfpm_conn_down_thread_cb,
				      NULL, 0, &zfpm_g->t_conn_down);
		return 0;
	}

	zfpm_g->stats.t_conn_down_finishes++;
	zfpm_rnodes_iter_cleanup(iter);

	/*
	 * Start the process of connecting to the FPM again.
	 */
	zfpm_start_connect_timer("cleanup complete");
	return 0;
}

/*
 * zfpm_connection_down
 *
 * Called when the connection to the FPM has gone down.
 */
static void zfpm_connection_down(const char *detail)
{
	if (!detail)
		detail = "unknown";

	assert(zfpm_g->state == ZFPM_STATE_ESTABLISHED);

	zlog_info("connection to the FPM has gone down: %s", detail);

	zfpm_read_off();
	zfpm_write_off();

	stream_reset(zfpm_g->ibuf);
	stream_reset(zfpm_g->obuf);

	if (zfpm_g->sock >= 0) {
		close(zfpm_g->sock);
		zfpm_g->sock = -1;
	}

	/*
	 * Start thread to clean up state after the connection goes down.
	 */
	assert(!zfpm_g->t_conn_down);
	zfpm_debug("Starting conn_down thread");
	zfpm_rnodes_iter_init(&zfpm_g->t_conn_down_state.iter);
	zfpm_g->t_conn_down = NULL;
	thread_add_timer_msec(zfpm_g->master, zfpm_conn_down_thread_cb, NULL, 0,
			      &zfpm_g->t_conn_down);
	zfpm_g->stats.t_conn_down_starts++;

	zfpm_set_state(ZFPM_STATE_IDLE, detail);
}

/*
 * zfpm_read_cb
 */
static int zfpm_read_cb(struct thread *thread)
{
	size_t already;
	struct stream *ibuf;
	uint16_t msg_len;
	fpm_msg_hdr_t *hdr;

	zfpm_g->stats.read_cb_calls++;
	zfpm_g->t_read = NULL;

	/*
	 * Check if async connect is now done.
	 */
	if (zfpm_g->state == ZFPM_STATE_CONNECTING) {
		zfpm_connect_check();
		return 0;
	}

	assert(zfpm_g->state == ZFPM_STATE_ESTABLISHED);
	assert(zfpm_g->sock >= 0);

	ibuf = zfpm_g->ibuf;

	already = stream_get_endp(ibuf);
	if (already < FPM_MSG_HDR_LEN) {
		ssize_t nbyte;

		nbyte = stream_read_try(ibuf, zfpm_g->sock,
					FPM_MSG_HDR_LEN - already);
		if (nbyte == 0 || nbyte == -1) {
			if (nbyte == -1) {
				char buffer[1024];

				sprintf(buffer, "closed socket in read(%d): %s",
					errno, safe_strerror(errno));
				zfpm_connection_down(buffer);
			} else
				zfpm_connection_down("closed socket in read");
			return 0;
		}

		if (nbyte != (ssize_t)(FPM_MSG_HDR_LEN - already))
			goto done;

		already = FPM_MSG_HDR_LEN;
	}

	stream_set_getp(ibuf, 0);

	hdr = (fpm_msg_hdr_t *)stream_pnt(ibuf);

	if (!fpm_msg_hdr_ok(hdr)) {
		zfpm_connection_down("invalid message header");
		return 0;
	}

	msg_len = fpm_msg_len(hdr);

	/*
	 * Read out the rest of the packet.
	 */
	if (already < msg_len) {
		ssize_t nbyte;

		nbyte = stream_read_try(ibuf, zfpm_g->sock, msg_len - already);

		if (nbyte == 0 || nbyte == -1) {
			if (nbyte == -1) {
				char buffer[1024];

				sprintf(buffer, "failed to read message(%d) %s",
					errno, safe_strerror(errno));
				zfpm_connection_down(buffer);
			} else
				zfpm_connection_down("failed to read message");
			return 0;
		}

		if (nbyte != (ssize_t)(msg_len - already))
			goto done;
	}

	zfpm_debug("Read out a full fpm message");

	/*
	 * Just throw it away for now.
	 */
	stream_reset(ibuf);

done:
	zfpm_read_on();
	return 0;
}

/*
 * zfpm_writes_pending
 *
 * Returns TRUE if we may have something to write to the FPM.
 */
static int zfpm_writes_pending(void)
{

	/*
	 * Check if there is any data in the outbound buffer that has not
	 * been written to the socket yet.
	 */
	if (stream_get_endp(zfpm_g->obuf) - stream_get_getp(zfpm_g->obuf))
		return 1;

	/*
	 * Check if there are any prefixes on the outbound queue.
	 */
	if (!TAILQ_EMPTY(&zfpm_g->dest_q))
		return 1;

	return 0;
}

/*
 * zfpm_encode_route
 *
 * Encode a message to the FPM with information about the given route.
 *
 * Returns the number of bytes written to the buffer. 0 or a negative
 * value indicates an error.
 */
static inline int zfpm_encode_route(rib_dest_t *dest, struct route_entry *re,
				    char *in_buf, size_t in_buf_len,
				    fpm_msg_type_e *msg_type)
{
	size_t len;
#ifdef HAVE_NETLINK
	int cmd;
#endif
	len = 0;

	*msg_type = FPM_MSG_TYPE_NONE;

	switch (zfpm_g->message_format) {

	case ZFPM_MSG_FORMAT_PROTOBUF:
#ifdef HAVE_PROTOBUF
		len = zfpm_protobuf_encode_route(dest, re, (uint8_t *)in_buf,
						 in_buf_len);
		*msg_type = FPM_MSG_TYPE_PROTOBUF;
#endif
		break;

	case ZFPM_MSG_FORMAT_NETLINK:
#ifdef HAVE_NETLINK
		*msg_type = FPM_MSG_TYPE_NETLINK;
		cmd = re ? RTM_NEWROUTE : RTM_DELROUTE;
		len = zfpm_netlink_encode_route(cmd, dest, re, in_buf,
						in_buf_len);
		assert(fpm_msg_align(len) == len);
		*msg_type = FPM_MSG_TYPE_NETLINK;
#endif /* HAVE_NETLINK */
		break;

	default:
		break;
	}

	return len;
}

/*
 * zfpm_route_for_update
 *
 * Returns the re that is to be sent to the FPM for a given dest.
 */
struct route_entry *zfpm_route_for_update(rib_dest_t *dest)
{
	return dest->selected_fib;
}

/*
 * zfpm_build_updates
 *
 * Process the outgoing queue and write messages to the outbound
 * buffer.
 */
static void zfpm_build_updates(void)
{
	struct stream *s;
	rib_dest_t *dest;
	unsigned char *buf, *data, *buf_end;
	size_t msg_len;
	size_t data_len;
	fpm_msg_hdr_t *hdr;
	struct route_entry *re;
	int is_add, write_msg;
	fpm_msg_type_e msg_type;

	s = zfpm_g->obuf;

	assert(stream_empty(s));

	do {

		/*
		 * Make sure there is enough space to write another message.
		 */
		if (STREAM_WRITEABLE(s) < FPM_MAX_MSG_LEN)
			break;

		buf = STREAM_DATA(s) + stream_get_endp(s);
		buf_end = buf + STREAM_WRITEABLE(s);

		dest = TAILQ_FIRST(&zfpm_g->dest_q);
		if (!dest)
			break;

		assert(CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM));

		hdr = (fpm_msg_hdr_t *)buf;
		hdr->version = FPM_PROTO_VERSION;

		data = fpm_msg_data(hdr);

		re = zfpm_route_for_update(dest);
		is_add = re ? 1 : 0;

		write_msg = 1;

		/*
		 * If this is a route deletion, and we have not sent the route
		 * to
		 * the FPM previously, skip it.
		 */
		if (!is_add && !CHECK_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM)) {
			write_msg = 0;
			zfpm_g->stats.nop_deletes_skipped++;
		}

		if (write_msg) {
			data_len = zfpm_encode_route(dest, re, (char *)data,
						     buf_end - data, &msg_type);

			assert(data_len);
			if (data_len) {
				hdr->msg_type = msg_type;
				msg_len = fpm_data_len_to_msg_len(data_len);
				hdr->msg_len = htons(msg_len);
				stream_forward_endp(s, msg_len);

				if (is_add)
					zfpm_g->stats.route_adds++;
				else
					zfpm_g->stats.route_dels++;
			}
		}

		/*
		 * Remove the dest from the queue, and reset the flag.
		 */
		UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		TAILQ_REMOVE(&zfpm_g->dest_q, dest, fpm_q_entries);

		if (is_add) {
			SET_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM);
		} else {
			UNSET_FLAG(dest->flags, RIB_DEST_SENT_TO_FPM);
		}

		/*
		 * Delete the destination if necessary.
		 */
		if (rib_gc_dest(dest->rnode))
			zfpm_g->stats.dests_del_after_update++;

	} while (1);
}

/*
 * zfpm_write_cb
 */
static int zfpm_write_cb(struct thread *thread)
{
	struct stream *s;
	int num_writes;

	zfpm_g->stats.write_cb_calls++;
	zfpm_g->t_write = NULL;

	/*
	 * Check if async connect is now done.
	 */
	if (zfpm_g->state == ZFPM_STATE_CONNECTING) {
		zfpm_connect_check();
		return 0;
	}

	assert(zfpm_g->state == ZFPM_STATE_ESTABLISHED);
	assert(zfpm_g->sock >= 0);

	num_writes = 0;

	do {
		int bytes_to_write, bytes_written;

		s = zfpm_g->obuf;

		/*
		 * If the stream is empty, try fill it up with data.
		 */
		if (stream_empty(s)) {
			zfpm_build_updates();
		}

		bytes_to_write = stream_get_endp(s) - stream_get_getp(s);
		if (!bytes_to_write)
			break;

		bytes_written =
			write(zfpm_g->sock, stream_pnt(s), bytes_to_write);
		zfpm_g->stats.write_calls++;
		num_writes++;

		if (bytes_written < 0) {
			if (ERRNO_IO_RETRY(errno))
				break;

			zfpm_connection_down("failed to write to socket");
			return 0;
		}

		if (bytes_written != bytes_to_write) {

			/*
			 * Partial write.
			 */
			stream_forward_getp(s, bytes_written);
			zfpm_g->stats.partial_writes++;
			break;
		}

		/*
		 * We've written out the entire contents of the stream.
		 */
		stream_reset(s);

		if (num_writes >= ZFPM_MAX_WRITES_PER_RUN) {
			zfpm_g->stats.max_writes_hit++;
			break;
		}

		if (zfpm_thread_should_yield(thread)) {
			zfpm_g->stats.t_write_yields++;
			break;
		}
	} while (1);

	if (zfpm_writes_pending())
		zfpm_write_on();

	return 0;
}

/*
 * zfpm_connect_cb
 */
static int zfpm_connect_cb(struct thread *t)
{
	int sock, ret;
	struct sockaddr_in serv;

	zfpm_g->t_connect = NULL;
	assert(zfpm_g->state == ZFPM_STATE_ACTIVE);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		zfpm_debug("Failed to create socket for connect(): %s",
			   strerror(errno));
		zfpm_g->stats.connect_no_sock++;
		return 0;
	}

	set_nonblocking(sock);

	/* Make server socket. */
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(zfpm_g->fpm_port);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	serv.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	if (!zfpm_g->fpm_server)
		serv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		serv.sin_addr.s_addr = (zfpm_g->fpm_server);

	/*
	 * Connect to the FPM.
	 */
	zfpm_g->connect_calls++;
	zfpm_g->stats.connect_calls++;
	zfpm_g->last_connect_call_time = monotime(NULL);

	ret = connect(sock, (struct sockaddr *)&serv, sizeof(serv));
	if (ret >= 0) {
		zfpm_g->sock = sock;
		zfpm_connection_up("connect succeeded");
		return 1;
	}

	if (errno == EINPROGRESS) {
		zfpm_g->sock = sock;
		zfpm_read_on();
		zfpm_write_on();
		zfpm_set_state(ZFPM_STATE_CONNECTING,
			       "async connect in progress");
		return 0;
	}

	zlog_info("can't connect to FPM %d: %s", sock, safe_strerror(errno));
	close(sock);

	/*
	 * Restart timer for retrying connection.
	 */
	zfpm_start_connect_timer("connect() failed");
	return 0;
}

/*
 * zfpm_set_state
 *
 * Move state machine into the given state.
 */
static void zfpm_set_state(zfpm_state_t state, const char *reason)
{
	zfpm_state_t cur_state = zfpm_g->state;

	if (!reason)
		reason = "Unknown";

	if (state == cur_state)
		return;

	zfpm_debug("beginning state transition %s -> %s. Reason: %s",
		   zfpm_state_to_str(cur_state), zfpm_state_to_str(state),
		   reason);

	switch (state) {

	case ZFPM_STATE_IDLE:
		assert(cur_state == ZFPM_STATE_ESTABLISHED);
		break;

	case ZFPM_STATE_ACTIVE:
		assert(cur_state == ZFPM_STATE_IDLE
		       || cur_state == ZFPM_STATE_CONNECTING);
		assert(zfpm_g->t_connect);
		break;

	case ZFPM_STATE_CONNECTING:
		assert(zfpm_g->sock);
		assert(cur_state == ZFPM_STATE_ACTIVE);
		assert(zfpm_g->t_read);
		assert(zfpm_g->t_write);
		break;

	case ZFPM_STATE_ESTABLISHED:
		assert(cur_state == ZFPM_STATE_ACTIVE
		       || cur_state == ZFPM_STATE_CONNECTING);
		assert(zfpm_g->sock);
		assert(zfpm_g->t_read);
		assert(zfpm_g->t_write);
		break;
	}

	zfpm_g->state = state;
}

/*
 * zfpm_calc_connect_delay
 *
 * Returns the number of seconds after which we should attempt to
 * reconnect to the FPM.
 */
static long zfpm_calc_connect_delay(void)
{
	time_t elapsed;

	/*
	 * Return 0 if this is our first attempt to connect.
	 */
	if (zfpm_g->connect_calls == 0) {
		return 0;
	}

	elapsed = zfpm_get_elapsed_time(zfpm_g->last_connect_call_time);

	if (elapsed > ZFPM_CONNECT_RETRY_IVL) {
		return 0;
	}

	return ZFPM_CONNECT_RETRY_IVL - elapsed;
}

/*
 * zfpm_start_connect_timer
 */
static void zfpm_start_connect_timer(const char *reason)
{
	long delay_secs;

	assert(!zfpm_g->t_connect);
	assert(zfpm_g->sock < 0);

	assert(zfpm_g->state == ZFPM_STATE_IDLE
	       || zfpm_g->state == ZFPM_STATE_ACTIVE
	       || zfpm_g->state == ZFPM_STATE_CONNECTING);

	delay_secs = zfpm_calc_connect_delay();
	zfpm_debug("scheduling connect in %ld seconds", delay_secs);

	thread_add_timer(zfpm_g->master, zfpm_connect_cb, 0, delay_secs,
			 &zfpm_g->t_connect);
	zfpm_set_state(ZFPM_STATE_ACTIVE, reason);
}

/*
 * zfpm_is_enabled
 *
 * Returns TRUE if the zebra FPM module has been enabled.
 */
static inline int zfpm_is_enabled(void)
{
	return zfpm_g->enabled;
}

/*
 * zfpm_conn_is_up
 *
 * Returns TRUE if the connection to the FPM is up.
 */
static inline int zfpm_conn_is_up(void)
{
	if (zfpm_g->state != ZFPM_STATE_ESTABLISHED)
		return 0;

	assert(zfpm_g->sock >= 0);

	return 1;
}

/*
 * zfpm_trigger_update
 *
 * The zebra code invokes this function to indicate that we should
 * send an update to the FPM about the given route_node.
 */
static int zfpm_trigger_update(struct route_node *rn, const char *reason)
{
	rib_dest_t *dest;
	char buf[PREFIX_STRLEN];

	/*
	 * Ignore if the connection is down. We will update the FPM about
	 * all destinations once the connection comes up.
	 */
	if (!zfpm_conn_is_up())
		return 0;

	dest = rib_dest_from_rnode(rn);

	if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)) {
		zfpm_g->stats.redundant_triggers++;
		return 0;
	}

	if (reason) {
		zfpm_debug("%s triggering update to FPM - Reason: %s",
			   prefix2str(&rn->p, buf, sizeof(buf)), reason);
	}

	SET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
	TAILQ_INSERT_TAIL(&zfpm_g->dest_q, dest, fpm_q_entries);
	zfpm_g->stats.updates_triggered++;

	/*
	 * Make sure that writes are enabled.
	 */
	if (zfpm_g->t_write)
		return 0;

	zfpm_write_on();
	return 0;
}

/*
 * zfpm_stats_timer_cb
 */
static int zfpm_stats_timer_cb(struct thread *t)
{
	zfpm_g->t_stats = NULL;

	/*
	 * Remember the stats collected in the last interval for display
	 * purposes.
	 */
	zfpm_stats_copy(&zfpm_g->stats, &zfpm_g->last_ivl_stats);

	/*
	 * Add the current set of stats into the cumulative statistics.
	 */
	zfpm_stats_compose(&zfpm_g->cumulative_stats, &zfpm_g->stats,
			   &zfpm_g->cumulative_stats);

	/*
	 * Start collecting stats afresh over the next interval.
	 */
	zfpm_stats_reset(&zfpm_g->stats);

	zfpm_start_stats_timer();

	return 0;
}

/*
 * zfpm_stop_stats_timer
 */
static void zfpm_stop_stats_timer(void)
{
	if (!zfpm_g->t_stats)
		return;

	zfpm_debug("Stopping existing stats timer");
	THREAD_TIMER_OFF(zfpm_g->t_stats);
}

/*
 * zfpm_start_stats_timer
 */
void zfpm_start_stats_timer(void)
{
	assert(!zfpm_g->t_stats);

	thread_add_timer(zfpm_g->master, zfpm_stats_timer_cb, 0,
			 ZFPM_STATS_IVL_SECS, &zfpm_g->t_stats);
}

/*
 * Helper macro for zfpm_show_stats() below.
 */
#define ZFPM_SHOW_STAT(counter)                                                \
	do {                                                                   \
		vty_out(vty, "%-40s %10lu %16lu\n", #counter,                  \
			total_stats.counter, zfpm_g->last_ivl_stats.counter);  \
	} while (0)

/*
 * zfpm_show_stats
 */
static void zfpm_show_stats(struct vty *vty)
{
	zfpm_stats_t total_stats;
	time_t elapsed;

	vty_out(vty, "\n%-40s %10s     Last %2d secs\n\n", "Counter", "Total",
		ZFPM_STATS_IVL_SECS);

	/*
	 * Compute the total stats up to this instant.
	 */
	zfpm_stats_compose(&zfpm_g->cumulative_stats, &zfpm_g->stats,
			   &total_stats);

	ZFPM_SHOW_STAT(connect_calls);
	ZFPM_SHOW_STAT(connect_no_sock);
	ZFPM_SHOW_STAT(read_cb_calls);
	ZFPM_SHOW_STAT(write_cb_calls);
	ZFPM_SHOW_STAT(write_calls);
	ZFPM_SHOW_STAT(partial_writes);
	ZFPM_SHOW_STAT(max_writes_hit);
	ZFPM_SHOW_STAT(t_write_yields);
	ZFPM_SHOW_STAT(nop_deletes_skipped);
	ZFPM_SHOW_STAT(route_adds);
	ZFPM_SHOW_STAT(route_dels);
	ZFPM_SHOW_STAT(updates_triggered);
	ZFPM_SHOW_STAT(redundant_triggers);
	ZFPM_SHOW_STAT(dests_del_after_update);
	ZFPM_SHOW_STAT(t_conn_down_starts);
	ZFPM_SHOW_STAT(t_conn_down_dests_processed);
	ZFPM_SHOW_STAT(t_conn_down_yields);
	ZFPM_SHOW_STAT(t_conn_down_finishes);
	ZFPM_SHOW_STAT(t_conn_up_starts);
	ZFPM_SHOW_STAT(t_conn_up_dests_processed);
	ZFPM_SHOW_STAT(t_conn_up_yields);
	ZFPM_SHOW_STAT(t_conn_up_aborts);
	ZFPM_SHOW_STAT(t_conn_up_finishes);

	if (!zfpm_g->last_stats_clear_time)
		return;

	elapsed = zfpm_get_elapsed_time(zfpm_g->last_stats_clear_time);

	vty_out(vty, "\nStats were cleared %lu seconds ago\n",
		(unsigned long)elapsed);
}

/*
 * zfpm_clear_stats
 */
static void zfpm_clear_stats(struct vty *vty)
{
	if (!zfpm_is_enabled()) {
		vty_out(vty, "The FPM module is not enabled...\n");
		return;
	}

	zfpm_stats_reset(&zfpm_g->stats);
	zfpm_stats_reset(&zfpm_g->last_ivl_stats);
	zfpm_stats_reset(&zfpm_g->cumulative_stats);

	zfpm_stop_stats_timer();
	zfpm_start_stats_timer();

	zfpm_g->last_stats_clear_time = monotime(NULL);

	vty_out(vty, "Cleared FPM stats\n");
}

/*
 * show_zebra_fpm_stats
 */
DEFUN (show_zebra_fpm_stats,
       show_zebra_fpm_stats_cmd,
       "show zebra fpm stats",
       SHOW_STR
       ZEBRA_STR
       "Forwarding Path Manager information\n"
       "Statistics\n")
{
	zfpm_show_stats(vty);
	return CMD_SUCCESS;
}

/*
 * clear_zebra_fpm_stats
 */
DEFUN (clear_zebra_fpm_stats,
       clear_zebra_fpm_stats_cmd,
       "clear zebra fpm stats",
       CLEAR_STR
       ZEBRA_STR
       "Clear Forwarding Path Manager information\n"
       "Statistics\n")
{
	zfpm_clear_stats(vty);
	return CMD_SUCCESS;
}

/*
 * update fpm connection information
 */
DEFUN ( fpm_remote_ip,
       fpm_remote_ip_cmd,
        "fpm connection ip A.B.C.D port (1-65535)",
        "fpm connection remote ip and port\n"
        "Remote fpm server ip A.B.C.D\n"
        "Enter ip ")
{

	in_addr_t fpm_server;
	uint32_t port_no;

	fpm_server = inet_addr(argv[3]->arg);
	if (fpm_server == INADDR_NONE)
		return CMD_ERR_INCOMPLETE;

	port_no = atoi(argv[5]->arg);
	if (port_no < TCP_MIN_PORT || port_no > TCP_MAX_PORT)
		return CMD_ERR_INCOMPLETE;

	zfpm_g->fpm_server = fpm_server;
	zfpm_g->fpm_port = port_no;


	return CMD_SUCCESS;
}

DEFUN ( no_fpm_remote_ip,
       no_fpm_remote_ip_cmd,
        "no fpm connection ip A.B.C.D port (1-65535)",
        "fpm connection remote ip and port\n"
        "Connection\n"
        "Remote fpm server ip A.B.C.D\n"
        "Enter ip ")
{
	if (zfpm_g->fpm_server != inet_addr(argv[4]->arg)
	    || zfpm_g->fpm_port != atoi(argv[6]->arg))
		return CMD_ERR_NO_MATCH;

	zfpm_g->fpm_server = FPM_DEFAULT_IP;
	zfpm_g->fpm_port = FPM_DEFAULT_PORT;

	return CMD_SUCCESS;
}

/*
 * zfpm_init_message_format
 */
static inline void zfpm_init_message_format(const char *format)
{
	int have_netlink, have_protobuf;

#ifdef HAVE_NETLINK
	have_netlink = 1;
#else
	have_netlink = 0;
#endif

#ifdef HAVE_PROTOBUF
	have_protobuf = 1;
#else
	have_protobuf = 0;
#endif

	zfpm_g->message_format = ZFPM_MSG_FORMAT_NONE;

	if (!format) {
		if (have_netlink) {
			zfpm_g->message_format = ZFPM_MSG_FORMAT_NETLINK;
		} else if (have_protobuf) {
			zfpm_g->message_format = ZFPM_MSG_FORMAT_PROTOBUF;
		}
		return;
	}

	if (!strcmp("netlink", format)) {
		if (!have_netlink) {
			zlog_err("FPM netlink message format is not available");
			return;
		}
		zfpm_g->message_format = ZFPM_MSG_FORMAT_NETLINK;
		return;
	}

	if (!strcmp("protobuf", format)) {
		if (!have_protobuf) {
			zlog_err(
				"FPM protobuf message format is not available");
			return;
		}
		zfpm_g->message_format = ZFPM_MSG_FORMAT_PROTOBUF;
		return;
	}

	zlog_warn("Unknown fpm format '%s'", format);
}

/**
 * fpm_remote_srv_write
 *
 * Module to write remote fpm connection
 *
 * Returns ZERO on success.
 */

static int fpm_remote_srv_write(struct vty *vty)
{
	struct in_addr in;

	in.s_addr = zfpm_g->fpm_server;

	if ((zfpm_g->fpm_server != FPM_DEFAULT_IP
	     && zfpm_g->fpm_server != INADDR_ANY)
	    || (zfpm_g->fpm_port != FPM_DEFAULT_PORT && zfpm_g->fpm_port != 0))
		vty_out(vty, "fpm connection ip %s port %d\n", inet_ntoa(in),
			zfpm_g->fpm_port);

	return 0;
}


/* Zebra node  */
static struct cmd_node zebra_node = {ZEBRA_NODE, "", 1};


/**
 * zfpm_init
 *
 * One-time initialization of the Zebra FPM module.
 *
 * @param[in] port port at which FPM is running.
 * @param[in] enable TRUE if the zebra FPM module should be enabled
 * @param[in] format to use to talk to the FPM. Can be 'netink' or 'protobuf'.
 *
 * Returns TRUE on success.
 */
static int zfpm_init(struct thread_master *master)
{
	int enable = 1;
	uint16_t port = 0;
	const char *format = THIS_MODULE->load_args;

	memset(zfpm_g, 0, sizeof(*zfpm_g));
	zfpm_g->master = master;
	TAILQ_INIT(&zfpm_g->dest_q);
	zfpm_g->sock = -1;
	zfpm_g->state = ZFPM_STATE_IDLE;

	zfpm_stats_init(&zfpm_g->stats);
	zfpm_stats_init(&zfpm_g->last_ivl_stats);
	zfpm_stats_init(&zfpm_g->cumulative_stats);

	install_node(&zebra_node, fpm_remote_srv_write);
	install_element(ENABLE_NODE, &show_zebra_fpm_stats_cmd);
	install_element(ENABLE_NODE, &clear_zebra_fpm_stats_cmd);
	install_element(CONFIG_NODE, &fpm_remote_ip_cmd);
	install_element(CONFIG_NODE, &no_fpm_remote_ip_cmd);

	zfpm_init_message_format(format);

	/*
	 * Disable FPM interface if no suitable format is available.
	 */
	if (zfpm_g->message_format == ZFPM_MSG_FORMAT_NONE)
		enable = 0;

	zfpm_g->enabled = enable;

	if (!zfpm_g->fpm_server)
		zfpm_g->fpm_server = FPM_DEFAULT_IP;

	if (!port)
		port = FPM_DEFAULT_PORT;

	zfpm_g->fpm_port = port;

	zfpm_g->obuf = stream_new(ZFPM_OBUF_SIZE);
	zfpm_g->ibuf = stream_new(ZFPM_IBUF_SIZE);

	zfpm_start_stats_timer();
	zfpm_start_connect_timer("initialized");
	return 0;
}

static int zebra_fpm_module_init(void)
{
	hook_register(rib_update, zfpm_trigger_update);
	hook_register(frr_late_init, zfpm_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "zebra_fpm", .version = FRR_VERSION,
		 .description = "zebra FPM (Forwarding Plane Manager) module",
		 .init = zebra_fpm_module_init, )
