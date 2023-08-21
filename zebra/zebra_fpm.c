// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Main implementation file for interface to Forwarding Plane Manager.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 */

#include <zebra.h>

#include "log.h"
#include "libfrr.h"
#include "stream.h"
#include "frrevent.h"
#include "network.h"
#include "command.h"
#include "lib/version.h"
#include "jhash.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_errors.h"

#include "fpm/fpm.h"
#include "zebra_fpm_private.h"
#include "zebra/zebra_router.h"
#include "zebra_vxlan_private.h"

DEFINE_MTYPE_STATIC(ZEBRA, FPM_MAC_INFO, "FPM_MAC_INFO");

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
#define FPM_MAX_MAC_MSG_LEN 512

static void zfpm_iterate_rmac_table(struct hash_bucket *bucket, void *args);

/*
 * Structure that holds state for iterating over all route_node
 * structures that are candidates for being communicated to the FPM.
 */
struct zfpm_rnodes_iter {
	rib_tables_iter_t tables_iter;
	route_table_iter_t iter;
};

/*
 * Statistics.
 */
struct zfpm_stats {
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
};

/*
 * States for the FPM state machine.
 */
enum zfpm_state {

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

};

/*
 * Message format to be used to communicate with the FPM.
 */
enum zfpm_msg_format {
	ZFPM_MSG_FORMAT_NONE,
	ZFPM_MSG_FORMAT_NETLINK,
	ZFPM_MSG_FORMAT_PROTOBUF,
};

/*
 * Globals.
 */
struct zfpm_glob {

	/*
	 * True if the FPM module has been enabled.
	 */
	int enabled;

	/*
	 * Message format to be used to communicate with the fpm.
	 */
	enum zfpm_msg_format message_format;

	struct event_loop *master;

	enum zfpm_state state;

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
	 * List of fpm_mac_info structures to be processed
	 */
	TAILQ_HEAD(zfpm_mac_q, fpm_mac_info_t) mac_q;

	/*
	 * Hash table of fpm_mac_info_t entries
	 *
	 * While adding fpm_mac_info_t for a MAC to the mac_q,
	 * it is possible that another fpm_mac_info_t node for the this MAC
	 * is already present in the queue.
	 * This is possible in the case of consecutive add->delete operations.
	 * To avoid such duplicate insertions in the mac_q,
	 * define a hash table for fpm_mac_info_t which can be looked up
	 * to see if an fpm_mac_info_t node for a MAC is already present
	 * in the mac_q.
	 */
	struct hash *fpm_mac_info_table;

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
	struct event *t_connect;
	struct event *t_write;
	struct event *t_read;

	/*
	 * Thread to clean up after the TCP connection to the FPM goes down
	 * and the state that belongs to it.
	 */
	struct event *t_conn_down;

	struct {
		struct zfpm_rnodes_iter iter;
	} t_conn_down_state;

	/*
	 * Thread to take actions once the TCP conn to the FPM comes up, and
	 * the state that belongs to it.
	 */
	struct event *t_conn_up;

	struct {
		struct zfpm_rnodes_iter iter;
	} t_conn_up_state;

	unsigned long connect_calls;
	time_t last_connect_call_time;

	/*
	 * Stats from the start of the current statistics interval up to
	 * now. These are the counters we typically update in the code.
	 */
	struct zfpm_stats stats;

	/*
	 * Statistics that were gathered in the last collection interval.
	 */
	struct zfpm_stats last_ivl_stats;

	/*
	 * Cumulative stats from the last clear to the start of the current
	 * statistics interval.
	 */
	struct zfpm_stats cumulative_stats;

	/*
	 * Stats interval timer.
	 */
	struct event *t_stats;

	/*
	 * If non-zero, the last time when statistics were cleared.
	 */
	time_t last_stats_clear_time;

	/*
	 * Flag to track the MAC dump status to FPM
	 */
	bool fpm_mac_dump_done;
};

static struct zfpm_glob zfpm_glob_space;
static struct zfpm_glob *zfpm_g = &zfpm_glob_space;

static int zfpm_trigger_update(struct route_node *rn, const char *reason);

static void zfpm_read_cb(struct event *thread);
static void zfpm_write_cb(struct event *thread);

static void zfpm_set_state(enum zfpm_state state, const char *reason);
static void zfpm_start_connect_timer(const char *reason);
static void zfpm_start_stats_timer(void);
static void zfpm_mac_info_del(struct fpm_mac_info_t *fpm_mac);

static const char ipv4_ll_buf[16] = "169.254.0.1";
union g_addr ipv4ll_gateway;

/*
 * zfpm_thread_should_yield
 */
static inline int zfpm_thread_should_yield(struct event *t)
{
	return event_should_yield(t);
}

/*
 * zfpm_state_to_str
 */
static const char *zfpm_state_to_str(enum zfpm_state state)
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
static inline void zfpm_rnodes_iter_init(struct zfpm_rnodes_iter *iter)
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
static inline struct route_node *
zfpm_rnodes_iter_next(struct zfpm_rnodes_iter *iter)
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
static inline void zfpm_rnodes_iter_pause(struct zfpm_rnodes_iter *iter)
{
	route_table_iter_pause(&iter->iter);
}

/*
 * zfpm_rnodes_iter_cleanup
 */
static inline void zfpm_rnodes_iter_cleanup(struct zfpm_rnodes_iter *iter)
{
	route_table_iter_cleanup(&iter->iter);
	rib_tables_iter_cleanup(&iter->tables_iter);
}

/*
 * zfpm_stats_init
 *
 * Initialize a statistics block.
 */
static inline void zfpm_stats_init(struct zfpm_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

/*
 * zfpm_stats_reset
 */
static inline void zfpm_stats_reset(struct zfpm_stats *stats)
{
	zfpm_stats_init(stats);
}

/*
 * zfpm_stats_copy
 */
static inline void zfpm_stats_copy(const struct zfpm_stats *src,
				   struct zfpm_stats *dest)
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
static void zfpm_stats_compose(const struct zfpm_stats *s1,
			       const struct zfpm_stats *s2,
			       struct zfpm_stats *result)
{
	const unsigned long *p1, *p2;
	unsigned long *result_p;
	int i, num_counters;

	p1 = (const unsigned long *)s1;
	p2 = (const unsigned long *)s2;
	result_p = (unsigned long *)result;

	num_counters = (sizeof(struct zfpm_stats) / sizeof(unsigned long));

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

	event_add_read(zfpm_g->master, zfpm_read_cb, 0, zfpm_g->sock,
		       &zfpm_g->t_read);
}

/*
 * zfpm_write_on
 */
static inline void zfpm_write_on(void)
{
	assert(!zfpm_g->t_write);
	assert(zfpm_g->sock >= 0);

	event_add_write(zfpm_g->master, zfpm_write_cb, 0, zfpm_g->sock,
			&zfpm_g->t_write);
}

/*
 * zfpm_read_off
 */
static inline void zfpm_read_off(void)
{
	EVENT_OFF(zfpm_g->t_read);
}

/*
 * zfpm_write_off
 */
static inline void zfpm_write_off(void)
{
	EVENT_OFF(zfpm_g->t_write);
}

static inline void zfpm_connect_off(void)
{
	EVENT_OFF(zfpm_g->t_connect);
}

static inline void zfpm_conn_down_off(void)
{
	EVENT_OFF(zfpm_g->t_conn_down);
}

/*
 * zfpm_conn_up_thread_cb
 *
 * Callback for actions to be taken when the connection to the FPM
 * comes up.
 */
static void zfpm_conn_up_thread_cb(struct event *thread)
{
	struct route_node *rnode;
	struct zfpm_rnodes_iter *iter;
	rib_dest_t *dest;

	iter = &zfpm_g->t_conn_up_state.iter;

	if (zfpm_g->state != ZFPM_STATE_ESTABLISHED) {
		zfpm_debug(
			"Connection not up anymore, conn_up thread aborting");
		zfpm_g->stats.t_conn_up_aborts++;
		goto done;
	}

	if (!zfpm_g->fpm_mac_dump_done) {
		/* Enqueue FPM updates for all the RMAC entries */
		hash_iterate(zrouter.l3vni_table, zfpm_iterate_rmac_table,
			     NULL);
		/* mark dump done so that its not repeated after yield */
		zfpm_g->fpm_mac_dump_done = true;
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
		event_add_timer_msec(zfpm_g->master, zfpm_conn_up_thread_cb,
				     NULL, 0, &zfpm_g->t_conn_up);
		return;
	}

	zfpm_g->stats.t_conn_up_finishes++;

done:
	zfpm_rnodes_iter_cleanup(iter);
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
	EVENT_OFF(zfpm_g->t_conn_up);

	zfpm_rnodes_iter_init(&zfpm_g->t_conn_up_state.iter);
	zfpm_g->fpm_mac_dump_done = false;

	zfpm_debug("Starting conn_up thread");

	event_add_timer_msec(zfpm_g->master, zfpm_conn_up_thread_cb, NULL, 0,
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
static void zfpm_conn_down_thread_cb(struct event *thread)
{
	struct route_node *rnode;
	struct zfpm_rnodes_iter *iter;
	rib_dest_t *dest;
	struct fpm_mac_info_t *mac = NULL;

	assert(zfpm_g->state == ZFPM_STATE_IDLE);

	/*
	 * Delink and free all fpm_mac_info_t nodes
	 * in the mac_q and fpm_mac_info_hash
	 */
	while ((mac = TAILQ_FIRST(&zfpm_g->mac_q)) != NULL)
		zfpm_mac_info_del(mac);

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
		event_add_timer_msec(zfpm_g->master, zfpm_conn_down_thread_cb,
				     NULL, 0, &zfpm_g->t_conn_down);
		return;
	}

	zfpm_g->stats.t_conn_down_finishes++;
	zfpm_rnodes_iter_cleanup(iter);

	/*
	 * Start the process of connecting to the FPM again.
	 */
	zfpm_start_connect_timer("cleanup complete");
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
	zfpm_rnodes_iter_init(&zfpm_g->t_conn_down_state.iter);
	zfpm_conn_down_off();
	event_add_timer_msec(zfpm_g->master, zfpm_conn_down_thread_cb, NULL, 0,
			     &zfpm_g->t_conn_down);
	zfpm_g->stats.t_conn_down_starts++;

	zfpm_set_state(ZFPM_STATE_IDLE, detail);
}

/*
 * zfpm_read_cb
 */
static void zfpm_read_cb(struct event *thread)
{
	size_t already;
	struct stream *ibuf;
	uint16_t msg_len;
	fpm_msg_hdr_t *hdr;

	zfpm_g->stats.read_cb_calls++;

	/*
	 * Check if async connect is now done.
	 */
	if (zfpm_g->state == ZFPM_STATE_CONNECTING) {
		zfpm_connect_check();
		return;
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

				snprintf(buffer, sizeof(buffer),
					 "closed socket in read(%d): %s", errno,
					 safe_strerror(errno));
				zfpm_connection_down(buffer);
			} else
				zfpm_connection_down("closed socket in read");
			return;
		}

		if (nbyte != (ssize_t)(FPM_MSG_HDR_LEN - already))
			goto done;

		already = FPM_MSG_HDR_LEN;
	}

	stream_set_getp(ibuf, 0);

	hdr = (fpm_msg_hdr_t *)stream_pnt(ibuf);

	if (!fpm_msg_hdr_ok(hdr)) {
		zfpm_connection_down("invalid message header");
		return;
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

				snprintf(buffer, sizeof(buffer),
					 "failed to read message(%d) %s", errno,
					 safe_strerror(errno));
				zfpm_connection_down(buffer);
			} else
				zfpm_connection_down("failed to read message");
			return;
		}

		if (nbyte != (ssize_t)(msg_len - already))
			goto done;
	}

	/*
	 * Just throw it away for now.
	 */
	stream_reset(ibuf);

done:
	zfpm_read_on();
}

static bool zfpm_updates_pending(void)
{
	if (!(TAILQ_EMPTY(&zfpm_g->dest_q)) || !(TAILQ_EMPTY(&zfpm_g->mac_q)))
		return true;

	return false;
}

/*
 * zfpm_writes_pending
 *
 * Returns true if we may have something to write to the FPM.
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
	 * Check if there are any updates scheduled on the outbound queues.
	 */
	if (zfpm_updates_pending())
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
#endif /* HAVE_NETLINK */
		break;

	case ZFPM_MSG_FORMAT_NONE:
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
 * Define an enum for return codes for queue processing functions
 *
 * FPM_WRITE_STOP: This return code indicates that the write buffer is full.
 * Stop processing all the queues and empty the buffer by writing its content
 * to the socket.
 *
 * FPM_GOTO_NEXT_Q: This return code indicates that either this queue is
 * empty or we have processed enough updates from this queue.
 * So, move on to the next queue.
 */
enum {
	FPM_WRITE_STOP = 0,
	FPM_GOTO_NEXT_Q = 1
};

#define FPM_QUEUE_PROCESS_LIMIT 10000

/*
 * zfpm_build_route_updates
 *
 * Process the dest_q queue and write FPM messages to the outbound buffer.
 */
static int zfpm_build_route_updates(void)
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
	uint16_t q_limit;

	if (TAILQ_EMPTY(&zfpm_g->dest_q))
		return FPM_GOTO_NEXT_Q;

	s = zfpm_g->obuf;
	q_limit = FPM_QUEUE_PROCESS_LIMIT;

	do  {
		/*
		 * Make sure there is enough space to write another message.
		 */
		if (STREAM_WRITEABLE(s) < FPM_MAX_MSG_LEN)
			return FPM_WRITE_STOP;

		buf = STREAM_DATA(s) + stream_get_endp(s);
		buf_end = buf + STREAM_WRITEABLE(s);

		dest = TAILQ_FIRST(&zfpm_g->dest_q);
		if (!dest)
			return FPM_GOTO_NEXT_Q;

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

			if (data_len) {
				hdr->msg_type = msg_type;
				msg_len = fpm_data_len_to_msg_len(data_len);
				hdr->msg_len = htons(msg_len);
				stream_forward_endp(s, msg_len);

				if (is_add)
					zfpm_g->stats.route_adds++;
				else
					zfpm_g->stats.route_dels++;
			} else {
				zlog_err("%s: Encoding Prefix: %pRN No valid nexthops",
					 __func__, dest->rnode);
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

		q_limit--;
		if (q_limit == 0) {
			/*
			 * We have processed enough updates in this queue.
			 * Now yield for other queues.
			 */
			return FPM_GOTO_NEXT_Q;
		}
	} while (true);
}

/*
 * zfpm_encode_mac
 *
 * Encode a message to FPM with information about the given MAC.
 *
 * Returns the number of bytes written to the buffer.
 */
static inline int zfpm_encode_mac(struct fpm_mac_info_t *mac, char *in_buf,
				size_t in_buf_len, fpm_msg_type_e *msg_type)
{
	size_t len = 0;

	*msg_type = FPM_MSG_TYPE_NONE;

	switch (zfpm_g->message_format) {

	case ZFPM_MSG_FORMAT_NONE:
		break;
	case ZFPM_MSG_FORMAT_NETLINK:
#ifdef HAVE_NETLINK
		len = zfpm_netlink_encode_mac(mac, in_buf, in_buf_len);
		assert(fpm_msg_align(len) == len);
		*msg_type = FPM_MSG_TYPE_NETLINK;
#endif /* HAVE_NETLINK */
		break;
	case ZFPM_MSG_FORMAT_PROTOBUF:
		break;
	}
	return len;
}

static int zfpm_build_mac_updates(void)
{
	struct stream *s;
	struct fpm_mac_info_t *mac;
	unsigned char *buf, *data, *buf_end;
	fpm_msg_hdr_t *hdr;
	size_t data_len, msg_len;
	fpm_msg_type_e msg_type;
	uint16_t q_limit;

	if (TAILQ_EMPTY(&zfpm_g->mac_q))
		return FPM_GOTO_NEXT_Q;

	s = zfpm_g->obuf;
	q_limit = FPM_QUEUE_PROCESS_LIMIT;

	do  {
		/* Make sure there is enough space to write another message. */
		if (STREAM_WRITEABLE(s) < FPM_MAX_MAC_MSG_LEN)
			return FPM_WRITE_STOP;

		buf = STREAM_DATA(s) + stream_get_endp(s);
		buf_end = buf + STREAM_WRITEABLE(s);

		mac = TAILQ_FIRST(&zfpm_g->mac_q);
		if (!mac)
			return FPM_GOTO_NEXT_Q;

		/* Check for no-op */
		if (!CHECK_FLAG(mac->fpm_flags, ZEBRA_MAC_UPDATE_FPM)) {
			zfpm_g->stats.nop_deletes_skipped++;
			zfpm_mac_info_del(mac);
			continue;
		}

		hdr = (fpm_msg_hdr_t *)buf;
		hdr->version = FPM_PROTO_VERSION;

		data = fpm_msg_data(hdr);
		data_len = zfpm_encode_mac(mac, (char *)data, buf_end - data,
						&msg_type);
		assert(data_len);

		hdr->msg_type = msg_type;
		msg_len = fpm_data_len_to_msg_len(data_len);
		hdr->msg_len = htons(msg_len);
		stream_forward_endp(s, msg_len);

		/* Remove the MAC from the queue, and delete it. */
		zfpm_mac_info_del(mac);

		q_limit--;
		if (q_limit == 0) {
			/*
			 * We have processed enough updates in this queue.
			 * Now yield for other queues.
			 */
			return FPM_GOTO_NEXT_Q;
		}
	} while (1);
}

/*
 * zfpm_build_updates
 *
 * Process the outgoing queues and write messages to the outbound
 * buffer.
 */
static void zfpm_build_updates(void)
{
	struct stream *s;

	s = zfpm_g->obuf;
	assert(stream_empty(s));

	do {
		/*
		 * Stop processing the queues if zfpm_g->obuf is full
		 * or we do not have more updates to process
		 */
		if (zfpm_build_mac_updates() == FPM_WRITE_STOP)
			break;
		if (zfpm_build_route_updates() == FPM_WRITE_STOP)
			break;
	} while (zfpm_updates_pending());
}

/*
 * zfpm_write_cb
 */
static void zfpm_write_cb(struct event *thread)
{
	struct stream *s;
	int num_writes;

	zfpm_g->stats.write_cb_calls++;

	/*
	 * Check if async connect is now done.
	 */
	if (zfpm_g->state == ZFPM_STATE_CONNECTING) {
		zfpm_connect_check();
		return;
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
			return;
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
}

/*
 * zfpm_connect_cb
 */
static void zfpm_connect_cb(struct event *t)
{
	int sock, ret;
	struct sockaddr_in serv;

	assert(zfpm_g->state == ZFPM_STATE_ACTIVE);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		zlog_err("Failed to create socket for connect(): %s",
			   strerror(errno));
		zfpm_g->stats.connect_no_sock++;
		return;
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
		return;
	}

	if (errno == EINPROGRESS) {
		zfpm_g->sock = sock;
		zfpm_read_on();
		zfpm_write_on();
		zfpm_set_state(ZFPM_STATE_CONNECTING,
			       "async connect in progress");
		return;
	}

	zlog_info("can't connect to FPM %d: %s", sock, safe_strerror(errno));
	close(sock);

	/*
	 * Restart timer for retrying connection.
	 */
	zfpm_start_connect_timer("connect() failed");
}

/*
 * zfpm_set_state
 *
 * Move state machine into the given state.
 */
static void zfpm_set_state(enum zfpm_state state, const char *reason)
{
	enum zfpm_state cur_state = zfpm_g->state;

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

	event_add_timer(zfpm_g->master, zfpm_connect_cb, 0, delay_secs,
			&zfpm_g->t_connect);
	zfpm_set_state(ZFPM_STATE_ACTIVE, reason);
}

/*
 * zfpm_is_enabled
 *
 * Returns true if the zebra FPM module has been enabled.
 */
static inline int zfpm_is_enabled(void)
{
	return zfpm_g->enabled;
}

/*
 * zfpm_conn_is_up
 *
 * Returns true if the connection to the FPM is up.
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
		zfpm_debug("%pFX triggering update to FPM - Reason: %s", &rn->p,
			   reason);
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
 * zfpm_trigger_remove
 *
 * The zebra code invokes this function to indicate that we should
 * send an remove to the FPM about the given route_node.
 */

static int zfpm_trigger_remove(struct route_node *rn)
{
	rib_dest_t *dest;

	if (!zfpm_conn_is_up())
		return 0;

	dest = rib_dest_from_rnode(rn);
	if (!CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM))
		return 0;

	zfpm_debug("%pRN Removing from update queue shutting down", rn);

	UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
	TAILQ_REMOVE(&zfpm_g->dest_q, dest, fpm_q_entries);

	return 0;
}

/*
 * Generate Key for FPM MAC info hash entry
 */
static unsigned int zfpm_mac_info_hash_keymake(const void *p)
{
	struct fpm_mac_info_t *fpm_mac = (struct fpm_mac_info_t *)p;
	uint32_t mac_key;

	mac_key = jhash(fpm_mac->macaddr.octet, ETH_ALEN, 0xa5a5a55a);

	return jhash_2words(mac_key, fpm_mac->vni, 0);
}

/*
 * Compare function for FPM MAC info hash lookup
 */
static bool zfpm_mac_info_cmp(const void *p1, const void *p2)
{
	const struct fpm_mac_info_t *fpm_mac1 = p1;
	const struct fpm_mac_info_t *fpm_mac2 = p2;

	if (memcmp(fpm_mac1->macaddr.octet, fpm_mac2->macaddr.octet, ETH_ALEN)
			!= 0)
		return false;
	if (fpm_mac1->vni != fpm_mac2->vni)
		return false;

	return true;
}

/*
 * Lookup FPM MAC info hash entry.
 */
static struct fpm_mac_info_t *zfpm_mac_info_lookup(struct fpm_mac_info_t *key)
{
	return hash_lookup(zfpm_g->fpm_mac_info_table, key);
}

/*
 * Callback to allocate fpm_mac_info_t structure.
 */
static void *zfpm_mac_info_alloc(void *p)
{
	const struct fpm_mac_info_t *key = p;
	struct fpm_mac_info_t *fpm_mac;

	fpm_mac = XCALLOC(MTYPE_FPM_MAC_INFO, sizeof(struct fpm_mac_info_t));

	memcpy(&fpm_mac->macaddr, &key->macaddr, ETH_ALEN);
	fpm_mac->vni = key->vni;

	return (void *)fpm_mac;
}

/*
 * Delink and free fpm_mac_info_t.
 */
static void zfpm_mac_info_del(struct fpm_mac_info_t *fpm_mac)
{
	hash_release(zfpm_g->fpm_mac_info_table, fpm_mac);
	TAILQ_REMOVE(&zfpm_g->mac_q, fpm_mac, fpm_mac_q_entries);
	XFREE(MTYPE_FPM_MAC_INFO, fpm_mac);
}

/*
 * zfpm_trigger_rmac_update
 *
 * Zebra code invokes this function to indicate that we should
 * send an update to FPM for given MAC entry.
 *
 * This function checks if we already have enqueued an update for this RMAC,
 * If yes, update the same fpm_mac_info_t. Else, create and enqueue an update.
 */
static int zfpm_trigger_rmac_update(struct zebra_mac *rmac,
				    struct zebra_l3vni *zl3vni, bool delete,
				    const char *reason)
{
	struct fpm_mac_info_t *fpm_mac, key;
	struct interface *vxlan_if, *svi_if;
	bool mac_found = false;

	/*
	 * Ignore if the connection is down. We will update the FPM about
	 * all destinations once the connection comes up.
	 */
	if (!zfpm_conn_is_up())
		return 0;

	if (reason) {
		zfpm_debug("triggering update to FPM - Reason: %s - %pEA",
			   reason, &rmac->macaddr);
	}

	vxlan_if = zl3vni_map_to_vxlan_if(zl3vni);
	svi_if = zl3vni_map_to_svi_if(zl3vni);

	memset(&key, 0, sizeof(key));

	memcpy(&key.macaddr, &rmac->macaddr, ETH_ALEN);
	key.vni = zl3vni->vni;

	/* Check if this MAC is already present in the queue. */
	fpm_mac = zfpm_mac_info_lookup(&key);

	if (fpm_mac) {
		mac_found = true;

		/*
		 * If the enqueued op is "add" and current op is "delete",
		 * this is a noop. So, Unset ZEBRA_MAC_UPDATE_FPM flag.
		 * While processing FPM queue, we will silently delete this
		 * MAC entry without sending any update for this MAC.
		 */
		if (!CHECK_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_DELETE_FPM) &&
		    delete == 1) {
			SET_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_DELETE_FPM);
			UNSET_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_UPDATE_FPM);
			return 0;
		}
	} else
		fpm_mac = hash_get(zfpm_g->fpm_mac_info_table, &key,
				   zfpm_mac_info_alloc);

	fpm_mac->r_vtep_ip.s_addr = rmac->fwd_info.r_vtep_ip.s_addr;
	fpm_mac->zebra_flags = rmac->flags;
	fpm_mac->vxlan_if = vxlan_if ? vxlan_if->ifindex : 0;
	fpm_mac->svi_if = svi_if ? svi_if->ifindex : 0;

	SET_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_UPDATE_FPM);
	if (delete)
		SET_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_DELETE_FPM);
	else
		UNSET_FLAG(fpm_mac->fpm_flags, ZEBRA_MAC_DELETE_FPM);

	if (!mac_found)
		TAILQ_INSERT_TAIL(&zfpm_g->mac_q, fpm_mac, fpm_mac_q_entries);

	zfpm_g->stats.updates_triggered++;

	/* If writes are already enabled, return. */
	if (zfpm_g->t_write)
		return 0;

	zfpm_write_on();
	return 0;
}

/*
 * This function is called when the FPM connections is established.
 * Iterate over all the RMAC entries for the given L3VNI
 * and enqueue the RMAC for FPM processing.
 */
static void zfpm_trigger_rmac_update_wrapper(struct hash_bucket *bucket,
					     void *args)
{
	struct zebra_mac *zrmac = (struct zebra_mac *)bucket->data;
	struct zebra_l3vni *zl3vni = (struct zebra_l3vni *)args;

	zfpm_trigger_rmac_update(zrmac, zl3vni, false, "RMAC added");
}

/*
 * This function is called when the FPM connections is established.
 * This function iterates over all the L3VNIs to trigger
 * FPM updates for RMACs currently available.
 */
static void zfpm_iterate_rmac_table(struct hash_bucket *bucket, void *args)
{
	struct zebra_l3vni *zl3vni = (struct zebra_l3vni *)bucket->data;

	hash_iterate(zl3vni->rmac_table, zfpm_trigger_rmac_update_wrapper,
		     (void *)zl3vni);
}

/*
 * struct zfpm_statsimer_cb
 */
static void zfpm_stats_timer_cb(struct event *t)
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
}

/*
 * zfpm_stop_stats_timer
 */
static void zfpm_stop_stats_timer(void)
{
	if (!zfpm_g->t_stats)
		return;

	zfpm_debug("Stopping existing stats timer");
	EVENT_OFF(zfpm_g->t_stats);
}

/*
 * zfpm_start_stats_timer
 */
void zfpm_start_stats_timer(void)
{
	assert(!zfpm_g->t_stats);

	event_add_timer(zfpm_g->master, zfpm_stats_timer_cb, 0,
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
	struct zfpm_stats total_stats;
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
DEFUN (fpm_remote_ip,
       fpm_remote_ip_cmd,
       "fpm connection ip A.B.C.D port (1-65535)",
       "Forwarding Path Manager\n"
       "Configure FPM connection\n"
       "Connect to IPv4 address\n"
       "Connect to IPv4 address\n"
       "TCP port number\n"
       "TCP port number\n")
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

DEFUN (no_fpm_remote_ip,
       no_fpm_remote_ip_cmd,
       "no fpm connection ip A.B.C.D port (1-65535)",
       NO_STR
       "Forwarding Path Manager\n"
       "Remove configured FPM connection\n"
       "Connect to IPv4 address\n"
       "Connect to IPv4 address\n"
       "TCP port number\n"
       "TCP port number\n")
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
			flog_err(EC_ZEBRA_NETLINK_NOT_AVAILABLE,
				 "FPM netlink message format is not available");
			return;
		}
		zfpm_g->message_format = ZFPM_MSG_FORMAT_NETLINK;
		return;
	}

	if (!strcmp("protobuf", format)) {
		if (!have_protobuf) {
			flog_err(
				EC_ZEBRA_PROTOBUF_NOT_AVAILABLE,
				"FPM protobuf message format is not available");
			return;
		}
		flog_warn(EC_ZEBRA_PROTOBUF_NOT_AVAILABLE,
			  "FPM protobuf message format is deprecated and scheduled to be removed. Please convert to using netlink format or contact dev@lists.frrouting.org with your use case.");
		zfpm_g->message_format = ZFPM_MSG_FORMAT_PROTOBUF;
		return;
	}

	flog_warn(EC_ZEBRA_FPM_FORMAT_UNKNOWN, "Unknown fpm format '%s'",
		  format);
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
		vty_out(vty, "fpm connection ip %pI4 port %d\n", &in,
			zfpm_g->fpm_port);

	return 0;
}


static int fpm_remote_srv_write(struct vty *vty);
/* Zebra node  */
static struct cmd_node zebra_node = {
	.name = "zebra",
	.node = ZEBRA_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "",
	.config_write = fpm_remote_srv_write,
};


/**
 * zfpm_init
 *
 * One-time initialization of the Zebra FPM module.
 *
 * @param[in] port port at which FPM is running.
 * @param[in] enable true if the zebra FPM module should be enabled
 * @param[in] format to use to talk to the FPM. Can be 'netink' or 'protobuf'.
 *
 * Returns true on success.
 */
static int zfpm_init(struct event_loop *master)
{
	int enable = 1;
	uint16_t port = 0;
	const char *format = THIS_MODULE->load_args;

	memset(zfpm_g, 0, sizeof(*zfpm_g));
	zfpm_g->master = master;
	TAILQ_INIT(&zfpm_g->dest_q);
	TAILQ_INIT(&zfpm_g->mac_q);

	/* Create hash table for fpm_mac_info_t enties */
	zfpm_g->fpm_mac_info_table = hash_create(zfpm_mac_info_hash_keymake,
						 zfpm_mac_info_cmp,
						 "FPM MAC info hash table");

	zfpm_g->sock = -1;
	zfpm_g->state = ZFPM_STATE_IDLE;

	zfpm_stats_init(&zfpm_g->stats);
	zfpm_stats_init(&zfpm_g->last_ivl_stats);
	zfpm_stats_init(&zfpm_g->cumulative_stats);

	memset(&ipv4ll_gateway, 0, sizeof(ipv4ll_gateway));
	if (inet_pton(AF_INET, ipv4_ll_buf, &ipv4ll_gateway.ipv4) != 1)
		zlog_warn("inet_pton failed for %s", ipv4_ll_buf);

	install_node(&zebra_node);
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

static int zfpm_fini(void)
{
	zfpm_write_off();
	zfpm_read_off();
	zfpm_connect_off();
	zfpm_conn_down_off();

	zfpm_stop_stats_timer();

	hook_unregister(rib_update, zfpm_trigger_update);
	hook_unregister(zebra_rmac_update, zfpm_trigger_rmac_update);

	return 0;
}

static int zebra_fpm_module_init(void)
{
	hook_register(rib_update, zfpm_trigger_update);
	hook_register(rib_shutdown, zfpm_trigger_remove);
	hook_register(zebra_rmac_update, zfpm_trigger_rmac_update);
	hook_register(frr_late_init, zfpm_init);
	hook_register(frr_early_fini, zfpm_fini);
	return 0;
}

FRR_MODULE_SETUP(.name = "zebra_fpm", .version = FRR_VERSION,
		 .description = "zebra FPM (Forwarding Plane Manager) module",
		 .init = zebra_fpm_module_init,
);
