// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra API server.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 */

#include <zebra.h>

/* clang-format off */
#include <errno.h>                /* for errno */
#include <netinet/in.h>           /* for sockaddr_in */
#include <stdint.h>               /* for uint8_t */
#include <stdio.h>                /* for snprintf */
#include <sys/socket.h>           /* for sockaddr_storage, AF_UNIX, accept... */
#include <sys/stat.h>             /* for umask, mode_t */
#include <sys/un.h>               /* for sockaddr_un */
#include <time.h>                 /* for NULL, tm, gmtime, time_t */
#include <unistd.h>               /* for close, unlink, ssize_t */

#include "lib/buffer.h"           /* for BUFFER_EMPTY, BUFFER_ERROR, BUFFE... */
#include "lib/command.h"          /* for vty, install_element, CMD_SUCCESS... */
#include "lib/hook.h"             /* for DEFINE_HOOK, DEFINE_KOOH, hook_call */
#include "lib/linklist.h"         /* for ALL_LIST_ELEMENTS_RO, ALL_LIST_EL... */
#include "lib/libfrr.h"           /* for frr_zclient_addr */
#include "lib/log.h"              /* for zlog_warn, zlog_debug, safe_strerror */
#include "lib/memory.h"           /* for MTYPE_TMP, XCALLOC, XFREE */
#include "lib/monotime.h"         /* for monotime, ONE_DAY_SECOND, ONE_WEE... */
#include "lib/network.h"          /* for set_nonblocking */
#include "lib/privs.h"            /* for zebra_privs_t, ZPRIVS_LOWER, ZPRI... */
#include "lib/route_types.h"      /* for ZEBRA_ROUTE_MAX */
#include "lib/sockopt.h"          /* for setsockopt_so_recvbuf, setsockopt... */
#include "lib/sockunion.h"        /* for sockopt_reuseaddr, sockopt_reuseport */
#include "lib/stream.h"           /* for STREAM_SIZE, stream (ptr only), ... */
#include "frrevent.h"                /* for thread (ptr only), EVENT_ARG, ... */
#include "lib/vrf.h"              /* for vrf_info_lookup, VRF_DEFAULT */
#include "lib/vty.h"              /* for vty_out, vty (ptr only) */
#include "lib/zclient.h"          /* for zmsghdr, ZEBRA_HEADER_SIZE, ZEBRA... */
#include "lib/frr_pthread.h"      /* for frr_pthread_new, frr_pthread_stop... */
#include "lib/frratomic.h"        /* for atomic_load_explicit, atomic_stor... */
#include "lib/lib_errors.h"       /* for generic ferr ids */
#include "lib/printfrr.h"         /* for string functions */

#include "zebra/debug.h"          /* for various debugging macros */
#include "zebra/rib.h"            /* for rib_score_proto */
#include "zebra/zapi_msg.h"       /* for zserv_handle_commands */
#include "zebra/zebra_vrf.h"      /* for zebra_vrf_lookup_by_id, zvrf */
#include "zebra/zserv.h"          /* for zserv */
#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"   /* for error messages */
/* clang-format on */

/* privileges */
extern struct zebra_privs_t zserv_privs;

/* The listener socket for clients connecting to us */
static int zsock;

/* The lock that protects access to zapi client objects */
static pthread_mutex_t client_mutex;

static struct zserv *find_client_internal(uint8_t proto,
					  unsigned short instance,
					  uint32_t session_id);

/* Mem type for zclients. */
DEFINE_MTYPE_STATIC(ZEBRA, ZSERV_CLIENT, "ZClients");

/*
 * Client thread events.
 *
 * These are used almost exclusively by client threads to drive their own event
 * loops. The only exception is in zserv_client_create(), which pushes an
 * initial ZSERV_CLIENT_READ event to start the API handler loop.
 */
enum zserv_client_event {
	/* Schedule a socket read */
	ZSERV_CLIENT_READ,
	/* Schedule a buffer write */
	ZSERV_CLIENT_WRITE,
};

/*
 * Main thread events.
 *
 * These are used by client threads to notify the main thread about various
 * events and to make processing requests.
 */
enum zserv_event {
	/* Schedule listen job on Zebra API socket */
	ZSERV_ACCEPT,
	/* The calling client has packets on its input buffer */
	ZSERV_PROCESS_MESSAGES,
	/* The calling client wishes to be killed */
	ZSERV_HANDLE_CLIENT_FAIL,
};

/*
 * Zebra server event driver for all client threads.
 *
 * This is essentially a wrapper around event_add_event() that centralizes
 * those scheduling calls into one place.
 *
 * All calls to this function schedule an event on the pthread running the
 * provided client.
 *
 * client
 *    the client in question, and thread target
 *
 * event
 *    the event to notify them about
 */
static void zserv_client_event(struct zserv *client,
			       enum zserv_client_event event);

/*
 * Zebra server event driver for the main thread.
 *
 * This is essentially a wrapper around event_add_event() that centralizes
 * those scheduling calls into one place.
 *
 * All calls to this function schedule an event on Zebra's main pthread.
 *
 * client
 *    the client in question
 *
 * event
 *    the event to notify the main thread about
 */
static void zserv_event(struct zserv *client, enum zserv_event event);


/* Client thread lifecycle -------------------------------------------------- */

/*
 * Free a zserv client object.
 */
void zserv_client_delete(struct zserv *client)
{
	XFREE(MTYPE_ZSERV_CLIENT, client);
}

/*
 * Log zapi message to zlog.
 *
 * errmsg (optional)
 *    Debugging message
 *
 * msg
 *    The message
 *
 * hdr (optional)
 *    The message header
 */
void zserv_log_message(const char *errmsg, struct stream *msg,
		       struct zmsghdr *hdr)
{
	zlog_debug("Rx'd ZAPI message");
	if (errmsg)
		zlog_debug("%s", errmsg);
	if (hdr) {
		zlog_debug(" Length: %d", hdr->length);
		zlog_debug("Command: %s", zserv_command_string(hdr->command));
		zlog_debug("    VRF: %u", hdr->vrf_id);
	}
	stream_hexdump(msg);
}

/*
 * Gracefuly shut down a client connection.
 *
 * Cancel any pending tasks for the client's thread. Then schedule a task on
 * the main thread to shut down the calling thread.
 *
 * It is not safe to close the client socket in this function. The socket is
 * owned by the main thread.
 *
 * Must be called from the client pthread, never the main thread.
 */
static void zserv_client_fail(struct zserv *client)
{
	flog_warn(
		EC_ZEBRA_CLIENT_IO_ERROR,
		"Client '%s' (session id %d) encountered an error and is shutting down.",
		zebra_route_string(client->proto), client->session_id);

	atomic_store_explicit(&client->pthread->running, false,
			      memory_order_relaxed);

	EVENT_OFF(client->t_read);
	EVENT_OFF(client->t_write);
	zserv_event(client, ZSERV_HANDLE_CLIENT_FAIL);
}

/*
 * Write all pending messages to client socket.
 *
 * This function first attempts to flush any buffered data. If unsuccessful,
 * the function reschedules itself and returns. If successful, it pops all
 * available messages from the output queue and continues to write data
 * directly to the socket until the socket would block. If the socket never
 * blocks and all data is written, the function returns without rescheduling
 * itself. If the socket ends up throwing EWOULDBLOCK, the remaining data is
 * buffered and the function reschedules itself.
 *
 * The utility of the buffer is that it allows us to vastly reduce lock
 * contention by allowing us to pop *all* messages off the output queue at once
 * instead of locking and unlocking each time we want to pop a single message
 * off the queue. The same thing could arguably be accomplished faster by
 * allowing the main thread to write directly into the buffer instead of
 * enqueuing packets onto an intermediary queue, but the intermediary queue
 * allows us to expose information about input and output queues to the user in
 * terms of number of packets rather than size of data.
 */
static void zserv_write(struct event *thread)
{
	struct zserv *client = EVENT_ARG(thread);
	struct stream *msg;
	uint32_t wcmd = 0;
	struct stream_fifo *cache;
	uint64_t time_now = monotime(NULL);

	/* If we have any data pending, try to flush it first */
	switch (buffer_flush_all(client->wb, client->sock)) {
	case BUFFER_ERROR:
		goto zwrite_fail;
	case BUFFER_PENDING:
		frr_with_mutex (&client->stats_mtx) {
			client->last_write_time = time_now;
		}
		zserv_client_event(client, ZSERV_CLIENT_WRITE);
		return;
	case BUFFER_EMPTY:
		break;
	}

	cache = stream_fifo_new();

	frr_with_mutex (&client->obuf_mtx) {
		while (stream_fifo_head(client->obuf_fifo))
			stream_fifo_push(cache,
					 stream_fifo_pop(client->obuf_fifo));
	}

	if (cache->tail) {
		msg = cache->tail;
		stream_set_getp(msg, 0);
		wcmd = stream_getw_from(msg, ZAPI_HEADER_CMD_LOCATION);
	}

	while (stream_fifo_head(cache)) {
		msg = stream_fifo_pop(cache);
		buffer_put(client->wb, STREAM_DATA(msg), stream_get_endp(msg));
		stream_free(msg);
	}

	stream_fifo_free(cache);

	/* If we have any data pending, try to flush it first */
	switch (buffer_flush_all(client->wb, client->sock)) {
	case BUFFER_ERROR:
		goto zwrite_fail;
	case BUFFER_PENDING:
		frr_with_mutex (&client->stats_mtx) {
			client->last_write_time = time_now;
		}
		zserv_client_event(client, ZSERV_CLIENT_WRITE);
		return;
	case BUFFER_EMPTY:
		break;
	}

	frr_with_mutex (&client->stats_mtx) {
		client->last_write_cmd = wcmd;
		client->last_write_time = time_now;
	}
	return;

zwrite_fail:
	flog_warn(EC_ZEBRA_CLIENT_WRITE_FAILED,
		  "%s: could not write to %s [fd = %d], closing.", __func__,
		  zebra_route_string(client->proto), client->sock);
	zserv_client_fail(client);
}

/*
 * Read and process data from a client socket.
 *
 * The responsibilities here are to read raw data from the client socket,
 * validate the header, encapsulate it into a single stream object, push it
 * onto the input queue and then notify the main thread that there is new data
 * available.
 *
 * This function first looks for any data in the client structure's working
 * input buffer. If data is present, it is assumed that reading stopped in a
 * previous invocation of this task and needs to be resumed to finish a message.
 * Otherwise, the socket data stream is assumed to be at the beginning of a new
 * ZAPI message (specifically at the header). The header is read and validated.
 * If the header passed validation then the length field found in the header is
 * used to compute the total length of the message. That much data is read (but
 * not inspected), appended to the header, placed into a stream and pushed onto
 * the client's input queue. A task is then scheduled on the main thread to
 * process the client's input queue. Finally, if all of this was successful,
 * this task reschedules itself.
 *
 * Any failure in any of these actions is handled by terminating the client.
 */
static void zserv_read(struct event *thread)
{
	struct zserv *client = EVENT_ARG(thread);
	int sock;
	size_t already;
	struct stream_fifo *cache;
	uint32_t p2p_orig;

	uint32_t p2p;
	struct zmsghdr hdr;

	p2p_orig = atomic_load_explicit(&zrouter.packets_to_process,
					memory_order_relaxed);
	cache = stream_fifo_new();
	p2p = p2p_orig;
	sock = EVENT_FD(thread);

	while (p2p) {
		ssize_t nb;
		bool hdrvalid;
		char errmsg[256];

		already = stream_get_endp(client->ibuf_work);

		/* Read length and command (if we don't have it already). */
		if (already < ZEBRA_HEADER_SIZE) {
			nb = stream_read_try(client->ibuf_work, sock,
					     ZEBRA_HEADER_SIZE - already);
			if ((nb == 0 || nb == -1)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug("connection closed socket [%d]",
						   sock);
				goto zread_fail;
			}
			if (nb != (ssize_t)(ZEBRA_HEADER_SIZE - already)) {
				/* Try again later. */
				break;
			}
			already = ZEBRA_HEADER_SIZE;
		}

		/* Reset to read from the beginning of the incoming packet. */
		stream_set_getp(client->ibuf_work, 0);

		/* Fetch header values */
		hdrvalid = zapi_parse_header(client->ibuf_work, &hdr);

		if (!hdrvalid) {
			snprintf(errmsg, sizeof(errmsg),
				 "%s: Message has corrupt header", __func__);
			zserv_log_message(errmsg, client->ibuf_work, NULL);
			goto zread_fail;
		}

		/* Validate header */
		if (hdr.marker != ZEBRA_HEADER_MARKER
		    || hdr.version != ZSERV_VERSION) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d version mismatch, marker %d, version %d",
				__func__, sock, hdr.marker, hdr.version);
			zserv_log_message(errmsg, client->ibuf_work, &hdr);
			goto zread_fail;
		}
		if (hdr.length < ZEBRA_HEADER_SIZE) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d message length %u is less than header size %d",
				__func__, sock, hdr.length, ZEBRA_HEADER_SIZE);
			zserv_log_message(errmsg, client->ibuf_work, &hdr);
			goto zread_fail;
		}
		if (hdr.length > STREAM_SIZE(client->ibuf_work)) {
			snprintf(
				errmsg, sizeof(errmsg),
				"Message has corrupt header\n%s: socket %d message length %u exceeds buffer size %lu",
				__func__, sock, hdr.length,
				(unsigned long)STREAM_SIZE(client->ibuf_work));
			zserv_log_message(errmsg, client->ibuf_work, &hdr);
			goto zread_fail;
		}

		/* Read rest of data. */
		if (already < hdr.length) {
			nb = stream_read_try(client->ibuf_work, sock,
					     hdr.length - already);
			if ((nb == 0 || nb == -1)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug(
						   "connection closed [%d] when reading zebra data",
						   sock);
				goto zread_fail;
			}
			if (nb != (ssize_t)(hdr.length - already)) {
				/* Try again later. */
				break;
			}
		}

		/* Debug packet information. */
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug("zebra message[%s:%u:%u] comes from socket [%d]",
				   zserv_command_string(hdr.command),
				   hdr.vrf_id, hdr.length,
				   sock);

		stream_set_getp(client->ibuf_work, 0);
		struct stream *msg = stream_dup(client->ibuf_work);

		stream_fifo_push(cache, msg);
		stream_reset(client->ibuf_work);
		p2p--;
	}

	if (p2p < p2p_orig) {
		uint64_t time_now = monotime(NULL);

		/* update session statistics */
		frr_with_mutex (&client->stats_mtx) {
			client->last_read_time = time_now;
			client->last_read_cmd = hdr.command;
		}

		/* publish read packets on client's input queue */
		frr_with_mutex (&client->ibuf_mtx) {
			while (cache->head)
				stream_fifo_push(client->ibuf_fifo,
						 stream_fifo_pop(cache));
		}

		/* Schedule job to process those packets */
		zserv_event(client, ZSERV_PROCESS_MESSAGES);

	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Read %d packets from client: %s", p2p_orig - p2p,
			   zebra_route_string(client->proto));

	/* Reschedule ourselves */
	zserv_client_event(client, ZSERV_CLIENT_READ);

	stream_fifo_free(cache);

	return;

zread_fail:
	stream_fifo_free(cache);
	zserv_client_fail(client);
}

static void zserv_client_event(struct zserv *client,
			       enum zserv_client_event event)
{
	switch (event) {
	case ZSERV_CLIENT_READ:
		event_add_read(client->pthread->master, zserv_read, client,
			       client->sock, &client->t_read);
		break;
	case ZSERV_CLIENT_WRITE:
		event_add_write(client->pthread->master, zserv_write, client,
				client->sock, &client->t_write);
		break;
	}
}

/* Main thread lifecycle ---------------------------------------------------- */

/*
 * Read and process messages from a client.
 *
 * This task runs on the main pthread. It is scheduled by client pthreads when
 * they have new messages available on their input queues. The client is passed
 * as the task argument.
 *
 * Each message is popped off the client's input queue and the action associated
 * with the message is executed. This proceeds until there are no more messages,
 * an error occurs, or the processing limit is reached.
 *
 * The client's I/O thread can push at most zrouter.packets_to_process messages
 * onto the input buffer before notifying us there are packets to read. As long
 * as we always process zrouter.packets_to_process messages here, then we can
 * rely on the read thread to handle queuing this task enough times to process
 * everything on the input queue.
 */
static void zserv_process_messages(struct event *thread)
{
	struct zserv *client = EVENT_ARG(thread);
	struct stream *msg;
	struct stream_fifo *cache = stream_fifo_new();
	uint32_t p2p = zrouter.packets_to_process;
	bool need_resched = false;

	frr_with_mutex (&client->ibuf_mtx) {
		uint32_t i;
		for (i = 0; i < p2p && stream_fifo_head(client->ibuf_fifo);
		     ++i) {
			msg = stream_fifo_pop(client->ibuf_fifo);
			stream_fifo_push(cache, msg);
		}

		/* Need to reschedule processing work if there are still
		 * packets in the fifo.
		 */
		if (stream_fifo_head(client->ibuf_fifo))
			need_resched = true;
	}

	/* Process the batch of messages */
	if (stream_fifo_head(cache))
		zserv_handle_commands(client, cache);

	stream_fifo_free(cache);

	/* Reschedule ourselves if necessary */
	if (need_resched)
		zserv_event(client, ZSERV_PROCESS_MESSAGES);
}

int zserv_send_message(struct zserv *client, struct stream *msg)
{
	frr_with_mutex (&client->obuf_mtx) {
		stream_fifo_push(client->obuf_fifo, msg);
	}

	zserv_client_event(client, ZSERV_CLIENT_WRITE);

	return 0;
}

/*
 * Send a batch of messages to a connected Zebra API client.
 */
int zserv_send_batch(struct zserv *client, struct stream_fifo *fifo)
{
	struct stream *msg;

	frr_with_mutex (&client->obuf_mtx) {
		msg = stream_fifo_pop(fifo);
		while (msg) {
			stream_fifo_push(client->obuf_fifo, msg);
			msg = stream_fifo_pop(fifo);
		}
	}

	zserv_client_event(client, ZSERV_CLIENT_WRITE);

	return 0;
}

/* Hooks for client connect / disconnect */
DEFINE_HOOK(zserv_client_connect, (struct zserv *client), (client));
DEFINE_KOOH(zserv_client_close, (struct zserv *client), (client));

/*
 * Deinitialize zebra client.
 *
 * - Deregister and deinitialize related internal resources
 * - Gracefuly close socket
 * - Free associated resources
 * - Free client structure
 *
 * This does *not* take any action on the struct event * fields. These are
 * managed by the owning pthread and any tasks associated with them must have
 * been stopped prior to invoking this function.
 */
static void zserv_client_free(struct zserv *client)
{
	if (client == NULL)
		return;

	hook_call(zserv_client_close, client);

	/* Close file descriptor. */
	if (client->sock) {
		unsigned long nroutes = 0;
		unsigned long nnhgs = 0;

		close(client->sock);

		if (DYNAMIC_CLIENT_GR_DISABLED(client)) {
			if (!client->synchronous) {
				zebra_mpls_client_cleanup_vrf_label(
					client->proto);

				nroutes = rib_score_proto(client->proto,
							  client->instance);
			}
			zlog_notice(
				"client %d disconnected %lu %s routes removed from the rib",
				client->sock, nroutes,
				zebra_route_string(client->proto));

			/* Not worrying about instance for now */
			if (!client->synchronous)
				nnhgs = zebra_nhg_score_proto(client->proto);
			zlog_notice(
				"client %d disconnected %lu %s nhgs removed from the rib",
				client->sock, nnhgs,
				zebra_route_string(client->proto));
		}
		client->sock = -1;
	}

	/* Free stream buffers. */
	if (client->ibuf_work)
		stream_free(client->ibuf_work);
	if (client->obuf_work)
		stream_free(client->obuf_work);
	if (client->ibuf_fifo)
		stream_fifo_free(client->ibuf_fifo);
	if (client->obuf_fifo)
		stream_fifo_free(client->obuf_fifo);
	if (client->wb)
		buffer_free(client->wb);

	/* Free buffer mutexes */
	pthread_mutex_destroy(&client->stats_mtx);
	pthread_mutex_destroy(&client->obuf_mtx);
	pthread_mutex_destroy(&client->ibuf_mtx);

	/* Free bitmaps. */
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			vrf_bitmap_free(&client->redist[afi][i]);
			redist_del_all_instances(&client->mi_redist[afi][i]);
		}

		vrf_bitmap_free(&client->redist_default[afi]);
		vrf_bitmap_free(&client->ridinfo[afi]);
		vrf_bitmap_free(&client->neighinfo[afi]);
	}

	/*
	 * If any instance are graceful restart enabled,
	 * client is not deleted
	 */
	if (DYNAMIC_CLIENT_GR_DISABLED(client)) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: Deleting client %s", __func__,
				   zebra_route_string(client->proto));
		zserv_client_delete(client);
	} else {
		/* Handle cases where client has GR instance. */
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: client %s restart enabled", __func__,
				   zebra_route_string(client->proto));
		if (zebra_gr_client_disconnect(client) < 0)
			zlog_err(
				"%s: GR enabled but could not handle disconnect event",
				__func__);
	}
}

void zserv_close_client(struct zserv *client)
{
	bool free_p = true;

	if (client->pthread) {
		/* synchronously stop and join pthread */
		frr_pthread_stop(client->pthread, NULL);

		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("Closing client '%s'",
				   zebra_route_string(client->proto));

		event_cancel_event(zrouter.master, client);
		EVENT_OFF(client->t_cleanup);
		EVENT_OFF(client->t_process);

		/* destroy pthread */
		frr_pthread_destroy(client->pthread);
		client->pthread = NULL;
	}

	/*
	 * Final check in case the client struct is in use in another
	 * pthread: if not in-use, continue and free the client
	 */
	frr_with_mutex (&client_mutex) {
		if (client->busy_count <= 0) {
			/* remove from client list */
			listnode_delete(zrouter.client_list, client);
		} else {
			/*
			 * The client session object may be in use, although
			 * the associated pthread is gone. Defer final
			 * cleanup.
			 */
			client->is_closed = true;
			free_p = false;
		}
	}

	/* delete client */
	if (free_p)
		zserv_client_free(client);
}

/*
 * This task is scheduled by a ZAPI client pthread on the main pthread when it
 * wants to stop itself. When this executes, the client connection should
 * already have been closed and the thread will most likely have died, but its
 * resources still need to be cleaned up.
 */
static void zserv_handle_client_fail(struct event *thread)
{
	struct zserv *client = EVENT_ARG(thread);

	zserv_close_client(client);
}

/*
 * Create a new client.
 *
 * This is called when a new connection is accept()'d on the ZAPI socket. It
 * initializes new client structure, notifies any subscribers of the connection
 * event and spawns the client's thread.
 *
 * sock
 *    client's socket file descriptor
 */
static struct zserv *zserv_client_create(int sock)
{
	struct zserv *client;
	size_t stream_size =
		MAX(ZEBRA_MAX_PACKET_SIZ, sizeof(struct zapi_route));
	int i;
	afi_t afi;

	client = XCALLOC(MTYPE_ZSERV_CLIENT, sizeof(struct zserv));

	/* Make client input/output buffer. */
	client->sock = sock;
	client->ibuf_fifo = stream_fifo_new();
	client->obuf_fifo = stream_fifo_new();
	client->ibuf_work = stream_new(stream_size);
	client->obuf_work = stream_new(stream_size);
	client->connect_time = monotime(NULL);
	pthread_mutex_init(&client->ibuf_mtx, NULL);
	pthread_mutex_init(&client->obuf_mtx, NULL);
	pthread_mutex_init(&client->stats_mtx, NULL);
	client->wb = buffer_new(0);
	TAILQ_INIT(&(client->gr_info_queue));

	/* Initialize flags */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_init(&client->redist[afi][i]);
		vrf_bitmap_init(&client->redist_default[afi]);
		vrf_bitmap_init(&client->ridinfo[afi]);
		vrf_bitmap_init(&client->neighinfo[afi]);
	}

	/* Add this client to linked list. */
	frr_with_mutex (&client_mutex) {
		listnode_add(zrouter.client_list, client);
	}

	struct frr_pthread_attr zclient_pthr_attrs = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop
	};
	client->pthread =
		frr_pthread_new(&zclient_pthr_attrs, "Zebra API client thread",
				"zebra_apic");

	/* start read loop */
	zserv_client_event(client, ZSERV_CLIENT_READ);

	/* call callbacks */
	hook_call(zserv_client_connect, client);

	/* start pthread */
	frr_pthread_run(client->pthread, NULL);

	return client;
}

/*
 * Retrieve a client object by the complete tuple of
 * {protocol, instance, session}. This version supports use
 * from a different pthread: the object will be returned marked
 * in-use. The caller *must* release the client object with the
 * release_client() api, to ensure that the in-use marker is cleared properly.
 */
struct zserv *zserv_acquire_client(uint8_t proto, unsigned short instance,
				   uint32_t session_id)
{
	struct zserv *client = NULL;

	frr_with_mutex (&client_mutex) {
		client = find_client_internal(proto, instance, session_id);
		if (client) {
			/* Don't return a dead/closed client object */
			if (client->is_closed)
				client = NULL;
			else
				client->busy_count++;
		}
	}

	return client;
}

/*
 * Release a client object that was acquired with the acquire_client() api.
 * After this has been called, the caller must not use the client pointer -
 * it may be freed if the client has closed.
 */
void zserv_release_client(struct zserv *client)
{
	/*
	 * Once we've decremented the client object's refcount, it's possible
	 * for it to be deleted as soon as we release the lock, so we won't
	 * touch the object again.
	 */
	frr_with_mutex (&client_mutex) {
		client->busy_count--;

		if (client->busy_count <= 0) {
			/*
			 * No more users of the client object. If the client
			 * session is closed, schedule cleanup on the zebra
			 * main pthread.
			 */
			if (client->is_closed)
				event_add_event(zrouter.master,
						zserv_handle_client_fail,
						client, 0, &client->t_cleanup);
		}
	}

	/*
	 * Cleanup must take place on the zebra main pthread, so we've
	 * scheduled an event.
	 */
}

/*
 * Accept socket connection.
 */
static void zserv_accept(struct event *thread)
{
	int accept_sock;
	int client_sock;
	struct sockaddr_in client;
	socklen_t len;

	accept_sock = EVENT_FD(thread);

	/* Reregister myself. */
	zserv_event(NULL, ZSERV_ACCEPT);

	len = sizeof(struct sockaddr_in);
	client_sock = accept(accept_sock, (struct sockaddr *)&client, &len);

	if (client_sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Can't accept zebra socket: %s",
			     safe_strerror(errno));
		return;
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(client_sock);

	/* Create new zebra client. */
	zserv_client_create(client_sock);
}

void zserv_close(void)
{
	/*
	 * On shutdown, let's close the socket down
	 * so that long running processes of killing the
	 * routing table doesn't leave us in a bad
	 * state where a client tries to reconnect
	 */
	close(zsock);
	zsock = -1;

	/* Free client list's mutex */
	pthread_mutex_destroy(&client_mutex);
}

void zserv_start(char *path)
{
	int ret;
	mode_t old_mask;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	if (!frr_zclient_addr(&sa, &sa_len, path))
		/* should be caught in zebra main() */
		return;

	/* Set umask */
	old_mask = umask(0077);

	/* Make UNIX domain socket. */
	zsock = socket(sa.ss_family, SOCK_STREAM, 0);
	if (zsock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Can't create zserv socket: %s",
			     safe_strerror(errno));
		return;
	}

	if (sa.ss_family != AF_UNIX) {
		sockopt_reuseaddr(zsock);
		sockopt_reuseport(zsock);
	} else {
		struct sockaddr_un *suna = (struct sockaddr_un *)&sa;
		if (suna->sun_path[0])
			unlink(suna->sun_path);
	}

	setsockopt_so_recvbuf(zsock, 1048576);
	setsockopt_so_sendbuf(zsock, 1048576);

	frr_with_privs((sa.ss_family != AF_UNIX) ? &zserv_privs : NULL) {
		ret = bind(zsock, (struct sockaddr *)&sa, sa_len);
	}
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Can't bind zserv socket on %s: %s",
			     path, safe_strerror(errno));
		close(zsock);
		zsock = -1;
		return;
	}

	ret = listen(zsock, 5);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Can't listen to zserv socket %s: %s", path,
			     safe_strerror(errno));
		close(zsock);
		zsock = -1;
		return;
	}

	umask(old_mask);

	zserv_event(NULL, ZSERV_ACCEPT);
}

void zserv_event(struct zserv *client, enum zserv_event event)
{
	switch (event) {
	case ZSERV_ACCEPT:
		event_add_read(zrouter.master, zserv_accept, NULL, zsock, NULL);
		break;
	case ZSERV_PROCESS_MESSAGES:
		event_add_event(zrouter.master, zserv_process_messages, client,
				0, &client->t_process);
		break;
	case ZSERV_HANDLE_CLIENT_FAIL:
		event_add_event(zrouter.master, zserv_handle_client_fail,
				client, 0, &client->t_cleanup);
	}
}


/* General purpose ---------------------------------------------------------- */

#define ZEBRA_TIME_BUF 32
static char *zserv_time_buf(time_t *time1, char *buf, int buflen)
{
	time_t now;

	assert(buf != NULL);
	assert(buflen >= ZEBRA_TIME_BUF);
	assert(time1 != NULL);

	if (!*time1) {
		snprintf(buf, buflen, "never   ");
		return (buf);
	}

	now = monotime(NULL);
	now -= *time1;

	frrtime_to_interval(now, buf, buflen);

	return buf;
}

/* Display client info details */
static void zebra_show_client_detail(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF], nhbuf[ZEBRA_TIME_BUF], mbuf[ZEBRA_TIME_BUF];
	time_t connect_time, last_read_time, last_write_time;
	uint32_t last_read_cmd, last_write_cmd;

	vty_out(vty, "Client: %s", zebra_route_string(client->proto));
	if (client->instance)
		vty_out(vty, " Instance: %u", client->instance);
	if (client->session_id)
		vty_out(vty, " [%u]", client->session_id);
	vty_out(vty, "\n");

	vty_out(vty, "------------------------ \n");
	vty_out(vty, "FD: %d \n", client->sock);

	frr_with_mutex (&client->stats_mtx) {
		connect_time = client->connect_time;
		last_read_time = client->last_read_time;
		last_write_time = client->last_write_time;

		last_read_cmd = client->last_read_cmd;
		last_write_cmd = client->last_write_cmd;
	}

	vty_out(vty, "Connect Time: %s \n",
		zserv_time_buf(&connect_time, cbuf, ZEBRA_TIME_BUF));
	if (client->nh_reg_time) {
		vty_out(vty, "Nexthop Registry Time: %s \n",
			zserv_time_buf(&client->nh_reg_time, nhbuf,
				       ZEBRA_TIME_BUF));
		if (client->nh_last_upd_time)
			vty_out(vty, "Nexthop Last Update Time: %s \n",
				zserv_time_buf(&client->nh_last_upd_time, mbuf,
					       ZEBRA_TIME_BUF));
		else
			vty_out(vty, "No Nexthop Update sent\n");
	} else
		vty_out(vty, "Not registered for Nexthop Updates\n");

	vty_out(vty,
		"Client will %sbe notified about the status of its routes.\n",
		client->notify_owner ? "" : "Not ");

	vty_out(vty, "Last Msg Rx Time: %s \n",
		zserv_time_buf(&last_read_time, rbuf, ZEBRA_TIME_BUF));
	vty_out(vty, "Last Msg Tx Time: %s \n",
		zserv_time_buf(&last_write_time, wbuf, ZEBRA_TIME_BUF));
	if (last_read_cmd)
		vty_out(vty, "Last Rcvd Cmd: %s \n",
			zserv_command_string(last_read_cmd));
	if (last_write_cmd)
		vty_out(vty, "Last Sent Cmd: %s \n",
			zserv_command_string(last_write_cmd));
	vty_out(vty, "\n");

	vty_out(vty, "Type        Add         Update      Del \n");
	vty_out(vty, "================================================== \n");
	vty_out(vty, "IPv4        %-12u%-12u%-12u\n", client->v4_route_add_cnt,
		client->v4_route_upd8_cnt, client->v4_route_del_cnt);
	vty_out(vty, "IPv6        %-12u%-12u%-12u\n", client->v6_route_add_cnt,
		client->v6_route_upd8_cnt, client->v6_route_del_cnt);
	vty_out(vty, "Redist:v4   %-12u%-12u%-12u\n", client->redist_v4_add_cnt,
		0, client->redist_v4_del_cnt);
	vty_out(vty, "Redist:v6   %-12u%-12u%-12u\n", client->redist_v6_add_cnt,
		0, client->redist_v6_del_cnt);
	vty_out(vty, "NHG         %-12u%-12u%-12u\n", client->nhg_add_cnt,
		client->nhg_upd8_cnt, client->nhg_del_cnt);
	vty_out(vty, "VRF         %-12u%-12u%-12u\n", client->vrfadd_cnt, 0,
		client->vrfdel_cnt);
	vty_out(vty, "Connected   %-12u%-12u%-12u\n", client->ifadd_cnt, 0,
		client->ifdel_cnt);
	vty_out(vty, "Interface   %-12u%-12u%-12u\n", client->ifup_cnt, 0,
		client->ifdown_cnt);
	vty_out(vty, "Intf Addr   %-12u%-12u%-12u\n",
		client->connected_rt_add_cnt, 0, client->connected_rt_del_cnt);
	vty_out(vty, "BFD peer    %-12u%-12u%-12u\n", client->bfd_peer_add_cnt,
		client->bfd_peer_upd8_cnt, client->bfd_peer_del_cnt);
	vty_out(vty, "NHT v4      %-12u%-12u%-12u\n",
		client->v4_nh_watch_add_cnt, 0, client->v4_nh_watch_rem_cnt);
	vty_out(vty, "NHT v6      %-12u%-12u%-12u\n",
		client->v6_nh_watch_add_cnt, 0, client->v6_nh_watch_rem_cnt);
	vty_out(vty, "VxLAN SG    %-12u%-12u%-12u\n", client->vxlan_sg_add_cnt,
		0, client->vxlan_sg_del_cnt);
	vty_out(vty, "VNI         %-12u%-12u%-12u\n", client->vniadd_cnt, 0,
		client->vnidel_cnt);
	vty_out(vty, "L3-VNI      %-12u%-12u%-12u\n", client->l3vniadd_cnt, 0,
		client->l3vnidel_cnt);
	vty_out(vty, "MAC-IP      %-12u%-12u%-12u\n", client->macipadd_cnt, 0,
		client->macipdel_cnt);
	vty_out(vty, "ES          %-12u%-12u%-12u\n", client->local_es_add_cnt,
		0, client->local_es_del_cnt);
	vty_out(vty, "ES-EVI      %-12u%-12u%-12u\n",
		client->local_es_evi_add_cnt, 0, client->local_es_evi_del_cnt);
	vty_out(vty, "Errors: %u\n", client->error_cnt);

#if defined DEV_BUILD
	vty_out(vty, "Input Fifo: %zu:%zu Output Fifo: %zu:%zu\n",
		client->ibuf_fifo->count, client->ibuf_fifo->max_count,
		client->obuf_fifo->count, client->obuf_fifo->max_count);
#endif
	vty_out(vty, "\n");
}

/* Display stale client information */
static void zebra_show_stale_client_detail(struct vty *vty,
					   struct zserv *client)
{
	char buf[PREFIX2STR_BUFFER];
	time_t uptime;
	struct client_gr_info *info = NULL;
	struct zserv *s = NULL;
	bool first_p = true;

	TAILQ_FOREACH (info, &client->gr_info_queue, gr_info) {
		if (first_p) {
			vty_out(vty, "Stale Client Information\n");
			vty_out(vty, "------------------------\n");

			if (client->instance)
				vty_out(vty, " Instance: %u", client->instance);
			if (client->session_id)
				vty_out(vty, " [%u]", client->session_id);

			first_p = false;
		}

		vty_out(vty, "VRF : %s\n", vrf_id_to_name(info->vrf_id));
		vty_out(vty, "Capabilities : ");
		switch (info->capabilities) {
		case ZEBRA_CLIENT_GR_CAPABILITIES:
			vty_out(vty, "Graceful Restart(%u seconds)\n",
				info->stale_removal_time);
			break;
		case ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE:
		case ZEBRA_CLIENT_ROUTE_UPDATE_PENDING:
		case ZEBRA_CLIENT_GR_DISABLE:
		case ZEBRA_CLIENT_RIB_STALE_TIME:
			vty_out(vty, "None\n");
			break;
		}

		if (ZEBRA_CLIENT_GR_ENABLED(info->capabilities)) {
			if (info->stale_client_ptr) {
				s = (struct zserv *)(info->stale_client_ptr);
				uptime = monotime(NULL);
				uptime -= s->restart_time;

				frrtime_to_interval(uptime, buf, sizeof(buf));

				vty_out(vty, "Last restart time : %s ago\n",
					buf);

				vty_out(vty, "Stalepath removal time: %d sec\n",
					info->stale_removal_time);
				if (info->t_stale_removal) {
					vty_out(vty,
						"Stale delete timer: %ld sec\n",
						event_timer_remain_second(
							info->t_stale_removal));
				}
			}
		}
	}
	vty_out(vty, "\n");
	return;
}

static void zebra_show_client_brief(struct vty *vty, struct zserv *client)
{
	char client_string[80];
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF];
	time_t connect_time, last_read_time, last_write_time;

	frr_with_mutex (&client->stats_mtx) {
		connect_time = client->connect_time;
		last_read_time = client->last_read_time;
		last_write_time = client->last_write_time;
	}

	if (client->instance || client->session_id)
		snprintfrr(client_string, sizeof(client_string), "%s[%u:%u]",
			   zebra_route_string(client->proto), client->instance,
			   client->session_id);
	else
		snprintfrr(client_string, sizeof(client_string), "%s",
			   zebra_route_string(client->proto));

	vty_out(vty, "%-10s%12s %12s%12s %10d/%-10d %10d/%-10d\n",
		client_string,
		zserv_time_buf(&connect_time, cbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&last_read_time, rbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&last_write_time, wbuf, ZEBRA_TIME_BUF),
		client->v4_route_add_cnt + client->v4_route_upd8_cnt,
		client->v4_route_del_cnt,
		client->v6_route_add_cnt + client->v6_route_upd8_cnt,
		client->v6_route_del_cnt);
}

/*
 * Common logic that searches the client list for a zapi client; this
 * MUST be called holding the client list mutex.
 */
static struct zserv *find_client_internal(uint8_t proto,
					  unsigned short instance,
					  uint32_t session_id)
{
	struct listnode *node, *nnode;
	struct zserv *client = NULL;

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (client->proto == proto && client->instance == instance &&
		    client->session_id == session_id)
			break;
	}

	return client;
}

/*
 * Public api that searches for a client session; this version is
 * used from the zebra main pthread.
 */
struct zserv *zserv_find_client(uint8_t proto, unsigned short instance)
{
	struct zserv *client;

	frr_with_mutex (&client_mutex) {
		client = find_client_internal(proto, instance, 0);
	}

	return client;
}

/*
 * Retrieve a client by its protocol, instance number, and session id.
 */
struct zserv *zserv_find_client_session(uint8_t proto, unsigned short instance,
					uint32_t session_id)
{
	struct zserv *client;

	frr_with_mutex (&client_mutex) {
		client = find_client_internal(proto, instance, session_id);
	}

	return client;

}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client,
       show_zebra_client_cmd,
       "show zebra client",
       SHOW_STR
       ZEBRA_STR
       "Client information\n")
{
	struct listnode *node;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		zebra_show_client_detail(vty, client);
		/* Show GR info if present */
		zebra_show_stale_client_detail(vty, client);
	}

	return CMD_SUCCESS;
}

/* This command is for debugging purpose. */
DEFUN (show_zebra_client_summary,
       show_zebra_client_summary_cmd,
       "show zebra client summary",
       SHOW_STR
       ZEBRA_STR
       "Client information brief\n"
       "Brief Summary\n")
{
	struct listnode *node;
	struct zserv *client;

	vty_out(vty,
		"Name      Connect Time    Last Read  Last Write      IPv4 Routes           IPv6 Routes\n");
	vty_out(vty,
		"------------------------------------------------------------------------------------------\n");

	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client))
		zebra_show_client_brief(vty, client);

	vty_out(vty, "Routes column shows (added+updated)/deleted\n");
	return CMD_SUCCESS;
}

static int zserv_client_close_cb(struct zserv *closed_client)
{
	struct listnode *node, *nnode;
	struct zserv *client = NULL;

	for (ALL_LIST_ELEMENTS(zrouter.client_list, node, nnode, client)) {
		if (client->proto == closed_client->proto)
			continue;

		zsend_client_close_notify(client, closed_client);
	}

	return 0;
}

void zserv_init(void)
{
	/* Client list init. */
	zrouter.client_list = list_new();
	zrouter.stale_client_list = list_new();

	/* Misc init. */
	zsock = -1;
	pthread_mutex_init(&client_mutex, NULL);

	install_element(ENABLE_NODE, &show_zebra_client_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_summary_cmd);

	hook_register(zserv_client_close, zserv_client_close_cb);
}
