/*
 * Zebra API server.
 * Portions:
 *   Copyright (C) 1997-1999  Kunihiro Ishiguro
 *   Copyright (C) 2015-2018  Cumulus Networks, Inc.
 *   et al.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "lib/thread.h"           /* for thread (ptr only), THREAD_ARG, ... */
#include "lib/vrf.h"              /* for vrf_info_lookup, VRF_DEFAULT */
#include "lib/vty.h"              /* for vty_out, vty (ptr only) */
#include "lib/zassert.h"          /* for assert */
#include "lib/zclient.h"          /* for zmsghdr, ZEBRA_HEADER_SIZE, ZEBRA... */
#include "lib/frr_pthread.h"      /* for frr_pthread_new, frr_pthread_stop... */
#include "lib/frratomic.h"        /* for atomic_load_explicit, atomic_stor... */

#include "zebra/debug.h"          /* for various debugging macros */
#include "zebra/rib.h"            /* for rib_score_proto */
#include "zebra/zapi_msg.h"       /* for zserv_handle_commands */
#include "zebra/zebra_vrf.h"      /* for zebra_vrf_lookup_by_id, zvrf */
#include "zebra/zserv.h"          /* for zserv */
/* clang-format on */

/* privileges */
extern struct zebra_privs_t zserv_privs;

/*
 * Client thread events.
 *
 * These are used almost exclusively by client threads to drive their own event
 * loops. The only exception is in zebra_client_create(), which pushes an
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
	ZSERV_HANDLE_CLOSE,
};

/*
 * Zebra server event driver for all client threads.
 *
 * This is essentially a wrapper around thread_add_event() that centralizes
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
 * This is essentially a wrapper around thread_add_event() that centralizes
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
static void zserv_log_message(const char *errmsg, struct stream *msg,
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
	zlog_hexdump(msg->data, STREAM_READABLE(msg));
}

/*
 * Gracefully shut down a client connection.
 *
 * Cancel any pending tasks for the client's thread. Then schedule a task on the
 * main thread to shut down the calling thread.
 *
 * Must be called from the client pthread, never the main thread.
 */
static void zserv_client_close(struct zserv *client)
{
	atomic_store_explicit(&client->pthread->running, false,
			      memory_order_seq_cst);
	THREAD_OFF(client->t_read);
	THREAD_OFF(client->t_write);
	zserv_event(client, ZSERV_HANDLE_CLOSE);
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
static int zserv_write(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);
	struct stream *msg;
	uint32_t wcmd = 0;
	struct stream_fifo *cache;

	/* If we have any data pending, try to flush it first */
	switch (buffer_flush_all(client->wb, client->sock)) {
	case BUFFER_ERROR:
		goto zwrite_fail;
	case BUFFER_PENDING:
		atomic_store_explicit(&client->last_write_time,
				      (uint32_t)monotime(NULL),
				      memory_order_relaxed);
		zserv_client_event(client, ZSERV_CLIENT_WRITE);
		return 0;
	case BUFFER_EMPTY:
		break;
	}

	cache = stream_fifo_new();

	pthread_mutex_lock(&client->obuf_mtx);
	{
		while (stream_fifo_head(client->obuf_fifo))
			stream_fifo_push(cache,
					 stream_fifo_pop(client->obuf_fifo));
	}
	pthread_mutex_unlock(&client->obuf_mtx);

	if (cache->tail) {
		msg = cache->tail;
		stream_set_getp(msg, 0);
		wcmd = stream_getw_from(msg, 6);
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
		atomic_store_explicit(&client->last_write_time,
				      (uint32_t)monotime(NULL),
				      memory_order_relaxed);
		zserv_client_event(client, ZSERV_CLIENT_WRITE);
		return 0;
	case BUFFER_EMPTY:
		break;
	}

	atomic_store_explicit(&client->last_write_cmd, wcmd,
			      memory_order_relaxed);

	atomic_store_explicit(&client->last_write_time,
			      (uint32_t)monotime(NULL), memory_order_relaxed);

	return 0;

zwrite_fail:
	zlog_warn("%s: could not write to %s [fd = %d], closing.", __func__,
		  zebra_route_string(client->proto), client->sock);
	zserv_client_close(client);
	return 0;
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
static int zserv_read(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);
	int sock;
	size_t already;
	struct stream_fifo *cache;
	uint32_t p2p_orig;

	uint32_t p2p;
	struct zmsghdr hdr;

	p2p_orig = atomic_load_explicit(&zebrad.packets_to_process,
					memory_order_relaxed);
	cache = stream_fifo_new();
	p2p = p2p_orig;
	sock = THREAD_FD(thread);

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
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("zebra message comes from socket [%d]",
				   sock);

		if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
			zserv_log_message(NULL, client->ibuf_work, &hdr);

		stream_set_getp(client->ibuf_work, 0);
		struct stream *msg = stream_dup(client->ibuf_work);

		stream_fifo_push(cache, msg);
		stream_reset(client->ibuf_work);
		p2p--;
	}

	if (p2p < p2p_orig) {
		/* update session statistics */
		atomic_store_explicit(&client->last_read_time, monotime(NULL),
				      memory_order_relaxed);
		atomic_store_explicit(&client->last_read_cmd, hdr.command,
				      memory_order_relaxed);

		/* publish read packets on client's input queue */
		pthread_mutex_lock(&client->ibuf_mtx);
		{
			while (cache->head)
				stream_fifo_push(client->ibuf_fifo,
						 stream_fifo_pop(cache));
		}
		pthread_mutex_unlock(&client->ibuf_mtx);

		/* Schedule job to process those packets */
		zserv_event(client, ZSERV_PROCESS_MESSAGES);

	}

	if (IS_ZEBRA_DEBUG_PACKET)
		zlog_debug("Read %d packets", p2p_orig - p2p);

	/* Reschedule ourselves */
	zserv_client_event(client, ZSERV_CLIENT_READ);

	stream_fifo_free(cache);

	return 0;

zread_fail:
	stream_fifo_free(cache);
	zserv_client_close(client);
	return -1;
}

static void zserv_client_event(struct zserv *client,
			       enum zserv_client_event event)
{
	switch (event) {
	case ZSERV_CLIENT_READ:
		thread_add_read(client->pthread->master, zserv_read, client,
				client->sock, &client->t_read);
		break;
	case ZSERV_CLIENT_WRITE:
		thread_add_write(client->pthread->master, zserv_write, client,
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
 * The client's I/O thread can push at most zebrad.packets_to_process messages
 * onto the input buffer before notifying us there are packets to read. As long
 * as we always process zebrad.packets_to_process messages here, then we can
 * rely on the read thread to handle queuing this task enough times to process
 * everything on the input queue.
 */
static int zserv_process_messages(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);
	struct stream *msg;
	struct stream_fifo *cache = stream_fifo_new();

	uint32_t p2p = zebrad.packets_to_process;

	pthread_mutex_lock(&client->ibuf_mtx);
	{
		uint32_t i;
		for (i = 0; i < p2p && stream_fifo_head(client->ibuf_fifo);
		     ++i) {
			msg = stream_fifo_pop(client->ibuf_fifo);
			stream_fifo_push(cache, msg);
		}

		msg = NULL;
	}
	pthread_mutex_unlock(&client->ibuf_mtx);

	while (stream_fifo_head(cache)) {
		msg = stream_fifo_pop(cache);
		zserv_handle_commands(client, msg);
		stream_free(msg);
	}

	stream_fifo_free(cache);

	return 0;
}

int zserv_send_message(struct zserv *client, struct stream *msg)
{
	/*
	 * This is a somewhat poorly named variable added with Zebra's portion
	 * of the label manager. That component does not use the regular
	 * zserv/zapi_msg interface for handling its messages, as the client
	 * itself runs in-process. Instead it uses synchronous writes on the
	 * zserv client's socket directly in the zread* handlers for its
	 * message types. Furthermore, it cannot handle the usual messages
	 * Zebra sends (such as those for interface changes) and so has added
	 * this flag and check here as a hack to suppress all messages that it
	 * does not explicitly know about.
	 *
	 * In any case this needs to be cleaned up at some point.
	 *
	 * See also:
	 *    zread_label_manager_request
	 *    zsend_label_manager_connect_response
	 *    zsend_assign_label_chunk_response
	 *    ...
	 */
	if (client->is_synchronous)
		return 0;

	pthread_mutex_lock(&client->obuf_mtx);
	{
		stream_fifo_push(client->obuf_fifo, msg);
	}
	pthread_mutex_unlock(&client->obuf_mtx);

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
 * - Gracefully close socket
 * - Free associated resources
 * - Free client structure
 *
 * This does *not* take any action on the struct thread * fields. These are
 * managed by the owning pthread and any tasks associated with them must have
 * been stopped prior to invoking this function.
 */
static void zserv_client_free(struct zserv *client)
{
	hook_call(zserv_client_close, client);

	/* Close file descriptor. */
	if (client->sock) {
		unsigned long nroutes;

		close(client->sock);
		nroutes = rib_score_proto(client->proto, client->instance);
		zlog_notice(
			"client %d disconnected. %lu %s routes removed from the rib",
			client->sock, nroutes,
			zebra_route_string(client->proto));
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
	pthread_mutex_destroy(&client->obuf_mtx);
	pthread_mutex_destroy(&client->ibuf_mtx);

	/* Free bitmaps. */
	for (afi_t afi = AFI_IP; afi < AFI_MAX; afi++)
		for (int i = 0; i < ZEBRA_ROUTE_MAX; i++)
			vrf_bitmap_free(client->redist[afi][i]);

	vrf_bitmap_free(client->redist_default);
	vrf_bitmap_free(client->ifinfo);
	vrf_bitmap_free(client->ridinfo);

	XFREE(MTYPE_TMP, client);
}

/*
 * Finish closing a client.
 *
 * This task is scheduled by a ZAPI client pthread on the main pthread when it
 * wants to stop itself. When this executes, the client connection should
 * already have been closed. This task's responsibility is to gracefully
 * terminate the client thread, update relevant internal datastructures and
 * free any resources allocated by the main thread.
 */
static int zserv_handle_client_close(struct thread *thread)
{
	struct zserv *client = THREAD_ARG(thread);

	/* synchronously stop thread */
	frr_pthread_stop(client->pthread, NULL);

	/* destroy frr_pthread */
	frr_pthread_destroy(client->pthread);
	client->pthread = NULL;

	listnode_delete(zebrad.client_list, client);
	zserv_client_free(client);
	return 0;
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
static void zserv_client_create(int sock)
{
	struct zserv *client;
	int i;
	afi_t afi;

	client = XCALLOC(MTYPE_TMP, sizeof(struct zserv));

	/* Make client input/output buffer. */
	client->sock = sock;
	client->ibuf_fifo = stream_fifo_new();
	client->obuf_fifo = stream_fifo_new();
	client->ibuf_work = stream_new(ZEBRA_MAX_PACKET_SIZ);
	client->obuf_work = stream_new(ZEBRA_MAX_PACKET_SIZ);
	pthread_mutex_init(&client->ibuf_mtx, NULL);
	pthread_mutex_init(&client->obuf_mtx, NULL);
	client->wb = buffer_new(0);

	/* Set table number. */
	client->rtm_table = zebrad.rtm_table_default;

	atomic_store_explicit(&client->connect_time, (uint32_t) monotime(NULL),
			      memory_order_relaxed);

	/* Initialize flags */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			client->redist[afi][i] = vrf_bitmap_init();
	client->redist_default = vrf_bitmap_init();
	client->ifinfo = vrf_bitmap_init();
	client->ridinfo = vrf_bitmap_init();

	/* by default, it's not a synchronous client */
	client->is_synchronous = 0;

	/* Add this client to linked list. */
	listnode_add(zebrad.client_list, client);

	struct frr_pthread_attr zclient_pthr_attrs = {
		.id = frr_pthread_get_id(),
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop
	};
	client->pthread =
		frr_pthread_new(&zclient_pthr_attrs, "Zebra API client thread");

	zebra_vrf_update_all(client);

	/* start read loop */
	zserv_client_event(client, ZSERV_CLIENT_READ);

	/* call callbacks */
	hook_call(zserv_client_connect, client);

	/* start pthread */
	frr_pthread_run(client->pthread, NULL);
}

/*
 * Accept socket connection.
 */
static int zserv_accept(struct thread *thread)
{
	int accept_sock;
	int client_sock;
	struct sockaddr_in client;
	socklen_t len;

	accept_sock = THREAD_FD(thread);

	/* Reregister myself. */
	zserv_event(NULL, ZSERV_ACCEPT);

	len = sizeof(struct sockaddr_in);
	client_sock = accept(accept_sock, (struct sockaddr *)&client, &len);

	if (client_sock < 0) {
		zlog_warn("Can't accept zebra socket: %s",
			  safe_strerror(errno));
		return -1;
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(client_sock);

	/* Create new zebra client. */
	zserv_client_create(client_sock);

	return 0;
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
	zebrad.sock = socket(sa.ss_family, SOCK_STREAM, 0);
	if (zebrad.sock < 0) {
		zlog_warn("Can't create zserv socket: %s",
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		return;
	}

	if (sa.ss_family != AF_UNIX) {
		sockopt_reuseaddr(zebrad.sock);
		sockopt_reuseport(zebrad.sock);
	} else {
		struct sockaddr_un *suna = (struct sockaddr_un *)&sa;
		if (suna->sun_path[0])
			unlink(suna->sun_path);
	}

	zserv_privs.change(ZPRIVS_RAISE);
	setsockopt_so_recvbuf(zebrad.sock, 1048576);
	setsockopt_so_sendbuf(zebrad.sock, 1048576);
	zserv_privs.change(ZPRIVS_LOWER);

	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");

	ret = bind(zebrad.sock, (struct sockaddr *)&sa, sa_len);
	if (ret < 0) {
		zlog_warn("Can't bind zserv socket on %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(zebrad.sock);
		zebrad.sock = -1;
		return;
	}
	if (sa.ss_family != AF_UNIX && zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	ret = listen(zebrad.sock, 5);
	if (ret < 0) {
		zlog_warn("Can't listen to zserv socket %s: %s", path,
			  safe_strerror(errno));
		zlog_warn(
			"zebra can't provide full functionality due to above error");
		close(zebrad.sock);
		zebrad.sock = -1;
		return;
	}

	umask(old_mask);

	zserv_event(NULL, ZSERV_ACCEPT);
}

void zserv_event(struct zserv *client, enum zserv_event event)
{
	switch (event) {
	case ZSERV_ACCEPT:
		thread_add_read(zebrad.master, zserv_accept, NULL, zebrad.sock,
				NULL);
		break;
	case ZSERV_PROCESS_MESSAGES:
		thread_add_event(zebrad.master, zserv_process_messages, client,
				 0, NULL);
		break;
	case ZSERV_HANDLE_CLOSE:
		thread_add_event(zebrad.master, zserv_handle_client_close,
				 client, 0, NULL);
	}
}


/* General purpose ---------------------------------------------------------- */

#define ZEBRA_TIME_BUF 32
static char *zserv_time_buf(time_t *time1, char *buf, int buflen)
{
	struct tm *tm;
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
	tm = gmtime(&now);

	if (now < ONE_DAY_SECOND)
		snprintf(buf, buflen, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min,
			 tm->tm_sec);
	else if (now < ONE_WEEK_SECOND)
		snprintf(buf, buflen, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour,
			 tm->tm_min);
	else
		snprintf(buf, buflen, "%02dw%dd%02dh", tm->tm_yday / 7,
			 tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
	return buf;
}

static void zebra_show_client_detail(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF], nhbuf[ZEBRA_TIME_BUF], mbuf[ZEBRA_TIME_BUF];
	time_t connect_time, last_read_time, last_write_time;
	uint16_t last_read_cmd, last_write_cmd;

	vty_out(vty, "Client: %s", zebra_route_string(client->proto));
	if (client->instance)
		vty_out(vty, " Instance: %d", client->instance);
	vty_out(vty, "\n");

	vty_out(vty, "------------------------ \n");
	vty_out(vty, "FD: %d \n", client->sock);
	vty_out(vty, "Route Table ID: %d \n", client->rtm_table);

	connect_time = (time_t) atomic_load_explicit(&client->connect_time,
						     memory_order_relaxed);

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

	last_read_time = (time_t)atomic_load_explicit(&client->last_read_time,
						      memory_order_relaxed);
	last_write_time = (time_t)atomic_load_explicit(&client->last_write_time,
						       memory_order_relaxed);

	last_read_cmd = atomic_load_explicit(&client->last_read_cmd,
					     memory_order_relaxed);
	last_write_cmd = atomic_load_explicit(&client->last_write_cmd,
					      memory_order_relaxed);

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

	vty_out(vty, "Type        Add        Update     Del \n");
	vty_out(vty, "================================================== \n");
	vty_out(vty, "IPv4        %-12d%-12d%-12d\n", client->v4_route_add_cnt,
		client->v4_route_upd8_cnt, client->v4_route_del_cnt);
	vty_out(vty, "IPv6        %-12d%-12d%-12d\n", client->v6_route_add_cnt,
		client->v6_route_upd8_cnt, client->v6_route_del_cnt);
	vty_out(vty, "Redist:v4   %-12d%-12d%-12d\n", client->redist_v4_add_cnt,
		0, client->redist_v4_del_cnt);
	vty_out(vty, "Redist:v6   %-12d%-12d%-12d\n", client->redist_v6_add_cnt,
		0, client->redist_v6_del_cnt);
	vty_out(vty, "Connected   %-12d%-12d%-12d\n", client->ifadd_cnt, 0,
		client->ifdel_cnt);
	vty_out(vty, "BFD peer    %-12d%-12d%-12d\n", client->bfd_peer_add_cnt,
		client->bfd_peer_upd8_cnt, client->bfd_peer_del_cnt);
	vty_out(vty, "Interface Up Notifications: %d\n", client->ifup_cnt);
	vty_out(vty, "Interface Down Notifications: %d\n", client->ifdown_cnt);
	vty_out(vty, "VNI add notifications: %d\n", client->vniadd_cnt);
	vty_out(vty, "VNI delete notifications: %d\n", client->vnidel_cnt);
	vty_out(vty, "L3-VNI add notifications: %d\n", client->l3vniadd_cnt);
	vty_out(vty, "L3-VNI delete notifications: %d\n", client->l3vnidel_cnt);
	vty_out(vty, "MAC-IP add notifications: %d\n", client->macipadd_cnt);
	vty_out(vty, "MAC-IP delete notifications: %d\n", client->macipdel_cnt);

#if defined DEV_BUILD
	vty_out(vty, "Input Fifo: %zu:%zu Output Fifo: %zu:%zu\n",
		client->ibuf_fifo->count, client->ibuf_fifo->max_count,
		client->obuf_fifo->count, client->obuf_fifo->max_count);
#endif
	vty_out(vty, "\n");
	return;
}

static void zebra_show_client_brief(struct vty *vty, struct zserv *client)
{
	char cbuf[ZEBRA_TIME_BUF], rbuf[ZEBRA_TIME_BUF];
	char wbuf[ZEBRA_TIME_BUF];
	time_t connect_time, last_read_time, last_write_time;

	connect_time = (time_t)atomic_load_explicit(&client->connect_time,
						    memory_order_relaxed);
	last_read_time = (time_t)atomic_load_explicit(&client->last_read_time,
						      memory_order_relaxed);
	last_write_time = (time_t)atomic_load_explicit(&client->last_write_time,
						       memory_order_relaxed);

	vty_out(vty, "%-8s%12s %12s%12s%8d/%-8d%8d/%-8d\n",
		zebra_route_string(client->proto),
		zserv_time_buf(&connect_time, cbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&last_read_time, rbuf, ZEBRA_TIME_BUF),
		zserv_time_buf(&last_write_time, wbuf, ZEBRA_TIME_BUF),
		client->v4_route_add_cnt + client->v4_route_upd8_cnt,
		client->v4_route_del_cnt,
		client->v6_route_add_cnt + client->v6_route_upd8_cnt,
		client->v6_route_del_cnt);
}

struct zserv *zserv_find_client(uint8_t proto, unsigned short instance)
{
	struct listnode *node, *nnode;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS(zebrad.client_list, node, nnode, client)) {
		if (client->proto == proto && client->instance == instance)
			return client;
	}

	return NULL;
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

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_detail(vty, client);

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
		"Name    Connect Time    Last Read  Last Write  IPv4 Routes       IPv6 Routes    \n");
	vty_out(vty,
		"--------------------------------------------------------------------------------\n");

	for (ALL_LIST_ELEMENTS_RO(zebrad.client_list, node, client))
		zebra_show_client_brief(vty, client);

	vty_out(vty, "Routes column shows (added+updated)/deleted\n");
	return CMD_SUCCESS;
}

#if defined(HANDLE_ZAPI_FUZZING)
void zserv_read_file(char *input)
{
	int fd;
	struct zserv *client = NULL;
	struct thread t;

	zebra_client_create(-1);

	frr_pthread_stop(client->pthread, NULL);
	frr_pthread_destroy(client->pthread);
	client->pthread = NULL;

	t.arg = client;

	fd = open(input, O_RDONLY | O_NONBLOCK);
	t.u.fd = fd;

	zserv_read(&t);

	close(fd);
}
#endif

void zserv_init(void)
{
	/* Client list init. */
	zebrad.client_list = list_new();
	zebrad.client_list->del = (void (*)(void *)) zserv_client_free;

	/* Misc init. */
	zebrad.sock = -1;

	install_element(ENABLE_NODE, &show_zebra_client_cmd);
	install_element(ENABLE_NODE, &show_zebra_client_summary_cmd);
}
