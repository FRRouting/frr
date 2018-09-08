/*
 * Zebra dataplane plugin for Forwarding Plane Manager (FPM) using netlink.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
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

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <string.h>

#include "config.h" /* Include this explicitly */
#include "lib/zebra.h"
#include "lib/json.h"
#include "lib/libfrr.h"
#include "lib/frratomic.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/debug.h"

#define SOUTHBOUND_DEFAULT_ADDR INADDR_LOOPBACK
#define SOUTHBOUND_DEFAULT_PORT 2620

/**
 * FPM header:
 * {
 *   version: 1 byte (always 1),
 *   type: 1 byte (1 for netlink, 2 protobuf),
 *   len: 2 bytes (network order),
 * }
 *
 * This header is used with any format to tell the users how many bytes to
 * expect.
 */
#define FPM_HEADER_SIZE 4

static const char *prov_name = "dplane_fpm_nl";

struct fpm_nl_ctx {
	/* data plane connection. */
	int socket;
	bool disabled;
	bool connecting;
	bool rib_complete;
	bool rmac_complete;
	struct sockaddr_storage addr;

	/* data plane buffers. */
	struct stream *ibuf;
	struct stream *obuf;
	pthread_mutex_t obuf_mutex;

	/*
	 * data plane context queue:
	 * When a FPM server connection becomes a bottleneck, we must keep the
	 * data plane contexts until we get a chance to process them.
	 */
	struct dplane_ctx_q ctxqueue;
	pthread_mutex_t ctxqueue_mutex;

	/* data plane events. */
	struct zebra_dplane_provider *prov;
	struct frr_pthread *fthread;
	struct thread *t_connect;
	struct thread *t_read;
	struct thread *t_write;
	struct thread *t_event;
	struct thread *t_dequeue;

	/* zebra events. */
	struct thread *t_ribreset;
	struct thread *t_ribwalk;
	struct thread *t_rmacreset;
	struct thread *t_rmacwalk;

	/* Statistic counters. */
	struct {
		/* Amount of bytes read into ibuf. */
		_Atomic uint32_t bytes_read;
		/* Amount of bytes written from obuf. */
		_Atomic uint32_t bytes_sent;
		/* Output buffer current usage. */
		_Atomic uint32_t obuf_bytes;
		/* Output buffer peak usage. */
		_Atomic uint32_t obuf_peak;

		/* Amount of connection closes. */
		_Atomic uint32_t connection_closes;
		/* Amount of connection errors. */
		_Atomic uint32_t connection_errors;

		/* Amount of user configurations: FNE_RECONNECT. */
		_Atomic uint32_t user_configures;
		/* Amount of user disable requests: FNE_DISABLE. */
		_Atomic uint32_t user_disables;

		/* Amount of data plane context processed. */
		_Atomic uint32_t dplane_contexts;
		/* Amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len;
		/* Peak amount of data plane contexts enqueued. */
		_Atomic uint32_t ctxqueue_len_peak;

		/* Amount of buffer full events. */
		_Atomic uint32_t buffer_full;
	} counters;
} *gfnc;

enum fpm_nl_events {
	/* Ask for FPM to reconnect the external server. */
	FNE_RECONNECT,
	/* Disable FPM. */
	FNE_DISABLE,
	/* Reset counters. */
	FNE_RESET_COUNTERS,
};

/*
 * Prototypes.
 */
static int fpm_process_event(struct thread *t);
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx);
static int fpm_rib_send(struct thread *t);
static int fpm_rib_reset(struct thread *t);
static int fpm_rmac_send(struct thread *t);
static int fpm_rmac_reset(struct thread *t);

/*
 * Helper functions.
 */

/**
 * Reorganizes the data on the buffer so it can fit more data.
 *
 * @param s stream pointer.
 */
static void stream_pulldown(struct stream *s)
{
	size_t rlen = STREAM_READABLE(s);

	/* No more data, so just move the pointers. */
	if (rlen == 0) {
		stream_reset(s);
		return;
	}

	/* Move the available data to the beginning. */
	memmove(s->data, &s->data[s->getp], rlen);
	s->getp = 0;
	s->endp = rlen;
}

/*
 * CLI.
 */
#define FPM_STR "Forwarding Plane Manager configuration\n"

DEFUN(fpm_set_address, fpm_set_address_cmd,
      "fpm address <A.B.C.D|X:X::X:X> [port (1-65535)]",
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;
	uint8_t naddr[INET6_BUFSIZ];

	if (argc == 5)
		port = strtol(argv[4]->arg, NULL, 10);

	/* Handle IPv4 addresses. */
	if (inet_pton(AF_INET, argv[2]->arg, naddr) == 1) {
		sin = (struct sockaddr_in *)&gfnc->addr;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port =
			port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		memcpy(&sin->sin_addr, naddr, sizeof(sin->sin_addr));

		goto ask_reconnect;
	}

	/* Handle IPv6 addresses. */
	if (inet_pton(AF_INET6, argv[2]->arg, naddr) != 1) {
		vty_out(vty, "%% Invalid address: %s\n", argv[2]->arg);
		return CMD_WARNING;
	}

	sin6 = (struct sockaddr_in6 *)&gfnc->addr;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port ? htons(port) : htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6->sin6_len = sizeof(*sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin6->sin6_addr, naddr, sizeof(sin6->sin6_addr));

ask_reconnect:
	thread_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_RECONNECT, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(no_fpm_set_address, no_fpm_set_address_cmd,
      "no fpm address [<A.B.C.D|X:X::X:X> [port <1-65535>]]",
      NO_STR
      FPM_STR
      "FPM remote listening server address\n"
      "Remote IPv4 FPM server\n"
      "Remote IPv6 FPM server\n"
      "FPM remote listening server port\n"
      "Remote FPM server port\n")
{
	thread_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_DISABLE, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(fpm_reset_counters, fpm_reset_counters_cmd,
      "clear fpm counters",
      CLEAR_STR
      FPM_STR
      "FPM statistic counters\n")
{
	thread_add_event(gfnc->fthread->master, fpm_process_event, gfnc,
			 FNE_RESET_COUNTERS, &gfnc->t_event);
	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters, fpm_show_counters_cmd,
      "show fpm counters",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n")
{
	vty_out(vty, "%30s\n%30s\n", "FPM counters", "============");

#define SHOW_COUNTER(label, counter) \
	vty_out(vty, "%28s: %u\n", (label), (counter))

	SHOW_COUNTER("Input bytes", gfnc->counters.bytes_read);
	SHOW_COUNTER("Output bytes", gfnc->counters.bytes_sent);
	SHOW_COUNTER("Output buffer current size", gfnc->counters.obuf_bytes);
	SHOW_COUNTER("Output buffer peak size", gfnc->counters.obuf_peak);
	SHOW_COUNTER("Connection closes", gfnc->counters.connection_closes);
	SHOW_COUNTER("Connection errors", gfnc->counters.connection_errors);
	SHOW_COUNTER("Data plane items processed",
		     gfnc->counters.dplane_contexts);
	SHOW_COUNTER("Data plane items enqueued",
		     gfnc->counters.ctxqueue_len);
	SHOW_COUNTER("Data plane items queue peak",
		     gfnc->counters.ctxqueue_len_peak);
	SHOW_COUNTER("Buffer full hits", gfnc->counters.buffer_full);
	SHOW_COUNTER("User FPM configurations", gfnc->counters.user_configures);
	SHOW_COUNTER("User FPM disable requests", gfnc->counters.user_disables);

#undef SHOW_COUNTER

	return CMD_SUCCESS;
}

DEFUN(fpm_show_counters_json, fpm_show_counters_json_cmd,
      "show fpm counters json",
      SHOW_STR
      FPM_STR
      "FPM statistic counters\n"
      JSON_STR)
{
	struct json_object *jo;

	jo = json_object_new_object();
	json_object_int_add(jo, "bytes-read", gfnc->counters.bytes_read);
	json_object_int_add(jo, "bytes-sent", gfnc->counters.bytes_sent);
	json_object_int_add(jo, "obuf-bytes", gfnc->counters.obuf_bytes);
	json_object_int_add(jo, "obuf-bytes-peak", gfnc->counters.obuf_peak);
	json_object_int_add(jo, "connection-closes",
			    gfnc->counters.connection_closes);
	json_object_int_add(jo, "connection-errors",
			    gfnc->counters.connection_errors);
	json_object_int_add(jo, "data-plane-contexts",
			    gfnc->counters.dplane_contexts);
	json_object_int_add(jo, "data-plane-contexts-queue",
			    gfnc->counters.ctxqueue_len);
	json_object_int_add(jo, "data-plane-contexts-queue-peak",
			    gfnc->counters.ctxqueue_len_peak);
	json_object_int_add(jo, "buffer-full-hits", gfnc->counters.buffer_full);
	json_object_int_add(jo, "user-configures",
			    gfnc->counters.user_configures);
	json_object_int_add(jo, "user-disables", gfnc->counters.user_disables);
	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);

	return CMD_SUCCESS;
}

static int fpm_write_config(struct vty *vty)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int written = 0;
	char addrstr[INET6_ADDRSTRLEN];

	if (gfnc->disabled)
		return written;

	switch (gfnc->addr.ss_family) {
	case AF_INET:
		written = 1;
		sin = (struct sockaddr_in *)&gfnc->addr;
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
		vty_out(vty, "fpm address %s", addrstr);
		if (sin->sin_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin->sin_port));

		vty_out(vty, "\n");
		break;
	case AF_INET6:
		written = 1;
		sin6 = (struct sockaddr_in6 *)&gfnc->addr;
		inet_ntop(AF_INET, &sin6->sin6_addr, addrstr, sizeof(addrstr));
		vty_out(vty, "fpm address %s", addrstr);
		if (sin6->sin6_port != htons(SOUTHBOUND_DEFAULT_PORT))
			vty_out(vty, " port %d", ntohs(sin6->sin6_port));

		vty_out(vty, "\n");
		break;

	default:
		break;
	}

	return written;
}

static struct cmd_node fpm_node = {
	.node = VTY_NODE,
	.prompt = "",
	.config_write = fpm_write_config,
};

/*
 * FPM functions.
 */
static int fpm_connect(struct thread *t);

static void fpm_reconnect(struct fpm_nl_ctx *fnc)
{
	/* Grab the lock to empty the stream and stop the zebra thread. */
	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	/* Avoid calling close on `-1`. */
	if (fnc->socket != -1) {
		close(fnc->socket);
		fnc->socket = -1;
	}

	stream_reset(fnc->ibuf);
	stream_reset(fnc->obuf);
	THREAD_OFF(fnc->t_read);
	THREAD_OFF(fnc->t_write);

	if (fnc->t_ribreset)
		thread_cancel_async(zrouter.master, &fnc->t_ribreset, NULL);
	if (fnc->t_ribwalk)
		thread_cancel_async(zrouter.master, &fnc->t_ribwalk, NULL);
	if (fnc->t_rmacreset)
		thread_cancel_async(zrouter.master, &fnc->t_rmacreset, NULL);
	if (fnc->t_rmacwalk)
		thread_cancel_async(zrouter.master, &fnc->t_rmacwalk, NULL);

	/* FPM is disabled, don't attempt to connect. */
	if (fnc->disabled)
		return;

	thread_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
			 &fnc->t_connect);
}

static int fpm_read(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	ssize_t rv;

	/* Let's ignore the input at the moment. */
	rv = stream_read_try(fnc->ibuf, fnc->socket,
			     STREAM_WRITEABLE(fnc->ibuf));
	if (rv == 0) {
		atomic_fetch_add_explicit(&fnc->counters.connection_closes, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: connection closed", __func__);

		fpm_reconnect(fnc);
		return 0;
	}
	if (rv == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK
		    || errno == EINTR)
			return 0;

		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		zlog_warn("%s: connection failure: %s", __func__,
			  strerror(errno));
		fpm_reconnect(fnc);
		return 0;
	}
	stream_reset(fnc->ibuf);

	/* Account all bytes read. */
	atomic_fetch_add_explicit(&fnc->counters.bytes_read, rv,
				  memory_order_relaxed);

	thread_add_read(fnc->fthread->master, fpm_read, fnc, fnc->socket,
			&fnc->t_read);

	return 0;
}

static int fpm_write(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	socklen_t statuslen;
	ssize_t bwritten;
	int rv, status;
	size_t btotal;

	if (fnc->connecting == true) {
		status = 0;
		statuslen = sizeof(status);

		rv = getsockopt(fnc->socket, SOL_SOCKET, SO_ERROR, &status,
				&statuslen);
		if (rv == -1 || status != 0) {
			if (rv != -1)
				zlog_warn("%s: connection failed: %s", __func__,
					  strerror(status));
			else
				zlog_warn("%s: SO_ERROR failed: %s", __func__,
					  strerror(status));

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);

			fpm_reconnect(fnc);
			return 0;
		}

		fnc->connecting = false;

		/* Ask zebra main thread to start walking the RIB table. */
		thread_add_timer(zrouter.master, fpm_rib_send, fnc, 0,
				 &fnc->t_ribwalk);
		thread_add_timer(zrouter.master, fpm_rmac_send, fnc, 0,
				 &fnc->t_rmacwalk);
	}

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	while (true) {
		/* Stream is empty: reset pointers and return. */
		if (STREAM_READABLE(fnc->obuf) == 0) {
			stream_reset(fnc->obuf);
			break;
		}

		/* Try to write all at once. */
		btotal = stream_get_endp(fnc->obuf) -
			stream_get_getp(fnc->obuf);
		bwritten = write(fnc->socket, stream_pnt(fnc->obuf), btotal);
		if (bwritten == 0) {
			atomic_fetch_add_explicit(
				&fnc->counters.connection_closes, 1,
				memory_order_relaxed);

			if (IS_ZEBRA_DEBUG_FPM)
				zlog_debug("%s: connection closed", __func__);
			break;
		}
		if (bwritten == -1) {
			/* Attempt to continue if blocked by a signal. */
			if (errno == EINTR)
				continue;
			/* Receiver is probably slow, lets give it some time. */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			atomic_fetch_add_explicit(
				&fnc->counters.connection_errors, 1,
				memory_order_relaxed);
			zlog_warn("%s: connection failure: %s", __func__,
				  strerror(errno));
			fpm_reconnect(fnc);
			break;
		}

		/* Account all bytes sent. */
		atomic_fetch_add_explicit(&fnc->counters.bytes_sent, bwritten,
					  memory_order_relaxed);

		/* Account number of bytes free. */
		atomic_fetch_sub_explicit(&fnc->counters.obuf_bytes, bwritten,
					  memory_order_relaxed);

		stream_forward_getp(fnc->obuf, (size_t)bwritten);
	}

	/* Stream is not empty yet, we must schedule more writes. */
	if (STREAM_READABLE(fnc->obuf)) {
		stream_pulldown(fnc->obuf);
		thread_add_write(fnc->fthread->master, fpm_write, fnc,
				 fnc->socket, &fnc->t_write);
		return 0;
	}

	return 0;
}

static int fpm_connect(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	struct sockaddr_in *sin = (struct sockaddr_in *)&fnc->addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&fnc->addr;
	socklen_t slen;
	int rv, sock;
	char addrstr[INET6_ADDRSTRLEN];

	sock = socket(fnc->addr.ss_family, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: fpm socket failed: %s", __func__,
			 strerror(errno));
		thread_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				 &fnc->t_connect);
		return 0;
	}

	set_nonblocking(sock);

	if (fnc->addr.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin);
	} else {
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, sizeof(addrstr));
		slen = sizeof(*sin6);
	}

	if (IS_ZEBRA_DEBUG_FPM)
		zlog_debug("%s: attempting to connect to %s:%d", __func__,
			   addrstr, ntohs(sin->sin_port));

	rv = connect(sock, (struct sockaddr *)&fnc->addr, slen);
	if (rv == -1 && errno != EINPROGRESS) {
		atomic_fetch_add_explicit(&fnc->counters.connection_errors, 1,
					  memory_order_relaxed);
		close(sock);
		zlog_warn("%s: fpm connection failed: %s", __func__,
			  strerror(errno));
		thread_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				 &fnc->t_connect);
		return 0;
	}

	fnc->connecting = (errno == EINPROGRESS);
	fnc->socket = sock;
	thread_add_read(fnc->fthread->master, fpm_read, fnc, sock,
			&fnc->t_read);
	thread_add_write(fnc->fthread->master, fpm_write, fnc, sock,
			 &fnc->t_write);

	/* Mark all routes as unsent. */
	thread_add_timer(zrouter.master, fpm_rib_reset, fnc, 0,
			 &fnc->t_ribreset);
	thread_add_timer(zrouter.master, fpm_rmac_reset, fnc, 0,
			 &fnc->t_rmacreset);

	return 0;
}

/**
 * Encode data plane operation context into netlink and enqueue it in the FPM
 * output buffer.
 *
 * @param fnc the netlink FPM context.
 * @param ctx the data plane operation context data.
 * @return 0 on success or -1 on not enough space.
 */
static int fpm_nl_enqueue(struct fpm_nl_ctx *fnc, struct zebra_dplane_ctx *ctx)
{
	uint8_t nl_buf[NL_PKT_BUF_SIZE];
	size_t nl_buf_len;
	ssize_t rv;
	uint64_t obytes, obytes_peak;

	nl_buf_len = 0;

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		rv = netlink_route_multipath(RTM_DELROUTE, ctx, nl_buf,
					     sizeof(nl_buf), true);
		if (rv <= 0) {
			zlog_err("%s: netlink_route_multipath failed",
				 __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;

		/* UPDATE operations need a INSTALL, otherwise just quit. */
		if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_DELETE)
			break;

		/* FALL THROUGH */
	case DPLANE_OP_ROUTE_INSTALL:
		rv = netlink_route_multipath(RTM_NEWROUTE, ctx,
					     &nl_buf[nl_buf_len],
					     sizeof(nl_buf) - nl_buf_len, true);
		if (rv <= 0) {
			zlog_err("%s: netlink_route_multipath failed",
				 __func__);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		break;

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		rv = netlink_macfdb_update_ctx(ctx, nl_buf, sizeof(nl_buf));
		if (rv <= 0) {
			zlog_err("%s: netlink_macfdb_update_ctx failed",
				 __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		break;

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_NONE:
		break;

	default:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: unhandled data plane message (%d) %s",
				   __func__, dplane_ctx_get_op(ctx),
				   dplane_op2str(dplane_ctx_get_op(ctx)));
		break;
	}

	/* Skip empty enqueues. */
	if (nl_buf_len == 0)
		return 0;

	/* We must know if someday a message goes beyond 65KiB. */
	assert((nl_buf_len + FPM_HEADER_SIZE) <= UINT16_MAX);

	/* Check if we have enough buffer space. */
	if (STREAM_WRITEABLE(fnc->obuf) < (nl_buf_len + FPM_HEADER_SIZE)) {
		atomic_fetch_add_explicit(&fnc->counters.buffer_full, 1,
					  memory_order_relaxed);

		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug(
				"%s: buffer full: wants to write %zu but has %zu",
				__func__, nl_buf_len + FPM_HEADER_SIZE,
				STREAM_WRITEABLE(fnc->obuf));

		return -1;
	}

	/*
	 * Fill in the FPM header information.
	 *
	 * See FPM_HEADER_SIZE definition for more information.
	 */
	stream_putc(fnc->obuf, 1);
	stream_putc(fnc->obuf, 1);
	stream_putw(fnc->obuf, nl_buf_len + FPM_HEADER_SIZE);

	/* Write current data. */
	stream_write(fnc->obuf, nl_buf, (size_t)nl_buf_len);

	/* Account number of bytes waiting to be written. */
	atomic_fetch_add_explicit(&fnc->counters.obuf_bytes,
				  nl_buf_len + FPM_HEADER_SIZE,
				  memory_order_relaxed);
	obytes = atomic_load_explicit(&fnc->counters.obuf_bytes,
				      memory_order_relaxed);
	obytes_peak = atomic_load_explicit(&fnc->counters.obuf_peak,
					   memory_order_relaxed);
	if (obytes_peak < obytes)
		atomic_store_explicit(&fnc->counters.obuf_peak, obytes,
				      memory_order_relaxed);

	/* Tell the thread to start writing. */
	thread_add_write(fnc->fthread->master, fpm_write, fnc, fnc->socket,
			 &fnc->t_write);

	return 0;
}

/**
 * Send all RIB installed routes to the connected data plane.
 */
static int fpm_rib_send(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	struct zebra_dplane_ctx *ctx;
	rib_tables_iter_t rt_iter;

	/* Allocate temporary context for all transactions. */
	ctx = dplane_ctx_alloc();

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL || dest->selected_fib == NULL)
				continue;

			/* Check for already sent routes. */
			if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM))
				continue;

			/* Enqueue route install. */
			dplane_ctx_reset(ctx);
			dplane_ctx_route_init(ctx, DPLANE_OP_ROUTE_INSTALL, rn,
					      dest->selected_fib);
			if (fpm_nl_enqueue(fnc, ctx) == -1) {
				/* Free the temporary allocated context. */
				dplane_ctx_fini(&ctx);

				thread_add_timer(zrouter.master, fpm_rib_send,
						 fnc, 1, &fnc->t_ribwalk);
				return 0;
			}

			/* Mark as sent. */
			SET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	/* Free the temporary allocated context. */
	dplane_ctx_fini(&ctx);

	/* All RIB routes sent! */
	fnc->rib_complete = true;

	return 0;
}

/*
 * The next three functions will handle RMAC enqueue.
 */
struct fpm_rmac_arg {
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	zebra_l3vni_t *zl3vni;
};

static void fpm_enqueue_rmac_table(struct hash_bucket *backet, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	zebra_mac_t *zrmac = backet->data;
	struct zebra_if *zif = fra->zl3vni->vxlan_if->info;
	const struct zebra_l2info_vxlan *vxl = &zif->l2info.vxl;
	struct zebra_if *br_zif;
	vlanid_t vid;
	bool sticky;

	/* Entry already sent. */
	if (CHECK_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT))
		return;

	sticky = !!CHECK_FLAG(zrmac->flags,
			      (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));
	br_zif = (struct zebra_if *)(zif->brslave_info.br_if->info);
	vid = IS_ZEBRA_IF_BRIDGE_VLAN_AWARE(br_zif) ? vxl->access_vlan : 0;

	dplane_ctx_reset(fra->ctx);
	dplane_ctx_set_op(fra->ctx, DPLANE_OP_MAC_INSTALL);
	dplane_mac_init(fra->ctx, fra->zl3vni->vxlan_if,
			zif->brslave_info.br_if, vid,
			&zrmac->macaddr, zrmac->fwd_info.r_vtep_ip, sticky);
	if (fpm_nl_enqueue(fra->fnc, fra->ctx) == -1) {
		thread_add_timer(zrouter.master, fpm_rmac_send,
				 fra->fnc, 1, &fra->fnc->t_rmacwalk);
	}
}

static void fpm_enqueue_l3vni_table(struct hash_bucket *backet, void *arg)
{
	struct fpm_rmac_arg *fra = arg;
	zebra_l3vni_t *zl3vni = backet->data;

	fra->zl3vni = zl3vni;
	hash_iterate(zl3vni->rmac_table, fpm_enqueue_rmac_table, zl3vni);
}

static int fpm_rmac_send(struct thread *t)
{
	struct fpm_rmac_arg fra;

	fra.fnc = THREAD_ARG(t);
	fra.ctx = dplane_ctx_alloc();
	hash_iterate(zrouter.l3vni_table, fpm_enqueue_l3vni_table, &fra);
	dplane_ctx_fini(&fra.ctx);

	return 0;
}

/**
 * Resets the RIB FPM flags so we send all routes again.
 */
static int fpm_rib_reset(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	rib_dest_t *dest;
	struct route_node *rn;
	struct route_table *rt;
	rib_tables_iter_t rt_iter;

	fnc->rib_complete = false;

	rt_iter.state = RIB_TABLES_ITER_S_INIT;
	while ((rt = rib_tables_iter_next(&rt_iter))) {
		for (rn = route_top(rt); rn; rn = srcdest_route_next(rn)) {
			dest = rib_dest_from_rnode(rn);
			/* Skip bad route entries. */
			if (dest == NULL)
				continue;

			UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
		}
	}

	return 0;
}

/*
 * The next three function will handle RMAC table reset.
 */
static void fpm_unset_rmac_table(struct hash_bucket *backet, void *arg)
{
	zebra_mac_t *zrmac = backet->data;

	UNSET_FLAG(zrmac->flags, ZEBRA_MAC_FPM_SENT);
}

static void fpm_unset_l3vni_table(struct hash_bucket *backet, void *arg)
{
	zebra_l3vni_t *zl3vni = backet->data;

	hash_iterate(zl3vni->rmac_table, fpm_unset_rmac_table, zl3vni);
}

static int fpm_rmac_reset(struct thread *t)
{
	hash_iterate(zrouter.l3vni_table, fpm_unset_l3vni_table, NULL);

	return 0;
}

static int fpm_process_queue(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	struct zebra_dplane_ctx *ctx;

	frr_mutex_lock_autounlock(&fnc->ctxqueue_mutex);

	while (true) {
		/* No space available yet. */
		if (STREAM_WRITEABLE(fnc->obuf) < NL_PKT_BUF_SIZE)
			break;

		/* Dequeue next item or quit processing. */
		ctx = dplane_ctx_dequeue(&fnc->ctxqueue);
		if (ctx == NULL)
			break;

		fpm_nl_enqueue(fnc, ctx);

		/* Account the processed entries. */
		atomic_fetch_add_explicit(&fnc->counters.dplane_contexts, 1,
					  memory_order_relaxed);
		atomic_fetch_sub_explicit(&fnc->counters.ctxqueue_len, 1,
					  memory_order_relaxed);

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(fnc->prov, ctx);
	}

	/* Check for more items in the queue. */
	if (atomic_load_explicit(&fnc->counters.ctxqueue_len,
				 memory_order_relaxed)
	    > 0)
		thread_add_timer(fnc->fthread->master, fpm_process_queue,
				 fnc, 0, &fnc->t_dequeue);

	return 0;
}

/**
 * Handles external (e.g. CLI, data plane or others) events.
 */
static int fpm_process_event(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	int event = THREAD_VAL(t);

	switch (event) {
	case FNE_DISABLE:
		zlog_info("%s: manual FPM disable event", __func__);
		fnc->disabled = true;
		atomic_fetch_add_explicit(&fnc->counters.user_disables, 1,
					  memory_order_relaxed);

		/* Call reconnect to disable timers and clean up context. */
		fpm_reconnect(fnc);
		break;

	case FNE_RECONNECT:
		zlog_info("%s: manual FPM reconnect event", __func__);
		fnc->disabled = false;
		atomic_fetch_add_explicit(&fnc->counters.user_configures, 1,
					  memory_order_relaxed);
		fpm_reconnect(fnc);
		break;

	case FNE_RESET_COUNTERS:
		zlog_info("%s: manual FPM counters reset event", __func__);
		memset(&fnc->counters, 0, sizeof(fnc->counters));
		break;

	default:
		if (IS_ZEBRA_DEBUG_FPM)
			zlog_debug("%s: unhandled event %d", __func__, event);
		break;
	}

	return 0;
}

/*
 * Data plane functions.
 */
static int fpm_nl_start(struct zebra_dplane_provider *prov)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	fnc->fthread = frr_pthread_new(NULL, prov_name, prov_name);
	assert(frr_pthread_run(fnc->fthread, NULL) == 0);
	fnc->ibuf = stream_new(NL_PKT_BUF_SIZE);
	fnc->obuf = stream_new(NL_PKT_BUF_SIZE * 128);
	pthread_mutex_init(&fnc->obuf_mutex, NULL);
	fnc->socket = -1;
	fnc->disabled = true;
	fnc->prov = prov;
	TAILQ_INIT(&fnc->ctxqueue);
	pthread_mutex_init(&fnc->ctxqueue_mutex, NULL);

	return 0;
}

static int fpm_nl_finish(struct zebra_dplane_provider *prov, bool early)
{
	struct fpm_nl_ctx *fnc;

	fnc = dplane_provider_get_data(prov);
	stream_free(fnc->ibuf);
	stream_free(fnc->obuf);
	close(fnc->socket);

	return 0;
}

static int fpm_nl_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	struct fpm_nl_ctx *fnc;
	int counter, limit;
	uint64_t cur_queue, peak_queue;

	fnc = dplane_provider_get_data(prov);
	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (ctx == NULL)
			break;

		/*
		 * Skip all notifications if not connected, we'll walk the RIB
		 * anyway.
		 */
		if (fnc->socket != -1 && fnc->connecting == false) {
			frr_mutex_lock_autounlock(&fnc->ctxqueue_mutex);
			dplane_ctx_enqueue_tail(&fnc->ctxqueue, ctx);

			/* Account the number of contexts. */
			atomic_fetch_add_explicit(&fnc->counters.ctxqueue_len,
						  1, memory_order_relaxed);
			cur_queue = atomic_load_explicit(
				&fnc->counters.ctxqueue_len,
				memory_order_relaxed);
			peak_queue = atomic_load_explicit(
				&fnc->counters.ctxqueue_len_peak,
				memory_order_relaxed);
			if (peak_queue < cur_queue)
				atomic_store_explicit(
					&fnc->counters.ctxqueue_len_peak,
					peak_queue, memory_order_relaxed);
			continue;
		}

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	if (atomic_load_explicit(&fnc->counters.ctxqueue_len,
				 memory_order_relaxed)
	    > 0)
		thread_add_timer(fnc->fthread->master, fpm_process_queue,
				 fnc, 0, &fnc->t_dequeue);

	return 0;
}

static int fpm_nl_new(struct thread_master *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	int rv;

	gfnc = calloc(1, sizeof(*gfnc));
	rv = dplane_provider_register(prov_name, DPLANE_PRIO_POSTPROCESS,
				      DPLANE_PROV_FLAG_THREADED, fpm_nl_start,
				      fpm_nl_process, fpm_nl_finish, gfnc,
				      &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);

	install_node(&fpm_node);
	install_element(ENABLE_NODE, &fpm_show_counters_cmd);
	install_element(ENABLE_NODE, &fpm_show_counters_json_cmd);
	install_element(ENABLE_NODE, &fpm_reset_counters_cmd);
	install_element(CONFIG_NODE, &fpm_set_address_cmd);
	install_element(CONFIG_NODE, &no_fpm_set_address_cmd);

	return 0;
}

static int fpm_nl_init(void)
{
	hook_register(frr_late_init, fpm_nl_new);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "dplane_fpm_nl",
	.version = "0.0.1",
	.description = "Data plane plugin for FPM using netlink.",
	.init = fpm_nl_init,
	)
