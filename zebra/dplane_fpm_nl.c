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
#include "lib/libfrr.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/ns.h"
#include "lib/frr_pthread.h"
#include "zebra/zebra_dplane.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/debug.h"

#define SOUTHBOUND_DEFAULT_ADDR INADDR_LOOPBACK
#define SOUTHBOUND_DEFAULT_PORT 2620

static const char *prov_name = "dplane_fpm_nl";

struct fpm_nl_ctx {
	/* data plane connection. */
	int socket;
	bool connecting;
	struct sockaddr_storage addr;

	/* data plane buffers. */
	struct stream *ibuf;
	struct stream *obuf;
	pthread_mutex_t obuf_mutex;

	/* data plane events. */
	struct frr_pthread *fthread;
	struct thread *t_connect;
	struct thread *t_read;
	struct thread *t_write;
};

/*
 * FPM functions.
 */
static int fpm_connect(struct thread *t);

static void fpm_reconnect(struct fpm_nl_ctx *fnc)
{
	/* Grab the lock to empty the stream and stop the zebra thread. */
	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	close(fnc->socket);
	fnc->socket = -1;
	stream_reset(fnc->ibuf);
	stream_reset(fnc->obuf);
	THREAD_OFF(fnc->t_read);
	THREAD_OFF(fnc->t_write);
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
		zlog_debug("%s: connection closed", __func__);
		fpm_reconnect(fnc);
		return 0;
	}
	if (rv == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK
		    || errno == EINTR)
			return 0;

		zlog_debug("%s: connection failure: %s", __func__,
			   strerror(errno));
		fpm_reconnect(fnc);
		return 0;
	}
	stream_reset(fnc->ibuf);

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
				zlog_debug("%s: connection failed: %s",
					   __func__, strerror(status));
			else
				zlog_debug("%s: SO_ERROR failed: %s", __func__,
					   strerror(status));

			fpm_reconnect(fnc);
			return 0;
		}

		fnc->connecting = false;
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
			zlog_debug("%s: connection closed", __func__);
			break;
		}
		if (bwritten == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK
			    || errno == EINTR)
				break;

			zlog_debug("%s: connection failure: %s", __func__,
				   strerror(errno));
			fpm_reconnect(fnc);
			break;
		}

		stream_forward_getp(fnc->obuf, (size_t)bwritten);
	}

	/* Stream is not empty yet, we must schedule more writes. */
	if (STREAM_READABLE(fnc->obuf)) {
		thread_add_write(fnc->fthread->master, fpm_write, fnc,
				 fnc->socket, &fnc->t_write);
		return 0;
	}

	return 0;
}

static int fpm_connect(struct thread *t)
{
	struct fpm_nl_ctx *fnc = THREAD_ARG(t);
	struct sockaddr_in *sin;
	int rv, sock;
	char addrstr[INET6_ADDRSTRLEN];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: fpm connection failed: %s", __func__,
			 strerror(errno));
		thread_add_timer(fnc->fthread->master, fpm_connect, fnc, 3,
				 &fnc->t_connect);
		return 0;
	}

	set_nonblocking(sock);

	sin = (struct sockaddr_in *)&fnc->addr;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(SOUTHBOUND_DEFAULT_ADDR);
	sin->sin_port = htons(SOUTHBOUND_DEFAULT_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin->sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	inet_ntop(AF_INET, &sin->sin_addr, addrstr, sizeof(addrstr));
	zlog_debug("%s: attempting to connect to %s:%d", __func__, addrstr,
		   ntohs(sin->sin_port));

	rv = connect(sock, (struct sockaddr *)sin, sizeof(*sin));
	if (rv == -1 && errno != EINPROGRESS) {
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

	nl_buf_len = 0;

	frr_mutex_lock_autounlock(&fnc->obuf_mutex);

	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		rv = netlink_route_multipath(RTM_DELROUTE, ctx, nl_buf,
					     sizeof(nl_buf));
		if (rv <= 0) {
			zlog_debug("%s: netlink_route_multipath failed",
				   __func__);
			return 0;
		}

		nl_buf_len = (size_t)rv;
		if (STREAM_WRITEABLE(fnc->obuf) < nl_buf_len) {
			zlog_debug("%s: not enough output buffer (%ld vs %lu)",
				   __func__, STREAM_WRITEABLE(fnc->obuf),
				   nl_buf_len);
			return -1;
		}

		/* UPDATE operations need a INSTALL, otherwise just quit. */
		if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_DELETE)
			break;

		/* FALL THROUGH */
	case DPLANE_OP_ROUTE_INSTALL:
		rv = netlink_route_multipath(RTM_NEWROUTE, ctx,
					     &nl_buf[nl_buf_len],
					     sizeof(nl_buf) - nl_buf_len);
		if (rv <= 0) {
			zlog_debug("%s: netlink_route_multipath failed",
				   __func__);
			return 0;
		}

		nl_buf_len += (size_t)rv;
		if (STREAM_WRITEABLE(fnc->obuf) < nl_buf_len) {
			zlog_debug("%s: not enough output buffer (%ld vs %lu)",
				   __func__, STREAM_WRITEABLE(fnc->obuf),
				   nl_buf_len);
			return -1;
		}
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
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
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
		zlog_debug("%s: unhandled data plane message (%d) %s",
			   __func__, dplane_ctx_get_op(ctx),
			   dplane_op2str(dplane_ctx_get_op(ctx)));
		break;
	}

	/* Skip empty enqueues. */
	if (nl_buf_len == 0)
		return 0;

	/*
	 * FPM header:
	 * {
	 *   version: 1 byte (always 1),
	 *   type: 1 byte (1 for netlink, 2 protobuf),
	 *   len: 2 bytes (network order),
	 * }
	 */
	stream_putc(fnc->obuf, 1);
	stream_putc(fnc->obuf, 1);
	assert(nl_buf_len < UINT16_MAX);
	stream_putw(fnc->obuf, nl_buf_len + 4);

	/* Write current data. */
	stream_write(fnc->obuf, nl_buf, (size_t)nl_buf_len);

	/* Tell the thread to start writing. */
	thread_add_write(fnc->fthread->master, fpm_write, fnc, fnc->socket,
			 &fnc->t_write);

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

	thread_add_timer(fnc->fthread->master, fpm_connect, fnc, 1,
			 &fnc->t_connect);

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
		if (fnc->socket != -1 && fnc->connecting == false)
			fpm_nl_enqueue(fnc, ctx);

		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static int fpm_nl_new(struct thread_master *tm)
{
	struct zebra_dplane_provider *prov = NULL;
	struct fpm_nl_ctx *fnc;
	int rv;

	fnc = calloc(1, sizeof(*fnc));
	rv = dplane_provider_register(prov_name, DPLANE_PRIO_POSTPROCESS,
				      DPLANE_PROV_FLAG_THREADED, fpm_nl_start,
				      fpm_nl_process, fpm_nl_finish, fnc,
				      &prov);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("%s register status: %d", prov_name, rv);

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
