/*
 * libzebra ZeroMQ bindings
 * Copyright (C) 2015  David Lamparter
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
#include <zmq.h>

#include "thread.h"
#include "memory.h"
#include "frr_zmq.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, ZEROMQ_CB, "ZeroMQ callback")

/* libzmq's context */
void *frrzmq_context = NULL;
static unsigned frrzmq_initcount = 0;

void frrzmq_init(void)
{
	if (frrzmq_initcount++ == 0) {
		frrzmq_context = zmq_ctx_new();
		zmq_ctx_set(frrzmq_context, ZMQ_IPV6, 1);
	}
}

void frrzmq_finish(void)
{
	if (--frrzmq_initcount == 0) {
		zmq_ctx_term(frrzmq_context);
		frrzmq_context = NULL;
	}
}

/* read callback integration */
struct frrzmq_cb {
	struct thread *thread;
	void *zmqsock;
	void *arg;

	void (*cb_msg)(void *arg, void *zmqsock, zmq_msg_t *msg);
};


static int frrzmq_read_msg(struct thread *t)
{
	struct frrzmq_cb *cb = THREAD_ARG(t);
	zmq_msg_t msg;
	int ret;

	while (1) {
		zmq_pollitem_t polli = {
			.socket = cb->zmqsock,
			.events = ZMQ_POLLIN
		};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;
		if (!(polli.revents & ZMQ_POLLIN))
			break;

		if (zmq_msg_init(&msg))
			goto out_err;
		ret = zmq_msg_recv(&msg, cb->zmqsock, ZMQ_NOBLOCK);
		if (ret < 0) {
			zmq_msg_close (&msg);

			if (errno == EAGAIN)
				break;
			goto out_err;
		}
		cb->cb_msg(cb->arg, cb->zmqsock, &msg);
		zmq_msg_close(&msg);
	}

	funcname_thread_add_read_write(THREAD_READ, t->master, frrzmq_read_msg,
			cb, t->u.fd, &cb->thread, t->funcname, t->schedfrom,
			t->schedfrom_line);
	return 0;

out_err:
	zlog_err("ZeroMQ error: %s(%d)", strerror (errno), errno);
	return 0;
}

struct frrzmq_cb *funcname_frrzmq_thread_read_msg(
		struct thread_master *master,
		void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
		void *arg, void *zmqsock, debugargdef)
{
	int fd;
	size_t fd_len = sizeof(fd);
	struct frrzmq_cb *cb;

	if (zmq_getsockopt(zmqsock, ZMQ_FD, &fd, &fd_len))
		return NULL;

	cb = XCALLOC(MTYPE_ZEROMQ_CB, sizeof(struct frrzmq_cb));
	if (!cb)
		return NULL;

	cb->arg = arg;
	cb->zmqsock = zmqsock;
	cb->cb_msg = func;
	funcname_thread_add_read_write(THREAD_READ, master, frrzmq_read_msg,
			cb, fd, &cb->thread, funcname, schedfrom, fromln);
	return cb;
}

void frrzmq_thread_cancel(struct frrzmq_cb *cb)
{
	thread_cancel(cb->thread);
	XFREE(MTYPE_ZEROMQ_CB, cb);
}
