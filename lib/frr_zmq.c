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
	int fd;

	bool cancelled;

	struct frrzmq_cb *dual; /* write one is self is read, and vice versa */

	void (*cb_msg)(void *arg, void *zmqsock);
	void (*cb_part)(void *arg, void *zmqsock, zmq_msg_t *msg,
			unsigned partnum);
	void (*cb_error)(void *arg, void *zmqsock);
};

static int frrzmq_read_msg(struct thread *t)
{
	struct frrzmq_cb *cb = THREAD_ARG(t);
	zmq_msg_t msg;
	unsigned partno;
	unsigned char read = 0;
	int ret, more;
	size_t moresz;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLIN};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;
		if (polli.revents & ZMQ_POLLERR)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLIN))
			break;

		if (cb->cb_msg) {
			cb->cb_msg(cb->arg, cb->zmqsock);
			read = 1;

			if (cb->cancelled) {
				if (cb->dual) {
					frrzmq_check_events(cb->dual,
							    ZMQ_POLLOUT);
					cb->dual->dual = NULL;
				}
				XFREE(MTYPE_ZEROMQ_CB, cb);
				return 0;
			}
			continue;
		}

		partno = 0;
		if (zmq_msg_init(&msg))
			goto out_err;
		do {
			ret = zmq_msg_recv(&msg, cb->zmqsock, ZMQ_NOBLOCK);
			if (ret < 0) {
				if (errno == EAGAIN)
					break;

				zmq_msg_close(&msg);
				goto out_err;
			}
			read = 1;

			cb->cb_part(cb->arg, cb->zmqsock, &msg, partno);
			if (cb->cancelled) {
				zmq_msg_close(&msg);
				if (cb->dual) {
					frrzmq_check_events(cb->dual,
							    ZMQ_POLLOUT);
					cb->dual->dual = NULL;
				}
				XFREE(MTYPE_ZEROMQ_CB, cb);
				return 0;
			}

			/* cb_part may have read additional parts of the
			 * message; don't use zmq_msg_more here */
			moresz = sizeof(more);
			more = 0;
			ret = zmq_getsockopt(cb->zmqsock, ZMQ_RCVMORE, &more,
					     &moresz);
			if (ret < 0) {
				zmq_msg_close(&msg);
				goto out_err;
			}

			partno++;
		} while (more);
		zmq_msg_close(&msg);
	}

	if (cb->dual && read)
		frrzmq_check_events(cb->dual, ZMQ_POLLOUT);

	funcname_thread_add_read_write(THREAD_READ, t->master, frrzmq_read_msg,
				       cb, cb->fd, &cb->thread, t->funcname,
				       t->schedfrom, t->schedfrom_line);
	return 0;

out_err:
	zlog_err("ZeroMQ error: %s(%d)", strerror(errno), errno);
	if (cb->cb_error)
		cb->cb_error(cb->arg, cb->zmqsock);
	return 0;
}

struct frrzmq_cb *funcname_frrzmq_thread_add_read(
	struct thread_master *master, void (*msgfunc)(void *arg, void *zmqsock),
	void (*partfunc)(void *arg, void *zmqsock, zmq_msg_t *msg,
			 unsigned partnum),
	void (*errfunc)(void *arg, void *zmqsock), void *arg, void *zmqsock,
	struct frrzmq_cb *dual, debugargdef)
{
	int fd, events;
	size_t len;
	struct frrzmq_cb *cb;

	if (!(msgfunc || partfunc) || (msgfunc && partfunc))
		return NULL;
	len = sizeof(fd);
	if (zmq_getsockopt(zmqsock, ZMQ_FD, &fd, &len))
		return NULL;
	len = sizeof(events);
	if (zmq_getsockopt(zmqsock, ZMQ_EVENTS, &events, &len))
		return NULL;

	cb = XCALLOC(MTYPE_ZEROMQ_CB, sizeof(struct frrzmq_cb));
	if (!cb)
		return NULL;

	cb->arg = arg;
	cb->zmqsock = zmqsock;
	cb->cb_msg = msgfunc;
	cb->cb_part = partfunc;
	cb->cb_error = errfunc;
	cb->fd = fd;
	cb->dual = dual;
	if (dual)
		dual->dual = cb;

	if (events & ZMQ_POLLERR) {
		if (cb->cb_error)
			cb->cb_error(cb->arg, cb->zmqsock);
		return NULL;
	}

	if (events & ZMQ_POLLIN)
		funcname_thread_add_event(master, frrzmq_read_msg, cb, fd,
					  &cb->thread, funcname, schedfrom,
					  fromln);
	else
		funcname_thread_add_read_write(
			THREAD_READ, master, frrzmq_read_msg, cb, fd,
			&cb->thread, funcname, schedfrom, fromln);
	return cb;
}

static int frrzmq_write_msg(struct thread *t)
{
	struct frrzmq_cb *cb = THREAD_ARG(t);
	unsigned char written = 0;
	int ret;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLOUT};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;
		if (polli.revents & ZMQ_POLLERR)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLOUT))
			break;

		if (cb->cb_msg) {
			cb->cb_msg(cb->arg, cb->zmqsock);
			written = 1;

			if (cb->cancelled) {
				if (cb->dual) {
					frrzmq_check_events(cb->dual,
							    ZMQ_POLLIN);
					cb->dual->dual = NULL;
				}
				XFREE(MTYPE_ZEROMQ_CB, cb);
				return 0;
			}
			continue;
		}
	}

	if (cb->dual && written)
		frrzmq_check_events(cb->dual, ZMQ_POLLIN);

	funcname_thread_add_read_write(
		THREAD_WRITE, t->master, frrzmq_write_msg, cb, cb->fd,
		&cb->thread, t->funcname, t->schedfrom, t->schedfrom_line);
	return 0;

out_err:
	zlog_err("ZeroMQ error: %s(%d)", strerror(errno), errno);
	return 0;
}
struct frrzmq_cb *funcname_frrzmq_thread_add_write(
	struct thread_master *master, void (*msgfunc)(void *arg, void *zmqsock),
	void (*errfunc)(void *arg, void *zmqsock), void *arg, void *zmqsock,
	struct frrzmq_cb *dual, debugargdef)
{
	int fd, events;
	size_t len;
	struct frrzmq_cb *cb;

	if (!msgfunc)
		return NULL;
	len = sizeof(fd);
	if (zmq_getsockopt(zmqsock, ZMQ_FD, &fd, &len))
		return NULL;
	len = sizeof(events);
	if (zmq_getsockopt(zmqsock, ZMQ_EVENTS, &events, &len))
		return NULL;

	cb = XCALLOC(MTYPE_ZEROMQ_CB, sizeof(struct frrzmq_cb));
	if (!cb)
		return NULL;

	cb->arg = arg;
	cb->zmqsock = zmqsock;
	cb->cb_msg = msgfunc;
	cb->cb_part = NULL;
	cb->cb_error = errfunc;
	cb->fd = fd;
	cb->dual = dual;
	if (dual)
		dual->dual = cb;

	if (events & ZMQ_POLLERR) {
		if (cb->cb_error)
			cb->cb_error(cb->arg, cb->zmqsock);
		return NULL;
	}

	if (events & ZMQ_POLLOUT)
		funcname_thread_add_event(master, frrzmq_write_msg, cb, fd,
					  &cb->thread, funcname, schedfrom,
					  fromln);
	else
		funcname_thread_add_read_write(
			THREAD_WRITE, master, frrzmq_write_msg, cb, fd,
			&cb->thread, funcname, schedfrom, fromln);
	return cb;
}

void frrzmq_thread_cancel(struct frrzmq_cb *cb)
{
	if (!cb)
		return;
	if (!cb->thread) {
		/* canceling from within callback */
		cb->cancelled = 1;
		return;
	}
	thread_cancel(cb->thread);
	if (cb->dual)
		cb->dual->dual = NULL;
	XFREE(MTYPE_ZEROMQ_CB, cb);
}

void frrzmq_check_events(struct frrzmq_cb *cb, int event)
{
	int events;
	size_t len;

	if (zmq_getsockopt(cb->zmqsock, ZMQ_EVENTS, &events, &len))
		return;
	if (events & event && cb->thread)
		funcname_thread_add_event(
			cb->thread->master,
			(event == ZMQ_POLLIN ? frrzmq_read_msg
					     : frrzmq_write_msg),
			cb, cb->fd, &cb->thread, cb->thread->funcname,
			cb->thread->schedfrom, cb->thread->schedfrom_line);
}
