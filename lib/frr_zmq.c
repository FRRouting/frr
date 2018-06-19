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

static int frrzmq_read_msg(struct thread *t)
{
	struct frrzmq_cb **cbp = THREAD_ARG(t);
	struct frrzmq_cb *cb;
	zmq_msg_t msg;
	unsigned partno;
	unsigned char read = 0;
	int ret, more;
	size_t moresz;

	if (!cbp)
		return 1;
	cb = (*cbp);
	if (!cb || !cb->zmqsock)
		return 1;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLIN};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLIN))
			break;

		if (cb->read.cb_msg) {
			cb->read.cb_msg(cb->read.arg, cb->zmqsock);
			read = 1;

			if (cb->read.cancelled) {
				frrzmq_check_events(cbp, &cb->write,
						    ZMQ_POLLOUT);
				cb->read.thread = NULL;
				if (cb->write.cancelled && !cb->write.thread)
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

			cb->read.cb_part(cb->read.arg, cb->zmqsock, &msg,
					 partno);
			if (cb->read.cancelled) {
				zmq_msg_close(&msg);
				frrzmq_check_events(cbp, &cb->write,
						    ZMQ_POLLOUT);
				cb->read.thread = NULL;
				if (cb->write.cancelled && !cb->write.thread)
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

	if (read)
		frrzmq_check_events(cbp, &cb->write, ZMQ_POLLOUT);

	funcname_thread_add_read_write(
		THREAD_READ, t->master, frrzmq_read_msg, cbp, cb->fd,
		&cb->read.thread, t->funcname, t->schedfrom, t->schedfrom_line);
	return 0;

out_err:
	zlog_err("ZeroMQ read error: %s(%d)", strerror(errno), errno);
	if (cb->read.cb_error)
		cb->read.cb_error(cb->read.arg, cb->zmqsock);
	return 1;
}

int funcname_frrzmq_thread_add_read(struct thread_master *master,
				    void (*msgfunc)(void *arg, void *zmqsock),
				    void (*partfunc)(void *arg, void *zmqsock,
						     zmq_msg_t *msg,
						     unsigned partnum),
				    void (*errfunc)(void *arg, void *zmqsock),
				    void *arg, void *zmqsock,
				    struct frrzmq_cb **cbp, debugargdef)
{
	int fd, events;
	size_t len;
	struct frrzmq_cb *cb;

	if (!cbp)
		return -1;
	if (!(msgfunc || partfunc) || (msgfunc && partfunc))
		return -1;
	len = sizeof(fd);
	if (zmq_getsockopt(zmqsock, ZMQ_FD, &fd, &len))
		return -1;
	len = sizeof(events);
	if (zmq_getsockopt(zmqsock, ZMQ_EVENTS, &events, &len))
		return -1;

	if (*cbp)
		cb = *cbp;
	else {
		cb = XCALLOC(MTYPE_ZEROMQ_CB, sizeof(struct frrzmq_cb));
		if (!cb)
			return -1;

		cb->write.cancelled = 1;
		*cbp = cb;
	}

	cb->zmqsock = zmqsock;
	cb->fd = fd;
	cb->read.arg = arg;
	cb->read.cb_msg = msgfunc;
	cb->read.cb_part = partfunc;
	cb->read.cb_error = errfunc;
	cb->read.cancelled = 0;

	if (events & ZMQ_POLLIN) {
		if (cb->read.thread) {
			thread_cancel(cb->read.thread);
			cb->read.thread = NULL;
		}
		funcname_thread_add_event(master, frrzmq_read_msg, cbp, fd,
					  &cb->read.thread, funcname, schedfrom,
					  fromln);
	} else
		funcname_thread_add_read_write(
			THREAD_READ, master, frrzmq_read_msg, cbp, fd,
			&cb->read.thread, funcname, schedfrom, fromln);
	return 0;
}

static int frrzmq_write_msg(struct thread *t)
{
	struct frrzmq_cb **cbp = THREAD_ARG(t);
	struct frrzmq_cb *cb;
	unsigned char written = 0;
	int ret;

	if (!cbp)
		return 1;
	cb = (*cbp);
	if (!cb || !cb->zmqsock)
		return 1;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLOUT};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLOUT))
			break;

		if (cb->write.cb_msg) {
			cb->write.cb_msg(cb->write.arg, cb->zmqsock);
			written = 1;

			if (cb->write.cancelled) {
				frrzmq_check_events(cbp, &cb->read, ZMQ_POLLIN);
				cb->write.thread = NULL;
				if (cb->read.cancelled && !cb->read.thread)
					XFREE(MTYPE_ZEROMQ_CB, cb);
				return 0;
			}
			continue;
		}
	}

	if (written)
		frrzmq_check_events(cbp, &cb->read, ZMQ_POLLIN);

	funcname_thread_add_read_write(THREAD_WRITE, t->master,
				       frrzmq_write_msg, cbp, cb->fd,
				       &cb->write.thread, t->funcname,
				       t->schedfrom, t->schedfrom_line);
	return 0;

out_err:
	zlog_err("ZeroMQ write error: %s(%d)", strerror(errno), errno);
	if (cb->write.cb_error)
		cb->write.cb_error(cb->write.arg, cb->zmqsock);
	return 1;
}
int funcname_frrzmq_thread_add_write(struct thread_master *master,
				     void (*msgfunc)(void *arg, void *zmqsock),
				     void (*errfunc)(void *arg, void *zmqsock),
				     void *arg, void *zmqsock,
				     struct frrzmq_cb **cbp, debugargdef)
{
	int fd, events;
	size_t len;
	struct frrzmq_cb *cb;

	if (!cbp)
		return -1;
	if (!msgfunc)
		return -1;
	len = sizeof(fd);
	if (zmq_getsockopt(zmqsock, ZMQ_FD, &fd, &len))
		return -1;
	len = sizeof(events);
	if (zmq_getsockopt(zmqsock, ZMQ_EVENTS, &events, &len))
		return -1;

	if (*cbp)
		cb = *cbp;
	else {
		cb = XCALLOC(MTYPE_ZEROMQ_CB, sizeof(struct frrzmq_cb));
		if (!cb)
			return -1;

		cb->read.cancelled = 1;
		*cbp = cb;
	}

	cb->zmqsock = zmqsock;
	cb->fd = fd;
	cb->write.arg = arg;
	cb->write.cb_msg = msgfunc;
	cb->write.cb_part = NULL;
	cb->write.cb_error = errfunc;
	cb->write.cancelled = 0;

	if (events & ZMQ_POLLOUT) {
		if (cb->write.thread) {
			thread_cancel(cb->write.thread);
			cb->write.thread = NULL;
		}
		funcname_thread_add_event(master, frrzmq_write_msg, cbp, fd,
					  &cb->write.thread, funcname,
					  schedfrom, fromln);
	} else
		funcname_thread_add_read_write(
			THREAD_WRITE, master, frrzmq_write_msg, cbp, fd,
			&cb->write.thread, funcname, schedfrom, fromln);
	return 0;
}

void frrzmq_thread_cancel(struct frrzmq_cb **cb, struct cb_core *core)
{
	if (!cb || !*cb)
		return;
	core->cancelled = 1;
	if (core->thread) {
		thread_cancel(core->thread);
		core->thread = NULL;
	}
	if ((*cb)->read.cancelled && !(*cb)->read.thread
	    && (*cb)->write.cancelled && (*cb)->write.thread)
		XFREE(MTYPE_ZEROMQ_CB, *cb);
}

void frrzmq_check_events(struct frrzmq_cb **cbp, struct cb_core *core,
			 int event)
{
	struct frrzmq_cb *cb;
	int events;
	size_t len;

	if (!cbp)
		return;
	cb = (*cbp);
	if (!cb || !cb->zmqsock)
		return;

	len = sizeof(events);
	if (zmq_getsockopt(cb->zmqsock, ZMQ_EVENTS, &events, &len))
		return;
	if (events & event && core->thread && !core->cancelled) {
		struct thread_master *tm = core->thread->master;
		thread_cancel(core->thread);
		core->thread = NULL;
		thread_add_event(tm, (event == ZMQ_POLLIN ? frrzmq_read_msg
							  : frrzmq_write_msg),
				 cbp, cb->fd, &core->thread);
	}
}
