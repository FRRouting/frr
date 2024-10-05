// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libzebra ZeroMQ bindings
 * Copyright (C) 2015  David Lamparter
 */

/*
 * IF YOU MODIFY THIS FILE PLEASE RUN `make check` and ensure that
 * the test_zmq.c unit test is still working.  There are dependencies
 * between the two that are extremely fragile.  My understanding
 * is that there is specialized ownership of the cb pointer based
 * upon what is happening.  Those assumptions are supposed to be
 * tested in the test_zmq.c
 */
#include <zebra.h>
#include <zmq.h>

#include "frrevent.h"
#include "memory.h"
#include "frr_zmq.h"
#include "log.h"
#include "lib_errors.h"

XREF_SETUP();

DEFINE_MTYPE_STATIC(LIB, ZEROMQ_CB, "ZeroMQ callback");

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

static void frrzmq_read_msg(struct event *t)
{
	struct frrzmq_cb **cbp = EVENT_ARG(t);
	struct frrzmq_cb *cb;
	zmq_msg_t msg;
	unsigned partno;
	unsigned char read = 0;
	int ret, more;
	size_t moresz;

	if (!cbp)
		return;
	cb = (*cbp);
	if (!cb || !cb->zmqsock)
		return;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLIN};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLIN))
			break;

		if (cb->read.cb_msg) {
			cb->in_cb = true;
			cb->read.cb_msg(cb->read.arg, cb->zmqsock);
			cb->in_cb = false;

			read = 1;

			if (cb->read.cancelled) {
				frrzmq_check_events(cbp, &cb->write,
						    ZMQ_POLLOUT);
				cb->read.thread = NULL;
				if (cb->write.cancelled && !cb->write.thread)
					XFREE(MTYPE_ZEROMQ_CB, *cbp);

				return;
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

			cb->in_cb = true;
			cb->read.cb_part(cb->read.arg, cb->zmqsock, &msg,
					 partno);
			cb->in_cb = false;

			if (cb->read.cancelled) {
				zmq_msg_close(&msg);
				frrzmq_check_events(cbp, &cb->write,
						    ZMQ_POLLOUT);
				cb->read.thread = NULL;
				if (cb->write.cancelled && !cb->write.thread)
					XFREE(MTYPE_ZEROMQ_CB, *cbp);

				return;
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

	event_add_read(t->master, frrzmq_read_msg, cbp, cb->fd,
		       &cb->read.thread);
	return;

out_err:
	flog_err(EC_LIB_ZMQ, "ZeroMQ read error: %s(%d)", strerror(errno),
		 errno);
	if (cb->read.cb_error)
		cb->read.cb_error(cb->read.arg, cb->zmqsock);
}

int _frrzmq_event_add_read(const struct xref_eventsched *xref,
			   struct event_loop *master,
			   void (*msgfunc)(void *arg, void *zmqsock),
			   void (*partfunc)(void *arg, void *zmqsock,
					    zmq_msg_t *msg, unsigned partnum),
			   void (*errfunc)(void *arg, void *zmqsock), void *arg,
			   void *zmqsock, struct frrzmq_cb **cbp)
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
		cb->write.cancelled = true;
		*cbp = cb;
	}

	cb->zmqsock = zmqsock;
	cb->fd = fd;
	cb->read.arg = arg;
	cb->read.cb_msg = msgfunc;
	cb->read.cb_part = partfunc;
	cb->read.cb_error = errfunc;
	cb->read.cancelled = false;
	cb->in_cb = false;

	if (events & ZMQ_POLLIN) {
		event_cancel(&cb->read.thread);

		event_add_event(master, frrzmq_read_msg, cbp, fd,
				&cb->read.thread);
	} else
		event_add_read(master, frrzmq_read_msg, cbp, fd,
			       &cb->read.thread);
	return 0;
}

static void frrzmq_write_msg(struct event *t)
{
	struct frrzmq_cb **cbp = EVENT_ARG(t);
	struct frrzmq_cb *cb;
	unsigned char written = 0;
	int ret;

	if (!cbp)
		return;
	cb = (*cbp);
	if (!cb || !cb->zmqsock)
		return;

	while (1) {
		zmq_pollitem_t polli = {.socket = cb->zmqsock,
					.events = ZMQ_POLLOUT};
		ret = zmq_poll(&polli, 1, 0);

		if (ret < 0)
			goto out_err;

		if (!(polli.revents & ZMQ_POLLOUT))
			break;

		if (cb->write.cb_msg) {
			cb->in_cb = true;
			cb->write.cb_msg(cb->write.arg, cb->zmqsock);
			cb->in_cb = false;

			written = 1;

			if (cb->write.cancelled) {
				frrzmq_check_events(cbp, &cb->read, ZMQ_POLLIN);
				cb->write.thread = NULL;
				if (cb->read.cancelled && !cb->read.thread)
					XFREE(MTYPE_ZEROMQ_CB, *cbp);

				return;
			}
			continue;
		}
	}

	if (written)
		frrzmq_check_events(cbp, &cb->read, ZMQ_POLLIN);

	event_add_write(t->master, frrzmq_write_msg, cbp, cb->fd,
			&cb->write.thread);
	return;

out_err:
	flog_err(EC_LIB_ZMQ, "ZeroMQ write error: %s(%d)", strerror(errno),
		 errno);
	if (cb->write.cb_error)
		cb->write.cb_error(cb->write.arg, cb->zmqsock);
}

int _frrzmq_event_add_write(const struct xref_eventsched *xref,
			    struct event_loop *master,
			    void (*msgfunc)(void *arg, void *zmqsock),
			    void (*errfunc)(void *arg, void *zmqsock),
			    void *arg, void *zmqsock, struct frrzmq_cb **cbp)
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
		cb->read.cancelled = true;
		*cbp = cb;
	}

	cb->zmqsock = zmqsock;
	cb->fd = fd;
	cb->write.arg = arg;
	cb->write.cb_msg = msgfunc;
	cb->write.cb_part = NULL;
	cb->write.cb_error = errfunc;
	cb->write.cancelled = false;
	cb->in_cb = false;

	if (events & ZMQ_POLLOUT) {
		event_cancel(&cb->write.thread);

		_event_add_event(xref, master, frrzmq_write_msg, cbp, fd,
				 &cb->write.thread);
	} else
		event_add_write(master, frrzmq_write_msg, cbp, fd,
				&cb->write.thread);
	return 0;
}

void frrzmq_thread_cancel(struct frrzmq_cb **cb, struct cb_core *core)
{
	if (!cb || !*cb)
		return;
	core->cancelled = true;
	event_cancel(&core->thread);

	/* If cancelled from within a callback, don't try to free memory
	 * in this path.
	 */
	if ((*cb)->in_cb)
		return;

	/* Ok to free the callback context if no more ... context. */
	if ((*cb)->read.cancelled && !(*cb)->read.thread
	    && (*cb)->write.cancelled && ((*cb)->write.thread == NULL))
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
	if ((events & event) && core->thread && !core->cancelled) {
		struct event_loop *tm = core->thread->master;

		event_cancel(&core->thread);

		if (event == ZMQ_POLLIN)
			event_add_event(tm, frrzmq_read_msg, cbp, cb->fd,
					&core->thread);
		else
			event_add_event(tm, frrzmq_write_msg, cbp, cb->fd,
					&core->thread);
	}
}
