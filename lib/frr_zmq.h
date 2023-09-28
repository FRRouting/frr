// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libzebra ZeroMQ bindings
 * Copyright (C) 2015  David Lamparter
 */

#ifndef _FRRZMQ_H
#define _FRRZMQ_H

#include "frrevent.h"
#include <zmq.h>

#ifdef __cplusplus
extern "C" {
#endif

/* linking/packaging note:  this is a separate library that needs to be
 * linked into any daemon/library/module that wishes to use its
 * functionality.  The purpose of this is to encapsulate the libzmq
 * dependency and not make libfrr/FRR itself depend on libzmq.
 *
 * libfrrzmq should be put in LDFLAGS/LIBADD *before* either libfrr or
 * libzmq, and both of these should always be listed, e.g.
 *   foo_LDFLAGS = libfrrzmq.la libfrr.la $(ZEROMQ_LIBS)
 */

/* callback integration */
struct cb_core {
	struct event *thread;
	void *arg;

	bool cancelled;

	void (*cb_msg)(void *arg, void *zmqsock);
	void (*cb_part)(void *arg, void *zmqsock, zmq_msg_t *msg,
			unsigned partnum);
	void (*cb_error)(void *arg, void *zmqsock);
};

struct frrzmq_cb {
	void *zmqsock;
	int fd;

	bool in_cb; /* This context is in a read or write callback. */

	struct cb_core read;
	struct cb_core write;
};

/* libzmq's context
 *
 * this is mostly here as a convenience, it has IPv6 enabled but nothing
 * else is tied to it;  you can use a separate context without problems
 */
extern void *frrzmq_context;

extern void frrzmq_init(void);
extern void frrzmq_finish(void);

#define _xref_zmq_a(type, f, d, call)                                          \
	({                                                                     \
		static const struct xref_eventsched _xref __attribute__(       \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_EVENTSCHED, NULL, __func__),   \
			.funcname = #f,                                        \
			.dest = #d,                                            \
			.event_type = EVENT_##type,                            \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		call;                                                          \
	}) /* end */

/* core event registration, one of these 2 macros should be used */
#define frrzmq_event_add_read_msg(m, f, e, a, z, d)                            \
	_xref_zmq_a(READ, f, d,                                                \
		    _frrzmq_event_add_read(&_xref, m, f, NULL, e, a, z, d))

#define frrzmq_event_add_read_part(m, f, e, a, z, d)                           \
	_xref_zmq_a(READ, f, d,                                                \
		    _frrzmq_event_add_read(&_xref, m, NULL, f, e, a, z, d))

#define frrzmq_event_add_write_msg(m, f, e, a, z, d)                           \
	_xref_zmq_a(WRITE, f, d,                                               \
		    _frrzmq_event_add_write(&_xref, m, f, e, a, z, d))

struct cb_core;
struct frrzmq_cb;

/* Set up a POLLIN or POLLOUT notification to be called from the libfrr main
 * loop. This has the following properties:
 *
 * - since ZeroMQ works with edge triggered notifications, it will loop and
 *   dispatch as many events as ZeroMQ has pending at the time libfrr calls
 *   into this code
 * - due to this looping (which means it non-single-issue), the callback is
 *   also persistent.  Do _NOT_ re-register the event inside of your
 *   callback function.
 * - either msgfunc or partfunc will be called (only one can be specified)
 *   - msgfunc is called once for each incoming message
 *   - if partfunc is specified, the message is read and partfunc is called
 *     for each ZeroMQ multi-part subpart.  Note that you can't send replies
 *     before all parts have been read because that violates the ZeroMQ FSM.
 * - write version doesn't allow for partial callback, you must handle the
 *   whole message (all parts) in msgfunc callback
 * - you can safely cancel the callback from within itself
 * - installing a callback will check for pending events (ZMQ_EVENTS) and
 *   may schedule the event to run as soon as libfrr is back in its main
 *   loop.
 */
extern int
_frrzmq_event_add_read(const struct xref_eventsched *xref,
		       struct event_loop *master,
		       void (*msgfunc)(void *arg, void *zmqsock),
		       void (*partfunc)(void *arg, void *zmqsock,
					zmq_msg_t *msg, unsigned partnum),
		       void (*errfunc)(void *arg, void *zmqsock), void *arg,
		       void *zmqsock, struct frrzmq_cb **cb);
extern int _frrzmq_event_add_write(const struct xref_eventsched *xref,
				   struct event_loop *master,
				   void (*msgfunc)(void *arg, void *zmqsock),
				   void (*errfunc)(void *arg, void *zmqsock),
				   void *arg, void *zmqsock,
				   struct frrzmq_cb **cb);

extern void frrzmq_thread_cancel(struct frrzmq_cb **cb, struct cb_core *core);

/*
 * http://api.zeromq.org/4-2:zmq-getsockopt#toc10
 *
 * As the descriptor is edge triggered, applications must update the state of
 * ZMQ_EVENTS after each invocation of zmq_send or zmq_recv.To be more explicit:
 * after calling zmq_send the socket may become readable (and vice versa)
 * without triggering a read event on the file descriptor.
 */
extern void frrzmq_check_events(struct frrzmq_cb **cbp, struct cb_core *core,
				int event);

#ifdef __cplusplus
}
#endif

#endif /* _FRRZMQ_H */
