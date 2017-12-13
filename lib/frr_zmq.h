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

#ifndef _FRRZMQ_H
#define _FRRZMQ_H

#include "thread.h"
#include <zmq.h>

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
	struct thread *thread;
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

#define debugargdef const char *funcname, const char *schedfrom, int fromln

/* core event registration, one of these 2 macros should be used */
#define frrzmq_thread_add_read_msg(m, f, e, a, z, d)                           \
	funcname_frrzmq_thread_add_read(m, f, NULL, e, a, z, d, #f, __FILE__,  \
					__LINE__)
#define frrzmq_thread_add_read_part(m, f, e, a, z, d)                          \
	funcname_frrzmq_thread_add_read(m, NULL, f, e, a, z, d, #f, __FILE__,  \
					__LINE__)
#define frrzmq_thread_add_write_msg(m, f, e, a, z, d)                          \
	funcname_frrzmq_thread_add_write(m, f, e, a, z, d, #f, __FILE__,       \
					 __LINE__)

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
extern int funcname_frrzmq_thread_add_read(
	struct thread_master *master, void (*msgfunc)(void *arg, void *zmqsock),
	void (*partfunc)(void *arg, void *zmqsock, zmq_msg_t *msg,
			 unsigned partnum),
	void (*errfunc)(void *arg, void *zmqsock), void *arg, void *zmqsock,
	struct frrzmq_cb **cb, debugargdef);
extern int funcname_frrzmq_thread_add_write(
	struct thread_master *master, void (*msgfunc)(void *arg, void *zmqsock),
	void (*errfunc)(void *arg, void *zmqsock), void *arg, void *zmqsock,
	struct frrzmq_cb **cb, debugargdef);

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

#endif /* _FRRZMQ_H */
