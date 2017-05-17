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

/* libzmq's context */
extern void *frrzmq_context;

extern void frrzmq_init (void);
extern void frrzmq_finish (void);

#define debugargdef const char *funcname, const char *schedfrom, int fromln

#define frrzmq_thread_read_msg(m,f,a,z) funcname_frrzmq_thread_read_msg( \
				m,f,a,z,#f,__FILE__,__LINE__)

struct frrzmq_cb;

extern struct frrzmq_cb *funcname_frrzmq_thread_read_msg(
		struct thread_master *master,
		void (*func)(void *arg, void *zmqsock, zmq_msg_t *msg),
		void *arg, void *zmqsock, debugargdef);

extern void frrzmq_thread_cancel(struct frrzmq_cb *cb);

#endif /* _FRRZMQ_H */
