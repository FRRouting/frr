/*
 * Pull-driven write event handler
 * Copyright (C) 2019  David Lamparter
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

#ifndef _WRITEPOLL_H
#define _WRITEPOLL_H

#include <stdbool.h>
#include <stdint.h>

#include "thread.h"
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pullwr;

/* This is a "pull-driven" write event handler.  Instead of having some buffer
 * or being driven by the availability of data, it triggers on the space being
 * available on the socket for data to be written on and then calls fill() to
 * get data to be sent.
 *
 * pullwr_* maintains an "idle" vs. "active" state, going into idle when a
 * fill() call completes without feeing more data into it.  The overall
 * semantics are:
 * - to put data out, call pullwr_write().  This is possible from both inside
 *   fill() callbacks or anywhere else.  Doing so puts the pullwr into
 *   active state.
 * - in active state, the fill() callback will be called and should feed more
 *   data in.  It should NOT loop to push out more than one "unit" of data;
 *   the pullwr code handles this by calling fill() until it has enough data.
 * - if there's nothing more to be sent, fill() returns without doing anything
 *   and pullwr goes into idle state after flushing all buffered data out.
 * - when new data becomes available, pullwr_bump() should be called to put
 *   the pullwr back into active mode so it will collect data from fill(),
 *   or you can directly call pullwr_write().
 * - only calling pullwr_write() from within fill() is the cleanest way of
 *   doing things.
 *
 * When the err() callback is called, the pullwr should be considered unusable
 * and released with pullwr_del().  This can be done from inside the callback,
 * the pullwr code holds no more references on it when calling err().
 */
extern struct pullwr *_pullwr_new(struct thread_master *tm, int fd,
		void *arg,
		void (*fill)(void *, struct pullwr *),
		void (*err)(void *, struct pullwr *, bool eof));
extern void pullwr_del(struct pullwr *pullwr);

/* type-checking wrapper.  makes sure fill() and err() take a first argument
 * whose type is identical to the type of arg.
 * => use "void fill(struct mystruct *arg, ...)" - no "void *arg"
 */
#define pullwr_new(tm, fd, arg, fill, err) ({                                  \
	void (*fill_typechk)(typeof(arg), struct pullwr *) = fill;          \
	void (*err_typechk)(typeof(arg), struct pullwr *, bool) = err;      \
	_pullwr_new(tm, fd, arg, (void *)fill_typechk, (void *)err_typechk);   \
})

/* max_spin_usec is the time after which the pullwr event handler will stop
 *   trying to get more data from fill() and yield control back to the
 *   thread_master.  It does reschedule itself to continue later; this is
 *   only to make sure we don't freeze the entire process if we're piping a
 *   lot of data to a local endpoint that reads quickly (i.e. no backpressure)
 *
 *   default: 2500 (2.5 ms)
 *
 * write_threshold is the amount of data buffered from fill() calls at which
 *   the pullwr code starts calling write().  But this is not a "limit".
 *   pullwr will keep poking fill() for more data until
 *   (a) max_spin_usec is reached; fill() will be called again later after
 *       returning to the thread_master to give other events a chance to run
 *   (b) fill() returns without pushing any data onto the pullwr with
 *       pullwr_write(), so fill() will NOT be called again until a call to
 *       pullwr_bump() or pullwr_write() comes in.
 *
 *   default: 16384 (16 kB)
 *
 * passing 0 for either value (or not calling it at all) uses the default.
 */
extern void pullwr_cfg(struct pullwr *pullwr, int64_t max_spin_usec,
		       size_t write_threshold);

extern void pullwr_bump(struct pullwr *pullwr);
extern void pullwr_write(struct pullwr *pullwr,
		const void *data, size_t len);

static inline void pullwr_write_stream(struct pullwr *pullwr,
		struct stream *s)
{
	pullwr_write(pullwr, s->data, stream_get_endp(s));
}

extern void pullwr_stats(struct pullwr *pullwr, uint64_t *total_written,
			 size_t *pending, size_t *kernel_pending);

#ifdef __cplusplus
}
#endif

#endif /* _WRITEPOLL_H */
