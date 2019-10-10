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

#include "zebra.h"

#include "pullwr.h"
#include "memory.h"
#include "monotime.h"

/* defaults */
#define PULLWR_THRESH	16384	/* size at which we start to call write() */
#define PULLWR_MAXSPIN	2500	/* max µs to spend grabbing more data */

struct pullwr {
	int fd;
	struct thread_master *tm;
	/* writer == NULL <=> we're idle */
	struct thread *writer;

	void *arg;
	void (*fill)(void *, struct pullwr *);
	void (*err)(void *, struct pullwr *, bool);

	/* ring buffer (although it's "un-ringed" on resizing, it WILL wrap
	 * around if data is trickling in while keeping it at a constant size)
	 */
	size_t bufsz, valid, pos;
	uint64_t total_written;
	char *buffer;

	size_t thresh;		/* PULLWR_THRESH */
	int64_t maxspin;	/* PULLWR_MAXSPIN */
};

DEFINE_MTYPE_STATIC(LIB, PULLWR_HEAD, "pull-driven write controller")
DEFINE_MTYPE_STATIC(LIB, PULLWR_BUF,  "pull-driven write buffer")

static int pullwr_run(struct thread *t);

struct pullwr *_pullwr_new(struct thread_master *tm, int fd,
		void *arg,
		void (*fill)(void *, struct pullwr *),
		void (*err)(void *, struct pullwr *, bool))
{
	struct pullwr *pullwr;

	pullwr = XCALLOC(MTYPE_PULLWR_HEAD, sizeof(*pullwr));
	pullwr->fd = fd;
	pullwr->tm = tm;
	pullwr->arg = arg;
	pullwr->fill = fill;
	pullwr->err = err;

	pullwr->thresh = PULLWR_THRESH;
	pullwr->maxspin = PULLWR_MAXSPIN;

	return pullwr;
}

void pullwr_del(struct pullwr *pullwr)
{
	THREAD_OFF(pullwr->writer);

	XFREE(MTYPE_PULLWR_BUF, pullwr->buffer);
	XFREE(MTYPE_PULLWR_HEAD, pullwr);
}

void pullwr_cfg(struct pullwr *pullwr, int64_t max_spin_usec,
		size_t write_threshold)
{
	pullwr->maxspin = max_spin_usec ?: PULLWR_MAXSPIN;
	pullwr->thresh = write_threshold ?: PULLWR_THRESH;
}

void pullwr_bump(struct pullwr *pullwr)
{
	if (pullwr->writer)
		return;

	thread_add_timer(pullwr->tm, pullwr_run, pullwr, 0, &pullwr->writer);
}

static size_t pullwr_iov(struct pullwr *pullwr, struct iovec *iov)
{
	size_t len1;

	if (pullwr->valid == 0)
		return 0;

	if (pullwr->pos + pullwr->valid <= pullwr->bufsz) {
		iov[0].iov_base = pullwr->buffer + pullwr->pos;
		iov[0].iov_len = pullwr->valid;
		return 1;
	}

	len1 = pullwr->bufsz - pullwr->pos;

	iov[0].iov_base = pullwr->buffer + pullwr->pos;
	iov[0].iov_len = len1;
	iov[1].iov_base = pullwr->buffer;
	iov[1].iov_len = pullwr->valid - len1;
	return 2;
}

static void pullwr_resize(struct pullwr *pullwr, size_t need)
{
	struct iovec iov[2];
	size_t niov, newsize;
	char *newbuf;

	/* the buffer is maintained at pullwr->thresh * 2 since we'll be
	 * trying to fill it as long as it's anywhere below pullwr->thresh.
	 * That means we frequently end up a little short of it and then write
	 * something that goes over the threshold.  So, just use double.
	 */
	if (need) {
		/* resize up */
		if (pullwr->bufsz - pullwr->valid >= need)
			return;

		newsize = MAX((pullwr->valid + need) * 2, pullwr->thresh * 2);
		newbuf = XMALLOC(MTYPE_PULLWR_BUF, newsize);
	} else if (!pullwr->valid) {
		/* resize down, buffer empty */
		newsize = 0;
		newbuf = NULL;
	} else {
		/* resize down */
		if (pullwr->bufsz - pullwr->valid < pullwr->thresh)
			return;
		newsize = MAX(pullwr->valid, pullwr->thresh * 2);
		newbuf = XMALLOC(MTYPE_PULLWR_BUF, newsize);
	}

	niov = pullwr_iov(pullwr, iov);
	if (niov >= 1) {
		memcpy(newbuf, iov[0].iov_base, iov[0].iov_len);
		if (niov >= 2)
			memcpy(newbuf + iov[0].iov_len,
				iov[1].iov_base, iov[1].iov_len);
	}

	XFREE(MTYPE_PULLWR_BUF, pullwr->buffer);
	pullwr->buffer = newbuf;
	pullwr->bufsz = newsize;
	pullwr->pos = 0;
}

void pullwr_write(struct pullwr *pullwr, const void *data, size_t len)
{
	pullwr_resize(pullwr, len);

	if (pullwr->pos + pullwr->valid > pullwr->bufsz) {
		size_t pos;

		pos = (pullwr->pos + pullwr->valid) % pullwr->bufsz;
		memcpy(pullwr->buffer + pos, data, len);
	} else {
		size_t max1, len1;
		max1 = pullwr->bufsz - (pullwr->pos + pullwr->valid);
		max1 = MIN(max1, len);

		memcpy(pullwr->buffer + pullwr->pos + pullwr->valid,
				data, max1);
		len1 = len - max1;

		if (len1)
			memcpy(pullwr->buffer, (char *)data + max1, len1);

	}
	pullwr->valid += len;

	pullwr_bump(pullwr);
}

static int pullwr_run(struct thread *t)
{
	struct pullwr *pullwr = THREAD_ARG(t);
	struct iovec iov[2];
	size_t niov, lastvalid;
	ssize_t nwr;
	struct timeval t0;
	bool maxspun = false;

	monotime(&t0);

	do {
		lastvalid = pullwr->valid - 1;
		while (pullwr->valid < pullwr->thresh
				&& pullwr->valid != lastvalid
				&& !maxspun) {
			lastvalid = pullwr->valid;
			pullwr->fill(pullwr->arg, pullwr);

			/* check after doing at least one fill() call so we
			 * don't spin without making progress on slow boxes
			 */
			if (!maxspun && monotime_since(&t0, NULL)
					>= pullwr->maxspin)
				maxspun = true;
		}

		if (pullwr->valid == 0) {
			/* we made a fill() call above that didn't feed any
			 * data in, and we have nothing more queued, so we go
			 * into idle, i.e. no calling thread_add_write()
			 */
			pullwr_resize(pullwr, 0);
			return 0;
		}

		niov = pullwr_iov(pullwr, iov);
		assert(niov);

		nwr = writev(pullwr->fd, iov, niov);
		if (nwr < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			pullwr->err(pullwr->arg, pullwr, false);
			return 0;
		}

		if (nwr == 0) {
			pullwr->err(pullwr->arg, pullwr, true);
			return 0;
		}

		pullwr->total_written += nwr;
		pullwr->valid -= nwr;
		pullwr->pos += nwr;
		pullwr->pos %= pullwr->bufsz;
	} while (pullwr->valid == 0 && !maxspun);
	/* pullwr->valid != 0 implies we did an incomplete write, i.e. socket
	 * is full and we go wait until it's available for writing again.
	 */

	thread_add_write(pullwr->tm, pullwr_run, pullwr, pullwr->fd,
			&pullwr->writer);

	/* if we hit the time limit, just keep the buffer, we'll probably need
	 * it anyway & another run is already coming up.
	 */
	if (!maxspun)
		pullwr_resize(pullwr, 0);
	return 0;
}

void pullwr_stats(struct pullwr *pullwr, uint64_t *total_written,
		  size_t *pending, size_t *kernel_pending)
{
	int tmp;

	*total_written = pullwr->total_written;
	*pending = pullwr->valid;

	if (ioctl(pullwr->fd, TIOCOUTQ, &tmp) != 0)
		tmp = 0;
	*kernel_pending = tmp;
}
