/*
 * basic test for seqlock
 *
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
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/uio.h>

#include "monotime.h"
#include "seqlock.h"
#include "printfrr.h"

static struct seqlock sqlo;
static pthread_t thr1;
static struct timeval start;

static void writestr(const char *str)
{
	struct iovec iov[2];
	char buf[32];
	int64_t usec = monotime_since(&start, NULL);

	snprintfrr(buf, sizeof(buf), "[%02" PRId64 "] ", usec / 100000);

	iov[0].iov_base = buf;
	iov[0].iov_len = strlen(buf);
	iov[1].iov_base = (char *)str;
	iov[1].iov_len = strlen(str);
	writev(1, iov, 2);
}

static void *thr1func(void *arg)
{
	assert(!seqlock_held(&sqlo));
	assert(seqlock_check(&sqlo, 1));
	seqlock_wait(&sqlo, 1);
	writestr("thr1 (unheld)\n");

	sleep(2);

	assert(seqlock_held(&sqlo));
	assert(seqlock_check(&sqlo, 1));
	seqlock_wait(&sqlo, 1);
	writestr("thr1 @1\n");

	seqlock_wait(&sqlo, 5);
	writestr("thr1 @5\n");

	seqlock_wait(&sqlo, 9);
	writestr("thr1 @9\n");

	seqlock_wait(&sqlo, 13);
	writestr("thr1 @13\n");

	seqlock_wait(&sqlo, 17);
	writestr("thr1 @17\n");

	seqlock_wait(&sqlo, 21);
	writestr("thr1 @21\n");
	return NULL;
}

int main(int argc, char **argv)
{
	monotime(&start);

	seqlock_init(&sqlo);

	assert(!seqlock_held(&sqlo));
	seqlock_acquire_val(&sqlo, 1);
	assert(seqlock_held(&sqlo));

	assert(seqlock_cur(&sqlo) == 1);
	assert(seqlock_bump(&sqlo) == 1);
	assert(seqlock_cur(&sqlo) == 5);
	assert(seqlock_bump(&sqlo) == 5);
	assert(seqlock_bump(&sqlo) == 9);
	assert(seqlock_bump(&sqlo) == 13);
	assert(seqlock_cur(&sqlo) == 17);

	assert(seqlock_held(&sqlo));
	seqlock_release(&sqlo);
	assert(!seqlock_held(&sqlo));

	pthread_create(&thr1, NULL, thr1func, NULL);
	sleep(1);

	writestr("main @5\n");
	seqlock_acquire_val(&sqlo, 5);
	sleep(2);

	writestr("main @9\n");
	seqlock_bump(&sqlo);
	sleep(1);

	writestr("main @17\n");
	seqlock_acquire_val(&sqlo, 17);
	sleep(1);

	writestr("main @release\n");
	seqlock_release(&sqlo);
	sleep(1);
}
