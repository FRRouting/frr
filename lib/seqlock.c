/*
 * "Sequence" lock primitive
 *
 * Copyright (C) 2015  David Lamparter <equinox@diac24.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <assert.h>

#include "seqlock.h"

#ifdef HAVE_SYNC_LINUX_FUTEX
/* Linux-specific - sys_futex() */
#include <sys/syscall.h>
#include <linux/futex.h>

static long sys_futex(void *addr1, int op, int val1, struct timespec *timeout,
		void *addr2, int val3)
{
	return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
}

#define wait_once(sqlo, val)	\
	sys_futex((int *)&sqlo->pos, FUTEX_WAIT, (int)val, NULL, NULL, 0)
#define wait_poke(sqlo)		\
	sys_futex((int *)&sqlo->pos, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

#elif defined(HAVE_SYNC_OPENBSD_FUTEX)
/* OpenBSD variant of the above.  untested, not upstream in OpenBSD. */
#include <sys/syscall.h>
#include <sys/futex.h>

#define wait_once(sqlo, val)	\
	futex((int *)&sqlo->pos, FUTEX_WAIT, (int)val, NULL, NULL, 0)
#define wait_poke(sqlo)		\
	futex((int *)&sqlo->pos, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

#elif defined(HAVE_SYNC_UMTX_OP)
/* FreeBSD-specific: umtx_op() */
#include <sys/umtx.h>

#define wait_once(sqlo, val)	\
	_umtx_op((void *)&sqlo->pos, UMTX_OP_WAIT_UINT, val, NULL, NULL)
#define wait_poke(sqlo)		\
	_umtx_op((void *)&sqlo->pos, UMTX_OP_WAKE, INT_MAX, NULL, NULL)

#else
/* generic version.  used on *BSD, Solaris and OSX.
 */

#define wait_init(sqlo)		do { \
		pthread_mutex_init(&sqlo->lock, NULL); \
		pthread_cond_init(&sqlo->wake, NULL); \
	} while (0)
#define wait_prep(sqlo)		pthread_mutex_lock(&sqlo->lock)
#define wait_once(sqlo, val)	pthread_cond_wait(&sqlo->wake, &sqlo->lock)
#define wait_done(sqlo)		pthread_mutex_unlock(&sqlo->lock)
#define wait_poke(sqlo)		do { \
		pthread_mutex_lock(&sqlo->lock); \
		pthread_cond_broadcast(&sqlo->wake); \
		pthread_mutex_unlock(&sqlo->lock); \
	} while (0)

#endif

#ifndef wait_init
#define wait_init(sqlo)		/**/
#define wait_prep(sqlo)		/**/
#define wait_done(sqlo)		/**/
#endif /* wait_init */


void seqlock_wait(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t cur, cal;

	seqlock_assert_valid(val);

	wait_prep(sqlo);
	while (1) {
		cur = atomic_load_explicit(&sqlo->pos, memory_order_acquire);
		if (!(cur & 1))
			break;
		cal = cur - val - 1;
		assert(cal < 0x40000000 || cal > 0xc0000000);
		if (cal < 0x80000000)
			break;

		wait_once(sqlo, cur);
	}
	wait_done(sqlo);
}

bool seqlock_check(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t cur;

	seqlock_assert_valid(val);

	cur = atomic_load_explicit(&sqlo->pos, memory_order_acquire);
	if (!(cur & 1))
		return 1;
	cur -= val;
	assert(cur < 0x40000000 || cur > 0xc0000000);
	return cur < 0x80000000;
}

void seqlock_acquire_val(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_assert_valid(val);

	atomic_store_explicit(&sqlo->pos, val, memory_order_release);
	wait_poke(sqlo);
}

void seqlock_release(struct seqlock *sqlo)
{
	atomic_store_explicit(&sqlo->pos, 0, memory_order_release);
	wait_poke(sqlo);
}

void seqlock_init(struct seqlock *sqlo)
{
	sqlo->pos = 0;
	wait_init(sqlo);
}


seqlock_val_t seqlock_cur(struct seqlock *sqlo)
{
	return atomic_load_explicit(&sqlo->pos, memory_order_acquire);
}

seqlock_val_t seqlock_bump(struct seqlock *sqlo)
{
	seqlock_val_t val;

	val = atomic_fetch_add_explicit(&sqlo->pos, 2, memory_order_release);
	wait_poke(sqlo);
	return val;
}
