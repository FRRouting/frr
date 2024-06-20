// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * "Sequence" lock primitive
 *
 * Copyright (C) 2015  David Lamparter <equinox@diac24.net>
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <assert.h>

#include "seqlock.h"

/****************************************
 * OS specific synchronization wrappers *
 ****************************************/

#ifndef __has_feature /* not available on old GCC */
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_THREAD__) || __has_feature(thread_sanitizer))
/* TSAN really does not understand what is going on with the low-level
 * futex/umtx calls.  This leads to a whole bunch of warnings, a lot of which
 * also have _extremely_ misleading text - since TSAN does not understand that
 * there is in fact a synchronization primitive involved, it can end up pulling
 * in completely unrelated things.
 *
 * What does work is the "unsupported platform" seqlock implementation based
 * on a pthread mutex + condvar, since TSAN of course suppports these.
 *
 * It may be possible to also fix this with TSAN annotations (__tsan_acquire
 * and __tsan_release), but using those (correctly) is not easy either, and
 * for now just get things rolling.
 */

#ifdef HAVE_SYNC_LINUX_FUTEX
#undef HAVE_SYNC_LINUX_FUTEX
#endif

#ifdef HAVE_SYNC_OPENBSD_FUTEX
#undef HAVE_SYNC_OPENBSD_FUTEX
#endif

#ifdef HAVE_SYNC_UMTX_OP
#undef HAVE_SYNC_UMTX_OP
#endif

#endif /* TSAN */

/*
 * Linux: sys_futex()
 */
#ifdef HAVE_SYNC_LINUX_FUTEX
#include <sys/syscall.h>
#include <linux/futex.h>

static long sys_futex(void *addr1, int op, int val1,
		      const struct timespec *timeout, void *addr2, int val3)
{
	return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
}

#define wait_once(sqlo, val)	\
	sys_futex((int *)&sqlo->pos, FUTEX_WAIT, (int)val, NULL, NULL, 0)
#define wait_time(sqlo, val, time, reltime)	\
	sys_futex((int *)&sqlo->pos, FUTEX_WAIT_BITSET, (int)val, time, \
		  NULL, ~0U)
#define wait_poke(sqlo)		\
	sys_futex((int *)&sqlo->pos, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

/*
 * OpenBSD: sys_futex(), almost the same as on Linux
 */
#elif defined(HAVE_SYNC_OPENBSD_FUTEX)
#include <sys/syscall.h>
#include <sys/futex.h>

#define TIME_RELATIVE		1

#define wait_once(sqlo, val)	\
	futex((int *)&sqlo->pos, FUTEX_WAIT, (int)val, NULL, NULL, 0)
#define wait_time(sqlo, val, time, reltime)	\
	futex((int *)&sqlo->pos, FUTEX_WAIT, (int)val, reltime, NULL, 0)
#define wait_poke(sqlo)		\
	futex((int *)&sqlo->pos, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

/*
 * FreeBSD: _umtx_op()
 */
#elif defined(HAVE_SYNC_UMTX_OP)
#include <sys/umtx.h>

#define wait_once(sqlo, val)	\
	_umtx_op((void *)&sqlo->pos, UMTX_OP_WAIT_UINT, val, NULL, NULL)
static int wait_time(struct seqlock *sqlo, uint32_t val,
		      const struct timespec *abstime,
		      const struct timespec *reltime)
{
	struct _umtx_time t;
	t._flags = UMTX_ABSTIME;
	t._clockid = CLOCK_MONOTONIC;
	memcpy(&t._timeout, abstime, sizeof(t._timeout));
	return _umtx_op((void *)&sqlo->pos, UMTX_OP_WAIT_UINT, val,
		 (void *)(uintptr_t) sizeof(t), &t);
}
#define wait_poke(sqlo)		\
	_umtx_op((void *)&sqlo->pos, UMTX_OP_WAKE, INT_MAX, NULL, NULL)

/*
 * generic version.  used on NetBSD, Solaris and OSX.  really shitty.
 */
#else

#define TIME_ABS_REALTIME	1

#define wait_init(sqlo)		do { \
		pthread_mutex_init(&sqlo->lock, NULL); \
		pthread_cond_init(&sqlo->wake, NULL); \
	} while (0)
#define wait_prep(sqlo)		pthread_mutex_lock(&sqlo->lock)
#define wait_once(sqlo, val)	pthread_cond_wait(&sqlo->wake, &sqlo->lock)
#define wait_time(sqlo, val, time, reltime) \
				pthread_cond_timedwait(&sqlo->wake, \
						       &sqlo->lock, time);
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
	cur = atomic_load_explicit(&sqlo->pos, memory_order_relaxed);

	while (cur & SEQLOCK_HELD) {
		cal = SEQLOCK_VAL(cur) - val - 1;
		assert(cal < 0x40000000 || cal > 0xc0000000);
		if (cal < 0x80000000)
			break;

		if ((cur & SEQLOCK_WAITERS)
		    || atomic_compare_exchange_weak_explicit(
				&sqlo->pos, &cur, cur | SEQLOCK_WAITERS,
				memory_order_relaxed, memory_order_relaxed)) {
			wait_once(sqlo, cur | SEQLOCK_WAITERS);
			cur = atomic_load_explicit(&sqlo->pos,
				memory_order_relaxed);
		}
		/* else: we failed to swap in cur because it just changed */
	}
	wait_done(sqlo);
}

bool seqlock_timedwait(struct seqlock *sqlo, seqlock_val_t val,
		       const struct timespec *abs_monotime_limit)
{
/*
 * ABS_REALTIME - used on NetBSD, Solaris and OSX
 */
#ifdef TIME_ABS_REALTIME
#define time_arg1 &abs_rt
#define time_arg2 NULL
#define time_prep
	struct timespec curmono, abs_rt;

	clock_gettime(CLOCK_MONOTONIC, &curmono);
	clock_gettime(CLOCK_REALTIME, &abs_rt);

	abs_rt.tv_nsec += abs_monotime_limit->tv_nsec - curmono.tv_nsec;
	if (abs_rt.tv_nsec < 0) {
		abs_rt.tv_sec--;
		abs_rt.tv_nsec += 1000000000;
	} else if (abs_rt.tv_nsec >= 1000000000) {
		abs_rt.tv_sec++;
		abs_rt.tv_nsec -= 1000000000;
	}
	abs_rt.tv_sec += abs_monotime_limit->tv_sec - curmono.tv_sec;

/*
 * RELATIVE - used on OpenBSD (might get a patch to get absolute monotime)
 */
#elif defined(TIME_RELATIVE)
	struct timespec reltime;

#define time_arg1 abs_monotime_limit
#define time_arg2 &reltime
#define time_prep \
	clock_gettime(CLOCK_MONOTONIC, &reltime);                              \
	reltime.tv_sec = abs_monotime_limit.tv_sec - reltime.tv_sec;           \
	reltime.tv_nsec = abs_monotime_limit.tv_nsec - reltime.tv_nsec;        \
	if (reltime.tv_nsec < 0) {                                             \
		reltime.tv_sec--;                                              \
		reltime.tv_nsec += 1000000000;                                 \
	}
/*
 * FreeBSD & Linux: absolute time re. CLOCK_MONOTONIC
 */
#else
#define time_arg1 abs_monotime_limit
#define time_arg2 NULL
#define time_prep
#endif

	bool ret = true;
	seqlock_val_t cur, cal;

	seqlock_assert_valid(val);

	wait_prep(sqlo);
	cur = atomic_load_explicit(&sqlo->pos, memory_order_relaxed);

	while (cur & SEQLOCK_HELD) {
		cal = SEQLOCK_VAL(cur) - val - 1;
		assert(cal < 0x40000000 || cal > 0xc0000000);
		if (cal < 0x80000000)
			break;

		if ((cur & SEQLOCK_WAITERS)
		    || atomic_compare_exchange_weak_explicit(
				&sqlo->pos, &cur, cur | SEQLOCK_WAITERS,
				memory_order_relaxed, memory_order_relaxed)) {
			int rv;

			time_prep

			rv = wait_time(sqlo, cur | SEQLOCK_WAITERS, time_arg1,
				       time_arg2);
			if (rv) {
				ret = false;
				break;
			}
			cur = atomic_load_explicit(&sqlo->pos,
				memory_order_relaxed);
		}
	}
	wait_done(sqlo);

	return ret;
}

bool seqlock_check(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t cur;

	seqlock_assert_valid(val);

	cur = atomic_load_explicit(&sqlo->pos, memory_order_relaxed);
	if (!(cur & SEQLOCK_HELD))
		return true;
	cur = SEQLOCK_VAL(cur) - val - 1;
	assert(cur < 0x40000000 || cur > 0xc0000000);
	return cur < 0x80000000;
}

void seqlock_acquire_val(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t prev;

	seqlock_assert_valid(val);

	prev = atomic_exchange_explicit(&sqlo->pos, val, memory_order_relaxed);
	if (prev & SEQLOCK_WAITERS)
		wait_poke(sqlo);
}

void seqlock_release(struct seqlock *sqlo)
{
	seqlock_val_t prev;

	prev = atomic_exchange_explicit(&sqlo->pos, 0, memory_order_relaxed);
	if (prev & SEQLOCK_WAITERS)
		wait_poke(sqlo);
}

void seqlock_init(struct seqlock *sqlo)
{
	sqlo->pos = 0;
	wait_init(sqlo);
}


seqlock_val_t seqlock_cur(struct seqlock *sqlo)
{
	return SEQLOCK_VAL(atomic_load_explicit(&sqlo->pos,
						memory_order_relaxed));
}

seqlock_val_t seqlock_bump(struct seqlock *sqlo)
{
	seqlock_val_t val, cur;

	cur = atomic_load_explicit(&sqlo->pos, memory_order_relaxed);
	seqlock_assert_valid(cur);

	do {
		val = SEQLOCK_VAL(cur) + SEQLOCK_INCR;
	} while (!atomic_compare_exchange_weak_explicit(&sqlo->pos, &cur, val,
			memory_order_relaxed, memory_order_relaxed));

	if (cur & SEQLOCK_WAITERS)
		wait_poke(sqlo);
	return val;
}
