// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * "Sequence" lock primitive
 *
 * Copyright (C) 2015  David Lamparter <equinox@diac24.net>
 */

#ifndef _SEQLOCK_H
#define _SEQLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "frratomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * this locking primitive is intended to use in a 1:N setup.
 *
 * - one "counter" seqlock issuing increasing numbers
 * - multiple seqlock users hold references on these numbers
 *
 * this is intended for implementing RCU reference-holding.  There is one
 * global counter, with threads locking a seqlock whenever they take a
 * reference.  A seqlock can also be idle/unlocked.
 *
 * The "counter" seqlock will always stay locked;  the RCU cleanup thread
 * continuously counts it up, waiting for threads to release or progress to a
 * sequence number further ahead.  If all threads are > N, references dropped
 * in N can be free'd.
 *
 * generally, the lock function is:
 *
 * Thread-A                  Thread-B
 *
 * seqlock_acquire(a)
 *    | running              seqlock_wait(b)      -- a <= b
 * seqlock_release()            | blocked
 * OR: seqlock_acquire(a')      |                 -- a' > b
 *                           (resumes)
 */

/* use sequentially increasing "ticket numbers".  lowest bit will always
 * be 1 to have a 'cleared' indication (i.e., counts 1,5,9,13,etc. )
 * 2nd lowest bit is used to indicate we have waiters.
 */
typedef _Atomic uint32_t	seqlock_ctr_t;
typedef uint32_t		seqlock_val_t;
#define seqlock_assert_valid(val) assert((val) & SEQLOCK_HELD)

/* NB: SEQLOCK_WAITERS is only allowed if SEQLOCK_HELD is also set; can't
 * have waiters on an unheld seqlock
 */
#define SEQLOCK_HELD		(1U << 0)
#define SEQLOCK_WAITERS		(1U << 1)
#define SEQLOCK_VAL(n)		((n) & ~SEQLOCK_WAITERS)
#define SEQLOCK_STARTVAL	1U
#define SEQLOCK_INCR		4U

/* TODO: originally, this was using "atomic_fetch_add", which is the reason
 * bit 0 is used to indicate held state.  With SEQLOCK_WAITERS added, there's
 * no fetch_add anymore (cmpxchg loop instead), so we don't need to use bit 0
 * for this anymore & can just special-case the value 0 for it and skip it in
 * counting.
 */

struct seqlock {
/* always used */
	seqlock_ctr_t pos;
/* used when futexes not available: (i.e. non-linux) */
	pthread_mutex_t lock;
	pthread_cond_t  wake;
};


/* sqlo = 0 - init state: not held */
extern void seqlock_init(struct seqlock *sqlo);


/* basically: "while (sqlo <= val) wait();"
 * returns when sqlo > val || !seqlock_held(sqlo)
 */
extern void seqlock_wait(struct seqlock *sqlo, seqlock_val_t val);

/* same, but time-limited (limit is an absolute CLOCK_MONOTONIC value) */
extern bool seqlock_timedwait(struct seqlock *sqlo, seqlock_val_t val,
			      const struct timespec *abs_monotime_limit);

/* one-shot test, returns true if seqlock_wait would return immediately */
extern bool seqlock_check(struct seqlock *sqlo, seqlock_val_t val);

static inline bool seqlock_held(struct seqlock *sqlo)
{
	return !!atomic_load_explicit(&sqlo->pos, memory_order_relaxed);
}

/* sqlo - get seqlock position -- for the "counter" seqlock */
extern seqlock_val_t seqlock_cur(struct seqlock *sqlo);

/* ++sqlo (but atomic & wakes waiters) - returns value that we bumped to.
 *
 * guarantees:
 *  - each seqlock_bump call bumps the position by exactly one SEQLOCK_INCR.
 *    There are no skipped/missed or multiple increments.
 *  - each return value is only returned from one seqlock_bump() call
 */
extern seqlock_val_t seqlock_bump(struct seqlock *sqlo);


/* sqlo = val - can be used on held seqlock. */
extern void seqlock_acquire_val(struct seqlock *sqlo, seqlock_val_t val);

/* sqlo = ref - standard pattern: acquire relative to other seqlock */
static inline void seqlock_acquire(struct seqlock *sqlo, struct seqlock *ref)
{
	seqlock_acquire_val(sqlo, seqlock_cur(ref));
}

/* sqlo = 0 - set seqlock position to 0, marking as non-held */
extern void seqlock_release(struct seqlock *sqlo);
/* release should normally be followed by a bump on the "counter", if
 * anything other than reading RCU items was done
 */

#ifdef __cplusplus
}
#endif

#endif /* _SEQLOCK_H */
