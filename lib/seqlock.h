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

#ifndef _SEQLOCK_H
#define _SEQLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "frratomic.h"

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
 * be 1 to have a 'cleared' indication (i.e., counts 1,3,5,7,etc. )
 */
typedef _Atomic uint32_t	seqlock_ctr_t;
typedef uint32_t		seqlock_val_t;
#define seqlock_assert_valid(val) assert(val & 1)


struct seqlock {
/* always used */
	seqlock_ctr_t pos;
/* used when futexes not available: (i.e. non-linux) */
	pthread_mutex_t lock;
	pthread_cond_t  wake;
};


/* sqlo = 0 - init state: not held */
extern void seqlock_init(struct seqlock *sqlo);


/* while (sqlo <= val) - wait until seqlock->pos > val, or seqlock unheld */
extern void seqlock_wait(struct seqlock *sqlo, seqlock_val_t val);
extern bool seqlock_check(struct seqlock *sqlo, seqlock_val_t val);

static inline bool seqlock_held(struct seqlock *sqlo)
{
	return !!atomic_load_explicit(&sqlo->pos, memory_order_relaxed);
}

/* sqlo - get seqlock position -- for the "counter" seqlock */
extern seqlock_val_t seqlock_cur(struct seqlock *sqlo);
/* sqlo++ - note: like x++, returns previous value, before bumping */
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

#endif /* _SEQLOCK_H */
