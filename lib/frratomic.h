/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRRATOMIC_H
#define _FRRATOMIC_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef FRR_AUTOCONF_ATOMIC
#error autoconf checks for atomic functions were not properly run
#endif

/* ISO C11 */
#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>

/* gcc 4.7 and newer */
#elif defined(HAVE___ATOMIC)

#define _Atomic volatile

#define memory_order_relaxed __ATOMIC_RELAXED
#define memory_order_consume __ATOMIC_CONSUME
#define memory_order_acquire __ATOMIC_ACQUIRE
#define memory_order_release __ATOMIC_RELEASE
#define memory_order_acq_rel __ATOMIC_ACQ_REL
#define memory_order_seq_cst __ATOMIC_SEQ_CST

#define atomic_load_explicit __atomic_load_n
#define atomic_store_explicit __atomic_store_n
#define atomic_exchange_explicit __atomic_exchange_n
#define atomic_fetch_add_explicit __atomic_fetch_add
#define atomic_fetch_sub_explicit __atomic_fetch_sub
#define atomic_fetch_and_explicit __atomic_fetch_and
#define atomic_fetch_or_explicit __atomic_fetch_or

#define atomic_compare_exchange_weak_explicit(atom, expect, desire, mem1,      \
					      mem2)                            \
	__atomic_compare_exchange_n(atom, expect, desire, 1, mem1, mem2)

/* gcc 4.1 and newer,
 * clang 3.3 (possibly older)
 *
 * __sync_swap isn't in gcc's documentation, but clang has it
 *
 * note __sync_synchronize()
 */
#elif defined(HAVE___SYNC)

#define _Atomic volatile

#define memory_order_relaxed 0
#define memory_order_consume 0
#define memory_order_acquire 0
#define memory_order_release 0
#define memory_order_acq_rel 0
#define memory_order_seq_cst 0

#define atomic_load_explicit(ptr, mem)                                         \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_fetch_and_add((ptr), 0);            \
		__sync_synchronize();                                          \
		rval;                                                          \
	})
#define atomic_store_explicit(ptr, val, mem)                                   \
	({                                                                     \
		__sync_synchronize();                                          \
		*(ptr) = (val);                                                \
		__sync_synchronize();                                          \
		(void)0;                                                       \
	})
#ifdef HAVE___SYNC_SWAP
#define atomic_exchange_explicit(ptr, val, mem)                                \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_swap((ptr, val), 0);                \
		__sync_synchronize();                                          \
		rval;                                                          \
	})
#else /* !HAVE___SYNC_SWAP */
#define atomic_exchange_explicit(ptr, val, mem)                                \
	({                                                                     \
		typeof(ptr) _ptr = (ptr);                                      \
		typeof(val) _val = (val);                                      \
		__sync_synchronize();                                          \
		typeof(*ptr) old1, old2 = __sync_fetch_and_add(_ptr, 0);       \
		do {                                                           \
			old1 = old2;                                           \
			old2 = __sync_val_compare_and_swap(_ptr, old1, _val);  \
		} while (old1 != old2);                                        \
		__sync_synchronize();                                          \
		old2;                                                          \
	})
#endif /* !HAVE___SYNC_SWAP */
#define atomic_fetch_add_explicit(ptr, val, mem)                               \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_fetch_and_add((ptr), (val));        \
		__sync_synchronize();                                          \
		rval;                                                          \
	})
#define atomic_fetch_sub_explicit(ptr, val, mem)                               \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_fetch_and_sub((ptr), (val));        \
		__sync_synchronize();                                          \
		rval;                                                          \
	})

#define atomic_compare_exchange_weak_explicit(atom, expect, desire, mem1,      \
					      mem2)                            \
	({                                                                     \
		typeof(atom) _atom = (atom);                                   \
		typeof(expect) _expect = (expect);                             \
		typeof(desire) _desire = (desire);                             \
		__sync_synchronize();                                          \
		typeof(*atom) rval =                                           \
			__sync_val_compare_and_swap(_atom, *_expect, _desire); \
		__sync_synchronize();                                          \
		bool ret = (rval == *_expect);                                 \
		*_expect = rval;                                               \
		ret;                                                           \
	})
#define atomic_fetch_and_explicit(ptr, val, mem)                               \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_fetch_and_and(ptr, val);            \
		__sync_synchronize();                                          \
		rval;                                                          \
	})
#define atomic_fetch_or_explicit(ptr, val, mem)                                \
	({                                                                     \
		__sync_synchronize();                                          \
		typeof(*ptr) rval = __sync_fetch_and_or(ptr, val);             \
		__sync_synchronize();                                          \
		rval;                                                          \
	})

#else /* !HAVE___ATOMIC && !HAVE_STDATOMIC_H */
#error no atomic functions...
#endif

#endif /* _FRRATOMIC_H */
