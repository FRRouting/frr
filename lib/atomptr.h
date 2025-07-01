// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-26  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ATOMPTR_H
#define _FRR_ATOMPTR_H

#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include "frratomic.h"

/* pointer with lock/deleted/invalid bit in lowest bit
 *
 * for atomlist/atomsort, "locked" means "this pointer can't be updated, the
 * item is being deleted".  it is permissible to assume the item will indeed
 * be deleted (as there are no replace/etc. ops in this).
 *
 * in general, lowest 2/3 bits on 32/64bit architectures are available for
 * uses like this; the only thing that will really break this is putting an
 * atomlist_item in a struct with "packed" attribute.  (it'll break
 * immediately and consistently.) -- don't do that.
 *
 * ATOMPTR_USER is currently unused (and available for atomic hash or skiplist
 * implementations.)
 */

/* atomic_atomptr_t may look a bit odd, it's for the sake of C++ compat */
typedef uintptr_t atomptr_t;
typedef atomic_uintptr_t atomic_atomptr_t;

#define ATOMPTR_MASK (UINTPTR_MAX - 3)
#define ATOMPTR_LOCK (1)
#define ATOMPTR_USER (2)
#define ATOMPTR_NULL (0)

/* this is intended to "ingest" a pointer into use as atomptr_t.
 * hence the assert
 */
static inline atomptr_t atomptr_i(void *val)
{
	atomptr_t atomval = (atomptr_t)val;

	assert(!(atomval & ATOMPTR_LOCK));
	return atomval;
}

static inline void *atomptr_p(atomptr_t val)
{
	return (void *)(val & ATOMPTR_MASK);
}

static inline bool atomptr_l(atomptr_t val)
{
	return (bool)(val & ATOMPTR_LOCK);
}

static inline bool atomptr_u(atomptr_t val)
{
	return (bool)(val & ATOMPTR_USER);
}

/* multi-flag operations */

static inline uintptr_t atomptr_xx(atomptr_t val)
{
	return val & (ATOMPTR_USER | ATOMPTR_LOCK);
}

static inline bool atomptr_is_ul(atomptr_t val)
{
	return atomptr_xx(val) == (ATOMPTR_USER | ATOMPTR_LOCK);
}

static inline bool atomptr_is_u0(atomptr_t val)
{
	return atomptr_xx(val) == ATOMPTR_USER;
}

static inline bool atomptr_is_0l(atomptr_t val)
{
	return atomptr_xx(val) == ATOMPTR_LOCK;
}

static inline bool atomptr_is_00(atomptr_t val)
{
	return atomptr_xx(val) == 0;
}

static inline atomptr_t atomptr_copy_flags(atomptr_t ptr, atomptr_t flags)
{
	return (ptr & ATOMPTR_MASK) | atomptr_xx(flags);
}

#endif /* _FRR_ATOMPTR_H */
