// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Generic vector interface header.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_VECTOR_H
#define _ZEBRA_VECTOR_H

#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* struct for vector */
struct _vector {
	/* active: index of last non-NULL item (+1)
	 * count:  number of non-NULL items (+1)
	 *
	 * the two will be different if a slot is set to NULL (without pulling
	 * up later items in the array).  Whether this happens depends on
	 * which vector functions are used.  If no empty slots are used, the
	 * two fields will be identical.
	 *
	 * alloced: size of array pointed to by index.  If this is 0, index
	 * points at a global variable rather than a malloc'd bit of memory.
	 * The vector code will convert to malloc'd memory if necessary to
	 * perform updates.
	 */
	unsigned int active;
	unsigned int alloced;
	unsigned int count;

	/* whether struct _vector itself is dynamically allocated */
	bool dynamic;

	void **index;	 /* index to data */
};
typedef struct _vector *vector;

#define VECTOR_MIN_SIZE 1

/* (Sometimes) usefull macros.  This macro convert index expression to
 array expression. */
/* Reference slot at given index, caller must ensure slot is active */
#define vector_slot(V,I)  ((V)->index[(I)])
/* Number of active slots.
 * Note that this differs from vector_count() as it the count returned
 * will include any empty slots
 */
#define vector_active(V) ((V)->active)

/* Prototypes. */
extern vector vector_init(unsigned int size);
extern void vector_ensure(vector v, unsigned int num);
extern int vector_empty_slot(vector v);
extern int vector_set(vector v, void *val);
extern int vector_set_index(vector v, unsigned int i, void *val);
extern void vector_unset(vector v, unsigned int i);
extern void vector_unset_value(vector v, void *val);
extern void vector_remove(vector v, unsigned int ix);
extern void vector_compact(vector v);

static inline unsigned int vector_count(vector v)
{
	return v->count;
}

extern void vector_free(vector v);

extern void *vector_lookup(vector, unsigned int);
extern void *vector_lookup_ensure(vector, unsigned int);
extern void vector_to_array(vector v, void ***dest, int *argc);
extern vector array_to_vector(void **src, int argc);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VECTOR_H */
