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
	unsigned int active;  /* number of active slots */
	unsigned int alloced; /* number of allocated slot */
	unsigned int count;
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
extern vector vector_copy(vector v);

extern void *vector_lookup(vector, unsigned int);
extern void *vector_lookup_ensure(vector, unsigned int);
extern void vector_to_array(vector v, void ***dest, int *argc);
extern vector array_to_vector(void **src, int argc);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VECTOR_H */
