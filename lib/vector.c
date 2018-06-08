/* Generic vector interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "vector.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, VECTOR, "Vector")
DEFINE_MTYPE_STATIC(LIB, VECTOR_INDEX, "Vector index")

/* Initialize vector : allocate memory and return vector. */
vector vector_init(unsigned int size)
{
	vector v = XCALLOC(MTYPE_VECTOR, sizeof(struct _vector));

	/* allocate at least one slot */
	if (size == 0)
		size = 1;

	v->alloced = size;
	v->active = 0;
	v->index = XCALLOC(MTYPE_VECTOR_INDEX, sizeof(void *) * size);
	return v;
}

void vector_free(vector v)
{
	XFREE(MTYPE_VECTOR_INDEX, v->index);
	XFREE(MTYPE_VECTOR, v);
}

vector vector_copy(vector v)
{
	unsigned int size;
	vector new = XCALLOC(MTYPE_VECTOR, sizeof(struct _vector));

	new->active = v->active;
	new->alloced = v->alloced;

	size = sizeof(void *) * (v->alloced);
	new->index = XCALLOC(MTYPE_VECTOR_INDEX, size);
	memcpy(new->index, v->index, size);

	return new;
}

/* Check assigned index, and if it runs short double index pointer */
void vector_ensure(vector v, unsigned int num)
{
	if (v->alloced > num)
		return;

	v->index = XREALLOC(MTYPE_VECTOR_INDEX, v->index,
			    sizeof(void *) * (v->alloced * 2));
	memset(&v->index[v->alloced], 0, sizeof(void *) * v->alloced);
	v->alloced *= 2;

	if (v->alloced <= num)
		vector_ensure(v, num);
}

/* This function only returns next empty slot index.  It dose not mean
   the slot's index memory is assigned, please call vector_ensure()
   after calling this function. */
int vector_empty_slot(vector v)
{
	unsigned int i;

	if (v->active == 0)
		return 0;

	for (i = 0; i < v->active; i++)
		if (v->index[i] == 0)
			return i;

	return i;
}

/* Set value to the smallest empty slot. */
int vector_set(vector v, void *val)
{
	unsigned int i;

	i = vector_empty_slot(v);
	vector_ensure(v, i);

	v->index[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

/* Set value to specified index slot. */
int vector_set_index(vector v, unsigned int i, void *val)
{
	vector_ensure(v, i);

	v->index[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

/* Look up vector.  */
void *vector_lookup(vector v, unsigned int i)
{
	if (i >= v->active)
		return NULL;
	return v->index[i];
}

/* Lookup vector, ensure it. */
void *vector_lookup_ensure(vector v, unsigned int i)
{
	vector_ensure(v, i);
	return v->index[i];
}

/* Unset value at specified index slot. */
void vector_unset(vector v, unsigned int i)
{
	if (i >= v->alloced)
		return;

	v->index[i] = NULL;

	if (i + 1 == v->active) {
		v->active--;
		while (i && v->index[--i] == NULL && v->active--)
			; /* Is this ugly ? */
	}
}

void vector_remove(vector v, unsigned int ix)
{
	if (ix >= v->active)
		return;

	int n = (--v->active) - ix;

	memmove(&v->index[ix], &v->index[ix + 1], n * sizeof(void *));
	v->index[v->active] = NULL;
}

void vector_compact(vector v)
{
	for (unsigned int i = 0; i < vector_active(v); ++i) {
		if (vector_slot(v, i) == NULL) {
			vector_remove(v, i);
			--i;
		}
	}
}

void vector_unset_value(vector v, void *val)
{
	size_t i;

	for (i = 0; i < v->active; i++)
		if (v->index[i] == val) {
			v->index[i] = NULL;
			break;
		}

	if (i + 1 == v->active)
		do
			v->active--;
		while (i && v->index[--i] == NULL);
}

/* Count the number of not emplty slot. */
unsigned int vector_count(vector v)
{
	unsigned int i;
	unsigned count = 0;

	for (i = 0; i < v->active; i++)
		if (v->index[i] != NULL)
			count++;

	return count;
}

void vector_to_array(vector v, void ***dest, int *argc)
{
	*dest = XCALLOC(MTYPE_TMP, sizeof(void *) * v->active);
	memcpy(*dest, v->index, sizeof(void *) * v->active);
	*argc = v->active;
}

vector array_to_vector(void **src, int argc)
{
	vector v = vector_init(VECTOR_MIN_SIZE);

	for (int i = 0; i < argc; i++)
		vector_set_index(v, i, src[i]);
	return v;
}
