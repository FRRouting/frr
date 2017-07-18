/*
 * qpb_allocator.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Header file for Quagga/FRR protobuf memory management code.
 */

#ifndef _QPB_ALLOCATOR_H_
#define _QPB_ALLOCATOR_H_

#include <google/protobuf-c/protobuf-c.h>

struct linear_allocator_t_;

/*
 * Alias for ProtobufCAllocator that is easier on the fingers.
 */
typedef ProtobufCAllocator qpb_allocator_t;

/*
 * qpb_alloc
 */
static inline void *qpb_alloc(qpb_allocator_t *allocator, size_t size)
{
	return allocator->alloc(allocator->allocator_data, size);
}

/*
 * qpb_alloc_ptr_array
 *
 * Allocate space for the specified number of pointers.
 */
static inline void *qpb_alloc_ptr_array(qpb_allocator_t *allocator,
					size_t num_ptrs)
{
	return qpb_alloc(allocator, num_ptrs * sizeof(void *));
}

/*
 * qpb_free
 */
static inline void qpb_free(qpb_allocator_t *allocator, void *ptr)
{
	allocator->free(allocator->allocator_data, ptr);
}

/*
 * QPB_ALLOC
 *
 * Convenience macro to reduce the probability of allocating memory of
 * incorrect size. It returns enough memory to store the given type,
 * and evaluates to an appropriately typed pointer.
 */
#define QPB_ALLOC(allocator, type) (type *)qpb_alloc(allocator, sizeof(type))

/*
 * Externs.
 */
extern void qpb_allocator_init_linear(qpb_allocator_t *,
				      struct linear_allocator_t_ *);

/*
 * The following macros are for the common case where a qpb allocator
 * is being used alongside a linear allocator that allocates memory
 * off of the stack.
 */
#define QPB_DECLARE_STACK_ALLOCATOR(allocator, size)                           \
	qpb_allocator_t allocator;                                             \
	linear_allocator_t lin_##allocator;                                    \
	char lin_##allocator##_buf[size]

#define QPB_INIT_STACK_ALLOCATOR(allocator)                                    \
	do {                                                                   \
		linear_allocator_init(&(lin_##allocator),                      \
				      lin_##allocator##_buf,                   \
				      sizeof(lin_##allocator##_buf));          \
		qpb_allocator_init_linear(&allocator, &(lin_##allocator));     \
	} while (0)

#define QPB_RESET_STACK_ALLOCATOR(allocator)                                   \
	do {                                                                   \
		linear_allocator_reset(&(lin_##allocator));                    \
	} while (0)

#endif /* _QPB_ALLOCATOR_H_ */
