/*
 * linear_allocator.h
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
 * Header file for the linear allocator.
 *
 * An allocator that allocates memory by walking down towards the end
 * of a buffer. No attempt is made to reuse blocks that are freed
 * subsequently. The assumption is that the buffer is big enough to
 * cover allocations for a given purpose.
 */
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Alignment for block allocated by the allocator. Must be a power of 2.
 */
#define LINEAR_ALLOCATOR_ALIGNMENT        8

#define LINEAR_ALLOCATOR_ALIGN(value)                                          \
	(((value) + LINEAR_ALLOCATOR_ALIGNMENT - 1)                            \
	 & ~(LINEAR_ALLOCATOR_ALIGNMENT - 1));

/*
 * linear_allocator_align_ptr
 */
static inline char *linear_allocator_align_ptr(char *ptr)
{
	return (char *)LINEAR_ALLOCATOR_ALIGN((intptr_t)ptr);
}

typedef struct linear_allocator_t_ {
	char *buf;

	/*
	 * Current location in the buffer.
	 */
	char *cur;

	/*
	 * End of buffer.
	 */
	char *end;

	/*
	 * Version number of the allocator, this is bumped up when the allocator
	 * is reset and helps identifies bad frees.
	 */
	uint32_t version;

	/*
	 * The number of blocks that are currently allocated.
	 */
	int num_allocated;
} linear_allocator_t;

/*
 * linear_allocator_block_t
 *
 * Header structure at the begining of each block.
 */
typedef struct linear_allocator_block_t_ {
	uint32_t flags;

	/*
	 * The version of the allocator when this block was allocated.
	 */
	uint32_t version;
	char data[0];
} linear_allocator_block_t;

#define LINEAR_ALLOCATOR_BLOCK_IN_USE 0x01

#define LINEAR_ALLOCATOR_HDR_SIZE (sizeof(linear_allocator_block_t))

/*
 * linear_allocator_block_size
 *
 * The total amount of space a block will take in the buffer,
 * including the size of the header.
 */
static inline size_t linear_allocator_block_size(size_t user_size)
{
	return LINEAR_ALLOCATOR_ALIGN(LINEAR_ALLOCATOR_HDR_SIZE + user_size);
}

/*
 * linear_allocator_ptr_to_block
 */
static inline linear_allocator_block_t *linear_allocator_ptr_to_block(void *ptr)
{
	void *block_ptr;
	block_ptr = ((char *)ptr) - offsetof(linear_allocator_block_t, data);
	return block_ptr;
}

/*
 * linear_allocator_init
 */
static inline void linear_allocator_init(linear_allocator_t *allocator,
					 char *buf, size_t buf_len)
{
	memset(allocator, 0, sizeof(*allocator));

	assert(linear_allocator_align_ptr(buf) == buf);
	allocator->buf = buf;
	allocator->cur = buf;
	allocator->end = buf + buf_len;
}

/*
 * linear_allocator_reset
 *
 * Prepare an allocator for reuse.
 *
 * *** NOTE ** This implicitly frees all the blocks in the allocator.
 */
static inline void linear_allocator_reset(linear_allocator_t *allocator)
{
	allocator->num_allocated = 0;
	allocator->version++;
	allocator->cur = allocator->buf;
}

/*
 * linear_allocator_alloc
 */
static inline void *linear_allocator_alloc(linear_allocator_t *allocator,
					   size_t user_size)
{
	size_t block_size;
	linear_allocator_block_t *block;

	block_size = linear_allocator_block_size(user_size);

	if (allocator->cur + block_size > allocator->end) {
		return NULL;
	}

	block = (linear_allocator_block_t *)allocator->cur;
	allocator->cur += block_size;

	block->flags = LINEAR_ALLOCATOR_BLOCK_IN_USE;
	block->version = allocator->version;
	allocator->num_allocated++;
	return block->data;
}

/*
 * linear_allocator_free
 */
static inline void linear_allocator_free(linear_allocator_t *allocator,
					 void *ptr)
{
	linear_allocator_block_t *block;

	if (((char *)ptr) < allocator->buf || ((char *)ptr) >= allocator->end) {
		assert(0);
		return;
	}

	block = linear_allocator_ptr_to_block(ptr);
	if (block->version != allocator->version) {
		assert(0);
		return;
	}

	block->flags = block->flags & ~LINEAR_ALLOCATOR_BLOCK_IN_USE;

	if (--allocator->num_allocated < 0) {
		assert(0);
	}
}
