// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR ID Number Allocator
 * Copyright (C) 2018  Amazon.com, Inc. or its affiliates
 */

#ifndef _ZEBRA_ID_ALLOC_H
#define _ZEBRA_ID_ALLOC_H

#include <strings.h>
#include <limits.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDALLOC_INVALID 0

#define IDALLOC_DIR_BITS     8
#define IDALLOC_SUBDIR_BITS  7
#define IDALLOC_PAGE_BITS    7
#define IDALLOC_WORD_BITS    5
#define IDALLOC_OFFSET_BITS  5

#define IDALLOC_DIR_COUNT (1 << IDALLOC_DIR_BITS)
#define IDALLOC_SUBDIR_COUNT (1 << IDALLOC_SUBDIR_BITS)
#define IDALLOC_PAGE_COUNT (1 << IDALLOC_PAGE_BITS)
#define IDALLOC_WORD_COUNT (1 << IDALLOC_WORD_BITS)

struct id_alloc_page {
	/* Bitmask of allocations. 1s indicates the ID is already allocated. */
	uint32_t allocated_mask[IDALLOC_WORD_COUNT];

	/* Bitmask for free space in allocated_mask. 1s indicate whole 32 bit
	 * section is full.
	 */
	uint32_t full_word_mask;

	/* The ID that bit 0 in allocated_mask corresponds to. */
	uint32_t base_value;

	struct id_alloc_page
		*next_has_free; /* Next page with at least one bit open */
};

struct id_alloc_subdir {
	struct id_alloc_page *sublevels[IDALLOC_PAGE_COUNT];
};

struct id_alloc_dir {
	struct id_alloc_subdir *sublevels[IDALLOC_SUBDIR_COUNT];
};

struct id_alloc {
	struct id_alloc_dir *sublevels[IDALLOC_DIR_COUNT];

	struct id_alloc_page *has_free;

	char *name;

	uint32_t allocated, capacity;
};

struct id_alloc_pool {
	struct id_alloc_pool *next;
	uint32_t id;
};

void idalloc_free(struct id_alloc *alloc, uint32_t id);
void idalloc_free_to_pool(struct id_alloc_pool **pool_ptr, uint32_t id);
void idalloc_drain_pool(struct id_alloc *alloc,
			struct id_alloc_pool **pool_ptr);
uint32_t idalloc_allocate(struct id_alloc *alloc);
uint32_t idalloc_allocate_prefer_pool(struct id_alloc *alloc,
				      struct id_alloc_pool **pool_ptr);
uint32_t idalloc_reserve(struct id_alloc *alloc, uint32_t id);
struct id_alloc *idalloc_new(const char *name);
void idalloc_destroy(struct id_alloc *alloc);

#ifdef __cplusplus
}
#endif

#endif
