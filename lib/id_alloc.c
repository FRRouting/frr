/*
 * FRR ID Number Allocator
 * Copyright (C) 2018  Amazon.com, Inc. or its affiliates
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "id_alloc.h"

#include "log.h"
#include "lib_errors.h"
#include "memory.h"

#include <inttypes.h>

DEFINE_MTYPE_STATIC(LIB, IDALLOC_ALLOCATOR, "ID Number Allocator");
DEFINE_MTYPE_STATIC(LIB, IDALLOC_ALLOCATOR_NAME, "ID Number Allocator Name");
DEFINE_MTYPE_STATIC(LIB, IDALLOC_DIRECTORY, "ID Number Allocator Directory");
DEFINE_MTYPE_STATIC(LIB, IDALLOC_SUBDIRECTORY,
		    "ID Number Allocator Subdirectory");
DEFINE_MTYPE_STATIC(LIB, IDALLOC_PAGE, "ID Number Allocator Page");
DEFINE_MTYPE_STATIC(LIB, IDALLOC_POOL,
		    "ID Number temporary holding pool entry");

#if UINT_MAX >= UINT32_MAX
#define FFS32(x) ffs(x)
#else
/* ints less than 32 bits? Yikes. */
#define FFS32(x) ffsl(x)
#endif

#define DIR_MASK    ((1<<IDALLOC_DIR_BITS)-1)
#define SUBDIR_MASK ((1<<IDALLOC_SUBDIR_BITS)-1)
#define FRR_ID_PAGE_MASK ((1<<IDALLOC_PAGE_BITS)-1)
#define WORD_MASK   ((1<<IDALLOC_WORD_BITS)-1)
#define OFFSET_MASK ((1<<IDALLOC_OFFSET_BITS)-1)

#define DIR_SHIFT    (IDALLOC_OFFSET_BITS + IDALLOC_WORD_BITS + \
		      IDALLOC_PAGE_BITS + IDALLOC_SUBDIR_BITS)
#define SUBDIR_SHIFT (IDALLOC_OFFSET_BITS + IDALLOC_WORD_BITS + \
		      IDALLOC_PAGE_BITS)
#define FRR_ID_PAGE_SHIFT (IDALLOC_OFFSET_BITS + IDALLOC_WORD_BITS)
#define WORD_SHIFT   (IDALLOC_OFFSET_BITS)
#define OFFSET_SHIFT (0)

#define ID_DIR(id)    ((id >> DIR_SHIFT)    & DIR_MASK)
#define ID_SUBDIR(id) ((id >> SUBDIR_SHIFT) & SUBDIR_MASK)
#define ID_PAGE(id)   ((id >> FRR_ID_PAGE_SHIFT) & FRR_ID_PAGE_MASK)
#define ID_WORD(id)   ((id >> WORD_SHIFT)   & WORD_MASK)
#define ID_OFFSET(id) ((id >> OFFSET_SHIFT) & OFFSET_MASK)

/*
 * Find the page that an ID number belongs to in an allocator.
 * Optionally create the page if it doesn't exist.
 */
static struct id_alloc_page *find_or_create_page(struct id_alloc *alloc,
						 uint32_t id, int create)
{
	struct id_alloc_dir *dir = NULL;
	struct id_alloc_subdir *subdir = NULL;
	struct id_alloc_page *page = NULL;

	dir = alloc->sublevels[ID_DIR(id)];
	if (dir == NULL) {
		if (create) {
			dir = XCALLOC(MTYPE_IDALLOC_DIRECTORY, sizeof(*dir));
			alloc->sublevels[ID_DIR(id)] = dir;
		} else {
			return NULL;
		}
	}

	subdir = dir->sublevels[ID_SUBDIR(id)];
	if (subdir == NULL) {
		if (create) {
			subdir = XCALLOC(MTYPE_IDALLOC_SUBDIRECTORY,
					 sizeof(*subdir));
			dir->sublevels[ID_SUBDIR(id)] = subdir;
		} else {
			return NULL;
		}
	}

	page = subdir->sublevels[ID_PAGE(id)];
	if (page == NULL && create) {
		page = XCALLOC(MTYPE_IDALLOC_PAGE, sizeof(*page));
		page->base_value = id;
		subdir->sublevels[ID_PAGE(id)] = page;

		alloc->capacity += 1 << FRR_ID_PAGE_SHIFT;
		page->next_has_free = alloc->has_free;
		alloc->has_free = page;
	} else if (page != NULL && create) {
		flog_err(
			EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s attempt to re-create page at %u",
			alloc->name, id);
	}

	return page;
}

/*
 * Return an ID number back to the allocator.
 * While this ID can be re-assigned through idalloc_allocate, the underlying
 * memory will not be freed. If this is the first free ID in the page, the page
 * will be added to the allocator's list of pages with free IDs.
 */
void idalloc_free(struct id_alloc *alloc, uint32_t id)
{
	struct id_alloc_page *page = NULL;

	int word, offset;
	uint32_t old_word, old_word_mask;

	page = find_or_create_page(alloc, id, 0);
	if (!page) {
		flog_err(EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s cannot free #%u. ID Block does not exist.",
			alloc->name, id);
		return;
	}

	word = ID_WORD(id);
	offset = ID_OFFSET(id);

	if ((page->allocated_mask[word] & (1 << offset)) == 0) {
		flog_err(EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s cannot free #%u. ID was not allocated at the time of free.",
			alloc->name, id);
		return;
	}

	old_word = page->allocated_mask[word];
	page->allocated_mask[word] &= ~(((uint32_t)1) << offset);
	alloc->allocated -= 1;

	if (old_word == UINT32_MAX) {
		/* first bit in this block of 32 to be freed.*/

		old_word_mask = page->full_word_mask;
		page->full_word_mask &= ~(((uint32_t)1) << word);

		if (old_word_mask == UINT32_MAX) {
			/* first bit in page freed, add this to the allocator's
			 * list of pages with free space
			 */
			page->next_has_free = alloc->has_free;
			alloc->has_free = page;
		}
	}
}

/*
 * Add a allocation page to the end of the allocator's current range.
 * Returns null if the allocator has had all possible pages allocated already.
 */
static struct id_alloc_page *create_next_page(struct id_alloc *alloc)
{
	if (alloc->capacity == 0 && alloc->sublevels[0])
		return NULL; /* All IDs allocated and the capacity looped. */

	return find_or_create_page(alloc, alloc->capacity, 1);
}

/*
 * Marks an ID within an allocator page as in use.
 * If the ID was the last free ID in the page, the page is removed from the
 * allocator's list of free IDs. In the typical allocation case, this page is
 * the first page in the list, and removing the page is fast. If instead an ID
 * is being reserved by number, this may end up scanning the whole single linked
 * list of pages in order to remove it.
 */
static void reserve_bit(struct id_alloc *alloc, struct id_alloc_page *page,
			int word, int offset)
{
	struct id_alloc_page *itr;

	page->allocated_mask[word] |= ((uint32_t)1) << offset;
	alloc->allocated += 1;

	if (page->allocated_mask[word] == UINT32_MAX) {
		page->full_word_mask |= ((uint32_t)1) << word;
		if (page->full_word_mask == UINT32_MAX) {
			if (alloc->has_free == page) {
				/* allocate always pulls from alloc->has_free */
				alloc->has_free = page->next_has_free;
			} else {
				/* reserve could pull from any page with free
				 * bits
				 */
				itr = alloc->has_free;
				while (itr) {
					if (itr->next_has_free == page) {
						itr->next_has_free =
							page->next_has_free;
						return;
					}

					itr = itr->next_has_free;
				}
			}
		}
	}
}

/*
 * Reserve an ID number from the allocator. Returns IDALLOC_INVALID (0) if the
 * allocator has no more IDs available.
 */
uint32_t idalloc_allocate(struct id_alloc *alloc)
{
	struct id_alloc_page *page;
	int word, offset;
	uint32_t return_value;

	if (alloc->has_free == NULL)
		create_next_page(alloc);

	if (alloc->has_free == NULL) {
		flog_err(EC_LIB_ID_EXHAUST,
			"ID Allocator %s has run out of IDs.", alloc->name);
		return IDALLOC_INVALID;
	}

	page = alloc->has_free;
	word = FFS32(~(page->full_word_mask)) - 1;

	if (word < 0 || word >= 32) {
		flog_err(EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s internal error. Page starting at %d is inconsistent.",
			alloc->name, page->base_value);
		return IDALLOC_INVALID;
	}

	offset = FFS32(~(page->allocated_mask[word])) - 1;
	if (offset < 0 || offset >= 32) {
		flog_err(EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s internal error. Page starting at %d is inconsistent on word %d",
			alloc->name, page->base_value, word);
		return IDALLOC_INVALID;
	}
	return_value = page->base_value + word * 32 + offset;

	reserve_bit(alloc, page, word, offset);

	return return_value;
}

/*
 * Tries to allocate a specific ID from the allocator. Returns IDALLOC_INVALID
 * when the ID being "reserved" has allready been assigned/reserved. This should
 * only be done with low numbered IDs, as the allocator needs to reserve bit-map
 * pages in order
 */
uint32_t idalloc_reserve(struct id_alloc *alloc, uint32_t id)
{
	struct id_alloc_page *page;
	int word, offset;

	while (alloc->capacity <= id)
		create_next_page(alloc);

	word = ID_WORD(id);
	offset = ID_OFFSET(id);
	page = find_or_create_page(alloc, id, 0);
	/* page can't be null because the loop above ensured it was created. */

	if (page->allocated_mask[word] & (((uint32_t)1) << offset)) {
		flog_err(EC_LIB_ID_CONSISTENCY,
			"ID Allocator %s could not reserve %u because it is already allocated.",
			alloc->name, id);
		return IDALLOC_INVALID;
	}

	reserve_bit(alloc, page, word, offset);
	return id;
}

/*
 * Set up an empty ID allocator, with IDALLOC_INVALID pre-reserved.
 */
struct id_alloc *idalloc_new(const char *name)
{
	struct id_alloc *ret;

	ret = XCALLOC(MTYPE_IDALLOC_ALLOCATOR, sizeof(*ret));
	ret->name = XSTRDUP(MTYPE_IDALLOC_ALLOCATOR_NAME, name);

	idalloc_reserve(ret, IDALLOC_INVALID);

	return ret;
}

/*
 * Free a subdir, and all pages below it.
 */
static void idalloc_destroy_subdir(struct id_alloc_subdir *subdir)
{
	int i;

	for (i = 0; i < IDALLOC_PAGE_COUNT; i++) {
		if (subdir->sublevels[i])
			XFREE(MTYPE_IDALLOC_PAGE, subdir->sublevels[i]);
		else
			break;
	}
	XFREE(MTYPE_IDALLOC_SUBDIRECTORY, subdir);
}

/*
 * Free a dir, and all subdirs/pages below it.
 */
static void idalloc_destroy_dir(struct id_alloc_dir *dir)
{
	int i;

	for (i = 0; i < IDALLOC_SUBDIR_COUNT; i++) {
		if (dir->sublevels[i])
			idalloc_destroy_subdir(dir->sublevels[i]);
		else
			break;
	}
	XFREE(MTYPE_IDALLOC_DIRECTORY, dir);
}

/*
 * Free all memory associated with an ID allocator.
 */
void idalloc_destroy(struct id_alloc *alloc)
{
	int i;

	for (i = 0; i < IDALLOC_DIR_COUNT; i++) {
		if (alloc->sublevels[i])
			idalloc_destroy_dir(alloc->sublevels[i]);
		else
			break;
	}

	XFREE(MTYPE_IDALLOC_ALLOCATOR_NAME, alloc->name);
	XFREE(MTYPE_IDALLOC_ALLOCATOR, alloc);
}

/*
 * Give an ID number to temporary holding pool.
 */
void idalloc_free_to_pool(struct id_alloc_pool **pool_ptr, uint32_t id)
{
	struct id_alloc_pool *new_pool;

	new_pool = XMALLOC(MTYPE_IDALLOC_POOL, sizeof(*new_pool));
	new_pool->id = id;
	new_pool->next = *pool_ptr;
	*pool_ptr = new_pool;
}

/*
 * Free all ID numbers held in a holding pool back to the main allocator.
 */
void idalloc_drain_pool(struct id_alloc *alloc, struct id_alloc_pool **pool_ptr)
{
	struct id_alloc_pool *current, *next;

	while (*pool_ptr) {
		current = *pool_ptr;
		next = current->next;
		idalloc_free(alloc, current->id);
		XFREE(MTYPE_IDALLOC_POOL, current);
		*pool_ptr = next;
	}
}

/*
 * Allocate an ID from either a holding pool, or the main allocator. IDs will
 * only be pulled form the main allocator when the pool is empty.
 */
uint32_t idalloc_allocate_prefer_pool(struct id_alloc *alloc,
				      struct id_alloc_pool **pool_ptr)
{
	uint32_t ret;
	struct id_alloc_pool *pool_head = *pool_ptr;

	if (pool_head) {
		ret = pool_head->id;
		*pool_ptr = pool_head->next;
		XFREE(MTYPE_IDALLOC_POOL, pool_head);
		return ret;
	} else {
		return idalloc_allocate(alloc);
	}
}
