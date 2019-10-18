/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "typesafe.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, TYPEDHASH_BUCKET, "Typed-hash bucket")
DEFINE_MTYPE_STATIC(LIB, SKIPLIST_OFLOW, "Skiplist overflow")
DEFINE_MTYPE_STATIC(LIB, HEAP_ARRAY, "Typed-heap array")

#if 0
static void hash_consistency_check(struct thash_head *head)
{
	uint32_t i;
	struct thash_item *item, *prev;

	for (i = 0; i < HASH_SIZE(*head); i++) {
		item = head->entries[i];
		prev = NULL;
		while (item) {
			assert(HASH_KEY(*head, item->hashval) == i);
			assert(!prev || item->hashval >= prev->hashval);
			prev = item;
			item = item->next;
		}
	}
}
#else
#define hash_consistency_check(x)
#endif

void typesafe_hash_grow(struct thash_head *head)
{
	uint32_t newsize = head->count, i, j;
	uint8_t newshift, delta;

	hash_consistency_check(head);

	newsize |= newsize >> 1;
	newsize |= newsize >> 2;
	newsize |= newsize >> 4;
	newsize |= newsize >> 8;
	newsize |= newsize >> 16;
	newsize++;
	newshift = __builtin_ctz(newsize) + 1;

	if (head->maxshift && newshift > head->maxshift)
		newshift = head->maxshift;
	if (newshift == head->tabshift)
		return;
	newsize = _HASH_SIZE(newshift);

	head->entries = XREALLOC(MTYPE_TYPEDHASH_BUCKET, head->entries,
			sizeof(head->entries[0]) * newsize);
	memset(head->entries + HASH_SIZE(*head), 0,
			sizeof(head->entries[0]) *
				(newsize - HASH_SIZE(*head)));

	delta = newshift - head->tabshift;

	i = HASH_SIZE(*head);
	if (i == 0)
		goto out;
	do {
		struct thash_item **apos, *item;

		i--;
		apos = &head->entries[i];

		for (j = 0; j < (1U << delta); j++) {
			item = *apos;
			*apos = NULL;

			head->entries[(i << delta) + j] = item;
			apos = &head->entries[(i << delta) + j];

			while ((item = *apos)) {
				uint32_t midbits;
				midbits = _HASH_KEY(newshift, item->hashval);
				midbits &= (1 << delta) - 1;
				if (midbits > j)
					break;
				apos = &item->next;
			}
		}
	} while (i > 0);

out:
	head->tabshift = newshift;
	hash_consistency_check(head);
}

void typesafe_hash_shrink(struct thash_head *head)
{
	uint32_t newsize = head->count, i, j;
	uint8_t newshift, delta;

	hash_consistency_check(head);

	if (!head->count) {
		XFREE(MTYPE_TYPEDHASH_BUCKET, head->entries);
		head->tabshift = 0;
		return;
	}

	newsize |= newsize >> 1;
	newsize |= newsize >> 2;
	newsize |= newsize >> 4;
	newsize |= newsize >> 8;
	newsize |= newsize >> 16;
	newsize++;
	newshift = __builtin_ctz(newsize) + 1;

	if (head->minshift && newshift < head->minshift)
		newshift = head->minshift;
	if (newshift == head->tabshift)
		return;
	newsize = _HASH_SIZE(newshift);

	delta = head->tabshift - newshift;

	for (i = 0; i < newsize; i++) {
		struct thash_item **apos = &head->entries[i];

		for (j = 0; j < (1U << delta); j++) {
			*apos = head->entries[(i << delta) + j];
			while (*apos)
				apos = &(*apos)->next;
		}
	}
	head->entries = XREALLOC(MTYPE_TYPEDHASH_BUCKET, head->entries,
			sizeof(head->entries[0]) * newsize);
	head->tabshift = newshift;

	hash_consistency_check(head);
}

/* skiplist */

static inline struct sskip_item *sl_level_get(struct sskip_item *item,
			size_t level)
{
	if (level < SKIPLIST_OVERFLOW)
		return item->next[level];
	if (level == SKIPLIST_OVERFLOW && !((uintptr_t)item->next[level] & 1))
		return item->next[level];

	uintptr_t ptrval = (uintptr_t)item->next[SKIPLIST_OVERFLOW];
	ptrval &= UINTPTR_MAX - 3;
	struct sskip_overflow *oflow = (struct sskip_overflow *)ptrval;
	return oflow->next[level - SKIPLIST_OVERFLOW];
}

static inline void sl_level_set(struct sskip_item *item, size_t level,
		struct sskip_item *value)
{
	if (level < SKIPLIST_OVERFLOW)
		item->next[level] = value;
	else if (level == SKIPLIST_OVERFLOW && !((uintptr_t)item->next[level] & 1))
		item->next[level] = value;
	else {
		uintptr_t ptrval = (uintptr_t)item->next[SKIPLIST_OVERFLOW];
		ptrval &= UINTPTR_MAX - 3;
		struct sskip_overflow *oflow = (struct sskip_overflow *)ptrval;
		oflow->next[level - SKIPLIST_OVERFLOW] = value;
	}
}

struct sskip_item *typesafe_skiplist_add(struct sskip_head *head,
		struct sskip_item *item,
		int (*cmpfn)(const struct sskip_item *a,
				const struct sskip_item *b))
{
	size_t level = SKIPLIST_MAXDEPTH, newlevel, auxlevel;
	struct sskip_item *prev = &head->hitem, *next, *auxprev, *auxnext;
	int cmpval;

	/* level / newlevel are 1-counted here */
	newlevel = __builtin_ctz(random()) + 1;
	if (newlevel > SKIPLIST_MAXDEPTH)
		newlevel = SKIPLIST_MAXDEPTH;

	next = NULL;
	while (level >= newlevel) {
		next = sl_level_get(prev, level - 1);
		if (!next) {
			level--;
			continue;
		}
		cmpval = cmpfn(next, item);
		if (cmpval < 0) {
			prev = next;
			continue;
		} else if (cmpval == 0) {
			return next;
		}
		level--;
	}

	/* check for duplicate item - could be removed if code doesn't rely
	 * on it, but not really work the complication. */
	auxlevel = level;
	auxprev = prev;
	while (auxlevel) {
		auxlevel--;
		auxnext = sl_level_get(auxprev, auxlevel);
		cmpval = 1;
		while (auxnext && (cmpval = cmpfn(auxnext, item)) < 0) {
			auxprev = auxnext;
			auxnext = sl_level_get(auxprev, auxlevel);
		}
		if (cmpval == 0)
			return auxnext;
	};

	head->count++;
	memset(item, 0, sizeof(*item));
	if (newlevel > SKIPLIST_EMBED) {
		struct sskip_overflow *oflow;
		oflow = XMALLOC(MTYPE_SKIPLIST_OFLOW, sizeof(void *)
				* (newlevel - SKIPLIST_OVERFLOW));
		item->next[SKIPLIST_OVERFLOW] = (struct sskip_item *)
				((uintptr_t)oflow | 1);
	}

	sl_level_set(item, level, next);
	sl_level_set(prev, level, item);
	/* level is now 0-counted and < newlevel*/
	while (level) {
		level--;
		next = sl_level_get(prev, level);
		while (next && cmpfn(next, item) < 0) {
			prev = next;
			next = sl_level_get(prev, level);
		}

		sl_level_set(item, level, next);
		sl_level_set(prev, level, item);
	};
	return NULL;
}

/* NOTE: level counting below is 1-based since that makes the code simpler! */

struct sskip_item *typesafe_skiplist_find(struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
				const struct sskip_item *a,
				const struct sskip_item *b))
{
	size_t level = SKIPLIST_MAXDEPTH;
	struct sskip_item *prev = &head->hitem, *next;
	int cmpval;

	while (level) {
		next = sl_level_get(prev, level - 1);
		if (!next) {
			level--;
			continue;
		}
		cmpval = cmpfn(next, item);
		if (cmpval < 0) {
			prev = next;
			continue;
		}
		if (cmpval == 0)
			return next;
		level--;
	}
	return NULL;
}

struct sskip_item *typesafe_skiplist_find_gteq(struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
				const struct sskip_item *a,
				const struct sskip_item *b))
{
	size_t level = SKIPLIST_MAXDEPTH;
	struct sskip_item *prev = &head->hitem, *next;
	int cmpval;

	while (level) {
		next = sl_level_get(prev, level - 1);
		if (!next) {
			level--;
			continue;
		}
		cmpval = cmpfn(next, item);
		if (cmpval < 0) {
			prev = next;
			continue;
		}
		if (cmpval == 0)
			return next;
		level--;
	}
	return next;
}

struct sskip_item *typesafe_skiplist_find_lt(struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
				const struct sskip_item *a,
				const struct sskip_item *b))
{
	size_t level = SKIPLIST_MAXDEPTH;
	struct sskip_item *prev = &head->hitem, *next, *best = NULL;
	int cmpval;

	while (level) {
		next = sl_level_get(prev, level - 1);
		if (!next) {
			level--;
			continue;
		}
		cmpval = cmpfn(next, item);
		if (cmpval < 0) {
			best = prev = next;
			continue;
		}
		level--;
	}
	return best;
}

struct sskip_item *typesafe_skiplist_del(
	struct sskip_head *head, struct sskip_item *item,
	int (*cmpfn)(const struct sskip_item *a, const struct sskip_item *b))
{
	size_t level = SKIPLIST_MAXDEPTH;
	struct sskip_item *prev = &head->hitem, *next;
	int cmpval;
	bool found = false;

	while (level) {
		next = sl_level_get(prev, level - 1);
		if (!next) {
			level--;
			continue;
		}
		if (next == item) {
			sl_level_set(prev, level - 1,
				sl_level_get(item, level - 1));
			level--;
			found = true;
			continue;
		}
		cmpval = cmpfn(next, item);
		if (cmpval < 0) {
			prev = next;
			continue;
		}
		level--;
	}

	if (!found)
		return NULL;

	/* TBD: assert when trying to remove non-existing item? */
	head->count--;

	if ((uintptr_t)item->next[SKIPLIST_OVERFLOW] & 1) {
		uintptr_t ptrval = (uintptr_t)item->next[SKIPLIST_OVERFLOW];
		ptrval &= UINTPTR_MAX - 3;
		struct sskip_overflow *oflow = (struct sskip_overflow *)ptrval;
		XFREE(MTYPE_SKIPLIST_OFLOW, oflow);
	}
	memset(item, 0, sizeof(*item));

	return item;
}

struct sskip_item *typesafe_skiplist_pop(struct sskip_head *head)
{
	size_t level = SKIPLIST_MAXDEPTH;
	struct sskip_item *prev = &head->hitem, *next, *item;

	item = sl_level_get(prev, 0);
	if (!item)
		return NULL;

	do {
		level--;

		next = sl_level_get(prev, level);
		if (next != item)
			continue;

		sl_level_set(prev, level, sl_level_get(item, level));
	} while (level);

	head->count--;

	if ((uintptr_t)item->next[SKIPLIST_OVERFLOW] & 1) {
		uintptr_t ptrval = (uintptr_t)item->next[SKIPLIST_OVERFLOW];
		ptrval &= UINTPTR_MAX - 3;
		struct sskip_overflow *oflow = (struct sskip_overflow *)ptrval;
		XFREE(MTYPE_SKIPLIST_OFLOW, oflow);
	}
	memset(item, 0, sizeof(*item));

	return item;
}

/* heap */

#if 0
static void heap_consistency_check(struct heap_head *head,
				   int (*cmpfn)(const struct heap_item *a,
						const struct heap_item *b),
				   uint32_t pos)
{
	uint32_t rghtpos = pos + 1;
	uint32_t downpos = HEAP_NARY * (pos + 1);

	if (pos + 1 > ~0U / HEAP_NARY)
		downpos = ~0U;

	if ((pos & (HEAP_NARY - 1)) != HEAP_NARY - 1 && rghtpos < head->count) {
		assert(cmpfn(head->array[rghtpos], head->array[pos]) >= 0);
		heap_consistency_check(head, cmpfn, rghtpos);
	}
	if (downpos < head->count) {
		assert(cmpfn(head->array[downpos], head->array[pos]) >= 0);
		heap_consistency_check(head, cmpfn, downpos);
	}
}
#else
#define heap_consistency_check(head, cmpfn, pos)
#endif

void typesafe_heap_resize(struct heap_head *head, bool grow)
{
	uint32_t newsize;

	if (grow) {
		newsize = head->arraysz;
		if (newsize <= 36)
			newsize = 72;
		else if (newsize < 262144)
			newsize += newsize / 2;
		else if (newsize < 0xaaaa0000)
			newsize += newsize / 3;
		else
			assert(!newsize);
	} else if (head->count > 0) {
		newsize = head->count;
	} else {
		XFREE(MTYPE_HEAP_ARRAY, head->array);
		head->arraysz = 0;
		return;
	}

	newsize += HEAP_NARY - 1;
	newsize &= ~(HEAP_NARY - 1);
	if (newsize == head->arraysz)
		return;

	head->array = XREALLOC(MTYPE_HEAP_ARRAY, head->array,
			       newsize * sizeof(struct heap_item *));
	head->arraysz = newsize;
}

void typesafe_heap_pushdown(struct heap_head *head, uint32_t pos,
		struct heap_item *item,
		int (*cmpfn)(const struct heap_item *a,
			     const struct heap_item *b))
{
	uint32_t rghtpos, downpos, moveto;

	while (1) {
		/* rghtpos: neighbor to the "right", inside block of NARY.
		 *          may be invalid if last in block, check nary_last()
		 * downpos: first neighbor in the "downwards" block further
		 *          away from the root
		 */
		rghtpos = pos + 1;

		/* make sure we can use the full 4G items */
		downpos = HEAP_NARY * (pos + 1);
		if (pos + 1 > ~0U / HEAP_NARY)
			/* multiplication overflowed.  ~0U is guaranteed
			 * to be an invalid index; size limit is enforced in
			 * resize()
			 */
			downpos = ~0U;

		/* only used on break */
		moveto = pos;

#define nary_last(x) (((x) & (HEAP_NARY - 1)) == HEAP_NARY - 1)
		if (downpos >= head->count
		    || cmpfn(head->array[downpos], item) >= 0) {
			/* not moving down; either at end or down is >= item */
			if (nary_last(pos) || rghtpos >= head->count
			    || cmpfn(head->array[rghtpos], item) >= 0)
				/* not moving right either - got our spot */
				break;

			moveto = rghtpos;

		/* else: downpos is valid and < item.  choose between down
		 * or right (if the latter is an option) */
		} else if (nary_last(pos) || cmpfn(head->array[rghtpos],
						   head->array[downpos]) >= 0)
			moveto = downpos;
		else
			moveto = rghtpos;
#undef nary_last

		head->array[pos] = head->array[moveto];
		head->array[pos]->index = pos;
		pos = moveto;
	}

	head->array[moveto] = item;
	item->index = moveto;

	heap_consistency_check(head, cmpfn, 0);
}

void typesafe_heap_pullup(struct heap_head *head, uint32_t pos,
		struct heap_item *item,
		int (*cmpfn)(const struct heap_item *a,
			     const struct heap_item *b))
{
	uint32_t moveto;

	while (pos != 0) {
		if ((pos & (HEAP_NARY - 1)) == 0)
			moveto = pos / HEAP_NARY - 1;
		else
			moveto = pos - 1;

		if (cmpfn(head->array[moveto], item) <= 0)
			break;

		head->array[pos] = head->array[moveto];
		head->array[pos]->index = pos;

		pos = moveto;
	}

	head->array[pos] = item;
	item->index = pos;

	heap_consistency_check(head, cmpfn, 0);
}
