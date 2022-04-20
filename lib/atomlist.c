/*
 * Copyright (c) 2016-2018  David Lamparter, for NetDEF, Inc.
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

#include <assert.h>

#include "atomlist.h"

void atomlist_add_head(struct atomlist_head *h, struct atomlist_item *item)
{
	atomptr_t prevval;
	atomptr_t i = atomptr_i(item);

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);

	/* updating ->last is possible here, but makes the code considerably
	 * more complicated... let's not.
	 */
	prevval = ATOMPTR_NULL;
	item->next = ATOMPTR_NULL;

	/* head-insert atomically
	 * release barrier: item + item->next writes must be completed
	 */
	while (!atomic_compare_exchange_weak_explicit(&h->first, &prevval, i,
				memory_order_release, memory_order_relaxed))
		atomic_store_explicit(&item->next, prevval,
				memory_order_relaxed);
}

void atomlist_add_tail(struct atomlist_head *h, struct atomlist_item *item)
{
	atomptr_t prevval = ATOMPTR_NULL;
	atomptr_t i = atomptr_i(item);
	atomptr_t hint;
	struct atomlist_item *prevptr;
	_Atomic atomptr_t *prev;

	item->next = ATOMPTR_NULL;

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);

	/* place new item into ->last
	 * release: item writes completed;  acquire: DD barrier on hint
	 */
	hint = atomic_exchange_explicit(&h->last, i, memory_order_acq_rel);

	while (1) {
		if (atomptr_p(hint) == NULL)
			prev = &h->first;
		else
			prev = &atomlist_itemp(hint)->next;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);
			prevptr = atomlist_itemp(prevval);
			if (prevptr == NULL)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		/* last item is being deleted - start over */
		if (atomptr_l(prevval)) {
			hint = ATOMPTR_NULL;
			continue;
		}

		/* no barrier - item->next is NULL and was so in xchg above */
		if (!atomic_compare_exchange_strong_explicit(prev, &prevval, i,
					memory_order_consume,
					memory_order_consume)) {
			hint = prevval;
			continue;
		}
		break;
	}
}

static void atomlist_del_core(struct atomlist_head *h,
			      struct atomlist_item *item,
			      _Atomic atomptr_t *hint,
			      atomptr_t next)
{
	_Atomic atomptr_t *prev = hint ? hint : &h->first, *upd;
	atomptr_t prevval, updval;
	struct atomlist_item *prevptr;

	/* drop us off "last" if needed.  no r/w to barrier. */
	prevval = atomptr_i(item);
	atomic_compare_exchange_strong_explicit(&h->last, &prevval,
			ATOMPTR_NULL,
			memory_order_relaxed, memory_order_relaxed);

	atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);

	/* the following code should be identical (except sort<>list) to
	 * atomsort_del_hint()
	 */
	while (1) {
		upd = NULL;
		updval = ATOMPTR_LOCK;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);

			/* track the beginning of a chain of deleted items
			 * this is necessary to make this lock-free; we can
			 * complete deletions started by other threads.
			 */
			if (!atomptr_l(prevval)) {
				updval = prevval;
				upd = prev;
			}

			prevptr = atomlist_itemp(prevval);
			if (prevptr == item)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		if (prevptr != item)
			/* another thread completed our deletion */
			return;

		if (!upd || atomptr_l(updval)) {
			/* failed to find non-deleted predecessor...
			 * have to try again
			 */
			prev = &h->first;
			continue;
		}

		if (!atomic_compare_exchange_strong_explicit(upd, &updval,
					next, memory_order_consume,
					memory_order_consume)) {
			/* prev doesn't point to item anymore, something
			 * was inserted.  continue at same position forward.
			 */
			continue;
		}
		break;
	}
}

void atomlist_del_hint(struct atomlist_head *h, struct atomlist_item *item,
		_Atomic atomptr_t *hint)
{
	atomptr_t next;

	/* mark ourselves in-delete - full barrier */
	next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
				memory_order_acquire);
	assert(!atomptr_l(next));	/* delete race on same item */

	atomlist_del_core(h, item, hint, next);
}

struct atomlist_item *atomlist_pop(struct atomlist_head *h)
{
	struct atomlist_item *item;
	atomptr_t next;

	/* grab head of the list - and remember it in replval for the
	 * actual delete below.  No matter what, the head of the list is
	 * where we start deleting because either it's our item, or it's
	 * some delete-marked items and then our item.
	 */
	next = atomic_load_explicit(&h->first, memory_order_consume);

	do {
		item = atomlist_itemp(next);
		if (!item)
			return NULL;

		/* try to mark deletion */
		next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
					memory_order_acquire);

	} while (atomptr_l(next));
	/* if loop is taken: delete race on same item (another pop or del)
	 * => proceed to next item
	 * if loop exited here: we have our item selected and marked
	 */
	atomlist_del_core(h, item, &h->first, next);
	return item;
}

struct atomsort_item *atomsort_add(struct atomsort_head *h,
		struct atomsort_item *item, int (*cmpfn)(
			const struct atomsort_item *,
			const struct atomsort_item *))
{
	_Atomic atomptr_t *prev;
	atomptr_t prevval;
	atomptr_t i = atomptr_i(item);
	struct atomsort_item *previtem;
	int cmpval;

	do {
		prev = &h->first;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_acquire);
			previtem = atomptr_p(prevval);

			if (!previtem || (cmpval = cmpfn(previtem, item)) > 0)
				break;
			if (cmpval == 0)
				return previtem;

			prev = &previtem->next;
		} while (1);

		if (atomptr_l(prevval))
			continue;

		item->next = prevval;
		if (atomic_compare_exchange_strong_explicit(prev, &prevval, i,
				memory_order_release, memory_order_relaxed))
			break;
	} while (1);

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);
	return NULL;
}

static void atomsort_del_core(struct atomsort_head *h,
		struct atomsort_item *item, _Atomic atomptr_t *hint,
		atomptr_t next)
{
	_Atomic atomptr_t *prev = hint ? hint : &h->first, *upd;
	atomptr_t prevval, updval;
	struct atomsort_item *prevptr;

	atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);

	/* the following code should be identical (except sort<>list) to
	 * atomlist_del_core()
	 */
	while (1) {
		upd = NULL;
		updval = ATOMPTR_LOCK;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);

			/* track the beginning of a chain of deleted items
			 * this is necessary to make this lock-free; we can
			 * complete deletions started by other threads.
			 */
			if (!atomptr_l(prevval)) {
				updval = prevval;
				upd = prev;
			}

			prevptr = atomsort_itemp(prevval);
			if (prevptr == item)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		if (prevptr != item)
			/* another thread completed our deletion */
			return;

		if (!upd || atomptr_l(updval)) {
			/* failed to find non-deleted predecessor...
			 * have to try again
			 */
			prev = &h->first;
			continue;
		}

		if (!atomic_compare_exchange_strong_explicit(upd, &updval,
					next, memory_order_relaxed,
					memory_order_relaxed)) {
			/* prev doesn't point to item anymore, something
			 * was inserted.  continue at same position forward.
			 */
			continue;
		}
		break;
	}
}

void atomsort_del_hint(struct atomsort_head *h, struct atomsort_item *item,
		_Atomic atomptr_t *hint)
{
	atomptr_t next;

	/* mark ourselves in-delete - full barrier */
	next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
				memory_order_seq_cst);
	assert(!atomptr_l(next));	/* delete race on same item */

	atomsort_del_core(h, item, hint, next);
}

struct atomsort_item *atomsort_pop(struct atomsort_head *h)
{
	struct atomsort_item *item;
	atomptr_t next;

	/* grab head of the list - and remember it in replval for the
	 * actual delete below.  No matter what, the head of the list is
	 * where we start deleting because either it's our item, or it's
	 * some delete-marked items and then our item.
	 */
	next = atomic_load_explicit(&h->first, memory_order_consume);

	do {
		item = atomsort_itemp(next);
		if (!item)
			return NULL;

		/* try to mark deletion */
		next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
					memory_order_acquire);

	} while (atomptr_l(next));
	/* if loop is taken: delete race on same item (another pop or del)
	 * => proceed to next item
	 * if loop exited here: we have our item selected and marked
	 */
	atomsort_del_core(h, item, &h->first, next);
	return item;
}
