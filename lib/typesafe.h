// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-2019  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_TYPESAFE_H
#define _FRR_TYPESAFE_H

#ifndef _TYPESAFE_EXPAND_MACROS
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "compiler.h"
#endif /* _TYPESAFE_EXPAND_MACROS */

#ifdef __cplusplus
extern "C" {
#endif

/* generic macros for all list-like types */

/* to iterate using the const variants of the functions, append "_const" to
 * the name of the container, e.g. "frr_each (my_list, head, item)" becomes
 * "frr_each (my_list_const, head, item)"
 */

#define frr_each(prefix, head, item)                                           \
	for (item = prefix##_first(head); item;                                \
			item = prefix##_next(head, item))
#define frr_each_safe(prefix, head, item)                                      \
	for (typeof(prefix##_next_safe(head, NULL)) prefix##_safe =            \
			prefix##_next_safe(head,                               \
				(item = prefix##_first(head)));                \
		item;                                                          \
		item = prefix##_safe,                                          \
			prefix##_safe = prefix##_next_safe(head, prefix##_safe))
#define frr_each_from(prefix, head, item, from)                                \
	for (item = from, from = prefix##_next_safe(head, item);               \
		item;                                                          \
		item = from, from = prefix##_next_safe(head, from))

/* reverse direction, only supported by a few containers */

#define frr_rev_each(prefix, head, item)                                       \
	for (item = prefix##_last(head); item;                                 \
			item = prefix##_prev(head, item))
#define frr_rev_each_safe(prefix, head, item)                                  \
	for (typeof(prefix##_prev_safe(head, NULL)) prefix##_safe =            \
			prefix##_prev_safe(head,                               \
				(item = prefix##_last(head)));                 \
		item;                                                          \
		item = prefix##_safe,                                          \
			prefix##_safe = prefix##_prev_safe(head, prefix##_safe))
#define frr_rev_each_from(prefix, head, item, from)                            \
	for (item = from, from = prefix##_prev_safe(head, item);               \
		item;                                                          \
		item = from, from = prefix##_prev_safe(head, from))

/* non-const variants.  these wrappers are the same for all the types, so
 * bundle them together here.
 */
#define TYPESAFE_FIRST_NEXT(prefix, type)                                      \
macro_pure type *prefix ## _first(struct prefix##_head *h)                     \
{                                                                              \
	return (type *)prefix ## _const_first(h);                              \
}                                                                              \
macro_pure type *prefix ## _next(struct prefix##_head *h, type *item)          \
{                                                                              \
	return (type *)prefix ## _const_next(h, item);                         \
}                                                                              \
/* ... */
#define TYPESAFE_LAST_PREV(prefix, type)                                       \
macro_pure type *prefix ## _last(struct prefix##_head *h)                      \
{                                                                              \
	return (type *)prefix ## _const_last(h);                               \
}                                                                              \
macro_pure type *prefix ## _prev(struct prefix##_head *h, type *item)          \
{                                                                              \
	return (type *)prefix ## _const_prev(h, item);                         \
}                                                                              \
/* ... */
#define TYPESAFE_FIND(prefix, type)                                            \
macro_inline type *prefix ## _find(struct prefix##_head *h,                    \
				   const type *item)                           \
{                                                                              \
	return (type *)prefix ## _const_find(h, item);                         \
}                                                                              \
/* ... */
#define TYPESAFE_FIND_CMP(prefix, type)                                        \
macro_inline type *prefix ## _find_lt(struct prefix##_head *h,                 \
				      const type *item)                        \
{                                                                              \
	return (type *)prefix ## _const_find_lt(h, item);                      \
}                                                                              \
macro_inline type *prefix ## _find_gteq(struct prefix##_head *h,               \
					const type *item)                      \
{                                                                              \
	return (type *)prefix ## _const_find_gteq(h, item);                    \
}                                                                              \
/* ... */

/* *_member via find - when there is no better membership check than find() */
#define TYPESAFE_MEMBER_VIA_FIND(prefix, type)                                 \
macro_inline bool prefix ## _member(struct prefix##_head *h,                   \
				    const type *item)                          \
{                                                                              \
	return item == prefix ## _const_find(h, item);                         \
}                                                                              \
/* ... */

/* *_member via find_gteq - same for non-unique containers */
#define TYPESAFE_MEMBER_VIA_FIND_GTEQ(prefix, type, cmpfn)                     \
macro_inline bool prefix ## _member(struct prefix##_head *h,                   \
				    const type *item)                          \
{                                                                              \
	const type *iter;                                                      \
	for (iter = prefix ## _const_find_gteq(h, item); iter;                 \
	     iter = prefix ## _const_next(h, iter)) {                          \
		if (iter == item)                                              \
			return true;                                           \
		if (cmpfn(iter, item) > 0)                                     \
			break;                                                 \
	}                                                                      \
	return false;                                                          \
}                                                                              \
/* ... */

/* SWAP_ALL_SIMPLE = for containers where the items don't point back to the
 * head *AND* the head doesn't point to itself (= everything except LIST,
 * DLIST and SKIPLIST), just switch out the entire head
 */
#define TYPESAFE_SWAP_ALL_SIMPLE(prefix)                                       \
macro_inline void prefix ## _swap_all(struct prefix##_head *a,                 \
				      struct prefix##_head *b)                 \
{                                                                              \
	struct prefix##_head tmp = *a;                                         \
	*a = *b;                                                               \
	*b = tmp;                                                              \
}                                                                              \
/* ... */

/* single-linked list, unsorted/arbitrary.
 * can be used as queue with add_tail / pop
 */

/* don't use these structs directly */
struct slist_item {
	struct slist_item *next;
};

struct slist_head {
	struct slist_item *first, **last_next;
	size_t count;
};

/* this replaces NULL as the value for ->next on the last item. */
extern struct slist_item typesafe_slist_sentinel;
#define _SLIST_LAST &typesafe_slist_sentinel

static inline void typesafe_list_add(struct slist_head *head,
		struct slist_item **pos, struct slist_item *item)
{
	item->next = *pos;
	*pos = item;
	if (pos == head->last_next)
		head->last_next = &item->next;
	head->count++;
}

extern bool typesafe_list_member(const struct slist_head *head,
				 const struct slist_item *item);

/* use as:
 *
 * PREDECL_LIST(namelist);
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * DECLARE_LIST(namelist, struct name, nlitem);
 */
#define PREDECL_LIST(prefix)                                                   \
struct prefix ## _head { struct slist_head sh; };                              \
struct prefix ## _item { struct slist_item si; };                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_LIST(var) { .sh = { .last_next = &var.sh.first, }, }

#define DECLARE_LIST(prefix, type, field)                                      \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
	h->sh.first = _SLIST_LAST;                                             \
	h->sh.last_next = &h->sh.first;                                        \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _add_head(struct prefix##_head *h, type *item)     \
{                                                                              \
	typesafe_list_add(&h->sh, &h->sh.first, &item->field.si);              \
}                                                                              \
macro_inline void prefix ## _add_tail(struct prefix##_head *h, type *item)     \
{                                                                              \
	typesafe_list_add(&h->sh, h->sh.last_next, &item->field.si);           \
}                                                                              \
macro_inline void prefix ## _add_after(struct prefix##_head *h,                \
		type *after, type *item)                                       \
{                                                                              \
	struct slist_item **nextp;                                             \
	nextp = after ? &after->field.si.next : &h->sh.first;                  \
	typesafe_list_add(&h->sh, nextp, &item->field.si);                     \
}                                                                              \
/* TODO: del_hint */                                                           \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct slist_item **iter = &h->sh.first;                               \
	while (*iter != _SLIST_LAST && *iter != &item->field.si)               \
		iter = &(*iter)->next;                                         \
	if (*iter == _SLIST_LAST)                                              \
		return NULL;                                                   \
	h->sh.count--;                                                         \
	*iter = item->field.si.next;                                           \
	if (item->field.si.next == _SLIST_LAST)                                \
		h->sh.last_next = iter;                                        \
	item->field.si.next = NULL;                                            \
	return item;                                                           \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct slist_item *sitem = h->sh.first;                                \
	if (sitem == _SLIST_LAST)                                              \
		return NULL;                                                   \
	h->sh.count--;                                                         \
	h->sh.first = sitem->next;                                             \
	if (h->sh.first == _SLIST_LAST)                                        \
		h->sh.last_next = &h->sh.first;                                \
	sitem->next = NULL;                                                    \
	return container_of(sitem, type, field.si);                            \
}                                                                              \
macro_inline void prefix ## _swap_all(struct prefix##_head *a,                 \
				      struct prefix##_head *b)                 \
{                                                                              \
	struct prefix##_head tmp = *a;                                         \
	*a = *b;                                                               \
	*b = tmp;                                                              \
	if (a->sh.last_next == &b->sh.first)                                   \
		a->sh.last_next = &a->sh.first;                                \
	if (b->sh.last_next == &a->sh.first)                                   \
		b->sh.last_next = &b->sh.first;                                \
}                                                                              \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	if (h->sh.first != _SLIST_LAST)                                        \
		return container_of(h->sh.first, type, field.si);              \
	return NULL;                                                           \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)                 \
{                                                                              \
	const struct slist_item *sitem = &item->field.si;                      \
	if (sitem->next != _SLIST_LAST)                                        \
		return container_of(sitem->next, type, field.si);              \
	return NULL;                                                           \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct slist_item *sitem;                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	sitem = &item->field.si;                                               \
	if (sitem->next != _SLIST_LAST)                                        \
		return container_of(sitem->next, type, field.si);              \
	return NULL;                                                           \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->sh.count;                                                    \
}                                                                              \
macro_pure bool prefix ## _anywhere(const type *item)                          \
{                                                                              \
	return item->field.si.next != NULL;                                    \
}                                                                              \
macro_pure bool prefix ## _member(const struct prefix##_head *h,               \
				  const type *item)                            \
{                                                                              \
	return typesafe_list_member(&h->sh, &item->field.si);                  \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

/* don't use these structs directly */
struct dlist_item {
	struct dlist_item *next;
	struct dlist_item *prev;
};

struct dlist_head {
	struct dlist_item hitem;
	size_t count;
};

static inline void typesafe_dlist_add(struct dlist_head *head,
		struct dlist_item *prev, struct dlist_item *item)
{
	/* SA on clang-11 thinks this can happen, but in reality -assuming no
	 * memory corruption- it can't.  DLIST uses a "closed" ring, i.e. the
	 * termination at the end of the list is not NULL but rather a pointer
	 * back to the head.  (This eliminates special-casing the first or last
	 * item.)
	 *
	 * Sadly, can't use assert() here since the libfrr assert / xref code
	 * uses typesafe lists itself...  that said, if an assert tripped here
	 * we'd already be way past some memory corruption, so we might as
	 * well just take the SEGV.  (In the presence of corruption, we'd see
	 * random SEGVs from places that make no sense at all anyway, an
	 * assert might actually be a red herring.)
	 *
	 * ("assume()" tells the compiler to produce code as if the condition
	 * will always hold;  it doesn't have any actual effect here, it'll
	 * just SEGV out on "item->next->prev = item".)
	 */
	assume(prev->next != NULL);

	item->next = prev->next;
	item->next->prev = item;
	item->prev = prev;
	prev->next = item;
	head->count++;
}

static inline void typesafe_dlist_swap_all(struct dlist_head *a,
					   struct dlist_head *b)
{
	struct dlist_head tmp = *a;

	a->count = b->count;
	if (a->count) {
		a->hitem.next = b->hitem.next;
		a->hitem.prev = b->hitem.prev;
		a->hitem.next->prev = &a->hitem;
		a->hitem.prev->next = &a->hitem;
	} else {
		a->hitem.next = &a->hitem;
		a->hitem.prev = &a->hitem;
	}

	b->count = tmp.count;
	if (b->count) {
		b->hitem.next = tmp.hitem.next;
		b->hitem.prev = tmp.hitem.prev;
		b->hitem.next->prev = &b->hitem;
		b->hitem.prev->next = &b->hitem;
	} else {
		b->hitem.next = &b->hitem;
		b->hitem.prev = &b->hitem;
	}
}

extern bool typesafe_dlist_member(const struct dlist_head *head,
				  const struct dlist_item *item);

/* double-linked list, for fast item deletion
 */
#define PREDECL_DLIST(prefix)                                                  \
struct prefix ## _head { struct dlist_head dh; };                              \
struct prefix ## _item { struct dlist_item di; };                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_DLIST(var) { .dh = { \
	.hitem = { &var.dh.hitem, &var.dh.hitem }, }, }

#define DECLARE_DLIST(prefix, type, field)                                     \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
	h->dh.hitem.prev = &h->dh.hitem;                                       \
	h->dh.hitem.next = &h->dh.hitem;                                       \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _add_head(struct prefix##_head *h, type *item)     \
{                                                                              \
	typesafe_dlist_add(&h->dh, &h->dh.hitem, &item->field.di);             \
}                                                                              \
macro_inline void prefix ## _add_tail(struct prefix##_head *h, type *item)     \
{                                                                              \
	typesafe_dlist_add(&h->dh, h->dh.hitem.prev, &item->field.di);         \
}                                                                              \
macro_inline void prefix ## _add_after(struct prefix##_head *h,                \
		type *after, type *item)                                       \
{                                                                              \
	struct dlist_item *prev;                                               \
	prev = after ? &after->field.di : &h->dh.hitem;                        \
	typesafe_dlist_add(&h->dh, prev, &item->field.di);                     \
}                                                                              \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct dlist_item *ditem = &item->field.di;                            \
	ditem->prev->next = ditem->next;                                       \
	ditem->next->prev = ditem->prev;                                       \
	h->dh.count--;                                                         \
	ditem->prev = ditem->next = NULL;                                      \
	return item;                                                           \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct dlist_item *ditem = h->dh.hitem.next;                           \
	if (ditem == &h->dh.hitem)                                             \
		return NULL;                                                   \
	ditem->prev->next = ditem->next;                                       \
	ditem->next->prev = ditem->prev;                                       \
	h->dh.count--;                                                         \
	ditem->prev = ditem->next = NULL;                                      \
	return container_of(ditem, type, field.di);                            \
}                                                                              \
macro_inline void prefix ## _swap_all(struct prefix##_head *a,                 \
				      struct prefix##_head *b)                 \
{                                                                              \
	typesafe_dlist_swap_all(&a->dh, &b->dh);                               \
}                                                                              \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	const struct dlist_item *ditem = h->dh.hitem.next;                     \
	if (ditem == &h->dh.hitem)                                             \
		return NULL;                                                   \
	return container_of(ditem, type, field.di);                            \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)	               \
{                                                                              \
	const struct dlist_item *ditem = &item->field.di;                      \
	if (ditem->next == &h->dh.hitem)                                       \
		return NULL;                                                   \
	return container_of(ditem->next, type, field.di);                      \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure const type *prefix ## _const_last(const struct prefix##_head *h)    \
{                                                                              \
	const struct dlist_item *ditem = h->dh.hitem.prev;                     \
	if (ditem == &h->dh.hitem)                                             \
		return NULL;                                                   \
	return container_of(ditem, type, field.di);                            \
}                                                                              \
macro_pure const type *prefix ## _const_prev(const struct prefix##_head *h,    \
					     const type *item)	               \
{                                                                              \
	const struct dlist_item *ditem = &item->field.di;                      \
	if (ditem->prev == &h->dh.hitem)                                       \
		return NULL;                                                   \
	return container_of(ditem->prev, type, field.di);                      \
}                                                                              \
TYPESAFE_LAST_PREV(prefix, type)                                               \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	return prefix ## _next(h, item);                                       \
}                                                                              \
macro_pure type *prefix ## _prev_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	return prefix ## _prev(h, item);                                       \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->dh.count;                                                    \
}                                                                              \
macro_pure bool prefix ## _anywhere(const type *item)                          \
{                                                                              \
	const struct dlist_item *ditem = &item->field.di;                      \
	return ditem->next && ditem->prev;                                     \
}                                                                              \
macro_pure bool prefix ## _member(const struct prefix##_head *h,               \
				  const type *item)                            \
{                                                                              \
	return typesafe_dlist_member(&h->dh, &item->field.di);                 \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

/* note: heap currently caps out at 4G items */

#define HEAP_NARY 8U
typedef uint32_t heap_index_i;

struct heap_item {
	uint32_t index;
};

struct heap_head {
	struct heap_item **array;
	uint32_t arraysz, count;
};

#define HEAP_RESIZE_TRESH_UP(h) \
	(h->hh.count + 1 >= h->hh.arraysz)
#define HEAP_RESIZE_TRESH_DN(h) \
	(h->hh.count == 0 || \
	 h->hh.arraysz - h->hh.count > (h->hh.count + 1024) / 2)

#define PREDECL_HEAP(prefix)                                                   \
struct prefix ## _head { struct heap_head hh; };                               \
struct prefix ## _item { struct heap_item hi; };                               \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_HEAP(var)		{ }

#define DECLARE_HEAP(prefix, type, field, cmpfn)                               \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	assert(h->hh.count == 0);                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline int prefix ## __cmp(const struct heap_item *a,                    \
		const struct heap_item *b)                                     \
{                                                                              \
	return cmpfn(container_of(a, type, field.hi),                          \
			container_of(b, type, field.hi));                      \
}                                                                              \
macro_inline type *prefix ## _add(struct prefix##_head *h, type *item)         \
{                                                                              \
	if (HEAP_RESIZE_TRESH_UP(h))                                           \
		typesafe_heap_resize(&h->hh, true);                            \
	typesafe_heap_pullup(&h->hh, h->hh.count, &item->field.hi,             \
			     prefix ## __cmp);                                 \
	h->hh.count++;                                                         \
	return NULL;                                                           \
}                                                                              \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct heap_item *other;                                               \
	uint32_t index = item->field.hi.index;                                 \
	assert(h->hh.array[index] == &item->field.hi);                         \
	h->hh.count--;                                                         \
	other = h->hh.array[h->hh.count];                                      \
	if (cmpfn(container_of(other, type, field.hi), item) < 0)              \
		typesafe_heap_pullup(&h->hh, index, other, prefix ## __cmp);   \
	else                                                                   \
		typesafe_heap_pushdown(&h->hh, index, other, prefix ## __cmp); \
	if (HEAP_RESIZE_TRESH_DN(h))                                           \
		typesafe_heap_resize(&h->hh, false);                           \
	return item;                                                           \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct heap_item *hitem, *other;                                       \
	if (h->hh.count == 0)                                                  \
		return NULL;                                                   \
	hitem = h->hh.array[0];                                                \
	h->hh.count--;                                                         \
	other = h->hh.array[h->hh.count];                                      \
	typesafe_heap_pushdown(&h->hh, 0, other, prefix ## __cmp);             \
	if (HEAP_RESIZE_TRESH_DN(h))                                           \
		typesafe_heap_resize(&h->hh, false);                           \
	return container_of(hitem, type, field.hi);                            \
}                                                                              \
TYPESAFE_SWAP_ALL_SIMPLE(prefix)                                               \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	if (h->hh.count == 0)                                                  \
		return NULL;                                                   \
	return container_of(h->hh.array[0], type, field.hi);                   \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)                 \
{                                                                              \
	uint32_t idx = item->field.hi.index + 1;                               \
	if (idx >= h->hh.count)                                                \
		return NULL;                                                   \
	return container_of(h->hh.array[idx], type, field.hi);                 \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	return prefix ## _next(h, item);                                       \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->hh.count;                                                    \
}                                                                              \
macro_pure bool prefix ## _member(const struct prefix##_head *h,               \
				  const type *item)                            \
{                                                                              \
	uint32_t idx = item->field.hi.index;                                   \
	if (idx >= h->hh.count)                                                \
		return false;                                                  \
	return h->hh.array[idx] == &item->field.hi;                            \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

extern void typesafe_heap_resize(struct heap_head *head, bool grow);
extern void typesafe_heap_pushdown(struct heap_head *head, uint32_t index,
		struct heap_item *item,
		int (*cmpfn)(const struct heap_item *a,
			     const struct heap_item *b));
extern void typesafe_heap_pullup(struct heap_head *head, uint32_t index,
		struct heap_item *item,
		int (*cmpfn)(const struct heap_item *a,
			     const struct heap_item *b));

/* single-linked list, sorted.
 * can be used as priority queue with add / pop
 */

/* don't use these structs directly */
struct ssort_item {
	struct ssort_item *next;
};

struct ssort_head {
	struct ssort_item *first;
	size_t count;
};

/* use as:
 *
 * PREDECL_SORTLIST(namelist)
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * DECLARE_SORTLIST(namelist, struct name, nlitem)
 */
#define _PREDECL_SORTLIST(prefix)                                              \
struct prefix ## _head { struct ssort_head sh; };                              \
struct prefix ## _item { struct ssort_item si; };                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_SORTLIST_UNIQ(var)		{ }
#define INIT_SORTLIST_NONUNIQ(var)	{ }

#define PREDECL_SORTLIST_UNIQ(prefix)                                          \
	_PREDECL_SORTLIST(prefix)
#define PREDECL_SORTLIST_NONUNIQ(prefix)                                       \
	_PREDECL_SORTLIST(prefix)

#define _DECLARE_SORTLIST(prefix, type, field, cmpfn_nuq, cmpfn_uq)            \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline type *prefix ## _add(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct ssort_item **np = &h->sh.first;                                 \
	int c = 1;                                                             \
	while (*np && (c = cmpfn_uq(                                           \
			container_of(*np, type, field.si), item)) < 0)         \
		np = &(*np)->next;                                             \
	if (c == 0)                                                            \
		return container_of(*np, type, field.si);                      \
	item->field.si.next = *np;                                             \
	*np = &item->field.si;                                                 \
	h->sh.count++;                                                         \
	return NULL;                                                           \
}                                                                              \
macro_inline const type *prefix ## _const_find_gteq(                           \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct ssort_item *sitem = h->sh.first;                          \
	int cmpval = 0;                                                        \
	while (sitem && (cmpval = cmpfn_nuq(                                   \
			container_of(sitem, type, field.si), item)) < 0)       \
		sitem = sitem->next;                                           \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
macro_inline const type *prefix ## _const_find_lt(                             \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct ssort_item *prev = NULL, *sitem = h->sh.first;            \
	int cmpval = 0;                                                        \
	while (sitem && (cmpval = cmpfn_nuq(                                   \
			container_of(sitem, type, field.si), item)) < 0)       \
		sitem = (prev = sitem)->next;                                  \
	return container_of_null(prev, type, field.si);                        \
}                                                                              \
TYPESAFE_FIND_CMP(prefix, type)                                                \
/* TODO: del_hint */                                                           \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct ssort_item **iter = &h->sh.first;                               \
	while (*iter && *iter != &item->field.si)                              \
		iter = &(*iter)->next;                                         \
	if (!*iter)                                                            \
		return NULL;                                                   \
	h->sh.count--;                                                         \
	*iter = item->field.si.next;                                           \
	item->field.si.next = NULL;                                            \
	return item;                                                           \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct ssort_item *sitem = h->sh.first;                                \
	if (!sitem)                                                            \
		return NULL;                                                   \
	h->sh.count--;                                                         \
	h->sh.first = sitem->next;                                             \
	return container_of(sitem, type, field.si);                            \
}                                                                              \
TYPESAFE_SWAP_ALL_SIMPLE(prefix)                                               \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	return container_of_null(h->sh.first, type, field.si);                 \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)                 \
{                                                                              \
	const struct ssort_item *sitem = &item->field.si;                      \
	return container_of_null(sitem->next, type, field.si);                 \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct ssort_item *sitem;                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	sitem = &item->field.si;                                               \
	return container_of_null(sitem->next, type, field.si);                 \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->sh.count;                                                    \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define DECLARE_SORTLIST_UNIQ(prefix, type, field, cmpfn)                      \
	_DECLARE_SORTLIST(prefix, type, field, cmpfn, cmpfn);                  \
									       \
macro_inline const type *prefix ## _const_find(const struct prefix##_head *h,  \
					       const type *item)               \
{                                                                              \
	const struct ssort_item *sitem = h->sh.first;                          \
	int cmpval = 0;                                                        \
	while (sitem && (cmpval = cmpfn(                                       \
			container_of(sitem, type, field.si), item)) < 0)       \
		sitem = sitem->next;                                           \
	if (!sitem || cmpval > 0)                                              \
		return NULL;                                                   \
	return container_of(sitem, type, field.si);                            \
}                                                                              \
TYPESAFE_FIND(prefix, type)                                                    \
TYPESAFE_MEMBER_VIA_FIND(prefix, type)                                         \
MACRO_REQUIRE_SEMICOLON() /* end */

#define DECLARE_SORTLIST_NONUNIQ(prefix, type, field, cmpfn)                   \
macro_inline int _ ## prefix ## _cmp(const type *a, const type *b)             \
{                                                                              \
	int cmpval = cmpfn(a, b);                                              \
	if (cmpval)                                                            \
		return cmpval;                                                 \
	if (a < b)                                                             \
		return -1;                                                     \
	if (a > b)                                                             \
		return 1;                                                      \
	return 0;                                                              \
}                                                                              \
	_DECLARE_SORTLIST(prefix, type, field, cmpfn, _ ## prefix ## _cmp);    \
TYPESAFE_MEMBER_VIA_FIND_GTEQ(prefix, type, cmpfn)                             \
MACRO_REQUIRE_SEMICOLON() /* end */


/* hash, "sorted" by hash value
 */

/* don't use these structs directly */
struct thash_item {
	struct thash_item *next;
	uint32_t hashval;
};

struct thash_head {
	struct thash_item **entries;
	uint32_t count;

	/* tabshift can be 0 if the hash table is empty and entries is NULL.
	 * otherwise it will always be 2 or larger because it contains
	 * the shift value *plus 1*.  This is a trick to make HASH_SIZE return
	 * the correct value (with the >> 1) for tabshift == 0, without needing
	 * a conditional branch.
	 */
	uint8_t tabshift;
	uint8_t minshift, maxshift;
};

#define _HASH_SIZE(tabshift)                                                   \
	({                                                                     \
		assume((tabshift) <= 31);                                      \
		(1U << (tabshift)) >> 1;                                       \
	})
#define HASH_SIZE(head) \
	_HASH_SIZE((head).tabshift)
#define _HASH_KEY(tabshift, val)                                               \
	({                                                                     \
		assume((tabshift) >= 2 && (tabshift) <= 31);                   \
		(val) >> (33 - (tabshift));                                    \
	})
#define HASH_KEY(head, val) \
	_HASH_KEY((head).tabshift, val)
#define HASH_GROW_THRESHOLD(head) \
	((head).count >= HASH_SIZE(head))
#define HASH_SHRINK_THRESHOLD(head) \
	((head).count <= (HASH_SIZE(head) - 1) / 2)

extern void typesafe_hash_grow(struct thash_head *head);
extern void typesafe_hash_shrink(struct thash_head *head);

/* use as:
 *
 * PREDECL_HASH(namelist)
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * DECLARE_HASH(namelist, struct name, nlitem, cmpfunc, hashfunc)
 */
#define PREDECL_HASH(prefix)                                                   \
struct prefix ## _head { struct thash_head hh; };                              \
struct prefix ## _item { struct thash_item hi; };                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_HASH(var)	{ }

#define DECLARE_HASH(prefix, type, field, cmpfn, hashfn)                       \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	assert(h->hh.count == 0);                                              \
	h->hh.minshift = 0;                                                    \
	typesafe_hash_shrink(&h->hh);                                          \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline type *prefix ## _add(struct prefix##_head *h, type *item)         \
{                                                                              \
	h->hh.count++;                                                         \
	if (!h->hh.tabshift || HASH_GROW_THRESHOLD(h->hh))                     \
		typesafe_hash_grow(&h->hh);                                    \
                                                                               \
	uint32_t hval = hashfn(item), hbits = HASH_KEY(h->hh, hval);           \
	item->field.hi.hashval = hval;                                         \
	struct thash_item **np = &h->hh.entries[hbits];                        \
	while (*np && (*np)->hashval < hval)                                   \
		np = &(*np)->next;                                             \
	while (*np && (*np)->hashval == hval) {                                \
		if (cmpfn(container_of(*np, type, field.hi), item) == 0) {     \
			h->hh.count--;                                         \
			return container_of(*np, type, field.hi);              \
		}                                                              \
		np = &(*np)->next;                                             \
	}                                                                      \
	item->field.hi.next = *np;                                             \
	*np = &item->field.hi;                                                 \
	return NULL;                                                           \
}                                                                              \
macro_inline const type *prefix ## _const_find(const struct prefix##_head *h,  \
					       const type *item)               \
{                                                                              \
	if (!h->hh.tabshift)                                                   \
		return NULL;                                                   \
	uint32_t hval = hashfn(item), hbits = HASH_KEY(h->hh, hval);           \
	const struct thash_item *hitem = h->hh.entries[hbits];                 \
	while (hitem && hitem->hashval < hval)                                 \
		hitem = hitem->next;                                           \
	while (hitem && hitem->hashval == hval) {                              \
		if (!cmpfn(container_of(hitem, type, field.hi), item))         \
			return container_of(hitem, type, field.hi);            \
		hitem = hitem->next;                                           \
	}                                                                      \
	return NULL;                                                           \
}                                                                              \
TYPESAFE_FIND(prefix, type)                                                    \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	if (!h->hh.tabshift)                                                   \
		return NULL;                                                   \
	uint32_t hval = item->field.hi.hashval, hbits = HASH_KEY(h->hh, hval); \
	struct thash_item **np = &h->hh.entries[hbits];                        \
	while (*np && (*np)->hashval < hval)                                   \
		np = &(*np)->next;                                             \
	while (*np && *np != &item->field.hi && (*np)->hashval == hval)        \
		np = &(*np)->next;                                             \
	if (*np != &item->field.hi)                                            \
		return NULL;                                                   \
	*np = item->field.hi.next;                                             \
	item->field.hi.next = NULL;                                            \
	h->hh.count--;                                                         \
	if (HASH_SHRINK_THRESHOLD(h->hh))                                      \
		typesafe_hash_shrink(&h->hh);                                  \
	return item;                                                           \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	uint32_t i;                                                            \
	for (i = 0; i < HASH_SIZE(h->hh); i++)                                 \
		if (h->hh.entries[i]) {                                        \
			struct thash_item *hitem = h->hh.entries[i];           \
			h->hh.entries[i] = hitem->next;                        \
			h->hh.count--;                                         \
			hitem->next = NULL;                                    \
			if (HASH_SHRINK_THRESHOLD(h->hh))                      \
				typesafe_hash_shrink(&h->hh);                  \
			return container_of(hitem, type, field.hi);            \
		}                                                              \
	return NULL;                                                           \
}                                                                              \
TYPESAFE_SWAP_ALL_SIMPLE(prefix)                                               \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	uint32_t i;                                                            \
	for (i = 0; i < HASH_SIZE(h->hh); i++)                                 \
		if (h->hh.entries[i])                                          \
			return container_of(h->hh.entries[i], type, field.hi); \
	return NULL;                                                           \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
                                             const type *item)                 \
{                                                                              \
	const struct thash_item *hitem = &item->field.hi;                      \
	if (hitem->next)                                                       \
		return container_of(hitem->next, type, field.hi);              \
	uint32_t i = HASH_KEY(h->hh, hitem->hashval) + 1;                      \
	for (; i < HASH_SIZE(h->hh); i++)				       \
		if (h->hh.entries[i])                                          \
			return container_of(h->hh.entries[i], type, field.hi); \
	return NULL;                                                           \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	if (!item)                                                             \
		return NULL;                                                   \
	return prefix ## _next(h, item);                                       \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->hh.count;                                                    \
}                                                                              \
macro_pure bool prefix ## _member(const struct prefix##_head *h,               \
				  const type *item)                            \
{                                                                              \
	if (!h->hh.tabshift)                                                   \
		return NULL;                                                   \
	uint32_t hval = item->field.hi.hashval, hbits = HASH_KEY(h->hh, hval); \
	const struct thash_item *hitem = h->hh.entries[hbits];                 \
	while (hitem && hitem->hashval < hval)                                 \
		hitem = hitem->next;                                           \
	for (hitem = h->hh.entries[hbits]; hitem && hitem->hashval <= hval;    \
	     hitem = hitem->next)                                              \
		if (hitem == &item->field.hi)                                  \
			return true;                                           \
	return false;                                                          \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

/* skiplist, sorted.
 * can be used as priority queue with add / pop
 */

/* don't use these structs directly */
#define SKIPLIST_MAXDEPTH	16
#define SKIPLIST_EMBED		4
#define SKIPLIST_OVERFLOW	(SKIPLIST_EMBED - 1)

struct sskip_item {
	struct sskip_item *next[SKIPLIST_EMBED];
};

struct sskip_overflow {
	struct sskip_item *next[SKIPLIST_MAXDEPTH - SKIPLIST_OVERFLOW];
};

struct sskip_head {
	struct sskip_item hitem;
	struct sskip_item *overflow[SKIPLIST_MAXDEPTH - SKIPLIST_OVERFLOW];
	size_t count;
};

/* use as:
 *
 * PREDECL_SKIPLIST(namelist)
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * DECLARE_SKIPLIST(namelist, struct name, nlitem, cmpfunc)
 */
#define _PREDECL_SKIPLIST(prefix)                                              \
struct prefix ## _head { struct sskip_head sh; };                              \
struct prefix ## _item { struct sskip_item si; };                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_SKIPLIST_UNIQ(var)		{ }
#define INIT_SKIPLIST_NONUNIQ(var)	{ }

#define _DECLARE_SKIPLIST(prefix, type, field, cmpfn_nuq, cmpfn_uq)            \
                                                                               \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
	h->sh.hitem.next[SKIPLIST_OVERFLOW] = (struct sskip_item *)            \
		((uintptr_t)h->sh.overflow | 1);                               \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline type *prefix ## _add(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct sskip_item *si;                                                 \
	si = typesafe_skiplist_add(&h->sh, &item->field.si, cmpfn_uq);         \
	return container_of_null(si, type, field.si);                          \
}                                                                              \
macro_inline const type *prefix ## _const_find_gteq(                           \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct sskip_item *sitem = typesafe_skiplist_find_gteq(&h->sh,   \
			&item->field.si, cmpfn_nuq);                           \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
macro_inline const type *prefix ## _const_find_lt(                             \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct sskip_item *sitem = typesafe_skiplist_find_lt(&h->sh,     \
			&item->field.si, cmpfn_nuq);                           \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
TYPESAFE_FIND_CMP(prefix, type)                                                \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct sskip_item *sitem = typesafe_skiplist_del(&h->sh,               \
			&item->field.si, cmpfn_uq);                            \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct sskip_item *sitem = typesafe_skiplist_pop(&h->sh);              \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
macro_inline void prefix ## _swap_all(struct prefix##_head *a,                 \
				      struct prefix##_head *b)                 \
{                                                                              \
	struct prefix##_head tmp = *a;                                         \
	*a = *b;                                                               \
	*b = tmp;                                                              \
	a->sh.hitem.next[SKIPLIST_OVERFLOW] = (struct sskip_item *)            \
		((uintptr_t)a->sh.overflow | 1);                               \
	b->sh.hitem.next[SKIPLIST_OVERFLOW] = (struct sskip_item *)            \
		((uintptr_t)b->sh.overflow | 1);                               \
}                                                                              \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	const struct sskip_item *first = h->sh.hitem.next[0];                  \
	return container_of_null(first, type, field.si);                       \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)		       \
{                                                                              \
	const struct sskip_item *next = item->field.si.next[0];                \
	return container_of_null(next, type, field.si);                        \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct sskip_item *next;                                               \
	next = item ? item->field.si.next[0] : NULL;                           \
	return container_of_null(next, type, field.si);                        \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->sh.count;                                                    \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_SKIPLIST_UNIQ(prefix)                                          \
	_PREDECL_SKIPLIST(prefix)
#define DECLARE_SKIPLIST_UNIQ(prefix, type, field, cmpfn)                      \
									       \
macro_inline int prefix ## __cmp(const struct sskip_item *a,                   \
		const struct sskip_item *b)                                    \
{                                                                              \
	return cmpfn(container_of(a, type, field.si),                          \
			container_of(b, type, field.si));                      \
}                                                                              \
macro_inline const type *prefix ## _const_find(const struct prefix##_head *h,  \
					       const type *item)               \
{                                                                              \
	const struct sskip_item *sitem = typesafe_skiplist_find(&h->sh,        \
			&item->field.si, &prefix ## __cmp);                    \
	return container_of_null(sitem, type, field.si);                       \
}                                                                              \
TYPESAFE_FIND(prefix, type)                                                    \
TYPESAFE_MEMBER_VIA_FIND(prefix, type)                                         \
                                                                               \
_DECLARE_SKIPLIST(prefix, type, field,                                         \
		prefix ## __cmp, prefix ## __cmp);                             \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_SKIPLIST_NONUNIQ(prefix)                                       \
	_PREDECL_SKIPLIST(prefix)
#define DECLARE_SKIPLIST_NONUNIQ(prefix, type, field, cmpfn)                   \
                                                                               \
macro_inline int prefix ## __cmp(const struct sskip_item *a,                   \
		const struct sskip_item *b)                                    \
{                                                                              \
	return cmpfn(container_of(a, type, field.si),                          \
			container_of(b, type, field.si));                      \
}                                                                              \
macro_inline int prefix ## __cmp_uq(const struct sskip_item *a,                \
		const struct sskip_item *b)                                    \
{                                                                              \
	int cmpval = cmpfn(container_of(a, type, field.si),                    \
			container_of(b, type, field.si));                      \
	if (cmpval)                                                            \
		return cmpval;                                                 \
	if (a < b)                                                             \
		return -1;                                                     \
	if (a > b)                                                             \
		return 1;                                                      \
	return 0;                                                              \
}                                                                              \
                                                                               \
_DECLARE_SKIPLIST(prefix, type, field,                                         \
		prefix ## __cmp, prefix ## __cmp_uq);                          \
TYPESAFE_MEMBER_VIA_FIND_GTEQ(prefix, type, cmpfn)                             \
MACRO_REQUIRE_SEMICOLON() /* end */


extern struct sskip_item *typesafe_skiplist_add(struct sskip_head *head,
		struct sskip_item *item, int (*cmpfn)(
			const struct sskip_item *a,
			const struct sskip_item *b));
extern const struct sskip_item *typesafe_skiplist_find(
		const struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
			const struct sskip_item *a,
			const struct sskip_item *b));
extern const struct sskip_item *typesafe_skiplist_find_gteq(
		const struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
			const struct sskip_item *a,
			const struct sskip_item *b));
extern const struct sskip_item *typesafe_skiplist_find_lt(
		const struct sskip_head *head,
		const struct sskip_item *item, int (*cmpfn)(
			const struct sskip_item *a,
			const struct sskip_item *b));
extern struct sskip_item *typesafe_skiplist_del(
		struct sskip_head *head, struct sskip_item *item, int (*cmpfn)(
			const struct sskip_item *a,
			const struct sskip_item *b));
extern struct sskip_item *typesafe_skiplist_pop(struct sskip_head *head);

#ifdef __cplusplus
}
#endif

/* this needs to stay at the end because both files include each other.
 * the resolved order is typesafe.h before typerb.h
 */
#include "typerb.h"

#endif /* _FRR_TYPESAFE_H */
