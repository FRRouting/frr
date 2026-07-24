// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2025-26  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ATOMHASH_H
#define _FRR_ATOMHASH_H

#include "lib/atomptr.h"

#define atomic _Atomic

/* comments & explanations for these datastructures are in lib/atomhash.c */

struct atomhash_item {
	atomic_atomptr_t next;

	uint32_t hashval;
};

/* lowest level of atomhash array is (1 << ATOMHASH_LOWEST_BITS) */
#define ATOMHASH_LOWEST_BITS  4
#define ATOMHASH_HIGHEST_BITS 32

struct atomhash_array;

struct atomhash_head {
	union {
		struct {
			/* TBD: combine level & count? */
			atomic_size_t level_hint;
			atomic_size_t count;
		};

		/* only used as pointer value -- indicates end of list */
		struct atomhash_item sentinel_end[1];
	};

	/* (struct atomhash_array *) */
	atomic_atomptr_t levels[ATOMHASH_HIGHEST_BITS + 1 - ATOMHASH_LOWEST_BITS];

	bool freeze_size;
};

/* _init *and* _fini require the caller to be exclusive owner of the struct.
 * for _init this tends not to be a problem, but pay attention for _fini.
 *
 * you will also trip an assertion if the hash table is not empty on _fini().
 * that's not technically necessary but if there are still items in the table
 * at that point that's a warning sign something is wrong somewhere else.
 */
void atomhash_init(struct atomhash_head *head);
void atomhash_fini(struct atomhash_head *head);

/* note as is generally a problem with lock-free datastructures, the return
 * value from any kind of get/find function is already outdated by the moment
 * it is returned.  you better have some other way to keep it valid (e.g. a
 * refcount somewhere)
 */
struct atomhash_item *atomhash_get(const struct atomhash_head *head,
				   const struct atomhash_item *ref, uint32_t ref_hashval,
				   int (*cmpfn)(const struct atomhash_item *,
						const struct atomhash_item *));

/* returns existing item if there is already one in the table one that compares
 * equal.  relying on that property is the primary "proper" way of using most
 * lock-free data structures in general.
 */
struct atomhash_item *atomhash_add(struct atomhash_head *head, struct atomhash_item *item,
				   int (*cmpfn)(const struct atomhash_item *,
						const struct atomhash_item *));

/* TODO: return value? */
void atomhash_del(struct atomhash_head *head, struct atomhash_item *item);

struct atomhash_item *atomhash_pop(struct atomhash_head *head);

const struct atomhash_item *atomhash_first(const struct atomhash_head *head);
const struct atomhash_item *atomhash_next(const struct atomhash_head *head,
					  const struct atomhash_item *item);


/* my dog ate the homework.  or in this case, clang-format ate the formatting.
 * ohwell, it's not what I would've formatted it like but it's passable.
 */
#define PREDECL_ATOMHASH(prefix)                                                                  \
	struct prefix##_head {                                                                    \
		struct atomhash_head hh;                                                          \
	};                                                                                        \
	struct prefix##_item {                                                                    \
		struct atomhash_item hi;                                                          \
	};                                                                                        \
	MACRO_REQUIRE_SEMICOLON()                                                                 \
	/* end */

#define INIT_ATOMHASH(var)                                                                        \
	{                                                                                         \
	}

#define DECLARE_ATOMHASH(prefix, type, field, cmpfn, hashfn)                                      \
	macro_inline void prefix##_init(struct prefix##_head *h)                                  \
	{                                                                                         \
		atomhash_init(&h->hh);                                                            \
	}                                                                                         \
	macro_inline void prefix##_fini(struct prefix##_head *h)                                  \
	{                                                                                         \
		atomhash_fini(&h->hh);                                                            \
	}                                                                                         \
	macro_inline int prefix##__cmp(const struct atomhash_item *a,                             \
				       const struct atomhash_item *b)                             \
	{                                                                                         \
		return cmpfn(container_of(a, type, field.hi), container_of(b, type, field.hi));   \
	}                                                                                         \
	macro_inline type *prefix##_add(struct prefix##_head *h, type *item)                      \
	{                                                                                         \
		struct atomhash_item *ret;                                                        \
		item->field.hi.hashval = hashfn(item);                                            \
		ret = atomhash_add(&h->hh, &item->field.hi, prefix##__cmp);                       \
		return container_of_null(ret, type, field.hi);                                    \
	}                                                                                         \
	macro_inline const type *prefix##_const_find(const struct prefix##_head *h,               \
						     const type *item)                            \
	{                                                                                         \
		uint32_t hashval = hashfn(item);                                                  \
		struct atomhash_item *ret = atomhash_get(&h->hh, &item->field.hi, hashval,        \
							 prefix##__cmp);                          \
		return container_of_null(ret, type, field.hi);                                    \
	}                                                                                         \
	TYPESAFE_FIND(prefix, type)                                                               \
	macro_inline type *prefix##_del(struct prefix##_head *h, type *item)                      \
	{                                                                                         \
		atomhash_del(&h->hh, &item->field.hi);                                            \
		return item;                                                                      \
	}                                                                                         \
	macro_inline type *prefix##_pop(struct prefix##_head *h)                                  \
	{                                                                                         \
		struct atomhash_item *ret = atomhash_pop(&h->hh);                                 \
		return container_of_null(ret, type, field.hi);                                    \
	}                                                                                         \
	macro_pure const type *prefix##_const_first(const struct prefix##_head *h)                \
	{                                                                                         \
		const struct atomhash_item *ret = atomhash_first(&h->hh);                         \
		return container_of_null(ret, type, field.hi);                                    \
	}                                                                                         \
	macro_pure const type *prefix##_const_next(const struct prefix##_head *h,                 \
						   const type *item)                              \
	{                                                                                         \
		const struct atomhash_item *ret = atomhash_next(&h->hh, &item->field.hi);         \
		return container_of_null(ret, type, field.hi);                                    \
	}                                                                                         \
	TYPESAFE_FIRST_NEXT(prefix, type)                                                         \
	macro_pure type *prefix##_next_safe(struct prefix##_head *h, type *item)                  \
	{                                                                                         \
		if (!item)                                                                        \
			return NULL;                                                              \
		return prefix##_next(h, item);                                                    \
	}                                                                                         \
	macro_pure size_t prefix##_count(const struct prefix##_head *h)                           \
	{                                                                                         \
		return atomic_load_explicit(&h->hh.count, memory_order_relaxed);                  \
	}                                                                                         \
	TYPESAFE_MEMBER_VIA_FIND(prefix, type)                                                    \
	MACRO_REQUIRE_SEMICOLON()                                                                 \
	/* end */

#endif /* _FRR_ATOMHASH_H */
