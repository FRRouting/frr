// SPDX-License-Identifier: ISC
/*
 * The following Red-Black tree implementation is based off code with
 * original copyright:
 *
 * Copyright (c) 2016 David Gwynne <dlg@openbsd.org>
 */

#ifndef _FRR_TYPERB_H
#define _FRR_TYPERB_H

#ifndef _TYPESAFE_EXPAND_MACROS
#include <string.h>
#include "typesafe.h"
#endif /* _TYPESAFE_EXPAND_MACROS */

#ifdef __cplusplus
extern "C" {
#endif

struct typed_rb_entry {
	struct typed_rb_entry *rbt_parent;
	struct typed_rb_entry *rbt_left;
	struct typed_rb_entry *rbt_right;
	unsigned int rbt_color;
};

struct typed_rb_root {
	struct typed_rb_entry *rbt_root;
	size_t count;
};

struct typed_rb_entry *typed_rb_insert(struct typed_rb_root *rbt,
		struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
struct typed_rb_entry *typed_rb_remove(struct typed_rb_root *rbt,
				       struct typed_rb_entry *rbe);
const struct typed_rb_entry *typed_rb_find(const struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
const struct typed_rb_entry *typed_rb_find_gteq(const struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
const struct typed_rb_entry *typed_rb_find_lt(const struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
struct typed_rb_entry *typed_rb_min(const struct typed_rb_root *rbt);
struct typed_rb_entry *typed_rb_max(const struct typed_rb_root *rbt);
struct typed_rb_entry *typed_rb_prev(const struct typed_rb_entry *rbe);
struct typed_rb_entry *typed_rb_next(const struct typed_rb_entry *rbe);
bool typed_rb_member(const struct typed_rb_root *rbt,
		     const struct typed_rb_entry *rbe);

#define _PREDECL_RBTREE(prefix)                                                \
struct prefix ## _head { struct typed_rb_root rr; };                           \
struct prefix ## _item { struct typed_rb_entry re; };                          \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_RBTREE_UNIQ(var)		{ }
#define INIT_RBTREE_NONUNIQ(var)	{ }

#define _DECLARE_RBTREE(prefix, type, field, cmpfn_nuq, cmpfn_uq)              \
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
	struct typed_rb_entry *re;                                             \
	re = typed_rb_insert(&h->rr, &item->field.re, cmpfn_uq);               \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_inline const type *prefix ## _const_find_gteq(                           \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_find_gteq(&h->rr, &item->field.re, cmpfn_nuq);           \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_inline const type *prefix ## _const_find_lt(                             \
		const struct prefix##_head *h, const type *item)               \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_find_lt(&h->rr, &item->field.re, cmpfn_nuq);             \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
TYPESAFE_FIND_CMP(prefix, type)                                                \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_remove(&h->rr, &item->field.re);                         \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_min(&h->rr);                                             \
	if (!re)                                                               \
		return NULL;                                                   \
	typed_rb_remove(&h->rr, re);                                           \
	return container_of(re, type, field.re);                               \
}                                                                              \
TYPESAFE_SWAP_ALL_SIMPLE(prefix)                                               \
macro_pure const type *prefix ## _const_first(const struct prefix##_head *h)   \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_min(&h->rr);                                             \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure const type *prefix ## _const_next(const struct prefix##_head *h,    \
					     const type *item)                 \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_next(&item->field.re);                                   \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
TYPESAFE_FIRST_NEXT(prefix, type)                                              \
macro_pure const type *prefix ## _const_last(const struct prefix##_head *h)    \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_max(&h->rr);                                             \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure const type *prefix ## _const_prev(const struct prefix##_head *h,    \
					     const type *item)                 \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_prev(&item->field.re);                                   \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
TYPESAFE_LAST_PREV(prefix, type)                                               \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = item ? typed_rb_next(&item->field.re) : NULL;                     \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure type *prefix ## _prev_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = item ? typed_rb_prev(&item->field.re) : NULL;                     \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->rr.count;                                                    \
}                                                                              \
macro_pure bool prefix ## _member(const struct prefix##_head *h,               \
				  const type *item)                            \
{                                                                              \
	return typed_rb_member(&h->rr, &item->field.re);                       \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_RBTREE_UNIQ(prefix)                                            \
	_PREDECL_RBTREE(prefix)
#define DECLARE_RBTREE_UNIQ(prefix, type, field, cmpfn)                        \
                                                                               \
macro_inline int prefix ## __cmp(const struct typed_rb_entry *a,               \
		const struct typed_rb_entry *b)                                \
{                                                                              \
	return cmpfn(container_of(a, type, field.re),                          \
			container_of(b, type, field.re));                      \
}                                                                              \
macro_inline const type *prefix ## _const_find(const struct prefix##_head *h,  \
					       const type *item)               \
{                                                                              \
	const struct typed_rb_entry *re;                                       \
	re = typed_rb_find(&h->rr, &item->field.re, &prefix ## __cmp);         \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
TYPESAFE_FIND(prefix, type)                                                    \
                                                                               \
_DECLARE_RBTREE(prefix, type, field, prefix ## __cmp, prefix ## __cmp);        \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_RBTREE_NONUNIQ(prefix)                                         \
	_PREDECL_RBTREE(prefix)
#define DECLARE_RBTREE_NONUNIQ(prefix, type, field, cmpfn)                     \
                                                                               \
macro_inline int prefix ## __cmp(const struct typed_rb_entry *a,               \
		const struct typed_rb_entry *b)                                \
{                                                                              \
	return cmpfn(container_of(a, type, field.re),                          \
			container_of(b, type, field.re));                      \
}                                                                              \
macro_inline int prefix ## __cmp_uq(const struct typed_rb_entry *a,            \
		const struct typed_rb_entry *b)                                \
{                                                                              \
	int cmpval = cmpfn(container_of(a, type, field.re),                    \
			container_of(b, type, field.re));                      \
	if (cmpval)                                                            \
		return cmpval;                                                 \
	if (a < b)                                                             \
		return -1;                                                     \
	if (a > b)                                                             \
		return 1;                                                      \
	return 0;                                                              \
}                                                                              \
                                                                               \
_DECLARE_RBTREE(prefix, type, field, prefix ## __cmp, prefix ## __cmp_uq);     \
MACRO_REQUIRE_SEMICOLON() /* end */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_TYPERB_H */
