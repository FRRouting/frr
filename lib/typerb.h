/*
 * The following Red-Black tree implementation is based off code with
 * original copyright:
 *
 * Copyright (c) 2016 David Gwynne <dlg@openbsd.org>
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

#ifndef _FRR_TYPERB_H
#define _FRR_TYPERB_H

#include "typesafe.h"

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
struct typed_rb_entry *typed_rb_find(struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
struct typed_rb_entry *typed_rb_find_gteq(struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
struct typed_rb_entry *typed_rb_find_lt(struct typed_rb_root *rbt,
		const struct typed_rb_entry *rbe,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b));
struct typed_rb_entry *typed_rb_min(struct typed_rb_root *rbt);
struct typed_rb_entry *typed_rb_next(struct typed_rb_entry *rbe);

#define _PREDECL_RBTREE(prefix)                                                \
struct prefix ## _head { struct typed_rb_root rr; };                           \
struct prefix ## _item { struct typed_rb_entry re; };

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
macro_inline type *prefix ## _find_gteq(struct prefix##_head *h,               \
		const type *item)                                              \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_find_gteq(&h->rr, &item->field.re, cmpfn_nuq);           \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_inline type *prefix ## _find_lt(struct prefix##_head *h,                 \
		const type *item)                                              \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_find_lt(&h->rr, &item->field.re, cmpfn_nuq);             \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
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
macro_pure type *prefix ## _first(struct prefix##_head *h)                     \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_min(&h->rr);                                             \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure type *prefix ## _next(struct prefix##_head *h, type *item)          \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_next(&item->field.re);                                   \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure type *prefix ## _next_safe(struct prefix##_head *h, type *item)     \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = item ? typed_rb_next(&item->field.re) : NULL;                     \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
macro_pure size_t prefix ## _count(const struct prefix##_head *h)              \
{                                                                              \
	return h->rr.count;                                                    \
}                                                                              \
/* ... */

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
macro_inline type *prefix ## _find(struct prefix##_head *h, const type *item)  \
{                                                                              \
	struct typed_rb_entry *re;                                             \
	re = typed_rb_find(&h->rr, &item->field.re, &prefix ## __cmp);         \
	return container_of_null(re, type, field.re);                          \
}                                                                              \
                                                                               \
_DECLARE_RBTREE(prefix, type, field, prefix ## __cmp, prefix ## __cmp)         \
/* ... */

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
_DECLARE_RBTREE(prefix, type, field, prefix ## __cmp, prefix ## __cmp_uq)      \
/* ... */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_TYPERB_H */
