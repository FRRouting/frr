// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-2019  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ATOMLIST_H
#define _FRR_ATOMLIST_H

#include "typesafe.h"
#ifndef _TYPESAFE_EXPAND_MACROS
#include "frratomic.h"
#endif /* _TYPESAFE_EXPAND_MACROS */

#ifdef __cplusplus
extern "C" {
#endif

/* pointer with lock/deleted/invalid bit in lowest bit
 *
 * for atomlist/atomsort, "locked" means "this pointer can't be updated, the
 * item is being deleted".  it is permissible to assume the item will indeed
 * be deleted (as there are no replace/etc. ops in this).
 *
 * in general, lowest 2/3 bits on 32/64bit architectures are available for
 * uses like this; the only thing that will really break this is putting an
 * atomlist_item in a struct with "packed" attribute.  (it'll break
 * immediately and consistently.) -- don't do that.
 *
 * ATOMPTR_USER is currently unused (and available for atomic hash or skiplist
 * implementations.)
 */

/* atomic_atomptr_t may look a bit odd, it's for the sake of C++ compat */
typedef uintptr_t		atomptr_t;
typedef atomic_uintptr_t	atomic_atomptr_t;

#define ATOMPTR_MASK (UINTPTR_MAX - 3)
#define ATOMPTR_LOCK (1)
#define ATOMPTR_USER (2)
#define ATOMPTR_NULL (0)

static inline atomptr_t atomptr_i(void *val)
{
	atomptr_t atomval = (atomptr_t)val;

	assert(!(atomval & ATOMPTR_LOCK));
	return atomval;
}
static inline void *atomptr_p(atomptr_t val)
{
	return (void *)(val & ATOMPTR_MASK);
}
static inline bool atomptr_l(atomptr_t val)
{
	return (bool)(val & ATOMPTR_LOCK);
}
static inline bool atomptr_u(atomptr_t val)
{
	return (bool)(val & ATOMPTR_USER);
}


/* the problem with, find(), find_gteq() and find_lt() on atomic lists is that
 * they're neither an "acquire" nor a "release" operation;  the element that
 * was found is still on the list and doesn't change ownership.  Therefore,
 * an atomic transition in ownership state can't be implemented.
 *
 * Contrast this with add() or pop(): both function calls atomically transfer
 * ownership of an item to or from the list, which makes them "acquire" /
 * "release" operations.
 *
 * What can be implemented atomically is a "find_pop()", i.e. try to locate an
 * item and atomically try to remove it if found.  It's not currently
 * implemented but can be added when needed.
 *
 * Either way - for find(), generally speaking, if you need to use find() on
 * a list then the whole thing probably isn't well-suited to atomic
 * implementation and you'll need to have extra locks around to make it work
 * correctly.
 */
#ifdef WNO_ATOMLIST_UNSAFE_FIND
# define atomic_find_warn
#else
# define atomic_find_warn __attribute__((_DEPRECATED( \
	"WARNING: find() on atomic lists cannot be atomic by principle; " \
	"check code to make sure usage pattern is OK and if it is, use " \
	"#define WNO_ATOMLIST_UNSAFE_FIND")))
#endif


/* single-linked list, unsorted/arbitrary.
 * can be used as queue with add_tail / pop
 *
 * all operations are lock-free, but not necessarily wait-free.  this means
 * that there is no state where the system as a whole stops making process,
 * but it *is* possible that a *particular* thread is delayed by some time.
 *
 * the only way for this to happen is for other threads to continuously make
 * updates.  an inactive / blocked / deadlocked other thread cannot cause such
 * delays, and to cause such delays a thread must be heavily hitting the list -
 * it's a rather theoretical concern.
 */

/* don't use these structs directly */
struct atomlist_item {
	atomic_uintptr_t next;
};
#define atomlist_itemp(val) ((struct atomlist_item *)atomptr_p(val))

struct atomlist_head {
	atomic_uintptr_t first, last;
	atomic_size_t count;
};

/* use as:
 *
 * PREDECL_ATOMLIST(namelist);
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * DECLARE_ATOMLIST(namelist, struct name, nlitem);
 */
#define PREDECL_ATOMLIST(prefix)                                               \
struct prefix ## _head { struct atomlist_head ah; };                           \
struct prefix ## _item { struct atomlist_item ai; };                           \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_ATOMLIST(var) { }

#define DECLARE_ATOMLIST(prefix, type, field)                                  \
macro_inline void prefix ## _add_head(struct prefix##_head *h, type *item)     \
{	atomlist_add_head(&h->ah, &item->field.ai); }                          \
macro_inline void prefix ## _add_tail(struct prefix##_head *h, type *item)     \
{	atomlist_add_tail(&h->ah, &item->field.ai); }                          \
macro_inline void prefix ## _del_hint(struct prefix##_head *h, type *item,     \
		atomic_atomptr_t *hint)                                        \
{	atomlist_del_hint(&h->ah, &item->field.ai, hint); }                    \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{	atomlist_del_hint(&h->ah, &item->field.ai, NULL);                      \
	/* TODO: Return NULL if not found */                                   \
	return item; }                                                         \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{	char *p = (char *)atomlist_pop(&h->ah);                                \
	return p ? (type *)(p - offsetof(type, field)) : NULL; }               \
macro_inline type *prefix ## _first(struct prefix##_head *h)                   \
{	char *p = atomptr_p(atomic_load_explicit(&h->ah.first,                 \
				memory_order_acquire));                        \
	return p ? (type *)(p - offsetof(type, field)) : NULL; }               \
macro_inline type *prefix ## _next(struct prefix##_head *h, type *item)        \
{	char *p = atomptr_p(atomic_load_explicit(&item->field.ai.next,         \
				memory_order_acquire));                        \
	return p ? (type *)(p - offsetof(type, field)) : NULL; }               \
macro_inline type *prefix ## _next_safe(struct prefix##_head *h, type *item)   \
{	return item ? prefix##_next(h, item) : NULL; }                         \
macro_inline size_t prefix ## _count(struct prefix##_head *h)                  \
{	return atomic_load_explicit(&h->ah.count, memory_order_relaxed); }     \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	assert(prefix ## _count(h) == 0);                                      \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

/* add_head:
 * - contention on ->first pointer
 * - return implies completion
 */
void atomlist_add_head(struct atomlist_head *h, struct atomlist_item *item);

/* add_tail:
 * - concurrent add_tail can cause wait but has progress guarantee
 * - return does NOT imply completion.  completion is only guaranteed after
 *   all other add_tail operations that started before this add_tail have
 *   completed as well.
 */
void atomlist_add_tail(struct atomlist_head *h, struct atomlist_item *item);

/* del/del_hint:
 *
 * OWNER MUST HOLD REFERENCE ON ITEM TO BE DELETED, ENSURING NO OTHER THREAD
 * WILL TRY TO DELETE THE SAME ITEM.  DELETING INCLUDES pop().
 *
 * as with all deletions, threads that started reading earlier may still hold
 * pointers to the deleted item.  completion is however guaranteed for all
 * reads starting later.
 */
void atomlist_del_hint(struct atomlist_head *h, struct atomlist_item *item,
		atomic_atomptr_t *hint);

/* pop:
 *
 * as with all deletions, threads that started reading earlier may still hold
 * pointers to the deleted item.  completion is however guaranteed for all
 * reads starting later.
 */
struct atomlist_item *atomlist_pop(struct atomlist_head *h);



struct atomsort_item {
	atomic_atomptr_t next;
};
#define atomsort_itemp(val) ((struct atomsort_item *)atomptr_p(val))

struct atomsort_head {
	atomic_atomptr_t first;
	atomic_size_t count;
};

#define _PREDECL_ATOMSORT(prefix)                                              \
struct prefix ## _head { struct atomsort_head ah; };                           \
struct prefix ## _item { struct atomsort_item ai; };                           \
MACRO_REQUIRE_SEMICOLON() /* end */

#define INIT_ATOMSORT_UNIQ(var)		{ }
#define INIT_ATOMSORT_NONUNIQ(var)	{ }

#define _DECLARE_ATOMSORT(prefix, type, field, cmpfn_nuq, cmpfn_uq)            \
macro_inline void prefix ## _init(struct prefix##_head *h)                     \
{                                                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline void prefix ## _fini(struct prefix##_head *h)                     \
{                                                                              \
	assert(h->ah.count == 0);                                              \
	memset(h, 0, sizeof(*h));                                              \
}                                                                              \
macro_inline type *prefix ## _add(struct prefix##_head *h, type *item)         \
{                                                                              \
	struct atomsort_item *p;                                               \
	p = atomsort_add(&h->ah, &item->field.ai, cmpfn_uq);                   \
	return container_of_null(p, type, field.ai);                           \
}                                                                              \
macro_inline type *prefix ## _first(struct prefix##_head *h)                   \
{                                                                              \
	struct atomsort_item *p;                                               \
	p = atomptr_p(atomic_load_explicit(&h->ah.first,                       \
				memory_order_acquire));                        \
	return container_of_null(p, type, field.ai);                           \
}                                                                              \
macro_inline type *prefix ## _next(struct prefix##_head *h, type *item)        \
{                                                                              \
	struct atomsort_item *p;                                               \
	p = atomptr_p(atomic_load_explicit(&item->field.ai.next,               \
				memory_order_acquire));                        \
	return container_of_null(p, type, field.ai);                           \
}                                                                              \
macro_inline type *prefix ## _next_safe(struct prefix##_head *h, type *item)   \
{                                                                              \
	return item ? prefix##_next(h, item) : NULL;                           \
}                                                                              \
atomic_find_warn                                                               \
macro_inline type *prefix ## _find_gteq(struct prefix##_head *h,               \
		const type *item)                                              \
{                                                                              \
	type *p = prefix ## _first(h);                                         \
	while (p && cmpfn_nuq(&p->field.ai, &item->field.ai) < 0)              \
		p = prefix ## _next(h, p);                                     \
	return p;                                                              \
}                                                                              \
atomic_find_warn                                                               \
macro_inline type *prefix ## _find_lt(struct prefix##_head *h,                 \
		const type *item)                                              \
{                                                                              \
	type *p = prefix ## _first(h), *prev = NULL;                           \
	while (p && cmpfn_nuq(&p->field.ai, &item->field.ai) < 0)              \
		p = prefix ## _next(h, (prev = p));                            \
	return prev;                                                           \
}                                                                              \
macro_inline void prefix ## _del_hint(struct prefix##_head *h, type *item,     \
		atomic_atomptr_t *hint)                                        \
{                                                                              \
	atomsort_del_hint(&h->ah, &item->field.ai, hint);                      \
}                                                                              \
macro_inline type *prefix ## _del(struct prefix##_head *h, type *item)         \
{                                                                              \
	atomsort_del_hint(&h->ah, &item->field.ai, NULL);                      \
	/* TODO: Return NULL if not found */                                   \
	return item;                                                           \
}                                                                              \
macro_inline size_t prefix ## _count(struct prefix##_head *h)                  \
{                                                                              \
	return atomic_load_explicit(&h->ah.count, memory_order_relaxed);       \
}                                                                              \
macro_inline type *prefix ## _pop(struct prefix##_head *h)                     \
{                                                                              \
	struct atomsort_item *p = atomsort_pop(&h->ah);                        \
	return p ? container_of(p, type, field.ai) : NULL;                     \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_ATOMSORT_UNIQ(prefix)                                          \
	_PREDECL_ATOMSORT(prefix)
#define DECLARE_ATOMSORT_UNIQ(prefix, type, field, cmpfn)                      \
                                                                               \
macro_inline int prefix ## __cmp(const struct atomsort_item *a,                \
		const struct atomsort_item *b)                                 \
{                                                                              \
	return cmpfn(container_of(a, type, field.ai),                          \
			container_of(b, type, field.ai));                      \
}                                                                              \
                                                                               \
_DECLARE_ATOMSORT(prefix, type, field,                                         \
		prefix ## __cmp, prefix ## __cmp);                             \
                                                                               \
atomic_find_warn                                                               \
macro_inline type *prefix ## _find(struct prefix##_head *h, const type *item)  \
{                                                                              \
	type *p = prefix ## _first(h);                                         \
	int cmpval = 0;                                                        \
	while (p && (cmpval = cmpfn(p, item)) < 0)                             \
		p = prefix ## _next(h, p);                                     \
	if (!p || cmpval > 0)                                                  \
		return NULL;                                                   \
	return p;                                                              \
}                                                                              \
MACRO_REQUIRE_SEMICOLON() /* end */

#define PREDECL_ATOMSORT_NONUNIQ(prefix)                                       \
	_PREDECL_ATOMSORT(prefix)
#define DECLARE_ATOMSORT_NONUNIQ(prefix, type, field, cmpfn)                   \
                                                                               \
macro_inline int prefix ## __cmp(const struct atomsort_item *a,                \
		const struct atomsort_item *b)                                 \
{                                                                              \
	return cmpfn(container_of(a, type, field.ai),                          \
			container_of(b, type, field.ai));                      \
}                                                                              \
macro_inline int prefix ## __cmp_uq(const struct atomsort_item *a,             \
		const struct atomsort_item *b)                                 \
{                                                                              \
	int cmpval = cmpfn(container_of(a, type, field.ai),                    \
			container_of(b, type, field.ai));                      \
	if (cmpval)                                                            \
		return cmpval;                                                 \
	if (a < b)                                                             \
		return -1;                                                     \
	if (a > b)                                                             \
		return 1;                                                      \
	return 0;                                                              \
}                                                                              \
                                                                               \
_DECLARE_ATOMSORT(prefix, type, field,                                         \
		prefix ## __cmp, prefix ## __cmp_uq);                          \
MACRO_REQUIRE_SEMICOLON() /* end */

struct atomsort_item *atomsort_add(struct atomsort_head *h,
		struct atomsort_item *item, int (*cmpfn)(
			const struct atomsort_item *,
			const struct atomsort_item *));

void atomsort_del_hint(struct atomsort_head *h,
		struct atomsort_item *item, atomic_atomptr_t *hint);

struct atomsort_item *atomsort_pop(struct atomsort_head *h);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ATOMLIST_H */
