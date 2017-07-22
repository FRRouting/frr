/*	$OpenBSD: tree.h,v 1.14 2015/05/25 03:07:49 deraadt Exp $	*/
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_TREE_H_
#define	_SYS_TREE_H_

/*
 * This file defines data structures for different types of trees:
 * splay trees and red-black trees.
 *
 * A splay tree is a self-organizing data structure.  Every operation
 * on the tree causes a splay to happen.  The splay moves the requested
 * node to the root of the tree and partly rebalances it.
 *
 * This has the benefit that request locality causes faster lookups as
 * the requested nodes move to the top of the tree.  On the other hand,
 * every lookup causes memory writes.
 *
 * The Balance Theorem bounds the total access time for m operations
 * and n inserts on an initially empty tree as O((m + n)lg n).  The
 * amortized cost for a sequence of m accesses to a splay tree is O(lg n);
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *	- every search path from the root to a leaf consists of the
 *	  same number of black nodes,
 *	- each red node (except for the root) has a black parent,
 *	- each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

#define SPLAY_HEAD(name, type)                                                 \
	struct name {                                                          \
		struct type *sph_root; /* root of the tree */                  \
	}

#define SPLAY_INITIALIZER(root)                                                \
	{                                                                      \
		NULL                                                           \
	}

#define SPLAY_INIT(root)                                                       \
	do {                                                                   \
		(root)->sph_root = NULL;                                       \
	} while (0)

#define SPLAY_ENTRY(type)                                                      \
	struct {                                                               \
		struct type *spe_left;  /* left element */                     \
		struct type *spe_right; /* right element */                    \
	}

#define SPLAY_LEFT(elm, field)		(elm)->field.spe_left
#define SPLAY_RIGHT(elm, field)		(elm)->field.spe_right
#define SPLAY_ROOT(head)		(head)->sph_root
#define SPLAY_EMPTY(head)		(SPLAY_ROOT(head) == NULL)

/* SPLAY_ROTATE_{LEFT,RIGHT} expect that tmp hold SPLAY_{RIGHT,LEFT} */
#define SPLAY_ROTATE_RIGHT(head, tmp, field)                                   \
	do {                                                                   \
		SPLAY_LEFT((head)->sph_root, field) = SPLAY_RIGHT(tmp, field); \
		SPLAY_RIGHT(tmp, field) = (head)->sph_root;                    \
		(head)->sph_root = tmp;                                        \
	} while (0)

#define SPLAY_ROTATE_LEFT(head, tmp, field)                                    \
	do {                                                                   \
		SPLAY_RIGHT((head)->sph_root, field) = SPLAY_LEFT(tmp, field); \
		SPLAY_LEFT(tmp, field) = (head)->sph_root;                     \
		(head)->sph_root = tmp;                                        \
	} while (0)

#define SPLAY_LINKLEFT(head, tmp, field)                                       \
	do {                                                                   \
		SPLAY_LEFT(tmp, field) = (head)->sph_root;                     \
		tmp = (head)->sph_root;                                        \
		(head)->sph_root = SPLAY_LEFT((head)->sph_root, field);        \
	} while (0)

#define SPLAY_LINKRIGHT(head, tmp, field)                                      \
	do {                                                                   \
		SPLAY_RIGHT(tmp, field) = (head)->sph_root;                    \
		tmp = (head)->sph_root;                                        \
		(head)->sph_root = SPLAY_RIGHT((head)->sph_root, field);       \
	} while (0)

#define SPLAY_ASSEMBLE(head, node, left, right, field)                         \
	do {                                                                   \
		SPLAY_RIGHT(left, field) =                                     \
			SPLAY_LEFT((head)->sph_root, field);                   \
		SPLAY_LEFT(right, field) =                                     \
			SPLAY_RIGHT((head)->sph_root, field);                  \
		SPLAY_LEFT((head)->sph_root, field) =                          \
			SPLAY_RIGHT(node, field);                              \
		SPLAY_RIGHT((head)->sph_root, field) =                         \
			SPLAY_LEFT(node, field);                               \
	} while (0)

/* Generates prototypes and inline functions */

#define SPLAY_PROTOTYPE(name, type, field, cmp)                                \
	void name##_SPLAY(struct name *, struct type *);                       \
	void name##_SPLAY_MINMAX(struct name *, int);                          \
	struct type *name##_SPLAY_INSERT(struct name *, struct type *);        \
	struct type *name##_SPLAY_REMOVE(struct name *, struct type *);        \
                                                                               \
	/* Finds the node with the same key as elm */                          \
	static __inline struct type *name##_SPLAY_FIND(struct name *head,      \
						       struct type *elm)       \
	{                                                                      \
		if (SPLAY_EMPTY(head))                                         \
			return (NULL);                                         \
		name##_SPLAY(head, elm);                                       \
		if ((cmp)(elm, (head)->sph_root) == 0)                         \
			return (head->sph_root);                               \
		return (NULL);                                                 \
	}                                                                      \
                                                                               \
	static __inline struct type *name##_SPLAY_NEXT(struct name *head,      \
						       struct type *elm)       \
	{                                                                      \
		name##_SPLAY(head, elm);                                       \
		if (SPLAY_RIGHT(elm, field) != NULL) {                         \
			elm = SPLAY_RIGHT(elm, field);                         \
			while (SPLAY_LEFT(elm, field) != NULL) {               \
				elm = SPLAY_LEFT(elm, field);                  \
			}                                                      \
		} else                                                         \
			elm = NULL;                                            \
		return (elm);                                                  \
	}                                                                      \
                                                                               \
	static __inline struct type *name##_SPLAY_MIN_MAX(struct name *head,   \
							  int val)             \
	{                                                                      \
		name##_SPLAY_MINMAX(head, val);                                \
		return (SPLAY_ROOT(head));                                     \
	}

/* Main splay operation.
 * Moves node close to the key of elm to top
 */
#define SPLAY_GENERATE(name, type, field, cmp)                                 \
	struct type *name##_SPLAY_INSERT(struct name *head, struct type *elm)  \
	{                                                                      \
		if (SPLAY_EMPTY(head)) {                                       \
			SPLAY_LEFT(elm, field) = SPLAY_RIGHT(elm, field) =     \
				NULL;                                          \
		} else {                                                       \
			int __comp;                                            \
			name##_SPLAY(head, elm);                               \
			__comp = (cmp)(elm, (head)->sph_root);                 \
			if (__comp < 0) {                                      \
				SPLAY_LEFT(elm, field) =                       \
					SPLAY_LEFT((head)->sph_root, field);   \
				SPLAY_RIGHT(elm, field) = (head)->sph_root;    \
				SPLAY_LEFT((head)->sph_root, field) = NULL;    \
			} else if (__comp > 0) {                               \
				SPLAY_RIGHT(elm, field) =                      \
					SPLAY_RIGHT((head)->sph_root, field);  \
				SPLAY_LEFT(elm, field) = (head)->sph_root;     \
				SPLAY_RIGHT((head)->sph_root, field) = NULL;   \
			} else                                                 \
				return ((head)->sph_root);                     \
		}                                                              \
		(head)->sph_root = (elm);                                      \
		return (NULL);                                                 \
	}                                                                      \
                                                                               \
	struct type *name##_SPLAY_REMOVE(struct name *head, struct type *elm)  \
	{                                                                      \
		struct type *__tmp;                                            \
		if (SPLAY_EMPTY(head))                                         \
			return (NULL);                                         \
		name##_SPLAY(head, elm);                                       \
		if ((cmp)(elm, (head)->sph_root) == 0) {                       \
			if (SPLAY_LEFT((head)->sph_root, field) == NULL) {     \
				(head)->sph_root =                             \
					SPLAY_RIGHT((head)->sph_root, field);  \
			} else {                                               \
				__tmp = SPLAY_RIGHT((head)->sph_root, field);  \
				(head)->sph_root =                             \
					SPLAY_LEFT((head)->sph_root, field);   \
				name##_SPLAY(head, elm);                       \
				SPLAY_RIGHT((head)->sph_root, field) = __tmp;  \
			}                                                      \
			return (elm);                                          \
		}                                                              \
		return (NULL);                                                 \
	}                                                                      \
                                                                               \
	void name##_SPLAY(struct name *head, struct type *elm)                 \
	{                                                                      \
		struct type __node, *__left, *__right, *__tmp;                 \
		int __comp;                                                    \
                                                                               \
		SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) =     \
			NULL;                                                  \
		__left = __right = &__node;                                    \
                                                                               \
		while ((__comp = (cmp)(elm, (head)->sph_root))) {              \
			if (__comp < 0) {                                      \
				__tmp = SPLAY_LEFT((head)->sph_root, field);   \
				if (__tmp == NULL)                             \
					break;                                 \
				if ((cmp)(elm, __tmp) < 0) {                   \
					SPLAY_ROTATE_RIGHT(head, __tmp,        \
							   field);             \
					if (SPLAY_LEFT((head)->sph_root,       \
						       field)                  \
					    == NULL)                           \
						break;                         \
				}                                              \
				SPLAY_LINKLEFT(head, __right, field);          \
			} else if (__comp > 0) {                               \
				__tmp = SPLAY_RIGHT((head)->sph_root, field);  \
				if (__tmp == NULL)                             \
					break;                                 \
				if ((cmp)(elm, __tmp) > 0) {                   \
					SPLAY_ROTATE_LEFT(head, __tmp, field); \
					if (SPLAY_RIGHT((head)->sph_root,      \
							field)                 \
					    == NULL)                           \
						break;                         \
				}                                              \
				SPLAY_LINKRIGHT(head, __left, field);          \
			}                                                      \
		}                                                              \
		SPLAY_ASSEMBLE(head, &__node, __left, __right, field);         \
	}                                                                      \
                                                                               \
	/* Splay with either the minimum or the maximum element                \
	 * Used to find minimum or maximum element in tree.                    \
	 */                                                                    \
	void name##_SPLAY_MINMAX(struct name *head, int __comp)                \
	{                                                                      \
		struct type __node, *__left, *__right, *__tmp;                 \
                                                                               \
		SPLAY_LEFT(&__node, field) = SPLAY_RIGHT(&__node, field) =     \
			NULL;                                                  \
		__left = __right = &__node;                                    \
                                                                               \
		while (1) {                                                    \
			if (__comp < 0) {                                      \
				__tmp = SPLAY_LEFT((head)->sph_root, field);   \
				if (__tmp == NULL)                             \
					break;                                 \
				if (__comp < 0) {                              \
					SPLAY_ROTATE_RIGHT(head, __tmp,        \
							   field);             \
					if (SPLAY_LEFT((head)->sph_root,       \
						       field)                  \
					    == NULL)                           \
						break;                         \
				}                                              \
				SPLAY_LINKLEFT(head, __right, field);          \
			} else if (__comp > 0) {                               \
				__tmp = SPLAY_RIGHT((head)->sph_root, field);  \
				if (__tmp == NULL)                             \
					break;                                 \
				if (__comp > 0) {                              \
					SPLAY_ROTATE_LEFT(head, __tmp, field); \
					if (SPLAY_RIGHT((head)->sph_root,      \
							field)                 \
					    == NULL)                           \
						break;                         \
				}                                              \
				SPLAY_LINKRIGHT(head, __left, field);          \
			}                                                      \
		}                                                              \
		SPLAY_ASSEMBLE(head, &__node, __left, __right, field);         \
	}

#define SPLAY_NEGINF	-1
#define SPLAY_INF	1

#define SPLAY_INSERT(name, x, y)	name##_SPLAY_INSERT(x, y)
#define SPLAY_REMOVE(name, x, y)	name##_SPLAY_REMOVE(x, y)
#define SPLAY_FIND(name, x, y)		name##_SPLAY_FIND(x, y)
#define SPLAY_NEXT(name, x, y)		name##_SPLAY_NEXT(x, y)
#define SPLAY_MIN(name, x)                                                     \
	(SPLAY_EMPTY(x) ? NULL : name##_SPLAY_MIN_MAX(x, SPLAY_NEGINF))
#define SPLAY_MAX(name, x)                                                     \
	(SPLAY_EMPTY(x) ? NULL : name##_SPLAY_MIN_MAX(x, SPLAY_INF))

#define SPLAY_FOREACH(x, name, head)                                           \
	for ((x) = SPLAY_MIN(name, head); (x) != NULL;                         \
	     (x) = SPLAY_NEXT(name, head, x))

/*
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

#define RB_BLACK	0
#define RB_RED		1

struct rb_type {
	int (*t_compare)(const void *, const void *);
	void (*t_augment)(void *);
	unsigned int t_offset; /* offset of rb_entry in type */
};

struct rbt_tree {
	struct rb_entry *rbt_root;
};

struct rb_entry {
	struct rb_entry *rbt_parent;
	struct rb_entry *rbt_left;
	struct rb_entry *rbt_right;
	unsigned int rbt_color;
};

#define RB_HEAD(_name, _type)                                                  \
	struct _name {                                                         \
		struct rbt_tree rbh_root;                                      \
	}

#define RB_ENTRY(_type)	struct rb_entry

static inline void _rb_init(struct rbt_tree *rbt)
{
	rbt->rbt_root = NULL;
}

static inline int _rb_empty(struct rbt_tree *rbt)
{
	return (rbt->rbt_root == NULL);
}

void *_rb_insert(const struct rb_type *, struct rbt_tree *, void *);
void *_rb_remove(const struct rb_type *, struct rbt_tree *, void *);
void *_rb_find(const struct rb_type *, struct rbt_tree *, const void *);
void *_rb_nfind(const struct rb_type *, struct rbt_tree *, const void *);
void *_rb_root(const struct rb_type *, struct rbt_tree *);
void *_rb_min(const struct rb_type *, struct rbt_tree *);
void *_rb_max(const struct rb_type *, struct rbt_tree *);
void *_rb_next(const struct rb_type *, void *);
void *_rb_prev(const struct rb_type *, void *);
void *_rb_left(const struct rb_type *, void *);
void *_rb_right(const struct rb_type *, void *);
void *_rb_parent(const struct rb_type *, void *);
void _rb_set_left(const struct rb_type *, void *, void *);
void _rb_set_right(const struct rb_type *, void *, void *);
void _rb_set_parent(const struct rb_type *, void *, void *);
void _rb_poison(const struct rb_type *, void *, unsigned long);
int _rb_check(const struct rb_type *, void *, unsigned long);

#define RB_INITIALIZER(_head)	{ { NULL } }

#define RB_PROTOTYPE(_name, _type, _field, _cmp)                               \
	extern const struct rb_type *const _name##_RB_TYPE;                    \
                                                                               \
	__attribute__((__unused__)) static inline void _name##_RB_INIT(        \
		struct _name *head)                                            \
	{                                                                      \
		_rb_init(&head->rbh_root);                                     \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_INSERT(struct _name *head, struct _type *elm)      \
	{                                                                      \
		return _rb_insert(_name##_RB_TYPE, &head->rbh_root, elm);      \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_REMOVE(struct _name *head, struct _type *elm)      \
	{                                                                      \
		return _rb_remove(_name##_RB_TYPE, &head->rbh_root, elm);      \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_FIND(struct _name *head, const struct _type *key)  \
	{                                                                      \
		return _rb_find(_name##_RB_TYPE, &head->rbh_root, key);        \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_NFIND(struct _name *head, const struct _type *key) \
	{                                                                      \
		return _rb_nfind(_name##_RB_TYPE, &head->rbh_root, key);       \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_ROOT(struct _name *head)                           \
	{                                                                      \
		return _rb_root(_name##_RB_TYPE, &head->rbh_root);             \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline int _name##_RB_EMPTY(        \
		struct _name *head)                                            \
	{                                                                      \
		return _rb_empty(&head->rbh_root);                             \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_MIN(struct _name *head)                            \
	{                                                                      \
		return _rb_min(_name##_RB_TYPE, &head->rbh_root);              \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_MAX(struct _name *head)                            \
	{                                                                      \
		return _rb_max(_name##_RB_TYPE, &head->rbh_root);              \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_NEXT(struct _type *elm)                            \
	{                                                                      \
		return _rb_next(_name##_RB_TYPE, elm);                         \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_PREV(struct _type *elm)                            \
	{                                                                      \
		return _rb_prev(_name##_RB_TYPE, elm);                         \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_LEFT(struct _type *elm)                            \
	{                                                                      \
		return _rb_left(_name##_RB_TYPE, elm);                         \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_RIGHT(struct _type *elm)                           \
	{                                                                      \
		return _rb_right(_name##_RB_TYPE, elm);                        \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline struct _type                 \
		*_name##_RB_PARENT(struct _type *elm)                          \
	{                                                                      \
		return _rb_parent(_name##_RB_TYPE, elm);                       \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline void _name##_RB_SET_LEFT(    \
		struct _type *elm, struct _type *left)                         \
	{                                                                      \
		return _rb_set_left(_name##_RB_TYPE, elm, left);               \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline void _name##_RB_SET_RIGHT(   \
		struct _type *elm, struct _type *right)                        \
	{                                                                      \
		return _rb_set_right(_name##_RB_TYPE, elm, right);             \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline void _name##_RB_SET_PARENT(  \
		struct _type *elm, struct _type *parent)                       \
	{                                                                      \
		return _rb_set_parent(_name##_RB_TYPE, elm, parent);           \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline void _name##_RB_POISON(      \
		struct _type *elm, unsigned long poison)                       \
	{                                                                      \
		return _rb_poison(_name##_RB_TYPE, elm, poison);               \
	}                                                                      \
                                                                               \
	__attribute__((__unused__)) static inline int _name##_RB_CHECK(        \
		struct _type *elm, unsigned long poison)                       \
	{                                                                      \
		return _rb_check(_name##_RB_TYPE, elm, poison);                \
	}

#define RB_GENERATE_INTERNAL(_name, _type, _field, _cmp, _aug)                 \
	static int _name##_RB_COMPARE(const void *lptr, const void *rptr)      \
	{                                                                      \
		const struct _type *l = lptr, *r = rptr;                       \
		return _cmp(l, r);                                             \
	}                                                                      \
	static const struct rb_type _name##_RB_INFO = {                        \
		_name##_RB_COMPARE, _aug, offsetof(struct _type, _field),      \
	};                                                                     \
	const struct rb_type *const _name##_RB_TYPE = &_name##_RB_INFO;

#define RB_GENERATE_AUGMENT(_name, _type, _field, _cmp, _aug)                  \
	static void _name##_RB_AUGMENT(void *ptr)                              \
	{                                                                      \
		struct _type *p = ptr;                                         \
		return _aug(p);                                                \
	}                                                                      \
	RB_GENERATE_INTERNAL(_name, _type, _field, _cmp, _name##_RB_AUGMENT)

#define RB_GENERATE(_name, _type, _field, _cmp)                                \
	RB_GENERATE_INTERNAL(_name, _type, _field, _cmp, NULL)

#define RB_INIT(_name, _head)		_name##_RB_INIT(_head)
#define RB_INSERT(_name, _head, _elm)	_name##_RB_INSERT(_head, _elm)
#define RB_REMOVE(_name, _head, _elm)	_name##_RB_REMOVE(_head, _elm)
#define RB_FIND(_name, _head, _key)	_name##_RB_FIND(_head, _key)
#define RB_NFIND(_name, _head, _key)	_name##_RB_NFIND(_head, _key)
#define RB_ROOT(_name, _head)		_name##_RB_ROOT(_head)
#define RB_EMPTY(_name, _head)		_name##_RB_EMPTY(_head)
#define RB_MIN(_name, _head)		_name##_RB_MIN(_head)
#define RB_MAX(_name, _head)		_name##_RB_MAX(_head)
#define RB_NEXT(_name, _elm)		_name##_RB_NEXT(_elm)
#define RB_PREV(_name, _elm)		_name##_RB_PREV(_elm)
#define RB_LEFT(_name, _elm)		_name##_RB_LEFT(_elm)
#define RB_RIGHT(_name, _elm)		_name##_RB_RIGHT(_elm)
#define RB_PARENT(_name, _elm)		_name##_RB_PARENT(_elm)
#define RB_SET_LEFT(_name, _elm, _l)	_name##_RB_SET_LEFT(_elm, _l)
#define RB_SET_RIGHT(_name, _elm, _r)	_name##_RB_SET_RIGHT(_elm, _r)
#define RB_SET_PARENT(_name, _elm, _p)	_name##_RB_SET_PARENT(_elm, _p)
#define RB_POISON(_name, _elm, _p)	_name##_RB_POISON(_elm, _p)
#define RB_CHECK(_name, _elm, _p)	_name##_RB_CHECK(_elm, _p)

#define RB_FOREACH(_e, _name, _head)                                           \
	for ((_e) = RB_MIN(_name, (_head)); (_e) != NULL;                      \
	     (_e) = RB_NEXT(_name, (_e)))

#define RB_FOREACH_SAFE(_e, _name, _head, _n)                                  \
	for ((_e) = RB_MIN(_name, (_head));                                    \
	     (_e) != NULL && ((_n) = RB_NEXT(_name, (_e)), 1); (_e) = (_n))

#define RB_FOREACH_REVERSE(_e, _name, _head)                                   \
	for ((_e) = RB_MAX(_name, (_head)); (_e) != NULL;                      \
	     (_e) = RB_PREV(_name, (_e)))

#define RB_FOREACH_REVERSE_SAFE(_e, _name, _head, _n)                          \
	for ((_e) = RB_MAX(_name, (_head));                                    \
	     (_e) != NULL && ((_n) = RB_PREV(_name, (_e)), 1); (_e) = (_n))

#endif /* _SYS_TREE_H_ */
