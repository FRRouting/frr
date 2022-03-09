/* RB-tree */

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "typerb.h"

#define RB_BLACK	0
#define RB_RED		1

#define rb_entry		typed_rb_entry
#define rbt_tree		typed_rb_root

#define RBE_LEFT(_rbe)		(_rbe)->rbt_left
#define RBE_RIGHT(_rbe)		(_rbe)->rbt_right
#define RBE_PARENT(_rbe)	(_rbe)->rbt_parent
#define RBE_COLOR(_rbe)		(_rbe)->rbt_color

#define RBH_ROOT(_rbt)		(_rbt)->rbt_root

static inline void rbe_set(struct rb_entry *rbe, struct rb_entry *parent)
{
	RBE_PARENT(rbe) = parent;
	RBE_LEFT(rbe) = RBE_RIGHT(rbe) = NULL;
	RBE_COLOR(rbe) = RB_RED;
}

static inline void rbe_set_blackred(struct rb_entry *black,
				    struct rb_entry *red)
{
	RBE_COLOR(black) = RB_BLACK;
	RBE_COLOR(red) = RB_RED;
}

static inline void rbe_rotate_left(struct rbt_tree *rbt, struct rb_entry *rbe)
{
	struct rb_entry *parent;
	struct rb_entry *tmp;

	tmp = RBE_RIGHT(rbe);
	RBE_RIGHT(rbe) = RBE_LEFT(tmp);
	if (RBE_RIGHT(rbe) != NULL)
		RBE_PARENT(RBE_LEFT(tmp)) = rbe;

	parent = RBE_PARENT(rbe);
	RBE_PARENT(tmp) = parent;
	if (parent != NULL) {
		if (rbe == RBE_LEFT(parent))
			RBE_LEFT(parent) = tmp;
		else
			RBE_RIGHT(parent) = tmp;
	} else
		RBH_ROOT(rbt) = tmp;

	RBE_LEFT(tmp) = rbe;
	RBE_PARENT(rbe) = tmp;
}

static inline void rbe_rotate_right(struct rbt_tree *rbt, struct rb_entry *rbe)
{
	struct rb_entry *parent;
	struct rb_entry *tmp;

	tmp = RBE_LEFT(rbe);
	RBE_LEFT(rbe) = RBE_RIGHT(tmp);
	if (RBE_LEFT(rbe) != NULL)
		RBE_PARENT(RBE_RIGHT(tmp)) = rbe;

	parent = RBE_PARENT(rbe);
	RBE_PARENT(tmp) = parent;
	if (parent != NULL) {
		if (rbe == RBE_LEFT(parent))
			RBE_LEFT(parent) = tmp;
		else
			RBE_RIGHT(parent) = tmp;
	} else
		RBH_ROOT(rbt) = tmp;

	RBE_RIGHT(tmp) = rbe;
	RBE_PARENT(rbe) = tmp;
}

static inline void rbe_insert_color(struct rbt_tree *rbt, struct rb_entry *rbe)
{
	struct rb_entry *parent, *gparent, *tmp;

	rbt->count++;

	while ((parent = RBE_PARENT(rbe)) != NULL
	       && RBE_COLOR(parent) == RB_RED) {
		gparent = RBE_PARENT(parent);

		if (parent == RBE_LEFT(gparent)) {
			tmp = RBE_RIGHT(gparent);
			if (tmp != NULL && RBE_COLOR(tmp) == RB_RED) {
				RBE_COLOR(tmp) = RB_BLACK;
				rbe_set_blackred(parent, gparent);
				rbe = gparent;
				continue;
			}

			if (RBE_RIGHT(parent) == rbe) {
				rbe_rotate_left(rbt, parent);
				tmp = parent;
				parent = rbe;
				rbe = tmp;
			}

			rbe_set_blackred(parent, gparent);
			rbe_rotate_right(rbt, gparent);
		} else {
			tmp = RBE_LEFT(gparent);
			if (tmp != NULL && RBE_COLOR(tmp) == RB_RED) {
				RBE_COLOR(tmp) = RB_BLACK;
				rbe_set_blackred(parent, gparent);
				rbe = gparent;
				continue;
			}

			if (RBE_LEFT(parent) == rbe) {
				rbe_rotate_right(rbt, parent);
				tmp = parent;
				parent = rbe;
				rbe = tmp;
			}

			rbe_set_blackred(parent, gparent);
			rbe_rotate_left(rbt, gparent);
		}
	}

	RBE_COLOR(RBH_ROOT(rbt)) = RB_BLACK;
}

static inline void rbe_remove_color(struct rbt_tree *rbt,
				    struct rb_entry *parent,
				    struct rb_entry *rbe)
{
	struct rb_entry *tmp;

	while ((rbe == NULL || RBE_COLOR(rbe) == RB_BLACK)
	       && rbe != RBH_ROOT(rbt) && parent) {
		if (RBE_LEFT(parent) == rbe) {
			tmp = RBE_RIGHT(parent);
			if (RBE_COLOR(tmp) == RB_RED) {
				rbe_set_blackred(tmp, parent);
				rbe_rotate_left(rbt, parent);
				tmp = RBE_RIGHT(parent);
			}
			if ((RBE_LEFT(tmp) == NULL
			     || RBE_COLOR(RBE_LEFT(tmp)) == RB_BLACK)
			    && (RBE_RIGHT(tmp) == NULL
				|| RBE_COLOR(RBE_RIGHT(tmp)) == RB_BLACK)) {
				RBE_COLOR(tmp) = RB_RED;
				rbe = parent;
				parent = RBE_PARENT(rbe);
			} else {
				if (RBE_RIGHT(tmp) == NULL
				    || RBE_COLOR(RBE_RIGHT(tmp)) == RB_BLACK) {
					struct rb_entry *oleft;

					oleft = RBE_LEFT(tmp);
					if (oleft != NULL)
						RBE_COLOR(oleft) = RB_BLACK;

					RBE_COLOR(tmp) = RB_RED;
					rbe_rotate_right(rbt, tmp);
					tmp = RBE_RIGHT(parent);
				}

				RBE_COLOR(tmp) = RBE_COLOR(parent);
				RBE_COLOR(parent) = RB_BLACK;
				if (RBE_RIGHT(tmp))
					RBE_COLOR(RBE_RIGHT(tmp)) = RB_BLACK;

				rbe_rotate_left(rbt, parent);
				rbe = RBH_ROOT(rbt);
				break;
			}
		} else {
			tmp = RBE_LEFT(parent);
			if (RBE_COLOR(tmp) == RB_RED) {
				rbe_set_blackred(tmp, parent);
				rbe_rotate_right(rbt, parent);
				tmp = RBE_LEFT(parent);
			}

			if ((RBE_LEFT(tmp) == NULL
			     || RBE_COLOR(RBE_LEFT(tmp)) == RB_BLACK)
			    && (RBE_RIGHT(tmp) == NULL
				|| RBE_COLOR(RBE_RIGHT(tmp)) == RB_BLACK)) {
				RBE_COLOR(tmp) = RB_RED;
				rbe = parent;
				parent = RBE_PARENT(rbe);
			} else {
				if (RBE_LEFT(tmp) == NULL
				    || RBE_COLOR(RBE_LEFT(tmp)) == RB_BLACK) {
					struct rb_entry *oright;

					oright = RBE_RIGHT(tmp);
					if (oright != NULL)
						RBE_COLOR(oright) = RB_BLACK;

					RBE_COLOR(tmp) = RB_RED;
					rbe_rotate_left(rbt, tmp);
					tmp = RBE_LEFT(parent);
				}

				RBE_COLOR(tmp) = RBE_COLOR(parent);
				RBE_COLOR(parent) = RB_BLACK;
				if (RBE_LEFT(tmp) != NULL)
					RBE_COLOR(RBE_LEFT(tmp)) = RB_BLACK;

				rbe_rotate_right(rbt, parent);
				rbe = RBH_ROOT(rbt);
				break;
			}
		}
	}

	if (rbe != NULL)
		RBE_COLOR(rbe) = RB_BLACK;
}

static inline struct rb_entry *
rbe_remove(struct rbt_tree *rbt, struct rb_entry *rbe)
{
	struct rb_entry *child, *parent, *old = rbe;
	unsigned int color;

	if (RBE_LEFT(rbe) == NULL)
		child = RBE_RIGHT(rbe);
	else if (RBE_RIGHT(rbe) == NULL)
		child = RBE_LEFT(rbe);
	else {
		struct rb_entry *tmp;

		rbe = RBE_RIGHT(rbe);
		while ((tmp = RBE_LEFT(rbe)) != NULL)
			rbe = tmp;

		child = RBE_RIGHT(rbe);
		parent = RBE_PARENT(rbe);
		color = RBE_COLOR(rbe);
		if (child != NULL)
			RBE_PARENT(child) = parent;
		if (parent != NULL) {
			if (RBE_LEFT(parent) == rbe)
				RBE_LEFT(parent) = child;
			else
				RBE_RIGHT(parent) = child;
		} else
			RBH_ROOT(rbt) = child;
		if (RBE_PARENT(rbe) == old)
			parent = rbe;
		*rbe = *old;

		tmp = RBE_PARENT(old);
		if (tmp != NULL) {
			if (RBE_LEFT(tmp) == old)
				RBE_LEFT(tmp) = rbe;
			else
				RBE_RIGHT(tmp) = rbe;
		} else
			RBH_ROOT(rbt) = rbe;

		RBE_PARENT(RBE_LEFT(old)) = rbe;
		if (RBE_RIGHT(old))
			RBE_PARENT(RBE_RIGHT(old)) = rbe;

		goto color;
	}

	parent = RBE_PARENT(rbe);
	color = RBE_COLOR(rbe);

	if (child != NULL)
		RBE_PARENT(child) = parent;
	if (parent != NULL) {
		if (RBE_LEFT(parent) == rbe)
			RBE_LEFT(parent) = child;
		else
			RBE_RIGHT(parent) = child;
	} else
		RBH_ROOT(rbt) = child;
color:
	if (color == RB_BLACK)
		rbe_remove_color(rbt, parent, child);

	rbt->count--;
	memset(old, 0, sizeof(*old));
	return (old);
}

struct typed_rb_entry *typed_rb_remove(struct rbt_tree *rbt,
				       struct rb_entry *rbe)
{
	return rbe_remove(rbt, rbe);
}

struct typed_rb_entry *typed_rb_insert(struct rbt_tree *rbt,
		struct rb_entry *rbe, int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b))
{
	struct rb_entry *tmp;
	struct rb_entry *parent = NULL;
	int comp = 0;

	tmp = RBH_ROOT(rbt);
	while (tmp != NULL) {
		parent = tmp;

		comp = cmpfn(rbe, tmp);
		if (comp < 0)
			tmp = RBE_LEFT(tmp);
		else if (comp > 0)
			tmp = RBE_RIGHT(tmp);
		else
			return tmp;
	}

	rbe_set(rbe, parent);

	if (parent != NULL) {
		if (comp < 0)
			RBE_LEFT(parent) = rbe;
		else
			RBE_RIGHT(parent) = rbe;
	} else
		RBH_ROOT(rbt) = rbe;

	rbe_insert_color(rbt, rbe);

	return NULL;
}

/* Finds the node with the same key as elm */
const struct rb_entry *typed_rb_find(const struct rbt_tree *rbt,
		const struct rb_entry *key,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b))
{
	const struct rb_entry *tmp = RBH_ROOT(rbt);
	int comp;

	while (tmp != NULL) {
		comp = cmpfn(key, tmp);
		if (comp < 0)
			tmp = RBE_LEFT(tmp);
		else if (comp > 0)
			tmp = RBE_RIGHT(tmp);
		else
			return tmp;
	}

	return NULL;
}

const struct rb_entry *typed_rb_find_gteq(const struct rbt_tree *rbt,
		const struct rb_entry *key,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b))
{
	const struct rb_entry *tmp = RBH_ROOT(rbt), *best = NULL;
	int comp;

	while (tmp != NULL) {
		comp = cmpfn(key, tmp);
		if (comp < 0) {
			best = tmp;
			tmp = RBE_LEFT(tmp);
		} else if (comp > 0)
			tmp = RBE_RIGHT(tmp);
		else
			return tmp;
	}

	return best;
}

const struct rb_entry *typed_rb_find_lt(const struct rbt_tree *rbt,
		const struct rb_entry *key,
		int (*cmpfn)(
			const struct typed_rb_entry *a,
			const struct typed_rb_entry *b))
{
	const struct rb_entry *tmp = RBH_ROOT(rbt), *best = NULL;
	int comp;

	while (tmp != NULL) {
		comp = cmpfn(key, tmp);
		if (comp <= 0)
			tmp = RBE_LEFT(tmp);
		else {
			best = tmp;
			tmp = RBE_RIGHT(tmp);
		}
	}

	return best;
}

struct rb_entry *typed_rb_next(const struct rb_entry *rbe_const)
{
	struct rb_entry *rbe = (struct rb_entry *)rbe_const;

	if (RBE_RIGHT(rbe) != NULL) {
		rbe = RBE_RIGHT(rbe);
		while (RBE_LEFT(rbe) != NULL)
			rbe = RBE_LEFT(rbe);
	} else {
		if (RBE_PARENT(rbe) && (rbe == RBE_LEFT(RBE_PARENT(rbe))))
			rbe = RBE_PARENT(rbe);
		else {
			while (RBE_PARENT(rbe)
			       && (rbe == RBE_RIGHT(RBE_PARENT(rbe))))
				rbe = RBE_PARENT(rbe);
			rbe = RBE_PARENT(rbe);
		}
	}

	return rbe;
}

struct rb_entry *typed_rb_prev(const struct rb_entry *rbe_const)
{
	struct rb_entry *rbe = (struct rb_entry *)rbe_const;

	if (RBE_LEFT(rbe)) {
		rbe = RBE_LEFT(rbe);
		while (RBE_RIGHT(rbe))
			rbe = RBE_RIGHT(rbe);
	} else {
		if (RBE_PARENT(rbe) && (rbe == RBE_RIGHT(RBE_PARENT(rbe))))
			rbe = RBE_PARENT(rbe);
		else {
			while (RBE_PARENT(rbe)
			       && (rbe == RBE_LEFT(RBE_PARENT(rbe))))
				rbe = RBE_PARENT(rbe);
			rbe = RBE_PARENT(rbe);
		}
	}

	return rbe;
}

struct rb_entry *typed_rb_min(const struct rbt_tree *rbt)
{
	struct rb_entry *rbe = RBH_ROOT(rbt);
	struct rb_entry *parent = NULL;

	while (rbe != NULL) {
		parent = rbe;
		rbe = RBE_LEFT(rbe);
	}

	return parent;
}

struct rb_entry *typed_rb_max(const struct rbt_tree *rbt)
{
	struct rb_entry *rbe = RBH_ROOT(rbt);
	struct rb_entry *parent = NULL;

	while (rbe != NULL) {
		parent = rbe;
		rbe = RBE_RIGHT(rbe);
	}

	return parent;
}

bool typed_rb_member(const struct typed_rb_root *rbt,
		     const struct typed_rb_entry *rbe)
{
	while (rbe->rbt_parent)
		rbe = rbe->rbt_parent;
	return rbe == rbt->rbt_root;
}
