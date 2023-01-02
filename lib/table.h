/*
 * Routing Table
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_TABLE_H
#define _ZEBRA_TABLE_H

#include "memory.h"
#include "hash.h"
#include "prefix.h"
#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(ROUTE_NODE);

/*
 * Forward declarations.
 */
struct route_node;
struct route_table;

/*
 * route_table_delegate_t
 *
 * Function vector that can be used by a client to customize the
 * behavior of one or more route tables.
 */
typedef const struct route_table_delegate_t_ route_table_delegate_t;

typedef struct route_node *(*route_table_create_node_func_t)(
	route_table_delegate_t *, struct route_table *);

typedef void (*route_table_destroy_node_func_t)(route_table_delegate_t *,
						struct route_table *,
						struct route_node *);

struct route_table_delegate_t_ {
	route_table_create_node_func_t create_node;
	route_table_destroy_node_func_t destroy_node;
};

PREDECL_HASH(rn_hash_node);

/* Routing table top structure. */
struct route_table {
	struct route_node *top;
	struct rn_hash_node_head hash;

	/*
	 * Delegate that performs certain functions for this table.
	 */
	route_table_delegate_t *delegate;
	void (*cleanup)(struct route_table *, struct route_node *);

	unsigned long count;

	/*
	 * User data.
	 */
	void *info;
};

/*
 * node->link is really internal to the table code and should not be
 * accessed by outside code.  We don't have any writers (yay), though some
 * readers are left to be fixed.
 *
 * rationale: we need to add a hash table in parallel, to speed up
 * exact-match lookups.
 *
 * same really applies for node->parent, though that's less of an issue.
 * table->link should be - and is - NEVER written by outside code
 */
#ifdef FRR_COMPILING_TABLE_C
#define table_rdonly(x)		x
#define table_internal(x)	x
#else
#define table_rdonly(x)		const x
#define table_internal(x)                                                      \
	const x __attribute__(                                                 \
		(deprecated("this should only be accessed by lib/table.c")))
/* table_internal is for node->link and node->lock, once we have done
 * something about remaining accesses */
#endif

/* so... the problem with this is that "const" doesn't mean "readonly".
 * It in fact may allow the compiler to optimize based on the assumption
 * that the value doesn't change.  Hence, since the only purpose of this
 * is to aid in development, don't put the "const" in release builds.
 *
 * (I haven't seen this actually break, but GCC and LLVM are getting ever
 * more aggressive in optimizing...)
 */
#ifndef DEV_BUILD
#undef table_rdonly
#define table_rdonly(x) x
#endif

/*
 * Macro that defines all fields in a route node.
 */
#define ROUTE_NODE_FIELDS                                                      \
	/* Actual prefix of this radix. */                                     \
	struct prefix p;                                                       \
                                                                               \
	/* Tree link. */                                                       \
	struct route_table *table_rdonly(table);                               \
	struct route_node *table_rdonly(parent);                               \
	struct route_node *table_rdonly(link[2]);                              \
                                                                               \
	/* Lock of this radix */                                               \
	unsigned int table_rdonly(lock);                                       \
                                                                               \
	struct rn_hash_node_item nodehash;                                     \
	/* Each node of route. */                                              \
	void *info;                                                            \


/* Each routing entry. */
struct route_node {
	ROUTE_NODE_FIELDS

#define l_left   link[0]
#define l_right  link[1]
};

typedef struct route_table_iter_t_ route_table_iter_t;

typedef enum {
	RT_ITER_STATE_INIT,
	RT_ITER_STATE_ITERATING,
	RT_ITER_STATE_PAUSED,
	RT_ITER_STATE_DONE
} route_table_iter_state_t;

/*
 * route_table_iter_t
 *
 * Structure that holds state for iterating over a route table.
 */
struct route_table_iter_t_ {

	route_table_iter_state_t state;

	/*
	 * Routing table that we are iterating over. The caller must ensure
	 * that that table outlives the iterator.
	 */
	struct route_table *table;

	/*
	 * The node that the iterator is currently on.
	 */
	struct route_node *current;

	/*
	 * The last prefix that the iterator processed before it was paused.
	 */
	struct prefix pause_prefix;
};

/* Prototypes. */
extern struct route_table *route_table_init(void);

extern struct route_table *
route_table_init_with_delegate(route_table_delegate_t *delegate);

extern route_table_delegate_t *route_table_get_default_delegate(void);

static inline void *route_table_get_info(struct route_table *table)
{
	return table->info;
}

static inline void route_table_set_info(struct route_table *table, void *d)
{
	table->info = d;
}

extern void route_table_finish(struct route_table *table);
extern struct route_node *route_top(struct route_table *table);
extern struct route_node *route_next(struct route_node *node);
extern struct route_node *route_next_until(struct route_node *node,
					   const struct route_node *limit);
extern struct route_node *route_node_get(struct route_table *table,
					 union prefixconstptr pu);
extern struct route_node *route_node_lookup(struct route_table *table,
					    union prefixconstptr pu);
extern struct route_node *route_node_lookup_maynull(struct route_table *table,
						    union prefixconstptr pu);
extern struct route_node *route_node_match(struct route_table *table,
					   union prefixconstptr pu);
extern struct route_node *route_node_match_ipv4(struct route_table *table,
						const struct in_addr *addr);
extern struct route_node *route_node_match_ipv6(struct route_table *table,
						const struct in6_addr *addr);

extern unsigned long route_table_count(struct route_table *table);

extern struct route_node *route_node_create(route_table_delegate_t *delegate,
					    struct route_table *table);
extern void route_node_delete(struct route_node *node);
extern void route_node_destroy(route_table_delegate_t *delegate,
			       struct route_table *table,
			       struct route_node *node);

extern struct route_node *route_table_get_next(struct route_table *table,
					       union prefixconstptr pu);
extern int route_table_prefix_iter_cmp(const struct prefix *p1,
				       const struct prefix *p2);

/*
 * Iterator functions.
 */
extern void route_table_iter_init(route_table_iter_t *iter,
				  struct route_table *table);
extern void route_table_iter_pause(route_table_iter_t *iter);
extern void route_table_iter_cleanup(route_table_iter_t *iter);

/*
 * Inline functions.
 */

/* Lock node. */
static inline struct route_node *route_lock_node(struct route_node *node)
{
	(*(unsigned *)&node->lock)++;
	return node;
}

/* Unlock node. */
static inline void route_unlock_node(struct route_node *node)
{
	assert(node->lock > 0);
	(*(unsigned *)&node->lock)--;

	if (node->lock == 0)
		route_node_delete(node);
}

static inline unsigned int route_node_get_lock_count(struct route_node *node)
{
	return node->lock;
}

/*
 * route_table_iter_next
 *
 * Get the next node in the tree.
 */
static inline struct route_node *route_table_iter_next(route_table_iter_t *iter)
{
	struct route_node *node;

	switch (iter->state) {

	case RT_ITER_STATE_INIT:

		/*
		 * We're just starting the iteration.
		 */
		node = route_top(iter->table);
		break;

	case RT_ITER_STATE_ITERATING:
		node = route_next(iter->current);
		break;

	case RT_ITER_STATE_PAUSED:

		/*
		 * Start with the node following pause_prefix.
		 */
		node = route_table_get_next(iter->table, &iter->pause_prefix);
		break;

	case RT_ITER_STATE_DONE:
		return NULL;

	default:
		/* Suppress uninitialized variable warning */
		node = NULL;
		assert(0);
	}

	iter->current = node;
	if (node)
		iter->state = RT_ITER_STATE_ITERATING;
	else
		iter->state = RT_ITER_STATE_DONE;

	return node;
}

/*
 * route_table_iter_is_done
 *
 * Returns true if the iteration is complete.
 */
static inline int route_table_iter_is_done(route_table_iter_t *iter)
{
	return iter->state == RT_ITER_STATE_DONE;
}

/*
 * route_table_iter_started
 *
 * Returns true if this iterator has started iterating over the tree.
 */
static inline int route_table_iter_started(route_table_iter_t *iter)
{
	return iter->state != RT_ITER_STATE_INIT;
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pRN"  (struct route_node *)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_TABLE_H */
