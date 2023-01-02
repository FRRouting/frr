/*
 * agg_table - Aggregate Table Header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __AGG_TABLE_H__
#define __AGG_TABLE_H__

#include "prefix.h"
#include "table.h"

#ifdef __cplusplus
extern "C" {
#endif

struct agg_table {
	struct route_table *route_table;

	void *info;
};

struct agg_node {
	/*
	 * Caution these must be the very first fields
	 * @see agg_node_to_rnode
	 * @see agg_node_from_rnode
	 */
	ROUTE_NODE_FIELDS

	/* Aggregation. */
	void *aggregate;
};

static inline struct route_node *agg_node_to_rnode(struct agg_node *node)
{
	return (struct route_node *)node;
}

static inline struct agg_node *agg_node_from_rnode(struct route_node *node)
{
	return (struct agg_node *)node;
}

static inline struct agg_node *agg_lock_node(struct agg_node *node)
{
	return (struct agg_node *)route_lock_node(agg_node_to_rnode(node));
}

static inline void agg_unlock_node(struct agg_node *node)
{
	route_unlock_node(agg_node_to_rnode(node));
}

static inline void agg_set_table_info(struct agg_table *atable, void *data)
{
	atable->info = data;
}

static inline void *agg_get_table_info(struct agg_table *atable)
{
	return atable->info;
}

static inline struct agg_node *agg_route_top(struct agg_table *table)
{
	return agg_node_from_rnode(route_top(table->route_table));
}

static inline struct agg_node *agg_route_next(struct agg_node *node)
{
	return agg_node_from_rnode(route_next(agg_node_to_rnode(node)));
}

static inline struct agg_node *agg_node_get(struct agg_table *table,
					    const struct prefix *p)
{
	return agg_node_from_rnode(route_node_get(table->route_table, p));
}

static inline struct agg_node *
agg_node_lookup(const struct agg_table *const table, const struct prefix *p)
{
	return agg_node_from_rnode(route_node_lookup(table->route_table, p));
}

static inline struct agg_node *agg_route_next_until(struct agg_node *node,
						    struct agg_node *limit)
{
	struct route_node *rnode;

	rnode = route_next_until(agg_node_to_rnode(node),
				agg_node_to_rnode(limit));

	return agg_node_from_rnode(rnode);
}

static inline struct agg_node *agg_node_match(struct agg_table *table,
					      const struct prefix *p)
{
	return agg_node_from_rnode(route_node_match(table->route_table, p));
}

static inline struct agg_node *agg_node_parent(struct agg_node *node)
{
	struct route_node *rn = agg_node_to_rnode(node);

	return agg_node_from_rnode(rn->parent);
}

static inline struct agg_node *agg_node_left(struct agg_node *node)
{
	struct route_node *rn = agg_node_to_rnode(node);

	return agg_node_from_rnode(rn->l_left);
}

static inline struct agg_node *agg_node_right(struct agg_node *node)
{
	struct route_node *rn = agg_node_to_rnode(node);

	return agg_node_from_rnode(rn->l_right);
}

extern struct agg_table *agg_table_init(void);

static inline void agg_table_finish(struct agg_table *atable)
{
	route_table_finish(atable->route_table);
	atable->route_table = NULL;

	XFREE(MTYPE_TMP, atable);
}

static inline struct agg_node *agg_route_table_top(struct agg_node *node)
{
	return (struct agg_node *)route_top(node->table);
}

static inline struct agg_table *agg_get_table(struct agg_node *node)
{
	return (struct agg_table *)route_table_get_info(node->table);
}

static inline const struct prefix *
agg_node_get_prefix(const struct agg_node *node)
{
	return &node->p;
}

static inline unsigned int agg_node_get_lock_count(const struct agg_node *node)
{
	return node->lock;
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pRN"  (struct agg_node *)
#endif

#ifdef __cplusplus
}
#endif

#endif
