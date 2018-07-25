/*
 * rfapi-table Header
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
#ifndef __RFAPI_TABLE_H__
#define __RFAPI_TABLE_H__
#include <table.h>

struct rfapi_node {
	/*
	 * CAUTION
	 *
	 * These fields must be the very first fields in this structure.
	 *
	 * @see bgp_node_to_rnode
	 * @see bgp_node_from_rnode
	 */
	ROUTE_NODE_FIELDS

	void *aggregate;
};


static inline struct rfapi_node *rfapi_lock_node(struct rfapi_node *node)
{
	return (struct rfapi_node *)route_lock_node((struct route_node *)node);
}

static inline void rfapi_unlock_node(struct rfapi_node *node)
{
	route_unlock_node((struct route_node *)node);
}

static inline struct rfapi_node *rfapi_route_next(struct rfapi_node *node)
{
	return (struct rfapi_node *)route_next((struct route_node *)node);
}

static inline struct rfapi_node *rfapi_route_top(struct route_table *node)
{
	return (struct rfapi_node *)route_top(node);
}

static inline struct rfapi_node *rfapi_route_node_get(struct route_table *table,
						      union prefixconstptr ptr)
{
	return (struct rfapi_node *)route_node_get(table, ptr);
}

static inline struct rfapi_node *
rfapi_route_node_lookup(struct route_table *table, union prefixconstptr ptr)
{
	return (struct rfapi_node *)route_node_lookup(table, ptr);
}

static inline struct rfapi_node *
rfapi_route_node_match(const struct route_table *table,
		       union prefixconstptr ptr)
{
	return (struct rfapi_node *)route_node_match(table, ptr);
}
#endif
