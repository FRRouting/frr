/*
 * RIPNG Table Routines
 * Copyright (C) 2017 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __RIPNGD_TABLE_H__
#define __RIPNGD_TABLE_H__

#include "table.h"

extern route_table_delegate_t ripng_delegate;

struct ripng_node
{
  ROUTE_NODE_FIELDS

  /* Aggregation. */
  void *aggregate;
};

static inline void
ripng_unlock_node (struct ripng_node *node)
{
  route_unlock_node ((struct route_node *)node);
}

static inline struct ripng_node *
ripng_table_top (struct route_table *table)
{
  return (struct ripng_node *)route_top (table);
}

static inline struct ripng_node *
ripng_route_next (struct ripng_node *node)
{
  return (struct ripng_node *)route_next ((struct route_node *)node);
}

static inline void
ripng_route_unlock_node (struct ripng_node *node)
{
  route_unlock_node ((struct route_node *)node);
}

static inline struct ripng_node *
ripng_route_lock_node (struct ripng_node *node)
{
  return (struct ripng_node *)route_lock_node ((struct route_node *)node);
}

static inline struct ripng_node *
ripng_route_node_match (struct route_table *table, struct prefix *p)
{
  return (struct ripng_node *)route_node_match (table, p);
}

static inline struct ripng_node *
ripng_route_node_get (struct route_table *table, struct prefix *p)
{
  return (struct ripng_node *)route_node_get (table, p);
}

static inline struct ripng_node *
ripng_route_node_lookup (struct route_table *table, struct prefix *p)
{
  return (struct ripng_node *)route_node_lookup (table, p);
}
static inline struct ripng_node *
ripng_route_next_until (struct ripng_node *node, struct ripng_node *until)
{
  return (struct ripng_node *)route_next_until ((struct route_node *)node,
						(struct route_node *)until);
}

#endif
