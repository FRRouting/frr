/*
 * RIPng daemon
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

#ifndef _ZEBRA_RIPNG_ROUTE_H
#define _ZEBRA_RIPNG_ROUTE_H

#include <table.h>

struct ripng_node {
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

static inline void ripng_unlock_node(struct ripng_node *node)
{
	route_unlock_node((struct route_node *)node);
}

static inline struct ripng_node *ripng_lock_node(struct ripng_node *node)
{
	return (struct ripng_node *)route_lock_node((struct route_node *)node);
}

static inline struct ripng_node *ripng_route_next(struct ripng_node *node)
{
	return (struct ripng_node *)route_next((struct route_node *)node);
}

static inline struct ripng_node *ripng_route_top(struct route_table *node)
{
	return (struct ripng_node *)route_top(node);
}

static inline struct ripng_node *
ripng_route_next_until(struct ripng_node *rn, const struct ripng_node *limit)
{
	return (struct ripng_node *)route_next_until(
		(struct route_node *)rn, (const struct route_node *)limit);
}

static inline struct ripng_node *ripng_route_node_get(struct route_table *table,
						      union prefixconstptr ptr)
{
	return (struct ripng_node *)route_node_get(table, ptr);
}

static inline struct ripng_node *
ripng_route_node_lookup(struct route_table *table, union prefixconstptr ptr)
{
	return (struct ripng_node *)route_node_lookup(table, ptr);
}

static inline struct ripng_node *
ripng_route_node_match(const struct route_table *table,
		       union prefixconstptr ptr)
{
	return (struct ripng_node *)route_node_match(table, ptr);
}

struct ripng_aggregate {
	/* Aggregate route count. */
	unsigned int count;

	/* Suppressed route count. */
	unsigned int suppress;

	/* Metric of this route.  */
	uint8_t metric;

	/* Tag field of RIPng packet.*/
	uint16_t tag;

	/* Route-map futures - this variables can be changed. */
	struct in6_addr nexthop_out;
	uint8_t metric_set;
	uint8_t metric_out;
	uint16_t tag_out;
};

extern void ripng_aggregate_increment(struct ripng_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement(struct ripng_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement_list(struct ripng_node *rp,
					   struct list *list);
extern int ripng_aggregate_add(struct prefix *p);
extern int ripng_aggregate_delete(struct prefix *p);
extern void ripng_aggregate_free(struct ripng_aggregate *aggregate);

#endif /* _ZEBRA_RIPNG_ROUTE_H */
