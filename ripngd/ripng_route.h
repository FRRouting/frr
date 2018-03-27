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

extern void ripng_aggregate_increment(struct route_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement(struct route_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement_list(struct route_node *rp,
					   struct list *list);
extern int ripng_aggregate_add(struct prefix *p);
extern int ripng_aggregate_delete(struct prefix *p);
extern void ripng_aggregate_free(struct ripng_aggregate *aggregate);

#endif /* _ZEBRA_RIPNG_ROUTE_H */
