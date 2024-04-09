// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPng daemon
 * Copyright (C) 1998 Kunihiro Ishiguro
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

extern void ripng_aggregate_increment(struct agg_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement(struct agg_node *rp,
				      struct ripng_info *rinfo);
extern void ripng_aggregate_decrement_list(struct agg_node *rp,
					   struct list *list);
extern int ripng_aggregate_add(struct ripng *ripng, struct prefix *p);
extern int ripng_aggregate_delete(struct ripng *ripng, struct prefix *p);
extern void ripng_aggregate_free(struct ripng_aggregate *aggregate);

#endif /* _ZEBRA_RIPNG_ROUTE_H */
