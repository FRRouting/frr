// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPng routes function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "prefix.h"
#include "agg_table.h"
#include "memory.h"
#include "if.h"
#include "vty.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"

DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_AGGREGATE, "RIPng aggregate");

static struct ripng_aggregate *ripng_aggregate_new(void)
{
	struct ripng_aggregate *new;

	new = XCALLOC(MTYPE_RIPNG_AGGREGATE, sizeof(struct ripng_aggregate));
	return new;
}

void ripng_aggregate_free(struct ripng_aggregate *aggregate)
{
	XFREE(MTYPE_RIPNG_AGGREGATE, aggregate);
}

/* Aggregate count increment check. */
void ripng_aggregate_increment(struct agg_node *child, struct ripng_info *rinfo)
{
	struct agg_node *np;
	struct ripng_aggregate *aggregate;

	for (np = child; np; np = agg_node_parent(np))
		if ((aggregate = np->aggregate) != NULL) {
			aggregate->count++;
			rinfo->suppress++;
		}
}

/* Aggregate count decrement check. */
void ripng_aggregate_decrement(struct agg_node *child, struct ripng_info *rinfo)
{
	struct agg_node *np;
	struct ripng_aggregate *aggregate;

	for (np = child; np; np = agg_node_parent(np))
		if ((aggregate = np->aggregate) != NULL) {
			aggregate->count--;
			rinfo->suppress--;
		}
}

/* Aggregate count decrement check for a list. */
void ripng_aggregate_decrement_list(struct agg_node *child, struct list *list)
{
	struct agg_node *np;
	struct ripng_aggregate *aggregate;
	struct ripng_info *rinfo = NULL;
	struct listnode *node = NULL;

	for (np = child; np; np = agg_node_parent(np))
		if ((aggregate = np->aggregate) != NULL)
			aggregate->count -= listcount(list);

	for (ALL_LIST_ELEMENTS_RO(list, node, rinfo))
		rinfo->suppress--;
}

/* RIPng routes treatment. */
int ripng_aggregate_add(struct ripng *ripng, struct prefix *p)
{
	struct agg_node *top;
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_aggregate *aggregate;
	struct ripng_aggregate *sub;
	struct list *list = NULL;
	struct listnode *node = NULL;

	/* Get top node for aggregation. */
	top = agg_node_get(ripng->table, p);

	/* Allocate new aggregate. */
	aggregate = ripng_aggregate_new();
	aggregate->metric = 1;

	top->aggregate = aggregate;

	/* Suppress routes match to the aggregate. */
	for (rp = agg_lock_node(top); rp; rp = agg_route_next_until(rp, top)) {
		/* Suppress normal route. */
		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, node, rinfo)) {
				aggregate->count++;
				rinfo->suppress++;
			}
		/* Suppress aggregate route.  This may not need. */
		if (rp != top && (sub = rp->aggregate) != NULL) {
			aggregate->count++;
			sub->suppress++;
		}
	}

	return 0;
}

/* Delete RIPng static route. */
int ripng_aggregate_delete(struct ripng *ripng, struct prefix *p)
{
	struct agg_node *top;
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_aggregate *aggregate;
	struct ripng_aggregate *sub;
	struct list *list = NULL;
	struct listnode *node = NULL;

	/* Get top node for aggregation. */
	top = agg_node_get(ripng->table, p);

	/* Allocate new aggregate. */
	aggregate = top->aggregate;

	/* Suppress routes match to the aggregate. */
	for (rp = agg_lock_node(top); rp; rp = agg_route_next_until(rp, top)) {
		/* Suppress normal route. */
		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, node, rinfo)) {
				aggregate->count--;
				rinfo->suppress--;
			}

		if (rp != top && (sub = rp->aggregate) != NULL) {
			aggregate->count--;
			sub->suppress--;
		}
	}

	top->aggregate = NULL;
	ripng_aggregate_free(aggregate);

	agg_unlock_node(top);
	agg_unlock_node(top);

	return 0;
}
