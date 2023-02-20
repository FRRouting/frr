// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Aggregate Route
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include "zebra.h"

#include "agg_table.h"


static struct route_node *agg_node_create(route_table_delegate_t *delegate,
					  struct route_table *table)
{
	struct agg_node *node;

	node = XCALLOC(MTYPE_TMP, sizeof(struct agg_node));

	return agg_node_to_rnode(node);
}

static void agg_node_destroy(route_table_delegate_t *delegate,
			     struct route_table *table, struct route_node *node)

{
	struct agg_node *anode = agg_node_from_rnode(node);

	XFREE(MTYPE_TMP, anode);
}

static route_table_delegate_t agg_table_delegate = {
	.create_node = agg_node_create,
	.destroy_node = agg_node_destroy,
};

struct agg_table *agg_table_init(void)
{
	struct agg_table *at;

	at = XCALLOC(MTYPE_TMP, sizeof(struct agg_table));

	at->route_table = route_table_init_with_delegate(&agg_table_delegate);
	route_table_set_info(at->route_table, at);

	return at;
}
