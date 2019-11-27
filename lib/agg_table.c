/*
 * Aggregate Route
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
