/* BGP routing table
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
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

#include <zebra.h>

#include "prefix.h"
#include "memory.h"
#include "sockunion.h"
#include "queue.h"
#include "filter.h"
#include "command.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgp_addpath.h"

void bgp_table_lock(struct bgp_table *rt)
{
	rt->lock++;
}

void bgp_table_unlock(struct bgp_table *rt)
{
	assert(rt->lock > 0);
	rt->lock--;

	if (rt->lock != 0) {
		return;
	}

	route_table_finish(rt->route_table);
	rt->route_table = NULL;

	XFREE(MTYPE_BGP_TABLE, rt);
}

void bgp_table_finish(struct bgp_table **rt)
{
	if (*rt != NULL) {
		bgp_table_unlock(*rt);
		*rt = NULL;
	}
}

inline void bgp_dest_unlock_node(struct bgp_dest *dest)
{
	bgp_delete_listnode(dest);
	struct route_node *rn = bgp_dest_to_rnode(dest);

	if (rn->lock == 1) {
		struct bgp_table *rt = bgp_dest_table(dest);
		if (rt->bgp)
			bgp_addpath_free_node_data(&rt->bgp->tx_addpath,
						   &dest->tx_addpath, rt->afi,
						   rt->safi);

		XFREE(MTYPE_BGP_NODE, dest);
		rn->info = NULL;
	}
	route_unlock_node(rn);
}

/*
 * Function vector to customize the behavior of the route table
 * library for BGP route tables.
 */
route_table_delegate_t bgp_table_delegate = {.create_node = route_node_create,
					     .destroy_node =
						     route_node_destroy};

/*
 * bgp_table_init
 */
struct bgp_table *bgp_table_init(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_table *rt;

	rt = XCALLOC(MTYPE_BGP_TABLE, sizeof(struct bgp_table));

	rt->route_table = route_table_init_with_delegate(&bgp_table_delegate);

	/*
	 * Set up back pointer to bgp_table.
	 */
	route_table_set_info(rt->route_table, rt);

	/*
	 * pointer to bgp instance allows working back from bgp_path_info to bgp
	 */
	rt->bgp = bgp;

	bgp_table_lock(rt);
	rt->afi = afi;
	rt->safi = safi;

	return rt;
}

/* Delete the route node from the selection deferral route list */
void bgp_delete_listnode(struct bgp_dest *dest)
{
	const struct route_node *rn = NULL;
	struct bgp_table *table = NULL;
	struct bgp *bgp = NULL;
	afi_t afi;
	safi_t safi;

	/* If the route to be deleted is selection pending, update the
	 * route node in gr_info
	 */
	if (CHECK_FLAG(dest->flags, BGP_NODE_SELECT_DEFER)) {
		table = bgp_dest_table(dest);

		if (table) {
			bgp = table->bgp;
			afi = table->afi;
			safi = table->safi;
		} else
			return;

		rn = bgp_dest_to_rnode(dest);

		if (bgp && rn && rn->lock == 1) {
			/* Delete the route from the selection pending list */
			if ((dest->rt_node)
			    && (bgp->gr_info[afi][safi].route_list)) {
				list_delete_node(
					bgp->gr_info[afi][safi].route_list,
					dest->rt_node);
				dest->rt_node = NULL;
			}
		}
	}
}

struct bgp_dest *bgp_table_subtree_lookup(const struct bgp_table *table,
					  const struct prefix *p)
{
	struct bgp_dest *dest = bgp_dest_from_rnode(table->route_table->top);
	struct bgp_dest *matched = NULL;

	if (dest == NULL)
		return NULL;


	while (dest) {
		const struct prefix *dest_p = bgp_dest_get_prefix(dest);
		struct route_node *node = dest->rn;

		if (dest_p->prefixlen >= p->prefixlen) {
			if (!prefix_match(p, dest_p))
				return NULL;

			matched = dest;
			break;
		}

		if (!prefix_match(dest_p, p))
			return NULL;

		if (dest_p->prefixlen == p->prefixlen) {
			matched = dest;
			break;
		}

		dest = bgp_dest_from_rnode(node->link[prefix_bit(
			&p->u.prefix, dest_p->prefixlen)]);
	}

	if (!matched)
		return NULL;

	bgp_dest_lock_node(matched);
	return matched;
}

printfrr_ext_autoreg_p("BD", printfrr_bd)
static ssize_t printfrr_bd(char *buf, size_t bsz, const char *fmt,
			   int prec, const void *ptr)
{
	const struct bgp_dest *dest = ptr;
	const struct prefix *p = bgp_dest_get_prefix(dest);

	prefix2str(p, buf, bsz);
	return 2;
}
