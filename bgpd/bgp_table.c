// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP routing table
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
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
#include "bgp_trace.h"

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

/*
 * bgp_dest_lock_node
 */
struct bgp_dest *bgp_dest_lock_node(struct bgp_dest *dest)
{
	frrtrace(1, frr_bgp, bgp_dest_lock, dest);
	struct route_node *rn = route_lock_node(bgp_dest_to_rnode(dest));

	return bgp_dest_from_rnode(rn);
}

/*
 * bgp_dest_get_prefix_str
 */
const char *bgp_dest_get_prefix_str(struct bgp_dest *dest)
{
	const struct prefix *p = NULL;
	static char str[PREFIX_STRLEN] = {0};

	p = bgp_dest_get_prefix(dest);
	if (p)
		return prefix2str(p, str, sizeof(str));

	return NULL;
}

/*
 * bgp_dest_unlock_node
 */
inline struct bgp_dest *bgp_dest_unlock_node(struct bgp_dest *dest)
{
	frrtrace(1, frr_bgp, bgp_dest_unlock, dest);
	bgp_delete_listnode(dest);
	struct route_node *rn = bgp_dest_to_rnode(dest);

	if (rn->lock == 1) {
		struct bgp_table *rt = bgp_dest_table(dest);
		if (rt->bgp) {
			bgp_addpath_free_node_data(&rt->bgp->tx_addpath,
						   &dest->tx_addpath, rt->afi,
						   rt->safi);
		}
		XFREE(MTYPE_BGP_NODE, dest);
		dest = NULL;
		rn->info = NULL;
	}
	route_unlock_node(rn);

	return dest;
}

/*
 * bgp_node_destroy
 */
static void bgp_node_destroy(route_table_delegate_t *delegate,
							struct route_table *table, struct route_node *node)
{
	struct bgp_dest *dest;
	struct bgp_table *rt;
	dest = bgp_dest_from_rnode(node);
	rt = table->info;
	if (dest) {
		if (rt->bgp) {
			bgp_addpath_free_node_data(&rt->bgp->tx_addpath,
										&dest->tx_addpath,
										rt->afi, rt->safi);
		}
		XFREE(MTYPE_BGP_NODE, dest);
		node->info = NULL;
	}

	XFREE(MTYPE_ROUTE_NODE, node);
}

/*
 * Function vector to customize the behavior of the route table
 * library for BGP route tables.
 */
route_table_delegate_t bgp_table_delegate = { .create_node = route_node_create,
					      .destroy_node = bgp_node_destroy };

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
			bgp->gr_info[afi][safi].gr_deferred--;
			UNSET_FLAG(dest->flags, BGP_NODE_SELECT_DEFER);
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

		dest = bgp_dest_from_rnode(
			node->link[prefix_bit(&p->u.prefix, dest_p->prefixlen)]);
	}

	if (!matched)
		return NULL;

	bgp_dest_lock_node(matched);
	return matched;
}

printfrr_ext_autoreg_p("BD", printfrr_bd);
static ssize_t printfrr_bd(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *ptr)
{
	const struct bgp_dest *dest = ptr;
	const struct prefix *p = bgp_dest_get_prefix(dest);
	char cbuf[PREFIX_STRLEN];

	if (!dest)
		return bputs(buf, "(null)");

#if !defined(DEV_BUILD)
	/* need to get the real length even if buffer too small */
	prefix2str(p, cbuf, sizeof(cbuf));
	return bputs(buf, cbuf);
#else
	return bprintfrr(buf, "%s(%p)", prefix2str(p, cbuf, sizeof(cbuf)), dest);
#endif
}
