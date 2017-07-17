/*
 * SRC-DEST Routing Table
 *
 * Copyright (C) 2017 by David Lamparter & Christian Franke,
 *                       Open Source Routing / NetDEF Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
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

#include <zebra.h>

#include "srcdest_table.h"

#include "memory.h"
#include "prefix.h"
#include "table.h"

DEFINE_MTYPE_STATIC(LIB, ROUTE_SRC_NODE, "Route source node")

/* ----- functions to manage rnodes _with_ srcdest table ----- */
struct srcdest_rnode {
	/* must be first in structure for casting to/from route_node */
	ROUTE_NODE_FIELDS;

	struct route_table *src_table;
};

static struct srcdest_rnode *srcdest_rnode_from_rnode(struct route_node *rn)
{
	assert(rnode_is_dstnode(rn));
	return (struct srcdest_rnode *)rn;
}

static struct route_node *srcdest_rnode_to_rnode(struct srcdest_rnode *srn)
{
	return (struct route_node *)srn;
}

static struct route_node *srcdest_rnode_create(route_table_delegate_t *delegate,
					       struct route_table *table)
{
	struct srcdest_rnode *srn;
	srn = XCALLOC(MTYPE_ROUTE_NODE, sizeof(struct srcdest_rnode));
	return srcdest_rnode_to_rnode(srn);
}

static void srcdest_rnode_destroy(route_table_delegate_t *delegate,
				  struct route_table *table,
				  struct route_node *rn)
{
	struct srcdest_rnode *srn = srcdest_rnode_from_rnode(rn);
	struct route_table *src_table;

	/* Clear route node's src_table here already, otherwise the
	 * deletion of the last node in the src_table will trigger
	 * another call to route_table_finish for the src_table.
	 *
	 * (Compare with srcdest_srcnode_destroy)
	 */
	src_table = srn->src_table;
	srn->src_table = NULL;
	route_table_finish(src_table);
	XFREE(MTYPE_ROUTE_NODE, rn);
}

route_table_delegate_t _srcdest_dstnode_delegate = {
	.create_node = srcdest_rnode_create,
	.destroy_node = srcdest_rnode_destroy};

/* ----- functions to manage rnodes _in_ srcdest table ----- */

/* node creation / deletion for srcdest source prefix nodes.
 * the route_node isn't actually different from the normal route_node,
 * but the cleanup is special to free the table (and possibly the
 * destination prefix's route_node) */

static struct route_node *
srcdest_srcnode_create(route_table_delegate_t *delegate,
		       struct route_table *table)
{
	return XCALLOC(MTYPE_ROUTE_SRC_NODE, sizeof(struct route_node));
}

static void srcdest_srcnode_destroy(route_table_delegate_t *delegate,
				    struct route_table *table,
				    struct route_node *rn)
{
	struct srcdest_rnode *srn;

	XFREE(MTYPE_ROUTE_SRC_NODE, rn);

	srn = table->info;
	if (srn->src_table && route_table_count(srn->src_table) == 0) {
		/* deleting the route_table from inside destroy_node is ONLY
		 * permitted IF table->count is 0!  see lib/table.c
		 * route_node_delete()
		 * for details */
		route_table_finish(srn->src_table);
		srn->src_table = NULL;

		/* drop the ref we're holding in srcdest_node_get().  there
		 * might be
		 * non-srcdest routes, so the route_node may still exist.
		 * hence, it's
		 * important to clear src_table above. */
		route_unlock_node(srcdest_rnode_to_rnode(srn));
	}
}

route_table_delegate_t _srcdest_srcnode_delegate = {
	.create_node = srcdest_srcnode_create,
	.destroy_node = srcdest_srcnode_destroy};

/* NB: read comments in code for refcounting before using! */
static struct route_node *srcdest_srcnode_get(struct route_node *rn,
					      struct prefix_ipv6 *src_p)
{
	struct srcdest_rnode *srn;

	if (!src_p || src_p->prefixlen == 0)
		return rn;

	srn = srcdest_rnode_from_rnode(rn);
	if (!srn->src_table) {
		/* this won't use srcdest_rnode, we're already on the source
		 * here */
		srn->src_table = route_table_init_with_delegate(
			&_srcdest_srcnode_delegate);
		srn->src_table->info = srn;

		/* there is no route_unlock_node on the original rn here.
		 * The reference is kept for the src_table. */
	} else {
		/* only keep 1 reference for the src_table, makes the
		 * refcounting
		 * more similar to the non-srcdest case.  Either way after
		 * return from
		 * function, the only reference held is the one on the return
		 * value.
		 *
		 * We can safely drop our reference here because src_table is
		 * holding
		 * another reference, so this won't free rn */
		route_unlock_node(rn);
	}

	return route_node_get(srn->src_table, (struct prefix *)src_p);
}

static struct route_node *srcdest_srcnode_lookup(struct route_node *rn,
						 struct prefix_ipv6 *src_p)
{
	struct srcdest_rnode *srn;

	if (!rn || !src_p || src_p->prefixlen == 0)
		return rn;

	/* We got this rn from a lookup, so its refcnt was incremented. As we
	 * won't
	 * return return rn from any point beyond here, we should decrement its
	 * refcnt.
	 */
	route_unlock_node(rn);

	srn = srcdest_rnode_from_rnode(rn);
	if (!srn->src_table)
		return NULL;

	return route_node_lookup(srn->src_table, (struct prefix *)src_p);
}

/* ----- exported functions ----- */

struct route_table *srcdest_table_init(void)
{
	return route_table_init_with_delegate(&_srcdest_dstnode_delegate);
}

struct route_node *srcdest_route_next(struct route_node *rn)
{
	struct route_node *next, *parent;

	/* For a non src-dest node, just return route_next */
	if (!(rnode_is_dstnode(rn) || rnode_is_srcnode(rn)))
		return route_next(rn);

	if (rnode_is_dstnode(rn)) {
		/* This means the route_node is part of the top hierarchy
		 * and refers to a destination prefix. */
		struct srcdest_rnode *srn = srcdest_rnode_from_rnode(rn);

		if (srn->src_table)
			next = route_top(srn->src_table);
		else
			next = NULL;

		if (next) {
			/* There is a source prefix. Return the node for it */
			route_unlock_node(rn);
			return next;
		} else {
			/* There is no source prefix, just continue as usual */
			return route_next(rn);
		}
	}

	/* This part handles the case of iterating source nodes. */
	parent = route_lock_node(rn->table->info);
	next = route_next(rn);

	if (next) {
		/* There is another source node, continue in the source table */
		route_unlock_node(parent);
		return next;
	} else {
		/* The source table is complete, continue in the parent table */
		return route_next(parent);
	}
}

struct route_node *srcdest_rnode_get(struct route_table *table,
				     union prefixptr dst_pu,
				     struct prefix_ipv6 *src_p)
{
	struct prefix_ipv6 *dst_p = dst_pu.p6;
	struct route_node *rn;

	rn = route_node_get(table, (struct prefix *)dst_p);
	return srcdest_srcnode_get(rn, src_p);
}

struct route_node *srcdest_rnode_lookup(struct route_table *table,
					union prefixptr dst_pu,
					struct prefix_ipv6 *src_p)
{
	struct prefix_ipv6 *dst_p = dst_pu.p6;
	struct route_node *rn;
	struct route_node *srn;

	rn = route_node_lookup_maynull(table, (struct prefix *)dst_p);
	srn = srcdest_srcnode_lookup(rn, src_p);

	if (rn != NULL && rn == srn && !rn->info) {
		/* Match the behavior of route_node_lookup and don't return an
		 * empty route-node for a dest-route */
		route_unlock_node(rn);
		return NULL;
	}
	return srn;
}

void srcdest_rnode_prefixes(struct route_node *rn, struct prefix **p,
			    struct prefix **src_p)
{
	if (rnode_is_srcnode(rn)) {
		struct route_node *dst_rn = rn->table->info;
		if (p)
			*p = &dst_rn->p;
		if (src_p)
			*src_p = &rn->p;
	} else {
		if (p)
			*p = &rn->p;
		if (src_p)
			*src_p = NULL;
	}
}

const char *srcdest_rnode2str(struct route_node *rn, char *str, int size)
{
	struct prefix *dst_p, *src_p;
	char dst_buf[PREFIX_STRLEN], src_buf[PREFIX_STRLEN];

	srcdest_rnode_prefixes(rn, &dst_p, &src_p);

	snprintf(str, size, "%s%s%s",
		 prefix2str(dst_p, dst_buf, sizeof(dst_buf)),
		 (src_p && src_p->prefixlen) ? " from " : "",
		 (src_p && src_p->prefixlen)
			 ? prefix2str(src_p, src_buf, sizeof(src_buf))
			 : "");
	return str;
}
