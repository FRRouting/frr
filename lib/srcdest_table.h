// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRC-DEST Routing Table
 *
 * Copyright (C) 2017 by David Lamparter & Christian Franke,
 *                       Open Source Routing / NetDEF Inc.
 *
 * This file is part of FRRouting (FRR)
 */

#ifndef _ZEBRA_SRC_DEST_TABLE_H
#define _ZEBRA_SRC_DEST_TABLE_H

/* old/IPv4/non-srcdest:
 * table -> route_node .info -> [obj]
 *
 * new/IPv6/srcdest:
 * table -...-> srcdest_rnode [prefix = dest] .info -> [obj]
 *                                            .src_table ->
 *         srcdest table -...-> route_node [prefix = src] .info -> [obj]
 *
 * non-srcdest routes (src = ::/0) are treated just like before, their
 * information being directly there in the info pointer.
 *
 * srcdest routes are found by looking up destination first, then looking
 * up the source in the "src_table".  src_table contains normal route_nodes,
 * whose prefix is the _source_ prefix.
 *
 * NB: info can be NULL on the destination rnode, if there are only srcdest
 * routes for a particular destination prefix.
 */

#include "prefix.h"
#include "table.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SRCDEST2STR_BUFFER (2*PREFIX2STR_BUFFER + sizeof(" from "))

/* extended route node for IPv6 srcdest routing */
struct srcdest_rnode;

extern route_table_delegate_t _srcdest_dstnode_delegate;
extern route_table_delegate_t _srcdest_srcnode_delegate;

extern struct route_table *srcdest_table_init(void);
extern struct route_node *srcdest_rnode_get(struct route_table *table,
					    union prefixconstptr dst_pu,
					    const struct prefix_ipv6 *src_p);
extern struct route_node *srcdest_rnode_lookup(struct route_table *table,
					       union prefixconstptr dst_pu,
					       const struct prefix_ipv6 *src_p);
extern void srcdest_rnode_prefixes(const struct route_node *rn,
				   const struct prefix **p,
				   const struct prefix **src_p);
extern const char *srcdest2str(const struct prefix *dst_p,
			       const struct prefix_ipv6 *src_p,
			       char *str, int size);
extern const char *srcdest_rnode2str(const struct route_node *rn, char *str,
				     int size);
extern struct route_node *srcdest_route_next(struct route_node *rn);

static inline int rnode_is_dstnode(const struct route_node *rn)
{
	return rn->table->delegate == &_srcdest_dstnode_delegate;
}

static inline int rnode_is_srcnode(const struct route_node *rn)
{
	return rn->table->delegate == &_srcdest_srcnode_delegate;
}

static inline struct route_table *srcdest_rnode_table(struct route_node *rn)
{
	if (rnode_is_srcnode(rn)) {
		struct route_node *dst_rn =
			(struct route_node *)route_table_get_info(rn->table);
		return dst_rn->table;
	} else {
		return rn->table;
	}
}
static inline void *srcdest_rnode_table_info(struct route_node *rn)
{
	return route_table_get_info(srcdest_rnode_table(rn));
}

extern struct route_table *srcdest_srcnode_table(struct route_node *rn);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SRC_DEST_TABLE_H */
