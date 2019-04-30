/*
 * IS-IS Rout(e)ing protocol               - isis_route.c
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "srcdest_table.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_zebra.h"

static struct isis_nexthop *isis_nexthop_create(struct in_addr *ip,
						ifindex_t ifindex)
{
	struct listnode *node;
	struct isis_nexthop *nexthop;

	for (ALL_LIST_ELEMENTS_RO(isis->nexthops, node, nexthop)) {
		if (nexthop->ifindex != ifindex)
			continue;
		if (ip && memcmp(&nexthop->ip, ip, sizeof(struct in_addr)) != 0)
			continue;

		nexthop->lock++;
		return nexthop;
	}

	nexthop = XCALLOC(MTYPE_ISIS_NEXTHOP, sizeof(struct isis_nexthop));

	nexthop->ifindex = ifindex;
	memcpy(&nexthop->ip, ip, sizeof(struct in_addr));
	listnode_add(isis->nexthops, nexthop);
	nexthop->lock++;

	return nexthop;
}

static void isis_nexthop_delete(struct isis_nexthop *nexthop)
{
	nexthop->lock--;
	if (nexthop->lock == 0) {
		listnode_delete(isis->nexthops, nexthop);
		XFREE(MTYPE_ISIS_NEXTHOP, nexthop);
	}

	return;
}

static int nexthoplookup(struct list *nexthops, struct in_addr *ip,
			 ifindex_t ifindex)
{
	struct listnode *node;
	struct isis_nexthop *nh;

	for (ALL_LIST_ELEMENTS_RO(nexthops, node, nh)) {
		if (!(memcmp(ip, &nh->ip, sizeof(struct in_addr)))
		    && ifindex == nh->ifindex)
			return 1;
	}

	return 0;
}

static struct isis_nexthop6 *isis_nexthop6_new(struct in6_addr *ip6,
					       ifindex_t ifindex)
{
	struct isis_nexthop6 *nexthop6;

	nexthop6 = XCALLOC(MTYPE_ISIS_NEXTHOP6, sizeof(struct isis_nexthop6));

	nexthop6->ifindex = ifindex;
	memcpy(&nexthop6->ip6, ip6, sizeof(struct in6_addr));
	nexthop6->lock++;

	return nexthop6;
}

static struct isis_nexthop6 *isis_nexthop6_create(struct in6_addr *ip6,
						  ifindex_t ifindex)
{
	struct listnode *node;
	struct isis_nexthop6 *nexthop6;

	for (ALL_LIST_ELEMENTS_RO(isis->nexthops6, node, nexthop6)) {
		if (nexthop6->ifindex != ifindex)
			continue;
		if (ip6
		    && memcmp(&nexthop6->ip6, ip6, sizeof(struct in6_addr))
			       != 0)
			continue;

		nexthop6->lock++;
		return nexthop6;
	}

	nexthop6 = isis_nexthop6_new(ip6, ifindex);

	return nexthop6;
}

static void isis_nexthop6_delete(struct isis_nexthop6 *nexthop6)
{

	nexthop6->lock--;
	if (nexthop6->lock == 0) {
		listnode_delete(isis->nexthops6, nexthop6);
		XFREE(MTYPE_ISIS_NEXTHOP6, nexthop6);
	}

	return;
}

static int nexthop6lookup(struct list *nexthops6, struct in6_addr *ip6,
			  ifindex_t ifindex)
{
	struct listnode *node;
	struct isis_nexthop6 *nh6;

	for (ALL_LIST_ELEMENTS_RO(nexthops6, node, nh6)) {
		if (!(memcmp(ip6, &nh6->ip6, sizeof(struct in6_addr)))
		    && ifindex == nh6->ifindex)
			return 1;
	}

	return 0;
}

static void adjinfo2nexthop(struct list *nexthops, struct isis_adjacency *adj)
{
	struct isis_nexthop *nh;

	for (unsigned int i = 0; i < adj->ipv4_address_count; i++) {
		struct in_addr *ipv4_addr = &adj->ipv4_addresses[i];
		if (!nexthoplookup(nexthops, ipv4_addr,
				   adj->circuit->interface->ifindex)) {
			nh = isis_nexthop_create(
				ipv4_addr, adj->circuit->interface->ifindex);
			nh->router_address = adj->router_address;
			listnode_add(nexthops, nh);
			return;
		}
	}
}

static void adjinfo2nexthop6(struct list *nexthops6, struct isis_adjacency *adj)
{
	struct isis_nexthop6 *nh6;

	for (unsigned int i = 0; i < adj->ipv6_address_count; i++) {
		struct in6_addr *ipv6_addr = &adj->ipv6_addresses[i];
		if (!nexthop6lookup(nexthops6, ipv6_addr,
				    adj->circuit->interface->ifindex)) {
			nh6 = isis_nexthop6_create(
				ipv6_addr, adj->circuit->interface->ifindex);
			nh6->router_address6 = adj->router_address6;
			listnode_add(nexthops6, nh6);
			return;
		}
	}
}

static struct isis_route_info *isis_route_info_new(struct prefix *prefix,
						   struct prefix_ipv6 *src_p,
						   uint32_t cost,
						   uint32_t depth,
						   struct list *adjacencies)
{
	struct isis_route_info *rinfo;
	struct isis_adjacency *adj;
	struct listnode *node;

	rinfo = XCALLOC(MTYPE_ISIS_ROUTE_INFO, sizeof(struct isis_route_info));

	if (prefix->family == AF_INET) {
		rinfo->nexthops = list_new();
		for (ALL_LIST_ELEMENTS_RO(adjacencies, node, adj)) {
			/* check for force resync this route */
			if (CHECK_FLAG(adj->circuit->flags,
				       ISIS_CIRCUIT_FLAPPED_AFTER_SPF))
				SET_FLAG(rinfo->flag,
					 ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
			/* update neighbor router address */
			if (depth == 2 && prefix->prefixlen == 32)
				adj->router_address = prefix->u.prefix4;
			adjinfo2nexthop(rinfo->nexthops, adj);
		}
	}
	if (prefix->family == AF_INET6) {
		rinfo->nexthops6 = list_new();
		for (ALL_LIST_ELEMENTS_RO(adjacencies, node, adj)) {
			/* check for force resync this route */
			if (CHECK_FLAG(adj->circuit->flags,
				       ISIS_CIRCUIT_FLAPPED_AFTER_SPF))
				SET_FLAG(rinfo->flag,
					 ISIS_ROUTE_FLAG_ZEBRA_RESYNC);
			/* update neighbor router address */
			if (depth == 2 && prefix->prefixlen == 128
			    && (!src_p || !src_p->prefixlen)) {
				adj->router_address6 = prefix->u.prefix6;
			}
			adjinfo2nexthop6(rinfo->nexthops6, adj);
		}
	}

	rinfo->cost = cost;
	rinfo->depth = depth;

	return rinfo;
}

static void isis_route_info_delete(struct isis_route_info *route_info)
{
	if (route_info->nexthops) {
		route_info->nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&route_info->nexthops);
	}

	if (route_info->nexthops6) {
		route_info->nexthops6->del =
			(void (*)(void *))isis_nexthop6_delete;
		list_delete(&route_info->nexthops6);
	}

	XFREE(MTYPE_ISIS_ROUTE_INFO, route_info);
}

static int isis_route_info_same_attrib(struct isis_route_info *new,
				       struct isis_route_info *old)
{
	if (new->cost != old->cost)
		return 0;
	if (new->depth != old->depth)
		return 0;

	return 1;
}

static int isis_route_info_same(struct isis_route_info *new,
				struct isis_route_info *old, uint8_t family)
{
	struct listnode *node;
	struct isis_nexthop *nexthop;
	struct isis_nexthop6 *nexthop6;

	if (!CHECK_FLAG(old->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
		return 0;

	if (CHECK_FLAG(new->flag, ISIS_ROUTE_FLAG_ZEBRA_RESYNC))
		return 0;

	if (!isis_route_info_same_attrib(new, old))
		return 0;

	if (family == AF_INET) {
		for (ALL_LIST_ELEMENTS_RO(new->nexthops, node, nexthop))
			if (nexthoplookup(old->nexthops, &nexthop->ip,
					  nexthop->ifindex)
			    == 0)
				return 0;

		for (ALL_LIST_ELEMENTS_RO(old->nexthops, node, nexthop))
			if (nexthoplookup(new->nexthops, &nexthop->ip,
					  nexthop->ifindex)
			    == 0)
				return 0;
	} else if (family == AF_INET6) {
		for (ALL_LIST_ELEMENTS_RO(new->nexthops6, node, nexthop6))
			if (nexthop6lookup(old->nexthops6, &nexthop6->ip6,
					   nexthop6->ifindex)
			    == 0)
				return 0;

		for (ALL_LIST_ELEMENTS_RO(old->nexthops6, node, nexthop6))
			if (nexthop6lookup(new->nexthops6, &nexthop6->ip6,
					   nexthop6->ifindex)
			    == 0)
				return 0;
	}

	return 1;
}

struct isis_route_info *isis_route_create(struct prefix *prefix,
					  struct prefix_ipv6 *src_p,
					  uint32_t cost,
					  uint32_t depth,
					  struct list *adjacencies,
					  struct isis_area *area,
					  struct route_table *table)
{
	struct route_node *route_node;
	struct isis_route_info *rinfo_new, *rinfo_old, *route_info = NULL;
	char buff[PREFIX2STR_BUFFER];
	uint8_t family;

	family = prefix->family;
	/* for debugs */
	prefix2str(prefix, buff, sizeof(buff));

	if (!table)
		return NULL;

	rinfo_new = isis_route_info_new(prefix, src_p, cost,
					depth, adjacencies);
	route_node = srcdest_rnode_get(table, prefix, src_p);

	rinfo_old = route_node->info;
	if (!rinfo_old) {
		if (isis->debugs & DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte (%s) route created: %s",
				   area->area_tag, buff);
		route_info = rinfo_new;
		UNSET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
	} else {
		route_unlock_node(route_node);
		if (isis->debugs & DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte (%s) route already exists: %s",
				   area->area_tag, buff);
		if (isis_route_info_same(rinfo_new, rinfo_old, family)) {
			if (isis->debugs & DEBUG_RTE_EVENTS)
				zlog_debug("ISIS-Rte (%s) route unchanged: %s",
					   area->area_tag, buff);
			isis_route_info_delete(rinfo_new);
			route_info = rinfo_old;
		} else {
			if (isis->debugs & DEBUG_RTE_EVENTS)
				zlog_debug("ISIS-Rte (%s) route changed: %s",
					   area->area_tag, buff);
			isis_route_info_delete(rinfo_old);
			route_info = rinfo_new;
			UNSET_FLAG(route_info->flag,
				   ISIS_ROUTE_FLAG_ZEBRA_SYNCED);
		}
	}

	SET_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE);
	route_node->info = route_info;

	return route_info;
}

static void isis_route_delete(struct route_node *rode,
			      struct route_table *table)
{
	struct isis_route_info *rinfo;
	char buff[SRCDEST2STR_BUFFER];
	struct prefix *prefix;
	struct prefix_ipv6 *src_p;

	/* for log */
	srcdest_rnode2str(rode, buff, sizeof(buff));

	srcdest_rnode_prefixes(rode, (const struct prefix **)&prefix,
			       (const struct prefix **)&src_p);

	rinfo = rode->info;
	if (rinfo == NULL) {
		if (isis->debugs & DEBUG_RTE_EVENTS)
			zlog_debug(
				"ISIS-Rte: tried to delete non-existant route %s",
				buff);
		return;
	}

	if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED)) {
		UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
		if (isis->debugs & DEBUG_RTE_EVENTS)
			zlog_debug("ISIS-Rte: route delete  %s", buff);
		isis_zebra_route_update(prefix, src_p, rinfo);
	}
	isis_route_info_delete(rinfo);
	rode->info = NULL;
	route_unlock_node(rode);
}

static void _isis_route_verify_table(struct isis_area *area,
				     struct route_table *table,
				     struct route_table **tables)
{
	struct route_node *rnode, *drnode;
	struct isis_route_info *rinfo;
	char buff[SRCDEST2STR_BUFFER];

	for (rnode = route_top(table); rnode;
	     rnode = srcdest_route_next(rnode)) {
		if (rnode->info == NULL)
			continue;
		rinfo = rnode->info;

		struct prefix *dst_p;
		struct prefix_ipv6 *src_p;

		srcdest_rnode_prefixes(rnode,
				       (const struct prefix **)&dst_p,
				       (const struct prefix **)&src_p);

		if (isis->debugs & DEBUG_RTE_EVENTS) {
			srcdest2str(dst_p, src_p, buff, sizeof(buff));
			zlog_debug(
				"ISIS-Rte (%s): route validate: %s %s %s %s",
				area->area_tag,
				(CHECK_FLAG(rinfo->flag,
					    ISIS_ROUTE_FLAG_ZEBRA_SYNCED)
					 ? "synced"
					 : "not-synced"),
				(CHECK_FLAG(rinfo->flag,
					    ISIS_ROUTE_FLAG_ZEBRA_RESYNC)
					 ? "resync"
					 : "not-resync"),
				(CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE)
					 ? "active"
					 : "inactive"),
				buff);
		}

		isis_zebra_route_update(dst_p, src_p, rinfo);

		if (CHECK_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE))
			continue;

		/* Area is either L1 or L2 => we use level route tables
		 * directly for
		 * validating => no problems with deleting routes. */
		if (!tables) {
			isis_route_delete(rnode, table);
			continue;
		}

		/* If area is L1L2, we work with merge table and
		 * therefore must
		 * delete node from level tables as well before deleting
		 * route info. */
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			drnode = srcdest_rnode_lookup(tables[level - 1],
						      dst_p, src_p);
			if (!drnode)
				continue;

			route_unlock_node(drnode);

			if (drnode->info != rnode->info)
				continue;

			drnode->info = NULL;
			route_unlock_node(drnode);
		}

		isis_route_delete(rnode, table);
	}
}

void isis_route_verify_table(struct isis_area *area, struct route_table *table)
{
	_isis_route_verify_table(area, table, NULL);
}

/* Function to validate route tables for L1L2 areas. In this case we can't use
 * level route tables directly, we have to merge them at first. L1 routes are
 * preferred over the L2 ones.
 *
 * Merge algorithm is trivial (at least for now). All L1 paths are copied into
 * merge table at first, then L2 paths are added if L1 path for same prefix
 * doesn't already exists there.
 *
 * FIXME: Is it right place to do it at all? Maybe we should push both levels
 * to the RIB with different zebra route types and let RIB handle this? */
void isis_route_verify_merge(struct isis_area *area,
			     struct route_table *level1_table,
			     struct route_table *level2_table)
{
	struct route_table *tables[] = { level1_table, level2_table };
	struct route_table *merge;
	struct route_node *rnode, *mrnode;

	merge = srcdest_table_init();

	for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
		for (rnode = route_top(tables[level - 1]); rnode;
		     rnode = srcdest_route_next(rnode)) {
			struct isis_route_info *rinfo = rnode->info;
			if (!rinfo)
				continue;

			struct prefix *prefix;
			struct prefix_ipv6 *src_p;

			srcdest_rnode_prefixes(rnode,
					       (const struct prefix **)&prefix,
					       (const struct prefix **)&src_p);
			mrnode = srcdest_rnode_get(merge, prefix, src_p);
			struct isis_route_info *mrinfo = mrnode->info;
			if (mrinfo) {
				route_unlock_node(mrnode);
				if (CHECK_FLAG(mrinfo->flag,
					       ISIS_ROUTE_FLAG_ACTIVE)) {
					/* Clear the ZEBRA_SYNCED flag on the
					 * L2 route when L1 wins, otherwise L2
					 * won't get reinstalled when L1
					 * disappears.
					 */
					UNSET_FLAG(
						rinfo->flag,
						ISIS_ROUTE_FLAG_ZEBRA_SYNCED
					);
					continue;
				} else {
					/* Clear the ZEBRA_SYNCED flag on the L1
					 * route when L2 wins, otherwise L1
					 * won't get reinstalled when it
					 * reappears.
					 */
					UNSET_FLAG(
						mrinfo->flag,
						ISIS_ROUTE_FLAG_ZEBRA_SYNCED
					);
				}
			}
			mrnode->info = rnode->info;
		}
	}

	_isis_route_verify_table(area, merge, tables);
	route_table_finish(merge);
}

void isis_route_invalidate_table(struct isis_area *area,
				 struct route_table *table)
{
	struct route_node *rode;
	struct isis_route_info *rinfo;
	for (rode = route_top(table); rode; rode = srcdest_route_next(rode)) {
		if (rode->info == NULL)
			continue;
		rinfo = rode->info;

		UNSET_FLAG(rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
	}
}
