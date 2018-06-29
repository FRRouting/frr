/*
 * Area Border Router function.
 * Copyright (C) 2004 Yasuhiro Ohara
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

#include "log.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_route.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6d.h"

unsigned char conf_debug_ospf6_abr;

int ospf6_is_router_abr(struct ospf6 *o)
{
	struct listnode *node;
	struct ospf6_area *oa;
	int area_count = 0;

	for (ALL_LIST_ELEMENTS_RO(o->area_list, node, oa))
		if (IS_AREA_ENABLED(oa))
			area_count++;

	if (area_count > 1)
		return 1;
	return 0;
}

static int ospf6_abr_nexthops_belong_to_area(struct ospf6_route *route,
					     struct ospf6_area *area)
{
	struct ospf6_interface *oi;

	oi = ospf6_interface_lookup_by_ifindex(
		ospf6_route_get_first_nh_index(route));
	if (oi && oi->area && oi->area == area)
		return 1;
	else
		return 0;
}

static void ospf6_abr_delete_route(struct ospf6_route *range,
				   struct ospf6_route *summary,
				   struct ospf6_route_table *summary_table,
				   struct ospf6_lsa *old)
{
	if (summary) {
		ospf6_route_remove(summary, summary_table);
	}

	if (old && !OSPF6_LSA_IS_MAXAGE(old))
		ospf6_lsa_purge(old);
}

void ospf6_abr_enable_area(struct ospf6_area *area)
{
	struct ospf6_area *oa;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(area->ospf6->area_list, node, nnode, oa))
		/* update B bit for each area */
		OSPF6_ROUTER_LSA_SCHEDULE(oa);
}

void ospf6_abr_disable_area(struct ospf6_area *area)
{
	struct ospf6_area *oa;
	struct ospf6_route *ro, *nro;
	struct ospf6_lsa *old;
	struct listnode *node, *nnode;

	/* Withdraw all summary prefixes previously originated */
	for (ro = ospf6_route_head(area->summary_prefix); ro; ro = nro) {
		nro = ospf6_route_next(ro);
		old = ospf6_lsdb_lookup(ro->path.origin.type,
					ro->path.origin.id,
					area->ospf6->router_id, area->lsdb);
		if (old)
			ospf6_lsa_purge(old);
		ospf6_route_remove(ro, area->summary_prefix);
	}

	/* Withdraw all summary router-routes previously originated */
	for (ro = ospf6_route_head(area->summary_router); ro; ro = nro) {
		nro = ospf6_route_next(ro);
		old = ospf6_lsdb_lookup(ro->path.origin.type,
					ro->path.origin.id,
					area->ospf6->router_id, area->lsdb);
		if (old)
			ospf6_lsa_purge(old);
		ospf6_route_remove(ro, area->summary_router);
	}

	/* Schedule Router-LSA for each area (ABR status may change) */
	for (ALL_LIST_ELEMENTS(area->ospf6->area_list, node, nnode, oa))
		/* update B bit for each area */
		OSPF6_ROUTER_LSA_SCHEDULE(oa);
}

/* RFC 2328 12.4.3. Summary-LSAs */
/* Returns 1 if a summary LSA has been generated for the area */
/* This is used by the area/range logic to add/remove blackhole routes */
int ospf6_abr_originate_summary_to_area(struct ospf6_route *route,
					struct ospf6_area *area)
{
	struct ospf6_lsa *lsa, *old = NULL;
	struct ospf6_route *summary, *range = NULL;
	struct ospf6_area *route_area;
	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	caddr_t p;
	struct ospf6_inter_prefix_lsa *prefix_lsa;
	struct ospf6_inter_router_lsa *router_lsa;
	struct ospf6_route_table *summary_table = NULL;
	uint16_t type;
	char buf[PREFIX2STR_BUFFER];
	int is_debug = 0;

	/* Only destination type network, range or ASBR are considered */
	if (route->type != OSPF6_DEST_TYPE_NETWORK
	    && route->type != OSPF6_DEST_TYPE_RANGE
	    && ((route->type != OSPF6_DEST_TYPE_ROUTER)
		|| !CHECK_FLAG(route->path.router_bits, OSPF6_ROUTER_BIT_E))) {
#if 0
		zlog_debug(
			"Route type is none of network, range nor ASBR, ignore");
#endif
		return 0;
	}

	/* AS External routes are never considered */
	if (route->path.type == OSPF6_PATH_TYPE_EXTERNAL1
	    || route->path.type == OSPF6_PATH_TYPE_EXTERNAL2) {
		if (is_debug)
			zlog_debug("Path type is external, skip");
		return 0;
	}

	/* do not generate if the path's area is the same as target area */
	if (route->path.area_id == area->area_id) {
#if 0
		zlog_debug("The route is in the area itself, ignore");
#endif
		return 0;
	}

	/* do not generate if the nexthops belongs to the target area */
	if (ospf6_abr_nexthops_belong_to_area(route, area)) {
#if 0
		zlog_debug("The route's nexthop is in the same area, ignore");
#endif
		return 0;
	}

	if (route->type == OSPF6_DEST_TYPE_ROUTER) {
		if (ADV_ROUTER_IN_PREFIX(&route->prefix)
		    == area->ospf6->router_id) {
			inet_ntop(AF_INET,
				  &(ADV_ROUTER_IN_PREFIX(&route->prefix)), buf,
				  sizeof(buf));
			zlog_debug(
				"%s: Skipping ASBR announcement for ABR (%s)",
				__func__, buf);
			return 0;
		}
	}

	if (route->type == OSPF6_DEST_TYPE_ROUTER) {
		if (IS_OSPF6_DEBUG_ABR
		    || IS_OSPF6_DEBUG_ORIGINATE(INTER_ROUTER)) {
			is_debug++;
			inet_ntop(AF_INET,
				  &(ADV_ROUTER_IN_PREFIX(&route->prefix)), buf,
				  sizeof(buf));
			zlog_debug("Originating summary in area %s for ASBR %s",
				   area->name, buf);
		}
		summary_table = area->summary_router;
	} else {
		if (IS_OSPF6_DEBUG_ABR
		    || IS_OSPF6_DEBUG_ORIGINATE(INTER_PREFIX))
			is_debug++;

		if (route->type == OSPF6_DEST_TYPE_NETWORK &&
		    route->path.origin.type ==
		    htons(OSPF6_LSTYPE_INTER_PREFIX)) {
			if (!CHECK_FLAG(route->flag, OSPF6_ROUTE_BEST)) {
				if (is_debug) {
					inet_ntop(AF_INET,
						  &(ADV_ROUTER_IN_PREFIX(
							&route->prefix)), buf,
						  sizeof(buf));
					zlog_debug(
						"%s: route %s with cost %u is not best, ignore."
						, __PRETTY_FUNCTION__, buf,
						route->path.cost);
				}
				return 0;
			}
		}

		if (is_debug) {
			prefix2str(&route->prefix, buf, sizeof(buf));
			zlog_debug("Originating summary in area %s for %s cost %u",
				   area->name, buf, route->path.cost);
		}
		summary_table = area->summary_prefix;
	}

	summary = ospf6_route_lookup(&route->prefix, summary_table);
	if (summary)
		old = ospf6_lsdb_lookup(summary->path.origin.type,
					summary->path.origin.id,
					area->ospf6->router_id, area->lsdb);

	/* if this route has just removed, remove corresponding LSA */
	if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)) {
		if (is_debug)
			zlog_debug(
				"The route has just removed, purge previous LSA");

		if (route->type == OSPF6_DEST_TYPE_RANGE) {
			/* Whether the route have active longer prefix */
			if (!CHECK_FLAG(route->flag,
					OSPF6_ROUTE_ACTIVE_SUMMARY)) {
				if (is_debug)
					zlog_debug(
						"The range is not active. withdraw");

				ospf6_abr_delete_route(route, summary,
						       summary_table, old);
			}
		} else if (old)
			ospf6_lsa_purge(old);

		return 0;
	}

	if ((route->type == OSPF6_DEST_TYPE_ROUTER) && IS_AREA_STUB(area)) {
		if (is_debug)
			zlog_debug(
				"Area has been stubbed, purge Inter-Router LSA");

		ospf6_abr_delete_route(route, summary, summary_table, old);
		return 0;
	}

	if (area->no_summary
	    && (route->path.subtype != OSPF6_PATH_SUBTYPE_DEFAULT_RT)) {
		if (is_debug)
			zlog_debug("Area has been stubbed, purge prefix LSA");

		ospf6_abr_delete_route(route, summary, summary_table, old);
		return 0;
	}

	/* do not generate if the route cost is greater or equal to LSInfinity
	 */
	if (route->path.cost >= OSPF_LS_INFINITY) {
		/* When we're clearing the range route because all active
		 * prefixes
		 * under the range are gone, we set the range's cost to
		 * OSPF_AREA_RANGE_COST_UNSPEC, which is > OSPF_LS_INFINITY. We
		 * don't want to trigger the code here for that. This code is
		 * for
		 * handling routes that have gone to infinity. The range removal
		 * happens
		 * elsewhere.
		 */
		if ((route->type != OSPF6_DEST_TYPE_RANGE)
		    && (route->path.cost != OSPF_AREA_RANGE_COST_UNSPEC)) {
			if (is_debug)
				zlog_debug(
					"The cost exceeds LSInfinity, withdraw");
			if (old)
				ospf6_lsa_purge(old);
			return 0;
		}
	}

	/* if this is a route to ASBR */
	if (route->type == OSPF6_DEST_TYPE_ROUTER) {
		/* Only the prefered best path is considered */
		if (!CHECK_FLAG(route->flag, OSPF6_ROUTE_BEST)) {
			if (is_debug)
				zlog_debug(
					"This is the secondary path to the ASBR, ignore");
			ospf6_abr_delete_route(route, summary, summary_table,
					       old);
			return 0;
		}

		/* Do not generate if the area is stub */
		/* XXX */
	}

	/* if this is an intra-area route, this may be suppressed by aggregation
	 */
	if (route->type == OSPF6_DEST_TYPE_NETWORK
	    && route->path.type == OSPF6_PATH_TYPE_INTRA) {
		/* search for configured address range for the route's area */
		route_area =
			ospf6_area_lookup(route->path.area_id, area->ospf6);
		assert(route_area);
		range = ospf6_route_lookup_bestmatch(&route->prefix,
						     route_area->range_table);

		/* ranges are ignored when originate backbone routes to transit
		   area.
		   Otherwise, if ranges are configured, the route is suppressed.
		   */
		if (range && !CHECK_FLAG(range->flag, OSPF6_ROUTE_REMOVE)
		    && (route->path.area_id != OSPF_AREA_BACKBONE
			|| !IS_AREA_TRANSIT(area))) {
			if (is_debug) {
				prefix2str(&range->prefix, buf, sizeof(buf));
				zlog_debug("Suppressed by range %s of area %s",
					   buf, route_area->name);
			}
			ospf6_abr_delete_route(route, summary, summary_table,
					       old);
			return 0;
		}
	}

	/* If this is a configured address range */
	if (route->type == OSPF6_DEST_TYPE_RANGE) {
		/* If DoNotAdvertise is set */
		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE)) {
			if (is_debug)
				zlog_debug(
					"This is the range with DoNotAdvertise set. ignore");
			ospf6_abr_delete_route(route, summary, summary_table,
					       old);
			return 0;
		}

		/* If there are no active prefixes in this range, remove */
		if (!CHECK_FLAG(route->flag, OSPF6_ROUTE_ACTIVE_SUMMARY)) {
			if (is_debug)
				zlog_debug("The range is not active. withdraw");
			ospf6_abr_delete_route(route, summary, summary_table,
					       old);
			return 0;
		}
	}

	/* Check export list */
	if (EXPORT_NAME(area)) {
		if (EXPORT_LIST(area) == NULL)
			EXPORT_LIST(area) =
				access_list_lookup(AFI_IP6, EXPORT_NAME(area));

		if (EXPORT_LIST(area))
			if (access_list_apply(EXPORT_LIST(area), &route->prefix)
			    == FILTER_DENY) {
				if (is_debug) {
					inet_ntop(AF_INET,
						  &(ADV_ROUTER_IN_PREFIX(
							  &route->prefix)),
						  buf, sizeof(buf));
					zlog_debug(
						"prefix %s was denied by export list",
						buf);
				}
				return 0;
			}
	}

	/* Check filter-list */
	if (PREFIX_LIST_OUT(area))
		if (prefix_list_apply(PREFIX_LIST_OUT(area), &route->prefix)
		    != PREFIX_PERMIT) {
			if (is_debug) {
				inet_ntop(
					AF_INET,
					&(ADV_ROUTER_IN_PREFIX(&route->prefix)),
					buf, sizeof(buf));
				zlog_debug(
					"prefix %s was denied by filter-list out",
					buf);
			}
			return 0;
		}

	/* the route is going to be originated. store it in area's summary_table
	 */
	if (summary == NULL) {
		summary = ospf6_route_copy(route);
		summary->path.origin.adv_router = area->ospf6->router_id;

		if (route->type == OSPF6_DEST_TYPE_ROUTER) {
			summary->path.origin.type =
				htons(OSPF6_LSTYPE_INTER_ROUTER);
			summary->path.origin.id =
				ADV_ROUTER_IN_PREFIX(&route->prefix);
		} else {
			summary->path.origin.type =
				htons(OSPF6_LSTYPE_INTER_PREFIX);
			summary->path.origin.id = ospf6_new_ls_id(
				summary->path.origin.type,
				summary->path.origin.adv_router, area->lsdb);
		}
		summary = ospf6_route_add(summary, summary_table);
	} else {
		summary->type = route->type;
		monotime(&summary->changed);
	}

	summary->path.router_bits = route->path.router_bits;
	summary->path.options[0] = route->path.options[0];
	summary->path.options[1] = route->path.options[1];
	summary->path.options[2] = route->path.options[2];
	summary->path.prefix_options = route->path.prefix_options;
	summary->path.area_id = area->area_id;
	summary->path.type = OSPF6_PATH_TYPE_INTER;
	summary->path.subtype = route->path.subtype;
	summary->path.cost = route->path.cost;
	/* summary->nexthop[0] = route->nexthop[0]; */

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;

	if (route->type == OSPF6_DEST_TYPE_ROUTER) {
		router_lsa = (struct ospf6_inter_router_lsa
				      *)((caddr_t)lsa_header
					 + sizeof(struct ospf6_lsa_header));
		p = (caddr_t)router_lsa + sizeof(struct ospf6_inter_router_lsa);

		/* Fill Inter-Area-Router-LSA */
		router_lsa->options[0] = route->path.options[0];
		router_lsa->options[1] = route->path.options[1];
		router_lsa->options[2] = route->path.options[2];
		OSPF6_ABR_SUMMARY_METRIC_SET(router_lsa, route->path.cost);
		router_lsa->router_id = ADV_ROUTER_IN_PREFIX(&route->prefix);
		type = htons(OSPF6_LSTYPE_INTER_ROUTER);
	} else {
		prefix_lsa = (struct ospf6_inter_prefix_lsa
				      *)((caddr_t)lsa_header
					 + sizeof(struct ospf6_lsa_header));
		p = (caddr_t)prefix_lsa + sizeof(struct ospf6_inter_prefix_lsa);

		/* Fill Inter-Area-Prefix-LSA */
		OSPF6_ABR_SUMMARY_METRIC_SET(prefix_lsa, route->path.cost);
		prefix_lsa->prefix.prefix_length = route->prefix.prefixlen;
		prefix_lsa->prefix.prefix_options = route->path.prefix_options;

		/* set Prefix */
		memcpy(p, &route->prefix.u.prefix6,
		       OSPF6_PREFIX_SPACE(route->prefix.prefixlen));
		ospf6_prefix_apply_mask(&prefix_lsa->prefix);
		p += OSPF6_PREFIX_SPACE(route->prefix.prefixlen);
		type = htons(OSPF6_LSTYPE_INTER_PREFIX);
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = type;
	lsa_header->id = summary->path.origin.id;
	lsa_header->adv_router = area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, area->lsdb);
	lsa_header->length = htons((caddr_t)p - (caddr_t)lsa_header);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, area);

	return 1;
}

void ospf6_abr_range_reset_cost(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6_route *range;

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa))
		for (range = ospf6_route_head(oa->range_table); range;
		     range = ospf6_route_next(range))
			OSPF6_ABR_RANGE_CLEAR_COST(range);
}

static inline uint32_t ospf6_abr_range_compute_cost(struct ospf6_route *range,
						    struct ospf6 *o)
{
	struct ospf6_route *ro;
	uint32_t cost = 0;

	for (ro = ospf6_route_match_head(&range->prefix, o->route_table); ro;
	     ro = ospf6_route_match_next(&range->prefix, ro)) {
		if (ro->path.area_id == range->path.area_id
		    && (ro->path.type == OSPF6_PATH_TYPE_INTRA)
		    && !CHECK_FLAG(ro->flag, OSPF6_ROUTE_REMOVE))
			cost = MAX(cost, ro->path.cost);
	}

	return cost;
}

static inline int
ospf6_abr_range_summary_needs_update(struct ospf6_route *range, uint32_t cost)
{
	int redo_summary = 0;

	if (CHECK_FLAG(range->flag, OSPF6_ROUTE_REMOVE)) {
		UNSET_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY);
		redo_summary = 1;
	} else if (CHECK_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE)) {
		if (range->path.cost != 0) {
			range->path.cost = 0;
			redo_summary = 1;
		}
	} else if (cost) {
		if ((OSPF6_PATH_COST_IS_CONFIGURED(range->path)
		     && range->path.cost != range->path.u.cost_config)) {
			range->path.cost = range->path.u.cost_config;
			SET_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY);
			redo_summary = 1;
		} else if (!OSPF6_PATH_COST_IS_CONFIGURED(range->path)
			   && range->path.cost != cost) {
			range->path.cost = cost;
			SET_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY);
			redo_summary = 1;
		}
	} else if (CHECK_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY)) {
		/* Cost is zero, meaning no active range */
		UNSET_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY);
		range->path.cost = OSPF_AREA_RANGE_COST_UNSPEC;
		redo_summary = 1;
	}

	return (redo_summary);
}

static void ospf6_abr_range_update(struct ospf6_route *range)
{
	uint32_t cost = 0;
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	int summary_orig = 0;

	assert(range->type == OSPF6_DEST_TYPE_RANGE);

	/* update range's cost and active flag */
	cost = ospf6_abr_range_compute_cost(range, ospf6);

	/* Non-zero cost is a proxy for active longer prefixes in this range.
	 * If there are active routes covered by this range AND either the
	 * configured
	 * cost has changed or the summarized cost has changed then redo
	 * summaries.
	 * Alternately, if there are no longer active prefixes and there are
	 * summary announcements, withdraw those announcements.
	 *
	 * The don't advertise code relies on the path.cost being set to UNSPEC
	 * to
	 * work the first time. Subsequent times the path.cost is not 0 anyway
	 * if there
	 * were active ranges.
	 */

	if (ospf6_abr_range_summary_needs_update(range, cost)) {
		for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa))
			summary_orig +=
				ospf6_abr_originate_summary_to_area(range, oa);

		if (CHECK_FLAG(range->flag, OSPF6_ROUTE_ACTIVE_SUMMARY)
		    && summary_orig) {
			if (!CHECK_FLAG(range->flag,
					OSPF6_ROUTE_BLACKHOLE_ADDED)) {
				if (IS_OSPF6_DEBUG_ABR)
					zlog_debug("Add discard route");

				ospf6_zebra_add_discard(range);
			}
		} else {
			/* Summary removed or no summary generated as no
			 * specifics exist */
			if (CHECK_FLAG(range->flag,
				       OSPF6_ROUTE_BLACKHOLE_ADDED)) {
				if (IS_OSPF6_DEBUG_ABR)
					zlog_debug("Delete discard route");

				ospf6_zebra_delete_discard(range);
			}
		}
	}
}

void ospf6_abr_originate_summary(struct ospf6_route *route)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6_route *range = NULL;

	if (route->type == OSPF6_DEST_TYPE_NETWORK) {
		oa = ospf6_area_lookup(route->path.area_id, ospf6);
		if (!oa) {
			zlog_err("OSPFv6 area lookup failed");
			return;
		}

		range = ospf6_route_lookup_bestmatch(&route->prefix,
						     oa->range_table);
		if (range) {
			ospf6_abr_range_update(range);
		}
	}

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa))
		ospf6_abr_originate_summary_to_area(route, oa);
}

void ospf6_abr_defaults_to_stub(struct ospf6 *o)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6_route *def, *route;

	if (!o->backbone)
		return;

	def = ospf6_route_create();
	def->type = OSPF6_DEST_TYPE_NETWORK;
	def->prefix.family = AF_INET6;
	def->prefix.prefixlen = 0;
	memset(&def->prefix.u.prefix6, 0, sizeof(struct in6_addr));
	def->type = OSPF6_DEST_TYPE_NETWORK;
	def->path.type = OSPF6_PATH_TYPE_INTER;
	def->path.subtype = OSPF6_PATH_SUBTYPE_DEFAULT_RT;
	def->path.area_id = o->backbone->area_id;

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
		if (!IS_AREA_STUB(oa)) {
			/* withdraw defaults when an area switches from stub to
			 * non-stub */
			route = ospf6_route_lookup(&def->prefix,
						   oa->summary_prefix);
			if (route
			    && (route->path.subtype == def->path.subtype)) {
				if (IS_OSPF6_DEBUG_ABR)
					zlog_debug(
						"Withdrawing default route from non-stubby area %s",
						oa->name);
				SET_FLAG(def->flag, OSPF6_ROUTE_REMOVE);
				ospf6_abr_originate_summary_to_area(def, oa);
			}
		} else {
			/* announce defaults to stubby areas */
			if (IS_OSPF6_DEBUG_ABR)
				zlog_debug(
					"Announcing default route into stubby area %s",
					oa->name);
			UNSET_FLAG(def->flag, OSPF6_ROUTE_REMOVE);
			ospf6_abr_originate_summary_to_area(def, oa);
		}
	}
	ospf6_route_delete(def);
}

void ospf6_abr_old_path_update(struct ospf6_route *old_route,
			       struct ospf6_route *route,
			       struct ospf6_route_table *table)
{
	struct ospf6_path *o_path = NULL;
	struct listnode *anode, *anext;
	struct listnode *nnode, *rnode, *rnext;
	struct ospf6_nexthop *nh, *rnh;

	for (ALL_LIST_ELEMENTS(old_route->paths, anode, anext, o_path)) {
		if (o_path->area_id != route->path.area_id ||
		    (memcmp(&(o_path)->origin, &(route)->path.origin,
			    sizeof(struct ospf6_ls_origin)) != 0))
			continue;

		if ((o_path->cost == route->path.cost) &&
		    (o_path->u.cost_e2 == route->path.u.cost_e2))
			continue;

		for (ALL_LIST_ELEMENTS_RO(o_path->nh_list, nnode, nh)) {
			for (ALL_LIST_ELEMENTS(old_route->nh_list, rnode,
					       rnext, rnh)) {
				if (!ospf6_nexthop_is_same(rnh, nh))
					continue;
				listnode_delete(old_route->nh_list, rnh);
				ospf6_nexthop_delete(rnh);
			}

		}

		listnode_delete(old_route->paths, o_path);
		ospf6_path_free(o_path);

		for (ALL_LIST_ELEMENTS(old_route->paths, anode,
				       anext, o_path)) {
			ospf6_merge_nexthops(old_route->nh_list,
					     o_path->nh_list);
		}

		if (IS_OSPF6_DEBUG_ABR || IS_OSPF6_DEBUG_EXAMIN(INTER_PREFIX))
			zlog_debug("%s: paths %u nh %u", __PRETTY_FUNCTION__,
				   old_route->paths ?
				   listcount(old_route->paths) : 0,
				   old_route->nh_list ?
				   listcount(old_route->nh_list) : 0);

		if (table->hook_add)
			(*table->hook_add)(old_route);

		if (old_route->path.origin.id == route->path.origin.id &&
		    old_route->path.origin.adv_router ==
		    route->path.origin.adv_router) {
			struct ospf6_path *h_path;

			h_path = (struct ospf6_path *)
			listgetdata(listhead(old_route->paths));
			old_route->path.origin.type = h_path->origin.type;
			old_route->path.origin.id = h_path->origin.id;
			old_route->path.origin.adv_router =
				h_path->origin.adv_router;
		}
	}
}

void ospf6_abr_old_route_remove(struct ospf6_lsa *lsa,
				struct ospf6_route *old,
				struct ospf6_route_table *table)
{
	if (listcount(old->paths) > 1) {
		struct listnode *anode, *anext, *nnode, *rnode, *rnext;
		struct ospf6_path *o_path;
		struct ospf6_nexthop *nh, *rnh;
		bool nh_updated = false;
		char buf[PREFIX2STR_BUFFER];

		for (ALL_LIST_ELEMENTS(old->paths, anode, anext, o_path)) {
			if (o_path->origin.adv_router != lsa->header->adv_router
			    && o_path->origin.id != lsa->header->id)
				continue;
			for (ALL_LIST_ELEMENTS_RO(o_path->nh_list, nnode, nh)) {
				for (ALL_LIST_ELEMENTS(old->nh_list,
							rnode, rnext, rnh)) {
					if (!ospf6_nexthop_is_same(rnh, nh))
						continue;
					listnode_delete(old->nh_list, rnh);
					ospf6_nexthop_delete(rnh);
				}
			}
			listnode_delete(old->paths, o_path);
			ospf6_path_free(o_path);
			nh_updated = true;
		}

		if (nh_updated) {
			if (listcount(old->paths)) {
				if (IS_OSPF6_DEBUG_ABR ||
				    IS_OSPF6_DEBUG_EXAMIN(INTER_PREFIX)) {
					prefix2str(&old->prefix, buf,
						   sizeof(buf));
					zlog_debug("%s: old %s updated nh %u",
						   __PRETTY_FUNCTION__, buf,
						   old->nh_list ?
						   listcount(old->nh_list) : 0);
				}

				if (table->hook_add)
					(*table->hook_add)(old);

				if ((old->path.origin.id == lsa->header->id) &&
				    (old->path.origin.adv_router
						 == lsa->header->adv_router)) {
					struct ospf6_path *h_path;

					h_path = (struct ospf6_path *)
						listgetdata(
							listhead(old->paths));
					old->path.origin.type =
						h_path->origin.type;
					old->path.origin.id = h_path->origin.id;
					old->path.origin.adv_router =
						h_path->origin.adv_router;
				}
			} else
				ospf6_route_remove(old, table);
		}
	} else
		ospf6_route_remove(old, table);

}

/* RFC 2328 16.2. Calculating the inter-area routes */
void ospf6_abr_examin_summary(struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
	struct prefix prefix, abr_prefix;
	struct ospf6_route_table *table = NULL;
	struct ospf6_route *range, *route, *old = NULL, *old_route;
	struct ospf6_route *abr_entry;
	uint8_t type = 0;
	char options[3] = {0, 0, 0};
	uint8_t prefix_options = 0;
	uint32_t cost = 0;
	uint8_t router_bits = 0;
	char buf[PREFIX2STR_BUFFER];
	int is_debug = 0;
	struct ospf6_inter_prefix_lsa *prefix_lsa = NULL;
	struct ospf6_inter_router_lsa *router_lsa = NULL;
	bool old_entry_updated = false;
	struct ospf6_path *path, *o_path, *ecmp_path;
	struct listnode *anode;
	char adv_router[16];

	memset(&prefix, 0, sizeof(prefix));

	if (lsa->header->type == htons(OSPF6_LSTYPE_INTER_PREFIX)) {
		if (IS_OSPF6_DEBUG_EXAMIN(INTER_PREFIX)) {
			is_debug++;
			zlog_debug("%s: Examin %s in area %s",
				   __PRETTY_FUNCTION__, lsa->name, oa->name);
		}

		prefix_lsa =
			(struct ospf6_inter_prefix_lsa *)OSPF6_LSA_HEADER_END(
				lsa->header);
		prefix.family = AF_INET6;
		prefix.prefixlen = prefix_lsa->prefix.prefix_length;
		ospf6_prefix_in6_addr(&prefix.u.prefix6, prefix_lsa,
				      &prefix_lsa->prefix);
		if (is_debug)
			prefix2str(&prefix, buf, sizeof(buf));
		table = oa->ospf6->route_table;
		type = OSPF6_DEST_TYPE_NETWORK;
		prefix_options = prefix_lsa->prefix.prefix_options;
		cost = OSPF6_ABR_SUMMARY_METRIC(prefix_lsa);
	} else if (lsa->header->type == htons(OSPF6_LSTYPE_INTER_ROUTER)) {
		if (IS_OSPF6_DEBUG_EXAMIN(INTER_ROUTER)) {
			is_debug++;
			zlog_debug("%s: Examin %s in area %s",
				   __PRETTY_FUNCTION__, lsa->name, oa->name);
		}

		router_lsa =
			(struct ospf6_inter_router_lsa *)OSPF6_LSA_HEADER_END(
				lsa->header);
		ospf6_linkstate_prefix(router_lsa->router_id, htonl(0),
				       &prefix);
		if (is_debug)
			inet_ntop(AF_INET, &router_lsa->router_id, buf,
				  sizeof(buf));

		table = oa->ospf6->brouter_table;
		type = OSPF6_DEST_TYPE_ROUTER;
		options[0] = router_lsa->options[0];
		options[1] = router_lsa->options[1];
		options[2] = router_lsa->options[2];
		cost = OSPF6_ABR_SUMMARY_METRIC(router_lsa);
		SET_FLAG(router_bits, OSPF6_ROUTER_BIT_E);
	} else
		assert(0);

	/* Find existing route */
	route = ospf6_route_lookup(&prefix, table);
	if (route)
		ospf6_route_lock(route);
	while (route && ospf6_route_is_prefix(&prefix, route)) {
		if (route->path.area_id == oa->area_id
		    && route->path.origin.type == lsa->header->type
		    && !CHECK_FLAG(route->flag, OSPF6_ROUTE_WAS_REMOVED)) {
			/* LSA adv. router could be part of route's
			 * paths list. Find the existing path and set
			 * old as the route.
			 */
			if (listcount(route->paths) > 1) {
				struct listnode *anode;
				struct ospf6_path *o_path;

				for (ALL_LIST_ELEMENTS_RO(route->paths, anode,
							  o_path)) {
					inet_ntop(AF_INET,
						  &o_path->origin.adv_router,
						  adv_router,
						  sizeof(adv_router));
					if (o_path->origin.id == lsa->header->id
					    && o_path->origin.adv_router ==
					    lsa->header->adv_router) {
						old = route;

						if (is_debug)
							zlog_debug("%s: old entry found in paths, adv_router %s",
							__PRETTY_FUNCTION__,
							adv_router);

						break;
					}
				}
			} else if (route->path.origin.id == lsa->header->id &&
				   route->path.origin.adv_router ==
				   lsa->header->adv_router)
				old = route;
		}
		route = ospf6_route_next(route);
	}
	if (route)
		ospf6_route_unlock(route);

	/* (1) if cost == LSInfinity or if the LSA is MaxAge */
	if (cost == OSPF_LS_INFINITY) {
		if (is_debug)
			zlog_debug("cost is LS_INFINITY, ignore");
		if (old)
			ospf6_abr_old_route_remove(lsa, old, table);
		return;
	}
	if (OSPF6_LSA_IS_MAXAGE(lsa)) {
		if (is_debug)
			zlog_debug("%s: LSA %s is MaxAge, ignore",
				   __PRETTY_FUNCTION__, lsa->name);
		if (old)
			ospf6_abr_old_route_remove(lsa, old, table);
		return;
	}

	/* (2) if the LSA is self-originated, ignore */
	if (lsa->header->adv_router == oa->ospf6->router_id) {
		if (is_debug)
			zlog_debug("LSA %s is self-originated, ignore",
				   lsa->name);
		if (old)
			ospf6_route_remove(old, table);
		return;
	}

	/* (3) if the prefix is equal to an active configured address range */
	/*     or if the NU bit is set in the prefix */
	if (lsa->header->type == htons(OSPF6_LSTYPE_INTER_PREFIX)) {
		/* must have been set in previous block */
		assert(prefix_lsa);

		range = ospf6_route_lookup(&prefix, oa->range_table);
		if (range) {
			if (is_debug)
				zlog_debug(
					"Prefix is equal to address range, ignore");
			if (old)
				ospf6_route_remove(old, table);
			return;
		}

		if (CHECK_FLAG(prefix_lsa->prefix.prefix_options,
			       OSPF6_PREFIX_OPTION_NU)
		    || CHECK_FLAG(prefix_lsa->prefix.prefix_options,
				  OSPF6_PREFIX_OPTION_LA)) {
			if (is_debug)
				zlog_debug("Prefix has NU/LA bit set, ignore");
			if (old)
				ospf6_route_remove(old, table);
			return;
		}
	}

	if (lsa->header->type == htons(OSPF6_LSTYPE_INTER_ROUTER)) {
		/* To pass test suites */
		if (!OSPF6_OPT_ISSET(router_lsa->options, OSPF6_OPT_R)
		    || !OSPF6_OPT_ISSET(router_lsa->options, OSPF6_OPT_V6)) {
			if (is_debug)
				zlog_debug("Prefix has NU/LA bit set, ignore");
			if (old)
				ospf6_route_remove(old, table);

			return;
		}
		/* Avoid infinite recursion if someone has maliciously announced
		   an
		   Inter-Router LSA for an ABR
		*/
		if (lsa->header->adv_router == router_lsa->router_id) {
			if (is_debug)
				zlog_debug(
					"Ignorning Inter-Router LSA for an ABR (%s)",
					buf);
			if (old)
				ospf6_route_remove(old, table);

			return;
		}
	}

	/* (4) if the routing table entry for the ABR does not exist */
	ospf6_linkstate_prefix(lsa->header->adv_router, htonl(0), &abr_prefix);
	abr_entry = ospf6_route_lookup(&abr_prefix, oa->ospf6->brouter_table);
	if (abr_entry == NULL || abr_entry->path.area_id != oa->area_id
	    || CHECK_FLAG(abr_entry->flag, OSPF6_ROUTE_REMOVE)
	    || !CHECK_FLAG(abr_entry->path.router_bits, OSPF6_ROUTER_BIT_B)) {
		if (is_debug)
			zlog_debug("%s: ABR router entry does not exist, ignore",
				   __PRETTY_FUNCTION__);
		if (old) {
			if (old->type == OSPF6_DEST_TYPE_ROUTER &&
			    oa->intra_brouter_calc) {
				if (is_debug)
					zlog_debug(
						   "%s: intra_brouter_calc is on, skip brouter remove: %s (%p)",
						   __PRETTY_FUNCTION__, buf,
						   (void *)old);
			} else {
				if (is_debug)
					zlog_debug("%s: remove old entry: %s %p ",
						   __PRETTY_FUNCTION__, buf,
						   (void *)old);
				ospf6_route_remove(old, table);
			}
		}
		return;
	}

	/* Check import list */
	if (IMPORT_NAME(oa)) {
		if (IMPORT_LIST(oa) == NULL)
			IMPORT_LIST(oa) =
				access_list_lookup(AFI_IP6, IMPORT_NAME(oa));

		if (IMPORT_LIST(oa))
			if (access_list_apply(IMPORT_LIST(oa), &prefix)
			    == FILTER_DENY) {
				if (is_debug)
					zlog_debug(
						"Prefix was denied by import-list");
				if (old)
					ospf6_route_remove(old, table);
				return;
			}
	}

	/* Check input prefix-list */
	if (PREFIX_LIST_IN(oa)) {
		if (prefix_list_apply(PREFIX_LIST_IN(oa), &prefix)
		    != PREFIX_PERMIT) {
			if (is_debug)
				zlog_debug("Prefix was denied by prefix-list");
			if (old)
				ospf6_route_remove(old, table);
			return;
		}
	}

	/* (5),(6): the path preference is handled by the sorting
	   in the routing table. Always install the path by substituting
	   old route (if any). */
	route = ospf6_route_create();

	route->type = type;
	route->prefix = prefix;
	route->path.origin.type = lsa->header->type;
	route->path.origin.id = lsa->header->id;
	route->path.origin.adv_router = lsa->header->adv_router;
	route->path.router_bits = router_bits;
	route->path.options[0] = options[0];
	route->path.options[1] = options[1];
	route->path.options[2] = options[2];
	route->path.prefix_options = prefix_options;
	route->path.area_id = oa->area_id;
	route->path.type = OSPF6_PATH_TYPE_INTER;
	route->path.cost = abr_entry->path.cost + cost;

	/* copy brouter rechable nexthops into the route. */
	ospf6_route_copy_nexthops(route, abr_entry);

	/* (7) If the routes are identical, copy the next hops over to existing
	   route. ospf6's route table implementation will otherwise string both
	   routes, but keep the older one as the best route since the routes
	   are identical.
	*/
	old = ospf6_route_lookup(&prefix, table);

	for (old_route = old; old_route; old_route = old_route->next) {
		if (!ospf6_route_is_same(old_route, route) ||
			(old_route->type != route->type) ||
			(old_route->path.type != route->path.type))
			continue;

		if ((ospf6_route_cmp(route, old_route) != 0)) {
			if (is_debug) {
				prefix2str(&prefix, buf, sizeof(buf));
				zlog_debug("%s: old %p %s cost %u new route cost %u are not same",
					   __PRETTY_FUNCTION__,
					   (void *)old_route, buf,
					   old_route->path.cost,
					   route->path.cost);
			}

			/* Check new route's adv. router is same in one of
			 * the paths with differed cost, if so remove the
			 * old path as later new route will be added.
			 */
			if (listcount(old_route->paths) > 1)
				ospf6_abr_old_path_update(old_route, route,
							  table);
			continue;
		}

		ospf6_route_merge_nexthops(old_route, route);
		old_entry_updated = true;

		for (ALL_LIST_ELEMENTS_RO(old_route->paths, anode,
						  o_path)) {
			if (o_path->area_id == route->path.area_id &&
			    (memcmp(&(o_path)->origin, &(route)->path.origin,
				    sizeof(struct ospf6_ls_origin)) == 0))
				break;
		}

		/* New adv. router for a existing path add to paths list */
		if (o_path == NULL) {
			ecmp_path = ospf6_path_dup(&route->path);

			/* Add a nh_list to new ecmp path */
			ospf6_copy_nexthops(ecmp_path->nh_list, route->nh_list);

			/* Add the new path to route's path list */
			listnode_add_sort(old_route->paths, ecmp_path);

			if (is_debug) {
				prefix2str(&route->prefix, buf, sizeof(buf));
				inet_ntop(AF_INET,
					  &ecmp_path->origin.adv_router,
					  adv_router, sizeof(adv_router));
				zlog_debug("%s: route %s cost %u another path %s added with nh %u, effective paths %u nh %u",
						__PRETTY_FUNCTION__, buf,
						old_route->path.cost,
						adv_router,
						listcount(ecmp_path->nh_list),
						old_route->paths ?
						listcount(old_route->paths) : 0,
						listcount(old_route->nh_list));
			}
		} else {
			/* adv. router exists in the list, update the nhs */
			list_delete_all_node(o_path->nh_list);
			ospf6_copy_nexthops(o_path->nh_list, route->nh_list);
		}

		if (is_debug)
			zlog_debug("%s: Update route: %s %p old cost %u new cost %u nh %u",
				   __PRETTY_FUNCTION__, buf, (void *)old_route,
				   old_route->path.cost, route->path.cost,
				   listcount(route->nh_list));

		/* For Inter-Prefix route: Update RIB/FIB,
		 * For Inter-Router trigger summary update
		 */
		if (table->hook_add)
			(*table->hook_add)(old_route);

		/* Delete new route */
		ospf6_route_delete(route);
		break;
	}

	if (old_entry_updated == false) {
		if (is_debug) {
			inet_ntop(AF_INET, &route->path.origin.adv_router,
				  adv_router, sizeof(adv_router));
			zlog_debug("%s: Install route: %s cost %u nh %u adv_router %s ",
				   __PRETTY_FUNCTION__, buf, route->path.cost,
				   listcount(route->nh_list), adv_router);
		}

		path = ospf6_path_dup(&route->path);
		ospf6_copy_nexthops(path->nh_list, abr_entry->nh_list);
		listnode_add_sort(route->paths, path);

		/* ospf6_ia_add_nw_route (table, &prefix, route); */
		ospf6_route_add(route, table);
	}
}

void ospf6_abr_examin_brouter(uint32_t router_id)
{
	struct ospf6_lsa *lsa;
	struct ospf6_area *oa;
	uint16_t type;

	if (ospf6_is_router_abr(ospf6))
		oa = ospf6->backbone;
	else
		oa = listgetdata(listhead(ospf6->area_list));

	/*
	 * It is possible to designate a non backbone
	 * area first.  If that is the case safely
	 * fall out of this function.
	 */
	if (oa == NULL)
		return;

	type = htons(OSPF6_LSTYPE_INTER_ROUTER);
	for (ALL_LSDB_TYPED_ADVRTR(oa->lsdb, type, router_id, lsa))
		ospf6_abr_examin_summary(lsa, oa);

	type = htons(OSPF6_LSTYPE_INTER_PREFIX);
	for (ALL_LSDB_TYPED_ADVRTR(oa->lsdb, type, router_id, lsa))
		ospf6_abr_examin_summary(lsa, oa);
}

void ospf6_abr_reimport(struct ospf6_area *oa)
{
	struct ospf6_lsa *lsa;
	uint16_t type;

	type = htons(OSPF6_LSTYPE_INTER_ROUTER);
	for (ALL_LSDB_TYPED(oa->lsdb, type, lsa))
		ospf6_abr_examin_summary(lsa, oa);

	type = htons(OSPF6_LSTYPE_INTER_PREFIX);
	for (ALL_LSDB_TYPED(oa->lsdb, type, lsa))
		ospf6_abr_examin_summary(lsa, oa);
}

void ospf6_abr_prefix_resummarize(struct ospf6 *o)
{
	struct ospf6_route *route;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Re-examining Inter-Prefix Summaries");

	for (route = ospf6_route_head(o->route_table); route;
	     route = ospf6_route_next(route))
		ospf6_abr_originate_summary(route);

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Finished re-examining Inter-Prefix Summaries");
}


/* Display functions */
static char *ospf6_inter_area_prefix_lsa_get_prefix_str(struct ospf6_lsa *lsa,
							char *buf, int buflen,
							int pos)
{
	struct ospf6_inter_prefix_lsa *prefix_lsa;
	struct in6_addr in6;

	if (lsa != NULL) {
		prefix_lsa =
			(struct ospf6_inter_prefix_lsa *)OSPF6_LSA_HEADER_END(
				lsa->header);

		ospf6_prefix_in6_addr(&in6, prefix_lsa, &prefix_lsa->prefix);
		if (buf) {
			inet_ntop(AF_INET6, &in6, buf, buflen);
			sprintf(&buf[strlen(buf)], "/%d",
				prefix_lsa->prefix.prefix_length);
		}
	}

	return (buf);
}

static int ospf6_inter_area_prefix_lsa_show(struct vty *vty,
					    struct ospf6_lsa *lsa)
{
	struct ospf6_inter_prefix_lsa *prefix_lsa;
	char buf[INET6_ADDRSTRLEN];

	prefix_lsa = (struct ospf6_inter_prefix_lsa *)OSPF6_LSA_HEADER_END(
		lsa->header);

	vty_out(vty, "     Metric: %lu\n",
		(unsigned long)OSPF6_ABR_SUMMARY_METRIC(prefix_lsa));

	ospf6_prefix_options_printbuf(prefix_lsa->prefix.prefix_options, buf,
				      sizeof(buf));
	vty_out(vty, "     Prefix Options: %s\n", buf);

	vty_out(vty, "     Prefix: %s\n",
		ospf6_inter_area_prefix_lsa_get_prefix_str(lsa, buf,
							   sizeof(buf), 0));

	return 0;
}

static char *ospf6_inter_area_router_lsa_get_prefix_str(struct ospf6_lsa *lsa,
							char *buf, int buflen,
							int pos)
{
	struct ospf6_inter_router_lsa *router_lsa;

	if (lsa != NULL) {
		router_lsa =
			(struct ospf6_inter_router_lsa *)OSPF6_LSA_HEADER_END(
				lsa->header);


		if (buf)
			inet_ntop(AF_INET, &router_lsa->router_id, buf, buflen);
	}

	return (buf);
}

static int ospf6_inter_area_router_lsa_show(struct vty *vty,
					    struct ospf6_lsa *lsa)
{
	struct ospf6_inter_router_lsa *router_lsa;
	char buf[64];

	router_lsa = (struct ospf6_inter_router_lsa *)OSPF6_LSA_HEADER_END(
		lsa->header);

	ospf6_options_printbuf(router_lsa->options, buf, sizeof(buf));
	vty_out(vty, "     Options: %s\n", buf);
	vty_out(vty, "     Metric: %lu\n",
		(unsigned long)OSPF6_ABR_SUMMARY_METRIC(router_lsa));

	inet_ntop(AF_INET, &router_lsa->router_id, buf, sizeof(buf));
	vty_out(vty, "     Destination Router ID: %s\n", buf);

	return 0;
}

/* Debug commands */
DEFUN (debug_ospf6_abr,
       debug_ospf6_abr_cmd,
       "debug ospf6 abr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
	OSPF6_DEBUG_ABR_ON();
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_abr,
       no_debug_ospf6_abr_cmd,
       "no debug ospf6 abr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ABR function\n"
      )
{
	OSPF6_DEBUG_ABR_OFF();
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_abr(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_ABR)
		vty_out(vty, "debug ospf6 abr\n");
	return 0;
}

void install_element_ospf6_debug_abr(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_abr_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_abr_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_abr_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_abr_cmd);
}

struct ospf6_lsa_handler inter_prefix_handler = {
	.lh_type = OSPF6_LSTYPE_INTER_PREFIX,
	.lh_name = "Inter-Prefix",
	.lh_short_name = "IAP",
	.lh_show = ospf6_inter_area_prefix_lsa_show,
	.lh_get_prefix_str = ospf6_inter_area_prefix_lsa_get_prefix_str,
	.lh_debug = 0};

struct ospf6_lsa_handler inter_router_handler = {
	.lh_type = OSPF6_LSTYPE_INTER_ROUTER,
	.lh_name = "Inter-Router",
	.lh_short_name = "IAR",
	.lh_show = ospf6_inter_area_router_lsa_show,
	.lh_get_prefix_str = ospf6_inter_area_router_lsa_get_prefix_str,
	.lh_debug = 0};

void ospf6_abr_init(void)
{
	ospf6_install_lsa_handler(&inter_prefix_handler);
	ospf6_install_lsa_handler(&inter_router_handler);
}
