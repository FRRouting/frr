/*
 * OSPF inter-area routing.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
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

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_dump.h"

static struct ospf_route *ospf_find_abr_route(struct route_table *rtrs,
					      struct prefix_ipv4 *abr,
					      struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct listnode *node;

	if ((rn = route_node_lookup(rtrs, (struct prefix *)abr)) == NULL)
		return NULL;

	route_unlock_node(rn);

	for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node, or))
		if (IPV4_ADDR_SAME(& or->u.std.area_id, &area->area_id)
		    && (or->u.std.flags & ROUTER_LSA_BORDER))
			return or ;

	return NULL;
}

static void ospf_ia_network_route(struct ospf *ospf, struct route_table *rt,
				  struct prefix_ipv4 *p,
				  struct ospf_route *new_or,
				  struct ospf_route *abr_or)
{
	struct route_node *rn1;
	struct ospf_route * or ;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: processing summary route to %pFX", __func__, p);

	/* Find a route to the same dest */
	if ((rn1 = route_node_lookup(rt, (struct prefix *)p))) {
		int res;

		route_unlock_node(rn1);

		if ((or = rn1->info)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: Found a route to the same network",
					__func__);
			/* Check the existing route. */
			if ((res = ospf_route_cmp(ospf, new_or, or)) < 0) {
				/* New route is better, so replace old one. */
				ospf_route_subst(rn1, new_or, abr_or);
			} else if (res == 0) {
				/* New and old route are equal, so next hops can
				 * be added. */
				route_lock_node(rn1);
				ospf_route_copy_nexthops(or, abr_or->paths);
				route_unlock_node(rn1);

				/* new route can be deleted, because existing
				 * route has been updated. */
				ospf_route_free(new_or);
			} else {
				/* New route is worse, so free it. */
				ospf_route_free(new_or);
				return;
			}
		} /* if (or)*/
	}	 /*if (rn1)*/
	else {    /* no route */
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: add new route to %pFX", __func__, p);
		ospf_route_add(rt, p, new_or, abr_or);
	}
}

static void ospf_ia_router_route(struct ospf *ospf, struct route_table *rtrs,
				 struct prefix_ipv4 *p,
				 struct ospf_route *new_or,
				 struct ospf_route *abr_or)
{
	struct ospf_route * or = NULL;
	struct route_node *rn;
	int ret;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: considering %pFX", __func__, p);

	/* Find a route to the same dest */
	rn = route_node_get(rtrs, (struct prefix *)p);

	if (rn->info == NULL)
		/* This is a new route */
		rn->info = list_new();
	else {
		struct ospf_area *or_area;
		or_area = ospf_area_lookup_by_area_id(ospf,
						      new_or->u.std.area_id);
		assert(or_area);
		/* This is an additional route */
		route_unlock_node(rn);
		or = ospf_find_asbr_route_through_area(rtrs, p, or_area);
	}

	if (or) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: a route to the same ABR through the same area exists",
				__func__);
		/* New route is better */
		if ((ret = ospf_route_cmp(ospf, new_or, or)) < 0) {
			listnode_delete(rn->info, or);
			ospf_route_free(or);
			/* proceed down */
		}
		/* Routes are the same */
		else if (ret == 0) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: merging the new route",
					   __func__);

			ospf_route_copy_nexthops(or, abr_or->paths);
			ospf_route_free(new_or);
			return;
		}
		/* New route is worse */
		else {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: skipping the new route",
					   __func__);
			ospf_route_free(new_or);
			return;
		}
	}

	ospf_route_copy_nexthops(new_or, abr_or->paths);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: adding the new route", __func__);

	listnode_add(rn->info, new_or);
}


static int process_summary_lsa(struct ospf_area *area, struct route_table *rt,
			       struct route_table *rtrs, struct ospf_lsa *lsa)
{
	struct ospf *ospf = area->ospf;
	struct ospf_area_range *range;
	struct ospf_route *abr_or, *new_or;
	struct summary_lsa *sl;
	struct prefix_ipv4 p, abr;
	uint32_t metric;

	if (lsa == NULL)
		return 0;

	sl = (struct summary_lsa *)lsa->data;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: LS ID: %pI4", __func__, &sl->header.id);

	metric = GET_METRIC(sl->metric);

	if (metric == OSPF_LS_INFINITY)
		return 0;

	if (IS_LSA_MAXAGE(lsa))
		return 0;

	if (ospf_lsa_is_self_originated(area->ospf, lsa))
		return 0;

	p.family = AF_INET;
	p.prefix = sl->header.id;

	if (sl->header.type == OSPF_SUMMARY_LSA)
		p.prefixlen = ip_masklen(sl->mask);
	else
		p.prefixlen = IPV4_MAX_BITLEN;

	apply_mask_ipv4(&p);

	if (sl->header.type == OSPF_SUMMARY_LSA
	    && (range = ospf_area_range_match_any(ospf, &p))
	    && ospf_area_range_active(range))
		return 0;

	/* XXX: This check seems dubious to me. If an ABR has already decided
	 * to consider summaries received in this area, then why would one wish
	 * to exclude default?
	 */
	if (IS_OSPF_ABR(ospf) && ospf->abr_type != OSPF_ABR_STAND
	    && area->external_routing != OSPF_AREA_DEFAULT
	    && p.prefix.s_addr == OSPF_DEFAULT_DESTINATION && p.prefixlen == 0)
		return 0; /* Ignore summary default from a stub area */

	abr.family = AF_INET;
	abr.prefix = sl->header.adv_router;
	abr.prefixlen = IPV4_MAX_BITLEN;
	apply_mask_ipv4(&abr);

	abr_or = ospf_find_abr_route(rtrs, &abr, area);

	if (abr_or == NULL)
		return 0;

	new_or = ospf_route_new();
	new_or->type = OSPF_DESTINATION_NETWORK;
	new_or->id = sl->header.id;
	new_or->mask = sl->mask;
	new_or->u.std.options = sl->header.options;
	new_or->u.std.origin = (struct lsa_header *)sl;
	new_or->cost = abr_or->cost + metric;
	new_or->u.std.area_id = area->area_id;
	new_or->u.std.external_routing = area->external_routing;
	new_or->path_type = OSPF_PATH_INTER_AREA;

	if (sl->header.type == OSPF_SUMMARY_LSA)
		ospf_ia_network_route(ospf, rt, &p, new_or, abr_or);
	else {
		new_or->type = OSPF_DESTINATION_ROUTER;
		new_or->u.std.flags = ROUTER_LSA_EXTERNAL;
		ospf_ia_router_route(ospf, rtrs, &p, new_or, abr_or);
	}

	return 0;
}

static void ospf_examine_summaries(struct ospf_area *area,
				   struct route_table *lsdb_rt,
				   struct route_table *rt,
				   struct route_table *rtrs)
{
	struct ospf_lsa *lsa;
	struct route_node *rn;

	LSDB_LOOP (lsdb_rt, rn, lsa)
		process_summary_lsa(area, rt, rtrs, lsa);
}

int ospf_area_is_transit(struct ospf_area *area)
{
	return (area->transit == OSPF_TRANSIT_TRUE)
	       || ospf_full_virtual_nbrs(
			  area); /* Cisco forgets to set the V-bit :( */
}

static void ospf_update_network_route(struct ospf *ospf, struct route_table *rt,
				      struct route_table *rtrs,
				      struct summary_lsa *lsa,
				      struct prefix_ipv4 *p,
				      struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_route * or, *abr_or, *new_or;
	struct prefix_ipv4 abr;
	uint32_t cost;

	abr.family = AF_INET;
	abr.prefix = lsa->header.adv_router;
	abr.prefixlen = IPV4_MAX_BITLEN;
	apply_mask_ipv4(&abr);

	abr_or = ospf_find_abr_route(rtrs, &abr, area);

	if (abr_or == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: can't find a route to the ABR",
				   __func__);
		return;
	}

	cost = abr_or->cost + GET_METRIC(lsa->metric);

	rn = route_node_lookup(rt, (struct prefix *)p);

	if (!rn) {
		if (ospf->abr_type != OSPF_ABR_SHORTCUT)
			return; /* Standard ABR can update only already
				   installed
				   backbone paths */
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Allowing Shortcut ABR to add new route",
				   __func__);
		new_or = ospf_route_new();
		new_or->type = OSPF_DESTINATION_NETWORK;
		new_or->id = lsa->header.id;
		new_or->mask = lsa->mask;
		new_or->u.std.options = lsa->header.options;
		new_or->u.std.origin = (struct lsa_header *)lsa;
		new_or->cost = cost;
		new_or->u.std.area_id = area->area_id;
		new_or->u.std.external_routing = area->external_routing;
		new_or->path_type = OSPF_PATH_INTER_AREA;
		ospf_route_add(rt, p, new_or, abr_or);

		return;
	} else {
		route_unlock_node(rn);
		if (rn->info == NULL)
			return;
	}

	or = rn->info;

	if (or->path_type != OSPF_PATH_INTRA_AREA &&
	    or->path_type != OSPF_PATH_INTER_AREA) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: ERR: path type is wrong", __func__);
		return;
	}

	if (ospf->abr_type == OSPF_ABR_SHORTCUT) {
		if (
			or->path_type == OSPF_PATH_INTRA_AREA
				  && !OSPF_IS_AREA_ID_BACKBONE(
					     or->u.std.area_id)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: Shortcut: this intra-area path is not backbone",
					__func__);
			return;
		}
	} else /* Not Shortcut ABR */
	{
		if (!OSPF_IS_AREA_ID_BACKBONE(or->u.std.area_id)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: route is not BB-associated",
					   __func__);
			return; /* We can update only BB routes */
		}
	}

	if (or->cost < cost) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: new route is worse", __func__);
		return;
	}

	if (or->cost == cost) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: new route is same distance, adding nexthops",
				__func__);
		ospf_route_copy_nexthops(or, abr_or->paths);
	}

	if (or->cost > cost) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: new route is better, overriding nexthops",
				__func__);
		ospf_route_subst_nexthops(or, abr_or->paths);
		or->cost = cost;

		if ((ospf->abr_type == OSPF_ABR_SHORTCUT)
		    && !OSPF_IS_AREA_ID_BACKBONE(or->u.std.area_id)) {
			or->path_type = OSPF_PATH_INTER_AREA;
			or->u.std.area_id = area->area_id;
			or->u.std.external_routing = area->external_routing;
			/* Note that we can do this only in Shortcut ABR mode,
			   because standard ABR must leave the route type and
			   area
			   unchanged
			*/
		}
	}
}

static void ospf_update_router_route(struct ospf *ospf,
				     struct route_table *rtrs,
				     struct summary_lsa *lsa,
				     struct prefix_ipv4 *p,
				     struct ospf_area *area)
{
	struct ospf_route * or, *abr_or, *new_or;
	struct prefix_ipv4 abr;
	uint32_t cost;

	abr.family = AF_INET;
	abr.prefix = lsa->header.adv_router;
	abr.prefixlen = IPV4_MAX_BITLEN;
	apply_mask_ipv4(&abr);

	abr_or = ospf_find_abr_route(rtrs, &abr, area);

	if (abr_or == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: can't find a route to the ABR",
				   __func__);
		return;
	}

	cost = abr_or->cost + GET_METRIC(lsa->metric);

	/* First try to find a backbone path,
	   because standard ABR can update only BB-associated paths */

	if ((ospf->backbone == NULL) && (ospf->abr_type != OSPF_ABR_SHORTCUT))
		return; /* no BB area, not Shortcut ABR, exiting */

	/* find the backbone route, if possible */
	if ((ospf->backbone == NULL)
	    || !(or = ospf_find_asbr_route_through_area(rtrs, p,
							ospf->backbone))) {
		if (ospf->abr_type != OSPF_ABR_SHORTCUT)

			/* route to ASBR through the BB not found
			   the router is not Shortcut ABR, exiting */

			return;
		else
		/* We're a Shortcut ABR*/
		{
			/* Let it either add a new router or update the route
			   through the same (non-BB) area. */

			new_or = ospf_route_new();
			new_or->type = OSPF_DESTINATION_ROUTER;
			new_or->id = lsa->header.id;
			new_or->mask = lsa->mask;
			new_or->u.std.options = lsa->header.options;
			new_or->u.std.origin = (struct lsa_header *)lsa;
			new_or->cost = cost;
			new_or->u.std.area_id = area->area_id;
			new_or->u.std.external_routing = area->external_routing;
			new_or->path_type = OSPF_PATH_INTER_AREA;
			new_or->u.std.flags = ROUTER_LSA_EXTERNAL;
			ospf_ia_router_route(ospf, rtrs, p, new_or, abr_or);

			return;
		}
	}

	/* At this point the "or" is always bb-associated */

	if (!(or->u.std.flags & ROUTER_LSA_EXTERNAL)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: the remote router is not an ASBR",
				   __func__);
		return;
	}

	if (or->path_type != OSPF_PATH_INTRA_AREA &&
	    or->path_type != OSPF_PATH_INTER_AREA)
		return;

	if (or->cost < cost)
		return;

	else if (or->cost == cost)
		ospf_route_copy_nexthops(or, abr_or->paths);

	else if (or->cost > cost) {
		ospf_route_subst_nexthops(or, abr_or->paths);
		or->cost = cost;

		/* Even if the ABR runs in Shortcut mode, we can't change
		   the path type and area, because the "or" is always
		   bb-associated
		   at this point and even Shortcut ABR can't change these
		   attributes */
	}
}

static int process_transit_summary_lsa(struct ospf_area *area,
				       struct route_table *rt,
				       struct route_table *rtrs,
				       struct ospf_lsa *lsa)
{
	struct ospf *ospf = area->ospf;
	struct summary_lsa *sl;
	struct prefix_ipv4 p;
	uint32_t metric;

	if (lsa == NULL)
		return 0;

	sl = (struct summary_lsa *)lsa->data;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: LS ID: %pI4", __func__, &lsa->data->id);
	metric = GET_METRIC(sl->metric);

	if (metric == OSPF_LS_INFINITY) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: metric is infinity, skip", __func__);
		return 0;
	}

	if (IS_LSA_MAXAGE(lsa)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: This LSA is too old", __func__);
		return 0;
	}

	if (ospf_lsa_is_self_originated(area->ospf, lsa)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: This LSA is mine, skip", __func__);
		return 0;
	}

	p.family = AF_INET;
	p.prefix = sl->header.id;

	if (sl->header.type == OSPF_SUMMARY_LSA)
		p.prefixlen = ip_masklen(sl->mask);
	else
		p.prefixlen = IPV4_MAX_BITLEN;

	apply_mask_ipv4(&p);

	if (sl->header.type == OSPF_SUMMARY_LSA)
		ospf_update_network_route(ospf, rt, rtrs, sl, &p, area);
	else
		ospf_update_router_route(ospf, rtrs, sl, &p, area);

	return 0;
}

static void ospf_examine_transit_summaries(struct ospf_area *area,
					   struct route_table *lsdb_rt,
					   struct route_table *rt,
					   struct route_table *rtrs)
{
	struct ospf_lsa *lsa;
	struct route_node *rn;

	LSDB_LOOP (lsdb_rt, rn, lsa)
		process_transit_summary_lsa(area, rt, rtrs, lsa);
}

void ospf_ia_routing(struct ospf *ospf, struct route_table *rt,
		     struct route_table *rtrs)
{
	struct listnode *node;
	struct ospf_area *area;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s:start", __func__);

	if (IS_OSPF_ABR(ospf)) {
		switch (ospf->abr_type) {
		case OSPF_ABR_STAND:
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s:Standard ABR", __func__);

			if ((area = ospf->backbone)) {
				if (IS_DEBUG_OSPF_EVENT) {
					zlog_debug(
						"%s:backbone area found, examining summaries",
						__func__);
				}

				OSPF_EXAMINE_SUMMARIES_ALL(area, rt, rtrs);

				for (ALL_LIST_ELEMENTS_RO(ospf->areas, node,
							  area))
					if (area != ospf->backbone)
						if (ospf_area_is_transit(area))
							OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL(
								area, rt, rtrs);
			} else if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s:backbone area NOT found",
					   __func__);
			break;
		case OSPF_ABR_IBM:
		case OSPF_ABR_CISCO:
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s:Alternative Cisco/IBM ABR",
					   __func__);
			area = ospf->backbone; /* Find the BB */

			/* If we have an active BB connection */
			if (area && ospf_act_bb_connection(ospf)) {
				if (IS_DEBUG_OSPF_EVENT) {
					zlog_debug(
						"%s: backbone area found, examining BB summaries",
						__func__);
				}

				OSPF_EXAMINE_SUMMARIES_ALL(area, rt, rtrs);

				for (ALL_LIST_ELEMENTS_RO(ospf->areas, node,
							  area))
					if (area != ospf->backbone)
						if (ospf_area_is_transit(area))
							OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL(
								area, rt, rtrs);
			} else { /* No active BB connection--consider all areas
				    */
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: Active BB connection not found",
						__func__);
				for (ALL_LIST_ELEMENTS_RO(ospf->areas, node,
							  area))
					OSPF_EXAMINE_SUMMARIES_ALL(area, rt,
								   rtrs);
			}
			break;
		case OSPF_ABR_SHORTCUT:
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s:Alternative Shortcut", __func__);
			area = ospf->backbone; /* Find the BB */

			/* If we have an active BB connection */
			if (area && ospf_act_bb_connection(ospf)) {
				if (IS_DEBUG_OSPF_EVENT) {
					zlog_debug(
						"%s: backbone area found, examining BB summaries",
						__func__);
				}
				OSPF_EXAMINE_SUMMARIES_ALL(area, rt, rtrs);
			}

			for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
				if (area != ospf->backbone)
					if (ospf_area_is_transit(area)
					    || ((area->shortcut_configured
						 != OSPF_SHORTCUT_DISABLE)
						&& ((ospf->backbone == NULL)
						    || ((area->shortcut_configured
							 == OSPF_SHORTCUT_ENABLE)
							&& area->shortcut_capability))))
						OSPF_EXAMINE_TRANSIT_SUMMARIES_ALL(
							area, rt, rtrs);
			break;
		default:
			break;
		}
	} else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s:not ABR, considering all areas",
				   __func__);

		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
			OSPF_EXAMINE_SUMMARIES_ALL(area, rt, rtrs);
	}
}
