// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF ABR functions.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
 */


#include <zebra.h>

#include "frrevent.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
#include "plist.h"
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
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_errors.h"

static struct ospf_area_range *ospf_area_range_new(struct prefix_ipv4 *p)
{
	struct ospf_area_range *range;

	range = XCALLOC(MTYPE_OSPF_AREA_RANGE, sizeof(struct ospf_area_range));
	range->addr = p->prefix;
	range->masklen = p->prefixlen;
	range->cost_config = OSPF_AREA_RANGE_COST_UNSPEC;

	return range;
}

static void ospf_area_range_free(struct ospf_area_range *range)
{
	XFREE(MTYPE_OSPF_AREA_RANGE, range);
}

static void ospf_area_range_add(struct ospf_area *area,
				struct route_table *ranges,
				struct ospf_area_range *range)
{
	struct route_node *rn;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefixlen = range->masklen;
	p.prefix = range->addr;
	apply_mask_ipv4(&p);

	rn = route_node_get(ranges, (struct prefix *)&p);
	if (rn->info) {
		route_unlock_node(rn);
		ospf_area_range_free(rn->info);
		rn->info = range;
	} else
		rn->info = range;
}

static void ospf_area_range_delete(struct ospf_area *area,
				   struct route_node *rn)
{
	struct ospf_area_range *range = rn->info;
	bool nssa = CHECK_FLAG(range->flags, OSPF_AREA_RANGE_NSSA);

	if (ospf_area_range_active(range) &&
	    CHECK_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE))
		ospf_delete_discard_route(area->ospf, area->ospf->new_table,
					  (struct prefix_ipv4 *)&rn->p, nssa);

	ospf_area_range_free(range);
	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);
}

struct ospf_area_range *ospf_area_range_lookup(struct ospf_area *area,
					       struct route_table *ranges,
					       struct prefix_ipv4 *p)
{
	struct route_node *rn;

	rn = route_node_lookup(ranges, (struct prefix *)p);
	if (rn) {
		route_unlock_node(rn);
		return rn->info;
	}
	return NULL;
}

struct ospf_area_range *ospf_area_range_lookup_next(struct ospf_area *area,
						    struct in_addr *range_net,
						    int first)
{
	struct route_node *rn;
	struct prefix_ipv4 p;
	struct ospf_area_range *find;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = *range_net;
	apply_mask_ipv4(&p);

	if (first)
		rn = route_top(area->ranges);
	else {
		rn = route_node_get(area->ranges, (struct prefix *)&p);
		rn = route_next(rn);
	}

	for (; rn; rn = route_next(rn))
		if (rn->info)
			break;

	if (rn && rn->info) {
		find = rn->info;
		*range_net = rn->p.u.prefix4;
		route_unlock_node(rn);
		return find;
	}
	return NULL;
}

static struct ospf_area_range *ospf_area_range_match(struct ospf_area *area,
						     struct route_table *ranges,
						     struct prefix_ipv4 *p)
{
	struct route_node *node;

	node = route_node_match(ranges, (struct prefix *)p);
	if (node) {
		route_unlock_node(node);
		return node->info;
	}
	return NULL;
}

struct ospf_area_range *ospf_area_range_match_any(struct ospf *ospf,
						  struct prefix_ipv4 *p)
{
	struct ospf_area_range *range;
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if ((range = ospf_area_range_match(area, area->ranges, p)))
			return range;

	return NULL;
}

int ospf_area_range_active(struct ospf_area_range *range)
{
	return range->specifics;
}

static int ospf_area_actively_attached(struct ospf_area *area)
{
	return area->act_ints;
}

int ospf_area_range_set(struct ospf *ospf, struct ospf_area *area,
			struct route_table *ranges, struct prefix_ipv4 *p,
			int advertise, bool nssa)
{
	struct ospf_area_range *range;

	range = ospf_area_range_lookup(area, ranges, p);
	if (range != NULL) {
		if (!CHECK_FLAG(advertise, OSPF_AREA_RANGE_ADVERTISE))
			range->cost_config = OSPF_AREA_RANGE_COST_UNSPEC;
		if ((CHECK_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE)
		     && !CHECK_FLAG(advertise, OSPF_AREA_RANGE_ADVERTISE))
		    || (!CHECK_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE)
			&& CHECK_FLAG(advertise, OSPF_AREA_RANGE_ADVERTISE)))
			ospf_schedule_abr_task(ospf);
	} else {
		range = ospf_area_range_new(p);
		ospf_area_range_add(area, ranges, range);
		ospf_schedule_abr_task(ospf);
	}

	if (CHECK_FLAG(advertise, OSPF_AREA_RANGE_ADVERTISE))
		SET_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE);
	else {
		UNSET_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE);
		range->cost_config = OSPF_AREA_RANGE_COST_UNSPEC;
	}

	if (nssa)
		SET_FLAG(range->flags, OSPF_AREA_RANGE_NSSA);

	return 1;
}

int ospf_area_range_cost_set(struct ospf *ospf, struct ospf_area *area,
			     struct route_table *ranges, struct prefix_ipv4 *p,
			     uint32_t cost)
{
	struct ospf_area_range *range;

	range = ospf_area_range_lookup(area, ranges, p);
	if (range == NULL)
		return 0;

	if (range->cost_config != cost) {
		range->cost_config = cost;
		if (ospf_area_range_active(range))
			ospf_schedule_abr_task(ospf);
	}

	return 1;
}

int ospf_area_range_unset(struct ospf *ospf, struct ospf_area *area,
			  struct route_table *ranges, struct prefix_ipv4 *p)
{
	struct route_node *rn;

	rn = route_node_lookup(ranges, (struct prefix *)p);
	if (rn == NULL)
		return 0;

	if (ospf_area_range_active(rn->info))
		ospf_schedule_abr_task(ospf);

	ospf_area_range_delete(area, rn);

	return 1;
}

int ospf_area_range_substitute_set(struct ospf *ospf, struct ospf_area *area,
				   struct prefix_ipv4 *p, struct prefix_ipv4 *s)
{
	struct ospf_area_range *range;

	range = ospf_area_range_lookup(area, area->ranges, p);

	if (range != NULL) {
		if (!CHECK_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE)
		    || !CHECK_FLAG(range->flags, OSPF_AREA_RANGE_SUBSTITUTE))
			ospf_schedule_abr_task(ospf);
	} else {
		range = ospf_area_range_new(p);
		ospf_area_range_add(area, area->ranges, range);
		ospf_schedule_abr_task(ospf);
	}

	SET_FLAG(range->flags, OSPF_AREA_RANGE_ADVERTISE);
	SET_FLAG(range->flags, OSPF_AREA_RANGE_SUBSTITUTE);
	range->subst_addr = s->prefix;
	range->subst_masklen = s->prefixlen;

	return 1;
}

int ospf_area_range_substitute_unset(struct ospf *ospf, struct ospf_area *area,
				     struct prefix_ipv4 *p)
{
	struct ospf_area_range *range;

	range = ospf_area_range_lookup(area, area->ranges, p);
	if (range == NULL)
		return 0;

	if (CHECK_FLAG(range->flags, OSPF_AREA_RANGE_SUBSTITUTE))
		if (ospf_area_range_active(range))
			ospf_schedule_abr_task(ospf);

	UNSET_FLAG(range->flags, OSPF_AREA_RANGE_SUBSTITUTE);
	range->subst_addr.s_addr = INADDR_ANY;
	range->subst_masklen = 0;

	return 1;
}

int ospf_act_bb_connection(struct ospf *ospf)
{
	struct ospf_interface *oi;
	struct listnode *node;
	int full_nbrs = 0;

	if (ospf->backbone == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->backbone->oiflist, node, oi)) {
		struct ospf_neighbor *nbr;
		struct route_node *rn;

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if (!nbr)
				continue;

			if (nbr->state == NSM_Full
			    || OSPF_GR_IS_ACTIVE_HELPER(nbr))
				full_nbrs++;
		}
	}

	return full_nbrs;
}

/* Determine whether this router is elected translator or not for area */
static int ospf_abr_nssa_am_elected(struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;
	struct router_lsa *rlsa;
	struct in_addr *best = NULL;

	LSDB_LOOP (ROUTER_LSDB(area), rn, lsa) {
		/* sanity checks */
		if (!lsa || (lsa->data->type != OSPF_ROUTER_LSA)
		    || IS_LSA_SELF(lsa))
			continue;

		rlsa = (struct router_lsa *)lsa->data;

		/* ignore non-ABR routers */
		if (!IS_ROUTER_LSA_BORDER(rlsa))
			continue;

		/* Router has Nt flag - always translate */
		if (IS_ROUTER_LSA_NT(rlsa)) {
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug("%s: router %pI4 asserts Nt",
					   __func__, &lsa->data->id);
			return 0;
		}

		if (best == NULL)
			best = &lsa->data->id;
		else if (IPV4_ADDR_CMP(&best->s_addr, &lsa->data->id.s_addr)
			 < 0)
			best = &lsa->data->id;
	}

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: best electable ABR is: %pI4", __func__, best);

	if (best == NULL)
		return 1;

	if (IPV4_ADDR_CMP(&best->s_addr, &area->ospf->router_id.s_addr) < 0)
		return 1;
	else
		return 0;
}

/* Check NSSA ABR status
 * assumes there are nssa areas
 */
void ospf_abr_nssa_check_status(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *lnode, *nnode;

	for (ALL_LIST_ELEMENTS(ospf->areas, lnode, nnode, area)) {
		uint8_t old_state = area->NSSATranslatorState;

		if (area->external_routing != OSPF_AREA_NSSA)
			continue;

		if (IS_DEBUG_OSPF(nssa, NSSA))
			zlog_debug("%s: checking area %pI4", __func__,
				   &area->area_id);

		if (!IS_OSPF_ABR(area->ospf)) {
			if (IS_DEBUG_OSPF(nssa, NSSA))
				zlog_debug("%s: not ABR", __func__);
			area->NSSATranslatorState =
				OSPF_NSSA_TRANSLATE_DISABLED;
		} else {
			switch (area->NSSATranslatorRole) {
			case OSPF_NSSA_ROLE_NEVER:
				/* We never Translate Type-7 LSA. */
				/* TODO: check previous state and flush? */
				if (IS_DEBUG_OSPF(nssa, NSSA))
					zlog_debug("%s: never translate",
						   __func__);
				area->NSSATranslatorState =
					OSPF_NSSA_TRANSLATE_DISABLED;
				break;

			case OSPF_NSSA_ROLE_ALWAYS:
				/* We always translate if we are an ABR
				 * TODO: originate new LSAs if state change?
				 * or let the nssa abr task take care of it?
				 */
				if (IS_DEBUG_OSPF(nssa, NSSA))
					zlog_debug("%s: translate always",
						   __func__);
				area->NSSATranslatorState =
					OSPF_NSSA_TRANSLATE_ENABLED;
				break;

			case OSPF_NSSA_ROLE_CANDIDATE:
				/* We are a candidate for Translation */
				if (ospf_abr_nssa_am_elected(area) > 0) {
					area->NSSATranslatorState =
						OSPF_NSSA_TRANSLATE_ENABLED;
					if (IS_DEBUG_OSPF(nssa, NSSA))
						zlog_debug(
							"%s: elected translator",
							__func__);
				} else {
					area->NSSATranslatorState =
						OSPF_NSSA_TRANSLATE_DISABLED;
					if (IS_DEBUG_OSPF(nssa, NSSA))
						zlog_debug("%s: not elected",
							   __func__);
				}
				break;
			}
		}
		/* RFC3101, 3.1:
		 * All NSSA border routers must set the E-bit in the Type-1
		 * router-LSAs
		 * of their directly attached non-stub areas, even when they are
		 * not
		 * translating.
		 */
		if (old_state != area->NSSATranslatorState) {
			if (old_state == OSPF_NSSA_TRANSLATE_DISABLED)
				ospf_asbr_status_update(ospf,
							++ospf->redistribute);
			else if (area->NSSATranslatorState
				 == OSPF_NSSA_TRANSLATE_DISABLED)
				ospf_asbr_status_update(ospf,
							--ospf->redistribute);
		}
	}
}

/* Check area border router status. */
void ospf_check_abr_status(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *node, *nnode;
	int bb_configured = 0;
	int bb_act_attached = 0;
	int areas_configured = 0;
	int areas_act_attached = 0;
	uint8_t new_flags = ospf->flags;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		if (listcount(area->oiflist)) {
			areas_configured++;

			if (OSPF_IS_AREA_BACKBONE(area))
				bb_configured = 1;
		}

		if (ospf_area_actively_attached(area)) {
			areas_act_attached++;

			if (OSPF_IS_AREA_BACKBONE(area))
				bb_act_attached = 1;
		}
	}

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug("%s: looked through areas", __func__);
		zlog_debug("%s: bb_configured: %d", __func__, bb_configured);
		zlog_debug("%s: bb_act_attached: %d", __func__,
			   bb_act_attached);
		zlog_debug("%s: areas_configured: %d", __func__,
			   areas_configured);
		zlog_debug("%s: areas_act_attached: %d", __func__,
			   areas_act_attached);
	}

	switch (ospf->abr_type) {
	case OSPF_ABR_SHORTCUT:
	case OSPF_ABR_STAND:
		if (areas_act_attached > 1)
			SET_FLAG(new_flags, OSPF_FLAG_ABR);
		else
			UNSET_FLAG(new_flags, OSPF_FLAG_ABR);
		break;

	case OSPF_ABR_IBM:
		if ((areas_act_attached > 1) && bb_configured)
			SET_FLAG(new_flags, OSPF_FLAG_ABR);
		else
			UNSET_FLAG(new_flags, OSPF_FLAG_ABR);
		break;

	case OSPF_ABR_CISCO:
		if ((areas_configured > 1) && bb_act_attached)
			SET_FLAG(new_flags, OSPF_FLAG_ABR);
		else
			UNSET_FLAG(new_flags, OSPF_FLAG_ABR);
		break;
	default:
		break;
	}

	if (new_flags != ospf->flags) {
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_ABR_STATUS_CHANGE);
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: new router flags: %x", __func__,
				   new_flags);
		ospf->flags = new_flags;
		ospf_router_lsa_update(ospf);
	}
}

static void ospf_abr_update_aggregate(struct ospf_area_range *range,
				      uint32_t cost, struct ospf_area *area)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	if (CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED)
	    && (range->cost != OSPF_STUB_MAX_METRIC_SUMMARY_COST)) {
		range->cost = OSPF_STUB_MAX_METRIC_SUMMARY_COST;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: use summary max-metric 0x%08x",
				   __func__, range->cost);
	} else if (range->cost_config != OSPF_AREA_RANGE_COST_UNSPEC) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: use configured cost %d", __func__,
				   range->cost_config);

		range->cost = range->cost_config;
	} else {
		if (!ospf_area_range_active(range)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: use cost %d", __func__, cost);

			range->cost = cost; /* 1st time get 1st cost */
		}

		if (cost > range->cost) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: update to %d", __func__, cost);

			range->cost = cost;
		}
	}

	range->specifics++;
}

static void set_metric(struct ospf_lsa *lsa, uint32_t metric)
{
	struct summary_lsa *header;
	uint8_t *mp;
	metric = htonl(metric);
	mp = (uint8_t *)&metric;
	mp++;
	header = (struct summary_lsa *)lsa->data;
	memcpy(header->metric, mp, 3);
}

/* ospf_abr_translate_nssa */
static int ospf_abr_translate_nssa(struct ospf_area *area, struct ospf_lsa *lsa)
{
	/* Incoming Type-7 or later aggregated Type-7
	 *
	 * LSA is skipped if P-bit is off.
	 * LSA is aggregated if within range.
	 *
	 * The Type-7 is translated, Installed/Approved as a Type-5 into
	 * global LSDB, then Flooded through AS
	 *
	 *  Later, any Unapproved Translated Type-5's are flushed/discarded
	 */

	struct ospf_lsa *old = NULL, *new = NULL;
	struct as_external_lsa *ext7;
	struct prefix_ipv4 p;
	struct ospf_area_range *range;

	if (!CHECK_FLAG(lsa->data->options, OSPF_OPTION_NP)) {
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("%s: LSA Id %pI4, P-bit off, NO Translation",
				   __func__, &lsa->data->id);
		return 1;
	}

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: LSA Id %pI4, TRANSLATING 7 to 5", __func__,
			   &lsa->data->id);

	ext7 = (struct as_external_lsa *)(lsa->data);
	p.prefix = lsa->data->id;
	p.prefixlen = ip_masklen(ext7->mask);

	if (ext7->e[0].fwd_addr.s_addr == OSPF_DEFAULT_DESTINATION) {
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug(
				"%s: LSA Id %pI4, Forward address is 0, NO Translation",
				__func__, &lsa->data->id);
		return 1;
	}

	/* try find existing AS-External LSA for this prefix */
	old = ospf_external_info_find_lsa(area->ospf, &p);

	if (CHECK_FLAG(lsa->flags, OSPF_LSA_IN_MAXAGE)) {
		/* if type-7 is removed, remove old translated type-5 lsa */
		if (old) {
			UNSET_FLAG(old->flags, OSPF_LSA_APPROVED);
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug(
					"%s: remove old translated LSA id %pI4",
					__func__, &old->data->id);
		}
		/* if type-7 is removed and type-5 does not exist, do not
		 * originate */
		return 1;
	}

	range = ospf_area_range_match(area, area->nssa_ranges, &p);
	if (range) {
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("Suppressed by range %pI4/%u of area %pI4",
				   &range->addr, range->masklen,
				   &area->area_id);

		ospf_abr_update_aggregate(range, GET_METRIC(ext7->e[0].metric),
					  area);
		return 1;
	}

	if (old && CHECK_FLAG(old->flags, OSPF_LSA_APPROVED)) {
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug(
				"%s: found old translated LSA Id %pI4, refreshing",
				__func__, &old->data->id);

		/* refresh */
		new = ospf_translated_nssa_refresh(area->ospf, lsa, old);
		if (!new) {
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug(
					"%s: could not refresh translated LSA Id %pI4",
					__func__, &old->data->id);
		}
	} else {
		/* no existing external route for this LSA Id
		 * originate translated LSA
		 */

		if (ospf_translated_nssa_originate(area->ospf, lsa, old)
		    == NULL) {
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug(
					"%s: Could not translate Type-7 for %pI4 to Type-5",
					__func__, &lsa->data->id);
			return 1;
		}
	}

	return 0;
}

static void ospf_abr_translate_nssa_range(struct ospf *ospf,
					  struct prefix_ipv4 *p, uint32_t cost)
{
	struct external_info ei = {};
	struct ospf_lsa *lsa;

	prefix_copy(&ei.p, p);
	ei.type = ZEBRA_ROUTE_OSPF;
	ei.route_map_set.metric = cost;
	ei.route_map_set.metric_type = -1;

	lsa = ospf_external_info_find_lsa(ospf, p);
	if (lsa)
		lsa = ospf_external_lsa_refresh(ospf, lsa, &ei,
						LSA_REFRESH_FORCE, true);
	else
		lsa = ospf_external_lsa_originate(ospf, &ei);
	SET_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT);
}

void ospf_abr_announce_network_to_area(struct prefix_ipv4 *p, uint32_t cost,
				       struct ospf_area *area)
{
	struct ospf_lsa *lsa, *old = NULL;
	struct summary_lsa *sl = NULL;
	uint32_t full_cost;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	if (CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED))
		full_cost = OSPF_STUB_MAX_METRIC_SUMMARY_COST;
	else
		full_cost = cost;

	old = ospf_lsa_lookup_by_prefix(area->lsdb, OSPF_SUMMARY_LSA, p,
					area->ospf->router_id);
	if (old) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: old summary found", __func__);

		sl = (struct summary_lsa *)old->data;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: old metric: %d, new metric: %d",
				   __func__, GET_METRIC(sl->metric), cost);

		if ((GET_METRIC(sl->metric) == full_cost)
		    && ((old->flags & OSPF_LSA_IN_MAXAGE) == 0)) {
			/* unchanged. simply reapprove it */
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: old summary approved",
					   __func__);
			SET_FLAG(old->flags, OSPF_LSA_APPROVED);
		} else {
			/* LSA is changed, refresh it */
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: refreshing summary", __func__);
			set_metric(old, full_cost);
			lsa = ospf_lsa_refresh(area->ospf, old);

			if (!lsa) {
				flog_warn(EC_OSPF_LSA_MISSING,
					  "%s: Could not refresh %pFX to %pI4",
					  __func__, (struct prefix *)p,
					  &area->area_id);
				return;
			}

			SET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
			/* This will flood through area. */
		}
	} else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: creating new summary", __func__);
		lsa = ospf_summary_lsa_originate(p, full_cost, area);
		/* This will flood through area. */

		if (!lsa) {
			flog_warn(EC_OSPF_LSA_MISSING,
				  "%s: Could not originate %pFX to %pi4",
				  __func__, (struct prefix *)p,
				  &area->area_id);
			return;
		}

		SET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: flooding new version of summary",
				   __func__);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static int ospf_abr_nexthops_belong_to_area(struct ospf_route * or,
					    struct ospf_area *area)
{
	struct listnode *node, *nnode;
	struct ospf_path *path;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(or->paths, node, path))
		for (ALL_LIST_ELEMENTS_RO(area->oiflist, nnode, oi))
			if (oi->ifp && oi->ifp->ifindex == path->ifindex)
				return 1;

	return 0;
}

static int ospf_abr_should_accept(struct prefix_ipv4 *p, struct ospf_area *area)
{
	if (IMPORT_NAME(area)) {
		if (IMPORT_LIST(area) == NULL)
			IMPORT_LIST(area) =
				access_list_lookup(AFI_IP, IMPORT_NAME(area));

		if (IMPORT_LIST(area))
			if (access_list_apply(IMPORT_LIST(area), p)
			    == FILTER_DENY)
				return 0;
	}

	return 1;
}

static int ospf_abr_plist_in_check(struct ospf_area *area,
				   struct ospf_route * or,
				   struct prefix_ipv4 *p)
{
	if (PREFIX_NAME_IN(area)) {
		if (PREFIX_LIST_IN(area) == NULL)
			PREFIX_LIST_IN(area) = prefix_list_lookup(
				AFI_IP, PREFIX_NAME_IN(area));
		if (PREFIX_LIST_IN(area))
			if (prefix_list_apply(PREFIX_LIST_IN(area), p)
			    != PREFIX_PERMIT)
				return 0;
	}
	return 1;
}

static int ospf_abr_plist_out_check(struct ospf_area *area,
				    struct ospf_route * or,
				    struct prefix_ipv4 *p)
{
	if (PREFIX_NAME_OUT(area)) {
		if (PREFIX_LIST_OUT(area) == NULL)
			PREFIX_LIST_OUT(area) = prefix_list_lookup(
				AFI_IP, PREFIX_NAME_OUT(area));
		if (PREFIX_LIST_OUT(area))
			if (prefix_list_apply(PREFIX_LIST_OUT(area), p)
			    != PREFIX_PERMIT)
				return 0;
	}
	return 1;
}

static void ospf_abr_announce_network(struct ospf *ospf, struct prefix_ipv4 *p,
				      struct ospf_route * or)
{
	struct ospf_area_range *range;
	struct ospf_area *area, *or_area;
	struct listnode *node;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	or_area = ospf_area_lookup_by_area_id(ospf, or->u.std.area_id);
	assert(or_area);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		if (IPV4_ADDR_SAME(& or->u.std.area_id, &area->area_id))
			continue;

		if (ospf_abr_nexthops_belong_to_area(or, area))
			continue;

		if (!ospf_abr_should_accept(p, area)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: prefix %pFX was denied by import-list",
					__func__, p);
			continue;
		}

		if (!ospf_abr_plist_in_check(area, or, p)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: prefix %pFX was denied by prefix-list",
					__func__, p);
			continue;
		}

		if (area->external_routing != OSPF_AREA_DEFAULT
		    && area->no_summary) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: area %pI4 is stub and no_summary",
					__func__, &area->area_id);
			continue;
		}

		if (or->path_type == OSPF_PATH_INTER_AREA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is inter-area route to %pFX",
					__func__, p);

			if (!OSPF_IS_AREA_BACKBONE(area))
				ospf_abr_announce_network_to_area(p, or->cost,
								  area);
		}

		if (or->path_type == OSPF_PATH_INTRA_AREA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is intra-area route to %pFX",
					__func__, p);
			if ((range = ospf_area_range_match(
				     or_area, or_area->ranges, p)) &&
			    !ospf_area_is_transit(area))
				ospf_abr_update_aggregate(range, or->cost,
							  area);
			else
				ospf_abr_announce_network_to_area(p, or->cost,
								  area);
		}
	}
}

static int ospf_abr_should_announce(struct ospf *ospf, struct prefix_ipv4 *p,
				    struct ospf_route * or)
{
	struct ospf_area *area;

	area = ospf_area_lookup_by_area_id(ospf, or->u.std.area_id);

	assert(area);

	if (EXPORT_NAME(area)) {
		if (EXPORT_LIST(area) == NULL)
			EXPORT_LIST(area) =
				access_list_lookup(AFI_IP, EXPORT_NAME(area));

		if (EXPORT_LIST(area))
			if (access_list_apply(EXPORT_LIST(area), p)
			    == FILTER_DENY)
				return 0;
	}

	return 1;
}

static void ospf_abr_process_nssa_translates(struct ospf *ospf)
{
	/* Scan through all NSSA_LSDB records for all areas;

	   If P-bit is on, translate all Type-7's to 5's and aggregate or
	   flood install as approved in Type-5 LSDB with XLATE Flag on
	   later, do same for all aggregates...  At end, DISCARD all
	   remaining UNAPPROVED Type-5's (Aggregate is for future ) */
	struct listnode *node;
	struct ospf_area *area;
	struct route_node *rn;
	struct ospf_lsa *lsa;

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (!area->NSSATranslatorState)
			continue; /* skip if not translator */

		if (area->external_routing != OSPF_AREA_NSSA)
			continue; /* skip if not Nssa Area */

		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("%s(): looking at area %pI4", __func__,
				   &area->area_id);

		LSDB_LOOP (NSSA_LSDB(area), rn, lsa)
			ospf_abr_translate_nssa(area, lsa);
	}

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_process_network_rt(struct ospf *ospf,
					struct route_table *rt)
{
	struct ospf_area *area;
	struct ospf_route * or ;
	struct route_node *rn;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		if ((or = rn->info) == NULL)
			continue;

		if (!(area = ospf_area_lookup_by_area_id(ospf,
							 or->u.std.area_id))) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
				"%s: area %pI4 no longer exists", __func__,
						&or->u.std.area_id);
			continue;
		}

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: this is a route to %pFX", __func__,
				   &rn->p);
		if (or->path_type >= OSPF_PATH_TYPE1_EXTERNAL) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is an External router, skipping",
					__func__);
			continue;
		}

		if (or->cost >= OSPF_LS_INFINITY) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this route's cost is infinity, skipping",
					__func__);
			continue;
		}

		if (or->type == OSPF_DESTINATION_DISCARD) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is a discard entry, skipping",
					__func__);
			continue;
		}

		if (
			or->path_type == OSPF_PATH_INTRA_AREA
				  && !ospf_abr_should_announce(
					     ospf, (struct prefix_ipv4 *)&rn->p,
					     or)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: denied by export-list",
					   __func__);
			continue;
		}

		if (
			or->path_type == OSPF_PATH_INTRA_AREA
				  && !ospf_abr_plist_out_check(
					     area, or,
					     (struct prefix_ipv4 *)&rn->p)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: denied by prefix-list",
					   __func__);
			continue;
		}

		if ((or->path_type == OSPF_PATH_INTER_AREA)
		    && !OSPF_IS_AREA_ID_BACKBONE(or->u.std.area_id)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this route is not backbone one, skipping",
					__func__);
			continue;
		}


		if ((ospf->abr_type == OSPF_ABR_CISCO)
		    || (ospf->abr_type == OSPF_ABR_IBM))

			if (!ospf_act_bb_connection(ospf) &&
			    or->path_type != OSPF_PATH_INTRA_AREA) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: ALT ABR: No BB connection, skip not intra-area routes",
						__func__);
				continue;
			}

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: announcing", __func__);
		ospf_abr_announce_network(ospf, (struct prefix_ipv4 *)&rn->p,
					  or);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_announce_rtr_to_area(struct prefix_ipv4 *p, uint32_t cost,
					  struct ospf_area *area)
{
	struct ospf_lsa *lsa, *old = NULL;
	struct summary_lsa *slsa = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	old = ospf_lsa_lookup_by_prefix(area->lsdb, OSPF_ASBR_SUMMARY_LSA, p,
					area->ospf->router_id);
	if (old) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: old summary found", __func__);
		slsa = (struct summary_lsa *)old->data;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: old metric: %d, new metric: %d",
				   __func__, GET_METRIC(slsa->metric), cost);
	}

	if (old && (GET_METRIC(slsa->metric) == cost)
	    && ((old->flags & OSPF_LSA_IN_MAXAGE) == 0)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: old summary approved", __func__);
		SET_FLAG(old->flags, OSPF_LSA_APPROVED);
	} else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: 2.2", __func__);

		if (old) {
			set_metric(old, cost);
			lsa = ospf_lsa_refresh(area->ospf, old);
		} else
			lsa = ospf_summary_asbr_lsa_originate(p, cost, area);
		if (!lsa) {
			flog_warn(EC_OSPF_LSA_MISSING,
				  "%s: Could not refresh/originate %pFX to %pI4",
				  __func__, (struct prefix *)p,
				  &area->area_id);
			return;
		}

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: flooding new version of summary",
				   __func__);

		/*
		zlog_info ("ospf_abr_announce_rtr_to_area(): creating new
		summary");
		lsa = ospf_summary_asbr_lsa (p, cost, area, old); */

		SET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
		/* ospf_flood_through_area (area, NULL, lsa);*/
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}


static void ospf_abr_announce_rtr(struct ospf *ospf, struct prefix_ipv4 *p,
				  struct ospf_route * or)
{
	struct listnode *node;
	struct ospf_area *area;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		if (IPV4_ADDR_SAME(& or->u.std.area_id, &area->area_id))
			continue;

		if (ospf_abr_nexthops_belong_to_area(or, area))
			continue;

		/* RFC3101: Do not generate ASBR type 4 LSA if NSSA ABR */
		if (or->u.std.external_routing == OSPF_AREA_NSSA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: do not generate LSA Type-4 %pI4 from NSSA",
					__func__, &p->prefix);
			continue;
		}

		if (area->external_routing != OSPF_AREA_DEFAULT) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: area %pI4 doesn't support external routing",
					__func__, &area->area_id);
			continue;
		}

		if (or->path_type == OSPF_PATH_INTER_AREA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is inter-area route to %pI4",
					__func__, &p->prefix);
			if (!OSPF_IS_AREA_BACKBONE(area))
				ospf_abr_announce_rtr_to_area(p, or->cost,
							      area);
		}

		if (or->path_type == OSPF_PATH_INTRA_AREA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this is intra-area route to %pI4",
					__func__, &p->prefix);
			ospf_abr_announce_rtr_to_area(p, or->cost, area);
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_process_router_rt(struct ospf *ospf,
				       struct route_table *rt)
{
	struct ospf_route * or ;
	struct route_node *rn;
	struct list *l;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		struct listnode *node, *nnode;
		char flag = 0;
		struct ospf_route *best = NULL;

		if (rn->info == NULL)
			continue;

		l = rn->info;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: this is a route to %pI4", __func__,
				   &rn->p.u.prefix4);

		for (ALL_LIST_ELEMENTS(l, node, nnode, or)) {
			if (!ospf_area_lookup_by_area_id(ospf,
							 or->u.std.area_id)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: area %pI4 no longer exists", __func__,
						&or->u.std.area_id);
				continue;
			}


			if (!CHECK_FLAG(or->u.std.flags, ROUTER_LSA_EXTERNAL)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: This is not an ASBR, skipping",
						__func__);
				continue;
			}

			if (!flag) {
				best = ospf_find_asbr_route(
					ospf, rt, (struct prefix_ipv4 *)&rn->p);
				flag = 1;
			}

			if (best == NULL)
				continue;

			if (or != best) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: This route is not the best among possible, skipping",
						__func__);
				continue;
			}

			if (
				or->path_type == OSPF_PATH_INTER_AREA
					  && !OSPF_IS_AREA_ID_BACKBONE(
						     or->u.std.area_id)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: This route is not a backbone one, skipping",
						__func__);
				continue;
			}

			if (or->cost >= OSPF_LS_INFINITY) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: This route has LS_INFINITY metric, skipping",
						__func__);
				continue;
			}

			if (ospf->abr_type == OSPF_ABR_CISCO
			    || ospf->abr_type == OSPF_ABR_IBM)
				if (!ospf_act_bb_connection(ospf) &&
				    or->path_type != OSPF_PATH_INTRA_AREA) {
					if (IS_DEBUG_OSPF_EVENT)
						zlog_debug(
							"%s: ALT ABR: No BB connection, skip not intra-area routes",
							__func__);
					continue;
				}

			ospf_abr_announce_rtr(ospf,
					      (struct prefix_ipv4 *)&rn->p, or);
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void
ospf_abr_unapprove_translates(struct ospf *ospf) /* For NSSA Translations */
{
	struct ospf_lsa *lsa;
	struct route_node *rn;

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Start", __func__);

	/* NSSA Translator is not checked, because it may have gone away,
	  and we would want to flush any residuals anyway */

	LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
		if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT)) {
			UNSET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug("%s: approved unset on link id %pI4",
					   __func__, &lsa->data->id);
		}

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_unapprove_summaries(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	struct route_node *rn;
	struct ospf_lsa *lsa;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: considering area %pI4", __func__,
				   &area->area_id);
		LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
			if (ospf_lsa_is_self_originated(ospf, lsa)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: approved unset on summary link id %pI4",
						__func__, &lsa->data->id);
				UNSET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
			}

		LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
			if (ospf_lsa_is_self_originated(ospf, lsa)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: approved unset on asbr-summary link id %pI4",
						__func__, &lsa->data->id);
				UNSET_FLAG(lsa->flags, OSPF_LSA_APPROVED);
			}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_prepare_aggregates(struct ospf *ospf, bool nssa)
{
	struct listnode *node;
	struct route_node *rn;
	struct ospf_area_range *range;
	struct ospf_area *area;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct route_table *ranges;

		if (nssa)
			ranges = area->nssa_ranges;
		else
			ranges = area->ranges;

		for (rn = route_top(ranges); rn; rn = route_next(rn))
			if ((range = rn->info) != NULL) {
				range->cost = 0;
				range->specifics = 0;
			}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_announce_aggregates(struct ospf *ospf)
{
	struct ospf_area *area, *ar;
	struct ospf_area_range *range;
	struct route_node *rn;
	struct prefix p;
	struct listnode *node, *n;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		for (rn = route_top(area->ranges); rn; rn = route_next(rn))
			if ((range = rn->info)) {
				if (!CHECK_FLAG(range->flags,
						OSPF_AREA_RANGE_ADVERTISE)) {
					if (IS_DEBUG_OSPF_EVENT)
						zlog_debug(
							"%s: discarding suppress-ranges",
							__func__);
					continue;
				}

				p.family = AF_INET;
				p.u.prefix4 = range->addr;
				p.prefixlen = range->masklen;

				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug("%s: this is range: %pFX",
						   __func__, &p);

				if (CHECK_FLAG(range->flags,
					       OSPF_AREA_RANGE_SUBSTITUTE)) {
					p.family = AF_INET;
					p.u.prefix4 = range->subst_addr;
					p.prefixlen = range->subst_masklen;
				}

				if (ospf_area_range_active(range)) {
					if (IS_DEBUG_OSPF_EVENT)
						zlog_debug("%s: active range",
							   __func__);

					for (ALL_LIST_ELEMENTS_RO(ospf->areas,
								  n, ar)) {
						if (ar == area)
							continue;

						/* We do not check nexthops
						   here, because
						   intra-area routes can be
						   associated with
						   one area only */

						/* backbone routes are not
						   summarized
						   when announced into transit
						   areas */

						if (ospf_area_is_transit(ar)
						    && OSPF_IS_AREA_BACKBONE(
							       area)) {
							if (IS_DEBUG_OSPF_EVENT)
								zlog_debug(
		"%s: Skipping announcement of BB aggregate into a transit area",
									__func__);
							continue;
						}
						ospf_abr_announce_network_to_area(
							(struct prefix_ipv4
								 *)&p,
							range->cost, ar);
					}
				}
			}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_send_nssa_aggregates(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	struct route_node *rn;
	struct prefix_ipv4 p;

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (!area->NSSATranslatorState)
			continue;

		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		for (rn = route_top(area->nssa_ranges); rn;
		     rn = route_next(rn)) {
			struct ospf_area_range *range;

			range = rn->info;
			if (!range)
				continue;

			p.family = AF_INET;
			p.prefix = range->addr;
			p.prefixlen = range->masklen;

			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug("%s: this is range: %pFX", __func__,
					   &p);

			if (ospf_area_range_active(range)
			    && CHECK_FLAG(range->flags,
					  OSPF_AREA_RANGE_ADVERTISE)) {
				if (IS_DEBUG_OSPF_NSSA)
					zlog_debug("%s: active range",
						   __func__);

				/* Fetch LSA-Type-7 from aggregate prefix, and
				 * then
				 *  translate, Install (as Type-5), Approve, and
				 * Flood
				 */
				ospf_abr_translate_nssa_range(ospf, &p,
							      range->cost);
			}
		} /* all area ranges*/
	}	 /* all areas */

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_announce_stub_defaults(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	struct prefix_ipv4 p;

	if (!IS_OSPF_ABR(ospf))
		return;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	p.family = AF_INET;
	p.prefix.s_addr = OSPF_DEFAULT_DESTINATION;
	p.prefixlen = 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		if ((area->external_routing != OSPF_AREA_STUB)
		    && (area->external_routing != OSPF_AREA_NSSA))
			continue;

		if (OSPF_IS_AREA_BACKBONE(area))
			continue; /* Sanity Check */

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: announcing 0.0.0.0/0 to area %pI4",
				   __func__, &area->area_id);
		ospf_abr_announce_network_to_area(&p, area->default_cost, area);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

/** @brief Function to check and generate indication
 *	   LSA for area on which we received
 *	   indication LSA flush.
 *  @param Ospf instance.
 *  @param Area on which indication lsa flush is to be generated.
 *  @return Void.
 */
void ospf_generate_indication_lsa(struct ospf *ospf, struct ospf_area *area)
{
	bool area_fr_not_supp = false;

	/* Check if you have any area which doesn't support
	 * flood reduction.
	 */

	area_fr_not_supp = ospf_check_fr_enabled_all(ospf) ? false : true;

	/* If any one of the area doestn't support FR, generate
	 * indication LSA on behalf of that area.
	 */

	if (area_fr_not_supp && !area->fr_info.area_ind_lsa_recvd &&
	    !area->fr_info.indication_lsa_self &&
	    !area->fr_info.area_dc_clear) {

		struct prefix_ipv4 p;
		struct ospf_lsa *new;

		p.family = AF_INET;
		p.prefix = ospf->router_id;
		p.prefixlen = IPV4_MAX_BITLEN;

		new = ospf_summary_asbr_lsa_originate(&p, OSPF_LS_INFINITY,
						      area);
		if (!new) {
			zlog_debug("%s: Indication lsa originate failed",
				   __func__);
			return;
		}
		/* save the indication lsa for that area */
		area->fr_info.indication_lsa_self = new;
	}
}

/** @brief Function to receive and process indication LSA
 *	   flush from area.
 *  @param lsa being flushed.
 *  @return Void.
 */
void ospf_recv_indication_lsa_flush(struct ospf_lsa *lsa)
{
	if (!IS_LSA_SELF(lsa) && IS_LSA_MAXAGE(lsa) &&
	    ospf_check_indication_lsa(lsa)) {
		lsa->area->fr_info.area_ind_lsa_recvd = false;

		OSPF_LOG_INFO("%s: Received an ind lsa: %pI4 area %pI4",
			      __func__, &lsa->data->id, &lsa->area->area_id);

		if (!IS_OSPF_ABR(lsa->area->ospf))
			return;

		/* If the LSA received is a indication LSA with maxage on
		 * the network, then check and regenerate indication
		 * LSA if any of our areas don't support flood reduction.
		 */
		ospf_generate_indication_lsa(lsa->area->ospf, lsa->area);
	}
}

/** @brief Function to generate indication LSAs.
 *  @param Ospf instance.
 *  @param Area on behalf of which indication
 *	   LSA is generated LSA.
 *  @return Void.
 */
void ospf_abr_generate_indication_lsa(struct ospf *ospf,
				      const struct ospf_area *area)
{
	struct ospf_lsa *new;
	struct listnode *node;
	struct ospf_area *o_area;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, o_area)) {
		if (o_area == area)
			continue;

		if (o_area->fr_info.indication_lsa_self ||
		    o_area->fr_info.area_ind_lsa_recvd ||
		    o_area->fr_info.area_dc_clear) {
			/* if the area has already received an
			 * indication LSA or if area already has
			 * LSAs with DC bit 0 other than
			 * indication LSA then don't generate
			 * indication LSA in those areas.
			 */
			OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
				       "Area %pI4 has LSAs with dc bit clear",
				       &o_area->area_id);
			continue;

		} else {

			struct prefix_ipv4 p;

			p.family = AF_INET;
			p.prefix = ospf->router_id;
			p.prefixlen = IPV4_MAX_BITLEN;

			new = ospf_summary_asbr_lsa_originate(
				&p, OSPF_LS_INFINITY, o_area);
			if (!new) {
				zlog_debug(
					"%s: Indication lsa originate Failed",
					__func__);
				return;
			}
			/* save the indication lsa for that area */
			o_area->fr_info.indication_lsa_self = new;
		}
	}
}

/** @brief Flush the indication LSA from all the areas
 *	   of ospf instance.
 *  @param Ospf instance.
 *  @return Void.
 */
void ospf_flush_indication_lsas(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (area->fr_info.indication_lsa_self) {
			OSPF_LOG_INFO(
				"Flushing ind lsa: %pI4 area %pI4",
				&area->fr_info.indication_lsa_self->data->id,
				&area->area_id);
			ospf_schedule_lsa_flush_area(
				area, area->fr_info.indication_lsa_self);
			area->fr_info.indication_lsa_self = NULL;
		}
	}
}

/** @brief Check if flood reduction is enabled on
 *	   all the areas.
 *  @param Ospf instance.
 *  @return Void.
 */
bool ospf_check_fr_enabled_all(struct ospf *ospf)
{
	const struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (!ospf_check_area_fr_enabled(area))
			return false;

	return true;
}

/** @brief Abr function to check conditions for generation
 *	   of indication. LSAs/announcing non-DNA routers
 *	   in the area.
 *  @param thread
 *  @return 0.
 */
static void ospf_abr_announce_non_dna_routers(struct event *thread)
{
	struct ospf_area *area;
	struct listnode *node;
	struct ospf *ospf = EVENT_ARG(thread);

	EVENT_OFF(ospf->t_abr_fr);

	if (!IS_OSPF_ABR(ospf))
		return;

	OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT, "%s(): Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "%s: Area %pI4 FR enabled: %d", __func__,
			       &area->area_id, area->fr_info.enabled);
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "LSA with DC bit clear: %d Received indication LSA: %d",
			       area->fr_info.area_dc_clear,
			       area->fr_info.area_ind_lsa_recvd);
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT, "FR state change: %d",
			       area->fr_info.state_changed);
		if (!OSPF_IS_AREA_BACKBONE(area) &&
		    area->fr_info.area_dc_clear) {
			/* rfc4136 rfc1793: Suppose if the abr is connected to
			 * a regular non-backbone OSPF area, Furthermore if
			 * the area has LSAs with the DC-bit clear, other
			 * than indication-LSAs. Then originate indication-LSAs
			 * into all other directly-connected "regular" areas,
			 * including the backbone area.
			 */
			ospf_abr_generate_indication_lsa(ospf, area);
		}

		if (OSPF_IS_AREA_BACKBONE(area) &&
		    (area->fr_info.area_dc_clear ||
		     area->fr_info.area_ind_lsa_recvd)) {
			/* rfc4136 rfc1793: Suppose if the abr is connected to
			 * backbone OSPF area. Furthermore, if backbone has
			 * LSAs with the DC-bit clear that are either
			 * a) not indication-LSAs or indication-LSAs or
			 * b) indication-LSAs that have been originated by
			 *    other routers,
			 * then originate indication-LSAs into all other
			 * directly-connected "regular" non-backbone areas.
			 */
			ospf_abr_generate_indication_lsa(ospf, area);
		}

		if (area->fr_info.enabled && area->fr_info.state_changed &&
		    area->fr_info.indication_lsa_self) {
			/* Ospf area flood reduction state changed
			 * area now supports flood reduction.
			 * check if all other areas support flood reduction
			 * if yes then flush indication LSAs generated in
			 * all the areas.
			 */
			if (ospf_check_fr_enabled_all(ospf))
				ospf_flush_indication_lsas(ospf);

			area->fr_info.state_changed = false;
		}

		/* If previously we had generated indication lsa
		 * but now area has lsas with dc bit set to 0
		 * apart from indication lsa, we'll clear indication lsa
		 */
		if (area->fr_info.area_dc_clear &&
		    area->fr_info.indication_lsa_self) {
			ospf_schedule_lsa_flush_area(
				area, area->fr_info.indication_lsa_self);
			area->fr_info.indication_lsa_self = NULL;
		}
	}

	OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT, "%s(): Stop", __func__);
}

static void ospf_abr_nssa_type7_default_create(struct ospf *ospf,
					       struct ospf_area *area,
					       struct ospf_lsa *lsa)
{
	struct external_info ei;

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug(
			"Announcing Type-7 default route into NSSA area %pI4",
			&area->area_id);

	/* Prepare the extrenal_info for aggregator */
	memset(&ei, 0, sizeof(struct external_info));
	ei.p.family = AF_INET;
	ei.p.prefixlen = 0;
	ei.tag = 0;
	ei.type = 0;
	ei.instance = ospf->instance;

	/* Compute default route type and metric. */
	if (area->nssa_default_originate.metric_value != -1)
		ei.route_map_set.metric =
			area->nssa_default_originate.metric_value;
	else
		ei.route_map_set.metric = DEFAULT_DEFAULT_ALWAYS_METRIC;
	if (area->nssa_default_originate.metric_type != -1)
		ei.route_map_set.metric_type =
			area->nssa_default_originate.metric_type;
	else
		ei.route_map_set.metric_type = DEFAULT_METRIC_TYPE;

	if (!lsa)
		ospf_nssa_lsa_originate(area, &ei);
	else
		ospf_nssa_lsa_refresh(area, lsa, &ei);
}

static void ospf_abr_nssa_type7_default_delete(struct ospf *ospf,
					       struct ospf_area *area,
					       struct ospf_lsa *lsa)
{
	if (lsa && !CHECK_FLAG(lsa->flags, OSPF_LSA_IN_MAXAGE)) {
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug(
				"Withdrawing Type-7 default route from area %pI4",
				&area->area_id);

		ospf_ls_retransmit_delete_nbr_area(area, lsa);
		ospf_refresher_unregister_lsa(ospf, lsa);
		ospf_lsa_flush_area(lsa, area);
	}
}

/* NSSA Type-7 default route. */
void ospf_abr_nssa_type7_defaults(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct in_addr id = {};
		struct ospf_lsa *lsa;

		lsa = ospf_lsdb_lookup_by_id(area->lsdb, OSPF_AS_NSSA_LSA, id,
					     area->ospf->router_id);
		if (area->external_routing == OSPF_AREA_NSSA
		    && area->nssa_default_originate.enabled
		    && (IS_OSPF_ABR(ospf)
			|| (IS_OSPF_ASBR(ospf)
			    && ospf->nssa_default_import_check.status)))
			ospf_abr_nssa_type7_default_create(ospf, area, lsa);
		else
			ospf_abr_nssa_type7_default_delete(ospf, area, lsa);
	}
}

static int ospf_abr_remove_unapproved_translates_apply(struct ospf *ospf,
						       struct ospf_lsa *lsa)
{
	if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT)
	    && !CHECK_FLAG(lsa->flags, OSPF_LSA_APPROVED)) {
		zlog_info("%s: removing unapproved translates, ID: %pI4",
			  __func__, &lsa->data->id);

		/* FLUSH THROUGHOUT AS */
		ospf_lsa_flush_as(ospf, lsa);

		/* DISCARD from LSDB  */
	}
	return 0;
}

static void ospf_abr_remove_unapproved_translates(struct ospf *ospf)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;

	/* All AREA PROCESS should have APPROVED necessary LSAs */
	/* Remove any left over and not APPROVED */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Start", __func__);

	LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
		ospf_abr_remove_unapproved_translates_apply(ospf, lsa);

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_remove_unapproved_summaries(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	struct route_node *rn;
	struct ospf_lsa *lsa;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: looking at area %pI4", __func__,
				   &area->area_id);

		LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
			if (ospf_lsa_is_self_originated(ospf, lsa))
				if (!CHECK_FLAG(lsa->flags, OSPF_LSA_APPROVED))
					ospf_lsa_flush_area(lsa, area);

		LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
			if (ospf_lsa_is_self_originated(ospf, lsa) &&
			    !CHECK_FLAG(lsa->flags, OSPF_LSA_APPROVED) &&
			    /* Do not remove indication LSAs while
			     * flushing unapproved summaries.
			     */
			    !ospf_check_indication_lsa(lsa))
				ospf_lsa_flush_area(lsa, area);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_manage_discard_routes(struct ospf *ospf, bool nssa)
{
	struct listnode *node, *nnode;
	struct route_node *rn;
	struct ospf_area *area;

	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		struct route_table *ranges;

		if (nssa)
			ranges = area->nssa_ranges;
		else
			ranges = area->ranges;

		for (rn = route_top(ranges); rn; rn = route_next(rn)) {
			struct ospf_area_range *range;

			range = rn->info;
			if (!range)
				continue;

			if (ospf_area_range_active(range)
			    && CHECK_FLAG(range->flags,
					  OSPF_AREA_RANGE_ADVERTISE))
				ospf_add_discard_route(
					ospf, ospf->new_table, area,
					(struct prefix_ipv4 *)&rn->p, nssa);
			else
				ospf_delete_discard_route(
					ospf, ospf->new_table,
					(struct prefix_ipv4 *)&rn->p, nssa);
		}
	}
}

/* This is the function taking care about ABR NSSA, i.e.  NSSA
   Translator, -LSA aggregation and flooding. For all NSSAs

   Any SELF-AS-LSA is in the Type-5 LSDB and Type-7 LSDB.  These LSA's
   are refreshed from the Type-5 LSDB, installed into the Type-7 LSDB
   with the P-bit set.

   Any received Type-5s are legal for an ABR, else illegal for IR.
   Received Type-7s are installed, by area, with incoming P-bit.  They
   are flooded; if the Elected NSSA Translator, then P-bit off.

   Additionally, this ABR will place "translated type-7's" into the
   Type-5 LSDB in order to keep track of APPROVAL or not.

   It will scan through every area, looking for Type-7 LSAs with P-Bit
   SET. The Type-7's are either AS-FLOODED & 5-INSTALLED or
   AGGREGATED.  Later, the AGGREGATED LSAs are AS-FLOODED &
   5-INSTALLED.

   5-INSTALLED is into the Type-5 LSDB; Any UNAPPROVED Type-5 LSAs
   left over are FLUSHED and DISCARDED.

   For External Calculations, any NSSA areas use the Type-7 AREA-LSDB,
   any ABR-non-NSSA areas use the Type-5 GLOBAL-LSDB. */

void ospf_abr_nssa_task(struct ospf *ospf) /* called only if any_nssa */
{
	if (ospf->gr_info.restart_in_progress)
		return;

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("Check for NSSA-ABR Tasks():");

	if (!IS_OSPF_ABR(ospf))
		return;

	if (!ospf->anyNSSA)
		return;

	/* Each area must confirm TranslatorRole */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Start", __func__);

	/* For all Global Entries flagged "local-translate", unset APPROVED */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: unapprove translates", __func__);

	ospf_abr_unapprove_translates(ospf);

	/* RESET all Ranges in every Area, same as summaries */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: NSSA initialize aggregates", __func__);
	ospf_abr_prepare_aggregates(ospf, true);

	/* For all NSSAs, Type-7s, translate to 5's, INSTALL/FLOOD, or
	 *  Aggregate as Type-7
	 * Install or Approve in Type-5 Global LSDB
	 */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: process translates", __func__);
	ospf_abr_process_nssa_translates(ospf);

	/* Translate/Send any "ranged" aggregates, and also 5-Install and
	 *  Approve
	 * Scan Type-7's for aggregates, translate to Type-5's,
	 *  Install/Flood/Approve
	 */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: send NSSA aggregates", __func__);
	ospf_abr_send_nssa_aggregates(ospf); /*TURNED OFF FOR NOW */

	/* Send any NSSA defaults as Type-5
	 *if (IS_DEBUG_OSPF_NSSA)
	 * zlog_debug ("ospf_abr_nssa_task(): announce nssa defaults");
	 *ospf_abr_announce_nssa_defaults (ospf);
	 * havnt a clue what above is supposed to do.
	 */

	/* Flush any unapproved previous translates from Global Data Base */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: remove unapproved translates", __func__);
	ospf_abr_remove_unapproved_translates(ospf);

	ospf_abr_manage_discard_routes(ospf, true);

	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: Stop", __func__);
}

/* This is the function taking care about ABR stuff, i.e.
   summary-LSA origination and flooding. */
void ospf_abr_task(struct ospf *ospf)
{
	if (ospf->gr_info.restart_in_progress)
		return;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	if (ospf->new_table == NULL || ospf->new_rtrs == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Routing tables are not yet ready",
				   __func__);
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: unapprove summaries", __func__);
	ospf_abr_unapprove_summaries(ospf);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: prepare aggregates", __func__);
	ospf_abr_prepare_aggregates(ospf, false);

	if (IS_OSPF_ABR(ospf)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: process network RT", __func__);
		ospf_abr_process_network_rt(ospf, ospf->new_table);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: process router RT", __func__);
		ospf_abr_process_router_rt(ospf, ospf->new_rtrs);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: announce aggregates", __func__);
		ospf_abr_announce_aggregates(ospf);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: announce stub defaults", __func__);
		ospf_abr_announce_stub_defaults(ospf);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: announce NSSA Type-7 defaults",
				   __func__);
		ospf_abr_nssa_type7_defaults(ospf);

		if (ospf->fr_configured) {
			OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
				       "%s(): announce non-DNArouters",
				       __func__);
			/*
			 * Schedule indication lsa generation timer,
			 * giving time for route synchronization in
			 * all the routers.
			 */
			event_add_timer(master,
					ospf_abr_announce_non_dna_routers, ospf,
					OSPF_ABR_DNA_TIMER, &ospf->t_abr_fr);
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: remove unapproved summaries", __func__);
	ospf_abr_remove_unapproved_summaries(ospf);

	ospf_abr_manage_discard_routes(ospf, false);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static void ospf_abr_task_timer(struct event *thread)
{
	struct ospf *ospf = EVENT_ARG(thread);

	ospf->t_abr_task = 0;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Running ABR task on timer");

	ospf_check_abr_status(ospf);
	ospf_abr_nssa_check_status(ospf);

	ospf_abr_task(ospf);
	ospf_abr_nssa_task(ospf); /* if nssa-abr, then scan Type-7 LSDB */
}

void ospf_schedule_abr_task(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Scheduling ABR task");

	event_add_timer(master, ospf_abr_task_timer, ospf, OSPF_ABR_TASK_DELAY,
			&ospf->t_abr_task);
}
