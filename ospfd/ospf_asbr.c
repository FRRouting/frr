// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_errors.h"

/* Remove external route. */
void ospf_external_route_remove(struct ospf *ospf, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_route * or ;

	rn = route_node_lookup(ospf->old_external_route, (struct prefix *)p);
	if (rn)
		if ((or = rn->info)) {
			zlog_info("Route[%pFX]: external path deleted", p);

			/* Remove route from zebra. */
			if (or->type == OSPF_DESTINATION_NETWORK)
				ospf_zebra_delete(
					ospf, (struct prefix_ipv4 *)&rn->p, or);

			ospf_route_free(or);
			rn->info = NULL;

			route_unlock_node(rn);
			route_unlock_node(rn);
			return;
		}

	zlog_info("Route[%pFX]: no such external path", p);
}

/* Add an External info for AS-external-LSA. */
struct external_info *ospf_external_info_new(struct ospf *ospf, uint8_t type,
					     unsigned short instance)
{
	struct external_info *new;

	new = XCALLOC(MTYPE_OSPF_EXTERNAL_INFO, sizeof(struct external_info));
	new->ospf = ospf;
	new->type = type;
	new->instance = instance;
	new->to_be_processed = 0;

	ospf_reset_route_map_set_values(&new->route_map_set);
	return new;
}

static void ospf_external_info_free(struct external_info *ei)
{
	XFREE(MTYPE_OSPF_EXTERNAL_INFO, ei);
}

void ospf_reset_route_map_set_values(struct route_map_set_values *values)
{
	values->metric = -1;
	values->metric_type = -1;
}

int ospf_route_map_set_compare(struct route_map_set_values *values1,
			       struct route_map_set_values *values2)
{
	return values1->metric == values2->metric
	       && values1->metric_type == values2->metric_type;
}

/* Add an External info for AS-external-LSA. */
struct external_info *
ospf_external_info_add(struct ospf *ospf, uint8_t type, unsigned short instance,
		       struct prefix_ipv4 p, ifindex_t ifindex,
		       struct in_addr nexthop, route_tag_t tag, uint32_t metric)
{
	struct external_info *new;
	struct route_node *rn;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		ext = ospf_external_add(ospf, type, instance);

	rn = route_node_get(EXTERNAL_INFO(ext), (struct prefix *)&p);
	/* If old info exists, -- discard new one or overwrite with new one? */
	if (rn && rn->info) {
		new = rn->info;
		if ((new->ifindex == ifindex)
		    && (new->nexthop.s_addr == nexthop.s_addr)
		    && (new->tag == tag)
		    && (new->metric == metric)) {
			route_unlock_node(rn);
			return NULL; /* NULL => no LSA to refresh */
		}

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Redistribute[%s][%d][%u]: %pFX discarding old info with NH %pI4.",
				ospf_redist_string(type), instance,
				ospf->vrf_id, &p, &nexthop.s_addr);
		XFREE(MTYPE_OSPF_EXTERNAL_INFO, rn->info);
	}

	/* Create new External info instance. */
	new = ospf_external_info_new(ospf, type, instance);
	new->p = p;
	new->ifindex = ifindex;
	new->nexthop = nexthop;
	new->tag = tag;
	new->orig_tag = tag;
	new->aggr_route = NULL;
	new->metric = metric;
	new->min_metric = 0;
	new->max_metric = OSPF_LS_INFINITY;

	/* we don't unlock rn from the get() because we're attaching the info */
	if (rn)
		rn->info = new;

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"Redistribute[%s][%u]: %pFX external info created, with NH %pI4, metric:%u",
			ospf_redist_string(type), ospf->vrf_id, &p,
			&nexthop.s_addr, metric);
	}
	return new;
}

void ospf_external_info_delete(struct ospf *ospf, uint8_t type,
			       unsigned short instance, struct prefix_ipv4 p)
{
	struct route_node *rn;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return;

	rn = route_node_lookup(EXTERNAL_INFO(ext), (struct prefix *)&p);
	if (rn) {
		ospf_external_info_free(rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
}

struct external_info *ospf_external_info_lookup(struct ospf *ospf, uint8_t type,
						unsigned short instance,
						struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return NULL;

	rn = route_node_lookup(EXTERNAL_INFO(ext), (struct prefix *)p);
	if (rn) {
		route_unlock_node(rn);
		if (rn->info)
			return rn->info;
	}

	return NULL;
}

struct ospf_lsa *ospf_external_info_find_lsa(struct ospf *ospf,
					     struct prefix_ipv4 *p)
{
	struct ospf_lsa *lsa;
	struct as_external_lsa *al;
	struct in_addr mask, id;

	/* First search the lsdb with address specific LSID
	 * where all the host bits are set, if there a matched
	 * LSA, return.
	 * Ex: For route 10.0.0.0/16, LSID is 10.0.255.255
	 * If no lsa with above LSID, use received address as
	 * LSID and check if any LSA in LSDB.
	 * If LSA found, check if the mask is same b/w the matched
	 * LSA and received prefix, if same then it is the LSA for
	 * this prefix.
	 * Ex: For route 10.0.0.0/16, LSID is 10.0.0.0
	 */

	masklen2ip(p->prefixlen, &mask);
	id.s_addr = p->prefix.s_addr | (~mask.s_addr);
	lsa = ospf_lsdb_lookup_by_id(ospf->lsdb, OSPF_AS_EXTERNAL_LSA, id,
				     ospf->router_id);
	if (lsa) {
		if (p->prefixlen == IPV4_MAX_BITLEN) {
			al = (struct as_external_lsa *)lsa->data;

			if (mask.s_addr != al->mask.s_addr)
				return NULL;
		}
		return lsa;
	}

	lsa = ospf_lsdb_lookup_by_id(ospf->lsdb, OSPF_AS_EXTERNAL_LSA,
				     p->prefix, ospf->router_id);

	if (lsa) {
		al = (struct as_external_lsa *)lsa->data;
		if (mask.s_addr == al->mask.s_addr)
			return lsa;
	}

	return NULL;
}


/* Update ASBR status. */
void ospf_asbr_status_update(struct ospf *ospf, uint8_t status)
{
	zlog_info("ASBR[%s:Status:%d]: Update",
		  ospf_get_name(ospf), status);

	/* ASBR on. */
	if (status) {
		/* Already ASBR. */
		if (IS_OSPF_ASBR(ospf)) {
			zlog_info("ASBR[%s:Status:%d]: Already ASBR",
				  ospf_get_name(ospf), status);
			return;
		}
		SET_FLAG(ospf->flags, OSPF_FLAG_ASBR);
	} else {
		/* Already non ASBR. */
		if (!IS_OSPF_ASBR(ospf)) {
			zlog_info("ASBR[%s:Status:%d]: Already non ASBR",
				  ospf_get_name(ospf), status);
			return;
		}
		UNSET_FLAG(ospf->flags, OSPF_FLAG_ASBR);
	}

	/* Transition from/to status ASBR, schedule timer. */
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_ASBR_STATUS_CHANGE);
	ospf_router_lsa_update(ospf);
}

/* If there's redistribution configured, we need to refresh external
 * LSAs (e.g. when default-metric changes or NSSA settings change).
 */
static void ospf_asbr_redist_update_timer(struct event *thread)
{
	struct ospf *ospf = EVENT_ARG(thread);
	int type;

	ospf->t_asbr_redist_update = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Running ASBR redistribution update on timer");

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		struct list *red_list;
		struct listnode *node;
		struct ospf_redist *red;

		red_list = ospf->redist[type];
		if (!red_list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
			ospf_external_lsa_refresh_type(ospf, type,
						       red->instance,
						       LSA_REFRESH_FORCE);
	}

	ospf_external_lsa_refresh_default(ospf);
}

void ospf_schedule_asbr_redist_update(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Scheduling ASBR redistribution update");

	event_add_timer(master, ospf_asbr_redist_update_timer, ospf,
			OSPF_ASBR_REDIST_UPDATE_DELAY,
			&ospf->t_asbr_redist_update);
}

void ospf_redistribute_withdraw(struct ospf *ospf, uint8_t type,
				unsigned short instance)
{
	struct route_node *rn;
	struct external_info *ei;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return;

	/* Delete external info for specified type. */
	if (!EXTERNAL_INFO(ext))
		return;

	for (rn = route_top(EXTERNAL_INFO(ext)); rn; rn = route_next(rn)) {
		ei = rn->info;

		if (!ei)
			continue;

		struct ospf_external_aggr_rt *aggr;

		if (is_default_prefix4(&ei->p)
		    && ospf->default_originate != DEFAULT_ORIGINATE_NONE)
			continue;

		aggr = ei->aggr_route;

		if (aggr)
			ospf_unlink_ei_from_aggr(ospf, aggr, ei);
		else if (ospf_external_info_find_lsa(ospf, &ei->p))
			ospf_external_lsa_flush(ospf, type, &ei->p,
						ei->ifindex /*, ei->nexthop */);

		ospf_external_info_free(ei);
		route_unlock_node(rn);
		rn->info = NULL;
	}
}


/* External Route Aggregator Handlers */
bool is_valid_summary_addr(struct prefix_ipv4 *p)
{
	/* Default prefix validation*/
	if (p->prefix.s_addr == INADDR_ANY)
		return false;

	/*Host route shouldn't be configured as summary addres*/
	if (p->prefixlen == IPV4_MAX_BITLEN)
		return false;

	return true;
}
void ospf_asbr_external_aggregator_init(struct ospf *instance)
{
	instance->rt_aggr_tbl = route_table_init();

	instance->t_external_aggr = NULL;

	instance->aggr_action = 0;

	instance->aggr_delay_interval = OSPF_EXTL_AGGR_DEFAULT_DELAY;
}

static unsigned int ospf_external_rt_hash_key(const void *data)
{
	const struct external_info *ei = data;
	unsigned int key = 0;

	key = prefix_hash_key(&ei->p);
	return key;
}

static bool ospf_external_rt_hash_cmp(const void *d1, const void *d2)
{
	const struct external_info *ei1 = d1;
	const struct external_info *ei2 = d2;

	return prefix_same((struct prefix *)&ei1->p, (struct prefix *)&ei2->p);
}

static struct ospf_external_aggr_rt *
ospf_external_aggregator_new(struct prefix_ipv4 *p)
{
	struct ospf_external_aggr_rt *aggr;

	aggr = (struct ospf_external_aggr_rt *)XCALLOC(
		MTYPE_OSPF_EXTERNAL_RT_AGGR,
		sizeof(struct ospf_external_aggr_rt));

	if (!aggr)
		return NULL;

	aggr->p.family = p->family;
	aggr->p.prefix = p->prefix;
	aggr->p.prefixlen = p->prefixlen;
	aggr->match_extnl_hash = hash_create(ospf_external_rt_hash_key,
					     ospf_external_rt_hash_cmp,
					     "Ospf external route hash");
	return aggr;
}

static void ospf_aggr_handle_external_info(void *data)
{
	struct external_info *ei = (struct external_info *)data;
	struct ospf_external_aggr_rt *aggr = NULL;
	struct ospf *ospf = ei->ospf;
	struct ospf_lsa *lsa = NULL;

	ei->aggr_route = NULL;

	ei->to_be_processed = true;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Handle extrenal route(%pI4/%d)", __func__,
			   &ei->p.prefix, ei->p.prefixlen);

	assert(ospf);

	if (!ospf_redistribute_check(ospf, ei, NULL))
		return;

	aggr = ospf_external_aggr_match(ospf, &ei->p);
	if (aggr) {
		(void)ospf_originate_summary_lsa(ospf, aggr, ei);
		return;
	}

	lsa = ospf_external_info_find_lsa(ospf, &ei->p);
	if (lsa)
		ospf_external_lsa_refresh(ospf, lsa, ei, LSA_REFRESH_FORCE, 1);
	else
		(void)ospf_external_lsa_originate(ospf, ei);
}

static void ospf_aggr_unlink_external_info(void *data)
{
	struct external_info *ei = (struct external_info *)data;

	ei->aggr_route = NULL;

	ei->to_be_processed = true;
}

void ospf_external_aggregator_free(struct ospf_external_aggr_rt *aggr)
{
	hash_clean_and_free(&aggr->match_extnl_hash,
			    (void *)ospf_aggr_unlink_external_info);

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Release the aggregator Address(%pI4/%d)",
			   __func__, &aggr->p.prefix, aggr->p.prefixlen);

	XFREE(MTYPE_OSPF_EXTERNAL_RT_AGGR, aggr);
}

static void ospf_external_aggr_add(struct ospf *ospf,
				   struct ospf_external_aggr_rt *aggr)
{
	struct route_node *rn;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Adding Aggregate route to Aggr table (%pI4/%d)",
			   __func__, &aggr->p.prefix, aggr->p.prefixlen);
	rn = route_node_get(ospf->rt_aggr_tbl, (struct prefix *)&aggr->p);
	if (rn->info)
		route_unlock_node(rn);
	else
		rn->info = aggr;
}

static void ospf_external_aggr_delete(struct ospf *ospf, struct route_node *rn)
{
	struct ospf_external_aggr_rt *aggr = rn->info;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Deleting Aggregate route (%pI4/%d)", __func__,
			   &aggr->p.prefix, aggr->p.prefixlen);

	/* Sent a Max age LSA if it is already originated. */
	if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED)) {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug("%s: Flushing Aggregate route (%pI4/%d)",
				   __func__, &aggr->p.prefix,
				   aggr->p.prefixlen);
		ospf_external_lsa_flush(ospf, 0, &aggr->p, 0);
	}

	rn->info = NULL;
	route_unlock_node(rn);
}

struct ospf_external_aggr_rt *
ospf_extrenal_aggregator_lookup(struct ospf *ospf, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_external_aggr_rt *summary_rt = NULL;

	rn = route_node_lookup(ospf->rt_aggr_tbl, (struct prefix *)p);
	if (rn) {
		summary_rt = rn->info;
		route_unlock_node(rn);
		return summary_rt;
	}
	return NULL;
}

struct ospf_external_aggr_rt *ospf_external_aggr_match(struct ospf *ospf,
						       struct prefix_ipv4 *p)
{
	struct route_node *node;
	struct ospf_external_aggr_rt *summary_rt = NULL;

	node = route_node_match(ospf->rt_aggr_tbl, (struct prefix *)p);
	if (node) {

		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			if (node->info) {
				struct ospf_external_aggr_rt *ag = node->info;

				zlog_debug(
					"%s: Matching aggregator found.prefix:%pI4/%d Aggregator %pI4/%d",
					__func__, &p->prefix, p->prefixlen,
					&ag->p.prefix, ag->p.prefixlen);
			}

		summary_rt = node->info;
		route_unlock_node(node);
		return summary_rt;
	}
	return NULL;
}

void ospf_unlink_ei_from_aggr(struct ospf *ospf,
			      struct ospf_external_aggr_rt *aggr,
			      struct external_info *ei)
{
	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug(
			"%s: Unlinking extrenal route(%pI4/%d) from aggregator(%pI4/%d), external route count:%ld",
			__func__, &ei->p.prefix, ei->p.prefixlen,
			&aggr->p.prefix, aggr->p.prefixlen,
			OSPF_EXTERNAL_RT_COUNT(aggr));
	hash_release(aggr->match_extnl_hash, ei);
	ei->aggr_route = NULL;

	/* Flush the aggreagte route if matching
	 * external route count becomes zero.
	 */
	if (!OSPF_EXTERNAL_RT_COUNT(aggr)
	    && CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED)) {

		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug("%s: Flushing the aggreagte route (%pI4/%d)",
				   __func__, &aggr->p.prefix,
				   aggr->p.prefixlen);

		/* Flush the aggregate LSA */
		ospf_external_lsa_flush(ospf, 0, &aggr->p, 0);

		/* Unset the Origination flag */
		UNSET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
	}
}

static void ospf_link_ei_to_aggr(struct ospf_external_aggr_rt *aggr,
				 struct external_info *ei)
{
	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug(
			"%s: Linking extrenal route(%pI4/%d) to aggregator(%pI4/%d)",
			__func__, &ei->p.prefix, ei->p.prefixlen,
			&aggr->p.prefix, aggr->p.prefixlen);
	(void)hash_get(aggr->match_extnl_hash, ei, hash_alloc_intern);
	ei->aggr_route = aggr;
}

struct ospf_lsa *ospf_originate_summary_lsa(struct ospf *ospf,
					    struct ospf_external_aggr_rt *aggr,
					    struct external_info *ei)
{
	struct ospf_lsa *lsa;
	struct external_info ei_aggr;
	struct as_external_lsa *asel;
	struct ospf_external_aggr_rt *old_aggr;
	route_tag_t tag = 0;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Prepare to originate Summary route(%pI4/%d)",
			   __func__, &aggr->p.prefix, aggr->p.prefixlen);

	/* This case to handle when the overlapping aggregator address
	 * is availbe.Best match will be considered.So need to delink
	 * from old aggregator and link to the new aggr.
	 */
	if (ei->aggr_route) {
		if (ei->aggr_route != aggr) {
			old_aggr = ei->aggr_route;
			ospf_unlink_ei_from_aggr(ospf, old_aggr, ei);
		}
	}

	/* Add the external route to hash table */
	ospf_link_ei_to_aggr(aggr, ei);

	lsa = ospf_external_info_find_lsa(ospf, &aggr->p);
	/* Don't originate external LSA,
	 * If it is configured not to advertise.
	 */
	if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE)) {
		/* If it is already originated as external LSA,
		 * But, it is configured not to advertise then
		 * flush the originated external lsa.
		 */
		if (lsa)
			ospf_external_lsa_flush(ospf, 0, &aggr->p, 0);
		UNSET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);

		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug(
				"%s: Don't originate the summary address,It is configured to not-advertise.",
				__func__);
		return NULL;
	}

	/* Prepare the extrenal_info for aggregator */
	memset(&ei_aggr, 0, sizeof(ei_aggr));
	ei_aggr.p = aggr->p;
	ei_aggr.tag = aggr->tag;
	ei_aggr.type = 0;
	ei_aggr.instance = ospf->instance;
	ei_aggr.route_map_set.metric = -1;
	ei_aggr.route_map_set.metric_type = -1;

	/* Summary route already originated,
	 * So, Do nothing.
	 */
	if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED)) {
		if (!lsa) {
			flog_warn(EC_OSPF_LSA_MISSING,
				  "%s: Could not refresh/originate %pI4/%d",
				  __func__, &aggr->p.prefix, aggr->p.prefixlen);
			return NULL;
		}

		asel = (struct as_external_lsa *)lsa->data;
		tag = (unsigned long)ntohl(asel->e[0].route_tag);

		/* If tag modified , then re-originate the route
		 * with modified tag details.
		 */
		if (tag != ei_aggr.tag) {
			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug(
					"%s: Route tag changed(old:%d new:%d,So refresh the summary route.(%pI4/%d)",
					__func__, tag, ei_aggr.tag,
					&aggr->p.prefix, aggr->p.prefixlen);

			ospf_external_lsa_refresh(ospf, lsa, &ei_aggr,
						  LSA_REFRESH_FORCE, 1);
		}
		return lsa;
	}

	if (lsa && IS_LSA_MAXAGE(lsa)) {
		/* This is special case.
		 * If a summary route need to be originated but where
		 * summary route already exist in lsdb with maxage, then
		 * it need to be refreshed.
		 */
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug(
				"%s: LSA is in MAX-AGE so refreshing LSA(%pI4/%d)",
				__func__, &aggr->p.prefix, aggr->p.prefixlen);

		ospf_external_lsa_refresh(ospf, lsa, &ei_aggr,
					  LSA_REFRESH_FORCE, 1);
		SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
		return lsa;
	}

	/* If the external route prefix same as aggregate route
	 * and if external route is already originated as TYPE-5
	 * then it need to be refreshed and originate bit should
	 * be set.
	 */
	if (lsa && prefix_same((struct prefix *)&ei_aggr.p,
			       (struct prefix *)&ei->p)) {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug(
				"%s: External route prefix is same as aggr so refreshing LSA(%pI4/%d)",
				__func__, &aggr->p.prefix, aggr->p.prefixlen);
		ospf_external_lsa_refresh(ospf, lsa, &ei_aggr,
					  LSA_REFRESH_FORCE, 1);
		SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
		return lsa;
	}

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Originate Summary route(%pI4/%d)", __func__,
			   &aggr->p.prefix, aggr->p.prefixlen);

	/* Originate summary LSA */
	lsa = ospf_external_lsa_originate(ospf, &ei_aggr);
	if (lsa) {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug("%s: Set the origination bit for aggregator",
				   __func__);
		SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
	}

	return lsa;
}
void ospf_unset_all_aggr_flag(struct ospf *ospf)
{
	struct route_node *rn = NULL;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("Unset the origination bit for all aggregator");

	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		struct ospf_external_aggr_rt *aggr = rn->info;

		UNSET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
	}
}

static void ospf_delete_all_marked_aggregators(struct ospf *ospf)
{
	struct route_node *rn = NULL;

	/* Loop through all the aggregators, Delete all aggregators
	 * which are marked as DELETE. Set action to NONE for remaining
	 * aggregators
	 */
	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		struct ospf_external_aggr_rt *aggr = rn->info;

		if (aggr->action != OSPF_ROUTE_AGGR_DEL) {
			aggr->action = OSPF_ROUTE_AGGR_NONE;
			continue;
		}
		ospf_external_aggr_delete(ospf, rn);
		ospf_external_aggregator_free(aggr);
	}
}

static void ospf_handle_aggregated_exnl_rt(struct ospf *ospf,
					   struct ospf_external_aggr_rt *aggr,
					   struct external_info *ei)
{
	struct ospf_lsa *lsa;
	struct as_external_lsa *al;
	struct in_addr mask;

	/* Handling the case where the external route prefix
	 * and aggregate prefix is same
	 * If same don't flush the originated external LSA.
	 */
	if (prefix_same((struct prefix *)&aggr->p, (struct prefix *)&ei->p)) {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug(
				"%s: External Route prefix same as Aggregator(%pI4/%d), so don't flush.",
				__func__, &ei->p.prefix, ei->p.prefixlen);
		return;
	}

	lsa = ospf_external_info_find_lsa(ospf, &ei->p);
	if (lsa) {
		al = (struct as_external_lsa *)lsa->data;
		masklen2ip(ei->p.prefixlen, &mask);

		if (mask.s_addr != al->mask.s_addr)
			return;

		ospf_external_lsa_flush(ospf, ei->type, &ei->p, 0);
	}
}

static void ospf_handle_exnl_rt_after_aggr_del(struct ospf *ospf,
					       struct external_info *ei)
{
	struct ospf_lsa *lsa;

	/* Process only marked external routes.
	 * These routes were part of a deleted
	 * aggregator.So, originate now.
	 */
	if (!ei->to_be_processed)
		return;

	ei->to_be_processed = false;

	lsa = ospf_external_info_find_lsa(ospf, &ei->p);

	if (lsa)
		ospf_external_lsa_refresh(ospf, lsa, ei, LSA_REFRESH_FORCE, 0);
	else {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug("%s: Originate external route(%pI4/%d)",
				   __func__, &ei->p.prefix, ei->p.prefixlen);

		ospf_external_lsa_originate(ospf, ei);
	}
}

static void ospf_handle_external_aggr_add(struct ospf *ospf)
{
	struct external_info *ei;
	struct route_node *rn = NULL;
	struct route_table *rt = NULL;
	int type = 0;

	/* Delete all the aggregators which are marked as
	 * OSPF_ROUTE_AGGR_DEL.
	 */
	ospf_delete_all_marked_aggregators(ospf);

	for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
		struct list *ext_list;
		struct listnode *node;
		struct ospf_external *ext;
		struct ospf_external_aggr_rt *aggr;

		ext_list = ospf->external[type];
		if (!ext_list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(ext_list, node, ext)) {
			rt = ext->external_info;
			if (!rt)
				continue;

			for (rn = route_top(rt); rn; rn = route_next(rn)) {
				if (!rn->info)
					continue;

				ei = rn->info;
				if (is_default_prefix4(&ei->p))
					continue;

				/* Check the AS-external-LSA
				 * should be originated.
				 */
				if (!ospf_redistribute_check(ospf, ei, NULL))
					continue;

				aggr = ospf_external_aggr_match(ospf, &ei->p);

				/* If matching aggregator found, Add
				 * the external route reference to the
				 * aggregator and originate the aggr
				 * route if it is advertisable.
				 * flush the external LSA if it is
				 * already originated for this external
				 * prefix.
				 */
				if (aggr) {
					ospf_originate_summary_lsa(ospf, aggr,
								   ei);

					/* All aggregated external rts
					 * are handled here.
					 */
					ospf_handle_aggregated_exnl_rt(
						ospf, aggr, ei);
					continue;
				}

				/* External routes which are only out
				 * of aggregation will be handled here.
				 */
				ospf_handle_exnl_rt_after_aggr_del(ospf, ei);
			}
		}
	}
}

static void
ospf_aggr_handle_advertise_change(struct ospf *ospf,
				  struct ospf_external_aggr_rt *aggr,
				  struct external_info *ei_aggr)
{
	struct ospf_lsa *lsa;

	/* Check if advertise option modified. */
	if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE)) {

		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug(
				"%s: Don't originate the summary address,It is configured to not-advertise.",
				__func__);

		if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED)) {

			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug(
					"%s: No-advertise,So Flush the Aggregate route(%pI4/%d)",
					__func__, &aggr->p.prefix,
					aggr->p.prefixlen);

			ospf_external_lsa_flush(ospf, 0, &aggr->p, 0);

			UNSET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);
		}
		return;
	}

	if (!CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED)) {
		if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
			zlog_debug("%s: Now it is advatisable", __func__);

		lsa = ospf_external_info_find_lsa(ospf, &ei_aggr->p);
		if (lsa && IS_LSA_MAXAGE(lsa)) {
			/* This is special case.
			 * If a summary route need to be originated but where
			 * summary route already exist in lsdb with maxage, then
			 * it need to be refreshed.
			 */
			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug(
					"%s: It is already with Maxage, So refresh it (%pI4/%d)",
					__func__, &aggr->p.prefix,
					aggr->p.prefixlen);

			ospf_external_lsa_refresh(ospf, lsa, ei_aggr,
						  LSA_REFRESH_FORCE, 1);

			SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_ORIGINATED);

		} else {

			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug(
					"%s: Originate Aggregate LSA (%pI4/%d)",
					__func__, &aggr->p.prefix,
					aggr->p.prefixlen);

			/* Originate summary LSA */
			lsa = ospf_external_lsa_originate(ospf, ei_aggr);
			if (lsa)
				SET_FLAG(aggr->flags,
					 OSPF_EXTERNAL_AGGRT_ORIGINATED);
		}
	}
}

static void ospf_handle_external_aggr_update(struct ospf *ospf)
{
	struct route_node *rn = NULL;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Process modified aggregators.", __func__);

	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn)) {
		struct ospf_external_aggr_rt *aggr;
		struct ospf_lsa *lsa = NULL;
		struct as_external_lsa *asel = NULL;
		struct external_info ei_aggr;
		route_tag_t tag = 0;

		if (!rn->info)
			continue;

		aggr = rn->info;

		if (aggr->action == OSPF_ROUTE_AGGR_DEL) {
			aggr->action = OSPF_ROUTE_AGGR_NONE;
			ospf_external_aggr_delete(ospf, rn);

			hash_clean_and_free(
				&aggr->match_extnl_hash,
				(void *)ospf_aggr_handle_external_info);

			ospf_external_aggregator_free(aggr);
		} else if (aggr->action == OSPF_ROUTE_AGGR_MODIFY) {

			aggr->action = OSPF_ROUTE_AGGR_NONE;

			/* Prepare the extrenal_info for aggregator */
			memset(&ei_aggr, 0, sizeof(ei_aggr));
			ei_aggr.p = aggr->p;
			ei_aggr.tag = aggr->tag;
			ei_aggr.type = 0;
			ei_aggr.instance = ospf->instance;
			ei_aggr.route_map_set.metric = -1;
			ei_aggr.route_map_set.metric_type = -1;

			/* Check if tag modified */
			if (CHECK_FLAG(aggr->flags,
				       OSPF_EXTERNAL_AGGRT_ORIGINATED)) {
				lsa = ospf_external_info_find_lsa(ospf,
								  &ei_aggr.p);
				if (!lsa) {
					flog_warn(EC_OSPF_LSA_MISSING,
						  "%s: Could not refresh/originate %pI4/%d",
						  __func__, &aggr->p.prefix,
						  aggr->p.prefixlen);
					continue;
				}

				asel = (struct as_external_lsa *)lsa->data;
				tag = (unsigned long)ntohl(
					asel->e[0].route_tag);

				/* If tag modified , then re-originate the
				 * route with modified tag details.
				 */
				if (tag != ei_aggr.tag) {
					if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
						zlog_debug(
							"%s: Route tag changed(old:%d new:%d,So refresh the summary route.(%pI4/%d)",
							__func__, tag,
							ei_aggr.tag,
							&aggr->p.prefix,
							aggr->p.prefixlen);

					ospf_external_lsa_refresh(
						ospf, lsa, &ei_aggr,
						LSA_REFRESH_FORCE, 1);
				}
			}

			/* Advertise option modified ?
			 * If so, handled it here.
			 */
			ospf_aggr_handle_advertise_change(ospf, aggr, &ei_aggr);
		}
	}
}

static void ospf_asbr_external_aggr_process(struct event *thread)
{
	struct ospf *ospf = EVENT_ARG(thread);
	int operation = 0;

	ospf->t_external_aggr = NULL;
	operation = ospf->aggr_action;

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: operation:%d", __func__, operation);

	switch (operation) {
	case OSPF_ROUTE_AGGR_ADD:
		ospf_handle_external_aggr_add(ospf);
		break;
	case OSPF_ROUTE_AGGR_DEL:
	case OSPF_ROUTE_AGGR_MODIFY:
		ospf_handle_external_aggr_update(ospf);
		break;
	default:
		break;
	}
}
static void ospf_external_aggr_timer(struct ospf *ospf,
				     struct ospf_external_aggr_rt *aggr,
				     enum ospf_aggr_action_t operation)
{
	aggr->action = operation;

	if (ospf->t_external_aggr) {
		if (ospf->aggr_action == OSPF_ROUTE_AGGR_ADD) {

			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug("%s: Not required to restart timer,set is already added.",
					   __func__);
			return;
		}

		if (operation == OSPF_ROUTE_AGGR_ADD) {
			if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
				zlog_debug(
					"%s, Restarting Aggregator delay timer.",
					__func__);
			EVENT_OFF(ospf->t_external_aggr);
		}
	}

	if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
		zlog_debug("%s: Start Aggregator delay timer %u(in seconds).",
			   __func__, ospf->aggr_delay_interval);

	ospf->aggr_action = operation;
	event_add_timer(master, ospf_asbr_external_aggr_process, ospf,
			ospf->aggr_delay_interval, &ospf->t_external_aggr);
}

int ospf_asbr_external_aggregator_set(struct ospf *ospf, struct prefix_ipv4 *p,
				      route_tag_t tag)
{
	struct ospf_external_aggr_rt *aggregator;

	aggregator = ospf_extrenal_aggregator_lookup(ospf, p);

	if (aggregator) {
		if (CHECK_FLAG(aggregator->flags,
			       OSPF_EXTERNAL_AGGRT_NO_ADVERTISE))
			UNSET_FLAG(aggregator->flags,
				   OSPF_EXTERNAL_AGGRT_NO_ADVERTISE);
		else if (aggregator->tag == tag)
			return OSPF_SUCCESS;

		aggregator->tag = tag;

		ospf_external_aggr_timer(ospf, aggregator,
					 OSPF_ROUTE_AGGR_MODIFY);
	} else {
		aggregator = ospf_external_aggregator_new(p);
		if (!aggregator)
			return OSPF_FAILURE;

		aggregator->tag = tag;

		ospf_external_aggr_add(ospf, aggregator);
		ospf_external_aggr_timer(ospf, aggregator, OSPF_ROUTE_AGGR_ADD);
	}

	return OSPF_SUCCESS;
}

int ospf_asbr_external_aggregator_unset(struct ospf *ospf,
					struct prefix_ipv4 *p, route_tag_t tag)
{
	struct route_node *rn;
	struct ospf_external_aggr_rt *aggr;

	rn = route_node_lookup(ospf->rt_aggr_tbl, (struct prefix *)p);
	if (!rn)
		return OSPF_INVALID;
	route_unlock_node(rn);

	aggr = rn->info;

	if (tag && (tag != aggr->tag))
		return OSPF_INVALID;

	if (!OSPF_EXTERNAL_RT_COUNT(aggr)) {
		ospf_external_aggr_delete(ospf, rn);
		ospf_external_aggregator_free(aggr);
		return OSPF_SUCCESS;
	}

	ospf_external_aggr_timer(ospf, aggr, OSPF_ROUTE_AGGR_DEL);

	return OSPF_SUCCESS;
}

int ospf_asbr_external_rt_no_advertise(struct ospf *ospf, struct prefix_ipv4 *p)
{
	struct ospf_external_aggr_rt *aggr;
	route_tag_t tag = 0;

	aggr = ospf_extrenal_aggregator_lookup(ospf, p);
	if (aggr) {
		if (CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE))
			return OSPF_SUCCESS;

		SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE);

		aggr->tag = tag;

		if (!OSPF_EXTERNAL_RT_COUNT(aggr))
			return OSPF_SUCCESS;

		ospf_external_aggr_timer(ospf, aggr, OSPF_ROUTE_AGGR_MODIFY);
	} else {
		aggr = ospf_external_aggregator_new(p);

		if (!aggr)
			return OSPF_FAILURE;

		SET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE);
		ospf_external_aggr_add(ospf, aggr);
		ospf_external_aggr_timer(ospf, aggr, OSPF_ROUTE_AGGR_ADD);
	}

	return OSPF_SUCCESS;
}

int ospf_asbr_external_rt_advertise(struct ospf *ospf, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_external_aggr_rt *aggr;

	rn = route_node_lookup(ospf->rt_aggr_tbl, (struct prefix *)p);
	if (!rn)
		return OSPF_INVALID;
	route_unlock_node(rn);

	aggr = rn->info;

	if (!CHECK_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE))
		return OSPF_INVALID;

	UNSET_FLAG(aggr->flags, OSPF_EXTERNAL_AGGRT_NO_ADVERTISE);

	if (!OSPF_EXTERNAL_RT_COUNT(aggr))
		return OSPF_SUCCESS;

	ospf_external_aggr_timer(ospf, aggr, OSPF_ROUTE_AGGR_MODIFY);
	return OSPF_SUCCESS;
}

int ospf_external_aggregator_timer_set(struct ospf *ospf, uint16_t interval)
{
	ospf->aggr_delay_interval = interval;
	return OSPF_SUCCESS;
}
