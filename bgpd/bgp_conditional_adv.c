/*
 * BGP Conditional advertisement
 * Copyright (C) 2020  Samsung Research Institute Bangalore.
 *			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "bgpd/bgp_conditional_adv.h"

const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json);

/* We just need bgp_dest node matches with filter prefix. So no need to
 * traverse each path here.
 */
struct bgp_dest *bgp_dest_matches_filter_prefix(struct bgp_table *table,
						struct filter *filter)
{
	uint32_t check_addr;
	uint32_t check_mask;
	struct in_addr mask;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;
	const struct prefix *dest_p = NULL;
	struct filter_cisco *cfilter = NULL;
	struct filter_zebra *zfilter = NULL;

	if (filter->cisco) {
		cfilter = &filter->u.cfilter;
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			dest_p = (struct prefix *)bgp_dest_get_prefix(dest);
			if (!dest_p)
				continue;
			pi = bgp_dest_get_bgp_path_info(dest);
			if (!pi)
				continue;
			check_addr = dest_p->u.prefix4.s_addr
				     & ~cfilter->addr_mask.s_addr;
			if (memcmp(&check_addr, &cfilter->addr.s_addr,
				   sizeof(check_addr))
			    != 0)
				continue;
			if (cfilter->extended) {
				masklen2ip(dest_p->prefixlen, &mask);
				check_mask = mask.s_addr
					     & ~cfilter->mask_mask.s_addr;
				if (memcmp(&check_mask, &cfilter->mask.s_addr,
					   sizeof(check_mask))
				    != 0)
					continue;
			}
			return dest;
		}
	} else {
		zfilter = &filter->u.zfilter;
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			dest_p = bgp_dest_get_prefix(dest);
			if (!dest_p)
				continue;
			pi = bgp_dest_get_bgp_path_info(dest);
			if (!pi)
				continue;
			if ((zfilter->prefix.family != dest_p->family)
			    || (zfilter->exact
				&& (zfilter->prefix.prefixlen
				    != dest_p->prefixlen)))
				continue;
			else if (!prefix_match(&zfilter->prefix, dest_p))
				continue;
			else
				return dest;
		}
	}
	return NULL;
}

enum route_map_cmd_result_t
bgp_check_rmap_prefixes_in_bgp_table(struct bgp_table *table,
				     struct route_map *rmap)
{
	afi_t afi;
	struct access_list *alist = NULL;
	struct filter *alist_filter = NULL;
	struct bgp_dest *dest = NULL;
	struct route_map_rule *match = NULL;
	enum route_map_cmd_result_t ret = RMAP_NOOP;

	if (!is_rmap_valid(rmap))
		return ret;

	/* If several match commands are configured, all must succeed for a
	 * given route in order for that route to match the clause (logical AND)
	 */
	for (match = rmap->head->match_list.head; match; match = match->next) {

		if (!match->cmd || !match->cmd->str || !match->value)
			continue;

		ret = RMAP_NOMATCH;

		afi = get_afi_from_match_rule(match->cmd->str);
		if (afi == AFI_MAX)
			return ret;

		alist = access_list_lookup(afi, (char *)match->value);
		if (!alist)
			return ret;

		/* If a match command refers to several objects in one
		 * command either of them should match (i.e logical OR)
		 */
		FOREACH_ACCESS_LIST_FILTER(alist, alist_filter) {
			dest = bgp_dest_matches_filter_prefix(table,
							      alist_filter);
			if (!dest)
				continue;

			ret = RMAP_MATCH;
			break;
		}
		/* None of the access-list's filter prefix of this Match rule is
		 * not matched with BGP table.
		 * So we do not need to process the remaining match rules
		 */
		if (ret != RMAP_MATCH)
			break;
	}

	/* route-map prefix not matched with prefixes in BGP table */
	return ret;
}

bool bgp_conditional_adv_routes(struct peer *peer, afi_t afi, safi_t safi,
				struct bgp_table *table, struct route_map *rmap,
				bool advertise)
{
	int addpath_capable;
	afi_t match_afi;
	bool ret = false;
	bool route_advertised = false;
	struct peer_af *paf = NULL;
	struct bgp_dest *dest = NULL;
	struct access_list *alist = NULL;
	struct filter *alist_filter = NULL;
	struct route_map_rule *match = NULL;
	struct update_subgroup *subgrp = NULL;

	paf = peer_af_find(peer, afi, safi);
	if (!paf)
		return ret;

	subgrp = PAF_SUBGRP(paf);
	/* Ignore if subgroup doesn't exist (implies AF is not negotiated) */
	if (!subgrp)
		return ret;

	if (!is_rmap_valid(rmap))
		return ret;

	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);

	/* If several match commands are configured, all must succeed for a
	 * given route in order for that route to match the clause (i.e. logical
	 * AND). But we are skipping this rule and advertising if match rule is
	 * valid and access-lists are having valid prefix - To be discussed
	 */
	for (match = rmap->head->match_list.head; match; match = match->next) {

		if (!match->cmd || !match->cmd->str || !match->value)
			continue;

		match_afi = get_afi_from_match_rule(match->cmd->str);
		if (match_afi == AFI_MAX)
			continue;

		alist = access_list_lookup(match_afi, (char *)match->value);
		if (!alist)
			continue;

		if (safi == SAFI_LABELED_UNICAST)
			safi = SAFI_UNICAST;

		/* If a match command refers to several objects in one
		 * command either of them should match (i.e logical OR)
		 */
		FOREACH_ACCESS_LIST_FILTER(alist, alist_filter) {
			dest = bgp_dest_matches_filter_prefix(table,
							      alist_filter);
			if (!dest)
				continue;

			ret = advertise_dest_routes(subgrp, dest, peer, afi,
						    safi, addpath_capable,
						    advertise);

			/* Atleast one route advertised */
			if (!route_advertised && ret)
				route_advertised = true;
		}
	}
	return route_advertised;
}

/* Handler of conditional advertisement timer event.
 * Each route in the condition-map is evaluated.
 */
static int bgp_conditional_adv_timer(struct thread *t)
{
	afi_t afi;
	safi_t safi;
	int pfx_rcd_safi;
	struct bgp *bgp = NULL;
	struct peer *peer = NULL;
	struct peer_af *paf = NULL;
	struct bgp_table *table = NULL;
	struct bgp_filter *filter = NULL;
	struct listnode *node, *nnode = NULL;
	struct update_subgroup *subgrp = NULL;
	enum route_map_cmd_result_t ret, prev_ret;
	bool route_advertised = false;
	bool adv_withdrawn = false;
	int adv_conditional = 0;

	bgp = THREAD_ARG(t);
	assert(bgp);

	bgp->t_condition_check = NULL;
	thread_add_timer(bm->master, bgp_conditional_adv_timer, bgp,
			 CONDITIONAL_ROUTES_POLL_TIME, &bgp->t_condition_check);

	/* loop through each peer and advertise or withdraw routes if
	 * advertise-map is configured and prefix(es) in condition-map
	 * does exist(exist-map)/not exist(non-exist-map) in BGP table based on
	 * condition(exist-map or non-exist map)
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		if (strmatch(get_afi_safi_str(afi, safi, true), "Unknown"))
			continue;

		/* labeled-unicast routes are installed in the unicast table
		 * so in order to display the correct PfxRcd value we must
		 * look at SAFI_UNICAST
		 */
		pfx_rcd_safi =
			(safi == SAFI_LABELED_UNICAST) ? SAFI_UNICAST : safi;

		table = bgp->rib[afi][pfx_rcd_safi];
		if (!table)
			continue;

		/* Process conditional advertisement for each peer */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				continue;
			if (!peer->afc[afi][safi])
				continue;

			filter = &peer->filter[afi][safi];

			if ((!filter->advmap.aname) || (!filter->advmap.cname)
			    || (!filter->advmap.amap) || (!filter->advmap.cmap))
				continue;

			/* cmap (route-map attached to exist-map or
			 * non-exist-map) map validation
			 */
			adv_withdrawn = false;
			adv_conditional = 0;

			ret = bgp_check_rmap_prefixes_in_bgp_table(table,
							filter->advmap.cmap);
			prev_ret =
				peer->advmap_info[afi][safi].cmap_prev_status;

			switch (ret) {
			case RMAP_NOOP:
				if (prev_ret == RMAP_NOOP)
					continue;

				peer->advmap_info[afi][safi].cmap_prev_status =
					ret;
				if (filter->advmap.status)
					continue;

				/* advertise previously withdrawn routes */
				adv_withdrawn = true;
				break;

			case RMAP_MATCH:
				/* Handle configuration changes */
				if (peer->advmap_info[afi][safi]
					    .config_change) {
					/* If configuration(ACL filetr prefixes)
					 * is changed and if the advertise-map
					 * filter previous status was withdraw
					 * then we need to advertise the
					 * previously withdrawn routes.
					 * Nothing to do if the filter status
					 * was advertise.
					 */
					if ((prev_ret != RMAP_NOOP)
					    && !filter->advmap.status)
						adv_withdrawn = true;

					adv_conditional =
						(filter->advmap.condition
						 == CONDITION_EXIST)
							? NLRI
							: WITHDRAW;
					peer->advmap_info[afi][safi]
						.config_change = false;
				} else {
					if (prev_ret != RMAP_MATCH)
						adv_conditional =
							(filter->advmap
								 .condition
							 == CONDITION_EXIST)
								? NLRI
								: WITHDRAW;
				}
				peer->advmap_info[afi][safi].cmap_prev_status =
					ret;
				break;

			case RMAP_NOMATCH:
				/* Handle configuration changes */
				if (peer->advmap_info[afi][safi]
					    .config_change) {
					/* If configuration(ACL filetr prefixes)
					 * is changed and if the advertise-map
					 * filter previous status was withdraw
					 * then we need to advertise the
					 * previously withdrawn routes.
					 * Nothing to do if the filter status
					 * was advertise.
					 */
					if ((prev_ret != RMAP_NOOP)
					    && !filter->advmap.status)
						adv_withdrawn = true;

					adv_conditional =
						(filter->advmap.condition
						 == CONDITION_EXIST)
							? WITHDRAW
							: NLRI;
					peer->advmap_info[afi][safi]
						.config_change = false;
				} else {
					if (prev_ret != RMAP_NOMATCH)
						adv_conditional =
							(filter->advmap
								 .condition
							 == CONDITION_EXIST)
								? WITHDRAW
								: NLRI;
				}
				peer->advmap_info[afi][safi].cmap_prev_status =
					ret;
				break;

			case RMAP_OKAY:
			case RMAP_ERROR:
			default:
				break;
			}

			/* amap (route-map attached to advertise-map)
			 * validation.
			 */
			ret = is_rmap_valid(filter->advmap.amap) ? RMAP_MATCH
								 : RMAP_NOOP;
			prev_ret =
				peer->advmap_info[afi][safi].amap_prev_status;

			if (ret == RMAP_NOOP) {
				if (prev_ret == RMAP_NOOP) {
					if (!adv_withdrawn)
						continue;
					/* Should not reach here. */
				}
				if (filter->advmap.status && !adv_withdrawn)
					continue;
			}

			/* Derive conditional advertisement status from
			 * condition and return value of condition-map
			 * validation.
			 */
			if (adv_conditional == NLRI)
				filter->advmap.status = true;
			else if (adv_conditional == WITHDRAW)
				filter->advmap.status = false;
			else {
				/* no change in advertise status. So, only
				 * previously withdrawn routes will be
				 * advertised if needed.
				 */
			}

			if (adv_withdrawn) {
				paf = peer_af_find(peer, afi, safi);
				if (paf) {
					update_subgroup_split_peer(paf, NULL);
					subgrp = paf->subgroup;
					if (subgrp && subgrp->update_group)
						subgroup_announce_table(
							paf->subgroup, NULL);
				}
			}
			if (adv_conditional) {
				route_advertised = bgp_conditional_adv_routes(
					peer, afi, safi, table,
					filter->advmap.amap,
					filter->advmap.status);

				/* amap_prev_status is only to check whether we
				 * have announced any routes(advertise/withdraw)
				 * or not. filter->advmap.status will have the
				 * actual filter status
				 */
				peer->advmap_info[afi][safi].amap_prev_status =
					route_advertised ? RMAP_MATCH
							 : RMAP_NOOP;
			}
		}
	}
	return 0;
}

void bgp_conditional_adv_enable(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp *bgp = peer->bgp;

	assert(bgp);

	/* This flag is used to monitor conditional routes status in BGP table,
	 * and advertise/withdraw routes only when there is a change in BGP
	 * table w.r.t conditional routes
	 */
	peer->advmap_info[afi][safi].amap_prev_status = RMAP_NOOP;
	peer->advmap_info[afi][safi].cmap_prev_status = RMAP_NOOP;
	peer->advmap_info[afi][safi].config_change = true;

	/* advertise-map is already configured on atleast one of its
	 * neighbors (AFI/SAFI). So just increment the counter.
	 */
	if (++bgp->condition_filter_count > 1)
		return;

	/* Register for conditional routes polling timer */
	thread_add_timer(bm->master, bgp_conditional_adv_timer, bgp,
			 CONDITIONAL_ROUTES_POLL_TIME, &bgp->t_condition_check);
}

void bgp_conditional_adv_disable(struct peer *peer, afi_t afi, safi_t safi)
{
	struct bgp *bgp = peer->bgp;

	assert(bgp);

	/* advertise-map is not configured on any of its neighbors or
	 * it is configured on more than one neighbor(AFI/SAFI).
	 * So there's nothing to do except decrementing the counter.
	 */
	if (--bgp->condition_filter_count != 0)
		return;

	/* Last filter removed. So cancel conditional routes polling thread. */
	THREAD_OFF(bgp->t_condition_check);
}
