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

static route_map_result_t
bgp_check_rmap_prefixes_in_bgp_table(struct bgp_table *table,
				     struct route_map *rmap)
{
	struct bgp_dest *dest;
	struct attr dummy_attr;
	struct bgp_path_info path;
	const struct prefix *dest_p;
	struct bgp_path_info *pi;
	route_map_result_t ret = RMAP_PERMITMATCH;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		dest_p = bgp_dest_get_prefix(dest);
		if (!dest_p)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			dummy_attr = *pi->attr;
			path.peer = pi->peer;
			path.attr = &dummy_attr;

			ret = route_map_apply(rmap, dest_p, RMAP_BGP, &path);
			if (ret == RMAP_PERMITMATCH)
				return ret;
		}
	}
	return ret;
}

static void bgp_conditional_adv_routes(struct peer *peer, afi_t afi,
				       safi_t safi, struct bgp_table *table,
				       struct route_map *rmap,
				       enum advertise advertise)
{
	int addpath_capable;
	const struct prefix *dest_p;
	struct attr dummy_attr, attr;
	struct bgp_path_info path;
	struct bgp_path_info *pi;
	struct peer_af *paf = NULL;
	struct bgp_dest *dest = NULL;
	struct update_subgroup *subgrp = NULL;

	paf = peer_af_find(peer, afi, safi);
	if (!paf)
		return;

	subgrp = PAF_SUBGRP(paf);
	/* Ignore if subgroup doesn't exist (implies AF is not negotiated) */
	if (!subgrp)
		return;

	addpath_capable = bgp_addpath_encode_tx(peer, afi, safi);

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		dest_p = bgp_dest_get_prefix(dest);
		if (!dest_p)
			continue;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			dummy_attr = *pi->attr;
			path.peer = pi->peer;
			path.attr = &dummy_attr;

			if (route_map_apply(rmap, dest_p, RMAP_BGP, &path)
			    != RMAP_PERMITMATCH)
				continue;

			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    || (addpath_capable
				&& bgp_addpath_tx_path(
					   peer->addpath_type[afi][safi],
					   pi))) {

				/* Skip route-map checks in
				 * subgroup_announce_check while executing from
				 * the conditional advertise scanner process.
				 * otherwise when route-map is also configured
				 * on same peer, routes in advertise-map may not
				 * be advertised as expected.
				 */
				if ((advertise == ADVERTISE)
				    && subgroup_announce_check(dest, pi, subgrp,
							       dest_p, &attr,
							       true))
					bgp_adj_out_set_subgroup(dest, subgrp,
								 &attr, pi);
				else {
					/* If default originate is enabled for
					 * the peer, do not send explicit
					 * withdraw. This will prevent deletion
					 * of default route advertised through
					 * default originate.
					 */
					if (CHECK_FLAG(
						    peer->af_flags[afi][safi],
						    PEER_FLAG_DEFAULT_ORIGINATE)
					    && is_default_prefix(dest_p))
						break;

					bgp_adj_out_unset_subgroup(
						dest, subgrp, 1,
						bgp_addpath_id_for_peer(
							peer, afi, safi,
							&pi->tx_addpath));
				}
			}
		}
	}
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
	route_map_result_t ret;

	bgp = THREAD_ARG(t);
	assert(bgp);

	bgp->t_condition_check = NULL;
	thread_add_timer(bm->master, bgp_conditional_adv_timer, bgp,
			 CONDITIONAL_ROUTES_POLL_TIME, &bgp->t_condition_check);

	/* loop through each peer and advertise or withdraw routes if
	 * advertise-map is configured and prefix(es) in condition-map
	 * does exist(exist-map)/not exist(non-exist-map) in BGP table
	 * based on condition(exist-map or non-exist map)
	 */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		FOREACH_AFI_SAFI (afi, safi) {
			if (strmatch(get_afi_safi_str(afi, safi, true),
				     "Unknown"))
				continue;

			if (!peer->afc[afi][safi])
				continue;

			/* labeled-unicast routes are installed in the unicast
			 * table so in order to display the correct PfxRcd value
			 * we must look at SAFI_UNICAST
			 */
			pfx_rcd_safi = (safi == SAFI_LABELED_UNICAST)
					       ? SAFI_UNICAST
					       : safi;

			table = bgp->rib[afi][pfx_rcd_safi];
			if (!table)
				continue;

			filter = &peer->filter[afi][safi];

			if (!filter->advmap.aname || !filter->advmap.cname
			    || !filter->advmap.amap || !filter->advmap.cmap)
				continue;

			if (!peer->advmap_config_change[afi][safi]
			    && !peer->advmap_table_change)
				continue;

			/* cmap (route-map attached to exist-map or
			 * non-exist-map) map validation
			 */
			ret = bgp_check_rmap_prefixes_in_bgp_table(
				table, filter->advmap.cmap);

			/* Derive conditional advertisement status from
			 * condition and return value of condition-map
			 * validation.
			 */
			if (filter->advmap.condition == CONDITION_EXIST)
				filter->advmap.advertise =
					(ret == RMAP_PERMITMATCH) ? ADVERTISE
								  : WITHDRAW;
			else
				filter->advmap.advertise =
					(ret == RMAP_PERMITMATCH) ? WITHDRAW
								  : ADVERTISE;

			/* Send regular update as per the existing policy.
			 * There is a change in route-map, match-rule, ACLs,
			 * or route-map filter configuration on the same peer.
			 */
			if (peer->advmap_config_change[afi][safi]) {
				paf = peer_af_find(peer, afi, safi);
				if (paf) {
					update_subgroup_split_peer(paf, NULL);
					subgrp = paf->subgroup;
					if (subgrp && subgrp->update_group)
						subgroup_announce_table(
							paf->subgroup, NULL);
				}
				peer->advmap_config_change[afi][safi] = false;
			}

			/* Send update as per the conditional advertisement */
			bgp_conditional_adv_routes(peer, afi, safi, table,
						   filter->advmap.amap,
						   filter->advmap.advertise);
		}
		peer->advmap_table_change = false;
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
	peer->advmap_config_change[afi][safi] = true;

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
