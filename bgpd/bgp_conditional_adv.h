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

#ifndef _FRR_BGP_CONDITION_ADV_H
#define _FRR_BGP_CONDITION_ADV_H
#include <zebra.h>
#include "prefix.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Polling time for monitoring condition-map routes in route table */
#define CONDITIONAL_ROUTES_POLL_TIME 60

#define FOREACH_ACCESS_LIST_FILTER(alist, filter)                              \
	for (filter = alist->head; filter; filter = filter->next)

static inline bool is_rmap_valid(struct route_map *rmap)
{
	if (!rmap || !rmap->head)
		return false;

	/* Doesn't make sense to configure advertise
	 * or condition map in deny/any clause.
	 */
	if (rmap->head->type != RMAP_PERMIT)
		return false;

	/* If a match command is not present, all routes match the clause */
	if (!rmap->head->match_list.head)
		return false;

	return true;
}

static inline afi_t get_afi_from_match_rule(const char *str)
{
	if (!strcmp(str, "ip address"))
		return AFI_IP;
	else if (!strcmp(str, "ipv6 address"))
		return AFI_IP6;
	else
		return AFI_MAX;
}

static inline bool advertise_dest_routes(struct update_subgroup *subgrp,
					 struct bgp_dest *dest,
					 struct peer *peer, afi_t afi,
					 safi_t safi, int addpath_capable,
					 bool advertise)
{
	struct attr attr;
	struct bgp_path_info *pi = NULL;
	const struct prefix *dest_p = NULL;
	bool route_advertised = false;

	dest_p = (struct prefix *)bgp_dest_get_prefix(dest);
	if (!dest_p)
		return route_advertised;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
		    || (addpath_capable
			&& bgp_addpath_tx_path(peer->addpath_type[afi][safi],
					       pi))) {

			/* Skip route-map checks in subgroup_announce_check
			 * while executing from the conditional advertise
			 * scanner process. otherwise when route-map is also
			 * configured on same peer, routes in advertise-map
			 * may not be advertised as expected.
			 */
			if (advertise
			    && subgroup_announce_check(dest, pi, subgrp, dest_p,
						       &attr, true)) {
				bgp_adj_out_set_subgroup(dest, subgrp, &attr,
							 pi);
				route_advertised = true;
			} else {
				/* If default originate is enabled for the
				 * peer, do not send explicit withdraw.
				 * This will prevent deletion of default route
				 * advertised through default originate.
				 */
				if (CHECK_FLAG(peer->af_flags[afi][safi],
					       PEER_FLAG_DEFAULT_ORIGINATE)
				    && is_default_prefix(dest_p))
					break;

				bgp_adj_out_unset_subgroup(
					dest, subgrp, 1,
					bgp_addpath_id_for_peer(
						peer, afi, safi,
						&pi->tx_addpath));
				route_advertised = true;
			}
		}
	}
	return route_advertised;
}

struct bgp_dest *bgp_dest_matches_filter_prefix(struct bgp_table *table,
						struct filter *filter);
extern enum route_map_cmd_result_t
bgp_check_rmap_prefixes_in_bgp_table(struct bgp_table *table,
				     struct route_map *rmap);
extern void bgp_conditional_adv_enable(struct peer *peer, afi_t afi,
				       safi_t safi);
extern void bgp_conditional_adv_disable(struct peer *peer, afi_t afi,
					safi_t safi);
extern bool bgp_conditional_adv_routes(struct peer *peer, afi_t afi,
				       safi_t safi, struct bgp_table *table,
				       struct route_map *rmap, bool advertise);
#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CONDITION_ADV_H */
