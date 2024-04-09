// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Static NHT code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "vrf.h"
#include "nexthop.h"
#include "srcdest_table.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"

static void static_nht_update_path(struct static_path *pn, struct prefix *nhp,
				   uint32_t nh_num, vrf_id_t nh_vrf_id)
{
	struct static_nexthop *nh;

	frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
		if (nh->nh_vrf_id != nh_vrf_id)
			continue;

		if (nh->type != STATIC_IPV4_GATEWAY
		    && nh->type != STATIC_IPV4_GATEWAY_IFNAME
		    && nh->type != STATIC_IPV6_GATEWAY
		    && nh->type != STATIC_IPV6_GATEWAY_IFNAME)
			continue;

		if (nhp->family == AF_INET
		    && nhp->u.prefix4.s_addr == nh->addr.ipv4.s_addr)
			nh->nh_valid = !!nh_num;

		if (nhp->family == AF_INET6
		    && memcmp(&nhp->u.prefix6, &nh->addr.ipv6, IPV6_MAX_BYTELEN)
			       == 0)
			nh->nh_valid = !!nh_num;

		if (nh->state == STATIC_START)
			static_zebra_route_add(pn, true);
	}
}

static void static_nht_update_safi(struct prefix *sp, struct prefix *nhp,
				   uint32_t nh_num, afi_t afi, safi_t safi,
				   struct static_vrf *svrf, vrf_id_t nh_vrf_id)
{
	struct route_table *stable;
	struct route_node *rn;
	struct static_path *pn;
	struct static_route_info *si;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	if (sp) {
		rn = srcdest_rnode_lookup(stable, sp, NULL);
		if (rn && rn->info) {
			si = static_route_info_from_rnode(rn);
			frr_each(static_path_list, &si->path_list, pn) {
				static_nht_update_path(pn, nhp, nh_num,
						       nh_vrf_id);
			}
			route_unlock_node(rn);
		}
		return;
	}

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			static_nht_update_path(pn, nhp, nh_num, nh_vrf_id);
		}
	}
}

void static_nht_update(struct prefix *sp, struct prefix *nhp, uint32_t nh_num,
		       afi_t afi, safi_t safi, vrf_id_t nh_vrf_id)
{
	struct static_vrf *svrf;

	RB_FOREACH (svrf, svrf_name_head, &svrfs)
		static_nht_update_safi(sp, nhp, nh_num, afi, safi, svrf,
				       nh_vrf_id);
}

static void static_nht_reset_start_safi(struct prefix *nhp, afi_t afi,
					safi_t safi, struct static_vrf *svrf,
					vrf_id_t nh_vrf_id)
{
	struct route_table *stable;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct route_node *rn;
	struct static_route_info *si;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		si = static_route_info_from_rnode(rn);
		if (!si)
			continue;
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				if (nh->nh_vrf_id != nh_vrf_id)
					continue;

				if (nhp->family == AF_INET
				    && nhp->u.prefix4.s_addr
					       != nh->addr.ipv4.s_addr)
					continue;

				if (nhp->family == AF_INET6
				    && memcmp(&nhp->u.prefix6, &nh->addr.ipv6,
					      16)
					       != 0)
					continue;

				/*
				 * We've been told that a nexthop we
				 * depend on has changed in some manner,
				 * so reset the state machine to allow
				 * us to start over.
				 */
				nh->state = STATIC_START;
			}
		}
	}
}

void static_nht_reset_start(struct prefix *nhp, afi_t afi, safi_t safi,
			    vrf_id_t nh_vrf_id)
{
	struct static_vrf *svrf;

	RB_FOREACH (svrf, svrf_name_head, &svrfs)
		static_nht_reset_start_safi(nhp, afi, safi, svrf, nh_vrf_id);
}

static void static_nht_mark_state_safi(struct prefix *sp, afi_t afi,
				       safi_t safi, struct vrf *vrf,
				       enum static_install_states state)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;

	svrf = vrf->info;
	if (!svrf)
		return;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	rn = srcdest_rnode_lookup(stable, sp, NULL);
	if (!rn)
		return;
	si = rn->info;
	if (si) {
		frr_each(static_path_list, &si->path_list, pn) {
			frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
				nh->state = state;
			}
		}
	}

	route_unlock_node(rn);
}

void static_nht_mark_state(struct prefix *sp, safi_t safi, vrf_id_t vrf_id,
			   enum static_install_states state)
{
	struct vrf *vrf;

	afi_t afi = AFI_IP;

	if (sp->family == AF_INET6)
		afi = AFI_IP6;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf || !vrf->info)
		return;

	static_nht_mark_state_safi(sp, afi, safi, vrf, state);
}
