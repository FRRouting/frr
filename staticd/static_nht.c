/*
 * Static NHT code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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

static void static_nht_update_rn(struct route_node *rn,
				 struct static_route_info *ri,
				 struct prefix *nhp, uint32_t nh_num,
				 vrf_id_t nh_vrf_id, struct vrf *vrf,
				 safi_t safi)
{
	struct static_nexthop *nh;

	RNODE_FOREACH_PATH_NH_RO(ri, nh)
	{
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
		    && memcmp(&nhp->u.prefix6, &nh->addr.ipv6, 16) == 0)
			nh->nh_valid = !!nh_num;

		if (nh->state == STATIC_START)
			static_zebra_route_add(rn, ri, vrf->vrf_id, safi, true);
	}
}

static void static_nht_update_safi(struct prefix *sp, struct prefix *nhp,
				   uint32_t nh_num, afi_t afi, safi_t safi,
				   struct vrf *vrf, vrf_id_t nh_vrf_id)
{
	struct route_table *stable;
	struct static_vrf *svrf;
	struct route_node *rn;
	struct static_route_info *ri;

	svrf = vrf->info;
	if (!svrf)
		return;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	if (sp) {
		rn = srcdest_rnode_lookup(stable, sp, NULL);
		if (rn) {
			RNODE_FOREACH_PATH_RO(rn, ri)
			{
				static_nht_update_rn(rn, ri, nhp, nh_num,
						     nh_vrf_id, vrf, safi);
			}
			route_unlock_node(rn);
		}
		return;
	}

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			static_nht_update_rn(rn, ri, nhp, nh_num, nh_vrf_id,
					     vrf, safi);
		}
	}
}

void static_nht_update(struct prefix *sp, struct prefix *nhp, uint32_t nh_num,
		       afi_t afi, vrf_id_t nh_vrf_id)
{

	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		static_nht_update_safi(sp, nhp, nh_num, afi, SAFI_UNICAST,
				       vrf, nh_vrf_id);
		static_nht_update_safi(sp, nhp, nh_num, afi, SAFI_MULTICAST,
				       vrf, nh_vrf_id);
	}
}

static void static_nht_reset_start_safi(struct prefix *nhp, afi_t afi,
					safi_t safi, struct vrf *vrf,
					vrf_id_t nh_vrf_id)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct static_nexthop *nh;
	struct static_route_info *ri;
	struct route_node *rn;

	svrf = vrf->info;
	if (!svrf)
		return;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	for (rn = route_top(stable); rn; rn = route_next(rn)) {
		RNODE_FOREACH_PATH_RO(rn, ri)
		{
			RNODE_FOREACH_PATH_NH_RO(ri, nh)
			{
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
				 * We've been told that a nexthop we depend
				 * on has changed in some manner, so reset
				 * the state machine to allow us to start
				 * over.
				 */
				nh->state = STATIC_START;
			}
		}
	}
}

void static_nht_reset_start(struct prefix *nhp, afi_t afi, vrf_id_t nh_vrf_id)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		static_nht_reset_start_safi(nhp, afi, SAFI_UNICAST,
					    vrf, nh_vrf_id);
		static_nht_reset_start_safi(nhp, afi, SAFI_MULTICAST,
					    vrf, nh_vrf_id);
	}
}

static void static_nht_mark_state_safi(struct prefix *sp, afi_t afi,
				       safi_t safi, struct vrf *vrf,
				       enum static_install_states state)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct route_node *rn;
	struct static_nexthop *nh;
	struct static_route_info *ri;

	svrf = vrf->info;
	if (!svrf)
		return;

	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return;

	rn = srcdest_rnode_lookup(stable, sp, NULL);
	if (!rn)
		return;

	RNODE_FOREACH_PATH_RO(rn, ri)
	{
		RNODE_FOREACH_PATH_NH_RO(ri, nh)
		{
			nh->state = state;
		}
	}

	route_unlock_node(rn);
}

void static_nht_mark_state(struct prefix *sp, vrf_id_t vrf_id,
			   enum static_install_states state)
{
	struct vrf *vrf;

	afi_t afi = AFI_IP;

	if (sp->family == AF_INET6)
		afi = AFI_IP6;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf || !vrf->info)
		return;

	static_nht_mark_state_safi(sp, afi, SAFI_UNICAST, vrf, state);
	static_nht_mark_state_safi(sp, afi, SAFI_MULTICAST, vrf, state);
}
