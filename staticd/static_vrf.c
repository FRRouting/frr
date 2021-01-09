/*
 * STATICd - vrf code
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

#include "vrf.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"

#include "static_memory.h"
#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_vty.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_RTABLE_INFO, "Static Route Table Info");

static void zebra_stable_node_cleanup(struct route_table *table,
				      struct route_node *node)
{
	struct static_nexthop *nh;
	struct static_path *pn;
	struct static_route_info *si;
	struct route_table *src_table;
	struct route_node *src_node;
	struct static_path *src_pn;
	struct static_route_info *src_si;

	si = node->info;

	if (si) {
		frr_each_safe(static_path_list, &si->path_list, pn) {
			frr_each_safe(static_nexthop_list, &pn->nexthop_list,
				       nh) {
				static_nexthop_list_del(&pn->nexthop_list, nh);
				XFREE(MTYPE_STATIC_NEXTHOP, nh);
			}
			static_path_list_del(&si->path_list, pn);
			XFREE(MTYPE_STATIC_PATH, pn);
		}

		/* clean up for dst table */
		src_table = srcdest_srcnode_table(node);
		if (src_table) {
			/* This means the route_node is part of the top
			 * hierarchy and refers to a destination prefix.
			 */
			for (src_node = route_top(src_table); src_node;
			     src_node = route_next(src_node)) {
				src_si = src_node->info;

				frr_each_safe(static_path_list,
					      &src_si->path_list, src_pn) {
					frr_each_safe(static_nexthop_list,
						      &src_pn->nexthop_list,
						      nh) {
						static_nexthop_list_del(
							&src_pn->nexthop_list,
							nh);
						XFREE(MTYPE_STATIC_NEXTHOP, nh);
					}
					static_path_list_del(&src_si->path_list,
							     src_pn);
					XFREE(MTYPE_STATIC_PATH, src_pn);
				}

				XFREE(MTYPE_STATIC_ROUTE, src_node->info);
			}
		}

		XFREE(MTYPE_STATIC_ROUTE, node->info);
	}
}

static struct static_vrf *static_vrf_alloc(void)
{
	struct route_table *table;
	struct static_vrf *svrf;
	struct stable_info *info;
	safi_t safi;
	afi_t afi;

	svrf = XCALLOC(MTYPE_STATIC_RTABLE_INFO, sizeof(struct static_vrf));

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			if (afi == AFI_IP6)
				table = srcdest_table_init();
			else
				table = route_table_init();

			info = XCALLOC(MTYPE_STATIC_RTABLE_INFO,
				       sizeof(struct stable_info));
			info->svrf = svrf;
			info->afi = afi;
			info->safi = safi;
			route_table_set_info(table, info);

			table->cleanup = zebra_stable_node_cleanup;
			svrf->stable[afi][safi] = table;
		}
	}
	return svrf;
}

static int static_vrf_new(struct vrf *vrf)
{
	struct static_vrf *svrf;

	svrf = static_vrf_alloc();
	vrf->info = svrf;
	svrf->vrf = vrf;

	return 0;
}

static int static_vrf_enable(struct vrf *vrf)
{
	static_zebra_vrf_register(vrf);

	static_fixup_vrf_ids(vrf->info);

	return 0;
}

static int static_vrf_disable(struct vrf *vrf)
{
	static_zebra_vrf_unregister(vrf);
	return 0;
}

static int static_vrf_delete(struct vrf *vrf)
{
	struct route_table *table;
	struct static_vrf *svrf;
	safi_t safi;
	afi_t afi;
	void *info;

	svrf = vrf->info;
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			table = svrf->stable[afi][safi];
			info = route_table_get_info(table);
			route_table_finish(table);
			XFREE(MTYPE_STATIC_RTABLE_INFO, info);
			svrf->stable[afi][safi] = NULL;
		}
	}
	XFREE(MTYPE_STATIC_RTABLE_INFO, svrf);
	return 0;
}

/* Lookup the static routing table in a VRF. */
struct route_table *static_vrf_static_table(afi_t afi, safi_t safi,
					    struct static_vrf *svrf)
{
	if (!svrf)
		return NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	return svrf->stable[afi][safi];
}

struct static_vrf *static_vrf_lookup_by_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (vrf)
		return ((struct static_vrf *)vrf->info);

	return NULL;
}

struct static_vrf *static_vrf_lookup_by_name(const char *name)
{
	struct vrf *vrf;

	if (!name)
		name = VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_name(name);
	if (vrf)
		return ((struct static_vrf *)vrf->info);

	return NULL;
}

static int static_vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (vrf->vrf_id != VRF_DEFAULT)
			vty_frame(vty, "vrf %s\n", vrf->name);

		static_config(vty, vrf->info, AFI_IP,
			      SAFI_UNICAST, "ip route");
		static_config(vty, vrf->info, AFI_IP,
			      SAFI_MULTICAST, "ip mroute");
		static_config(vty, vrf->info, AFI_IP6,
			      SAFI_UNICAST, "ipv6 route");

		if (vrf->vrf_id != VRF_DEFAULT)
			vty_endframe(vty, " exit-vrf\n!\n");
	}

	return 0;
}

int static_vrf_has_config(struct static_vrf *svrf)
{
	struct route_table *table;
	safi_t safi;
	afi_t afi;

	/*
	 * NOTE: This is a don't care for the default VRF, but we go through
	 * the motions to keep things consistent.
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		table = svrf->stable[afi][safi];
		if (!table)
			continue;
		if (route_table_count(table))
			return 1;
	}

	return 0;
}

void static_vrf_init(void)
{
	vrf_init(static_vrf_new, static_vrf_enable,
		 static_vrf_disable, static_vrf_delete, NULL);

	vrf_cmd_init(static_vrf_config_write, &static_privs);
}

void static_vrf_terminate(void)
{
	vrf_terminate();
}

struct static_vrf *static_vty_get_unknown_vrf(const char *vrf_name)
{
	struct static_vrf *svrf;
	struct vrf *vrf;

	svrf = static_vrf_lookup_by_name(vrf_name);

	if (svrf)
		return svrf;

	vrf = vrf_get(VRF_UNKNOWN, vrf_name);
	if (!vrf)
		return NULL;
	svrf = vrf->info;
	if (!svrf)
		return NULL;
	/* Mark as having FRR configuration */
	vrf_set_user_cfged(vrf);

	return svrf;
}
