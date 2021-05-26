/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
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

#include "lib/northbound.h"
#include "lib/routemap.h"
#include "ospf_routemap_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_ospf_route_map_info = {
	.name = "frr-ospf-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-ospf-route-map:metric-type",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_metric_type_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_metric_type_destroy,
			}
		},
		{
		.xpath = NULL,
		},
	}
};
