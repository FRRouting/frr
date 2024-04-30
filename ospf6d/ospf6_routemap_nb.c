// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#include <zebra.h>

#include "lib/northbound.h"
#include "lib/routemap.h"
#include "ospf6_routemap_nb.h"

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

const struct frr_yang_module_info frr_ospf6_route_map_info = {
	.name = "frr-ospf6-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-ospf6-route-map:ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
