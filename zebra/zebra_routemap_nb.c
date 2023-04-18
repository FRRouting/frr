// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "zebra_routemap_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_zebra_route_map_info = {
	.name = "frr-zebra-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-instance",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_instance_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_instance_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-zebra-route-map:source-protocol",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv4-src-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-zebra-route-map:ipv6-src-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
