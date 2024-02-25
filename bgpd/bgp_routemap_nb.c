// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */


#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_routemap_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bgp_route_map_info = {
	.name = "frr-bgp-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:local-preference",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_local_preference_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_local_preference_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:alias",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_alias_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_alias_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:script",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_script_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_script_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:origin",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_origin_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_origin_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_rpki_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_rpki_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:rpki-extcommunity",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:probability",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_probability_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_probability_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-vrf",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_destroy,
			}
		},
	    {
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:source-protocol",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-interface",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:peer-local",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_peer_local_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_peer_local_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:list-name",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_list_name_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-default-route",
			.cbs = {
				.create = lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_create,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-vni",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:evpn-route-type",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:route-distinguisher",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list",
			.cbs = {
				.create = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_create,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_destroy,
				.apply_finish = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-bgp-route-map:ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_modify,
				.destroy = lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:distance",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_distance_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_distance_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-rt",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-nt",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-soo",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:ipv6-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:preference",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_preference_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_preference_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:label-index",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_label_index_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:local-pref",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_local_pref_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_local_pref_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:weight",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_weight_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_weight_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:origin",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_origin_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_origin_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:originator-id",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_originator_id_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_originator_id_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:table",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_table_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_table_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:atomic-aggregate",
			.cbs = {
				.create = lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_create,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aigp-metric",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_aigp_metric_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_aigp_metric_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:prepend-as-path",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:last-as",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_last_as_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_last_as_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:exclude-as-path",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:replace-as-path",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_replace_as_path_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_replace_as_path_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-none",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_community_none_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_community_none_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:community-string",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_community_string_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-none",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_large_community_none_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_large_community_none_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:large-community-string",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_large_community_string_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_large_community_string_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator",
			.cbs = {
				.create = lib_route_map_entry_set_action_rmap_set_action_aggregator_create,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_aggregator_destroy,
				.apply_finish = lib_route_map_entry_set_action_rmap_set_action_aggregator_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:comm-list-name",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_comm_list_name_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_comm_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-none",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb",
			.cbs = {
				.create = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_create,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_destroy,
				.apply_finish = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_finish,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/lb-type",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_lb_type_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/bandwidth",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-color",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:extcommunity-lb/two-octet-as-specific",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_two_octet_as_specific_modify,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv4",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv6",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/set-action/rmap-set-action/frr-bgp-route-map:l3vpn-nexthop-encapsulation",
			.cbs = {
				.modify = lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_modify,
				.destroy = lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
