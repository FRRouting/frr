// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 VmWare
 *                    Sarita Patra
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "vrf.h"
#include "routemap.h"
#include "pimd/pim_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_pim_info = {
	.name = "frr-pim",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ecmp",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ecmp-rebalance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_rebalance_modify,
			}
		},
		{
			.xpath = "/frr-pim:pim/address-family/join-prune-interval",
			.cbs = {
				.modify = pim_address_family_join_prune_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/keep-alive-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_keep_alive_timer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/rp-keep-alive-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_keep_alive_timer_modify,
			}
		},
		{
			.xpath = "/frr-pim:pim/address-family",
			.cbs = {
				.create = pim_address_family_create,
				.destroy = pim_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-pim:pim/address-family/packets",
			.cbs = {
				.modify = pim_address_family_packets_modify,
			}
		},
		{
			.xpath = "/frr-pim:pim/address-family/register-suppress-time",
			.cbs = {
				.modify = pim_address_family_register_suppress_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/send-v6-secondary",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-action",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/spt-switchover/spt-infinity-prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/dm-prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_dm_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_dm_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/ssm-pingd-source-ip",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/hold-time",
			.cbs = {
				.modify = pim_msdp_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/keep-alive",
			.cbs = {
				.modify = pim_msdp_keep_alive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/connection-retry",
			.cbs = {
				.modify = pim_msdp_connection_retry_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/log-neighbor-events",
			.cbs = {
				.modify = pim_msdp_log_neighbor_events_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/log-sa-events",
			.cbs = {
				.modify = pim_msdp_log_sa_events_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/originator-id",
			.cbs = {
				.modify = pim_msdp_originator_id_modify,
				.destroy = pim_msdp_originator_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp/shutdown",
			.cbs = {
				.modify = pim_msdp_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups",
			.cbs = {
				.create = pim_msdp_mesh_group_create,
				.destroy = pim_msdp_mesh_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups/source",
			.cbs = {
				.modify = pim_msdp_mesh_group_source_modify,
				.destroy = pim_msdp_mesh_group_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-mesh-groups/members",
			.cbs = {
				.create = pim_msdp_mesh_group_members_create,
				.destroy = pim_msdp_mesh_group_members_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/source-ip",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-filter-in",
			.cbs = {
				.modify = pim_msdp_peer_sa_filter_in_modify,
				.destroy = pim_msdp_peer_sa_filter_in_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-filter-out",
			.cbs = {
				.modify = pim_msdp_peer_sa_filter_out_modify,
				.destroy = pim_msdp_peer_sa_filter_out_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/authentication-type",
			.cbs = {
				.modify = pim_msdp_peer_authentication_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/authentication-key",
			.cbs = {
				.modify = pim_msdp_peer_authentication_key_modify,
				.destroy = pim_msdp_peer_authentication_key_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/sa-limit",
			.cbs = {
				.modify = pim_msdp_peer_sa_limit_modify,
				.destroy = pim_msdp_peer_sa_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/msdp-peer/as",
			.cbs = {
				.modify = pim_msdp_peer_as_modify,
				.destroy = pim_msdp_peer_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_destroy,
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peerlink-rif",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/reg-address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/my-role",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mlag/peer-state",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/register-accept-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/pim-join-route-map",
			.cbs = {
				.modify = pim_join_route_map_modify,
				.destroy = pim_join_route_map_detroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mcast-rpf-lookup",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/mcast-rpf-lookup/mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_mcast_rpf_lookup_mode_modify
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family",
			.cbs = {
				.create = lib_interface_pim_address_family_create,
				.destroy = lib_interface_pim_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/pim-enable",
			.cbs = {
				.modify = lib_interface_pim_address_family_pim_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/pim-passive-enable",
			.cbs = {
				.modify = lib_interface_pim_address_family_pim_passive_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/pim-mode",
			.cbs = {
				.modify = lib_interface_pim_address_family_pim_mode_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/dr-priority",
			.cbs = {
				.modify = lib_interface_pim_address_family_dr_priority_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/hello-interval",
			.cbs = {
				.modify = lib_interface_pim_address_family_hello_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/hello-holdtime",
			.cbs = {
				.modify = lib_interface_pim_address_family_hello_holdtime_modify,
				.destroy = lib_interface_pim_address_family_hello_holdtime_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/neighbor-filter-prefix-list",
			.cbs = {
				.modify = lib_interface_pim_address_family_nbr_plist_modify,
				.destroy = lib_interface_pim_address_family_nbr_plist_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/join-prune-interval",
			.cbs = {
				.modify = lib_interface_pim_address_family_join_prune_interval_modify,
				.destroy = lib_interface_pim_address_family_join_prune_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/assert-interval",
			.cbs = {
				.modify = lib_interface_pim_assert_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/assert-override-interval",
			.cbs = {
				.modify = lib_interface_pim_assert_override_interval_modify,
				.destroy = lib_interface_pim_assert_override_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bfd",
			.cbs = {
				.create = lib_interface_pim_address_family_bfd_create,
				.destroy = lib_interface_pim_address_family_bfd_destroy,
				.apply_finish = lib_interface_pim_address_family_bfd_apply_finish,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bfd/min-rx-interval",
			.cbs = {
				.modify = lib_interface_pim_address_family_bfd_min_rx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bfd/min-tx-interval",
			.cbs = {
				.modify = lib_interface_pim_address_family_bfd_min_tx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bfd/detect_mult",
			.cbs = {
				.modify = lib_interface_pim_address_family_bfd_detect_mult_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bfd/profile",
			.cbs = {
				.modify = lib_interface_pim_address_family_bfd_profile_modify,
				.destroy = lib_interface_pim_address_family_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/bsm",
			.cbs = {
				.modify = lib_interface_pim_address_family_bsm_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/unicast-bsm",
			.cbs = {
				.modify = lib_interface_pim_address_family_unicast_bsm_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/active-active",
			.cbs = {
				.modify = lib_interface_pim_address_family_active_active_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/use-source",
			.cbs = {
				.modify = lib_interface_pim_address_family_use_source_modify,
				.destroy = lib_interface_pim_address_family_use_source_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-oil",
			.cbs = {
				.modify = lib_interface_pim_address_family_multicast_boundary_oil_modify,
				.destroy = lib_interface_pim_address_family_multicast_boundary_oil_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/multicast-boundary-acl",
			.cbs = {
				.modify = lib_interface_pim_address_family_multicast_boundary_acl_modify,
				.destroy = lib_interface_pim_address_family_multicast_boundary_acl_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute",
			.cbs = {
				.create = lib_interface_pim_address_family_mroute_create,
				.destroy = lib_interface_pim_address_family_mroute_oif_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-pim:pim/address-family/mroute/oif",
			.cbs = {
				.create = lib_interface_pim_address_family_mroute_oif_create,
				.destroy = lib_interface_pim_address_family_mroute_oif_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_pim_route_map_info = {
	.name = "frr-pim-route-map",
	.nodes = {
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:ipv4-multicast-source-address",
			.cbs = {
				.modify = pim_route_map_match_source_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:ipv6-multicast-source-address",
			.cbs = {
				.modify = pim_route_map_match_source_v6_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:ipv4-multicast-group-address",
			.cbs = {
				.modify = pim_route_map_match_group_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:ipv6-multicast-group-address",
			.cbs = {
				.modify = pim_route_map_match_group_v6_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:multicast-interface",
			.cbs = {
				.modify = pim_route_map_match_interface_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-route-map:lib/route-map/entry/match-condition/rmap-match-condition/frr-pim-route-map:list-name",
			.cbs = {
				.modify = pim_route_map_match_list_name_modify,
				.destroy = lib_route_map_entry_match_destroy,
			}
		},
		{
			.xpath = NULL
		}
	}
};
/* clang-format on */

/* clang-format off */
const struct frr_yang_module_info frr_pim_rp_info = {
	.name = "frr-pim-rp",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/group-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/static-rp/rp-list/prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/enable",
			.cbs = {
				.modify = pim_embedded_rp_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/group-list",
			.cbs = {
				.modify = pim_embedded_rp_group_list_modify,
				.destroy = pim_embedded_rp_group_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/embedded-rp/maximum-rps",
			.cbs = {
				.modify = pim_embedded_rp_maximum_rps_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/discovery-enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_discovery_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-scope",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_scope_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/announce-holdtime",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_announce_holdtime_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list/group",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/candidate-rp-list/prefix-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_candidate_rp_list_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/send-rp-discovery",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_send_rp_discovery_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-scope",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_scope_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/discovery-holdtime",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_discovery_holdtime_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/if-loopback",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/auto-rp/mapping-agent/if-any",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_auto_rp_mapping_agent_addrsel_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info frr_pim_candidate_info = {
	.name = "frr-pim-candidate",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr/bsr-priority",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_priority_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr/address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr/if-loopback",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-bsr/if-any",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_bsr_addrsel_destroy,
			}
		},

		/* Candidate-RP */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/rp-priority",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_priority_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/advertisement-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_adv_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/group-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_group_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_group_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/if-loopback",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-pim:pim/address-family/frr-pim-rp:rp/frr-pim-candidate:candidate-rp/if-any",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_candidate_rp_addrsel_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_gmp_info = {
	.name = "frr-gmp",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family",
			.cbs = {
				.create = lib_interface_gmp_address_family_create,
				.destroy = lib_interface_gmp_address_family_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/enable",
			.cbs = {
				.modify = lib_interface_gmp_address_family_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/igmp-version",
			.cbs = {
				.modify = lib_interface_gmp_address_family_igmp_version_modify,
				.destroy = lib_interface_gmp_address_family_igmp_version_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/mld-version",
			.cbs = {
				.modify = lib_interface_gmp_address_family_mld_version_modify,
				.destroy = lib_interface_gmp_address_family_mld_version_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/query-interval",
			.cbs = {
				.modify = lib_interface_gmp_address_family_query_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/query-max-response-time",
			.cbs = {
				.modify = lib_interface_gmp_address_family_query_max_response_time_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/last-member-query-interval",
			.cbs = {
				.modify = lib_interface_gmp_address_family_last_member_query_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/last-member-query-count",
			.cbs = {
				.modify = lib_interface_gmp_address_family_last_member_query_count_modify,
				.destroy = lib_interface_gmp_address_family_last_member_query_count_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/robustness-variable",
			.cbs = {
				.modify = lib_interface_gmp_address_family_robustness_variable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/join-group",
			.cbs = {
				.create = lib_interface_gmp_address_family_join_group_create,
				.destroy = lib_interface_gmp_address_family_join_group_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/max-sources",
			.cbs = {
				.modify = lib_interface_gm_max_sources_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/max-groups",
			.cbs = {
				.modify = lib_interface_gm_max_groups_modify,
			}
		},
				{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/proxy",
			.cbs = {
				.modify = lib_interface_gmp_address_family_proxy_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/immediate-leave",
			.cbs = {
				.modify = lib_interface_gmp_immediate_leave_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/require-router-alert",
			.cbs = {
				.modify = lib_interface_gmp_require_router_alert_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/route-map",
			.cbs = {
				.modify = lib_interface_gm_rmap_modify,
				.destroy = lib_interface_gm_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/access-list",
			.cbs = {
				.modify = lib_interface_gm_alist_modify,
				.destroy = lib_interface_gm_alist_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-gmp:gmp/address-family/static-group",
			.cbs = {
				.create = lib_interface_gmp_address_family_static_group_create,
				.destroy = lib_interface_gmp_address_family_static_group_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
