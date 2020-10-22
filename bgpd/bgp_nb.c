/*
 * Bgp northbound callbacks registery
 * Copyright (C) 2020  Nvidia
 *		       Chirag Shah
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

#include "northbound.h"
#include "libfrr.h"
#include "bgpd/bgp_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bgp_info = {
	.name = "frr-bgp",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp",
			.cbs = {
				.cli_show = cli_show_router_bgp,
				.create = bgp_router_create,
				.destroy = bgp_router_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-as",
			.cbs = {
				.modify = bgp_global_local_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/router-id",
			.cbs = {
				.cli_show = cli_show_router_bgp_router_id,
				.modify = bgp_global_router_id_modify,
				.destroy = bgp_global_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier",
			.cbs = {
				.cli_show = cli_show_router_bgp_confederation_identifier,
				.modify = bgp_global_confederation_identifier_modify,
				.destroy = bgp_global_confederation_identifier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as",
			.cbs = {
				.cli_show = cli_show_router_bgp_confederation_member_as,
				.create = bgp_global_confederation_member_as_create,
				.destroy = bgp_global_confederation_member_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config",
			.cbs = {
				.cli_show = cli_show_router_bgp_med_config,
				.apply_finish = bgp_global_med_config_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/enable-med-admin",
			.cbs = {
				.modify = bgp_global_med_config_enable_med_admin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-admin",
			.cbs = {
				.modify = bgp_global_med_config_max_med_admin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-time",
			.cbs = {
				.modify = bgp_global_med_config_max_med_onstart_up_time_modify,
				.destroy = bgp_global_med_config_max_med_onstart_up_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-value",
			.cbs = {
				.modify = bgp_global_med_config_max_med_onstart_up_value_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector",
			.cbs = {
				.cli_show = cli_show_router_bgp_route_reflector,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id",
			.cbs = {
				.modify = bgp_global_route_reflector_route_reflector_cluster_id_modify,
				.destroy = bgp_global_route_reflector_route_reflector_cluster_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/no-client-reflect",
			.cbs = {
				.modify = bgp_global_route_reflector_no_client_reflect_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/allow-outbound-policy",
			.cbs = {
				.modify = bgp_global_route_reflector_allow_outbound_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options",
			.cbs = {
				.apply_finish = bgp_global_route_selection_options_apply_finish,
				.cli_show = cli_show_router_bgp_route_selection,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/always-compare-med",
			.cbs = {
				.modify = bgp_global_route_selection_options_always_compare_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/deterministic-med",
			.cbs = {
				.modify = bgp_global_route_selection_options_deterministic_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/confed-med",
			.cbs = {
				.modify = bgp_global_route_selection_options_confed_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/missing-as-worst-med",
			.cbs = {
				.modify = bgp_global_route_selection_options_missing_as_worst_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/aspath-confed",
			.cbs = {
				.modify = bgp_global_route_selection_options_aspath_confed_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/ignore-as-path-length",
			.cbs = {
				.modify = bgp_global_route_selection_options_ignore_as_path_length_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/external-compare-router-id",
			.cbs = {
				.modify = bgp_global_route_selection_options_external_compare_router_id_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/allow-multiple-as",
			.cbs = {
				.modify = bgp_global_route_selection_options_allow_multiple_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/multi-path-as-set",
			.cbs = {
				.modify = bgp_global_route_selection_options_multi_path_as_set_modify,
				.destroy = bgp_global_route_selection_options_multi_path_as_set_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config",
			.cbs = {
				.cli_show = cli_show_router_global_neighbor_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/dynamic-neighbors-limit",
			.cbs = {
				.modify = bgp_global_global_neighbor_config_dynamic_neighbors_limit_modify,
				.destroy = bgp_global_global_neighbor_config_dynamic_neighbors_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes",
			.cbs = {
				.modify = bgp_global_global_neighbor_config_log_neighbor_changes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta",
			.cbs = {
				.modify = bgp_global_global_neighbor_config_packet_quanta_config_wpkt_quanta_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta",
			.cbs = {
				.modify = bgp_global_global_neighbor_config_packet_quanta_config_rpkt_quanta_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled",
			.cbs = {
				.modify = bgp_global_graceful_restart_enabled_modify,
				.destroy = bgp_global_graceful_restart_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_global_graceful_restart_graceful_restart_disable_modify,
				.destroy = bgp_global_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/preserve-fw-entry",
			.cbs = {
				.modify = bgp_global_graceful_restart_preserve_fw_entry_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/restart-time",
			.cbs = {
				.modify = bgp_global_graceful_restart_restart_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/stale-routes-time",
			.cbs = {
				.modify = bgp_global_graceful_restart_stale_routes_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/selection-deferral-time",
			.cbs = {
				.modify = bgp_global_graceful_restart_selection_deferral_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = bgp_global_graceful_restart_rib_stale_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size",
			.cbs = {
				.cli_show = cli_show_router_global_update_group_config_subgroup_pkt_queue_size,
				.modify = bgp_global_global_update_group_config_subgroup_pkt_queue_size_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/coalesce-time",
			.cbs = {
				.cli_show = cli_show_router_global_update_group_config_coalesce_time,
				.modify = bgp_global_global_update_group_config_coalesce_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/rmap-delay-time",
			.cbs = {
				.modify = bgp_global_global_config_timers_rmap_delay_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time",
			.cbs = {
				.modify = bgp_global_global_config_timers_update_delay_time_modify,
				.destroy = bgp_global_global_config_timers_update_delay_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/establish-wait-time",
			.cbs = {
				.modify = bgp_global_global_config_timers_establish_wait_time_modify,
				.destroy = bgp_global_global_config_timers_establish_wait_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/connect-retry-interval",
			.cbs = {
				.modify = bgp_global_global_config_timers_connect_retry_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/hold-time",
			.cbs = {
				.modify = bgp_global_global_config_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/keepalive",
			.cbs = {
				.modify = bgp_global_global_config_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/instance-type-view",
			.cbs = {
				.modify = bgp_global_instance_type_view_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-multihop-connected-route-check",
			.cbs = {
				.cli_show = cli_show_router_global_ebgp_multihop_connected_route_check,
				.modify = bgp_global_ebgp_multihop_connected_route_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-external-failover",
			.cbs = {
				.cli_show = cli_show_router_bgp_fast_external_failover,
				.modify = bgp_global_fast_external_failover_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-pref",
			.cbs = {
				.cli_show = cli_show_router_bgp_local_pref,
				.modify = bgp_global_local_pref_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-shutdown",
			.cbs = {
				.cli_show = cli_show_router_bgp_default_shutdown,
				.modify = bgp_global_default_shutdown_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-requires-policy",
			.cbs = {
				.cli_show = cli_show_router_bgp_ebgp_requires_policy,
				.modify = bgp_global_ebgp_requires_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-hostname",
			.cbs = {
				.cli_show = cli_show_router_bgp_show_hostname,
				.modify = bgp_global_show_hostname_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-nexthop-hostname",
			.cbs = {
				.cli_show = cli_show_router_bgp_show_nexthop_hostname,
				.modify = bgp_global_show_nexthop_hostname_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/import-check",
			.cbs = {
				.cli_show = cli_show_router_bgp_import_check,
				.modify = bgp_global_import_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable",
			.cbs = {
				.cli_show = cli_show_router_bgp_graceful_shutdown,
				.modify = bgp_global_graceful_shutdown_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list",
			.cbs = {
				.create = bgp_global_bmp_config_target_list_create,
				.destroy = bgp_global_bmp_config_target_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/incoming-session/session-list",
			.cbs = {
				.create = bgp_global_bmp_config_target_list_incoming_session_session_list_create,
				.destroy = bgp_global_bmp_config_target_list_incoming_session_session_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list",
			.cbs = {
				.create = bgp_global_bmp_config_target_list_outgoing_session_session_list_create,
				.destroy = bgp_global_bmp_config_target_list_outgoing_session_session_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/min-retry-time",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_outgoing_session_session_list_min_retry_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/max-retry-time",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_outgoing_session_session_list_max_retry_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/mirror",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_mirror_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-time",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_stats_time_modify,
				.destroy = bgp_global_bmp_config_target_list_stats_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv4-access-list",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_ipv4_access_list_modify,
				.destroy = bgp_global_bmp_config_target_list_ipv4_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv6-access-list",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_ipv6_access_list_modify,
				.destroy = bgp_global_bmp_config_target_list_ipv6_access_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_global_bmp_config_target_list_afi_safis_afi_safi_create,
				.destroy = bgp_global_bmp_config_target_list_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/mirror-buffer-limit",
			.cbs = {
				.modify = bgp_global_bmp_config_mirror_buffer_limit_modify,
				.destroy = bgp_global_bmp_config_mirror_buffer_limit_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_create,
				.destroy = bgp_global_afi_safis_afi_safi_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_header,
				.cli_show_end = cli_show_bgp_global_afi_safi_header_end,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor",
			.cbs = {
				.create = bgp_neighbors_neighbor_create,
				.destroy = bgp_neighbors_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-interface",
			.cbs = {
				.modify = bgp_neighbors_neighbor_local_interface_modify,
				.destroy = bgp_neighbors_neighbor_local_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-port",
			.cbs = {
				.modify = bgp_neighbors_neighbor_local_port_modify,
				.destroy = bgp_neighbors_neighbor_local_port_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/peer-group",
			.cbs = {
				.modify = bgp_neighbors_neighbor_peer_group_modify,
				.destroy = bgp_neighbors_neighbor_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/password",
			.cbs = {
				.modify = bgp_neighbors_neighbor_password_modify,
				.destroy = bgp_neighbors_neighbor_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ttl-security",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ttl_security_modify,
				.destroy = bgp_neighbors_neighbor_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/solo",
			.cbs = {
				.modify = bgp_neighbors_neighbor_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/enforce-first-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/description",
			.cbs = {
				.modify = bgp_neighbors_neighbor_description_modify,
				.destroy = bgp_neighbors_neighbor_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/passive-mode",
			.cbs = {
				.modify = bgp_neighbors_neighbor_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_neighbors_neighbor_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_neighbors_neighbor_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_neighbors_neighbor_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_neighbors_neighbor_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/override-capability",
			.cbs = {
				.modify = bgp_neighbors_neighbor_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/ip",
			.cbs = {
				.modify = bgp_neighbors_neighbor_update_source_ip_modify,
				.destroy = bgp_neighbors_neighbor_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/interface",
			.cbs = {
				.modify = bgp_neighbors_neighbor_update_source_interface_modify,
				.destroy = bgp_neighbors_neighbor_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_neighbor_remote_as_remote_as_modify,
				.destroy = bgp_neighbors_neighbor_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ebgp_multihop_enabled_modify,
				.destroy = bgp_neighbors_neighbor_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_modify,
				.destroy = bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as",
			.cbs = {
				.apply_finish = bgp_neighbors_neighbor_local_as_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/local-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_local_as_local_as_modify,
				.destroy = bgp_neighbors_neighbor_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-prepend",
			.cbs = {
				.modify = bgp_neighbors_neighbor_local_as_no_prepend_modify,
				.destroy = bgp_neighbors_neighbor_local_as_no_prepend_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-replace-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_local_as_no_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/enable",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_detect_multiplier_modify,
				.destroy = bgp_neighbors_neighbor_bfd_options_detect_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_required_min_rx_modify,
				.destroy = bgp_neighbors_neighbor_bfd_options_required_min_rx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_desired_min_tx_modify,
				.destroy = bgp_neighbors_neighbor_bfd_options_desired_min_tx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/session-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_session_type_modify,
				.destroy = bgp_neighbors_neighbor_bfd_options_session_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_neighbors_neighbor_bfd_options_check_cp_failure_modify,
				.destroy = bgp_neighbors_neighbor_bfd_options_check_cp_failure_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown",
			.cbs = {
				.apply_finish = bgp_neighbors_neighbor_admin_shutdown_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_neighbors_neighbor_admin_shutdown_enable_modify,
				.destroy = bgp_neighbors_neighbor_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/message",
			.cbs = {
				.modify = bgp_neighbors_neighbor_admin_shutdown_message_modify,
				.destroy = bgp_neighbors_neighbor_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/enable",
			.cbs = {
				.modify = bgp_neighbors_neighbor_graceful_restart_enable_modify,
				.destroy = bgp_neighbors_neighbor_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_modify,
				.destroy = bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_modify,
				.destroy = bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/advertise-interval",
			.cbs = {
				.modify = bgp_neighbors_neighbor_timers_advertise_interval_modify,
				.destroy = bgp_neighbors_neighbor_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/connect-time",
			.cbs = {
				.modify = bgp_neighbors_neighbor_timers_connect_time_modify,
				.destroy = bgp_neighbors_neighbor_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/hold-time",
			.cbs = {
				.modify = bgp_neighbors_neighbor_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/keepalive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/v6only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_v6only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/peer-group",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_peer_group_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/password",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_password_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ttl-security",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ttl_security_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/solo",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/enforce-first-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/description",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_description_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/passive-mode",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/override-capability",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/ip",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_update_source_ip_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/interface",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_update_source_interface_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as",
			.cbs = {
				.apply_finish = bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as",
			.cbs = {
				.apply_finish = bgp_neighbors_unnumbered_neighbor_local_as_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/local-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_local_as_local_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-prepend",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-replace-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_local_as_no_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/enable",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/session-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown",
			.cbs = {
				.apply_finish = bgp_neighbors_unnumbered_neighbor_admin_shutdown_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/message",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/enable",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/advertise-interval",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/connect-time",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_timers_connect_time_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/hold-time",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/keepalive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group",
			.cbs = {
				.create = bgp_peer_groups_peer_group_create,
				.destroy = bgp_peer_groups_peer_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv4-listen-range",
			.cbs = {
				.create = bgp_peer_groups_peer_group_ipv4_listen_range_create,
				.destroy = bgp_peer_groups_peer_group_ipv4_listen_range_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv6-listen-range",
			.cbs = {
				.create = bgp_peer_groups_peer_group_ipv6_listen_range_create,
				.destroy = bgp_peer_groups_peer_group_ipv6_listen_range_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/password",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_password_modify,
				.destroy = bgp_peer_groups_peer_group_password_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ttl-security",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ttl_security_modify,
				.destroy = bgp_peer_groups_peer_group_ttl_security_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/solo",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_solo_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/enforce-first-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_enforce_first_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/description",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_description_modify,
				.destroy = bgp_peer_groups_peer_group_description_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/passive-mode",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_passive_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_capability_options_dynamic_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_capability_options_strict_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_capability_options_extended_nexthop_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_capability_options_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/override-capability",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_capability_options_override_capability_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/ip",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_update_source_ip_modify,
				.destroy = bgp_peer_groups_peer_group_update_source_ip_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/interface",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_update_source_interface_modify,
				.destroy = bgp_peer_groups_peer_group_update_source_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as",
			.cbs = {
				.apply_finish = bgp_peer_group_neighbor_remote_as_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_modify,
				.destroy = bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_modify,
				.destroy = bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ebgp_multihop_enabled_modify,
				.destroy = bgp_peer_groups_peer_group_ebgp_multihop_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_modify,
				.destroy = bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_ebgp_multihop_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as",
			.cbs = {
				.apply_finish = bgp_peer_groups_peer_group_local_as_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/local-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_local_as_local_as_modify,
				.destroy = bgp_peer_groups_peer_group_local_as_local_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-prepend",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_local_as_no_prepend_modify,
				.destroy = bgp_peer_groups_peer_group_local_as_no_prepend_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-replace-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_local_as_no_replace_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/enable",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_detect_multiplier_modify,
				.destroy = bgp_peer_groups_peer_group_bfd_options_detect_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_required_min_rx_modify,
				.destroy = bgp_peer_groups_peer_group_bfd_options_required_min_rx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_desired_min_tx_modify,
				.destroy = bgp_peer_groups_peer_group_bfd_options_desired_min_tx_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/session-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_session_type_modify,
				.destroy = bgp_peer_groups_peer_group_bfd_options_session_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_bfd_options_check_cp_failure_modify,
				.destroy = bgp_peer_groups_peer_group_bfd_options_check_cp_failure_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown",
			.cbs = {
				.apply_finish = bgp_peer_groups_peer_group_admin_shutdown_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_admin_shutdown_enable_modify,
				.destroy = bgp_peer_groups_peer_group_admin_shutdown_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/message",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_admin_shutdown_message_modify,
				.destroy = bgp_peer_groups_peer_group_admin_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/enable",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_graceful_restart_enable_modify,
				.destroy = bgp_peer_groups_peer_group_graceful_restart_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_modify,
				.destroy = bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_modify,
				.destroy = bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/advertise-interval",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_timers_advertise_interval_modify,
				.destroy = bgp_peer_groups_peer_group_timers_advertise_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/connect-time",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_timers_connect_time_modify,
				.destroy = bgp_peer_groups_peer_group_timers_connect_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/hold-time",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_timers_hold_time_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/keepalive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_timers_keepalive_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_network_config_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_network_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_aggregate_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_aggregate_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_admin_distance_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_admin_distance_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_use_multiple_paths_ebgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_redistribution_list_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_redistribution_list,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/metric",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_admin_distance_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/external",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/local",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rd",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rd,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_nexthop,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vpn_modify,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_import_vpn,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_vpn_modify,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_export_vpn,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_import_vrfs,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_export,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_network_config_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_network_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_aggregate_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_aggregate_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_admin_distance_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_admin_distance_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_use_multiple_paths_ebgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_redistribution_list_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_redistribution_list,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/metric",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_admin_distance_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/external",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/local",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rd",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_vpn_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_export,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rt-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_use_multiple_paths_ebgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_use_multiple_paths_ebgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_network_config_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_network_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_aggregate_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_admin_distance_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_admin_distance_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/external",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/local",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_network_config_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_network_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_backdoor_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_aggregate_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_as_set_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_summary_only_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_origin_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_match_med_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route",
			.cbs = {
				.apply_finish = bgp_global_afi_safi_admin_distance_route_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_create,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_unicast_admin_distance_route,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish,
				.cli_show = cli_show_bgp_global_afi_safi_route_flap_dampening,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/external",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/local",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-flowspec/flow-spec-config/interface",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_modify,
				.destroy = bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config",
			.cbs = {
				.apply_finish = bgp_global_afi_safis_afi_safi_network_config_apply_finish,
				.create = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_destroy,
				.cli_show = cli_show_bgp_global_afi_safi_network_config,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_label_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_create,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list",
			.cbs = {
				.create = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_create,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_label_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_modify,
				.destroy = bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_pre_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_post_policy_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy,
				.apply_finish = bgp_peer_group_afi_safi_prefix_limit_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify,
				.destroy = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
