/*
 * Bgp northbound callbacks api interfaces
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

#ifndef _FRR_BGP_NB_H_
#define _FRR_BGP_NB_H_

#include "northbound.h"

extern const struct frr_yang_module_info frr_bgp_info;

/* prototypes */
int bgp_router_create(struct nb_cb_create_args *args);
int bgp_router_destroy(struct nb_cb_destroy_args *args);
int bgp_global_local_as_modify(struct nb_cb_modify_args *args);
int bgp_global_router_id_modify(struct nb_cb_modify_args *args);
int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args);
int bgp_global_confederation_identifier_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_confederation_member_as_create(struct nb_cb_create_args *args);
int bgp_global_confederation_member_as_destroy(struct nb_cb_destroy_args *args);
int bgp_global_med_config_enable_med_admin_modify(
	struct nb_cb_modify_args *args);
int bgp_global_med_config_max_med_admin_modify(struct nb_cb_modify_args *args);
int bgp_global_med_config_max_med_onstart_up_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_med_config_max_med_onstart_up_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_med_config_max_med_onstart_up_value_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_route_reflector_cluster_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_route_reflector_no_client_reflect_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_always_compare_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_deterministic_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_confed_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_missing_as_worst_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_aspath_confed_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_ignore_as_path_length_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_external_compare_router_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_allow_multiple_as_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_multi_path_as_set_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_selection_options_multi_path_as_set_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_global_neighbor_config_dynamic_neighbors_limit_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_neighbor_config_dynamic_neighbors_limit_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_global_neighbor_config_log_neighbor_changes_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_neighbor_config_packet_quanta_config_wpkt_quanta_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_neighbor_config_packet_quanta_config_rpkt_quanta_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_enabled_modify(struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_update_group_config_subgroup_pkt_queue_size_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_update_group_config_coalesce_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_rmap_delay_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_update_delay_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_update_delay_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_global_config_timers_establish_wait_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_establish_wait_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_global_config_timers_connect_retry_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_hold_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_global_config_timers_keepalive_modify(
	struct nb_cb_modify_args *args);
int bgp_global_instance_type_view_modify(struct nb_cb_modify_args *args);
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args);
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args);
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args);
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args);
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args);
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_import_check_modify(struct nb_cb_modify_args *args);
int bgp_global_graceful_shutdown_enable_modify(struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_create(struct nb_cb_create_args *args);
int bgp_global_bmp_config_target_list_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_incoming_session_session_list_create(
	struct nb_cb_create_args *args);
int bgp_global_bmp_config_target_list_incoming_session_session_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_outgoing_session_session_list_create(
	struct nb_cb_create_args *args);
int bgp_global_bmp_config_target_list_outgoing_session_session_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_outgoing_session_session_list_min_retry_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_outgoing_session_session_list_max_retry_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_mirror_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_stats_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_stats_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_ipv4_access_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_ipv4_access_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_ipv6_access_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_ipv6_access_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_mirror_buffer_limit_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_mirror_buffer_limit_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_create(struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_create(struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_local_interface_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_local_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_local_port_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_local_port_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_peer_group_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_password_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_password_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_ttl_security_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_ttl_security_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_solo_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_enforce_first_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_description_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_description_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_passive_mode_modify(struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_update_source_ip_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_update_source_interface_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_local_as_local_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_timers_connect_time_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_timers_hold_time_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_timers_keepalive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_create(struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_v6only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_peer_group_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_peer_group_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_password_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_password_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_ttl_security_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_ttl_security_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_solo_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_enforce_first_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_description_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_description_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_passive_mode_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_update_source_ip_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_update_source_interface_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_local_as_local_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_connect_time_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_hold_time_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_timers_keepalive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_create(struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ipv4_listen_range_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_ipv4_listen_range_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ipv6_listen_range_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_ipv6_listen_range_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_password_modify(struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_password_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ttl_security_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_ttl_security_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_solo_modify(struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_enforce_first_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_description_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_description_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_passive_mode_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_update_source_ip_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_update_source_ip_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_update_source_interface_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_update_source_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_local_as_local_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_timers_connect_time_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_timers_hold_time_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_timers_keepalive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vpn_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_vpn_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vpn_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_vpn_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_create(
	struct nb_cb_create_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_label_index_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_modify(
	struct nb_cb_modify_args *args);
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args);

/*
 * Callback registered with routing_nb lib to validate only
 * one instance of bgp instance is allowed
 */
int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_router_bgp(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults);
void cli_show_router_bgp_router_id(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_router_bgp_route_selection(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
void cli_show_router_bgp_ebgp_requires_policy(struct vty *vty,
					      struct lyd_node *dnode,
					      bool show_defaults);
void cli_show_router_bgp_suppress_duplicates(struct vty *vty,
					      struct lyd_node *dnode,
					      bool show_defaults);
void cli_show_router_bgp_default_shutdown(struct vty *vty,
					  struct lyd_node *dnode,
					  bool show_defaults);
void cli_show_router_bgp_import_check(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_router_bgp_show_hostname(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_router_bgp_show_nexthop_hostname(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults);
void cli_show_router_bgp_fast_external_failover(struct vty *vty,
						struct lyd_node *dnode,
						bool show_defaults);
void cli_show_router_global_neighbor_config(struct vty *vty,
					    struct lyd_node *dnode,
					    bool show_defaults);
void cli_show_router_global_update_group_config_subgroup_pkt_queue_size(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_router_global_update_group_config_coalesce_time(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_router_global_ebgp_multihop_connected_route_check(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_router_bgp_local_pref(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_router_bgp_route_reflector(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
void cli_show_router_bgp_confederation_identifier(struct vty *vty,
						  struct lyd_node *dnode,
						  bool show_defaults);
void cli_show_router_bgp_confederation_member_as(struct vty *vty,
						 struct lyd_node *dnode,
						 bool show_defaults);
void cli_show_router_bgp_graceful_shutdown(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_router_bgp_med_config(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_bgp_global_afi_safi_header(struct vty *vty,
					 struct lyd_node *dnode,
					 bool show_defaults);
void cli_show_bgp_global_afi_safi_header_end(struct vty *vty,
					     struct lyd_node *dnode);
void cli_show_bgp_global_afi_safi_network_config(struct vty *vty,
						 struct lyd_node *dnode,
						 bool show_defaults);
void cli_show_bgp_global_afi_safi_unicast_aggregate_route(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_admin_distance_config(struct vty *vty,
							struct lyd_node *dnode,
							bool show_defaults);
void cli_show_bgp_global_afi_safi_route_flap_dampening(struct vty *vty,
						       struct lyd_node *dnode,
						       bool show_defaults);
void cli_show_bgp_global_afi_safi_unicast_admin_distance_route(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_unicast_use_multiple_paths_ebgp_maximum_paths(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_redistribution_list(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_nexthop(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rd(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_import_vpn(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_export_vpn(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_import_vrfs(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);
void cli_show_bgp_global_afi_safi_ip_unicast_vpn_config_rmap_export(
	struct vty *vty, struct lyd_node *dnode, bool show_defaults);

void bgp_global_route_selection_options_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_med_config_apply_finish(struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_network_config_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safi_aggregate_route_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safi_admin_distance_route_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safi_ip_unicast_redistribution_list_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_neighbor_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_unnumbered_neighbor_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_peer_group_neighbor_remote_as_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_unnumbered_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_peer_groups_peer_group_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_peer_groups_peer_group_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_peer_group_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_neighbor_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_unnumbered_neighbor_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args);
void bgp_peer_group_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args);

/* xpath macros */
/* route-list */
#define FRR_BGP_GLOBAL_XPATH                                                   \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-bgp:bgp"

#define FRR_BGP_GLOBAL_AS_XPATH                                                \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-bgp:bgp/local-as"
#define FRR_BGP_AFI_SAFI_REDIST_XPATH                                          \
	"./global/afi-safis/afi-safi[afi-safi-name='%s']/%s/"                  \
	"redistribution-list[route-type='%s'][route-instance='%s']"
#define FRR_BGP_NEIGHBOR_NUM_XPATH "./neighbors/neighbor[remote-address='%s']%s"
#define FRR_BGP_NEIGHBOR_UNNUM_XPATH                                           \
	"./neighbors/unnumbered-neighbor[interface='%s']%s"
#define FRR_BGP_PEER_GROUP_XPATH                                               \
	"./peer-groups/peer-group[peer-group-name='%s']%s"
#define FRR_BGP_NEIGHBOR_NUM_AFI_SAFI_XPATH                                    \
	"./neighbors/neighbor[remote-address='%s']/afi-safis/afi-safi[afi-safi-name='%s']"
#define FRR_BGP_NEIGHBOR_UNNUM_AFI_SAFI_XPATH                                  \
	"./neighbors/neighbor[interface='%s']/afi-safis/afi-safi[afi-safi-name='%s']"
#define FRR_BGP_PEER_GROUP_AFI_SAFI_XPATH                                      \
	"./peer-groups/peer-group[peer-group-name='%s']/afi-safis/afi-safi[afi-safi-name='%s']"
#define FRR_BGP_AF_XPATH "/afi-safis/afi-safi[afi-safi-name='%s']"

#endif
