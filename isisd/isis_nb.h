// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
 */

#ifndef ISISD_ISIS_NB_H_
#define ISISD_ISIS_NB_H_

extern const struct frr_yang_module_info frr_isisd_info;

/* Forward declaration(s). */
struct isis_area;
struct isis_circuit;
struct isis_adjacency;

/* Mandatory callbacks. */
int isis_instance_create(struct nb_cb_create_args *args);
int isis_instance_destroy(struct nb_cb_destroy_args *args);
int isis_instance_is_type_modify(struct nb_cb_modify_args *args);
int isis_instance_area_address_create(struct nb_cb_create_args *args);
int isis_instance_area_address_destroy(struct nb_cb_destroy_args *args);
int isis_instance_dynamic_hostname_modify(struct nb_cb_modify_args *args);
int isis_instance_attached_send_modify(struct nb_cb_modify_args *args);
int isis_instance_attached_receive_modify(struct nb_cb_modify_args *args);
int isis_instance_attached_modify(struct nb_cb_modify_args *args);
int isis_instance_overload_enabled_modify(struct nb_cb_modify_args *args);
int isis_instance_overload_on_startup_modify(struct nb_cb_modify_args *args);
int isis_instance_advertise_high_metrics_modify(struct nb_cb_modify_args *args);
int isis_instance_metric_style_modify(struct nb_cb_modify_args *args);
int isis_instance_purge_originator_modify(struct nb_cb_modify_args *args);
int isis_instance_admin_group_send_zero_modify(struct nb_cb_modify_args *args);
int isis_instance_asla_legacy_flag_modify(struct nb_cb_modify_args *args);
int isis_instance_lsp_mtu_modify(struct nb_cb_modify_args *args);
int isis_instance_advertise_passive_only_modify(struct nb_cb_modify_args *args);
int isis_instance_lsp_refresh_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int isis_instance_lsp_refresh_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int isis_instance_lsp_maximum_lifetime_level_1_modify(
	struct nb_cb_modify_args *args);
int isis_instance_lsp_maximum_lifetime_level_2_modify(
	struct nb_cb_modify_args *args);
int isis_instance_lsp_generation_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int isis_instance_lsp_generation_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_ietf_backoff_delay_create(struct nb_cb_create_args *args);
int isis_instance_spf_ietf_backoff_delay_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_spf_ietf_backoff_delay_init_delay_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_minimum_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_minimum_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_prefix_priorities_critical_access_list_name_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_prefix_priorities_critical_access_list_name_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_spf_prefix_priorities_high_access_list_name_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_prefix_priorities_high_access_list_name_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_spf_prefix_priorities_medium_access_list_name_modify(
	struct nb_cb_modify_args *args);
int isis_instance_spf_prefix_priorities_medium_access_list_name_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_area_password_create(struct nb_cb_create_args *args);
int isis_instance_area_password_destroy(struct nb_cb_destroy_args *args);
int isis_instance_area_password_password_modify(struct nb_cb_modify_args *args);
int isis_instance_area_password_password_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_area_password_authenticate_snp_modify(
	struct nb_cb_modify_args *args);
int isis_instance_domain_password_create(struct nb_cb_create_args *args);
int isis_instance_domain_password_destroy(struct nb_cb_destroy_args *args);
int isis_instance_domain_password_password_modify(
	struct nb_cb_modify_args *args);
int isis_instance_domain_password_password_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_domain_password_authenticate_snp_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv4_create(
	struct nb_cb_create_args *args);
int isis_instance_default_information_originate_ipv4_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_default_information_originate_ipv4_always_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv4_route_map_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv4_route_map_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_default_information_originate_ipv4_metric_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv6_create(
	struct nb_cb_create_args *args);
int isis_instance_default_information_originate_ipv6_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_default_information_originate_ipv6_always_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv6_route_map_modify(
	struct nb_cb_modify_args *args);
int isis_instance_default_information_originate_ipv6_route_map_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_default_information_originate_ipv6_metric_modify(
	struct nb_cb_modify_args *args);
int isis_instance_redistribute_ipv4_create(struct nb_cb_create_args *args);
int isis_instance_redistribute_ipv4_destroy(struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv4_route_map_modify(
	struct nb_cb_modify_args *args);
int isis_instance_redistribute_ipv4_route_map_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv4_metric_modify(
	struct nb_cb_modify_args *args);
int isis_instance_redistribute_ipv4_metric_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv4_table_create(struct nb_cb_create_args *args);
int isis_instance_redistribute_ipv4_table_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv6_create(struct nb_cb_create_args *args);
int isis_instance_redistribute_ipv6_destroy(struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv6_route_map_modify(
	struct nb_cb_modify_args *args);
int isis_instance_redistribute_ipv6_route_map_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv6_metric_modify(
	struct nb_cb_modify_args *args);
int isis_instance_redistribute_ipv6_metric_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_redistribute_ipv6_table_create(struct nb_cb_create_args *args);
int isis_instance_redistribute_ipv6_table_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv4_multicast_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv4_multicast_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv4_multicast_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_multi_topology_ipv4_management_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv4_management_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv4_management_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_multi_topology_ipv6_unicast_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv6_unicast_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv6_unicast_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_multi_topology_ipv6_multicast_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv6_multicast_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv6_multicast_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_multi_topology_ipv6_management_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv6_management_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv6_management_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_multi_topology_ipv6_dstsrc_create(
	struct nb_cb_create_args *args);
int isis_instance_multi_topology_ipv6_dstsrc_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_multi_topology_ipv6_dstsrc_overload_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_1_lfa_load_sharing_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_1_lfa_priority_limit_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_1_lfa_priority_limit_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_fast_reroute_level_1_lfa_tiebreaker_create(
	struct nb_cb_create_args *args);
int isis_instance_fast_reroute_level_1_lfa_tiebreaker_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_fast_reroute_level_1_lfa_tiebreaker_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_fast_reroute_level_2_lfa_load_sharing_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_2_lfa_priority_limit_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_2_lfa_priority_limit_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_fast_reroute_level_2_lfa_tiebreaker_create(
	struct nb_cb_create_args *args);
int isis_instance_fast_reroute_level_2_lfa_tiebreaker_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_fast_reroute_level_2_lfa_tiebreaker_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_modify(
	struct nb_cb_modify_args *args);
int isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_log_adjacency_changes_modify(struct nb_cb_modify_args *args);
int isis_instance_log_pdu_drops_modify(struct nb_cb_modify_args *args);
int isis_instance_mpls_te_create(struct nb_cb_create_args *args);
int isis_instance_mpls_te_destroy(struct nb_cb_destroy_args *args);
int isis_instance_mpls_te_router_address_modify(struct nb_cb_modify_args *args);
int isis_instance_mpls_te_router_address_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_mpls_te_router_address_ipv6_modify(
	struct nb_cb_modify_args *args);
int isis_instance_mpls_te_router_address_ipv6_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_mpls_te_export_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_create(struct nb_cb_create_args *args);
int lib_interface_isis_destroy(struct nb_cb_destroy_args *args);
int lib_interface_isis_area_tag_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_ipv4_routing_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_ipv6_routing_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_circuit_type_modify(struct nb_cb_modify_args *args);
void lib_interface_isis_bfd_monitoring_apply_finish(
	struct nb_cb_apply_finish_args *args);
int lib_interface_isis_bfd_monitoring_enabled_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_bfd_monitoring_profile_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_bfd_monitoring_profile_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_segment_routing_enabled_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_enabled_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srgb_lower_bound_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srgb_upper_bound_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srlb_lower_bound_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srlb_upper_bound_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_msd_node_msd_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_msd_node_msd_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_create(
	struct nb_cb_create_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_last_hop_behavior_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_n_flag_clear_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_create(
	struct nb_cb_create_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_pre_validate(
	struct nb_cb_pre_validate_args *args);
void isis_instance_segment_routing_algorithm_prefix_sid_apply_finish(
	struct nb_cb_apply_finish_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_sid_value_type_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_sid_value_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_last_hop_behavior_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_algorithm_prefix_sid_n_flag_clear_modify(
	struct nb_cb_modify_args *args);
int isis_instance_flex_algo_create(struct nb_cb_create_args *args);
int isis_instance_flex_algo_destroy(struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_advertise_definition_modify(
	struct nb_cb_modify_args *args);
int isis_instance_flex_algo_advertise_definition_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_affinity_include_any_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_affinity_include_any_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_affinity_include_all_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_affinity_include_all_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_affinity_exclude_any_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_affinity_exclude_any_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_prefix_metric_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_prefix_metric_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_dplane_sr_mpls_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_dplane_sr_mpls_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_dplane_srv6_create(struct nb_cb_create_args *args);
int isis_instance_flex_algo_dplane_srv6_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_dplane_ip_create(struct nb_cb_create_args *args);
int isis_instance_flex_algo_dplane_ip_destroy(struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_metric_type_modify(struct nb_cb_modify_args *args);
int isis_instance_flex_algo_priority_modify(struct nb_cb_modify_args *args);
int isis_instance_flex_algo_priority_destroy(struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_frr_disable_modify(struct nb_cb_modify_args *args);
int isis_instance_flex_algo_frr_disable_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_affinity_mapping_create(
	struct nb_cb_create_args *args);
int isis_instance_flex_algo_affinity_mapping_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_flex_algo_affinity_mapping_value_modify(
	struct nb_cb_modify_args *args);
int isis_instance_flex_algo_affinity_mapping_value_destroy(
	struct nb_cb_destroy_args *args);
int isis_instance_segment_routing_srv6_enabled_modify(
	struct nb_cb_modify_args *args);
void cli_show_isis_srv6_enabled(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
int isis_instance_segment_routing_srv6_locator_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srv6_locator_destroy(
	struct nb_cb_destroy_args *args);
void cli_show_isis_srv6_locator(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
int isis_instance_segment_routing_srv6_msd_node_msd_max_segs_left_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srv6_msd_node_msd_max_end_pop_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srv6_msd_node_msd_max_h_encaps_modify(
	struct nb_cb_modify_args *args);
int isis_instance_segment_routing_srv6_msd_node_msd_max_end_d_modify(
	struct nb_cb_modify_args *args);
void cli_show_isis_srv6_node_msd(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
int isis_instance_segment_routing_srv6_interface_modify(
	struct nb_cb_modify_args *args);
void cli_show_isis_srv6_interface(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
int isis_instance_mpls_ldp_sync_destroy(struct nb_cb_destroy_args *args);
int isis_instance_mpls_ldp_sync_create(struct nb_cb_create_args *args);
int isis_instance_mpls_ldp_sync_holddown_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_csnp_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_csnp_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_psnp_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_psnp_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_hello_padding_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_hello_interval_level_1_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_hello_interval_level_2_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_hello_multiplier_level_1_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_hello_multiplier_level_2_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_metric_level_1_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_metric_level_2_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_priority_level_1_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_priority_level_2_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_network_type_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_passive_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_password_create(struct nb_cb_create_args *args);
int lib_interface_isis_password_destroy(struct nb_cb_destroy_args *args);
int lib_interface_isis_password_password_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_password_password_type_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_disable_three_way_handshake_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_standard_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv4_multicast_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv4_management_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv6_unicast_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv6_multicast_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv6_management_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_mpls_ldp_sync_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_mpls_holddown_modify(struct nb_cb_modify_args *args);
int lib_interface_isis_mpls_holddown_destroy(struct nb_cb_destroy_args *args);
int lib_interface_isis_fast_reroute_level_1_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_create(
	struct nb_cb_create_args *args);
int lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_isis_fast_reroute_level_1_remote_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_isis_fast_reroute_level_1_ti_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_1_ti_lfa_node_protection_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_1_ti_lfa_link_fallback_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_create(
	struct nb_cb_create_args *args);
int lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_isis_fast_reroute_level_2_remote_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_isis_fast_reroute_level_2_ti_lfa_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_ti_lfa_node_protection_modify(
	struct nb_cb_modify_args *args);
int lib_interface_isis_fast_reroute_level_2_ti_lfa_link_fallback_modify(
	struct nb_cb_modify_args *args);
struct yang_data *
lib_interface_state_isis_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_interface_state_isis_adjacencies_adjacency_get_next(
	struct nb_cb_get_next_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_sys_type_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_sysid_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_snpa_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_hold_timer_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_neighbor_priority_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_state_isis_adjacencies_adjacency_state_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_get_next(
	struct nb_cb_get_next_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_af_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_value_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_weight_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_protection_requested_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_get_next(
	struct nb_cb_get_next_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_af_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_value_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_weight_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_protection_requested_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_changes_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_number_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_state_isis_event_counters_init_fails_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_adjacency_rejects_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_id_len_mismatch_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_max_area_addresses_mismatch_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_authentication_type_fails_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_state_isis_event_counters_authentication_fails_get_elem(
	struct nb_cb_get_elem_args *args);

/* Optional 'pre_validate' callbacks. */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_pre_validate(
	struct nb_cb_pre_validate_args *args);
int isis_instance_segment_routing_label_blocks_pre_validate(
	struct nb_cb_pre_validate_args *args);

/* Optional 'apply_finish' callbacks. */
void ietf_backoff_delay_apply_finish(struct nb_cb_apply_finish_args *args);
void area_password_apply_finish(struct nb_cb_apply_finish_args *args);
void domain_password_apply_finish(struct nb_cb_apply_finish_args *args);
void default_info_origin_apply_finish(const struct lyd_node *dnode, int family);
void default_info_origin_ipv4_apply_finish(
	struct nb_cb_apply_finish_args *args);
void default_info_origin_ipv6_apply_finish(
	struct nb_cb_apply_finish_args *args);
void redistribute_apply_finish(const struct lyd_node *dnode, int family);
void redistribute_ipv4_apply_finish(struct nb_cb_apply_finish_args *args);
void redistribute_ipv6_apply_finish(struct nb_cb_apply_finish_args *args);
void isis_instance_segment_routing_srgb_apply_finish(
	struct nb_cb_apply_finish_args *args);
void isis_instance_segment_routing_srlb_apply_finish(
	struct nb_cb_apply_finish_args *args);
void isis_instance_segment_routing_prefix_sid_map_prefix_sid_apply_finish(
	struct nb_cb_apply_finish_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_router_isis(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_router_isis_end(struct vty *vty, const struct lyd_node *dnode);
void cli_show_ip_isis_ipv4(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_isis_ipv6(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_isis_bfd_monitoring(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_area_address(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_is_type(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_dynamic_hostname(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_attached_send(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_isis_attached_receive(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_overload(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_overload_on_startup(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_advertise_high_metrics(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_metric_style(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_area_pwd(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_domain_pwd(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_lsp_timers(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_lsp_mtu(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_advertise_passive_only(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_spf_min_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_spf_ietf_backoff(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_spf_prefix_priority(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_isis_purge_origin(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mpls_te(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_admin_group_send_zero(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults);
void cli_show_isis_asla_legacy_flag(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_mpls_te_router_addr(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_isis_mpls_te_router_addr_ipv6(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults);
void cli_show_isis_mpls_te_export(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_isis_def_origin_ipv4(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_def_origin_ipv6(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_redistribute_ipv4(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_redistribute_ipv6(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_mt_ipv4_multicast(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_redistribute_ipv4_table(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_isis_redistribute_ipv6_table(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_isis_mt_ipv4_mgmt(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mt_ipv6_unicast(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_mt_ipv6_multicast(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_mt_ipv6_mgmt(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mt_ipv6_dstsrc(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_isis_sr_enabled(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_label_blocks(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_node_msd(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_prefix_sid(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_prefix_sid_algorithm(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_isis_frr_lfa_priority_limit(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
void cli_show_isis_frr_lfa_tiebreaker(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_isis_frr_lfa_load_sharing(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_isis_frr_remote_lfa_plist(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_passive(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_ip_isis_password(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_ip_isis_metric(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
void cli_show_ip_isis_hello_interval(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_hello_multi(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_isis_threeway_shake(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_hello_padding(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_csnp_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_psnp_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_mt_standard(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_isis_mt_ipv4_multicast(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_mt_ipv4_mgmt(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_mt_ipv6_unicast(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ip_isis_mt_ipv6_multicast(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_mt_ipv6_mgmt(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_mt_ipv6_dstsrc(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_frr(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_frr_lfa_exclude_interface(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_frr_remote_lfa_max_metric(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_circ_type(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_ip_isis_network_type(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_priority(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_isis_log_adjacency(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_isis_log_pdu_drops(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_isis_mpls_ldp_sync(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_isis_mpls_ldp_sync_holddown(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
void cli_show_isis_mpls_if_ldp_sync(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_mpls_if_ldp_sync_holddown(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults);
void cli_show_isis_flex_algo(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
void cli_show_isis_flex_algo_end(struct vty *vty, const struct lyd_node *dnode);

/* Notifications. */
void isis_notif_db_overload(const struct isis_area *area, bool overload);
void isis_notif_lsp_too_large(const struct isis_circuit *circuit,
			      uint32_t pdu_size, const uint8_t *lsp_id);
void isis_notif_if_state_change(const struct isis_circuit *circuit, bool down);
void isis_notif_corrupted_lsp(const struct isis_area *area,
			      const uint8_t *lsp_id); /* currently unused */
void isis_notif_lsp_exceed_max(const struct isis_area *area,
			       const uint8_t *lsp_id);
void isis_notif_max_area_addr_mismatch(const struct isis_circuit *circuit,
				       uint8_t max_area_addrs,
				       const char *raw_pdu, size_t raw_pdu_len);
void isis_notif_authentication_type_failure(const struct isis_circuit *circuit,
					    const char *raw_pdu,
					    size_t raw_pdu_len);
void isis_notif_authentication_failure(const struct isis_circuit *circuit,
				       const char *raw_pdu, size_t raw_pdu_len);
void isis_notif_adj_state_change(const struct isis_adjacency *adj,
				 int new_state, const char *reason);
void isis_notif_reject_adjacency(const struct isis_circuit *circuit,
				 const char *reason, const char *raw_pdu,
				 size_t raw_pdu_len);
void isis_notif_area_mismatch(const struct isis_circuit *circuit,
			      const char *raw_pdu, size_t raw_pdu_len);
void isis_notif_lsp_received(const struct isis_circuit *circuit,
			     const uint8_t *lsp_id, uint32_t seqno,
			     uint32_t timestamp, const char *sys_id);
void isis_notif_lsp_gen(const struct isis_area *area, const uint8_t *lsp_id,
			uint32_t seqno, uint32_t timestamp);
void isis_notif_id_len_mismatch(const struct isis_circuit *circuit,
				uint8_t rcv_id_len, const char *raw_pdu,
				size_t raw_pdu_len);
void isis_notif_version_skew(const struct isis_circuit *circuit,
			     uint8_t version, const char *raw_pdu,
			     size_t raw_pdu_len);
void isis_notif_lsp_error(const struct isis_circuit *circuit,
			  const uint8_t *lsp_id, const char *raw_pdu,
			  size_t raw_pdu_len, uint32_t offset,
			  uint8_t tlv_type);
void isis_notif_seqno_skipped(const struct isis_circuit *circuit,
			      const uint8_t *lsp_id);
void isis_notif_own_lsp_purge(const struct isis_circuit *circuit,
			      const uint8_t *lsp_id);
/* cmp */
int cli_cmp_isis_redistribute_table(const struct lyd_node *dnode1,
				    const struct lyd_node *dnode2);

/* We also declare hook for every notification */

DECLARE_HOOK(isis_hook_db_overload, (const struct isis_area *area), (area));
DECLARE_HOOK(isis_hook_lsp_too_large,
	     (const struct isis_circuit *circuit, uint32_t pdu_size,
	      const uint8_t *lsp_id),
	     (circuit, pdu_size, lsp_id));
/* Note: no isis_hook_corrupted_lsp - because this notificaiton is not used */
DECLARE_HOOK(isis_hook_lsp_exceed_max,
	     (const struct isis_area *area, const uint8_t *lsp_id),
	     (area, lsp_id));
DECLARE_HOOK(isis_hook_max_area_addr_mismatch,
	     (const struct isis_circuit *circuit, uint8_t max_addrs,
	      const char *raw_pdu, size_t raw_pdu_len),
	     (circuit, max_addrs, raw_pdu, raw_pdu_len));
DECLARE_HOOK(isis_hook_authentication_type_failure,
	     (const struct isis_circuit *circuit, const char *raw_pdu,
	      size_t raw_pdu_len),
	     (circuit, raw_pdu, raw_pdu_len));
DECLARE_HOOK(isis_hook_authentication_failure,
	     (const struct isis_circuit *circuit, const char *raw_pdu,
	      size_t raw_pdu_len),
	     (circuit, raw_pdu, raw_pdu_len));
DECLARE_HOOK(isis_hook_adj_state_change, (const struct isis_adjacency *adj),
	     (adj));
DECLARE_HOOK(isis_hook_reject_adjacency,
	     (const struct isis_circuit *circuit, const char *pdu,
	      size_t pdu_len),
	     (circuit, pdu, pdu_len));
DECLARE_HOOK(isis_hook_area_mismatch,
	     (const struct isis_circuit *circuit, const char *raw_pdu,
	      size_t raw_pdu_len),
	     (circuit));
DECLARE_HOOK(isis_hook_id_len_mismatch,
	     (const struct isis_circuit *circuit, uint8_t rcv_id_len,
	      const char *raw_pdu, size_t raw_pdu_len),
	     (circuit, rcv_id_len, raw_pdu, raw_pdu_len));
DECLARE_HOOK(isis_hook_version_skew,
	     (const struct isis_circuit *circuit, uint8_t version,
	      const char *raw_pdu, size_t raw_pdu_len),
	     (circuit));
DECLARE_HOOK(isis_hook_lsp_error,
	     (const struct isis_circuit *circuit, const uint8_t *lsp_id,
	      const char *raw_pdu, size_t raw_pdu_len),
	     (circuit));
DECLARE_HOOK(isis_hook_seqno_skipped,
	     (const struct isis_circuit *circuit, const uint8_t *lsp_id),
	     (circuit, lsp_id));
DECLARE_HOOK(isis_hook_own_lsp_purge,
	     (const struct isis_circuit *circuit, const uint8_t *lsp_id),
	     (circuit, lsp_id));

#endif /* ISISD_ISIS_NB_H_ */
