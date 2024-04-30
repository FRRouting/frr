// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Cumulus Networks, Inc.
 *                    Chirag Shah
 */

#ifndef ZEBRA_ZEBRA_NB_H_
#define ZEBRA_ZEBRA_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_zebra_info;

/* prototypes */
int get_route_information_rpc(struct nb_cb_rpc_args *args);
int get_v6_mroute_info_rpc(struct nb_cb_rpc_args *args);
int get_vrf_info_rpc(struct nb_cb_rpc_args *args);
int get_vrf_vni_info_rpc(struct nb_cb_rpc_args *args);
int get_evpn_info_rpc(struct nb_cb_rpc_args *args);
int get_vni_info_rpc(struct nb_cb_rpc_args *args);
int get_evpn_vni_rmac_rpc(struct nb_cb_rpc_args *args);
int get_evpn_vni_nexthops_rpc(struct nb_cb_rpc_args *args);
int clear_evpn_dup_addr_rpc(struct nb_cb_rpc_args *args);
int get_evpn_macs_rpc(struct nb_cb_rpc_args *args);
int get_evpn_arp_cache_rpc(struct nb_cb_rpc_args *args);
int get_pbr_ipset_rpc(struct nb_cb_rpc_args *args);
int get_pbr_iptable_rpc(struct nb_cb_rpc_args *args);
int get_debugs_rpc(struct nb_cb_rpc_args *args);
int zebra_mcast_rpf_lookup_modify(struct nb_cb_modify_args *args);
int zebra_ip_forwarding_modify(struct nb_cb_modify_args *args);
int zebra_ip_forwarding_destroy(struct nb_cb_destroy_args *args);
int zebra_ipv6_forwarding_modify(struct nb_cb_modify_args *args);
int zebra_ipv6_forwarding_destroy(struct nb_cb_destroy_args *args);
int zebra_workqueue_hold_timer_modify(struct nb_cb_modify_args *args);
int zebra_zapi_packets_modify(struct nb_cb_modify_args *args);
int zebra_import_kernel_table_table_id_modify(struct nb_cb_modify_args *args);
int zebra_import_kernel_table_table_id_destroy(struct nb_cb_destroy_args *args);
int zebra_import_kernel_table_distance_modify(struct nb_cb_modify_args *args);
int zebra_import_kernel_table_route_map_modify(struct nb_cb_modify_args *args);
int zebra_import_kernel_table_route_map_destroy(
	struct nb_cb_destroy_args *args);
int zebra_allow_external_route_update_create(struct nb_cb_create_args *args);
int zebra_allow_external_route_update_destroy(struct nb_cb_destroy_args *args);
int zebra_dplane_queue_limit_modify(struct nb_cb_modify_args *args);
#if HAVE_BFDD == 0
int zebra_ptm_enable_modify(struct nb_cb_modify_args *args);
#endif
int zebra_route_map_delay_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_events_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_events_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_zapi_send_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_zapi_send_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_zapi_recv_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_zapi_recv_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_zapi_detail_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_zapi_detail_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_kernel_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_kernel_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_kernel_msg_send_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_kernel_msg_send_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_kernel_msg_recv_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_kernel_msg_recv_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_rib_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_rib_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_rib_detail_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_rib_detail_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_fpm_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_fpm_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_nht_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_nht_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_nht_detail_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_nht_detail_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_mpls_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_mpls_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_vxlan_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_vxlan_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_pw_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_pw_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_dplane_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_dplane_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_dplane_detail_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_dplane_detail_destroy(struct nb_cb_destroy_args *args);
int zebra_debugs_debug_mlag_modify(struct nb_cb_modify_args *args);
int zebra_debugs_debug_mlag_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv4_addrs_create(struct nb_cb_create_args *args);
int lib_interface_zebra_ipv4_addrs_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv4_addrs_label_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv4_addrs_label_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv4_p2p_addrs_create(struct nb_cb_create_args *args);
int lib_interface_zebra_ipv4_p2p_addrs_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv4_p2p_addrs_label_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv4_p2p_addrs_label_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_addrs_create(struct nb_cb_create_args *args);
int lib_interface_zebra_ipv6_addrs_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_multicast_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_multicast_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_detect_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_enabled_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_enabled_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_bandwidth_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_bandwidth_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_mpls_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_mpls_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_create(struct nb_cb_create_args *args);
int lib_interface_zebra_link_params_destroy(struct nb_cb_destroy_args *args);
void lib_interface_zebra_link_params_apply_finish(
	struct nb_cb_apply_finish_args *args);
int lib_interface_zebra_link_params_metric_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_metric_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_max_bandwidth_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_max_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_max_reservable_bandwidth_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_max_reservable_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_create(
	struct nb_cb_create_args *args);
void lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_modify(
	struct nb_cb_modify_args *args);
void lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int lib_interface_zebra_link_params_residual_bandwidth_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_residual_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_available_bandwidth_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_available_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_utilized_bandwidth_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_utilized_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_legacy_admin_group_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_legacy_admin_group_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_affinities_create(struct nb_cb_create_args *args);
int lib_interface_zebra_affinities_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_affinity_create(struct nb_cb_create_args *args);
int lib_interface_zebra_affinity_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_affinity_mode_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_neighbor_create(
	struct nb_cb_create_args *args);
int lib_interface_zebra_link_params_neighbor_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_neighbor_remote_as_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_neighbor_ipv4_remote_id_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_delay_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_delay_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_min_max_delay_create(
	struct nb_cb_create_args *args);
int lib_interface_zebra_link_params_min_max_delay_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_min_max_delay_delay_min_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_min_max_delay_delay_max_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_delay_variation_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_delay_variation_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_params_packet_loss_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_link_params_packet_loss_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_type_0_create(struct nb_cb_create_args *args);
int lib_interface_zebra_evpn_mh_type_0_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_type_0_esi_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_evpn_mh_type_0_esi_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_type_3_create(struct nb_cb_create_args *args);
int lib_interface_zebra_evpn_mh_type_3_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_type_3_system_mac_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_evpn_mh_type_3_system_mac_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_type_3_local_discriminator_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_evpn_mh_type_3_local_discriminator_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_evpn_mh_df_preference_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_evpn_mh_bypass_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_evpn_mh_uplink_modify(struct nb_cb_modify_args *args);
#if defined(HAVE_RTADV)
int lib_interface_zebra_ipv6_router_advertisements_send_advertisements_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_managed_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_other_config_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_link_mtu_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_reachable_time_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_retrans_timer_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_default_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_default_lifetime_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_default_router_preference_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_create(
	struct nb_cb_create_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_valid_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_on_link_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_preferred_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_autonomous_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_router_address_flag_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_create(
	struct nb_cb_create_args *args);
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_create(
	struct nb_cb_create_args *args);
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_destroy(
	struct nb_cb_destroy_args *args);
#endif /* defined(HAVE_RTADV) */
#if HAVE_BFDD == 0
int lib_interface_zebra_ptm_enable_modify(struct nb_cb_modify_args *args);
#endif
struct yang_data *
lib_interface_zebra_state_up_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_zebra_state_down_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_zebra_state_zif_type_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_zebra_state_ptm_status_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_zebra_state_vlan_id_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_interface_zebra_state_vni_id_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_zebra_state_remote_vtep_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_zebra_state_mcast_group_get_elem(
	struct nb_cb_get_elem_args *args);
int lib_vrf_zebra_router_id_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_router_id_destroy(struct nb_cb_destroy_args *args);
int lib_vrf_zebra_ipv6_router_id_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_ipv6_router_id_destroy(struct nb_cb_destroy_args *args);
int lib_vrf_zebra_filter_protocol_create(struct nb_cb_create_args *args);
int lib_vrf_zebra_filter_protocol_destroy(struct nb_cb_destroy_args *args);
void lib_vrf_zebra_filter_protocol_apply_finish(
	struct nb_cb_apply_finish_args *args);
int lib_vrf_zebra_filter_protocol_route_map_modify(
	struct nb_cb_modify_args *args);
int lib_vrf_zebra_filter_nht_create(struct nb_cb_create_args *args);
int lib_vrf_zebra_filter_nht_destroy(struct nb_cb_destroy_args *args);
void lib_vrf_zebra_filter_nht_apply_finish(struct nb_cb_apply_finish_args *args);
int lib_vrf_zebra_filter_nht_route_map_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_resolve_via_default_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_resolve_via_default_destroy(struct nb_cb_destroy_args *args);
int lib_vrf_zebra_ipv6_resolve_via_default_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_ipv6_resolve_via_default_destroy(
	struct nb_cb_destroy_args *args);
int lib_vrf_zebra_netns_table_range_create(struct nb_cb_create_args *args);
int lib_vrf_zebra_netns_table_range_destroy(struct nb_cb_destroy_args *args);
int lib_vrf_zebra_netns_table_range_start_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_netns_table_range_end_modify(struct nb_cb_modify_args *args);
const void *lib_vrf_zebra_ribs_rib_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_get_keys(struct nb_cb_get_keys_args *args);
const void *
lib_vrf_zebra_ribs_rib_lookup_entry(struct nb_cb_lookup_entry_args *args);
const void *
lib_vrf_zebra_ribs_rib_lookup_next(struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_afi_safi_name_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_table_id_get_elem(struct nb_cb_get_elem_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_get_next(struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_get_keys(struct nb_cb_get_keys_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_lookup_entry(struct nb_cb_lookup_entry_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_lookup_next(struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_prefix_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_protocol_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_protocol_v6_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_vrf_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_distance_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_metric_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_tag_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_selected_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_installed_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_failed_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_queued_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_internal_flags_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_internal_status_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_uptime_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_vrf_zebra_ribs_rib_route_nexthop_group_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_nexthop_group_get_keys(
	struct nb_cb_get_keys_args *args);
const void *lib_vrf_zebra_ribs_rib_route_nexthop_group_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_nexthop_group_name_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_keys(
	struct nb_cb_get_keys_args *args);
const void *lib_vrf_zebra_ribs_rib_route_route_entry_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_route_entry_get_keys(
	struct nb_cb_get_keys_args *args);
const void *lib_vrf_zebra_ribs_rib_route_route_entry_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_protocol_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_instance_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_distance_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_metric_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_tag_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_selected_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_installed_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_failed_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_queued_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_internal_flags_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_internal_status_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_uptime_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_id_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_get_keys(
	struct nb_cb_get_keys_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_nh_type_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_vrf_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_gateway_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_interface_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_bh_type_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_onlink_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_color_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_get_keys(
	struct nb_cb_get_keys_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_id_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_seg_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_get_next(
	struct nb_cb_get_next_args *args);
int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_get_keys(
	struct nb_cb_get_keys_args *args);
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_id_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_label_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_ttl_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_duplicate_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_recursive_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_active_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_fib_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_weight_get_elem(
	struct nb_cb_get_elem_args *args);
int lib_vrf_zebra_l3vni_id_modify(struct nb_cb_modify_args *args);
int lib_vrf_zebra_l3vni_id_destroy(struct nb_cb_destroy_args *args);
int lib_vrf_zebra_prefix_only_modify(struct nb_cb_modify_args *args);

#ifdef __cplusplus
}
#endif

#endif
