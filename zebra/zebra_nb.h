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
int lib_interface_zebra_ip_addrs_create(struct nb_cb_create_args *args);
int lib_interface_zebra_ip_addrs_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ip_addrs_label_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_ip_addrs_label_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_ip_addrs_ip4_peer_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_ip_addrs_ip4_peer_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_multicast_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_multicast_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_link_detect_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_link_detect_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_shutdown_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_shutdown_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_bandwidth_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_bandwidth_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_mpls_modify(struct nb_cb_modify_args *args);
int lib_interface_zebra_mpls_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_legacy_admin_group_modify(
	struct nb_cb_modify_args *args);
int lib_interface_zebra_legacy_admin_group_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_zebra_affinity_create(struct nb_cb_create_args *args);
int lib_interface_zebra_affinity_destroy(struct nb_cb_destroy_args *args);
int lib_interface_zebra_affinity_mode_modify(struct nb_cb_modify_args *args);
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
