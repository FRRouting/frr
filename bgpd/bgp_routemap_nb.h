// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#ifndef _FRR_BGP_ROUTEMAP_NB_H_
#define _FRR_BGP_ROUTEMAP_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_route_map_info;

/* prototypes */
int lib_route_map_entry_match_condition_rmap_match_condition_local_preference_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_local_preference_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_alias_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_alias_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_script_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_script_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_origin_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_origin_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_rpki_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_rpki_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_rpki_extcommunity_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_probability_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_probability_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_vrf_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv4_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_interface_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_ipv6_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_local_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_peer_local_destroy(struct nb_cb_destroy_args *args);
<<<<<<< HEAD
=======
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_ipv4_address_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_ipv4_address_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_interface_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_interface_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_ipv6_address_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_src_peer_ipv6_address_destroy(
	struct nb_cb_destroy_args *args);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
int lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_access_list_num_extended_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_list_name_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_list_name_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_create(struct nb_cb_create_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_default_route_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_vni_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_evpn_route_type_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_route_distinguisher_destroy(struct nb_cb_destroy_args *args);
<<<<<<< HEAD
void lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_destroy(struct nb_cb_destroy_args *args);
=======
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_create(
	struct nb_cb_create_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_destroy(
	struct nb_cb_destroy_args *args);
void lib_route_map_entry_match_condition_rmap_match_condition_comm_list_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_modify(struct nb_cb_modify_args *args);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_exact_match_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_comm_list_comm_list_name_any_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv4_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv6_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_distance_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_distance_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_rt_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_nt_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_soo_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_nexthop_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_preference_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_preference_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_label_index_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_label_index_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_local_pref_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_local_pref_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_weight_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_weight_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_origin_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_origin_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_originator_id_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_originator_id_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_table_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_table_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_create(struct nb_cb_create_args *args);
int lib_route_map_entry_set_action_rmap_set_action_atomic_aggregate_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aigp_metric_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aigp_metric_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_prepend_as_path_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_last_as_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_last_as_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_exclude_as_path_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_replace_as_path_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_replace_as_path_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_community_none_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_community_none_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_community_string_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_community_string_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_large_community_none_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_large_community_none_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_large_community_string_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_large_community_string_destroy(struct nb_cb_destroy_args *args);
<<<<<<< HEAD
void lib_route_map_entry_set_action_rmap_set_action_aggregator_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_destroy(struct nb_cb_destroy_args *args);
=======
int lib_route_map_entry_set_action_rmap_set_action_aggregator_create(
	struct nb_cb_create_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_destroy(
	struct nb_cb_destroy_args *args);
void lib_route_map_entry_set_action_rmap_set_action_aggregator_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_asn_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_aggregator_aggregator_address_modify(struct nb_cb_modify_args *args);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_comm_list_num_extended_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_comm_list_name_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_comm_list_name_destroy(struct nb_cb_destroy_args *args);
<<<<<<< HEAD
void lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_lb_type_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_lb_type_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_two_octet_as_specific_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_two_octet_as_specific_destroy(struct nb_cb_destroy_args *args);
=======
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_create(
	struct nb_cb_create_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_destroy(
	struct nb_cb_destroy_args *args);
void lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_finish(struct nb_cb_apply_finish_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_lb_type_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_bandwidth_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_lb_two_octet_as_specific_modify(struct nb_cb_modify_args *args);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_none_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv4_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_evpn_gateway_ip_ipv6_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_extcommunity_color_destroy(
	struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_modify(
	struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_l3vpn_nexthop_encapsulation_destroy(
	struct nb_cb_destroy_args *args);

#ifdef __cplusplus
}
#endif

#endif
