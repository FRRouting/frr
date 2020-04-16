/*
 * Copyright (C) 2020 Cumulus Networks, Inc.
 *                    Chirag Shah
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

#ifndef ZEBRA_ZEBRA_NB_H_
#define ZEBRA_ZEBRA_NB_H_

extern const struct frr_yang_module_info frr_zebra_info;

/* prototypes */
int get_route_information_rpc(const char *xpath, const struct list *input,
			      struct list *output);
int get_v6_mroute_info_rpc(const char *xpath, const struct list *input,
			   struct list *output);
int get_vrf_info_rpc(const char *xpath, const struct list *input,
		     struct list *output);
int get_vrf_vni_info_rpc(const char *xpath, const struct list *input,
			 struct list *output);
int get_evpn_info_rpc(const char *xpath, const struct list *input,
		      struct list *output);
int get_vni_info_rpc(const char *xpath, const struct list *input,
		     struct list *output);
int get_evpn_vni_rmac_rpc(const char *xpath, const struct list *input,
			  struct list *output);
int get_evpn_vni_nexthops_rpc(const char *xpath, const struct list *input,
			      struct list *output);
int clear_evpn_dup_addr_rpc(const char *xpath, const struct list *input,
			    struct list *output);
int get_evpn_macs_rpc(const char *xpath, const struct list *input,
		      struct list *output);
int get_evpn_arp_cache_rpc(const char *xpath, const struct list *input,
			   struct list *output);
int get_pbr_ipset_rpc(const char *xpath, const struct list *input,
		      struct list *output);
int get_pbr_iptable_rpc(const char *xpath, const struct list *input,
			struct list *output);
int get_debugs_rpc(const char *xpath, const struct list *input,
		   struct list *output);
int zebra_mcast_rpf_lookup_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int zebra_ip_forwarding_modify(enum nb_event event,
			       const struct lyd_node *dnode,
			       union nb_resource *resource);
int zebra_ip_forwarding_destroy(enum nb_event event,
				const struct lyd_node *dnode);
int zebra_ipv6_forwarding_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int zebra_ipv6_forwarding_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
int zebra_workqueue_hold_timer_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int zebra_zapi_packets_modify(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource);
int zebra_import_kernel_table_table_id_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int zebra_import_kernel_table_table_id_destroy(enum nb_event event,
					       const struct lyd_node *dnode);
int zebra_import_kernel_table_distance_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int zebra_import_kernel_table_route_map_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource);
int zebra_import_kernel_table_route_map_destroy(enum nb_event event,
						const struct lyd_node *dnode);
int zebra_allow_external_route_update_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int zebra_allow_external_route_update_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int zebra_dplane_queue_limit_modify(enum nb_event event,
				    const struct lyd_node *dnode,
				    union nb_resource *resource);
int zebra_vrf_vni_mapping_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int zebra_vrf_vni_mapping_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
int zebra_vrf_vni_mapping_vni_id_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int zebra_vrf_vni_mapping_vni_id_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int zebra_vrf_vni_mapping_prefix_only_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int zebra_vrf_vni_mapping_prefix_only_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int zebra_debugs_debug_events_modify(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource);
int zebra_debugs_debug_events_destroy(enum nb_event event,
				      const struct lyd_node *dnode);
int zebra_debugs_debug_zapi_send_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int zebra_debugs_debug_zapi_send_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int zebra_debugs_debug_zapi_recv_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int zebra_debugs_debug_zapi_recv_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int zebra_debugs_debug_zapi_detail_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int zebra_debugs_debug_zapi_detail_destroy(enum nb_event event,
					   const struct lyd_node *dnode);
int zebra_debugs_debug_kernel_modify(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource);
int zebra_debugs_debug_kernel_destroy(enum nb_event event,
				      const struct lyd_node *dnode);
int zebra_debugs_debug_kernel_msg_send_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int zebra_debugs_debug_kernel_msg_send_destroy(enum nb_event event,
					       const struct lyd_node *dnode);
int zebra_debugs_debug_kernel_msg_recv_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int zebra_debugs_debug_kernel_msg_recv_destroy(enum nb_event event,
					       const struct lyd_node *dnode);
int zebra_debugs_debug_rib_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int zebra_debugs_debug_rib_destroy(enum nb_event event,
				   const struct lyd_node *dnode);
int zebra_debugs_debug_rib_detail_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int zebra_debugs_debug_rib_detail_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int zebra_debugs_debug_fpm_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int zebra_debugs_debug_fpm_destroy(enum nb_event event,
				   const struct lyd_node *dnode);
int zebra_debugs_debug_nht_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int zebra_debugs_debug_nht_destroy(enum nb_event event,
				   const struct lyd_node *dnode);
int zebra_debugs_debug_nht_detail_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int zebra_debugs_debug_nht_detail_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int zebra_debugs_debug_mpls_modify(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource);
int zebra_debugs_debug_mpls_destroy(enum nb_event event,
				    const struct lyd_node *dnode);
int zebra_debugs_debug_vxlan_modify(enum nb_event event,
				    const struct lyd_node *dnode,
				    union nb_resource *resource);
int zebra_debugs_debug_vxlan_destroy(enum nb_event event,
				     const struct lyd_node *dnode);
int zebra_debugs_debug_pw_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int zebra_debugs_debug_pw_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
int zebra_debugs_debug_dplane_modify(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource);
int zebra_debugs_debug_dplane_destroy(enum nb_event event,
				      const struct lyd_node *dnode);
int zebra_debugs_debug_dplane_detail_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource);
int zebra_debugs_debug_dplane_detail_destroy(enum nb_event event,
					     const struct lyd_node *dnode);
int zebra_debugs_debug_mlag_modify(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource);
int zebra_debugs_debug_mlag_destroy(enum nb_event event,
				    const struct lyd_node *dnode);
int lib_interface_zebra_ip_addrs_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int lib_interface_zebra_ip_addrs_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int lib_interface_zebra_ip_addrs_label_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int lib_interface_zebra_ip_addrs_label_destroy(enum nb_event event,
					       const struct lyd_node *dnode);
int lib_interface_zebra_ip_addrs_ip4_peer_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource);
int lib_interface_zebra_ip_addrs_ip4_peer_destroy(enum nb_event event,
						  const struct lyd_node *dnode);
int lib_interface_zebra_multicast_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int lib_interface_zebra_multicast_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int lib_interface_zebra_link_detect_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_zebra_link_detect_destroy(enum nb_event event,
					    const struct lyd_node *dnode);
int lib_interface_zebra_shutdown_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int lib_interface_zebra_shutdown_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int lib_interface_zebra_bandwidth_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int lib_interface_zebra_bandwidth_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int lib_route_map_entry_match_condition_ipv4_prefix_length_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_match_condition_ipv4_prefix_length_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_route_map_entry_match_condition_ipv6_prefix_length_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_match_condition_ipv6_prefix_length_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_route_map_entry_match_condition_source_protocol_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_match_condition_source_protocol_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_route_map_entry_match_condition_source_instance_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_match_condition_source_instance_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_route_map_entry_set_action_source_v4_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_set_action_source_v4_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_route_map_entry_set_action_source_v6_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_route_map_entry_set_action_source_v6_destroy(
	enum nb_event event, const struct lyd_node *dnode);
struct yang_data *
lib_interface_zebra_state_up_count_get_elem(const char *xpath,
					    const void *list_entry);
struct yang_data *
lib_interface_zebra_state_down_count_get_elem(const char *xpath,
					      const void *list_entry);
struct yang_data *
lib_interface_zebra_state_zif_type_get_elem(const char *xpath,
					    const void *list_entry);
struct yang_data *
lib_interface_zebra_state_ptm_status_get_elem(const char *xpath,
					      const void *list_entry);
struct yang_data *
lib_interface_zebra_state_vlan_id_get_elem(const char *xpath,
					   const void *list_entry);
struct yang_data *
lib_interface_zebra_state_vni_id_get_elem(const char *xpath,
					  const void *list_entry);
struct yang_data *
lib_interface_zebra_state_remote_vtep_get_elem(const char *xpath,
					       const void *list_entry);
struct yang_data *
lib_interface_zebra_state_mcast_group_get_elem(const char *xpath,
					       const void *list_entry);
int lib_vrf_ribs_rib_create(enum nb_event event, const struct lyd_node *dnode,
			    union nb_resource *resource);
int lib_vrf_ribs_rib_destroy(enum nb_event event, const struct lyd_node *dnode);
const void *lib_vrf_ribs_rib_get_next(const void *parent_list_entry,
				      const void *list_entry);
int lib_vrf_ribs_rib_get_keys(const void *list_entry,
			      struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_route_get_next(const void *parent_list_entry,
					    const void *list_entry);
int lib_vrf_ribs_rib_route_get_keys(const void *list_entry,
				    struct yang_list_keys *keys);
const void *
lib_vrf_ribs_rib_route_lookup_entry(const void *parent_list_entry,
				    const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_prefix_get_elem(const char *xpath,
				       const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_protocol_get_elem(const char *xpath,
					 const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_protocol_v6_get_elem(const char *xpath,
					    const void *list_entry);
struct yang_data *lib_vrf_ribs_rib_route_vrf_get_elem(const char *xpath,
						      const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_distance_get_elem(const char *xpath,
					 const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_metric_get_elem(const char *xpath,
				       const void *list_entry);
struct yang_data *lib_vrf_ribs_rib_route_tag_get_elem(const char *xpath,
						      const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_selected_get_elem(const char *xpath,
					 const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_installed_get_elem(const char *xpath,
					  const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_failed_get_elem(const char *xpath,
				       const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_queued_get_elem(const char *xpath,
				       const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_internal_flags_get_elem(const char *xpath,
					       const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_internal_status_get_elem(const char *xpath,
						const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_uptime_get_elem(const char *xpath,
				       const void *list_entry);
const void *
lib_vrf_ribs_rib_route_nexthop_group_get_next(const void *parent_list_entry,
					      const void *list_entry);
int lib_vrf_ribs_rib_route_nexthop_group_get_keys(const void *list_entry,
						  struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_route_nexthop_group_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_name_get_elem(const char *xpath,
						   const void *list_entry);
const void *lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_next(
	const void *parent_list_entry, const void *list_entry);
int lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_keys(
	const void *list_entry, struct yang_list_keys *keys);
int lib_vrf_ribs_rib_create(enum nb_event event, const struct lyd_node *dnode,
			    union nb_resource *resource);
int lib_vrf_ribs_rib_destroy(enum nb_event event, const struct lyd_node *dnode);
const void *lib_vrf_ribs_rib_get_next(const void *parent_list_entry,
				      const void *list_entry);
int lib_vrf_ribs_rib_get_keys(const void *list_entry,
			      struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_route_get_next(const void *parent_list_entry,
					    const void *list_entry);
int lib_vrf_ribs_rib_route_get_keys(const void *list_entry,
				    struct yang_list_keys *keys);
const void *
lib_vrf_ribs_rib_route_lookup_entry(const void *parent_list_entry,
				    const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_prefix_get_elem(const char *xpath,
				       const void *list_entry);
const void *
lib_vrf_ribs_rib_route_route_entry_get_next(const void *parent_list_entry,
					    const void *list_entry);
int lib_vrf_ribs_rib_route_route_entry_get_keys(const void *list_entry,
						struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_route_route_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_protocol_get_elem(const char *xpath,
						     const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_instance_get_elem(const char *xpath,
						     const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_distance_get_elem(const char *xpath,
						     const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_metric_get_elem(const char *xpath,
						   const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_tag_get_elem(const char *xpath,
						const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_selected_get_elem(const char *xpath,
						     const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_installed_get_elem(const char *xpath,
						      const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_failed_get_elem(const char *xpath,
						   const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_queued_get_elem(const char *xpath,
						   const void *list_entry);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_flags_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_status_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_uptime_get_elem(const char *xpath,
						   const void *list_entry);
const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_next(
	const void *parent_list_entry, const void *list_entry);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_keys(
	const void *list_entry, struct yang_list_keys *keys);
const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_name_get_elem(
	const char *xpath, const void *list_entry);
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_next(
	const void *parent_list_entry, const void *list_entry);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_keys(
	const void *list_entry, struct yang_list_keys *keys);
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_nh_type_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_vrf_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_gateway_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_interface_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_bh_type_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_onlink_get_elem(
	const char *xpath, const void *list_entry);
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_next(
	const void *parent_list_entry, const void *list_entry);
int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_keys(
	const void *list_entry, struct yang_list_keys *keys);
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_id_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_label_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_duplicate_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_recursive_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_active_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_fib_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_weight_get_elem(
	const char *xpath, const void *list_entry);

#endif
