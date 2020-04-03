/*
 * Zebra northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#ifndef _FRR_ZEBRA_NB_H_
#define _FRR_ZEBRA_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_zebra_info;

/* Mandatory callbacks. */
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
int lib_interface_zebra_ip4_addr_list_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_zebra_ip4_addr_list_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int lib_interface_zebra_ip4_addr_list_ip4_peer_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_zebra_ip4_addr_list_ip4_peer_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_zebra_ip4_addr_list_label_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource);
int lib_interface_zebra_ip4_addr_list_label_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_zebra_ip6_addr_list_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_zebra_ip6_addr_list_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int lib_interface_zebra_ip6_addr_list_label_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource);
int lib_interface_zebra_ip6_addr_list_label_destroy(
	enum nb_event event, const struct lyd_node *dnode);
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

/* Optional 'apply_finish' callbacks. */

/* Optional 'cli_show' callbacks. */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ZEBRA_NB_H_ */
