/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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

#ifndef ISISD_ISIS_NB_H_
#define ISISD_ISIS_NB_H_

extern const struct frr_yang_module_info frr_isisd_info;

/* Forward declaration(s). */
struct isis_area;
struct isis_circuit;
struct isis_adjacency;

/* Mandatory callbacks. */
int isis_instance_create(enum nb_event event, const struct lyd_node *dnode,
			 union nb_resource *resource);
int isis_instance_destroy(enum nb_event event, const struct lyd_node *dnode);
int isis_instance_is_type_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int isis_instance_area_address_create(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int isis_instance_area_address_destroy(enum nb_event event,
				       const struct lyd_node *dnode);
int isis_instance_dynamic_hostname_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int isis_instance_attached_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int isis_instance_overload_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource);
int isis_instance_metric_style_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int isis_instance_purge_originator_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int isis_instance_lsp_mtu_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int isis_instance_lsp_refresh_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_lsp_refresh_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_lsp_maximum_lifetime_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_lsp_maximum_lifetime_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_lsp_generation_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_lsp_generation_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_destroy(enum nb_event event,
						 const struct lyd_node *dnode);
int isis_instance_spf_ietf_backoff_delay_init_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_minimum_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_spf_minimum_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_area_password_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource);
int isis_instance_area_password_destroy(enum nb_event event,
					const struct lyd_node *dnode);
int isis_instance_area_password_password_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource);
int isis_instance_area_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_area_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_domain_password_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int isis_instance_domain_password_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int isis_instance_domain_password_password_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int isis_instance_domain_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_domain_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv4_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv4_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_default_information_originate_ipv4_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv4_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_default_information_originate_ipv4_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv6_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv6_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_default_information_originate_ipv6_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_default_information_originate_ipv6_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_default_information_originate_ipv6_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_redistribute_ipv4_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int isis_instance_redistribute_ipv4_destroy(enum nb_event event,
					    const struct lyd_node *dnode);
int isis_instance_redistribute_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_redistribute_ipv4_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_redistribute_ipv4_metric_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int isis_instance_redistribute_ipv6_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int isis_instance_redistribute_ipv6_destroy(enum nb_event event,
					    const struct lyd_node *dnode);
int isis_instance_redistribute_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_redistribute_ipv6_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_redistribute_ipv6_metric_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int isis_instance_multi_topology_ipv4_multicast_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv4_multicast_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv4_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv4_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv4_management_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv4_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_unicast_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_unicast_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv6_unicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_multicast_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_multicast_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv6_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_management_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv6_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_dstsrc_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_multi_topology_ipv6_dstsrc_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int isis_instance_multi_topology_ipv6_dstsrc_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int isis_instance_log_adjacency_changes_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource);
int isis_instance_mpls_te_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int isis_instance_mpls_te_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
int isis_instance_mpls_te_router_address_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource);
int isis_instance_mpls_te_router_address_destroy(enum nb_event event,
						 const struct lyd_node *dnode);
int lib_interface_isis_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource);
int lib_interface_isis_destroy(enum nb_event event,
			       const struct lyd_node *dnode);
int lib_interface_isis_area_tag_modify(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource);
int lib_interface_isis_ipv4_routing_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_isis_ipv6_routing_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_isis_circuit_type_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_isis_bfd_monitoring_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_isis_csnp_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_csnp_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_psnp_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_psnp_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_hello_padding_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource);
int lib_interface_isis_hello_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_hello_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_hello_multiplier_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_hello_multiplier_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_metric_level_1_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_isis_metric_level_2_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_isis_priority_level_1_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource);
int lib_interface_isis_priority_level_2_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource);
int lib_interface_isis_network_type_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_isis_passive_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int lib_interface_isis_password_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource);
int lib_interface_isis_password_destroy(enum nb_event event,
					const struct lyd_node *dnode);
int lib_interface_isis_password_password_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource);
int lib_interface_isis_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_disable_three_way_handshake_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv4_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv4_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv4_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv6_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv6_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv6_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
const void *
lib_interface_isis_adjacencies_adjacency_get_next(const void *parent_list_entry,
						  const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_sys_type_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_sysid_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_snpa_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *lib_interface_isis_adjacencies_adjacency_hold_timer_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_neighbor_priority_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_adjacencies_adjacency_state_get_elem(const char *xpath,
							const void *list_entry);
struct yang_data *lib_interface_isis_event_counters_adjacency_changes_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *lib_interface_isis_event_counters_adjacency_number_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_event_counters_init_fails_get_elem(const char *xpath,
						      const void *list_entry);
struct yang_data *lib_interface_isis_event_counters_adjacency_rejects_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *lib_interface_isis_event_counters_id_len_mismatch_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_event_counters_max_area_addresses_mismatch_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_event_counters_authentication_type_fails_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
lib_interface_isis_event_counters_authentication_fails_get_elem(
	const char *xpath, const void *list_entry);

/* Optional 'apply_finish' callbacks. */
void ietf_backoff_delay_apply_finish(const struct lyd_node *dnode);
void area_password_apply_finish(const struct lyd_node *dnode);
void domain_password_apply_finish(const struct lyd_node *dnode);
void default_info_origin_apply_finish(const struct lyd_node *dnode, int family);
void default_info_origin_ipv4_apply_finish(const struct lyd_node *dnode);
void default_info_origin_ipv6_apply_finish(const struct lyd_node *dnode);
void redistribute_apply_finish(const struct lyd_node *dnode, int family);
void redistribute_ipv4_apply_finish(const struct lyd_node *dnode);
void redistribute_ipv6_apply_finish(const struct lyd_node *dnode);

/* Optional 'cli_show' callbacks. */
void cli_show_router_isis(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_ip_isis_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_isis_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_isis_bfd_monitoring(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_area_address(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_is_type(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_dynamic_hostname(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_attached(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_overload(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_metric_style(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_area_pwd(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_isis_domain_pwd(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_isis_lsp_gen_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_ref_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_max_lifetime(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_lsp_mtu(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_spf_min_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_spf_ietf_backoff(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_isis_purge_origin(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mpls_te(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_isis_mpls_te_router_addr(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_isis_def_origin_ipv4(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_def_origin_ipv6(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_redistribute_ipv4(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_redistribute_ipv6(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_isis_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_isis_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_isis_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_isis_passive(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_ip_isis_password(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_ip_isis_metric(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults);
void cli_show_ip_isis_hello_interval(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_hello_multi(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_isis_threeway_shake(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_hello_padding(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_csnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_psnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_isis_mt_ipv4_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ip_isis_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ip_isis_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_isis_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_isis_circ_type(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_ip_isis_network_type(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_isis_priority(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_isis_log_adjacency(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);

/* Notifications. */
void isis_notif_db_overload(const struct isis_area *area, bool overload);
void isis_notif_lsp_too_large(const struct isis_circuit *circuit,
			      uint32_t pdu_size, const char *lsp_id);
void isis_notif_if_state_change(const struct isis_circuit *circuit, bool down);
void isis_notif_corrupted_lsp(const struct isis_area *area,
			      const char *lsp_id); /* currently unused */
void isis_notif_lsp_exceed_max(const struct isis_area *area,
			       const char *lsp_id);
void isis_notif_max_area_addr_mismatch(const struct isis_circuit *circuit,
				       uint8_t max_area_addrs,
				       const char *raw_pdu);
void isis_notif_authentication_type_failure(const struct isis_circuit *circuit,
					    const char *raw_pdu);
void isis_notif_authentication_failure(const struct isis_circuit *circuit,
				       const char *raw_pdu);
void isis_notif_adj_state_change(const struct isis_adjacency *adj,
				 int new_state, const char *reason);
void isis_notif_reject_adjacency(const struct isis_circuit *circuit,
				 const char *reason, const char *raw_pdu);
void isis_notif_area_mismatch(const struct isis_circuit *circuit,
			      const char *raw_pdu);
void isis_notif_lsp_received(const struct isis_circuit *circuit,
			     const char *lsp_id, uint32_t seqno,
			     uint32_t timestamp, const char *sys_id);
void isis_notif_lsp_gen(const struct isis_area *area, const char *lsp_id,
			uint32_t seqno, uint32_t timestamp);
void isis_notif_id_len_mismatch(const struct isis_circuit *circuit,
				uint8_t rcv_id_len, const char *raw_pdu);
void isis_notif_version_skew(const struct isis_circuit *circuit,
			     uint8_t version, const char *raw_pdu);
void isis_notif_lsp_error(const struct isis_circuit *circuit,
			  const char *lsp_id, const char *raw_pdu,
			  uint32_t offset, uint8_t tlv_type);
void isis_notif_seqno_skipped(const struct isis_circuit *circuit,
			      const char *lsp_id);
void isis_notif_own_lsp_purge(const struct isis_circuit *circuit,
			      const char *lsp_id);

#endif /* ISISD_ISIS_NB_H_ */
