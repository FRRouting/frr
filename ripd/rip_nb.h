// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#ifndef _FRR_RIP_NB_H_
#define _FRR_RIP_NB_H_

#include "northbound.h"

extern const struct frr_yang_module_info frr_ripd_info;
extern const struct frr_yang_module_info frr_ripd_cli_info;

/* Mandatory callbacks. */
int ripd_instance_create(struct nb_cb_create_args *args);
int ripd_instance_destroy(struct nb_cb_destroy_args *args);
const void *ripd_instance_get_next(struct nb_cb_get_next_args *args);
int ripd_instance_get_keys(struct nb_cb_get_keys_args *args);
const void *ripd_instance_lookup_entry(struct nb_cb_lookup_entry_args *args);
int ripd_instance_allow_ecmp_modify(struct nb_cb_modify_args *args);
int ripd_instance_default_information_originate_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_default_metric_modify(struct nb_cb_modify_args *args);
int ripd_instance_distance_default_modify(struct nb_cb_modify_args *args);
int ripd_instance_distance_source_create(struct nb_cb_create_args *args);
int ripd_instance_distance_source_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_distance_source_distance_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_distance_source_access_list_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_distance_source_access_list_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_explicit_neighbor_create(struct nb_cb_create_args *args);
int ripd_instance_explicit_neighbor_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_network_create(struct nb_cb_create_args *args);
int ripd_instance_network_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_interface_create(struct nb_cb_create_args *args);
int ripd_instance_interface_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_offset_list_create(struct nb_cb_create_args *args);
int ripd_instance_offset_list_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_offset_list_access_list_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_offset_list_metric_modify(struct nb_cb_modify_args *args);
int ripd_instance_passive_default_modify(struct nb_cb_modify_args *args);
int ripd_instance_passive_interface_create(struct nb_cb_create_args *args);
int ripd_instance_passive_interface_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_non_passive_interface_create(struct nb_cb_create_args *args);
int ripd_instance_non_passive_interface_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_distribute_list_create(struct nb_cb_create_args *args);
int ripd_instance_distribute_list_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_redistribute_create(struct nb_cb_create_args *args);
int ripd_instance_redistribute_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_redistribute_route_map_modify(struct nb_cb_modify_args *args);
int ripd_instance_redistribute_route_map_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_redistribute_metric_modify(struct nb_cb_modify_args *args);
int ripd_instance_redistribute_metric_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_if_route_maps_if_route_map_create(
	struct nb_cb_create_args *args);
int ripd_instance_if_route_maps_if_route_map_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_if_route_maps_if_route_map_in_route_map_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_if_route_maps_if_route_map_in_route_map_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_if_route_maps_if_route_map_out_route_map_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_if_route_maps_if_route_map_out_route_map_destroy(
	struct nb_cb_destroy_args *args);
int ripd_instance_static_route_create(struct nb_cb_create_args *args);
int ripd_instance_static_route_destroy(struct nb_cb_destroy_args *args);
int ripd_instance_timers_flush_interval_modify(struct nb_cb_modify_args *args);
int ripd_instance_timers_holddown_interval_modify(
	struct nb_cb_modify_args *args);
int ripd_instance_timers_update_interval_modify(struct nb_cb_modify_args *args);
int ripd_instance_version_receive_modify(struct nb_cb_modify_args *args);
int ripd_instance_version_send_modify(struct nb_cb_modify_args *args);
int ripd_instance_default_bfd_profile_modify(struct nb_cb_modify_args *args);
int ripd_instance_default_bfd_profile_destroy(struct nb_cb_destroy_args *args);
const void *ripd_instance_state_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args);
int ripd_instance_state_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args);
const void *ripd_instance_state_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *ripd_instance_state_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripd_instance_state_neighbors_neighbor_last_update_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
ripd_instance_state_routes_route_get_next(struct nb_cb_get_next_args *args);
int ripd_instance_state_routes_route_get_keys(struct nb_cb_get_keys_args *args);
const void *ripd_instance_state_routes_route_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *ripd_instance_state_routes_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripd_instance_state_routes_route_next_hop_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripd_instance_state_routes_route_interface_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripd_instance_state_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args);
const void *ripd_instance_state_routes_route_nexthops_nexthop_get_next(
	struct nb_cb_get_next_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_nh_type_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_protocol_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_rip_type_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_gateway_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_interface_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_from_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_tag_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_external_metric_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_expire_time_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripd_instance_state_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args);
int clear_rip_route_rpc(struct nb_cb_rpc_args *args);
int lib_interface_rip_split_horizon_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_v2_broadcast_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_version_receive_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_version_send_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_authentication_scheme_mode_modify(
	struct nb_cb_modify_args *args);
int lib_interface_rip_authentication_scheme_md5_auth_length_modify(
	struct nb_cb_modify_args *args);
int lib_interface_rip_authentication_scheme_md5_auth_length_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_rip_authentication_password_modify(
	struct nb_cb_modify_args *args);
int lib_interface_rip_authentication_password_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_rip_authentication_key_chain_modify(
	struct nb_cb_modify_args *args);
int lib_interface_rip_authentication_key_chain_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_rip_bfd_create(struct nb_cb_create_args *args);
int lib_interface_rip_bfd_destroy(struct nb_cb_destroy_args *args);
int lib_interface_rip_bfd_enable_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_bfd_enable_destroy(struct nb_cb_destroy_args *args);
int lib_interface_rip_bfd_profile_modify(struct nb_cb_modify_args *args);
int lib_interface_rip_bfd_profile_destroy(struct nb_cb_destroy_args *args);

/* Optional 'apply_finish' callbacks. */
void ripd_instance_redistribute_apply_finish(
	struct nb_cb_apply_finish_args *args);
void ripd_instance_timers_apply_finish(struct nb_cb_apply_finish_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_router_rip(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults);
void cli_show_end_router_rip(struct vty *vty, const struct lyd_node *dnode);
void cli_show_rip_allow_ecmp(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults);
void cli_show_rip_default_information_originate(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults);
void cli_show_rip_default_metric(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_rip_distance(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rip_distance_source(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_rip_neighbor(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rip_network_prefix(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_rip_network_interface(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rip_offset_list(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_rip_passive_default(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_rip_passive_interface(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rip_non_passive_interface(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_rip_redistribute(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_rip_route(struct vty *vty, const struct lyd_node *dnode,
			bool show_defaults);
void cli_show_rip_timers(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults);
void cli_show_rip_version(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_ip_rip_split_horizon(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_rip_v2_broadcast(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_rip_receive_version(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_rip_send_version(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ripd_instance_default_bfd_profile(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults);
void cli_show_ip_rip_authentication_scheme(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_ip_rip_authentication_string(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_ip_rip_authentication_key_chain(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults);
void cli_show_ip_rip_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_ip_rip_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);

/* Notifications. */
extern void ripd_notif_send_auth_type_failure(const char *ifname);
extern void ripd_notif_send_auth_failure(const char *ifname);

extern void rip_cli_init(void);

#endif /* _FRR_RIP_NB_H_ */
