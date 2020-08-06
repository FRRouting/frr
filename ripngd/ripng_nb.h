/*
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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

#ifndef _FRR_RIPNG_NB_H_
#define _FRR_RIPNG_NB_H_

extern const struct frr_yang_module_info frr_ripngd_info;

/* Mandatory callbacks. */
int ripngd_instance_create(struct nb_cb_create_args *args);
int ripngd_instance_destroy(struct nb_cb_destroy_args *args);
const void *ripngd_instance_get_next(struct nb_cb_get_next_args *args);
int ripngd_instance_get_keys(struct nb_cb_get_keys_args *args);
const void *ripngd_instance_lookup_entry(struct nb_cb_lookup_entry_args *args);
int ripngd_instance_allow_ecmp_modify(struct nb_cb_modify_args *args);
int ripngd_instance_default_information_originate_modify(
	struct nb_cb_modify_args *args);
int ripngd_instance_default_metric_modify(struct nb_cb_modify_args *args);
int ripngd_instance_network_create(struct nb_cb_create_args *args);
int ripngd_instance_network_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_interface_create(struct nb_cb_create_args *args);
int ripngd_instance_interface_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_offset_list_create(struct nb_cb_create_args *args);
int ripngd_instance_offset_list_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_offset_list_access_list_modify(
	struct nb_cb_modify_args *args);
int ripngd_instance_offset_list_metric_modify(struct nb_cb_modify_args *args);
int ripngd_instance_passive_interface_create(struct nb_cb_create_args *args);
int ripngd_instance_passive_interface_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_redistribute_create(struct nb_cb_create_args *args);
int ripngd_instance_redistribute_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_redistribute_route_map_modify(
	struct nb_cb_modify_args *args);
int ripngd_instance_redistribute_route_map_destroy(
	struct nb_cb_destroy_args *args);
int ripngd_instance_redistribute_metric_modify(struct nb_cb_modify_args *args);
int ripngd_instance_redistribute_metric_destroy(
	struct nb_cb_destroy_args *args);
int ripngd_instance_static_route_create(struct nb_cb_create_args *args);
int ripngd_instance_static_route_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_aggregate_address_create(struct nb_cb_create_args *args);
int ripngd_instance_aggregate_address_destroy(struct nb_cb_destroy_args *args);
int ripngd_instance_timers_flush_interval_modify(
	struct nb_cb_modify_args *args);
int ripngd_instance_timers_holddown_interval_modify(
	struct nb_cb_modify_args *args);
int ripngd_instance_timers_update_interval_modify(
	struct nb_cb_modify_args *args);
const void *ripngd_instance_state_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args);
int ripngd_instance_state_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args);
const void *ripngd_instance_state_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *ripngd_instance_state_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripngd_instance_state_neighbors_neighbor_last_update_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	struct nb_cb_get_elem_args *args);
const void *
ripngd_instance_state_routes_route_get_next(struct nb_cb_get_next_args *args);
int ripngd_instance_state_routes_route_get_keys(
	struct nb_cb_get_keys_args *args);
const void *ripngd_instance_state_routes_route_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *ripngd_instance_state_routes_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripngd_instance_state_routes_route_next_hop_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripngd_instance_state_routes_route_interface_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *ripngd_instance_state_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args);
int clear_ripng_route_rpc(struct nb_cb_rpc_args *args);
int lib_interface_ripng_split_horizon_modify(struct nb_cb_modify_args *args);

/* Optional 'apply_finish' callbacks. */
void ripngd_instance_redistribute_apply_finish(
	struct nb_cb_apply_finish_args *args);
void ripngd_instance_timers_apply_finish(struct nb_cb_apply_finish_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_router_ripng(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ripng_allow_ecmp(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_ripng_default_information_originate(struct vty *vty,
						  struct lyd_node *dnode,
						  bool show_defaults);
void cli_show_ripng_default_metric(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ripng_network_prefix(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ripng_network_interface(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ripng_offset_list(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_ripng_passive_interface(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ripng_redistribute(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);
void cli_show_ripng_route(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_ripng_aggregate_address(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ripng_timers(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ipv6_ripng_split_horizon(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults);

#endif /* _FRR_RIPNG_NB_H_ */
