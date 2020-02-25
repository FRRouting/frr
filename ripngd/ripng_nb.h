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
int ripngd_instance_create(enum nb_event event, const struct lyd_node *dnode,
			   union nb_resource *resource);
int ripngd_instance_destroy(enum nb_event event, const struct lyd_node *dnode);
const void *ripngd_instance_get_next(const void *parent_list_entry,
				     const void *list_entry);
int ripngd_instance_get_keys(const void *list_entry,
			     struct yang_list_keys *keys);
const void *ripngd_instance_lookup_entry(const void *parent_list_entry,
					 const struct yang_list_keys *keys);
int ripngd_instance_allow_ecmp_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int ripngd_instance_default_information_originate_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int ripngd_instance_default_metric_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int ripngd_instance_network_create(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource);
int ripngd_instance_network_destroy(enum nb_event event,
				    const struct lyd_node *dnode);
int ripngd_instance_interface_create(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource);
int ripngd_instance_interface_destroy(enum nb_event event,
				      const struct lyd_node *dnode);
int ripngd_instance_offset_list_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource);
int ripngd_instance_offset_list_destroy(enum nb_event event,
					const struct lyd_node *dnode);
int ripngd_instance_offset_list_access_list_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource);
int ripngd_instance_offset_list_metric_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource);
int ripngd_instance_passive_interface_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int ripngd_instance_passive_interface_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int ripngd_instance_redistribute_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int ripngd_instance_redistribute_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int ripngd_instance_redistribute_route_map_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int ripngd_instance_redistribute_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int ripngd_instance_redistribute_metric_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource);
int ripngd_instance_redistribute_metric_destroy(enum nb_event event,
						const struct lyd_node *dnode);
int ripngd_instance_static_route_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int ripngd_instance_static_route_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int ripngd_instance_aggregate_address_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int ripngd_instance_aggregate_address_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int ripngd_instance_timers_flush_interval_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource);
int ripngd_instance_timers_holddown_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int ripngd_instance_timers_update_interval_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
const void *
ripngd_instance_state_neighbors_neighbor_get_next(const void *parent_list_entry,
						  const void *list_entry);
int ripngd_instance_state_neighbors_neighbor_get_keys(
	const void *list_entry, struct yang_list_keys *keys);
const void *ripngd_instance_state_neighbors_neighbor_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *ripngd_instance_state_neighbors_neighbor_address_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *ripngd_instance_state_neighbors_neighbor_last_update_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	const char *xpath, const void *list_entry);
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	const char *xpath, const void *list_entry);
const void *
ripngd_instance_state_routes_route_get_next(const void *parent_list_entry,
					    const void *list_entry);
int ripngd_instance_state_routes_route_get_keys(const void *list_entry,
						struct yang_list_keys *keys);
const void *ripngd_instance_state_routes_route_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys);
struct yang_data *
ripngd_instance_state_routes_route_prefix_get_elem(const char *xpath,
						   const void *list_entry);
struct yang_data *
ripngd_instance_state_routes_route_next_hop_get_elem(const char *xpath,
						     const void *list_entry);
struct yang_data *
ripngd_instance_state_routes_route_interface_get_elem(const char *xpath,
						      const void *list_entry);
struct yang_data *
ripngd_instance_state_routes_route_metric_get_elem(const char *xpath,
						   const void *list_entry);
int clear_ripng_route_rpc(const char *xpath, const struct list *input,
			  struct list *output);
int lib_interface_ripng_split_horizon_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);

/* Optional 'apply_finish' callbacks. */
void ripngd_instance_redistribute_apply_finish(const struct lyd_node *dnode);
void ripngd_instance_timers_apply_finish(const struct lyd_node *dnode);

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
