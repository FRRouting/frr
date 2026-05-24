// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#ifndef FRR_OSPF6_NB_H
#define FRR_OSPF6_NB_H

#include "northbound.h"

struct ospf6;

extern const struct frr_yang_module_info ospf6d_ietf_routing_info;
extern const struct frr_yang_module_info ospf6d_ietf_routing_ospf_deviation_info;
extern const struct frr_yang_module_info ospf6d_ietf_ospf_info;

/* Shared lookup: find an OSPFv3 instance by the ietf-routing instance name. */
const char *ospf6d_ietf_ospf_instance_name(const struct ospf6 *ospf6);
struct ospf6 *ospf6d_ietf_ospf_lookup_instance(const char *name);

const void *ospf6d_ietf_routing_control_plane_protocol_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_routing_control_plane_protocol_get_keys(struct nb_cb_get_keys_args *args);
const void *
ospf6d_ietf_routing_control_plane_protocol_lookup_entry(struct nb_cb_lookup_entry_args *args);

/* Config callbacks. */
int ospf6d_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_type_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_summary_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_summary_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args);

struct yang_data *ospf6d_ietf_ospf_router_id_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_statistics_originate_new_lsa_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_statistics_rx_new_lsas_count_get_elem(struct nb_cb_get_elem_args *args);
const void *ospf6d_ietf_ospf_areas_area_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args);
const void *ospf6d_ietf_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_abr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_asbr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf6d_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args);

const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_get_keys(struct nb_cb_get_keys_args *args);
const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_lookup_entry(struct nb_cb_lookup_entry_args *args);

const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args);
const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem(
	struct nb_cb_get_elem_args *args);

#endif /* FRR_OSPF6_NB_H */
