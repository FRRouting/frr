// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 21 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#ifndef _FRR_OSPF_NB_H_
#define _FRR_OSPF_NB_H_

#include "northbound.h"

extern const struct frr_yang_module_info frr_ospfd_lite_info;
extern const struct frr_yang_module_info frr_ospfd_lite_cli_info;

int lib_interface_ospf_interface_create(struct nb_cb_create_args *args);
int lib_interface_ospf_interface_destroy(struct nb_cb_destroy_args *args);
const void *lib_interface_ospf_interface_get_next(struct nb_cb_get_next_args *args);
int lib_interface_ospf_interface_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_interface_ospf_interface_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *lib_interface_ospf_interface_state_state_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_ospf_interface_state_hello_timer_get_elem(struct nb_cb_get_elem_args *args);
const void *lib_interface_ospf_interface_state_neighbors_neighbor_get_next(struct nb_cb_get_next_args *args);
int lib_interface_ospf_interface_state_neighbors_neighbor_get_keys(struct nb_cb_get_keys_args *args);
const void *lib_interface_ospf_interface_state_neighbors_neighbor_lookup_entry(struct nb_cb_lookup_entry_args *args);

struct yang_data *lib_interface_ospf_interface_state_neighbors_neighbor_get_elem(struct nb_cb_get_elem_args *args);

struct yang_data *lib_interface_ospf_interface_state_neighbors_neighbor_neighbor_router_id_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_ospf_interface_state_neighbors_neighbor_address_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *lib_interface_ospf_interface_state_neighbors_neighbor_state_get_elem(struct nb_cb_get_elem_args *args);

int ospf_instance_create(struct nb_cb_create_args *args);
int ospf_instance_destroy(struct nb_cb_destroy_args *args);
const void *ospf_instance_get_next(struct nb_cb_get_next_args *args);
int ospf_instance_get_keys(struct nb_cb_get_keys_args *args);
const void *ospf_instance_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *ospf_instance_state_router_flags_router_flag_get_elem(struct nb_cb_get_elem_args *args);
const void *ospf_instance_state_router_flags_router_flag_get_next(struct nb_cb_get_next_args *args);
struct yang_data *ospf_instance_state_statistics_originate_new_lsa_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_state_statistics_rx_new_lsas_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_state_statistics_spf_timestamp_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_state_statistics_spf_duration_get_elem(struct nb_cb_get_elem_args *args);
int ospf_instance_areas_area_create(struct nb_cb_create_args *args);
int ospf_instance_areas_area_destroy(struct nb_cb_destroy_args *args);
const void *ospf_instance_areas_area_get_next(struct nb_cb_get_next_args *args);
int ospf_instance_areas_area_get_keys(struct nb_cb_get_keys_args *args);
const void *ospf_instance_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_spf_runs_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_abr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_asbr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_area_scope_lsa_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_spf_timestamp_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_active_interfaces_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_full_nbrs_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf_instance_areas_area_state_statistics_full_virtual_get_elem(struct nb_cb_get_elem_args *args);

#ifdef __cplusplus
}
#endif

#endif
