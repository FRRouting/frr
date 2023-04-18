// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#ifndef _FRR_ZEBRA_ROUTEMAP_NB_H_
#define _FRR_ZEBRA_ROUTEMAP_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

/* prototypes */
int lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv4_prefix_length_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_ipv6_prefix_length_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_instance_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_instance_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_match_condition_rmap_match_condition_source_protocol_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv4_src_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv6_src_address_destroy(struct nb_cb_destroy_args *args);

#ifdef __cplusplus
}
#endif

#endif
