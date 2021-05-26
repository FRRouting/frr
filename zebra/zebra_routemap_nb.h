/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
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
