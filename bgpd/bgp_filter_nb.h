// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Filter Northbound Header
 * Copyright (C) 2024 FRRouting
 */

#ifndef _FRR_BGP_FILTER_NB_H_
#define _FRR_BGP_FILTER_NB_H_

#include "northbound.h"

extern const struct frr_yang_module_info frr_bgp_filter_info;

/* community-list */
int lib_community_list_create(struct nb_cb_create_args *args);
int lib_community_list_destroy(struct nb_cb_destroy_args *args);
int lib_community_list_entry_create(struct nb_cb_create_args *args);
int lib_community_list_entry_destroy(struct nb_cb_destroy_args *args);
int lib_community_list_entry_action_modify(struct nb_cb_modify_args *args);
int lib_community_list_entry_action_destroy(struct nb_cb_destroy_args *args);
int lib_community_list_entry_type_modify(struct nb_cb_modify_args *args);
int lib_community_list_entry_standard_community_string_create(struct nb_cb_create_args *args);
int lib_community_list_entry_standard_community_string_destroy(struct nb_cb_destroy_args *args);
int lib_community_list_entry_expanded_community_string_modify(struct nb_cb_modify_args *args);
int lib_community_list_entry_expanded_community_string_destroy(struct nb_cb_destroy_args *args);

/* large-community-list */
int lib_large_community_list_create(struct nb_cb_create_args *args);
int lib_large_community_list_destroy(struct nb_cb_destroy_args *args);
int lib_large_community_list_entry_create(struct nb_cb_create_args *args);
int lib_large_community_list_entry_destroy(struct nb_cb_destroy_args *args);
int lib_large_community_list_entry_action_modify(struct nb_cb_modify_args *args);
int lib_large_community_list_entry_action_destroy(struct nb_cb_destroy_args *args);
int lib_large_community_list_entry_type_modify(struct nb_cb_modify_args *args);
int lib_large_community_list_entry_standard_large_community_string_create(
	struct nb_cb_create_args *args);
int lib_large_community_list_entry_standard_large_community_string_destroy(
	struct nb_cb_destroy_args *args);
int lib_large_community_list_entry_expanded_large_community_string_modify(
	struct nb_cb_modify_args *args);
int lib_large_community_list_entry_expanded_large_community_string_destroy(
	struct nb_cb_destroy_args *args);

/* extcommunity-list */
int lib_extcommunity_list_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_entry_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_action_modify(struct nb_cb_modify_args *args);
int lib_extcommunity_list_entry_action_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_type_modify(struct nb_cb_modify_args *args);
int lib_extcommunity_list_entry_rt_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_entry_rt_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_soo_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_entry_soo_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_nt_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_entry_nt_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_color_create(struct nb_cb_create_args *args);
int lib_extcommunity_list_entry_color_destroy(struct nb_cb_destroy_args *args);
int lib_extcommunity_list_entry_expanded_extcommunity_string_modify(struct nb_cb_modify_args *args);
int lib_extcommunity_list_entry_expanded_extcommunity_string_destroy(
	struct nb_cb_destroy_args *args);

/* as-path-list */
int lib_as_path_list_create(struct nb_cb_create_args *args);
int lib_as_path_list_destroy(struct nb_cb_destroy_args *args);
int lib_as_path_list_entry_create(struct nb_cb_create_args *args);
int lib_as_path_list_entry_destroy(struct nb_cb_destroy_args *args);
int lib_as_path_list_entry_action_modify(struct nb_cb_modify_args *args);
int lib_as_path_list_entry_action_destroy(struct nb_cb_destroy_args *args);
int lib_as_path_list_entry_as_path_modify(struct nb_cb_modify_args *args);
int lib_as_path_list_entry_as_path_destroy(struct nb_cb_destroy_args *args);

#endif /* _FRR_BGP_FILTER_NB_H_ */
