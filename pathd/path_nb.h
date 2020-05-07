/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#ifndef _FRR_PATH_NB_H_
#define _FRR_PATH_NB_H_

extern const struct frr_yang_module_info frr_pathd_info;

/* Mandatory callbacks. */
int pathd_te_segment_list_create(struct nb_cb_create_args *args);
int pathd_te_segment_list_destroy(struct nb_cb_destroy_args *args);

const void *pathd_te_segment_list_get_next(struct nb_cb_get_next_args *args);
int pathd_te_segment_list_get_keys(struct nb_cb_get_keys_args *args);
const void *
pathd_te_segment_list_lookup_entry(struct nb_cb_lookup_entry_args *args);

int pathd_te_segment_list_segment_create(struct nb_cb_create_args *args);
int pathd_te_segment_list_segment_destroy(struct nb_cb_destroy_args *args);
int pathd_te_segment_list_protocol_origin_modify(
	struct nb_cb_modify_args *args);
int pathd_te_segment_list_originator_modify(struct nb_cb_modify_args *args);
int pathd_te_segment_list_segment_sid_value_modify(
	struct nb_cb_modify_args *args);
int pathd_te_segment_list_segment_nai_destroy(struct nb_cb_destroy_args *args);
void pathd_te_segment_list_segment_nai_apply_finish(
	struct nb_cb_apply_finish_args *args);
int pathd_te_sr_policy_create(struct nb_cb_create_args *args);
int pathd_te_sr_policy_destroy(struct nb_cb_destroy_args *args);
const void *pathd_te_sr_policy_get_next(struct nb_cb_get_next_args *args);
int pathd_te_sr_policy_get_keys(struct nb_cb_get_keys_args *args);
const void *pathd_te_sr_policy_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
int pathd_te_sr_policy_name_modify(struct nb_cb_modify_args *args);
int pathd_te_sr_policy_name_destroy(struct nb_cb_destroy_args *args);
int pathd_te_sr_policy_binding_sid_modify(struct nb_cb_modify_args *args);
int pathd_te_sr_policy_binding_sid_destroy(struct nb_cb_destroy_args *args);
struct yang_data *
pathd_te_sr_policy_is_operational_get_elem(struct nb_cb_get_elem_args *args);
int pathd_te_sr_policy_candidate_path_create(struct nb_cb_create_args *args);
int pathd_te_sr_policy_candidate_path_destroy(struct nb_cb_destroy_args *args);
int pathd_te_sr_policy_candidate_path_name_modify(
	struct nb_cb_modify_args *args);
const void *
pathd_te_sr_policy_candidate_path_get_next(struct nb_cb_get_next_args *args);
int pathd_te_sr_policy_candidate_path_get_keys(
	struct nb_cb_get_keys_args *args);
const void *pathd_te_sr_policy_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
int pathd_te_sr_policy_candidate_path_metrics_destroy(
	struct nb_cb_destroy_args *args);
void pathd_te_sr_policy_candidate_path_metrics_apply_finish(
	struct nb_cb_apply_finish_args *args);
struct yang_data *
pathd_te_sr_policy_candidate_path_is_best_candidate_path_get_elem(
	struct nb_cb_get_elem_args *args);
int pathd_te_sr_policy_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_originator_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_discriminator_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_type_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_segment_list_name_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_segment_list_name_destroy(
	struct nb_cb_destroy_args *args);
int pathd_te_sr_policy_candidate_path_bandwidth_modify(
	struct nb_cb_modify_args *args);
int pathd_te_sr_policy_candidate_path_bandwidth_destroy(
	struct nb_cb_destroy_args *args);

/* Optional 'apply_finish' callbacks. */
void pathd_apply_finish(struct nb_cb_apply_finish_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_te_path_segment_list(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_te_path_segment_list_segment(struct vty *vty,
					   struct lyd_node *dnode,
					   bool show_defaults);
void cli_show_te_path_sr_policy(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_te_path_sr_policy_name(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_te_path_sr_policy_binding_sid(struct vty *vty,
					    struct lyd_node *dnode,
					    bool show_defaults);
void cli_show_te_path_sr_policy_candidate_path(struct vty *vty,
					       struct lyd_node *dnode,
					       bool show_defaults);

#endif /* _FRR_PATH_NB_H_ */
