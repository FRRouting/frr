// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#ifndef _FRR_PATH_NB_H_
#define _FRR_PATH_NB_H_

#include "pathd/pathd.h"

extern const struct frr_yang_module_info frr_pathd_info;

/* Mandatory callbacks. */
int pathd_srte_segment_list_create(struct nb_cb_create_args *args);
int pathd_srte_segment_list_destroy(struct nb_cb_destroy_args *args);

const void *pathd_srte_segment_list_get_next(struct nb_cb_get_next_args *args);
int pathd_srte_segment_list_get_keys(struct nb_cb_get_keys_args *args);
const void *
pathd_srte_segment_list_lookup_entry(struct nb_cb_lookup_entry_args *args);

int pathd_srte_segment_list_segment_create(struct nb_cb_create_args *args);
int pathd_srte_segment_list_segment_destroy(struct nb_cb_destroy_args *args);
int pathd_srte_segment_list_protocol_origin_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_segment_list_originator_modify(struct nb_cb_modify_args *args);
int pathd_srte_segment_list_segment_sid_value_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_segment_list_segment_nai_destroy(
	struct nb_cb_destroy_args *args);
void pathd_srte_segment_list_segment_nai_apply_finish(
	struct nb_cb_apply_finish_args *args);
int pathd_srte_segment_list_segment_sid_value_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_create(struct nb_cb_create_args *args);
int pathd_srte_policy_destroy(struct nb_cb_destroy_args *args);
const void *pathd_srte_policy_get_next(struct nb_cb_get_next_args *args);
int pathd_srte_policy_get_keys(struct nb_cb_get_keys_args *args);
const void *
pathd_srte_policy_lookup_entry(struct nb_cb_lookup_entry_args *args);
int pathd_srte_policy_name_modify(struct nb_cb_modify_args *args);
int pathd_srte_policy_name_destroy(struct nb_cb_destroy_args *args);
int pathd_srte_policy_binding_sid_modify(struct nb_cb_modify_args *args);
int pathd_srte_policy_binding_sid_destroy(struct nb_cb_destroy_args *args);
struct yang_data *
pathd_srte_policy_is_operational_get_elem(struct nb_cb_get_elem_args *args);
int pathd_srte_policy_candidate_path_create(struct nb_cb_create_args *args);
int pathd_srte_policy_candidate_path_destroy(struct nb_cb_destroy_args *args);
int pathd_srte_policy_candidate_path_name_modify(
	struct nb_cb_modify_args *args);
const void *
pathd_srte_policy_candidate_path_get_next(struct nb_cb_get_next_args *args);
int pathd_srte_policy_candidate_path_get_keys(struct nb_cb_get_keys_args *args);
const void *pathd_srte_policy_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
void pathd_srte_policy_candidate_path_bandwidth_apply_finish(
	struct nb_cb_apply_finish_args *args);
int pathd_srte_policy_candidate_path_bandwidth_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_candidate_path_exclude_any_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_exclude_any_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_candidate_path_include_any_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_include_any_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_candidate_path_include_all_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_include_all_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_candidate_path_metrics_destroy(
	struct nb_cb_destroy_args *args);
void pathd_srte_policy_candidate_path_metrics_apply_finish(
	struct nb_cb_apply_finish_args *args);
int pathd_srte_policy_candidate_path_objfun_destroy(
	struct nb_cb_destroy_args *args);
void pathd_srte_policy_candidate_path_objfun_apply_finish(
	struct nb_cb_apply_finish_args *args);
struct yang_data *
pathd_srte_policy_candidate_path_is_best_candidate_path_get_elem(
	struct nb_cb_get_elem_args *args);
int pathd_srte_policy_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_originator_modify(
	struct nb_cb_modify_args *args);
struct yang_data *pathd_srte_policy_candidate_path_discriminator_get_elem(
	struct nb_cb_get_elem_args *args);
int pathd_srte_policy_candidate_path_type_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_segment_list_name_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_candidate_path_segment_list_name_destroy(
	struct nb_cb_destroy_args *args);

/* Optional 'apply_finish' callbacks. */
void pathd_apply_finish(struct nb_cb_apply_finish_args *args);

/* Optional 'cli_show' callbacks. */
void cli_show_srte_segment_list(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
void cli_show_srte_segment_list_end(struct vty *vty,
				    const struct lyd_node *dnode);
void cli_show_srte_segment_list_segment(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_srte_policy(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_srte_policy_end(struct vty *vty, const struct lyd_node *dnode);
void cli_show_srte_policy_name(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_srte_policy_binding_sid(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_srte_policy_candidate_path(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults);
void cli_show_srte_policy_candidate_path_end(struct vty *vty,
					     const struct lyd_node *dnode);

/* Utility functions */
typedef void (*of_pref_cp_t)(enum objfun_type type, void *arg);
void iter_objfun_prefs(const struct lyd_node *dnode, const char *path,
		       of_pref_cp_t fun, void *arg);

#endif /* _FRR_PATH_NB_H_ */
