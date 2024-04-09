/* Triggered SRTE config
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PATHD_PATH_TSRTE_H
#define _PATHD_PATH_TSRTE_H

#include "zebra.h"
#include "stream.h"
#include "zclient.h"

extern const struct frr_yang_module_info frr_pathd_triggered_srte_info;

/* cli initialisation */
extern void path_tsrte_cli_init(void);

/* zebra part */
int path_zebra_handle_tsrte_bgp_ready(struct zclient *zclient,
				      struct stream *s);
int path_zebra_send_te_ready(enum srte_protocol_origin protocol_origin);

int path_zebra_handle_triggered_te_register(struct stream *s,
					    uint32_t type);
void path_zebra_srte_bgp_policy_candidate_changed(
	struct srte_policy *policy, struct srte_candidate *candidate);

/* triggered srte northbound configuration */
int pathd_srte_policy_template_create(struct nb_cb_create_args *args);
int pathd_srte_policy_template_destroy(struct nb_cb_destroy_args *args);
const void *
pathd_srte_policy_template_get_next(struct nb_cb_get_next_args *args);
int pathd_srte_policy_template_get_keys(struct nb_cb_get_keys_args *args);
const void *
pathd_srte_policy_template_lookup_entry(struct nb_cb_lookup_entry_args *args);
int pathd_srte_policy_template_name_modify(struct nb_cb_modify_args *args);
int pathd_srte_policy_template_name_destroy(struct nb_cb_destroy_args *args);
int pathd_srte_policy_template_candidate_path_create(
	struct nb_cb_create_args *args);
int pathd_srte_policy_template_candidate_path_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_template_candidate_path_name_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_template_candidate_path_protocol_origin_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_template_candidate_path_originator_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_template_candidate_path_type_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_template_candidate_path_flex_algo_number_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_template_candidate_path_flex_algo_number_destroy(
	struct nb_cb_destroy_args *args);
int pathd_srte_policy_label_blocks_pre_validate(
	struct nb_cb_pre_validate_args *args);
void pathd_srte_policy_label_blocks_apply_finish(
	struct nb_cb_apply_finish_args *args);
void cli_show_pathd_srte_policy_label_blocks(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults);
int pathd_srte_policy_label_blocks_template_upper_bound_modify(
	struct nb_cb_modify_args *args);
int pathd_srte_policy_label_blocks_template_lower_bound_modify(
	struct nb_cb_modify_args *args);
void cli_show_srte_policy_template(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_srte_policy_template_name(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
void cli_show_srte_policy_template_candidate_path(struct vty *vty,
						  const struct lyd_node *dnode,
						  bool show_defaults);
const void *pathd_srte_policy_template_candidate_path_get_next(
	struct nb_cb_get_next_args *args);
int pathd_srte_policy_template_candidate_path_get_keys(
	struct nb_cb_get_keys_args *args);
const void *pathd_srte_policy_template_candidate_path_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
#endif /* _PATHD_PATH_TSRTE_H */
