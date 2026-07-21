// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound API
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_NB_H_
#define _FRR_BGP_NB_H_

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_info;

/* Instance create/destroy */
int bgp_nb_bgp_create(struct nb_cb_create_args *args);
int bgp_nb_bgp_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_routing_destroy(struct nb_cb_destroy_args *args);

void bgp_nb_cli_show_router_bgp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_router_bgp_end(struct vty *vty, const struct lyd_node *dnode);

/* Global leaves */
int bgp_nb_local_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_router_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_router_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_instance_type_view_modify(struct nb_cb_modify_args *args);
int bgp_nb_as_notation_modify(struct nb_cb_modify_args *args);

int bgp_nb_log_neighbor_changes_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_log_neighbor_changes(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_ebgp_requires_policy(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_import_check_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_import_check(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);


int bgp_nb_cluster_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_cluster_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_cluster_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_no_client_reflect_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_no_client_reflect(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_always_compare_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_always_compare_med(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_deterministic_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_deterministic_med(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_local_pref_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_local_pref(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_fast_external_failover_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_fast_external_failover(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_suppress_duplicates_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_suppress_duplicates(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

int bgp_nb_graceful_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_reject_as_sets_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_reject_as_sets(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_enforce_first_as_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_connected_route_check_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_connected_route_check(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_allow_outbound_policy_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_allow_outbound_policy(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_hard_admin_reset_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_hard_admin_reset(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_show_hostname_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_show_hostname(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_show_nexthop_hostname(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_external_compare_router_id_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_external_compare_router_id(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

int bgp_nb_ignore_as_path_length_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_ignore_as_path_length(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_compare_aigp_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_compare_aigp(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_use_imported_attributes_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_use_imported_attributes(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_aspath_confed_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_aspath_confed(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_allow_multiple_as_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_allow_multiple_as(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_multi_path_as_set_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_multi_path_as_set(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_type_multipath_relax(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_confed_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_confed_med(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_missing_as_worst_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_missing_as_worst_med(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_bandwidth_handling_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_bandwidth_handling(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

void bgp_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_H_ */
