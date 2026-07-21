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

void bgp_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_H_ */
