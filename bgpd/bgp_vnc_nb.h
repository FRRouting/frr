// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP VNC/RFAPI northbound
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_VNC_NB_H_
#define _FRR_BGP_VNC_NB_H_

#include "northbound.h"

#if ENABLE_BGP_VNC

extern const struct frr_yang_module_info frr_bgp_vnc_info;

int bgp_global_vnc_create(struct nb_cb_create_args *args);
int bgp_global_vnc_rfp_holddown_factor_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_rfp_full_table_download_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_defaults_create(struct nb_cb_create_args *args);
int bgp_global_vnc_defaults_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_defaults_rd_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_defaults_response_lifetime_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_defaults_rt_import_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_defaults_rt_export_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_create(struct nb_cb_create_args *args);
int bgp_global_vnc_nve_group_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_group_prefix_vn_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_prefix_un_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_rd_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_response_lifetime_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_rt_import_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_rt_export_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_policy_create(struct nb_cb_create_args *args);
int bgp_global_vnc_vrf_policy_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_vrf_policy_label_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_policy_label_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_vrf_policy_rd_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_policy_rt_import_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_policy_rt_export_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_policy_nexthop_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_bgp_mode_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_bgp_group_nve_group_create(struct nb_cb_create_args *args);
int bgp_global_vnc_export_bgp_group_nve_group_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_zebra_mode_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_zebra_mode_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_zebra_group_nve_group_create(struct nb_cb_create_args *args);
int bgp_global_vnc_export_zebra_group_nve_group_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_mode_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redistribute_ipv4_source_create(struct nb_cb_create_args *args);
int bgp_global_vnc_redistribute_ipv4_source_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_ipv6_source_create(struct nb_cb_create_args *args);
int bgp_global_vnc_redistribute_ipv6_source_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_nve_group_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redistribute_nve_group_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_lifetime_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redistribute_lifetime_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_resolve_nve_roo_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redistribute_resolve_nve_roo_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redistribute_exterior_view_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redistribute_exterior_view_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_redist_bgp_direct_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redist_bgp_direct_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redist_bgp_direct_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_redist_bgp_direct_ext_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_export_bgp_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_bgp_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_bgp_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_bgp_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_zebra_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_zebra_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_zebra_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_zebra_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_bgp_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_bgp_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_export_zebra_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_export_zebra_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_nve_redist_bgp_direct_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_redist_bgp_direct_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_redist_bgp_direct_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_redist_bgp_direct_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_redist_bgp_direct_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_redist_bgp_direct_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_bgp_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_bgp_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_bgp_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_bgp_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_zebra_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_zebra_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_zebra_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_zebra_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_bgp_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_bgp_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_export_zebra_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_export_zebra_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_vrf_export_ipv4_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_export_ipv4_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_vrf_export_ipv6_plist_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_export_ipv6_plist_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_vrf_export_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_vrf_export_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_advertise_un_method_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_advertise_un_method_destroy(struct nb_cb_destroy_args *args);
void vnc_advertise_un_method_cli_show(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_global_vnc_defaults_l2rd_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_defaults_l2rd_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_nve_group_l2rd_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_nve_group_l2rd_destroy(struct nb_cb_destroy_args *args);

int bgp_global_vnc_l2_group_create(struct nb_cb_create_args *args);
int bgp_global_vnc_l2_group_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_l2_group_logical_network_id_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_l2_group_labels_create(struct nb_cb_create_args *args);
int bgp_global_vnc_l2_group_labels_destroy(struct nb_cb_destroy_args *args);
int bgp_global_vnc_l2_group_rt_import_modify(struct nb_cb_modify_args *args);
int bgp_global_vnc_l2_group_rt_export_modify(struct nb_cb_modify_args *args);
void vnc_l2_group_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_l2_group_cli_show_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_global_vnc_noop_destroy(struct nb_cb_destroy_args *args);

void vnc_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_rfp_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_defaults_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_defaults_cli_show_end(struct vty *vty, const struct lyd_node *dnode);
void vnc_nve_group_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_nve_group_cli_show_end(struct vty *vty, const struct lyd_node *dnode);
void vnc_vrf_policy_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_vrf_policy_cli_show_end(struct vty *vty, const struct lyd_node *dnode);
void vnc_export_bgp_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_export_zebra_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void vnc_redistribute_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

void bgp_vnc_cli_init(void);

#endif /* ENABLE_BGP_VNC */

#endif /* _FRR_BGP_VNC_NB_H_ */
