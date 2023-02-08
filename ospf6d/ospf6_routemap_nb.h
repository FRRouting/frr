// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020        Vmware
 *                           Sarita Patra
 */

#ifndef _FRR_OSPF6_ROUTEMAP_NB_H_
#define _FRR_OSPF6_ROUTEMAP_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_ospf_route_map_info;
extern const struct frr_yang_module_info frr_ospf6_route_map_info;

/* prototypes */
int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_ipv6_address_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_action_rmap_set_action_metric_type_modify(struct nb_cb_modify_args *args);
int lib_route_map_entry_set_action_rmap_set_action_metric_type_destroy(struct nb_cb_destroy_args *args);

#ifdef __cplusplus
}
#endif

#endif
