/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _FRR_STATIC_NB_H_
#define _FRR_STATIC_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_staticd_info;

/* Mandatory callbacks. */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_tag_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	struct nb_cb_destroy_args *args);
int route_next_hop_bfd_create(struct nb_cb_create_args *args);
int route_next_hop_bfd_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_source_modify(struct nb_cb_modify_args *args);
int route_next_hop_bfd_source_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_profile_modify(struct nb_cb_modify_args *args);
int route_next_hop_bfd_profile_destroy(struct nb_cb_destroy_args *args);
int route_next_hop_bfd_multi_hop_modify(struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_tag_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	struct nb_cb_destroy_args *args);

/* Optional 'apply_finish' callbacks. */

void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args);
void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args);

/* Optional 'pre_validate' callbacks. */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate(
	struct nb_cb_pre_validate_args *args);

/*
 * Callback registered with routing_nb lib to validate only
 * one instance of staticd is allowed
 */
int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args);

/* xpath macros */
/* route-list */
#define FRR_STATIC_ROUTE_INFO_KEY_XPATH                                        \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[prefix='%s'][afi-safi='%s']/"          \
	"path-list[table-id='%u'][distance='%u']"

#define FRR_STATIC_ROUTE_INFO_KEY_NO_DISTANCE_XPATH                            \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[prefix='%s'][afi-safi='%s']/"          \
	"path-list[table-id='%u']"


#define FRR_STATIC_ROUTE_PATH_TAG_XPATH "/tag"

/* route-list/frr-nexthops */
#define FRR_STATIC_ROUTE_NH_KEY_XPATH                                          \
	"/frr-nexthops/"                                                       \
	"nexthop[nh-type='%s'][vrf='%s'][gateway='%s'][interface='%s']"

#define FRR_STATIC_ROUTE_NH_ONLINK_XPATH "/onlink"

#define FRR_STATIC_ROUTE_NH_COLOR_XPATH "/srte-color"

#define FRR_STATIC_ROUTE_NH_BH_XPATH "/bh-type"

#define FRR_STATIC_ROUTE_NH_LABEL_XPATH "/mpls-label-stack"

#define FRR_STATIC_ROUTE_NHLB_KEY_XPATH "/entry[id='%u']/label"

/* route-list/srclist */
#define FRR_S_ROUTE_SRC_INFO_KEY_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[prefix='%s'][afi-safi='%s']/"          \
	"src-list[src-prefix='%s']/path-list[table-id='%u'][distance='%u']"

#define FRR_S_ROUTE_SRC_INFO_KEY_NO_DISTANCE_XPATH                             \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"              \
	"frr-staticd:staticd/route-list[prefix='%s'][afi-safi='%s']/"          \
	"src-list[src-prefix='%s']/path-list[table-id='%u']"

/* route-list/frr-nexthops */
#define FRR_DEL_S_ROUTE_NH_KEY_XPATH                                           \
	FRR_STATIC_ROUTE_INFO_KEY_XPATH                                        \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

/* route-list/frr-nexthops */
#define FRR_DEL_S_ROUTE_NH_KEY_NO_DISTANCE_XPATH                               \
	FRR_STATIC_ROUTE_INFO_KEY_NO_DISTANCE_XPATH                            \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

/* route-list/src/src-list/frr-nexthops*/
#define FRR_DEL_S_ROUTE_SRC_NH_KEY_XPATH                                       \
	FRR_S_ROUTE_SRC_INFO_KEY_XPATH                                         \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

/* route-list/src/src-list/frr-nexthops*/
#define FRR_DEL_S_ROUTE_SRC_NH_KEY_NO_DISTANCE_XPATH                           \
	FRR_S_ROUTE_SRC_INFO_KEY_NO_DISTANCE_XPATH                             \
	FRR_STATIC_ROUTE_NH_KEY_XPATH

#ifdef __cplusplus
}
#endif

#endif
