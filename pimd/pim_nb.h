/*
 * Copyright (C) 2020 VmWare
 *                    Sarita Patra
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

#ifndef _FRR_PIM_NB_H_
#define _FRR_PIM_NB_H_

extern const struct frr_yang_module_info frr_pim_info;
extern const struct frr_yang_module_info frr_pim_rp_info;
extern const struct frr_yang_module_info frr_igmp_info;

/* frr-pim prototypes*/
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_modify(
	struct nb_cb_modify_args *args);
int pim_join_prune_interval_modify(struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_keep_alive_timer_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_rp_keep_alive_timer_modify(
	struct nb_cb_modify_args *args);
int pim_packets_modify(struct nb_cb_modify_args *args);
int pim_register_suppress_time_modify(struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy(
	struct nb_cb_destroy_args *args);
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_apply_finish(
	struct nb_cb_apply_finish_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy(
	struct nb_cb_destroy_args *args);
int pim_msdp_hold_time_modify(struct nb_cb_modify_args *args);
int pim_msdp_keep_alive_modify(struct nb_cb_modify_args *args);
int pim_msdp_connection_retry_modify(struct nb_cb_modify_args *args);
int pim_msdp_mesh_group_create(struct nb_cb_create_args *args);
int pim_msdp_mesh_group_destroy(struct nb_cb_destroy_args *args);
int pim_msdp_mesh_group_members_create(struct nb_cb_create_args *args);
int pim_msdp_mesh_group_members_destroy(struct nb_cb_destroy_args *args);
int pim_msdp_mesh_group_source_modify(struct nb_cb_modify_args *args);
int pim_msdp_mesh_group_source_destroy(struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_destroy(
	struct nb_cb_destroy_args *args);
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish(
	struct nb_cb_apply_finish_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_dr_priority_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_create(struct nb_cb_create_args *args);
int lib_interface_pim_destroy(struct nb_cb_destroy_args *args);
int lib_interface_pim_pim_enable_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_hello_interval_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_hello_holdtime_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_hello_holdtime_destroy(struct nb_cb_destroy_args *args);
int lib_interface_pim_bfd_create(struct nb_cb_create_args *args);
int lib_interface_pim_bfd_destroy(struct nb_cb_destroy_args *args);
void lib_interface_pim_bfd_apply_finish(struct nb_cb_apply_finish_args *args);
int lib_interface_pim_bfd_min_rx_interval_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_bfd_min_tx_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_bfd_detect_mult_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_bfd_profile_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_bfd_profile_destroy(struct nb_cb_destroy_args *args);
int lib_interface_pim_bsm_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_unicast_bsm_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_active_active_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_create(struct nb_cb_create_args *args);
int lib_interface_pim_address_family_destroy(struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_use_source_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_use_source_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_multicast_boundary_oil_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_multicast_boundary_oil_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_mroute_create(
	struct nb_cb_create_args *args);
int lib_interface_pim_address_family_mroute_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_mroute_oif_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_mroute_oif_destroy(
	struct nb_cb_destroy_args *args);

/* frr-pim-rp prototypes*/
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy(
	struct nb_cb_destroy_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy(
	struct nb_cb_destroy_args *args);

/* frr-igmp prototypes*/
int lib_interface_igmp_create(struct nb_cb_create_args *args);
int lib_interface_igmp_destroy(struct nb_cb_destroy_args *args);
int lib_interface_igmp_igmp_enable_modify(struct nb_cb_modify_args *args);
int lib_interface_igmp_version_modify(struct nb_cb_modify_args *args);
int lib_interface_igmp_version_destroy(struct nb_cb_destroy_args *args);
int lib_interface_igmp_query_interval_modify(struct nb_cb_modify_args *args);
int lib_interface_igmp_query_max_response_time_modify(
	struct nb_cb_modify_args *args);
int lib_interface_igmp_last_member_query_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_igmp_robustness_variable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_igmp_address_family_create(struct nb_cb_create_args *args);
int lib_interface_igmp_address_family_destroy(struct nb_cb_destroy_args *args);
int lib_interface_igmp_address_family_static_group_create(
	struct nb_cb_create_args *args);
int lib_interface_igmp_address_family_static_group_destroy(
	struct nb_cb_destroy_args *args);

/*
 * Callback registered with routing_nb lib to validate only
 * one instance of staticd is allowed
 */
int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args);

#define FRR_PIM_XPATH                                                   \
	"/frr-routing:routing/control-plane-protocols/"                 \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"       \
	"frr-pim:pim"
#define FRR_PIM_AF_XPATH                                                \
	"/frr-routing:routing/control-plane-protocols/"                 \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"       \
	"frr-pim:pim/address-family[address-family='%s']"
#define FRR_PIM_STATIC_RP_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                 \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"       \
	"frr-pim:pim/address-family[address-family='%s']/"              \
	"frr-pim-rp:rp/static-rp/rp-list[rp-address='%s']"
#define FRR_IGMP_JOIN_XPATH                                             \
	"./frr-igmp:igmp/address-family[address-family='%s']/"          \
	"static-group[group-addr='%s'][source-addr='%s']"
#define FRR_PIM_MSDP_XPATH FRR_PIM_AF_XPATH "/msdp"

#endif /* _FRR_PIM_NB_H_ */
