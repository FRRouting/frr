// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 VmWare
 *                    Sarita Patra
 */

#ifndef _FRR_PIM_NB_H_
#define _FRR_PIM_NB_H_

extern const struct frr_yang_module_info frr_pim_info;
extern const struct frr_yang_module_info frr_pim_rp_info;
extern const struct frr_yang_module_info frr_gmp_info;

/* frr-pim prototypes*/
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ecmp_rebalance_modify(
	struct nb_cb_modify_args *args);
int pim_address_family_join_prune_interval_modify(struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_keep_alive_timer_modify(
	struct nb_cb_modify_args *args);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_keep_alive_timer_modify(
	struct nb_cb_modify_args *args);
int pim_address_family_create(struct nb_cb_create_args *args);
int pim_address_family_destroy(struct nb_cb_destroy_args *args);
int pim_address_family_packets_modify(struct nb_cb_modify_args *args);
int pim_address_family_register_suppress_time_modify(
	struct nb_cb_modify_args *args);
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
int lib_interface_pim_address_family_dr_priority_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_create(struct nb_cb_create_args *args);
int lib_interface_pim_address_family_destroy(struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_pim_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_pim_passive_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_hello_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_hello_holdtime_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_hello_holdtime_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_bfd_create(struct nb_cb_create_args *args);
int lib_interface_pim_address_family_bfd_destroy(
	struct nb_cb_destroy_args *args);
void lib_interface_pim_address_family_bfd_apply_finish(
	struct nb_cb_apply_finish_args *args);
int lib_interface_pim_address_family_bfd_min_rx_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_bfd_min_tx_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_bfd_detect_mult_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_bfd_profile_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_bfd_profile_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_pim_address_family_bsm_modify(struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_unicast_bsm_modify(
	struct nb_cb_modify_args *args);
int lib_interface_pim_address_family_active_active_modify(
	struct nb_cb_modify_args *args);
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

/* frr-gmp prototypes*/
int lib_interface_gmp_address_family_create(
	struct nb_cb_create_args *args);
int lib_interface_gmp_address_family_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_gmp_address_family_enable_modify(
	struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_igmp_version_modify(
	struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_igmp_version_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_gmp_address_family_mld_version_modify(
	struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_mld_version_destroy(
	struct nb_cb_destroy_args *args);
int lib_interface_gmp_address_family_query_interval_modify(
	struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_query_max_response_time_modify(
		struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_last_member_query_interval_modify(
		struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_robustness_variable_modify(
		struct nb_cb_modify_args *args);
int lib_interface_gmp_address_family_static_group_create(
		struct nb_cb_create_args *args);
int lib_interface_gmp_address_family_static_group_destroy(
		struct nb_cb_destroy_args *args);

/*
 * Callback registered with routing_nb lib to validate only
 * one instance of staticd is allowed
 */
int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args);

#if PIM_IPV == 4
#define FRR_PIM_AF_XPATH_VAL "frr-routing:ipv4"
#else
#define FRR_PIM_AF_XPATH_VAL "frr-routing:ipv6"
#endif

#define FRR_PIM_VRF_XPATH                                               \
	"/frr-routing:routing/control-plane-protocols/"                 \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"       \
	"frr-pim:pim/address-family[address-family='%s']"
#define FRR_PIM_INTERFACE_XPATH                                         \
	"./frr-pim:pim/address-family[address-family='%s']"
#define FRR_PIM_ENABLE_XPATH                                            \
	"%s/frr-pim:pim/address-family[address-family='%s']/pim-enable"
#define FRR_PIM_ROUTER_XPATH                                            \
	"/frr-pim:pim/address-family[address-family='%s']"
#define FRR_PIM_MROUTE_XPATH                                            \
	"./frr-pim:pim/address-family[address-family='%s']/"            \
	"mroute[source-addr='%s'][group-addr='%s']"
#define FRR_PIM_STATIC_RP_XPATH                                         \
	"/frr-routing:routing/control-plane-protocols/"                 \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']/"       \
	"frr-pim:pim/address-family[address-family='%s']/"              \
	"frr-pim-rp:rp/static-rp/rp-list[rp-address='%s']"
#define FRR_GMP_INTERFACE_XPATH                                         \
	"./frr-gmp:gmp/address-family[address-family='%s']"
#define FRR_GMP_ENABLE_XPATH                                            \
	"%s/frr-gmp:gmp/address-family[address-family='%s']/enable"
#define FRR_GMP_JOIN_XPATH                                              \
	"./frr-gmp:gmp/address-family[address-family='%s']/"            \
	"static-group[group-addr='%s'][source-addr='%s']"
#define FRR_PIM_MSDP_XPATH FRR_PIM_VRF_XPATH "/msdp"

#endif /* _FRR_PIM_NB_H_ */
