/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

extern const struct frr_yang_module_info frr_routing_info;
extern const struct frr_yang_module_info frr_pim_info;
extern const struct frr_yang_module_info frr_pim_rp_info;
extern const struct frr_yang_module_info frr_igmp_info;

/* frr-pim prototypes*/
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_ecmp_rebalance_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_join_prune_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_keep_alive_timer_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_rp_keep_alive_timer_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_packets_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_register_suppress_time_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_send_v6_secondary_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_action_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_spt_switchover_spt_infinity_prefix_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_prefix_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_ssm_pingd_source_ip_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_mesh_group_name_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_member_ip_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_mesh_group_source_ip_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_msdp_peer_source_ip_destroy(
	enum nb_event event, const struct lyd_node *dnode);
void routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_apply_finish(
	const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peerlink_rif_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_reg_address_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_my_role_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_mlag_peer_state_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_register_accept_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_pim_pim_enable_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource);
int lib_interface_pim_pim_enable_destroy(enum nb_event event,
					 const struct lyd_node *dnode);
int lib_interface_pim_dr_priority_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int lib_interface_pim_hello_interval_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource);
int lib_interface_pim_hello_holdtime_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource);
int lib_interface_pim_hello_holdtime_destroy(enum nb_event event,
					     const struct lyd_node *dnode);
int lib_interface_pim_bfd_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int lib_interface_pim_bfd_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
void lib_interface_pim_bfd_apply_finish(const struct lyd_node *dnode);
int lib_interface_pim_bfd_min_rx_interval_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource);
int lib_interface_pim_bfd_min_tx_interval_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource);
int lib_interface_pim_bfd_detect_mult_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_pim_bsm_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource);
int lib_interface_pim_bsm_destroy(enum nb_event event,
				  const struct lyd_node *dnode);
int lib_interface_pim_unicast_bsm_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource);
int lib_interface_pim_unicast_bsm_destroy(enum nb_event event,
					  const struct lyd_node *dnode);
int lib_interface_pim_active_active_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource);
int lib_interface_pim_active_active_destroy(enum nb_event event,
					    const struct lyd_node *dnode);
int lib_interface_pim_address_family_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource);
int lib_interface_pim_address_family_destroy(enum nb_event event,
					     const struct lyd_node *dnode);
int lib_interface_pim_address_family_use_source_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_pim_address_family_use_source_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_pim_address_family_multicast_boundary_oil_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_pim_address_family_multicast_boundary_oil_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_pim_address_family_mroute_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource);
int lib_interface_pim_address_family_mroute_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int lib_interface_pim_address_family_mroute_oif_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_pim_address_family_mroute_oif_destroy(
	enum nb_event event, const struct lyd_node *dnode);

/* frr-igmp prototypes*/
int lib_interface_igmp_igmp_enable_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource);
int lib_interface_igmp_version_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource);
int lib_interface_igmp_version_destroy(enum nb_event event,
				       const struct lyd_node *dnode);
int lib_interface_igmp_query_interval_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_igmp_query_max_response_time_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_igmp_last_member_query_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_igmp_robustness_variable_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource);
int lib_interface_igmp_address_family_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource);
int lib_interface_igmp_address_family_destroy(enum nb_event event,
					      const struct lyd_node *dnode);
int lib_interface_igmp_address_family_static_group_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int lib_interface_igmp_address_family_static_group_destroy(
	enum nb_event event, const struct lyd_node *dnode);

/* frr-pim-rp prototypes*/
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_group_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource);
int routing_control_plane_protocols_control_plane_protocol_pim_address_family_rp_static_rp_rp_list_prefix_list_destroy(
	enum nb_event event, const struct lyd_node *dnode);

#endif /* _FRR_PIM_NB_H_ */
