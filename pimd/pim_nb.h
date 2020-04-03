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

/* Mandatory callbacks. */
int pim_instance_create(enum nb_event event, const struct lyd_node *dnode,
                         union nb_resource *resource);
int pim_instance_destroy(enum nb_event event, const struct lyd_node *dnode);
int pim_instance_ecmp_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_ecmp_destroy(enum nb_event event, const struct lyd_node *dnode);
int pim_instance_ecmp_rebalance_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_ecmp_rebalance_destroy(enum nb_event event, const struct lyd_node *dnode);
int pim_instance_join_prune_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_keep_alive_timer_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_rp_ka_timer_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_packets_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_register_suppress_time_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_af_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_af_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_instance_send_v6_secondary_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_send_v6_secondary_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_spt_switch_action_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_spt_switch_infinity_prefix_list_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_spt_switch_infinity_prefix_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_ssm_prefix_list_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_instance_ssm_prefix_list_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_instance_ssm_pingd_source_ip_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_ssm_pingd_source_ip_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_msdp_mesh_group_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_msdp_mesh_group_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_msdp_mesh_group_member_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_msdp_mesh_group_member_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_msdp_mesh_group_source_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_msdp_mesh_group_source_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_msdp_peer_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_msdp_peer_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_msdp_peer_ip_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_msdp_peer_ip_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
void pim_instance_mlag_apply_finish(const struct lyd_node *dnode);
int pim_instance_mlag_peerlink_rif_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_mlag_peerlink_rif_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_mlag_reg_address_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_mlag_reg_address_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_instance_mlag_my_role_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_mlag_peer_state_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_register_accept_list_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_instance_register_accept_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_interface_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_destroy(enum nb_event event,
                        const struct lyd_node *dnode);

int pim_interface_dr_priority_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_hello_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_hello_holdtime_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_hello_holdtime_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_interface_bfd_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_interface_bfd_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
void pim_interface_bfd_apply_finish(const struct lyd_node *dnode);
int pim_interface_bfd_min_rx_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_bfd_min_tx_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_bfd_detect_mult_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_bsm_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_bsm_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_interface_unicast_bsm_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_unicast_bsm_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_interface_active_active_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_active_active_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_interface_af_create(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_af_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_interface_use_source_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_use_source_destroy(enum nb_event event,
                                const struct lyd_node *dnode);
int pim_interface_multicast_boundary_oil_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_multicast_boundary_oil_destroy(enum nb_event event,
                                const struct lyd_node *dnode);

int pim_instance_rp_list_create(enum nb_event event,
			const struct lyd_node *dnode,
			union nb_resource *resource);

int pim_instance_rp_list_destroy(enum nb_event event,
			const struct lyd_node *dnode);

int pim_instance_rp_group_list_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);

int pim_instance_rp_group_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode);

int pim_instance_rp_prefix_list_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);

int pim_instance_rp_prefix_list_destroy(enum nb_event event,
                        const struct lyd_node *dnode);


int pim_interface_igmp_enable_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_interface_igmp_version_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_interface_query_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_query_max_response_time_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_last_member_query_interval_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_robustness_variable_modify(enum nb_event event,
                                const struct lyd_node *dnode,
                                union nb_resource *resource);
int pim_interface_mroute_create(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_interface_mroute_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
int pim_interface_mroute_oif_modify(enum nb_event event,
                        const struct lyd_node *dnode,
                        union nb_resource *resource);
int pim_interface_mroute_oif_destroy(enum nb_event event,
                        const struct lyd_node *dnode);
/*
int pimd_instance_vrf_create(enum nb_event event, const struct lyd_node *dnode,
                         union nb_resource *resource);
int pimd_instance_vrf_destroy(enum nb_event event, const struct lyd_node *dnode);
int pimd_instance_vrf_join_prune_interval_modify(enum nb_event event,
                                             const struct lyd_node *dnode,
                                             union nb_resource *resource);
*/
#endif /* _FRR_PIM_NB_H_ */
