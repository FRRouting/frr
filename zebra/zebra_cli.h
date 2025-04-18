// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _ZEBRA_CLI_H
#define _ZEBRA_CLI_H 1

extern const struct frr_yang_module_info frr_zebra_cli_info;

void zebra_cli_init(void);

void zebra_route_map_delay_cli_write(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults);
void lib_interface_zebra_multicast_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void lib_interface_zebra_mpls_cli_write(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults);
void lib_interface_zebra_ip_nhrp_6wind_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv6_nhrp_6wind_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ip_nhrp_nflog_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv6_nhrp_nflog_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_detect_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_enabled_cli_write(struct vty *vty,
						  const struct lyd_node *dnode,
						  bool show_defaults);
void lib_interface_zebra_bandwidth_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void lib_interface_zebra_link_params_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_cli_write_end(struct vty *vty,
					      const struct lyd_node *dnode);
void lib_interface_zebra_link_params_metric_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_max_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_max_reservable_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_legacy_admin_group_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_neighbor_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_delay_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_delay_variation_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_packet_loss_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_residual_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_available_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_utilized_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_affinities_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_link_params_affinity_mode_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv4_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv4_p2p_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv6_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_bypass_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_df_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_type_3_system_mac_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_type_0_esi_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_type_3_local_discriminator_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_evpn_mh_uplink_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_retrans_timer_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_send_advertisements_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_default_lifetime_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_reachable_time_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv6_router_advertisements_managed_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_other_config_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_default_router_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ipv6_router_advertisements_link_mtu_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void
lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_interface_zebra_ptm_enable_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void zebra_vrf_indent_cli_write(struct vty *vty,
				       const struct lyd_node *dnode);
void lib_vrf_zebra_router_id_cli_write(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults);
void lib_vrf_zebra_ipv6_router_id_cli_write(struct vty *vty,
						   const struct lyd_node *dnode,
						   bool show_defaults);
void lib_vrf_zebra_filter_protocol_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void lib_vrf_zebra_filter_nht_cli_write(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults);
void lib_vrf_zebra_resolve_via_default_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_vrf_zebra_ipv6_resolve_via_default_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_vrf_zebra_nhrp_6wind_port_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void lib_vrf_mpls_fec_nexthop_resolution_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_vrf_zebra_netns_table_range_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void lib_vrf_zebra_l3vni_id_cli_write(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults);
#endif
