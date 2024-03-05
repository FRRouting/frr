// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  Cumulus Networks, Inc.
 * Chirag Shah
 */

#include <zebra.h>
#include "interface.h"
#include "northbound.h"
#include "libfrr.h"
#include "zebra_nb.h"

const char *features[] = {
#if HAVE_BFDD == 0
	"ptm-bfd",
#endif
#if defined(HAVE_RTADV)
	"ipv6-router-advertisements",
#endif
	NULL
};

/* clang-format off */
const struct frr_yang_module_info frr_zebra_info = {
	.name = "frr-zebra",
	.features = features,
	.nodes = {
		{
			.xpath = "/frr-zebra:zebra/mcast-rpf-lookup",
			.cbs = {
				.modify = zebra_mcast_rpf_lookup_modify,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/ip-forwarding",
			.cbs = {
				.modify = zebra_ip_forwarding_modify,
				.destroy = zebra_ip_forwarding_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/ipv6-forwarding",
			.cbs = {
				.modify = zebra_ipv6_forwarding_modify,
				.destroy = zebra_ipv6_forwarding_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/workqueue-hold-timer",
			.cbs = {
				.modify = zebra_workqueue_hold_timer_modify,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/zapi-packets",
			.cbs = {
				.modify = zebra_zapi_packets_modify,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/import-kernel-table/table-id",
			.cbs = {
				.modify = zebra_import_kernel_table_table_id_modify,
				.destroy = zebra_import_kernel_table_table_id_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/import-kernel-table/distance",
			.cbs = {
				.modify = zebra_import_kernel_table_distance_modify,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/import-kernel-table/route-map",
			.cbs = {
				.modify = zebra_import_kernel_table_route_map_modify,
				.destroy = zebra_import_kernel_table_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/allow-external-route-update",
			.cbs = {
				.create = zebra_allow_external_route_update_create,
				.destroy = zebra_allow_external_route_update_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/dplane-queue-limit",
			.cbs = {
				.modify = zebra_dplane_queue_limit_modify,
			}
		},
#if HAVE_BFDD == 0
		{
			.xpath = "/frr-zebra:zebra/ptm-enable",
			.cbs = {
				.modify = zebra_ptm_enable_modify,
			}
		},
#endif
		{
			.xpath = "/frr-zebra:zebra/route-map-delay",
			.cbs = {
				.modify = zebra_route_map_delay_modify,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-events",
			.cbs = {
				.modify = zebra_debugs_debug_events_modify,
				.destroy = zebra_debugs_debug_events_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-zapi-send",
			.cbs = {
				.modify = zebra_debugs_debug_zapi_send_modify,
				.destroy = zebra_debugs_debug_zapi_send_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-zapi-recv",
			.cbs = {
				.modify = zebra_debugs_debug_zapi_recv_modify,
				.destroy = zebra_debugs_debug_zapi_recv_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-zapi-detail",
			.cbs = {
				.modify = zebra_debugs_debug_zapi_detail_modify,
				.destroy = zebra_debugs_debug_zapi_detail_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-kernel",
			.cbs = {
				.modify = zebra_debugs_debug_kernel_modify,
				.destroy = zebra_debugs_debug_kernel_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-kernel-msg-send",
			.cbs = {
				.modify = zebra_debugs_debug_kernel_msg_send_modify,
				.destroy = zebra_debugs_debug_kernel_msg_send_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-kernel-msg-recv",
			.cbs = {
				.modify = zebra_debugs_debug_kernel_msg_recv_modify,
				.destroy = zebra_debugs_debug_kernel_msg_recv_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-rib",
			.cbs = {
				.modify = zebra_debugs_debug_rib_modify,
				.destroy = zebra_debugs_debug_rib_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-rib-detail",
			.cbs = {
				.modify = zebra_debugs_debug_rib_detail_modify,
				.destroy = zebra_debugs_debug_rib_detail_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-fpm",
			.cbs = {
				.modify = zebra_debugs_debug_fpm_modify,
				.destroy = zebra_debugs_debug_fpm_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-nht",
			.cbs = {
				.modify = zebra_debugs_debug_nht_modify,
				.destroy = zebra_debugs_debug_nht_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-nht-detail",
			.cbs = {
				.modify = zebra_debugs_debug_nht_detail_modify,
				.destroy = zebra_debugs_debug_nht_detail_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-mpls",
			.cbs = {
				.modify = zebra_debugs_debug_mpls_modify,
				.destroy = zebra_debugs_debug_mpls_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-vxlan",
			.cbs = {
				.modify = zebra_debugs_debug_vxlan_modify,
				.destroy = zebra_debugs_debug_vxlan_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-pw",
			.cbs = {
				.modify = zebra_debugs_debug_pw_modify,
				.destroy = zebra_debugs_debug_pw_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-dplane",
			.cbs = {
				.modify = zebra_debugs_debug_dplane_modify,
				.destroy = zebra_debugs_debug_dplane_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-dplane-detail",
			.cbs = {
				.modify = zebra_debugs_debug_dplane_detail_modify,
				.destroy = zebra_debugs_debug_dplane_detail_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:zebra/debugs/debug-mlag",
			.cbs = {
				.modify = zebra_debugs_debug_mlag_modify,
				.destroy = zebra_debugs_debug_mlag_destroy,
			}
		},
		{
			.xpath = "/frr-zebra:get-route-information",
			.cbs = {
				.rpc = get_route_information_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-v6-mroute-info",
			.cbs = {
				.rpc = get_v6_mroute_info_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-vrf-info",
			.cbs = {
				.rpc = get_vrf_info_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-vrf-vni-info",
			.cbs = {
				.rpc = get_vrf_vni_info_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-evpn-info",
			.cbs = {
				.rpc = get_evpn_info_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-vni-info",
			.cbs = {
				.rpc = get_vni_info_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-evpn-vni-rmac",
			.cbs = {
				.rpc = get_evpn_vni_rmac_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-evpn-vni-nexthops",
			.cbs = {
				.rpc = get_evpn_vni_nexthops_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:clear-evpn-dup-addr",
			.cbs = {
				.rpc = clear_evpn_dup_addr_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-evpn-macs",
			.cbs = {
				.rpc = get_evpn_macs_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-evpn-arp-cache",
			.cbs = {
				.rpc = get_evpn_arp_cache_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-pbr-ipset",
			.cbs = {
				.rpc = get_pbr_ipset_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-pbr-iptable",
			.cbs = {
				.rpc = get_pbr_iptable_rpc,
			}
		},
		{
			.xpath = "/frr-zebra:get-debugs",
			.cbs = {
				.rpc = get_debugs_rpc,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-addrs",
			.cbs = {
				.create = lib_interface_zebra_ipv4_addrs_create,
				.destroy = lib_interface_zebra_ipv4_addrs_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-addrs/label",
			.cbs = {
				.modify = lib_interface_zebra_ipv4_addrs_label_modify,
				.destroy = lib_interface_zebra_ipv4_addrs_label_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-p2p-addrs",
			.cbs = {
				.create = lib_interface_zebra_ipv4_p2p_addrs_create,
				.destroy = lib_interface_zebra_ipv4_p2p_addrs_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-p2p-addrs/label",
			.cbs = {
				.modify = lib_interface_zebra_ipv4_p2p_addrs_label_modify,
				.destroy = lib_interface_zebra_ipv4_p2p_addrs_label_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-addrs",
			.cbs = {
				.create = lib_interface_zebra_ipv6_addrs_create,
				.destroy = lib_interface_zebra_ipv6_addrs_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/multicast",
			.cbs = {
				.modify = lib_interface_zebra_multicast_modify,
				.destroy = lib_interface_zebra_multicast_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-detect",
			.cbs = {
				.modify = lib_interface_zebra_link_detect_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/enabled",
			.cbs = {
				.modify = lib_interface_zebra_enabled_modify,
				.destroy = lib_interface_zebra_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_bandwidth_modify,
				.destroy = lib_interface_zebra_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/mpls",
			.cbs = {
				.modify = lib_interface_zebra_mpls_modify,
				.destroy = lib_interface_zebra_mpls_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params",
			.cbs = {
				.create = lib_interface_zebra_link_params_create,
				.destroy = lib_interface_zebra_link_params_destroy,
				.apply_finish = lib_interface_zebra_link_params_apply_finish,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/metric",
			.cbs = {
				.modify = lib_interface_zebra_link_params_metric_modify,
				.destroy = lib_interface_zebra_link_params_metric_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/max-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_max_bandwidth_modify,
				.destroy = lib_interface_zebra_link_params_max_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/max-reservable-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_max_reservable_bandwidth_modify,
				.destroy = lib_interface_zebra_link_params_max_reservable_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/unreserved-bandwidths/unreserved-bandwidth",
			.cbs = {
				.create = lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_create,
				.destroy = lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/unreserved-bandwidths/unreserved-bandwidth/unreserved-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_unreserved_bandwidth_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/residual-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_residual_bandwidth_modify,
				.destroy = lib_interface_zebra_link_params_residual_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/available-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_available_bandwidth_modify,
				.destroy = lib_interface_zebra_link_params_available_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/utilized-bandwidth",
			.cbs = {
				.modify = lib_interface_zebra_link_params_utilized_bandwidth_modify,
				.destroy = lib_interface_zebra_link_params_utilized_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/legacy-admin-group",
			.cbs = {
				.modify = lib_interface_zebra_legacy_admin_group_modify,
				.destroy = lib_interface_zebra_legacy_admin_group_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities",
			.cbs = {
				.create = lib_interface_zebra_affinities_create,
				.destroy = lib_interface_zebra_affinities_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities/affinity",
			.cbs = {
				.create = lib_interface_zebra_affinity_create,
				.destroy = lib_interface_zebra_affinity_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/affinity-mode",
			.cbs = {
				.modify = lib_interface_zebra_affinity_mode_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor",
			.cbs = {
				.create = lib_interface_zebra_link_params_neighbor_create,
				.destroy = lib_interface_zebra_link_params_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor/remote-as",
			.cbs = {
				.modify = lib_interface_zebra_link_params_neighbor_remote_as_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor/ipv4-remote-id",
			.cbs = {
				.modify = lib_interface_zebra_link_params_neighbor_ipv4_remote_id_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/delay",
			.cbs = {
				.modify = lib_interface_zebra_link_params_delay_modify,
				.destroy = lib_interface_zebra_link_params_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay",
			.cbs = {
				.create = lib_interface_zebra_link_params_min_max_delay_create,
				.destroy = lib_interface_zebra_link_params_min_max_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay/delay-min",
			.cbs = {
				.modify = lib_interface_zebra_link_params_min_max_delay_delay_min_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/min-max-delay/delay-max",
			.cbs = {
				.modify = lib_interface_zebra_link_params_min_max_delay_delay_max_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/delay-variation",
			.cbs = {
				.modify = lib_interface_zebra_link_params_delay_variation_modify,
				.destroy = lib_interface_zebra_link_params_delay_variation_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/packet-loss",
			.cbs = {
				.modify = lib_interface_zebra_link_params_packet_loss_modify,
				.destroy = lib_interface_zebra_link_params_packet_loss_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-0",
			.cbs = {
				.create = lib_interface_zebra_evpn_mh_type_0_create,
				.destroy = lib_interface_zebra_evpn_mh_type_0_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-0/esi",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_type_0_esi_modify,
				.destroy = lib_interface_zebra_evpn_mh_type_0_esi_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3",
			.cbs = {
				.create = lib_interface_zebra_evpn_mh_type_3_create,
				.destroy = lib_interface_zebra_evpn_mh_type_3_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/system-mac",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_type_3_system_mac_modify,
				.destroy = lib_interface_zebra_evpn_mh_type_3_system_mac_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/local-discriminator",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_type_3_local_discriminator_modify,
				.destroy = lib_interface_zebra_evpn_mh_type_3_local_discriminator_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/df-preference",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_df_preference_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/bypass",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_bypass_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/uplink",
			.cbs = {
				.modify = lib_interface_zebra_evpn_mh_uplink_modify,
			}
		},
#if defined(HAVE_RTADV)
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/send-advertisements",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_send_advertisements_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/max-rtr-adv-interval",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/managed-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_managed_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/other-config-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_other_config_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/link-mtu",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_link_mtu_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/reachable-time",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_reachable_time_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/retrans-timer",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_retrans_timer_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/cur-hop-limit",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_default_lifetime_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_default_lifetime_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/fast-retransmit",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/advertisement-interval-option",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-preference",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-router-preference",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_default_router_preference_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix",
			.cbs = {
				.create = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_create,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain",
			.cbs = {
				.create = lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_create,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain/lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_lifetime_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/valid-lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_valid_lifetime_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/on-link-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_on_link_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/preferred-lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_preferred_lifetime_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/autonomous-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_autonomous_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix/router-address-flag",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_router_address_flag_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address",
			.cbs = {
				.create = lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_create,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address/lifetime",
			.cbs = {
				.modify = lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_modify,
				.destroy = lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_lifetime_destroy,
			}
		},
#endif /* defined(HAVE_RTADV) */
#if HAVE_BFDD == 0
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ptm-enable",
			.cbs = {
				.modify = lib_interface_zebra_ptm_enable_modify,
			}
		},
#endif
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/up-count",
			.cbs = {
				.get_elem = lib_interface_zebra_state_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/down-count",
			.cbs = {
				.get_elem = lib_interface_zebra_state_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/zif-type",
			.cbs = {
				.get_elem = lib_interface_zebra_state_zif_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/ptm-status",
			.cbs = {
				.get_elem = lib_interface_zebra_state_ptm_status_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/vlan-id",
			.cbs = {
				.get_elem = lib_interface_zebra_state_vlan_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/vni-id",
			.cbs = {
				.get_elem = lib_interface_zebra_state_vni_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/remote-vtep",
			.cbs = {
				.get_elem = lib_interface_zebra_state_remote_vtep_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/mcast-group",
			.cbs = {
				.get_elem = lib_interface_zebra_state_mcast_group_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/state/bond",
			.cbs = {
				.get_elem = lib_interface_zebra_state_bond_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/router-id",
			.cbs = {
				.modify = lib_vrf_zebra_router_id_modify,
				.destroy = lib_vrf_zebra_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-router-id",
			.cbs = {
				.modify = lib_vrf_zebra_ipv6_router_id_modify,
				.destroy = lib_vrf_zebra_ipv6_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-protocol",
			.cbs = {
				.create = lib_vrf_zebra_filter_protocol_create,
				.destroy = lib_vrf_zebra_filter_protocol_destroy,
				.apply_finish = lib_vrf_zebra_filter_protocol_apply_finish,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-protocol/route-map",
			.cbs = {
				.modify = lib_vrf_zebra_filter_protocol_route_map_modify,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-nht",
			.cbs = {
				.create = lib_vrf_zebra_filter_nht_create,
				.destroy = lib_vrf_zebra_filter_nht_destroy,
				.apply_finish = lib_vrf_zebra_filter_nht_apply_finish,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-nht/route-map",
			.cbs = {
				.modify = lib_vrf_zebra_filter_nht_route_map_modify,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/resolve-via-default",
			.cbs = {
				.modify = lib_vrf_zebra_resolve_via_default_modify,
				.destroy = lib_vrf_zebra_resolve_via_default_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-resolve-via-default",
			.cbs = {
				.modify = lib_vrf_zebra_ipv6_resolve_via_default_modify,
				.destroy = lib_vrf_zebra_ipv6_resolve_via_default_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range",
			.cbs = {
				.create = lib_vrf_zebra_netns_table_range_create,
				.destroy = lib_vrf_zebra_netns_table_range_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range/start",
			.cbs = {
				.modify = lib_vrf_zebra_netns_table_range_start_modify,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range/end",
			.cbs = {
				.modify = lib_vrf_zebra_netns_table_range_end_modify,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_lookup_entry,
				.lookup_next = lib_vrf_zebra_ribs_rib_lookup_next,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/afi-safi-name",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_afi_safi_name_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/table-id",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_table_id_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_route_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_route_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_route_lookup_entry,
				.lookup_next = lib_vrf_zebra_ribs_rib_route_lookup_next,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/prefix",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_prefix_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_route_route_entry_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_route_route_entry_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_route_route_entry_lookup_entry,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/protocol",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_protocol_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/instance",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_instance_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/distance",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_distance_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/metric",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_metric_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/tag",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_tag_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/selected",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_selected_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/installed",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_installed_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/failed",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_failed_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/queued",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_queued_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/internal-flags",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_internal_flags_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/internal-status",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_internal_status_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/uptime",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_uptime_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/id",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_id_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_lookup_entry,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/nh-type",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_nh_type_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/vrf",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_vrf_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/gateway",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_gateway_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/interface",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/bh-type",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_bh_type_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/onlink",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_onlink_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/srte-color",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_color_get_elem,
			}
		},

		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/srv6-segs-stack/entry",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_lookup_entry,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/srv6-segs-stack/entry/id",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_id_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/srv6-segs-stack/entry/seg",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_srv6_segs_stack_entry_seg_get_elem,
			}
		},

		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/mpls-label-stack/entry",
			.cbs = {
				.get_next = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_get_next,
				.get_keys = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_get_keys,
				.lookup_entry = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_lookup_entry,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/mpls-label-stack/entry/id",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_id_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/mpls-label-stack/entry/label",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_label_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/mpls-label-stack/entry/ttl",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_ttl_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_mpls_label_stack_entry_traffic_class_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/duplicate",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_duplicate_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/recursive",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_recursive_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/active",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_active_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/fib",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_fib_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/nexthop/weight",
			.cbs = {
				.get_elem = lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_nexthop_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/l3vni-id",
			.cbs = {
				.modify = lib_vrf_zebra_l3vni_id_modify,
				.destroy = lib_vrf_zebra_l3vni_id_destroy,
			}
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/prefix-only",
			.cbs = {
				.modify = lib_vrf_zebra_prefix_only_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
