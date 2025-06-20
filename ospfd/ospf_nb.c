// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 19 2025, fenglei <fengleiljx@gmail.com>
 *
 */

#include <zebra.h>

#include "ospfd/ospf_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_info = {
	.name = "frr-ospfd",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance",
			.cbs = {
				.create = lib_interface_ospf_instance_create,
				.destroy = lib_interface_ospf_instance_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/enable",
			.cbs = {
				.modify = lib_interface_ospf_instance_bfd_monitoring_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/profile",
			.cbs = {
				.modify = lib_interface_ospf_instance_bfd_monitoring_profile_modify,
				.destroy = lib_interface_ospf_instance_bfd_monitoring_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/type",
			.cbs = {
				.modify = lib_interface_ospf_instance_network_type_modify,
				.destroy = lib_interface_ospf_instance_network_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/delay-reflood",
			.cbs = {
				.modify = lib_interface_ospf_instance_network_p2mp_delay_reflood_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/non-broadcast",
			.cbs = {
				.modify = lib_interface_ospf_instance_network_p2mp_non_broadcast_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2p/dmvpn",
			.cbs = {
				.modify = lib_interface_ospf_instance_network_p2p_dmvpn_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/enable",
			.cbs = {
				.modify = lib_interface_ospf_instance_mpls_ldp_sync_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/holddown",
			.cbs = {
				.modify = lib_interface_ospf_instance_mpls_ldp_sync_holddown_modify,
				.destroy = lib_interface_ospf_instance_mpls_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/area",
			.cbs = {
				.modify = lib_interface_ospf_instance_area_modify,
				.destroy = lib_interface_ospf_instance_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/capability/opaque",
			.cbs = {
				.modify = lib_interface_ospf_instance_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/passive",
			.cbs = {
				.modify = lib_interface_ospf_instance_passive_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/type",
			.cbs = {
				.modify = lib_interface_ospf_instance_authentication_type_modify,
				.destroy = lib_interface_ospf_instance_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/password",
			.cbs = {
				.modify = lib_interface_ospf_instance_authentication_password_modify,
				.destroy = lib_interface_ospf_instance_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key",
			.cbs = {
				.create = lib_interface_ospf_instance_authentication_message_digest_key_create,
				.destroy = lib_interface_ospf_instance_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key/mds-key",
			.cbs = {
				.modify = lib_interface_ospf_instance_authentication_message_digest_key_mds_key_modify,
				.destroy = lib_interface_ospf_instance_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/key-chain",
			.cbs = {
				.modify = lib_interface_ospf_instance_authentication_key_chain_modify,
				.destroy = lib_interface_ospf_instance_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/cost",
			.cbs = {
				.modify = lib_interface_ospf_instance_cost_modify,
				.destroy = lib_interface_ospf_instance_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_instance_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_hello_interval_modify,
				.destroy = lib_interface_ospf_instance_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_retransmit_interval_modify,
				.destroy = lib_interface_ospf_instance_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-window",
			.cbs = {
				.modify = lib_interface_ospf_instance_retransmit_window_modify,
				.destroy = lib_interface_ospf_instance_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/graceful-restart/hello-delay",
			.cbs = {
				.modify = lib_interface_ospf_instance_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_instance_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_instance_transmit_delay_modify,
				.destroy = lib_interface_ospf_instance_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_instance_mtu_ignore_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/priority",
			.cbs = {
				.modify = lib_interface_ospf_instance_priority_modify,
				.destroy = lib_interface_ospf_instance_priority_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address",
			.cbs = {
				.create = lib_interface_ospf_instance_interface_address_create,
				.destroy = lib_interface_ospf_instance_interface_address_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/area",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_area_modify,
				.destroy = lib_interface_ospf_instance_interface_address_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/capability/opaque",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/passive",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_passive_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/type",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_authentication_type_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/password",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_authentication_password_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key",
			.cbs = {
				.create = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_create,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key/mds-key",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/key-chain",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_authentication_key_chain_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/cost",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_cost_modify,
				.destroy = lib_interface_ospf_instance_interface_address_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_hello_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_retransmit_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-window",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_retransmit_window_modify,
				.destroy = lib_interface_ospf_instance_interface_address_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/graceful-restart/hello-delay",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_transmit_delay_modify,
				.destroy = lib_interface_ospf_instance_interface_address_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_mtu_ignore_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/priority",
			.cbs = {
				.modify = lib_interface_ospf_instance_interface_address_priority_modify,
				.destroy = lib_interface_ospf_instance_interface_address_priority_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance",
			.cbs = {
				.create = ospf_instance_create,
				.destroy = ospf_instance_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/auto-cost-reference-bandwidth",
			.cbs = {
				.modify = ospf_instance_auto_cost_reference_bandwidth_modify,
				.destroy = ospf_instance_auto_cost_reference_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/use-arp",
			.cbs = {
				.modify = ospf_instance_use_arp_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/capability-opaque",
			.cbs = {
				.modify = ospf_instance_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/compatible-rfc1583",
			.cbs = {
				.modify = ospf_instance_compatible_rfc1583_modify,
				.destroy = ospf_instance_compatible_rfc1583_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-metric",
			.cbs = {
				.modify = ospf_instance_default_metric_modify,
				.destroy = ospf_instance_default_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/write-multiplier",
			.cbs = {
				.modify = ospf_instance_write_multiplier_modify,
				.destroy = ospf_instance_write_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/as",
			.cbs = {
				.modify = ospf_instance_router_info_as_modify,
				.destroy = ospf_instance_router_info_as_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/area",
			.cbs = {
				.modify = ospf_instance_router_info_area_modify,
				.destroy = ospf_instance_router_info_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/originate",
			.cbs = {
				.modify = ospf_instance_default_information_originate_modify,
				.destroy = ospf_instance_default_information_originate_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric",
			.cbs = {
				.modify = ospf_instance_default_information_metric_modify,
				.destroy = ospf_instance_default_information_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric-type",
			.cbs = {
				.modify = ospf_instance_default_information_metric_type_modify,
				.destroy = ospf_instance_default_information_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/route-map",
			.cbs = {
				.modify = ospf_instance_default_information_route_map_modify,
				.destroy = ospf_instance_default_information_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute",
			.cbs = {
				.create = ospf_instance_redistribute_create,
				.destroy = ospf_instance_redistribute_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric",
			.cbs = {
				.modify = ospf_instance_redistribute_metric_modify,
				.destroy = ospf_instance_redistribute_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric-type",
			.cbs = {
				.modify = ospf_instance_redistribute_metric_type_modify,
				.destroy = ospf_instance_redistribute_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/route-map",
			.cbs = {
				.modify = ospf_instance_redistribute_route_map_modify,
				.destroy = ospf_instance_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/admin-value",
			.cbs = {
				.modify = ospf_instance_distance_admin_value_modify,
				.destroy = ospf_instance_distance_admin_value_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/external",
			.cbs = {
				.modify = ospf_instance_distance_ospf_external_modify,
				.destroy = ospf_instance_distance_ospf_external_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/inter-area",
			.cbs = {
				.modify = ospf_instance_distance_ospf_inter_area_modify,
				.destroy = ospf_instance_distance_ospf_inter_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/intra-area",
			.cbs = {
				.modify = ospf_instance_distance_ospf_intra_area_modify,
				.destroy = ospf_instance_distance_ospf_intra_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distribute-list/dlist",
			.cbs = {
				.create = ospf_instance_distribute_list_dlist_create,
				.destroy = ospf_instance_distribute_list_dlist_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/administrative",
			.cbs = {
				.modify = ospf_instance_max_metric_router_lsa_administrative_modify,
				.destroy = ospf_instance_max_metric_router_lsa_administrative_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-shutdown",
			.cbs = {
				.modify = ospf_instance_max_metric_router_lsa_on_shutdown_modify,
				.destroy = ospf_instance_max_metric_router_lsa_on_shutdown_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-startup",
			.cbs = {
				.modify = ospf_instance_max_metric_router_lsa_on_startup_modify,
				.destroy = ospf_instance_max_metric_router_lsa_on_startup_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/on",
			.cbs = {
				.modify = ospf_instance_mpls_te_on_modify,
				.destroy = ospf_instance_mpls_te_on_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/router-address",
			.cbs = {
				.modify = ospf_instance_mpls_te_router_address_modify,
				.destroy = ospf_instance_mpls_te_router_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/as",
			.cbs = {
				.modify = ospf_instance_mpls_te_inter_as_as_modify,
				.destroy = ospf_instance_mpls_te_inter_as_as_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/area",
			.cbs = {
				.modify = ospf_instance_mpls_te_inter_as_area_modify,
				.destroy = ospf_instance_mpls_te_inter_as_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/abr-type",
			.cbs = {
				.modify = ospf_instance_ospf_abr_type_modify,
				.destroy = ospf_instance_ospf_abr_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/opaque-lsa",
			.cbs = {
				.modify = ospf_instance_ospf_opaque_lsa_modify,
				.destroy = ospf_instance_ospf_opaque_lsa_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/rfc1583compatibility",
			.cbs = {
				.modify = ospf_instance_ospf_rfc1583compatibility_modify,
				.destroy = ospf_instance_ospf_rfc1583compatibility_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/send-extra-data",
			.cbs = {
				.modify = ospf_instance_ospf_send_extra_data_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/maxage-delay",
			.cbs = {
				.modify = ospf_instance_ospf_maxage_delay_modify,
				.destroy = ospf_instance_ospf_maxage_delay_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/lsa-refresh",
			.cbs = {
				.modify = ospf_instance_ospf_lsa_refresh_modify,
				.destroy = ospf_instance_ospf_lsa_refresh_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/router-id",
			.cbs = {
				.modify = ospf_instance_ospf_router_id_modify,
				.destroy = ospf_instance_ospf_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/write-multiplier",
			.cbs = {
				.modify = ospf_instance_ospf_write_multiplier_modify,
				.destroy = ospf_instance_ospf_write_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/refresh-interval",
			.cbs = {
				.modify = ospf_instance_timers_refresh_interval_modify,
				.destroy = ospf_instance_timers_refresh_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/lsa-min-arrival",
			.cbs = {
				.modify = ospf_instance_timers_lsa_min_arrival_modify,
				.destroy = ospf_instance_timers_lsa_min_arrival_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/lsa-all",
			.cbs = {
				.modify = ospf_instance_timers_throttle_lsa_all_modify,
				.destroy = ospf_instance_timers_throttle_lsa_all_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/delay",
			.cbs = {
				.modify = ospf_instance_timers_throttle_spf_delay_modify,
				.destroy = ospf_instance_timers_throttle_spf_delay_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/hold",
			.cbs = {
				.modify = ospf_instance_timers_throttle_spf_hold_modify,
				.destroy = ospf_instance_timers_throttle_spf_hold_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/max",
			.cbs = {
				.modify = ospf_instance_timers_throttle_spf_max_modify,
				.destroy = ospf_instance_timers_throttle_spf_max_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/lower-bound",
			.cbs = {
				.modify = ospf_instance_segment_routing_global_block_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/upper-bound",
			.cbs = {
				.modify = ospf_instance_segment_routing_global_block_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/lower-bound",
			.cbs = {
				.modify = ospf_instance_segment_routing_srlb_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/upper-bound",
			.cbs = {
				.modify = ospf_instance_segment_routing_srlb_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/node-msd",
			.cbs = {
				.modify = ospf_instance_segment_routing_node_msd_modify,
				.destroy = ospf_instance_segment_routing_node_msd_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/on",
			.cbs = {
				.modify = ospf_instance_segment_routing_on_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid",
			.cbs = {
				.create = ospf_instance_segment_routing_prefix_sid_create,
				.destroy = ospf_instance_segment_routing_prefix_sid_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/prefix",
			.cbs = {
				.modify = ospf_instance_segment_routing_prefix_sid_prefix_modify,
				.destroy = ospf_instance_segment_routing_prefix_sid_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/last-hop-behavior",
			.cbs = {
				.modify = ospf_instance_segment_routing_prefix_sid_last_hop_behavior_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor",
			.cbs = {
				.create = ospf_instance_neighbor_create,
				.destroy = ospf_instance_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/priority",
			.cbs = {
				.modify = ospf_instance_neighbor_priority_modify,
				.destroy = ospf_instance_neighbor_priority_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/poll-interval",
			.cbs = {
				.modify = ospf_instance_neighbor_poll_interval_modify,
				.destroy = ospf_instance_neighbor_poll_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network",
			.cbs = {
				.create = ospf_instance_network_create,
				.destroy = ospf_instance_network_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network/area",
			.cbs = {
				.modify = ospf_instance_network_area_modify,
				.destroy = ospf_instance_network_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface",
			.cbs = {
				.create = ospf_instance_passive_interface_create,
				.destroy = ospf_instance_passive_interface_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface/address",
			.cbs = {
				.modify = ospf_instance_passive_interface_address_modify,
				.destroy = ospf_instance_passive_interface_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area",
			.cbs = {
				.create = ospf_instance_areas_area_create,
				.destroy = ospf_instance_areas_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication",
			.cbs = {
				.create = ospf_instance_areas_area_authentication_create,
				.destroy = ospf_instance_areas_area_authentication_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication/message-digest",
			.cbs = {
				.modify = ospf_instance_areas_area_authentication_message_digest_modify,
				.destroy = ospf_instance_areas_area_authentication_message_digest_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/default-cost",
			.cbs = {
				.modify = ospf_instance_areas_area_default_cost_modify,
				.destroy = ospf_instance_areas_area_default_cost_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/export-list",
			.cbs = {
				.modify = ospf_instance_areas_area_export_list_modify,
				.destroy = ospf_instance_areas_area_export_list_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/import-list",
			.cbs = {
				.modify = ospf_instance_areas_area_import_list_modify,
				.destroy = ospf_instance_areas_area_import_list_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/prefix",
			.cbs = {
				.modify = ospf_instance_areas_area_filter_list_prefix_modify,
				.destroy = ospf_instance_areas_area_filter_list_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/in",
			.cbs = {
				.modify = ospf_instance_areas_area_filter_list_in_modify,
				.destroy = ospf_instance_areas_area_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/out",
			.cbs = {
				.modify = ospf_instance_areas_area_filter_list_out_modify,
				.destroy = ospf_instance_areas_area_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/flood-reduction",
			.cbs = {
				.modify = ospf_instance_areas_area_flood_reduction_modify,
				.destroy = ospf_instance_areas_area_flood_reduction_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa",
			.cbs = {
				.create = ospf_instance_areas_area_nssa_create,
				.destroy = ospf_instance_areas_area_nssa_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/no-summary",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/translator-role",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_translator_role_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-originate",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_default_originate_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_default_metric_metric_modify,
				.destroy = ospf_instance_areas_area_nssa_default_metric_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric-type",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_default_metric_metric_type_modify,
				.destroy = ospf_instance_areas_area_nssa_default_metric_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/suppress-fa",
			.cbs = {
				.modify = ospf_instance_areas_area_nssa_suppress_fa_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range",
			.cbs = {
				.create = ospf_instance_areas_area_ranges_range_create,
				.destroy = ospf_instance_areas_area_ranges_range_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/advertise",
			.cbs = {
				.modify = ospf_instance_areas_area_ranges_range_advertise_modify,
				.destroy = ospf_instance_areas_area_ranges_range_advertise_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/not-advertise",
			.cbs = {
				.modify = ospf_instance_areas_area_ranges_range_not_advertise_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/cost",
			.cbs = {
				.modify = ospf_instance_areas_area_ranges_range_cost_modify,
				.destroy = ospf_instance_areas_area_ranges_range_cost_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/substitute",
			.cbs = {
				.modify = ospf_instance_areas_area_ranges_range_substitute_modify,
				.destroy = ospf_instance_areas_area_ranges_range_substitute_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub",
			.cbs = {
				.create = ospf_instance_areas_area_stub_create,
				.destroy = ospf_instance_areas_area_stub_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub/no-summary",
			.cbs = {
				.modify = ospf_instance_areas_area_stub_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/shortcut-mode",
			.cbs = {
				.modify = ospf_instance_areas_area_shortcut_mode_modify,
				.destroy = ospf_instance_areas_area_shortcut_mode_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link",
			.cbs = {
				.create = ospf_instance_areas_area_virtual_link_create,
				.destroy = ospf_instance_areas_area_virtual_link_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/type",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_authentication_type_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/password",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_authentication_password_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key",
			.cbs = {
				.create = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_create,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key/mds-key",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/key-chain",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_authentication_key_chain_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/dead-interval",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_timers_dead_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_dead_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/hello-interval",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_timers_hello_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-interval",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_timers_retransmit_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-window",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_timers_retransmit_window_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/transmit-delay",
			.cbs = {
				.modify = ospf_instance_areas_area_virtual_link_timers_transmit_delay_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-process",
			.cbs = {
				.rpc = clear_ospf_process_rpc,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-neighbor",
			.cbs = {
				.rpc = clear_ospf_neighbor_rpc,
			}
		},
		{
			.xpath = "/frr-ospfd:clear-ospf-interface",
			.cbs = {
				.rpc = clear_ospf_interface_rpc,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_cli_info = {
	.name = "frr-ospfd",
	.nodes = {
		{
			.xpath = "/frr-ospfd:ospf/instance",
			.cbs = {
				.cli_show = cli_show_ospf_instance,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/auto-cost-reference-bandwidth",
			.cbs = {
				.cli_show = cli_show_ospf_instance_auto_cost_reference_bandwidth,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/use-arp",
			.cbs = {
				.cli_show = cli_show_ospf_instance_use_arp,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/capability-opaque",
			.cbs = {
				.cli_show = cli_show_ospf_instance_capability_opaque,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/compatible-rfc1583",
			.cbs = {
				.cli_show = cli_show_ospf_instance_compatible_rfc1583,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_metric,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/write-multiplier",
			.cbs = {
				.cli_show = cli_show_ospf_instance_write_multiplier,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_router_info_as,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_router_info_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/originate",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_originate,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_metric,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_metric_type,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/route-map",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_route_map,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_metric,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_metric_type,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/route-map",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_route_map,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/admin-value",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_admin_value,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/external",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_external,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/inter-area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_inter_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/intra-area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_intra_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distribute-list/dlist",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distribute_list_dlist,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/administrative",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_administrative,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-shutdown",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_on_shutdown,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-startup",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_on_startup,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/on",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_on,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/router-address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_router_address,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_inter_as_as,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_inter_as_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/abr-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_abr_type,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/opaque-lsa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_opaque_lsa,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/rfc1583compatibility",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_rfc1583compatibility,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/send-extra-data",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_send_extra_data,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/maxage-delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_maxage_delay,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/lsa-refresh",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_lsa_refresh,
			}
		},		
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/router-id",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_router_id,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/write-multiplier",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_write_multiplier,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/refresh-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_refresh_interval,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/lsa-min-arrival",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_lsa_min_arrival,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/lsa-all",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_lsa_all,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_delay,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/hold",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_hold,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/max",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_max,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/lower-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_global_block_lower_bound,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/upper-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_global_block_upper_bound,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/lower-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_srlb_lower_bound,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/upper-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_srlb_upper_bound,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/node-msd",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_node_msd,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/on",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_on,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/prefix",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid_prefix,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/last-hop-behavior",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid_last_hop_behavior,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/priority",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor_priority,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/poll-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor_poll_interval,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network",
			.cbs = {
				.cli_show = cli_show_ospf_instance_network,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_network_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface",
			.cbs = {
				.cli_show = cli_show_ospf_instance_passive_interface,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface/address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_passive_interface_address,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_authentication,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication/message-digest",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_authentication_message_digest,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/default-cost",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_default_cost,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/export-list",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_export_list,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/import-list",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_import_list,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/prefix",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_prefix,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/in",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_in,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/out",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_out,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/flood-reduction",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_flood_reduction,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/no-summary",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_no_summary,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/translator-role",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_translator_role,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-originate",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_originate,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_metric_metric,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_metric_metric_type,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/suppress-fa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_suppress_fa,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/advertise",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_advertise,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/not-advertise",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_not_advertise,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/cost",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_cost,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/substitute",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_substitute,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_stub,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub/no-summary",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_stub_no_summary,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/shortcut-mode",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_shortcut_mode,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_type,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/password",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_password,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_message_digest_key,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_key_chain,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/dead-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_dead_interval,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/hello-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_hello_interval,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_retransmit_interval,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-window",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_retransmit_window,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/transmit-delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_transmit_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/enable",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_bfd_monitoring_enable,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/profile",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_bfd_monitoring_profile,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_type,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/delay-reflood",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2mp_delay_reflood,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/non-broadcast",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2mp_non_broadcast,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2p/dmvpn",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2p_dmvpn,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/enable",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mpls_ldp_sync_enable,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/holddown",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mpls_ldp_sync_holddown,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/area",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_area,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/capability/opaque",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_capability_opaque,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/passive",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_passive,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_type,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/password",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_password,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_message_digest_key,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_message_digest_key_mds_key,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_key_chain,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/cost",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_cost,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_dead_interval_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/hello-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_hello_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_retransmit_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-window",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_retransmit_window,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/graceful-restart/hello-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_graceful_restart_hello_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/transmit-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_transmit_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mtu-ignore",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mtu_ignore,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/priority",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_priority,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/area",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_area,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/capability/opaque",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_capability_opaque,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/passive",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_passive,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_type,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/password",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_password,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_message_digest_key,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_key_chain,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/cost",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_cost,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_dead_interval_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/hello-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_hello_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_retransmit_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-window",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_retransmit_window,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/graceful-restart/hello-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/transmit-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_transmit_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/mtu-ignore",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_mtu_ignore,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/priority",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_priority,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
