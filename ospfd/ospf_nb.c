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
			.xpath = "/frr-ospfd:ospf/instance",
			.cbs = {
				.cli_show = cli_show_ospf_instance,
				.cli_show_end = cli_show_ospf_instance_end,
				.create = ospf_instance_create,
				.destroy = ospf_instance_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/auto-cost-reference-bandwidth",
			.cbs = {
				.cli_show = cli_show_ospf_instance_auto_cost_reference_bandwidth,
				.modify = ospf_instance_auto_cost_reference_bandwidth_modify,
				.destroy = ospf_instance_auto_cost_reference_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/use-arp",
			.cbs = {
				.cli_show = cli_show_ospf_instance_use_arp,
				.modify = ospf_instance_use_arp_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_metric,
				.modify = ospf_instance_default_metric_modify,
				.destroy = ospf_instance_default_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/flood-reduction",
			.cbs = {
				.cli_show = cli_show_ospf_instance_flood_reduction,
				.modify = ospf_instance_flood_reduction_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/maximum-paths",
			.cbs = {
				.cli_show = cli_show_ospf_instance_maximum_paths,
				.modify = ospf_instance_maximum_paths_modify,
				.destroy = ospf_instance_maximum_paths_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/external-route-aggregation/timer",
			.cbs = {
				.cli_show = cli_show_ospf_instance_external_route_aggregation_timer,
				.modify = ospf_instance_external_route_aggregation_timer_modify,
				.destroy = ospf_instance_external_route_aggregation_timer_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/external-route-aggregation/address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_external_route_aggregation_address,
				.create = ospf_instance_external_route_aggregation_address_create,
				.destroy = ospf_instance_external_route_aggregation_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/external-route-aggregation/address/tag",
			.cbs = {
				.cli_show = cli_show_ospf_instance_external_route_aggregation_address_tag,
				.modify = ospf_instance_external_route_aggregation_address_tag_modify,
				.destroy = ospf_instance_external_route_aggregation_address_tag_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/external-route-aggregation/address/not-advertise",
			.cbs = {
				.cli_show = cli_show_ospf_instance_external_route_aggregation_address_not_advertise,
				.modify = ospf_instance_external_route_aggregation_address_not_advertise_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/socket/buffer/all",
			.cbs = {
				.cli_show = cli_show_ospf_instance_socket_buffer_all,
				.modify = ospf_instance_socket_buffer_all_modify,
				.destroy = ospf_instance_socket_buffer_all_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/socket/buffer/recv",
			.cbs = {
				.cli_show = cli_show_ospf_instance_socket_buffer_recv,
				.modify = ospf_instance_socket_buffer_recv_modify,
				.destroy = ospf_instance_socket_buffer_recv_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/socket/buffer/send",
			.cbs = {
				.cli_show = cli_show_ospf_instance_socket_buffer_send,
				.modify = ospf_instance_socket_buffer_send_modify,
				.destroy = ospf_instance_socket_buffer_send_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/socket/enable-interface",
			.cbs = {
				.cli_show = cli_show_ospf_instance_socket_enable_interface,
				.modify = ospf_instance_socket_enable_interface_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/log-adjacency/change",
			.cbs = {
				.cli_show = cli_show_ospf_instance_log_adjacency_change,
				.modify = ospf_instance_log_adjacency_change_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/log-adjacency/detail",
			.cbs = {
				.cli_show = cli_show_ospf_instance_log_adjacency_detail,
				.modify = ospf_instance_log_adjacency_detail_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/fast-reroute/ti-lfa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_fast_reroute_ti_lfa,
				.modify = ospf_instance_fast_reroute_ti_lfa_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/fast-reroute/node-protection",
			.cbs = {
				.cli_show = cli_show_ospf_instance_fast_reroute_node_protection,
				.modify = ospf_instance_fast_reroute_node_protection_modify,
				.destroy = ospf_instance_fast_reroute_node_protection_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_router_info_as,
				.modify = ospf_instance_router_info_as_modify,
				.destroy = ospf_instance_router_info_as_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/router-info/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_router_info_area,
				.modify = ospf_instance_router_info_area_modify,
				.destroy = ospf_instance_router_info_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/originate",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_originate,
				.modify = ospf_instance_default_information_originate_modify,
				.destroy = ospf_instance_default_information_originate_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_metric,
				.modify = ospf_instance_default_information_metric_modify,
				.destroy = ospf_instance_default_information_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_metric_type,
				.modify = ospf_instance_default_information_metric_type_modify,
				.destroy = ospf_instance_default_information_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/default-information/route-map",
			.cbs = {
				.cli_show = cli_show_ospf_instance_default_information_route_map,
				.modify = ospf_instance_default_information_route_map_modify,
				.destroy = ospf_instance_default_information_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute,
				.create = ospf_instance_redistribute_create,
				.destroy = ospf_instance_redistribute_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_metric,
				.modify = ospf_instance_redistribute_metric_modify,
				.destroy = ospf_instance_redistribute_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_metric_type,
				.modify = ospf_instance_redistribute_metric_type_modify,
				.destroy = ospf_instance_redistribute_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/redistribute/route-map",
			.cbs = {
				.cli_show = cli_show_ospf_instance_redistribute_route_map,
				.modify = ospf_instance_redistribute_route_map_modify,
				.destroy = ospf_instance_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/admin-value",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_admin_value,
				.modify = ospf_instance_distance_admin_value_modify,
				.destroy = ospf_instance_distance_admin_value_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/external",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_external,
				.modify = ospf_instance_distance_ospf_external_modify,
				.destroy = ospf_instance_distance_ospf_external_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/inter-area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_inter_area,
				.modify = ospf_instance_distance_ospf_inter_area_modify,
				.destroy = ospf_instance_distance_ospf_inter_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distance/ospf/intra-area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distance_ospf_intra_area,
				.modify = ospf_instance_distance_ospf_intra_area_modify,
				.destroy = ospf_instance_distance_ospf_intra_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/distribute-list/dlist",
			.cbs = {
				.cli_show = cli_show_ospf_instance_distribute_list_dlist,
				.create = ospf_instance_distribute_list_dlist_create,
				.destroy = ospf_instance_distribute_list_dlist_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/administrative",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_administrative,
				.modify = ospf_instance_max_metric_router_lsa_administrative_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-shutdown",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_on_shutdown,
				.modify = ospf_instance_max_metric_router_lsa_on_shutdown_modify,
				.destroy = ospf_instance_max_metric_router_lsa_on_shutdown_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/max-metric/router-lsa/on-startup",
			.cbs = {
				.cli_show = cli_show_ospf_instance_max_metric_router_lsa_on_startup,
				.modify = ospf_instance_max_metric_router_lsa_on_startup_modify,
				.destroy = ospf_instance_max_metric_router_lsa_on_startup_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/on",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_on,
				.modify = ospf_instance_mpls_te_on_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/export",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_export,
				.modify = ospf_instance_mpls_te_export_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/router-address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_router_address,
				.modify = ospf_instance_mpls_te_router_address_modify,
				.destroy = ospf_instance_mpls_te_router_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_inter_as_as,
				.modify = ospf_instance_mpls_te_inter_as_as_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls-te/inter-as/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_te_inter_as_area,
				.modify = ospf_instance_mpls_te_inter_as_area_modify,
				.destroy = ospf_instance_mpls_te_inter_as_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/abr-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_abr_type,
				.modify = ospf_instance_ospf_abr_type_modify,
				.destroy = ospf_instance_ospf_abr_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/opaque-lsa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_opaque_lsa,
				.modify = ospf_instance_ospf_opaque_lsa_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/rfc1583compatibility",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_rfc1583compatibility,
				.modify = ospf_instance_ospf_rfc1583compatibility_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/send-extra-data",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_send_extra_data,
				.modify = ospf_instance_ospf_send_extra_data_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/maxage-delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_maxage_delay,
				.modify = ospf_instance_ospf_maxage_delay_modify,
				.destroy = ospf_instance_ospf_maxage_delay_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/lsa-refresh",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_lsa_refresh,
				.modify = ospf_instance_ospf_lsa_refresh_modify,
				.destroy = ospf_instance_ospf_lsa_refresh_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/router-id",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_router_id,
				.modify = ospf_instance_ospf_router_id_modify,
				.destroy = ospf_instance_ospf_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/ospf/write-multiplier",
			.cbs = {
				.cli_show = cli_show_ospf_instance_ospf_write_multiplier,
				.modify = ospf_instance_ospf_write_multiplier_modify,
				.destroy = ospf_instance_ospf_write_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/refresh-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_refresh_interval,
				.modify = ospf_instance_timers_refresh_interval_modify,
				.destroy = ospf_instance_timers_refresh_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/lsa-min-arrival",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_lsa_min_arrival,
				.modify = ospf_instance_timers_lsa_min_arrival_modify,
				.destroy = ospf_instance_timers_lsa_min_arrival_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/lsa-all",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_lsa_all,
				.modify = ospf_instance_timers_throttle_lsa_all_modify,
				.destroy = ospf_instance_timers_throttle_lsa_all_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_delay,
				.modify = ospf_instance_timers_throttle_spf_delay_modify,
				.destroy = ospf_instance_timers_throttle_spf_delay_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/hold",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_hold,
				.modify = ospf_instance_timers_throttle_spf_hold_modify,
				.destroy = ospf_instance_timers_throttle_spf_hold_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/timers/throttle/spf/max",
			.cbs = {
				.cli_show = cli_show_ospf_instance_timers_throttle_spf_max,
				.modify = ospf_instance_timers_throttle_spf_max_modify,
				.destroy = ospf_instance_timers_throttle_spf_max_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/lower-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_global_block_lower_bound,
				.modify = ospf_instance_segment_routing_global_block_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/global-block/upper-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_global_block_upper_bound,
				.modify = ospf_instance_segment_routing_global_block_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/lower-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_srlb_lower_bound,
				.modify = ospf_instance_segment_routing_srlb_lower_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/srlb/upper-bound",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_srlb_upper_bound,
				.modify = ospf_instance_segment_routing_srlb_upper_bound_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/node-msd",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_node_msd,
				.modify = ospf_instance_segment_routing_node_msd_modify,
				.destroy = ospf_instance_segment_routing_node_msd_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/on",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_on,
				.modify = ospf_instance_segment_routing_on_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid,
				.create = ospf_instance_segment_routing_prefix_sid_create,
				.destroy = ospf_instance_segment_routing_prefix_sid_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/prefix",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid_prefix,
				.modify = ospf_instance_segment_routing_prefix_sid_prefix_modify,
				.destroy = ospf_instance_segment_routing_prefix_sid_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/segment-routing/prefix-sid/last-hop-behavior",
			.cbs = {
				.cli_show = cli_show_ospf_instance_segment_routing_prefix_sid_last_hop_behavior,
				.modify = ospf_instance_segment_routing_prefix_sid_last_hop_behavior_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor,
				.create = ospf_instance_neighbor_create,
				.destroy = ospf_instance_neighbor_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/priority",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor_priority,
				.modify = ospf_instance_neighbor_priority_modify,
				.destroy = ospf_instance_neighbor_priority_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/neighbor/poll-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_neighbor_poll_interval,
				.modify = ospf_instance_neighbor_poll_interval_modify,
				.destroy = ospf_instance_neighbor_poll_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network",
			.cbs = {
				.cli_show = cli_show_ospf_instance_network,
				.create = ospf_instance_network_create,
				.destroy = ospf_instance_network_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/network/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_network_area,
				.modify = ospf_instance_network_area_modify,
				.destroy = ospf_instance_network_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface",
			.cbs = {
				.cli_show = cli_show_ospf_instance_passive_interface,
				.create = ospf_instance_passive_interface_create,
				.destroy = ospf_instance_passive_interface_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/passive-interface/address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_passive_interface_address,
				.modify = ospf_instance_passive_interface_address_modify,
				.destroy = ospf_instance_passive_interface_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/pce/address",
			.cbs = {
				.cli_show = cli_show_ospf_instance_pce_address,
				.modify = ospf_instance_pce_address_modify,
				.destroy = ospf_instance_pce_address_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/pce/domain-as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_pce_domain_as,
				.modify = ospf_instance_pce_domain_as_modify,
				.destroy = ospf_instance_pce_domain_as_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/pce/flags",
			.cbs = {
				.cli_show = cli_show_ospf_instance_pce_flags,
				.modify = ospf_instance_pce_flags_modify,
				.destroy = ospf_instance_pce_flags_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/pce/neighbor-as",
			.cbs = {
				.cli_show = cli_show_ospf_instance_pce_neighbor_as,
				.modify = ospf_instance_pce_neighbor_as_modify,
				.destroy = ospf_instance_pce_neighbor_as_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/pce/scope",
			.cbs = {
				.cli_show = cli_show_ospf_instance_pce_scope,
				.modify = ospf_instance_pce_scope_modify,
				.destroy = ospf_instance_pce_scope_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/helper/enable",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_helper_enable,
				.modify = ospf_instance_graceful_restart_helper_enable_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/helper/advertise-id",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_helper_advertise_id,
				.modify = ospf_instance_graceful_restart_helper_advertise_id_modify,
				.destroy = ospf_instance_graceful_restart_helper_advertise_id_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/helper/planned-only",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_helper_planned_only,
				.modify = ospf_instance_graceful_restart_helper_planned_only_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/helper/strict-lsa-checking",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_helper_strict_lsa_checking,
				.modify = ospf_instance_graceful_restart_helper_strict_lsa_checking_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/helper/grace-timer",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_helper_grace_timer,
				.modify = ospf_instance_graceful_restart_helper_grace_timer_modify,
				.destroy = ospf_instance_graceful_restart_helper_grace_timer_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/graceful-restart/grace-period",
			.cbs = {
				.cli_show = cli_show_ospf_instance_graceful_restart_grace_period,
				.modify = ospf_instance_graceful_restart_grace_period_modify,
				.destroy = ospf_instance_graceful_restart_grace_period_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls/ldp-sync/enable",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_ldp_sync_enable,
				.modify = ospf_instance_mpls_ldp_sync_enable_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/mpls/ldp-sync/holddown",
			.cbs = {
				.cli_show = cli_show_ospf_instance_mpls_ldp_sync_holddown,
				.modify = ospf_instance_mpls_ldp_sync_holddown_modify,
				.destroy = ospf_instance_mpls_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area,
				.create = ospf_instance_areas_area_create,
				.destroy = ospf_instance_areas_area_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_authentication,
				.create = ospf_instance_areas_area_authentication_create,
				.destroy = ospf_instance_areas_area_authentication_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/authentication/message-digest",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_authentication_message_digest,
				.modify = ospf_instance_areas_area_authentication_message_digest_modify,
				.destroy = ospf_instance_areas_area_authentication_message_digest_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/default-cost",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_default_cost,
				.modify = ospf_instance_areas_area_default_cost_modify,
				.destroy = ospf_instance_areas_area_default_cost_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/export-list",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_export_list,
				.modify = ospf_instance_areas_area_export_list_modify,
				.destroy = ospf_instance_areas_area_export_list_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/import-list",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_import_list,
				.modify = ospf_instance_areas_area_import_list_modify,
				.destroy = ospf_instance_areas_area_import_list_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/prefix",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_prefix,
				.modify = ospf_instance_areas_area_filter_list_prefix_modify,
				.destroy = ospf_instance_areas_area_filter_list_prefix_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/in",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_in,
				.modify = ospf_instance_areas_area_filter_list_in_modify,
				.destroy = ospf_instance_areas_area_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/filter-list/out",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_filter_list_out,
				.modify = ospf_instance_areas_area_filter_list_out_modify,
				.destroy = ospf_instance_areas_area_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/flood-reduction",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_flood_reduction,
				.modify = ospf_instance_areas_area_flood_reduction_modify,
				.destroy = ospf_instance_areas_area_flood_reduction_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa,
				.create = ospf_instance_areas_area_nssa_create,
				.destroy = ospf_instance_areas_area_nssa_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/no-summary",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_no_summary,
				.modify = ospf_instance_areas_area_nssa_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/translator-role",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_translator_role,
				.modify = ospf_instance_areas_area_nssa_translator_role_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-originate",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_originate,
				.modify = ospf_instance_areas_area_nssa_default_originate_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_metric_metric,
				.modify = ospf_instance_areas_area_nssa_default_metric_metric_modify,
				.destroy = ospf_instance_areas_area_nssa_default_metric_metric_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/default-metric/metric-type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_default_metric_metric_type,
				.modify = ospf_instance_areas_area_nssa_default_metric_metric_type_modify,
				.destroy = ospf_instance_areas_area_nssa_default_metric_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/nssa/suppress-fa",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_nssa_suppress_fa,
				.modify = ospf_instance_areas_area_nssa_suppress_fa_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range,
				.create = ospf_instance_areas_area_ranges_range_create,
				.destroy = ospf_instance_areas_area_ranges_range_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/advertise",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_advertise,
				.modify = ospf_instance_areas_area_ranges_range_advertise_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/not-advertise",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_not_advertise,
				.modify = ospf_instance_areas_area_ranges_range_not_advertise_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/cost",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_cost,
				.modify = ospf_instance_areas_area_ranges_range_cost_modify,
				.destroy = ospf_instance_areas_area_ranges_range_cost_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/ranges/range/substitute",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_ranges_range_substitute,
				.modify = ospf_instance_areas_area_ranges_range_substitute_modify,
				.destroy = ospf_instance_areas_area_ranges_range_substitute_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_stub,
				.create = ospf_instance_areas_area_stub_create,
				.destroy = ospf_instance_areas_area_stub_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/stub/no-summary",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_stub_no_summary,
				.modify = ospf_instance_areas_area_stub_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/shortcut-mode",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_shortcut_mode,
				.modify = ospf_instance_areas_area_shortcut_mode_modify,
				.destroy = ospf_instance_areas_area_shortcut_mode_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link,
				.create = ospf_instance_areas_area_virtual_link_create,
				.destroy = ospf_instance_areas_area_virtual_link_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/type",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_type,
				.modify = ospf_instance_areas_area_virtual_link_authentication_type_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/password",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_password,
				.modify = ospf_instance_areas_area_virtual_link_authentication_password_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_message_digest_key,
				.create = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_create,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key,
				.modify = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_authentication_key_chain,
				.modify = ospf_instance_areas_area_virtual_link_authentication_key_chain_modify,
				.destroy = ospf_instance_areas_area_virtual_link_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/dead-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_dead_interval,
				.modify = ospf_instance_areas_area_virtual_link_timers_dead_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_dead_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/hello-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_hello_interval,
				.modify = ospf_instance_areas_area_virtual_link_timers_hello_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_retransmit_interval,
				.modify = ospf_instance_areas_area_virtual_link_timers_retransmit_interval_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/retransmit-window",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_retransmit_window,
				.modify = ospf_instance_areas_area_virtual_link_timers_retransmit_window_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-ospfd:ospf/instance/areas/area/virtual-link/timers/transmit-delay",
			.cbs = {
				.cli_show = cli_show_ospf_instance_areas_area_virtual_link_timers_transmit_delay,
				.modify = ospf_instance_areas_area_virtual_link_timers_transmit_delay_modify,
				.destroy = ospf_instance_areas_area_virtual_link_timers_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance,
				.cli_show_end = cli_show_lib_interface_ospf_instance_end,
				.create = lib_interface_ospf_instance_create,
				.destroy = lib_interface_ospf_instance_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/enable",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_bfd_monitoring_enable,
				.modify = lib_interface_ospf_instance_bfd_monitoring_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/bfd-monitoring/profile",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_bfd_monitoring_profile,
				.modify = lib_interface_ospf_instance_bfd_monitoring_profile_modify,
				.destroy = lib_interface_ospf_instance_bfd_monitoring_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_type,
				.modify = lib_interface_ospf_instance_network_type_modify,
				.destroy = lib_interface_ospf_instance_network_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/delay-reflood",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2mp_delay_reflood,
				.modify = lib_interface_ospf_instance_network_p2mp_delay_reflood_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2mp/non-broadcast",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2mp_non_broadcast,
				.modify = lib_interface_ospf_instance_network_p2mp_non_broadcast_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/network/p2p/dmvpn",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_network_p2p_dmvpn,
				.modify = lib_interface_ospf_instance_network_p2p_dmvpn_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/enable",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mpls_ldp_sync_enable,
				.modify = lib_interface_ospf_instance_mpls_ldp_sync_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mpls/ldp-sync/holddown",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mpls_ldp_sync_holddown,
				.modify = lib_interface_ospf_instance_mpls_ldp_sync_holddown_modify,
				.destroy = lib_interface_ospf_instance_mpls_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/area",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_area,
				.modify = lib_interface_ospf_instance_area_modify,
				.destroy = lib_interface_ospf_instance_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/capability/opaque",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_capability_opaque,
				.modify = lib_interface_ospf_instance_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/passive",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_passive,
				.modify = lib_interface_ospf_instance_passive_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_type,
				.modify = lib_interface_ospf_instance_authentication_type_modify,
				.destroy = lib_interface_ospf_instance_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/password",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_password,
				.modify = lib_interface_ospf_instance_authentication_password_modify,
				.destroy = lib_interface_ospf_instance_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_message_digest_key,
				.create = lib_interface_ospf_instance_authentication_message_digest_key_create,
				.destroy = lib_interface_ospf_instance_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_message_digest_key_mds_key,
				.modify = lib_interface_ospf_instance_authentication_message_digest_key_mds_key_modify,
				.destroy = lib_interface_ospf_instance_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_authentication_key_chain,
				.modify = lib_interface_ospf_instance_authentication_key_chain_modify,
				.destroy = lib_interface_ospf_instance_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/cost",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_cost,
				.modify = lib_interface_ospf_instance_cost_modify,
				.destroy = lib_interface_ospf_instance_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_dead_interval_interval,
				.modify = lib_interface_ospf_instance_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_instance_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier,
				.modify = lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_instance_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/hello-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_hello_interval,
				.modify = lib_interface_ospf_instance_hello_interval_modify,
				.destroy = lib_interface_ospf_instance_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_retransmit_interval,
				.modify = lib_interface_ospf_instance_retransmit_interval_modify,
				.destroy = lib_interface_ospf_instance_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/retransmit-window",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_retransmit_window,
				.modify = lib_interface_ospf_instance_retransmit_window_modify,
				.destroy = lib_interface_ospf_instance_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/graceful-restart/hello-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_graceful_restart_hello_delay,
				.modify = lib_interface_ospf_instance_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_instance_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/transmit-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_transmit_delay,
				.modify = lib_interface_ospf_instance_transmit_delay_modify,
				.destroy = lib_interface_ospf_instance_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/mtu-ignore",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_mtu_ignore,
				.modify = lib_interface_ospf_instance_mtu_ignore_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/priority",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_priority,
				.modify = lib_interface_ospf_instance_priority_modify,
				.destroy = lib_interface_ospf_instance_priority_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address,
				.create = lib_interface_ospf_instance_interface_address_create,
				.destroy = lib_interface_ospf_instance_interface_address_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/area",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_area,
				.modify = lib_interface_ospf_instance_interface_address_area_modify,
				.destroy = lib_interface_ospf_instance_interface_address_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/capability/opaque",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_capability_opaque,
				.modify = lib_interface_ospf_instance_interface_address_capability_opaque_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/passive",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_passive,
				.modify = lib_interface_ospf_instance_interface_address_passive_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/type",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_type,
				.modify = lib_interface_ospf_instance_interface_address_authentication_type_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/password",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_password,
				.modify = lib_interface_ospf_instance_interface_address_authentication_password_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_password_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_message_digest_key,
				.create = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_create,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/message-digest-key/mds-key",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key,
				.modify = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_message_digest_key_mds_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/authentication/key-chain",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_authentication_key_chain,
				.modify = lib_interface_ospf_instance_interface_address_authentication_key_chain_modify,
				.destroy = lib_interface_ospf_instance_interface_address_authentication_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/cost",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_cost,
				.modify = lib_interface_ospf_instance_interface_address_cost_modify,
				.destroy = lib_interface_ospf_instance_interface_address_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_dead_interval_interval,
				.modify = lib_interface_ospf_instance_interface_address_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier,
				.modify = lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier_modify,
				.destroy = lib_interface_ospf_instance_interface_address_dead_interval_minimal_hello_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/hello-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_hello_interval,
				.modify = lib_interface_ospf_instance_interface_address_hello_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-interval",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_retransmit_interval,
				.modify = lib_interface_ospf_instance_interface_address_retransmit_interval_modify,
				.destroy = lib_interface_ospf_instance_interface_address_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/retransmit-window",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_retransmit_window,
				.modify = lib_interface_ospf_instance_interface_address_retransmit_window_modify,
				.destroy = lib_interface_ospf_instance_interface_address_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/graceful-restart/hello-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay,
				.modify = lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_instance_interface_address_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/transmit-delay",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_transmit_delay,
				.modify = lib_interface_ospf_instance_interface_address_transmit_delay_modify,
				.destroy = lib_interface_ospf_instance_interface_address_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/mtu-ignore",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_mtu_ignore,
				.modify = lib_interface_ospf_instance_interface_address_mtu_ignore_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/instance/interface-address/priority",
			.cbs = {
				.cli_show = cli_show_lib_interface_ospf_instance_interface_address_priority,
				.modify = lib_interface_ospf_instance_interface_address_priority_modify,
				.destroy = lib_interface_ospf_instance_interface_address_priority_destroy,
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
