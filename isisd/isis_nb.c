// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "isisd/isis_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_isisd_info = {
	.name = "frr-isisd",
	.nodes = {
		{
			.xpath = "/frr-isisd:isis/instance",
			.cbs = {
				.cli_show = cli_show_router_isis,
				.cli_show_end = cli_show_router_isis_end,
				.create = isis_instance_create,
				.destroy = isis_instance_destroy,
			},
			.priority = NB_DFLT_PRIORITY - 1,
		},
		{
			.xpath = "/frr-isisd:isis/instance/is-type",
			.cbs = {
				.cli_show = cli_show_isis_is_type,
				.modify = isis_instance_is_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-address",
			.cbs = {
				.cli_show = cli_show_isis_area_address,
				.create = isis_instance_area_address_create,
				.destroy = isis_instance_area_address_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/dynamic-hostname",
			.cbs = {
				.cli_show = cli_show_isis_dynamic_hostname,
				.modify = isis_instance_dynamic_hostname_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/attach-send",
			.cbs = {
				.cli_show = cli_show_isis_attached_send,
				.modify = isis_instance_attached_send_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/attach-receive-ignore",
			.cbs = {
				.cli_show = cli_show_isis_attached_receive,
				.modify = isis_instance_attached_receive_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/attached",
			.cbs = {
				.modify = isis_instance_attached_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/overload/enabled",
			.cbs = {
				.cli_show = cli_show_isis_overload,
				.modify = isis_instance_overload_enabled_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/overload/on-startup",
			.cbs = {
				.cli_show = cli_show_isis_overload_on_startup,
				.modify = isis_instance_overload_on_startup_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/advertise-high-metrics",
			.cbs = {
				.cli_show = cli_show_advertise_high_metrics,
				.modify = isis_instance_advertise_high_metrics_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/metric-style",
			.cbs = {
				.cli_show = cli_show_isis_metric_style,
				.modify = isis_instance_metric_style_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/purge-originator",
			.cbs = {
				.cli_show = cli_show_isis_purge_origin,
				.modify = isis_instance_purge_originator_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/admin-group-send-zero",
			.cbs = {
				.cli_show = cli_show_isis_admin_group_send_zero,
				.modify = isis_instance_admin_group_send_zero_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/asla-legacy-flag",
			.cbs = {
				.cli_show = cli_show_isis_asla_legacy_flag,
				.modify = isis_instance_asla_legacy_flag_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/mtu",
			.cbs = {
				.cli_show = cli_show_isis_lsp_mtu,
				.modify = isis_instance_lsp_mtu_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/advertise-passive-only",
			.cbs = {
				.cli_show = cli_show_advertise_passive_only,
				.modify = isis_instance_advertise_passive_only_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers",
			.cbs = {
				.cli_show = cli_show_isis_lsp_timers,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-1/refresh-interval",
			.cbs = {
				.modify = isis_instance_lsp_refresh_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-1/maximum-lifetime",
			.cbs = {
				.modify = isis_instance_lsp_maximum_lifetime_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-1/generation-interval",
			.cbs = {
				.modify = isis_instance_lsp_generation_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-2/refresh-interval",
			.cbs = {
				.modify = isis_instance_lsp_refresh_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-2/maximum-lifetime",
			.cbs = {
				.modify = isis_instance_lsp_maximum_lifetime_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/timers/level-2/generation-interval",
			.cbs = {
				.modify = isis_instance_lsp_generation_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay",
			.cbs = {
				.apply_finish = ietf_backoff_delay_apply_finish,
				.cli_show = cli_show_isis_spf_ietf_backoff,
				.create = isis_instance_spf_ietf_backoff_delay_create,
				.destroy = isis_instance_spf_ietf_backoff_delay_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_init_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_short_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_long_delay_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_hold_down_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn",
			.cbs = {
				.modify = isis_instance_spf_ietf_backoff_delay_time_to_learn_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval",
			.cbs = {
				.cli_show = cli_show_isis_spf_min_interval,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-1",
			.cbs = {
				.modify = isis_instance_spf_minimum_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-2",
			.cbs = {
				.modify = isis_instance_spf_minimum_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/prefix-priorities/critical/access-list-name",
			.cbs = {
				.cli_show = cli_show_isis_spf_prefix_priority,
				.modify = isis_instance_spf_prefix_priorities_critical_access_list_name_modify,
				.destroy = isis_instance_spf_prefix_priorities_critical_access_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/prefix-priorities/high/access-list-name",
			.cbs = {
				.cli_show = cli_show_isis_spf_prefix_priority,
				.modify = isis_instance_spf_prefix_priorities_high_access_list_name_modify,
				.destroy = isis_instance_spf_prefix_priorities_high_access_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/prefix-priorities/medium/access-list-name",
			.cbs = {
				.cli_show = cli_show_isis_spf_prefix_priority,
				.modify = isis_instance_spf_prefix_priorities_medium_access_list_name_modify,
				.destroy = isis_instance_spf_prefix_priorities_medium_access_list_name_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password",
			.cbs = {
				.apply_finish = area_password_apply_finish,
				.cli_show = cli_show_isis_area_pwd,
				.create = isis_instance_area_password_create,
				.destroy = isis_instance_area_password_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password",
			.cbs = {
				.modify = isis_instance_area_password_password_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password-type",
			.cbs = {
				.modify = isis_instance_area_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/authenticate-snp",
			.cbs = {
				.modify = isis_instance_area_password_authenticate_snp_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password",
			.cbs = {
				.apply_finish = domain_password_apply_finish,
				.cli_show = cli_show_isis_domain_pwd,
				.create = isis_instance_domain_password_create,
				.destroy = isis_instance_domain_password_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password",
			.cbs = {
				.modify = isis_instance_domain_password_password_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password-type",
			.cbs = {
				.modify = isis_instance_domain_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/authenticate-snp",
			.cbs = {
				.modify = isis_instance_domain_password_authenticate_snp_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4",
			.cbs = {
				.apply_finish = default_info_origin_ipv4_apply_finish,
				.cli_show = cli_show_isis_def_origin_ipv4,
				.create = isis_instance_default_information_originate_ipv4_create,
				.destroy = isis_instance_default_information_originate_ipv4_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/always",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv4_always_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/route-map",
			.cbs = {
				.destroy = isis_instance_default_information_originate_ipv4_route_map_destroy,
				.modify = isis_instance_default_information_originate_ipv4_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/metric",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv4_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6",
			.cbs = {
				.apply_finish = default_info_origin_ipv6_apply_finish,
				.cli_show = cli_show_isis_def_origin_ipv6,
				.create = isis_instance_default_information_originate_ipv6_create,
				.destroy = isis_instance_default_information_originate_ipv6_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/always",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv6_always_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/route-map",
			.cbs = {
				.destroy = isis_instance_default_information_originate_ipv6_route_map_destroy,
				.modify = isis_instance_default_information_originate_ipv6_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/metric",
			.cbs = {
				.modify = isis_instance_default_information_originate_ipv6_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4",
			.cbs = {
				.apply_finish = redistribute_ipv4_apply_finish,
				.cli_show = cli_show_isis_redistribute_ipv4,
				.create = isis_instance_redistribute_ipv4_create,
				.destroy = isis_instance_redistribute_ipv4_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv4_route_map_destroy,
				.modify = isis_instance_redistribute_ipv4_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/metric",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv4_metric_destroy,
				.modify = isis_instance_redistribute_ipv4_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/table",
			.cbs = {
				.cli_show = cli_show_isis_redistribute_ipv4_table,
                                .cli_cmp = cli_cmp_isis_redistribute_table,
				.create = isis_instance_redistribute_ipv4_table_create,
				.destroy = isis_instance_redistribute_ipv4_table_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/table/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv4_route_map_destroy,
				.modify = isis_instance_redistribute_ipv4_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/table/metric",
			.cbs = {
				.modify = isis_instance_redistribute_ipv4_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6",
			.cbs = {
				.apply_finish = redistribute_ipv6_apply_finish,
				.cli_show = cli_show_isis_redistribute_ipv6,
				.create = isis_instance_redistribute_ipv6_create,
				.destroy = isis_instance_redistribute_ipv6_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv6_route_map_destroy,
				.modify = isis_instance_redistribute_ipv6_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/metric",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv6_metric_destroy,
				.modify = isis_instance_redistribute_ipv6_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/table",
			.cbs = {
				.cli_show = cli_show_isis_redistribute_ipv6_table,
				.cli_cmp = cli_cmp_isis_redistribute_table,
				.create = isis_instance_redistribute_ipv6_table_create,
				.destroy = isis_instance_redistribute_ipv6_table_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/table/route-map",
			.cbs = {
				.destroy = isis_instance_redistribute_ipv6_route_map_destroy,
				.modify = isis_instance_redistribute_ipv6_route_map_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/table/metric",
			.cbs = {
				.modify = isis_instance_redistribute_ipv6_metric_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv4_multicast,
				.create = isis_instance_multi_topology_ipv4_multicast_create,
				.destroy = isis_instance_multi_topology_ipv4_multicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv4_multicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv4_mgmt,
				.create = isis_instance_multi_topology_ipv4_management_create,
				.destroy = isis_instance_multi_topology_ipv4_management_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv4_management_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_unicast,
				.create = isis_instance_multi_topology_ipv6_unicast_create,
				.destroy = isis_instance_multi_topology_ipv6_unicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_unicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_multicast,
				.create = isis_instance_multi_topology_ipv6_multicast_create,
				.destroy = isis_instance_multi_topology_ipv6_multicast_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_multicast_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_mgmt,
				.create = isis_instance_multi_topology_ipv6_management_create,
				.destroy = isis_instance_multi_topology_ipv6_management_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_management_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc",
			.cbs = {
				.cli_show = cli_show_isis_mt_ipv6_dstsrc,
				.create = isis_instance_multi_topology_ipv6_dstsrc_create,
				.destroy = isis_instance_multi_topology_ipv6_dstsrc_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload",
			.cbs = {
				.modify = isis_instance_multi_topology_ipv6_dstsrc_overload_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-1/lfa/load-sharing",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_load_sharing,
				.modify = isis_instance_fast_reroute_level_1_lfa_load_sharing_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-1/lfa/priority-limit",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_priority_limit,
				.modify = isis_instance_fast_reroute_level_1_lfa_priority_limit_modify,
				.destroy = isis_instance_fast_reroute_level_1_lfa_priority_limit_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-1/lfa/tiebreaker",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_tiebreaker,
				.create = isis_instance_fast_reroute_level_1_lfa_tiebreaker_create,
				.destroy = isis_instance_fast_reroute_level_1_lfa_tiebreaker_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-1/lfa/tiebreaker/type",
			.cbs = {
				.modify = isis_instance_fast_reroute_level_1_lfa_tiebreaker_type_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-1/remote-lfa/prefix-list",
			.cbs = {
				.cli_show = cli_show_isis_frr_remote_lfa_plist,
				.modify = isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_modify,
				.destroy = isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-2/lfa/load-sharing",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_load_sharing,
				.modify = isis_instance_fast_reroute_level_2_lfa_load_sharing_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-2/lfa/priority-limit",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_priority_limit,
				.modify = isis_instance_fast_reroute_level_2_lfa_priority_limit_modify,
				.destroy = isis_instance_fast_reroute_level_2_lfa_priority_limit_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-2/lfa/tiebreaker",
			.cbs = {
				.cli_show = cli_show_isis_frr_lfa_tiebreaker,
				.create = isis_instance_fast_reroute_level_2_lfa_tiebreaker_create,
				.destroy = isis_instance_fast_reroute_level_2_lfa_tiebreaker_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-2/lfa/tiebreaker/type",
			.cbs = {
				.modify = isis_instance_fast_reroute_level_2_lfa_tiebreaker_type_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/fast-reroute/level-2/remote-lfa/prefix-list",
			.cbs = {
				.cli_show = cli_show_isis_frr_remote_lfa_plist,
				.modify = isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_modify,
				.destroy = isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_destroy,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/log-adjacency-changes",
			.cbs = {
				.cli_show = cli_show_isis_log_adjacency,
				.modify = isis_instance_log_adjacency_changes_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/log-pdu-drops",
			.cbs = {
				.cli_show = cli_show_isis_log_pdu_drops,
				.modify = isis_instance_log_pdu_drops_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te,
				.create = isis_instance_mpls_te_create,
				.destroy = isis_instance_mpls_te_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te/router-address",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te_router_addr,
				.destroy = isis_instance_mpls_te_router_address_destroy,
				.modify = isis_instance_mpls_te_router_address_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te/router-address-v6",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te_router_addr_ipv6,
				.destroy = isis_instance_mpls_te_router_address_ipv6_destroy,
				.modify = isis_instance_mpls_te_router_address_ipv6_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls-te/export",
			.cbs = {
				.cli_show = cli_show_isis_mpls_te_export,
				.modify = isis_instance_mpls_te_export_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/enabled",
			.cbs = {
				.modify = isis_instance_segment_routing_enabled_modify,
				.cli_show = cli_show_isis_sr_enabled,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks",
			.cbs = {
				.pre_validate = isis_instance_segment_routing_label_blocks_pre_validate,
				.cli_show = cli_show_isis_label_blocks,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srgb",
			.cbs = {
				.apply_finish = isis_instance_segment_routing_srgb_apply_finish,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srgb/lower-bound",
			.cbs = {
				.modify = isis_instance_segment_routing_srgb_lower_bound_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srgb/upper-bound",
			.cbs = {
				.modify = isis_instance_segment_routing_srgb_upper_bound_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srlb",
			.cbs = {
				.apply_finish = isis_instance_segment_routing_srlb_apply_finish,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srlb/lower-bound",
			.cbs = {
				.modify = isis_instance_segment_routing_srlb_lower_bound_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/label-blocks/srlb/upper-bound",
			.cbs = {
				.modify = isis_instance_segment_routing_srlb_upper_bound_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/msd/node-msd",
			.cbs = {
				.modify = isis_instance_segment_routing_msd_node_msd_modify,
				.destroy = isis_instance_segment_routing_msd_node_msd_destroy,
				.cli_show = cli_show_isis_node_msd,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid",
			.cbs = {
				.create = isis_instance_segment_routing_prefix_sid_map_prefix_sid_create,
				.destroy = isis_instance_segment_routing_prefix_sid_map_prefix_sid_destroy,
				.pre_validate = isis_instance_segment_routing_prefix_sid_map_prefix_sid_pre_validate,
				.apply_finish = isis_instance_segment_routing_prefix_sid_map_prefix_sid_apply_finish,
				.cli_show = cli_show_isis_prefix_sid,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/sid-value-type",
			.cbs = {
				.modify = isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/sid-value",
			.cbs = {
				.modify = isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/last-hop-behavior",
			.cbs = {
				.modify = isis_instance_segment_routing_prefix_sid_map_prefix_sid_last_hop_behavior_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/n-flag-clear",
			.cbs = {
				.modify = isis_instance_segment_routing_prefix_sid_map_prefix_sid_n_flag_clear_modify,
			}
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid",
			.cbs = {
				.create = isis_instance_segment_routing_algorithm_prefix_sid_create,
				.destroy = isis_instance_segment_routing_algorithm_prefix_sid_destroy,
				.pre_validate = isis_instance_segment_routing_algorithm_prefix_sid_pre_validate,
				.apply_finish = isis_instance_segment_routing_algorithm_prefix_sid_apply_finish,
				.cli_show = cli_show_isis_prefix_sid_algorithm,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid/sid-value-type",
			.cbs = {
				.modify = isis_instance_segment_routing_algorithm_prefix_sid_sid_value_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid/sid-value",
			.cbs = {
				.modify = isis_instance_segment_routing_algorithm_prefix_sid_sid_value_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid/last-hop-behavior",
			.cbs = {
				.modify = isis_instance_segment_routing_algorithm_prefix_sid_last_hop_behavior_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid/n-flag-clear",
			.cbs = {
				.modify = isis_instance_segment_routing_algorithm_prefix_sid_n_flag_clear_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo",
			.cbs = {
				.cli_show = cli_show_isis_flex_algo,
				.cli_show_end = cli_show_isis_flex_algo_end,
				.create = isis_instance_flex_algo_create,
				.destroy = isis_instance_flex_algo_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/advertise-definition",
			.cbs = {
				.modify = isis_instance_flex_algo_advertise_definition_modify,
				.destroy = isis_instance_flex_algo_advertise_definition_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/affinity-include-alls/affinity-include-all",
			.cbs = {
				.create = isis_instance_flex_algo_affinity_include_all_create,
				.destroy = isis_instance_flex_algo_affinity_include_all_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/affinity-include-anies/affinity-include-any",
			.cbs = {
				.create = isis_instance_flex_algo_affinity_include_any_create,
				.destroy = isis_instance_flex_algo_affinity_include_any_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/affinity-exclude-anies/affinity-exclude-any",
			.cbs = {
				.create = isis_instance_flex_algo_affinity_exclude_any_create,
				.destroy = isis_instance_flex_algo_affinity_exclude_any_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/prefix-metric",
			.cbs = {
				.create = isis_instance_flex_algo_prefix_metric_create,
				.destroy = isis_instance_flex_algo_prefix_metric_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/metric-type",
			.cbs = {
				.modify = isis_instance_flex_algo_metric_type_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/dplane-sr-mpls",
			.cbs = {
				.create = isis_instance_flex_algo_dplane_sr_mpls_create,
				.destroy = isis_instance_flex_algo_dplane_sr_mpls_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/dplane-srv6",
			.cbs = {
				.create = isis_instance_flex_algo_dplane_srv6_create,
				.destroy = isis_instance_flex_algo_dplane_srv6_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/dplane-ip",
			.cbs = {
				.create = isis_instance_flex_algo_dplane_ip_create,
				.destroy = isis_instance_flex_algo_dplane_ip_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/flex-algos/flex-algo/priority",
			.cbs = {
				.modify = isis_instance_flex_algo_priority_modify,
				.destroy = isis_instance_flex_algo_priority_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/enabled",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_enabled_modify,
				.cli_show = cli_show_isis_srv6_enabled,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/locator",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_locator_modify,
				.destroy = isis_instance_segment_routing_srv6_locator_destroy,
				.cli_show = cli_show_isis_srv6_locator,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-segs-left",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_msd_node_msd_max_segs_left_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-end-pop",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_msd_node_msd_max_end_pop_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-h-encaps",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_msd_node_msd_max_h_encaps_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-end-d",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_msd_node_msd_max_end_d_modify,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd",
			.cbs = {
				.cli_show = cli_show_isis_srv6_node_msd,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/segment-routing-srv6/interface",
			.cbs = {
				.modify = isis_instance_segment_routing_srv6_interface_modify,
				.cli_show = cli_show_isis_srv6_interface,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls/ldp-sync",
			.cbs = {
				.cli_show = cli_show_isis_mpls_ldp_sync,
				.create = isis_instance_mpls_ldp_sync_create,
				.destroy = isis_instance_mpls_ldp_sync_destroy,
			},
		},
		{
			.xpath = "/frr-isisd:isis/instance/mpls/ldp-sync/holddown",
			.cbs = {
				.cli_show = cli_show_isis_mpls_ldp_sync_holddown,
				.modify = isis_instance_mpls_ldp_sync_holddown_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis",
			.cbs = {
				.create = lib_interface_isis_create,
				.destroy = lib_interface_isis_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/area-tag",
			.cbs = {
				.modify = lib_interface_isis_area_tag_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/circuit-type",
			.cbs = {
				.cli_show = cli_show_ip_isis_circ_type,
				.modify = lib_interface_isis_circuit_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv4-routing",
			.cbs = {
				.cli_show = cli_show_ip_isis_ipv4,
				.modify = lib_interface_isis_ipv4_routing_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv6-routing",
			.cbs = {
				.cli_show = cli_show_ip_isis_ipv6,
				.modify = lib_interface_isis_ipv6_routing_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring",
			.cbs = {
				.apply_finish = lib_interface_isis_bfd_monitoring_apply_finish,
				.cli_show = cli_show_ip_isis_bfd_monitoring,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring/enabled",
			.cbs = {
				.modify = lib_interface_isis_bfd_monitoring_enabled_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring/profile",
			.cbs = {
				.modify = lib_interface_isis_bfd_monitoring_profile_modify,
				.destroy = lib_interface_isis_bfd_monitoring_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_csnp_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_csnp_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_csnp_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_psnp_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_psnp_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_psnp_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/padding",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_padding,
				.modify = lib_interface_isis_hello_padding_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_interval,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1",
			.cbs = {
				.modify = lib_interface_isis_hello_interval_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2",
			.cbs = {
				.modify = lib_interface_isis_hello_interval_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier",
			.cbs = {
				.cli_show = cli_show_ip_isis_hello_multi,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1",
			.cbs = {
				.modify = lib_interface_isis_hello_multiplier_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2",
			.cbs = {
				.modify = lib_interface_isis_hello_multiplier_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric",
			.cbs = {
				.cli_show = cli_show_ip_isis_metric,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-1",
			.cbs = {
				.modify = lib_interface_isis_metric_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-2",
			.cbs = {
				.modify = lib_interface_isis_metric_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority",
			.cbs = {
				.cli_show = cli_show_ip_isis_priority,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-1",
			.cbs = {
				.modify = lib_interface_isis_priority_level_1_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-2",
			.cbs = {
				.modify = lib_interface_isis_priority_level_2_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/network-type",
			.cbs = {
				.cli_show = cli_show_ip_isis_network_type,
				.modify = lib_interface_isis_network_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/passive",
			.cbs = {
				.cli_show = cli_show_ip_isis_passive,
				.modify = lib_interface_isis_passive_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password",
			.cbs = {
				.cli_show = cli_show_ip_isis_password,
				.create = lib_interface_isis_password_create,
				.destroy = lib_interface_isis_password_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password",
			.cbs = {
				.modify = lib_interface_isis_password_password_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password-type",
			.cbs = {
				.modify = lib_interface_isis_password_password_type_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake",
			.cbs = {
				.cli_show = cli_show_ip_isis_threeway_shake,
				.modify = lib_interface_isis_disable_three_way_handshake_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/standard",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_standard,
				.modify = lib_interface_isis_multi_topology_standard_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv4_multicast,
				.modify = lib_interface_isis_multi_topology_ipv4_multicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv4_mgmt,
				.modify = lib_interface_isis_multi_topology_ipv4_management_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_unicast,
				.modify = lib_interface_isis_multi_topology_ipv6_unicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_multicast,
				.modify = lib_interface_isis_multi_topology_ipv6_multicast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_mgmt,
				.modify = lib_interface_isis_multi_topology_ipv6_management_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc",
			.cbs = {
				.cli_show = cli_show_ip_isis_mt_ipv6_dstsrc,
				.modify = lib_interface_isis_multi_topology_ipv6_dstsrc_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute",
			.cbs = {
				.cli_show = cli_show_ip_isis_frr,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_1_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/lfa/exclude-interface",
			.cbs = {
				.cli_show = cli_show_frr_lfa_exclude_interface,
				.create = lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_create,
				.destroy = lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/remote-lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_1_remote_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/remote-lfa/maximum-metric",
			.cbs = {
				.cli_show = cli_show_frr_remote_lfa_max_metric,
				.modify = lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_modify,
				.destroy = lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/ti-lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_1_ti_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/ti-lfa/node-protection",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_1_ti_lfa_node_protection_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/ti-lfa/link-fallback",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_1_ti_lfa_link_fallback_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_2_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/lfa/exclude-interface",
			.cbs = {
				.cli_show = cli_show_frr_lfa_exclude_interface,
				.create = lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_create,
				.destroy = lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/remote-lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_2_remote_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/remote-lfa/maximum-metric",
			.cbs = {
				.cli_show = cli_show_frr_remote_lfa_max_metric,
				.modify = lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_modify,
				.destroy = lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/ti-lfa/enable",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_2_ti_lfa_enable_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/ti-lfa/node-protection",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_2_ti_lfa_node_protection_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/ti-lfa/link-fallback",
			.cbs = {
				.modify = lib_interface_isis_fast_reroute_level_2_ti_lfa_link_fallback_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis",
			.cbs = {
				.get_elem = lib_interface_state_isis_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency",
			.cbs = {
				.get_next = lib_interface_state_isis_adjacencies_adjacency_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-sys-type",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_neighbor_sys_type_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-sysid",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_neighbor_sysid_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-extended-circuit-id",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_neighbor_extended_circuit_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-snpa",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_neighbor_snpa_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/hold-timer",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_hold_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/neighbor-priority",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_neighbor_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/state",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid",
			.cbs = {
				.get_next = lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/af",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_af_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/value",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/weight",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/adjacency-sids/adjacency-sid/protection-requested",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_adjacency_sids_adjacency_sid_protection_requested_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid",
			.cbs = {
				.get_next = lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_get_next,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/af",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_af_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/value",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_value_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/weight",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_weight_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/adjacencies/adjacency/lan-adjacency-sids/lan-adjacency-sid/protection-requested",
			.cbs = {
				.get_elem = lib_interface_state_isis_adjacencies_adjacency_lan_adjacency_sids_lan_adjacency_sid_protection_requested_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-changes",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_adjacency_changes_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-number",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_adjacency_number_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/init-fails",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_init_fails_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/adjacency-rejects",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_adjacency_rejects_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/id-len-mismatch",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_id_len_mismatch_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/max-area-addresses-mismatch",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_max_area_addresses_mismatch_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/authentication-type-fails",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_authentication_type_fails_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/state/frr-isisd:isis/event-counters/authentication-fails",
			.cbs = {
				.get_elem = lib_interface_state_isis_event_counters_authentication_fails_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/mpls/ldp-sync",
			.cbs = {
				.cli_show = cli_show_isis_mpls_if_ldp_sync,
				.modify = lib_interface_isis_mpls_ldp_sync_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/mpls/holddown",
			.cbs = {
				.cli_show = cli_show_isis_mpls_if_ldp_sync_holddown,
				.modify = lib_interface_isis_mpls_holddown_modify,
				.destroy = lib_interface_isis_mpls_holddown_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
