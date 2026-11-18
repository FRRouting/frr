// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound API - YANG node registration
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "bgpd/bgp_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bgp_info = {
	.name = "frr-bgp",
	.nodes = {
		{
			.xpath = "/frr-bgp:bgp-daemon/no-rib",
			.cbs = {
				.modify = bgp_nb_daemon_no_rib_modify,
				.cli_show = bgp_nb_cli_show_daemon_no_rib,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/session-dscp",
			.cbs = {
				.modify = bgp_nb_daemon_session_dscp_modify,
				.destroy = bgp_nb_daemon_session_dscp_destroy,
				.cli_show = bgp_nb_cli_show_daemon_session_dscp,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/input-queue-limit",
			.cbs = {
				.modify = bgp_nb_daemon_inq_limit_modify,
				.destroy = bgp_nb_daemon_inq_limit_destroy,
				.cli_show = bgp_nb_cli_show_daemon_inq_limit,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/output-queue-limit",
			.cbs = {
				.modify = bgp_nb_daemon_outq_limit_modify,
				.destroy = bgp_nb_daemon_outq_limit_destroy,
				.cli_show = bgp_nb_cli_show_daemon_outq_limit,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/suppress-fib-pending",
			.cbs = {
				.modify = bgp_nb_daemon_suppress_fib_modify,
				.cli_show = bgp_nb_cli_show_daemon_suppress_fib,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/suppress-fib-pending-delay",
			.cbs = {
				.modify = bgp_nb_daemon_suppress_fib_delay_modify,
				.destroy = bgp_nb_daemon_suppress_fib_delay_destroy,
				.cli_show = bgp_nb_cli_show_daemon_suppress_fib_delay,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/ipv6-auto-ra",
			.cbs = {
				.modify = bgp_nb_daemon_ipv6_auto_ra_modify,
				.cli_show = bgp_nb_cli_show_daemon_ipv6_auto_ra,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/update-delay-time",
			.cbs = {
				.modify = bgp_nb_daemon_update_delay_modify,
				.destroy = bgp_nb_daemon_update_delay_destroy,
				.cli_show = bgp_nb_cli_show_daemon_update_delay,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/establish-wait-time",
			.cbs = {
				.modify = bgp_nb_daemon_establish_wait_modify,
				.destroy = bgp_nb_daemon_establish_wait_destroy,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/advertisement-delay-time",
			.cbs = {
				.modify = bgp_nb_daemon_advertisement_delay_modify,
				.destroy = bgp_nb_daemon_advertisement_delay_destroy,
				.cli_show = bgp_nb_cli_show_daemon_advertisement_delay,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/community-alias",
			.cbs = {
				.create = bgp_nb_daemon_community_alias_create,
				.destroy = bgp_nb_daemon_community_alias_destroy,
				.cli_show = bgp_nb_cli_show_daemon_community_alias,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/community-alias/alias",
			.cbs = {
				.modify = bgp_nb_daemon_community_alias_name_modify,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/send-extra-data",
			.cbs = {
				.modify = bgp_nb_daemon_send_extra_data_modify,
				.cli_show = bgp_nb_cli_show_daemon_send_extra_data,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/snmp-traps/rfc4273",
			.cbs = {
				.modify = bgp_nb_daemon_snmp_traps_rfc4273_modify,
				.cli_show = bgp_nb_cli_show_daemon_snmp_traps_rfc4273,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/snmp-traps/bgp4-mibv2",
			.cbs = {
				.modify = bgp_nb_daemon_snmp_traps_bgp4_mibv2_modify,
				.cli_show = bgp_nb_cli_show_daemon_snmp_traps_bgp4_mibv2,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/snmp-traps/rfc4382",
			.cbs = {
				.modify = bgp_nb_daemon_snmp_traps_rfc4382_modify,
				.cli_show = bgp_nb_cli_show_daemon_snmp_traps_rfc4382,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/rmap-delay-time",
			.cbs = {
				.modify = bgp_nb_daemon_rmap_delay_time_modify,
				.cli_show = bgp_nb_cli_show_daemon_rmap_delay_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/enabled",
			.cbs = {
				.modify = bgp_nb_daemon_gr_enabled_modify,
				.destroy = bgp_nb_daemon_gr_enabled_destroy,
				.cli_show = bgp_nb_cli_show_daemon_gr_enabled,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_nb_daemon_gr_disable_modify,
				.destroy = bgp_nb_daemon_gr_disable_destroy,
				.cli_show = bgp_nb_cli_show_daemon_gr_disable,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/stale-routes-time",
			.cbs = {
				.modify = bgp_nb_daemon_gr_stale_routes_time_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_stale_routes_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/restart-time",
			.cbs = {
				.modify = bgp_nb_daemon_gr_restart_time_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_restart_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/selection-deferral-time",
			.cbs = {
				.modify = bgp_nb_daemon_gr_select_defer_time_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_select_defer_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = bgp_nb_daemon_gr_rib_stale_time_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_rib_stale_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/preserve-fw-entry",
			.cbs = {
				.modify = bgp_nb_daemon_gr_preserve_fw_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_preserve_fw,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-shutdown/enable",
			.cbs = {
				.modify = bgp_nb_daemon_graceful_shutdown_modify,
				.cli_show = bgp_nb_cli_show_daemon_graceful_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp",
			.cbs = {
				.create = bgp_nb_bgp_create,
				.destroy = bgp_nb_bgp_destroy,
				.cli_show = bgp_nb_cli_show_router_bgp,
				.cli_show_end = bgp_nb_cli_show_router_bgp_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-as",
			.cbs = {
				.modify = bgp_nb_local_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/router-id",
			.cbs = {
				.modify = bgp_nb_router_id_modify,
				.destroy = bgp_nb_router_id_destroy,
				.cli_show = bgp_nb_cli_show_router_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/instance-type-view",
			.cbs = {
				.modify = bgp_nb_instance_type_view_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/as-notation",
			.cbs = {
				.modify = bgp_nb_as_notation_modify,
				.destroy = bgp_nb_as_notation_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes",
			.cbs = {
				.modify = bgp_nb_log_neighbor_changes_modify,
				.cli_show = bgp_nb_cli_show_log_neighbor_changes,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-requires-policy",
			.cbs = {
				.modify = bgp_nb_ebgp_requires_policy_modify,
				.cli_show = bgp_nb_cli_show_ebgp_requires_policy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/import-check",
			.cbs = {
				.modify = bgp_nb_import_check_modify,
				.cli_show = bgp_nb_cli_show_import_check,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id",
			.cbs = {
				.modify = bgp_nb_cluster_id_modify,
				.destroy = bgp_nb_cluster_id_destroy,
				.cli_show = bgp_nb_cli_show_cluster_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/no-client-reflect",
			.cbs = {
				.modify = bgp_nb_no_client_reflect_modify,
				.cli_show = bgp_nb_cli_show_no_client_reflect,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/always-compare-med",
			.cbs = {
				.modify = bgp_nb_always_compare_med_modify,
				.cli_show = bgp_nb_cli_show_always_compare_med,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/deterministic-med",
			.cbs = {
				.modify = bgp_nb_deterministic_med_modify,
				.cli_show = bgp_nb_cli_show_deterministic_med,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-pref",
			.cbs = {
				.modify = bgp_nb_local_pref_modify,
				.cli_show = bgp_nb_cli_show_local_pref,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-external-failover",
			.cbs = {
				.modify = bgp_nb_fast_external_failover_modify,
				.cli_show = bgp_nb_cli_show_fast_external_failover,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-duplicates",
			.cbs = {
				.modify = bgp_nb_suppress_duplicates_modify,
				.cli_show = bgp_nb_cli_show_suppress_duplicates,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable",
			.cbs = {
				.modify = bgp_nb_graceful_shutdown_modify,
				.cli_show = bgp_nb_cli_show_graceful_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/mirror-buffer-limit",
			.cbs = {
				.modify = bgp_nb_bmp_mirror_buffer_limit_modify,
				.destroy = bgp_nb_bmp_mirror_buffer_limit_destroy,
				.cli_show = bgp_nb_cli_show_bmp_mirror_buffer_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list",
			.cbs = {
				.create = bgp_nb_bmp_target_create,
				.destroy = bgp_nb_bmp_target_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target,
				.cli_show_end = bgp_nb_cli_show_bmp_target_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/mirror",
			.cbs = {
				.modify = bgp_nb_bmp_target_mirror_modify,
				.cli_show = bgp_nb_cli_show_bmp_target_mirror,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-time",
			.cbs = {
				.modify = bgp_nb_bmp_target_stats_time_modify,
				.destroy = bgp_nb_bmp_target_stats_time_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target_stats_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-send-experimental",
			.cbs = {
				.modify = bgp_nb_bmp_target_stats_experimental_modify,
				.cli_show = bgp_nb_cli_show_bmp_target_stats_experimental,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv4-access-list",
			.cbs = {
				.modify = bgp_nb_bmp_target_acl_modify,
				.destroy = bgp_nb_bmp_target_acl_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target_acl_v4,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv6-access-list",
			.cbs = {
				.modify = bgp_nb_bmp_target_acl_modify,
				.destroy = bgp_nb_bmp_target_acl_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target_acl_v6,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/initiation-sysdescr",
			.cbs = {
				.modify = bgp_nb_bmp_target_initiation_modify,
				.destroy = bgp_nb_bmp_target_initiation_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target_initiation_sysdescr,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/initiation-sysname",
			.cbs = {
				.modify = bgp_nb_bmp_target_initiation_modify,
				.destroy = bgp_nb_bmp_target_initiation_destroy,
				.cli_show = bgp_nb_cli_show_bmp_target_initiation_sysname,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/incoming-session/session-list",
			.cbs = {
				.create = bgp_nb_bmp_listener_create,
				.destroy = bgp_nb_bmp_listener_destroy,
				.cli_show = bgp_nb_cli_show_bmp_listener,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list",
			.cbs = {
				.create = bgp_nb_bmp_connect_create,
				.destroy = bgp_nb_bmp_connect_destroy,
				.cli_show = bgp_nb_cli_show_bmp_connect,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/min-retry-time",
			.cbs = {
				.modify = bgp_nb_bmp_connect_leaf_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/max-retry-time",
			.cbs = {
				.modify = bgp_nb_bmp_connect_leaf_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/source-interface",
			.cbs = {
				.modify = bgp_nb_bmp_connect_leaf_modify,
				.destroy = bgp_nb_bmp_connect_leaf_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/import-vrf",
			.cbs = {
				.create = bgp_nb_bmp_import_vrf_create,
				.destroy = bgp_nb_bmp_import_vrf_destroy,
				.cli_show = bgp_nb_cli_show_bmp_import_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv4-unicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l3vpn-ipv6-unicast/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/pre-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/post-policy",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/common-config/loc-rib",
			.cbs = {
				.modify = bgp_nb_bmp_monitor_modify,
				.cli_show = bgp_nb_cli_show_bmp_monitor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/reject-as-sets",
			.cbs = {
				.modify = bgp_nb_reject_as_sets_modify,
				.cli_show = bgp_nb_cli_show_reject_as_sets,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/enforce-first-as",
			.cbs = {
				.modify = bgp_nb_enforce_first_as_modify,
				.destroy = bgp_nb_enforce_first_as_destroy,
				.cli_show = bgp_nb_cli_show_enforce_first_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-multihop-connected-route-check",
			.cbs = {
				.modify = bgp_nb_connected_route_check_modify,
				.cli_show = bgp_nb_cli_show_connected_route_check,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/allow-outbound-policy",
			.cbs = {
				.modify = bgp_nb_allow_outbound_policy_modify,
				.cli_show = bgp_nb_cli_show_allow_outbound_policy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/hard-administrative-reset",
			.cbs = {
				.modify = bgp_nb_hard_admin_reset_modify,
				.destroy = bgp_nb_hard_admin_reset_destroy,
				.cli_show = bgp_nb_cli_show_hard_admin_reset,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-hostname",
			.cbs = {
				.modify = bgp_nb_show_hostname_modify,
				.cli_show = bgp_nb_cli_show_show_hostname,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-nexthop-hostname",
			.cbs = {
				.modify = bgp_nb_show_nexthop_hostname_modify,
				.cli_show = bgp_nb_cli_show_show_nexthop_hostname,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/external-compare-router-id",
			.cbs = {
				.modify = bgp_nb_external_compare_router_id_modify,
				.cli_show = bgp_nb_cli_show_external_compare_router_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/ignore-as-path-length",
			.cbs = {
				.modify = bgp_nb_ignore_as_path_length_modify,
				.cli_show = bgp_nb_cli_show_ignore_as_path_length,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/compare-aigp",
			.cbs = {
				.modify = bgp_nb_compare_aigp_modify,
				.cli_show = bgp_nb_cli_show_compare_aigp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/use-imported-attributes",
			.cbs = {
				.modify = bgp_nb_use_imported_attributes_modify,
				.cli_show = bgp_nb_cli_show_use_imported_attributes,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/aspath-confed",
			.cbs = {
				.modify = bgp_nb_aspath_confed_modify,
				.cli_show = bgp_nb_cli_show_aspath_confed,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/allow-multiple-as",
			.cbs = {
				.modify = bgp_nb_allow_multiple_as_modify,
				.cli_show = bgp_nb_cli_show_allow_multiple_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/multi-path-as-set",
			.cbs = {
				.modify = bgp_nb_multi_path_as_set_modify,
				.destroy = bgp_nb_multi_path_as_set_destroy,
				.cli_show = bgp_nb_cli_show_multi_path_as_set,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/peer-type-multipath-relax",
			.cbs = {
				.modify = bgp_nb_peer_type_multipath_relax_modify,
				.cli_show = bgp_nb_cli_show_peer_type_multipath_relax,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/confed-med",
			.cbs = {
				.modify = bgp_nb_confed_med_modify,
				.cli_show = bgp_nb_cli_show_confed_med,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/missing-as-worst-med",
			.cbs = {
				.modify = bgp_nb_missing_as_worst_med_modify,
				.cli_show = bgp_nb_cli_show_missing_as_worst_med,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/bandwidth-handling",
			.cbs = {
				.modify = bgp_nb_bandwidth_handling_modify,
				.cli_show = bgp_nb_cli_show_bandwidth_handling,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/keepalive",
			.cbs = {
				.modify = bgp_nb_keepalive_modify,
				.cli_show = bgp_nb_cli_show_keepalive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/hold-time",
			.cbs = {
				.modify = bgp_nb_hold_time_modify,
				.cli_show = bgp_nb_cli_show_holdtime,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/minimum-holdtime",
			.cbs = {
				.modify = bgp_nb_minimum_holdtime_modify,
				.destroy = bgp_nb_minimum_holdtime_destroy,
				.cli_show = bgp_nb_cli_show_minimum_holdtime,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/rmap-delay-time",
			.cbs = {
				.modify = bgp_nb_rmap_delay_time_modify,
				.cli_show = bgp_nb_cli_show_rmap_delay_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time",
			.cbs = {
				.modify = bgp_nb_update_delay_time_modify,
				.destroy = bgp_nb_update_delay_time_destroy,
				.cli_show = bgp_nb_cli_show_update_delay_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/establish-wait-time",
			.cbs = {
				.modify = bgp_nb_establish_wait_time_modify,
				.destroy = bgp_nb_establish_wait_time_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/advertisement-delay-time",
			.cbs = {
				.modify = bgp_nb_advertisement_delay_modify,
				.destroy = bgp_nb_advertisement_delay_destroy,
				.cli_show = bgp_nb_cli_show_advertisement_delay,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/conditional-advertisement-timer",
			.cbs = {
				.modify = bgp_nb_conditional_advertisement_timer_modify,
				.cli_show = bgp_nb_cli_show_conditional_advertisement_timer,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/default-originate-timer",
			.cbs = {
				.modify = bgp_nb_default_originate_timer_modify,
				.destroy = bgp_nb_default_originate_timer_destroy,
				.cli_show = bgp_nb_cli_show_default_originate_timer,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6",
			.cbs = {
				.cli_show = bgp_nb_cli_show_srv6,
				.cli_show_end = bgp_nb_cli_show_srv6_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/locator",
			.cbs = {
				.modify = bgp_nb_srv6_locator_modify,
				.destroy = bgp_nb_srv6_locator_destroy,
				.cli_show = bgp_nb_cli_show_srv6_locator,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/encap-behavior",
			.cbs = {
				.modify = bgp_nb_srv6_encap_behavior_modify,
				.cli_show = bgp_nb_cli_show_srv6_encap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/segment-routing/srv6/srv6-only",
			.cbs = {
				.modify = bgp_nb_srv6_only_modify,
				.cli_show = bgp_nb_cli_show_srv6_only,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-per-vrf-export/sid-index",
			.cbs = {
				.modify = bgp_nb_sid_vpn_per_vrf_index_modify,
				.destroy = bgp_nb_sid_vpn_per_vrf_index_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_per_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-per-vrf-export/sid-auto",
			.cbs = {
				.create = bgp_nb_sid_vpn_per_vrf_auto_create,
				.destroy = bgp_nb_sid_vpn_per_vrf_auto_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_per_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/sid-vpn-per-vrf-export/sid-explicit",
			.cbs = {
				.modify = bgp_nb_sid_vpn_per_vrf_explicit_modify,
				.destroy = bgp_nb_sid_vpn_per_vrf_explicit_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_per_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/link-state/distribute/bgp-fabric-link-state",
			.cbs = {
				.create = bgp_nb_ls_fabric_create,
				.destroy = bgp_nb_ls_fabric_destroy,
				.cli_show = bgp_nb_cli_show_ls_fabric,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/link-state/distribute/bgp-fabric-link-state/instance-id",
			.cbs = {
				.modify = bgp_nb_ls_fabric_instance_id_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-flowspec/flow-spec-config/local-install/enable",
			.cbs = {
				.modify = bgp_nb_fs_local_install_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-flowspec/flow-spec-config/local-install/interface",
			.cbs = {
				.create = bgp_nb_fs_local_install_interface_create,
				.destroy = bgp_nb_fs_local_install_interface_destroy,
				.cli_show = bgp_nb_cli_show_fs_local_install_interface,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-flowspec/flow-spec-config/local-install/enable",
			.cbs = {
				.modify = bgp_nb_fs_local_install_enable_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-flowspec/flow-spec-config/local-install/interface",
			.cbs = {
				.create = bgp_nb_fs_local_install_interface_create,
				.destroy = bgp_nb_fs_local_install_interface_destroy,
				.cli_show = bgp_nb_cli_show_fs_local_install_interface,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_nb_global_afi_safi_create,
				.destroy = bgp_nb_global_afi_safi_destroy,
				.cli_show = bgp_nb_cli_show_global_afi_safi,
				.cli_show_end = bgp_nb_cli_show_global_afi_safi_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/network-config",
			.cbs = {
				.create = bgp_nb_network_create,
				.destroy = bgp_nb_network_destroy,
				.cli_show = bgp_nb_cli_show_network,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/network-config/backdoor",
			.cbs = {
				.modify = bgp_nb_network_backdoor_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/network-config/label-index",
			.cbs = {
				.modify = bgp_nb_network_label_index_modify,
				.destroy = bgp_nb_network_label_index_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/network-config/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_network_rmap_modify,
				.destroy = bgp_nb_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route",
			.cbs = {
				.create = bgp_nb_aggregate_create,
				.destroy = bgp_nb_aggregate_destroy,
				.cli_show = bgp_nb_cli_show_aggregate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/as-set",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/summary-only",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/match-med",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/upa",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/upa-drop",
			.cbs = {
				.modify = bgp_nb_aggregate_bool_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/origin",
			.cbs = {
				.modify = bgp_nb_aggregate_origin_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_aggregate_rmap_modify,
				.destroy = bgp_nb_aggregate_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/suppress-map",
			.cbs = {
				.modify = bgp_nb_aggregate_suppress_modify,
				.destroy = bgp_nb_aggregate_suppress_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/upa-max-routes",
			.cbs = {
				.modify = bgp_nb_aggregate_upa_max_modify,
				.destroy = bgp_nb_aggregate_upa_max_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ebgp_modify,
				.destroy = bgp_nb_maxpaths_ebgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ebgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_modify,
				.destroy = bgp_nb_maxpaths_ibgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ibgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_cluster_modify,
				.destroy = bgp_nb_maxpaths_ibgp_cluster_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ebgp_modify,
				.destroy = bgp_nb_maxpaths_ebgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ebgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_modify,
				.destroy = bgp_nb_maxpaths_ibgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ibgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_cluster_modify,
				.destroy = bgp_nb_maxpaths_ibgp_cluster_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ebgp_modify,
				.destroy = bgp_nb_maxpaths_ebgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ebgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_modify,
				.destroy = bgp_nb_maxpaths_ibgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ibgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_cluster_modify,
				.destroy = bgp_nb_maxpaths_ibgp_cluster_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ebgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ebgp_modify,
				.destroy = bgp_nb_maxpaths_ebgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ebgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/maximum-paths",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_modify,
				.destroy = bgp_nb_maxpaths_ibgp_destroy,
				.cli_show = bgp_nb_cli_show_maxpaths_ibgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list",
			.cbs = {
				.modify = bgp_nb_maxpaths_ibgp_cluster_modify,
				.destroy = bgp_nb_maxpaths_ibgp_cluster_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list",
			.cbs = {
				.create = bgp_nb_redistribute_create,
				.destroy = bgp_nb_redistribute_destroy,
				.cli_show = bgp_nb_cli_show_redistribute,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/metric",
			.cbs = {
				.modify = bgp_nb_redistribute_metric_modify,
				.destroy = bgp_nb_redistribute_metric_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = bgp_nb_redistribute_rmap_modify,
				.destroy = bgp_nb_redistribute_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list",
			.cbs = {
				.create = bgp_nb_redistribute_create,
				.destroy = bgp_nb_redistribute_destroy,
				.cli_show = bgp_nb_cli_show_redistribute,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/metric",
			.cbs = {
				.modify = bgp_nb_redistribute_metric_modify,
				.destroy = bgp_nb_redistribute_metric_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/rmap-policy-import",
			.cbs = {
				.modify = bgp_nb_redistribute_rmap_modify,
				.destroy = bgp_nb_redistribute_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/external",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/local",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/external",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/local",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route",
			.cbs = {
				.create = bgp_nb_distance_route_create,
				.destroy = bgp_nb_distance_route_destroy,
				.cli_show = bgp_nb_cli_show_distance_route,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_nb_distance_route_distance_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/access-list",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route",
			.cbs = {
				.create = bgp_nb_distance_route_create,
				.destroy = bgp_nb_distance_route_destroy,
				.cli_show = bgp_nb_cli_show_distance_route,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_nb_distance_route_distance_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/access-list",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/external",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/local",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/external",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/internal",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/local",
			.cbs = {
				.modify = bgp_nb_distance_bgp_modify,
				.cli_show = bgp_nb_cli_show_distance_bgp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route",
			.cbs = {
				.create = bgp_nb_distance_route_create,
				.destroy = bgp_nb_distance_route_destroy,
				.cli_show = bgp_nb_cli_show_distance_route,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_nb_distance_route_distance_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/access-list",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route",
			.cbs = {
				.create = bgp_nb_distance_route_create,
				.destroy = bgp_nb_distance_route_destroy,
				.cli_show = bgp_nb_cli_show_distance_route,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/distance",
			.cbs = {
				.modify = bgp_nb_distance_route_distance_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/access-list",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_table_map_modify,
				.destroy = bgp_nb_table_map_destroy,
				.cli_show = bgp_nb_cli_show_table_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_table_map_modify,
				.destroy = bgp_nb_table_map_destroy,
				.cli_show = bgp_nb_cli_show_table_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_table_map_modify,
				.destroy = bgp_nb_table_map_destroy,
				.cli_show = bgp_nb_cli_show_table_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/prefer-global",
			.cbs = {
				.modify = bgp_nb_nexthop_prefer_global_modify,
				.cli_show = bgp_nb_cli_show_nexthop_prefer_global,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/prefer-global",
			.cbs = {
				.modify = bgp_nb_nexthop_prefer_global_modify,
				.cli_show = bgp_nb_cli_show_nexthop_prefer_global,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/prefer-global",
			.cbs = {
				.modify = bgp_nb_nexthop_prefer_global_modify,
				.cli_show = bgp_nb_cli_show_nexthop_prefer_global,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-all-vni",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_all_vni_modify,
				.cli_show = bgp_nb_cli_show_evpn_advertise_all_vni,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/import-autort-rfc8365-compatible",
			.cbs = {
				.modify = bgp_nb_evpn_autort_rfc8365_modify,
				.cli_show = bgp_nb_cli_show_evpn_autort_rfc8365,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/export-autort-rfc8365-compatible",
			.cbs = {
				.modify = bgp_nb_evpn_autort_rfc8365_modify,
				.cli_show = bgp_nb_cli_show_evpn_autort_rfc8365,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-default-gateway",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_default_gw_modify,
				.cli_show = bgp_nb_cli_show_evpn_advertise_default_gw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-svi-ip",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_svi_ip_modify,
				.cli_show = bgp_nb_cli_show_evpn_advertise_svi_ip,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/enable-resolve-overlay-index",
			.cbs = {
				.modify = bgp_nb_evpn_resolve_overlay_modify,
				.cli_show = bgp_nb_cli_show_evpn_resolve_overlay,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/flooding",
			.cbs = {
				.modify = bgp_nb_evpn_flooding_modify,
				.cli_show = bgp_nb_cli_show_evpn_flooding,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/mac-vrf-site-of-origin",
			.cbs = {
				.modify = bgp_nb_evpn_macvrf_soo_modify,
				.destroy = bgp_nb_evpn_macvrf_soo_destroy,
				.cli_show = bgp_nb_cli_show_evpn_macvrf_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/duplicate-address-detection/enable",
			.cbs = {
				.modify = bgp_nb_evpn_dad_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_dad_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/duplicate-address-detection/max-moves",
			.cbs = {
				.modify = bgp_nb_evpn_dad_param_modify,
				.cli_show = bgp_nb_cli_show_evpn_dad_max_moves,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/duplicate-address-detection/time",
			.cbs = {
				.modify = bgp_nb_evpn_dad_param_modify,
				.cli_show = bgp_nb_cli_show_evpn_dad_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/duplicate-address-detection/freeze-time",
			.cbs = {
				.modify = bgp_nb_evpn_dad_param_modify,
				.destroy = bgp_nb_evpn_dad_param_destroy,
				.cli_show = bgp_nb_cli_show_evpn_dad_freeze_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/duplicate-address-detection/freeze-permanent",
			.cbs = {
				.create = bgp_nb_evpn_dad_freeze_permanent_create,
				.destroy = bgp_nb_evpn_dad_freeze_permanent_destroy,
				.cli_show = bgp_nb_cli_show_evpn_dad_freeze_permanent,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/multihoming/use-es-l3nhg",
			.cbs = {
				.modify = bgp_nb_evpn_use_es_l3nhg_modify,
				.cli_show = bgp_nb_cli_show_evpn_use_es_l3nhg,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/multihoming/disable-ead-evi-rx",
			.cbs = {
				.modify = bgp_nb_evpn_disable_ead_evi_rx_modify,
				.cli_show = bgp_nb_cli_show_evpn_disable_ead_evi_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/multihoming/disable-ead-evi-tx",
			.cbs = {
				.modify = bgp_nb_evpn_disable_ead_evi_tx_modify,
				.cli_show = bgp_nb_cli_show_evpn_disable_ead_evi_tx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/multihoming/ead-es-fragment-evi-limit",
			.cbs = {
				.modify = bgp_nb_evpn_ead_es_frag_modify,
				.destroy = bgp_nb_evpn_ead_es_frag_destroy,
				.cli_show = bgp_nb_cli_show_evpn_ead_es_frag,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/default-originate/ipv4",
			.cbs = {
				.modify = bgp_nb_evpn_default_originate_modify,
				.cli_show = bgp_nb_cli_show_evpn_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/default-originate/ipv6",
			.cbs = {
				.modify = bgp_nb_evpn_default_originate_modify,
				.cli_show = bgp_nb_cli_show_evpn_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-unicast/enable",
			.cbs = {
				.modify = bgp_nb_evpn_type5_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_type5_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-unicast/gateway-ip",
			.cbs = {
				.modify = bgp_nb_evpn_type5_gateway_ip_modify,
				.destroy = bgp_nb_evpn_type5_gateway_ip_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-unicast/route-map",
			.cbs = {
				.modify = bgp_nb_evpn_type5_route_map_modify,
				.destroy = bgp_nb_evpn_type5_route_map_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-unicast/skip-evpn-imported",
			.cbs = {
				.modify = bgp_nb_evpn_type5_skip_evpn_imported_modify,
				.destroy = bgp_nb_evpn_type5_skip_evpn_imported_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-vpn/enable",
			.cbs = {
				.modify = bgp_nb_evpn_type5_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_type5_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv4-vpn/route-map",
			.cbs = {
				.modify = bgp_nb_evpn_type5_route_map_modify,
				.destroy = bgp_nb_evpn_type5_route_map_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-unicast/enable",
			.cbs = {
				.modify = bgp_nb_evpn_type5_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_type5_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-unicast/gateway-ip",
			.cbs = {
				.modify = bgp_nb_evpn_type5_gateway_ip_modify,
				.destroy = bgp_nb_evpn_type5_gateway_ip_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-unicast/route-map",
			.cbs = {
				.modify = bgp_nb_evpn_type5_route_map_modify,
				.destroy = bgp_nb_evpn_type5_route_map_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-unicast/skip-evpn-imported",
			.cbs = {
				.modify = bgp_nb_evpn_type5_skip_evpn_imported_modify,
				.destroy = bgp_nb_evpn_type5_skip_evpn_imported_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-vpn/enable",
			.cbs = {
				.modify = bgp_nb_evpn_type5_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_type5_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/ipv6-vpn/route-map",
			.cbs = {
				.modify = bgp_nb_evpn_type5_route_map_modify,
				.destroy = bgp_nb_evpn_type5_route_map_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-pip/enable",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_pip_enable_modify,
				.cli_show = bgp_nb_cli_show_evpn_advertise_pip_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-pip/system-ip",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_pip_param_modify,
				.destroy = bgp_nb_evpn_advertise_pip_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/advertise-pip/system-mac",
			.cbs = {
				.modify = bgp_nb_evpn_advertise_pip_param_modify,
				.destroy = bgp_nb_evpn_advertise_pip_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/multihoming/ead-es-export-route-target",
			.cbs = {
				.create = bgp_nb_evpn_ead_es_rt_create,
				.destroy = bgp_nb_evpn_ead_es_rt_destroy,
				.cli_show = bgp_nb_cli_show_evpn_ead_es_rt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/rd",
			.cbs = {
				.modify = bgp_nb_evpn_vrf_rd_modify,
				.destroy = bgp_nb_evpn_vrf_rd_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vrf_rd,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/import-route-target",
			.cbs = {
				.create = bgp_nb_evpn_vrf_rt_create,
				.destroy = bgp_nb_evpn_vrf_rt_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vrf_rt_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/export-route-target",
			.cbs = {
				.create = bgp_nb_evpn_vrf_rt_create,
				.destroy = bgp_nb_evpn_vrf_rt_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vrf_rt_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/import-auto-route-target",
			.cbs = {
				.modify = bgp_nb_evpn_vrf_rt_auto_modify,
				.destroy = bgp_nb_evpn_vrf_rt_auto_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vrf_rt_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/ip-vrf/export-auto-route-target",
			.cbs = {
				.modify = bgp_nb_evpn_vrf_rt_auto_modify,
				.destroy = bgp_nb_evpn_vrf_rt_auto_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vrf_rt_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni",
			.cbs = {
				.create = bgp_nb_evpn_vni_create,
				.destroy = bgp_nb_evpn_vni_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni,
				.cli_show_end = bgp_nb_cli_show_evpn_vni_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/rd",
			.cbs = {
				.modify = bgp_nb_evpn_vni_rd_modify,
				.destroy = bgp_nb_evpn_vni_rd_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni_rd,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/import-route-target",
			.cbs = {
				.create = bgp_nb_evpn_vni_rt_create,
				.destroy = bgp_nb_evpn_vni_rt_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni_rt_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/export-route-target",
			.cbs = {
				.create = bgp_nb_evpn_vni_rt_create,
				.destroy = bgp_nb_evpn_vni_rt_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni_rt_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/import-auto-route-target",
			.cbs = {
				.modify = bgp_nb_evpn_vni_rt_auto_modify,
				.destroy = bgp_nb_evpn_vni_rt_auto_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni_rt_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/export-auto-route-target",
			.cbs = {
				.modify = bgp_nb_evpn_vni_rt_auto_modify,
				.destroy = bgp_nb_evpn_vni_rt_auto_destroy,
				.cli_show = bgp_nb_cli_show_evpn_vni_rt_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/advertise-default-gateway",
			.cbs = {
				.modify = bgp_nb_evpn_vni_advertise_default_gw_modify,
				.cli_show = bgp_nb_cli_show_evpn_vni_advertise_default_gw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/advertise-svi-ip",
			.cbs = {
				.modify = bgp_nb_evpn_vni_advertise_svi_ip_modify,
				.cli_show = bgp_nb_cli_show_evpn_vni_advertise_svi_ip,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/advertise-subnet",
			.cbs = {
				.modify = bgp_nb_evpn_vni_advertise_subnet_modify,
				.cli_show = bgp_nb_cli_show_evpn_vni_advertise_subnet,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l2vpn-evpn/vni/flooding",
			.cbs = {
				.modify = bgp_nb_evpn_vni_flooding_modify,
				.cli_show = bgp_nb_cli_show_evpn_vni_flooding,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_dampening_param_modify,
				.destroy = bgp_nb_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/upa/originate-all",
			.cbs = {
				.modify = bgp_nb_upa_originate_modify,
				.cli_show = bgp_nb_cli_show_upa_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/upa/max-routes",
			.cbs = {
				.modify = bgp_nb_upa_max_routes_modify,
				.cli_show = bgp_nb_cli_show_upa_max_routes,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/upa/drop",
			.cbs = {
				.modify = bgp_nb_upa_drop_modify,
				.cli_show = bgp_nb_cli_show_upa_drop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/upa/originate-all",
			.cbs = {
				.modify = bgp_nb_upa_originate_modify,
				.cli_show = bgp_nb_cli_show_upa_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/upa/max-routes",
			.cbs = {
				.modify = bgp_nb_upa_max_routes_modify,
				.cli_show = bgp_nb_cli_show_upa_max_routes,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/upa/drop",
			.cbs = {
				.modify = bgp_nb_upa_drop_modify,
				.cli_show = bgp_nb_cli_show_upa_drop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = bgp_nb_vpn_import_modify,
				.cli_show = bgp_nb_cli_show_vpn_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = bgp_nb_vpn_export_modify,
				.cli_show = bgp_nb_cli_show_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vpn",
			.cbs = {
				.modify = bgp_nb_vpn_import_modify,
				.cli_show = bgp_nb_cli_show_vpn_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-vpn",
			.cbs = {
				.modify = bgp_nb_vpn_export_modify,
				.cli_show = bgp_nb_cli_show_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_vpn_rmap_import_modify,
				.destroy = bgp_nb_vpn_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_vpn_rmap_export_modify,
				.destroy = bgp_nb_vpn_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_vpn_rmap_import_modify,
				.destroy = bgp_nb_vpn_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_vpn_rmap_export_modify,
				.destroy = bgp_nb_vpn_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rd",
			.cbs = {
				.modify = bgp_nb_vpn_rd_modify,
				.destroy = bgp_nb_vpn_rd_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rd,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rd",
			.cbs = {
				.modify = bgp_nb_vpn_rd_modify,
				.destroy = bgp_nb_vpn_rd_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rd,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label",
			.cbs = {
				.modify = bgp_nb_vpn_label_modify,
				.destroy = bgp_nb_vpn_label_destroy,
				.cli_show = bgp_nb_cli_show_vpn_label,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = bgp_nb_vpn_label_auto_modify,
				.destroy = bgp_nb_vpn_label_auto_destroy,
				.cli_show = bgp_nb_cli_show_vpn_label_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-allocation-mode",
			.cbs = {
				.modify = bgp_nb_vpn_label_alloc_mode_modify,
				.cli_show = bgp_nb_cli_show_vpn_label_alloc_mode,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label",
			.cbs = {
				.modify = bgp_nb_vpn_label_modify,
				.destroy = bgp_nb_vpn_label_destroy,
				.cli_show = bgp_nb_cli_show_vpn_label,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label-auto",
			.cbs = {
				.modify = bgp_nb_vpn_label_auto_modify,
				.destroy = bgp_nb_vpn_label_auto_destroy,
				.cli_show = bgp_nb_cli_show_vpn_label_auto,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-allocation-mode",
			.cbs = {
				.modify = bgp_nb_vpn_label_alloc_mode_modify,
				.cli_show = bgp_nb_cli_show_vpn_label_alloc_mode,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = bgp_nb_vpn_nexthop_modify,
				.destroy = bgp_nb_vpn_nexthop_destroy,
				.cli_show = bgp_nb_cli_show_vpn_nexthop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/nexthop",
			.cbs = {
				.modify = bgp_nb_vpn_nexthop_modify,
				.destroy = bgp_nb_vpn_nexthop_destroy,
				.cli_show = bgp_nb_cli_show_vpn_nexthop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = bgp_nb_vpn_rt_import_create,
				.destroy = bgp_nb_vpn_rt_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rt_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = bgp_nb_vpn_rt_export_create,
				.destroy = bgp_nb_vpn_rt_export_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rt_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-rt-list",
			.cbs = {
				.create = bgp_nb_vpn_rt_import_create,
				.destroy = bgp_nb_vpn_rt_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rt_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-rt-list",
			.cbs = {
				.create = bgp_nb_vpn_rt_export_create,
				.destroy = bgp_nb_vpn_rt_export_destroy,
				.cli_show = bgp_nb_cli_show_vpn_rt_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = bgp_nb_vpn_import_vrf_create,
				.destroy = bgp_nb_vpn_import_vrf_destroy,
				.cli_show = bgp_nb_cli_show_vpn_import_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vrf-list",
			.cbs = {
				.create = bgp_nb_vpn_import_vrf_create,
				.destroy = bgp_nb_vpn_import_vrf_destroy,
				.cli_show = bgp_nb_cli_show_vpn_import_vrf,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/vrf-rmap-import",
			.cbs = {
				.modify = bgp_nb_vpn_vrf_rmap_import_modify,
				.destroy = bgp_nb_vpn_vrf_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_vrf_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/vrf-rmap-import",
			.cbs = {
				.modify = bgp_nb_vpn_vrf_rmap_import_modify,
				.destroy = bgp_nb_vpn_vrf_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_vpn_vrf_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config",
			.cbs = {
				.create = bgp_nb_vpn_network_rd_create,
				.destroy = bgp_nb_vpn_network_rd_destroy,
				.flags = F_NB_CB_DESTROY_RECURSE,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list",
			.cbs = {
				.create = bgp_nb_vpn_network_prefix_create,
				.destroy = bgp_nb_vpn_network_prefix_destroy,
				.cli_show = bgp_nb_cli_show_vpn_network_prefix,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = bgp_nb_vpn_network_label_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_vpn_network_rmap_modify,
				.destroy = bgp_nb_vpn_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config",
			.cbs = {
				.create = bgp_nb_vpn_network_rd_create,
				.destroy = bgp_nb_vpn_network_rd_destroy,
				.flags = F_NB_CB_DESTROY_RECURSE,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list",
			.cbs = {
				.create = bgp_nb_vpn_network_prefix_create,
				.destroy = bgp_nb_vpn_network_prefix_destroy,
				.cli_show = bgp_nb_cli_show_vpn_network_prefix,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/label-index",
			.cbs = {
				.modify = bgp_nb_vpn_network_label_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/rmap-policy-export",
			.cbs = {
				.modify = bgp_nb_vpn_network_rmap_modify,
				.destroy = bgp_nb_vpn_network_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/retain-route-target-all",
			.cbs = {
				.modify = bgp_nb_vpn_retain_rt_modify,
				.cli_show = bgp_nb_cli_show_vpn_retain_rt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/retain-route-target-all",
			.cbs = {
				.modify = bgp_nb_vpn_retain_rt_modify,
				.cli_show = bgp_nb_cli_show_vpn_retain_rt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = bgp_nb_vpn_redirect_rt_modify,
				.destroy = bgp_nb_vpn_redirect_rt_destroy,
				.cli_show = bgp_nb_cli_show_vpn_redirect_rt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/redirect-rt-ipv6",
			.cbs = {
				.modify = bgp_nb_vpn_redirect_rt_ipv6_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/redirect-rt",
			.cbs = {
				.modify = bgp_nb_vpn_redirect_rt_modify,
				.destroy = bgp_nb_vpn_redirect_rt_destroy,
				.cli_show = bgp_nb_cli_show_vpn_redirect_rt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/redirect-rt-ipv6",
			.cbs = {
				.modify = bgp_nb_vpn_redirect_rt_ipv6_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/sid-vpn-export/sid-index",
			.cbs = {
				.modify = bgp_nb_sid_vpn_export_index_modify,
				.destroy = bgp_nb_sid_vpn_export_index_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/sid-vpn-export/sid-auto",
			.cbs = {
				.create = bgp_nb_sid_vpn_export_auto_create,
				.destroy = bgp_nb_sid_vpn_export_auto_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/sid-vpn-export/sid-explicit",
			.cbs = {
				.modify = bgp_nb_sid_vpn_export_explicit_modify,
				.destroy = bgp_nb_sid_vpn_export_explicit_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/sid-vpn-export/sid-index",
			.cbs = {
				.modify = bgp_nb_sid_vpn_export_index_modify,
				.destroy = bgp_nb_sid_vpn_export_index_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/sid-vpn-export/sid-auto",
			.cbs = {
				.create = bgp_nb_sid_vpn_export_auto_create,
				.destroy = bgp_nb_sid_vpn_export_auto_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/sid-vpn-export/sid-explicit",
			.cbs = {
				.modify = bgp_nb_sid_vpn_export_explicit_modify,
				.destroy = bgp_nb_sid_vpn_export_explicit_destroy,
				.cli_show = bgp_nb_cli_show_sid_vpn_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-export/sid-index",
			.cbs = {
				.modify = bgp_nb_sid_export_index_modify,
				.destroy = bgp_nb_sid_export_index_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-export/sid-auto",
			.cbs = {
				.create = bgp_nb_sid_export_auto_create,
				.destroy = bgp_nb_sid_export_auto_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-export/sid-explicit",
			.cbs = {
				.modify = bgp_nb_sid_export_explicit_modify,
				.destroy = bgp_nb_sid_export_explicit_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-export/behavior-dt46",
			.cbs = {
				.modify = bgp_nb_sid_export_dt46_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/sid-export/route-map",
			.cbs = {
				.modify = bgp_nb_sid_export_rmap_modify,
				.destroy = bgp_nb_sid_export_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-export/sid-index",
			.cbs = {
				.modify = bgp_nb_sid_export_index_modify,
				.destroy = bgp_nb_sid_export_index_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-export/sid-auto",
			.cbs = {
				.create = bgp_nb_sid_export_auto_create,
				.destroy = bgp_nb_sid_export_auto_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-export/sid-explicit",
			.cbs = {
				.modify = bgp_nb_sid_export_explicit_modify,
				.destroy = bgp_nb_sid_export_explicit_destroy,
				.cli_show = bgp_nb_cli_show_sid_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-export/behavior-dt46",
			.cbs = {
				.modify = bgp_nb_sid_export_dt46_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/sid-export/route-map",
			.cbs = {
				.modify = bgp_nb_sid_export_rmap_modify,
				.destroy = bgp_nb_sid_export_rmap_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier",
			.cbs = {
				.modify = bgp_nb_confederation_identifier_modify,
				.destroy = bgp_nb_confederation_identifier_destroy,
				.cli_show = bgp_nb_cli_show_confederation_identifier,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as",
			.cbs = {
				.create = bgp_nb_confederation_member_as_create,
				.destroy = bgp_nb_confederation_member_as_destroy,
				.cli_show = bgp_nb_cli_show_confederation_member_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/enable-med-admin",
			.cbs = {
				.modify = bgp_nb_enable_med_admin_modify,
				.cli_show = bgp_nb_cli_show_enable_med_admin,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-admin",
			.cbs = {
				.modify = bgp_nb_max_med_admin_modify,
				.cli_show = bgp_nb_cli_show_max_med_admin,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-time",
			.cbs = {
				.modify = bgp_nb_max_med_onstartup_time_modify,
				.destroy = bgp_nb_max_med_onstartup_time_destroy,
				.cli_show = bgp_nb_cli_show_max_med_onstartup_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-value",
			.cbs = {
				.modify = bgp_nb_max_med_onstartup_value_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/dynamic-neighbors-limit",
			.cbs = {
				.modify = bgp_nb_dynamic_neighbors_limit_modify,
				.destroy = bgp_nb_dynamic_neighbors_limit_destroy,
				.cli_show = bgp_nb_cli_show_dynamic_neighbors_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-afi-safi",
			.cbs = {
				.create = bgp_nb_default_afi_safi_create,
				.destroy = bgp_nb_default_afi_safi_destroy,
				.cli_show = bgp_nb_cli_show_default_afi_safi,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/stale-routes-time",
			.cbs = {
				.modify = bgp_nb_gr_stale_routes_time_modify,
				.cli_show = bgp_nb_cli_show_gr_stale_routes_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/restart-time",
			.cbs = {
				.modify = bgp_nb_gr_restart_time_modify,
				.cli_show = bgp_nb_cli_show_gr_restart_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/selection-deferral-time",
			.cbs = {
				.modify = bgp_nb_gr_select_defer_time_modify,
				.cli_show = bgp_nb_cli_show_gr_select_defer_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = bgp_nb_gr_rib_stale_time_modify,
				.cli_show = bgp_nb_cli_show_gr_rib_stale_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/preserve-fw-entry",
			.cbs = {
				.modify = bgp_nb_gr_preserve_fw_modify,
				.cli_show = bgp_nb_cli_show_gr_preserve_fw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/notification",
			.cbs = {
				.modify = bgp_nb_gr_notification_modify,
				.destroy = bgp_nb_gr_notification_destroy,
				.cli_show = bgp_nb_cli_show_gr_notification,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/disable-eor",
			.cbs = {
				.modify = bgp_nb_gr_disable_eor_modify,
				.cli_show = bgp_nb_cli_show_gr_disable_eor,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/long-lived-stale-time",
			.cbs = {
				.modify = bgp_nb_gr_llgr_stale_time_modify,
				.destroy = bgp_nb_gr_llgr_stale_time_destroy,
				.cli_show = bgp_nb_cli_show_gr_llgr_stale_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled",
			.cbs = {
				.modify = bgp_nb_gr_enabled_modify,
				.destroy = bgp_nb_gr_enabled_destroy,
				.cli_show = bgp_nb_cli_show_gr_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_nb_gr_disable_modify,
				.destroy = bgp_nb_gr_disable_destroy,
				.cli_show = bgp_nb_cli_show_gr_disable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/tcp-keepalive/idle",
			.cbs = {
				.modify = bgp_nb_tcp_keepalive_idle_modify,
				.destroy = bgp_nb_tcp_keepalive_idle_destroy,
				.cli_show = bgp_nb_cli_show_tcp_keepalive_idle,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/tcp-keepalive/interval",
			.cbs = {
				.modify = bgp_nb_tcp_keepalive_interval_modify,
				.destroy = bgp_nb_tcp_keepalive_interval_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/tcp-keepalive/probes",
			.cbs = {
				.modify = bgp_nb_tcp_keepalive_probes_modify,
				.destroy = bgp_nb_tcp_keepalive_probes_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta",
			.cbs = {
				.modify = bgp_nb_wpkt_quanta_modify,
				.cli_show = bgp_nb_cli_show_wpkt_quanta,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta",
			.cbs = {
				.modify = bgp_nb_rpkt_quanta_modify,
				.cli_show = bgp_nb_cli_show_rpkt_quanta,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/coalesce-time",
			.cbs = {
				.modify = bgp_nb_coalesce_time_modify,
				.cli_show = bgp_nb_cli_show_coalesce_time,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size",
			.cbs = {
				.modify = bgp_nb_subgroup_pkt_queue_size_modify,
				.cli_show = bgp_nb_cli_show_subgroup_pkt_queue_size,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-originate-set-only-unconditional",
			.cbs = {
				.modify = bgp_nb_default_originate_setonly_modify,
				.cli_show = bgp_nb_cli_show_default_originate_setonly,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-shutdown",
			.cbs = {
				.modify = bgp_nb_default_shutdown_modify,
				.cli_show = bgp_nb_cli_show_default_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/shutdown",
			.cbs = {
				.modify = bgp_nb_shutdown_modify,
				.cli_show = bgp_nb_cli_show_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/shutdown-message",
			.cbs = {
				.modify = bgp_nb_shutdown_message_modify,
				.destroy = bgp_nb_shutdown_message_destroy,
				.cli_show = bgp_nb_cli_show_shutdown_message,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/shutdown-no-notify",
			.cbs = {
				.modify = bgp_nb_shutdown_no_notify_modify,
				.destroy = bgp_nb_shutdown_no_notify_destroy,
				.cli_show = bgp_nb_cli_show_shutdown_no_notify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/allow-martian-nexthop",
			.cbs = {
				.modify = bgp_nb_allow_martian_modify,
				.cli_show = bgp_nb_cli_show_allow_martian,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/use-underlays-nexthop-weight",
			.cbs = {
				.modify = bgp_nb_use_underlays_nexthop_weight_modify,
				.cli_show = bgp_nb_cli_show_use_underlays_nexthop_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-fib-pending",
			.cbs = {
				.modify = bgp_nb_suppress_fib_pending_modify,
				.cli_show = bgp_nb_cli_show_suppress_fib_pending,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-fib-pending-delay",
			.cbs = {
				.modify = bgp_nb_suppress_fib_pending_delay_modify,
				.destroy = bgp_nb_suppress_fib_pending_delay_destroy,
				.cli_show = bgp_nb_cli_show_suppress_fib_pending_delay,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-convergence",
			.cbs = {
				.modify = bgp_nb_fast_convergence_modify,
				.cli_show = bgp_nb_cli_show_fast_convergence,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ipv6-auto-ra",
			.cbs = {
				.modify = bgp_nb_ipv6_auto_ra_modify,
				.cli_show = bgp_nb_cli_show_ipv6_auto_ra,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/labeled-unicast-explicit-null",
			.cbs = {
				.modify = bgp_nb_labeled_unicast_explicit_null_modify,
				.cli_show = bgp_nb_cli_show_labeled_unicast_explicit_null,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-dynamic-capability",
			.cbs = {
				.modify = bgp_nb_default_dynamic_capability_modify,
				.cli_show = bgp_nb_cli_show_default_dynamic_capability,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-link-local-capability",
			.cbs = {
				.modify = bgp_nb_default_link_local_capability_modify,
				.cli_show = bgp_nb_cli_show_default_link_local_capability,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-software-version-capability",
			.cbs = {
				.modify = bgp_nb_default_software_version_capability_modify,
				.cli_show = bgp_nb_cli_show_default_software_version_capability,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor",
			.cbs = {
				.create = bgp_nb_neighbor_create,
				.destroy = bgp_nb_neighbor_destroy,
				.cli_show = bgp_nb_cli_show_neighbor,
				.cli_show_end = bgp_nb_cli_show_neighbor_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_nb_neighbor_remote_as_type_modify,
				.destroy = bgp_nb_neighbor_remote_as_type_destroy,
				.cli_show = bgp_nb_cli_show_neighbor_remote_as_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_nb_neighbor_remote_as_modify,
				.destroy = bgp_nb_neighbor_remote_as_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group",
			.cbs = {
				.create = bgp_nb_peer_group_create,
				.destroy = bgp_nb_peer_group_destroy,
				.cli_show = bgp_nb_cli_show_peer_group,
				.cli_show_end = bgp_nb_cli_show_peer_group_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_nb_peer_group_remote_as_type_modify,
				.destroy = bgp_nb_peer_group_remote_as_type_destroy,
				.cli_show = bgp_nb_cli_show_peer_group_remote_as_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_nb_peer_group_remote_as_modify,
				.destroy = bgp_nb_peer_group_remote_as_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv4-listen-range",
			.cbs = {
				.create = bgp_nb_peer_group_listen_range_create,
				.destroy = bgp_nb_peer_group_listen_range_destroy,
				.cli_show = bgp_nb_cli_show_peer_group_listen_range,
			},
			/*
			 * A listen range can only be added once the group has a
			 * remote-as, so it must be applied after its siblings.
			 */
			.priority = NB_DFLT_PRIORITY + 1,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv6-listen-range",
			.cbs = {
				.create = bgp_nb_peer_group_listen_range_create,
				.destroy = bgp_nb_peer_group_listen_range_destroy,
				.cli_show = bgp_nb_cli_show_peer_group_listen_range,
			},
			.priority = NB_DFLT_PRIORITY + 1,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor",
			.cbs = {
				.create = bgp_nb_unnumbered_neighbor_create,
				.destroy = bgp_nb_unnumbered_neighbor_destroy,
				.cli_show = bgp_nb_cli_show_unnumbered_neighbor,
				.cli_show_end = bgp_nb_cli_show_unnumbered_neighbor_end,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/v6only",
			.cbs = {
				.modify = bgp_nb_unnumbered_v6only_modify,
				.cli_show = bgp_nb_cli_show_unnumbered_v6only,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/peer-group",
			.cbs = {
				.modify = bgp_nb_unnumbered_peer_group_modify,
				.destroy = bgp_nb_unnumbered_peer_group_destroy,
				.cli_show = bgp_nb_cli_show_unnumbered_peer_group,
			},
			/* Same create-then-bind ordering as numbered neighbors. */
			.priority = NB_DFLT_PRIORITY + 1,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_nb_neighbor_remote_as_type_modify,
				.destroy = bgp_nb_neighbor_remote_as_type_destroy,
				.cli_show = bgp_nb_cli_show_neighbor_remote_as_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify = bgp_nb_neighbor_remote_as_modify,
				.destroy = bgp_nb_neighbor_remote_as_destroy,
			},
		},
		/* Shared session leaves: numbered neighbor */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/password",
			.cbs = {
				.modify = bgp_nb_peer_password_modify,
				.destroy = bgp_nb_peer_password_destroy,
				.cli_show = bgp_nb_cli_show_peer_password,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/description",
			.cbs = {
				.modify = bgp_nb_peer_description_modify,
				.destroy = bgp_nb_peer_description_destroy,
				.cli_show = bgp_nb_cli_show_peer_description,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_local_link_id_modify,
				.destroy = bgp_nb_peer_ls_local_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_local_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/remote-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_remote_link_id_modify,
				.destroy = bgp_nb_peer_ls_remote_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_remote_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/passive-mode",
			.cbs = {
				.modify = bgp_nb_peer_passive_modify,
				.cli_show = bgp_nb_cli_show_peer_passive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/solo",
			.cbs = {
				.modify = bgp_nb_peer_solo_modify,
				.cli_show = bgp_nb_cli_show_peer_solo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_enable_modify,
				.destroy = bgp_nb_peer_shutdown_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/message",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_message_modify,
				.destroy = bgp_nb_peer_shutdown_message_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_message,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/rtt",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_rtt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/rtt-count",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_count_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_count_destroy,
			},
		},
		/* Shared session leaves: unnumbered */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/password",
			.cbs = {
				.modify = bgp_nb_peer_password_modify,
				.destroy = bgp_nb_peer_password_destroy,
				.cli_show = bgp_nb_cli_show_peer_password,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/description",
			.cbs = {
				.modify = bgp_nb_peer_description_modify,
				.destroy = bgp_nb_peer_description_destroy,
				.cli_show = bgp_nb_cli_show_peer_description,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_local_link_id_modify,
				.destroy = bgp_nb_peer_ls_local_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_local_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/remote-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_remote_link_id_modify,
				.destroy = bgp_nb_peer_ls_remote_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_remote_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/passive-mode",
			.cbs = {
				.modify = bgp_nb_peer_passive_modify,
				.cli_show = bgp_nb_cli_show_peer_passive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/solo",
			.cbs = {
				.modify = bgp_nb_peer_solo_modify,
				.cli_show = bgp_nb_cli_show_peer_solo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_enable_modify,
				.destroy = bgp_nb_peer_shutdown_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/message",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_message_modify,
				.destroy = bgp_nb_peer_shutdown_message_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_message,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/rtt",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_rtt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/rtt-count",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_count_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_count_destroy,
			},
		},
		/* Shared session leaves: peer-group */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/password",
			.cbs = {
				.modify = bgp_nb_peer_password_modify,
				.destroy = bgp_nb_peer_password_destroy,
				.cli_show = bgp_nb_cli_show_peer_password,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/description",
			.cbs = {
				.modify = bgp_nb_peer_description_modify,
				.destroy = bgp_nb_peer_description_destroy,
				.cli_show = bgp_nb_cli_show_peer_description,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_local_link_id_modify,
				.destroy = bgp_nb_peer_ls_local_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_local_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/remote-link-id",
			.cbs = {
				.modify = bgp_nb_peer_ls_remote_link_id_modify,
				.destroy = bgp_nb_peer_ls_remote_link_id_destroy,
				.cli_show = bgp_nb_cli_show_peer_ls_remote_link_id,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/passive-mode",
			.cbs = {
				.modify = bgp_nb_peer_passive_modify,
				.cli_show = bgp_nb_cli_show_peer_passive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/solo",
			.cbs = {
				.modify = bgp_nb_peer_solo_modify,
				.cli_show = bgp_nb_cli_show_peer_solo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/enable",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_enable_modify,
				.destroy = bgp_nb_peer_shutdown_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/message",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_message_modify,
				.destroy = bgp_nb_peer_shutdown_message_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_message,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/rtt",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_destroy,
				.cli_show = bgp_nb_cli_show_peer_shutdown_rtt,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/rtt-count",
			.cbs = {
				.modify = bgp_nb_peer_shutdown_rtt_count_modify,
				.destroy = bgp_nb_peer_shutdown_rtt_count_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/ip",
			.cbs = {
				.modify = bgp_nb_peer_update_source_ip_modify,
				.destroy = bgp_nb_peer_update_source_ip_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_ip,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/interface",
			.cbs = {
				.modify = bgp_nb_peer_update_source_if_modify,
				.destroy = bgp_nb_peer_update_source_if_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_if,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_enabled_modify,
				.destroy = bgp_nb_peer_ebgp_mh_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_ttl_modify,
				.destroy = bgp_nb_peer_ebgp_mh_ttl_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_ttl,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_nb_peer_disable_connected_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_connected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ttl-security",
			.cbs = {
				.modify = bgp_nb_peer_ttl_security_modify,
				.destroy = bgp_nb_peer_ttl_security_destroy,
				.cli_show = bgp_nb_cli_show_peer_ttl_security,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/local-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_modify,
				.destroy = bgp_nb_peer_local_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-prepend",
			.cbs = {
				.modify = bgp_nb_peer_local_as_no_prepend_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/replace-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_replace_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/dual-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_dual_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/keepalive",
			.cbs = {
				.modify = bgp_nb_peer_timers_keepalive_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_keepalive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/hold-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_holdtime_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_holdtime,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/connect-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_connect_modify,
				.destroy = bgp_nb_peer_timers_connect_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_connect,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/delayopen",
			.cbs = {
				.modify = bgp_nb_peer_timers_delayopen_modify,
				.destroy = bgp_nb_peer_timers_delayopen_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_delayopen,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/advertise-interval",
			.cbs = {
				.modify = bgp_nb_peer_advertise_interval_modify,
				.destroy = bgp_nb_peer_advertise_interval_destroy,
				.cli_show = bgp_nb_cli_show_peer_advertise_interval,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_dynamic_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_dynamic,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_enhe_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_enhe,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_nb_peer_cap_negotiate_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_negotiate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/fqdn-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_fqdn_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_fqdn,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/enforce-first-as",
			.cbs = {
				.modify = bgp_nb_peer_enforce_first_as_modify,
				.cli_show = bgp_nb_cli_show_peer_enforce_first_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/ip",
			.cbs = {
				.modify = bgp_nb_peer_update_source_ip_modify,
				.destroy = bgp_nb_peer_update_source_ip_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_ip,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/interface",
			.cbs = {
				.modify = bgp_nb_peer_update_source_if_modify,
				.destroy = bgp_nb_peer_update_source_if_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_if,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_enabled_modify,
				.destroy = bgp_nb_peer_ebgp_mh_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_ttl_modify,
				.destroy = bgp_nb_peer_ebgp_mh_ttl_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_ttl,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_nb_peer_disable_connected_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_connected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ttl-security",
			.cbs = {
				.modify = bgp_nb_peer_ttl_security_modify,
				.destroy = bgp_nb_peer_ttl_security_destroy,
				.cli_show = bgp_nb_cli_show_peer_ttl_security,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/local-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_modify,
				.destroy = bgp_nb_peer_local_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-prepend",
			.cbs = {
				.modify = bgp_nb_peer_local_as_no_prepend_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/replace-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_replace_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/dual-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_dual_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/keepalive",
			.cbs = {
				.modify = bgp_nb_peer_timers_keepalive_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_keepalive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/hold-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_holdtime_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_holdtime,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/connect-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_connect_modify,
				.destroy = bgp_nb_peer_timers_connect_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_connect,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/delayopen",
			.cbs = {
				.modify = bgp_nb_peer_timers_delayopen_modify,
				.destroy = bgp_nb_peer_timers_delayopen_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_delayopen,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/advertise-interval",
			.cbs = {
				.modify = bgp_nb_peer_advertise_interval_modify,
				.destroy = bgp_nb_peer_advertise_interval_destroy,
				.cli_show = bgp_nb_cli_show_peer_advertise_interval,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_dynamic_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_dynamic,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_enhe_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_enhe,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_nb_peer_cap_negotiate_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_negotiate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/fqdn-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_fqdn_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_fqdn,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/enforce-first-as",
			.cbs = {
				.modify = bgp_nb_peer_enforce_first_as_modify,
				.cli_show = bgp_nb_cli_show_peer_enforce_first_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/ip",
			.cbs = {
				.modify = bgp_nb_peer_update_source_ip_modify,
				.destroy = bgp_nb_peer_update_source_ip_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_ip,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/interface",
			.cbs = {
				.modify = bgp_nb_peer_update_source_if_modify,
				.destroy = bgp_nb_peer_update_source_if_destroy,
				.cli_show = bgp_nb_cli_show_peer_update_source_if,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/enabled",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_enabled_modify,
				.destroy = bgp_nb_peer_ebgp_mh_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify = bgp_nb_peer_ebgp_mh_ttl_modify,
				.destroy = bgp_nb_peer_ebgp_mh_ttl_destroy,
				.cli_show = bgp_nb_cli_show_peer_ebgp_mh_ttl,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify = bgp_nb_peer_disable_connected_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_connected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ttl-security",
			.cbs = {
				.modify = bgp_nb_peer_ttl_security_modify,
				.destroy = bgp_nb_peer_ttl_security_destroy,
				.cli_show = bgp_nb_cli_show_peer_ttl_security,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/local-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_modify,
				.destroy = bgp_nb_peer_local_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-prepend",
			.cbs = {
				.modify = bgp_nb_peer_local_as_no_prepend_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/replace-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_replace_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/dual-as",
			.cbs = {
				.modify = bgp_nb_peer_local_as_dual_as_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/keepalive",
			.cbs = {
				.modify = bgp_nb_peer_timers_keepalive_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_keepalive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/hold-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_holdtime_modify,
				.cli_show = bgp_nb_cli_show_peer_timers_holdtime,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/connect-time",
			.cbs = {
				.modify = bgp_nb_peer_timers_connect_modify,
				.destroy = bgp_nb_peer_timers_connect_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_connect,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/delayopen",
			.cbs = {
				.modify = bgp_nb_peer_timers_delayopen_modify,
				.destroy = bgp_nb_peer_timers_delayopen_destroy,
				.cli_show = bgp_nb_cli_show_peer_timers_delayopen,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/advertise-interval",
			.cbs = {
				.modify = bgp_nb_peer_advertise_interval_modify,
				.destroy = bgp_nb_peer_advertise_interval_destroy,
				.cli_show = bgp_nb_cli_show_peer_advertise_interval,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/dynamic-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_dynamic_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_dynamic,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_enhe_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_enhe,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/capability-negotiate",
			.cbs = {
				.modify = bgp_nb_peer_cap_negotiate_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_negotiate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/fqdn-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_fqdn_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_fqdn,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/enforce-first-as",
			.cbs = {
				.modify = bgp_nb_peer_enforce_first_as_modify,
				.cli_show = bgp_nb_cli_show_peer_enforce_first_as,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/software-version-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_soft_version_modify,
				.destroy = bgp_nb_peer_cap_soft_version_destroy,
				.cli_show = bgp_nb_cli_show_peer_cap_soft_version,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/link-local-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_link_local_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_link_local,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/override-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_override_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/tcp-mss",
			.cbs = {
				.modify = bgp_nb_peer_tcp_mss_modify,
				.destroy = bgp_nb_peer_tcp_mss_destroy,
				.cli_show = bgp_nb_cli_show_peer_tcp_mss,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ip-transparent",
			.cbs = {
				.modify = bgp_nb_peer_ip_transparent_modify,
				.cli_show = bgp_nb_cli_show_peer_ip_transparent,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/rpki-strict",
			.cbs = {
				.modify = bgp_nb_peer_rpki_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_rpki_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-role/role",
			.cbs = {
				.modify = bgp_nb_peer_local_role_modify,
				.destroy = bgp_nb_peer_local_role_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_role,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-role/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_local_role_strict_modify,
				.destroy = bgp_nb_peer_local_role_strict_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/software-version-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_soft_version_modify,
				.destroy = bgp_nb_peer_cap_soft_version_destroy,
				.cli_show = bgp_nb_cli_show_peer_cap_soft_version,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/link-local-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_link_local_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_link_local,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/override-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_override_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/tcp-mss",
			.cbs = {
				.modify = bgp_nb_peer_tcp_mss_modify,
				.destroy = bgp_nb_peer_tcp_mss_destroy,
				.cli_show = bgp_nb_cli_show_peer_tcp_mss,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ip-transparent",
			.cbs = {
				.modify = bgp_nb_peer_ip_transparent_modify,
				.cli_show = bgp_nb_cli_show_peer_ip_transparent,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/rpki-strict",
			.cbs = {
				.modify = bgp_nb_peer_rpki_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_rpki_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-role/role",
			.cbs = {
				.modify = bgp_nb_peer_local_role_modify,
				.destroy = bgp_nb_peer_local_role_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_role,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-role/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_local_role_strict_modify,
				.destroy = bgp_nb_peer_local_role_strict_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/software-version-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_soft_version_modify,
				.destroy = bgp_nb_peer_cap_soft_version_destroy,
				.cli_show = bgp_nb_cli_show_peer_cap_soft_version,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/link-local-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_link_local_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_link_local,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/override-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_override_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/strict-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_cap_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/tcp-mss",
			.cbs = {
				.modify = bgp_nb_peer_tcp_mss_modify,
				.destroy = bgp_nb_peer_tcp_mss_destroy,
				.cli_show = bgp_nb_cli_show_peer_tcp_mss,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ip-transparent",
			.cbs = {
				.modify = bgp_nb_peer_ip_transparent_modify,
				.cli_show = bgp_nb_cli_show_peer_ip_transparent,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/rpki-strict",
			.cbs = {
				.modify = bgp_nb_peer_rpki_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_rpki_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-role/role",
			.cbs = {
				.modify = bgp_nb_peer_local_role_modify,
				.destroy = bgp_nb_peer_local_role_destroy,
				.cli_show = bgp_nb_cli_show_peer_local_role,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-role/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_local_role_strict_modify,
				.destroy = bgp_nb_peer_local_role_strict_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/enable",
			.cbs = {
				.modify = bgp_nb_peer_bfd_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_nb_peer_bfd_detect_mult_modify,
				.destroy = bgp_nb_peer_bfd_detect_mult_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_rx_modify,
				.destroy = bgp_nb_peer_bfd_min_rx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_tx_modify,
				.destroy = bgp_nb_peer_bfd_min_tx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_nb_peer_bfd_cbit_modify,
				.destroy = bgp_nb_peer_bfd_cbit_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_cbit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/profile",
			.cbs = {
				.modify = bgp_nb_peer_bfd_profile_modify,
				.destroy = bgp_nb_peer_bfd_profile_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_profile,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/strict-hold-time",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_hold_modify,
				.destroy = bgp_nb_peer_bfd_strict_hold_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict_hold,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/enable",
			.cbs = {
				.modify = bgp_nb_peer_bfd_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_nb_peer_bfd_detect_mult_modify,
				.destroy = bgp_nb_peer_bfd_detect_mult_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_rx_modify,
				.destroy = bgp_nb_peer_bfd_min_rx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_tx_modify,
				.destroy = bgp_nb_peer_bfd_min_tx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_nb_peer_bfd_cbit_modify,
				.destroy = bgp_nb_peer_bfd_cbit_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_cbit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/profile",
			.cbs = {
				.modify = bgp_nb_peer_bfd_profile_modify,
				.destroy = bgp_nb_peer_bfd_profile_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_profile,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/strict-hold-time",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_hold_modify,
				.destroy = bgp_nb_peer_bfd_strict_hold_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict_hold,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/enable",
			.cbs = {
				.modify = bgp_nb_peer_bfd_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/detect-multiplier",
			.cbs = {
				.modify = bgp_nb_peer_bfd_detect_mult_modify,
				.destroy = bgp_nb_peer_bfd_detect_mult_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/required-min-rx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_rx_modify,
				.destroy = bgp_nb_peer_bfd_min_rx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/desired-min-tx",
			.cbs = {
				.modify = bgp_nb_peer_bfd_min_tx_modify,
				.destroy = bgp_nb_peer_bfd_min_tx_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/check-cp-failure",
			.cbs = {
				.modify = bgp_nb_peer_bfd_cbit_modify,
				.destroy = bgp_nb_peer_bfd_cbit_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_cbit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/profile",
			.cbs = {
				.modify = bgp_nb_peer_bfd_profile_modify,
				.destroy = bgp_nb_peer_bfd_profile_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_profile,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/strict-mode",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_modify,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/strict-hold-time",
			.cbs = {
				.modify = bgp_nb_peer_bfd_strict_hold_modify,
				.destroy = bgp_nb_peer_bfd_strict_hold_destroy,
				.cli_show = bgp_nb_cli_show_peer_bfd_strict_hold,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/path-attribute/discard",
			.cbs = {
				.create = bgp_nb_peer_path_attr_discard_create,
				.destroy = bgp_nb_peer_path_attr_discard_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_discard,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_nb_peer_path_attr_withdraw_create,
				.destroy = bgp_nb_peer_path_attr_withdraw_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_withdraw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/enable",
			.cbs = {
				.modify = bgp_nb_peer_gr_enable_modify,
				.destroy = bgp_nb_peer_gr_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_nb_peer_gr_helper_modify,
				.destroy = bgp_nb_peer_gr_helper_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_helper,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_nb_peer_gr_disable_modify,
				.destroy = bgp_nb_peer_gr_disable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_disable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/aigp",
			.cbs = {
				.modify = bgp_nb_peer_aigp_modify,
				.cli_show = bgp_nb_cli_show_peer_aigp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_nb_peer_extended_link_bw_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_link_bw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_nb_peer_disable_link_bw_ieee_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_link_bw_ieee,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-optional-parameters",
			.cbs = {
				.modify = bgp_nb_peer_extended_opt_params_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_opt_params,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_nb_peer_send_nhc_modify,
				.cli_show = bgp_nb_cli_show_peer_send_nhc,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_nb_peer_as_loop_detection_modify,
				.cli_show = bgp_nb_cli_show_peer_as_loop_detection,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/oad",
			.cbs = {
				.modify = bgp_nb_peer_oad_modify,
				.cli_show = bgp_nb_cli_show_peer_oad,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-shutdown",
			.cbs = {
				.modify = bgp_nb_peer_graceful_shutdown_modify,
				.cli_show = bgp_nb_cli_show_peer_graceful_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/path-attribute/discard",
			.cbs = {
				.create = bgp_nb_peer_path_attr_discard_create,
				.destroy = bgp_nb_peer_path_attr_discard_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_discard,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_nb_peer_path_attr_withdraw_create,
				.destroy = bgp_nb_peer_path_attr_withdraw_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_withdraw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/enable",
			.cbs = {
				.modify = bgp_nb_peer_gr_enable_modify,
				.destroy = bgp_nb_peer_gr_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_nb_peer_gr_helper_modify,
				.destroy = bgp_nb_peer_gr_helper_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_helper,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_nb_peer_gr_disable_modify,
				.destroy = bgp_nb_peer_gr_disable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_disable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/aigp",
			.cbs = {
				.modify = bgp_nb_peer_aigp_modify,
				.cli_show = bgp_nb_cli_show_peer_aigp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_nb_peer_extended_link_bw_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_link_bw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_nb_peer_disable_link_bw_ieee_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_link_bw_ieee,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/extended-optional-parameters",
			.cbs = {
				.modify = bgp_nb_peer_extended_opt_params_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_opt_params,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_nb_peer_send_nhc_modify,
				.cli_show = bgp_nb_cli_show_peer_send_nhc,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_nb_peer_as_loop_detection_modify,
				.cli_show = bgp_nb_cli_show_peer_as_loop_detection,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/oad",
			.cbs = {
				.modify = bgp_nb_peer_oad_modify,
				.cli_show = bgp_nb_cli_show_peer_oad,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-shutdown",
			.cbs = {
				.modify = bgp_nb_peer_graceful_shutdown_modify,
				.cli_show = bgp_nb_cli_show_peer_graceful_shutdown,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/path-attribute/discard",
			.cbs = {
				.create = bgp_nb_peer_path_attr_discard_create,
				.destroy = bgp_nb_peer_path_attr_discard_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_discard,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/path-attribute/treat-as-withdraw",
			.cbs = {
				.create = bgp_nb_peer_path_attr_withdraw_create,
				.destroy = bgp_nb_peer_path_attr_withdraw_destroy,
				.cli_show = bgp_nb_cli_show_peer_path_attr_withdraw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/enable",
			.cbs = {
				.modify = bgp_nb_peer_gr_enable_modify,
				.destroy = bgp_nb_peer_gr_enable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_enable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify = bgp_nb_peer_gr_helper_modify,
				.destroy = bgp_nb_peer_gr_helper_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_helper,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify = bgp_nb_peer_gr_disable_modify,
				.destroy = bgp_nb_peer_gr_disable_destroy,
				.cli_show = bgp_nb_cli_show_peer_gr_disable,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/aigp",
			.cbs = {
				.modify = bgp_nb_peer_aigp_modify,
				.cli_show = bgp_nb_cli_show_peer_aigp,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/extended-link-bandwidth",
			.cbs = {
				.modify = bgp_nb_peer_extended_link_bw_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_link_bw,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = bgp_nb_peer_disable_link_bw_ieee_modify,
				.cli_show = bgp_nb_cli_show_peer_disable_link_bw_ieee,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/extended-optional-parameters",
			.cbs = {
				.modify = bgp_nb_peer_extended_opt_params_modify,
				.cli_show = bgp_nb_cli_show_peer_extended_opt_params,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/send-nexthop-characteristics",
			.cbs = {
				.modify = bgp_nb_peer_send_nhc_modify,
				.cli_show = bgp_nb_cli_show_peer_send_nhc,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/sender-as-path-loop-detection",
			.cbs = {
				.modify = bgp_nb_peer_as_loop_detection_modify,
				.cli_show = bgp_nb_cli_show_peer_as_loop_detection,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/oad",
			.cbs = {
				.modify = bgp_nb_peer_oad_modify,
				.cli_show = bgp_nb_cli_show_peer_oad,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-shutdown",
			.cbs = {
				.modify = bgp_nb_peer_graceful_shutdown_modify,
				.cli_show = bgp_nb_cli_show_peer_graceful_shutdown,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/peer-group",
			.cbs = {
				.modify = bgp_nb_neighbor_peer_group_modify,
				.destroy = bgp_nb_neighbor_peer_group_destroy,
				.cli_show = bgp_nb_cli_show_neighbor_peer_group,
			},
			/*
			 * Bind must run after the neighbor list create in the
			 * same candidate (create+bind batch); otherwise APPLY
			 * soft-lookup misses the peer and returns element-not-
			 * found, leaving members unbound.
			 */
			.priority = NB_DFLT_PRIORITY + 1,
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-port",
			.cbs = {
				.modify = bgp_nb_neighbor_local_port_modify,
				.destroy = bgp_nb_neighbor_local_port_destroy,
				.cli_show = bgp_nb_cli_show_neighbor_local_port,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-interface",
			.cbs = {
				.modify = bgp_nb_neighbor_local_interface_modify,
				.destroy = bgp_nb_neighbor_local_interface_destroy,
				.cli_show = bgp_nb_cli_show_neighbor_local_interface,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_nb_peer_afi_safi_create,
				.destroy = bgp_nb_peer_afi_safi_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_nb_peer_af_enabled_modify,
				.destroy = bgp_nb_peer_af_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable",
			.cbs = {
				.modify = bgp_nb_peer_dampening_enable_modify,
				.cli_show = bgp_nb_cli_show_peer_dampening,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay",
			.cbs = {
				.modify = bgp_nb_peer_dampening_param_modify,
				.destroy = bgp_nb_peer_dampening_param_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_nb_peer_afi_safi_create,
				.destroy = bgp_nb_peer_afi_safi_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_nb_peer_af_enabled_modify,
				.destroy = bgp_nb_peer_af_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_nb_peer_afi_safi_create,
				.destroy = bgp_nb_peer_afi_safi_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/enabled",
			.cbs = {
				.modify = bgp_nb_peer_af_enabled_modify,
				.destroy = bgp_nb_peer_af_enabled_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_enabled,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/encapsulation/type",
			.cbs = {
				.create = bgp_nb_peer_af_encapsulation_create,
				.destroy = bgp_nb_peer_af_encapsulation_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_encapsulation,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_self_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_self_force,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_med_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_med_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration",
			.cbs = {
				.modify = bgp_nb_peer_af_soft_reconfig_modify,
				.cli_show = bgp_nb_cli_show_peer_af_soft_reconfig,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace",
			.cbs = {
				.modify = bgp_nb_peer_af_remove_private_as_all_replace_modify,
				.cli_show = bgp_nb_cli_show_peer_af_remove_private_as_all_replace,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client",
			.cbs = {
				.modify = bgp_nb_peer_af_reflector_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_reflector_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client",
			.cbs = {
				.modify = bgp_nb_peer_af_rserver_client_modify,
				.cli_show = bgp_nb_cli_show_peer_af_rserver_client,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute",
			.cbs = {
				.modify = bgp_nb_peer_af_weight_modify,
				.destroy = bgp_nb_peer_af_weight_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_weight,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community",
			.cbs = {
				.modify = bgp_nb_peer_af_send_large_community_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_large_community,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community-rpki",
			.cbs = {
				.modify = bgp_nb_peer_af_send_ext_community_rpki_modify,
				.cli_show = bgp_nb_cli_show_peer_af_send_ext_community_rpki,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as",
			.cbs = {
				.modify = bgp_nb_peer_af_allow_own_origin_as_modify,
				.destroy = bgp_nb_peer_af_allow_own_origin_as_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allow_own_origin_as,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allowas-in-route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_allowas_in_rmap_modify,
				.destroy = bgp_nb_peer_af_allowas_in_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_allowas_in_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_modify,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = bgp_nb_peer_af_default_originate_rmap_modify,
				.destroy = bgp_nb_peer_af_default_originate_rmap_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_default_originate_rmap,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/rmap-import",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_import_modify,
				.destroy = bgp_nb_peer_af_rmap_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/rmap-export",
			.cbs = {
				.modify = bgp_nb_peer_af_rmap_export_modify,
				.destroy = bgp_nb_peer_af_rmap_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_rmap_export,
			},
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list",
			.cbs = {
				.create = bgp_nb_peer_af_prefix_limit_create,
				.destroy = bgp_nb_peer_af_prefix_limit_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/max-prefixes",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_max_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_max,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/force-check",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_force_modify,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tr-restart-timer",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-shutdown-threshold-pct",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/prefix-limit/direction-list/options/tw-warning-only",
			.cbs = {
				.modify = bgp_nb_peer_af_prefix_limit_option_modify,
				.destroy = bgp_nb_peer_af_prefix_limit_option_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_prefix_limit_noop,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/path-type",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_type_modify,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_type,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/best-selected-paths",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_best_selected_modify,
				.destroy = bgp_nb_peer_af_addpath_best_selected_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_best_selected,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/disable-addpath-rx",
			.cbs = {
				.modify = bgp_nb_peer_af_disable_addpath_rx_modify,
				.cli_show = bgp_nb_cli_show_peer_af_disable_addpath_rx,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/add-paths/addpath-rx-paths-limit",
			.cbs = {
				.modify = bgp_nb_peer_af_addpath_rx_limit_modify,
				.destroy = bgp_nb_peer_af_addpath_rx_limit_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_addpath_rx_limit,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_local_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_local_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_local_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_local_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = bgp_nb_peer_af_nexthop_local_unchanged_modify,
				.cli_show = bgp_nb_cli_show_peer_af_nexthop_local_unchanged,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_map_modify,
				.destroy = bgp_nb_peer_af_advertise_map_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/conditional-advertisement/non-exist-map",
			.cbs = {
				.modify = bgp_nb_peer_af_advertise_cond_modify,
				.destroy = bgp_nb_peer_af_advertise_cond_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_advertise_map_cond,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/accept-own",
			.cbs = {
				.modify = bgp_nb_peer_af_accept_own_modify,
				.cli_show = bgp_nb_cli_show_peer_af_accept_own,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/soo",
			.cbs = {
				.modify = bgp_nb_peer_af_soo_modify,
				.destroy = bgp_nb_peer_af_soo_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_soo,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/upa",
			.cbs = {
				.modify = bgp_nb_peer_af_upa_modify,
				.cli_show = bgp_nb_cli_show_peer_af_upa,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_send_modify,
				.destroy = bgp_nb_peer_af_orf_send_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_send,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_receive_modify,
				.destroy = bgp_nb_peer_af_orf_receive_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_receive,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both",
			.cbs = {
				.modify = bgp_nb_peer_af_orf_both_modify,
				.destroy = bgp_nb_peer_af_orf_both_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_orf_both,
			},
		},
		{
			.xpath = "/frr-interface:lib/frr-interface:interface/frr-bgp:mpls-bgp-forwarding",
			.cbs = {
				.modify = lib_interface_mpls_bgp_forwarding_modify,
				.cli_show = bgp_nb_cli_show_mpls_bgp_forwarding,
			},
		},
		{
			.xpath = "/frr-interface:lib/frr-interface:interface/frr-bgp:mpls-l3vpn-multi-domain-switching",
			.cbs = {
				.modify = lib_interface_mpls_l3vpn_multi_domain_switching_modify,
				.cli_show = bgp_nb_cli_show_mpls_l3vpn_multi_domain_switching,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/disable-eor",
			.cbs = {
				.modify = bgp_nb_daemon_gr_disable_eor_modify,
				.cli_show = bgp_nb_cli_show_daemon_gr_disable_eor,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/long-lived-stale-time",
			.cbs = {
				.modify = bgp_nb_daemon_gr_llgr_stale_time_modify,
				.destroy = bgp_nb_daemon_gr_llgr_stale_time_destroy,
				.cli_show = bgp_nb_cli_show_daemon_gr_llgr_stale_time,
			},
		},
		{
			.xpath = "/frr-bgp:bgp-daemon/graceful-restart/notification",
			.cbs = {
				.modify = bgp_nb_daemon_gr_notification_modify,
				.destroy = bgp_nb_daemon_gr_notification_destroy,
				.cli_show = bgp_nb_cli_show_daemon_gr_notification,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/access-list-policy-export",
			.cbs = {
				.modify = bgp_nb_distance_route_acl_modify,
				.destroy = bgp_nb_distance_route_acl_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/as-path",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/extended-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/large-community",
			.cbs = {
				.modify = bgp_nb_aggregate_attr_modify,
				.destroy = bgp_nb_aggregate_attr_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi",
			.cbs = {
				.create = bgp_nb_global_afi_safi_create,
				.destroy = bgp_nb_global_afi_safi_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/connect-retry-interval",
			.cbs = {
				.modify = bgp_nb_connect_retry_modify,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/session-type",
			.cbs = {
				.modify = bgp_nb_peer_bfd_session_type_modify,
				.destroy = bgp_nb_peer_bfd_session_type_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/session-type",
			.cbs = {
				.modify = bgp_nb_peer_bfd_session_type_modify,
				.destroy = bgp_nb_peer_bfd_session_type_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unreachability/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as",
			.cbs = {
				.modify = bgp_nb_peer_af_as_override_modify,
				.cli_show = bgp_nb_cli_show_peer_af_as_override,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/access-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_export_modify,
				.destroy = bgp_nb_peer_af_access_list_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/access-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_access_list_import_modify,
				.destroy = bgp_nb_peer_af_access_list_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_access_list_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-export",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_export_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/as-path-filter-list-import",
			.cbs = {
				.modify = bgp_nb_peer_af_aspath_filter_import_modify,
				.destroy = bgp_nb_peer_af_aspath_filter_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_aspath_filter_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/plist-export",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_export_modify,
				.destroy = bgp_nb_peer_af_plist_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/plist-import",
			.cbs = {
				.modify = bgp_nb_peer_af_plist_import_modify,
				.destroy = bgp_nb_peer_af_plist_import_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_plist_import,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-export",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/link-state/filter-config/unsuppress-map-import",
			.cbs = {
				.modify = bgp_nb_peer_af_unsuppress_map_export_modify,
				.destroy = bgp_nb_peer_af_unsuppress_map_export_destroy,
				.cli_show = bgp_nb_cli_show_peer_af_unsuppress_map_export,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/session-type",
			.cbs = {
				.modify = bgp_nb_peer_bfd_session_type_modify,
				.destroy = bgp_nb_peer_bfd_session_type_destroy,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
