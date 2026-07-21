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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp",
			.cbs = {
				.create = bgp_nb_bgp_create,
				.destroy = bgp_nb_bgp_destroy,
				.cli_show = bgp_nb_cli_show_router_bgp,
				.cli_show_end = bgp_nb_cli_show_router_bgp_end,
			},
			.priority = NB_DFLT_PRIORITY - 1,
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
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/software-version-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_soft_version_modify,
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
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/software-version-capability",
			.cbs = {
				.modify = bgp_nb_peer_cap_soft_version_modify,
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
			},
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
