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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/prefer-mpls-over-srv6",
			.cbs = {
				.modify = bgp_nb_prefer_mpls_over_srv6_modify,
				.cli_show = bgp_nb_cli_show_prefer_mpls_over_srv6,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier-pretty",
			.cbs = {
				.modify = bgp_nb_confederation_identifier_pretty_modify,
				.destroy = bgp_nb_confederation_identifier_pretty_destroy,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as-pretty",
			.cbs = {
				.create = bgp_nb_confederation_member_as_pretty_create,
				.destroy = bgp_nb_confederation_member_as_pretty_destroy,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as-pretty/as-pretty",
			.cbs = {
				.modify = bgp_nb_confederation_member_as_pretty_val_modify,
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
			.xpath = NULL,
		},
	}
};
/* clang-format on */
