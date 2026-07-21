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
			.xpath = NULL,
		},
	}
};
/* clang-format on */
