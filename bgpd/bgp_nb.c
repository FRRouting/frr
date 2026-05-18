// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgpd northbound — module registration.
 *
 * Registers the `frr-bgp` YANG module with the northbound layer and binds
 * create/modify/destroy callbacks against XPath nodes as each phase of the
 * migration plan (`BGPD_NB_MIGRATION_PLAN.md`) converts them.
 *
 * cli_show callbacks (used by `show running-config` rendering) are
 * registered separately in `frr_bgp_cli_info`, mirroring the staticd
 * `frr_staticd_cli_info` pattern at `staticd/static_vty.c:2091`. Phase 5
 * adds cli_show callbacks; until then `show running-config` is served by
 * the existing legacy `bgp_config_write_*` functions in `bgp_vty.c`.
 *
 * See FRRouting/frr#5428.
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bgp_info = {
	.name = "frr-bgp",
	.nodes = {
		/* Phase 2.0 — control-plane-protocol context (bgp container). */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp",
			.cbs = {
				.create  = bgp_router_create,
				.destroy = bgp_router_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},

		/* Phase 2 — global leaves. */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/router-id",
			.cbs = {
				.modify   = bgp_global_router_id_modify,
				.destroy  = bgp_global_router_id_destroy,
				.cli_show = bgp_global_router_id_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-shutdown",
			.cbs = {
				.modify   = bgp_global_default_shutdown_modify,
				.destroy  = bgp_global_default_shutdown_destroy,
				.cli_show = bgp_global_default_shutdown_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-hostname",
			.cbs = {
				.modify  = bgp_global_show_hostname_modify,
				.destroy = bgp_global_show_hostname_destroy,
				.cli_show = bgp_global_show_hostname_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-nexthop-hostname",
			.cbs = {
				.modify  = bgp_global_show_nexthop_hostname_modify,
				.destroy = bgp_global_show_nexthop_hostname_destroy,
				.cli_show = bgp_global_show_nexthop_hostname_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/always-compare-med",
			.cbs = {
				.modify  = bgp_global_always_compare_med_modify,
				.destroy = bgp_global_always_compare_med_destroy,
				.cli_show = bgp_global_always_compare_med_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/external-compare-router-id",
			.cbs = {
				.modify  = bgp_global_external_compare_router_id_modify,
				.destroy = bgp_global_external_compare_router_id_destroy,
				.cli_show = bgp_global_external_compare_router_id_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/ignore-as-path-length",
			.cbs = {
				.modify  = bgp_global_ignore_as_path_length_modify,
				.destroy = bgp_global_ignore_as_path_length_destroy,
				.cli_show = bgp_global_ignore_as_path_length_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/aspath-confed",
			.cbs = {
				.modify  = bgp_global_aspath_confed_modify,
				.destroy = bgp_global_aspath_confed_destroy,
				.cli_show = bgp_global_aspath_confed_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/confed-med",
			.cbs = {
				.modify  = bgp_global_confed_med_modify,
				.destroy = bgp_global_confed_med_destroy,
				.cli_show = bgp_global_confed_med_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/missing-as-worst-med",
			.cbs = {
				.modify  = bgp_global_missing_as_worst_med_modify,
				.destroy = bgp_global_missing_as_worst_med_destroy,
				.cli_show = bgp_global_missing_as_worst_med_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes",
			.cbs = {
				.modify   = bgp_global_log_neighbor_changes_modify,
				.destroy  = bgp_global_log_neighbor_changes_destroy,
				.cli_show = bgp_global_log_neighbor_changes_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/import-check",
			.cbs = {
				.modify  = bgp_global_import_check_modify,
				.destroy = bgp_global_import_check_destroy,
				.cli_show = bgp_global_import_check_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta",
			.cbs = {
				.modify  = bgp_global_wpkt_quanta_modify,
				.destroy = bgp_global_wpkt_quanta_destroy,
				.cli_show = bgp_global_wpkt_quanta_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta",
			.cbs = {
				.modify  = bgp_global_rpkt_quanta_modify,
				.destroy = bgp_global_rpkt_quanta_destroy,
				.cli_show = bgp_global_rpkt_quanta_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/coalesce-time",
			.cbs = {
				.modify  = bgp_global_coalesce_time_modify,
				.destroy = bgp_global_coalesce_time_destroy,
				.cli_show = bgp_global_coalesce_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size",
			.cbs = {
				.modify  = bgp_global_subgroup_pkt_queue_size_modify,
				.destroy = bgp_global_subgroup_pkt_queue_size_destroy,
				.cli_show = bgp_global_subgroup_pkt_queue_size_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier",
			.cbs = {
				.modify  = bgp_global_confederation_identifier_modify,
				.destroy = bgp_global_confederation_identifier_destroy,
				.cli_show = bgp_global_confederation_identifier_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as",
			.cbs = {
				.create  = bgp_global_confederation_member_as_create,
				.destroy = bgp_global_confederation_member_as_destroy,
				.cli_show = bgp_global_confederation_member_as_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/minimum-holdtime",
			.cbs = {
				.modify  = bgp_global_minimum_holdtime_modify,
				.destroy = bgp_global_minimum_holdtime_destroy,
				.cli_show = bgp_global_minimum_holdtime_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/allow-martian-nexthop",
			.cbs = {
				.modify   = bgp_global_allow_martian_nexthop_modify,
				.destroy  = bgp_global_allow_martian_nexthop_destroy,
				.cli_show = bgp_global_allow_martian_nexthop_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/use-underlays-nexthop-weight",
			.cbs = {
				.modify  = bgp_global_use_underlays_nexthop_weight_modify,
				.destroy = bgp_global_use_underlays_nexthop_weight_destroy,
				.cli_show = bgp_global_use_underlays_nexthop_weight_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/allow-outbound-policy",
			.cbs = {
				.modify  = bgp_global_route_reflector_allow_outbound_policy_modify,
				.destroy = bgp_global_route_reflector_allow_outbound_policy_destroy,
				.cli_show = bgp_global_allow_outbound_policy_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bgp-ls-distribute",
			.cbs = {
				.create  = bgp_global_bgp_ls_distribute_create,
				.destroy = bgp_global_bgp_ls_distribute_destroy,
				.cli_show = bgp_global_bgp_ls_distribute_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bgp-ls-distribute/instance-id",
			.cbs = {
				.modify = bgp_global_bgp_ls_distribute_instance_id_modify,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/bestpath-aigp",
			.cbs = {
				.modify  = bgp_global_bestpath_aigp_modify,
				.destroy = bgp_global_bestpath_aigp_destroy,
				.cli_show = bgp_global_bestpath_aigp_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/bestpath-use-imported-attributes",
			.cbs = {
				.modify  = bgp_global_bestpath_use_imported_attributes_modify,
				.destroy = bgp_global_bestpath_use_imported_attributes_destroy,
				.cli_show = bgp_global_bestpath_use_imported_attributes_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/dynamic-neighbors-limit",
			.cbs = {
				.modify  = bgp_global_dynamic_neighbors_limit_modify,
				.destroy = bgp_global_dynamic_neighbors_limit_destroy,
				.cli_show = bgp_global_dynamic_neighbors_limit_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config",
			.cbs = {
				.apply_finish = bgp_global_med_config_apply_finish,
				.destroy      = bgp_global_med_config_destroy,
				.cli_show = bgp_global_med_config_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-software-version-capability",
			.cbs = {
				.modify  = bgp_global_default_software_version_capability_modify,
				.destroy = bgp_global_default_software_version_capability_destroy,
				.cli_show = bgp_global_default_software_version_capability_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/tcp-keepalive",
			.cbs = {
				.apply_finish = bgp_global_tcp_keepalive_apply_finish,
				.destroy      = bgp_global_tcp_keepalive_destroy,
				.cli_show = bgp_global_tcp_keepalive_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/hold-time",
			.cbs = {
				.modify  = bgp_global_hold_time_modify,
				.destroy = bgp_global_hold_time_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/keepalive",
			.cbs = {
				.modify  = bgp_global_keepalive_modify,
				.destroy = bgp_global_keepalive_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/reject-as-sets",
			.cbs = {
				.modify  = bgp_global_reject_as_sets_modify,
				.destroy = bgp_global_reject_as_sets_destroy,
				.cli_show = bgp_global_reject_as_sets_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled",
			.cbs = {
				.modify  = bgp_global_graceful_restart_enabled_modify,
				.destroy = bgp_global_graceful_restart_enabled_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/restart-time",
			.cbs = {
				.modify  = bgp_global_graceful_restart_restart_time_modify,
				.destroy = bgp_global_graceful_restart_restart_time_destroy,
				.cli_show = bgp_global_restart_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/selection-deferral-time",
			.cbs = {
				.modify  = bgp_global_graceful_restart_selection_deferral_time_modify,
				.destroy = bgp_global_graceful_restart_selection_deferral_time_destroy,
				.cli_show = bgp_global_selection_deferral_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/administrative-shutdown",
			.cbs = {
				.apply_finish = bgp_global_administrative_shutdown_apply_finish,
				.destroy      = bgp_global_administrative_shutdown_destroy,
				.cli_show = bgp_global_administrative_shutdown_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/enforce-first-as-global",
			.cbs = {
				.modify  = bgp_global_enforce_first_as_global_modify,
				.destroy = bgp_global_enforce_first_as_global_destroy,
				.cli_show = bgp_global_enforce_first_as_global_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-duplicates",
			.cbs = {
				.modify  = bgp_global_suppress_duplicates_modify,
				.destroy = bgp_global_suppress_duplicates_destroy,
				.cli_show = bgp_global_suppress_duplicates_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-requires-policy",
			.cbs = {
				.modify  = bgp_global_ebgp_requires_policy_modify,
				.destroy = bgp_global_ebgp_requires_policy_destroy,
				.cli_show = bgp_global_ebgp_requires_policy_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-external-failover",
			.cbs = {
				.modify  = bgp_global_fast_external_failover_modify,
				.destroy = bgp_global_fast_external_failover_destroy,
				.cli_show = bgp_global_fast_external_failover_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/deterministic-med",
			.cbs = {
				.modify  = bgp_global_deterministic_med_modify,
				.destroy = bgp_global_deterministic_med_destroy,
				.cli_show = bgp_global_deterministic_med_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/labeled-unicast-explicit-null",
			.cbs = {
				.modify  = bgp_global_labeled_unicast_explicit_null_modify,
				.destroy = bgp_global_labeled_unicast_explicit_null_destroy,
				.cli_show = bgp_global_labeled_unicast_explicit_null_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ipv6-auto-ra",
			.cbs = {
				.modify  = bgp_global_ipv6_auto_ra_modify,
				.destroy = bgp_global_ipv6_auto_ra_destroy,
				.cli_show = bgp_global_ipv6_auto_ra_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/allow-multiple-as",
			.cbs = {
				.modify  = bgp_global_allow_multiple_as_modify,
				.destroy = bgp_global_allow_multiple_as_destroy,
				.cli_show = bgp_global_allow_multiple_as_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/multi-path-as-set",
			.cbs = {
				.modify  = bgp_global_multi_path_as_set_modify,
				.destroy = bgp_global_multi_path_as_set_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/peer-type-multipath-relax",
			.cbs = {
				.modify  = bgp_global_peer_type_multipath_relax_modify,
				.destroy = bgp_global_peer_type_multipath_relax_destroy,
				.cli_show = bgp_global_peer_type_multipath_relax_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable",
			.cbs = {
				.modify  = bgp_global_graceful_shutdown_enable_modify,
				.destroy = bgp_global_graceful_shutdown_enable_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-fib-pending",
			.cbs = {
				.apply_finish = bgp_global_suppress_fib_pending_apply_finish,
				.destroy      = bgp_global_suppress_fib_pending_destroy,
				.cli_show = bgp_global_suppress_fib_pending_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/advertisement-delay-global",
			.cbs = {
				.modify  = bgp_global_advertisement_delay_global_modify,
				.destroy = bgp_global_advertisement_delay_global_destroy,
				.cli_show = bgp_global_advertisement_delay_global_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time",
			.cbs = {
				.modify  = bgp_global_update_delay_time_modify,
				.destroy = bgp_global_update_delay_time_destroy,
				.cli_show = bgp_global_update_delay_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/establish-wait-time",
			.cbs = {
				.modify  = bgp_global_establish_wait_time_modify,
				.destroy = bgp_global_establish_wait_time_destroy,
				.cli_show = bgp_global_establish_wait_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/connect-retry-interval",
			.cbs = {
				.modify  = bgp_global_connect_retry_interval_modify,
				.destroy = bgp_global_connect_retry_interval_destroy,
				.cli_show = bgp_global_connect_retry_interval_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/conditional-advertisement-period",
			.cbs = {
				.modify  = bgp_global_conditional_advertisement_period_modify,
				.destroy = bgp_global_conditional_advertisement_period_destroy,
				.cli_show = bgp_global_conditional_advertisement_period_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-originate-timer",
			.cbs = {
				.modify  = bgp_global_default_originate_timer_modify,
				.destroy = bgp_global_default_originate_timer_destroy,
				.cli_show = bgp_global_default_originate_timer_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bestpath-bandwidth",
			.cbs = {
				.modify  = bgp_global_bestpath_bandwidth_modify,
				.destroy = bgp_global_bestpath_bandwidth_destroy,
				.cli_show = bgp_global_bestpath_bandwidth_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart-notification",
			.cbs = {
				.modify  = bgp_global_graceful_restart_notification_modify,
				.destroy = bgp_global_graceful_restart_notification_destroy,
				.cli_show = bgp_global_graceful_restart_notification_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/long-lived-graceful-restart-stale-time",
			.cbs = {
				.modify  = bgp_global_long_lived_graceful_restart_stale_time_modify,
				.destroy = bgp_global_long_lived_graceful_restart_stale_time_destroy,
				.cli_show = bgp_global_long_lived_graceful_restart_stale_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-convergence",
			.cbs = {
				.modify   = bgp_global_fast_convergence_modify,
				.destroy  = bgp_global_fast_convergence_destroy,
				.cli_show = bgp_global_fast_convergence_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-link-local-capability",
			.cbs = {
				.modify  = bgp_global_default_link_local_capability_modify,
				.destroy = bgp_global_default_link_local_capability_destroy,
				.cli_show = bgp_global_default_link_local_capability_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-dynamic-capability",
			.cbs = {
				.modify  = bgp_global_default_dynamic_capability_modify,
				.destroy = bgp_global_default_dynamic_capability_destroy,
				.cli_show = bgp_global_default_dynamic_capability_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id",
			.cbs = {
				.modify  = bgp_global_route_reflector_cluster_id_modify,
				.destroy = bgp_global_route_reflector_cluster_id_destroy,
				.cli_show = bgp_global_route_reflector_cluster_id_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/no-client-reflect",
			.cbs = {
				.modify  = bgp_global_no_client_reflect_modify,
				.destroy = bgp_global_no_client_reflect_destroy,
				.cli_show = bgp_global_no_client_reflect_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-pref",
			.cbs = {
				.modify  = bgp_global_local_pref_modify,
				.destroy = bgp_global_local_pref_destroy,
				.cli_show = bgp_global_local_pref_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-multihop-connected-route-check",
			.cbs = {
				.modify  = bgp_global_ebgp_multihop_connected_route_check_modify,
				.destroy = bgp_global_ebgp_multihop_connected_route_check_destroy,
				.cli_show = bgp_global_ebgp_multihop_connected_route_check_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/rib-stale-time",
			.cbs = {
				.modify  = bgp_global_graceful_restart_rib_stale_time_modify,
				.destroy = bgp_global_graceful_restart_rib_stale_time_destroy,
				.cli_show = bgp_global_rib_stale_time_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/preserve-fw-entry",
			.cbs = {
				.modify  = bgp_global_graceful_restart_preserve_fw_entry_modify,
				.destroy = bgp_global_graceful_restart_preserve_fw_entry_destroy,
				.cli_show = bgp_global_preserve_fw_entry_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/stale-routes-time",
			.cbs = {
				.modify  = bgp_global_graceful_restart_stale_routes_time_modify,
				.destroy = bgp_global_graceful_restart_stale_routes_time_destroy,
				.cli_show = bgp_global_stale_routes_time_cli_show,
			},
		},

		/* Phase 3a (neighbor) entries. */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor",
			.cbs = {
				.create  = bgp_neighbor_create,
				.destroy = bgp_neighbor_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as-type",
			.cbs = {
				.modify = bgp_neighbor_remote_as_type_modify,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as",
			.cbs = {
				.modify  = bgp_neighbor_remote_as_modify,
				.destroy = bgp_neighbor_remote_as_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/password",
			.cbs = {
				.modify  = bgp_neighbor_password_modify,
				.destroy = bgp_neighbor_password_destroy,
				.cli_show = bgp_neighbor_password_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/description",
			.cbs = {
				.modify  = bgp_neighbor_description_modify,
				.destroy = bgp_neighbor_description_destroy,
				.cli_show = bgp_neighbor_description_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/passive-mode",
			.cbs = {
				.modify  = bgp_neighbor_passive_mode_modify,
				.destroy = bgp_neighbor_passive_mode_destroy,
				.cli_show = bgp_neighbor_passive_mode_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/solo",
			.cbs = {
				.modify  = bgp_neighbor_solo_modify,
				.destroy = bgp_neighbor_solo_destroy,
				.cli_show = bgp_neighbor_solo_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/enforce-first-as",
			.cbs = {
				.modify  = bgp_neighbor_enforce_first_as_modify,
				.destroy = bgp_neighbor_enforce_first_as_destroy,
				.cli_show = bgp_neighbor_enforce_first_as_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ttl-security",
			.cbs = {
				.modify  = bgp_neighbor_ttl_security_modify,
				.destroy = bgp_neighbor_ttl_security_destroy,
				.cli_show = bgp_neighbor_ttl_security_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/enable",
			.cbs = {
				.modify  = bgp_neighbor_admin_shutdown_enable_modify,
				.destroy = bgp_neighbor_admin_shutdown_enable_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/message",
			.cbs = {
				.modify  = bgp_neighbor_admin_shutdown_message_modify,
				.destroy = bgp_neighbor_admin_shutdown_message_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/enabled",
			.cbs = {
				.modify  = bgp_neighbor_ebgp_multihop_enabled_modify,
				.destroy = bgp_neighbor_ebgp_multihop_enabled_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/multihop-ttl",
			.cbs = {
				.modify  = bgp_neighbor_ebgp_multihop_ttl_modify,
				.destroy = bgp_neighbor_ebgp_multihop_ttl_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/disable-connected-check",
			.cbs = {
				.modify  = bgp_neighbor_ebgp_multihop_disable_connected_check_modify,
				.destroy = bgp_neighbor_ebgp_multihop_disable_connected_check_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/ip",
			.cbs = {
				.modify  = bgp_neighbor_update_source_ip_modify,
				.destroy = bgp_neighbor_update_source_ip_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/interface",
			.cbs = {
				.modify  = bgp_neighbor_update_source_interface_modify,
				.destroy = bgp_neighbor_update_source_interface_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/connect-time",
			.cbs = {
				.modify  = bgp_neighbor_timers_connect_time_modify,
				.destroy = bgp_neighbor_timers_connect_time_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/advertise-interval",
			.cbs = {
				.modify  = bgp_neighbor_timers_advertise_interval_modify,
				.destroy = bgp_neighbor_timers_advertise_interval_destroy,
				.cli_show = bgp_nb_handled_by_parent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as",
			.cbs = {
				.apply_finish = bgp_neighbor_local_as_apply_finish,
				.destroy      = bgp_neighbor_local_as_destroy,
				.cli_show = bgp_neighbor_local_as_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options",
			.cbs = {
				.apply_finish = bgp_neighbor_bfd_options_apply_finish,
				.destroy      = bgp_neighbor_bfd_options_destroy,
				.cli_show = bgp_neighbor_bfd_options_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/dynamic-capability",
			.cbs = {
				.modify  = bgp_neighbor_capabilities_dynamic_modify,
				.destroy = bgp_neighbor_capabilities_dynamic_destroy,
				.cli_show = bgp_neighbor_capabilities_dynamic_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/strict-capability",
			.cbs = {
				.modify  = bgp_neighbor_capabilities_strict_modify,
				.destroy = bgp_neighbor_capabilities_strict_destroy,
				.cli_show = bgp_neighbor_capabilities_strict_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/override-capability",
			.cbs = {
				.modify  = bgp_neighbor_capabilities_override_modify,
				.destroy = bgp_neighbor_capabilities_override_destroy,
				.cli_show = bgp_neighbor_capabilities_override_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/extended-nexthop-capability",
			.cbs = {
				.modify  = bgp_neighbor_capabilities_extended_nexthop_modify,
				.destroy = bgp_neighbor_capabilities_extended_nexthop_destroy,
				.cli_show = bgp_neighbor_capabilities_extended_nexthop_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/capability-negotiate",
			.cbs = {
				.modify  = bgp_neighbor_capabilities_negotiate_modify,
				.destroy = bgp_neighbor_capabilities_negotiate_destroy,
				.cli_show = bgp_neighbor_capabilities_negotiate_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/aigp",
			.cbs = {
				.modify  = bgp_neighbor_aigp_modify,
				.destroy = bgp_neighbor_aigp_destroy,
				.cli_show = bgp_neighbor_aigp_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ip-transparent",
			.cbs = {
				.modify  = bgp_neighbor_ip_transparent_modify,
				.destroy = bgp_neighbor_ip_transparent_destroy,
				.cli_show = bgp_neighbor_ip_transparent_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-link-bandwidth",
			.cbs = {
				.modify  = bgp_neighbor_extended_link_bandwidth_modify,
				.destroy = bgp_neighbor_extended_link_bandwidth_destroy,
				.cli_show = bgp_neighbor_extended_link_bandwidth_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify  = bgp_neighbor_disable_link_bw_encoding_ieee_modify,
				.destroy = bgp_neighbor_disable_link_bw_encoding_ieee_destroy,
				.cli_show = bgp_neighbor_disable_link_bw_encoding_ieee_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/extended-optional-parameters",
			.cbs = {
				.modify  = bgp_neighbor_extended_optional_parameters_modify,
				.destroy = bgp_neighbor_extended_optional_parameters_destroy,
				.cli_show = bgp_neighbor_extended_optional_parameters_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify  = bgp_neighbor_send_nexthop_characteristics_modify,
				.destroy = bgp_neighbor_send_nexthop_characteristics_destroy,
				.cli_show = bgp_neighbor_send_nexthop_characteristics_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/rpki-strict",
			.cbs = {
				.modify  = bgp_neighbor_rpki_strict_modify,
				.destroy = bgp_neighbor_rpki_strict_destroy,
				.cli_show = bgp_neighbor_rpki_strict_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-fqdn",
			.cbs = {
				.modify  = bgp_neighbor_capability_fqdn_modify,
				.destroy = bgp_neighbor_capability_fqdn_destroy,
				.cli_show = bgp_neighbor_capability_fqdn_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-link-local",
			.cbs = {
				.modify  = bgp_neighbor_capability_link_local_modify,
				.destroy = bgp_neighbor_capability_link_local_destroy,
				.cli_show = bgp_neighbor_capability_link_local_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/as-loop-detection",
			.cbs = {
				.modify  = bgp_neighbor_as_loop_detection_modify,
				.destroy = bgp_neighbor_as_loop_detection_destroy,
				.cli_show = bgp_neighbor_as_loop_detection_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-software-version",
			.cbs = {
				.modify  = bgp_neighbor_capability_software_version_modify,
				.destroy = bgp_neighbor_capability_software_version_destroy,
				.cli_show = bgp_neighbor_capability_software_version_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-software-version-latest-encoding",
			.cbs = {
				.modify  = bgp_neighbor_capability_software_version_latest_encoding_modify,
				.destroy = bgp_neighbor_capability_software_version_latest_encoding_destroy,
				.cli_show = bgp_neighbor_capability_software_version_latest_encoding_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/tcp-mss",
			.cbs = {
				.modify  = bgp_neighbor_tcp_mss_modify,
				.destroy = bgp_neighbor_tcp_mss_destroy,
				.cli_show = bgp_neighbor_tcp_mss_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/port",
			.cbs = {
				.modify  = bgp_neighbor_port_modify,
				.destroy = bgp_neighbor_port_destroy,
				.cli_show = bgp_neighbor_port_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-role",
			.cbs = {
				.apply_finish = bgp_neighbor_local_role_apply_finish,
				.destroy      = bgp_neighbor_local_role_destroy,
				.cli_show = bgp_neighbor_local_role_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/enable",
			.cbs = {
				.modify  = bgp_neighbor_gr_enable_modify,
				.destroy = bgp_neighbor_gr_enable_destroy,
				.cli_show = bgp_neighbor_gr_enable_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-helper",
			.cbs = {
				.modify  = bgp_neighbor_gr_helper_modify,
				.destroy = bgp_neighbor_gr_helper_destroy,
				.cli_show = bgp_neighbor_gr_helper_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-disable",
			.cbs = {
				.modify  = bgp_neighbor_gr_disable_modify,
				.destroy = bgp_neighbor_gr_disable_destroy,
				.cli_show = bgp_neighbor_gr_disable_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers",
			.cbs = {
				.apply_finish = bgp_neighbor_timers_apply_finish,
				.destroy      = bgp_neighbor_timers_destroy,
				.cli_show = bgp_neighbor_timers_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/oad",
			.cbs = {
				.modify  = bgp_neighbor_oad_modify,
				.destroy = bgp_neighbor_oad_destroy,
				.cli_show = bgp_neighbor_oad_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ls-local-link-id",
			.cbs = {
				.modify  = bgp_neighbor_ls_local_link_id_modify,
				.destroy = bgp_neighbor_ls_local_link_id_destroy,
				.cli_show = bgp_neighbor_ls_local_link_id_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ls-remote-link-id",
			.cbs = {
				.modify  = bgp_neighbor_ls_remote_link_id_modify,
				.destroy = bgp_neighbor_ls_remote_link_id_destroy,
				.cli_show = bgp_neighbor_ls_remote_link_id_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/peer-graceful-shutdown",
			.cbs = {
				.modify  = bgp_neighbor_peer_graceful_shutdown_modify,
				.destroy = bgp_neighbor_peer_graceful_shutdown_destroy,
				.cli_show = bgp_neighbor_peer_graceful_shutdown_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers-delayopen",
			.cbs = {
				.modify  = bgp_neighbor_timers_delayopen_modify,
				.destroy = bgp_neighbor_timers_delayopen_destroy,
				.cli_show = bgp_neighbor_timers_delayopen_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/shutdown-rtt",
			.cbs = {
				.apply_finish = bgp_neighbor_shutdown_rtt_apply_finish,
				.destroy      = bgp_neighbor_shutdown_rtt_destroy,
				.cli_show = bgp_neighbor_shutdown_rtt_cli_show,
			},
		},

		/* Phase 3c — per-AF per-peer flag toggles. */
#define BGP_NB_AF_XPATH(_leaf)                                                 \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/" \
	"frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/" _leaf
		{ .xpath = BGP_NB_AF_XPATH("soft-reconfiguration-inbound"),
		  .cbs = { .modify = bgp_neighbor_af_soft_reconfig_in_modify,
			   .destroy = bgp_neighbor_af_soft_reconfig_in_destroy,
			   .cli_show = bgp_neighbor_af_soft_reconfig_in_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("as-override"),
		  .cbs = { .modify = bgp_neighbor_af_as_override_modify,
			   .destroy = bgp_neighbor_af_as_override_destroy,
			   .cli_show = bgp_neighbor_af_as_override_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("route-reflector-client"),
		  .cbs = { .modify = bgp_neighbor_af_rr_client_modify,
			   .destroy = bgp_neighbor_af_rr_client_destroy,
			   .cli_show = bgp_neighbor_af_rr_client_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("route-server-client"),
		  .cbs = { .modify = bgp_neighbor_af_rs_client_modify,
			   .destroy = bgp_neighbor_af_rs_client_destroy,
			   .cli_show = bgp_neighbor_af_rs_client_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("next-hop-self"),
		  .cbs = { .modify = bgp_neighbor_af_nexthop_self_modify,
			   .destroy = bgp_neighbor_af_nexthop_self_destroy,
			   .cli_show = bgp_neighbor_af_nexthop_self_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("next-hop-self-force"),
		  .cbs = { .modify = bgp_neighbor_af_nexthop_self_force_modify,
			   .destroy = bgp_neighbor_af_nexthop_self_force_destroy,
			   .cli_show = bgp_neighbor_af_nexthop_self_force_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("remove-private-as"),
		  .cbs = { .modify = bgp_neighbor_af_remove_private_as_modify,
			   .destroy = bgp_neighbor_af_remove_private_as_destroy,
			   .cli_show = bgp_neighbor_af_remove_private_as_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("remove-private-as-all"),
		  .cbs = { .modify = bgp_neighbor_af_remove_private_as_all_modify,
			   .destroy = bgp_neighbor_af_remove_private_as_all_destroy,
			   .cli_show = bgp_neighbor_af_remove_private_as_all_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("remove-private-as-replace-as"),
		  .cbs = { .modify = bgp_neighbor_af_remove_private_as_replace_modify,
			   .destroy = bgp_neighbor_af_remove_private_as_replace_destroy,
			   .cli_show = bgp_neighbor_af_remove_private_as_replace_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("remove-private-as-all-replace-as"),
		  .cbs = { .modify = bgp_neighbor_af_remove_private_as_all_replace_modify,
			   .destroy = bgp_neighbor_af_remove_private_as_all_replace_destroy,
			   .cli_show = bgp_neighbor_af_remove_private_as_all_replace_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("nexthop-local-unchanged"),
		  .cbs = { .modify = bgp_neighbor_af_nexthop_local_unchanged_modify,
			   .destroy = bgp_neighbor_af_nexthop_local_unchanged_destroy,
			   .cli_show = bgp_neighbor_af_nexthop_local_unchanged_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("send-community-standard"),
		  .cbs = { .modify = bgp_neighbor_af_send_community_modify,
			   .destroy = bgp_neighbor_af_send_community_destroy,
			   .cli_show = bgp_neighbor_af_send_community_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("send-community-extended"),
		  .cbs = { .modify = bgp_neighbor_af_send_ext_community_modify,
			   .destroy = bgp_neighbor_af_send_ext_community_destroy,
			   .cli_show = bgp_neighbor_af_send_ext_community_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("send-community-large"),
		  .cbs = { .modify = bgp_neighbor_af_send_large_community_modify,
			   .destroy = bgp_neighbor_af_send_large_community_destroy,
			   .cli_show = bgp_neighbor_af_send_large_community_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("graceful-shutdown"),
		  .cbs = { .modify = bgp_neighbor_af_graceful_shutdown_modify,
			   .destroy = bgp_neighbor_af_graceful_shutdown_destroy,
			   .cli_show = bgp_neighbor_af_graceful_shutdown_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("accept-own"),
		  .cbs = { .modify = bgp_neighbor_af_accept_own_modify,
			   .destroy = bgp_neighbor_af_accept_own_destroy,
			   .cli_show = bgp_neighbor_af_accept_own_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("disable-addpath-rx"),
		  .cbs = { .modify = bgp_neighbor_af_disable_addpath_rx_modify,
			   .destroy = bgp_neighbor_af_disable_addpath_rx_destroy,
			   .cli_show = bgp_neighbor_af_disable_addpath_rx_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("addpath-tx-all-paths"),
		  .cbs = { .modify = bgp_neighbor_af_addpath_tx_all_modify,
			   .destroy = bgp_neighbor_af_addpath_tx_all_destroy,
			   .cli_show = bgp_neighbor_af_addpath_tx_all_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("addpath-tx-bestpath-per-as"),
		  .cbs = { .modify = bgp_neighbor_af_addpath_tx_bestpath_per_as_modify,
			   .destroy = bgp_neighbor_af_addpath_tx_bestpath_per_as_destroy,
			   .cli_show = bgp_neighbor_af_addpath_tx_bestpath_per_as_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("enabled"),
		  .cbs = { .modify = bgp_neighbor_af_enabled_modify,
			   .destroy = bgp_neighbor_af_enabled_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("encapsulation-srv6"),
		  .cbs = { .modify = bgp_neighbor_af_encapsulation_srv6_modify,
			   .destroy = bgp_neighbor_af_encapsulation_srv6_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("encapsulation-mpls"),
		  .cbs = { .modify = bgp_neighbor_af_encapsulation_mpls_modify,
			   .destroy = bgp_neighbor_af_encapsulation_mpls_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("attribute-unchanged-as-path"),
		  .cbs = { .modify = bgp_neighbor_af_attr_unchanged_as_path_modify,
			   .destroy = bgp_neighbor_af_attr_unchanged_as_path_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("attribute-unchanged-next-hop"),
		  .cbs = { .modify = bgp_neighbor_af_attr_unchanged_next_hop_modify,
			   .destroy = bgp_neighbor_af_attr_unchanged_next_hop_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
		{ .xpath = BGP_NB_AF_XPATH("attribute-unchanged-med"),
		  .cbs = { .modify = bgp_neighbor_af_attr_unchanged_med_modify,
			   .destroy = bgp_neighbor_af_attr_unchanged_med_destroy,
			   .cli_show = bgp_nb_handled_by_parent_cli_show } },
#undef BGP_NB_AF_XPATH

		/* Phase 3b (peer-group) entries. */
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group",
			.cbs = {
				.create  = bgp_peer_group_create,
				.destroy = bgp_peer_group_destroy,
				.cli_show = bgp_peer_group_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv4-listen-range",
			.cbs = {
				.create  = bgp_peer_group_ipv4_listen_range_create,
				.destroy = bgp_peer_group_ipv4_listen_range_destroy,
				.cli_show = bgp_peer_group_ipv4_listen_range_cli_show,
			},
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv6-listen-range",
			.cbs = {
				.create  = bgp_peer_group_ipv6_listen_range_create,
				.destroy = bgp_peer_group_ipv6_listen_range_destroy,
				.cli_show = bgp_peer_group_ipv6_listen_range_cli_show,
			},
		},

		/* Phase 3c (address-family) entries go here. */

		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
