// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgpd northbound — module registration and XPath macros.
 *
 * Tracks the migration of bgpd to the YANG/Northbound management model
 * (FRRouting/frr#5428). This header is intentionally minimal at first; each
 * phase of the migration plan (`BGPD_NB_MIGRATION_PLAN.md`) adds the
 * declarations for callbacks it converts.
 */

#ifndef _FRR_BGP_NB_H_
#define _FRR_BGP_NB_H_

#include "lib/northbound.h"
#include "lib/vrf.h"

#include "bgpd/bgpd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_info;

/*
 * XPath roots for the frr-bgp YANG module.
 *
 * The list keys for `control-plane-protocol` are `type`, `name`, `vrf` (see
 * `yang/frr-routing.yang:242-263`). For bgpd we use:
 *   - type: always `frr-bgp:bgp`
 *   - name: always `bgp` (default instance) or the view name
 *   - vrf:  vrf name (`default` for the global table)
 */

#define BGP_INSTANCE_KEY_XPATH                                                 \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']"

#define BGP_CONTAINER_XPATH BGP_INSTANCE_KEY_XPATH "/frr-bgp:bgp"

#define BGP_GLOBAL_XPATH BGP_CONTAINER_XPATH "/global"

#define BGP_GLOBAL_ROUTER_ID_XPATH BGP_GLOBAL_XPATH "/router-id"

#define BGP_NEIGHBORS_XPATH BGP_CONTAINER_XPATH "/neighbors"

#define BGP_NEIGHBOR_XPATH BGP_NEIGHBORS_XPATH "/neighbor[remote-address='%s']"

#define BGP_PEER_GROUPS_XPATH BGP_CONTAINER_XPATH "/peer-groups"

#define BGP_PEER_GROUP_XPATH                                                   \
	BGP_PEER_GROUPS_XPATH "/peer-group[peer-group-name='%s']"

/*
 * Helpers to derive the `control-plane-protocol` list keys from a
 * `struct bgp *`. Used by every DEFPY_YANG that builds a bgp-rooted xpath:
 *
 *   nb_cli_apply_changes(vty, BGP_GLOBAL_XPATH,
 *                        "frr-bgp:bgp",
 *                        bgp_nb_cpp_name(bgp),
 *                        bgp_nb_vrf_key(bgp));
 */
static inline const char *bgp_nb_cpp_name(const struct bgp *bgp)
{
	return (bgp->name && bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
		       ? bgp->name
		       : "bgp";
}

static inline const char *bgp_nb_vrf_key(const struct bgp *bgp)
{
	return (bgp->name && bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		       ? bgp->name
		       : VRF_DEFAULT_NAME;
}

/*
 * Callback prototypes — added per migration phase.
 */

/* --- Phase 2.0: control-plane-protocol context (bgp container) ----------- */

int bgp_router_create(struct nb_cb_create_args *args);
int bgp_router_destroy(struct nb_cb_destroy_args *args);

/* --- Phase 2: global leaves --------------------------------------------- */

int bgp_global_router_id_modify(struct nb_cb_modify_args *args);
int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args);
int bgp_global_default_shutdown_destroy(struct nb_cb_destroy_args *args);
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_show_hostname_destroy(struct nb_cb_destroy_args *args);
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args);
int bgp_global_always_compare_med_modify(struct nb_cb_modify_args *args);
int bgp_global_always_compare_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_external_compare_router_id_modify(struct nb_cb_modify_args *args);
int bgp_global_external_compare_router_id_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_ignore_as_path_length_modify(struct nb_cb_modify_args *args);
int bgp_global_ignore_as_path_length_destroy(struct nb_cb_destroy_args *args);
int bgp_global_aspath_confed_modify(struct nb_cb_modify_args *args);
int bgp_global_aspath_confed_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confed_med_modify(struct nb_cb_modify_args *args);
int bgp_global_confed_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_missing_as_worst_med_modify(struct nb_cb_modify_args *args);
int bgp_global_missing_as_worst_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_log_neighbor_changes_modify(struct nb_cb_modify_args *args);
int bgp_global_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args);
int bgp_global_import_check_modify(struct nb_cb_modify_args *args);
int bgp_global_import_check_destroy(struct nb_cb_destroy_args *args);
int bgp_global_wpkt_quanta_modify(struct nb_cb_modify_args *args);
int bgp_global_wpkt_quanta_destroy(struct nb_cb_destroy_args *args);
int bgp_global_rpkt_quanta_modify(struct nb_cb_modify_args *args);
int bgp_global_rpkt_quanta_destroy(struct nb_cb_destroy_args *args);
int bgp_global_coalesce_time_modify(struct nb_cb_modify_args *args);
int bgp_global_coalesce_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args);
int bgp_global_subgroup_pkt_queue_size_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args);
int bgp_global_confederation_identifier_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_confederation_member_as_create(
	struct nb_cb_create_args *args);
int bgp_global_confederation_member_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_minimum_holdtime_modify(struct nb_cb_modify_args *args);
int bgp_global_minimum_holdtime_destroy(struct nb_cb_destroy_args *args);
int bgp_global_allow_martian_nexthop_modify(struct nb_cb_modify_args *args);
int bgp_global_allow_martian_nexthop_destroy(struct nb_cb_destroy_args *args);
int bgp_global_use_underlays_nexthop_weight_modify(
	struct nb_cb_modify_args *args);
int bgp_global_use_underlays_nexthop_weight_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_allow_outbound_policy_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bgp_ls_distribute_create(struct nb_cb_create_args *args);
int bgp_global_bgp_ls_distribute_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bgp_ls_distribute_instance_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bestpath_aigp_modify(struct nb_cb_modify_args *args);
int bgp_global_bestpath_aigp_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bestpath_use_imported_attributes_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bestpath_use_imported_attributes_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_dynamic_neighbors_limit_modify(
	struct nb_cb_modify_args *args);
int bgp_global_dynamic_neighbors_limit_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_med_config_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_global_med_config_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_software_version_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_software_version_capability_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_tcp_keepalive_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_global_tcp_keepalive_destroy(struct nb_cb_destroy_args *args);
int bgp_global_hold_time_modify(struct nb_cb_modify_args *args);
int bgp_global_hold_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_keepalive_modify(struct nb_cb_modify_args *args);
int bgp_global_keepalive_destroy(struct nb_cb_destroy_args *args);
int bgp_global_reject_as_sets_modify(struct nb_cb_modify_args *args);
int bgp_global_reject_as_sets_destroy(struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_enabled_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_enabled_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_restart_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_selection_deferral_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_administrative_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_global_administrative_shutdown_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_enforce_first_as_global_modify(
	struct nb_cb_modify_args *args);
int bgp_global_enforce_first_as_global_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args);
int bgp_global_suppress_duplicates_destroy(struct nb_cb_destroy_args *args);
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
int bgp_global_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args);
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args);
int bgp_global_fast_external_failover_destroy(struct nb_cb_destroy_args *args);
int bgp_global_deterministic_med_modify(struct nb_cb_modify_args *args);
int bgp_global_deterministic_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_labeled_unicast_explicit_null_modify(
	struct nb_cb_modify_args *args);
int bgp_global_labeled_unicast_explicit_null_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_ipv6_auto_ra_modify(struct nb_cb_modify_args *args);
int bgp_global_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args);
int bgp_global_allow_multiple_as_modify(struct nb_cb_modify_args *args);
int bgp_global_allow_multiple_as_destroy(struct nb_cb_destroy_args *args);
int bgp_global_multi_path_as_set_modify(struct nb_cb_modify_args *args);
int bgp_global_multi_path_as_set_destroy(struct nb_cb_destroy_args *args);
int bgp_global_peer_type_multipath_relax_modify(
	struct nb_cb_modify_args *args);
int bgp_global_peer_type_multipath_relax_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_shutdown_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_suppress_fib_pending_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_global_suppress_fib_pending_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_advertisement_delay_global_modify(
	struct nb_cb_modify_args *args);
int bgp_global_advertisement_delay_global_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_update_delay_time_modify(struct nb_cb_modify_args *args);
int bgp_global_update_delay_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_establish_wait_time_modify(struct nb_cb_modify_args *args);
int bgp_global_establish_wait_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_connect_retry_interval_modify(struct nb_cb_modify_args *args);
int bgp_global_connect_retry_interval_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_conditional_advertisement_period_modify(
	struct nb_cb_modify_args *args);
int bgp_global_conditional_advertisement_period_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_default_originate_timer_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_originate_timer_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bestpath_bandwidth_modify(struct nb_cb_modify_args *args);
int bgp_global_bestpath_bandwidth_destroy(struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_notification_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_notification_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_long_lived_graceful_restart_stale_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_long_lived_graceful_restart_stale_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_fast_convergence_modify(struct nb_cb_modify_args *args);
int bgp_global_fast_convergence_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_link_local_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_link_local_capability_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_default_dynamic_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_dynamic_capability_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_route_reflector_cluster_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_no_client_reflect_modify(struct nb_cb_modify_args *args);
int bgp_global_no_client_reflect_destroy(struct nb_cb_destroy_args *args);
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args);
int bgp_global_local_pref_destroy(struct nb_cb_destroy_args *args);
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args);
int bgp_global_ebgp_multihop_connected_route_check_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_rib_stale_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_preserve_fw_entry_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_stale_routes_time_destroy(
	struct nb_cb_destroy_args *args);

/* --- Phase 3a (neighbor): list entry create/destroy + remote-as leaves --- */

int bgp_neighbor_create(struct nb_cb_create_args *args);
int bgp_neighbor_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_remote_as_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_password_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_password_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_description_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_description_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_passive_mode_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_passive_mode_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_solo_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_solo_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ttl_security_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_admin_shutdown_enable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_admin_shutdown_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_admin_shutdown_message_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_admin_shutdown_message_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_enabled_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_enabled_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_ttl_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_ttl_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_disable_connected_check_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_update_source_ip_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_update_source_ip_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_update_source_interface_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_timers_connect_time_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_timers_connect_time_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_local_as_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_neighbor_local_as_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_bfd_options_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_neighbor_bfd_options_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_dynamic_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_strict_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_strict_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_override_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_override_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_extended_nexthop_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_extended_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_negotiate_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_negotiate_destroy(
	struct nb_cb_destroy_args *args);

/* --- Phase 3a direct-child flag batch (BGP_NEIGHBOR_FLAG_CB macro) --- */
#define _BGP_NB_PEER_FLAG_DECL(_name)                                          \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args);     \
	int bgp_neighbor_##_name##_destroy(struct nb_cb_destroy_args *args)
_BGP_NB_PEER_FLAG_DECL(aigp);
_BGP_NB_PEER_FLAG_DECL(ip_transparent);
_BGP_NB_PEER_FLAG_DECL(extended_link_bandwidth);
_BGP_NB_PEER_FLAG_DECL(disable_link_bw_encoding_ieee);
_BGP_NB_PEER_FLAG_DECL(extended_optional_parameters);
_BGP_NB_PEER_FLAG_DECL(send_nexthop_characteristics);
_BGP_NB_PEER_FLAG_DECL(rpki_strict);
_BGP_NB_PEER_FLAG_DECL(capability_fqdn);
_BGP_NB_PEER_FLAG_DECL(capability_link_local);
_BGP_NB_PEER_FLAG_DECL(as_loop_detection);
_BGP_NB_PEER_FLAG_DECL(capability_software_version);
_BGP_NB_PEER_FLAG_DECL(capability_software_version_latest_encoding);
_BGP_NB_PEER_FLAG_DECL(peer_graceful_shutdown);
int bgp_neighbor_timers_delayopen_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_timers_delayopen_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_shutdown_rtt_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_neighbor_shutdown_rtt_destroy(struct nb_cb_destroy_args *args);
#undef _BGP_NB_PEER_FLAG_DECL

int bgp_neighbor_tcp_mss_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_tcp_mss_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_port_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_port_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_local_role_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_neighbor_local_role_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_enable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_helper_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_helper_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_disable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_disable_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_timers_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_neighbor_timers_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_oad_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_oad_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ls_local_link_id_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ls_local_link_id_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ls_remote_link_id_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args);

/* --- Phase 3c (neighbor per-AF flag toggles) --- */
#define _BGP_NB_PEER_AF_FLAG_DECL(_name)                                       \
	int bgp_neighbor_af_##_name##_modify(struct nb_cb_modify_args *args);  \
	int bgp_neighbor_af_##_name##_destroy(                                 \
		struct nb_cb_destroy_args *args)
_BGP_NB_PEER_AF_FLAG_DECL(soft_reconfig_in);
_BGP_NB_PEER_AF_FLAG_DECL(as_override);
_BGP_NB_PEER_AF_FLAG_DECL(rr_client);
_BGP_NB_PEER_AF_FLAG_DECL(rs_client);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_self);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_self_force);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_all);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_replace);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_all_replace);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_local_unchanged);
_BGP_NB_PEER_AF_FLAG_DECL(send_community);
_BGP_NB_PEER_AF_FLAG_DECL(send_ext_community);
_BGP_NB_PEER_AF_FLAG_DECL(send_large_community);
_BGP_NB_PEER_AF_FLAG_DECL(graceful_shutdown);
_BGP_NB_PEER_AF_FLAG_DECL(accept_own);
_BGP_NB_PEER_AF_FLAG_DECL(disable_addpath_rx);
_BGP_NB_PEER_AF_FLAG_DECL(addpath_tx_all);
_BGP_NB_PEER_AF_FLAG_DECL(addpath_tx_bestpath_per_as);
_BGP_NB_PEER_AF_FLAG_DECL(enabled);
_BGP_NB_PEER_AF_FLAG_DECL(encapsulation_srv6);
_BGP_NB_PEER_AF_FLAG_DECL(encapsulation_mpls);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_as_path);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_next_hop);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_med);
#undef _BGP_NB_PEER_AF_FLAG_DECL

/* --- Phase 3b (peer-group): list create/destroy + listen-range leaf-lists --- */

int bgp_peer_group_create(struct nb_cb_create_args *args);
int bgp_peer_group_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_group_ipv4_listen_range_create(struct nb_cb_create_args *args);
int bgp_peer_group_ipv4_listen_range_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_group_ipv6_listen_range_create(struct nb_cb_create_args *args);
int bgp_peer_group_ipv6_listen_range_destroy(struct nb_cb_destroy_args *args);

/* --- Phase 3c (address-family): declarations go here --- */

/* --- Phase 5 cli_show callbacks (example wiring; full set is TODO) --- */
void bgp_global_router_id_cli_show(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
void bgp_global_default_shutdown_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
void bgp_global_log_neighbor_changes_cli_show(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults);
void bgp_global_fast_convergence_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults);
void bgp_global_allow_martian_nexthop_cli_show(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults);
void bgp_neighbor_passive_mode_cli_show(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
void bgp_neighbor_solo_cli_show(struct vty *vty,
				const struct lyd_node *dnode,
				bool show_defaults);
void bgp_neighbor_enforce_first_as_cli_show(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults);
void bgp_neighbor_description_cli_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
void bgp_neighbor_password_cli_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);

/* Bulk-generated via BGP_GLOBAL_BOOL_CLI_SHOW / BGP_NEIGHBOR_BOOL_CLI_SHOW. */
#define _BGP_GBL_CLI(_n) void bgp_global_##_n##_cli_show(struct vty *, \
	const struct lyd_node *, bool)
#define _BGP_PEER_CLI(_n) void bgp_neighbor_##_n##_cli_show(struct vty *, \
	const struct lyd_node *, bool)
_BGP_GBL_CLI(deterministic_med);
_BGP_GBL_CLI(always_compare_med);
_BGP_GBL_CLI(import_check);
_BGP_GBL_CLI(suppress_duplicates);
_BGP_GBL_CLI(reject_as_sets);
_BGP_GBL_CLI(ebgp_requires_policy);
_BGP_GBL_CLI(show_hostname);
_BGP_GBL_CLI(show_nexthop_hostname);
_BGP_GBL_CLI(graceful_shutdown);
_BGP_GBL_CLI(no_client_to_client_reflection);
_BGP_GBL_CLI(cluster_id_self);
_BGP_GBL_CLI(disable_ebgp_connected_route_check);
_BGP_GBL_CLI(enforce_first_as_global);
_BGP_GBL_CLI(default_link_local_capability);
_BGP_GBL_CLI(default_dynamic_capability);
_BGP_GBL_CLI(use_underlays_nexthop_weight);
_BGP_GBL_CLI(peer_type_multipath_relax);
_BGP_GBL_CLI(ipv6_auto_ra);
_BGP_PEER_CLI(aigp);
_BGP_PEER_CLI(ip_transparent);
_BGP_PEER_CLI(extended_link_bandwidth);
_BGP_PEER_CLI(disable_link_bw_encoding_ieee);
_BGP_PEER_CLI(extended_optional_parameters);
_BGP_PEER_CLI(send_nexthop_characteristics);
_BGP_PEER_CLI(rpki_strict);
_BGP_PEER_CLI(capability_fqdn);
_BGP_PEER_CLI(capability_link_local);
_BGP_PEER_CLI(as_loop_detection);
_BGP_PEER_CLI(oad);
_BGP_PEER_CLI(peer_graceful_shutdown);
#undef _BGP_GBL_CLI
#undef _BGP_PEER_CLI

/* Per-AF cli_show forward decls. */
#define _BGP_AF_CLI(_n) void bgp_neighbor_af_##_n##_cli_show(struct vty *, \
	const struct lyd_node *, bool)
_BGP_AF_CLI(soft_reconfig_in);
_BGP_AF_CLI(as_override);
_BGP_AF_CLI(rr_client);
_BGP_AF_CLI(rs_client);
_BGP_AF_CLI(nexthop_self);
_BGP_AF_CLI(nexthop_self_force);
_BGP_AF_CLI(remove_private_as);
_BGP_AF_CLI(remove_private_as_all);
_BGP_AF_CLI(remove_private_as_replace);
_BGP_AF_CLI(remove_private_as_all_replace);
_BGP_AF_CLI(nexthop_local_unchanged);
_BGP_AF_CLI(send_community);
_BGP_AF_CLI(send_ext_community);
_BGP_AF_CLI(send_large_community);
_BGP_AF_CLI(graceful_shutdown);
_BGP_AF_CLI(accept_own);
_BGP_AF_CLI(disable_addpath_rx);
_BGP_AF_CLI(addpath_tx_all);
_BGP_AF_CLI(addpath_tx_bestpath_per_as);
#undef _BGP_AF_CLI

/* Batch 2 forward decls. */
#define _BGP_GBL_CLI(_n) void bgp_global_##_n##_cli_show(struct vty *, \
	const struct lyd_node *, bool)
#define _BGP_PEER_CLI(_n) void bgp_neighbor_##_n##_cli_show(struct vty *, \
	const struct lyd_node *, bool)
_BGP_GBL_CLI(coalesce_time);
_BGP_GBL_CLI(subgroup_pkt_queue_size);
_BGP_GBL_CLI(wpkt_quanta);
_BGP_GBL_CLI(rpkt_quanta);
_BGP_GBL_CLI(minimum_holdtime);
_BGP_GBL_CLI(dynamic_neighbors_limit);
_BGP_GBL_CLI(advertisement_delay_global);
_BGP_GBL_CLI(update_delay_time);
_BGP_GBL_CLI(restart_time);
_BGP_GBL_CLI(selection_deferral_time);
_BGP_GBL_CLI(external_compare_router_id);
_BGP_GBL_CLI(ignore_as_path_length);
_BGP_GBL_CLI(aspath_confed);
_BGP_GBL_CLI(confed_med);
_BGP_GBL_CLI(missing_as_worst_med);
_BGP_GBL_CLI(bestpath_aigp);
_BGP_GBL_CLI(bestpath_use_imported_attributes);
_BGP_GBL_CLI(allow_multiple_as);
_BGP_GBL_CLI(multi_path_as_set);
_BGP_GBL_CLI(confederation_identifier);
_BGP_GBL_CLI(confederation_member_as);
_BGP_PEER_CLI(local_as);
_BGP_PEER_CLI(timers);
_BGP_PEER_CLI(local_role);
_BGP_PEER_CLI(admin_shutdown);
_BGP_PEER_CLI(ebgp_multihop);
_BGP_PEER_CLI(ttl_security);
_BGP_PEER_CLI(tcp_mss);
_BGP_PEER_CLI(port);
_BGP_PEER_CLI(timers_delayopen);
_BGP_PEER_CLI(ls_local_link_id);
_BGP_PEER_CLI(ls_remote_link_id);
_BGP_PEER_CLI(shutdown_rtt);
_BGP_PEER_CLI(neighbor_remote_as);
_BGP_PEER_CLI(update_source);
_BGP_PEER_CLI(capabilities_dynamic);
_BGP_PEER_CLI(capabilities_strict);
_BGP_PEER_CLI(capabilities_override);
_BGP_PEER_CLI(capabilities_extended_nexthop);
_BGP_PEER_CLI(capabilities_negotiate);
_BGP_GBL_CLI(always_compare_med);
_BGP_GBL_CLI(fast_external_failover);
_BGP_GBL_CLI(labeled_unicast_explicit_null);
_BGP_GBL_CLI(allow_outbound_policy);
_BGP_GBL_CLI(instance_id);
_BGP_GBL_CLI(default_software_version_capability);
_BGP_GBL_CLI(establish_wait_time);
_BGP_GBL_CLI(connect_retry_interval);
_BGP_GBL_CLI(conditional_advertisement_period);
_BGP_GBL_CLI(default_originate_timer);
_BGP_GBL_CLI(bestpath_bandwidth);
_BGP_GBL_CLI(graceful_restart_notification);
_BGP_GBL_CLI(long_lived_graceful_restart_stale_time);
_BGP_GBL_CLI(route_reflector_cluster_id);
_BGP_GBL_CLI(no_client_reflect);
_BGP_GBL_CLI(local_pref);
_BGP_GBL_CLI(ebgp_multihop_connected_route_check);
_BGP_GBL_CLI(rib_stale_time);
_BGP_GBL_CLI(preserve_fw_entry);
_BGP_GBL_CLI(stale_routes_time);
_BGP_GBL_CLI(med_config);
_BGP_GBL_CLI(tcp_keepalive);
_BGP_GBL_CLI(administrative_shutdown);
_BGP_GBL_CLI(suppress_fib_pending);
_BGP_GBL_CLI(bgp_ls_distribute);
_BGP_PEER_CLI(bfd_options);
_BGP_PEER_CLI(gr_enable);
_BGP_PEER_CLI(gr_helper);
_BGP_PEER_CLI(gr_disable);
_BGP_PEER_CLI(capability_software_version);
_BGP_PEER_CLI(capability_software_version_latest_encoding);
void bgp_peer_group_cli_show(struct vty *, const struct lyd_node *, bool);
void bgp_peer_group_ipv4_listen_range_cli_show(struct vty *,
	const struct lyd_node *, bool);
void bgp_peer_group_ipv6_listen_range_cli_show(struct vty *,
	const struct lyd_node *, bool);

/*
 * No-op cli_show used for leaves whose parent container's cli_show
 * already emits the compound CLI block (apply_finish containers like
 * timers, local-as, admin-shutdown, ebgp-multihop, update-source,
 * neighbor-remote-as, local-role, shutdown-rtt, etc.). Wiring this
 * gives 100% raw .cli_show coverage and prevents accidental future
 * duplicate emission.
 */
void bgp_nb_handled_by_parent_cli_show(struct vty *, const struct lyd_node *,
				       bool);

#undef _BGP_GBL_CLI
#undef _BGP_PEER_CLI

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_H_ */
