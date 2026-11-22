// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound API
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_NB_H_
#define _FRR_BGP_NB_H_

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_info;

/* Instance create/destroy */
int bgp_nb_bgp_create(struct nb_cb_create_args *args);
int bgp_nb_bgp_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_routing_destroy(struct nb_cb_destroy_args *args);

void bgp_nb_cli_show_router_bgp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_router_bgp_end(struct vty *vty, const struct lyd_node *dnode);

struct bgp;
const char *bgp_nb_instance_xpath(const struct bgp *bgp, char *buf, size_t buflen);

/*
 * True when path-attribute @attr_num cannot be discarded (or treated as
 * withdraw). @dnode is a neighbor, unnumbered-neighbor or peer-group node,
 * or a node below one, in the candidate. @errmsg gets the reason.
 */
bool bgp_nb_path_attr_forbidden(const struct lyd_node *dnode, uint8_t attr_num, bool withdraw,
				char *errmsg, size_t errmsg_len);
void bgp_nb_cli_show_instance(struct vty *vty, const struct lyd_node *dnode);
void bgp_nb_cli_show_instance_bgp(struct vty *vty, struct bgp *bgp);

/* Global leaves */
int bgp_nb_local_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_local_as_pretty_modify(struct nb_cb_modify_args *args);
int bgp_nb_local_as_pretty_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_router_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_router_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_instance_type_view_modify(struct nb_cb_modify_args *args);
int bgp_nb_as_notation_modify(struct nb_cb_modify_args *args);

int bgp_nb_log_neighbor_changes_modify(struct nb_cb_modify_args *args);
int bgp_nb_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_log_neighbor_changes(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
int bgp_nb_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_ebgp_requires_policy(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_import_check_modify(struct nb_cb_modify_args *args);
int bgp_nb_import_check_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_import_check(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);


int bgp_nb_cluster_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_cluster_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_cluster_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_no_client_reflect_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_no_client_reflect(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_always_compare_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_always_compare_med(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_deterministic_med_modify(struct nb_cb_modify_args *args);
int bgp_nb_deterministic_med_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_deterministic_med(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_local_pref_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_local_pref(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_fast_external_failover_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_fast_external_failover(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_suppress_duplicates_modify(struct nb_cb_modify_args *args);
int bgp_nb_suppress_duplicates_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_suppress_duplicates(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

int bgp_nb_graceful_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_reject_as_sets_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_reject_as_sets(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_enforce_first_as_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_connected_route_check_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_connected_route_check(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_allow_outbound_policy_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_allow_outbound_policy(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_hard_admin_reset_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_hard_admin_reset(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_show_hostname_modify(struct nb_cb_modify_args *args);
int bgp_nb_show_hostname_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_show_hostname(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
int bgp_nb_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_show_nexthop_hostname(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_external_compare_router_id_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_external_compare_router_id(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

int bgp_nb_ignore_as_path_length_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_ignore_as_path_length(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_compare_aigp_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_compare_aigp(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_use_imported_attributes_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_use_imported_attributes(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_prefer_mpls_over_srv6_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_prefer_mpls_over_srv6(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_aspath_confed_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_aspath_confed(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_allow_multiple_as_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_allow_multiple_as(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_multi_path_as_set_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_multi_path_as_set(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_type_multipath_relax(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_confed_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_confed_med(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_missing_as_worst_med_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_missing_as_worst_med(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_bandwidth_handling_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_bandwidth_handling(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_keepalive_modify(struct nb_cb_modify_args *args);
int bgp_nb_keepalive_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_hold_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_hold_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_keepalive(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_holdtime(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_minimum_holdtime_modify(struct nb_cb_modify_args *args);
int bgp_nb_minimum_holdtime_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_minimum_holdtime(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_confederation_identifier_modify(struct nb_cb_modify_args *args);
int bgp_nb_confederation_identifier_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_confederation_identifier(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_confederation_identifier_pretty_modify(struct nb_cb_modify_args *args);
int bgp_nb_confederation_identifier_pretty_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_confederation_member_as_create(struct nb_cb_create_args *args);
int bgp_nb_confederation_member_as_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_confederation_member_as(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_confederation_member_as_pretty_create(struct nb_cb_create_args *args);
int bgp_nb_confederation_member_as_pretty_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_confederation_member_as_pretty_val_modify(struct nb_cb_modify_args *args);

int bgp_nb_enable_med_admin_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_enable_med_admin(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_max_med_admin_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_max_med_admin(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_max_med_onstartup_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_max_med_onstartup_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_max_med_onstartup_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_max_med_onstartup_value_modify(struct nb_cb_modify_args *args);

int bgp_nb_update_delay_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_update_delay_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_update_delay_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_establish_wait_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_establish_wait_time_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_advertisement_delay_modify(struct nb_cb_modify_args *args);
int bgp_nb_advertisement_delay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_advertisement_delay(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

int bgp_nb_conditional_advertisement_timer_modify(struct nb_cb_modify_args *args);
int bgp_nb_conditional_advertisement_timer_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_conditional_advertisement_timer(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);

int bgp_nb_default_originate_timer_modify(struct nb_cb_modify_args *args);
int bgp_nb_default_originate_timer_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_originate_timer(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);


int bgp_nb_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_dynamic_neighbors_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_default_afi_safi_create(struct nb_cb_create_args *args);
int bgp_nb_default_afi_safi_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_gr_stale_routes_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_stale_routes_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_gr_restart_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_restart_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_gr_select_defer_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_select_defer_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_gr_rib_stale_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_rib_stale_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_gr_preserve_fw_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_preserve_fw_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_preserve_fw(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_gr_notification_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_notification_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_notification(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_gr_disable_eor_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_disable_eor(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_gr_llgr_stale_time_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_llgr_stale_time(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_gr_enabled_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_enabled_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_enabled(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_gr_disable_modify(struct nb_cb_modify_args *args);
int bgp_nb_gr_disable_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_gr_disable(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_tcp_keepalive_idle_modify(struct nb_cb_modify_args *args);
int bgp_nb_tcp_keepalive_idle_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_tcp_keepalive_interval_modify(struct nb_cb_modify_args *args);
int bgp_nb_tcp_keepalive_interval_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_tcp_keepalive_probes_modify(struct nb_cb_modify_args *args);
int bgp_nb_tcp_keepalive_probes_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_tcp_keepalive_idle(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_wpkt_quanta_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_wpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_rpkt_quanta_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_rpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_coalesce_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_coalesce_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_coalesce_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_subgroup_pkt_queue_size(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_default_originate_setonly_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_originate_setonly(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_default_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_shutdown(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_shutdown(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_shutdown_message_modify(struct nb_cb_modify_args *args);
int bgp_nb_shutdown_message_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_shutdown_no_notify_modify(struct nb_cb_modify_args *args);
int bgp_nb_shutdown_no_notify_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_shutdown_no_notify(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_allow_martian_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_allow_martian(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_use_underlays_nexthop_weight_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_use_underlays_nexthop_weight(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);

int bgp_nb_suppress_fib_pending_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_suppress_fib_pending(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_suppress_fib_pending_delay_modify(struct nb_cb_modify_args *args);
int bgp_nb_suppress_fib_pending_delay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_suppress_fib_pending_delay(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

int bgp_nb_fast_convergence_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_fast_convergence(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_ipv6_auto_ra_modify(struct nb_cb_modify_args *args);
int bgp_nb_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_labeled_unicast_explicit_null_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_labeled_unicast_explicit_null(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_default_dynamic_capability_modify(struct nb_cb_modify_args *args);
int bgp_nb_default_dynamic_capability_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_dynamic_capability(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

int bgp_nb_default_link_local_capability_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_link_local_capability(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_default_software_version_capability_modify(struct nb_cb_modify_args *args);
int bgp_nb_default_software_version_capability_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_software_version_capability(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults);
int bgp_nb_default_software_version_latest_modify(struct nb_cb_modify_args *args);
int bgp_nb_default_software_version_latest_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_software_version_latest(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);

/* Numbered neighbors */
int bgp_nb_neighbor_create(struct nb_cb_create_args *args);
int bgp_nb_neighbor_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_neighbor(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_neighbor_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args);
int bgp_nb_neighbor_remote_as_type_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_neighbor_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_neighbor_remote_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_remote_as_pretty_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_remote_as_pretty_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_peer_apply_finish(struct nb_cb_apply_finish_args *args);

/* Peer-groups */
int bgp_nb_peer_group_create(struct nb_cb_create_args *args);
int bgp_nb_peer_group_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_group(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_peer_group_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_peer_group_remote_as_type_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_group_remote_as_type_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_group_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_peer_group_remote_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_group_remote_as_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_peer_group_listen_range_create(struct nb_cb_create_args *args);
int bgp_nb_peer_group_listen_range_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_group_listen_range(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

/* Unnumbered neighbors */
int bgp_nb_unnumbered_neighbor_create(struct nb_cb_create_args *args);
int bgp_nb_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_unnumbered_neighbor(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void bgp_nb_cli_show_unnumbered_neighbor_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_unnumbered_v6only_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_unnumbered_v6only(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_unnumbered_peer_group_modify(struct nb_cb_modify_args *args);
int bgp_nb_unnumbered_peer_group_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_unnumbered_peer_group(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

/* Shared neighbor / unnumbered / peer-group session leaves */
int bgp_nb_peer_password_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_password_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_password(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_peer_description_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_description_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_description(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_peer_passive_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_passive(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_peer_solo_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_solo(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_peer_shutdown_enable_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_shutdown_enable(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_peer_shutdown_message_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_shutdown_message_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_peer_shutdown_rtt_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_shutdown_rtt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_shutdown_rtt(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_peer_shutdown_rtt_count_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_shutdown_rtt_count_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_peer_update_source_ip_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_update_source_ip_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_update_source_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_update_source_if_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_update_source_if_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_update_source_if(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_ebgp_mh_enabled_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_ebgp_mh_enabled_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_ebgp_mh_enabled(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_ebgp_mh_ttl_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_ebgp_mh_ttl_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_ebgp_mh_ttl(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_peer_disable_connected_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_disable_connected(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_peer_ttl_security_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_ttl_security_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_ttl_security(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_peer_local_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_local_as_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_local_as_pretty_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_local_as_pretty_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_local_as(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_peer_local_as_no_prepend_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_local_as_replace_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_local_as_dual_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_timers_keepalive_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_timers_keepalive_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_timers_keepalive(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void bgp_nb_cli_show_peer_timers_holdtime(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_timers_holdtime_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_timers_holdtime_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_timers_connect_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_timers_connect_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_timers_connect(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_timers_delayopen_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_timers_delayopen_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_timers_delayopen(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_advertise_interval_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_advertise_interval_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_advertise_interval(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_peer_cap_dynamic_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_cap_dynamic_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_cap_dynamic(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_peer_cap_enhe_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_cap_enhe(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_peer_cap_negotiate_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_cap_negotiate(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
int bgp_nb_peer_cap_fqdn_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_cap_fqdn(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_peer_enforce_first_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_enforce_first_as_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);


int bgp_nb_peer_cap_soft_version_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_cap_soft_version_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_cap_soft_version(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_cap_soft_version_latest_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_cap_soft_version_latest_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_cap_soft_version_latest(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
int bgp_nb_peer_cap_link_local_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_cap_link_local_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_cap_link_local(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_cap_override_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_cap_override(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_peer_cap_strict_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_cap_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_tcp_mss_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_tcp_mss_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_tcp_mss(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
int bgp_nb_peer_ip_transparent_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_ip_transparent(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_rpki_strict_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_rpki_strict(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_peer_local_role_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_local_role_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_local_role(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_local_role_strict_modify(struct nb_cb_modify_args *args);


int bgp_nb_peer_bfd_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_enable_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_bfd_detect_mult_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_min_rx_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_min_tx_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_cbit_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_bfd_cbit(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_peer_bfd_profile_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_profile_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_peer_bfd_strict_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_bfd_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_bfd_strict_hold_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_strict_hold_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_bfd_strict_hold(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);


int bgp_nb_peer_path_attr_discard_create(struct nb_cb_create_args *args);
int bgp_nb_peer_path_attr_discard_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_path_attr_discard(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_peer_path_attr_withdraw_create(struct nb_cb_create_args *args);
int bgp_nb_peer_path_attr_withdraw_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_path_attr_withdraw(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_peer_gr_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_gr_enable_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_gr_enable(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_peer_gr_helper_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_gr_helper_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_gr_helper(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_peer_gr_disable_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_gr_disable_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_gr_disable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_aigp_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_aigp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_peer_oad_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_oad(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_peer_graceful_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);


int bgp_nb_neighbor_peer_group_modify(struct nb_cb_modify_args *args);
int bgp_nb_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_neighbor_peer_group(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_neighbor_local_port_modify(struct nb_cb_modify_args *args);
int bgp_nb_neighbor_local_port_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_neighbor_local_port(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_neighbor_local_interface_modify(struct nb_cb_modify_args *args);
int bgp_nb_neighbor_local_interface_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_neighbor_local_interface(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);


int bgp_nb_peer_afi_safi_create(struct nb_cb_create_args *args);
int bgp_nb_peer_afi_safi_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_af_enabled_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_enabled_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_enabled(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_peer_af_soft_reconfig_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_soft_reconfig(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_peer_af_encapsulation_create(struct nb_cb_create_args *args);
int bgp_nb_peer_af_encapsulation_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_encapsulation(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_af_nexthop_self_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_nexthop_self(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_af_nexthop_self_force_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_nexthop_self_force(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_aspath_unchanged_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_aspath_unchanged(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_peer_af_nexthop_unchanged_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_nexthop_unchanged(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_peer_af_med_unchanged_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_med_unchanged(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_af_as_override_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_as_override(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_af_remove_private_as_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_remove_private_as(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_peer_af_remove_private_as_all_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_remove_private_as_all(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
int bgp_nb_peer_af_remove_private_as_replace_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_remove_private_as_replace(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults);
int bgp_nb_peer_af_remove_private_as_all_replace_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_remove_private_as_all_replace(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults);
int bgp_nb_peer_af_reflector_client_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_reflector_client(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_peer_af_rserver_client_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_rserver_client(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_peer_af_weight_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_weight_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_weight(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_peer_af_send_community_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_send_community(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_peer_af_send_ext_community_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_send_ext_community(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_send_large_community_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_send_large_community(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
int bgp_nb_peer_af_send_ext_community_rpki_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_send_ext_community_rpki(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
int bgp_nb_peer_af_allow_own_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_allow_own_as_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_allow_own_as(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_af_allow_own_origin_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_allow_own_origin_as_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_allow_own_origin_as(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
int bgp_nb_peer_af_allowas_in_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_allowas_in_rmap_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_allowas_in_rmap(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_peer_af_default_originate_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_default_originate_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_default_originate(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_peer_af_default_originate_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_default_originate_rmap_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_default_originate_rmap(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
int bgp_nb_peer_af_plist_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_plist_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_plist_import(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_af_plist_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_plist_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_plist_export(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
int bgp_nb_peer_af_access_list_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_access_list_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_access_list_import(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_access_list_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_access_list_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_access_list_export(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_aspath_filter_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_aspath_filter_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_aspath_filter_import(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
int bgp_nb_peer_af_aspath_filter_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_aspath_filter_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_aspath_filter_export(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
int bgp_nb_peer_af_rmap_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_rmap_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_rmap_import(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_af_rmap_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_rmap_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_rmap_export(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_af_unsuppress_map_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_unsuppress_map_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_unsuppress_map_export(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
int bgp_nb_peer_af_prefix_limit_create(struct nb_cb_create_args *args);
int bgp_nb_peer_af_prefix_limit_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_af_prefix_limit_max_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_prefix_limit_force_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_prefix_limit_option_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_prefix_limit_option_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_prefix_limit_max(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void bgp_nb_cli_show_peer_af_prefix_limit_noop(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_peer_af_addpath_type_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_addpath_best_selected_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_addpath_best_selected_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_addpath_type(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void bgp_nb_cli_show_peer_af_addpath_best_selected(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
int bgp_nb_peer_af_disable_addpath_rx_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_disable_addpath_rx(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_addpath_rx_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_addpath_rx_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_addpath_rx_limit(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_peer_af_advertise_map_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_advertise_map_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_advertise_map(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_af_advertise_cond_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_advertise_cond_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_advertise_map_cond(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_peer_af_accept_own_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_accept_own(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
int bgp_nb_peer_af_soo_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_af_soo_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_af_soo(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_peer_af_upa_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_upa(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_peer_af_orf_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_nb_peer_af_orf_send_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_orf_send(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_peer_af_orf_receive_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_orf_receive(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_peer_af_nexthop_local_unchanged_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_af_nexthop_local_unchanged(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);

int bgp_nb_global_afi_safi_create(struct nb_cb_create_args *args);
int bgp_nb_global_afi_safi_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_global_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
void bgp_nb_cli_show_global_afi_safi_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_network_create(struct nb_cb_create_args *args);
int bgp_nb_network_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_network(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_network_backdoor_modify(struct nb_cb_modify_args *args);
int bgp_nb_network_label_index_modify(struct nb_cb_modify_args *args);
int bgp_nb_network_label_index_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_network_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_network_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_vpn_network_rd_create(struct nb_cb_create_args *args);
int bgp_nb_vpn_network_rd_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_vpn_network_prefix_create(struct nb_cb_create_args *args);
int bgp_nb_vpn_network_prefix_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_network_prefix(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
int bgp_nb_vpn_network_label_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_network_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_network_rmap_destroy(struct nb_cb_destroy_args *args);


void bgp_cli_init(void);
void bgp_cli_bmp_init(void);
void bgp_cli_snmp_traps_init(void);

#ifdef __cplusplus
}
#endif


int bgp_nb_aggregate_create(struct nb_cb_create_args *args);
int bgp_nb_aggregate_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_aggregate(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_aggregate_bool_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_origin_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_aggregate_suppress_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_suppress_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_aggregate_upa_max_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_upa_max_destroy(struct nb_cb_destroy_args *args);


int bgp_nb_maxpaths_ebgp_modify(struct nb_cb_modify_args *args);
int bgp_nb_maxpaths_ebgp_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_maxpaths_ebgp(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_maxpaths_ibgp_modify(struct nb_cb_modify_args *args);
int bgp_nb_maxpaths_ibgp_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_maxpaths_ibgp(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_maxpaths_ibgp_cluster_modify(struct nb_cb_modify_args *args);

int bgp_nb_redistribute_create(struct nb_cb_create_args *args);
int bgp_nb_redistribute_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_redistribute(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
int bgp_nb_redistribute_metric_modify(struct nb_cb_modify_args *args);
int bgp_nb_redistribute_metric_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_redistribute_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_redistribute_rmap_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_distance_bgp_modify(struct nb_cb_modify_args *args);
int bgp_nb_distance_bgp_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_distance_bgp(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
int bgp_nb_distance_route_create(struct nb_cb_create_args *args);
int bgp_nb_distance_route_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_distance_route(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_distance_route_distance_modify(struct nb_cb_modify_args *args);
int bgp_nb_distance_route_acl_modify(struct nb_cb_modify_args *args);
int bgp_nb_distance_route_acl_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_table_map_modify(struct nb_cb_modify_args *args);
int bgp_nb_table_map_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_table_map(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_dampening_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_dampening_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_dampening_param_modify(struct nb_cb_modify_args *args);
int bgp_nb_dampening_param_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_dampening(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_peer_dampening_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_dampening_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_dampening_param_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_dampening_param_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_dampening(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_upa_originate_modify(struct nb_cb_modify_args *args);
int bgp_nb_upa_originate_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_upa_originate(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_upa_max_routes_modify(struct nb_cb_modify_args *args);
int bgp_nb_upa_max_routes_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_upa_max_routes(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_upa_drop_modify(struct nb_cb_modify_args *args);
int bgp_nb_upa_drop_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_upa_drop(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_nexthop_prefer_global_modify(struct nb_cb_modify_args *args);
int bgp_nb_nexthop_prefer_global_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_nexthop_prefer_global(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_evpn_advertise_all_vni_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_advertise_all_vni_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_advertise_all_vni(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_evpn_autort_rfc8365_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_autort_rfc8365_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_autort_rfc8365(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

int bgp_nb_evpn_advertise_default_gw_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_advertise_default_gw_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_advertise_default_gw(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_evpn_advertise_svi_ip_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_advertise_svi_ip_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_advertise_svi_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_evpn_resolve_overlay_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_resolve_overlay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_resolve_overlay(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_evpn_flooding_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_flooding_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_flooding(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_evpn_macvrf_soo_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_macvrf_soo_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_macvrf_soo(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_evpn_dad_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_dad_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_dad_param_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_dad_param_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_dad_freeze_permanent_create(struct nb_cb_create_args *args);
int bgp_nb_evpn_dad_freeze_permanent_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_dad_enable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
void bgp_nb_cli_show_evpn_dad_max_moves(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
void bgp_nb_cli_show_evpn_dad_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
void bgp_nb_cli_show_evpn_dad_freeze_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void bgp_nb_cli_show_evpn_dad_freeze_permanent(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_evpn_use_es_l3nhg_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_use_es_l3nhg_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_use_es_l3nhg(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_evpn_disable_ead_evi_rx_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_disable_ead_evi_rx_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_disable_ead_evi_rx(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_evpn_disable_ead_evi_tx_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_disable_ead_evi_tx_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_disable_ead_evi_tx(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
int bgp_nb_evpn_ead_es_frag_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_ead_es_frag_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_ead_es_frag(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_evpn_default_originate_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_default_originate_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_default_originate(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_evpn_type5_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_type5_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_type5_gateway_ip_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_type5_gateway_ip_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_type5_route_map_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_type5_route_map_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_type5_skip_evpn_imported_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_type5_skip_evpn_imported_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_type5_enable(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_evpn_advertise_pip_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_advertise_pip_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_evpn_advertise_pip_param_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_advertise_pip_param_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_advertise_pip_enable(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void bgp_nb_cli_show_evpn_advertise_pip_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_evpn_ead_es_rt_create(struct nb_cb_create_args *args);
int bgp_nb_evpn_ead_es_rt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_ead_es_rt(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_evpn_vrf_rd_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vrf_rd_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vrf_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_evpn_vrf_yang_reapply(struct bgp *bgp);

int bgp_nb_evpn_vrf_rt_create(struct nb_cb_create_args *args);
int bgp_nb_evpn_vrf_rt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vrf_rt_import(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
void bgp_nb_cli_show_evpn_vrf_rt_export(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_evpn_vrf_rt_auto_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vrf_rt_auto_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vrf_rt_auto(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_evpn_vni_rt_auto_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_rt_auto_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_rt_auto(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_evpn_vni_create(struct nb_cb_create_args *args);
int bgp_nb_evpn_vni_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_evpn_vni_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_evpn_vni_rd_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_evpn_vni_rt_create(struct nb_cb_create_args *args);
int bgp_nb_evpn_vni_rt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_rt_import(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
void bgp_nb_cli_show_evpn_vni_rt_export(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);

int bgp_nb_evpn_vni_advertise_default_gw_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_advertise_default_gw_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_advertise_default_gw(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_evpn_vni_advertise_svi_ip_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_advertise_svi_ip_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_advertise_svi_ip(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_evpn_vni_advertise_subnet_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_advertise_subnet_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_advertise_subnet(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

int bgp_nb_evpn_vni_flooding_modify(struct nb_cb_modify_args *args);
int bgp_nb_evpn_vni_flooding_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_evpn_vni_flooding(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_vpn_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_import(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_vpn_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_export(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_vpn_rmap_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_rmap_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_rmap_import(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_vpn_rmap_export_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_rmap_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_rmap_export(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_vpn_rd_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_rd_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_rd(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_vpn_label_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_label_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_label(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_vpn_label_auto_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_label_auto_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_label_auto(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
int bgp_nb_vpn_label_alloc_mode_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_label_alloc_mode_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_label_alloc_mode(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_vpn_nexthop_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_nexthop_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_nexthop(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_vpn_rt_import_create(struct nb_cb_create_args *args);
int bgp_nb_vpn_rt_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_rt_import(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_vpn_rt_export_create(struct nb_cb_create_args *args);
int bgp_nb_vpn_rt_export_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_rt_export(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_vpn_import_vrf_create(struct nb_cb_create_args *args);
int bgp_nb_vpn_import_vrf_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_import_vrf(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_vpn_vrf_rmap_import_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_vrf_rmap_import_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_vrf_rmap_import(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

int bgp_nb_vpn_retain_rt_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_retain_rt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_retain_rt(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

/* BMP */
int bgp_nb_bmp_mirror_buffer_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_mirror_buffer_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_mirror_buffer_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_bmp_target_create(struct nb_cb_create_args *args);
int bgp_nb_bmp_target_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_target(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_bmp_target_end(struct vty *vty, const struct lyd_node *dnode);

int bgp_nb_bmp_target_mirror_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_bmp_target_mirror(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_bmp_target_stats_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_target_stats_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_target_stats_time(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

int bgp_nb_bmp_target_stats_experimental_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_bmp_target_stats_experimental(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_bmp_target_acl_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_target_acl_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_target_acl_v4(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
void bgp_nb_cli_show_bmp_target_acl_v6(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_bmp_target_initiation_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_target_initiation_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_target_initiation_sysdescr(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void bgp_nb_cli_show_bmp_target_initiation_sysname(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_bmp_listener_create(struct nb_cb_create_args *args);
int bgp_nb_bmp_listener_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_listener(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_bmp_connect_create(struct nb_cb_create_args *args);
int bgp_nb_bmp_connect_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_connect(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_bmp_connect_leaf_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_connect_leaf_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_bmp_import_vrf_create(struct nb_cb_create_args *args);
int bgp_nb_bmp_import_vrf_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_import_vrf(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_bmp_monitor_modify(struct nb_cb_modify_args *args);
int bgp_nb_bmp_monitor_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_bmp_monitor(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int bgp_nb_bmp_monitor_extra_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_bmp_monitor_extra(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_vpn_redirect_rt_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_redirect_rt_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_vpn_redirect_rt(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
int bgp_nb_vpn_redirect_rt_ipv6_modify(struct nb_cb_modify_args *args);
int bgp_nb_vpn_redirect_rt_ipv6_destroy(struct nb_cb_destroy_args *args);

int bgp_nb_sid_vpn_export_index_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_vpn_export_index_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_vpn_export_auto_create(struct nb_cb_create_args *args);
int bgp_nb_sid_vpn_export_auto_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_vpn_export_explicit_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_vpn_export_explicit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_sid_vpn_export(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

int bgp_nb_sid_vpn_per_vrf_index_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_vpn_per_vrf_index_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_vpn_per_vrf_auto_create(struct nb_cb_create_args *args);
int bgp_nb_sid_vpn_per_vrf_auto_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_vpn_per_vrf_explicit_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_vpn_per_vrf_explicit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_sid_vpn_per_vrf(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_sid_export_index_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_export_index_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_export_auto_create(struct nb_cb_create_args *args);
int bgp_nb_sid_export_auto_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_export_explicit_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_export_explicit_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_export_dt46_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_export_dt46_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_sid_export_rmap_modify(struct nb_cb_modify_args *args);
int bgp_nb_sid_export_rmap_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_sid_export(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/* segment-routing srv6 */
int bgp_nb_srv6_locator_modify(struct nb_cb_modify_args *args);
int bgp_nb_srv6_locator_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_srv6_encap_behavior_modify(struct nb_cb_modify_args *args);
int bgp_nb_srv6_encap_behavior_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_srv6_only_modify(struct nb_cb_modify_args *args);
int bgp_nb_srv6_only_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_srv6(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_srv6_end(struct vty *vty, const struct lyd_node *dnode);
void bgp_nb_cli_show_srv6_locator(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void bgp_nb_cli_show_srv6_encap(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void bgp_nb_cli_show_srv6_only(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_ls_fabric_create(struct nb_cb_create_args *args);
int bgp_nb_ls_fabric_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_ls_fabric_instance_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_ls_fabric_instance_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_ls_fabric(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/* flowspec local-install */
int bgp_nb_fs_local_install_enable_modify(struct nb_cb_modify_args *args);
int bgp_nb_fs_local_install_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_fs_local_install_interface_create(struct nb_cb_create_args *args);
int bgp_nb_fs_local_install_interface_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_fs_local_install_interface(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

/* neighbor LS link ids */
int bgp_nb_peer_ls_local_link_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_ls_local_link_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_ls_local_link_id(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_ls_remote_link_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_peer_ls_remote_link_id(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);


int bgp_nb_peer_extended_link_bw_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_extended_link_bw(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_peer_disable_link_bw_ieee_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_disable_link_bw_ieee(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_peer_extended_opt_params_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_extended_opt_params(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_peer_send_nhc_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_send_nhc(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_peer_as_loop_detection_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_peer_as_loop_detection(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

/* Daemon-wide (/frr-bgp:bgp-daemon) CONFIG_NODE knobs */
int bgp_nb_daemon_no_rib_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_no_rib(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
int bgp_nb_daemon_session_dscp_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_session_dscp_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_session_dscp(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_daemon_inq_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_inq_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_inq_limit(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
int bgp_nb_daemon_outq_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_outq_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_outq_limit(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_daemon_suppress_fib_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_suppress_fib(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_daemon_suppress_fib_delay_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_suppress_fib_delay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_suppress_fib_delay(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_daemon_ipv6_auto_ra_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_daemon_update_delay_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_update_delay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_update_delay(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int bgp_nb_daemon_establish_wait_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_establish_wait_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_daemon_advertisement_delay_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_advertisement_delay_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_advertisement_delay(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
int bgp_nb_daemon_community_alias_create(struct nb_cb_create_args *args);
int bgp_nb_daemon_community_alias_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_community_alias(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_daemon_community_alias_name_modify(struct nb_cb_modify_args *args);

int bgp_nb_daemon_send_extra_data_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_send_extra_data(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_daemon_snmp_traps_rfc4273_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_snmp_traps_rfc4273(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_daemon_snmp_traps_bgp4_mibv2_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_snmp_traps_bgp4_mibv2(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
int bgp_nb_daemon_snmp_traps_rfc4382_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_snmp_traps_rfc4382(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
int bgp_nb_daemon_rmap_delay_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_rmap_delay_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_rmap_delay_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_daemon_gr_enabled_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_enabled_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_enabled(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_daemon_gr_disable_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_disable_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_disable(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
int bgp_nb_daemon_gr_stale_routes_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_stale_routes_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
int bgp_nb_daemon_gr_restart_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_restart_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_daemon_gr_select_defer_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_select_defer_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
int bgp_nb_daemon_gr_rib_stale_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_rib_stale_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
int bgp_nb_daemon_gr_preserve_fw_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_preserve_fw_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_preserve_fw(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_daemon_graceful_shutdown_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);

/* Interface MPLS BGP knobs */
int lib_interface_mpls_bgp_forwarding_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_mpls_bgp_forwarding(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
int lib_interface_mpls_l3vpn_multi_domain_switching_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_mpls_l3vpn_multi_domain_switching(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults);

int bgp_nb_as_notation_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_enforce_first_as_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_hard_admin_reset_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_multi_path_as_set_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_gr_llgr_stale_time_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_maxpaths_ibgp_cluster_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_shutdown_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_local_role_strict_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_bfd_detect_mult_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_bfd_min_rx_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_bfd_min_tx_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_bfd_cbit_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_peer_bfd_session_type_modify(struct nb_cb_modify_args *args);
int bgp_nb_peer_bfd_session_type_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_aggregate_attr_modify(struct nb_cb_modify_args *args);
int bgp_nb_aggregate_attr_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_connect_retry_modify(struct nb_cb_modify_args *args);
int bgp_nb_connect_retry_destroy(struct nb_cb_destroy_args *args);
int bgp_nb_daemon_gr_notification_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_notification_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_notification(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
int bgp_nb_daemon_gr_disable_eor_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_daemon_gr_disable_eor(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
int bgp_nb_daemon_gr_llgr_stale_time_modify(struct nb_cb_modify_args *args);
int bgp_nb_daemon_gr_llgr_stale_time_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_daemon_gr_llgr_stale_time(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

#endif /* _FRR_BGP_NB_H_ */
