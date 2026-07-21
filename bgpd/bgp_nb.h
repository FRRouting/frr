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

/* Global leaves */
int bgp_nb_local_as_modify(struct nb_cb_modify_args *args);
int bgp_nb_router_id_modify(struct nb_cb_modify_args *args);
int bgp_nb_router_id_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_instance_type_view_modify(struct nb_cb_modify_args *args);
int bgp_nb_as_notation_modify(struct nb_cb_modify_args *args);

int bgp_nb_log_neighbor_changes_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_log_neighbor_changes(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_ebgp_requires_policy(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_import_check_modify(struct nb_cb_modify_args *args);
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
void bgp_nb_cli_show_deterministic_med(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_local_pref_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_local_pref(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

int bgp_nb_fast_external_failover_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_fast_external_failover(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);

int bgp_nb_suppress_duplicates_modify(struct nb_cb_modify_args *args);
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
void bgp_nb_cli_show_show_hostname(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
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
int bgp_nb_hold_time_modify(struct nb_cb_modify_args *args);
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

int bgp_nb_confederation_member_as_create(struct nb_cb_create_args *args);
int bgp_nb_confederation_member_as_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_confederation_member_as(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

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

int bgp_nb_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args);
int bgp_nb_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_dynamic_neighbors_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);

int bgp_nb_default_afi_safi_create(struct nb_cb_create_args *args);
int bgp_nb_default_afi_safi_destroy(struct nb_cb_destroy_args *args);
void bgp_nb_cli_show_default_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

int bgp_nb_gr_stale_routes_time_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_gr_restart_time_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

int bgp_nb_gr_select_defer_time_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

int bgp_nb_gr_rib_stale_time_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);

int bgp_nb_gr_preserve_fw_modify(struct nb_cb_modify_args *args);
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
void bgp_nb_cli_show_coalesce_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

int bgp_nb_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_subgroup_pkt_queue_size(struct vty *vty, const struct lyd_node *dnode,
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
void bgp_nb_cli_show_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

int bgp_nb_labeled_unicast_explicit_null_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_labeled_unicast_explicit_null(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_default_dynamic_capability_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_dynamic_capability(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

int bgp_nb_default_link_local_capability_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_link_local_capability(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

int bgp_nb_default_software_version_capability_modify(struct nb_cb_modify_args *args);
void bgp_nb_cli_show_default_software_version_capability(struct vty *vty,
							 const struct lyd_node *dnode,
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

void bgp_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_H_ */
