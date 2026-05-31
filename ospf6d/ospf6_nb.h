// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#ifndef FRR_OSPF6_NB_H
#define FRR_OSPF6_NB_H

#include "northbound.h"

struct ospf6;

#define OSPF6D_IETF_ROUTING_CP_XPATH                                          \
	"/ietf-routing:routing/control-plane-protocols/"                      \
	"control-plane-protocol"
#define OSPF6D_IETF_ROUTING_PROTOCOL_TYPE_XPATH                               \
	OSPF6D_IETF_ROUTING_CP_XPATH "[type='ietf-ospf:ospfv3']"
#define OSPF6D_IETF_ROUTING_PROTOCOL_XPATH                                    \
	OSPF6D_IETF_ROUTING_PROTOCOL_TYPE_XPATH "[name='%s']"
#define OSPF6D_IETF_OSPF_XPATH                                                \
	OSPF6D_IETF_ROUTING_CP_XPATH "/ietf-ospf:ospf"

extern const struct frr_yang_module_info ospf6d_ietf_routing_info;
extern const struct frr_yang_module_info ospf6d_ietf_routing_ospf_deviation_info;
extern const struct frr_yang_module_info ospf6d_ietf_ospf_info;

/* Shared lookup: find an OSPFv3 instance by the ietf-routing instance name. */
const char *ospf6d_ietf_ospf_instance_name(const struct ospf6 *ospf6);
struct ospf6 *ospf6d_ietf_ospf_lookup_instance(const char *name);

int ospf6d_ietf_routing_control_plane_protocol_create(struct nb_cb_create_args *args);
int ospf6d_ietf_routing_control_plane_protocol_destroy(struct nb_cb_destroy_args *args);
const void *ospf6d_ietf_routing_control_plane_protocol_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_routing_control_plane_protocol_get_keys(struct nb_cb_get_keys_args *args);
const void *
ospf6d_ietf_routing_control_plane_protocol_lookup_entry(struct nb_cb_lookup_entry_args *args);

/* Config callbacks. */
int ospf6d_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_type_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_summary_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_summary_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_transmit_delay_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_preference_all_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_preference_all_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_preference_intra_area_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_preference_intra_area_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_preference_inter_area_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_preference_inter_area_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_preference_internal_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_preference_internal_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_preference_external_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_preference_external_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_spf_control_paths_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_spf_control_paths_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_auto_cost_enabled_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_auto_cost_reference_bandwidth_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_auto_cost_reference_bandwidth_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_graceful_restart_enabled_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_graceful_restart_restart_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_graceful_restart_helper_enabled_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_graceful_restart_helper_enabled_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_destroy(struct nb_cb_destroy_args *args);
void ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_apply_finish(struct nb_cb_apply_finish_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_enabled_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_destroy(struct nb_cb_destroy_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_modify(struct nb_cb_modify_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_destroy(struct nb_cb_destroy_args *args);

struct yang_data *ospf6d_ietf_ospf_router_id_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_statistics_originate_new_lsa_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_statistics_rx_new_lsas_count_get_elem(struct nb_cb_get_elem_args *args);
const void *ospf6d_ietf_ospf_areas_area_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args);
const void *ospf6d_ietf_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_abr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_asbr_count_get_elem(struct nb_cb_get_elem_args *args);
struct yang_data *ospf6d_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args);

const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_get_next(struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_get_keys(struct nb_cb_get_keys_args *args);
const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_lookup_entry(struct nb_cb_lookup_entry_args *args);

const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args);
int ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args);
const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args);
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem(
	struct nb_cb_get_elem_args *args);

/* RPC callbacks (RFC 9129). */
int ospf6d_ietf_ospf_clear_neighbor_rpc(struct nb_cb_rpc_args *args);
int ospf6d_ietf_ospf_clear_database_rpc(struct nb_cb_rpc_args *args);

/* Notification emitters (RFC 9129). */
struct ospf6_neighbor;
struct ospf6_interface;
void ospf6d_ietf_notif_init(void);
void ospf6d_ietf_notif_restart_status_change(struct ospf6 *ospf6, int status, int exit_reason);
void ospf6d_ietf_notif_nbr_restart_helper_status_change(struct ospf6_neighbor *on, int status,
							uint16_t age, int exit_reason);
void ospf6d_ietf_notif_if_rx_bad_packet(struct ospf6_interface *oi, struct in6_addr src,
					uint8_t packet_type);
void ospf6d_ietf_notif_if_config_error(struct ospf6_interface *oi, struct in6_addr src,
				       uint8_t packet_type, const char *error_name);

#endif /* FRR_OSPF6_NB_H */
