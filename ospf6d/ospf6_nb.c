// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "vrf.h"

#include "ospf6_nb.h"
#include "ospf6_top.h"

/* clang-format off */
const struct frr_yang_module_info ospf6d_ietf_routing_info = {
	.name = "ietf-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPF6D_IETF_ROUTING_CP_XPATH,
			.cbs = {
				.create = ospf6d_ietf_routing_control_plane_protocol_create,
				.destroy = ospf6d_ietf_routing_control_plane_protocol_destroy,
				.get_next = ospf6d_ietf_routing_control_plane_protocol_get_next,
				.get_keys = ospf6d_ietf_routing_control_plane_protocol_get_keys,
				.lookup_entry =
					ospf6d_ietf_routing_control_plane_protocol_lookup_entry,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = NULL,
		},
	},
};

const struct frr_yang_module_info ospf6d_ietf_routing_ospf_deviation_info = {
	.name = "frr-deviations-ietf-routing-ospf",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = NULL,
		},
	},
};

static const char * const ospf6d_ietf_ospf_features[] = {
	"auto-cost",
	"bfd",
	"explicit-router-id",
	"graceful-restart",
	"key-chain",
	"max-ecmp",
	"mtu-ignore",
	"ospfv3-authentication-trailer",
	NULL,
};

const char *ospf6d_ietf_ospf_instance_name(const struct ospf6 *ospf6)
{
	return ospf6->name ? ospf6->name : VRF_DEFAULT_NAME;
}

const struct frr_yang_module_info ospf6d_ietf_ospf_info = {
	.name = "ietf-ospf",
	.features = (const char **)ospf6d_ietf_ospf_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/router-id",
			.cbs = {
				.get_elem = ospf6d_ietf_ospf_router_id_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/explicit-router-id",
			.cbs = {
				.modify = ospf6d_ietf_ospf_explicit_router_id_modify,
				.destroy = ospf6d_ietf_ospf_explicit_router_id_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/preference/all",
			.cbs = {
				.modify = ospf6d_ietf_ospf_preference_all_modify,
				.destroy = ospf6d_ietf_ospf_preference_all_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/preference/intra-area",
			.cbs = {
				.modify = ospf6d_ietf_ospf_preference_intra_area_modify,
				.destroy = ospf6d_ietf_ospf_preference_intra_area_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/preference/inter-area",
			.cbs = {
				.modify = ospf6d_ietf_ospf_preference_inter_area_modify,
				.destroy = ospf6d_ietf_ospf_preference_inter_area_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/preference/internal",
			.cbs = {
				.modify = ospf6d_ietf_ospf_preference_internal_modify,
				.destroy = ospf6d_ietf_ospf_preference_internal_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/preference/external",
			.cbs = {
				.modify = ospf6d_ietf_ospf_preference_external_modify,
				.destroy = ospf6d_ietf_ospf_preference_external_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/spf-control/paths",
			.cbs = {
				.modify = ospf6d_ietf_ospf_spf_control_paths_modify,
				.destroy = ospf6d_ietf_ospf_spf_control_paths_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/auto-cost/enabled",
			.cbs = {
				.modify = ospf6d_ietf_ospf_auto_cost_enabled_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/auto-cost/reference-bandwidth",
			.cbs = {
				.modify = ospf6d_ietf_ospf_auto_cost_reference_bandwidth_modify,
				.destroy = ospf6d_ietf_ospf_auto_cost_reference_bandwidth_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/graceful-restart/enabled",
			.cbs = {
				.modify = ospf6d_ietf_ospf_graceful_restart_enabled_modify,
				.destroy = ospf6d_ietf_ospf_graceful_restart_enabled_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/graceful-restart/restart-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_graceful_restart_restart_interval_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/graceful-restart/helper-enabled",
			.cbs = {
				.modify = ospf6d_ietf_ospf_graceful_restart_helper_enabled_modify,
				.destroy = ospf6d_ietf_ospf_graceful_restart_helper_enabled_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/graceful-restart/helper-strict-lsa-checking",
			.cbs = {
				.modify = ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_modify,
				.destroy = ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/statistics/originate-new-lsa-count",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_statistics_originate_new_lsa_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/statistics/rx-new-lsas-count",
			.cbs = {
				.get_elem = ospf6d_ietf_ospf_statistics_rx_new_lsas_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/areas/area",
			.cbs = {
				.create = ospf6d_ietf_ospf_areas_area_create,
				.destroy = ospf6d_ietf_ospf_areas_area_destroy,
				.get_next = ospf6d_ietf_ospf_areas_area_get_next,
				.get_keys = ospf6d_ietf_ospf_areas_area_get_keys,
				.lookup_entry = ospf6d_ietf_ospf_areas_area_lookup_entry,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/areas/area/area-type",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_type_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH "/areas/area/summary",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_summary_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_summary_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/statistics/spf-runs-count",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/statistics/abr-count",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_statistics_abr_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/statistics/asbr-count",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_statistics_asbr_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/statistics/area-scope-lsa-count",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface",
			.cbs = {
				.create = ospf6d_ietf_ospf_areas_area_interfaces_interface_create,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_destroy,
				.get_next = ospf6d_ietf_ospf_areas_area_interfaces_interface_get_next,
				.get_keys = ospf6d_ietf_ospf_areas_area_interfaces_interface_get_keys,
				.lookup_entry =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_lookup_entry,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/cost",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/hello-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/dead-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/retransmit-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/priority",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/mtu-ignore",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/transmit-delay",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_transmit_delay_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/interface-type",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/passive",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/bfd",
			.cbs = {
				.apply_finish = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_apply_finish,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/bfd/enabled",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_enabled_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/bfd/local-multiplier",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/bfd/desired-min-tx-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/bfd/required-min-rx-interval",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/authentication/ospfv3-key-chain",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/ranges/range",
			.cbs = {
				.create = ospf6d_ietf_ospf_areas_area_ranges_range_create,
				.destroy = ospf6d_ietf_ospf_areas_area_ranges_range_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/ranges/range/advertise",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_ranges_range_advertise_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_ranges_range_advertise_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/ranges/range/cost",
			.cbs = {
				.modify = ospf6d_ietf_ospf_areas_area_ranges_range_cost_modify,
				.destroy = ospf6d_ietf_ospf_areas_area_ranges_range_cost_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor",
			.cbs = {
				.get_next =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next,
				.get_keys =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys,
				.lookup_entry =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor/address",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem,
			},
		},
		{
			.xpath = OSPF6D_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor/state",
			.cbs = {
				.get_elem =
					ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
