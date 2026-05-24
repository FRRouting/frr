// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "vrf.h"

#include "ospf6_nb.h"
#include "ospf6_top.h"

#define OSPF6D_IETF_ROUTING_CP_XPATH                                          \
	"/ietf-routing:routing/control-plane-protocols/"                      \
	"control-plane-protocol"
#define OSPF6D_IETF_OSPF_XPATH                                                \
	OSPF6D_IETF_ROUTING_CP_XPATH "/ietf-ospf:ospf"

/* clang-format off */
const struct frr_yang_module_info ospf6d_ietf_routing_info = {
	.name = "ietf-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPF6D_IETF_ROUTING_CP_XPATH,
			.cbs = {
				.get_next = ospf6d_ietf_routing_control_plane_protocol_get_next,
				.get_keys = ospf6d_ietf_routing_control_plane_protocol_get_keys,
				.lookup_entry =
					ospf6d_ietf_routing_control_plane_protocol_lookup_entry,
			},
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

/*
 * RFC 9129's ietf-ospf is the target northbound shape for OSPFv2 and OSPFv3.
 * Load it now so OSPFv3 work can converge on the shared standard model.
 * Enable all features so leaves gated by 'if-feature' (e.g. explicit-router-id,
 * mtu-ignore) appear in the compiled schema and become callable from converted
 * callbacks.
 */
static const char * const ospf6d_ietf_ospf_features[] = { "*", NULL };

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
