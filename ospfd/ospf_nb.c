// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "ospf_nb.h"

#define OSPFD_IETF_ROUTING_CP_XPATH                                           \
	"/ietf-routing:routing/control-plane-protocols/"                      \
	"control-plane-protocol"
#define OSPFD_IETF_OSPF_XPATH                                                 \
	OSPFD_IETF_ROUTING_CP_XPATH "/ietf-ospf:ospf"

/* clang-format off */
const struct frr_yang_module_info ospfd_ietf_routing_info = {
	.name = "ietf-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPFD_IETF_ROUTING_CP_XPATH,
			.cbs = {
				.get_next = ospfd_ietf_routing_control_plane_protocol_get_next,
				.get_keys = ospfd_ietf_routing_control_plane_protocol_get_keys,
				.lookup_entry =
					ospfd_ietf_routing_control_plane_protocol_lookup_entry,
			},
		},
		{
			.xpath = NULL,
		},
	},
};

const struct frr_yang_module_info ospfd_ietf_routing_ospf_deviation_info = {
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
 * Load it now so work can converge on the standard model while FRR-specific
 * callbacks are filled in incrementally. Enable all features so leaves gated
 * by 'if-feature' (e.g. explicit-router-id, mtu-ignore) appear in the
 * compiled schema and become callable from converted callbacks.
 */
static const char * const ospfd_ietf_ospf_features[] = { "*", NULL };

const struct frr_yang_module_info ospfd_ietf_ospf_info = {
	.name = "ietf-ospf",
	.features = (const char **)ospfd_ietf_ospf_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/router-id",
			.cbs = {
				.get_elem = ospfd_ietf_ospf_router_id_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/explicit-router-id",
			.cbs = {
				.modify = ospfd_ietf_ospf_explicit_router_id_modify,
				.destroy = ospfd_ietf_ospf_explicit_router_id_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/statistics/originate-new-lsa-count",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_statistics_originate_new_lsa_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/statistics/rx-new-lsas-count",
			.cbs = {
				.get_elem = ospfd_ietf_ospf_statistics_rx_new_lsas_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/areas/area",
			.cbs = {
				.get_next = ospfd_ietf_ospf_areas_area_get_next,
				.get_keys = ospfd_ietf_ospf_areas_area_get_keys,
				.lookup_entry = ospfd_ietf_ospf_areas_area_lookup_entry,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/statistics/spf-runs-count",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/statistics/abr-count",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_statistics_abr_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/statistics/asbr-count",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_statistics_asbr_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/statistics/area-scope-lsa-count",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface",
			.cbs = {
				.get_next = ospfd_ietf_ospf_areas_area_interfaces_interface_get_next,
				.get_keys = ospfd_ietf_ospf_areas_area_interfaces_interface_get_keys,
				.lookup_entry =
					ospfd_ietf_ospf_areas_area_interfaces_interface_lookup_entry,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor",
			.cbs = {
				.get_next =
					ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next,
				.get_keys =
					ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys,
				.lookup_entry =
					ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor/address",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem,
			},
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/neighbors/neighbor/state",
			.cbs = {
				.get_elem =
					ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
