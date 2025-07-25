// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 21 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "ospfd/ospf_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_lite_info = {
	.name = "frr-ospfd-lite",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface",
			.cbs = {
				.create = lib_interface_ospf_interface_create,
				.destroy = lib_interface_ospf_interface_destroy,
				.get_next = lib_interface_ospf_interface_get_next,
				.get_keys = lib_interface_ospf_interface_get_keys,
				.lookup_entry = lib_interface_ospf_interface_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/state",
			.cbs = {
				.get_elem = lib_interface_ospf_interface_state_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/hello-timer",
			.cbs = {
				.get_elem = lib_interface_ospf_interface_state_hello_timer_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor",
			.cbs = {
				.get_next = lib_interface_ospf_interface_state_neighbors_neighbor_get_next,
				.get_keys = lib_interface_ospf_interface_state_neighbors_neighbor_get_keys,
				.lookup_entry = lib_interface_ospf_interface_state_neighbors_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/neighbor-router-id",
			.cbs = {
				.get_elem = lib_interface_ospf_interface_state_neighbors_neighbor_neighbor_router_id_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = lib_interface_ospf_interface_state_neighbors_neighbor_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/state",
			.cbs = {
				.get_elem = lib_interface_ospf_interface_state_neighbors_neighbor_state_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance",
			.cbs = {
				.create = ospf_instance_create,
				.destroy = ospf_instance_destroy,
				.get_next = ospf_instance_get_next,
				.get_keys = ospf_instance_get_keys,
				.lookup_entry = ospf_instance_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/state/router-flags/router-flag",
			.cbs = {
				.get_elem = ospf_instance_state_router_flags_router_flag_get_elem,
				.get_next = ospf_instance_state_router_flags_router_flag_get_next,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/state/statistics/originate-new-lsa-count",
			.cbs = {
				.get_elem = ospf_instance_state_statistics_originate_new_lsa_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/state/statistics/rx-new-lsas-count",
			.cbs = {
				.get_elem = ospf_instance_state_statistics_rx_new_lsas_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/state/statistics/spf/timestamp",
			.cbs = {
				.get_elem = ospf_instance_state_statistics_spf_timestamp_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/state/statistics/spf/duration",
			.cbs = {
				.get_elem = ospf_instance_state_statistics_spf_duration_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area",
			.cbs = {
				.create = ospf_instance_areas_area_create,
				.destroy = ospf_instance_areas_area_destroy,
				.get_next = ospf_instance_areas_area_get_next,
				.get_keys = ospf_instance_areas_area_get_keys,
				.lookup_entry = ospf_instance_areas_area_lookup_entry,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/spf-runs-count",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_spf_runs_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/abr-count",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_abr_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/asbr-count",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_asbr_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/area-scope-lsa-count",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_area_scope_lsa_count_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/spf-timestamp",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_spf_timestamp_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/active-interfaces",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_active_interfaces_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/full-nbrs",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_full_nbrs_get_elem,
			}
		},
		{
			.xpath = "/frr-ospfd-lite:ospf/instance/areas/area/state/statistics/full-virtual",
			.cbs = {
				.get_elem = ospf_instance_areas_area_state_statistics_full_virtual_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
