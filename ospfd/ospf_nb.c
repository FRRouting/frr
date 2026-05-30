// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "ospfd/ospfd.h"
#include "ospfd/ospf_nsm.h"
#include "ospf_nb.h"

const char *ospfd_ietf_instance_name(unsigned short instance, const char *name,
				     char *buf, size_t buf_len)
{
	if (instance) {
		snprintf(buf, buf_len, "%u", instance);
		return buf;
	}

	return name ? name : VRF_DEFAULT_NAME;
}

const char *ospfd_ietf_ospf_instance_name(const struct ospf *ospf, char *buf,
					  size_t buf_len)
{
	return ospfd_ietf_instance_name(ospf->instance, ospf_get_name(ospf),
				       buf, buf_len);
}

/*
 * Translate FRR's internal NSM state code into RFC 9129's `nbr-state-type`
 * numeric value.  FRR lifecycle states without protocol existence fold into
 * the RFC `down` state so tear-down remains observable.
 */
static const int ospfd_ietf_nbr_state_table[OSPF_NSM_STATE_MAX] = {
	[NSM_DependUpon] = 1, /* down */
	[NSM_Deleted] = 1,    /* down */
	[NSM_Down] = 1,       /* down */
	[NSM_Attempt] = 2,    /* attempt */
	[NSM_Init] = 3,       /* init */
	[NSM_TwoWay] = 4,     /* 2-way */
	[NSM_ExStart] = 5,    /* exstart */
	[NSM_Exchange] = 6,   /* exchange */
	[NSM_Loading] = 7,    /* loading */
	[NSM_Full] = 8,       /* full */
};

int ospfd_ietf_nbr_state_yang(int nsm_state)
{
	int val;

	if (nsm_state < 0 ||
	    (size_t)nsm_state >= array_size(ospfd_ietf_nbr_state_table))
		return -1;

	val = ospfd_ietf_nbr_state_table[nsm_state];
	return val ? val : -1;
}

int ospfd_ietf_routing_protocol_instance_xpath(char *xpath, size_t xpath_len,
					       unsigned short instance,
					       const char *name)
{
	char instance_name[XPATH_MAXLEN];

	return snprintf(xpath, xpath_len, OSPFD_IETF_ROUTING_PROTOCOL_XPATH,
			ospfd_ietf_instance_name(instance, name, instance_name,
						 sizeof(instance_name)));
}

int ospfd_ietf_routing_protocol_xpath(char *xpath, size_t xpath_len,
				      const struct ospf *ospf)
{
	return ospfd_ietf_routing_protocol_instance_xpath(
		xpath, xpath_len, ospf->instance, ospf_get_name(ospf));
}

/* clang-format off */
const struct frr_yang_module_info ospfd_ietf_routing_info = {
	.name = "ietf-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = OSPFD_IETF_ROUTING_CP_XPATH,
			.cbs = {
				.create = ospfd_ietf_routing_control_plane_protocol_create,
				.destroy = ospfd_ietf_routing_control_plane_protocol_destroy,
				.get_next = ospfd_ietf_routing_control_plane_protocol_get_next,
				.get_keys = ospfd_ietf_routing_control_plane_protocol_get_keys,
				.lookup_entry =
					ospfd_ietf_routing_control_plane_protocol_lookup_entry,
			},
			.cfg_opt_in = true,
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
			.xpath = OSPFD_IETF_OSPF_XPATH "/preference/all",
			.cbs = {
				.modify = ospfd_ietf_ospf_preference_all_modify,
				.destroy = ospfd_ietf_ospf_preference_all_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/preference/intra-area",
			.cbs = {
				.modify = ospfd_ietf_ospf_preference_intra_area_modify,
				.destroy = ospfd_ietf_ospf_preference_intra_area_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/preference/inter-area",
			.cbs = {
				.modify = ospfd_ietf_ospf_preference_inter_area_modify,
				.destroy = ospfd_ietf_ospf_preference_inter_area_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/preference/internal",
			.cbs = {
				.modify = ospfd_ietf_ospf_preference_internal_modify,
				.destroy = ospfd_ietf_ospf_preference_internal_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/preference/external",
			.cbs = {
				.modify = ospfd_ietf_ospf_preference_external_modify,
				.destroy = ospfd_ietf_ospf_preference_external_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/spf-control/paths",
			.cbs = {
				.modify = ospfd_ietf_ospf_spf_control_paths_modify,
				.destroy = ospfd_ietf_ospf_spf_control_paths_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/mpls/ldp/igp-sync",
			.cbs = {
				.modify = ospfd_ietf_ospf_mpls_ldp_igp_sync_modify,
				.destroy = ospfd_ietf_ospf_mpls_ldp_igp_sync_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/stub-router/always",
			.cbs = {
				.create = ospfd_ietf_ospf_stub_router_always_create,
				.destroy = ospfd_ietf_ospf_stub_router_always_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/auto-cost/enabled",
			.cbs = {
				.modify = ospfd_ietf_ospf_auto_cost_enabled_modify,
				.destroy = ospfd_ietf_ospf_auto_cost_enabled_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/auto-cost/reference-bandwidth",
			.cbs = {
				.modify = ospfd_ietf_ospf_auto_cost_reference_bandwidth_modify,
				.destroy = ospfd_ietf_ospf_auto_cost_reference_bandwidth_destroy,
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
				.create = ospfd_ietf_ospf_areas_area_create,
				.destroy = ospfd_ietf_ospf_areas_area_destroy,
				.get_next = ospfd_ietf_ospf_areas_area_get_next,
				.get_keys = ospfd_ietf_ospf_areas_area_get_keys,
				.lookup_entry = ospfd_ietf_ospf_areas_area_lookup_entry,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/areas/area/area-type",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_type_modify,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/areas/area/summary",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_summary_modify,
				.destroy = ospfd_ietf_ospf_areas_area_summary_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH "/areas/area/default-cost",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_default_cost_modify,
				.destroy = ospfd_ietf_ospf_areas_area_default_cost_destroy,
			},
			.cfg_opt_in = true,
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
				.create = ospfd_ietf_ospf_areas_area_interfaces_interface_create,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_destroy,
				.get_next = ospfd_ietf_ospf_areas_area_interfaces_interface_get_next,
				.get_keys = ospfd_ietf_ospf_areas_area_interfaces_interface_get_keys,
				.lookup_entry =
					ospfd_ietf_ospf_areas_area_interfaces_interface_lookup_entry,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/cost",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_cost_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_cost_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/hello-interval",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/dead-interval",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/retransmit-interval",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/priority",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_priority_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_priority_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/mtu-ignore",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/transmit-delay",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_transmit_delay_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_transmit_delay_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/interface-type",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_interface_type_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_interface_type_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/passive",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_passive_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_passive_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/interfaces/interface/prefix-suppression",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_interfaces_interface_prefix_suppression_modify,
				.destroy = ospfd_ietf_ospf_areas_area_interfaces_interface_prefix_suppression_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/ranges/range",
			.cbs = {
				.create = ospfd_ietf_ospf_areas_area_ranges_range_create,
				.destroy = ospfd_ietf_ospf_areas_area_ranges_range_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/ranges/range/advertise",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_ranges_range_advertise_modify,
				.destroy = ospfd_ietf_ospf_areas_area_ranges_range_advertise_destroy,
			},
			.cfg_opt_in = true,
		},
		{
			.xpath = OSPFD_IETF_OSPF_XPATH
				 "/areas/area/ranges/range/cost",
			.cbs = {
				.modify = ospfd_ietf_ospf_areas_area_ranges_range_cost_modify,
				.destroy = ospfd_ietf_ospf_areas_area_ranges_range_cost_destroy,
			},
			.cfg_opt_in = true,
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
