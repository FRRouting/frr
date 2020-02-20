/*
 * Copyright (C) 2020  Cumulus Networks, Inc.
 * Chirag Shah
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "northbound.h"
#include "libfrr.h"
#include "zebra_nb.h"

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/up-count
 */
struct yang_data *
lib_interface_zebra_state_up_count_get_elem(const char *xpath,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/down-count
 */
struct yang_data *
lib_interface_zebra_state_down_count_get_elem(const char *xpath,
					      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/zif-type
 */
struct yang_data *
lib_interface_zebra_state_zif_type_get_elem(const char *xpath,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/ptm-status
 */
struct yang_data *
lib_interface_zebra_state_ptm_status_get_elem(const char *xpath,
					      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/vlan-id
 */
struct yang_data *
lib_interface_zebra_state_vlan_id_get_elem(const char *xpath,
					   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/vni-id
 */
struct yang_data *
lib_interface_zebra_state_vni_id_get_elem(const char *xpath,
					  const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/remote-vtep
 */
struct yang_data *
lib_interface_zebra_state_remote_vtep_get_elem(const char *xpath,
					       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/mcast-group
 */
struct yang_data *
lib_interface_zebra_state_mcast_group_get_elem(const char *xpath,
					       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

const void *lib_vrf_ribs_rib_get_next(const void *parent_list_entry,
				      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_get_keys(const void *list_entry,
			      struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_vrf_ribs_rib_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route
 */
const void *lib_vrf_ribs_rib_route_get_next(const void *parent_list_entry,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_get_keys(const void *list_entry,
				    struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_lookup_entry(const void *parent_list_entry,
				    const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/prefix
 */
struct yang_data *lib_vrf_ribs_rib_route_prefix_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry
 */
const void *
lib_vrf_ribs_rib_route_route_entry_get_next(const void *parent_list_entry,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_route_entry_get_keys(const void *list_entry,
						struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_vrf_ribs_rib_route_route_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/protocol
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_protocol_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/instance
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_instance_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/distance
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_distance_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/metric
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_metric_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/tag
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_tag_get_elem(const char *xpath,
						const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/selected
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_selected_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/installed
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_installed_get_elem(const char *xpath,
						      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/failed
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_failed_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/queued
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_queued_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/internal-flags
 */
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_flags_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/internal-status
 */
struct yang_data *lib_vrf_ribs_rib_route_route_entry_internal_status_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/uptime
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_uptime_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group
 */
const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_route_entry_nexthop_group_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_vrf_ribs_rib_route_route_entry_nexthop_group_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/name
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_name_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop
 */
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/nh-type
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_nh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/vrf
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_vrf_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/gateway
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_gateway_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/interface
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_interface_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/bh-type
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_bh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/onlink
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_onlink_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry
 */
const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/id
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_id_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_label_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/duplicate
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_duplicate_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/recursive
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_recursive_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/active
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_active_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/fib
 */
struct yang_data *
lib_vrf_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_fib_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}
