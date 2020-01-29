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
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/protocol
 */
struct yang_data *
lib_vrf_ribs_rib_route_protocol_get_elem(const char *xpath,
					 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/protocol-v6
 */
struct yang_data *
lib_vrf_ribs_rib_route_protocol_v6_get_elem(const char *xpath,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/vrf
 */
struct yang_data *lib_vrf_ribs_rib_route_vrf_get_elem(const char *xpath,
						      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/distance
 */
struct yang_data *
lib_vrf_ribs_rib_route_distance_get_elem(const char *xpath,
					 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/metric
 */
struct yang_data *lib_vrf_ribs_rib_route_metric_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/tag
 */
struct yang_data *lib_vrf_ribs_rib_route_tag_get_elem(const char *xpath,
						      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/selected
 */
struct yang_data *
lib_vrf_ribs_rib_route_selected_get_elem(const char *xpath,
					 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/installed
 */
struct yang_data *
lib_vrf_ribs_rib_route_installed_get_elem(const char *xpath,
					  const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/failed
 */
struct yang_data *lib_vrf_ribs_rib_route_failed_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/queued
 */
struct yang_data *lib_vrf_ribs_rib_route_queued_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/internal-flags
 */
struct yang_data *
lib_vrf_ribs_rib_route_internal_flags_get_elem(const char *xpath,
					       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/internal-status
 */
struct yang_data *
lib_vrf_ribs_rib_route_internal_status_get_elem(const char *xpath,
						const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/uptime
 */
struct yang_data *lib_vrf_ribs_rib_route_uptime_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group
 */
const void *
lib_vrf_ribs_rib_route_nexthop_group_get_next(const void *parent_list_entry,
					      const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_nexthop_group_get_keys(const void *list_entry,
						  struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_vrf_ribs_rib_route_nexthop_group_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/name
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_name_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop
 */
const void *lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/nh-type
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_nh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/vrf
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_vrf_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/gateway
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_gateway_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/interface
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_interface_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/bh-type
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_bh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/onlink
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_onlink_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry
 */
const void *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/id
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_id_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_label_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/duplicate
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_duplicate_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/recursive
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_recursive_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/active
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_active_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/nexthop-group/frr-nexthops/nexthop/fib
 */
struct yang_data *
lib_vrf_ribs_rib_route_nexthop_group_frr_nexthops_nexthop_fib_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}
