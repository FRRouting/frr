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
#include "zebra/zebra_router.h"

const void *lib_vrf_ribs_rib_get_next(const void *parent_list_entry,
				      const void *list_entry)
{
	struct vrf *vrf = (struct vrf *)parent_list_entry;
	struct zebra_router_table *zrt =
		(struct zebra_router_table *)list_entry;

	struct zebra_vrf *zvrf;
	afi_t afi;
	safi_t safi;

	zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);

	if (list_entry == NULL) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;

		zrt = zebra_router_find_zrt(zvrf, zvrf->table_id, afi, safi);
		if (zrt == NULL)
			return NULL;
	} else {
		zrt = RB_NEXT(zebra_router_table_head, zrt);
		/* vrf_id/ns_id do not match, only walk for the given VRF */
		while (zrt && zrt->ns_id != zvrf->zns->ns_id)
			zrt = RB_NEXT(zebra_router_table_head, zrt);
	}

	return zrt;
}

int lib_vrf_ribs_rib_get_keys(const void *list_entry,
			      struct yang_list_keys *keys)
{
	const struct zebra_router_table *zrt = list_entry;
	// struct vrf *vrf;

	assert(zrt);

	keys->num = 2;

	snprintf(keys->key[0], sizeof(keys->key[0]), "%s",
		 "frr-zebra:ipv4-unicast");
	/* TODO: implement key[0], afi-safi identityref */
	snprintf(keys->key[1], sizeof(keys->key[1]), "%" PRIu32, zrt->tableid);
#if 0
	if (!vrf_is_backend_netns()) {
		zlog_debug("vrf backed netns ns_id %u", zrt->ns_id);
		return NB_ERR_INCONSISTENCY;
	}
	vrf = vrf_lookup_by_id((vrf_id_t)zrt->ns_id);

	if (!vrf) {
		zlog_debug("vrf is not found for ns_id %u", zrt->ns_id);
		return NB_ERR_INCONSISTENCY;
	}
#endif

	/* TODO: implement me. */
	return NB_OK;
}

const void *lib_vrf_ribs_rib_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys)
{
	struct vrf *vrf = (struct vrf *)parent_list_entry;
	// uint32_t tableid = strtoul(keys->key[1], NULL, 10);
	struct zebra_vrf *zvrf;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;

	zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);

	return zebra_router_find_zrt(zvrf, zvrf->table_id, afi, safi);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route
 */
const void *lib_vrf_ribs_rib_route_get_next(const void *parent_list_entry,
					    const void *list_entry)
{
	const struct zebra_router_table *zrt = parent_list_entry;
	const struct route_node *rn = list_entry;

	if (list_entry == NULL) {
		rn = route_top(zrt->table);
	} else {
		rn = srcdest_route_next((struct route_node *)rn);
	}

	return rn;
}

int lib_vrf_ribs_rib_route_get_keys(const void *list_entry,
				    struct yang_list_keys *keys)
{
	const struct route_node *rn = list_entry;
	char dst_buf[PREFIX_STRLEN];
	const struct prefix *dst_p;

	srcdest_rnode_prefixes(rn, &dst_p, NULL);
	keys->num = 1;
	strlcpy(keys->key[0], prefix2str(dst_p, dst_buf, sizeof(dst_p)),
		sizeof(keys->key[0]));

	return NB_OK;
}

const void *
lib_vrf_ribs_rib_route_lookup_entry(const void *parent_list_entry,
				    const struct yang_list_keys *keys)
{
	const struct zebra_router_table *zrt = parent_list_entry;
	struct prefix p;
	struct route_node *rn;

	yang_str2prefix(keys->key[0], &p);

	rn = route_node_lookup(zrt->table, &p);

	if (!rn) {
		char buf[PREFIX_STRLEN];
		zlog_debug("prefix %s is not present in route table",
			   prefix2str(&p, buf, sizeof(buf)));
	}

	return rn;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/prefix
 */
struct yang_data *lib_vrf_ribs_rib_route_prefix_get_elem(const char *xpath,
							 const void *list_entry)
{
	const struct route_node *rn = list_entry;

	return yang_data_new_prefix(xpath, &rn->p);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:ribs/rib/route/route-entry
 */
const void *
lib_vrf_ribs_rib_route_route_entry_get_next(const void *parent_list_entry,
					    const void *list_entry)
{
	struct route_entry *re = NULL;

	return re;
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
