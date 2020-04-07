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
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"

static void zebra_extract_afi_safi_key(char *key, int len, afi_t afi,
				       safi_t safi, const char *mname)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		snprintf(key, len, "%s:%s", mname, "ipv4-unicast");
	if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		snprintf(key, len, "%s:%s", mname, "ipv6-unicast");
	if (afi == AFI_IP && safi == SAFI_MULTICAST)
		snprintf(key, len, "%s:%s", "frr-zebra", "ipv4-multicast");
	if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		snprintf(key, len, "%s:%s", "frr-zebra", "ipv6-multicast");
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/up-count
 */
struct yang_data *
lib_interface_zebra_state_up_count_get_elem(const char *xpath,
					    const void *list_entry)
{
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;

	zebra_if = ifp->info;

	return yang_data_new_uint16(xpath, zebra_if->up_count);
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/down-count
 */
struct yang_data *
lib_interface_zebra_state_down_count_get_elem(const char *xpath,
					      const void *list_entry)
{
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;

	zebra_if = ifp->info;

	return yang_data_new_uint16(xpath, zebra_if->down_count);
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
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;
	struct zebra_l2info_vlan *vlan_info;

	if (!IS_ZEBRA_IF_VLAN(ifp))
		return NULL;

	zebra_if = ifp->info;
	vlan_info = &zebra_if->l2info.vl;

	return yang_data_new_uint16(xpath, vlan_info->vid);
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/vni-id
 */
struct yang_data *
lib_interface_zebra_state_vni_id_get_elem(const char *xpath,
					  const void *list_entry)
{
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;
	struct zebra_l2info_vxlan *vxlan_info;

	if (!IS_ZEBRA_IF_VXLAN(ifp))
		return NULL;

	zebra_if = ifp->info;
	vxlan_info = &zebra_if->l2info.vxl;

	return yang_data_new_uint32(xpath, vxlan_info->vni);
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/remote-vtep
 */
struct yang_data *
lib_interface_zebra_state_remote_vtep_get_elem(const char *xpath,
					       const void *list_entry)
{
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;
	struct zebra_l2info_vxlan *vxlan_info;

	if (!IS_ZEBRA_IF_VXLAN(ifp))
		return NULL;

	zebra_if = ifp->info;
	vxlan_info = &zebra_if->l2info.vxl;

	return yang_data_new_ipv4(xpath, &vxlan_info->vtep_ip);
}

/*
 * XPath: /frr-interface:lib/interface/frr-zebra:zebra/state/mcast-group
 */
struct yang_data *
lib_interface_zebra_state_mcast_group_get_elem(const char *xpath,
					       const void *list_entry)
{
	const struct interface *ifp = list_entry;
	struct zebra_if *zebra_if;
	struct zebra_l2info_vxlan *vxlan_info;

	if (!IS_ZEBRA_IF_VXLAN(ifp))
		return NULL;

	zebra_if = ifp->info;
	vxlan_info = &zebra_if->l2info.vxl;

	return yang_data_new_ipv4(xpath, &vxlan_info->mcast_grp);
}

const void *lib_vrf_zebra_ribs_rib_get_next(const void *parent_list_entry,
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

		/* Start from AFI_IP and SAFI_UNICAST */
		zrt = zebra_router_find_zrt(zvrf, zvrf->table_id, afi, safi);
		if (zrt == NULL)
			return NULL;
	} else {
		zrt = RB_NEXT(zebra_router_table_head, zrt);
		/* vrf_id/ns_id do not match, only walk for the given VRF */
		while (zrt && zrt->ns_id != zvrf->zns->ns_id)
			zrt = RB_NEXT(zebra_router_table_head, zrt);
	}

	if (IS_ZEBRA_DEBUG_EVENT && zrt)
		zlog_debug("%s: vrf %s afi %s safi %s", __func__, vrf->name,
			   afi2str(zrt->afi), safi2str(zrt->safi));

	return zrt;
}

int lib_vrf_zebra_ribs_rib_get_keys(const void *list_entry,
				    struct yang_list_keys *keys)
{
	const struct zebra_router_table *zrt = list_entry;

	assert(zrt);

	keys->num = 2;
	zebra_extract_afi_safi_key(keys->key[0], sizeof(keys->key[0]), zrt->afi,
				   zrt->safi, "frr-zebra");

	snprintf(keys->key[1], sizeof(keys->key[1]), "%" PRIu32, zrt->tableid);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: key[0] %s key[1] %s", __func__, keys->key[0],
			   keys->key[1]);

	return NB_OK;
}

const void *
lib_vrf_zebra_ribs_rib_lookup_entry(const void *parent_list_entry,
				    const struct yang_list_keys *keys)
{
	struct vrf *vrf = (struct vrf *)parent_list_entry;
	struct zebra_vrf *zvrf;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;

	zvrf = zebra_vrf_lookup_by_id(vrf->vrf_id);

	return zebra_router_find_zrt(zvrf, zvrf->table_id, afi, safi);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route
 */
const void *lib_vrf_zebra_ribs_rib_route_get_next(const void *parent_list_entry,
						  const void *list_entry)
{
	const struct zebra_router_table *zrt = parent_list_entry;
	const struct route_node *rn = list_entry;

	if (list_entry == NULL)
		rn = route_top(zrt->table);
	else
		rn = srcdest_route_next((struct route_node *)rn);

	return rn;
}

int lib_vrf_zebra_ribs_rib_route_get_keys(const void *list_entry,
					  struct yang_list_keys *keys)
{
	const struct route_node *rn = list_entry;
	char dst_buf[PREFIX_STRLEN] = {'\0'};

	keys->num = 1;
	prefix2str(&rn->p, dst_buf, sizeof(dst_buf));

	strlcpy(keys->key[0], dst_buf, sizeof(keys->key[0]));

	return NB_OK;
}

const void *
lib_vrf_zebra_ribs_rib_route_lookup_entry(const void *parent_list_entry,
					  const struct yang_list_keys *keys)
{
	const struct zebra_router_table *zrt = parent_list_entry;
	struct prefix p;
	struct route_node *rn;

	yang_str2prefix(keys->key[0], &p);

	rn = route_node_match(zrt->table, &p);
	if (!rn) {
		if (IS_ZEBRA_DEBUG_EVENT) {
			char buf[PREFIX_STRLEN];

			zlog_debug("prefix %s is not present in route table",
				   prefix2str(&p, buf, sizeof(buf)));
		}
		return NULL;
	}
	route_unlock_node(rn);

	return rn;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/prefix
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_prefix_get_elem(const char *xpath,
					     const void *list_entry)
{
	const struct route_node *rn = list_entry;

	return yang_data_new_prefix(xpath, &rn->p);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry
 */
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_get_next(const void *parent_list_entry,
						  const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;
	struct route_node *rn = (struct route_node *)parent_list_entry;

	if (list_entry == NULL)
		RNODE_FIRST_RE(rn, re);
	else
		RNODE_NEXT_RE(rn, re);

	if (re) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: next route_entry is found.", __func__);
	}

	return re;
}

int lib_vrf_zebra_ribs_rib_route_route_entry_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	keys->num = 1;

	strlcpy(keys->key[0], zebra_route_string(re->type),
		sizeof(keys->key[0]));

	return NB_OK;
}

const void *lib_vrf_zebra_ribs_rib_route_route_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	struct route_node *rn = (struct route_node *)parent_list_entry;
	struct route_entry *re = NULL;
	int type = 0;
	char *ptype = (char *)keys->key[0];

	if (strncmp(ptype, "kernel", 10) == 0)
		type = 1;
	else if (strncmp(ptype, "connected", 10) == 0)
		type = 2;
	else if (strncmp(ptype, "static", 10) == 0)
		type = 3;
	else if (strncmp(ptype, "rip", 10) == 0)
		type = 4;
	else if (strncmp(ptype, "ripng", 10) == 0)
		type = 5;
	else if (strncmp(ptype, "ospf", 10) == 0)
		type = 6;
	else if (strncmp(ptype, "ospf6", 10) == 0)
		type = 7;
	else if (strncmp(ptype, "isis", 10) == 0)
		type = 8;
	else if (strncmp(ptype, "bgp", 10) == 0)
		type = 9;
	else if (strncmp(ptype, "table", 10) == 0)
		type = 15;
	else if (strncmp(ptype, "sharp", 10) == 0)
		type = 23;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: type %u", __func__, type);

	RNODE_FOREACH_RE (rn, re) {
		if (type == re->type)
			return re;
	}

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/protocol
 */
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_protocol_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	return yang_data_new_enum(xpath, re->type);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/instance
 */
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_instance_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (re->instance)
		return yang_data_new_uint16(xpath, re->instance);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/distance
 */
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_distance_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	return yang_data_new_uint8(xpath, re->distance);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/metric
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_metric_get_elem(const char *xpath,
							 const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	return yang_data_new_uint32(xpath, re->metric);
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/tag
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_tag_get_elem(const char *xpath,
						      const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (re->tag)
		return yang_data_new_uint32(xpath, re->tag);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/selected
 */
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_selected_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/installed
 */
struct yang_data *lib_vrf_zebra_ribs_rib_route_route_entry_installed_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/failed
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_failed_get_elem(const char *xpath,
							 const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_FAILED))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/queued
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_queued_get_elem(const char *xpath,
							 const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/internal-flags
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_internal_flags_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (re->flags)
		return yang_data_new_int32(xpath, re->flags);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/internal-status
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_internal_status_get_elem(
	const char *xpath, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)list_entry;

	if (re->status)
		return yang_data_new_int32(xpath, re->status);

	return NULL;
}

/*
 * XPath: /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/uptime
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_uptime_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group
 */
const void *lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	struct route_entry *re = (struct route_entry *)parent_list_entry;
	struct nhg_hash_entry *nhe = (struct nhg_hash_entry *)list_entry;

	if (list_entry == NULL) {
		nhe = re->nhe;
		return nhe;
	}
	return NULL;
}

int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	struct nhg_hash_entry *nhe = (struct nhg_hash_entry *)list_entry;

	keys->num = 1;
	snprintf(keys->key[0], sizeof(keys->key[0]), "%" PRIu32, nhe->id);

	return NB_OK;
}

const void *lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/name
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_name_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nhg_hash_entry *nhe = (struct nhg_hash_entry *)list_entry;

	if (nhe) {
		char name[20] = {'\0'};

		snprintf(name, sizeof(name), "%" PRIu32, nhe->id);
		return yang_data_new_string(xpath, name);
	}
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop
 */
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;
	struct nhg_hash_entry *nhe = (struct nhg_hash_entry *)parent_list_entry;

	if (list_entry == NULL)
		nexthop = (nhe->nhg.nexthop);
	else
		nexthop = nexthop_next(nexthop);

	return nexthop;
}

int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;
	char buf[PREFIX2STR_BUFFER];

	keys->num = 3;

	strlcpy(keys->key[0], yang_nexthop_type2str(nexthop->type),
		sizeof(keys->key[0]));

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &nexthop->gate.ipv4, buf, sizeof(buf));
		strlcpy(keys->key[1], buf, sizeof(keys->key[1]));

		if (nexthop->ifindex)
			strlcpy(keys->key[2],
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id),
				sizeof(keys->key[2]));
		else
			/* no ifindex */
			strlcpy(keys->key[2], " ", sizeof(keys->key[2]));

		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, sizeof(buf));
		strlcpy(keys->key[1], buf, sizeof(keys->key[1]));

		if (nexthop->ifindex)
			strlcpy(keys->key[2],
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id),
				sizeof(keys->key[2]));
		else
			/* no ifindex */
			strlcpy(keys->key[2], " ", sizeof(keys->key[2]));

		break;
	case NEXTHOP_TYPE_IFINDEX:
		strlcpy(keys->key[1], "", sizeof(keys->key[1]));
		strlcpy(keys->key[2],
			ifindex2ifname(nexthop->ifindex, nexthop->vrf_id),
			sizeof(keys->key[2]));

		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		/* Gateway IP */
		strlcpy(keys->key[1], "", sizeof(keys->key[1]));
		strlcpy(keys->key[2], "", sizeof(keys->key[2]));
		break;
	default:
		break;
	}

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: key1 %s key2 %s  key3 %s", __func__,
			   keys->key[0], keys->key[1], keys->key[2]);

	return NB_OK;
}

const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/nh-type
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_nh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		return yang_data_new_string(xpath, "ifindex");
	case NEXTHOP_TYPE_IPV4:
		return yang_data_new_string(xpath, "ip4");
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return yang_data_new_string(xpath, "ip4-ifindex");
	case NEXTHOP_TYPE_IPV6:
		return yang_data_new_string(xpath, "ip6");
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		return yang_data_new_string(xpath, "ip6-ifindex");
	default:
		break;
	}

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/vrf
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_vrf_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	return yang_data_new_string(xpath, vrf_id_to_name(nexthop->vrf_id));
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/gateway
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_gateway_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;
	struct ipaddr addr;

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		addr.ipa_type = IPADDR_V4;
		memcpy(&addr.ipaddr_v4, &(nexthop->gate.ipv4),
		       sizeof(struct in_addr));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		addr.ipa_type = IPADDR_V6;
		memcpy(&addr.ipaddr_v6, &(nexthop->gate.ipv6),
		       sizeof(struct in6_addr));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
	case NEXTHOP_TYPE_IFINDEX:
		/* No addr here */
		return yang_data_new_string(xpath, "");
	default:
		break;
	}

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf2[INET6_ADDRSTRLEN];

		zlog_debug("%s: ipaddr %s ", __func__,
			   ipaddr2str(&addr, buf2, sizeof(buf2)));
	}
	return yang_data_new_ip(xpath, &addr);
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/interface
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_interface_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (nexthop->ifindex) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: ifindex %s", __func__,
				   ifindex2ifname(nexthop->ifindex,
						  nexthop->vrf_id));
		yang_data_new_string(xpath, ifindex2ifname(nexthop->ifindex,
							   nexthop->vrf_id));
	}

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/bh-type
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_bh_type_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;
	char type_str[PREFIX2STR_BUFFER] = {'\0'};

	if (nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		return NULL;

	switch (nexthop->bh_type) {
	case BLACKHOLE_NULL:
		strlcpy(type_str, "null", 12);
		break;
	case BLACKHOLE_REJECT:
		strlcpy(type_str, "reject", 12);
		break;
	case BLACKHOLE_ADMINPROHIB:
		strlcpy(type_str, "prohibited", 12);
		break;
	case BLACKHOLE_UNSPEC:
		strlcpy(type_str, "unspec", 12);
		break;
	}

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: type %s ", __func__, type_str);

	return yang_data_new_string(xpath, type_str);
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/onlink
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_onlink_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK))
		return yang_data_new_bool(xpath, true);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry
 */
const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

int lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_get_keys(
	const void *list_entry, struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

const void *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/id
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_id_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_label_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/duplicate
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_duplicate_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_DUPLICATE))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/recursive
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_recursive_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/active
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_active_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/fib
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_fib_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
		return yang_data_new_empty(xpath);

	return NULL;
}

/*
 * XPath:
 * /frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route/route-entry/nexthop-group/frr-nexthops/nexthop/weight
 */
struct yang_data *
lib_vrf_zebra_ribs_rib_route_route_entry_nexthop_group_frr_nexthops_nexthop_weight_get_elem(
	const char *xpath, const void *list_entry)
{
	struct nexthop *nexthop = (struct nexthop *)list_entry;

	if (nexthop->weight)
		return yang_data_new_uint8(xpath, nexthop->weight);

	return NULL;
}
