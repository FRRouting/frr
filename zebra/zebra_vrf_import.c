// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra native VRF route import.
 * Copyright (C) 2026 Proxmox Server Solutions GmbH
 *                    Gabriel Goller
 */

#include <zebra.h>

#include "memory.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "prefix.h"
#include "routemap.h"
#include "vrf.h"

#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vrf_import.h"
#include "zebra/zebra_routemap.h"

DEFINE_MTYPE_STATIC(ZEBRA, VRF_IMPORT, "Zebra VRF import config");
DEFINE_MTYPE_STATIC(ZEBRA, VRF_IMPORT_NAME, "Zebra VRF import name");

struct zebra_vrf_import {
	afi_t afi;
	safi_t safi;
	char *src_vrf_name;
	char *rmap_name;

	struct zebra_vrf_imports_item item;
};

DECLARE_DLIST(zebra_vrf_imports, struct zebra_vrf_import, item);

void zebra_vrf_import_init(struct zebra_vrf *zvrf)
{
	zebra_vrf_imports_init(&zvrf->vrf_imports);
}

static void zebra_vrf_import_free(struct zebra_vrf_import *import)
{
	if (!import)
		return;

	XFREE(MTYPE_VRF_IMPORT_NAME, import->src_vrf_name);
	XFREE(MTYPE_VRF_IMPORT_NAME, import->rmap_name);
	XFREE(MTYPE_VRF_IMPORT, import);
}

static struct zebra_vrf_import *zebra_vrf_import_lookup(struct zebra_vrf *zvrf, afi_t afi,
							safi_t safi, const char *src_vrf_name)
{
	struct zebra_vrf_import *import;

	frr_each (zebra_vrf_imports, &zvrf->vrf_imports, import) {
		if (import->afi == afi && import->safi == safi &&
		    strmatch(import->src_vrf_name, src_vrf_name))
			return import;
	}

	return NULL;
}

static bool zebra_vrf_import_re_match(const struct route_entry *re, vrf_id_t src_vrf_id)
{
	return re->type == ZEBRA_ROUTE_VRF_IMPORT && re->vrf_import_src_vrf_id == src_vrf_id;
}

static void zebra_vrf_import_del_prefix(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
					vrf_id_t src_vrf_id, const struct prefix *p)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re, *next;

	table = zebra_vrf_table(afi, safi, zvrf_id(dst_zvrf));
	if (!table)
		return;

	rn = srcdest_rnode_lookup(table, p, NULL);
	if (!rn)
		return;

	RNODE_FOREACH_RE_SAFE (rn, re, next) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		if (zebra_vrf_import_re_match(re, src_vrf_id))
			rib_delnode(rn, re);
	}

	route_unlock_node(rn);
}

static void zebra_vrf_import_del_all(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
				     vrf_id_t src_vrf_id)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re, *next;

	table = zebra_vrf_table(afi, safi, zvrf_id(dst_zvrf));
	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		RNODE_FOREACH_RE_SAFE (rn, re, next) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;

			if (zebra_vrf_import_re_match(re, src_vrf_id))
				rib_delnode(rn, re);
		}
	}
}

static bool zebra_vrf_import_copy_one_nh(struct nexthop_group *ng, const struct nexthop *src_nh,
					 vrf_id_t dst_vrf_id, afi_t afi)
{
	struct nexthop *nh;

	switch (src_nh->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (afi != AFI_IP)
			return false;
		nh = nexthop_new();
		nh->type = NEXTHOP_TYPE_IPV4;
		nh->vrf_id = dst_vrf_id;
		nh->gate.ipv4 = src_nh->gate.ipv4;
		nexthop_group_add_sorted(ng, nh);
		return true;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (afi != AFI_IP6 || IN6_IS_ADDR_LINKLOCAL(&src_nh->gate.ipv6))
			return false;
		nh = nexthop_new();
		nh->type = NEXTHOP_TYPE_IPV6;
		nh->vrf_id = dst_vrf_id;
		nh->gate.ipv6 = src_nh->gate.ipv6;
		nexthop_group_add_sorted(ng, nh);
		return true;
	case NEXTHOP_TYPE_BLACKHOLE:
		nh = nexthop_new();
		nh->type = NEXTHOP_TYPE_BLACKHOLE;
		nh->vrf_id = dst_vrf_id;
		nh->bh_type = src_nh->bh_type;
		nexthop_group_add_sorted(ng, nh);
		return true;
	case NEXTHOP_TYPE_IFINDEX:
		/* Interface-only routes are unsafe across VRFs. */
		return false;
	}

	return false;
}

static struct nexthop_group *zebra_vrf_import_copy_nhg(struct route_entry *src_re,
						       vrf_id_t dst_vrf_id, afi_t afi)
{
	struct nexthop_group *ng;
	struct nexthop *src_nh;
	bool copied = false;

	ng = nexthop_group_new();
	for (ALL_NEXTHOPS(src_re->nhe->nhg, src_nh))
		copied |= zebra_vrf_import_copy_one_nh(ng, src_nh, dst_vrf_id, afi);

	if (!copied) {
		nexthop_group_delete(&ng);
		return NULL;
	}

	return ng;
}

static int zebra_vrf_import_add_route(struct zebra_vrf_import *import, struct zebra_vrf *dst_zvrf,
				      struct zebra_vrf *src_zvrf, struct route_node *src_rn,
				      struct route_entry *src_re)
{
	struct route_entry *newre;
	struct nexthop_group *ng;
	struct prefix p;
	route_map_result_t ret = RMAP_PERMITMATCH;
	uint32_t import_flags;

	if (!src_re || CHECK_FLAG(src_re->status, ROUTE_ENTRY_REMOVED))
		return 0;

	if (src_re->type == ZEBRA_ROUTE_VRF_IMPORT)
		return 0;

	/*
	 * Replace any previous copy of this source prefix first. Scan/rescan paths
	 * call directly into this helper, and RIB update paths rely on this delete
	 * when replacing a selected source route with another selected route that is
	 * later denied by policy or cannot be imported.
	 */
	zebra_vrf_import_del_prefix(dst_zvrf, import->afi, import->safi, zvrf_id(src_zvrf),
				    &src_rn->p);

	if (import->rmap_name) {
		struct nexthop *match_nh = src_re->nhe->nhg.nexthop;

		ret = zebra_vrf_import_route_map_check(import->afi, src_re, &src_rn->p, match_nh,
						       import->rmap_name);
	}

	if (ret != RMAP_PERMITMATCH)
		return 0;

	ng = zebra_vrf_import_copy_nhg(src_re, zvrf_id(dst_zvrf), import->afi);
	if (!ng)
		return 0;

	import_flags = src_re->flags;
	UNSET_FLAG(import_flags, ZEBRA_FLAG_SELECTED);
	UNSET_FLAG(import_flags, ZEBRA_FLAG_RR_USE_DISTANCE);

	newre = zebra_rib_route_entry_new(zvrf_id(dst_zvrf), ZEBRA_ROUTE_VRF_IMPORT, 0,
					  import_flags, 0, dst_zvrf->table_id, src_re->metric,
					  src_re->mtu, src_re->distance, src_re->tag);
	newre->vrf_import_src_vrf_id = zvrf_id(src_zvrf);

	prefix_copy(&p, &src_rn->p);
	rib_add_multipath(import->afi, import->safi, &p, NULL, newre, ng, false, true);
	nexthop_group_delete(&ng);

	return 0;
}

static struct route_entry *zebra_vrf_import_selected_route(struct route_node *rn)
{
	rib_dest_t *dest = rib_dest_from_rnode(rn);
	struct route_entry *re;

	if (!dest)
		return NULL;

	re = dest->selected_fib;
	if (!re)
		return NULL;

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
		return NULL;

	return re;
}

static void zebra_vrf_import_scan(struct zebra_vrf_import *import, struct zebra_vrf *dst_zvrf)
{
	struct vrf *src_vrf;
	struct zebra_vrf *src_zvrf;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;

	src_vrf = vrf_lookup_by_name(import->src_vrf_name);
	if (!src_vrf || !src_vrf->info)
		return;
	src_zvrf = src_vrf->info;

	table = zebra_vrf_table(import->afi, SAFI_UNICAST, zvrf_id(src_zvrf));
	if (!table)
		return;

	for (rn = route_top(table); rn; rn = srcdest_route_next(rn)) {
		re = zebra_vrf_import_selected_route(rn);
		if (re)
			zebra_vrf_import_add_route(import, dst_zvrf, src_zvrf, rn, re);
	}
}

int zebra_vrf_import_add(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
			 const char *src_vrf_name, const char *rmap_name)
{
	struct zebra_vrf_import *import;

	if (!dst_zvrf || !src_vrf_name || afi >= AFI_MAX || safi >= SAFI_MAX)
		return -1;

	import = zebra_vrf_import_lookup(dst_zvrf, afi, safi, src_vrf_name);
	if (!import) {
		import = XCALLOC(MTYPE_VRF_IMPORT, sizeof(*import));
		import->afi = afi;
		import->safi = safi;
		import->src_vrf_name = XSTRDUP(MTYPE_VRF_IMPORT_NAME, src_vrf_name);
		zebra_vrf_imports_add_tail(&dst_zvrf->vrf_imports, import);
	}

	XFREE(MTYPE_VRF_IMPORT_NAME, import->rmap_name);
	if (rmap_name)
		import->rmap_name = XSTRDUP(MTYPE_VRF_IMPORT_NAME, rmap_name);

	zebra_vrf_import_scan(import, dst_zvrf);
	return 0;
}

int zebra_vrf_import_del(struct zebra_vrf *dst_zvrf, afi_t afi, safi_t safi,
			 const char *src_vrf_name)
{
	struct zebra_vrf_import *import;
	struct vrf *src_vrf;

	if (!dst_zvrf || !src_vrf_name)
		return -1;

	import = zebra_vrf_import_lookup(dst_zvrf, afi, safi, src_vrf_name);
	if (!import)
		return 0;

	src_vrf = vrf_lookup_by_name(import->src_vrf_name);
	if (src_vrf)
		zebra_vrf_import_del_all(dst_zvrf, afi, safi, src_vrf->vrf_id);

	zebra_vrf_imports_del(&dst_zvrf->vrf_imports, import);
	zebra_vrf_import_free(import);

	return 0;
}

static void zebra_vrf_import_rescan_dst(struct zebra_vrf *dst_zvrf, afi_t afi)
{
	struct zebra_vrf_import *import;
	struct vrf *src_vrf;

	if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
		return;

	frr_each (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
		if (import->afi != afi || import->safi != SAFI_UNICAST)
			continue;

		src_vrf = vrf_lookup_by_name(import->src_vrf_name);
		if (src_vrf)
			zebra_vrf_import_del_all(dst_zvrf, import->afi, import->safi,
						 src_vrf->vrf_id);
		zebra_vrf_import_scan(import, dst_zvrf);
	}
}

void zebra_vrf_import_rib_update(struct route_node *rn, struct route_entry *old_selected,
				 struct route_entry *new_selected)
{
	struct route_entry *src_re = new_selected ? new_selected : old_selected;
	struct zebra_vrf *src_zvrf;
	struct vrf *vrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;
	afi_t afi;

	if (!src_re || src_re->type == ZEBRA_ROUTE_VRF_IMPORT)
		return;

	afi = family2afi(rn->p.family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	src_zvrf = vrf_info_lookup(src_re->vrf_id);
	if (!src_zvrf)
		return;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
			continue;

		frr_each (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (import->afi != afi || import->safi != SAFI_UNICAST)
				continue;
			if (!strmatch(import->src_vrf_name, zvrf_name(src_zvrf)))
				continue;

			zebra_vrf_import_del_prefix(dst_zvrf, import->afi, import->safi,
						    zvrf_id(src_zvrf), &rn->p);
			if (new_selected)
				zebra_vrf_import_add_route(import, dst_zvrf, src_zvrf, rn,
							   new_selected);
		}
	}

	/* A route in this VRF may have appeared/disappeared as a resolver for
	 * imported routes.  Force a conservative re-evaluation because VRF-import
	 * routes created before their destination nexthop was resolvable may not
	 * otherwise get revisited immediately.
	 */
	zebra_vrf_import_rescan_dst(src_zvrf, afi);
}

void zebra_vrf_import_route_map_update(const char *rmap_name)
{
	struct vrf *vrf;
	struct vrf *src_vrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;

	if (!rmap_name)
		return;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
			continue;

		frr_each_safe (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (!import->rmap_name || !strmatch(import->rmap_name, rmap_name))
				continue;

			src_vrf = vrf_lookup_by_name(import->src_vrf_name);
			if (src_vrf)
				zebra_vrf_import_del_all(dst_zvrf, import->afi, import->safi,
							 src_vrf->vrf_id);
			zebra_vrf_import_scan(import, dst_zvrf);
		}
	}
}

void zebra_vrf_import_vrf_enable(struct zebra_vrf *zvrf)
{
	struct vrf *vrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;

	/* Re-scan imports from this source when a VRF appears/enables. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
			continue;

		frr_each (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (strmatch(import->src_vrf_name, zvrf_name(zvrf)))
				zebra_vrf_import_scan(import, dst_zvrf);
		}
	}
}

void zebra_vrf_import_vrf_delete(struct zebra_vrf *zvrf)
{
	struct vrf *vrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;

	/* Remove imports configured in this destination VRF. */
	while ((import = zebra_vrf_imports_first(&zvrf->vrf_imports)))
		zebra_vrf_import_del(zvrf, import->afi, import->safi, import->src_vrf_name);

	/* Remove imported routes in other VRFs sourced from this VRF. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports) ||
		    dst_zvrf == zvrf)
			continue;

		frr_each (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (!strmatch(import->src_vrf_name, zvrf_name(zvrf)))
				continue;
			zebra_vrf_import_del_all(dst_zvrf, import->afi, import->safi,
						 zvrf_id(zvrf));
		}
	}

	zebra_vrf_imports_fini(&zvrf->vrf_imports);
}
