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
DEFINE_MTYPE_STATIC(ZEBRA, VRF_IMPORT_SRC_INDEX, "Zebra VRF import source index");

PREDECL_DLIST(zebra_vrf_import_src_index_imports);
PREDECL_HASH(zebra_vrf_import_src_index);

struct zebra_vrf_import {
	afi_t afi;
	safi_t safi;

	/* Configured source VRF name. This remains authoritative because the
	 * source VRF may not exist yet, or may be deleted and recreated with a
	 * different vrf_id.
	 */
	char *src_vrf_name;
	char *rmap_name;
	struct zebra_vrf *dst_zvrf;

	/* Runtime reverse-index bucket this import is currently linked into.
	 * NULL means src_vrf_name does not currently resolve to an existing VRF.
	 */
	struct zebra_vrf_import_src_index *src_index;
	struct zebra_vrf_imports_item item;
	struct zebra_vrf_import_src_index_imports_item src_index_item;
};

/* Runtime reverse index used by zebra_vrf_import_rib_update(). This maps a
 * resolved source VRF id plus AFI/SAFI to the import configs interested in
 * route changes from that source.
 */
struct zebra_vrf_import_src_index {
	vrf_id_t src_vrf_id;
	afi_t afi;
	safi_t safi;
	struct zebra_vrf_import_src_index_imports_head imports;
	struct zebra_vrf_import_src_index_item hash_item;
};

DECLARE_DLIST(zebra_vrf_imports, struct zebra_vrf_import, item);
DECLARE_DLIST(zebra_vrf_import_src_index_imports, struct zebra_vrf_import, src_index_item);

static int zebra_vrf_import_src_index_cmp(const struct zebra_vrf_import_src_index *a,
					  const struct zebra_vrf_import_src_index *b)
{
	if (a->src_vrf_id != b->src_vrf_id)
		return a->src_vrf_id < b->src_vrf_id ? -1 : 1;
	if (a->afi != b->afi)
		return a->afi < b->afi ? -1 : 1;
	return a->safi - b->safi;
}

static uint32_t zebra_vrf_import_src_index_hash(const struct zebra_vrf_import_src_index *src_index)
{
	return jhash_3words(src_index->src_vrf_id, src_index->afi, src_index->safi, 0);
}

DECLARE_HASH(zebra_vrf_import_src_index, struct zebra_vrf_import_src_index, hash_item,
	     zebra_vrf_import_src_index_cmp, zebra_vrf_import_src_index_hash);

static struct zebra_vrf_import_src_index_head zebra_vrf_import_src_index_table;

void zebra_vrf_import_init(struct zebra_vrf *zvrf)
{
	zebra_vrf_imports_init(&zvrf->vrf_imports);
}

static struct zebra_vrf_import_src_index *zebra_vrf_import_src_index_lookup(vrf_id_t src_vrf_id,
									    afi_t afi, safi_t safi)
{
	struct zebra_vrf_import_src_index lookup = {
		.src_vrf_id = src_vrf_id,
		.afi = afi,
		.safi = safi,
	};

	return zebra_vrf_import_src_index_find(&zebra_vrf_import_src_index_table, &lookup);
}

static struct zebra_vrf_import_src_index *zebra_vrf_import_src_index_get(vrf_id_t src_vrf_id,
									 afi_t afi, safi_t safi)
{
	struct zebra_vrf_import_src_index *src_index;

	src_index = zebra_vrf_import_src_index_lookup(src_vrf_id, afi, safi);
	if (src_index)
		return src_index;

	src_index = XCALLOC(MTYPE_VRF_IMPORT_SRC_INDEX, sizeof(*src_index));
	src_index->src_vrf_id = src_vrf_id;
	src_index->afi = afi;
	src_index->safi = safi;
	zebra_vrf_import_src_index_imports_init(&src_index->imports);
	zebra_vrf_import_src_index_add(&zebra_vrf_import_src_index_table, src_index);

	return src_index;
}

static void zebra_vrf_import_unlink_src_index(struct zebra_vrf_import *import)
{
	struct zebra_vrf_import_src_index *src_index;

	if (!import || !import->src_index)
		return;

	src_index = import->src_index;
	zebra_vrf_import_src_index_imports_del(&src_index->imports, import);
	import->src_index = NULL;

	if (zebra_vrf_import_src_index_imports_count(&src_index->imports))
		return;

	zebra_vrf_import_src_index_del(&zebra_vrf_import_src_index_table, src_index);
	zebra_vrf_import_src_index_imports_fini(&src_index->imports);
	XFREE(MTYPE_VRF_IMPORT_SRC_INDEX, src_index);
}

static void zebra_vrf_import_link_src_index(struct zebra_vrf_import *import, vrf_id_t src_vrf_id)
{
	struct zebra_vrf_import_src_index *src_index;

	if (!import)
		return;

	if (import->src_index && import->src_index->src_vrf_id == src_vrf_id &&
	    import->src_index->afi == import->afi && import->src_index->safi == import->safi)
		return;

	zebra_vrf_import_unlink_src_index(import);
	src_index = zebra_vrf_import_src_index_get(src_vrf_id, import->afi, import->safi);
	zebra_vrf_import_src_index_imports_add_tail(&src_index->imports, import);
	import->src_index = src_index;
}

static void zebra_vrf_import_refresh_src_index(struct zebra_vrf_import *import)
{
	struct vrf *src_vrf;

	if (!import)
		return;

	src_vrf = vrf_lookup_by_name(import->src_vrf_name);
	if (!zvrf_is_active(import->dst_zvrf) || !src_vrf || !vrf_is_enabled(src_vrf)) {
		zebra_vrf_import_unlink_src_index(import);
		return;
	}

	zebra_vrf_import_link_src_index(import, src_vrf->vrf_id);
}

static void zebra_vrf_import_free(struct zebra_vrf_import *import)
{
	if (!import)
		return;

	zebra_vrf_import_unlink_src_index(import);
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

static struct nexthop_group *zebra_vrf_import_rewrite_nhg(afi_t afi, vrf_id_t dst_vrf_id,
							  const union g_addr *gate)
{
	struct nexthop_group *ng;
	struct nexthop *nh;

	ng = nexthop_group_new();
	nh = nexthop_new();
	nh->vrf_id = dst_vrf_id;
	if (afi == AFI_IP) {
		nh->type = NEXTHOP_TYPE_IPV4;
		nh->gate.ipv4 = gate->ipv4;
	} else {
		nh->type = NEXTHOP_TYPE_IPV6;
		nh->gate.ipv6 = gate->ipv6;
	}
	nexthop_group_add_sorted(ng, nh);

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
	union g_addr set_gate = {};
	afi_t set_afi = AFI_UNSPEC;
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
						       import->rmap_name, &set_afi, &set_gate);
	}

	if (ret != RMAP_PERMITMATCH)
		return 0;

	if (set_afi != AFI_UNSPEC) {
		if (set_afi != import->afi)
			return 0;
		ng = zebra_vrf_import_rewrite_nhg(import->afi, zvrf_id(dst_zvrf), &set_gate);
	} else {
		ng = zebra_vrf_import_copy_nhg(src_re, zvrf_id(dst_zvrf), import->afi);
	}

	if (!ng)
		return 0;

	import_flags = src_re->flags;
	if (set_afi != AFI_UNSPEC)
		SET_FLAG(import_flags, ZEBRA_FLAG_ALLOW_RECURSION);
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
	if (!src_vrf || !vrf_is_enabled(src_vrf) || !src_vrf->info)
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
		import->dst_zvrf = dst_zvrf;
		zebra_vrf_imports_add_tail(&dst_zvrf->vrf_imports, import);
	}

	XFREE(MTYPE_VRF_IMPORT_NAME, import->rmap_name);
	if (rmap_name)
		import->rmap_name = XSTRDUP(MTYPE_VRF_IMPORT_NAME, rmap_name);

	zebra_vrf_import_refresh_src_index(import);
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

static void zebra_vrf_import_queue_dst(struct zebra_vrf *dst_zvrf, afi_t afi)
{
	struct route_table *table;

	if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
		return;

	table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(dst_zvrf));
	if (!table)
		return;

	rib_update_table(table, RIB_UPDATE_OTHER, ZEBRA_ROUTE_VRF_IMPORT);
}

void zebra_vrf_import_resolver_update(struct route_node *rn, struct route_entry *re)
{
	struct zebra_vrf *zvrf;
	afi_t afi;

	if (!rn || !re || re->type == ZEBRA_ROUTE_VRF_IMPORT)
		return;

	afi = family2afi(rn->p.family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	zvrf = vrf_info_lookup(re->vrf_id);
	if (!zvrf)
		return;

	zebra_vrf_import_queue_dst(zvrf, afi);
}

void zebra_vrf_import_rib_update(struct route_node *rn, struct route_entry *old_selected,
				 struct route_entry *new_selected)
{
	struct route_entry *src_re = new_selected ? new_selected : old_selected;
	struct zebra_vrf *src_zvrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;
	struct zebra_vrf_import_src_index *src_index;
	afi_t afi;

	if (!src_re || src_re->type == ZEBRA_ROUTE_VRF_IMPORT)
		return;

	afi = family2afi(rn->p.family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	src_zvrf = vrf_info_lookup(src_re->vrf_id);
	if (!src_zvrf)
		return;

	src_index = zebra_vrf_import_src_index_lookup(zvrf_id(src_zvrf), afi, SAFI_UNICAST);
	if (!src_index)
		return;

	frr_each_safe (zebra_vrf_import_src_index_imports, &src_index->imports, import) {
		/* Be defensive: source VRF IDs can be removed/reused. If an import
		 * somehow remains in an old ID bucket, never import from a VRF whose
		 * name does not match the configured source.
		 */
		if (!strmatch(import->src_vrf_name, zvrf_name(src_zvrf))) {
			zebra_vrf_import_unlink_src_index(import);
			continue;
		}

		dst_zvrf = import->dst_zvrf;
		if (new_selected)
			zebra_vrf_import_add_route(import, dst_zvrf, src_zvrf, rn, new_selected);
		else
			zebra_vrf_import_del_prefix(dst_zvrf, import->afi, import->safi,
						    zvrf_id(src_zvrf), &rn->p);
	}
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

	frr_each (zebra_vrf_imports, &zvrf->vrf_imports, import) {
		zebra_vrf_import_refresh_src_index(import);
		zebra_vrf_import_scan(import, zvrf);
	}

	/* Re-scan imports from this source when a VRF appears/enables. */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
			continue;

		frr_each (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (!zvrf_is_active(dst_zvrf) ||
			    !strmatch(import->src_vrf_name, zvrf_name(zvrf)))
				continue;
			zebra_vrf_import_link_src_index(import, zvrf_id(zvrf));
			zebra_vrf_import_scan(import, dst_zvrf);
		}
	}
}

static void zebra_vrf_import_src_vrf_down(struct zebra_vrf *zvrf)
{
	struct vrf *vrf;
	struct zebra_vrf *dst_zvrf;
	struct zebra_vrf_import *import;
	const char *src_vrf_name = zvrf_name(zvrf);
	vrf_id_t src_vrf_id = zvrf_id(zvrf);

	/* Remove imported routes and reverse-index entries sourced from this VRF.
	 * This must run when a VRF is disabled, not just deleted, because its
	 * numeric vrf_id can be removed or reused while the configured VRF object
	 * and import config remain.
	 */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		dst_zvrf = vrf->info;
		if (!dst_zvrf || !zebra_vrf_imports_count(&dst_zvrf->vrf_imports))
			continue;

		frr_each_safe (zebra_vrf_imports, &dst_zvrf->vrf_imports, import) {
			if (!strmatch(import->src_vrf_name, src_vrf_name))
				continue;
			zebra_vrf_import_unlink_src_index(import);
			zebra_vrf_import_del_all(dst_zvrf, import->afi, import->safi, src_vrf_id);
		}
	}
}

void zebra_vrf_import_vrf_disable(struct zebra_vrf *zvrf)
{
	struct zebra_vrf_import *import;

	frr_each_safe (zebra_vrf_imports, &zvrf->vrf_imports, import) {
		if (import->src_index)
			zebra_vrf_import_del_all(zvrf, import->afi, import->safi,
						 import->src_index->src_vrf_id);
		zebra_vrf_import_unlink_src_index(import);
	}
	zebra_vrf_import_src_vrf_down(zvrf);
}

void zebra_vrf_import_vrf_delete(struct zebra_vrf *zvrf)
{
	struct zebra_vrf_import *import;

	/* Remove imports configured in this destination VRF. */
	while ((import = zebra_vrf_imports_first(&zvrf->vrf_imports)))
		zebra_vrf_import_del(zvrf, import->afi, import->safi, import->src_vrf_name);

	zebra_vrf_import_src_vrf_down(zvrf);
	zebra_vrf_imports_fini(&zvrf->vrf_imports);
}
