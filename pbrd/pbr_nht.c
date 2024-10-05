// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR-nht Code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include <log.h>
#include <nexthop.h>
#include "nexthop_group.h"
#include "nexthop_group_private.h"
#include <hash.h>
#include <jhash.h>
#include <vty.h>
#include <zclient.h>
#include <debug.h>

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_memory.h"
#include "pbrd/pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_NHG, "PBR Nexthop Groups");

struct hash *pbr_nhg_hash;
static struct hash *pbr_nhrc_hash;
static struct hash *pbr_nhg_allocated_id_hash;

static uint32_t pbr_nhg_low_table;
static uint32_t pbr_nhg_high_table;
static uint32_t pbr_next_unallocated_table_id;
static uint32_t pbr_nhg_low_rule;
static uint32_t pbr_nhg_high_rule;

static void pbr_nht_install_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
					  struct nexthop_group nhg);
static void
pbr_nht_uninstall_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
				struct nexthop_group nhg,
				enum nexthop_types_t nh_type);

/*
 * Nexthop refcount.
 */
struct nhrc {
	struct nexthop nexthop;
	unsigned int refcount;
};

/* Hash functions for pbr_nhrc_hash ---------------------------------------- */

static void *pbr_nhrc_hash_alloc(void *p)
{
	struct nhrc *nhrc = XCALLOC(MTYPE_PBR_NHG, sizeof(struct nhrc));
	nhrc->nexthop = *(struct nexthop *)p;
	nhrc->nexthop.next = NULL;
	nhrc->nexthop.prev = NULL;
	return nhrc;
}

static bool pbr_nhrc_hash_equal(const void *arg1, const void *arg2)
{
	const struct nexthop *nh1, *nh2;

	nh1 = arg1;
	nh2 = arg2;

	return nexthop_same(nh1, nh2);
}

/* ------------------------------------------------------------------------- */

static void *pbr_nh_alloc(void *p)
{
	struct pbr_nexthop_cache *new;
	struct pbr_nexthop_cache *pnhc = (struct pbr_nexthop_cache *)p;
	struct nhrc *nhrc;

	new = XCALLOC(MTYPE_PBR_NHG, sizeof(*new));
	nhrc = hash_get(pbr_nhrc_hash, &pnhc->nexthop, pbr_nhrc_hash_alloc);
	new->nexthop = nhrc->nexthop;

	/* Decremented again in pbr_nh_delete */
	++nhrc->refcount;

	DEBUGD(&pbr_dbg_nht, "%s: Sending nexthop to Zebra", __func__);

	pbr_send_rnh(&new->nexthop, true);

	new->valid = false;
	return new;
}

static void pbr_nh_delete(struct pbr_nexthop_cache **pnhc)
{
	struct nhrc *nhrc;

	nhrc = hash_lookup(pbr_nhrc_hash, &((*pnhc)->nexthop));

	if (nhrc)
		--nhrc->refcount;
	if (!nhrc || nhrc->refcount == 0) {
		DEBUGD(&pbr_dbg_nht, "%s: Removing nexthop from Zebra",
		       __func__);
		pbr_send_rnh(&((*pnhc)->nexthop), false);
	}
	if (nhrc && nhrc->refcount == 0) {
		hash_release(pbr_nhrc_hash, nhrc);
		XFREE(MTYPE_PBR_NHG, nhrc);
	}

	XFREE(MTYPE_PBR_NHG, *pnhc);
}

static void pbr_nh_delete_iterate(struct hash_bucket *b, void *p)
{
	pbr_nh_delete((struct pbr_nexthop_cache **)&b->data);
}

static uint32_t pbr_nh_hash_key(const void *arg)
{
	uint32_t key;
	const struct pbr_nexthop_cache *pbrnc = arg;

	key = nexthop_hash(&pbrnc->nexthop);

	return key;
}

static bool pbr_nh_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_cache *pbrnc1 =
		(const struct pbr_nexthop_cache *)arg1;
	const struct pbr_nexthop_cache *pbrnc2 =
		(const struct pbr_nexthop_cache *)arg2;

	if (pbrnc1->nexthop.vrf_id != pbrnc2->nexthop.vrf_id)
		return false;

	if (pbrnc1->nexthop.ifindex != pbrnc2->nexthop.ifindex)
		return false;

	if (pbrnc1->nexthop.type != pbrnc2->nexthop.type)
		return false;

	switch (pbrnc1->nexthop.type) {
	case NEXTHOP_TYPE_IFINDEX:
		return pbrnc1->nexthop.ifindex == pbrnc2->nexthop.ifindex;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		return pbrnc1->nexthop.gate.ipv4.s_addr
		       == pbrnc2->nexthop.gate.ipv4.s_addr;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_IPV6:
		return !memcmp(&pbrnc1->nexthop.gate.ipv6,
			       &pbrnc2->nexthop.gate.ipv6, 16);
	case NEXTHOP_TYPE_BLACKHOLE:
		return pbrnc1->nexthop.bh_type == pbrnc2->nexthop.bh_type;
	}

	/*
	 * We should not get here
	 */
	return false;
}

static void pbr_nhgc_delete(struct pbr_nexthop_group_cache *p)
{
	hash_iterate(p->nhh, pbr_nh_delete_iterate, NULL);
	hash_free(p->nhh);
	XFREE(MTYPE_PBR_NHG, p);
}

static void *pbr_nhgc_alloc(void *p)
{
	struct pbr_nexthop_group_cache *new;
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)p;

	new = XCALLOC(MTYPE_PBR_NHG, sizeof(*new));

	strlcpy(new->name, pnhgc->name, sizeof(pnhgc->name));
	pbr_nht_reserve_next_table_id(new);

	DEBUGD(&pbr_dbg_nht, "%s: NHT: %s assigned Table ID: %u", __func__,
	       new->name, new->table_id);

	new->nhh = hash_create_size(8, pbr_nh_hash_key, pbr_nh_hash_equal,
				    "PBR NH Cache Hash");
	return new;
}


void pbr_nhgroup_add_cb(const char *name)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct nexthop_group_cmd *nhgc;

	nhgc = nhgc_find(name);

	if (!nhgc) {
		DEBUGD(&pbr_dbg_nht, "%s: Could not find nhgc with name: %s",
		       __func__, name);
		return;
	}

	pnhgc = pbr_nht_add_group(name);

	if (!pnhgc)
		return;

	DEBUGD(&pbr_dbg_nht, "%s: Added nexthop-group %s", __func__, name);

	pbr_map_check_nh_group_change(name);
}

void pbr_nhgroup_modify_cb(const struct nexthop_group_cmd *nhgc)
{
}

void pbr_nhgroup_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				const struct nexthop *nhop)
{
	char debugstr[256];
	struct pbr_nexthop_group_cache pnhgc_find = {};
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_cache pnhc_find = {};
	struct pbr_nexthop_cache *pnhc;

	/* find pnhgc by name */
	strlcpy(pnhgc_find.name, nhgc->name, sizeof(pnhgc_find.name));
	pnhgc = hash_lookup(pbr_nhg_hash, &pnhgc_find);

	if (!pnhgc) {
		/* Check if configured table range is exhausted */
		if (!pbr_nht_has_unallocated_table()) {
			zlog_warn(
				"%s: Exhausted all table identifiers; cannot create nexthop-group cache for nexthop-group '%s'",
				__func__, nhgc->name);
			return;
		}

		/* No nhgc but range not exhausted? Then alloc it */
		pnhgc = hash_get(pbr_nhg_hash, &pnhgc_find, pbr_nhgc_alloc);
	}

	/* create & insert new pnhc into pnhgc->nhh */
	pnhc_find.nexthop = *nhop;
	pnhc = hash_get(pnhgc->nhh, &pnhc_find, pbr_nh_alloc);

	/* set parent pnhgc */
	pnhc->parent = pnhgc;

	if (DEBUG_MODE_CHECK(&pbr_dbg_nht, DEBUG_MODE_ALL)) {
		nexthop2str(nhop, debugstr, sizeof(debugstr));
		DEBUGD(&pbr_dbg_nht, "%s: Added %s to nexthop-group %s",
		       __func__, debugstr, nhgc->name);
	}

	pbr_nht_install_nexthop_group(pnhgc, nhgc->nhg);
	pbr_map_check_nh_group_change(nhgc->name);

	if (nhop->type == NEXTHOP_TYPE_IFINDEX
	    || (nhop->type == NEXTHOP_TYPE_IPV6_IFINDEX
		&& IN6_IS_ADDR_LINKLOCAL(&nhop->gate.ipv6))) {
		struct interface *ifp;

		ifp = if_lookup_by_index(nhop->ifindex, nhop->vrf_id);
		if (ifp)
			pbr_nht_nexthop_interface_update(ifp);
	}
}

void pbr_nhgroup_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				const struct nexthop *nhop)
{
	char debugstr[256];
	struct pbr_nexthop_group_cache pnhgc_find = {};
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_cache pnhc_find = {};
	struct pbr_nexthop_cache *pnhc;
	enum nexthop_types_t nh_type = nhop->type;

	/* find pnhgc by name */
	strlcpy(pnhgc_find.name, nhgc->name, sizeof(pnhgc_find.name));
	pnhgc = hash_lookup(pbr_nhg_hash, &pnhgc_find);

	/*
	 * Ignore deletions of nhg we did not / could not allocate nhgc for
	 * Occurs when PBR table range is full but new nhg keep coming in
	 */
	if (!pnhgc)
		return;

	/* delete pnhc from pnhgc->nhh */
	pnhc_find.nexthop = *nhop;
	pnhc = hash_release(pnhgc->nhh, &pnhc_find);

	/* delete pnhc */
	pbr_nh_delete(&pnhc);

	if (DEBUG_MODE_CHECK(&pbr_dbg_nht, DEBUG_MODE_ALL)) {
		nexthop2str(nhop, debugstr, sizeof(debugstr));
		DEBUGD(&pbr_dbg_nht, "%s: Removed %s from nexthop-group %s",
		       __func__, debugstr, nhgc->name);
	}

	if (pnhgc->nhh->count)
		pbr_nht_install_nexthop_group(pnhgc, nhgc->nhg);
	else
		pbr_nht_uninstall_nexthop_group(pnhgc, nhgc->nhg, nh_type);

	pbr_map_check_nh_group_change(nhgc->name);
}

void pbr_nhgroup_delete_cb(const char *name)
{
	DEBUGD(&pbr_dbg_nht, "%s: Removed nexthop-group %s", __func__, name);

	/* delete group from all pbrms's */
	pbr_nht_delete_group(name);

	pbr_map_check_nh_group_change(name);
}

static void
pbr_nht_find_nhg_from_table_update(struct pbr_nexthop_group_cache *pnhgc,
				   uint32_t table_id, bool installed)
{
	if (pnhgc->table_id == table_id) {
		DEBUGD(&pbr_dbg_nht, "%s: %s: Table ID (%u) matches %s",
		       __func__, (installed ? "install" : "remove"), table_id,
		       pnhgc->name);

		pnhgc->installed = installed;
		pnhgc->valid = installed;
		pbr_map_schedule_policy_from_nhg(pnhgc->name, pnhgc->installed);
	}
}

static void pbr_nht_find_nhg_from_table_install(struct hash_bucket *b,
						void *data)
{
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)b->data;
	uint32_t table_id = *(uint32_t *)data;

	pbr_nht_find_nhg_from_table_update(pnhgc, table_id, true);
}

void pbr_nht_route_installed_for_table(uint32_t table_id)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_find_nhg_from_table_install,
		     &table_id);
}

static void pbr_nht_find_nhg_from_table_remove(struct hash_bucket *b,
					       void *data)
{
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)b->data;
	uint32_t table_id = *(uint32_t *)data;

	pbr_nht_find_nhg_from_table_update(pnhgc, table_id, false);
}

void pbr_nht_route_removed_for_table(uint32_t table_id)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_find_nhg_from_table_remove,
		     &table_id);
}

/*
 * Loop through all nexthops in a nexthop group to check that they are all the
 * same. If they are not all the same, log this peculiarity.
 *
 * nhg
 *    The nexthop group to check
 *
 * Returns:
 *    - AFI of last nexthop in the group
 *    - AFI_MAX on error
 */
static afi_t pbr_nht_which_afi(struct nexthop_group nhg,
			       enum nexthop_types_t nh_type)
{
	struct nexthop *nexthop;
	afi_t install_afi = AFI_MAX;
	bool v6, v4, bh;

	if (nh_type) {
		switch (nh_type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			return AFI_IP;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			return AFI_IP6;
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_BLACKHOLE:
			return AFI_MAX;
		}
	}

	v6 = v4 = bh = false;

	for (ALL_NEXTHOPS(nhg, nexthop)) {
		nh_type = nexthop->type;

		switch (nh_type) {
		case NEXTHOP_TYPE_IFINDEX:
			break;
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			v6 = true;
			install_afi = AFI_IP;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			v4 = true;
			install_afi = AFI_IP6;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			bh = true;
			break;
		}
	}

	/* Interface and/or blackhole nexthops only. */
	if (!v4 && !v6)
		install_afi = AFI_MAX;

	if (!bh && v6 && v4)
		DEBUGD(&pbr_dbg_nht,
		       "%s: Saw both V6 and V4 nexthops...using %s", __func__,
		       afi2str(install_afi));
	if (bh && (v6 || v4))
		DEBUGD(&pbr_dbg_nht,
		       "%s: Saw blackhole nexthop(s) with %s%s%s nexthop(s), using AFI_MAX.",
		       __func__, v4 ? "v4" : "", (v4 && v6) ? " and " : "",
		       v6 ? "v6" : "");

	return install_afi;
}

static void pbr_nht_install_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
					  struct nexthop_group nhg)
{
	afi_t install_afi;
	enum nexthop_types_t nh_type = 0;

	install_afi = pbr_nht_which_afi(nhg, nh_type);

	route_add(pnhgc, nhg, install_afi);
}

static void
pbr_nht_uninstall_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
				struct nexthop_group nhg,
				enum nexthop_types_t nh_type)
{
	afi_t install_afi;

	install_afi = pbr_nht_which_afi(nhg, nh_type);

	pnhgc->installed = false;
	pnhgc->valid = false;
	route_delete(pnhgc, install_afi);
}

void pbr_nht_change_group(const char *name)
{
	struct nexthop_group_cmd *nhgc;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;
	struct nexthop *nhop;

	nhgc = nhgc_find(name);
	if (!nhgc)
		return;

	memset(&find, 0, sizeof(find));
	snprintf(find.name, sizeof(find.name), "%s", name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		DEBUGD(&pbr_dbg_nht,
		       "%s: Could not find nexthop-group cache w/ name '%s'",
		       __func__, name);
		return;
	}

	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		struct pbr_nexthop_cache lookup;
		struct pbr_nexthop_cache *pnhc;

		lookup.nexthop = *nhop;
		pnhc = hash_lookup(pnhgc->nhh, &lookup);
		if (!pnhc) {
			pnhc = hash_get(pnhgc->nhh, &lookup, pbr_nh_alloc);
			pnhc->parent = pnhgc;
		}
	}
	pbr_nht_install_nexthop_group(pnhgc, nhgc->nhg);
}

char *pbr_nht_nexthop_make_name(char *name, size_t l,
				uint32_t seqno, char *buffer)
{
	snprintf(buffer, l, "%s%u", name, seqno);
	return buffer;
}

/* Set data derived from nhg in pbrms */
void pbr_nht_set_seq_nhg_data(struct pbr_map_sequence *pbrms,
			      const struct nexthop_group_cmd *nhgc)
{
	const struct nexthop_group *nhg;

	if (!nhgc)
		return;

	nhg = &nhgc->nhg;
	if (!nhg->nexthop)
		return;

	switch (nhg->nexthop->type) {
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		pbrms->family = AF_INET6;
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		pbrms->family = AF_INET;
		break;
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}
}

/* Configure a routemap sequence to use a given nexthop group */
void pbr_nht_set_seq_nhg(struct pbr_map_sequence *pbrms, const char *name)
{
	struct nexthop_group_cmd *nhgc;

	if (!name)
		return;

	pbrms->nhgrp_name = XSTRDUP(MTYPE_TMP, name);
	pbrms->forwarding_type = PBR_FT_NEXTHOP_GROUP;

	nhgc = nhgc_find(name);
	if (!nhgc)
		return;

	pbr_nht_set_seq_nhg_data(pbrms, nhgc);
}

void pbr_nht_add_individual_nexthop(struct pbr_map_sequence *pbrms,
				    const struct nexthop *nhop)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_cache *pnhc;
	struct pbr_nexthop_cache lookup;
	struct nexthop *nh;
	char buf[PBR_NHC_NAMELEN];

	pbrms->nhg = nexthop_group_new();
	pbrms->internal_nhg_name = XSTRDUP(
		MTYPE_TMP,
		pbr_nht_nexthop_make_name(pbrms->parent->name, PBR_NHC_NAMELEN,
					  pbrms->seqno, buf));
	pbrms->forwarding_type = PBR_FT_NEXTHOP_SINGLE;

	nh = nexthop_new();
	memcpy(nh, nhop, sizeof(*nh));

	nexthop_group_add_sorted(pbrms->nhg, nh);

	memset(&find, 0, sizeof(find));
	pbr_nht_nexthop_make_name(pbrms->parent->name, PBR_NHC_NAMELEN,
				  pbrms->seqno, find.name);

	if (!pbr_nht_has_unallocated_table()) {
		zlog_warn(
			"%s: Exhausted all table identifiers; cannot create nexthop-group cache for nexthop-group '%s'",
			__func__, find.name);
		return;
	}

	if (!pbrms->internal_nhg_name)
		pbrms->internal_nhg_name = XSTRDUP(MTYPE_TMP, find.name);

	pnhgc = hash_get(pbr_nhg_hash, &find, pbr_nhgc_alloc);

	lookup.nexthop = *pbrms->nhg->nexthop;
	pnhc = hash_get(pnhgc->nhh, &lookup, pbr_nh_alloc);
	pnhc->parent = pnhgc;
	if (nhop->vrf_id != VRF_DEFAULT) {
		struct vrf *vrf = vrf_lookup_by_id(nhop->vrf_id);

		if (vrf)
			strlcpy(pnhc->vrf_name, vrf->name,
				sizeof(pnhc->vrf_name));
	}

	if (nhop->ifindex != 0) {
		struct interface *ifp =
			if_lookup_by_index(nhop->ifindex, nhop->vrf_id);

		if (ifp)
			strlcpy(pnhc->intf_name, ifp->name,
				sizeof(pnhc->intf_name));
	}
	pbr_nht_install_nexthop_group(pnhgc, *pbrms->nhg);
}

static void pbr_nht_release_individual_nexthop(struct pbr_map_sequence *pbrms)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_cache *pnhc;
	struct pbr_nexthop_cache lup;
	struct nexthop *nh;
	enum nexthop_types_t nh_type = 0;

	memset(&find, 0, sizeof(find));
	snprintf(find.name, sizeof(find.name), "%s", pbrms->internal_nhg_name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	nh = pbrms->nhg->nexthop;
	nh_type = nh->type;
	lup.nexthop = *nh;
	pnhc = hash_lookup(pnhgc->nhh, &lup);
	pnhc->parent = NULL;
	hash_release(pnhgc->nhh, pnhc);
	pbr_nh_delete(&pnhc);
	pbr_nht_uninstall_nexthop_group(pnhgc, *pbrms->nhg, nh_type);

	hash_release(pbr_nhg_hash, pnhgc);
	pbr_nhgc_delete(pnhgc);

	nexthop_group_delete(&pbrms->nhg);
	XFREE(MTYPE_TMP, pbrms->internal_nhg_name);
}

void pbr_nht_delete_individual_nexthop(struct pbr_map_sequence *pbrms)
{
	struct pbr_map *pbrm = pbrms->parent;

	/* The idea here is to send a delete command to zebra only once,
	 * and set 'valid' and 'installed' to false only when the last
	 * rule is being deleted. In other words, the pbr common should be
	 * updated only when the last rule is being updated or deleted.
	 */
	if (pbrm->seqnumbers->count == 1)
		pbr_map_delete_nexthops(pbrms);

	pbr_nht_release_individual_nexthop(pbrms);
}

struct pbr_nexthop_group_cache *pbr_nht_add_group(const char *name)
{
	struct nexthop *nhop;
	struct nexthop_group_cmd *nhgc;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache lookup;

	if (!pbr_nht_has_unallocated_table()) {
		zlog_warn(
			"%s: Exhausted all table identifiers; cannot create nexthop-group cache for nexthop-group '%s'",
			__func__, name);
		return NULL;
	}

	nhgc = nhgc_find(name);

	if (!nhgc) {
		DEBUGD(&pbr_dbg_nht, "%s: Could not find nhgc with name: %s",
		       __func__, name);
		return NULL;
	}

	snprintf(lookup.name, sizeof(lookup.name), "%s", name);
	pnhgc = hash_get(pbr_nhg_hash, &lookup, pbr_nhgc_alloc);
	DEBUGD(&pbr_dbg_nht, "%s: Retrieved NHGC @ %p", __func__, pnhgc);

	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		struct pbr_nexthop_cache lookupc;
		struct pbr_nexthop_cache *pnhc;

		lookupc.nexthop = *nhop;
		pnhc = hash_lookup(pnhgc->nhh, &lookupc);
		if (!pnhc) {
			pnhc = hash_get(pnhgc->nhh, &lookupc, pbr_nh_alloc);
			pnhc->parent = pnhgc;
		}
	}

	return pnhgc;
}

void pbr_nht_delete_group(const char *name)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *snode;
	struct pbr_map *pbrm;
	struct pbr_nexthop_group_cache pnhgc_find;
	struct pbr_nexthop_group_cache *pnhgc;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, snode, pbrms)) {
			if (pbrms->nhgrp_name
			    && strmatch(pbrms->nhgrp_name, name)) {
				pbrms->reason |= PBR_MAP_INVALID_NO_NEXTHOPS;
				pbrms->nhg = NULL;
				pbrms->internal_nhg_name = NULL;
				pbrm->valid = false;
			}
		}
	}

	strlcpy(pnhgc_find.name, name, sizeof(pnhgc_find.name));
	pnhgc = hash_release(pbr_nhg_hash, &pnhgc_find);

	/*
	 * Ignore deletions of nh we did not / could not allocate nhgc for
	 * Occurs when PBR table range is full but new nhg keep coming in
	 */
	if (!pnhgc)
		return;

	/* Remove and recalculate the next table id */
	hash_release(pbr_nhg_allocated_id_hash, pnhgc);
	pbr_nht_update_next_unallocated_table_id();

	pbr_nhgc_delete(pnhgc);
}

bool pbr_nht_nexthop_valid(struct nexthop_group *nhg)
{
	DEBUGD(&pbr_dbg_nht, "%s: %p", __func__, nhg);
	return true;
}

bool pbr_nht_nexthop_group_valid(const char *name)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache lookup;

	DEBUGD(&pbr_dbg_nht, "%s: %s", __func__, name);

	snprintf(lookup.name, sizeof(lookup.name), "%s", name);
	pnhgc = hash_get(pbr_nhg_hash, &lookup, NULL);
	if (!pnhgc)
		return false;
	DEBUGD(&pbr_dbg_nht, "%s:    %d %d", __func__, pnhgc->valid,
	       pnhgc->installed);
	if (pnhgc->valid && pnhgc->installed)
		return true;

	return false;
}

struct pbr_nht_individual {
	struct zapi_route *nhr;
	struct interface *ifp;
	struct pbr_vrf *pbr_vrf;
	struct pbr_nexthop_cache *pnhc;
	vrf_id_t old_vrf_id;

	bool valid;

	bool nhr_matched;
};

static bool
pbr_nht_individual_nexthop_gw_update(struct pbr_nexthop_cache *pnhc,
				     struct pbr_nht_individual *pnhi)
{
	bool is_valid = pnhc->valid;

	/*
	 * If we have an interface down event, let's note that
	 * it is happening and find all the nexthops that depend
	 * on that interface.  As that if we have an interface
	 * flapping fast enough it means that zebra might turn
	 * those nexthop tracking events into a no-update
	 * So let's search and do the right thing on the
	 * interface event.
	 */
	if (!pnhi->nhr) {
		switch (pnhc->nexthop.type) {
		case NEXTHOP_TYPE_BLACKHOLE:
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV6:
			goto done;
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (pnhc->nexthop.ifindex == pnhi->ifp->ifindex)
				is_valid = if_is_up(pnhi->ifp);
			goto done;
		}

		goto done;
	}

	switch (pnhi->nhr->prefix.family) {
	case AF_INET:
		if (pnhc->nexthop.gate.ipv4.s_addr
		    != pnhi->nhr->prefix.u.prefix4.s_addr)
			goto done; /* Unrelated change */
		break;
	case AF_INET6:
		if (memcmp(&pnhc->nexthop.gate.ipv6,
			   &pnhi->nhr->prefix.u.prefix6, 16)
		    != 0)
			goto done; /* Unrelated change */
		break;
	}

	pnhi->nhr_matched = true;
	if (!pnhi->nhr->nexthop_num) {
		is_valid = false;
		goto done;
	}

	if (pnhc->nexthop.type == NEXTHOP_TYPE_IPV4_IFINDEX
	    || pnhc->nexthop.type == NEXTHOP_TYPE_IPV6_IFINDEX) {

		/* GATEWAY_IFINDEX type shouldn't resolve to group */
		if (pnhi->nhr->nexthop_num > 1) {
			is_valid = false;
			goto done;
		}

		/* If whatever we resolved to wasn't on the interface we
		 * specified. (i.e. not a connected route), its invalid.
		 */
		if (pnhi->nhr->nexthops[0].ifindex != pnhc->nexthop.ifindex) {
			is_valid = false;
			goto done;
		}
	}

	is_valid = true;

done:
	pnhc->valid = is_valid;

	return pnhc->valid;
}

static bool
pbr_nht_individual_nexthop_interface_update(struct pbr_nexthop_cache *pnhc,
					    struct pbr_nht_individual *pnhi)
{
	bool is_valid = pnhc->valid;

	if (!pnhi->ifp) /* It doesn't care about non-interface updates */
		goto done;

	if (pnhc->nexthop.ifindex
	    != pnhi->ifp->ifindex) /* Un-related interface */
		goto done;

	pnhi->nhr_matched = true;
	is_valid = !!if_is_up(pnhi->ifp);

done:
	pnhc->valid = is_valid;

	return pnhc->valid;
}

/* Given this update either from interface or nexthop tracking, re-validate this
 * nexthop.
 *
 * If the update is un-related, the subroutines shoud just return their cached
 * valid state.
 */
static void pbr_nht_individual_nexthop_update(struct pbr_nexthop_cache *pnhc,
					      struct pbr_nht_individual *pnhi)
{
	assert(pnhi->nhr || pnhi->ifp); /* Either nexthop or interface update */

	switch (pnhc->nexthop.type) {
	case NEXTHOP_TYPE_IFINDEX:
		pbr_nht_individual_nexthop_interface_update(pnhc, pnhi);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (IN6_IS_ADDR_LINKLOCAL(&pnhc->nexthop.gate.ipv6)) {
			pbr_nht_individual_nexthop_interface_update(pnhc, pnhi);
			break;
		}
		fallthrough;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
		pbr_nht_individual_nexthop_gw_update(pnhc, pnhi);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		pnhc->valid = true;
		break;
	}
}

static void pbr_nht_individual_nexthop_update_lookup(struct hash_bucket *b,
						     void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct pbr_nht_individual *pnhi = data;
	bool old_valid;

	old_valid = pnhc->valid;

	pbr_nht_individual_nexthop_update(pnhc, pnhi);

	DEBUGD(&pbr_dbg_nht, "    Found %pFX: old: %d new: %d",
	       &pnhi->nhr->prefix, old_valid, pnhc->valid);

	if (pnhc->valid)
		pnhi->valid = true;
}

static void pbr_nexthop_group_cache_iterate_to_group(struct hash_bucket *b,
						     void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct nexthop_group *nhg = data;
	struct nexthop *nh = NULL;

	copy_nexthops(&nh, &pnhc->nexthop, NULL);

	_nexthop_add(&nhg->nexthop, nh);
}

static void
pbr_nexthop_group_cache_to_nexthop_group(struct nexthop_group *nhg,
					 struct pbr_nexthop_group_cache *pnhgc)
{
	hash_iterate(pnhgc->nhh, pbr_nexthop_group_cache_iterate_to_group, nhg);
}

static void pbr_nht_nexthop_update_lookup(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_nht_individual pnhi = {};
	struct nexthop_group nhg = {};
	bool old_valid;

	old_valid = pnhgc->valid;

	pnhi.nhr = (struct zapi_route *)data;
	pnhi.valid = false;
	pnhi.nhr_matched = false;
	hash_iterate(pnhgc->nhh, pbr_nht_individual_nexthop_update_lookup,
		     &pnhi);

	if (!pnhi.nhr_matched)
		return;

	/*
	 * If any of the specified nexthops are valid we are valid
	 */
	pnhgc->valid = !!pnhi.valid;

	pbr_nexthop_group_cache_to_nexthop_group(&nhg, pnhgc);

	if (pnhgc->valid)
		pbr_nht_install_nexthop_group(pnhgc, nhg);
	else
		pbr_nht_uninstall_nexthop_group(pnhgc, nhg, 0);

	/* Don't need copied nexthops anymore */
	nexthops_free(nhg.nexthop);

	if (old_valid != pnhgc->valid)
		pbr_map_check_nh_group_change(pnhgc->name);
}

void pbr_nht_nexthop_update(struct zapi_route *nhr)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_nexthop_update_lookup, nhr);
}

struct nhrc_vrf_info {
	struct pbr_vrf *pbr_vrf;
	uint32_t old_vrf_id;
	struct nhrc *nhrc;
};

static int pbr_nht_nhrc_vrf_change(struct hash_bucket *b, void *data)
{
	struct nhrc *nhrc = b->data;
	struct nhrc_vrf_info *nhrcvi = data;

	if (nhrc->nexthop.vrf_id == nhrcvi->old_vrf_id) {
		nhrcvi->nhrc = nhrc;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static int pbr_nht_individual_nexthop_vrf_handle(struct hash_bucket *b,
						 void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct pbr_nht_individual *pnhi = data;

	if (pnhc->looked_at == true)
		return HASHWALK_CONTINUE;

	if (pnhc->nexthop.vrf_id == VRF_DEFAULT)
		return HASHWALK_CONTINUE;

	if (strncmp(pnhc->vrf_name, pbr_vrf_name(pnhi->pbr_vrf),
		    sizeof(pnhc->vrf_name))
	    == 0) {
		pnhi->pnhc = pnhc;

		if (pnhc->nexthop.vrf_id != pbr_vrf_id(pnhi->pbr_vrf)) {
			struct nhrc_vrf_info nhrcvi;

			memset(&nhrcvi, 0, sizeof(nhrcvi));
			nhrcvi.pbr_vrf = pnhi->pbr_vrf;
			nhrcvi.old_vrf_id = pnhc->nexthop.vrf_id;

			pnhi->nhr_matched = true;
			pnhi->old_vrf_id = pnhc->nexthop.vrf_id;

			do {
				nhrcvi.nhrc = NULL;
				hash_walk(pbr_nhrc_hash,
					  pbr_nht_nhrc_vrf_change, &nhrcvi);
				if (nhrcvi.nhrc) {
					hash_release(pbr_nhrc_hash,
						     nhrcvi.nhrc);
					nhrcvi.nhrc->nexthop.vrf_id =
						pbr_vrf_id(pnhi->pbr_vrf);
					(void)hash_get(pbr_nhrc_hash,
						       nhrcvi.nhrc,
						       hash_alloc_intern);
					pbr_send_rnh(&nhrcvi.nhrc->nexthop, true);
				}
			} while (nhrcvi.nhrc);
		}

		pnhc->looked_at = true;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static void pbr_nht_clear_looked_at(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;

	pnhc->looked_at = false;
}

static void pbr_nht_nexthop_vrf_handle(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_vrf *pbr_vrf = data;
	struct pbr_nht_individual pnhi = {};

	hash_iterate(pnhgc->nhh, pbr_nht_clear_looked_at, NULL);
	memset(&pnhi, 0, sizeof(pnhi));
	pnhi.pbr_vrf = pbr_vrf;
	do {
		struct pbr_nexthop_cache *pnhc;

		pnhi.pnhc = NULL;
		hash_walk(pnhgc->nhh, pbr_nht_individual_nexthop_vrf_handle,
			  &pnhi);

		if (!pnhi.pnhc)
			continue;

		pnhc = pnhi.pnhc;
		pnhc->nexthop.vrf_id = pnhi.old_vrf_id;
		pnhi.pnhc = hash_release(pnhgc->nhh, pnhi.pnhc);
		if (pnhi.pnhc) {
			pnhi.pnhc->nexthop.vrf_id = pbr_vrf_id(pbr_vrf);

			(void)hash_get(pnhgc->nhh, pnhi.pnhc,
				       hash_alloc_intern);
		} else
			pnhc->nexthop.vrf_id = pbr_vrf_id(pbr_vrf);

		pbr_map_check_vrf_nh_group_change(pnhgc->name, pbr_vrf,
						  pnhi.old_vrf_id);
	} while (pnhi.pnhc);
}

void pbr_nht_vrf_update(struct pbr_vrf *pbr_vrf)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_nexthop_vrf_handle, pbr_vrf);
}

static void pbr_nht_individual_nexthop_interface_handle(struct hash_bucket *b,
							void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct pbr_nht_individual *pnhi = data;

	if (pnhc->nexthop.ifindex == 0)
		return;

	if ((strncmp(pnhc->intf_name, pnhi->ifp->name, sizeof(pnhc->intf_name))
	     == 0)
	    && pnhc->nexthop.ifindex != pnhi->ifp->ifindex)
		pnhi->pnhc = pnhc;
}

static void pbr_nht_nexthop_interface_handle(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct interface *ifp = data;
	struct pbr_nht_individual pnhi = {};
	struct nhrc *nhrc;
	uint32_t old_ifindex;

	do {
		memset(&pnhi, 0, sizeof(pnhi));
		pnhi.ifp = ifp;
		hash_iterate(pnhgc->nhh,
			     pbr_nht_individual_nexthop_interface_handle,
			     &pnhi);

		if (!pnhi.pnhc)
			continue;

		pnhi.pnhc = hash_release(pnhgc->nhh, pnhi.pnhc);
		old_ifindex = pnhi.pnhc->nexthop.ifindex;

		nhrc = hash_lookup(pbr_nhrc_hash, &pnhi.pnhc->nexthop);
		if (nhrc) {
			hash_release(pbr_nhrc_hash, nhrc);
			nhrc->nexthop.ifindex = ifp->ifindex;
			(void)hash_get(pbr_nhrc_hash, nhrc, hash_alloc_intern);
		}
		pnhi.pnhc->nexthop.ifindex = ifp->ifindex;

		(void)hash_get(pnhgc->nhh, pnhi.pnhc, hash_alloc_intern);

		pbr_map_check_interface_nh_group_change(pnhgc->name, ifp,
							old_ifindex);
	} while (pnhi.pnhc);
}

void pbr_nht_interface_update(struct interface *ifp)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_nexthop_interface_handle, ifp);
}

static void
pbr_nht_individual_nexthop_interface_update_lookup(struct hash_bucket *b,
						   void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct pbr_nht_individual *pnhi = data;
	bool old_valid;

	old_valid = pnhc->valid;

	pbr_nht_individual_nexthop_update(pnhc, pnhi);

	DEBUGD(&pbr_dbg_nht, "    Found %s: old: %d new: %d", pnhi->ifp->name,
	       old_valid, pnhc->valid);

	if (pnhc->valid)
		pnhi->valid = true;
}

static void pbr_nht_nexthop_interface_update_lookup(struct hash_bucket *b,
						    void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_nht_individual pnhi = {};
	struct nexthop_group nhg = {};
	bool old_valid;

	old_valid = pnhgc->valid;

	pnhi.ifp = data;
	pnhi.valid = false;
	hash_iterate(pnhgc->nhh,
		     pbr_nht_individual_nexthop_interface_update_lookup, &pnhi);

	/*
	 * If any of the specified nexthops are valid we are valid
	 */
	pnhgc->valid = pnhi.valid;

	pbr_nexthop_group_cache_to_nexthop_group(&nhg, pnhgc);

	if (pnhgc->valid)
		pbr_nht_install_nexthop_group(pnhgc, nhg);
	else
		pbr_nht_uninstall_nexthop_group(pnhgc, nhg, 0);

	nexthops_free(nhg.nexthop);

	if (old_valid != pnhgc->valid)
		pbr_map_check_nh_group_change(pnhgc->name);
}

void pbr_nht_nexthop_interface_update(struct interface *ifp)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_nexthop_interface_update_lookup,
		     ifp);
}

static bool pbr_nhg_allocated_id_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_group_cache *left, *right;

	left = (const struct pbr_nexthop_group_cache *)arg1;
	right = (const struct pbr_nexthop_group_cache *)arg2;

	return left->table_id == right->table_id;
}

static uint32_t pbr_nhg_allocated_id_hash_key(const void *arg)
{
	const struct pbr_nexthop_group_cache *nhgc = arg;

	/* table_id makes elements in this hash unique */
	return nhgc->table_id;
}

static uint32_t pbr_nhg_hash_key(const void *arg)
{
	const struct pbr_nexthop_group_cache *nhgc = arg;

	return jhash(&nhgc->name, strlen(nhgc->name), 0x52c34a96);
}

static bool pbr_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_group_cache *nhgc1 =
		(const struct pbr_nexthop_group_cache *)arg1;
	const struct pbr_nexthop_group_cache *nhgc2 =
		(const struct pbr_nexthop_group_cache *)arg2;

	return !strcmp(nhgc1->name, nhgc2->name);
}

uint32_t pbr_nht_find_next_unallocated_table_id(void)
{
	struct pbr_nexthop_group_cache iter;

	/*
	 * Find the smallest unallocated table id
	 * This can be non-trivial considering nhg removals / shifting upper &
	 * lower bounds, so start at the lowest in the range and continue until
	 * an unallocated space is found
	 */
	for (iter.table_id = pbr_nhg_low_table;
	     iter.table_id < pbr_nhg_high_table; ++iter.table_id)
		if (!hash_lookup(pbr_nhg_allocated_id_hash, &iter))
			return iter.table_id;

	/* Configured range is full, cannot install anywhere */
	return 0;
}

bool pbr_nht_has_unallocated_table(void)
{
	return !!pbr_next_unallocated_table_id;
}

void pbr_nht_update_next_unallocated_table_id(void)
{
	pbr_next_unallocated_table_id =
		pbr_nht_find_next_unallocated_table_id();
}

uint32_t pbr_nht_reserve_next_table_id(struct pbr_nexthop_group_cache *nhgc)
{
	/* Nothing to reserve if all tables in range already used */
	if (!pbr_next_unallocated_table_id)
		return 0;

	/* Reserve this table id */
	nhgc->table_id = pbr_next_unallocated_table_id;

	/* Mark table id as allocated in id-indexed hash */
	(void)hash_get(pbr_nhg_allocated_id_hash, nhgc, hash_alloc_intern);

	/* Pre-compute the next unallocated table id */
	pbr_nht_update_next_unallocated_table_id();

	/* Present caller with reserved table id */
	return nhgc->table_id;
}

void pbr_nht_set_tableid_range(uint32_t low, uint32_t high)
{
	pbr_nhg_low_table = low;
	pbr_nhg_high_table = high;

	/* Re-compute next unallocated id within new range */
	pbr_nht_update_next_unallocated_table_id();
}

void pbr_nht_write_table_range(struct vty *vty)
{
	if (pbr_nhg_low_table != PBR_NHT_DEFAULT_LOW_TABLEID
	    || pbr_nhg_high_table != PBR_NHT_DEFAULT_HIGH_TABLEID) {
		vty_out(vty, "pbr table range %u %u\n", pbr_nhg_low_table,
			pbr_nhg_high_table);
	}
}

uint32_t pbr_nht_get_next_rule(uint32_t seqno)
{
	return seqno + pbr_nhg_low_rule - 1;
}
void pbr_nht_set_rule_range(uint32_t low, uint32_t high)
{
	pbr_nhg_low_rule = low;
	pbr_nhg_high_rule = high;
}

void pbr_nht_write_rule_range(struct vty *vty)
{
	if (pbr_nhg_low_rule != PBR_NHT_DEFAULT_LOW_RULE
	    || pbr_nhg_high_rule != PBR_NHT_DEFAULT_HIGH_RULE) {
		vty_out(vty, "pbr rule range %u %u\n", pbr_nhg_low_rule,
			pbr_nhg_high_rule);
	}
}

uint32_t pbr_nht_get_table(const char *name)
{
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_group_cache *pnhgc;

	memset(&find, 0, sizeof(find));
	snprintf(find.name, sizeof(find.name), "%s", name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		DEBUGD(&pbr_dbg_nht,
		       "%s: Could not find nexthop-group cache w/ name '%s'",
		       __func__, name);
		return 5000;
	}

	return pnhgc->table_id;
}

bool pbr_nht_get_installed(const char *name)
{
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_group_cache *pnhgc;

	memset(&find, 0, sizeof(find));
	snprintf(find.name, sizeof(find.name), "%s", name);

	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc)
		return false;

	return pnhgc->installed;
}

static void pbr_nht_show_nhg_nexthops(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct vty *vty = data;

	vty_out(vty, "\tValid: %d ", pnhc->valid);
	nexthop_group_write_nexthop(vty, &pnhc->nexthop);
}

static void pbr_nht_json_nhg_nexthops(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	json_object *all_hops = data;
	json_object *this_hop;

	this_hop = json_object_new_object();
	nexthop_group_json_nexthop(this_hop, &pnhc->nexthop);
	json_object_boolean_add(this_hop, "valid", pnhc->valid);

	json_object_array_add(all_hops, this_hop);
}

struct pbr_nht_show {
	struct vty *vty;
	json_object *json;
	const char *name;
};

static void pbr_nht_show_nhg(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_nht_show *pns = data;
	struct vty *vty;

	if (pns->name && strcmp(pns->name, pnhgc->name) != 0)
		return;

	vty = pns->vty;
	vty_out(vty, "Nexthop-Group: %s Table: %u Valid: %d Installed: %d\n",
		pnhgc->name, pnhgc->table_id, pnhgc->valid, pnhgc->installed);

	hash_iterate(pnhgc->nhh, pbr_nht_show_nhg_nexthops, vty);
}

static void pbr_nht_json_nhg(struct hash_bucket *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_nht_show *pns = data;
	json_object *j, *this_group, *group_hops;

	if (pns->name && strcmp(pns->name, pnhgc->name) != 0)
		return;

	j = pns->json;
	this_group = json_object_new_object();

	if (!j || !this_group)
		return;

	json_object_int_add(this_group, "id", pnhgc->table_id);
	json_object_string_add(this_group, "name", pnhgc->name);
	json_object_boolean_add(this_group, "valid", pnhgc->valid);
	json_object_boolean_add(this_group, "installed", pnhgc->installed);

	group_hops = json_object_new_array();

	if (group_hops) {
		hash_iterate(pnhgc->nhh, pbr_nht_json_nhg_nexthops, group_hops);
		json_object_object_add(this_group, "nexthops", group_hops);
	}

	json_object_array_add(j, this_group);
}

void pbr_nht_show_nexthop_group(struct vty *vty, const char *name)
{
	struct pbr_nht_show pns;

	pns.vty = vty;
	pns.name = name;

	hash_iterate(pbr_nhg_hash, pbr_nht_show_nhg, &pns);
}

void pbr_nht_json_nexthop_group(json_object *j, const char *name)
{
	struct pbr_nht_show pns;

	pns.name = name;
	pns.json = j;

	hash_iterate(pbr_nhg_hash, pbr_nht_json_nhg, &pns);
}

void pbr_nht_init(void)
{
	pbr_nhg_hash = hash_create_size(
		16, pbr_nhg_hash_key, pbr_nhg_hash_equal, "PBR NHG Cache Hash");
	pbr_nhrc_hash =
		hash_create_size(16, (unsigned int (*)(const void *))nexthop_hash,
				 pbr_nhrc_hash_equal, "PBR NH Hash");
	pbr_nhg_allocated_id_hash = hash_create_size(
		16, pbr_nhg_allocated_id_hash_key,
		pbr_nhg_allocated_id_hash_equal, "PBR Allocated Table Hash");

	pbr_nhg_low_table = PBR_NHT_DEFAULT_LOW_TABLEID;
	pbr_nhg_high_table = PBR_NHT_DEFAULT_HIGH_TABLEID;
	pbr_nhg_low_rule = PBR_NHT_DEFAULT_LOW_RULE;
	pbr_nhg_high_rule = PBR_NHT_DEFAULT_HIGH_RULE;

	/* First unallocated table is lowest in range on init */
	pbr_next_unallocated_table_id = PBR_NHT_DEFAULT_LOW_TABLEID;
}
