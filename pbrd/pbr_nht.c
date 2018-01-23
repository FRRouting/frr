/*
 * PBR-nht Code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <log.h>
#include <nexthop.h>
#include <nexthop_group.h>
#include <hash.h>
#include <jhash.h>
#include <vty.h>
#include <zclient.h>

#include "pbrd/pbr_nht.h"
#include "pbrd/pbr_map.h"
#include "pbrd/pbr_event.h"
#include "pbrd/pbr_zebra.h"
#include "pbrd/pbr_memory.h"
#include "pbrd/pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_NHG, "PBR Nexthop Groups")

static struct hash *pbr_nhg_hash;

static uint32_t pbr_nhg_low_table;
static uint32_t pbr_nhg_high_table;
static uint32_t pbr_nhg_low_rule;
static uint32_t pbr_nhg_high_rule;
static bool nhg_tableid[65535];

static void *pbr_nh_alloc(void *p)
{
	struct pbr_nexthop_cache *new;
	struct pbr_nexthop_cache *pnhc = (struct pbr_nexthop_cache *)p;

	new = XCALLOC(MTYPE_PBR_NHG, sizeof(*new));
	memcpy(&new->nexthop, &pnhc->nexthop, sizeof(struct nexthop));

	DEBUGD(&pbr_dbg_nht, "%s: Sending nexthop to Zebra",
	       __PRETTY_FUNCTION__);

	pbr_send_rnh(&new->nexthop, true);

	new->valid = false;
	return new;
}

static void pbr_nh_delete(struct pbr_nexthop_cache **pnhc)
{
	pbr_send_rnh(&(*pnhc)->nexthop, false);

	XFREE(MTYPE_PBR_NHG, *pnhc);
}

static uint32_t pbr_nh_hash_key(void *arg)
{
	uint32_t key;
	struct pbr_nexthop_cache *pbrnc = (struct pbr_nexthop_cache *)arg;

	key = jhash_1word(pbrnc->nexthop.vrf_id, 0x45afe398);
	key = jhash_1word(pbrnc->nexthop.ifindex, key);
	key = jhash_1word(pbrnc->nexthop.type, key);
	key = jhash(&pbrnc->nexthop.gate, sizeof(union g_addr), key);

	return key;
}

static int pbr_nh_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_cache *pbrnc1 =
		(const struct pbr_nexthop_cache *)arg1;
	const struct pbr_nexthop_cache *pbrnc2 =
		(const struct pbr_nexthop_cache *)arg2;

	if (pbrnc1->nexthop.vrf_id != pbrnc2->nexthop.vrf_id)
		return 0;

	if (pbrnc1->nexthop.ifindex != pbrnc2->nexthop.ifindex)
		return 0;

	if (pbrnc1->nexthop.type != pbrnc2->nexthop.type)
		return 0;

	switch (pbrnc1->nexthop.type) {
	case NEXTHOP_TYPE_IFINDEX:
		return 1;
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
	return 0;
}

void pbr_nhgroup_add_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new(PBR_NHG_NEW, name);

	pbr_event_enqueue(pbre);
	DEBUGD(&pbr_dbg_nht, "%s: Received ADD cb for %s", __PRETTY_FUNCTION__,
	       name);
}

void pbr_nhgroup_add_nexthop_cb(const struct nexthop_group_cmd *nhg,
				const struct nexthop *nhop)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new(PBR_NHG_ADD_NEXTHOP, nhg->name);

	pbr_event_enqueue(pbre);
	DEBUGD(&pbr_dbg_nht, "%s: Received NEXTHOP_ADD cb for %s",
	       __PRETTY_FUNCTION__, nhg->name);
}

void pbr_nhgroup_del_nexthop_cb(const struct nexthop_group_cmd *nhg,
				const struct nexthop *nhop)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new(PBR_NHG_DEL_NEXTHOP, nhg->name);

	pbr_event_enqueue(pbre);
	DEBUGD(&pbr_dbg_nht, "%s: Received NEXTHOP_DEL cb for %s",
	       __PRETTY_FUNCTION__, nhg->name);
}

void pbr_nhgroup_delete_cb(const char *name)
{
	struct pbr_event *pbre;

	pbre = pbr_event_new(PBR_NHG_DELETE, name);

	pbr_event_enqueue(pbre);
	DEBUGD(&pbr_dbg_nht, "%s: Received DELETE cb for %s",
	       __PRETTY_FUNCTION__, name);
}

#if 0
static struct pbr_nexthop_cache *pbr_nht_lookup_nexthop(struct nexthop *nexthop)
{
	return NULL;
}
#endif

static void pbr_nht_find_nhg_from_table_install(struct hash_backet *b,
						void *data)
{
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)b->data;
	uint32_t *table_id = (uint32_t *)data;

	if (pnhgc->table_id == *table_id) {
		DEBUGD(&pbr_dbg_nht, "%s: Table ID (%u) matches %s",
		       __PRETTY_FUNCTION__, *table_id, pnhgc->name);
		pnhgc->installed = true;
		pbr_map_schedule_policy_from_nhg(pnhgc->name);
	}
}

void pbr_nht_route_installed_for_table(uint32_t table_id)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_find_nhg_from_table_install,
		     &table_id);
}

static void pbr_nht_find_nhg_from_table_remove(struct hash_backet *b,
					       void *data)
{
	;
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
static afi_t pbr_nht_which_afi(struct nexthop_group nhg)
{
	struct nexthop *nexthop;
	afi_t install_afi = AFI_MAX;
	bool v6, v4, bh;
	v6 = v4 = bh = false;

	for (ALL_NEXTHOPS(nhg, nexthop)) {
		switch (nexthop->type) {
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
			install_afi = AFI_MAX;
			break;
		}
	}

	if (!bh && v6 && v4)
		DEBUGD(&pbr_dbg_nht,
		       "%s: Saw both V6 and V4 nexthops...using %s",
		       __PRETTY_FUNCTION__, afi2str(install_afi));
	if (bh && (v6 || v4))
		DEBUGD(&pbr_dbg_nht,
		       "%s: Saw blackhole nexthop(s) with %s%s%s nexthop(s), using AFI_MAX.",
		       __PRETTY_FUNCTION__, v4 ? "v4" : "",
		       (v4 && v6) ? " and " : "", v6 ? "v6" : "");

	return install_afi;
}

static void pbr_nht_install_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
					  struct nexthop_group nhg)
{
	afi_t install_afi;

	install_afi = pbr_nht_which_afi(nhg);

	pnhgc->installed = false;
	route_add(pnhgc, nhg, install_afi);
}

static void
pbr_nht_uninstall_nexthop_group(struct pbr_nexthop_group_cache *pnhgc,
				struct nexthop_group nhg)
{
	afi_t install_afi;

	install_afi = pbr_nht_which_afi(nhg);

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
	strcpy(find.name, name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		DEBUGD(&pbr_dbg_nht,
		       "%s: Could not find nexthop-group cache w/ name '%s'",
		       __PRETTY_FUNCTION__, name);
		return;
	}

	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		struct pbr_nexthop_cache lookup;
		struct pbr_nexthop_cache *pnhc;

		memcpy(&lookup.nexthop, nhop, sizeof(*nhop));
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

static void *pbr_nhgc_alloc(void *p)
{
	struct pbr_nexthop_group_cache *new;
	struct pbr_nexthop_group_cache *pnhgc =
		(struct pbr_nexthop_group_cache *)p;

	new = XCALLOC(MTYPE_PBR_NHG, sizeof(*new));

	strcpy(new->name, pnhgc->name);
	new->table_id = pbr_nht_get_next_tableid();

	DEBUGD(&pbr_dbg_nht, "%s: NHT: %s assigned Table ID: %u",
	       __PRETTY_FUNCTION__, new->name, new->table_id);

	new->nhh = hash_create_size(8, pbr_nh_hash_key, pbr_nh_hash_equal,
				    "PBR NH Cache Hash");
	return new;
}

void pbr_nht_add_individual_nexthop(const char *name, uint32_t seqno)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_cache *pnhc;
	struct pbr_map_sequence *pbrms;
	struct pbr_nexthop_cache lookup;

	pbrms = pbrms_get(name, seqno);

	memset(&find, 0, sizeof(find));
	pbr_nht_nexthop_make_name(pbrms->parent->name, PBR_MAP_NAMELEN,
				  pbrms->seqno, find.name);
	if (!pbrms->internal_nhg_name)
		pbrms->internal_nhg_name = XSTRDUP(MTYPE_TMP, find.name);

	pnhgc = hash_get(pbr_nhg_hash, &find, pbr_nhgc_alloc);

	memcpy(&lookup.nexthop, pbrms->nhg->nexthop, sizeof(struct nexthop));
	pnhc = hash_get(pnhgc->nhh, &lookup, pbr_nh_alloc);
	pnhc->parent = pnhgc;
	pbr_nht_install_nexthop_group(pnhgc, *pbrms->nhg);
}

void pbr_nht_delete_individual_nexthop(const char *name, uint32_t seqno)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_cache *pnhc;
	struct pbr_nexthop_cache lup;
	struct pbr_map_sequence *pbrms;
	struct nexthop *nh;

	pbrms = pbrms_get(name, seqno);

	memset(&find, 0, sizeof(find));
	strcpy(&find.name[0], pbrms->internal_nhg_name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	nh = pbrms->nhg->nexthop;
	memcpy(&lup.nexthop, nh, sizeof(struct nexthop));
	pnhc = hash_lookup(pnhgc->nhh, &lup);
	pnhc->parent = NULL;
	hash_release(pnhgc->nhh, pnhc);
	pbr_nh_delete(&pnhc);
	pbr_nht_uninstall_nexthop_group(pnhgc, *pbrms->nhg);

	hash_release(pbr_nhg_hash, pnhgc);

	nexthop_del(pbrms->nhg, nh);
	nexthop_free(nh);
	nexthop_group_delete(&pbrms->nhg);
	XFREE(MTYPE_TMP, pbrms->internal_nhg_name);
}

void pbr_nht_add_group(const char *name)
{
	struct nexthop *nhop;
	struct nexthop_group_cmd *nhgc;
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache lookup;

	nhgc = nhgc_find(name);

	if (!nhgc) {
		zlog_warn("%s: Could not find group %s to add",
			  __PRETTY_FUNCTION__, name);
		return;
	}

	strcpy(lookup.name, name);
	pnhgc = hash_get(pbr_nhg_hash, &lookup, pbr_nhgc_alloc);
	DEBUGD(&pbr_dbg_nht, "%s: Retrieved NHGC @ %p", __PRETTY_FUNCTION__,
	       pnhgc);

	for (ALL_NEXTHOPS(nhgc->nhg, nhop)) {
		struct pbr_nexthop_cache lookup;
		struct pbr_nexthop_cache *pnhc;

		memcpy(&lookup.nexthop, nhop, sizeof(*nhop));
		pnhc = hash_lookup(pnhgc->nhh, &lookup);
		if (!pnhc) {
			pnhc = hash_get(pnhgc->nhh, &lookup, pbr_nh_alloc);
			pnhc->parent = pnhgc;
		}
	}
}

void pbr_nht_delete_group(const char *name)
{
	struct pbr_map_sequence *pbrms;
	struct listnode *snode;
	struct pbr_map *pbrm;

	RB_FOREACH (pbrm, pbr_map_entry_head, &pbr_maps) {
		for (ALL_LIST_ELEMENTS_RO(pbrm->seqnumbers, snode, pbrms)) {
			if (pbrms->nhgrp_name
			    && strcmp(pbrms->nhgrp_name, name) == 0) {
				pbrms->reason |= PBR_MAP_INVALID_NO_NEXTHOPS;
				pbrm->valid = false;
			}
		}
	}
}

bool pbr_nht_nexthop_valid(struct nexthop_group *nhg)
{
	DEBUGD(&pbr_dbg_nht, "%s: %p", __PRETTY_FUNCTION__, nhg);
	return true;
}

bool pbr_nht_nexthop_group_valid(const char *name)
{
	struct pbr_nexthop_group_cache *pnhgc;
	struct pbr_nexthop_group_cache lookup;

	DEBUGD(&pbr_dbg_nht, "%s: %s", __PRETTY_FUNCTION__, name);

	strcpy(lookup.name, name);
	pnhgc = hash_get(pbr_nhg_hash, &lookup, NULL);
	if (!pnhgc)
		return false;
	DEBUGD(&pbr_dbg_nht, "%s: \t%d %d", __PRETTY_FUNCTION__, pnhgc->valid,
	       pnhgc->installed);
	if (pnhgc->valid && pnhgc->installed)
		return true;

	return false;
}

struct pbr_nht_individual {
	struct zapi_route *nhr;

	uint32_t valid;
};

static void pbr_nht_individual_nexthop_update_lookup(struct hash_backet *b,
						     void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct pbr_nht_individual *pnhi = data;
	char buf[PREFIX_STRLEN];
	bool old_valid;

	old_valid = pnhc->valid;

	switch (pnhi->nhr->prefix.family) {
	case AF_INET:
		if (pnhc->nexthop.gate.ipv4.s_addr
		    == pnhi->nhr->prefix.u.prefix4.s_addr)
			pnhc->valid = !!pnhi->nhr->nexthop_num;
		break;
	case AF_INET6:
		if (memcmp(&pnhc->nexthop.gate.ipv6,
			   &pnhi->nhr->prefix.u.prefix6, 16) == 0)
			pnhc->valid = !!pnhi->nhr->nexthop_num;
		break;
	}

	DEBUGD(&pbr_dbg_nht, "\tFound %s: old: %d new: %d",
	       prefix2str(&pnhi->nhr->prefix, buf, sizeof(buf)), old_valid,
	       pnhc->valid);

	if (old_valid != pnhc->valid) {
		struct pbr_event *pbre;

		pbre = pbr_event_new(PBR_NH_CHANGED, pnhc->parent->name);

		pbr_event_enqueue(pbre);
	}

	if (pnhc->valid)
		pnhi->valid += 1;
}

static void pbr_nht_nexthop_update_lookup(struct hash_backet *b, void *data)
{
	struct pbr_nexthop_group_cache *pnhgc = b->data;
	struct pbr_nht_individual pnhi;

	pnhi.nhr = (struct zapi_route *)data;
	pnhi.valid = 0;
	hash_iterate(pnhgc->nhh, pbr_nht_individual_nexthop_update_lookup,
		     &pnhi);

	/*
	 * If any of the specified nexthops are valid we are valid
	 */
	pnhgc->valid = !!pnhi.valid;
}

void pbr_nht_nexthop_update(struct zapi_route *nhr)
{
	hash_iterate(pbr_nhg_hash, pbr_nht_nexthop_update_lookup, nhr);
}

static uint32_t pbr_nhg_hash_key(void *arg)
{
	struct pbr_nexthop_group_cache *nhgc =
		(struct pbr_nexthop_group_cache *)arg;

	return jhash(&nhgc->name, strlen(nhgc->name), 0x52c34a96);
}

static int pbr_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct pbr_nexthop_group_cache *nhgc1 =
		(const struct pbr_nexthop_group_cache *)arg1;
	const struct pbr_nexthop_group_cache *nhgc2 =
		(const struct pbr_nexthop_group_cache *)arg2;

	return !strcmp(nhgc1->name, nhgc2->name);
}


uint32_t pbr_nht_get_next_tableid(void)
{
	uint32_t i;
	bool found = false;

	for (i = pbr_nhg_low_table; i <= pbr_nhg_high_table; i++) {
		if (nhg_tableid[i] == false) {
			found = true;
			break;
		}
	}

	if (found) {
		nhg_tableid[i] = true;
		return i;
	} else
		return 0;
}

void pbr_nht_set_tableid_range(uint32_t low, uint32_t high)
{
	pbr_nhg_low_table = low;
	pbr_nhg_high_table = high;
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
	strcpy(find.name, name);
	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		DEBUGD(&pbr_dbg_nht,
		       "%s: Could not find nexthop-group cache w/ name '%s'",
		       __PRETTY_FUNCTION__, name);
		return 5000;
	}

	return pnhgc->table_id;
}

bool pbr_nht_get_installed(const char *name)
{
	struct pbr_nexthop_group_cache find;
	struct pbr_nexthop_group_cache *pnhgc;

	memset(&find, 0, sizeof(find));
	strcpy(find.name, name);

	pnhgc = hash_lookup(pbr_nhg_hash, &find);

	if (!pnhgc) {
		return false;
	}

	return pnhgc->installed;
}

static void pbr_nht_show_nhg_nexthops(struct hash_backet *b, void *data)
{
	struct pbr_nexthop_cache *pnhc = b->data;
	struct vty *vty = data;

	vty_out(vty, "\tValid: %d", pnhc->valid);
	nexthop_group_write_nexthop(vty, &pnhc->nexthop);
}

struct pbr_nht_show {
	struct vty *vty;
	const char *name;
};

static void pbr_nht_show_nhg(struct hash_backet *b, void *data)
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

void pbr_nht_show_nexthop_group(struct vty *vty, const char *name)
{
	struct pbr_nht_show pns;

	pns.vty = vty;
	pns.name = name;

	hash_iterate(pbr_nhg_hash, pbr_nht_show_nhg, &pns);
}

void pbr_nht_init(void)
{
	pbr_nhg_hash = hash_create_size(
		16, pbr_nhg_hash_key, pbr_nhg_hash_equal, "PBR NHG Cache Hash");

	pbr_nhg_low_table = PBR_NHT_DEFAULT_LOW_TABLEID;
	pbr_nhg_high_table = PBR_NHT_DEFAULT_HIGH_TABLEID;
	pbr_nhg_low_rule = PBR_NHT_DEFAULT_LOW_RULE;
	pbr_nhg_high_rule = PBR_NHT_DEFAULT_HIGH_RULE;
	memset(&nhg_tableid, 0, 65535 * sizeof(uint8_t));
}
