// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN-MH bridge-port protection
 * Copyright (C) 2026 Cisco Systems, Inc.
 * Patrice Brissette
 */

#include <zebra.h>

#include "lib/bitfield.h"
#include "lib/frrevent.h"
#include "lib/jhash.h"
#include "lib/json.h"
#include "lib/memory.h"
#include "lib/printfrr.h"
#include "lib/typesafe.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_bpp.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP, "EVPN-MH bridge-port protection entry");

enum zebra_evpn_bpp_state {
	ZEBRA_EVPN_BPP_PENDING,
};

/* Why an entry is not ready; an entry is ready when none is set. */
#define ZEBRA_EVPN_BPP_NO_LOCAL_ES  (1 << 0)
#define ZEBRA_EVPN_BPP_BD_HAS_L2VNI (1 << 1)
#define ZEBRA_EVPN_BPP_ES_HAS_L2VNI (1 << 2)
#define ZEBRA_EVPN_BPP_NO_SVI_VRF   (1 << 3)
#define ZEBRA_EVPN_BPP_NO_L3VNI	    (1 << 4)
#define ZEBRA_EVPN_BPP_L3VNI_DOWN   (1 << 5)
#define ZEBRA_EVPN_BPP_L3MH_OFF	    (1 << 6)

static const struct {
	uint32_t flag;
	const char *str;
} zebra_evpn_bpp_reasons[] = {
	{ ZEBRA_EVPN_BPP_NO_LOCAL_ES, "no local ES" },
	{ ZEBRA_EVPN_BPP_BD_HAS_L2VNI, "L2VNI on BD" },
	{ ZEBRA_EVPN_BPP_ES_HAS_L2VNI, "ES has an L2VNI" },
	{ ZEBRA_EVPN_BPP_NO_SVI_VRF, "no SVI or IP-VRF" },
	{ ZEBRA_EVPN_BPP_NO_L3VNI, "IP-VRF has no L3VNI" },
	{ ZEBRA_EVPN_BPP_L3VNI_DOWN, "L3VNI down" },
	{ ZEBRA_EVPN_BPP_L3MH_OFF, "l3vni-neigh off" },
};

#define ZEBRA_EVPN_BPP_NO_PEER_STR "no eligible peer"

PREDECL_HASH(zebra_evpn_bpp_hash);

struct zebra_evpn_bpp {
	/* key; the ifindex is not used as it is cleared before the
	 * interface cleanup runs
	 */
	struct zebra_if *zif;
	vlanid_t vid;

	/* from the VLAN's SVI */
	vrf_id_t vrf_id;
	vni_t l3vni;

	enum zebra_evpn_bpp_state state;
	uint32_t pending_flags;

	struct zebra_evpn_bpp_hash_item hash_item;
};

static int zebra_evpn_bpp_cmp(const struct zebra_evpn_bpp *e1, const struct zebra_evpn_bpp *e2)
{
	int ret;

	ret = numcmp((uintptr_t)e1->zif, (uintptr_t)e2->zif);
	if (ret)
		return ret;
	return numcmp(e1->vid, e2->vid);
}

static uint32_t zebra_evpn_bpp_hash_key(const struct zebra_evpn_bpp *e)
{
	return jhash_2words((uint32_t)(uintptr_t)e->zif, e->vid, 0x6270705f);
}

DECLARE_HASH(zebra_evpn_bpp_hash, struct zebra_evpn_bpp, hash_item, zebra_evpn_bpp_cmp,
	     zebra_evpn_bpp_hash_key);

static struct zebra_evpn_bpp_hash_head bpp_hash;
static bool bpp_inited;
static struct event *bpp_re_eval_ev;

static const char *zebra_evpn_bpp_state_str(enum zebra_evpn_bpp_state state)
{
	switch (state) {
	case ZEBRA_EVPN_BPP_PENDING:
		return "PENDING";
	}
	return "unknown";
}

static const char *zebra_evpn_bpp_reasons_str(uint32_t flags, char *buf, size_t len)
{
	size_t i;

	buf[0] = '\0';
	if (!flags) {
		strlcpy(buf, ZEBRA_EVPN_BPP_NO_PEER_STR, len);
		return buf;
	}

	for (i = 0; i < array_size(zebra_evpn_bpp_reasons); i++) {
		if (!CHECK_FLAG(flags, zebra_evpn_bpp_reasons[i].flag))
			continue;
		if (buf[0])
			strlcat(buf, ", ", len);
		strlcat(buf, zebra_evpn_bpp_reasons[i].str, len);
	}

	return buf;
}

/* Does a VLAN of the bond other than vid have an L2VNI? */
static bool zebra_evpn_bpp_zif_has_l2vni(struct zebra_if *zif, struct interface *br_if,
					 vlanid_t skip_vid)
{
	struct zebra_evpn_access_bd *acc_bd;
	vlanid_t vid;

	if (!br_if || !bf_is_inited(zif->vlan_bitmap))
		return false;

	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX)
	{
		if (vid == skip_vid)
			continue;
		acc_bd = zebra_evpn_acc_vl_find(vid, br_if);
		if (acc_bd && acc_bd->zevpn)
			return true;
	}

	return false;
}

static void zebra_evpn_bpp_eval(struct zebra_evpn_bpp *e)
{
	struct zebra_if *zif = e->zif;
	struct interface *br_if = zif->brslave_info.br_if;
	struct zebra_vrf *evpn_zvrf = zebra_vrf_get_evpn();
	struct zebra_evpn_access_bd *acc_bd = NULL;
	struct interface *svi = NULL;
	struct zebra_l3vni *zl3vni = NULL;
	char old_buf[128];
	char new_buf[128];
	uint32_t flags = 0;

	e->vrf_id = VRF_UNKNOWN;
	e->l3vni = 0;

	if (br_if)
		acc_bd = zebra_evpn_acc_vl_find(e->vid, br_if);
	if (acc_bd && acc_bd->vlan_zif)
		svi = acc_bd->vlan_zif->ifp;
	if (svi && svi->vrf) {
		e->vrf_id = svi->vrf->vrf_id;
		zl3vni = zl3vni_from_vrf(e->vrf_id);
		if (zl3vni)
			e->l3vni = zl3vni->vni;
	}

	if (!zif->es_info.es)
		SET_FLAG(flags, ZEBRA_EVPN_BPP_NO_LOCAL_ES);
	if (acc_bd && acc_bd->zevpn)
		SET_FLAG(flags, ZEBRA_EVPN_BPP_BD_HAS_L2VNI);
	if (zebra_evpn_bpp_zif_has_l2vni(zif, br_if, e->vid))
		SET_FLAG(flags, ZEBRA_EVPN_BPP_ES_HAS_L2VNI);
	if (e->vrf_id == VRF_UNKNOWN)
		SET_FLAG(flags, ZEBRA_EVPN_BPP_NO_SVI_VRF);
	else if (!zl3vni)
		SET_FLAG(flags, ZEBRA_EVPN_BPP_NO_L3VNI);
	else if (!is_l3vni_oper_up(zl3vni))
		SET_FLAG(flags, ZEBRA_EVPN_BPP_L3VNI_DOWN);
	if (!evpn_zvrf || !evpn_zvrf->advertise_l3vni_neigh)
		SET_FLAG(flags, ZEBRA_EVPN_BPP_L3MH_OFF);

	if (flags == e->pending_flags)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("bridge-port protection %s vlan %u: %s -> %s", zif->ifp->name, e->vid,
			   zebra_evpn_bpp_reasons_str(e->pending_flags, old_buf, sizeof(old_buf)),
			   zebra_evpn_bpp_reasons_str(flags, new_buf, sizeof(new_buf)));
	e->pending_flags = flags;
}

static struct zebra_evpn_bpp *zebra_evpn_bpp_find(struct zebra_if *zif, vlanid_t vid)
{
	struct zebra_evpn_bpp key = { .zif = zif, .vid = vid };

	return zebra_evpn_bpp_hash_find(&bpp_hash, &key);
}

static struct zebra_evpn_bpp *zebra_evpn_bpp_new(struct zebra_if *zif, vlanid_t vid)
{
	struct zebra_evpn_bpp *e;

	e = XCALLOC(MTYPE_ZEVPN_BPP, sizeof(*e));
	e->zif = zif;
	e->vid = vid;
	e->vrf_id = VRF_UNKNOWN;
	e->state = ZEBRA_EVPN_BPP_PENDING;
	e->pending_flags = ZEBRA_EVPN_BPP_NO_LOCAL_ES;
	zebra_evpn_bpp_hash_add(&bpp_hash, e);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("bridge-port protection %s vlan %u add", zif->ifp->name, vid);
	return e;
}

static void zebra_evpn_bpp_free(struct zebra_evpn_bpp *e)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		zlog_debug("bridge-port protection %s vlan %u del", e->zif->ifp->name, e->vid);

	zebra_evpn_bpp_hash_del(&bpp_hash, e);
	XFREE(MTYPE_ZEVPN_BPP, e);
}

void zebra_evpn_bpp_if_update(struct zebra_if *zif)
{
	struct zebra_evpn_bpp *e;
	bool protect;
	vlanid_t vid;

	if (!bpp_inited)
		return;

	protect = CHECK_FLAG(zif->es_info.flags, ZIF_CFG_ES_FLAG_BPP) &&
		  bf_is_inited(zif->vlan_bitmap);

	frr_each_safe (zebra_evpn_bpp_hash, &bpp_hash, e) {
		if (e->zif != zif)
			continue;
		if (protect && bf_test_index(zif->vlan_bitmap, e->vid))
			continue;
		zebra_evpn_bpp_free(e);
	}

	if (!protect)
		return;

	bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX)
	{
		e = zebra_evpn_bpp_find(zif, vid);
		if (!e)
			e = zebra_evpn_bpp_new(zif, vid);
		zebra_evpn_bpp_eval(e);
	}
}

void zebra_evpn_bpp_if_del(struct zebra_if *zif)
{
	struct zebra_evpn_bpp *e;

	if (!bpp_inited)
		return;

	frr_each_safe (zebra_evpn_bpp_hash, &bpp_hash, e) {
		if (e->zif == zif)
			zebra_evpn_bpp_free(e);
	}
}

static void zebra_evpn_bpp_re_eval_all(struct event *event)
{
	struct zebra_evpn_bpp *e;

	frr_each (zebra_evpn_bpp_hash, &bpp_hash, e)
		zebra_evpn_bpp_eval(e);
}

void zebra_evpn_bpp_re_eval_schedule(void)
{
	if (!bpp_inited || !zebra_evpn_bpp_hash_count(&bpp_hash))
		return;

	event_add_event(zrouter.master, zebra_evpn_bpp_re_eval_all, NULL, 0, &bpp_re_eval_ev);
}

static int zebra_evpn_bpp_show_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn_bpp *e1 = *(const struct zebra_evpn_bpp **)p1;
	const struct zebra_evpn_bpp *e2 = *(const struct zebra_evpn_bpp **)p2;
	int ret;

	ret = strcmp(e1->zif->ifp->name, e2->zif->ifp->name);
	if (ret)
		return ret;
	return numcmp(e1->vid, e2->vid);
}

static void zebra_evpn_bpp_show_entry(struct vty *vty, const struct zebra_evpn_bpp *e)
{
	struct zebra_evpn_es *es = e->zif->es_info.es;
	char l3vni_str[16] = "-";
	char reasons[128];

	if (e->l3vni)
		snprintfrr(l3vni_str, sizeof(l3vni_str), "%u", e->l3vni);

	vty_out(vty, "%-16s %-5u %-30s %-16s %-8s %-8s %s\n", e->zif->ifp->name, e->vid,
		es ? es->esi_str : "-", e->vrf_id != VRF_UNKNOWN ? vrf_id_to_name(e->vrf_id) : "-",
		l3vni_str, zebra_evpn_bpp_state_str(e->state),
		zebra_evpn_bpp_reasons_str(e->pending_flags, reasons, sizeof(reasons)));
}

static void zebra_evpn_bpp_json_entry(json_object *json_vlans, const struct zebra_evpn_bpp *e)
{
	json_object *json_vlan = json_object_new_object();
	json_object *json_reasons = json_object_new_array();
	char vid_str[8];
	size_t i;

	if (e->vrf_id != VRF_UNKNOWN)
		json_object_string_add(json_vlan, "vrf", vrf_id_to_name(e->vrf_id));
	if (e->l3vni)
		json_object_int_add(json_vlan, "l3vni", e->l3vni);
	json_object_string_add(json_vlan, "state", zebra_evpn_bpp_state_str(e->state));
	json_object_boolean_add(json_vlan, "ready", !e->pending_flags);

	if (!e->pending_flags)
		json_array_string_add(json_reasons, ZEBRA_EVPN_BPP_NO_PEER_STR);
	for (i = 0; i < array_size(zebra_evpn_bpp_reasons); i++) {
		if (CHECK_FLAG(e->pending_flags, zebra_evpn_bpp_reasons[i].flag))
			json_array_string_add(json_reasons, zebra_evpn_bpp_reasons[i].str);
	}
	json_object_object_add(json_vlan, "reasons", json_reasons);

	snprintfrr(vid_str, sizeof(vid_str), "%u", e->vid);
	json_object_object_add(json_vlans, vid_str, json_vlan);
}

void zebra_evpn_bpp_show(struct vty *vty, bool uj)
{
	json_object *json = NULL;
	json_object *json_if = NULL;
	json_object *json_vlans = NULL;
	struct zebra_evpn_bpp **sorted;
	struct zebra_evpn_bpp *e;
	const struct zebra_if *prev_zif = NULL;
	size_t count;
	size_t i = 0;

	if (uj)
		json = json_object_new_object();

	count = bpp_inited ? zebra_evpn_bpp_hash_count(&bpp_hash) : 0;
	if (!count) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	sorted = XCALLOC(MTYPE_TMP, count * sizeof(*sorted));
	frr_each (zebra_evpn_bpp_hash, &bpp_hash, e)
		sorted[i++] = e;
	qsort(sorted, count, sizeof(*sorted), zebra_evpn_bpp_show_cmp);

	if (!uj)
		vty_out(vty, "%-16s %-5s %-30s %-16s %-8s %-8s %s\n", "Interface", "VLAN", "ESI",
			"VRF", "L3VNI", "State", "Reasons");

	for (i = 0; i < count; i++) {
		e = sorted[i];
		if (!uj) {
			zebra_evpn_bpp_show_entry(vty, e);
			continue;
		}

		if (e->zif != prev_zif) {
			struct zebra_evpn_es *es = e->zif->es_info.es;

			json_if = json_object_new_object();
			if (es)
				json_object_string_add(json_if, "esi", es->esi_str);
			json_vlans = json_object_new_object();
			json_object_object_add(json_if, "vlans", json_vlans);
			json_object_object_add(json, e->zif->ifp->name, json_if);
			prev_zif = e->zif;
		}
		zebra_evpn_bpp_json_entry(json_vlans, e);
	}

	XFREE(MTYPE_TMP, sorted);

	if (uj)
		vty_json(vty, json);
}

void zebra_evpn_bpp_init(void)
{
	zebra_evpn_bpp_hash_init(&bpp_hash);
	bpp_inited = true;
}

void zebra_evpn_bpp_terminate(void)
{
	struct zebra_evpn_bpp *e;

	if (!bpp_inited)
		return;

	event_cancel(&bpp_re_eval_ev);
	while ((e = zebra_evpn_bpp_hash_pop(&bpp_hash)))
		XFREE(MTYPE_ZEVPN_BPP, e);
	zebra_evpn_bpp_hash_fini(&bpp_hash);
	bpp_inited = false;
}
