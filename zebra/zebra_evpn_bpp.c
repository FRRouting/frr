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
#include "lib/monotime.h"
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

enum zebra_evpn_bpp_event {
	ZEBRA_EVPN_BPP_EV_CREATED,
	ZEBRA_EVPN_BPP_EV_REASONS,
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

	enum zebra_evpn_bpp_event last_event;
	time_t last_event_time;

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

static const char *zebra_evpn_bpp_event_str(enum zebra_evpn_bpp_event event)
{
	switch (event) {
	case ZEBRA_EVPN_BPP_EV_CREATED:
		return "created";
	case ZEBRA_EVPN_BPP_EV_REASONS:
		return "reasons changed";
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

static void zebra_evpn_bpp_eval(struct zebra_evpn_bpp *e, bool created)
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

	if (created) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s vlan %u add: %s", zif->ifp->name,
				   e->vid,
				   zebra_evpn_bpp_reasons_str(flags, new_buf, sizeof(new_buf)));
		e->last_event = ZEBRA_EVPN_BPP_EV_CREATED;
	} else {
		if (flags == e->pending_flags)
			return;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s vlan %u: %s -> %s", zif->ifp->name,
				   e->vid,
				   zebra_evpn_bpp_reasons_str(e->pending_flags, old_buf,
							      sizeof(old_buf)),
				   zebra_evpn_bpp_reasons_str(flags, new_buf, sizeof(new_buf)));
		e->last_event = ZEBRA_EVPN_BPP_EV_REASONS;
	}

	e->pending_flags = flags;
	e->last_event_time = monotime(NULL);
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
	zebra_evpn_bpp_hash_add(&bpp_hash, e);

	return e;
}

static void zebra_evpn_bpp_free(struct zebra_evpn_bpp *e)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
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
		if (e) {
			zebra_evpn_bpp_eval(e, false);
			continue;
		}
		zebra_evpn_bpp_eval(zebra_evpn_bpp_new(zif, vid), true);
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
		zebra_evpn_bpp_eval(e, false);
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

static const char *zebra_evpn_bpp_vrf_str(const struct zebra_evpn_bpp *e)
{
	return e->vrf_id != VRF_UNKNOWN ? vrf_id_to_name(e->vrf_id) : "-";
}

/* No peer table yet: an ES has no Members. */
static uint32_t zebra_evpn_bpp_member_count(const struct zebra_evpn_es *es)
{
	return 0;
}

static void zebra_evpn_bpp_show_entry(struct vty *vty, const struct zebra_evpn_bpp *e)
{
	struct zebra_evpn_es *es = e->zif->es_info.es;
	char l3vni_str[16] = "-";
	char reasons[128];

	if (e->l3vni)
		snprintfrr(l3vni_str, sizeof(l3vni_str), "%u", e->l3vni);

	vty_out(vty, "%-16s %-5u %-30s %-16s %-8s %-10s %-8s %s\n", e->zif->ifp->name, e->vid,
		es ? es->esi_str : "-", zebra_evpn_bpp_vrf_str(e), l3vni_str, "-",
		zebra_evpn_bpp_state_str(e->state),
		zebra_evpn_bpp_reasons_str(e->pending_flags, reasons, sizeof(reasons)));
}

static void zebra_evpn_bpp_show_entry_detail(struct vty *vty, const struct zebra_evpn_bpp *e)
{
	struct zebra_evpn_es *es = e->zif->es_info.es;
	char l3vni_str[16] = "-";
	char reasons[128];
	char age[32];

	if (e->l3vni)
		snprintfrr(l3vni_str, sizeof(l3vni_str), "%u", e->l3vni);

	vty_out(vty, "Interface: %s  VLAN: %u\n", e->zif->ifp->name, e->vid);
	vty_out(vty, "  ESI: %s\n", es ? es->esi_str : "-");
	vty_out(vty, "  VRF: %s  L3VNI: %s\n", zebra_evpn_bpp_vrf_str(e), l3vni_str);
	vty_out(vty, "  Group: -\n");
	vty_out(vty, "  State: %s  Ready: %s\n", zebra_evpn_bpp_state_str(e->state),
		e->pending_flags ? "no" : "yes");
	vty_out(vty, "  Reasons: %s\n",
		zebra_evpn_bpp_reasons_str(e->pending_flags, reasons, sizeof(reasons)));
	vty_out(vty, "  Members: %u\n", zebra_evpn_bpp_member_count(es));
	vty_out(vty, "  Last event: %s, %s ago\n\n", zebra_evpn_bpp_event_str(e->last_event),
		frrtime_to_interval(monotime(NULL) - e->last_event_time, age, sizeof(age)));
}

static void zebra_evpn_bpp_json_entry(json_object *json_vlans, const struct zebra_evpn_bpp *e,
				      bool detail)
{
	json_object *json_vlan = json_object_new_object();
	json_object *json_reasons = json_object_new_array();
	char vid_str[8];
	char age[32];
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

	if (detail)
		json_object_int_add(json_vlan, "memberCount",
				    zebra_evpn_bpp_member_count(e->zif->es_info.es));

	json_object_string_add(json_vlan, "lastEvent", zebra_evpn_bpp_event_str(e->last_event));
	json_object_string_add(json_vlan, "lastEventTime",
			       frrtime_to_interval(monotime(NULL) - e->last_event_time, age,
						   sizeof(age)));

	snprintfrr(vid_str, sizeof(vid_str), "%u", e->vid);
	json_object_object_add(json_vlans, vid_str, json_vlan);
}

/* All entries sorted by interface name, then VLAN; the caller frees it. */
static struct zebra_evpn_bpp **zebra_evpn_bpp_sorted(size_t *count)
{
	struct zebra_evpn_bpp **sorted;
	struct zebra_evpn_bpp *e;
	size_t i = 0;

	*count = bpp_inited ? zebra_evpn_bpp_hash_count(&bpp_hash) : 0;
	if (!*count)
		return NULL;

	sorted = XCALLOC(MTYPE_TMP, *count * sizeof(*sorted));
	frr_each (zebra_evpn_bpp_hash, &bpp_hash, e)
		sorted[i++] = e;
	qsort(sorted, *count, sizeof(*sorted), zebra_evpn_bpp_show_cmp);

	return sorted;
}

void zebra_evpn_bpp_show(struct vty *vty, const char *ifname, bool detail, bool uj)
{
	json_object *json = NULL;
	json_object *json_if = NULL;
	json_object *json_vlans = NULL;
	struct zebra_evpn_bpp **sorted;
	struct zebra_evpn_bpp *e;
	const struct zebra_if *prev_zif = NULL;
	bool header = false;
	size_t count;
	size_t i;

	if (uj)
		json = json_object_new_object();

	sorted = zebra_evpn_bpp_sorted(&count);

	for (i = 0; i < count; i++) {
		e = sorted[i];
		if (ifname && strcmp(ifname, e->zif->ifp->name))
			continue;

		if (!uj) {
			if (detail) {
				zebra_evpn_bpp_show_entry_detail(vty, e);
				continue;
			}
			if (!header) {
				vty_out(vty, "%-16s %-5s %-30s %-16s %-8s %-10s %-8s %s\n",
					"Interface", "VLAN", "ESI", "VRF", "L3VNI", "Group",
					"State", "Reasons");
				header = true;
			}
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
		zebra_evpn_bpp_json_entry(json_vlans, e, detail);
	}

	XFREE(MTYPE_TMP, sorted);

	if (uj)
		vty_json(vty, json);
}

/* Show the protected ES of entries[0..count), all on the same bond. */
static void zebra_evpn_bpp_show_member_es(struct vty *vty, json_object *json,
					  struct zebra_evpn_bpp **entries, size_t count)
{
	struct zebra_if *zif = entries[0]->zif;
	struct zebra_evpn_es *es = zif->es_info.es;
	json_object *json_es = NULL;
	json_object *json_vrfs = NULL;
	vrf_id_t *vrfs;
	char vrfs_str[256] = "";
	size_t nvrfs = 0;
	size_t i, j;

	/* Distinct VRFs of the ready entries, in VLAN order. */
	vrfs = XCALLOC(MTYPE_TMP, count * sizeof(*vrfs));
	for (i = 0; i < count; i++) {
		if (entries[i]->pending_flags)
			continue;
		for (j = 0; j < nvrfs; j++)
			if (vrfs[j] == entries[i]->vrf_id)
				break;
		if (j == nvrfs)
			vrfs[nvrfs++] = entries[i]->vrf_id;
	}

	if (json) {
		json_es = json_object_new_object();
		json_object_string_add(json_es, "interface", zif->ifp->name);
		json_object_string_add(json_es, "state",
				       zebra_evpn_bpp_state_str(entries[0]->state));
		json_object_int_add(json_es, "vlanCount", count);
		json_vrfs = json_object_new_array();
		for (i = 0; i < nvrfs; i++)
			json_array_string_add(json_vrfs, vrf_id_to_name(vrfs[i]));
		json_object_object_add(json_es, "readyVrfs", json_vrfs);
		json_object_object_add(json_es, "members", json_object_new_array());
		json_object_object_add(json, es->esi_str, json_es);
	} else {
		for (i = 0; i < nvrfs; i++) {
			if (i)
				strlcat(vrfs_str, ", ", sizeof(vrfs_str));
			strlcat(vrfs_str, vrf_id_to_name(vrfs[i]), sizeof(vrfs_str));
		}
		vty_out(vty, "ESI %s  Interface %s  Group -  State %s\n", es->esi_str,
			zif->ifp->name, zebra_evpn_bpp_state_str(entries[0]->state));
		vty_out(vty, "  VLANs: %zu   VRFs: %s\n", count, nvrfs ? vrfs_str : "-");
		vty_out(vty, "  %-11s %-15s %-7s %s\n", "NH-ID", "VTEP", "Family", "RMAC");
		vty_out(vty, "\n");
	}

	XFREE(MTYPE_TMP, vrfs);
}

void zebra_evpn_bpp_show_member(struct vty *vty, const esi_t *esi, bool uj)
{
	json_object *json = NULL;
	struct zebra_evpn_bpp **sorted;
	struct zebra_evpn_es *es;
	size_t count;
	size_t i, j;

	if (uj)
		json = json_object_new_object();

	sorted = zebra_evpn_bpp_sorted(&count);

	for (i = 0; i < count; i = j) {
		for (j = i + 1; j < count && sorted[j]->zif == sorted[i]->zif; j++)
			;

		es = sorted[i]->zif->es_info.es;
		if (!es)
			continue;
		if (esi && memcmp(&es->esi, esi, sizeof(*esi)))
			continue;

		zebra_evpn_bpp_show_member_es(vty, json, &sorted[i], j - i);
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
