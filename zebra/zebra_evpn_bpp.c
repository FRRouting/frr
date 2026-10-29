// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN-MH bridge-port protection
 * Copyright (C) 2026 Cisco Systems, Inc.
 * Patrice Brissette
 */

#include <zebra.h>

#include "lib/bitfield.h"
#include "lib/frrevent.h"
#include "lib/ipaddr.h"
#include "lib/jhash.h"
#include "lib/json.h"
#include "lib/memory.h"
#include "lib/monotime.h"
#include "lib/prefix.h"
#include "lib/printfrr.h"
#include "lib/stream.h"
#include "lib/typesafe.h"
#include "lib/vrf.h"
#include "lib/vty.h"
#include "lib/zclient.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_bpp.h"
#include "zebra/zserv.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP, "EVPN-MH bridge-port protection entry");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP_EVI, "EVPN-MH bridge-port protection ES-EVI");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP_IF, "EVPN-MH bridge-port protection interface");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP_PEER, "EVPN-MH bridge-port protection peer");

enum zebra_evpn_bpp_state {
	ZEBRA_EVPN_BPP_PENDING,
	ZEBRA_EVPN_BPP_ACTIVE,
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
PREDECL_SORTLIST_UNIQ(zebra_evpn_bpp_evi_list);
PREDECL_HASH(zebra_evpn_bpp_peer_hash);
PREDECL_HASH(zebra_evpn_bpp_if_hash);

/* Entry of an ES bond for one VLAN; key is the VLAN */
struct zebra_evpn_bpp {
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
	return numcmp(e1->vid, e2->vid);
}

static uint32_t zebra_evpn_bpp_hash_key(const struct zebra_evpn_bpp *e)
{
	return jhash_1word(e->vid, 0x6270705f);
}

DECLARE_HASH(zebra_evpn_bpp_hash, struct zebra_evpn_bpp, hash_item, zebra_evpn_bpp_cmp,
	     zebra_evpn_bpp_hash_key);

/* An (ES, L3VNI) association sent to bgpd as an ES-EVI; one per IP-VRF
 * with at least one ready entry on the ES bond.
 */
struct zebra_evpn_bpp_evi {
	esi_t esi;
	vni_t l3vni;

	/* still wanted by the sync in progress */
	bool keep;

	struct zebra_evpn_bpp_evi_list_item item;
};

static int zebra_evpn_bpp_evi_cmp(const struct zebra_evpn_bpp_evi *e1,
				  const struct zebra_evpn_bpp_evi *e2)
{
	int ret;

	ret = numcmp(e1->l3vni, e2->l3vni);
	if (ret)
		return ret;
	return memcmp(&e1->esi, &e2->esi, sizeof(esi_t));
}

DECLARE_SORTLIST_UNIQ(zebra_evpn_bpp_evi_list, struct zebra_evpn_bpp_evi, item,
		      zebra_evpn_bpp_evi_cmp);

/* A peer bgpd reported eligible for this ES. Key is (type, VTEP). */
struct zebra_evpn_bpp_peer {
	uint8_t type;
	struct ipaddr vtep;
	struct ethaddr rmac;

	struct zebra_evpn_bpp_peer_hash_item item;
};

static int zebra_evpn_bpp_peer_cmp(const struct zebra_evpn_bpp_peer *p1,
				   const struct zebra_evpn_bpp_peer *p2)
{
	int ret;

	ret = numcmp(p1->type, p2->type);
	if (ret)
		return ret;
	return ipaddr_cmp(&p1->vtep, &p2->vtep);
}

static uint32_t zebra_evpn_bpp_peer_hash_key(const struct zebra_evpn_bpp_peer *p)
{
	return jhash_1word(p->type, ipaddr_hash(&p->vtep));
}

DECLARE_HASH(zebra_evpn_bpp_peer_hash, struct zebra_evpn_bpp_peer, item, zebra_evpn_bpp_peer_cmp,
	     zebra_evpn_bpp_peer_hash_key);

/* Protection state of an ES bond: its entries and the ES-EVIs sent for it.
 * Keyed by zif; the ifindex is cleared before the interface cleanup runs.
 */
struct zebra_evpn_bpp_if {
	struct zebra_if *zif;
	struct zebra_evpn_bpp_hash_head entries;
	struct zebra_evpn_bpp_evi_list_head evis;
	struct zebra_evpn_bpp_peer_hash_head peers;

	struct zebra_evpn_bpp_if_hash_item item;
};

static int zebra_evpn_bpp_if_cmp(const struct zebra_evpn_bpp_if *b1,
				 const struct zebra_evpn_bpp_if *b2)
{
	return numcmp((uintptr_t)b1->zif, (uintptr_t)b2->zif);
}

static uint32_t zebra_evpn_bpp_if_hash_key(const struct zebra_evpn_bpp_if *bif)
{
	return jhash_1word((uint32_t)(uintptr_t)bif->zif, 0x6270705f);
}

DECLARE_HASH(zebra_evpn_bpp_if_hash, struct zebra_evpn_bpp_if, item, zebra_evpn_bpp_if_cmp,
	     zebra_evpn_bpp_if_hash_key);

static struct zebra_evpn_bpp_if_hash_head bpp_if_hash;
static bool bpp_inited;
static struct event *bpp_re_eval_ev;

static const char *zebra_evpn_bpp_state_str(enum zebra_evpn_bpp_state state)
{
	switch (state) {
	case ZEBRA_EVPN_BPP_PENDING:
		return "PENDING";
	case ZEBRA_EVPN_BPP_ACTIVE:
		return "ACTIVE";
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

static const char *zebra_evpn_bpp_flags_str(uint32_t flags, char *buf, size_t len)
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

/* Shown reason: pending flags, or "no eligible peer" when ready but unbound. */
static const char *zebra_evpn_bpp_reasons_str(const struct zebra_evpn_bpp *e, char *buf, size_t len)
{
	if (e->pending_flags)
		return zebra_evpn_bpp_flags_str(e->pending_flags, buf, len);
	if (e->state == ZEBRA_EVPN_BPP_ACTIVE) {
		buf[0] = '\0';
		return buf;
	}
	strlcpy(buf, ZEBRA_EVPN_BPP_NO_PEER_STR, len);
	return buf;
}

static const char *zebra_evpn_bpp_family_str(const struct ipaddr *ip)
{
	if (IS_IPADDR_V4(ip))
		return "ipv4";
	if (IS_IPADDR_V6(ip))
		return "ipv6";
	return "-";
}

static const char *zebra_evpn_bpp_type_str(uint8_t type)
{
	if (type == ZAPI_EVPN_BPP_PEER_L3)
		return "L3";
	if (type == ZAPI_EVPN_BPP_PEER_L2)
		return "L2";
	return "-";
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

/* acc_bd->vlan_zif is cleared while the SVI is oper-down. The SVI still
 * owns the VRF/L3VNI mapping, so look it up even when it is not up.
 */
struct zebra_evpn_bpp_svi_ctx {
	vlanid_t vid;
	struct interface *br_if;
	struct interface *svi;
};

static int zebra_evpn_bpp_svi_walk(struct interface *ifp, void *arg)
{
	struct zebra_evpn_bpp_svi_ctx *ctx = arg;
	struct zebra_if *zif;

	zif = ifp->info;
	if (!zif || zif->zif_type != ZEBRA_IF_VLAN || zif->link != ctx->br_if)
		return NS_WALK_CONTINUE;
	if (zif->l2info.vl.vid == ctx->vid) {
		ctx->svi = ifp;
		return NS_WALK_STOP;
	}
	return NS_WALK_CONTINUE;
}

static struct interface *zebra_evpn_bpp_svi_find(vlanid_t vid, struct interface *br_if)
{
	struct zebra_evpn_bpp_svi_ctx ctx = { .vid = vid, .br_if = br_if };

	if (!br_if)
		return NULL;
	zebra_ns_ifp_walk_all(zebra_evpn_bpp_svi_walk, &ctx);
	return ctx.svi;
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
	if (!svi)
		svi = zebra_evpn_bpp_svi_find(e->vid, br_if);
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
				   zebra_evpn_bpp_flags_str(flags, new_buf, sizeof(new_buf)));
		e->last_event = ZEBRA_EVPN_BPP_EV_CREATED;
	} else {
		if (flags == e->pending_flags)
			return;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s vlan %u: %s -> %s", zif->ifp->name,
				   e->vid,
				   zebra_evpn_bpp_flags_str(e->pending_flags, old_buf,
							    sizeof(old_buf)),
				   zebra_evpn_bpp_flags_str(flags, new_buf, sizeof(new_buf)));
		e->last_event = ZEBRA_EVPN_BPP_EV_REASONS;
	}

	e->pending_flags = flags;
	e->last_event_time = monotime(NULL);
}

static struct zebra_evpn_bpp_if *zebra_evpn_bpp_if_find(struct zebra_if *zif)
{
	struct zebra_evpn_bpp_if key = { .zif = zif };

	return zebra_evpn_bpp_if_hash_find(&bpp_if_hash, &key);
}

static struct zebra_evpn_bpp_if *zebra_evpn_bpp_if_new(struct zebra_if *zif)
{
	struct zebra_evpn_bpp_if *bif;

	bif = XCALLOC(MTYPE_ZEVPN_BPP_IF, sizeof(*bif));
	bif->zif = zif;
	zebra_evpn_bpp_hash_init(&bif->entries);
	zebra_evpn_bpp_evi_list_init(&bif->evis);
	zebra_evpn_bpp_peer_hash_init(&bif->peers);
	zebra_evpn_bpp_if_hash_add(&bpp_if_hash, bif);

	return bif;
}

/* The caller has emptied the entries and the ES-EVIs */
static void zebra_evpn_bpp_peer_flush(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_bpp_peer *peer;

	while ((peer = zebra_evpn_bpp_peer_hash_pop(&bif->peers)))
		XFREE(MTYPE_ZEVPN_BPP_PEER, peer);
}

static void zebra_evpn_bpp_if_free(struct zebra_evpn_bpp_if *bif)
{
	zebra_evpn_bpp_if_hash_del(&bpp_if_hash, bif);
	zebra_evpn_bpp_peer_flush(bif);
	zebra_evpn_bpp_hash_fini(&bif->entries);
	zebra_evpn_bpp_evi_list_fini(&bif->evis);
	zebra_evpn_bpp_peer_hash_fini(&bif->peers);
	XFREE(MTYPE_ZEVPN_BPP_IF, bif);
}

static struct zebra_evpn_bpp *zebra_evpn_bpp_find(struct zebra_evpn_bpp_if *bif, vlanid_t vid)
{
	struct zebra_evpn_bpp key = { .vid = vid };

	return zebra_evpn_bpp_hash_find(&bif->entries, &key);
}

static struct zebra_evpn_bpp *zebra_evpn_bpp_new(struct zebra_evpn_bpp_if *bif, vlanid_t vid)
{
	struct zebra_evpn_bpp *e;

	e = XCALLOC(MTYPE_ZEVPN_BPP, sizeof(*e));
	e->zif = bif->zif;
	e->vid = vid;
	e->vrf_id = VRF_UNKNOWN;
	e->state = ZEBRA_EVPN_BPP_PENDING;
	zebra_evpn_bpp_hash_add(&bif->entries, e);

	return e;
}

static void zebra_evpn_bpp_free(struct zebra_evpn_bpp_if *bif, struct zebra_evpn_bpp *e)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
		zlog_debug("bridge-port protection %s vlan %u del", e->zif->ifp->name, e->vid);

	zebra_evpn_bpp_hash_del(&bif->entries, e);
	XFREE(MTYPE_ZEVPN_BPP, e);
}

static bool zebra_evpn_bpp_es_ready(const struct zebra_evpn_es *es)
{
	return es && CHECK_FLAG(es->flags, ZEBRA_EVPNES_READY_FOR_BGP);
}

static uint32_t zebra_evpn_bpp_member_count(const struct zebra_evpn_bpp_if *bif)
{
	return bif ? zebra_evpn_bpp_peer_hash_count(&bif->peers) : 0;
}

/* Bound while ≥ 1 entry is ready and the Group has ≥ 1 Member. */
static bool zebra_evpn_bpp_if_bound(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_bpp *e;

	if (!bif || !zebra_evpn_bpp_member_count(bif))
		return false;

	frr_each (zebra_evpn_bpp_hash, &bif->entries, e) {
		if (!e->pending_flags)
			return true;
	}
	return false;
}

static void zebra_evpn_bpp_apply_state(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_bpp *e;
	enum zebra_evpn_bpp_state want;
	bool bound = zebra_evpn_bpp_if_bound(bif);

	frr_each (zebra_evpn_bpp_hash, &bif->entries, e) {
		want = (!e->pending_flags && bound) ? ZEBRA_EVPN_BPP_ACTIVE
						    : ZEBRA_EVPN_BPP_PENDING;
		if (e->state == want)
			continue;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s vlan %u state %s -> %s",
				   e->zif->ifp->name, e->vid, zebra_evpn_bpp_state_str(e->state),
				   zebra_evpn_bpp_state_str(want));
		e->state = want;
		e->last_event = ZEBRA_EVPN_BPP_EV_REASONS;
		e->last_event_time = monotime(NULL);
	}
}

/* Inform BGP about a local ES to L3VNI association */
static void zebra_evpn_bpp_evi_send(const struct zebra_evpn_bpp_if *bif,
				    const struct zebra_evpn_bpp_evi *evi, bool add)
{
	struct zserv *client;
	struct stream *s;
	char esi_buf[ESI_STR_LEN];

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return;

	s = stream_new(ZEBRA_SMALL_PACKET_SIZE);

	zclient_create_header(s, add ? ZEBRA_LOCAL_ES_EVI_ADD : ZEBRA_LOCAL_ES_EVI_DEL,
			      zebra_vrf_get_evpn_id());
	stream_put(s, &evi->esi, sizeof(esi_t));
	stream_putl(s, evi->l3vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
		zlog_debug("bridge-port protection %s send %s local es %s l3vni %u to %s",
			   bif->zif->ifp->name, add ? "add" : "del",
			   esi_to_str(&evi->esi, esi_buf, sizeof(esi_buf)), evi->l3vni,
			   zebra_route_string(client->proto));

	if (add)
		client->local_es_evi_add_cnt++;
	else
		client->local_es_evi_del_cnt++;
	zserv_send_message(client, s);
}

static struct zebra_evpn_bpp_evi *zebra_evpn_bpp_evi_find(struct zebra_evpn_bpp_if *bif,
							  const esi_t *esi, vni_t l3vni)
{
	struct zebra_evpn_bpp_evi key = { .l3vni = l3vni };

	memcpy(&key.esi, esi, sizeof(esi_t));
	return zebra_evpn_bpp_evi_list_find(&bif->evis, &key);
}

/* Send an ES-EVI per IP-VRF that still has an L3VNI on the ES. SVI and
 * L3VNI oper-down are not inputs (the entry is PENDING, the ES-EVI stays).
 * Nothing is sent for an ES that BGP does not know; BGP drops its
 * ES-EVIs with the ES.
 */
static void zebra_evpn_bpp_evi_sync(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_es *es = bif->zif->es_info.es;
	bool es_ready = zebra_evpn_bpp_es_ready(es);
	struct zebra_evpn_bpp_evi *evi;
	struct zebra_evpn_bpp *e;

	frr_each (zebra_evpn_bpp_evi_list, &bif->evis, evi)
		evi->keep = false;

	frr_each (zebra_evpn_bpp_hash, &bif->entries, e) {
		if ((e->pending_flags & ~ZEBRA_EVPN_BPP_L3VNI_DOWN) || !e->l3vni || !es_ready)
			continue;

		evi = zebra_evpn_bpp_evi_find(bif, &es->esi, e->l3vni);
		if (!evi) {
			evi = XCALLOC(MTYPE_ZEVPN_BPP_EVI, sizeof(*evi));
			memcpy(&evi->esi, &es->esi, sizeof(esi_t));
			evi->l3vni = e->l3vni;
			zebra_evpn_bpp_evi_list_add(&bif->evis, evi);
			zebra_evpn_bpp_evi_send(bif, evi, true);
		}
		evi->keep = true;
	}

	frr_each_safe (zebra_evpn_bpp_evi_list, &bif->evis, evi) {
		if (evi->keep)
			continue;
		if (es_ready && !memcmp(&es->esi, &evi->esi, sizeof(esi_t)))
			zebra_evpn_bpp_evi_send(bif, evi, false);
		zebra_evpn_bpp_evi_list_del(&bif->evis, evi);
		XFREE(MTYPE_ZEVPN_BPP_EVI, evi);
	}

	zebra_evpn_bpp_apply_state(bif);
}

/* Sync the ES-EVIs and free the bond state once it has no entry */
static void zebra_evpn_bpp_if_sync(struct zebra_evpn_bpp_if *bif)
{
	zebra_evpn_bpp_evi_sync(bif);
	if (!zebra_evpn_bpp_hash_count(&bif->entries))
		zebra_evpn_bpp_if_free(bif);
}

void zebra_evpn_bpp_es_update(struct zebra_evpn_es *es)
{
	struct zebra_evpn_bpp_if *bif;

	if (!bpp_inited || !es->zif)
		return;

	bif = zebra_evpn_bpp_if_find(es->zif);
	if (bif)
		zebra_evpn_bpp_evi_sync(bif);
}

void zebra_evpn_bpp_es_send_all(struct zebra_evpn_es *es, bool add)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp_evi *evi;

	if (!bpp_inited || !es->zif)
		return;

	bif = zebra_evpn_bpp_if_find(es->zif);
	if (!bif)
		return;

	frr_each (zebra_evpn_bpp_evi_list, &bif->evis, evi) {
		if (!memcmp(&evi->esi, &es->esi, sizeof(esi_t)))
			zebra_evpn_bpp_evi_send(bif, evi, add);
	}
}

void zebra_evpn_bpp_if_update(struct zebra_if *zif)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;
	bool protect;
	vlanid_t vid;

	if (!bpp_inited)
		return;

	protect = CHECK_FLAG(zif->es_info.flags, ZIF_CFG_ES_FLAG_BPP) &&
		  bf_is_inited(zif->vlan_bitmap);

	bif = zebra_evpn_bpp_if_find(zif);
	if (!bif) {
		if (!protect)
			return;
		bif = zebra_evpn_bpp_if_new(zif);
	}

	if (!protect)
		zebra_evpn_bpp_peer_flush(bif);

	frr_each_safe (zebra_evpn_bpp_hash, &bif->entries, e) {
		if (protect && bf_test_index(zif->vlan_bitmap, e->vid))
			continue;
		zebra_evpn_bpp_free(bif, e);
	}

	if (protect) {
		bf_for_each_set_bit(zif->vlan_bitmap, vid, IF_VLAN_BITMAP_MAX)
		{
			e = zebra_evpn_bpp_find(bif, vid);
			if (e) {
				zebra_evpn_bpp_eval(e, false);
				continue;
			}
			zebra_evpn_bpp_eval(zebra_evpn_bpp_new(bif, vid), true);
		}
	}

	zebra_evpn_bpp_if_sync(bif);
}

void zebra_evpn_bpp_if_del(struct zebra_if *zif)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;

	if (!bpp_inited)
		return;

	bif = zebra_evpn_bpp_if_find(zif);
	if (!bif)
		return;

	while ((e = zebra_evpn_bpp_hash_first(&bif->entries)))
		zebra_evpn_bpp_free(bif, e);
	zebra_evpn_bpp_peer_flush(bif);

	zebra_evpn_bpp_if_sync(bif);
}

static void zebra_evpn_bpp_re_eval_all(struct event *event)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;

	frr_each (zebra_evpn_bpp_if_hash, &bpp_if_hash, bif) {
		frr_each (zebra_evpn_bpp_hash, &bif->entries, e)
			zebra_evpn_bpp_eval(e, false);
		zebra_evpn_bpp_evi_sync(bif);
	}
}

void zebra_evpn_bpp_re_eval_schedule(void)
{
	if (!bpp_inited || !zebra_evpn_bpp_if_hash_count(&bpp_if_hash))
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

void zebra_evpn_bpp_peer_update(const struct zapi_evpn_bpp_peer *zpeer, bool add)
{
	struct zebra_evpn_es *es;
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp_peer *peer;
	struct zebra_evpn_bpp_peer key = {};
	char esi_buf[ESI_STR_LEN];

	if (!bpp_inited || !zpeer)
		return;

	es = zebra_evpn_es_find(&zpeer->esi);
	if (!es || !es->zif)
		return;
	if (!CHECK_FLAG(es->zif->es_info.flags, ZIF_CFG_ES_FLAG_BPP))
		return;

	bif = zebra_evpn_bpp_if_find(es->zif);
	if (!bif)
		return;

	key.type = zpeer->type;
	key.vtep = zpeer->vtep;
	peer = zebra_evpn_bpp_peer_hash_find(&bif->peers, &key);

	if (!add) {
		if (!peer)
			return;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s member del vtep %pIA",
				   es->zif->ifp->name, &peer->vtep);
		zebra_evpn_bpp_peer_hash_del(&bif->peers, peer);
		XFREE(MTYPE_ZEVPN_BPP_PEER, peer);
		zebra_evpn_bpp_apply_state(bif);
		return;
	}

	if (peer) {
		if (!memcmp(&peer->rmac, &zpeer->rmac, ETH_ALEN))
			return;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s member rmac %pEA -> %pEA vtep %pIA",
				   es->zif->ifp->name, &peer->rmac, &zpeer->rmac, &peer->vtep);
		memcpy(&peer->rmac, &zpeer->rmac, ETH_ALEN);
		return;
	}

	peer = XCALLOC(MTYPE_ZEVPN_BPP_PEER, sizeof(*peer));
	peer->type = zpeer->type;
	peer->vtep = zpeer->vtep;
	memcpy(&peer->rmac, &zpeer->rmac, ETH_ALEN);
	zebra_evpn_bpp_peer_hash_add(&bif->peers, peer);

	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
		zlog_debug("bridge-port protection %s member add esi %s vtep %pIA rmac %pEA",
			   es->zif->ifp->name, esi_to_str(&zpeer->esi, esi_buf, sizeof(esi_buf)),
			   &peer->vtep, &peer->rmac);

	zebra_evpn_bpp_apply_state(bif);
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
		zebra_evpn_bpp_reasons_str(e, reasons, sizeof(reasons)));
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
	vty_out(vty, "  Reasons: %s\n", zebra_evpn_bpp_reasons_str(e, reasons, sizeof(reasons)));
	vty_out(vty, "  Members: %u\n",
		zebra_evpn_bpp_member_count(zebra_evpn_bpp_if_find(e->zif)));
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

	if (e->pending_flags) {
		for (i = 0; i < array_size(zebra_evpn_bpp_reasons); i++) {
			if (CHECK_FLAG(e->pending_flags, zebra_evpn_bpp_reasons[i].flag))
				json_array_string_add(json_reasons, zebra_evpn_bpp_reasons[i].str);
		}
	} else if (e->state != ZEBRA_EVPN_BPP_ACTIVE) {
		json_array_string_add(json_reasons, ZEBRA_EVPN_BPP_NO_PEER_STR);
	}
	json_object_object_add(json_vlan, "reasons", json_reasons);

	if (detail)
		json_object_int_add(json_vlan, "memberCount",
				    zebra_evpn_bpp_member_count(zebra_evpn_bpp_if_find(e->zif)));

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
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;
	size_t i = 0;

	*count = 0;
	if (!bpp_inited)
		return NULL;
	frr_each (zebra_evpn_bpp_if_hash, &bpp_if_hash, bif)
		*count += zebra_evpn_bpp_hash_count(&bif->entries);
	if (!*count)
		return NULL;

	sorted = XCALLOC(MTYPE_TMP, *count * sizeof(*sorted));
	frr_each (zebra_evpn_bpp_if_hash, &bpp_if_hash, bif)
		frr_each (zebra_evpn_bpp_hash, &bif->entries, e)
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
			struct zebra_evpn_bpp_if *bif = zebra_evpn_bpp_if_find(e->zif);

			json_if = json_object_new_object();
			if (es)
				json_object_string_add(json_if, "esi", es->esi_str);
			json_object_boolean_add(json_if, "bound", zebra_evpn_bpp_if_bound(bif));
			json_object_int_add(json_if, "memberCount",
					    zebra_evpn_bpp_member_count(bif));
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

static int zebra_evpn_bpp_peer_show_cmp(const void *p1, const void *p2)
{
	const struct zebra_evpn_bpp_peer *a = *(const struct zebra_evpn_bpp_peer **)p1;
	const struct zebra_evpn_bpp_peer *b = *(const struct zebra_evpn_bpp_peer **)p2;
	int ret;

	ret = numcmp(a->type, b->type);
	if (ret)
		return ret;
	return ipaddr_cmp(&a->vtep, &b->vtep);
}

static struct zebra_evpn_bpp_peer **zebra_evpn_bpp_peers_sorted(struct zebra_evpn_bpp_if *bif,
								size_t *count)
{
	struct zebra_evpn_bpp_peer **sorted;
	struct zebra_evpn_bpp_peer *peer;
	size_t i = 0;

	*count = bif ? zebra_evpn_bpp_peer_hash_count(&bif->peers) : 0;
	if (!*count)
		return NULL;

	sorted = XCALLOC(MTYPE_TMP, *count * sizeof(*sorted));
	frr_each (zebra_evpn_bpp_peer_hash, &bif->peers, peer)
		sorted[i++] = peer;
	qsort(sorted, *count, sizeof(*sorted), zebra_evpn_bpp_peer_show_cmp);
	return sorted;
}

static json_object *zebra_evpn_bpp_json_member(const struct zebra_evpn_bpp_peer *peer)
{
	json_object *json_m = json_object_new_object();
	char vtep_buf[IPADDR_STRING_SIZE];
	char mac_buf[ETHER_ADDR_STRLEN];

	ipaddr2str(&peer->vtep, vtep_buf, sizeof(vtep_buf));
	prefix_mac2str(&peer->rmac, mac_buf, sizeof(mac_buf));
	json_object_string_add(json_m, "vtep", vtep_buf);
	json_object_string_add(json_m, "family", zebra_evpn_bpp_family_str(&peer->vtep));
	json_object_string_add(json_m, "rmac", mac_buf);
	json_object_string_add(json_m, "type", zebra_evpn_bpp_type_str(peer->type));
	return json_m;
}

/* Show the protected ES of entries[0..count), all on the same bond. */
static void zebra_evpn_bpp_show_member_es(struct vty *vty, json_object *json,
					  struct zebra_evpn_bpp **entries, size_t count)
{
	struct zebra_if *zif = entries[0]->zif;
	struct zebra_evpn_es *es = zif->es_info.es;
	struct zebra_evpn_bpp_if *bif = zebra_evpn_bpp_if_find(zif);
	struct zebra_evpn_bpp_evi *evi;
	struct zebra_evpn_bpp_peer **peers;
	json_object *json_es = NULL;
	json_object *json_vrfs = NULL;
	json_object *json_evis = NULL;
	json_object *json_members = NULL;
	vrf_id_t *vrfs;
	char vrfs_str[256] = "";
	char evis_str[256] = "";
	char vni_str[16];
	const char *state_str;
	size_t nvrfs = 0;
	size_t npeers = 0;
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

	state_str = zebra_evpn_bpp_if_bound(bif) ? "ACTIVE" : "PENDING";
	peers = zebra_evpn_bpp_peers_sorted(bif, &npeers);

	if (json) {
		json_es = json_object_new_object();
		json_object_string_add(json_es, "interface", zif->ifp->name);
		json_object_string_add(json_es, "state", state_str);
		json_object_boolean_add(json_es, "bound", zebra_evpn_bpp_if_bound(bif));
		json_object_int_add(json_es, "vlanCount", count);
		json_vrfs = json_object_new_array();
		for (i = 0; i < nvrfs; i++)
			json_array_string_add(json_vrfs, vrf_id_to_name(vrfs[i]));
		json_object_object_add(json_es, "readyVrfs", json_vrfs);
		json_evis = json_object_new_array();
		if (bif)
			frr_each (zebra_evpn_bpp_evi_list, &bif->evis, evi)
				json_object_array_add(json_evis, json_object_new_int(evi->l3vni));
		json_object_object_add(json_es, "esEviL3vnis", json_evis);
		json_members = json_object_new_array();
		for (i = 0; i < npeers; i++)
			json_object_array_add(json_members, zebra_evpn_bpp_json_member(peers[i]));
		json_object_object_add(json_es, "members", json_members);
		json_object_object_add(json, es->esi_str, json_es);
	} else {
		for (i = 0; i < nvrfs; i++) {
			if (i)
				strlcat(vrfs_str, ", ", sizeof(vrfs_str));
			strlcat(vrfs_str, vrf_id_to_name(vrfs[i]), sizeof(vrfs_str));
		}
		if (bif)
			frr_each (zebra_evpn_bpp_evi_list, &bif->evis, evi) {
				if (evis_str[0])
					strlcat(evis_str, ", ", sizeof(evis_str));
				snprintfrr(vni_str, sizeof(vni_str), "%u", evi->l3vni);
				strlcat(evis_str, vni_str, sizeof(evis_str));
			}
		vty_out(vty, "ESI %s  Interface %s  Group -  State %s\n", es->esi_str,
			zif->ifp->name, state_str);
		vty_out(vty, "  VLANs: %zu   VRFs: %s\n", count, nvrfs ? vrfs_str : "-");
		vty_out(vty, "  ES-EVI L3VNIs: %s\n", evis_str[0] ? evis_str : "-");
		vty_out(vty, "  %-11s %-40s %-7s %s\n", "NH-ID", "VTEP", "Family", "RMAC");
		for (i = 0; i < npeers; i++) {
			char vtep_buf[IPADDR_STRING_SIZE];

			ipaddr2str(&peers[i]->vtep, vtep_buf, sizeof(vtep_buf));
			vty_out(vty, "  %-11s %-40s %-7s %pEA\n", "-", vtep_buf,
				zebra_evpn_bpp_family_str(&peers[i]->vtep), &peers[i]->rmac);
		}
		vty_out(vty, "\n");
	}

	XFREE(MTYPE_TMP, peers);
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
	zebra_evpn_bpp_if_hash_init(&bpp_if_hash);
	bpp_inited = true;
}

void zebra_evpn_bpp_terminate(void)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;
	struct zebra_evpn_bpp_evi *evi;

	if (!bpp_inited)
		return;

	event_cancel(&bpp_re_eval_ev);
	while ((bif = zebra_evpn_bpp_if_hash_first(&bpp_if_hash))) {
		while ((e = zebra_evpn_bpp_hash_pop(&bif->entries)))
			XFREE(MTYPE_ZEVPN_BPP, e);
		while ((evi = zebra_evpn_bpp_evi_list_pop(&bif->evis)))
			XFREE(MTYPE_ZEVPN_BPP_EVI, evi);
		zebra_evpn_bpp_if_free(bif);
	}
	zebra_evpn_bpp_if_hash_fini(&bpp_if_hash);
	bpp_inited = false;
}
