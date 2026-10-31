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
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_errors.h"
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
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP_NH, "EVPN-MH bridge-port protection member");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVPN_BPP_XLOG, "EVPN-MH bridge-port protection export");

enum zebra_evpn_bpp_state {
	ZEBRA_EVPN_BPP_DISABLED,
	ZEBRA_EVPN_BPP_PENDING,
	ZEBRA_EVPN_BPP_ACTIVE,
	ZEBRA_EVPN_BPP_WITHDRAWING,
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
PREDECL_HASH(zebra_evpn_bpp_nh_hash);
PREDECL_HASH(zebra_evpn_bpp_if_hash);
PREDECL_HASH(zebra_evpn_bpp_nh_id_hash);
PREDECL_HASH(zebra_evpn_bpp_xtab_nh_hash);
PREDECL_HASH(zebra_evpn_bpp_xtab_nhg_hash);
PREDECL_HASH(zebra_evpn_bpp_xtab_bind_hash);

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
	uint32_t nh_id;

	struct zebra_evpn_bpp_peer_hash_item item;
};

/* Shared Member: one ID per (type, VTEP), referenced by every Group. */
struct zebra_evpn_bpp_nh {
	uint8_t type;
	struct ipaddr vtep;
	struct ethaddr rmac;
	uint32_t nh_id;
	uint32_t ref_cnt;
	bool exported;

	struct zebra_evpn_bpp_nh_hash_item item;
	struct zebra_evpn_bpp_nh_id_hash_item id_item;
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

static int zebra_evpn_bpp_nh_cmp(const struct zebra_evpn_bpp_nh *n1,
				 const struct zebra_evpn_bpp_nh *n2)
{
	int ret;

	ret = numcmp(n1->type, n2->type);
	if (ret)
		return ret;
	return ipaddr_cmp(&n1->vtep, &n2->vtep);
}

static uint32_t zebra_evpn_bpp_nh_hash_key(const struct zebra_evpn_bpp_nh *nh)
{
	return jhash_1word(nh->type, ipaddr_hash(&nh->vtep));
}

DECLARE_HASH(zebra_evpn_bpp_nh_hash, struct zebra_evpn_bpp_nh, item, zebra_evpn_bpp_nh_cmp,
	     zebra_evpn_bpp_nh_hash_key);

static int zebra_evpn_bpp_nh_id_cmp(const struct zebra_evpn_bpp_nh *n1,
				    const struct zebra_evpn_bpp_nh *n2)
{
	return numcmp(n1->nh_id, n2->nh_id);
}

static uint32_t zebra_evpn_bpp_nh_id_key(const struct zebra_evpn_bpp_nh *nh)
{
	return jhash_1word(nh->nh_id, 0x62707069);
}

DECLARE_HASH(zebra_evpn_bpp_nh_id_hash, struct zebra_evpn_bpp_nh, id_item,
	     zebra_evpn_bpp_nh_id_cmp, zebra_evpn_bpp_nh_id_key);

/* Protection state of an ES bond: its entries and the ES-EVIs sent for it.
 * Keyed by zif; the ifindex is cleared before the interface cleanup runs.
 */
enum zebra_evpn_bpp_xstatus {
	ZEBRA_EVPN_BPP_X_NONE = 0,
	ZEBRA_EVPN_BPP_X_SENT,
	ZEBRA_EVPN_BPP_X_ACKED,
};

struct zebra_evpn_bpp_if {
	struct zebra_if *zif;
	struct zebra_evpn_bpp_hash_head entries;
	struct zebra_evpn_bpp_evi_list_head evis;
	struct zebra_evpn_bpp_peer_hash_head peers;
	enum zebra_evpn_bpp_state lifecycle_state;
	bool group_exported;
	enum zebra_evpn_bpp_xstatus export_status;

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

#define ZEBRA_EVPN_BPP_EXPORT_LOG_LEN	  512
#define ZEBRA_EVPN_BPP_EXPORT_LOG_MEMBERS 16

struct zebra_evpn_bpp_xtab_nh {
	uint32_t nh_id;
	uint8_t type;
	struct ipaddr vtep;
	struct ethaddr rmac;
	struct zebra_evpn_bpp_xtab_nh_hash_item item;
};

struct zebra_evpn_bpp_xtab_nhg {
	uint32_t nhg_id;
	esi_t esi;
	char esi_str[ESI_STR_LEN];
	uint32_t member_count;
	struct dplane_evpn_mh_member members[ES_VTEP_MAX_CNT];
	struct zebra_evpn_bpp_xtab_nhg_hash_item item;
};

struct zebra_evpn_bpp_xtab_bind {
	ifindex_t ifindex;
	char ifname[IFNAMSIZ];
	uint32_t backup_nhg_id;
	esi_t esi;
	char esi_str[ESI_STR_LEN];
	struct zebra_evpn_bpp_xtab_bind_hash_item item;
};

struct zebra_evpn_bpp_xlog {
	uint32_t seq;
	enum dplane_op_e op;
	bool is_del;
	bool replay;
	bool completed;
	enum zebra_dplane_result result;
	time_t time;
	uint32_t id;
	uint8_t type;
	char ifname[IFNAMSIZ];
	esi_t esi;
	struct ipaddr vtep;
	struct ethaddr rmac;
	uint32_t member_count;
	uint32_t member_ids[ZEBRA_EVPN_BPP_EXPORT_LOG_MEMBERS];
};

static int zebra_evpn_bpp_xtab_nh_cmp(const struct zebra_evpn_bpp_xtab_nh *a,
				      const struct zebra_evpn_bpp_xtab_nh *b)
{
	return numcmp(a->nh_id, b->nh_id);
}

static uint32_t zebra_evpn_bpp_xtab_nh_key(const struct zebra_evpn_bpp_xtab_nh *e)
{
	return jhash_1word(e->nh_id, 0x6270706e);
}

DECLARE_HASH(zebra_evpn_bpp_xtab_nh_hash, struct zebra_evpn_bpp_xtab_nh, item,
	     zebra_evpn_bpp_xtab_nh_cmp, zebra_evpn_bpp_xtab_nh_key);

static int zebra_evpn_bpp_xtab_nhg_cmp(const struct zebra_evpn_bpp_xtab_nhg *a,
				       const struct zebra_evpn_bpp_xtab_nhg *b)
{
	return numcmp(a->nhg_id, b->nhg_id);
}

static uint32_t zebra_evpn_bpp_xtab_nhg_key(const struct zebra_evpn_bpp_xtab_nhg *e)
{
	return jhash_1word(e->nhg_id, 0x62707067);
}

DECLARE_HASH(zebra_evpn_bpp_xtab_nhg_hash, struct zebra_evpn_bpp_xtab_nhg, item,
	     zebra_evpn_bpp_xtab_nhg_cmp, zebra_evpn_bpp_xtab_nhg_key);

static int zebra_evpn_bpp_xtab_bind_cmp(const struct zebra_evpn_bpp_xtab_bind *a,
					const struct zebra_evpn_bpp_xtab_bind *b)
{
	return numcmp(a->ifindex, b->ifindex);
}

static uint32_t zebra_evpn_bpp_xtab_bind_key(const struct zebra_evpn_bpp_xtab_bind *e)
{
	return jhash_1word((uint32_t)e->ifindex, 0x62707062);
}

DECLARE_HASH(zebra_evpn_bpp_xtab_bind_hash, struct zebra_evpn_bpp_xtab_bind, item,
	     zebra_evpn_bpp_xtab_bind_cmp, zebra_evpn_bpp_xtab_bind_key);

static struct zebra_evpn_bpp_if_hash_head bpp_if_hash;
static struct zebra_evpn_bpp_nh_hash_head bpp_nh_hash;
static struct zebra_evpn_bpp_nh_id_hash_head bpp_nh_retire;
static struct zebra_evpn_bpp_xtab_nh_hash_head bpp_xtab_nh;
static struct zebra_evpn_bpp_xtab_nhg_hash_head bpp_xtab_nhg;
static struct zebra_evpn_bpp_xtab_bind_hash_head bpp_xtab_bind;
static struct zebra_evpn_bpp_xlog bpp_xlog[ZEBRA_EVPN_BPP_EXPORT_LOG_LEN];
static uint32_t bpp_xlog_head;
static uint32_t bpp_xlog_count;
static uint32_t bpp_xlog_seq;
static uint32_t bpp_xlog_overruns;
static uint32_t bpp_xcnt_member_add;
static uint32_t bpp_xcnt_member_del;
static uint32_t bpp_xcnt_group_add;
static uint32_t bpp_xcnt_group_upd;
static uint32_t bpp_xcnt_group_del;
static uint32_t bpp_xcnt_bind_add;
static uint32_t bpp_xcnt_bind_del;
static bool bpp_inited;
static struct event *bpp_re_eval_ev;

static void zebra_evpn_bpp_export_sync(struct zebra_evpn_bpp_if *bif);
static const char *zebra_evpn_bpp_xstatus_str(enum zebra_evpn_bpp_xstatus st);

static const char *zebra_evpn_bpp_state_str(enum zebra_evpn_bpp_state state)
{
	switch (state) {
	case ZEBRA_EVPN_BPP_DISABLED:
		return "DISABLED";
	case ZEBRA_EVPN_BPP_PENDING:
		return "PENDING";
	case ZEBRA_EVPN_BPP_ACTIVE:
		return "ACTIVE";
	case ZEBRA_EVPN_BPP_WITHDRAWING:
		return "WITHDRAWING";
	}
	return "unknown";
}

static void zebra_evpn_bpp_lifecycle_set(struct zebra_evpn_bpp_if *bif,
					 enum zebra_evpn_bpp_state state)
{
	if (bif->lifecycle_state == state)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
		zlog_debug("bridge-port protection %s lifecycle %s -> %s", bif->zif->ifp->name,
			   zebra_evpn_bpp_state_str(bif->lifecycle_state),
			   zebra_evpn_bpp_state_str(state));
	bif->lifecycle_state = state;
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

static void zebra_evpn_bpp_group_id_ensure(struct zebra_evpn_es *es)
{
	if (!es || es->l3_nhg_id)
		return;

	es->l3_nhg_id = zebra_evpn_mh_nhid_alloc(NHG_TYPE_L3_BPP);
	if (!es->l3_nhg_id)
		flog_err(EC_ZEBRA_TM_EXHAUSTED_IDS,
			 "bridge-port protection group id alloc failed for es %s", es->esi_str);
	else if (zebra_evpn_mh_is_fdb_nh(es->l3_nhg_id)) {
		zebra_evpn_mh_id_channel_violation(es->l3_nhg_id, "protection Group alloc");
		zebra_evpn_mh_nhid_free(es->l3_nhg_id);
		es->l3_nhg_id = 0;
	}
}

static void zebra_evpn_bpp_group_id_release(struct zebra_evpn_es *es)
{
	struct zebra_evpn_bpp_nh key;

	if (!es || !es->l3_nhg_id)
		return;

	key = (struct zebra_evpn_bpp_nh){ .nh_id = es->l3_nhg_id };
	if (!zebra_evpn_bpp_nh_id_hash_find(&bpp_nh_retire, &key))
		zebra_evpn_mh_nhid_free(es->l3_nhg_id);
	es->l3_nhg_id = 0;
}

static uint32_t zebra_evpn_bpp_nh_ref(uint8_t type, const struct ipaddr *vtep)
{
	struct zebra_evpn_bpp_nh key = { .type = type, .vtep = *vtep };
	struct zebra_evpn_bpp_nh *nh;

	nh = zebra_evpn_bpp_nh_hash_find(&bpp_nh_hash, &key);
	if (!nh) {
		nh = XCALLOC(MTYPE_ZEVPN_BPP_NH, sizeof(*nh));
		nh->type = type;
		nh->vtep = *vtep;
		nh->nh_id = zebra_evpn_mh_nhid_alloc(NHG_TYPE_L3_BPP_NH);
		if (!nh->nh_id) {
			flog_err(EC_ZEBRA_TM_EXHAUSTED_IDS,
				 "bridge-port protection member id alloc failed for vtep %pIA",
				 vtep);
			XFREE(MTYPE_ZEVPN_BPP_NH, nh);
			return 0;
		}
		if (zebra_evpn_mh_is_fdb_nh(nh->nh_id)) {
			zebra_evpn_mh_id_channel_violation(nh->nh_id, "protection Member alloc");
			zebra_evpn_mh_nhid_free(nh->nh_id);
			XFREE(MTYPE_ZEVPN_BPP_NH, nh);
			return 0;
		}
		zebra_evpn_bpp_nh_hash_add(&bpp_nh_hash, nh);
	}

	nh->ref_cnt++;
	return nh->nh_id;
}

static void zebra_evpn_bpp_nh_deref(uint8_t type, const struct ipaddr *vtep)
{
	struct zebra_evpn_bpp_nh key = { .type = type, .vtep = *vtep };
	struct zebra_evpn_bpp_nh *nh;

	nh = zebra_evpn_bpp_nh_hash_find(&bpp_nh_hash, &key);
	if (!nh)
		return;

	if (nh->ref_cnt)
		nh->ref_cnt--;
	if (nh->ref_cnt)
		return;

	zebra_evpn_bpp_nh_hash_del(&bpp_nh_hash, nh);
	if (!nh->exported) {
		zebra_evpn_mh_nhid_free(nh->nh_id);
		XFREE(MTYPE_ZEVPN_BPP_NH, nh);
		return;
	}
	zebra_evpn_bpp_nh_id_hash_add(&bpp_nh_retire, nh);
}

static void zebra_evpn_bpp_peer_unlink(struct zebra_evpn_bpp_peer *peer)
{
	if (!peer->nh_id)
		return;

	zebra_evpn_bpp_nh_deref(peer->type, &peer->vtep);
	peer->nh_id = 0;
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
	zebra_evpn_bpp_group_id_ensure(zif->es_info.es);
	zebra_evpn_bpp_lifecycle_set(bif, ZEBRA_EVPN_BPP_PENDING);

	return bif;
}

/* The caller has emptied the entries and the ES-EVIs */
static void zebra_evpn_bpp_peer_flush(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_bpp_peer *peer;

	while ((peer = zebra_evpn_bpp_peer_hash_pop(&bif->peers))) {
		zebra_evpn_bpp_peer_unlink(peer);
		XFREE(MTYPE_ZEVPN_BPP_PEER, peer);
	}
}

static void zebra_evpn_bpp_if_free(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_es *es = bif->zif->es_info.es;

	zebra_evpn_bpp_if_hash_del(&bpp_if_hash, bif);
	zebra_evpn_bpp_peer_flush(bif);
	zebra_evpn_bpp_group_id_release(es);
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

static const char *zebra_evpn_bpp_xstatus_str(enum zebra_evpn_bpp_xstatus st)
{
	switch (st) {
	case ZEBRA_EVPN_BPP_X_NONE:
		return "none";
	case ZEBRA_EVPN_BPP_X_SENT:
		return "sent";
	case ZEBRA_EVPN_BPP_X_ACKED:
		return "acked";
	}
	return "none";
}

static struct zebra_evpn_bpp_xlog *zebra_evpn_bpp_xlog_push(enum dplane_op_e op, bool is_del,
							    uint32_t id)
{
	struct zebra_evpn_bpp_xlog *ent;

	if (bpp_xlog_count == ZEBRA_EVPN_BPP_EXPORT_LOG_LEN) {
		bpp_xlog_overruns++;
		bpp_xlog_count--;
	}
	ent = &bpp_xlog[bpp_xlog_head];
	memset(ent, 0, sizeof(*ent));
	ent->seq = ++bpp_xlog_seq;
	ent->op = op;
	ent->is_del = is_del;
	ent->id = id;
	ent->time = monotime(NULL);
	bpp_xlog_head = (bpp_xlog_head + 1) % ZEBRA_EVPN_BPP_EXPORT_LOG_LEN;
	if (bpp_xlog_count < ZEBRA_EVPN_BPP_EXPORT_LOG_LEN)
		bpp_xlog_count++;
	return ent;
}

static struct zebra_evpn_bpp_xlog *zebra_evpn_bpp_xlog_find(enum dplane_op_e op, uint32_t id,
							    const char *ifname)
{
	uint32_t i, idx, n;

	if (!bpp_xlog_count)
		return NULL;
	n = bpp_xlog_count;
	idx = (bpp_xlog_head + ZEBRA_EVPN_BPP_EXPORT_LOG_LEN - 1) % ZEBRA_EVPN_BPP_EXPORT_LOG_LEN;
	for (i = 0; i < n; i++) {
		struct zebra_evpn_bpp_xlog *ent = &bpp_xlog[idx];

		if (!ent->completed && ent->op == op) {
			if (op == DPLANE_OP_BR_PORT_UPDATE) {
				if (ifname && !strcmp(ent->ifname, ifname))
					return ent;
			} else if (ent->id == id) {
				return ent;
			}
		}
		idx = (idx + ZEBRA_EVPN_BPP_EXPORT_LOG_LEN - 1) % ZEBRA_EVPN_BPP_EXPORT_LOG_LEN;
	}
	return NULL;
}

static void zebra_evpn_bpp_xtab_nh_upsert(const struct zebra_evpn_bpp_nh *nh)
{
	struct zebra_evpn_bpp_xtab_nh key = { .nh_id = nh->nh_id };
	struct zebra_evpn_bpp_xtab_nh *e;

	e = zebra_evpn_bpp_xtab_nh_hash_find(&bpp_xtab_nh, &key);
	if (!e) {
		e = XCALLOC(MTYPE_ZEVPN_BPP_XLOG, sizeof(*e));
		e->nh_id = nh->nh_id;
		zebra_evpn_bpp_xtab_nh_hash_add(&bpp_xtab_nh, e);
	}
	e->type = nh->type;
	e->vtep = nh->vtep;
	e->rmac = nh->rmac;
}

static void zebra_evpn_bpp_xtab_nh_del(uint32_t nh_id)
{
	struct zebra_evpn_bpp_xtab_nh key = { .nh_id = nh_id };
	struct zebra_evpn_bpp_xtab_nh *e;

	e = zebra_evpn_bpp_xtab_nh_hash_find(&bpp_xtab_nh, &key);
	if (!e)
		return;
	zebra_evpn_bpp_xtab_nh_hash_del(&bpp_xtab_nh, e);
	XFREE(MTYPE_ZEVPN_BPP_XLOG, e);
}

static int zebra_evpn_bpp_peer_ptr_cmp(const void *a, const void *b)
{
	const struct zebra_evpn_bpp_peer *p1 = *(const struct zebra_evpn_bpp_peer *const *)a;
	const struct zebra_evpn_bpp_peer *p2 = *(const struct zebra_evpn_bpp_peer *const *)b;
	int ret;

	ret = numcmp(p1->type, p2->type);
	if (ret)
		return ret;
	return ipaddr_cmp(&p1->vtep, &p2->vtep);
}

static uint32_t zebra_evpn_bpp_group_members(struct zebra_evpn_bpp_if *bif,
					     struct dplane_evpn_mh_member *out, uint32_t max)
{
	struct zebra_evpn_bpp_peer **sorted;
	struct zebra_evpn_bpp_peer *peer;
	uint32_t n = zebra_evpn_bpp_peer_hash_count(&bif->peers);
	uint32_t i = 0, count = 0;

	if (!n)
		return 0;
	sorted = XCALLOC(MTYPE_TMP, n * sizeof(*sorted));
	frr_each (zebra_evpn_bpp_peer_hash, &bif->peers, peer)
		sorted[i++] = peer;
	qsort(sorted, n, sizeof(*sorted), zebra_evpn_bpp_peer_ptr_cmp);
	for (i = 0; i < n && count < max; i++) {
		if (!sorted[i]->nh_id)
			continue;
		out[count].nh_id = sorted[i]->nh_id;
		out[count].type = sorted[i]->type;
		out[count].vtep = sorted[i]->vtep;
		out[count].rmac = sorted[i]->rmac;
		count++;
	}
	XFREE(MTYPE_TMP, sorted);
	return count;
}

static void zebra_evpn_bpp_xtab_nhg_upsert(uint32_t nhg_id, const esi_t *esi, uint32_t member_count,
					   const struct dplane_evpn_mh_member *members)
{
	struct zebra_evpn_bpp_xtab_nhg key = { .nhg_id = nhg_id };
	struct zebra_evpn_bpp_xtab_nhg *e;

	e = zebra_evpn_bpp_xtab_nhg_hash_find(&bpp_xtab_nhg, &key);
	if (!e) {
		e = XCALLOC(MTYPE_ZEVPN_BPP_XLOG, sizeof(*e));
		e->nhg_id = nhg_id;
		zebra_evpn_bpp_xtab_nhg_hash_add(&bpp_xtab_nhg, e);
	}
	if (esi) {
		memcpy(&e->esi, esi, sizeof(esi_t));
		esi_to_str(esi, e->esi_str, sizeof(e->esi_str));
	}
	e->member_count = member_count > ES_VTEP_MAX_CNT ? ES_VTEP_MAX_CNT : member_count;
	if (e->member_count && members)
		memcpy(e->members, members, e->member_count * sizeof(*members));
}

static void zebra_evpn_bpp_xtab_nhg_del(uint32_t nhg_id)
{
	struct zebra_evpn_bpp_xtab_nhg key = { .nhg_id = nhg_id };
	struct zebra_evpn_bpp_xtab_nhg *e;

	e = zebra_evpn_bpp_xtab_nhg_hash_find(&bpp_xtab_nhg, &key);
	if (!e)
		return;
	zebra_evpn_bpp_xtab_nhg_hash_del(&bpp_xtab_nhg, e);
	XFREE(MTYPE_ZEVPN_BPP_XLOG, e);
}

static void zebra_evpn_bpp_member_enqueue(struct zebra_evpn_bpp_nh *nh, bool is_del)
{
	struct zebra_evpn_bpp_xlog *ent;

	dplane_evpn_mh_nh_update(is_del, nh->nh_id, nh->type, &nh->vtep, &nh->rmac);
	ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_EVPN_MH_NH_UPDATE, is_del, nh->nh_id);
	ent->type = nh->type;
	ent->vtep = nh->vtep;
	ent->rmac = nh->rmac;
	if (is_del) {
		bpp_xcnt_member_del++;
		nh->exported = false;
		zebra_evpn_bpp_xtab_nh_del(nh->nh_id);
	} else {
		if (nh->exported)
			; /* in-place RMAC */
		else
			bpp_xcnt_member_add++;
		nh->exported = true;
		zebra_evpn_bpp_xtab_nh_upsert(nh);
	}
}

static void zebra_evpn_bpp_group_enqueue(struct zebra_evpn_es *es, struct zebra_evpn_bpp_if *bif,
					 bool is_del)
{
	struct dplane_evpn_mh_member members[ES_VTEP_MAX_CNT];
	struct zebra_evpn_bpp_xlog *ent;
	uint32_t count = 0, i;

	if (!es || !es->l3_nhg_id)
		return;
	if (!is_del)
		count = zebra_evpn_bpp_group_members(bif, members, ES_VTEP_MAX_CNT);
	if (!is_del && !count)
		return;
	if (!is_del && bif->group_exported) {
		struct zebra_evpn_bpp_xtab_nhg key = { .nhg_id = es->l3_nhg_id };
		struct zebra_evpn_bpp_xtab_nhg *cur;

		cur = zebra_evpn_bpp_xtab_nhg_hash_find(&bpp_xtab_nhg, &key);
		if (cur && cur->member_count == count &&
		    !memcmp(cur->members, members, count * sizeof(*members)))
			return;
	}

	dplane_evpn_mh_nhg_update(is_del, es->l3_nhg_id, &es->esi, count, count ? members : NULL);
	ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_EVPN_MH_NHG_UPDATE, is_del, es->l3_nhg_id);
	memcpy(&ent->esi, &es->esi, sizeof(esi_t));
	ent->member_count = count;
	for (i = 0; i < count && i < ZEBRA_EVPN_BPP_EXPORT_LOG_MEMBERS; i++)
		ent->member_ids[i] = members[i].nh_id;
	if (is_del) {
		struct zebra_evpn_bpp_nh key, *hold;

		bpp_xcnt_group_del++;
		bif->group_exported = false;
		zebra_evpn_bpp_xtab_nhg_del(es->l3_nhg_id);
		key = (struct zebra_evpn_bpp_nh){ .nh_id = es->l3_nhg_id };
		if (!zebra_evpn_bpp_nh_id_hash_find(&bpp_nh_retire, &key)) {
			hold = XCALLOC(MTYPE_ZEVPN_BPP_NH, sizeof(*hold));
			hold->nh_id = es->l3_nhg_id;
			zebra_evpn_bpp_nh_id_hash_add(&bpp_nh_retire, hold);
		}
		es->l3_nhg_id = 0;
	} else {
		if (bif->group_exported)
			bpp_xcnt_group_upd++;
		else
			bpp_xcnt_group_add++;
		bif->group_exported = true;
		zebra_evpn_bpp_xtab_nhg_upsert(es->l3_nhg_id, &es->esi, count, members);
	}
}

static void zebra_evpn_bpp_member_dels(void)
{
	struct zebra_evpn_bpp_nh *nh;

	frr_each_safe (zebra_evpn_bpp_nh_id_hash, &bpp_nh_retire, nh) {
		if (!nh->exported)
			continue;
		zebra_evpn_bpp_member_enqueue(nh, true);
	}
}

static void zebra_evpn_bpp_member_adds(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_bpp_peer *peer;
	struct zebra_evpn_bpp_nh key, *nh;

	frr_each (zebra_evpn_bpp_peer_hash, &bif->peers, peer) {
		if (!peer->nh_id)
			continue;
		key = (struct zebra_evpn_bpp_nh){ .type = peer->type, .vtep = peer->vtep };
		nh = zebra_evpn_bpp_nh_hash_find(&bpp_nh_hash, &key);
		if (!nh)
			continue;
		if (nh->exported && !memcmp(&nh->rmac, &peer->rmac, ETH_ALEN))
			continue;
		nh->rmac = peer->rmac;
		zebra_evpn_bpp_member_enqueue(nh, false);
	}
}

static void zebra_evpn_bpp_export_sync(struct zebra_evpn_bpp_if *bif)
{
	struct zebra_evpn_es *es = bif->zif->es_info.es;
	bool bound = zebra_evpn_bpp_if_bound(bif);
	bool was_bound = es && es->bpp_backup_nhg_id;

	if (bound) {
		zebra_evpn_bpp_group_id_ensure(es);
		zebra_evpn_bpp_member_adds(bif);
		zebra_evpn_bpp_group_enqueue(es, bif, false);
		zebra_evpn_bpp_member_dels();
		if (es)
			zebra_evpn_es_br_port_update(es);
		if (bif->export_status == ZEBRA_EVPN_BPP_X_NONE)
			bif->export_status = ZEBRA_EVPN_BPP_X_SENT;
		zebra_evpn_bpp_lifecycle_set(bif, ZEBRA_EVPN_BPP_ACTIVE);
	} else {
		if (was_bound || bif->group_exported)
			zebra_evpn_bpp_lifecycle_set(bif, ZEBRA_EVPN_BPP_WITHDRAWING);
		if (was_bound && es)
			zebra_evpn_es_br_port_update(es);
		if (bif->group_exported)
			zebra_evpn_bpp_group_enqueue(es, bif, true);
		zebra_evpn_bpp_member_dels();
		bif->export_status = ZEBRA_EVPN_BPP_X_NONE;
		zebra_evpn_bpp_lifecycle_set(bif, zebra_evpn_bpp_hash_count(&bif->entries)
							  ? ZEBRA_EVPN_BPP_PENDING
							  : ZEBRA_EVPN_BPP_DISABLED);
	}
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
	zebra_evpn_bpp_export_sync(bif);
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
	if (bif) {
		zebra_evpn_bpp_group_id_ensure(es);
		zebra_evpn_bpp_evi_sync(bif);
	}
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

void zebra_evpn_bpp_es_clear(struct zebra_evpn_es *es)
{
	struct zebra_evpn_bpp_if *bif;

	if (!bpp_inited || !es || !es->zif)
		return;

	bif = zebra_evpn_bpp_if_find(es->zif);
	if (!bif)
		return;

	zebra_evpn_bpp_peer_flush(bif);
	zebra_evpn_bpp_apply_state(bif);
	zebra_evpn_bpp_group_id_release(es);
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
	else
		zebra_evpn_bpp_group_id_ensure(zif->es_info.es);

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

	if (zpeer->type != ZAPI_EVPN_BPP_PEER_L3) {
		flog_err(EC_ZEBRA_BAD_NHG_MESSAGE,
			 "bridge-port protection member type %u is not L3", zpeer->type);
		if (zmh_info)
			zmh_info->bpp_id_err++;
		return;
	}

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
		zebra_evpn_bpp_peer_unlink(peer);
		XFREE(MTYPE_ZEVPN_BPP_PEER, peer);
		zebra_evpn_bpp_apply_state(bif);
		return;
	}

	zebra_evpn_bpp_group_id_ensure(es);

	if (peer) {
		if (!memcmp(&peer->rmac, &zpeer->rmac, ETH_ALEN))
			return;
		if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
			zlog_debug("bridge-port protection %s member rmac %pEA -> %pEA vtep %pIA",
				   es->zif->ifp->name, &peer->rmac, &zpeer->rmac, &peer->vtep);
		memcpy(&peer->rmac, &zpeer->rmac, ETH_ALEN);
		zebra_evpn_bpp_apply_state(bif);
		return;
	}

	peer = XCALLOC(MTYPE_ZEVPN_BPP_PEER, sizeof(*peer));
	peer->type = zpeer->type;
	peer->vtep = zpeer->vtep;
	memcpy(&peer->rmac, &zpeer->rmac, ETH_ALEN);
	peer->nh_id = zebra_evpn_bpp_nh_ref(peer->type, &peer->vtep);
	if (!peer->nh_id) {
		XFREE(MTYPE_ZEVPN_BPP_PEER, peer);
		return;
	}
	zebra_evpn_bpp_peer_hash_add(&bif->peers, peer);

	if (IS_ZEBRA_DEBUG_EVPN_MH_PROT)
		zlog_debug("bridge-port protection %s member add esi %s vtep %pIA rmac %pEA",
			   es->zif->ifp->name, esi_to_str(&zpeer->esi, esi_buf, sizeof(esi_buf)),
			   &peer->vtep, &peer->rmac);

	zebra_evpn_bpp_apply_state(bif);
}

static const char *zebra_evpn_bpp_id_str(uint32_t id, char *buf, size_t buflen)
{
	if (!id) {
		strlcpy(buf, "-", buflen);
		return buf;
	}
	snprintfrr(buf, buflen, "0x%x", id);
	return buf;
}

static void zebra_evpn_bpp_json_id(json_object *json, const char *key, uint32_t id)
{
	char type_key[32];
	char ch_key[32];

	json_object_int_add(json, key, id);
	snprintfrr(type_key, sizeof(type_key), "%sType", key);
	snprintfrr(ch_key, sizeof(ch_key), "%sChannel", key);
	json_object_int_add(json, type_key, NHG_ID_TYPE(id));
	json_object_string_add(json, ch_key, zebra_evpn_mh_id_channel(id));
}

static void zebra_evpn_bpp_show_entry(struct vty *vty, const struct zebra_evpn_bpp *e)
{
	struct zebra_evpn_es *es = e->zif->es_info.es;
	char l3vni_str[16] = "-";
	char group_str[16];
	char reasons[128];

	if (e->l3vni)
		snprintfrr(l3vni_str, sizeof(l3vni_str), "%u", e->l3vni);
	zebra_evpn_bpp_id_str(es ? es->l3_nhg_id : 0, group_str, sizeof(group_str));

	vty_out(vty, "%-16s %-5u %-30s %-16s %-8s %-10s %-8s %s\n", e->zif->ifp->name, e->vid,
		es ? es->esi_str : "-", zebra_evpn_bpp_vrf_str(e), l3vni_str, group_str,
		zebra_evpn_bpp_state_str(e->state),
		zebra_evpn_bpp_reasons_str(e, reasons, sizeof(reasons)));
}

static void zebra_evpn_bpp_show_entry_detail(struct vty *vty, const struct zebra_evpn_bpp *e)
{
	struct zebra_evpn_es *es = e->zif->es_info.es;
	char l3vni_str[16] = "-";
	char group_str[16];
	char reasons[128];
	char age[32];

	if (e->l3vni)
		snprintfrr(l3vni_str, sizeof(l3vni_str), "%u", e->l3vni);
	zebra_evpn_bpp_id_str(es ? es->l3_nhg_id : 0, group_str, sizeof(group_str));

	vty_out(vty, "Interface: %s  VLAN: %u\n", e->zif->ifp->name, e->vid);
	vty_out(vty, "  ESI: %s\n", es ? es->esi_str : "-");
	vty_out(vty, "  VRF: %s  L3VNI: %s\n", zebra_evpn_bpp_vrf_str(e), l3vni_str);
	vty_out(vty, "  Group: %s type %u channel %s\n", group_str,
		es && es->l3_nhg_id ? NHG_ID_TYPE(es->l3_nhg_id) : 0,
		es && es->l3_nhg_id ? zebra_evpn_mh_id_channel(es->l3_nhg_id) : "-");
	{
		struct zebra_evpn_bpp_if *bif = zebra_evpn_bpp_if_find(e->zif);
		enum zebra_evpn_bpp_xstatus st = ZEBRA_EVPN_BPP_X_NONE;

		if (!e->pending_flags && e->state == ZEBRA_EVPN_BPP_ACTIVE && bif)
			st = bif->export_status;
		vty_out(vty, "  State: %s  Ready: %s  Export: %s\n",
			zebra_evpn_bpp_state_str(e->state), e->pending_flags ? "no" : "yes",
			zebra_evpn_bpp_xstatus_str(st));
	}
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
	{
		struct zebra_evpn_bpp_if *bif = zebra_evpn_bpp_if_find(e->zif);
		enum zebra_evpn_bpp_xstatus st = ZEBRA_EVPN_BPP_X_NONE;

		if (!e->pending_flags && e->state == ZEBRA_EVPN_BPP_ACTIVE && bif)
			st = bif->export_status;
		json_object_string_add(json_vlan, "exportStatus", zebra_evpn_bpp_xstatus_str(st));
	}

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
			if (es && es->l3_nhg_id)
				zebra_evpn_bpp_json_id(json_if, "groupId", es->l3_nhg_id);
			json_object_int_add(json_if, "idChannelErrors",
					    zmh_info ? zmh_info->bpp_id_err : 0);
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
	if (peer->nh_id)
		zebra_evpn_bpp_json_id(json_m, "nhId", peer->nh_id);
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

	state_str = zebra_evpn_bpp_state_str(bif->lifecycle_state);
	peers = zebra_evpn_bpp_peers_sorted(bif, &npeers);

	if (json) {
		json_es = json_object_new_object();
		json_object_string_add(json_es, "interface", zif->ifp->name);
		json_object_string_add(json_es, "state", state_str);
		json_object_boolean_add(json_es, "bound", zebra_evpn_bpp_if_bound(bif));
		json_object_int_add(json_es, "vlanCount", count);
		if (es->l3_nhg_id)
			zebra_evpn_bpp_json_id(json_es, "groupId", es->l3_nhg_id);
		json_object_int_add(json_es, "idChannelErrors",
				    zmh_info ? zmh_info->bpp_id_err : 0);
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
		vty_out(vty, "ESI %s  Interface %s  Group %s  State %s\n", es->esi_str,
			zif->ifp->name,
			zebra_evpn_bpp_id_str(es->l3_nhg_id, vni_str, sizeof(vni_str)), state_str);
		vty_out(vty, "  VLANs: %zu   VRFs: %s\n", count, nvrfs ? vrfs_str : "-");
		vty_out(vty, "  ES-EVI L3VNIs: %s\n", evis_str[0] ? evis_str : "-");
		vty_out(vty, "  %-11s %-40s %-7s %s\n", "NH-ID", "VTEP", "Family", "RMAC");
		for (i = 0; i < npeers; i++) {
			char vtep_buf[IPADDR_STRING_SIZE];

			ipaddr2str(&peers[i]->vtep, vtep_buf, sizeof(vtep_buf));
			vty_out(vty, "  %-11s %-40s %-7s %pEA\n",
				zebra_evpn_bpp_id_str(peers[i]->nh_id, vni_str, sizeof(vni_str)),
				vtep_buf, zebra_evpn_bpp_family_str(&peers[i]->vtep),
				&peers[i]->rmac);
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

bool zebra_evpn_bpp_es_bound(const struct zebra_evpn_es *es)
{
	if (!es || !es->zif)
		return false;
	return zebra_evpn_bpp_if_bound(zebra_evpn_bpp_if_find(es->zif));
}

void zebra_evpn_bpp_export_br_port(struct zebra_evpn_es *es, bool is_del)
{
	struct zebra_evpn_bpp_xlog *ent;
	struct zebra_evpn_bpp_xtab_bind key, *e;
	struct zebra_evpn_bpp_if *bif;
	uint32_t backup;

	if (!es || !es->zif || !es->zif->ifp)
		return;

	backup = is_del ? 0 : es->l3_nhg_id;
	ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_BR_PORT_UPDATE, is_del, backup);
	strlcpy(ent->ifname, es->zif->ifp->name, sizeof(ent->ifname));
	memcpy(&ent->esi, &es->esi, sizeof(esi_t));

	key = (struct zebra_evpn_bpp_xtab_bind){ .ifindex = es->zif->ifp->ifindex };
	e = zebra_evpn_bpp_xtab_bind_hash_find(&bpp_xtab_bind, &key);
	if (is_del) {
		bpp_xcnt_bind_del++;
		if (e) {
			zebra_evpn_bpp_xtab_bind_hash_del(&bpp_xtab_bind, e);
			XFREE(MTYPE_ZEVPN_BPP_XLOG, e);
		}
		return;
	}

	bpp_xcnt_bind_add++;
	if (!e) {
		e = XCALLOC(MTYPE_ZEVPN_BPP_XLOG, sizeof(*e));
		e->ifindex = es->zif->ifp->ifindex;
		zebra_evpn_bpp_xtab_bind_hash_add(&bpp_xtab_bind, e);
	}
	strlcpy(e->ifname, es->zif->ifp->name, sizeof(e->ifname));
	e->backup_nhg_id = es->l3_nhg_id;
	memcpy(&e->esi, &es->esi, sizeof(esi_t));
	esi_to_str(&es->esi, e->esi_str, sizeof(e->esi_str));

	bif = zebra_evpn_bpp_if_find(es->zif);
	if (bif && bif->export_status == ZEBRA_EVPN_BPP_X_NONE)
		bif->export_status = ZEBRA_EVPN_BPP_X_SENT;
}

void zebra_evpn_bpp_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	struct zebra_evpn_bpp_xlog *ent;
	struct zebra_evpn_bpp_nh key, *nh;
	const char *ifname;
	uint32_t id = 0;

	if (!ctx || !bpp_inited)
		return;

	op = dplane_ctx_get_op(ctx);
	ifname = dplane_ctx_get_ifname(ctx);
	if (op == DPLANE_OP_EVPN_MH_NH_UPDATE)
		id = dplane_ctx_get_evpn_mh_nh_id(ctx);
	else if (op == DPLANE_OP_EVPN_MH_NHG_UPDATE)
		id = dplane_ctx_get_evpn_mh_nhg_id(ctx);
	else if (op == DPLANE_OP_BR_PORT_UPDATE)
		id = dplane_ctx_get_br_port_backup_nhg_id(ctx);
	else if (op != DPLANE_OP_EVPN_MH_REPLAY_DONE)
		return;

	ent = zebra_evpn_bpp_xlog_find(op, id, ifname);
	if (ent) {
		ent->completed = true;
		ent->result = dplane_ctx_get_status(ctx);
	}

	if (op == DPLANE_OP_BR_PORT_UPDATE &&
	    dplane_ctx_get_status(ctx) == ZEBRA_DPLANE_REQUEST_SUCCESS && id &&
	    zebra_evpn_mh_id_is_l3_bpp(id)) {
		struct zebra_evpn_bpp_if *bif;

		frr_each (zebra_evpn_bpp_if_hash, &bpp_if_hash, bif) {
			if (!ifname || strcmp(bif->zif->ifp->name, ifname))
				continue;
			if (bif->export_status == ZEBRA_EVPN_BPP_X_SENT)
				bif->export_status = ZEBRA_EVPN_BPP_X_ACKED;
		}
	}

	if ((op == DPLANE_OP_EVPN_MH_NH_UPDATE || op == DPLANE_OP_EVPN_MH_NHG_UPDATE) &&
	    dplane_ctx_get_evpn_mh_is_del(ctx)) {
		key = (struct zebra_evpn_bpp_nh){ .nh_id = id };
		nh = zebra_evpn_bpp_nh_id_hash_find(&bpp_nh_retire, &key);
		if (nh) {
			zebra_evpn_bpp_nh_id_hash_del(&bpp_nh_retire, nh);
			XFREE(MTYPE_ZEVPN_BPP_NH, nh);
		}
	}
}

void zebra_evpn_bpp_replay(void)
{
	struct zebra_evpn_bpp_xtab_nh *nh;
	struct zebra_evpn_bpp_xtab_nhg *nhg;
	struct zebra_evpn_bpp_xtab_bind *bind;
	struct zebra_evpn_bpp_xlog *ent;
	struct zebra_evpn_es *es;
	struct ipaddr sph_filters[ES_VTEP_MAX_CNT];
	uint32_t i;

	if (!bpp_inited)
		return;

	memset(sph_filters, 0, sizeof(sph_filters));
	frr_each (zebra_evpn_bpp_xtab_nh_hash, &bpp_xtab_nh, nh) {
		dplane_evpn_mh_nh_update(false, nh->nh_id, nh->type, &nh->vtep, &nh->rmac);
		ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_EVPN_MH_NH_UPDATE, false, nh->nh_id);
		ent->replay = true;
		ent->type = nh->type;
		ent->vtep = nh->vtep;
		ent->rmac = nh->rmac;
	}
	frr_each (zebra_evpn_bpp_xtab_nhg_hash, &bpp_xtab_nhg, nhg) {
		dplane_evpn_mh_nhg_update(false, nhg->nhg_id, &nhg->esi, nhg->member_count,
					  nhg->members);
		ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_EVPN_MH_NHG_UPDATE, false, nhg->nhg_id);
		ent->replay = true;
		memcpy(&ent->esi, &nhg->esi, sizeof(esi_t));
		ent->member_count = nhg->member_count;
		for (i = 0; i < nhg->member_count && i < ZEBRA_EVPN_BPP_EXPORT_LOG_MEMBERS; i++)
			ent->member_ids[i] = nhg->members[i].nh_id;
	}
	frr_each (zebra_evpn_bpp_xtab_bind_hash, &bpp_xtab_bind, bind) {
		es = zebra_evpn_es_find(&bind->esi);
		if (!es || !es->zif || !es->zif->ifp)
			continue;
		dplane_br_port_update(es->zif->ifp, false, 0, sph_filters, bind->backup_nhg_id);
		ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_BR_PORT_UPDATE, false,
					       bind->backup_nhg_id);
		ent->replay = true;
		strlcpy(ent->ifname, bind->ifname, sizeof(ent->ifname));
		memcpy(&ent->esi, &bind->esi, sizeof(esi_t));
	}
	dplane_evpn_mh_replay_done();
	ent = zebra_evpn_bpp_xlog_push(DPLANE_OP_EVPN_MH_REPLAY_DONE, false, 0);
	ent->replay = true;
}

static json_object *zebra_evpn_bpp_json_xtab_member(const struct dplane_evpn_mh_member *m)
{
	json_object *json = json_object_new_object();
	char mac_buf[ETHER_ADDR_STRLEN];
	char vtep_buf[IPADDR_STRING_SIZE];

	json_object_int_add(json, "nhId", m->nh_id);
	json_object_int_add(json, "type", NHG_ID_TYPE(m->nh_id));
	json_object_string_add(json, "family", zebra_evpn_bpp_family_str(&m->vtep));
	ipaddr2str(&m->vtep, vtep_buf, sizeof(vtep_buf));
	json_object_string_add(json, "vtep", vtep_buf);
	prefix_mac2str(&m->rmac, mac_buf, sizeof(mac_buf));
	json_object_string_add(json, "rmac", mac_buf);
	return json;
}

void zebra_evpn_bpp_show_export(struct vty *vty, bool uj)
{
	json_object *json, *jt, *jm, *jg, *jb, *jlog, *je;
	struct zebra_evpn_bpp_xtab_nh *nh;
	struct zebra_evpn_bpp_xtab_nhg *nhg;
	struct zebra_evpn_bpp_xtab_bind *bind;
	uint32_t i, idx, n;
	char id_str[16];
	char mac_buf[ETHER_ADDR_STRLEN];
	char vtep_buf[IPADDR_STRING_SIZE];

	if (!uj) {
		vty_out(vty, "Use 'json' to display the export log\n");
		return;
	}

	json = json_object_new_object();
	jt = json_object_new_object();
	jm = json_object_new_object();
	jg = json_object_new_object();
	jb = json_object_new_object();
	jlog = json_object_new_array();

	frr_each (zebra_evpn_bpp_xtab_nh_hash, &bpp_xtab_nh, nh) {
		json_object *e = json_object_new_object();

		json_object_int_add(e, "nhId", nh->nh_id);
		json_object_int_add(e, "type", NHG_ID_TYPE(nh->nh_id));
		json_object_string_add(e, "family", zebra_evpn_bpp_family_str(&nh->vtep));
		ipaddr2str(&nh->vtep, vtep_buf, sizeof(vtep_buf));
		json_object_string_add(e, "vtep", vtep_buf);
		prefix_mac2str(&nh->rmac, mac_buf, sizeof(mac_buf));
		json_object_string_add(e, "rmac", mac_buf);
		snprintfrr(id_str, sizeof(id_str), "0x%x", nh->nh_id);
		json_object_object_add(jm, id_str, e);
	}
	frr_each (zebra_evpn_bpp_xtab_nhg_hash, &bpp_xtab_nhg, nhg) {
		json_object *e = json_object_new_object();
		json_object *arr = json_object_new_array();
		uint32_t mi;

		json_object_int_add(e, "nhgId", nhg->nhg_id);
		json_object_int_add(e, "type", NHG_ID_TYPE(nhg->nhg_id));
		json_object_string_add(e, "esi", nhg->esi_str);
		for (mi = 0; mi < nhg->member_count; mi++)
			json_object_array_add(arr,
					      zebra_evpn_bpp_json_xtab_member(&nhg->members[mi]));
		json_object_object_add(e, "members", arr);
		snprintfrr(id_str, sizeof(id_str), "0x%x", nhg->nhg_id);
		json_object_object_add(jg, id_str, e);
	}
	frr_each (zebra_evpn_bpp_xtab_bind_hash, &bpp_xtab_bind, bind) {
		json_object *e = json_object_new_object();

		json_object_int_add(e, "ifindex", bind->ifindex);
		json_object_string_add(e, "interface", bind->ifname);
		json_object_int_add(e, "backupNhgId", bind->backup_nhg_id);
		json_object_int_add(e, "type", NHG_ID_TYPE(bind->backup_nhg_id));
		json_object_string_add(e, "esi", bind->esi_str);
		json_object_object_add(jb, bind->ifname, e);
	}

	json_object_object_add(jt, "members", jm);
	json_object_object_add(jt, "groups", jg);
	json_object_object_add(jt, "bindings", jb);
	json_object_object_add(json, "tables", jt);

	n = bpp_xlog_count;
	idx = (bpp_xlog_head + ZEBRA_EVPN_BPP_EXPORT_LOG_LEN - n) % ZEBRA_EVPN_BPP_EXPORT_LOG_LEN;
	for (i = 0; i < n; i++) {
		struct zebra_evpn_bpp_xlog *ent = &bpp_xlog[idx];
		json_object *ids;
		uint32_t mi;

		je = json_object_new_object();
		json_object_int_add(je, "seq", ent->seq);
		json_object_string_add(je, "op", dplane_op2str(ent->op));
		json_object_string_add(je, "action", ent->is_del ? "del" : "add");
		json_object_int_add(je, "id", ent->id);
		if (ent->replay)
			json_object_boolean_add(je, "replay", true);
		if (ent->ifname[0])
			json_object_string_add(je, "interface", ent->ifname);
		if (!ipaddr_is_zero(&ent->vtep)) {
			ipaddr2str(&ent->vtep, vtep_buf, sizeof(vtep_buf));
			json_object_string_add(je, "vtep", vtep_buf);
		}
		if (ent->member_count) {
			ids = json_object_new_array();
			for (mi = 0;
			     mi < ent->member_count && mi < ZEBRA_EVPN_BPP_EXPORT_LOG_MEMBERS; mi++)
				json_object_array_add(ids,
						      json_object_new_int64(ent->member_ids[mi]));
			json_object_object_add(je, "memberIds", ids);
		}
		json_object_boolean_add(je, "completed", ent->completed);
		if (ent->completed)
			json_object_string_add(je, "result", dplane_res2str(ent->result));
		json_object_array_add(jlog, je);
		idx = (idx + 1) % ZEBRA_EVPN_BPP_EXPORT_LOG_LEN;
	}
	json_object_object_add(json, "log", jlog);

	je = json_object_new_object();
	json_object_int_add(je, "memberAdd", bpp_xcnt_member_add);
	json_object_int_add(je, "memberDel", bpp_xcnt_member_del);
	json_object_int_add(je, "groupAdd", bpp_xcnt_group_add);
	json_object_int_add(je, "groupUpdate", bpp_xcnt_group_upd);
	json_object_int_add(je, "groupDel", bpp_xcnt_group_del);
	json_object_int_add(je, "bindingAdd", bpp_xcnt_bind_add);
	json_object_int_add(je, "bindingDel", bpp_xcnt_bind_del);
	json_object_int_add(je, "logOverruns", bpp_xlog_overruns);
	json_object_int_add(je, "membersLive", zebra_evpn_bpp_nh_hash_count(&bpp_nh_hash));
	json_object_int_add(je, "pendingDeletes", zebra_evpn_bpp_nh_id_hash_count(&bpp_nh_retire));
	json_object_object_add(json, "counters", je);

	vty_json(vty, json);
}

void zebra_evpn_bpp_init(void)
{
	zebra_evpn_bpp_if_hash_init(&bpp_if_hash);
	zebra_evpn_bpp_nh_hash_init(&bpp_nh_hash);
	zebra_evpn_bpp_nh_id_hash_init(&bpp_nh_retire);
	zebra_evpn_bpp_xtab_nh_hash_init(&bpp_xtab_nh);
	zebra_evpn_bpp_xtab_nhg_hash_init(&bpp_xtab_nhg);
	zebra_evpn_bpp_xtab_bind_hash_init(&bpp_xtab_bind);
	bpp_inited = true;
}

void zebra_evpn_bpp_terminate(void)
{
	struct zebra_evpn_bpp_if *bif;
	struct zebra_evpn_bpp *e;
	struct zebra_evpn_bpp_evi *evi;
	struct zebra_evpn_bpp_nh *nh;
	struct zebra_evpn_bpp_xtab_nh *xnh;
	struct zebra_evpn_bpp_xtab_nhg *xnhg;
	struct zebra_evpn_bpp_xtab_bind *xbind;

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
	while ((nh = zebra_evpn_bpp_nh_hash_pop(&bpp_nh_hash))) {
		zebra_evpn_mh_nhid_free(nh->nh_id);
		XFREE(MTYPE_ZEVPN_BPP_NH, nh);
	}
	while ((nh = zebra_evpn_bpp_nh_id_hash_pop(&bpp_nh_retire))) {
		zebra_evpn_mh_nhid_free(nh->nh_id);
		XFREE(MTYPE_ZEVPN_BPP_NH, nh);
	}
	while ((xnh = zebra_evpn_bpp_xtab_nh_hash_pop(&bpp_xtab_nh)))
		XFREE(MTYPE_ZEVPN_BPP_XLOG, xnh);
	while ((xnhg = zebra_evpn_bpp_xtab_nhg_hash_pop(&bpp_xtab_nhg)))
		XFREE(MTYPE_ZEVPN_BPP_XLOG, xnhg);
	while ((xbind = zebra_evpn_bpp_xtab_bind_hash_pop(&bpp_xtab_bind)))
		XFREE(MTYPE_ZEVPN_BPP_XLOG, xbind);
	zebra_evpn_bpp_if_hash_fini(&bpp_if_hash);
	zebra_evpn_bpp_nh_hash_fini(&bpp_nh_hash);
	zebra_evpn_bpp_nh_id_hash_fini(&bpp_nh_retire);
	zebra_evpn_bpp_xtab_nh_hash_fini(&bpp_xtab_nh);
	zebra_evpn_bpp_xtab_nhg_hash_fini(&bpp_xtab_nhg);
	zebra_evpn_bpp_xtab_bind_hash_fini(&bpp_xtab_bind);
	bpp_inited = false;
}
