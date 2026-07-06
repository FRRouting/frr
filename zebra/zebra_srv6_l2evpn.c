// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 L2 EVPN — Multi-VLAN-to-EVI mapping (VXLAN-decoupled).
 *
 * Phase 1: EVI-bundle table management + dataplane-backend op scaffolding.
 * See srv6_l2evpn_vlan_to_evi_design.md.
 *
 * Copyright (C) 2026 FRR contributors.
 */

#include <zebra.h>

#include "lib/memory.h"
#include "lib/hash.h"
#include "lib/jhash.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/vty.h"
#include "lib/if.h"
#include "lib/monotime.h"

#include "zebra/debug.h"
#include "zebra/zebra_srv6_l2evpn.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_srl2.h"
#include "zebra/zebra_dplane.h"
#include "zebra/interface.h"
#include "zebra/zebra_l2.h"
#include "zebra/rt_netlink.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_srv6.h"

#include "lib/srv6.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SRV6_EVI, "SRv6 L2 EVPN EVI");
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SRV6_EVI_BD, "SRv6 L2 EVPN EVI member BD");

DEFINE_QOBJ_TYPE(zebra_srv6_evi);

/* Global EVI table: vni -> struct zebra_srv6_evi */
static struct srv6_evi_htab_head srv6_evi_table[1];
static bool srv6_evi_inited;

/* -------------------------------------------------------------------------- */
/* Backend op scaffolding                                                      */
/*                                                                             */
/* Phase 1 provides placeholder ops so the vtable wiring compiles and EVIs can */
/* be created/configured.  The op bodies are migrated from the existing VXLAN  */
/* path (VXLAN backend) and from the srl2/DT2U path (SRv6 backend) in later    */
/* phases — see design §11 (migration inventory).                              */
/* -------------------------------------------------------------------------- */

/*
 * NOTE: the EVI VLAN is now bound onto each overlay (srl2 / bum-srl2) bridge
 * port INSIDE zebra_srl2_get_or_create() — while the port is still down and
 * freshly enslaved, before it is brought up (canonical ordering).  The former
 * standalone srv6_evi_port_vlan_bind() helper was removed because binding the
 * VLAN after the port was already up did not stick.
 */

/* ----- SRv6 backend (op bodies filled in phase 3/4) ----- */

static int srv6_dp_mac_install(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool was_static)
{
	struct zebra_srl2 *srl2;
	struct ipaddr vtep_ip = {};
	enum zebra_dplane_result res;
	bool sticky;

	/*
	 * SRv6 unicast (End.DT2U) MAC install — migrated from the inline
	 * has_srv6_sid branch in zebra_evpn_rem_mac_install() (design §11.2).
	 *
	 * Acquire (or reuse) the unicast srl2 encap interface for this MAC's
	 * SID, anchored on the EVI's bridge (zevpn->bridge_if) rather than a
	 * vxlan device.  One reference per SID: only acquire when not already
	 * holding one (srl2_ifindex == 0).
	 */
	if (!mac->has_srv6_sid)
		return 0;

	if (!zevpn->bridge_if) {
		zlog_warn("%s: SRv6 EVI %u has no bridge_if; cannot install MAC %pEA", __func__,
			  zevpn->vni, &mac->macaddr);
		return -1;
	}

	if (mac->srl2_ifindex == 0) {
		/* The EVI VLAN is bound inside get_or_create (while the port is
		 * down + enslaved, before it is brought up), so unicast frames
		 * reach the End.DT2U encap (default PVID would otherwise drop
		 * them).
		 */
		srl2 = zebra_srl2_get_or_create(&mac->srv6_sid, zevpn->bridge_if->ifindex,
						false /* is_bum */, zevpn->vid);
		if (srl2) {
			mac->srl2_ifindex = srl2->ifindex;
			/* The unicast srl2 oif now exists — re-report the EVI to
			 * bgpd so it installs the local End.DT2U decap SID on
			 * this (current) oif from its interface-add hook, where
			 * the interface is operative.
			 */
			zebra_evpn_send_add_to_client(zevpn);
		} else {
			zlog_warn("%s: failed to get/create srl2 for SID %pI6 on EVI %u", __func__,
				  &mac->srv6_sid, zevpn->vni);
			return -1;
		}
	}

	/*
	 * Program the bridge FDB entry with the srl2 (End.DT2U) interface as the
	 * egress, VLAN-scoped by zevpn->vid, with NO vxlan device.  We pass the
	 * EVI bridge as the ctx interface (for vrf/ns); the kernel provider
	 * routes to netlink_srl2_macfdb_encode() because srl2_ifindex != 0, which
	 * ignores the ctx ifindex and programs ndm_ifindex = srl2_ifindex.
	 */
	sticky = !!CHECK_FLAG(mac->flags, (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));

	res = dplane_rem_mac_add(zevpn->bridge_if, zevpn->bridge_if, zevpn->vid, &mac->macaddr,
				 zevpn->vni, &vtep_ip, sticky, 0 /* nhg_id */, was_static,
				 &mac->srv6_sid, mac->srl2_ifindex);
	return (res != ZEBRA_DPLANE_REQUEST_FAILURE) ? 0 : -1;
}

static int srv6_dp_mac_uninstall(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool force)
{
	struct ipaddr vtep_ip = {};
	enum zebra_dplane_result res;

	/*
	 * Withdraw the srl2 FDB entry only.  The srl2 *reference* is released on
	 * MAC removal by the existing path in zebra_evpn_mac.c (backend-agnostic,
	 * keyed on mac->srl2_ifindex), so we must not release it here or the
	 * refcount would underflow.
	 */
	if (mac->srl2_ifindex == 0 || !zevpn->bridge_if)
		return 0;

	res = dplane_rem_mac_del_srl2(zevpn->bridge_if, zevpn->bridge_if, zevpn->vid,
				      &mac->macaddr, zevpn->vni, &vtep_ip,
				      mac->has_srv6_sid ? &mac->srv6_sid : NULL, mac->srl2_ifindex);
	return (res != ZEBRA_DPLANE_REQUEST_FAILURE) ? 0 : -1;
}

static int srv6_dp_neigh_install(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool was_static)
{
	/* TODO(phase3): SRv6 neigh program. */
	return 0;
}

static int srv6_dp_neigh_uninstall(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool force)
{
	/* TODO(phase3): SRv6 neigh withdraw. */
	return 0;
}

static int srv6_dp_flood(struct zebra_evpn *zevpn, void *arg)
{
	/* TODO(phase4): bum-srl2 (DT2M/DT2U) setup/teardown, per-VLAN scope. */
	return 0;
}

static struct interface *srv6_dp_bridge(struct zebra_evpn *zevpn)
{
	/* TODO(phase3): return the EVI's vlan-aware bridge_if. */
	return NULL;
}

const struct zevpn_dp_ops zevpn_dp_ops_srv6 = {
	.name = "srv6",
	.mac_install = srv6_dp_mac_install,
	.mac_uninstall = srv6_dp_mac_uninstall,
	.neigh_install = srv6_dp_neigh_install,
	.neigh_uninstall = srv6_dp_neigh_uninstall,
	.flood_setup = srv6_dp_flood,
	.flood_teardown = srv6_dp_flood,
	.bridge = srv6_dp_bridge,
};

/* ----- VXLAN backend: verbatim wrappers over the existing functions ----- *
 *
 * These call the existing exported VXLAN dataplane functions unchanged, so
 * once the shared EVPN code is routed through zevpn->dp_ops (phase 3) the
 * VXLAN path is behavior-identical (design §11.4 step 1).  Call sites are NOT
 * converted in this phase, so these wrappers are not yet on the hot path.
 */
static int vxlan_dp_mac_install(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool was_static)
{
	return zebra_evpn_rem_mac_install(zevpn, mac, was_static);
}

static int vxlan_dp_mac_uninstall(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool force)
{
	return zebra_evpn_rem_mac_uninstall(zevpn, mac, force);
}

static int vxlan_dp_neigh_install(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool was_static)
{
	return zebra_evpn_rem_neigh_install(zevpn, n, was_static);
}

static int vxlan_dp_neigh_uninstall(struct zebra_evpn *zevpn, struct zebra_neigh *n, bool force)
{
	/* NOTE(phase3): the existing zebra_evpn_neigh_uninstall() is static in
	 * zebra_evpn_neigh.c.  When call sites are converted, export it (or add
	 * a public wrapper) and call it here.  Until then this is unreachable.
	 */
	return 0;
}

static int vxlan_dp_flood(struct zebra_evpn *zevpn, void *arg)
{
	/* NOTE(phase3/4): VXLAN BUM is head-end replication via
	 * zebra_evpn_vtep_install(); wrap it here when flood is routed through
	 * the vtable.  Unreachable until call sites are converted.
	 */
	return 0;
}

static struct interface *vxlan_dp_bridge(struct zebra_evpn *zevpn)
{
	/* TODO(phase3): return netdev master of zevpn->vxlan_if. */
	return NULL;
}

const struct zevpn_dp_ops zevpn_dp_ops_vxlan = {
	.name = "vxlan",
	.mac_install = vxlan_dp_mac_install,
	.mac_uninstall = vxlan_dp_mac_uninstall,
	.neigh_install = vxlan_dp_neigh_install,
	.neigh_uninstall = vxlan_dp_neigh_uninstall,
	.flood_setup = vxlan_dp_flood,
	.flood_teardown = vxlan_dp_flood,
	.bridge = vxlan_dp_bridge,
};

/* -------------------------------------------------------------------------- */
/* Service-type helpers                                                        */
/* -------------------------------------------------------------------------- */

const char *zevpn_l2_service2str(enum zevpn_l2_service svc)
{
	switch (svc) {
	case ZEVPN_SVC_VLAN_AWARE_BUNDLE:
		return "vlan-aware-bundle";
	case ZEVPN_SVC_VLAN_BASED:
		return "vlan-based";
	case ZEVPN_SVC_VLAN_BUNDLE:
		return "vlan-bundle";
	}
	return "unknown";
}

int zevpn_l2_service_str2enum(const char *s, enum zevpn_l2_service *out)
{
	if (!s || !out)
		return -1;
	if (strcmp(s, "vlan-aware-bundle") == 0)
		*out = ZEVPN_SVC_VLAN_AWARE_BUNDLE;
	else if (strcmp(s, "vlan-based") == 0)
		*out = ZEVPN_SVC_VLAN_BASED;
	else if (strcmp(s, "vlan-bundle") == 0)
		*out = ZEVPN_SVC_VLAN_BUNDLE;
	else
		return -1;
	return 0;
}

/* eth_tag policy: VLAN-aware bundle carries the VLAN; others carry 0. */
static uint32_t srv6_evi_eth_tag(const struct zebra_srv6_evi *evi, vlanid_t vid)
{
	return (evi->svc_type == ZEVPN_SVC_VLAN_AWARE_BUNDLE) ? (uint32_t)vid : 0;
}

/* -------------------------------------------------------------------------- */
/* Hash helpers                                                                */
/* -------------------------------------------------------------------------- */

static int srv6_evi_htab_cmp(const struct zebra_srv6_evi *a, const struct zebra_srv6_evi *b)
{
	if (a->vni < b->vni)
		return -1;
	if (a->vni > b->vni)
		return 1;
	return 0;
}

static uint32_t srv6_evi_htab_hash(const struct zebra_srv6_evi *evi)
{
	return jhash_1word(evi->vni, 0);
}

DECLARE_HASH(srv6_evi_htab, struct zebra_srv6_evi, htab_item, srv6_evi_htab_cmp,
	     srv6_evi_htab_hash);

/* -------------------------------------------------------------------------- */
/* EVI lifecycle                                                               */
/* -------------------------------------------------------------------------- */

struct zebra_srv6_evi *zebra_srv6_evi_lookup(vni_t vni)
{
	struct zebra_srv6_evi key = {};

	if (!srv6_evi_inited)
		return NULL;
	key.vni = vni;
	return srv6_evi_htab_find(srv6_evi_table, &key);
}

struct zebra_srv6_evi *zebra_srv6_evi_get_or_create(vni_t vni)
{
	struct zebra_srv6_evi *evi;

	evi = zebra_srv6_evi_lookup(vni);
	if (evi)
		return evi;

	evi = XCALLOC(MTYPE_ZEBRA_SRV6_EVI, sizeof(*evi));
	evi->vni = vni;
	evi->dp_backend = ZEVPN_DP_SRV6;
	evi->svc_type = ZEVPN_SVC_VLAN_AWARE_BUNDLE; /* preferred default */
	evi->dp_ops = &zevpn_dp_ops_srv6;
	evi_bds_init(&evi->bds);
	QOBJ_REG(evi, zebra_srv6_evi);

	srv6_evi_htab_add(srv6_evi_table, evi);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: created SRv6 EVI %u (svc %s)", __func__, vni,
			   zevpn_l2_service2str(evi->svc_type));
	return evi;
}

static void srv6_evi_bd_free(struct zebra_srv6_evi_bd *bd)
{
	/* TODO(phase2/3): tear down the backing zevpn + dataplane. */
	XFREE(MTYPE_ZEBRA_SRV6_EVI_BD, bd);
}

/* Free an EVI's contents + struct WITHOUT touching the hash table. */
static void srv6_evi_free(struct zebra_srv6_evi *evi)
{
	struct zebra_srv6_evi_bd *bd;

	if (!evi)
		return;

	frr_each_safe (evi_bds, &evi->bds, bd) {
		evi_bds_del(&evi->bds, bd);
		srv6_evi_bd_free(bd);
	}
	evi_bds_fini(&evi->bds);
	QOBJ_UNREG(evi);
	XFREE(MTYPE_ZEBRA_SRV6_EVI, evi);
}

void zebra_srv6_evi_del(struct zebra_srv6_evi *evi)
{
	struct zebra_evpn *zevpn;
	ifindex_t bridge_ifindex = 0;

	if (!evi)
		return;

	/* Capture the bridge ifindex before the zevpn is torn down so we can
	 * force-delete this EVI's srl2/bum-srl2 interfaces afterwards.
	 */
	if (evi->bridge_if)
		bridge_ifindex = evi->bridge_if->ifindex;

	/* Tear down the realized SRv6-backed zebra_evpn (withdraw from BGP). */
	zevpn = zebra_evpn_lookup(evi->vni);
	if (zevpn && zevpn->dp_ops == &zevpn_dp_ops_srv6) {
		zebra_evpn_send_del_to_client(zevpn);
		/*
		 * Free neighbors, MACs and remote VTEPs BEFORE zebra_evpn_del():
		 * that only frees the (assumed-empty) hash containers - the MAC
		 * hash with a NULL free-func and the VTEP list not at all - so
		 * without these the remote VTEP/MAC entries and their list nodes
		 * leak.  Mirrors zebra_evpn_cleanup_all().
		 */
		zebra_evpn_neigh_del_all(zevpn, 1, 0, DEL_ALL_NEIGH, NULL);
		zebra_evpn_mac_del_all(zevpn, 1, 0, DEL_ALL_MAC, NULL);
		zebra_evpn_vtep_del_all(zevpn, 1, NULL);
		zebra_evpn_del(zevpn);
	}

	/*
	 * Remove this EVI's srl2/bum-srl2 interfaces.  They are created
	 * on-demand (refcounted by MAC/BUM routes), but the bulk zevpn delete
	 * above does not reliably drop those references, so force-delete every
	 * srl2 slaved to this EVI's bridge.  Otherwise the interfaces linger
	 * and a later re-add fails with "File exists" on creation.
	 */
	if (bridge_ifindex)
		zebra_srl2_release_all_on_bridge(bridge_ifindex);

	/* The dedicated local decap interface was just force-deleted above. */
	evi->local_decap_oif = 0;

	/*
	 * Return this EVI's per-EVI service SIDs to the SID-manager pool.  They
	 * were allocated via get_srv6_sid() keyed by {behavior, dt2_vni}, so
	 * release with the same contexts.  No-op if never allocated.
	 */
	if (evi->dt2u_sid_valid || evi->dt2m_sid_valid) {
		struct srv6_sid_ctx ctx = {};

		ctx.vrf_id = VRF_DEFAULT;
		ctx.dt2_vni = evi->vni;

		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2U;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2M;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		evi->dt2u_sid_valid = false;
		evi->dt2m_sid_valid = false;
	}

	srv6_evi_htab_del(srv6_evi_table, evi);
	srv6_evi_free(evi);
}

/* -------------------------------------------------------------------------- */
/* Member-VLAN management                                                      */
/* -------------------------------------------------------------------------- */

struct zebra_srv6_evi_bd *zebra_srv6_evi_vlan_find(struct zebra_srv6_evi *evi, vlanid_t vid)
{
	struct zebra_srv6_evi_bd *bd;

	if (!evi)
		return NULL;
	frr_each (evi_bds, &evi->bds, bd)
		if (bd->vid == vid)
			return bd;
	return NULL;
}

struct zebra_srv6_evi_bd *zebra_srv6_evi_vlan_add(struct zebra_srv6_evi *evi, vlanid_t vid)
{
	struct zebra_srv6_evi_bd *bd;

	if (!evi)
		return NULL;

	bd = zebra_srv6_evi_vlan_find(evi, vid);
	if (bd)
		return bd; /* idempotent */

	/* VLAN-based service is single-VLAN per EVI. */
	if (evi->svc_type == ZEVPN_SVC_VLAN_BASED && evi_bds_count(&evi->bds) >= 1) {
		zlog_warn("%s: EVI %u is vlan-based; only one VLAN allowed", __func__, evi->vni);
		return NULL;
	}

	bd = XCALLOC(MTYPE_ZEBRA_SRV6_EVI_BD, sizeof(*bd));
	bd->vid = vid;
	bd->eth_tag = srv6_evi_eth_tag(evi, vid);
	bd->zevpn = NULL; /* backing zebra_evpn created in phase 2/3 */

	evi_bds_add_tail(&evi->bds, bd);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: EVI %u + vlan %u (eth_tag %u)", __func__, evi->vni, vid,
			   bd->eth_tag);

	/* Realize once we have a bridge (first member VLAN drives the
	 * per-EVI zebra_evpn vid for now; see realize() note).
	 */
	zebra_srv6_evi_realize(evi);
	return bd;
}

int zebra_srv6_evi_vlan_del(struct zebra_srv6_evi *evi, vlanid_t vid)
{
	struct zebra_srv6_evi_bd *bd;

	bd = zebra_srv6_evi_vlan_find(evi, vid);
	if (!bd)
		return -1;
	evi_bds_del(&evi->bds, bd);
	srv6_evi_bd_free(bd);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Config setters                                                              */
/* -------------------------------------------------------------------------- */

void zebra_srv6_evi_set_locator(struct zebra_srv6_evi *evi, const char *locator)
{
	if (!evi || !locator)
		return;

	/* No change → nothing to do. */
	if (strncmp(evi->locator, locator, sizeof(evi->locator)) == 0)
		return;

	/*
	 * Runtime locator reassignment (e.g. `evi N locator LOC-A` -> `locator
	 * LOC-B`).  If this EVI already holds DT2U/DT2M service SIDs drawn from
	 * the OLD locator, release them (and the local decap srl2 keyed by the
	 * old DT2U SID) and clear the valid flags BEFORE switching the name.
	 * Otherwise srv6_evi_alloc_sids() is idempotent and short-circuits on
	 * the still-"valid" stale SIDs, so realize() would keep advertising the
	 * old locator's SIDs and never draw from the new locator's block.
	 * Mirrors zebra_srv6_evi_on_locator_update() (the format-change path).
	 */
	if (evi->dt2u_sid_valid || evi->dt2m_sid_valid) {
		struct srv6_sid_ctx ctx = {};

		if (evi->local_decap_oif != 0) {
			zebra_srl2_release(&evi->local_decap_sid);
			evi->local_decap_oif = 0;
			memset(&evi->local_decap_sid, 0, sizeof(evi->local_decap_sid));
		}

		/* Release the old SIDs from the OLD locator (evi->locator still
		 * holds the old name here).
		 */
		ctx.vrf_id = VRF_DEFAULT;
		ctx.dt2_vni = evi->vni;
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2U;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2M;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		evi->dt2u_sid_valid = false;
		evi->dt2m_sid_valid = false;
	}

	strlcpy(evi->locator, locator, sizeof(evi->locator));

	/*
	 * Reallocate from the new locator and re-notify bgpd.  Safe to call
	 * unconditionally: realize() is a no-op until vni + bridge are set (on
	 * initial config the bridge is applied right after via set_bridge(),
	 * which realizes then); on a live reassignment the bridge already
	 * exists so the SIDs are drawn from the new locator immediately.
	 */
	zebra_srv6_evi_realize(evi);
}

void zebra_srv6_evi_set_bridge(struct zebra_srv6_evi *evi, struct interface *bridge_if)
{
	if (!evi)
		return;
	evi->bridge_if = bridge_if;
	zebra_srv6_evi_realize(evi);
}

int zebra_srv6_evi_set_service(struct zebra_srv6_evi *evi, enum zevpn_l2_service svc)
{
	struct zebra_srv6_evi_bd *bd;

	if (!evi)
		return -1;

	/*
	 * Block only a CHANGE of service-type once it has already been set.
	 * The service-type selects the Linux bridge model this EVI runs on —
	 *   vlan-bundle              -> VLAN-unaware bridge (vlan_filtering 0),
	 *                               C-tags transported transparently;
	 *   vlan-based / vlan-aware  -> VLAN-aware bridge   (vlan_filtering 1).
	 * That bridge property is owned by the operator and fixed when the
	 * bridge is created; FRR cannot safely flip it on a live bridge
	 * (flipping vlan_filtering flushes all VLAN/FDB state).  So changing
	 * the service-type after it has been configured cannot reconfigure the
	 * bound bridge and would leave an inconsistent datapath — require the
	 * operator to delete and recreate the EVI bound to a matching bridge.
	 *
	 * The FIRST setting is always allowed: the value carried before that is
	 * only a default placeholder, and blocking it (or blocking on the bound
	 * bridge) would break legitimate initial configuration.
	 */
	if (evi->svc_type_set && evi->svc_type != svc) {
		zlog_warn("%s: EVI %u: service-type change (%s -> %s) not allowed; delete and recreate the EVI bound to a matching bridge",
			  __func__, evi->vni, zevpn_l2_service2str(evi->svc_type),
			  zevpn_l2_service2str(svc));
		return -1;
	}

	evi->svc_type = svc;
	evi->svc_type_set = true;

	/* Re-derive eth_tag for existing members per the service type. */
	frr_each (evi_bds, &evi->bds, bd)
		bd->eth_tag = srv6_evi_eth_tag(evi, bd->vid);

	/* Idempotent no-op until vni + bridge are configured. */
	zebra_srv6_evi_realize(evi);
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Realize: materialize a zebra_evpn for an SRv6 EVI and announce to BGP        */
/* -------------------------------------------------------------------------- */

/*
 * Create (or update) the per-EVI zebra_evpn object for an SRv6 EVI and mark it
 * ready for BGP.  This is what makes remote MACIP (Type-2) for the EVI's VNI
 * resolve to a zebra_evpn whose dp_ops is the SRv6 backend, so MAC installs are
 * dispatched to srv6_dp_mac_install (no VXLAN device).
 *
 * NOTE (vlan-aware-bundle): zebra_evpn is keyed by VNI and carries a single
 * vid, so this realizes ONE zebra_evpn per EVI using the first member VLAN.
 * Full per-VLAN MAC separation for a multi-VLAN bundle needs per-(VNI,vid)
 * keying (eth_tag) and is the remaining bundle work (design §3/§4).  For
 * vlan-based service (one VLAN per EVI) this mapping is exact.
 */
/* -------------------------------------------------------------------------- */
/* Per-EVI SRv6 service SID allocation                                          */
/* -------------------------------------------------------------------------- */

/* True if 'sid' is already assigned (DT2U or DT2M) to some OTHER EVI. */
/*
 * Allocate one End.DT2U/End.DT2M service SID for this EVI through zebra's SRv6
 * SID manager.  The manager keys every SID by the full struct srv6_sid_ctx
 * (behavior + vrf_id + oif + dt2_vni), so passing dt2_vni = EVI VNI yields a
 * distinct function per EVI, and routing through the manager means per-EVI
 * SIDs share ONE namespace with VPWS End.DX2 (oif-keyed) and L3VPN End.DT4/DT6
 * (vrf-keyed) under the same locator — no cross-service collisions.
 *
 * get_srv6_sid() is idempotent by ctx (returns the existing SID on re-call) and
 * reserves the function in the locator's block.  Dynamic mode (sid_value=NULL)
 * does not return the address, so we recompose it from sid->func/wide_func.
 */
static bool srv6_evi_alloc_one_sid(struct zebra_srv6_evi *evi, struct srv6_locator *loc,
				   enum seg6local_action_t behavior, struct in6_addr *out)
{
	struct srv6_sid_ctx ctx = {};
	struct zebra_srv6_sid *zsid = NULL;

	ctx.behavior = behavior;
	ctx.vrf_id = VRF_DEFAULT;
	ctx.dt2_vni = evi->vni;

	/*
	 * get_srv6_sid() returns 0 when it hands back an existing SID whose
	 * value is unchanged, 1 when it allocates a NEW SID (or the value
	 * changed), and <0 on error.  Both 0 and 1 are success — *sid is
	 * populated in either case.  Accept both; only <0 (or a NULL sid) is a
	 * real failure.  (Previously this rejected the >0 "newly allocated"
	 * case, so the FIRST allocation attempt was always treated as declined
	 * and only a later retry — which hit the return-0 "existing" path —
	 * succeeded.  Bring-up recovered via repeated realize() passes, but the
	 * locator format-change path calls realize() exactly once, so the new
	 * uSID SID was rejected and the per-EVI decap never reallocated.)
	 */
	if (get_srv6_sid(&zsid, &ctx, NULL, evi->locator, false) < 0 || !zsid) {
		zlog_warn("%s: EVI %u: SID manager declined %s under locator %s", __func__,
			  evi->vni, seg6local_action2str(behavior), evi->locator);
		return false;
	}

	/* Dynamic allocation returns the SID object; recompose the address. */
	return zebra_srv6_l2_sid_compose(out, loc, zsid->func, zsid->wide_func);
}

/*
 * Allocate this EVI's End.DT2U (unicast) and End.DT2M (BUM) service SIDs via
 * the SID manager.  Idempotent; returns true once both SIDs are valid.
 */
static bool srv6_evi_alloc_sids(struct zebra_srv6_evi *evi)
{
	struct srv6_locator *loc;

	if (!evi)
		return false;
	if (evi->dt2u_sid_valid && evi->dt2m_sid_valid)
		return true;
	if (evi->locator[0] == '\0')
		return false;

	loc = zebra_srv6_locator_lookup(evi->locator);
	if (!loc) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: EVI %u locator %s not known yet", __func__, evi->vni,
				   evi->locator);
		return false;
	}

	if (!evi->dt2u_sid_valid &&
	    srv6_evi_alloc_one_sid(evi, loc, ZEBRA_SEG6_LOCAL_ACTION_END_DT2U, &evi->dt2u_sid))
		evi->dt2u_sid_valid = true;

	if (!evi->dt2m_sid_valid &&
	    srv6_evi_alloc_one_sid(evi, loc, ZEBRA_SEG6_LOCAL_ACTION_END_DT2M, &evi->dt2m_sid))
		evi->dt2m_sid_valid = true;

	if (evi->dt2u_sid_valid && evi->dt2m_sid_valid) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: EVI %u SIDs DT2U %pI6 DT2M %pI6 (locator %s)", __func__,
				   evi->vni, &evi->dt2u_sid, &evi->dt2m_sid, evi->locator);
		return true;
	}

	zlog_warn("%s: EVI %u: could not allocate per-EVI SIDs under locator %s", __func__,
		  evi->vni, evi->locator);
	return false;
}

void zebra_srv6_evi_realize(struct zebra_srv6_evi *evi)
{
	struct zebra_evpn *zevpn;
	struct zebra_srv6_evi_bd *bd;

	if (!evi || evi->vni == 0 || !evi->bridge_if)
		return; /* not enough config yet */

	zevpn = zebra_evpn_lookup(evi->vni);
	if (!zevpn)
		zevpn = zebra_evpn_add(evi->vni);
	if (!zevpn) {
		zlog_warn("%s: failed to create zebra_evpn for SRv6 EVI %u", __func__, evi->vni);
		return;
	}

	/* Flip this EVI's zebra_evpn to the SRv6 backend, anchored on the
	 * vlan-aware bridge (no vxlan_if).
	 */
	zevpn->dp_ops = &zevpn_dp_ops_srv6;
	zevpn->bridge_if = evi->bridge_if;

	/*
	 * Allocate this EVI's own End.DT2U/End.DT2M service SIDs from its
	 * locator (idempotent).  Local seg6local install on the EVI's
	 * srl2/bum-srl2 and reporting the SIDs up to bgpd are wired in the
	 * following sub-phases.
	 */
	srv6_evi_alloc_sids(evi);

	/*
	 * Point svi_if at the bridge so the VNI_ADD sent to BGP carries the
	 * bridge ifindex as the "SVI" — bgpd's bridge finder
	 * (bgp_find_bridge_from_vni_cb) then resolves the bridge via its
	 * "SVI is the bridge" path (svi->link_ifindex == 0), which is how
	 * bgpd locates the bridge to install the local DT2U/DT2M/DX2 decap
	 * SIDs.  Without this a pure-L2 SRv6 EVI (no real SVI) would leave
	 * bgpd unable to find the bridge.  No effect on VXLAN EVIs.
	 */
	if (!zevpn->svi_if)
		zevpn->svi_if = evi->bridge_if;

	/*
	 * Per-service VLAN binding for the single backing zebra_evpn:
	 *
	 *  vlan-based        : exactly one member VLAN -> tag the FDB with it.
	 *  vlan-bundle       : N VLANs collapse into ONE flat bridge-domain on a
	 *                      VLAN-unaware bridge; C-tags are transported
	 *                      transparently and the FDB is keyed by MAC only, so
	 *                      program vid 0 (no VLAN scoping). eth_tag is already
	 *                      0 for every member (srv6_evi_eth_tag()).
	 *  vlan-aware-bundle : per-(VNI,vid) demux is the remaining bundle work
	 *                      (design §3/§4); falls back to first-member vid here.
	 *
	 * Point every member BD at the backing zevpn so local-MAC origination
	 * (zebra_srv6_evi_vni_by_bridge_vlan) resolves regardless of member.
	 */
	if (evi->svc_type == ZEVPN_SVC_VLAN_BUNDLE)
		zevpn->vid = 0;
	else {
		bd = evi_bds_first(&evi->bds);
		if (bd)
			zevpn->vid = bd->vid;
	}

	/*
	 * C6: for vlan-bundle every overlay/decap/flood port MUST stay at vid 0
	 * so decapsulated and flooded frames keep their customer C-tag intact
	 * (transparent transport, RFC 7432 - 6.2).  Self-correct rather than abort
	 * to guard against a future refactor VLAN-scoping a bundle EVI.
	 */
	if (evi->svc_type == ZEVPN_SVC_VLAN_BUNDLE && zevpn->vid != 0) {
		zlog_warn("%s: EVI %u vlan-bundle must be vid 0 (was %u); forcing 0", __func__,
			  evi->vni, zevpn->vid);
		zevpn->vid = 0;
	}

	/*
	 * C2: single-FDB collapse.  For vlan-bundle (and vlan-based) all member
	 * BDs share the ONE backing zebra_evpn and its single MAC/neigh table;
	 * no per-BD zebra_evpn is created.  The bds list is retained only for
	 * configuration/reporting and kernel VLAN membership, never for FDB
	 * scoping.  Point every member BD at the backing zevpn so local-MAC
	 * origination (zebra_srv6_evi_vni_by_bridge_vlan) resolves for any member.
	 */
	{
		struct zebra_srv6_evi_bd *member;

		frr_each (evi_bds, &evi->bds, member)
			member->zevpn = zevpn;
	}

	/*
	 * The ZEBRA_VNI_ADD message encodes the VTEP/originator IP via
	 * stream_put_ipaddr(), which requires a valid address family.  An SRv6
	 * EVI has no VTEP, and a zeroed ipaddr has family IPADDR_NONE(0) — that
	 * makes stream_put_ipaddr() emit a malformed value and bgpd's decode
	 * abort the whole VNI_ADD ("unknown ip address-family: 0").  Set an
	 * IPv4 zero so the message is well-formed; bgpd substitutes its
	 * router-id as the originator when the VTEP IP is zero.
	 */
	if (zevpn->local_vtep_ip.ipa_type == IPADDR_NONE) {
		SET_IPADDR_V4(&zevpn->local_vtep_ip);
		zevpn->local_vtep_ip.ipaddr_v4.s_addr = INADDR_ANY;
	}

	/*
	 * Create this EVI's dedicated, locally-owned decap interface (§13).
	 * Done here (after zevpn->vid is set) so the VLAN bind uses the correct
	 * EVI VLAN, and before zebra_evpn_send_add_to_client() so the VNI_ADD
	 * carries the local decap oif.
	 *
	 * Used as the l2dev for BOTH the local End.DT2U and End.DT2M decap
	 * routes; lifetime = local EVI config (NOT any peer's advertisement).
	 * This decouples local decap from the peer-keyed srl2/bum-srl2 (FDB/flood
	 * only), so a peer withdraw or SID change never disturbs local decap, and
	 * decap installs immediately at realize without waiting for a peer.
	 *
	 * Created flood-OFF (is_bum=false → unicast brport flags): it is only an
	 * injection point for decapsulated frames into the bridge; the kernel
	 * does the FDB/flood on the bridge afterwards.  A flood-ON local decap
	 * port would let the bridge flood BUM back out it → re-encap toward our
	 * own SID → loop.  The peer-keyed bum-srl2 remains the only flood port.
	 * Keyed by the EVI's own DT2U SID (distinct from any remote SID).
	 */
	if (evi->dt2u_sid_valid && (evi->local_decap_oif == 0 ||
				    !IPV6_ADDR_SAME(&evi->local_decap_sid, &evi->dt2u_sid))) {
		struct zebra_srl2 *decap;

		/*
		 * The decap interface is keyed by dt2u_sid.  If a decap already
		 * exists but was built for a DIFFERENT SID (locator legacy<->uSID
		 * reallocation changed dt2u_sid), drop the stale one first so we
		 * don't leak it and so local_decap_oif stops pointing at the old
		 * (now-deleted) ifindex.  get_or_create() is idempotent by SID, so
		 * when the SID is unchanged this whole block is skipped (the gate
		 * above is false) — no srl2 refcount churn on repeated realize.
		 */
		if (evi->local_decap_oif != 0 &&
		    !IPV6_ADDR_SAME(&evi->local_decap_sid, &evi->dt2u_sid)) {
			zebra_srl2_release(&evi->local_decap_sid);
			evi->local_decap_oif = 0;
		}

		decap = zebra_srl2_get_or_create(&evi->dt2u_sid, evi->bridge_if->ifindex,
						 false /* is_bum: flood-off */, zevpn->vid);

		if (decap) {
			evi->local_decap_oif = decap->ifindex;
			evi->local_decap_sid = evi->dt2u_sid;
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u local decap l2dev %s (ifindex %u) for SID %pI6",
					   __func__, evi->vni, decap->ifname, decap->ifindex,
					   &evi->dt2u_sid);
		} else {
			evi->local_decap_oif = 0;
			zlog_warn("%s: EVI %u: failed to create local decap interface", __func__,
				  evi->vni);
		}
	}

	/*
	 * Repair VLAN membership on any peer-keyed srl2/bum-srl2 already on this
	 * bridge.  Those ports are created on demand from remote Type-2/Type-3
	 * updates, which can arrive before the EVI's member BD is linked (vid
	 * still 0) — e.g. when per-EVI SID allocation is async and the first
	 * realize ran with vid 0.  get_or_create then skipped their per-port
	 * VLAN bind, leaving them on the default PVID.  realize runs again once
	 * vid is known, so sweep every port here and (re)bind the EVI VLAN.
	 * Idempotent; no-op for vlan-bundle (vid 0).
	 */
	if (zevpn->vid)
		zebra_srl2_bind_vlan_on_bridge(evi->bridge_if->ifindex, zevpn->vid);

	/*
	 * Re-program remote SRv6 MAC FDB entries now that vid is resolved and
	 * the egress srl2 ports are VLAN-bound.  A remote MAC received during
	 * the earlier vid-0 window was filed under vid 0 (or rejected, because
	 * its egress srl2 wasn't yet a member of the EVI VLAN); re-issuing here
	 * lands it on the correct VLAN so unicast to the peer works.
	 */
	if (zevpn->vid)
		zebra_evpn_rem_srv6_macs_reinstall(zevpn);

	SET_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP);
	zebra_evpn_send_add_to_client(zevpn);

	/*
	 * Re-scan the kernel bridge FDB for this EVI's bridge + VLAN so local
	 * MACs already present in the kernel are originated as Type-2.  Local
	 * MACs (static FDB entries, or MACs learned before an EVI delete/re-add)
	 * emit their RTM_NEWNEIGH only once — on a re-add zebra never sees them
	 * again, so without this rescan a re-added SRv6 EVI never advertises
	 * its pre-existing local MACs (and peers never build the unicast srl2).
	 * Mirrors the VXLAN VNI-up path (zebra_evpn_read_mac_neigh).  vid 0
	 * (vlan-bundle) means no VLAN filter — read the whole bridge FDB.
	 */
	{
		struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

		if (zns)
			dplane_fdb_read_for_bridge(zns, evi->bridge_if, evi->bridge_if, zevpn->vid);
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: realized SRv6 EVI %u on bridge %s vid %u", __func__, evi->vni,
			   evi->bridge_if->name, zevpn->vid);
}

/* -------------------------------------------------------------------------- */
/* Local MAC mapping: (bridge, vlan) -> SRv6 EVI VNI                            */
/* -------------------------------------------------------------------------- */

/*
 * Find the SRv6 EVI VNI for a (bridge, vlan) pair.  Used by
 * zebra_evpn_map_vlan() to associate locally-learned MACs with an SRv6 EVI,
 * which has no vxlan device and therefore no vxlan-derived bridge VLAN->VNI
 * entry.  Returns the VNI, or 0 if no SRv6 EVI matches.
 */
vni_t zebra_srv6_evi_vni_by_bridge_vlan(const struct interface *br_if, vlanid_t vid)
{
	struct zebra_srv6_evi *evi;
	struct zebra_srv6_evi_bd *bd;
	vni_t found = 0;

	if (!srv6_evi_inited || !br_if)
		return 0;

	/* Read-only walk of the EVI table looking for a bridge/vlan match. */
	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		if (evi->bridge_if != br_if)
			continue;
		/*
		 * vlan-bundle: one flat bridge-domain on a VLAN-unaware bridge.
		 * Local FDB events on such a bridge carry vid 0, while the EVI's
		 * member BDs hold the customer VLANs (10/20/30). Match on the
		 * bridge alone so locally-learned MACs still resolve to this EVI
		 * and originate Type-2 (eth_tag 0).
		 *
		 * C4: RFC 7432 - 6.2 requires a MAC to be unique across ALL member
		 * C-VLANs of a bundle, because the whole bundle shares ONE FDB
		 * (keyed by MAC only, vid 0).  A duplicate MAC on two C-VLANs is a
		 * misconfiguration; because the bridge presents vid 0 for every
		 * such event zebra cannot distinguish the offending C-VLANs here,
		 * so the collision is resolved last-writer-wins by the shared FDB.
		 */
		if (evi->svc_type == ZEVPN_SVC_VLAN_BUNDLE) {
			found = evi->vni;
			break;
		}
		frr_each (evi_bds, &evi->bds, bd) {
			if (bd->vid == vid) {
				found = evi->vni;
				break;
			}
		}
		if (found)
			break;
	}
	return found;
}

/* -------------------------------------------------------------------------- */
/* Replay all SRv6 EVIs to BGP                                                  */
/* -------------------------------------------------------------------------- */

/*
 * (Re)announce every configured SRv6 EVI to BGP.  Called when BGP enables
 * advertise-all-vni (zebra_vxlan_advertise_all_vni): zebra's normal rebuild
 * (zevpn_build_hash_table) only discovers VNIs from VXLAN interfaces, so SRv6
 * EVIs (no vxlan device) must be replayed here, otherwise their ZEBRA_VNI_ADD
 * is only ever sent once at config time and the VNI never goes "live" in BGP
 * if BGP connected/enabled afterwards.
 */
void zebra_srv6_l2evpn_replay(void)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited)
		return;

	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi)
		zebra_srv6_evi_realize(evi);
}

/* -------------------------------------------------------------------------- */
/* Per-EVI SID reallocation on locator format/behavior change                   */
/* -------------------------------------------------------------------------- */

/*
 * Called when an SRv6 locator's encoding changes at runtime (legacy <-> uSID,
 * i.e. `behavior usid` / `format usid-fNNNN`).  zebra_srv6_locator_format_set()
 * (and the `behavior usid` toggle) already purge the SID-manager entries and
 * re-notify the locator to zclients, but the per-EVI DT2U/DT2M bookkeeping
 * (evi->dt2{u,m}_sid_valid) is separate state that is otherwise only cleared on
 * EVI teardown.  Because srv6_evi_alloc_sids() is idempotent and short-circuits
 * when those flags are set, the EVIs would keep their stale (old-format) SIDs
 * forever — the symptom being per-VNI SIDs that stay in legacy format while the
 * VPWS DX2 SID (which has its own bgpd-side reallocation hook,
 * bgp_evpn_vpws_on_locator_update) correctly flips to uSID.
 *
 * This mirrors that VPWS hook on the zebra side: for every EVI anchored on the
 * changed locator, drop the local decap interface keyed by the OLD DT2U SID,
 * return the old SIDs to the manager, clear the valid flags, and re-realize.
 * Re-realizing re-allocates the SIDs from the now-updated locator block (so the
 * correct uSID function range is used), recreates the local decap interface
 * with the new SID, and re-sends ZEBRA_VNI_ADD to bgpd carrying the new
 * DT2U/DT2M SIDs — bgpd then reinstalls the local seg6local decap routes and
 * re-advertises Type-2/Type-3 with the corrected codepoint.
 *
 * Must be called AFTER the locator's parent block has been (re)allocated and
 * the locator re-notified, so get_srv6_sid() inside realize draws from the new
 * block.
 */
void zebra_srv6_evi_on_locator_update(const char *locname)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || !locname || locname[0] == '\0')
		return;

	/* realize() below mutates other tables (srl2) but never this one, and
	 * frr_each_safe protects the current entry, so we can walk in place
	 * without snapshotting the table first.
	 */
	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi) {
		struct srv6_sid_ctx ctx = {};

		if (strncmp(evi->locator, locname, sizeof(evi->locator)) != 0)
			continue;
		if (!evi->dt2u_sid_valid && !evi->dt2m_sid_valid)
			continue; /* nothing allocated yet; realize allocs fresh */

		zlog_info("SRv6 EVI %u: locator %s encoding changed, reallocating service SIDs (old DT2U %pI6 DT2M %pI6)",
			  evi->vni, locname, &evi->dt2u_sid, &evi->dt2m_sid);

		/*
		 * Drop the local decap interface keyed by the SID it was actually
		 * built for so its stale seg6local kernel route/port is removed;
		 * realize recreates it keyed by the new SID.
		 */
		if (evi->local_decap_oif != 0) {
			zebra_srl2_release(&evi->local_decap_sid);
			evi->local_decap_oif = 0;
			memset(&evi->local_decap_sid, 0, sizeof(evi->local_decap_sid));
		}

		/*
		 * Return the old SIDs to the SID manager.  The format-change path
		 * may already have purged the manager's entries for this locator
		 * (zebra_srv6_sid_entry_del_by_locator_all_sids); release is a
		 * no-op if the ctx is already gone.
		 */
		ctx.vrf_id = VRF_DEFAULT;
		ctx.dt2_vni = evi->vni;
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2U;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2M;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		evi->dt2u_sid_valid = false;
		evi->dt2m_sid_valid = false;

		/* Re-allocate from the updated locator and re-notify bgpd. */
		zebra_srv6_evi_realize(evi);
	}
}

/* -------------------------------------------------------------------------- */
/* Remote BUM (Type-3) handling for SRv6 EVIs                                   */
/* -------------------------------------------------------------------------- */

/*
 * SRv6 BUM endpoint for a remote VTEP/peer (Type-3 IMET carrying a BUM SID).
 * Creates/refreshes/releases the bum-srl2 flood port toward the peer, anchored
 * on the EVI's vlan-aware bridge (no vxlan device).  This is the SRv6 backend
 * counterpart of the BUM block in zebra_vxlan_remote_vtep_add(); the bridge is
 * zevpn->bridge_if instead of the vxlan_if's bridge slave (design §11.2).
 */
void zebra_srv6_evi_remote_bum(struct zebra_evpn *zevpn, struct ipaddr *vtep_ip,
			       const struct in6_addr *bum_sid)
{
	struct zebra_vtep *zvtep;
	ifindex_t br_ifindex;

	if (!zevpn || !zevpn->bridge_if)
		return;
	br_ifindex = zevpn->bridge_if->ifindex;

	/* Track the remote VTEP for BUM-SID bookkeeping (no VXLAN HER). */
	zvtep = zebra_evpn_vtep_find(zevpn, vtep_ip);
	if (!zvtep)
		zvtep = zebra_evpn_vtep_add(zevpn, vtep_ip, VXLAN_FLOOD_DISABLED);
	if (!zvtep)
		return;
	zvtep->gr_refresh_time = monotime(NULL);

	/*
	 * BUM SID changed (peer re-advertised a new value, e.g. after an EVI
	 * delete/re-add).  Prefer updating the existing bum-srl2's encap SID
	 * IN PLACE: this keeps the kernel interface and its ifindex stable, so
	 * the local End.DT2M decap route that uses this bum-srl2 as l2dev is
	 * NOT orphaned.  Only if the in-place update fails do we fall back to
	 * release + recreate (which churns the interface).
	 */
	if (zvtep->has_bum_srv6_sid && bum_sid &&
	    memcmp(&zvtep->bum_srv6_sid, bum_sid, sizeof(zvtep->bum_srv6_sid)) != 0) {
		struct zebra_srl2 *updated = zebra_srl2_update_sid(&zvtep->bum_srv6_sid, bum_sid);

		if (updated) {
			/* Stable ifindex; just record the new SID. The local
			 * BUM decap route keeps working on the same oif.
			 */
			zvtep->bum_srv6_sid = *bum_sid;
			zvtep->gr_refresh_time = monotime(NULL);
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u BUM srl2 SID updated in place to %pI6",
					   __func__, zevpn->vni, bum_sid);
			return;
		}

		/* Fallback: in-place update unsupported -> release + recreate. */
		zebra_srl2_release(&zvtep->bum_srv6_sid);
		zvtep->has_bum_srv6_sid = false;
	}

	/* Create the bum-srl2 flood port toward the peer's BUM SID. */
	if (bum_sid && !IN6_IS_ADDR_UNSPECIFIED(bum_sid) && !zvtep->has_bum_srv6_sid) {
		/* The EVI VLAN is bound inside get_or_create (port down +
		 * enslaved, before up) so BUM frames egress on the correct
		 * VLAN; default PVID would otherwise drop EVI traffic.
		 */
		struct zebra_srl2 *bum_srl2 = zebra_srl2_get_or_create(bum_sid, br_ifindex,
								       true /* is_bum */,
								       zevpn->vid);

		if (bum_srl2) {
			zvtep->bum_srv6_sid = *bum_sid;
			zvtep->has_bum_srv6_sid = true;
			/* The bum-srl2 oif now exists — re-report the EVI to
			 * bgpd so it installs the local BUM decap SID on this
			 * (current) oif from its interface-add hook.
			 */
			zebra_evpn_send_add_to_client(zevpn);
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u BUM srl2 %s for peer SID %pI6", __func__,
					   zevpn->vni, bum_srl2->ifname, bum_sid);
		} else {
			zlog_warn("%s: EVI %u failed to create bum-srl2 for SID %pI6", __func__,
				  zevpn->vni, bum_sid);
		}
	}

	/* BUM SID withdrawn -> release the bum-srl2. */
	if ((!bum_sid || IN6_IS_ADDR_UNSPECIFIED(bum_sid)) && zvtep->has_bum_srv6_sid) {
		zebra_srl2_release(&zvtep->bum_srv6_sid);
		zvtep->has_bum_srv6_sid = false;
	}
}

/* -------------------------------------------------------------------------- */
/* Config write                                                                */
/* -------------------------------------------------------------------------- */

int zebra_srv6_l2evpn_config_write(struct vty *vty)
{
	struct zebra_srv6_evi *evi;
	struct zebra_srv6_evi_bd *bd;

	if (!srv6_evi_inited || srv6_evi_htab_count(srv6_evi_table) == 0)
		return 0;

	vty_out(vty, "  l2-evpn\n");
	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		vty_out(vty, "   evi %u", evi->vni);
		if (evi->locator[0])
			vty_out(vty, " locator %s", evi->locator);
		if (evi->bridge_if)
			vty_out(vty, " bridge %s", evi->bridge_if->name);
		vty_out(vty, "\n");
		vty_out(vty, "    service-type %s\n", zevpn_l2_service2str(evi->svc_type));
		frr_each (evi_bds, &evi->bds, bd)
			vty_out(vty, "    vlan %u\n", bd->vid);
		vty_out(vty, "   exit\n");
	}
	vty_out(vty, "  exit\n");
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Init / terminate                                                            */
/* -------------------------------------------------------------------------- */

void zebra_srv6_l2evpn_init(void)
{
	srv6_evi_htab_init(srv6_evi_table);
	srv6_evi_inited = true;
}

void zebra_srv6_l2evpn_terminate(void)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited)
		return;
	/* srv6_evi_free tears down each EVI's members + struct; detach from the
	 * table first (frr_each_safe permits delete mid-traversal).
	 */
	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi) {
		srv6_evi_htab_del(srv6_evi_table, evi);
		srv6_evi_free(evi);
	}
	srv6_evi_htab_fini(srv6_evi_table);
	srv6_evi_inited = false;
}
