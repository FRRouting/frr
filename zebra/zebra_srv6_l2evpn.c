// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 L2 EVPN — Multi-VLAN-to-EVI mapping.
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
#include "lib/zclient.h"
#include "zebra/zebra_sr6.h"
#include "zebra/zebra_dplane.h"
#include "zebra/interface.h"
#include "zebra/zebra_l2.h"
#include "zebra/rt_netlink.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_srv6.h"

#include "lib/srv6.h"
#include "lib/vrf.h"

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
/* path (VXLAN backend) and from the sr6/DT2U path (SRv6 backend) in later    */
/* phases — see design §11 (migration inventory).                              */
/* -------------------------------------------------------------------------- */

/*
 * NOTE: the EVI VLAN is now bound onto each overlay (sr6 / bum-sr6) bridge
 * port INSIDE zebra_sr6_get_or_create() — while the port is still down and
 * freshly enslaved, before it is brought up (canonical ordering).  The former
 * standalone srv6_evi_port_vlan_bind() helper was removed because binding the
 * VLAN after the port was already up did not stick.
 */

/* ----- SRv6 backend (op bodies filled in phase 3/4) ----- */

static int srv6_dp_mac_install(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool was_static)
{
	struct zebra_sr6 *sr6;
	struct ipaddr vtep_ip = {};
	enum zebra_dplane_result res;
	bool sticky;

	/*
	 * SRv6 unicast (End.DT2U) MAC install — migrated from the inline
	 * has_srv6_sid branch in zebra_evpn_rem_mac_install() (design 11.2).
	 *
	 * Acquire (or reuse) the unicast sr6 encap interface for this MAC's
	 * SID, anchored on the EVI's bridge (zevpn->bridge_if).  One reference
	 * per SID: acquire only when not already holding one, tracked by
	 * sr6_ref_held (sr6_ifindex is 0 during the async create window).
	 */
	if (!mac->has_srv6_sid)
		return 0;

	if (!zevpn->bridge_if) {
		zlog_warn("%s: SRv6 EVI %u has no bridge_if; cannot install MAC %pEA", __func__,
			  zevpn->vni, &mac->macaddr);
		return -1;
	}

	if (!mac->sr6_ref_held) {
		/* The EVI VLAN is bound inside get_or_create (while the port is
		 * down + enslaved, before it is brought up), so unicast frames
		 * reach the End.DT2U encap (default PVID would otherwise drop
		 * them).
		 *
		 * Acquire once per SID, keyed off sr6_ref_held (NOT
		 * sr6_ifindex == 0): the ifindex is 0 through the async-create
		 * window, so gating on it made the realize reinstall sweep
		 * re-acquire and inflate the sr6 refcount, leaking the old
		 * interface on a peer SID change.
		 */
		sr6 = zebra_sr6_get_or_create(&mac->srv6_sid, zevpn->bridge_if->ifindex,
						false /* is_bum */, zevpn->vid);
		if (sr6) {
			mac->sr6_ref_held = true;
			mac->sr6_bridge_ifindex = zevpn->bridge_if->ifindex;
			mac->sr6_ifindex = sr6->ifindex;
			/* The unicast sr6 oif now exists — re-report the EVI to
			 * bgpd so it installs the local End.DT2U decap SID on
			 * this (current) oif from its interface-add hook, where
			 * the interface is operative.
			 */
			zebra_evpn_send_add_to_client(zevpn);
		} else {
			zlog_warn("%s: failed to get/create sr6 for SID %pI6 on EVI %u", __func__,
				  &mac->srv6_sid, zevpn->vni);
			return -1;
		}
	} else if (mac->sr6_ifindex == 0) {
		/* Reference already held but the netdev was still pending when we
		 * acquired it; refresh the ifindex now resolved by
		 * zebra_sr6_if_add() so the FDB entry programs the right oif.
		 */
		sr6 = zebra_sr6_lookup(&mac->srv6_sid, mac->sr6_bridge_ifindex, false);
		if (sr6)
			mac->sr6_ifindex = sr6->ifindex;
	}

	/*
	 * Still no resolved oif: the sr6 netdev is genuinely still mid-create
	 * (async-create window). dplane_rem_mac_add() below only takes the
	 * correctly-built sticky/permanent netlink_sr6_macfdb_encode() path
	 * when sr6_ifindex != 0 - with it still 0 here, mac_update_common()
	 * would fall back to the generic FDB encoder with ifp == br_ifp (both
	 * zevpn->bridge_if), i.e. a bridge-self-referencing FDB entry without
	 * NTF_STICKY, which the kernel rejects outright ("bridge: FDB entry
	 * towards bridge must be permanent") - and unlike a deferred install,
	 * that failure is never retried. Bail out here instead: zebra_sr6_if_add()
	 * re-realizes the EVI once the netdev's ifindex is known, which re-enters
	 * this function with a resolved sr6_ifindex.
	 */
	if (mac->sr6_ifindex == 0)
		return 0;

	/*
	 * Program the bridge FDB entry with the sr6 (End.DT2U) interface as the
	 * egress, VLAN-scoped by zevpn->vid.  We pass the
	 * EVI bridge as the ctx interface (for vrf/ns); the kernel provider
	 * routes to netlink_sr6_macfdb_encode() because sr6_ifindex != 0, which
	 * ignores the ctx ifindex and programs ndm_ifindex = sr6_ifindex.
	 */
	sticky = !!CHECK_FLAG(mac->flags, (ZEBRA_MAC_STICKY | ZEBRA_MAC_REMOTE_DEF_GW));

	res = dplane_rem_mac_add(zevpn->bridge_if, zevpn->bridge_if, zevpn->vid, &mac->macaddr,
				 zevpn->vni, &vtep_ip, sticky, 0 /* nhg_id */, was_static,
				 &mac->srv6_sid, mac->sr6_ifindex);
	return (res != ZEBRA_DPLANE_REQUEST_FAILURE) ? 0 : -1;
}

static int srv6_dp_mac_uninstall(struct zebra_evpn *zevpn, struct zebra_mac *mac, bool force)
{
	struct ipaddr vtep_ip = {};
	enum zebra_dplane_result res;

	/*
	 * Withdraw the sr6 FDB entry only.  The sr6 *reference* is released on
	 * MAC removal by the existing path in zebra_evpn_mac.c (backend-agnostic,
	 * keyed on mac->sr6_ifindex), so we must not release it here or the
	 * refcount would underflow.
	 */
	if (mac->sr6_ifindex == 0 || !zevpn->bridge_if)
		return 0;

	res = dplane_rem_mac_del_sr6(zevpn->bridge_if, zevpn->bridge_if, zevpn->vid,
				      &mac->macaddr, zevpn->vni, &vtep_ip,
				      mac->has_srv6_sid ? &mac->srv6_sid : NULL, mac->sr6_ifindex);
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
	/* TODO(phase4): bum-sr6 (DT2M/DT2U) setup/teardown, per-VLAN scope. */
	return 0;
}

static struct interface *srv6_dp_bridge(struct zebra_evpn *zevpn)
{
	struct zebra_srv6_evi *evi = zebra_srv6_evi_lookup(zevpn->vni);

	return evi ? evi->bridge_if : NULL;
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
	evi->l2_encap_mode = ZEBRA_SR6_ENCAP_MODE_FULL; /* `l2-encap-mode` default */
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

/*
 * Tear down an EVI's REALIZED state while KEEPING its config object (vni,
 * locator, bridge, member list): withdraw the backing zebra_evpn (and its
 * Type-2/Type-3 routes) from BGP, free its remote MAC/neigh/VTEP forwarding,
 * release this EVI's sr6/bum-sr6 ports and its per-EVI service SIDs, and clear
 * the local decap anchor.  Used by both evi_del (full delete) and vlan_del
 * (last member VLAN removed), so a later re-add of config or a VLAN
 * re-realizes cleanly.  Idempotent and safe on a never-realized EVI: the zevpn
 * lookup fails, and the SID / bridge releases are guarded.
 */
static void zebra_srv6_evi_unrealize(struct zebra_srv6_evi *evi)
{
	struct zebra_evpn *zevpn;
	ifindex_t bridge_ifindex = 0;

	if (!evi)
		return;

	/* Capture the bridge ifindex before the zevpn is torn down so we can
	 * force-delete this EVI's sr6/bum-sr6 interfaces afterwards.
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
	 * Remove this EVI's sr6/bum-sr6 interfaces.  They are created
	 * on-demand (refcounted by MAC/BUM routes), but the bulk zevpn delete
	 * above does not reliably drop those references, so force-delete every
	 * sr6 slaved to this EVI's bridge.  Otherwise the interfaces linger
	 * and a later re-add fails with "File exists" on creation.
	 */
	if (bridge_ifindex)
		zebra_sr6_release_all_on_bridge(bridge_ifindex);

	/*
	 * The realized state is gone: the self-PVID is no longer bound and the
	 * kernel FDB/neighbor tables must be read again when the VLAN comes back,
	 * even on the same bridge.  Without this realize() would skip both, and
	 * existing local hosts would stay unadvertised until they are learned
	 * again.
	 */
	evi->self_pvid_bound_vid = 0;
	evi->self_pvid_bound_ifindex = 0;
	evi->kernel_state_rescan_bridge_ifindex = 0;

	/* The dedicated local decap sr6 was just released above.  Clear both
	 * the cached oif and the held-SID marker so a later re-add of this EVI
	 * starts clean (and never tries to release a stale SID).
	 */
	evi->local_decap_oif = 0;
	memset(&evi->local_decap_sid, 0, sizeof(evi->local_decap_sid));

	/*
	 * Return this EVI's per-EVI service SIDs to the SID-manager pool.  They
	 * were allocated via get_srv6_sid() keyed by {behavior, dt2_bd}, so
	 * release with the same contexts.  No-op if never allocated.
	 */
	if (evi->dt2u_sid_valid || evi->dt2m_sid_valid) {
		struct srv6_sid_ctx ctx = {};

		ctx.vrf_id = VRF_DEFAULT;
		ctx.dt2_bd = evi->vni;

		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2U;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT2M;
		zebra_srv6_l2_sid_release(&ctx, evi->locator);

		evi->dt2u_sid_valid = false;
		evi->dt2m_sid_valid = false;
	}
}

void zebra_srv6_evi_del(struct zebra_srv6_evi *evi)
{
	if (!evi)
		return;

	zebra_srv6_evi_unrealize(evi);
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

	/*
	 * Dropping a member VLAN changes the EVI's forwarding scope, so the
	 * REALIZED state must follow - removing only the config entry would
	 * leave the backing zebra_evpn forwarding into the removed VLAN and its
	 * local MAC/IMET routes still advertised (the reported bug: a
	 * vlan-based EVI losing its only VLAN kept forwarding + advertising).
	 *
	 *  - No member left  -> fully un-realize: withdraw the VNI and its
	 *    routes from BGP, free remote MAC/neigh/VTEP state, release the sr6
	 *    ports and per-EVI SIDs.  The EVI config object stays, so re-adding
	 *    a VLAN re-realizes it.  vlan-based (single VLAN per EVI) always
	 *    lands here.
	 *  - Members remain  -> re-realize to rebuild consistently: the removed
	 *    VLAN may have been the one driving zevpn->vid, so re-pick it from a
	 *    surviving member and re-advertise.  realize() is idempotent.
	 */
	if (evi_bds_count(&evi->bds) == 0)
		zebra_srv6_evi_unrealize(evi);
	else
		zebra_srv6_evi_realize(evi);

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
	 * the OLD locator, release them (and the local decap sr6 keyed by the
	 * old DT2U SID) and clear the valid flags BEFORE switching the name.
	 * Otherwise srv6_evi_alloc_sids() is idempotent and short-circuits on
	 * the still-"valid" stale SIDs, so realize() would keep advertising the
	 * old locator's SIDs and never draw from the new locator's block.
	 * Mirrors zebra_srv6_evi_on_locator_update() (the format-change path).
	 */
	if (evi->dt2u_sid_valid || evi->dt2m_sid_valid) {
		struct srv6_sid_ctx ctx = {};

		if (!IN6_IS_ADDR_UNSPECIFIED(&evi->local_decap_sid)) {
			zebra_sr6_release(&evi->local_decap_sid, evi->local_decap_bridge_ifindex, false);
			evi->local_decap_oif = 0;
			memset(&evi->local_decap_sid, 0, sizeof(evi->local_decap_sid));
		}

		/* Release the old SIDs from the OLD locator (evi->locator still
		 * holds the old name here).
		 */
		ctx.vrf_id = VRF_DEFAULT;
		ctx.dt2_bd = evi->vni;
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

void zebra_srv6_evi_set_bridge(struct zebra_srv6_evi *evi, const char *bridge_name,
			       struct interface *bridge_if)
{
	if (!evi)
		return;
	/*
	 * Always retain the configured NAME, even when the bridge does not
	 * exist yet (bridge_if == NULL).  The name is what persists to the
	 * running-config and what zebra_srv6_l2evpn_bridge_resolve() matches on
	 * when the bridge later appears; storing only a failed lookup would lose
	 * the binding and silently accept the command.
	 */
	if (bridge_name)
		strlcpy(evi->bridge_name, bridge_name, sizeof(evi->bridge_name));

	/*
	 * A genuine REBIND (bound to one bridge, now moving to a different one)
	 * must release ALL state anchored on the OLD bridge - not only the local
	 * decap anchor (which realize() re-acquires), but the remote MAC and BUM
	 * sr6 references: srv6_dp_mac_install() trusts mac->sr6_ref_held and the
	 * saved mac->sr6_bridge_ifindex, and the BUM path trusts
	 * zvtep->sr6_bridge_ifindex, so a reinstall sweep would keep using the
	 * old port and leave remote traffic on the old bridge while local decap
	 * moved to the new one.  Unrealize while bridge_if still points at the
	 * OLD bridge so those ports are released and the VNI is withdrawn; the
	 * realize() below rebuilds everything on the new bridge (bgpd re-imports
	 * the remote routes after the fresh VNI_ADD).
	 */
	if (evi->bridge_if && bridge_if && evi->bridge_if != bridge_if)
		zebra_srv6_evi_unrealize(evi);

	evi->bridge_if = bridge_if; /* may be NULL - resolved later */
	zebra_srv6_evi_realize(evi); /* no-op while bridge_if is NULL */
}

/*
 * A bridge interface appeared: bind it to any EVI that was configured with its
 * name but could not resolve it yet (bridge_if still NULL).  Idempotent - EVIs
 * already bound are skipped - and safe to call on every bridge add/update.
 */
void zebra_srv6_l2evpn_bridge_resolve(struct interface *ifp)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || !ifp || ifp->ifindex == 0)
		return;

	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		if (evi->bridge_if || evi->bridge_name[0] == '\0')
			continue;
		if (strncmp(evi->bridge_name, ifp->name, sizeof(evi->bridge_name)) != 0)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: bridge %s (ifindex %u) appeared; binding EVI %u",
				   __func__, ifp->name, ifp->ifindex, evi->vni);

		evi->bridge_if = ifp;
		zebra_srv6_evi_realize(evi);
	}
}

/*
 * A bridge interface is being deleted: unbind it from any EVI that resolved to
 * it, but KEEP the configured name so the EVI re-resolves if the bridge is
 * recreated.  This also prevents evi->bridge_if from dangling once zebra frees
 * the (operator-owned, not FRR-configured) interface.
 */
void zebra_srv6_l2evpn_bridge_unresolve(struct interface *ifp)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || !ifp)
		return;

	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		if (evi->bridge_if != ifp)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: bridge %s (ifindex %u) removed; unbinding EVI %u (keeps config)",
				   __func__, ifp->name, ifp->ifindex, evi->vni);

		evi->bridge_if = NULL; /* bridge_name retained for re-resolution */
	}
}

void zebra_srv6_evi_set_vrf(struct zebra_srv6_evi *evi, vrf_id_t vrf_id)
{
	if (!evi)
		return;
	if (evi->vrf_id == vrf_id)
		return;
	evi->vrf_id = vrf_id;
	/* Re-realize so the VNI_ADD to bgpd carries the updated tenant_vrf_id. */
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
 * dispatched to srv6_dp_mac_install.
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
 * (behavior + vrf_id + oif + dt2_bd), so passing dt2_bd = EVI VNI yields a
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
	ctx.dt2_bd = evi->vni;

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

/*
 * Per-EVI `l2-encap-mode <full|reduced>`.  Stores the mode and, when it
 * changes on an EVI already bound to a bridge, re-programs that bridge's
 * sr6/bum-sr6 interfaces live (same SID / MTU, new mode) via the dplane.
 */
void zebra_srv6_evi_set_encap_mode(struct zebra_srv6_evi *evi, uint8_t mode)
{
	if (!evi)
		return;
	if (mode != ZEBRA_SR6_ENCAP_MODE_REDUCED)
		mode = ZEBRA_SR6_ENCAP_MODE_FULL;
	if (evi->l2_encap_mode == mode)
		return;

	evi->l2_encap_mode = mode;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: EVI %u l2-encap-mode -> %s", __func__, evi->vni,
			   zebra_sr6_encap_mode2str(mode));

	if (evi->bridge_if && evi->bridge_if->ifindex)
		zebra_sr6_reprogram_on_bridge(evi->bridge_if->ifindex);
}

uint8_t zebra_srv6_evi_encap_mode_by_bridge(ifindex_t bridge_ifindex)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || bridge_ifindex == 0)
		return ZEBRA_SR6_ENCAP_MODE_FULL;
	frr_each (srv6_evi_htab, srv6_evi_table, evi)
		if (evi->bridge_if && evi->bridge_if->ifindex == bridge_ifindex)
			return evi->l2_encap_mode;
	return ZEBRA_SR6_ENCAP_MODE_FULL;
}

void zebra_srv6_l2evpn_realize_on_bridge(ifindex_t bridge_ifindex)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || bridge_ifindex == 0)
		return;
	frr_each (srv6_evi_htab, srv6_evi_table, evi)
		if (evi->bridge_if && evi->bridge_if->ifindex == bridge_ifindex)
			zebra_srv6_evi_realize(evi);
}

void zebra_srv6_evi_realize(struct zebra_srv6_evi *evi)
{
	struct zebra_evpn *zevpn;
	struct zebra_srv6_evi_bd *bd;
	struct interface *br_if;

	if (!evi || evi->vni == 0 || !evi->bridge_if)
		return; /* not enough config yet */

	br_if = evi->bridge_if;

	/*
	 * Discover the operator-owned sr6 (End.DT2U) / bum-sr6 (End.DT2M) on this
	 * EVI's bridge.  The encap mode is NOT read back from the kernel: it is
	 * the per-EVI `l2-encap-mode` config (default full), pushed onto these
	 * interfaces with every changelink.
	 */
	evi->sr6_ifindex = zebra_sr6_discover_on_bridge(br_if->ifindex, false, NULL);
	evi->bum_sr6_ifindex = zebra_sr6_discover_on_bridge(br_if->ifindex, true, NULL);

	zevpn = zebra_evpn_lookup(evi->vni);
	if (zevpn) {
		/*
		 * The VNI already has a zebra_evpn.  If it is not one we created
		 * (dp_ops already == SRv6), a VXLAN EVI owns this VNI: refuse the
		 * conflict instead of hijacking it.  Flipping dp_ops/bridge_if to
		 * the SRv6 backend would silently break the live VXLAN service,
		 * and deleting this SRv6 EVI would later free the shared object.
		 */
		if (zevpn->dp_ops != &zevpn_dp_ops_srv6) {
			zlog_warn("%s: VNI %u already in use by VXLAN, refusing SRv6 EVI realize",
				  __func__, evi->vni);
			return;
		}
	} else {
		zevpn = zebra_evpn_add(evi->vni);
		if (!zevpn) {
			zlog_warn("%s: failed to create zebra_evpn for SRv6 EVI %u", __func__,
				  evi->vni);
			return;
		}
	}

	/* Flip this EVI's zebra_evpn to the SRv6 backend, anchored on the
	 * vlan-aware bridge.
	 */
	zevpn->dp_ops = &zevpn_dp_ops_srv6;
	zevpn->bridge_if = br_if;
	/* Propagate the tenant VRF so bgpd's VNI_ADD carries the correct
	 * tenant_vrf_id for symmetric IRB (bgpevpn_link_to_l3vni). Copy
	 * VRF_DEFAULT too, so that "no vrf" detaches the EVI from its old tenant.
	 */
	zevpn->vrf_id = evi->vrf_id;

	/*
	 * Allocate this EVI's own End.DT2U/End.DT2M service SIDs from its
	 * locator (idempotent).  Local seg6local install on the EVI's
	 * sr6/bum-sr6 and reporting the SIDs up to bgpd are wired in the
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
		zevpn->svi_if = br_if;

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
	 * This decouples local decap from the peer-keyed sr6/bum-sr6 (FDB/flood
	 * only), so a peer withdraw or SID change never disturbs local decap, and
	 * decap installs immediately at realize without waiting for a peer.
	 *
	 * Created flood-OFF (is_bum=false → unicast brport flags): it is only an
	 * injection point for decapsulated frames into the bridge; the kernel
	 * does the FDB/flood on the bridge afterwards.  A flood-ON local decap
	 * port would let the bridge flood BUM back out it → re-encap toward our
	 * own SID → loop.  The peer-keyed bum-sr6 remains the only flood port.
	 * Keyed by the EVI's own DT2U SID (distinct from any remote SID).
	 */
	/*
	 * Self-heal a stale decap oif: if the sr6 device backing it was ever
	 * deleted out from under us (e.g. externally, or by anything else that
	 * doesn't go through zebra_sr6_release()), local_decap_oif keeps
	 * pointing at a now-nonexistent ifindex forever - "have_decap" below
	 * keys off local_decap_sid, not the ifindex, so it would see the SID
	 * as already held and never notice, leaving the EVI stuck advertising
	 * a route to a dead interface (l2dev <unknown>, inactive) until an
	 * operator removes and re-adds the whole EVI. Detect that here and
	 * release + clear local_decap_sid so "!have_decap" below recreates it
	 * on its own, same as any other sid_changed trigger already does.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&evi->local_decap_sid) && evi->local_decap_oif != 0 &&
	    !if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT), evi->local_decap_oif)) {
		zlog_warn("%s: EVI %u: local decap oif %u no longer exists; will recreate",
			  __func__, evi->vni, evi->local_decap_oif);
		zebra_sr6_release(&evi->local_decap_sid, evi->local_decap_bridge_ifindex, false);
		memset(&evi->local_decap_sid, 0, sizeof(evi->local_decap_sid));
		evi->local_decap_oif = 0;
	}

	if (evi->dt2u_sid_valid) {
		bool have_decap = !IN6_IS_ADDR_UNSPECIFIED(&evi->local_decap_sid);
		bool sid_changed = have_decap &&
				   !IPV6_ADDR_SAME(&evi->local_decap_sid, &evi->dt2u_sid);
		/*
		 * The local decap sr6 is keyed by {SID, bridge}.  Changing the
		 * EVI's bridge (operator rebind, or delete+recreate with a new
		 * ifindex) while the SID is unchanged must also re-acquire it:
		 * otherwise the cached local_decap_bridge_ifindex keeps pointing
		 * at the OLD bridge, leaving decap on the old bridge or without a
		 * usable port.
		 */
		bool bridge_changed = have_decap &&
				      evi->local_decap_bridge_ifindex != evi->bridge_if->ifindex;

		/*
		 * Acquire the local decap sr6 exactly once per dt2u SID.  The
		 * "do we already hold it?" test keys off local_decap_sid (recorded
		 * the moment we acquire, even while the netdev's ifindex is still
		 * pending) - NOT local_decap_oif.  local_decap_oif stays 0 through
		 * the whole discovery window (the operator-owned netdev is not yet
		 * seen, so get_or_create returns ifindex 0 until zebra_sr6_if_add
		 * resolves it), so gating on oif == 0 made every realize pass
		 * re-acquire and inflate the sr6 refcount (sr6_get_or_create does
		 * refcnt++ per call); a single release on a later SID change then
		 * could never drive the refcount to 0, leaking the old interface.
		 * Keying off the SID makes the acquire idempotent, so refcount
		 * stays 1.
		 */
		if (!have_decap || sid_changed || bridge_changed) {
			struct zebra_sr6 *decap;

			/*
			 * SID changed (locator legacy<->uSID reallocation changed
			 * dt2u_sid) OR the bridge changed: release the sr6 keyed by
			 * the OLD {SID, bridge} first so it is reset (not leaked)
			 * and local_decap_* stops pointing at the stale interface /
			 * old bridge, then reacquire on the current bridge below.
			 */
			if (sid_changed || bridge_changed) {
				zebra_sr6_release(&evi->local_decap_sid, evi->local_decap_bridge_ifindex, false);
				memset(&evi->local_decap_sid, 0,
				       sizeof(evi->local_decap_sid));
				evi->local_decap_oif = 0;
			}

			/*
			 * Local decap anchor: resolves the same operator-owned
			 * sr6-<n> as the peer-keyed entry, so it must never program
			 * our own SID as the encap segment (that overwrote the
			 * remote SID on sr6-1).
			 */
			decap = zebra_sr6_get_or_create_local_decap(&evi->dt2u_sid, br_if->ifindex,
								    zevpn->vid);
			if (decap) {
				/* Record the held SID now; the ifindex is filled
				 * in below once the netdev materialises.
				 */
				evi->local_decap_sid = evi->dt2u_sid;
				evi->local_decap_bridge_ifindex = evi->bridge_if->ifindex;
				evi->local_decap_oif = decap->ifindex;
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug("%s: EVI %u local decap l2dev %s (ifindex %u) for SID %pI6",
						   __func__, evi->vni, decap->ifname,
						   decap->ifindex, &evi->dt2u_sid);
			} else {
				memset(&evi->local_decap_sid, 0,
				       sizeof(evi->local_decap_sid));
				evi->local_decap_oif = 0;
				zlog_warn("%s: EVI %u: failed to create local decap interface",
					  __func__, evi->vni);
			}
		}

		/*
		 * Refresh the cached oif from the tracked entry WITHOUT taking a
		 * new reference, so the ifindex resolved asynchronously by
		 * zebra_sr6_if_add() lands here on a subsequent realize.
		 */
		if (!IN6_IS_ADDR_UNSPECIFIED(&evi->local_decap_sid)) {
			struct zebra_sr6 *d = zebra_sr6_lookup(&evi->local_decap_sid,
							       evi->local_decap_bridge_ifindex,
							       false);

			evi->local_decap_oif = d ? d->ifindex : 0;
		}
	}

	/*
	 * Repair VLAN membership on any peer-keyed sr6/bum-sr6 already on this
	 * bridge.  Those ports are created on demand from remote Type-2/Type-3
	 * updates, which can arrive before the EVI's member BD is linked (vid
	 * still 0) — e.g. when per-EVI SID allocation is async and the first
	 * realize ran with vid 0.  get_or_create then skipped their per-port
	 * VLAN bind, leaving them on the default PVID.  realize runs again once
	 * vid is known, so sweep every port here and (re)bind the EVI VLAN.
	 * Idempotent; no-op for vlan-bundle (vid 0).
	 */
	if (zevpn->vid)
		zebra_sr6_bind_vlan_on_bridge(br_if->ifindex, zevpn->vid);

	/*
	 * The bridge device's OWN self-VLAN/PVID must also match the EVI's
	 * VLAN, distinct from the per-port bind above. When VRF-routed IRB
	 * traffic is delivered directly to this bridge device (VRF route
	 * resolves to a local, directly-connected subnet on this bridge),
	 * the kernel's br_dev_xmit() has no ingress port to derive a VLAN
	 * from and falls back to the bridge's own default self-PVID (VLAN
	 * 1) for its FDB lookup. Since every real FDB entry on a
	 * vlan-filtering bridge is tagged with the EVI's actual VLAN, that
	 * mismatched lookup key misses unconditionally -- regardless of
	 * whether the destination MAC is genuinely known -- and falls back
	 * to flooding, which leaks the packet out the fabric-facing BUM
	 * port to every other PE even though it was already correctly
	 * routed to this one. Setting the bridge's own self-PVID to the
	 * EVI's VLAN here closes that gap the same way the per-port bind
	 * above already does for the tunnel ports.
	 *
	 * Gate on self_pvid_bound_vid (mirrors kernel_state_rescan_bridge_ifindex
	 * below): realize() runs on every remote MAC install, not just on an
	 * actual VLAN change, and re-issuing this RTM_SETLINK on every one of
	 * those redundant passes races the kernel's bridge VLAN reprogramming
	 * against the remote-MAC FDB add already in flight on the same dplane
	 * FIFO for the very MAC that triggered this realize() pass -
	 * intermittently dropping that install. Re-apply only when the vid
	 * actually changes (or on the first realize); no-op for vlan-bundle
	 * (vid 0).
	 */
	if (zevpn->vid && (evi->self_pvid_bound_vid != zevpn->vid ||
			   evi->self_pvid_bound_ifindex != br_if->ifindex)) {
		dplane_sr6_bridge_vlan_add(br_if->ifindex, zevpn->vid, true /* untagged */,
					   true /* pvid */, true /* self */);
		/*
		 * Setting VLAN 400 as the new self-PVID demotes the bridge's
		 * default VLAN 1 from PVID, but leaves it registered as a
		 * second, still-untagged self-membership. With two untagged
		 * VLAN contexts on the bridge's own self-entry, a locally
		 * generated broadcast (e.g. this EVI's anycast IRB gateway
		 * answering its own ARP request) gets delivered to the local
		 * stack once per VLAN - a spurious duplicate reply. Strip
		 * the stale VLAN 1 self-membership alongside binding VLAN
		 * 400, mirroring the per-port cleanup above.
		 */
		if (zevpn->vid != 1)
			dplane_sr6_bridge_vlan_del(br_if->ifindex, 1, true /* self */);
		evi->self_pvid_bound_vid = zevpn->vid;
		evi->self_pvid_bound_ifindex = br_if->ifindex;
	}

	/*
	 * Re-program remote SRv6 MAC FDB entries now that the egress sr6 ports
	 * exist (and, for VLAN-scoped services, are VLAN-bound).  A remote MAC
	 * received during the earlier window - sr6 port not present yet, so the
	 * install held a reference with sr6_ifindex == 0, or (for VLAN-scoped
	 * EVIs) its egress sr6 wasn't yet a member of the EVI VLAN - is
	 * re-issued here so it lands on the now-resolved port.
	 *
	 * Run this for EVERY service type, NOT gated on a nonzero vid: a
	 * vlan-bundle legitimately uses vid 0, so the nonzero-vid guard (which
	 * the VLAN-bind above correctly keeps) would leave a bundle's
	 * late-resolved MACs unprogrammed until the next BGP update arrives.
	 */
	zebra_evpn_rem_srv6_macs_reinstall(zevpn);

	SET_FLAG(zevpn->flags, ZEVPN_READY_FOR_BGP);
	zebra_evpn_send_add_to_client(zevpn);

	/* RFC 9135 section 9: Anycast Gateway advertisement.
	 * For IRB-enabled EVIs (VRF binding present), (re)register the bridge
	 * SVI MAC+IP as the local gateway entry so it's ready to advertise as
	 * a sticky Default GW Type-2 route.  Whether it actually gets sent to
	 * bgpd is gated by the existing advertise-default-gw knob (checked via
	 * advertise_gw_macip_enabled() inside zebra_evpn_{mac,neigh}_gw_macip_add()) -
	 * same knob/CLI/ZAPI plumbing already used by the VXLAN path, so it is
	 * NOT force-enabled here.  This allows remote PEs to suppress ARP/ND
	 * for the gateway IP and enables seamless CE mobility without
	 * re-ARPing, when the operator has opted in.  The MACIP send is
	 * idempotent -- it overwrites any stale entry with fresh SID-embedded
	 * attributes.
	 */
	if (evi->vrf_id != VRF_DEFAULT)
		zebra_srv6_evpn_gw_macip_add(br_if, zevpn);

	/*
	 * Re-scan the kernel bridge FDB *and* neighbor table for this EVI's
	 * bridge + VLAN so local MACs and ARP/ND entries already present in
	 * the kernel are (re-)originated as Type-2. Both emit their
	 * RTM_NEWNEIGH only once -- on zebra restart, or an EVI delete/re-add,
	 * zebra never sees an already-established kernel entry again, so
	 * without this rescan a (re-)realized SRv6 EVI silently drops any
	 * pre-existing local host's MAC+IP route (the plain MAC-only route
	 * still gets re-learned once new traffic arrives, masking this as a
	 * "partial" loss rather than the missing neighbor rescan it is).
	 * Mirrors the VXLAN VNI-up path (zebra_evpn_read_mac_neigh(), which
	 * calls both dplane_fdb_read_for_bridge() and
	 * dplane_neigh_read_for_vlan() together) - this EVI-realize path only
	 * ever had the FDB half. vid 0 (vlan-bundle) means no VLAN filter -
	 * read the whole bridge FDB. The EVI's bridge itself (not a separate
	 * VLAN sub-interface) is where the SVI IP/ARP lives here, so it is
	 * also the neighbor-read's "vlan interface".
	 *
	 * realize() itself runs far more often than the bridge actually
	 * changes (every remote MAC install, VLAN repair, interface-add hook,
	 * ...); re-issuing a full kernel FDB+neighbor dump request on every
	 * one of those redundant calls floods the dataplane instead of
	 * helping, so only do this once per bridge (tracked by ifindex, reset
	 * whenever the bridge actually changes).
	 */
	if (evi->kernel_state_rescan_bridge_ifindex != br_if->ifindex) {
		struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

		if (zns) {
			dplane_fdb_read_for_bridge(zns, br_if, br_if, zevpn->vid);
			dplane_neigh_read_for_vlan(zns, br_if);
			evi->kernel_state_rescan_bridge_ifindex = br_if->ifindex;
		}
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: realized SRv6 EVI %u on bridge %s vid %u", __func__, evi->vni,
			   br_if->name, zevpn->vid);
}

/* -------------------------------------------------------------------------- */
/* Local MAC mapping: (bridge, vlan) -> SRv6 EVI VNI                            */
/* -------------------------------------------------------------------------- */

/*
 * Find the SRv6 EVI VNI for a (bridge, vlan) pair.  Used by
 * zebra_evpn_map_vlan() to associate locally-learned MACs with an SRv6 EVI,
 * which the bridge VLAN->VNI table does not cover.  Returns the VNI, or 0 if
 * no SRv6 EVI matches.
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

/* Find the first SRv6 EVI whose bridge_if matches br_if.
 * Used by zebra_evpn_from_svi() to resolve ARP/ND events on SRv6 bridges.
 */
struct zebra_srv6_evi *zebra_srv6_evi_find_by_bridge(const struct interface *br_if)
{
	struct zebra_srv6_evi *evi;

	if (!br_if)
		return NULL;

	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		if (evi->bridge_if == br_if)
			return evi;
	}

	return NULL;
}

/* -------------------------------------------------------------------------- */
/* Replay all SRv6 EVIs to BGP                                                  */
/* -------------------------------------------------------------------------- */

/*
 * (Re)announce every configured SRv6 EVI to BGP.  Called when BGP enables
 * advertise-all-vni (zebra_vxlan_advertise_all_vni): zebra's normal rebuild
 * (zevpn_build_hash_table) only discovers VNIs from VXLAN interfaces, so SRv6
 * EVIs must be replayed here, otherwise their ZEBRA_VNI_ADD
 * is only ever sent once at config time and the VNI never goes "live" in BGP
 * if BGP connected/enabled afterwards.
 */
void zebra_srv6_l2evpn_replay(void)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited)
		return;

	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi) {
		/*
		 * Force the kernel FDB/neighbor rescan inside realize() below,
		 * even though this bridge may already have been rescanned once
		 * before. This replay path runs specifically when bgpd
		 * (re)enables advertise-all-vni - most commonly after a
		 * bgpd-only restart while zebra keeps running - and existing
		 * local MACs/neighbors need to be re-originated as Type-2 to
		 * the newly (re)connected bgp client even though zebra's own
		 * bridge state never changed. The per-bridge gate in realize()
		 * only knows how to suppress *its own* redundant calls; it has
		 * no way to tell that the client on the other end just lost
		 * all of its EVPN state.
		 */
		evi->kernel_state_rescan_bridge_ifindex = 0;
		zebra_srv6_evi_realize(evi);
	}
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

	/* realize() below mutates other tables (sr6) but never this one, and
	 * frr_each_safe protects the current entry, so we can walk in place
	 * without snapshotting the table first.
	 */
	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi) {
		struct srv6_sid_ctx ctx = {};

		if (strncmp(evi->locator, locname, sizeof(evi->locator)) != 0)
			continue;

		/*
		 * A waiting EVI - its locator was configured before it was usable,
		 * so an earlier realize() could not allocate (srv6_evi_alloc_sids
		 * found no locator) and dt2{u,m}_sid_valid are still false - has no
		 * old SIDs to reclaim.  It is precisely the EVI that must RETRY now
		 * that the locator is available: this callback is the only retry
		 * hook, and it fires both on a format/behavior change AND when
		 * `prefix ...` first makes the locator usable (locator_prefix ->
		 * zebra_srv6_locator_format_set -> here).  Realize it to allocate
		 * fresh; the old code skipped it, stranding it with no SIDs forever.
		 */
		if (!evi->dt2u_sid_valid && !evi->dt2m_sid_valid) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u waiting on locator %s now available; realizing",
					   __func__, evi->vni, locname);
			zebra_srv6_evi_realize(evi);
			continue;
		}

		zlog_info("SRv6 EVI %u: locator %s encoding changed, reallocating service SIDs (old DT2U %pI6 DT2M %pI6)",
			  evi->vni, locname, &evi->dt2u_sid, &evi->dt2m_sid);

		/*
		 * Drop the local decap interface keyed by the SID it was actually
		 * built for so its stale seg6local kernel route/port is removed;
		 * realize recreates it keyed by the new SID.
		 */
		if (!IN6_IS_ADDR_UNSPECIFIED(&evi->local_decap_sid)) {
			zebra_sr6_release(&evi->local_decap_sid, evi->local_decap_bridge_ifindex, false);
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
		ctx.dt2_bd = evi->vni;
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

/*
 * A locator (or its prefix) was DELETED.  Every EVI drawing its SIDs from it
 * holds allocations that no longer exist, but srv6_evi_alloc_sids() short-
 * circuits on the still-"valid" dt2{u,m}_sid_valid flags, so a later port
 * event or realize() would re-send those stale SIDs in ZEBRA_VNI_ADD and let
 * bgpd reinstall/advertise SIDs whose allocations were freed.  Tear each
 * affected EVI's realized state down (withdraw the VNI from bgpd, release the
 * local decap + per-EVI SIDs, clear the valid flags) via unrealize; the EVI
 * config stays, so assigning a new locator (or re-adding this one) re-realizes
 * it through zebra_srv6_evi_on_locator_update().
 */
void zebra_srv6_evi_on_locator_delete(const char *locname)
{
	struct zebra_srv6_evi *evi;

	if (!srv6_evi_inited || !locname || locname[0] == '\0')
		return;

	frr_each_safe (srv6_evi_htab, srv6_evi_table, evi) {
		if (strncmp(evi->locator, locname, sizeof(evi->locator)) != 0)
			continue;
		if (!evi->dt2u_sid_valid && !evi->dt2m_sid_valid)
			continue;

		zlog_info("SRv6 EVI %u: locator %s deleted, invalidating service SIDs",
			  evi->vni, locname);
		zebra_srv6_evi_unrealize(evi);
	}
}

/* -------------------------------------------------------------------------- */
/* Remote BUM (Type-3) handling for SRv6 EVIs                                   */
/* -------------------------------------------------------------------------- */

/*
 * SRv6 BUM endpoint for a remote VTEP/peer (Type-3 IMET carrying a BUM SID).
 * Creates/refreshes/releases the bum-sr6 flood port toward the peer, anchored
 * on the EVI's vlan-aware bridge.  This is the SRv6 backend
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

	/* Track the remote VTEP for BUM-SID bookkeeping. */
	zvtep = zebra_evpn_vtep_find(zevpn, vtep_ip);
	if (!zvtep)
		zvtep = zebra_evpn_vtep_add(zevpn, vtep_ip, VXLAN_FLOOD_DISABLED);
	if (!zvtep)
		return;
	zvtep->gr_refresh_time = monotime(NULL);

	/*
	 * BUM SID changed (peer re-advertised a new value, e.g. after an EVI
	 * delete/re-add).  Prefer updating the existing bum-sr6's encap SID
	 * IN PLACE: this keeps the kernel interface and its ifindex stable, so
	 * the local End.DT2M decap route that uses this bum-sr6 as l2dev is
	 * NOT orphaned.  Only if the in-place update fails do we fall back to
	 * release + recreate (which churns the interface).
	 */
	if (zvtep->has_bum_srv6_sid && bum_sid &&
	    memcmp(&zvtep->bum_srv6_sid, bum_sid, sizeof(zvtep->bum_srv6_sid)) != 0) {
		struct zebra_sr6 *updated = zebra_sr6_update_sid(&zvtep->bum_srv6_sid, bum_sid,
								 zvtep->sr6_bridge_ifindex, true);

		if (updated) {
			/* Stable ifindex; just record the new SID. The local
			 * BUM decap route keeps working on the same oif.
			 */
			zvtep->bum_srv6_sid = *bum_sid;
			zvtep->gr_refresh_time = monotime(NULL);
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u BUM sr6 SID updated in place to %pI6",
					   __func__, zevpn->vni, bum_sid);
			return;
		}

		/* Fallback: in-place update unsupported -> release + recreate. */
		zebra_sr6_release(&zvtep->bum_srv6_sid, zvtep->sr6_bridge_ifindex, true);
		zvtep->has_bum_srv6_sid = false;
	}

	/* Create the bum-sr6 flood port toward the peer's BUM SID. */
	if (bum_sid && !IN6_IS_ADDR_UNSPECIFIED(bum_sid) && !zvtep->has_bum_srv6_sid) {
		/* The EVI VLAN is bound inside get_or_create (port down +
		 * enslaved, before up) so BUM frames egress on the correct
		 * VLAN; default PVID would otherwise drop EVI traffic.
		 */
		struct zebra_sr6 *bum_sr6 = zebra_sr6_get_or_create(bum_sid, br_ifindex,
								       true /* is_bum */,
								       zevpn->vid);

		if (bum_sr6) {
			zvtep->bum_srv6_sid = *bum_sid;
			zvtep->sr6_bridge_ifindex = br_ifindex;
			zvtep->has_bum_srv6_sid = true;
			/* The bum-sr6 oif now exists — re-report the EVI to
			 * bgpd so it installs the local BUM decap SID on this
			 * (current) oif from its interface-add hook.
			 */
			zebra_evpn_send_add_to_client(zevpn);
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: EVI %u BUM sr6 %s for peer SID %pI6", __func__,
					   zevpn->vni, bum_sr6->ifname, bum_sid);
		} else {
			zlog_warn("%s: EVI %u failed to create bum-sr6 for SID %pI6", __func__,
				  zevpn->vni, bum_sid);
		}
	}

	/* BUM SID withdrawn -> release the bum-sr6. */
	if ((!bum_sid || IN6_IS_ADDR_UNSPECIFIED(bum_sid)) && zvtep->has_bum_srv6_sid) {
		zebra_sr6_release(&zvtep->bum_srv6_sid, zvtep->sr6_bridge_ifindex, true);
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
	uint32_t mtu = zebra_sr6_get_mtu();
	bool have_evis = srv6_evi_inited && srv6_evi_htab_count(srv6_evi_table) > 0;

	/* Nothing to persist: no EVIs, MTU unset.  (l2-encap-mode is per EVI.) */
	if (!have_evis && mtu == ZEBRA_SR6_MTU_UNSET)
		return 0;

	vty_out(vty, "  l2-evpn\n");

	/* Device-wide sr6 MTU; only emitted when explicitly configured. */
	if (mtu != ZEBRA_SR6_MTU_UNSET)
		vty_out(vty, "   l2-mtu %u\n", mtu);

	frr_each (srv6_evi_htab, srv6_evi_table, evi) {
		vty_out(vty, "   evi %u", evi->vni);
		if (evi->locator[0])
			vty_out(vty, " locator %s", evi->locator);
		/*
		 * Persist the configured NAME, not bridge_if->name: the binding
		 * must survive a save even when the bridge is not currently
		 * resolved (bridge_if NULL), otherwise `write memory` would drop
		 * it and the EVI would lose its bridge across a reload.
		 */
		if (evi->bridge_name[0])
			vty_out(vty, " bridge %s", evi->bridge_name);
		vty_out(vty, "\n");
		vty_out(vty, "    service-type %s\n", zevpn_l2_service2str(evi->svc_type));
		/* Per-EVI encap mode; only emitted when not the default (full). */
		if (evi->l2_encap_mode != ZEBRA_SR6_ENCAP_MODE_FULL)
			vty_out(vty, "    l2-encap-mode %s\n",
				zebra_sr6_encap_mode2str(evi->l2_encap_mode));
		frr_each (evi_bds, &evi->bds, bd)
			vty_out(vty, "    vlan %u\n", bd->vid);
		if (evi->vrf_id != VRF_DEFAULT)
			vty_out(vty, "    vrf %s\n", vrf_id_to_name(evi->vrf_id));
		/*
		 * Close with "!", not "exit" - "exit" is a generic command
		 * available at virtually every vty node (including the
		 * top-level CONFIG_NODE). In a shared/integrated frr.conf, a
		 * foreign daemon (bgpd, isisd) that doesn't recognize this
		 * EVI block's enclosing commands stays parked at CONFIG_NODE
		 * while skipping each unrecognized line; the bare "exit" then
		 * matches CONFIG_NODE's own exit command, which pops out of
		 * config mode entirely and aborts the rest of the file read
		 * for that daemon (see vty_config_node_exit() in lib/vty.c).
		 * "!" is always a no-op comment, so it's silently skipped by
		 * every daemon regardless of node state - matching the
		 * existing convention used by the sibling locators/locator
		 * blocks in this same file.
		 */
		vty_out(vty, "   !\n");
	}
	vty_out(vty, "  !\n");
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
