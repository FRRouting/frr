// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 SR-L2 (sr6) tunnel interface management.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>

#ifdef GNU_LINUX /* SRv6 L2 EVPN uses the Linux netlink/seg6 dataplane */

#include "lib/hash.h"
#include "lib/jhash.h"
#include "lib/memory.h"
#include "lib/log.h"
#include "lib/if.h"
#include "lib/vrf.h"

#include "zebra/debug.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/zebra_sr6.h"
#include "zebra/zebra_router.h"
#include "zebra/interface.h" /* struct zebra_if, brslave_info */
#include "zebra/zebra_srv6_l2evpn.h"
#include "zebra/zebra_srv6_vpws.h"
#include "zebra/zebra_dplane.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR6, "Zebra SRv6 SR-L2 interface");

static void sr6_reset_if(ifindex_t ifindex, ifindex_t bridge_ifindex);
/* -------------------------------------------------------------------------- */
/* Hash / compare helpers                                                      */
/* -------------------------------------------------------------------------- */

static int sr6_htab_cmp(const struct zebra_sr6 *a, const struct zebra_sr6 *b)
{
	return memcmp(&a->sid, &b->sid, sizeof(a->sid));
}

static uint32_t sr6_htab_hash(const struct zebra_sr6 *e)
{
	return jhash(&e->sid, sizeof(e->sid), 0);
}

DECLARE_HASH(sr6_htab, struct zebra_sr6, htab_item, sr6_htab_cmp, sr6_htab_hash);

/* Global hash table: SID (in6_addr) -> struct zebra_sr6 */
static struct sr6_htab_head sr6_table[1];
static bool sr6_inited;

/* Sequential counter for generating unique interface names. */

/*
 * Fallback sr6 encapsulation mode (FULL) for sr6 interfaces not bound to an
 * EVI.  The operative mode is per EVI: `l2-encap-mode <full|reduced>` inside
 * the EVI node (zebra_srv6_evi_encap_mode_by_bridge()).
 */
static enum zebra_sr6_encap_mode sr6_encap_mode = ZEBRA_SR6_ENCAP_MODE_FULL;

void zebra_sr6_set_encap_mode(enum zebra_sr6_encap_mode mode)
{
	sr6_encap_mode = mode;
}

enum zebra_sr6_encap_mode zebra_sr6_get_encap_mode(void)
{
	return sr6_encap_mode;
}

const char *zebra_sr6_encap_mode2str(enum zebra_sr6_encap_mode mode)
{
	return mode == ZEBRA_SR6_ENCAP_MODE_REDUCED ? "reduced" : "full";
}


uint8_t zebra_sr6_kernel_encap_mode(ifindex_t ifindex, uint8_t fallback)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (ifindex == 0)
		return fallback;
	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
	if (!ifp)
		return fallback;
	zif = ifp->info;
	if (zif && zif->sr6_kernel_mode_present)
		return zif->sr6_kernel_mode;
	return fallback;
}

/*
 * Device-wide MTU for sr6 interfaces.  0 (ZEBRA_SR6_MTU_UNSET) means "leave
 * it to the kernel sr6 driver default" (= 1422 on a 1500 underlay); a non-zero
 * value is set via `l2-mtu <n>`, emitted as IFLA_MTU at interface-create time
 * (if_netlink.c SR6_CREATE branch) and pushed live onto existing interfaces
 * here.  See zebra_sr6.h for the underlay-sizing note.
 */
static uint32_t sr6_mtu = ZEBRA_SR6_MTU_UNSET;

uint32_t zebra_sr6_get_mtu(void)
{
	return sr6_mtu;
}

/*
 * Store the new device-wide MTU and push it live onto every existing
 * sr6/bum-sr6 interface via the DPLANE THREAD (dplane_sr6_program()
 * an RTM_SETLINK IFLA_MTU) so the operator does not have to bounce the EVIs -
 * never synchronous netlink from this (main/CLI) thread.  New interfaces pick
 * the MTU up at create time.
 *
 * On `no l2-mtu` (mtu == ZEBRA_SR6_MTU_UNSET) we store UNSET (so interfaces
 * created afterwards omit IFLA_MTU and get the sr6 driver default) AND actively
 * reprogram existing interfaces back to ZEBRA_SR6_DEFAULT_MTU - otherwise the
 * dataplane would keep the previously-configured value until a recreate.  The
 * value actually pushed to the kernel is therefore `apply`, never 0 (the kernel
 * rejects IFLA_MTU 0).
 */
void zebra_sr6_set_mtu(uint32_t mtu)
{
	struct zebra_sr6 *sr6;
	uint32_t apply = (mtu == ZEBRA_SR6_MTU_UNSET) ? ZEBRA_SR6_DEFAULT_MTU : mtu;

	sr6_mtu = mtu;

	/* EVPN sr6 / bum-sr6 (this module's own hash). */
	if (sr6_inited)
		frr_each (sr6_htab, sr6_table, sr6) {
			if (sr6->ifindex <= 0 || sr6->local_decap)
				continue;
			dplane_sr6_program(sr6->ifindex, &sr6->sid, apply,
					    zebra_srv6_evi_encap_mode_by_bridge(
						    sr6->bridge_ifindex));
		}

	/*
	 * VPWS sr6 encap ports live in a separate subsystem/hash
	 * (zebra_srv6_vpws.c) that this walk cannot see, so ask it to
	 * reprogram its own interfaces.  Self-guarded (no-op if VPWS is not
	 * initialised).
	 */
	zebra_srv6_vpws_apply_mtu(apply);
}

void zebra_sr6_walk(void (*cb)(struct zebra_sr6 *sr6, void *arg), void *arg)
{
	struct zebra_sr6 *sr6;

	if (sr6_inited)
		frr_each (sr6_htab, sr6_table, sr6)
			cb(sr6, arg);
}


/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

void zebra_sr6_init(void)
{
	sr6_htab_init(sr6_table);
	sr6_inited = true;
}

/*
 * Delete every sr6/bum-sr6 kernel interface we created.  Called on graceful
 * zebra shutdown (from zebra_finalize) BEFORE the command netlink socket is
 * closed, so these netdevs don't persist after FRR stops.  A hard SIGKILL
 * can't run this; such leftovers are still reclaimed as orphans on next start.
 */

void zebra_sr6_terminate(void)
{
	struct zebra_sr6 *entry;

	if (!sr6_inited)
		return;

	frr_each_safe (sr6_htab, sr6_table, entry) {
		sr6_htab_del(sr6_table, entry);
		XFREE(MTYPE_ZEBRA_SR6, entry);
	}
	sr6_htab_fini(sr6_table);
	sr6_inited = false;
}

struct zebra_sr6 *zebra_sr6_lookup(const struct in6_addr *sid)
{
	struct zebra_sr6 key = {};

	key.sid = *sid;
	return sr6_htab_find(sr6_table, &key);
}

/*
 * Find an sr6 interface slaved to @bridge_ifindex of the requested purpose
 * (is_bum=false → unicast sr6-N, is_bum=true → bum-sr6-N).  With one bridge
 * per EVI there is exactly one of each; returns the first match or NULL.
 */
struct zebra_sr6 *zebra_sr6_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum)
{
	struct zebra_sr6 *entry;

	if (!sr6_inited || bridge_ifindex == 0)
		return NULL;
	frr_each (sr6_htab, sr6_table, entry)
		if (entry->bridge_ifindex == bridge_ifindex && entry->is_bum == is_bum)
			return entry;
	return NULL;
}

/*
 * Return (or create) the sr6 interface for @sid on bridge @bridge_ifindex.
 * Increments refcnt.
 */
/*
 * Discover the operator-owned sr6 (is_bum=false, prefix "sr6-") or bum-sr6
 * (is_bum=true, prefix "bum-sr6-") interface slaved to @bridge_ifindex.  FRR
 * never creates it.  Returns its ifindex (0 if not present yet) and, when
 * @namebuf is non-NULL, copies its name.
 */
ifindex_t zebra_sr6_discover_on_bridge(ifindex_t bridge_ifindex, bool is_bum, char *namebuf)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	const char *pfx = is_bum ? "bum-sr6-" : "sr6-";
	size_t pfxlen = strlen(pfx);

	if (!vrf || bridge_ifindex == 0)
		return 0;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (!zif || ifp->ifindex == 0)
			continue;
		if (zif->brslave_info.bridge_ifindex != bridge_ifindex)
			continue;
		if (strncmp(ifp->name, pfx, pfxlen) != 0)
			continue;
		if (namebuf)
			strlcpy(namebuf, ifp->name, IFNAMSIZ);
		return ifp->ifindex;
	}
	return 0;
}

/*
 * Program an operator-owned sr6 entry in place with its SID, the device-wide
 * MTU and the owning EVI's configured `l2-encap-mode` (default full).  FRR
 * never creates the interface.
 */
static void sr6_program_if(struct zebra_sr6 *entry)
{
	if (!entry || entry->ifindex == 0)
		return;
	/* Never push our own (local decap) SID as the encap segment. */
	if (entry->local_decap)
		return;
	dplane_sr6_program(entry->ifindex, &entry->sid,
			    zebra_sr6_get_mtu() ? zebra_sr6_get_mtu()
						 : ZEBRA_SR6_DEFAULT_MTU,
			    zebra_srv6_evi_encap_mode_by_bridge(entry->bridge_ifindex));
}

/*
 * Push the owning EVI's (new) `l2-encap-mode` onto every sr6/bum-sr6 on
 * @bridge_ifindex: tracked entries keep their SID, discovered-but-untracked
 * EVI ports (no remote SID yet) are reset (segs ::) with the new mode so the
 * kernel never holds a stale mode.  Driven by the per-EVI CLI.
 */
void zebra_sr6_reprogram_on_bridge(ifindex_t bridge_ifindex)
{
	struct zebra_sr6 *entry;
	bool have_ucast = false, have_bum = false;
	ifindex_t ifindex;

	if (!sr6_inited || bridge_ifindex == 0)
		return;

	frr_each (sr6_htab, sr6_table, entry) {
		if (entry->bridge_ifindex != bridge_ifindex || entry->ifindex == 0)
			continue;
		/* Local decap anchor: shares sr6-<n> with the remote entry but
		 * carries OUR SID - never program it as encap.
		 */
		if (entry->local_decap)
			continue;
		sr6_program_if(entry);
		if (entry->is_bum)
			have_bum = true;
		else
			have_ucast = true;
	}

	if (!have_ucast) {
		ifindex = zebra_sr6_discover_on_bridge(bridge_ifindex, false, NULL);
		if (ifindex)
			sr6_reset_if(ifindex, bridge_ifindex);
	}
	if (!have_bum) {
		ifindex = zebra_sr6_discover_on_bridge(bridge_ifindex, true, NULL);
		if (ifindex)
			sr6_reset_if(ifindex, bridge_ifindex);
	}
}

static struct zebra_sr6 *sr6_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					   bool is_bum, vlanid_t vid, bool local_decap)
{
	struct zebra_sr6 key = {};
	struct zebra_sr6 *entry;
	char ifname[IFNAMSIZ] = {};
	ifindex_t ifindex;

	key.sid = *sid;
	entry = sr6_htab_find(sr6_table, &key);
	if (entry) {
		entry->refcnt++;
		if (entry->ifindex == 0) {
			entry->ifindex = zebra_sr6_discover_on_bridge(bridge_ifindex, is_bum,
								 entry->ifname);
			if (entry->ifindex)
				sr6_program_if(entry);
		}
		return entry;
	}

	/*
	 * Operator-owned model: FRR does NOT create the sr6 netdev.  The operator
	 * pre-creates sr6-<n> (unicast, End.DT2U) / bum-sr6-<n> (BUM, End.DT2M)
	 * and enslaves them to the bridge.  Discover the one for this bridge+role
	 * by name prefix; if not present yet, record the SID (ifindex 0) and
	 * program it when zebra_sr6_if_add() sees the netdev appear.
	 */
	ifindex = zebra_sr6_discover_on_bridge(bridge_ifindex, is_bum, ifname);

	entry = XCALLOC(MTYPE_ZEBRA_SR6, sizeof(*entry));
	entry->sid = *sid;
	entry->ifindex = ifindex;
	entry->bridge_ifindex = bridge_ifindex;
	entry->vid = vid;
	strlcpy(entry->ifname, ifname, sizeof(entry->ifname));
	entry->refcnt = 1;
	entry->is_bum = is_bum;
	entry->local_decap = local_decap; /* set BEFORE any program below */

	sr6_htab_add(sr6_table, entry);

	if (ifindex)
		sr6_program_if(entry); /* no-op for a local decap anchor */
	else if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: no %s sr6 on bridge %u yet for SID %pI6 (program on if-add)",
			   __func__, is_bum ? "BUM" : "unicast", bridge_ifindex, sid);

	return entry;
}

struct zebra_sr6 *zebra_sr6_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					    bool is_bum, vlanid_t vid)
{
	return sr6_get_or_create(sid, bridge_ifindex, is_bum, vid, false);
}

struct zebra_sr6 *zebra_sr6_get_or_create_local_decap(const struct in6_addr *sid,
						       ifindex_t bridge_ifindex, vlanid_t vid)
{
	return sr6_get_or_create(sid, bridge_ifindex, false /* unicast sr6 */, vid, true);
}

/*
 * Interface-add hook (driven from if_add_update()).  When a queued sr6/
 * bum-sr6 netdev appears, record its ifindex, finish the deferred bridge
 * programming through the dplane FIFO (addr-gen-mode -> enslave -> brport ->
 * vlan -> up), and re-realize the EVI on its bridge so local_decap_oif and the
 * remote MAC FDB pick up the now-known ifindex.  Mirrors zebra_srv6_vpws_if_add.
 */
void zebra_sr6_if_add(struct interface *ifp)
{
	struct zebra_sr6 *entry;
	struct zebra_if *zif;
	ifindex_t bridge_ifindex;
	bool is_bum;

	if (!sr6_inited || !ifp || ifp->ifindex == 0)
		return;
	if (strncmp(ifp->name, "bum-sr6-", strlen("bum-sr6-")) == 0)
		is_bum = true;
	else if (strncmp(ifp->name, "sr6-", strlen("sr6-")) == 0)
		is_bum = false;
	else
		return;

	zif = ifp->info;
	bridge_ifindex = zif ? zif->brslave_info.bridge_ifindex : 0;

	/*
	 * Operator-owned interface appeared (or its master/ifindex resolved).
	 * Bind + program any tracked entry that was waiting (ifindex 0).  FRR never
	 * enslaves, brings up or VLAN-binds it - the operator did that.
	 */
	frr_each (sr6_htab, sr6_table, entry) {
		if (entry->ifindex != 0 || entry->is_bum != is_bum)
			continue;
		/*
		 * Bind only when this interface's bridge is known AND matches the
		 * entry's EVI bridge.  The interface-add hook can fire before the
		 * enslave is processed (bridge_ifindex still 0); binding by role
		 * alone would then bind other EVIs' pending SIDs to this netdev.
		 * Defer instead - a later fire (or realize) with the bridge known
		 * binds correctly, matching zebra_sr6_discover_on_bridge().
		 */
		if (bridge_ifindex == 0 || entry->bridge_ifindex != bridge_ifindex)
			continue;

		entry->ifindex = ifp->ifindex;
		strlcpy(entry->ifname, ifp->name, sizeof(entry->ifname));
		sr6_program_if(entry);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: sr6 %s (ifindex %u) appeared; programmed SID %pI6",
				   __func__, ifp->name, ifp->ifindex, &entry->sid);
	}

	if (bridge_ifindex != 0)
		zebra_srv6_l2evpn_realize_on_bridge(bridge_ifindex);
}

/*
 * (Re)bind the EVI VLAN (tagged) onto EVERY sr6/bum-sr6 slaved to
 * @bridge_ifindex.  Idempotent.  Used by realize() to repair ports that were
 * created from a remote Type-2/Type-3 update during a window when the EVI's
 * vid was still 0 (so get_or_create skipped the per-port bind) — they'd
 * otherwise sit on the default PVID only and never carry EVI traffic.
 */
void zebra_sr6_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid)
{
	struct zebra_sr6 *entry;

	if (!sr6_inited || bridge_ifindex == 0 || vid == 0)
		return;

	frr_each (sr6_htab, sr6_table, entry)
		if (entry->bridge_ifindex == bridge_ifindex)
			dplane_sr6_bridge_vlan_add(entry->ifindex, vid, false /* untagged */,
						    false /* pvid */);
}

/*
 * Delete every kernel sr6-* / bum-sr6-* interface slaved to @bridge_ifindex
 * that is NOT tracked in our hash table.  Such interfaces are orphans left by
 * a prior zebra run (sr6 interfaces persist across an FRR restart, but the
 * in-memory table and the name counter are reset) — they would otherwise never
 * be cleaned: the hash-based teardown can't see them, and the create-time
 * orphan pre-delete only catches a name that the counter happens to
 * regenerate.  Scan zebra's interface table by name prefix + bridge master.
 */
static void sr6_release_kernel_orphans_on_bridge(ifindex_t bridge_ifindex,
						  const ifindex_t *skip, size_t nskip)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	if (!vrf)
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;
		size_t i;
		bool handled = false;

		if (!zif)
			continue;
		if (zif->brslave_info.bridge_ifindex != bridge_ifindex)
			continue;
		if (strncmp(ifp->name, "sr6-", strlen("sr6-")) != 0 && strncmp(ifp->name, "bum-sr6-", strlen("bum-sr6-")) != 0)
			continue;

		/*
		 * Skip interfaces the tracked-entry loop already reset in this
		 * teardown.  Those entries have just been removed from the hash,
		 * so a name-prefix match here would otherwise re-reset the SAME
		 * ifindex - a redundant duplicate RTM_NEWLINK changelink in the
		 * same dplane batch.  Only genuinely untracked leftovers (from a
		 * prior zebra run) should be reset here.
		 */
		for (i = 0; i < nskip; i++) {
			if (skip[i] == ifp->ifindex) {
				handled = true;
				break;
			}
		}
		if (handled)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: resetting orphan sr6 %s (ifindex %u) on bridge %u (EVI teardown)",
				   __func__, ifp->name, ifp->ifindex, bridge_ifindex);
		sr6_reset_if(ifp->ifindex, bridge_ifindex);
	}
}

/*
 * Force-delete every sr6/bum-sr6 slaved to @bridge_ifindex regardless of
 * refcount (frr_each_safe permits deleting the current entry mid-walk).  Then
 * sweep the kernel for any orphan sr6 on the bridge that isn't tracked in our
 * table (left by a prior zebra run).
 */
void zebra_sr6_release_all_on_bridge(ifindex_t bridge_ifindex)
{
	struct zebra_sr6 *entry;
	ifindex_t reset_ifindexes[64];
	size_t n_reset = 0;

	if (!sr6_inited || bridge_ifindex == 0)
		return;

	frr_each_safe (sr6_htab, sr6_table, entry) {
		if (entry->bridge_ifindex != bridge_ifindex)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: resetting sr6 %s (ifindex %u) SID %pI6 on bridge %u (EVI teardown)",
				   __func__, entry->ifname, entry->ifindex, &entry->sid,
				   bridge_ifindex);

		sr6_reset_if(entry->ifindex, entry->bridge_ifindex);
		if (n_reset < array_size(reset_ifindexes))
			reset_ifindexes[n_reset++] = entry->ifindex;
		sr6_htab_del(sr6_table, entry);
		XFREE(MTYPE_ZEBRA_SR6, entry);
	}

	/*
	 * Catch interfaces left behind by a previous zebra run (not in table),
	 * skipping the ones just reset above so we don't emit a second, redundant
	 * reset changelink for the same ifindex.
	 */
	sr6_release_kernel_orphans_on_bridge(bridge_ifindex, reset_ifindexes, n_reset);
}

/*
 * Reprogram the encap SID of the sr6 entry currently keyed by @old_sid to
 * @new_sid, IN PLACE — the kernel interface (and its ifindex) is preserved, so
 * any local seg6local decap route using it as l2dev stays valid.  The hash is
 * re-keyed from old_sid to new_sid.  Returns the (same) entry on success, NULL
 * on failure (caller should fall back to release + get_or_create).
 */
struct zebra_sr6 *zebra_sr6_update_sid(const struct in6_addr *old_sid,
					 const struct in6_addr *new_sid)
{
	struct zebra_sr6 *entry = zebra_sr6_lookup(old_sid);

	if (!entry)
		return NULL;

	/* Nothing to do if the SID is unchanged. */
	if (memcmp(&entry->sid, new_sid, sizeof(entry->sid)) == 0)
		return entry;

	/*
	 * Reprogram the kernel interface's encap SID in place via the dplane.
	 * Use the full {MTU, encap-mode, SID} changelink so the EVI's configured
	 * `l2-encap-mode` is preserved (a SID-only update would fall back to the
	 * FULL default and silently undo `l2-encap-mode reduced`).
	 */
	dplane_sr6_program(entry->ifindex, new_sid,
			    zebra_sr6_get_mtu() ? zebra_sr6_get_mtu()
						 : ZEBRA_SR6_DEFAULT_MTU,
			    zebra_srv6_evi_encap_mode_by_bridge(entry->bridge_ifindex));

	/* Re-key the hash entry: remove under old SID, reinsert under new. */
	sr6_htab_del(sr6_table, entry);
	entry->sid = *new_sid;
	sr6_htab_add(sr6_table, entry);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: sr6 %s (ifindex %u) re-keyed to SID %pI6", __func__,
			   entry->ifname, entry->ifindex, new_sid);

	return entry;
}

/*
 * Reset an operator-owned sr6 interface's encap policy in place: program segs
 * :: (stop encapsulating) while keeping the MTU and the owning EVI's
 * `l2-encap-mode` (FULL if no EVI is bound to @bridge_ifindex any more).
 * The netdev is never deleted.
 */
static void sr6_reset_if(ifindex_t ifindex, ifindex_t bridge_ifindex)
{
	struct in6_addr any = {};

	if (ifindex == 0)
		return;
	dplane_sr6_program(ifindex, &any,
			    zebra_sr6_get_mtu() ? zebra_sr6_get_mtu()
						 : ZEBRA_SR6_DEFAULT_MTU,
			    zebra_srv6_evi_encap_mode_by_bridge(bridge_ifindex));
}

/*
 * Decrement refcount.  Reset the encap policy when it reaches zero; the
 * operator-owned kernel interface is never deleted.
 */
void zebra_sr6_release(const struct in6_addr *sid)
{
	struct zebra_sr6 *entry = zebra_sr6_lookup(sid);

	if (!entry)
		return;

	if (entry->refcnt > 1) {
		entry->refcnt--;
		return;
	}

	/*
	 * Last reference.  A local decap anchor shares sr6-<n> with the
	 * peer-keyed entry: just drop it, do NOT reset the netdev (that would
	 * wipe a live remote encap).  Otherwise reset (segs ::), keep it.
	 */
	if (entry->local_decap) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: dropping local decap anchor %s (ifindex %u) SID %pI6",
				   __func__, entry->ifname, entry->ifindex, sid);
		sr6_htab_del(sr6_table, entry);
		XFREE(MTYPE_ZEBRA_SR6, entry);
		return;
	}

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: resetting sr6 if %s (ifindex %u) for SID %pI6", __func__,
			   entry->ifname, entry->ifindex, sid);

	sr6_reset_if(entry->ifindex, entry->bridge_ifindex);
	sr6_htab_del(sr6_table, entry);
	XFREE(MTYPE_ZEBRA_SR6, entry);
}

#else /* !GNU_LINUX - SRv6 L2 EVPN dataplane is netlink-only; stub out */

#include "zebra/zebra_sr6.h"

static enum zebra_sr6_encap_mode sr6_encap_mode = ZEBRA_SR6_ENCAP_MODE_FULL;

void zebra_sr6_set_encap_mode(enum zebra_sr6_encap_mode mode)
{
	sr6_encap_mode = mode;
}

enum zebra_sr6_encap_mode zebra_sr6_get_encap_mode(void)
{
	return sr6_encap_mode;
}

const char *zebra_sr6_encap_mode2str(enum zebra_sr6_encap_mode mode)
{
	return mode == ZEBRA_SR6_ENCAP_MODE_REDUCED ? "reduced" : "full";
}


uint8_t zebra_sr6_kernel_encap_mode(ifindex_t ifindex, uint8_t fallback)
{
	return fallback;
}

static uint32_t sr6_mtu = ZEBRA_SR6_MTU_UNSET;

void zebra_sr6_set_mtu(uint32_t mtu)
{
	sr6_mtu = mtu;
}

uint32_t zebra_sr6_get_mtu(void)
{
	return sr6_mtu;
}

void zebra_sr6_init(void)
{
}

void zebra_sr6_if_add(struct interface *ifp)
{
}

void zebra_sr6_terminate(void)
{
}

struct zebra_sr6 *zebra_sr6_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					    bool is_bum, vlanid_t vid)
{
	return NULL;
}

void zebra_sr6_release(const struct in6_addr *sid)
{
}

struct zebra_sr6 *zebra_sr6_update_sid(const struct in6_addr *old_sid,
					 const struct in6_addr *new_sid)
{
	return NULL;
}

struct zebra_sr6 *zebra_sr6_lookup(const struct in6_addr *sid)
{
	return NULL;
}

void zebra_sr6_walk(void (*cb)(struct zebra_sr6 *sr6, void *arg), void *arg)
{
}

struct zebra_sr6 *zebra_sr6_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum)
{
	return NULL;
}

ifindex_t zebra_sr6_discover_on_bridge(ifindex_t bridge_ifindex, bool is_bum, char *namebuf)
{
	return 0;
}

void zebra_sr6_release_all_on_bridge(ifindex_t bridge_ifindex)
{
}

void zebra_sr6_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid)
{
}

void zebra_sr6_reprogram_on_bridge(ifindex_t bridge_ifindex)
{
}

struct zebra_sr6 *zebra_sr6_get_or_create_local_decap(const struct in6_addr *sid,
						       ifindex_t bridge_ifindex, vlanid_t vid)
{
	return NULL;
}

#endif /* GNU_LINUX */
