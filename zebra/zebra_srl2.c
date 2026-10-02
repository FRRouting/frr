// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 SR-L2 (srl2) tunnel interface management.
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
#include "zebra/zebra_srl2.h"
#include "zebra/zebra_router.h"
#include "zebra/interface.h" /* struct zebra_if, brslave_info */
#include "zebra/zebra_srv6_l2evpn.h"
#include "zebra/zebra_srv6_vpws.h"
#include "zebra/zebra_dplane.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SRL2, "Zebra SRv6 SR-L2 interface");

static void srl2_reset_if(ifindex_t ifindex);
/* -------------------------------------------------------------------------- */
/* Hash / compare helpers                                                      */
/* -------------------------------------------------------------------------- */

static int srl2_htab_cmp(const struct zebra_srl2 *a, const struct zebra_srl2 *b)
{
	return memcmp(&a->sid, &b->sid, sizeof(a->sid));
}

static uint32_t srl2_htab_hash(const struct zebra_srl2 *e)
{
	return jhash(&e->sid, sizeof(e->sid), 0);
}

DECLARE_HASH(srl2_htab, struct zebra_srl2, htab_item, srl2_htab_cmp, srl2_htab_hash);

/* Global hash table: SID (in6_addr) -> struct zebra_srl2 */
static struct srl2_htab_head srl2_table[1];
static bool srl2_inited;

/* Sequential counter for generating unique interface names. */

/*
 * Device-wide sr6 encapsulation mode for srl2 interfaces.  Defaults to FULL;
 * changed via the `l2-encap-mode <full|reduced>` CLI.  Read by rt_netlink.c
 * when it builds the IFLA_SR6_ENCAP_MODE attribute at interface-create time.
 */
static enum zebra_srl2_encap_mode srl2_encap_mode = ZEBRA_SRL2_ENCAP_MODE_FULL;

void zebra_srl2_set_encap_mode(enum zebra_srl2_encap_mode mode)
{
	srl2_encap_mode = mode;
}

enum zebra_srl2_encap_mode zebra_srl2_get_encap_mode(void)
{
	return srl2_encap_mode;
}

const char *zebra_srl2_encap_mode2str(enum zebra_srl2_encap_mode mode)
{
	return mode == ZEBRA_SRL2_ENCAP_MODE_REDUCED ? "reduced" : "full";
}


uint8_t zebra_srl2_kernel_encap_mode(ifindex_t ifindex, uint8_t fallback)
{
	struct interface *ifp;
	struct zebra_if *zif;

	if (ifindex == 0)
		return fallback;
	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
	if (!ifp)
		return fallback;
	zif = ifp->info;
	if (zif && zif->srl2_kernel_mode_present)
		return zif->srl2_kernel_mode;
	return fallback;
}

/*
 * Device-wide MTU for srl2 interfaces.  0 (ZEBRA_SRL2_MTU_UNSET) means "leave
 * it to the kernel sr6 driver default" (= 1422 on a 1500 underlay); a non-zero
 * value is set via `l2-mtu <n>`, emitted as IFLA_MTU at interface-create time
 * (if_netlink.c SRL2_CREATE branch) and pushed live onto existing interfaces
 * here.  See zebra_srl2.h for the underlay-sizing note.
 */
static uint32_t srl2_mtu = ZEBRA_SRL2_MTU_UNSET;

uint32_t zebra_srl2_get_mtu(void)
{
	return srl2_mtu;
}

/*
 * Store the new device-wide MTU and push it live onto every existing
 * srl2/bum-srl2 interface via the DPLANE THREAD (dplane_srl2_program()
 * an RTM_SETLINK IFLA_MTU) so the operator does not have to bounce the EVIs -
 * never synchronous netlink from this (main/CLI) thread.  New interfaces pick
 * the MTU up at create time.
 *
 * On `no l2-mtu` (mtu == ZEBRA_SRL2_MTU_UNSET) we store UNSET (so interfaces
 * created afterwards omit IFLA_MTU and get the sr6 driver default) AND actively
 * reprogram existing interfaces back to ZEBRA_SRL2_DEFAULT_MTU - otherwise the
 * dataplane would keep the previously-configured value until a recreate.  The
 * value actually pushed to the kernel is therefore `apply`, never 0 (the kernel
 * rejects IFLA_MTU 0).
 */
void zebra_srl2_set_mtu(uint32_t mtu)
{
	struct zebra_srl2 *srl2;
	uint32_t apply = (mtu == ZEBRA_SRL2_MTU_UNSET) ? ZEBRA_SRL2_DEFAULT_MTU : mtu;

	srl2_mtu = mtu;

	/* EVPN srl2 / bum-srl2 (this module's own hash). */
	if (srl2_inited)
		frr_each (srl2_htab, srl2_table, srl2) {
			if (srl2->ifindex <= 0)
				continue;
			dplane_srl2_program(srl2->ifindex, &srl2->sid, apply,
					    zebra_srl2_kernel_encap_mode(
						    srl2->ifindex,
						    zebra_srl2_get_encap_mode()));
		}

	/*
	 * VPWS srl2 encap ports live in a separate subsystem/hash
	 * (zebra_srv6_vpws.c) that this walk cannot see, so ask it to
	 * reprogram its own interfaces.  Self-guarded (no-op if VPWS is not
	 * initialised).
	 */
	zebra_srv6_vpws_apply_mtu(apply);
}

void zebra_srl2_walk(void (*cb)(struct zebra_srl2 *srl2, void *arg), void *arg)
{
	struct zebra_srl2 *srl2;

	if (srl2_inited)
		frr_each (srl2_htab, srl2_table, srl2)
			cb(srl2, arg);
}


/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

void zebra_srl2_init(void)
{
	srl2_htab_init(srl2_table);
	srl2_inited = true;
}

/*
 * Delete every srl2/bum-srl2 kernel interface we created.  Called on graceful
 * zebra shutdown (from zebra_finalize) BEFORE the command netlink socket is
 * closed, so these netdevs don't persist after FRR stops.  A hard SIGKILL
 * can't run this; such leftovers are still reclaimed as orphans on next start.
 */
void zebra_srl2_delete_all_kernel(void)
{
	/*
	 * srl2 netdevs are operator-owned - FRR never deletes them.  Retained
	 * as a no-op so the shutdown path (main.c) stays unchanged.
	 */
}

void zebra_srl2_terminate(void)
{
	struct zebra_srl2 *entry;

	if (!srl2_inited)
		return;

	frr_each_safe (srl2_htab, srl2_table, entry) {
		srl2_htab_del(srl2_table, entry);
		XFREE(MTYPE_ZEBRA_SRL2, entry);
	}
	srl2_htab_fini(srl2_table);
	srl2_inited = false;
}

struct zebra_srl2 *zebra_srl2_lookup(const struct in6_addr *sid)
{
	struct zebra_srl2 key = {};

	key.sid = *sid;
	return srl2_htab_find(srl2_table, &key);
}

/*
 * Find an srl2 interface slaved to @bridge_ifindex of the requested purpose
 * (is_bum=false → unicast srl2-N, is_bum=true → bum-srl2-N).  With one bridge
 * per EVI there is exactly one of each; returns the first match or NULL.
 */
struct zebra_srl2 *zebra_srl2_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum)
{
	struct zebra_srl2 *entry;

	if (!srl2_inited || bridge_ifindex == 0)
		return NULL;
	frr_each (srl2_htab, srl2_table, entry)
		if (entry->bridge_ifindex == bridge_ifindex && entry->is_bum == is_bum)
			return entry;
	return NULL;
}

/*
 * Return (or create) the srl2 interface for @sid on bridge @bridge_ifindex.
 * Increments refcnt.
 */
/*
 * Discover the operator-owned srl2 (is_bum=false, prefix "srl2-") or bum-srl2
 * (is_bum=true, prefix "bum-srl2-") interface slaved to @bridge_ifindex.  FRR
 * never creates it.  Returns its ifindex (0 if not present yet) and, when
 * @namebuf is non-NULL, copies its name.
 */
ifindex_t zebra_srl2_discover_on_bridge(ifindex_t bridge_ifindex, bool is_bum, char *namebuf)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	const char *pfx = is_bum ? "bum-srl2-" : "srl2-";
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
 * Program an operator-owned srl2 entry in place with its SID, the device-wide
 * MTU and the kernel-mirrored encap mode.  FRR never creates the interface.
 */
static void srl2_program_if(struct zebra_srl2 *entry)
{
	if (!entry || entry->ifindex == 0)
		return;
	dplane_srl2_program(entry->ifindex, &entry->sid,
			    zebra_srl2_get_mtu() ? zebra_srl2_get_mtu()
						 : ZEBRA_SRL2_DEFAULT_MTU,
			    zebra_srl2_kernel_encap_mode(entry->ifindex,
						 zebra_srl2_get_encap_mode()));
}

struct zebra_srl2 *zebra_srl2_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					    bool is_bum, vlanid_t vid)
{
	struct zebra_srl2 key = {};
	struct zebra_srl2 *entry;
	char ifname[IFNAMSIZ] = {};
	ifindex_t ifindex;

	key.sid = *sid;
	entry = srl2_htab_find(srl2_table, &key);
	if (entry) {
		entry->refcnt++;
		if (entry->ifindex == 0) {
			entry->ifindex = zebra_srl2_discover_on_bridge(bridge_ifindex, is_bum,
								 entry->ifname);
			if (entry->ifindex)
				srl2_program_if(entry);
		}
		return entry;
	}

	/*
	 * Operator-owned model: FRR does NOT create the srl2 netdev.  The operator
	 * pre-creates srl2-<n> (unicast, End.DT2U) / bum-srl2-<n> (BUM, End.DT2M)
	 * and enslaves them to the bridge.  Discover the one for this bridge+role
	 * by name prefix; if not present yet, record the SID (ifindex 0) and
	 * program it when zebra_srl2_if_add() sees the netdev appear.
	 */
	ifindex = zebra_srl2_discover_on_bridge(bridge_ifindex, is_bum, ifname);

	entry = XCALLOC(MTYPE_ZEBRA_SRL2, sizeof(*entry));
	entry->sid = *sid;
	entry->ifindex = ifindex;
	entry->bridge_ifindex = bridge_ifindex;
	entry->vid = vid;
	strlcpy(entry->ifname, ifname, sizeof(entry->ifname));
	entry->refcnt = 1;
	entry->is_bum = is_bum;

	srl2_htab_add(srl2_table, entry);

	if (ifindex)
		srl2_program_if(entry);
	else if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: no %s srl2 on bridge %u yet for SID %pI6 (program on if-add)",
			   __func__, is_bum ? "BUM" : "unicast", bridge_ifindex, sid);

	return entry;
}

/*
 * Interface-add hook (driven from if_add_update()).  When a queued srl2/
 * bum-srl2 netdev appears, record its ifindex, finish the deferred bridge
 * programming through the dplane FIFO (addr-gen-mode -> enslave -> brport ->
 * vlan -> up), and re-realize the EVI on its bridge so local_decap_oif and the
 * remote MAC FDB pick up the now-known ifindex.  Mirrors zebra_srv6_vpws_if_add.
 */
void zebra_srl2_if_add(struct interface *ifp)
{
	struct zebra_srl2 *entry;
	struct zebra_if *zif;
	ifindex_t bridge_ifindex;
	bool is_bum;

	if (!srl2_inited || !ifp || ifp->ifindex == 0)
		return;
	if (strncmp(ifp->name, "bum-srl2-", 9) == 0)
		is_bum = true;
	else if (strncmp(ifp->name, "srl2-", 5) == 0)
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
	frr_each (srl2_htab, srl2_table, entry) {
		if (entry->ifindex != 0 || entry->is_bum != is_bum)
			continue;
		if (bridge_ifindex != 0 && entry->bridge_ifindex != bridge_ifindex)
			continue;

		entry->ifindex = ifp->ifindex;
		strlcpy(entry->ifname, ifp->name, sizeof(entry->ifname));
		srl2_program_if(entry);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: srl2 %s (ifindex %u) appeared; programmed SID %pI6",
				   __func__, ifp->name, ifp->ifindex, &entry->sid);
	}

	if (bridge_ifindex != 0)
		zebra_srv6_l2evpn_realize_on_bridge(bridge_ifindex);
}

/*
 * (Re)bind the EVI VLAN (tagged) onto EVERY srl2/bum-srl2 slaved to
 * @bridge_ifindex.  Idempotent.  Used by realize() to repair ports that were
 * created from a remote Type-2/Type-3 update during a window when the EVI's
 * vid was still 0 (so get_or_create skipped the per-port bind) — they'd
 * otherwise sit on the default PVID only and never carry EVI traffic.
 */
void zebra_srl2_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid)
{
	struct zebra_srl2 *entry;

	if (!srl2_inited || bridge_ifindex == 0 || vid == 0)
		return;

	frr_each (srl2_htab, srl2_table, entry)
		if (entry->bridge_ifindex == bridge_ifindex)
			dplane_srl2_bridge_vlan_add(entry->ifindex, vid, false /* untagged */,
						    false /* pvid */);
}

/*
 * Delete every kernel srl2-* / bum-srl2-* interface slaved to @bridge_ifindex
 * that is NOT tracked in our hash table.  Such interfaces are orphans left by
 * a prior zebra run (srl2 interfaces persist across an FRR restart, but the
 * in-memory table and the name counter are reset) — they would otherwise never
 * be cleaned: the hash-based teardown can't see them, and the create-time
 * orphan pre-delete only catches a name that the counter happens to
 * regenerate.  Scan zebra's interface table by name prefix + bridge master.
 */
static void srl2_release_kernel_orphans_on_bridge(ifindex_t bridge_ifindex,
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
		if (strncmp(ifp->name, "srl2-", 5) != 0 && strncmp(ifp->name, "bum-srl2-", 9) != 0)
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
			zlog_debug("%s: resetting orphan srl2 %s (ifindex %u) on bridge %u (EVI teardown)",
				   __func__, ifp->name, ifp->ifindex, bridge_ifindex);
		srl2_reset_if(ifp->ifindex);
	}
}

/*
 * Force-delete every srl2/bum-srl2 slaved to @bridge_ifindex regardless of
 * refcount (frr_each_safe permits deleting the current entry mid-walk).  Then
 * sweep the kernel for any orphan srl2 on the bridge that isn't tracked in our
 * table (left by a prior zebra run).
 */
void zebra_srl2_release_all_on_bridge(ifindex_t bridge_ifindex)
{
	struct zebra_srl2 *entry;
	ifindex_t reset_ifindexes[64];
	size_t n_reset = 0;

	if (!srl2_inited || bridge_ifindex == 0)
		return;

	frr_each_safe (srl2_htab, srl2_table, entry) {
		if (entry->bridge_ifindex != bridge_ifindex)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: resetting srl2 %s (ifindex %u) SID %pI6 on bridge %u (EVI teardown)",
				   __func__, entry->ifname, entry->ifindex, &entry->sid,
				   bridge_ifindex);

		srl2_reset_if(entry->ifindex);
		if (n_reset < array_size(reset_ifindexes))
			reset_ifindexes[n_reset++] = entry->ifindex;
		srl2_htab_del(srl2_table, entry);
		XFREE(MTYPE_ZEBRA_SRL2, entry);
	}

	/*
	 * Catch interfaces left behind by a previous zebra run (not in table),
	 * skipping the ones just reset above so we don't emit a second, redundant
	 * reset changelink for the same ifindex.
	 */
	srl2_release_kernel_orphans_on_bridge(bridge_ifindex, reset_ifindexes, n_reset);
}

/*
 * Reprogram the encap SID of the srl2 entry currently keyed by @old_sid to
 * @new_sid, IN PLACE — the kernel interface (and its ifindex) is preserved, so
 * any local seg6local decap route using it as l2dev stays valid.  The hash is
 * re-keyed from old_sid to new_sid.  Returns the (same) entry on success, NULL
 * on failure (caller should fall back to release + get_or_create).
 */
struct zebra_srl2 *zebra_srl2_update_sid(const struct in6_addr *old_sid,
					 const struct in6_addr *new_sid)
{
	struct zebra_srl2 *entry = zebra_srl2_lookup(old_sid);

	if (!entry)
		return NULL;

	/* Nothing to do if the SID is unchanged. */
	if (memcmp(&entry->sid, new_sid, sizeof(entry->sid)) == 0)
		return entry;

	/* Reprogram the kernel interface's encap SID in place via the dplane. */
	dplane_srl2_update_sid(entry->ifindex, new_sid);

	/* Re-key the hash entry: remove under old SID, reinsert under new. */
	srl2_htab_del(srl2_table, entry);
	entry->sid = *new_sid;
	srl2_htab_add(srl2_table, entry);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: srl2 %s (ifindex %u) re-keyed to SID %pI6", __func__,
			   entry->ifname, entry->ifindex, new_sid);

	return entry;
}

/*
 * Reset an operator-owned srl2 interface's encap policy in place: program segs
 * :: (stop encapsulating) while keeping the kernel-mirrored MTU and encap mode.
 * The netdev is never deleted.
 */
static void srl2_reset_if(ifindex_t ifindex)
{
	struct in6_addr any = {};

	if (ifindex == 0)
		return;
	dplane_srl2_program(ifindex, &any,
			    zebra_srl2_get_mtu() ? zebra_srl2_get_mtu()
						 : ZEBRA_SRL2_DEFAULT_MTU,
			    zebra_srl2_kernel_encap_mode(ifindex,
						 zebra_srl2_get_encap_mode()));
}

/*
 * Decrement refcount.  Reset the encap policy when it reaches zero; the
 * operator-owned kernel interface is never deleted.
 */
void zebra_srl2_release(const struct in6_addr *sid)
{
	struct zebra_srl2 *entry = zebra_srl2_lookup(sid);

	if (!entry)
		return;

	if (entry->refcnt > 1) {
		entry->refcnt--;
		return;
	}

	/* Last reference - reset the interface (segs ::), keep it in place. */
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: resetting srl2 if %s (ifindex %u) for SID %pI6", __func__,
			   entry->ifname, entry->ifindex, sid);

	srl2_reset_if(entry->ifindex);
	srl2_htab_del(srl2_table, entry);
	XFREE(MTYPE_ZEBRA_SRL2, entry);
}

#else /* !GNU_LINUX - SRv6 L2 EVPN dataplane is netlink-only; stub out */

#include "zebra/zebra_srl2.h"

static enum zebra_srl2_encap_mode srl2_encap_mode = ZEBRA_SRL2_ENCAP_MODE_FULL;

void zebra_srl2_set_encap_mode(enum zebra_srl2_encap_mode mode)
{
	srl2_encap_mode = mode;
}

enum zebra_srl2_encap_mode zebra_srl2_get_encap_mode(void)
{
	return srl2_encap_mode;
}

const char *zebra_srl2_encap_mode2str(enum zebra_srl2_encap_mode mode)
{
	return mode == ZEBRA_SRL2_ENCAP_MODE_REDUCED ? "reduced" : "full";
}


uint8_t zebra_srl2_kernel_encap_mode(ifindex_t ifindex, uint8_t fallback)
{
	return fallback;
}

static uint32_t srl2_mtu = ZEBRA_SRL2_MTU_UNSET;

void zebra_srl2_set_mtu(uint32_t mtu)
{
	srl2_mtu = mtu;
}

uint32_t zebra_srl2_get_mtu(void)
{
	return srl2_mtu;
}

void zebra_srl2_init(void)
{
}

void zebra_srl2_if_add(struct interface *ifp)
{
}

void zebra_srl2_terminate(void)
{
}

void zebra_srl2_delete_all_kernel(void)
{
}

struct zebra_srl2 *zebra_srl2_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					    bool is_bum, vlanid_t vid)
{
	return NULL;
}

void zebra_srl2_release(const struct in6_addr *sid)
{
}

struct zebra_srl2 *zebra_srl2_update_sid(const struct in6_addr *old_sid,
					 const struct in6_addr *new_sid)
{
	return NULL;
}

struct zebra_srl2 *zebra_srl2_lookup(const struct in6_addr *sid)
{
	return NULL;
}

void zebra_srl2_walk(void (*cb)(struct zebra_srl2 *srl2, void *arg), void *arg)
{
}

struct zebra_srl2 *zebra_srl2_find_on_bridge(ifindex_t bridge_ifindex, bool is_bum)
{
	return NULL;
}

ifindex_t zebra_srl2_discover_on_bridge(ifindex_t bridge_ifindex, bool is_bum, char *namebuf)
{
	return 0;
}

void zebra_srl2_release_all_on_bridge(ifindex_t bridge_ifindex)
{
}

void zebra_srl2_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid)
{
}

#endif /* GNU_LINUX */
