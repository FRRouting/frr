// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 SR-L2 (srl2) tunnel interface management.
 * Copyright (C) 2024 FRR Contributors.
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
#include "zebra/zebra_srl2.h"
#include "zebra/zebra_router.h"
#include "zebra/interface.h" /* struct zebra_if, brslave_info */

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SRL2, "Zebra SRv6 SR-L2 interface");

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
static uint32_t srl2_next_id;

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
	srl2_next_id = 0;
}

/*
 * Delete every srl2/bum-srl2 kernel interface we created.  Called on graceful
 * zebra shutdown (from zebra_finalize) BEFORE the command netlink socket is
 * closed, so these netdevs don't persist after FRR stops.  A hard SIGKILL
 * can't run this; such leftovers are still reclaimed as orphans on next start.
 */
void zebra_srl2_delete_all_kernel(void)
{
	struct zebra_srl2 *entry;

	if (srl2_inited)
		frr_each (srl2_htab, srl2_table, entry)
			netlink_srl2_if_del(entry->ifindex);
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
struct zebra_srl2 *zebra_srl2_get_or_create(const struct in6_addr *sid, ifindex_t bridge_ifindex,
					    bool is_bum, vlanid_t vid)
{
	struct zebra_srl2 key = {};
	struct zebra_srl2 *entry;
	char ifname[IFNAMSIZ];
	ifindex_t new_ifindex;

	key.sid = *sid;
	entry = srl2_htab_find(srl2_table, &key);
	if (entry) {
		entry->refcnt++;
		return entry;
	}

	/*
	 * Unicast srl2 (flood off) is named  srl2-N
	 * BUM srl2     (flood on)  is named  bum-srl2-N
	 *
	 * The prefix is the authoritative role marker - bgpd uses it to
	 * pick the right l2dev for DT2U (unicast) vs DT2M (BUM) decap
	 * routes.  Both share the same monotonically-increasing counter
	 * so the resulting kernel ifnames are deterministic and the order
	 * of remote-MAC vs remote-VTEP arrival doesn't matter.
	 */
	if (is_bum)
		snprintf(ifname, sizeof(ifname), "bum-srl2-%u", srl2_next_id++);
	else
		snprintf(ifname, sizeof(ifname), "srl2-%u", srl2_next_id++);

	/*
	 * srl2 interfaces persist across an FRR restart (e.g. zebra running in
	 * a netns), but srl2_next_id restarts at 0 — so a freshly generated
	 * name can collide with an orphaned interface left by a prior zebra
	 * run, causing netlink_srl2_if_add to fail with EEXIST.  Such an
	 * interface is, by definition, not tracked in our table (we only reach
	 * here on a table miss), so it is a stale orphan: delete it before
	 * (re)creating with the current SID.
	 */
	{
		struct interface *orphan = if_lookup_by_name(ifname, VRF_DEFAULT);

		if (orphan && orphan->ifindex) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug("%s: removing stale orphan %s (ifindex %u) before recreate",
					   __func__, ifname, orphan->ifindex);
			netlink_srl2_if_del(orphan->ifindex);
		}
	}

	/* Ask the kernel to create the srl2 interface. */
	new_ifindex = netlink_srl2_if_add(ifname, sid);
	if (new_ifindex <= 0) {
		zlog_err("%s: failed to create srl2 interface %s for SID %pI6", __func__, ifname,
			 sid);
		return NULL;
	}

	/* Add the new interface as a bridge slave. */
	if (bridge_ifindex) {
		if (netlink_srl2_if_set_master(new_ifindex, bridge_ifindex) < 0) {
			zlog_warn("%s: srl2 %s created but failed to add to bridge %u", __func__,
				  ifname, bridge_ifindex);
			/* Continue - FDB may still work if the interface is up. */
		} else {
			if (is_bum) {
				if (netlink_srl2_if_set_brport_bum_flags(new_ifindex) < 0)
					zlog_warn("%s: srl2 %s (BUM): failed to set BUM brport flags",
						  __func__, ifname);
			} else {
				if (netlink_srl2_if_set_brport_flags(new_ifindex) < 0)
					zlog_warn("%s: srl2 %s: failed to set unicast brport flags",
						  __func__, ifname);
			}

			/*
			 * Bind the EVI VLAN (tagged) onto the port while it is
			 * still DOWN and freshly enslaved.  vid 0 (vlan-bundle)
			 * => no VLAN filter.  Must happen before bringing the
			 * port up, otherwise the membership is lost.
			 */
			if (vid)
				netlink_srl2_bridge_vlan_add(new_ifindex, vid, false /* untagged */,
							     false /* pvid */);
		}
	}

	/*
	 * Bring the port UP only now — after enslave + brport flags + VLAN
	 * bind (canonical `ip link add down; set master; bridge vlan add; set
	 * up` ordering).  addr_gen_mode=none was already set while down in
	 * netlink_srl2_if_add(), so no link-local is generated.
	 */
	netlink_srl2_if_up(new_ifindex);

	entry = XCALLOC(MTYPE_ZEBRA_SRL2, sizeof(*entry));
	entry->sid = *sid;
	entry->ifindex = new_ifindex;
	entry->bridge_ifindex = bridge_ifindex;
	strlcpy(entry->ifname, ifname, sizeof(entry->ifname));
	entry->refcnt = 1;
	entry->is_bum = is_bum;

	srl2_htab_add(srl2_table, entry);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: created srl2 if %s ifindex %u for SID %pI6 on bridge %u", __func__,
			   ifname, new_ifindex, sid, bridge_ifindex);

	return entry;
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
			netlink_srl2_bridge_vlan_add(entry->ifindex, vid, false /* untagged */,
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
static void srl2_release_kernel_orphans_on_bridge(ifindex_t bridge_ifindex)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	if (!vrf)
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_if *zif = ifp->info;

		if (!zif)
			continue;
		if (zif->brslave_info.bridge_ifindex != bridge_ifindex)
			continue;
		if (strncmp(ifp->name, "srl2-", 5) != 0 && strncmp(ifp->name, "bum-srl2-", 9) != 0)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: deleting orphan srl2 %s (ifindex %u) on bridge %u (EVI teardown)",
				   __func__, ifp->name, ifp->ifindex, bridge_ifindex);
		netlink_srl2_if_del(ifp->ifindex);
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

	if (!srl2_inited || bridge_ifindex == 0)
		return;

	frr_each_safe (srl2_htab, srl2_table, entry) {
		if (entry->bridge_ifindex != bridge_ifindex)
			continue;

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("%s: force-deleting srl2 %s (ifindex %u) SID %pI6 on bridge %u (EVI teardown)",
				   __func__, entry->ifname, entry->ifindex, &entry->sid,
				   bridge_ifindex);

		netlink_srl2_if_del(entry->ifindex);
		srl2_htab_del(srl2_table, entry);
		XFREE(MTYPE_ZEBRA_SRL2, entry);
	}

	/* Catch interfaces left behind by a previous zebra run (not in table). */
	srl2_release_kernel_orphans_on_bridge(bridge_ifindex);
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

	/* Reprogram the kernel interface's encap SID without recreating it. */
	if (netlink_srl2_if_update_sid(entry->ifindex, new_sid) < 0) {
		zlog_warn("%s: in-place SID update failed for %s (ifindex %u)", __func__,
			  entry->ifname, entry->ifindex);
		return NULL;
	}

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
 * Decrement refcount.  Delete the kernel interface when it reaches zero.
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

	/* Last reference - delete the kernel interface. */
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("%s: deleting srl2 if %s (ifindex %u) for SID %pI6", __func__,
			   entry->ifname, entry->ifindex, sid);

	netlink_srl2_if_del(entry->ifindex);
	srl2_htab_del(srl2_table, entry);
	XFREE(MTYPE_ZEBRA_SRL2, entry);
}

#else /* !GNU_LINUX - SRv6 L2 EVPN dataplane is netlink-only; stub out */

#include "zebra/zebra_srl2.h"

void zebra_srl2_init(void)
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

void zebra_srl2_release_all_on_bridge(ifindex_t bridge_ifindex)
{
}

void zebra_srl2_bind_vlan_on_bridge(ifindex_t bridge_ifindex, vlanid_t vid)
{
}

#endif /* GNU_LINUX */
