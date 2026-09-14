// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN Neighbor code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif

#include "hash.h"
#include "interface.h"
#include "jhash.h"
#include "memory.h"
#include "prefix.h"
#include "vlan.h"
#include "json.h"

#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/rt.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_if.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mac.h"

DEFINE_MTYPE_STATIC(ZEBRA, NEIGH, "EVI Neighbor");

static struct zebra_neigh *zebra_evpn_neigh_add(struct zebra_evpn *zevpn,
						const struct ipaddr *ip,
						const struct ethaddr *mac,
						struct zebra_mac *zmac,
						uint32_t n_flags);
static void zebra_evpn_l3vni_remote_neigh_teardown(struct zebra_evpn *zevpn,
						   struct zebra_neigh *n);
static void zebra_evpn_l3vni_remote_neigh_uninstall(struct zebra_neigh *n);

int neigh_list_cmp(void *p1, void *p2)
{
	const struct zebra_neigh *n1 = p1;
	const struct zebra_neigh *n2 = p2;

	return ipaddr_cmp(&n1->ip, &n2->ip);
}

uint32_t num_dup_detected_neighs(struct zebra_evpn *zevpn)
{
	uint32_t num_neighs = 0;
	struct zebra_neigh *nbr;

	frr_each (zebra_neigh_db, zevpn->neigh_table, nbr)
		if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
			num_neighs++;

	return num_neighs;
}

void zebra_evpn_find_neigh_addr_width(const struct zebra_neigh_db_head *table,
				      int *restrict addr_width, int *restrict r_vtep_width)
{
	const struct zebra_neigh *n;

	frr_each (zebra_neigh_db_const, table, n) {
		char buf[INET6_ADDRSTRLEN];
		int width;

		width = strlen(ipaddr2str(&n->ip, buf, sizeof(buf)));
		if (width > *addr_width)
			*addr_width = width;

		width = strlen(ipaddr2str(&n->r_vtep_ip, buf, sizeof(buf)));
		if (width > *r_vtep_width)
			*r_vtep_width = width;
	}
}

/*
 * Count of remote neighbors referencing this MAC.
 */
int remote_neigh_count(struct zebra_mac *zmac)
{
	struct zebra_neigh *n = NULL;
	struct listnode *node = NULL;
	int count = 0;

	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
			count++;
	}

	return count;
}

/*
 * Install remote neighbor into the kernel.
 */
int zebra_evpn_rem_neigh_install(struct zebra_evpn *zevpn,
				 struct zebra_neigh *n, bool was_static)
{
	struct interface *vlan_if;
	int flags;
	int ret = 0;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	vlan_if = zevpn_map_to_svi(zevpn, true);
	if (!vlan_if)
		return -1;

	flags = DPLANE_NTF_EXT_LEARNED;
	if (n->flags & ZEBRA_NEIGH_ROUTER_FLAG)
		flags |= DPLANE_NTF_ROUTER;
	ZEBRA_NEIGH_SET_ACTIVE(n);

	dplane_rem_neigh_add(vlan_if, &n->ip, &n->emac, flags, was_static);

	return ret;
}

/*
 * Install neighbor hash entry - called upon access VLAN change.
 */
void zebra_evpn_install_neigh_hash(struct zebra_evpn *zevpn, struct zebra_neigh *n)
{
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		zebra_evpn_rem_neigh_install(zevpn, n, false /*was_static*/);
}

/*
 * Callback to allocate neighbor hash entry.
 */
static void *zebra_evpn_neigh_alloc(void *p)
{
	const struct zebra_neigh *tmp_n = p;
	struct zebra_neigh *n;

	n = XCALLOC(MTYPE_NEIGH, sizeof(struct zebra_neigh));
	*n = *tmp_n;

	return ((void *)n);
}

static void zebra_evpn_local_neigh_ref_mac(struct zebra_neigh *n,
					   const struct ethaddr *macaddr,
					   struct zebra_mac *mac,
					   bool send_mac_update)
{
	bool old_static;
	bool new_static;

	memcpy(&n->emac, macaddr, ETH_ALEN);
	n->mac = mac;

	/* Link to new MAC */
	if (!mac)
		return;

	listnode_add_sort(mac->neigh_list, n);
	if (n->flags & ZEBRA_NEIGH_ALL_PEER_FLAGS) {
		old_static = zebra_evpn_mac_is_static(mac);
		++mac->sync_neigh_cnt;
		new_static = zebra_evpn_mac_is_static(mac);
		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug(
				"sync-neigh ref mac vni %u ip %pIA mac %pEA ref %d",
				n->zevpn->vni, &n->ip, &n->emac,
				mac->sync_neigh_cnt);
		if ((old_static != new_static) && send_mac_update)
			/* program the local mac in the kernel */
			zebra_evpn_sync_mac_dp_install(
				mac, false /*set_inactive*/,
				false /*force_clear_static*/, __func__);
	}
}

/* sync-path that is active on an ES peer */
static void zebra_evpn_sync_neigh_dp_install(struct zebra_neigh *n,
					     bool set_inactive,
					     bool force_clear_static,
					     const char *caller)
{
	struct zebra_ns *zns;
	struct interface *ifp;
	bool set_static;
	bool set_router;

	zns = zebra_ns_lookup(NS_DEFAULT);
	ifp = if_lookup_by_index_per_ns(zns, n->ifindex);
	if (!ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug(
				"%s: dp-install sync-neigh vni %u ip %pIA mac %pEA if %d f 0x%x skipped",
				caller, n->zevpn->vni, &n->ip, &n->emac,
				n->ifindex, n->flags);
		return;
	}

	if (force_clear_static)
		set_static = false;
	else
		set_static = zebra_evpn_neigh_is_static(n);

	set_router = !!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

	/* XXX - this will change post integration with the new kernel */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE))
		set_inactive = true;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug(
			"%s: dp-install sync-neigh vni %u ip %pIA mac %pEA if %s(%d) f 0x%x%s%s%s",
			caller, n->zevpn->vni, &n->ip, &n->emac,
			ifp->name, n->ifindex, n->flags,
			set_router ? " router" : "",
			set_static ? " static" : "",
			set_inactive ? " inactive" : "");
	dplane_local_neigh_add(ifp, &n->ip, &n->emac, set_router, set_static,
			       set_inactive);
}

/*
 * Inform BGP about local neighbor addition.
 */
int zebra_evpn_neigh_send_add_to_client(vni_t vni, const struct ipaddr *ip,
					const struct ethaddr *macaddr,
					struct zebra_mac *zmac,
					uint32_t neigh_flags, uint32_t seq)
{
	uint8_t flags = 0;

	if (CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_LOCAL_INACTIVE)) {
		/* host reachability has not been verified locally */

		/* if no ES peer is claiming reachability we can't advertise
		 * the entry
		 */
		if (!CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
			return 0;

		/* ES peers are claiming reachability; we will
		 * advertise the entry but with a proxy flag
		 */
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT);
	}

	if (CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_DEF_GW))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
	/* Set router flag (R-bit) based on local neigh entry add */
	if (CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_ROUTER_FLAG))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);
	if (CHECK_FLAG(neigh_flags, ZEBRA_NEIGH_SVI_IP))
		SET_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP);

	return zebra_evpn_macip_send_msg_to_client(vni, macaddr, ip, flags, seq,
						   ZEBRA_NEIGH_ACTIVE, 0,
						   zmac->es, ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local neighbor deletion.
 */
int zebra_evpn_neigh_send_del_to_client(vni_t vni, struct ipaddr *ip,
					struct ethaddr *macaddr, uint32_t flags,
					int state, bool force)
{
	if (!force) {
		if (CHECK_FLAG(flags, ZEBRA_NEIGH_LOCAL_INACTIVE)
		    && !CHECK_FLAG(flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
			/* the neigh was not advertised - nothing  to delete */
			return 0;
	}

	return zebra_evpn_macip_send_msg_to_client(
		vni, macaddr, ip, 0, 0, state, 0, NULL, ZEBRA_MACIP_DEL);
}

/*
 * Inform BGP about a pure-L3 (no-L2VNI) local neighbor addition. The MAC/IP is
 * tagged ZEBRA_MACIP_TYPE_L3_NEIGH_SYNC and carries the BD VLAN as the ETAG so
 * bgpd originates it as a label[0]=0 RT-2 sourced from the VRF's L3VNI. The ESI
 * is resolved from the neighbor's access BD (its host ES bond) so a receiver
 * can ESI-match the route; es is NULL for a single-homed neighbor.
 */
static int zebra_evpn_neigh_send_add_to_client_l3(vni_t vni,
						  const struct ipaddr *ip,
						  const struct ethaddr *macaddr,
						  vlanid_t eth_tag, uint32_t seq,
						  struct zebra_evpn_es *es)
{
	return zebra_evpn_macip_send_msg_to_client(
		vni, macaddr, ip, ZEBRA_MACIP_TYPE_L3_NEIGH_SYNC, seq,
		ZEBRA_NEIGH_ACTIVE, eth_tag, es, ZEBRA_MACIP_ADD);
}

/* Inform BGP about a pure-L3 (no-L2VNI) local neighbor deletion. */
static int zebra_evpn_neigh_send_del_to_client_l3(vni_t vni,
						  const struct ipaddr *ip,
						  const struct ethaddr *macaddr,
						  vlanid_t eth_tag)
{
	return zebra_evpn_macip_send_msg_to_client(vni, macaddr, ip, 0, 0,
						   ZEBRA_NEIGH_ACTIVE, eth_tag,
						   NULL, ZEBRA_MACIP_DEL);
}

/* Withdraw one pure-L3 neighbor's RT-2, delete its DB entry, and release the
 * singleton hold it took when learned. NOTE: this may free both neigh and
 * (when it was the last holder) zevpn -- callers must not touch either
 * afterwards.
 */
static void zebra_evpn_l3vni_neigh_del_one(struct zebra_evpn *zevpn,
					   struct zebra_neigh *neigh)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_L3_NEIGH)
		zlog_debug("local L3VNI-neigh del ip %pIA mac %pEA L3-VNI %u",
			   &neigh->ip, &neigh->emac, zevpn->vni);

	zebra_evpn_neigh_send_del_to_client_l3(zevpn->vni, &neigh->ip,
					       &neigh->emac, neigh->eth_tag);
	zebra_evpn_neigh_del(zevpn, neigh);

	/* Release this neighbor's hold on the singleton. */
	zebra_evpn_l3_neigh_sync_unref(zevpn);
}

/*
 * Local ARP/ND learn on a no-L2VNI SVI: build a pure-L3 neighbor in the
 * L3VNI-keyed neighbor-sync singleton and advertise it to bgpd. The host MAC
 * is kept in n->emac (it is part of the RT-2 NLRI and becomes the neighbor's
 * lladdr on the peering leaf); the kernel bridge still learns that MAC in the
 * access BD's FDB. The RT-2's ESI is resolved from the neighbor's access BD
 * (its host ES bond) via zebra_evpn_l3vni_neigh_es(). With no L2VNI the BD has
 * no EVPN L2 instance, so no linked zebra_mac is created or advertised as an
 * EVPN MAC route. The existing zebra_evpn_local_neigh_update() cannot be reused
 * here: it dereferences zevpn->vxlan_if (NULL for the singleton) and
 * auto-creates a zebra_mac.
 */
int zebra_evpn_l3vni_local_neigh_update(struct interface *ifp,
					struct interface *br_if,
					const struct ipaddr *ip,
					const struct ethaddr *macaddr,
					bool is_own, bool is_router)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;
	struct zebra_evpn_es *es;
	struct ipaddr vtep_ip = {};
	vni_t vni = 0;
	vlanid_t vid = 0;

	/* Only local learn originates here; remote sync-install is handled by
	 * the RX path in a later phase.
	 */
	if (is_own)
		return 0;

	if (!zebra_evpn_l3vni_neigh_sync_bd(ifp, br_if, &vni, &vtep_ip, &vid)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_L3_NEIGH)
			zlog_debug("local neigh ip %pIA on %s: not an L3VNI-neigh BD",
				   ip, ifp->name);
		return 0;
	}

	zevpn = zebra_evpn_l3_neigh_sync_ref(vni);
	if (!zevpn)
		return 0;
	zevpn->local_vtep_ip = vtep_ip;

	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		/* Keep the hold taken above as this neighbor's reference. */
		n = zebra_evpn_neigh_add(zevpn, ip, macaddr, NULL,
					 ZEBRA_NEIGH_LOCAL);
	} else {
		bool mac_changed = !!memcmp(&n->emac, macaddr, ETH_ALEN);
		bool etag_changed = n->eth_tag != vid;

		/* Existing neighbor: drop the transient hold. */
		zebra_evpn_l3_neigh_sync_unref(zevpn);

		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			/* Local learn supersedes the peer's sync: remove the
			 * remote kernel neighbor and sync-MAC, then re-originate
			 * as local. The remote install's hold carries over as
			 * this local entry's hold.
			 */
			zebra_evpn_l3vni_remote_neigh_uninstall(n);
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
			n->rem_seq = 0;
			if (mac_changed)
				memcpy(&n->emac, macaddr, ETH_ALEN);
		} else if (!mac_changed && !etag_changed &&
			   (is_router ==
			    !!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG))) {
			n->ifindex = ifp->ifindex;
			return 0;
		} else if (mac_changed || etag_changed) {
			/* The RT-2 NLRI key is (MAC, IP, ETAG): a MAC or ETAG
			 * change is a different route (the singleton's neigh
			 * table is IP-keyed and shared across no-L2VNI BDs), so
			 * withdraw the old (old-MAC, IP, old-ETAG) first.
			 */
			zebra_evpn_neigh_send_del_to_client_l3(vni, &n->ip,
							       &n->emac,
							       n->eth_tag);
			if (mac_changed)
				memcpy(&n->emac, macaddr, ETH_ALEN);
		}
	}

	SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	if (is_router)
		SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	n->ifindex = ifp->ifindex;
	n->eth_tag = vid;

	/* Mark active so generic client replay picks it up (zebra_evpn_neigh_add
	 * leaves the entry inactive).
	 */
	ZEBRA_NEIGH_SET_ACTIVE(n);

	if (IS_ZEBRA_DEBUG_EVPN_MH_L3_NEIGH)
		zlog_debug("local L3VNI-neigh add ip %pIA mac %pEA L3-VNI %u ETAG %u",
			   ip, macaddr, vni, vid);

	es = zebra_evpn_l3vni_neigh_es(&n->emac, ifp);
	zebra_evpn_neigh_send_add_to_client_l3(vni, &n->ip, &n->emac,
					       n->eth_tag, n->loc_seq, es);

	/* A multi-member BD with no cached MAC->access-port binding yet resolves
	 * to a zero ESI (the ARP/ND arrived before the bridge FDB notification);
	 * a later real FDB event populates the cache and re-advertises with the
	 * resolved ESI. There is no targeted FDB backfill.
	 */
	return 0;
}

/* Migrate one pure-L3 neighbor into the L2VNI EVI during an ML3->ML2 transition:
 * build the L2 local MAC on its access port (resolved from the BD MAC->port
 * cache, not the SVI) then re-drive the L2 local neighbor, so the transition
 * originates a normal L2 MAC-IP from the existing reachable kernel ARP state.
 * Returns false if the access port is unresolved or either L2 update fails.
 * The caller still drops the pure-L3 copy because the L2VNI owns the BD/ETAG.
 */
static bool zebra_evpn_l3vni_neigh_migrate_to_l2(struct zebra_evpn *l2zevpn,
						 struct interface *svi_ifp,
						 const struct ipaddr *ip,
						 const struct ethaddr *mac,
						 bool is_router, vlanid_t vid)
{
	struct interface *acc_ifp;
	struct zebra_vrf *zvrf;

	if (!l2zevpn || !svi_ifp)
		return false;
	acc_ifp = zebra_evpn_l3vni_neigh_acc_ifp(mac, svi_ifp);
	zvrf = zebra_vrf_get_evpn();
	if (!acc_ifp || !zvrf)
		return false;

	if (zebra_evpn_add_update_local_mac(zvrf, l2zevpn, acc_ifp, mac, vid,
					    false /* sticky */,
					    false /* local_inactive */,
					    false /* dp_static */, NULL) < 0)
		return false;
	if (zebra_evpn_local_neigh_update(l2zevpn, svi_ifp, ip, mac, is_router,
					  false /* local_inactive */,
					  false /* dp_static */) < 0)
		return false;
	return true;
}

/*
 * Local RTM_DELNEIGH on a no-L2VNI SVI: withdraw a pure-L3 synced neighbor.
 * The existing zebra_evpn_neigh_del_ip() rejects a neighbor that has no linked
 * zebra_mac and dereferences vxlan_if, so a dedicated delete is required. The
 * lookup is mode-independent (resolves the L3VNI from the SVI's VRF, not the
 * current mode) so a synced neighbor can still be torn down after the BD
 * has left L3VNI neighbor-sync mode (knob off, L3VNI down, or an L2VNI
 * appeared).
 */
int zebra_evpn_l3vni_local_neigh_del(struct interface *ifp,
				     struct interface *br_if,
				     const struct ipaddr *ip)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;
	vni_t vni = 0;

	if (!zebra_evpn_l3vni_from_svi(ifp, &vni))
		return 0;

	/* Look up without a hold: an empty container must not be resurrected
	 * only to delete nothing.
	 */
	zevpn = zebra_evpn_l3_neigh_sync_lookup(vni);
	if (!zevpn)
		return 0;

	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n || n->mac) /* pure-L3 neighbors have no linked zebra_mac */
		return 0;

	/* Ignore a stale kernel delete from a different SVI than the one this
	 * neighbor is currently installed on (e.g. the old SVI flushed during an
	 * ETAG/service-VLAN move): it must not evict the neighbor on its current
	 * SVI.
	 */
	if (ifp && n->ifindex && ifp->ifindex != n->ifindex)
		return 0;

	/* A kernel delete can also evict a remote synced entry; tear that down
	 * (kernel + sync-MAC, no bgpd withdraw) rather than the local path.
	 */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		zebra_evpn_l3vni_remote_neigh_teardown(zevpn, n);
	else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
		zebra_evpn_l3vni_neigh_del_one(zevpn, n);
	return 0;
}

/* Withdraw and delete every pure-L3 neighbor in a singleton. Used when a
 * BD leaves L3VNI neighbor-sync mode (L3VNI oper-down, knob off) so no stale
 * RT-2, per-neighbor hold, or kernel state is left behind. Locally-learned
 * entries are withdrawn to bgpd; remote synced entries have their kernel
 * neighbor and sync-MAC removed.
 */
void zebra_evpn_l3vni_neigh_flush(struct zebra_evpn *zevpn)
{
	struct zebra_neigh *n;

	if (!zevpn || !CHECK_FLAG(zevpn->flags, ZEVPN_L3_NEIGH_SYNC))
		return;

	/* Pin the singleton across the walk so releasing the last neighbor's
	 * hold does not free it mid-iteration.
	 */
	zevpn->l3_sync_holders++;

	frr_each_safe (zebra_neigh_db, zevpn->neigh_table, n) {
		if (n->mac)
			continue;
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
			zebra_evpn_l3vni_neigh_del_one(zevpn, n);
		else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
			zebra_evpn_l3vni_remote_neigh_teardown(zevpn, n);
	}

	/* Drop the pin; frees the singleton if it is now unheld and empty. */
	zebra_evpn_l3_neigh_sync_unref(zevpn);
}

static void zebra_evpn_l3vni_neigh_flush_cb(struct hash_bucket *bucket,
					    void *arg)
{
	struct zebra_evpn *zevpn = bucket->data;

	if (CHECK_FLAG(zevpn->flags, ZEVPN_L3_NEIGH_SYNC))
		zebra_evpn_l3vni_neigh_flush(zevpn);
}

/* Flush every L3VNI neighbor-sync singleton (e.g. on advertise-l3vni-neigh
 * disable). hash_iterate tolerates deletion of the current element.
 */
void zebra_evpn_l3vni_neigh_flush_all(void)
{
	struct zebra_vrf *zvrf = zebra_vrf_get_evpn();

	if (zvrf && zvrf->evpn_table)
		hash_iterate(zvrf->evpn_table, zebra_evpn_l3vni_neigh_flush_cb,
			     NULL);
}

/* A BD just gained an L2VNI: hand its LOCAL pure-L3 neighbors off to the new
 * L2VNI EVI so the config transition itself re-originates them as normal L2
 * MAC-IP routes from the existing reachable kernel ARP state, then drop the
 * pure-L3 entry. The local kernel neighbor is owned by the kernel and stays in
 * place (as long as it is reachable), so re-driving it through
 * zebra_evpn_local_neigh_update() links the L2 MAC and originates the MAC-IP.
 * REMOTE synced entries are torn down instead; the L2 path relearns them
 * through its own sync.
 */
void zebra_evpn_l3vni_neigh_handoff_bd(vni_t l3vni, vlanid_t vid,
				       struct zebra_evpn *l2zevpn,
				       struct interface *svi_ifp)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;

	zevpn = zebra_evpn_l3_neigh_sync_lookup(l3vni);
	if (!zevpn)
		return;

	/* Pin across the walk so releasing the last hold does not free it. */
	zevpn->l3_sync_holders++;

	frr_each_safe (zebra_neigh_db, zevpn->neigh_table, n) {
		if (n->mac || n->eth_tag != vid)
			continue;

		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			struct ipaddr ip = n->ip;
			struct ethaddr mac = n->emac;

			/* Attempt to migrate to the L2VNI (originates the L2
			 * MAC-IP), then drop the pure-L3 copy regardless: once the
			 * L2VNI owns the BD/ETAG, pure-L3 must relinquish it. If
			 * migration failed (unresolved access port), the L2 path
			 * re-learns the host through its own kernel/sync.
			 */
			zebra_evpn_l3vni_neigh_migrate_to_l2(
				l2zevpn, svi_ifp, &ip, &mac,
				!!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG),
				vid);
			zebra_evpn_l3vni_neigh_del_one(zevpn, n);
		} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			zebra_evpn_l3vni_remote_neigh_teardown(zevpn, n);
		}
	}

	zebra_evpn_l3_neigh_sync_unref(zevpn);
}

/* A BD is losing its L2VNI (ML2 -> ML3): request kernel discovery for its
 * active LOCAL L2 host neighbors, so any still-present host is re-learned
 * through the normal kernel NEWNEIGH path after the bridge/VXLAN
 * reconfiguration. Must run AFTER the BD's L2VNI has been cleared so the
 * pure-L3 BD check passes when the kernel reports the refreshed neighbor.
 */
void zebra_evpn_l2vni_neigh_handoff_to_l3(struct zebra_evpn *l2zevpn,
					  struct interface *svi_ifp)
{
	struct zebra_neigh *n;

	if (!l2zevpn || !svi_ifp)
		return;

	frr_each_safe (zebra_neigh_db, l2zevpn->neigh_table, n) {
		/* Only probe genuine, active local host entries; skip
		 * gateway/SVI-IP control-plane and inactive/suppressed state.
		 */
		if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
			continue;
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW) ||
		    CHECK_FLAG(n->flags, ZEBRA_NEIGH_SVI_IP) ||
		    CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE))
			continue;
		if (!IS_ZEBRA_NEIGH_ACTIVE(n))
			continue;
		dplane_neigh_discover(svi_ifp, &n->ip);
	}
}

/* Re-advertise every pure-L3 neighbor learned for a given host MAC/ETAG after
 * its FDB-derived ESI became known, changed, or was cleared, so the RT-2 and
 * the ARP/ND learn converge regardless of the order the two events arrive in.
 */
void zebra_evpn_l3vni_neigh_readvertise_mac(vni_t l3vni,
					    const struct ethaddr *macaddr,
					    vlanid_t vid)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;

	zevpn = zebra_evpn_l3_neigh_sync_lookup(l3vni);
	if (!zevpn)
		return;

	frr_each_safe (zebra_neigh_db, zevpn->neigh_table, n) {
		struct interface *svi_ifp;

		if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL) || n->mac)
			continue;
		if (n->eth_tag != vid ||
		    memcmp(&n->emac, macaddr, ETH_ALEN) != 0)
			continue;
		if (!IS_ZEBRA_NEIGH_ACTIVE(n))
			continue;

		svi_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
						    n->ifindex);
		zebra_evpn_neigh_send_add_to_client_l3(
			l3vni, &n->ip, &n->emac, n->eth_tag, n->loc_seq,
			zebra_evpn_l3vni_neigh_es(&n->emac, svi_ifp));
	}
}

/* Re-advertise every pure-L3 neighbor of an access BD (all MACs on one ETAG),
 * re-resolving each ESI. Used when a change affects a whole BD rather than a
 * single MAC -- e.g. an access port's ES was added, removed, or toggled bypass,
 * which changes the ESI even for neighbors whose MAC->port binding is not
 * cached (they resolve via the single-member-BD fallback).
 */
void zebra_evpn_l3vni_neigh_readvertise_bd(vni_t l3vni, vlanid_t vid)
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;

	zevpn = zebra_evpn_l3_neigh_sync_lookup(l3vni);
	if (!zevpn)
		return;

	frr_each_safe (zebra_neigh_db, zevpn->neigh_table, n) {
		struct interface *svi_ifp;

		if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL) || n->mac)
			continue;
		if (n->eth_tag != vid || !IS_ZEBRA_NEIGH_ACTIVE(n))
			continue;

		svi_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
						    n->ifindex);
		zebra_evpn_neigh_send_add_to_client_l3(
			l3vni, &n->ip, &n->emac, n->eth_tag, n->loc_seq,
			zebra_evpn_l3vni_neigh_es(&n->emac, svi_ifp));
	}
}


/* Resolve the access-BD SVI for an ETAG within an L3VNI's bridge. Returns the
 * SVI interface (and, when wanted, the access BD) or NULL if not found.
 */
static struct interface *
zebra_evpn_l3vni_etag_svi(vni_t l3vni, vlanid_t vid,
			  struct zebra_evpn_access_bd **acc_bd_out)
{
	struct zebra_l3vni *zl3vni;
	struct zebra_evpn_access_bd *acc_bd;

	zl3vni = zl3vni_lookup(l3vni);
	if (!zl3vni || !zl3vni->bridge_if)
		return NULL;

	acc_bd = zebra_evpn_acc_vl_find(vid, zl3vni->bridge_if);
	if (!acc_bd || !acc_bd->vlan_zif || !acc_bd->vlan_zif->ifp)
		return NULL;

	if (acc_bd_out)
		*acc_bd_out = acc_bd;
	return acc_bd->vlan_zif->ifp;
}

/* Remove the local-ES sync-MAC pinned for a remote pure-L3 neighbor, if any.
 * The exact ES bond it was programmed against is remembered on the neighbor so
 * a MAC/ETAG/ESI change removes the old FDB entry instead of leaking it. The
 * bridge master is resolved from the ES bond's slave-info, not the ETAG's
 * access BD, which a service VLAN move can remove.
 */
static void zebra_evpn_l3vni_sync_mac_del(struct zebra_neigh *n)
{
	struct interface *bond_ifp;
	struct zebra_if *bond_zif;
	struct interface *br_if;

	if (!n->sync_mac_ifindex)
		return;

	bond_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					     n->sync_mac_ifindex);
	bond_zif = bond_ifp ? bond_ifp->info : NULL;
	br_if = bond_zif ? bond_zif->brslave_info.br_if : NULL;
	if (bond_ifp && br_if)
		dplane_local_mac_del(bond_ifp, br_if, n->eth_tag, &n->emac);
	n->sync_mac_ifindex = 0;
}

/* Remove a remote pure-L3 neighbor's kernel state: the NTF_EXT_LEARNED neighbor
 * on its ETAG SVI and its local-ES sync-MAC. Leaves the DB entry in place.
 */
static void zebra_evpn_l3vni_remote_neigh_uninstall(struct zebra_neigh *n)
{
	struct interface *svi_ifp;

	/* Resolve the SVI by the installed ifindex (not the ETAG's access BD,
	 * which a service VLAN move can remove) so the kernel neighbor is not
	 * orphaned.
	 */
	svi_ifp = if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT),
					    n->ifindex);
	if (svi_ifp)
		dplane_rem_neigh_delete(svi_ifp, &n->ip);
	zebra_evpn_l3vni_sync_mac_del(n);
}

/* Fully tear down a remote pure-L3 neighbor: kernel state, DB entry, and the
 * singleton hold it took when installed.
 */
static void zebra_evpn_l3vni_remote_neigh_teardown(struct zebra_evpn *zevpn,
						   struct zebra_neigh *n)
{
	if (IS_ZEBRA_DEBUG_EVPN_MH_L3_NEIGH)
		zlog_debug("remote L3VNI-neigh del ip %pIA mac %pEA L3-VNI %u",
			   &n->ip, &n->emac, zevpn->vni);

	zebra_evpn_l3vni_remote_neigh_uninstall(n);
	zebra_evpn_neigh_del(zevpn, n);
	zebra_evpn_l3_neigh_sync_unref(zevpn);
}

/*
 * Install a pure-L3 (no-L2VNI) synced neighbor received as an ESI-matched
 * label[0]=0 RT-2. There is no L2VNI/zebra_mac: the host MAC lives only on the
 * zebra_neigh (n->mac stays NULL) and the kernel neighbor is programmed
 * NTF_EXT_LEARNED on the ETAG-selected access SVI (no bridge FDB for it). When
 * the RT-2's ESI is a local ES on a no-L2VNI BD, the host MAC is also pinned
 * into the bridge FDB against that ES bond so routed delivery reaches the exact
 * port instead of flooding the VLAN.
 *
 * A locally-learned neighbor for the same host is authoritative (all-active
 * L3MH can see both), so the redundant remote copy is ignored when one exists.
 */
void zebra_evpn_l3vni_remote_neigh_add(vni_t vni, const struct ipaddr *ip,
				       const struct ethaddr *macaddr,
				       vlanid_t eth_tag, uint32_t seq,
				       const esi_t *esi, bool is_router)
{
	struct zebra_evpn *zevpn;
	struct zebra_evpn_access_bd *acc_bd = NULL;
	struct interface *svi_ifp, *bond_ifp = NULL;
	struct zebra_neigh *n;
	struct zebra_evpn_es *es;
	struct zebra_vrf *zvrf;
	ifindex_t desired_mac_ifindex;
	uint32_t flags;

	/* Honor the RX gate: ignore a queued or late ADD once the operator has
	 * disabled advertise-l3vni-neigh (DEL is still processed for cleanup).
	 */
	zvrf = zebra_vrf_get_evpn();
	if (!zvrf || !zvrf->advertise_l3vni_neigh)
		return;

	/* bgpd only sends this ADD for a local ESI, so the ES bond is an up
	 * member of this BD and the BD/SVI normally exists by now. A transient
	 * startup drop (SVI not yet resolved) is re-driven when bgpd re-imports
	 * (ES local-change, knob toggle, or route refresh); a dedicated zebra
	 * pending-install replay is deferred.
	 */
	svi_ifp = zebra_evpn_l3vni_etag_svi(vni, eth_tag, &acc_bd);
	if (!svi_ifp)
		return;

	/* Desired local-ES sync-MAC pin (0 = none): only for a local ES on a
	 * no-L2VNI BD. Computed from the incoming ESI so an ESI change is
	 * reconciled below even when MAC/ETAG are unchanged.
	 */
	es = zebra_evpn_es_find(esi);
	if (es && CHECK_FLAG(es->flags, ZEBRA_EVPNES_LOCAL) && es->zif &&
	    es->zif->ifp && !acc_bd->zevpn)
		bond_ifp = es->zif->ifp;
	desired_mac_ifindex = bond_ifp ? bond_ifp->ifindex : 0;

	zevpn = zebra_evpn_l3_neigh_sync_ref(vni);
	if (!zevpn)
		return;

	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (n && CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
		/* Local learn wins over the peer's redundant sync. */
		zebra_evpn_l3_neigh_sync_unref(zevpn);
		return;
	}

	if (!n) {
		/* Keep the hold taken above as this neighbor's reference. */
		n = zebra_evpn_neigh_add(zevpn, ip, macaddr, NULL,
					 ZEBRA_NEIGH_REMOTE);
	} else {
		bool mac_chg = !!memcmp(&n->emac, macaddr, ETH_ALEN);
		bool etag_chg = n->eth_tag != eth_tag;

		/* Existing remote entry: drop the transient hold. */
		zebra_evpn_l3_neigh_sync_unref(zevpn);

		/* An ETAG change moves the kernel neighbor to another SVI. Delete
		 * the old kernel neighbor by its installed SVI ifindex, not by
		 * re-resolving the ETAG's access BD: a service VLAN move can
		 * remove the old BD, which would orphan the neighbor.
		 */
		if (etag_chg) {
			struct interface *old_svi;

			old_svi = if_lookup_by_index_per_ns(
				zebra_ns_lookup(NS_DEFAULT), n->ifindex);
			if (old_svi)
				dplane_rem_neigh_delete(old_svi, &n->ip);
		}

		/* Remove the old sync-MAC when its pin, MAC, or ETAG changed;
		 * its removal keys off the pre-update emac/eth_tag, so do it
		 * before those are overwritten.
		 */
		if (n->sync_mac_ifindex &&
		    (n->sync_mac_ifindex != desired_mac_ifindex || mac_chg ||
		     etag_chg))
			zebra_evpn_l3vni_sync_mac_del(n);

		memcpy(&n->emac, macaddr, ETH_ALEN);
	}

	UNSET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
	if (is_router)
		SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	n->ifindex = svi_ifp->ifindex;
	n->eth_tag = eth_tag;
	n->rem_seq = seq;

	flags = DPLANE_NTF_EXT_LEARNED;
	if (is_router)
		flags |= DPLANE_NTF_ROUTER;
	ZEBRA_NEIGH_SET_ACTIVE(n);
	dplane_rem_neigh_add(svi_ifp, &n->ip, &n->emac, flags,
			     false /* was_static */);

	if (IS_ZEBRA_DEBUG_EVPN_MH_L3_NEIGH)
		zlog_debug("remote L3VNI-neigh add ip %pIA mac %pEA L3-VNI %u ETAG %u",
			   ip, macaddr, vni, eth_tag);

	/* (Re)install the local-ES sync-MAC against the ES bond (bridge master)
	 * so routed delivery hits the exact port instead of flooding the VLAN.
	 */
	if (bond_ifp && n->sync_mac_ifindex != desired_mac_ifindex &&
	    acc_bd->bridge_zif && acc_bd->bridge_zif->ifp) {
		dplane_local_mac_add(bond_ifp, acc_bd->bridge_zif->ifp, eth_tag,
				     macaddr, false /* sticky */,
				     1 /* set_static: synced */,
				     0 /* set_inactive */);
		n->sync_mac_ifindex = desired_mac_ifindex;
	}
}

/* Withdraw a remote pure-L3 synced neighbor. A locally-learned neighbor for the
 * same host is left untouched (a remote withdraw must not delete local state),
 * and the (MAC, ETAG) must match so a stale withdraw does not delete a newer
 * entry that reused this IP.
 */
void zebra_evpn_l3vni_remote_neigh_del(struct zebra_evpn *zevpn,
				       const struct ipaddr *ip,
				       const struct ethaddr *macaddr,
				       vlanid_t eth_tag)
{
	struct zebra_neigh *n;

	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n || n->mac || !CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		return;

	if (memcmp(&n->emac, macaddr, ETH_ALEN) || n->eth_tag != eth_tag)
		return;

	zebra_evpn_l3vni_remote_neigh_teardown(zevpn, n);
}

static void zebra_evpn_neigh_send_add_del_to_client(struct zebra_neigh *n,
						    bool old_bgp_ready,
						    bool new_bgp_ready)
{
	if (new_bgp_ready)
		zebra_evpn_neigh_send_add_to_client(n->zevpn->vni, &n->ip,
						    &n->emac, n->mac, n->flags,
						    n->loc_seq);
	else if (old_bgp_ready)
		zebra_evpn_neigh_send_del_to_client(n->zevpn->vni, &n->ip,
						    &n->emac, n->flags,
						    n->state, true /*force*/);
}

/* if the static flag associated with the neigh changes we need
 * to update the sync-neigh references against the MAC
 * and inform the dataplane about the static flag changes.
 */
void zebra_evpn_sync_neigh_static_chg(struct zebra_neigh *n, bool old_n_static,
				      bool new_n_static, bool defer_n_dp,
				      bool defer_mac_dp, const char *caller)
{
	struct zebra_mac *mac = n->mac;
	bool old_mac_static;
	bool new_mac_static;

	if (old_n_static == new_n_static)
		return;

	/* update the neigh sync references in the dataplane. if
	 * the neigh is in the middle of updates the caller can
	 * request for a defer
	 */
	if (!defer_n_dp)
		zebra_evpn_sync_neigh_dp_install(n, false /* set_inactive */,
						 false /* force_clear_static */,
						 __func__);

	if (!mac)
		return;

	/* update the mac sync ref cnt */
	old_mac_static = zebra_evpn_mac_is_static(mac);
	if (new_n_static) {
		++mac->sync_neigh_cnt;
	} else if (old_n_static) {
		if (mac->sync_neigh_cnt)
			--mac->sync_neigh_cnt;
	}
	new_mac_static = zebra_evpn_mac_is_static(mac);

	/* update the mac sync references in the dataplane */
	if ((old_mac_static != new_mac_static) && !defer_mac_dp)
		zebra_evpn_sync_mac_dp_install(mac, false /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug(
			"sync-neigh ref-chg vni %u ip %pIA mac %pEA f 0x%x %d%s%s%s%s by %s",
			n->zevpn ? n->zevpn->vni : 0, &n->ip, &n->emac, n->flags,
			mac->sync_neigh_cnt,
			old_n_static ? " old_n_static" : "",
			new_n_static ? " new_n_static" : "",
			old_mac_static ? " old_mac_static" : "",
			new_mac_static ? " new_mac_static" : "", caller);
}

/* Neigh hold timer is used to age out peer-active flag.
 *
 * During this wait time we expect the dataplane component or an
 * external neighmgr daemon to probe existing hosts to independently
 * establish their presence on the ES.
 */
static void zebra_evpn_neigh_hold_exp_cb(struct event *t)
{
	struct zebra_neigh *n;
	bool old_bgp_ready;
	bool new_bgp_ready;
	bool old_n_static;
	bool new_n_static;

	n = EVENT_ARG(t);
	/* the purpose of the hold timer is to age out the peer-active
	 * flag
	 */
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
		return;

	old_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	old_n_static = zebra_evpn_neigh_is_static(n);
	UNSET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);
	new_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	new_n_static = zebra_evpn_neigh_is_static(n);

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug("sync-neigh vni %u ip %pIA mac %pEA 0x%x hold expired",
			   n->zevpn ? n->zevpn->vni : 0, &n->ip, &n->emac, n->flags);

	/* re-program the local neigh in the dataplane if the neigh is no
	 * longer static
	 */
	if (old_n_static != new_n_static)
		zebra_evpn_sync_neigh_static_chg(
			n, old_n_static, new_n_static, false /*defer_n_dp*/,
			false /*defer_mac_dp*/, __func__);

	/* inform bgp if needed */
	if (old_bgp_ready != new_bgp_ready)
		zebra_evpn_neigh_send_add_del_to_client(n, old_bgp_ready,
							new_bgp_ready);
}

static inline void zebra_evpn_neigh_start_hold_timer(struct zebra_neigh *n)
{
	if (event_is_scheduled(n->hold_timer))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH && n->zevpn)
		zlog_debug("sync-neigh vni %u ip %pIA mac %pEA 0x%x hold start",
			   n->zevpn->vni, &n->ip, &n->emac, n->flags);
	event_add_timer(zrouter.master, zebra_evpn_neigh_hold_exp_cb, n,
			zmh_info->neigh_hold_time, &n->hold_timer);
}

static void zebra_evpn_local_neigh_deref_mac(struct zebra_neigh *n,
					     bool send_mac_update)
{
	struct zebra_mac *mac = n->mac;
	struct zebra_evpn *zevpn = n->zevpn;
	bool old_static;
	bool new_static;

	n->mac = NULL;
	if (!mac)
		return;

	if ((n->flags & ZEBRA_NEIGH_ALL_PEER_FLAGS) && mac->sync_neigh_cnt) {
		old_static = zebra_evpn_mac_is_static(mac);
		--mac->sync_neigh_cnt;
		new_static = zebra_evpn_mac_is_static(mac);
		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug(
				"sync-neigh deref mac vni %u ip %pIA mac %pEA ref %d",
				n->zevpn->vni, &n->ip, &n->emac,
				mac->sync_neigh_cnt);
		if ((old_static != new_static) && send_mac_update)
			/* program the local mac in the kernel */
			zebra_evpn_sync_mac_dp_install(
				mac, false /* set_inactive */,
				false /* force_clear_static */, __func__);
	}

	listnode_delete(mac->neigh_list, n);
	zebra_evpn_deref_ip2mac(zevpn, mac);
}

bool zebra_evpn_neigh_is_bgp_seq_ok(struct zebra_evpn *zevpn,
				    struct zebra_neigh *n,
				    const struct ethaddr *macaddr, uint32_t seq,
				    bool sync)
{
	uint32_t tmp_seq;
	const char *n_type;
	bool is_local = false;

	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
		tmp_seq = n->loc_seq;
		n_type = "local";
		is_local = true;
	} else {
		tmp_seq = n->rem_seq;
		n_type = "remote";
	}

	if (seq < tmp_seq) {
		if (is_local && !zebra_evpn_neigh_is_ready_for_bgp(n)) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH ||
			    IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s-macip not ready vni %u %s mac %pEA IP %pIA lower seq %u f 0x%x",
					sync ? "sync" : "remote", zevpn->vni,
					n_type, macaddr, &n->ip, tmp_seq,
					n->flags);
			return true;
		}

		/* if the neigh was never advertised to bgp we must accept
		 * whatever sequence number bgp sends
		 */
		if (!is_local && zebra_vxlan_get_accept_bgp_seq()) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH
			    || IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s-macip accept vni %u %s mac %pEA IP %pIA lower seq %u f 0x%x",
					sync ? "sync" : "remote", zevpn->vni,
					n_type, macaddr, &n->ip,
					tmp_seq, n->flags);
			return true;
		}

		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH || IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s-macip ignore vni %u %s mac %pEA IP %pIA as existing has higher seq %u f 0x%x",
				sync ? "sync" : "remote", zevpn->vni, n_type,
				macaddr, &n->ip, tmp_seq, n->flags);
		return false;
	}

	return true;
}

/*
 * Add neighbor entry.
 */
static struct zebra_neigh *zebra_evpn_neigh_add(struct zebra_evpn *zevpn,
						const struct ipaddr *ip,
						const struct ethaddr *mac,
						struct zebra_mac *zmac,
						uint32_t n_flags)
{
	struct zebra_neigh tmp_n;
	struct zebra_neigh *n = NULL;

	memset(&tmp_n, 0, sizeof(tmp_n));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = zebra_neigh_db_find(zevpn->neigh_table, &tmp_n);
	if (!n) {
		n = zebra_evpn_neigh_alloc(&tmp_n);
		zebra_neigh_db_add(zevpn->neigh_table, n);
	}

	n->state = ZEBRA_NEIGH_INACTIVE;
	n->zevpn = zevpn;
	event_cancel(&n->dad_ip_auto_recovery_timer);
	n->flags = n_flags;
	n->uptime = monotime(NULL);
	n->gr_refresh_time = monotime(NULL);

	if (!zmac)
		zmac = zebra_evpn_mac_lookup(zevpn, mac);
	zebra_evpn_local_neigh_ref_mac(n, mac, zmac,
				       false /* send_mac_update */);

	return n;
}

/*
 * Delete neighbor entry.
 */
int zebra_evpn_neigh_del(struct zebra_evpn *zevpn, struct zebra_neigh *n)
{
	if (n->mac)
		listnode_delete(n->mac->neigh_list, n);

	/* Cancel auto recovery */
	event_cancel(&n->dad_ip_auto_recovery_timer);

	/* Cancel proxy hold timer */
	zebra_evpn_neigh_stop_hold_timer(n);

	/* Free the VNI hash entry and allocated memory. */
	zebra_neigh_db_del(zevpn->neigh_table, n);
	XFREE(MTYPE_NEIGH, n);

	return 0;
}

void zebra_evpn_sync_neigh_del(struct zebra_neigh *n)
{
	bool old_n_static;
	bool new_n_static;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH && n->zevpn)
		zlog_debug("sync-neigh del vni %u ip %pIA mac %pEA f 0x%x",
			   n->zevpn->vni, &n->ip, &n->emac, n->flags);

	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE)) {
		struct zebra_ns *zns = NULL;
		struct interface *ifp = NULL;

		if (n->zevpn && n->zevpn->vxlan_if && n->zevpn->vxlan_if->vrf) {
			struct zebra_vrf *zvrf = n->zevpn->vxlan_if->vrf->info;

			if (zvrf)
				zns = zvrf->zns;
		}

		if (zns)
			ifp = if_lookup_by_index_per_ns(zns, n->ifindex);

		/* Only start the hold timer if the local interface is operative.
		 * If the interface is down, ES_PEER_ACTIVE will stay until
		 * the interface comes up and BGP provides a new update.
		 */

		if (ifp && if_is_operative(ifp)) {
			zebra_evpn_neigh_start_hold_timer(n);
		} else {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH) {
				char if_name_buf[64] = "unknown";

				if (ifp)
					strlcpy(if_name_buf, ifp->name, sizeof(if_name_buf));
				else if (n->ifindex != 0)
					snprintf(if_name_buf, sizeof(if_name_buf), "ifindex %d",
						 n->ifindex);

				zlog_debug("sync-neigh vni %u ip %pIA DEL: ifp %s (idx %d) is not operative, not starting hold_timer for ES_PEER_ACTIVE flag 0x%x",
					   n->zevpn ? n->zevpn->vni : 0, &n->ip, if_name_buf,
					   n->ifindex, n->flags);
			}
		}
	}

	old_n_static = zebra_evpn_neigh_is_static(n);
	UNSET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY);
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
		zebra_evpn_neigh_start_hold_timer(n);
	new_n_static = zebra_evpn_neigh_is_static(n);

	if (old_n_static != new_n_static && n->zevpn)
		zebra_evpn_sync_neigh_static_chg(
			n, old_n_static, new_n_static, false /*defer-dp*/,
			false /*defer_mac_dp*/, __func__);
}

struct zebra_neigh *zebra_evpn_proc_sync_neigh_update(
	struct zebra_evpn *zevpn, struct zebra_neigh *n, uint16_t ipa_len,
	const struct ipaddr *ipaddr, uint8_t flags, uint32_t seq,
	const esi_t *esi, struct zebra_mac *mac)
{
	struct interface *ifp = NULL;
	bool is_router;
	uint32_t tmp_seq;
	bool old_router = false;
	bool old_bgp_ready = false;
	bool new_bgp_ready;
	bool inform_dataplane = false;
	bool inform_bgp = false;
	bool old_mac_static;
	bool new_mac_static;
	bool set_dp_inactive = false;
	bool created;
	ifindex_t ifindex = 0;

	/* locate l3-svi */
	ifp = zevpn_map_to_svi(zevpn, true);
	if (ifp)
		ifindex = ifp->ifindex;

	is_router = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);
	old_mac_static = zebra_evpn_mac_is_static(mac);

	if (!n) {
		uint32_t n_flags = 0;

		/* New neighbor - create */
		SET_FLAG(n_flags, ZEBRA_NEIGH_LOCAL);
		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
			SET_FLAG(n_flags, ZEBRA_NEIGH_ES_PEER_PROXY);
		else
			SET_FLAG(n_flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);
		SET_FLAG(n_flags, ZEBRA_NEIGH_LOCAL_INACTIVE);

		n = zebra_evpn_neigh_add(zevpn, ipaddr, &mac->macaddr, mac,
					 n_flags);
		n->ifindex = ifindex;
		ZEBRA_NEIGH_SET_ACTIVE(n);

		created = true;
		inform_dataplane = true;
		inform_bgp = true;
		set_dp_inactive = true;
	} else {
		bool mac_change;
		uint32_t old_flags = n->flags;
		bool old_n_static;
		bool new_n_static;

		created = false;
		old_n_static = zebra_evpn_neigh_is_static(n);
		old_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
		old_router = !!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

		mac_change = !!memcmp(&n->emac, &mac->macaddr, ETH_ALEN);

		/* deref and clear old info */
		if (mac_change) {
			if (old_bgp_ready) {
				zebra_evpn_neigh_send_del_to_client(
					zevpn->vni, &n->ip, &n->emac, n->flags,
					n->state, false /*force*/);
				old_bgp_ready = false;
			}
			zebra_evpn_local_neigh_deref_mac(n,
							 false /*send_mac_update*/);
		}
		/* clear old fwd info */
		n->rem_seq = 0;
		memset(&n->r_vtep_ip.ip.addr, 0, sizeof(n->r_vtep_ip.ip));

		/* setup new flags */
		n->flags = 0;
		SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
		/* retain activity flag if the neigh was
		 * previously local
		 */
		if (old_flags & ZEBRA_NEIGH_LOCAL) {
			n->flags |= (old_flags & ZEBRA_NEIGH_LOCAL_INACTIVE);
		} else {
			inform_dataplane = true;
			set_dp_inactive = true;
			n->flags |= ZEBRA_NEIGH_LOCAL_INACTIVE;
		}

		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT)) {
			SET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY);
			/* if the neigh was peer-active previously we
			 * need to keep the flag and start the
			 * holdtimer on it. the peer-active flag is
			 * cleared on holdtimer expiry.
			 */
			if (CHECK_FLAG(old_flags, ZEBRA_NEIGH_ES_PEER_ACTIVE)) {
				SET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);
				zebra_evpn_neigh_start_hold_timer(n);
			}
		} else {
			SET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);
			/* stop hold timer if a peer has verified
			 * reachability
			 */
			zebra_evpn_neigh_stop_hold_timer(n);
		}
		ZEBRA_NEIGH_SET_ACTIVE(n);

		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH && (old_flags != n->flags))
			zlog_debug(
				"sync-neigh vni %u ip %pIA mac %pEA old_f 0x%x new_f 0x%x",
				n->zevpn->vni, &n->ip, &n->emac,
				old_flags, n->flags);

		new_n_static = zebra_evpn_neigh_is_static(n);
		if (mac_change) {
			set_dp_inactive = true;
			n->flags |= ZEBRA_NEIGH_LOCAL_INACTIVE;
			inform_dataplane = true;
			zebra_evpn_local_neigh_ref_mac(
				n, &mac->macaddr, mac,
				false /*send_mac_update*/);
		} else if (old_n_static != new_n_static) {
			inform_dataplane = true;
			/* if static flags have changed without a mac change
			 * we need to create the correct sync-refs against
			 * the existing mac
			 */
			zebra_evpn_sync_neigh_static_chg(
				n, old_n_static, new_n_static,
				true /*defer_dp*/, true /*defer_mac_dp*/,
				__func__);
		}

		/* Update the forwarding info. */
		if (n->ifindex != ifindex) {
			n->ifindex = ifindex;
			inform_dataplane = true;
		}

		n->uptime = monotime(NULL);
		n->gr_refresh_time = monotime(NULL);
	}

	/* update the neigh seq. we don't bother with the mac seq as
	 * sync_mac_update already took care of that
	 */
	tmp_seq = MAX(n->loc_seq, seq);
	if (tmp_seq != n->loc_seq) {
		n->loc_seq = tmp_seq;
		inform_bgp = true;
	}

	/* Mark Router flag (R-bit) */
	if (is_router)
		SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

	if (old_router != is_router)
		inform_dataplane = true;

	new_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	if (old_bgp_ready != new_bgp_ready)
		inform_bgp = true;

	new_mac_static = zebra_evpn_mac_is_static(mac);
	if (old_mac_static != new_mac_static)
		zebra_evpn_sync_mac_dp_install(mac, false /* set_inactive */,
					       false /* force_clear_static */,
					       __func__);

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug(
			"sync-neigh %s vni %u ip %pIA mac %pEA if %s(%d) seq %d f 0x%x%s%s",
			created ? "created" : "updated", n->zevpn->vni,
			&n->ip, &n->emac,
			ifp ? ifp->name : "", ifindex, n->loc_seq, n->flags,
			inform_bgp ? " inform_bgp" : "",
			inform_dataplane ? " inform_dp" : "");

	if (inform_dataplane)
		zebra_evpn_sync_neigh_dp_install(n, set_dp_inactive,
						 false /* force_clear_static */,
						 __func__);

	if (inform_bgp)
		zebra_evpn_neigh_send_add_del_to_client(n, old_bgp_ready,
							new_bgp_ready);

	return n;
}

/*
 * Uninstall remote neighbor from the kernel.
 */
static int zebra_evpn_neigh_uninstall(struct zebra_evpn *zevpn,
				      struct zebra_neigh *n)
{
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	vlan_if = zevpn_map_to_svi(zevpn, false);
	if (!vlan_if)
		return -1;

	ZEBRA_NEIGH_SET_INACTIVE(n);
	n->loc_seq = 0;

	dplane_rem_neigh_delete(vlan_if, &n->ip);

	return 0;
}

/*
 * Delete all neighbor entries for this EVPN.
 */
void zebra_evpn_neigh_del_all(struct zebra_evpn *zevpn, int uninstall, int upd_client,
			      uint32_t flags, struct l2vni_walk_ctx *l2_wctx)
{
	struct zebra_neigh *n;

	frr_each_safe (zebra_neigh_db, zevpn->neigh_table, n) {
		bool hit_local = (flags & DEL_LOCAL_NEIGH) && (n->flags & ZEBRA_NEIGH_LOCAL);
		bool hit_remote = (flags & DEL_REMOTE_NEIGH) && (n->flags & ZEBRA_NEIGH_REMOTE);

		if (!hit_local && !hit_remote)
			continue;

		/*
		 * If we are doing stale cleanup of remote neighs
		 * and if this neigh is not marked stale, then don't delete it.
		 */
		if (l2_wctx && l2_wctx->gr_stale_cleanup &&
		    CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE) &&
		    (n->gr_refresh_time > l2_wctx->gr_cleanup_time))
			continue;

		if (upd_client && (n->flags & ZEBRA_NEIGH_LOCAL))
			zebra_evpn_neigh_send_del_to_client(zevpn->vni, &n->ip, &n->emac, n->flags,
							    n->state, false /*force*/);

		if (uninstall) {
			if (zebra_evpn_neigh_is_static(n))
				zebra_evpn_sync_neigh_dp_install(
					n, false /* set_inactive */,
					true /* force_clear_static */,
					__func__);
			if ((n->flags & ZEBRA_NEIGH_REMOTE))
				zebra_evpn_neigh_uninstall(zevpn, n);
		}

		zebra_evpn_neigh_del(zevpn, n);
	}
}

/*
 * Look up neighbor hash entry.
 */
struct zebra_neigh *zebra_evpn_neigh_lookup(struct zebra_evpn *zevpn,
					    const struct ipaddr *ip)
{
	struct zebra_neigh tmp;
	struct zebra_neigh *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	n = zebra_neigh_db_find(zevpn->neigh_table, &tmp);

	return n;
}

/*
 * Process all neighbors associated with a MAC upon the MAC being learnt
 * locally or undergoing any other change (such as sequence number).
 */
void zebra_evpn_process_neigh_on_local_mac_change(struct zebra_evpn *zevpn,
						  struct zebra_mac *zmac,
						  bool seq_change,
						  bool es_change)
{
	struct zebra_neigh *n = NULL;
	struct listnode *node = NULL;
	struct zebra_vrf *zvrf = NULL;

	zvrf = zevpn->vxlan_if->vrf->info;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on local MAC %pEA %s, VNI %u",
			   &zmac->macaddr, seq_change ? "CHANGE" : "ADD",
			   zevpn->vni);

	/* Walk all neighbors and mark any inactive local neighbors as
	 * active and/or update sequence number upon a move, and inform BGP.
	 * The action for remote neighbors is TBD.
	 * NOTE: We can't simply uninstall remote neighbors as the kernel may
	 * accidentally end up deleting a just-learnt local neighbor.
	 */
	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_NEIGH_INACTIVE(n) || seq_change
			    || es_change) {
				ZEBRA_NEIGH_SET_ACTIVE(n);
				n->loc_seq = zmac->loc_seq;
				if (!(zebra_evpn_do_dup_addr_detect(zvrf)
				      && zvrf->dad_freeze
				      && !!CHECK_FLAG(n->flags,
						      ZEBRA_NEIGH_DUPLICATE)))
					zebra_evpn_neigh_send_add_to_client(
						zevpn->vni, &n->ip, &n->emac,
						n->mac, n->flags, n->loc_seq);
			}
		}
	}
}

/*
 * Process all neighbors associated with a local MAC upon the MAC being
 * deleted.
 */
void zebra_evpn_process_neigh_on_local_mac_del(struct zebra_evpn *zevpn,
					       struct zebra_mac *zmac)
{
	struct zebra_neigh *n = NULL;
	struct listnode *node = NULL;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on local MAC %pEA DEL, VNI %u",
			   &zmac->macaddr, zevpn->vni);

	/* Walk all local neighbors and mark as inactive and inform
	 * BGP, if needed.
	 * TBD: There is currently no handling for remote neighbors. We
	 * don't expect them to exist, if they do, do we install the MAC
	 * as a remote MAC and the neighbor as remote?
	 */
	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_NEIGH_ACTIVE(n)) {
				ZEBRA_NEIGH_SET_INACTIVE(n);
				n->loc_seq = 0;
				zebra_evpn_neigh_send_del_to_client(
					zevpn->vni, &n->ip, &n->emac, n->flags,
					ZEBRA_NEIGH_ACTIVE, false /*force*/);
			}
		}
	}
}

/*
 * Process all neighbors associated with a MAC upon the MAC being remotely
 * learnt.
 */
void zebra_evpn_process_neigh_on_remote_mac_add(struct zebra_evpn *zevpn,
						struct zebra_mac *zmac)
{
	struct zebra_neigh *n = NULL;
	struct listnode *node = NULL;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on remote MAC %pEA ADD, VNI %u",
			   &zmac->macaddr, zevpn->vni);

	/* Walk all local neighbors and mark as inactive and inform
	 * BGP, if needed.
	 */
	for (ALL_LIST_ELEMENTS_RO(zmac->neigh_list, node, n)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			if (IS_ZEBRA_NEIGH_ACTIVE(n)) {
				ZEBRA_NEIGH_SET_INACTIVE(n);
				n->loc_seq = 0;
				zebra_evpn_neigh_send_del_to_client(
					zevpn->vni, &n->ip, &n->emac, n->flags,
					ZEBRA_NEIGH_ACTIVE, false /* force */);
			}
		}
	}
}

/*
 * Process all neighbors associated with a remote MAC upon the MAC being
 * deleted.
 */
void zebra_evpn_process_neigh_on_remote_mac_del(struct zebra_evpn *zevpn,
						struct zebra_mac *zmac)
{
	/* NOTE: Currently a NO-OP. */
}

static inline void zebra_evpn_local_neigh_update_log(
	const char *pfx, struct zebra_neigh *n, bool is_router,
	bool local_inactive, bool old_bgp_ready, bool new_bgp_ready,
	bool inform_dataplane, bool inform_bgp, const char *sfx)
{
	if (!IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		return;

	zlog_debug("%s neigh vni %u ip %pIA mac %pEA f 0x%x%s%s%s%s%s%s %s", pfx,
		   n->zevpn->vni, &n->ip, &n->emac, n->flags,
		   is_router ? " router" : "",
		   local_inactive ? " local-inactive" : "",
		   old_bgp_ready ? " old_bgp_ready" : "",
		   new_bgp_ready ? " new_bgp_ready" : "",
		   inform_dataplane ? " inform_dp" : "",
		   inform_bgp ? " inform_bgp" : "", sfx);
}

/* As part Duplicate Address Detection (DAD) for IP mobility
 * MAC binding changes, ensure to inherit duplicate flag
 * from MAC.
 */
static int zebra_evpn_ip_inherit_dad_from_mac(struct zebra_vrf *zvrf,
					      bool is_old_mac_dup,
					      struct zebra_mac *new_zmac,
					      struct zebra_neigh *nbr)
{
	bool is_new_mac_dup = false;

	if (!zebra_evpn_do_dup_addr_detect(zvrf))
		return 0;
	/* Check old or new MAC is detected as duplicate
	 * mark this neigh as duplicate
	 */
	if (new_zmac)
		is_new_mac_dup =
			CHECK_FLAG(new_zmac->flags, ZEBRA_MAC_DUPLICATE);
	/* Old and/or new MAC can be in duplicate state,
	 * based on that IP/Neigh Inherits the flag.
	 * If New MAC is marked duplicate, inherit to the IP.
	 * If old MAC is duplicate but new MAC is not, clear
	 * duplicate flag for IP and reset detection params
	 * and let IP DAD retrigger.
	 */
	if (is_new_mac_dup && !CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
		SET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
		/* Capture Duplicate detection time */
		nbr->dad_dup_detect_time = monotime(NULL);
		/* Mark neigh inactive */
		ZEBRA_NEIGH_SET_INACTIVE(nbr);

		return 1;
	} else if (is_old_mac_dup && !is_new_mac_dup) {
		UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
		nbr->dad_count = 0;
		nbr->detect_start_time.tv_sec = 0;
		nbr->detect_start_time.tv_usec = 0;
	}
	return 0;
}

static void zebra_evpn_dad_ip_auto_recovery_exp(struct event *t)
{
	struct zebra_vrf *zvrf = NULL;
	struct zebra_neigh *nbr = NULL;
	struct zebra_evpn *zevpn = NULL;

	nbr = EVENT_ARG(t);

	/* since this is asynchronous we need sanity checks*/
	zvrf = vrf_info_lookup(nbr->zevpn->vrf_id);
	if (!zvrf)
		return;

	zevpn = zebra_evpn_lookup(nbr->zevpn->vni);
	if (!zevpn)
		return;

	nbr = zebra_evpn_neigh_lookup(zevpn, &nbr->ip);
	if (!nbr)
		return;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%s: duplicate addr MAC %pEA IP %pIA flags 0x%x learn count %u vni %u auto recovery expired",
			__func__, &nbr->emac, &nbr->ip, nbr->flags,
			nbr->dad_count, zevpn->vni);

	UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
	nbr->dad_count = 0;
	nbr->detect_start_time.tv_sec = 0;
	nbr->detect_start_time.tv_usec = 0;
	nbr->dad_dup_detect_time = 0;
	nbr->dad_ip_auto_recovery_timer = NULL;
	ZEBRA_NEIGH_SET_ACTIVE(nbr);

	/* Send to BGP */
	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL)) {
		zebra_evpn_neigh_send_add_to_client(zevpn->vni, &nbr->ip,
						    &nbr->emac, nbr->mac,
						    nbr->flags, nbr->loc_seq);
	} else if (!!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE)) {
		zebra_evpn_rem_neigh_install(zevpn, nbr, false /*was_static*/);
	}
}

static void zebra_evpn_dup_addr_detect_for_neigh(struct zebra_vrf *zvrf, struct zebra_neigh *nbr,
						 struct ipaddr *vtep_ip, bool do_dad,
						 bool *is_dup_detect, bool is_local)
{

	struct timeval elapsed = {0, 0};
	bool reset_params = false;

	if (!zebra_evpn_do_dup_addr_detect(zvrf))
		return;

	/* IP is detected as duplicate or inherit dup
	 * state, hold on to install as remote entry
	 * only if freeze is enabled.
	 */
	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: duplicate addr MAC %pEA IP %pIA flags 0x%x skip installing, learn count %u recover time %u",
				__func__, &nbr->emac, &nbr->ip,
				nbr->flags, nbr->dad_count,
				zvrf->dad_freeze_time);

		if (zvrf->dad_freeze)
			*is_dup_detect = true;

		/* warn-only action, neigh will be installed.
		 * freeze action, it will not be installed.
		 */
		return;
	}

	if (!do_dad)
		return;

	/* Check if detection time (M-secs) expired.
	 * Reset learn count and detection start time.
	 * During remote mac add, count should already be 1
	 * via local learning.
	 */
	monotime_since(&nbr->detect_start_time, &elapsed);
	reset_params = (elapsed.tv_sec > zvrf->dad_time);

	if (is_local && !reset_params) {
		/* RFC-7432: A PE/VTEP that detects a MAC mobility
		 * event via LOCAL learning starts an M-second timer.
		 *
		 * NOTE: This is the START of the probe with count is
		 * 0 during LOCAL learn event.
		 */
		reset_params = !nbr->dad_count;
	}

	if (reset_params) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: duplicate addr MAC %pEA IP %pIA flags 0x%x detection time passed, reset learn count %u",
				__func__, &nbr->emac, &nbr->ip,
				nbr->flags, nbr->dad_count);
		/* Reset learn count but do not start detection
		 * during REMOTE learn event.
		 */
		nbr->dad_count = 0;
		/* Start dup. addr detection (DAD) start time,
		 * ONLY during LOCAL learn.
		 */
		if (is_local)
			monotime(&nbr->detect_start_time);

	} else if (!is_local) {
		/* For REMOTE IP/Neigh, increment detection count
		 * ONLY while in probe window, once window passed,
		 * next local learn event should trigger DAD.
		 */
		nbr->dad_count++;
	}

	/* For LOCAL IP/Neigh learn event, once count is reset above via either
	 * initial/start detection time or passed the probe time, the count
	 * needs to be incremented.
	 */
	if (is_local)
		nbr->dad_count++;

	if (nbr->dad_count >= zvrf->dad_max_moves) {
		flog_warn(EC_ZEBRA_DUP_IP_DETECTED,
			  "VNI %u: MAC %pEA IP %pIA detected as duplicate during %s VTEP %pIA",
			  nbr->zevpn->vni, &nbr->emac, &nbr->ip,
			  is_local ? "local update, last" : "remote update, from", vtep_ip);

		SET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);

		/* Capture Duplicate detection time */
		nbr->dad_dup_detect_time = monotime(NULL);

		/* Start auto recovery timer for this IP */
		event_cancel(&nbr->dad_ip_auto_recovery_timer);
		if (zvrf->dad_freeze && zvrf->dad_freeze_time) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s: duplicate addr MAC %pEA IP %pIA flags 0x%x auto recovery time %u start",
					__func__, &nbr->emac, &nbr->ip,
					nbr->flags, zvrf->dad_freeze_time);

			event_add_timer(zrouter.master,
					zebra_evpn_dad_ip_auto_recovery_exp,
					nbr, zvrf->dad_freeze_time,
					&nbr->dad_ip_auto_recovery_timer);
		}
		if (zvrf->dad_freeze)
			*is_dup_detect = true;
	}
}

int zebra_evpn_local_neigh_update(struct zebra_evpn *zevpn,
				  struct interface *ifp,
				  const struct ipaddr *ip,
				  const struct ethaddr *macaddr, bool is_router,
				  bool local_inactive, bool dp_static)
{
	struct zebra_vrf *zvrf;
	struct zebra_neigh *n = NULL;
	struct zebra_mac *zmac = NULL, *old_zmac = NULL;
	uint32_t old_mac_seq = 0, mac_new_seq = 0;
	bool upd_mac_seq = false;
	bool neigh_mac_change = false;
	bool neigh_on_hold = false;
	bool neigh_was_remote = false;
	bool do_dad = false;
	struct ipaddr vtep_ip = { .ipa_type = IPADDR_NONE };
	bool inform_dataplane = false;
	bool created = false;
	bool new_static = false;
	bool old_bgp_ready = false;
	bool new_bgp_ready;
	bool is_old_mac_dup = false;

	/* Check if the MAC exists. */
	zmac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!zmac) {
		/* create a dummy MAC if the MAC is not already present */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("AUTO MAC %pEA created for neigh %pIA on VNI %u",
				   macaddr, ip, zevpn->vni);

		zmac = zebra_evpn_mac_add_auto(zevpn, macaddr);
		if (!zmac) {
			zlog_debug("Failed to add MAC %pEA VNI %u", macaddr,
				   zevpn->vni);
			return -1;
		}
	} else {
		if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_REMOTE)) {
			/*
			 * We don't change the MAC to local upon a neighbor
			 * learn event, we wait for the explicit local MAC
			 * learn. However, we have to compute its sequence
			 * number in preparation for when it actually turns
			 * local.
			 */
			upd_mac_seq = true;
		}
	}

	zvrf = zevpn->vxlan_if->vrf->info;
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("        Unable to find vrf for: %d",
				   zevpn->vxlan_if->vrf->vrf_id);
		return -1;
	}

	/* Check if the neighbor exists. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		/* New neighbor - create */
		n = zebra_evpn_neigh_add(zevpn, ip, macaddr, zmac, 0);

		/* Set "local" forwarding info. */
		SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
		n->ifindex = ifp->ifindex;
		created = true;
	} else {
		n->gr_refresh_time = monotime(NULL);

		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			bool mac_different;
			bool cur_is_router;
			bool old_local_inactive;

			old_local_inactive = !!CHECK_FLAG(
				n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE);

			old_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);

			/* Note any changes and see if of interest to BGP. */
			mac_different = !!memcmp(&n->emac, macaddr, ETH_ALEN);
			cur_is_router =
				!!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
			new_static = zebra_evpn_neigh_is_static(n);
			if (!mac_different && is_router == cur_is_router
			    && old_local_inactive == local_inactive
			    && dp_static != new_static) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"        Ignoring entry mac is the same and is_router == cur_is_router");
				n->ifindex = ifp->ifindex;
				return 0;
			}

			old_zmac = n->mac;
			if (!mac_different) {
				/* XXX - cleanup this code duplication */
				bool is_neigh_freezed = false;

				/* Only the router flag has changed. */
				if (is_router)
					SET_FLAG(n->flags,
						 ZEBRA_NEIGH_ROUTER_FLAG);
				else
					UNSET_FLAG(n->flags,
						   ZEBRA_NEIGH_ROUTER_FLAG);

				if (local_inactive)
					SET_FLAG(n->flags,
						 ZEBRA_NEIGH_LOCAL_INACTIVE);
				else
					UNSET_FLAG(n->flags,
						   ZEBRA_NEIGH_LOCAL_INACTIVE);
				new_bgp_ready =
					zebra_evpn_neigh_is_ready_for_bgp(n);

				if (dp_static != new_static)
					inform_dataplane = true;

				/* Neigh is in freeze state and freeze action
				 * is enabled, do not send update to client.
				 */
				is_neigh_freezed =
					(zebra_evpn_do_dup_addr_detect(zvrf)
					 && zvrf->dad_freeze
					 && CHECK_FLAG(n->flags,
						       ZEBRA_NEIGH_DUPLICATE));

				zebra_evpn_local_neigh_update_log(
					"local", n, is_router, local_inactive,
					old_bgp_ready, new_bgp_ready, false,
					false, "flag-update");

				if (inform_dataplane)
					zebra_evpn_sync_neigh_dp_install(
						n, false /* set_inactive */,
						false /* force_clear_static */,
						__func__);

				/* if the neigh can no longer be advertised
				 * remove it from bgp
				 */
				if (!is_neigh_freezed) {
					zebra_evpn_neigh_send_add_del_to_client(
						n, old_bgp_ready,
						new_bgp_ready);
				} else {
					if (IS_ZEBRA_DEBUG_VXLAN
					    && IS_ZEBRA_NEIGH_ACTIVE(n))
						zlog_debug(
							"        Neighbor active and frozen");
				}
				return 0;
			}

			/* The MAC has changed, need to issue a delete
			 * first as this means a different MACIP route.
			 * Also, need to do some unlinking/relinking.
			 * We also need to update the MAC's sequence number
			 * in different situations.
			 */
			if (old_bgp_ready) {
				zebra_evpn_neigh_send_del_to_client(
					zevpn->vni, &n->ip, &n->emac, n->flags,
					n->state, false /*force*/);
				old_bgp_ready = false;
			}
			if (old_zmac) {
				is_old_mac_dup = CHECK_FLAG(old_zmac->flags, ZEBRA_MAC_DUPLICATE);
				old_mac_seq = CHECK_FLAG(old_zmac->flags,
							 ZEBRA_MAC_REMOTE)
						      ? old_zmac->rem_seq
						      : old_zmac->loc_seq;
				neigh_mac_change = upd_mac_seq = true;
				zebra_evpn_local_neigh_deref_mac(
					n, true /* send_mac_update */);
			}

			/* if mac changes abandon peer flags and tell
			 * dataplane to clear the static flag
			 */
			if (zebra_evpn_neigh_clear_sync_info(n))
				inform_dataplane = true;
			/* Update the forwarding info. */
			n->ifindex = ifp->ifindex;

			/* Link to new MAC */
			zebra_evpn_local_neigh_ref_mac(
				n, macaddr, zmac, true /* send_mac_update */);
		} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			/*
			 * Neighbor has moved from remote to local. Its
			 * MAC could have also changed as part of the move.
			 */
			if (memcmp(n->emac.octet, macaddr->octet, ETH_ALEN)
			    != 0) {
				old_zmac = n->mac;
				if (old_zmac) {
					is_old_mac_dup = CHECK_FLAG(old_zmac->flags, ZEBRA_MAC_DUPLICATE);
					old_mac_seq =
						CHECK_FLAG(old_zmac->flags,
							   ZEBRA_MAC_REMOTE)
							? old_zmac->rem_seq
							: old_zmac->loc_seq;
					neigh_mac_change = upd_mac_seq = true;
					zebra_evpn_local_neigh_deref_mac(
						n, true /* send_update */);
				}

				/* Link to new MAC */
				zebra_evpn_local_neigh_ref_mac(
					n, macaddr, zmac, true /*send_update*/);
			}
			/* Based on Mobility event Scenario-B from the
			 * draft, neigh's previous state was remote treat this
			 * event for DAD.
			 */
			neigh_was_remote = true;
			vtep_ip = n->r_vtep_ip;
			/* Mark appropriately */
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
			memset(&n->r_vtep_ip.ip.addr, 0, sizeof(n->r_vtep_ip.ip));
			SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
			n->ifindex = ifp->ifindex;
		}
	}

	/* If MAC was previously remote, or the neighbor had a different
	 * MAC earlier, recompute the sequence number.
	 */
	if (upd_mac_seq) {
		uint32_t seq1, seq2;

		seq1 = CHECK_FLAG(zmac->flags, ZEBRA_MAC_REMOTE)
			       ? zmac->rem_seq + 1
			       : zmac->loc_seq;
		seq2 = neigh_mac_change ? old_mac_seq + 1 : 0;
		mac_new_seq = zmac->loc_seq < MAX(seq1, seq2) ? MAX(seq1, seq2)
							      : zmac->loc_seq;
	}

	if (local_inactive)
		SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE);

	/* Mark Router flag (R-bit) */
	if (is_router)
		SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

	/* if zebra and dataplane don't agree this is a sync entry
	 * re-install in the dataplane */
	new_static = zebra_evpn_neigh_is_static(n);
	if (dp_static != new_static)
		inform_dataplane = true;

	/* Check old and/or new MAC detected as duplicate mark
	 * the neigh as duplicate
	 */
	if (zebra_evpn_ip_inherit_dad_from_mac(zvrf, is_old_mac_dup, zmac, n)) {
		flog_warn(
			EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
			"VNI %u: MAC %pEA IP %pIA detected as duplicate during local update, inherit duplicate from MAC",
			zevpn->vni, macaddr, &n->ip);
	}

	/* For IP Duplicate Address Detection (DAD) is trigger,
	 * when the event is extended mobility based on scenario-B
	 * from the draft, IP/Neigh's MAC binding changed and
	 * neigh's previous state was remote.
	 */
	if (neigh_mac_change && neigh_was_remote)
		do_dad = true;

	zebra_evpn_dup_addr_detect_for_neigh(zvrf, n, &vtep_ip, do_dad, &neigh_on_hold, true);

	if (inform_dataplane)
		zebra_evpn_sync_neigh_dp_install(n, false /* set_inactive */,
						 false /* force_clear_static */,
						 __func__);

	/* Before we program this in BGP, we need to check if MAC is locally
	 * learnt. If not, force neighbor to be inactive and reset its seq.
	 */
	if (!CHECK_FLAG(zmac->flags, ZEBRA_MAC_LOCAL)) {
		zebra_evpn_local_neigh_update_log(
			"local", n, is_router, local_inactive, false, false,
			inform_dataplane, false, "auto-mac");
		ZEBRA_NEIGH_SET_INACTIVE(n);
		n->loc_seq = 0;
		zmac->loc_seq = mac_new_seq;
		return 0;
	}

	zebra_evpn_local_neigh_update_log("local", n, is_router, local_inactive,
					  false, false, inform_dataplane, true,
					  created ? "created" : "updated");

	/* If the MAC's sequence number has changed, inform the MAC and all
	 * neighbors associated with the MAC to BGP, else just inform this
	 * neighbor.
	 */
	if (upd_mac_seq && zmac->loc_seq != mac_new_seq) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Seq changed for MAC %pEA VNI %u - old %u new %u",
				macaddr, zevpn->vni,
				zmac->loc_seq, mac_new_seq);
		zmac->loc_seq = mac_new_seq;
		if (zebra_evpn_mac_send_add_to_client(zevpn->vni, macaddr,
						      zmac->flags,
						      zmac->loc_seq, zmac->es))
			return -1;
		zebra_evpn_process_neigh_on_local_mac_change(zevpn, zmac, 1,
							     0 /*es_change*/);
		return 0;
	}

	n->loc_seq = zmac->loc_seq;

	if (!neigh_on_hold) {
		ZEBRA_NEIGH_SET_ACTIVE(n);
		new_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
		zebra_evpn_neigh_send_add_del_to_client(n, old_bgp_ready,
							new_bgp_ready);
	} else {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("        Neighbor on hold not sending");
	}
	return 0;
}

static void zebra_evpn_stale_remote_neigh_add(struct zebra_evpn *zevpn, const struct ipaddr *ip,
					      const struct ethaddr *macaddr, bool is_router)
{
	struct zebra_neigh *n = NULL;
	struct zebra_mac *zmac = NULL;

	/* Nothing to do if the entry already exists */
	if (zebra_evpn_neigh_lookup(zevpn, ip))
		return;

	/* Check if the MAC exists. */
	zmac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!zmac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("EVPN-GR: zmac for MAC %pEA not found. L2VNI %u", macaddr,
				   zevpn->vni);
		return;
	}

	/* New neighbor - create */
	n = zebra_evpn_neigh_add(zevpn, ip, macaddr, zmac, 0);
	if (!n) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("EVPN-GR: Can't create neigh entry for IP %pIA MAC %pEA, L2VNI %u",
				   ip, macaddr, zevpn->vni);
		return;
	}

	/* Set "remote" forwarding info. */
	SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
	ZEBRA_NEIGH_SET_ACTIVE(n);
	n->r_vtep_ip = zmac->fwd_info.r_vtep_ip;

	if (is_router)
		SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
	else
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("EVPN-GR: Added stale remote %sneigh entry IP %pIA MAC %pEA, L2VNI %u",
			   is_router ? "router " : "", ip, macaddr, zevpn->vni);
}

int zebra_evpn_remote_neigh_update(struct zebra_evpn *zevpn, struct interface *ifp,
				   const struct ipaddr *ip, const struct ethaddr *macaddr,
				   uint16_t state, bool is_router)
{
	struct zebra_neigh *n = NULL;
	struct zebra_mac *zmac = NULL;

	/* If the neighbor is unknown, there is no further action. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		if (zrouter.graceful_restart)
			zebra_evpn_stale_remote_neigh_add(zevpn, ip, macaddr, is_router);
		return 0;
	}

	/* If a remote entry, see if it needs to be refreshed */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
#ifdef GNU_LINUX
		if (state & NUD_STALE)
			zebra_evpn_rem_neigh_install(zevpn, n,
						     false /*was_static*/);
#endif
	} else {
		/* We got a "remote" neighbor notification for an entry
		 * we think is local. This can happen in a multihoming
		 * scenario - but only if the MAC is already "remote".
		 * Just mark our entry as "remote".
		 */
		zmac = zebra_evpn_mac_lookup(zevpn, macaddr);
		if (!zmac || !CHECK_FLAG(zmac->flags, ZEBRA_MAC_REMOTE)) {
			zlog_debug(
				"Ignore remote neigh %pIA (MAC %pEA) on L2-VNI %u - MAC unknown or local",
				&n->ip, macaddr, zevpn->vni);
			return -1;
		}

		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ALL_LOCAL_FLAGS);
		SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);
		ZEBRA_NEIGH_SET_ACTIVE(n);
		n->r_vtep_ip = zmac->fwd_info.r_vtep_ip;
	}

	return 0;
}

/* Notify Neighbor entries to the Client, skips the GW entry */
static void zebra_evpn_send_neigh_hash_entry_to_client(struct mac_walk_ctx *wctx,
						       struct zebra_neigh *zn)
{
	struct zebra_mac *zmac = NULL;

	if (CHECK_FLAG(zn->flags, ZEBRA_NEIGH_DEF_GW))
		return;

	if (!CHECK_FLAG(zn->flags, ZEBRA_NEIGH_LOCAL) ||
	    !IS_ZEBRA_NEIGH_ACTIVE(zn))
		return;

	/* Pure-L3 (no-L2VNI) neighbors carry the host MAC in emac but have no
	 * linked zebra_mac; replay them tagged as L3-neigh-sync, skipping the
	 * zebra_mac lookup the L2 path requires. Re-resolve the ESI from the
	 * neighbor's SVI so a changed ES state is reflected on replay.
	 */
	if (CHECK_FLAG(wctx->zevpn->flags, ZEVPN_L3_NEIGH_SYNC)) {
		struct interface *svi_ifp = if_lookup_by_index_per_ns(
			zebra_ns_lookup(NS_DEFAULT), zn->ifindex);

		zebra_evpn_neigh_send_add_to_client_l3(
			wctx->zevpn->vni, &zn->ip, &zn->emac, zn->eth_tag,
			zn->loc_seq,
			zebra_evpn_l3vni_neigh_es(&zn->emac, svi_ifp));
		return;
	}

	zmac = zebra_evpn_mac_lookup(wctx->zevpn, &zn->emac);
	if (!zmac)
		return;

	zebra_evpn_neigh_send_add_to_client(wctx->zevpn->vni, &zn->ip,
					    &zn->emac, zn->mac, zn->flags,
					    zn->loc_seq);
}

/* Iterator of a specific EVPN */
void zebra_evpn_send_neigh_to_client(struct zebra_evpn *zevpn)
{
	struct mac_walk_ctx wctx;
	struct zebra_neigh *n;

	memset(&wctx, 0, sizeof(wctx));
	wctx.zevpn = zevpn;

	frr_each (zebra_neigh_db, zevpn->neigh_table, n)
		zebra_evpn_send_neigh_hash_entry_to_client(&wctx, n);
}

void zebra_evpn_clear_dup_neigh_hash(struct zebra_evpn *zevpn, struct zebra_neigh *nbr)
{
	char buf[INET6_ADDRSTRLEN];

	if (!nbr)
		return;

	if (!CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
		return;

	if (IS_ZEBRA_DEBUG_VXLAN) {
		ipaddr2str(&nbr->ip, buf, sizeof(buf));
		zlog_debug("%s: clear neigh %s dup state, flags 0x%x seq %u",
			   __func__, buf, nbr->flags, nbr->loc_seq);
	}

	UNSET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);
	nbr->dad_count = 0;
	nbr->detect_start_time.tv_sec = 0;
	nbr->detect_start_time.tv_usec = 0;
	nbr->dad_dup_detect_time = 0;
	event_cancel(&nbr->dad_ip_auto_recovery_timer);

	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_LOCAL)) {
		zebra_evpn_neigh_send_add_to_client(zevpn->vni, &nbr->ip,
						    &nbr->emac, nbr->mac,
						    nbr->flags, nbr->loc_seq);
	} else if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_REMOTE)) {
		zebra_evpn_rem_neigh_install(zevpn, nbr, false /*was_static*/);
	}
}

/*
 * Print a specific neighbor entry.
 */
void zebra_evpn_print_neigh(const struct zebra_neigh *n, void *ctxt, json_object *json)
{
	struct vty *vty;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	const char *type_str;
	const char *state_str;
	bool flags_present = false;
	struct zebra_vrf *zvrf = NULL;
	struct timeval detect_start_time = {0, 0};
	char timebuf[MONOTIME_STRLEN];
	char thread_buf[EVENT_TIMER_STRLEN];
	time_t uptime;
	char up_str[MONOTIME_STRLEN];

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return;

	uptime = monotime(NULL);
	uptime -= n->uptime;

	frrtime_to_interval(uptime, up_str, sizeof(up_str));

	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	type_str = CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL) ? "local" : "remote";
	state_str = IS_ZEBRA_NEIGH_ACTIVE(n) ? "active" : "inactive";
	vty = (struct vty *)ctxt;
	if (json == NULL) {
		bool sync_info = false;

		vty_out(vty, "IP: %s\n",
			ipaddr2str(&n->ip, buf2, sizeof(buf2)));
		vty_out(vty, " Type: %s\n", type_str);
		vty_out(vty, " State: %s\n", state_str);
		vty_out(vty, " Uptime: %s\n", up_str);
		vty_out(vty, " MAC: %s\n",
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
		vty_out(vty, " VLAN: %d\n", n->zevpn->vid);
		vty_out(vty, " Sync-info:");
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE)) {
			vty_out(vty, " local-inactive");
			sync_info = true;
		}
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY)) {
			vty_out(vty, " peer-proxy");
			sync_info = true;
		}
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE)) {
			vty_out(vty, " peer-active");
			sync_info = true;
		}
		if (event_is_scheduled(n->hold_timer)) {
			vty_out(vty, " (ht: %s)",
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      n->hold_timer));
			sync_info = true;
		}
		if (!sync_info)
			vty_out(vty, " -");
		vty_out(vty, "\n");
	} else {
		json_object_string_add(json, "uptime", up_str);
		json_object_string_add(json, "ip", buf2);
		json_object_string_add(json, "type", type_str);
		json_object_string_add(json, "state", state_str);
		json_object_string_add(json, "mac", buf1);
		json_object_int_add(json, "vlan", n->zevpn->vid);
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE))
			json_object_boolean_true_add(json, "localInactive");
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY))
			json_object_boolean_true_add(json, "peerProxy");
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
			json_object_boolean_true_add(json, "peerActive");
		if (event_is_scheduled(n->hold_timer))
			json_object_string_add(
				json, "peerActiveHold",
				event_timer_to_hhmmss(thread_buf,
						      sizeof(thread_buf),
						      n->hold_timer));
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		if (n->mac && n->mac->es) {
			if (json)
				json_object_string_add(json, "remoteEs",
						       n->mac->es->esi_str);
			else
				vty_out(vty, " Remote ES: %s\n",
					n->mac->es->esi_str);
		} else if (!n->mac) {
			/* pure-L3 (no-L2VNI) neighbor sync: no remote VTEP */
			if (json)
				json_object_boolean_true_add(json,
							     "l3NeighSync");
			else
				vty_out(vty, " L3 neighbor-sync\n");
		} else {
			if (json)
				json_object_string_addf(json, "remoteVtep", "%pIA", &n->r_vtep_ip);
			else
				vty_out(vty, " Remote VTEP: %pIA\n", &n->r_vtep_ip);
		}
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW)) {
		if (!json) {
			vty_out(vty, " Flags: Default-gateway");
			flags_present = true;
		} else
			json_object_boolean_true_add(json, "defaultGateway");
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG)) {
		if (!json) {
			vty_out(vty,
				flags_present ? " ,Router" : " Flags: Router");
			flags_present = true;
		}
	}
	if (json == NULL) {
		if (flags_present)
			vty_out(vty, "\n");
		vty_out(vty, " Local Seq: %u Remote Seq: %u\n", n->loc_seq,
			n->rem_seq);

		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE)) {
			vty_out(vty, " Duplicate, detected at %s",
				time_to_string(n->dad_dup_detect_time,
					       timebuf));
		} else if (n->dad_count) {
			monotime_since(&n->detect_start_time,
				       &detect_start_time);
			if (detect_start_time.tv_sec <= zvrf->dad_time) {
				time_to_string(n->detect_start_time.tv_sec,
					       timebuf);
				vty_out(vty,
					" Duplicate detection started at %s, detection count %u\n",
					timebuf, n->dad_count);
			}
		}
	} else {
		json_object_int_add(json, "localSequence", n->loc_seq);
		json_object_int_add(json, "remoteSequence", n->rem_seq);
		json_object_int_add(json, "detectionCount", n->dad_count);
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE))
			json_object_boolean_true_add(json, "isDuplicate");
		else
			json_object_boolean_false_add(json, "isDuplicate");
	}
}

void zebra_evpn_print_neigh_hdr(struct vty *vty, int addr_width, int r_vtep_width)
{
	vty_out(vty, "Flags: I=local-inactive, P=peer-active, X=peer-proxy\n");
	vty_out(vty, "%*s %-6s %-5s %-8s %-17s %*s %s\n", -addr_width, "Neighbor", "Type", "Flags",
		"State", "MAC", -r_vtep_width, "Remote ES/VTEP", "Seq #'s");
}

static char *zebra_evpn_print_neigh_flags(const struct zebra_neigh *n, char *flags_buf,
					  uint32_t flags_buf_sz)
{
	snprintf(flags_buf, flags_buf_sz, "%s%s%s",
			(n->flags & ZEBRA_NEIGH_ES_PEER_ACTIVE) ?
			"P" : "",
			(n->flags & ZEBRA_NEIGH_ES_PEER_PROXY) ?
			"X" : "",
			(n->flags & ZEBRA_NEIGH_LOCAL_INACTIVE) ?
			"I" : "");

	return flags_buf;
}

/*
 * Print neighbor hash entry - called for display of all neighbors.
 */
void zebra_evpn_print_neigh_hash(struct neigh_walk_ctx *wctx, const struct zebra_neigh *n,
				 int addr_width, int r_vtep_width)
{
	struct vty *vty;
	json_object *json_evpn = NULL, *json_row = NULL;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	char addr_buf[INET6_ADDRSTRLEN];
	const char *state_str;
	char flags_buf[6];

	vty = wctx->vty;
	json_evpn = wctx->json;

	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	state_str = IS_ZEBRA_NEIGH_ACTIVE(n) ? "active" : "inactive";
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
		if (wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
			return;

		if (json_evpn == NULL) {
			vty_out(vty, "%*s %-6s %-5s %-8s %-17s %*s %u/%u\n", -addr_width, buf2,
				"local",
				zebra_evpn_print_neigh_flags(n, flags_buf, sizeof(flags_buf)),
				state_str, buf1, -r_vtep_width, "", n->loc_seq, n->rem_seq);
		} else {
			json_row = json_object_new_object();

			json_object_string_add(json_row, "type", "local");
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(json_row, "mac", buf1);
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW))
				json_object_boolean_true_add(json_row,
							     "defaultGateway");
			json_object_int_add(json_row, "localSequence",
					    n->loc_seq);
			json_object_int_add(json_row, "remoteSequence",
					    n->rem_seq);
			json_object_int_add(json_row, "detectionCount",
					    n->dad_count);
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE))
				json_object_boolean_true_add(json_row,
							     "isDuplicate");
			else
				json_object_boolean_false_add(json_row,
							      "isDuplicate");
		}
		wctx->count++;
	} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		if ((wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP) &&
		    !ipaddr_is_same(&n->r_vtep_ip, &wctx->r_vtep_ip))
			return;

		if (json_evpn == NULL) {
			if ((wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
			    && (wctx->count == 0))
				zebra_evpn_print_neigh_hdr(vty, addr_width, r_vtep_width);

			if (!n->mac)
				strlcpy(addr_buf, "l3-sync", sizeof(addr_buf));
			else if (n->mac->es == NULL)
				ipaddr2str(&n->r_vtep_ip, addr_buf, sizeof(addr_buf));

			vty_out(vty, "%*s %-6s %-5s %-8s %-17s %*s %u/%u\n", -addr_width, buf2,
				"remote",
				zebra_evpn_print_neigh_flags(n, flags_buf, sizeof(flags_buf)),
				state_str, buf1, -r_vtep_width,
				(n->mac && n->mac->es) ? n->mac->es->esi_str : addr_buf,
				n->loc_seq, n->rem_seq);
		} else {
			json_row = json_object_new_object();

			json_object_string_add(json_row, "type", "remote");
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(json_row, "mac", buf1);
			if (n->mac && n->mac->es)
				json_object_string_add(json_row, "remoteEs",
						       n->mac->es->esi_str);
			else if (!n->mac)
				json_object_boolean_true_add(json_row,
							     "l3NeighSync");
			else
				json_object_string_addf(json_row, "remoteVtep", "%pIA",
							&n->r_vtep_ip);
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW))
				json_object_boolean_true_add(json_row,
							     "defaultGateway");
			json_object_int_add(json_row, "localSequence",
					    n->loc_seq);
			json_object_int_add(json_row, "remoteSequence",
					    n->rem_seq);
			json_object_int_add(json_row, "detectionCount",
					    n->dad_count);
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE))
				json_object_boolean_true_add(json_row,
							     "isDuplicate");
			else
				json_object_boolean_false_add(json_row,
							      "isDuplicate");
		}
		wctx->count++;
	}

	if (json_evpn)
		json_object_object_add(json_evpn, buf2, json_row);
}

/*
 * Print neighbor hash entry in detail - called for display of all neighbors.
 */
void zebra_evpn_print_neigh_hash_detail(struct neigh_walk_ctx *wctx, const struct zebra_neigh *n)
{
	struct vty *vty;
	json_object *json_evpn = NULL, *json_row = NULL;
	char buf[INET6_ADDRSTRLEN];

	vty = wctx->vty;
	json_evpn = wctx->json;
	if (!n)
		return;

	ipaddr2str(&n->ip, buf, sizeof(buf));
	if (json_evpn)
		json_row = json_object_new_object();

	zebra_evpn_print_neigh(n, vty, json_row);

	if (json_evpn)
		json_object_object_add(json_evpn, buf, json_row);
}

void zebra_evpn_print_dad_neigh_hash(struct neigh_walk_ctx *ctxt, const struct zebra_neigh *nbr,
				     int addr_width, int r_vtep_width)
{
	if (!nbr)
		return;

	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
		zebra_evpn_print_neigh_hash(ctxt, nbr, addr_width, r_vtep_width);
}

void zebra_evpn_print_dad_neigh_hash_detail(struct neigh_walk_ctx *ctxt,
					    const struct zebra_neigh *nbr)
{
	if (!nbr)
		return;

	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
		zebra_evpn_print_neigh_hash_detail(ctxt, nbr);
}

void zebra_evpn_neigh_remote_macip_add(struct zebra_evpn *zevpn, struct zebra_vrf *zvrf,
				       const struct ipaddr *ipaddr, struct zebra_mac *mac,
				       struct ipaddr *vtep_ip, uint8_t flags, uint32_t seq)
{
	struct zebra_neigh *n;
	int update_neigh = 0;
	struct zebra_mac *old_mac = NULL;
	bool old_static = false;
	bool do_dad = false;
	bool is_dup_detect = false;
	bool is_router;
	bool is_old_mac_dup = false;

	assert(mac);
	is_router = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

	/* Check if the remote neighbor itself is unknown or has a
	 * change. If so, create or update and then install the entry.
	 */
	n = zebra_evpn_neigh_lookup(zevpn, ipaddr);
	if (n) {
		/* Refresh entry */
		n->gr_refresh_time = monotime(NULL);
	}

	if (!n || !CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE) ||
	    is_router != !!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG) ||
	    (memcmp(&n->emac, &mac->macaddr, sizeof(struct ethaddr)) != 0) ||
	    !ipaddr_is_same(&n->r_vtep_ip, vtep_ip) || seq != n->rem_seq)
		update_neigh = 1;

	if (update_neigh) {
		if (!n) {
			n = zebra_evpn_neigh_add(zevpn, ipaddr, &mac->macaddr,
						 mac, 0);
		} else {
			/* When host moves but changes its (MAC,IP)
			 * binding, BGP may install a MACIP entry that
			 * corresponds to "older" location of the host
			 * in transient situations (because {IP1,M1}
			 * is a different route from {IP1,M2}). Check
			 * the sequence number and ignore this update
			 * if appropriate.
			 */

			if (!zebra_evpn_neigh_is_bgp_seq_ok(
				    zevpn, n, &mac->macaddr, seq, false))
				return;
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
				old_static = zebra_evpn_neigh_is_static(n);
				if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
					zlog_debug(
						"sync->remote neigh vni %u ip %pIA mac %pEA seq %d f0x%x",
						n->zevpn->vni, &n->ip, &n->emac,
						seq, n->flags);
				if (IS_ZEBRA_NEIGH_ACTIVE(n))
					zebra_evpn_neigh_send_del_to_client(
						zevpn->vni, &n->ip, &n->emac,
						n->flags, n->state,
						false /*force*/);
				zebra_evpn_neigh_clear_sync_info(n);
			}
			if (memcmp(&n->emac, &mac->macaddr,
				   sizeof(struct ethaddr))
			    != 0) {
				/* update neigh list for macs */
				old_mac =
					zebra_evpn_mac_lookup(zevpn, &n->emac);
				if (old_mac) {
					is_old_mac_dup = CHECK_FLAG(old_mac->flags, ZEBRA_MAC_DUPLICATE);
					listnode_delete(old_mac->neigh_list, n);
					n->mac = NULL;
					zebra_evpn_deref_ip2mac(zevpn, old_mac);
				}
				n->mac = mac;
				listnode_add_sort(mac->neigh_list, n);
				memcpy(&n->emac, &mac->macaddr, ETH_ALEN);

				/* Check Neigh's current state is local
				 * (this is the case where neigh/host has  moved
				 * from L->R) and check previous detection
				 * started via local learning.
				 *
				 * RFC-7432: A PE/VTEP that detects a MAC
				 * mobilit event via local learning starts
				 * an M-second timer.
				 * VTEP-IP or seq. change along is not
				 * considered for dup. detection.
				 *
				 * Mobilty event scenario-B IP-MAC binding
				 * changed.
				 */
				if ((!CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
				    && n->dad_count)
					do_dad = true;
			}
		}

		/* Set "remote" forwarding info. */
		UNSET_FLAG(n->flags, ZEBRA_NEIGH_ALL_LOCAL_FLAGS);
		n->r_vtep_ip = *vtep_ip;
		SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);

		/* Set router flag (R-bit) to this Neighbor entry */
		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG))
			SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
		else
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

		/* Check old or new MAC detected as duplicate,
		 * inherit duplicate flag to this neigh.
		 */
		if (zebra_evpn_ip_inherit_dad_from_mac(zvrf, is_old_mac_dup, mac, n)) {
			flog_warn(
				EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
				"VNI %u: MAC %pEA IP %pIA detected as duplicate during remote update, inherit duplicate from MAC",
				zevpn->vni, &mac->macaddr, &n->ip);
		}

		/* Check duplicate address detection for IP */
		zebra_evpn_dup_addr_detect_for_neigh(zvrf, n, &n->r_vtep_ip, do_dad, &is_dup_detect,
						     false);
		/* Install the entry. */
		if (!is_dup_detect)
			zebra_evpn_rem_neigh_install(zevpn, n, old_static);
	}

	/* Update seq number. */
	n->rem_seq = seq;
}

int zebra_evpn_neigh_gw_macip_add(struct interface *ifp,
				  struct zebra_evpn *zevpn, struct ipaddr *ip,
				  struct zebra_mac *mac)
{
	struct zebra_neigh *n;

	assert(mac);

	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n)
		n = zebra_evpn_neigh_add(zevpn, ip, &mac->macaddr, mac, 0);
	else
		n->gr_refresh_time = monotime(NULL);

	/* Set "local" forwarding info. */
	SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	ZEBRA_NEIGH_SET_ACTIVE(n);
	memcpy(&n->emac, &mac->macaddr, ETH_ALEN);
	n->ifindex = ifp->ifindex;

	/* Only advertise in BGP if the knob is enabled */
	if (advertise_gw_macip_enabled(zevpn)) {

		SET_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW);
		/* Set Router flag (R-bit) */
		if (ip->ipa_type == IPADDR_V6)
			SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"SVI %s(%u) L2-VNI %u, sending GW MAC %pEA IP %pIA add to BGP with flags 0x%x",
				ifp->name, ifp->ifindex, zevpn->vni,
				&mac->macaddr, ip, n->flags);

		zebra_evpn_neigh_send_add_to_client(
			zevpn->vni, ip, &n->emac, n->mac, n->flags, n->loc_seq);
	} else if (advertise_svi_macip_enabled(zevpn)) {

		SET_FLAG(n->flags, ZEBRA_NEIGH_SVI_IP);
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"SVI %s(%u) L2-VNI %u, sending SVI MAC %pEA IP %pIA add to BGP with flags 0x%x",
				ifp->name, ifp->ifindex, zevpn->vni,
				&mac->macaddr, ip, n->flags);

		zebra_evpn_neigh_send_add_to_client(
			zevpn->vni, ip, &n->emac, n->mac, n->flags, n->loc_seq);
	}

	return 0;
}

void zebra_evpn_neigh_remote_uninstall(struct zebra_evpn *zevpn,
				       struct zebra_vrf *zvrf,
				       struct zebra_neigh *n,
				       struct zebra_mac *mac,
				       const struct ipaddr *ipaddr)
{
	if (zvrf->dad_freeze && CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE)
	    && CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)
	    && (memcmp(n->emac.octet, mac->macaddr.octet, ETH_ALEN) == 0)) {
		struct interface *vlan_if;

		vlan_if = zevpn_map_to_svi(zevpn, true);
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: IP %pIA (flags 0x%x intf %s) is remote and duplicate, read kernel for local entry",
				__func__, ipaddr, n->flags,
				vlan_if ? vlan_if->name : "Unknown");
		if (vlan_if)
			dplane_neigh_read_specific_ip(zvrf->zns, ipaddr, vlan_if);
	}

	/* When the MAC changes for an IP, it is possible the
	 * client may update the new MAC before trying to delete the
	 * "old" neighbor (as these are two different MACIP routes).
	 * Do the delete only if the MAC matches.
	 */
	if (!memcmp(n->emac.octet, mac->macaddr.octet, ETH_ALEN)) {
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
			zebra_evpn_sync_neigh_del(n);
		} else if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
			zebra_evpn_neigh_uninstall(zevpn, n);
			zebra_evpn_neigh_del(zevpn, n);
			zebra_evpn_deref_ip2mac(zevpn, mac);
		}
	} else {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: IP %pIA MAC %pEA (flags 0x%x) found doesn't match MAC %pEA, ignoring Neigh DEL",
				__func__, ipaddr, &n->emac, n->flags,
				&mac->macaddr);
	}
}

int zebra_evpn_neigh_del_ip(struct zebra_evpn *zevpn, const struct ipaddr *ip)
{
	struct zebra_neigh *n;
	struct zebra_mac *zmac;
	bool old_bgp_ready;
	bool new_bgp_ready;
	struct zebra_vrf *zvrf;

	/* If entry doesn't exist, nothing to do. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n)
		return 0;

	zmac = zebra_evpn_mac_lookup(zevpn, &n->emac);
	if (!zmac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Trying to del a neigh %pIA without a mac %pEA on VNI %u",
				ip, &n->emac,
				zevpn->vni);

		return 0;
	}

	/* If it is a remote entry, the kernel has aged this out or someone has
	 * deleted it, it needs to be re-installed as FRR is the owner.
	 */
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		zebra_evpn_rem_neigh_install(zevpn, n, false /*was_static*/);
		return 0;
	}

	/* if this is a sync entry it cannot be dropped re-install it in
	 * the dataplane
	 */
	old_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	if (zebra_evpn_neigh_is_static(n)) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug("re-add sync neigh vni %u ip %pIA mac %pEA 0x%x",
				   n->zevpn->vni, &n->ip, &n->emac,
				   n->flags);

		if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE))
			SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE);
		/* inform-bgp about change in local-activity if any */
		new_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
		zebra_evpn_neigh_send_add_del_to_client(n, old_bgp_ready,
							new_bgp_ready);

		/* re-install the entry in the kernel */
		zebra_evpn_sync_neigh_dp_install(n, false /* set_inactive */,
						 false /* force_clear_static */,
						 __func__);

		return 0;
	}

	zvrf = zevpn->vxlan_if->vrf->info;
	if (!zvrf) {
		zlog_debug("%s: VNI %u vrf lookup failed.", __func__,
			   zevpn->vni);
		return -1;
	}

	/* In case of feeze action, if local neigh is in duplicate state,
	 * Mark the Neigh as inactive before sending delete request to BGPd,
	 * If BGPd has remote entry, it will re-install
	 */
	if (zvrf->dad_freeze && CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE))
		ZEBRA_NEIGH_SET_INACTIVE(n);

	/* Remove neighbor from BGP. */
	zebra_evpn_neigh_send_del_to_client(zevpn->vni, &n->ip, &n->emac,
					    n->flags, n->state,
					    false /* force */);

	/* Delete this neighbor entry. */
	zebra_evpn_neigh_del(zevpn, n);

	/* see if the AUTO mac needs to be deleted */
	if (CHECK_FLAG(zmac->flags, ZEBRA_MAC_AUTO)
	    && !zebra_evpn_mac_in_use(zmac))
		zebra_evpn_mac_del(zevpn, zmac);

	return 0;
}
