/*
 * Zebra EVPN Neighbor code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

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
#include "zebra/zebra_memory.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mac.h"

DEFINE_MTYPE_STATIC(ZEBRA, NEIGH, "EVI Neighbor");

/*
 * Make hash key for neighbors.
 */
static unsigned int neigh_hash_keymake(const void *p)
{
	const zebra_neigh_t *n = p;
	const struct ipaddr *ip = &n->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32,
		      array_size(ip->ipaddr_v6.s6_addr32), 0);
}

/*
 * Compare two neighbor hash structures.
 */
static bool neigh_cmp(const void *p1, const void *p2)
{
	const zebra_neigh_t *n1 = p1;
	const zebra_neigh_t *n2 = p2;

	if (n1 == NULL && n2 == NULL)
		return true;

	if (n1 == NULL || n2 == NULL)
		return false;

	return (memcmp(&n1->ip, &n2->ip, sizeof(struct ipaddr)) == 0);
}

int neigh_list_cmp(void *p1, void *p2)
{
	const zebra_neigh_t *n1 = p1;
	const zebra_neigh_t *n2 = p2;

	return memcmp(&n1->ip, &n2->ip, sizeof(struct ipaddr));
}

struct hash *zebra_neigh_db_create(const char *desc)
{
	return hash_create(neigh_hash_keymake, neigh_cmp, desc);
}

uint32_t num_dup_detected_neighs(zebra_evpn_t *zevpn)
{
	unsigned int i;
	uint32_t num_neighs = 0;
	struct hash *hash;
	struct hash_bucket *hb;
	zebra_neigh_t *nbr;

	hash = zevpn->neigh_table;
	if (!hash)
		return num_neighs;
	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hb->next) {
			nbr = (zebra_neigh_t *)hb->data;
			if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
				num_neighs++;
		}
	}

	return num_neighs;
}

/*
 * Helper function to determine maximum width of neighbor IP address for
 * display - just because we're dealing with IPv6 addresses that can
 * widely vary.
 */
void zebra_evpn_find_neigh_addr_width(struct hash_bucket *bucket, void *ctxt)
{
	zebra_neigh_t *n;
	char buf[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;
	int width;

	n = (zebra_neigh_t *)bucket->data;

	ipaddr2str(&n->ip, buf, sizeof(buf));
	width = strlen(buf);
	if (width > wctx->addr_width)
		wctx->addr_width = width;
}

/*
 * Count of remote neighbors referencing this MAC.
 */
int remote_neigh_count(zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
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
int zebra_evpn_rem_neigh_install(zebra_evpn_t *zevpn, zebra_neigh_t *n,
				 bool was_static)
{
	struct interface *vlan_if;
	int flags;
	int ret = 0;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	vlan_if = zevpn_map_to_svi(zevpn);
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
void zebra_evpn_install_neigh_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_neigh_t *n;
	struct neigh_walk_ctx *wctx = ctxt;

	n = (zebra_neigh_t *)bucket->data;

	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
		zebra_evpn_rem_neigh_install(wctx->zevpn, n,
					     false /*was_static*/);
}

/*
 * Callback to allocate neighbor hash entry.
 */
static void *zebra_evpn_neigh_alloc(void *p)
{
	const zebra_neigh_t *tmp_n = p;
	zebra_neigh_t *n;

	n = XCALLOC(MTYPE_NEIGH, sizeof(zebra_neigh_t));
	*n = *tmp_n;

	return ((void *)n);
}

static void zebra_evpn_local_neigh_ref_mac(zebra_neigh_t *n,
					   struct ethaddr *macaddr,
					   zebra_mac_t *mac,
					   bool send_mac_update)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
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
				"sync-neigh ref mac vni %u ip %s mac %s ref %d",
				n->zevpn->vni,
				ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
				prefix_mac2str(&n->emac, macbuf,
					       sizeof(macbuf)),
				mac->sync_neigh_cnt);
		if ((old_static != new_static) && send_mac_update)
			/* program the local mac in the kernel */
			zebra_evpn_sync_mac_dp_install(
				mac, false /*set_inactive*/,
				false /*force_clear_static*/, __func__);
	}
}

/* sync-path that is active on an ES peer */
static void zebra_evpn_sync_neigh_dp_install(zebra_neigh_t *n,
					     bool set_inactive,
					     bool force_clear_static,
					     const char *caller)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	struct zebra_ns *zns;
	struct interface *ifp;
	bool set_static;
	bool set_router;

	zns = zebra_ns_lookup(NS_DEFAULT);
	ifp = if_lookup_by_index_per_ns(zns, n->ifindex);
	if (!ifp) {
		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug(
				"%s: dp-install sync-neigh vni %u ip %s mac %s if %d f 0x%x skipped",
				caller, n->zevpn->vni,
				ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
				prefix_mac2str(&n->emac, macbuf,
					       sizeof(macbuf)),
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
			"%s: dp-install sync-neigh vni %u ip %s mac %s if %s(%d) f 0x%x%s%s%s",
			caller, n->zevpn->vni,
			ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
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
int zebra_evpn_neigh_send_add_to_client(vni_t vni, struct ipaddr *ip,
					struct ethaddr *macaddr,
					zebra_mac_t *zmac, uint32_t neigh_flags,
					uint32_t seq)
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

	return zebra_evpn_macip_send_msg_to_client(
		vni, macaddr, ip, flags, seq, ZEBRA_NEIGH_ACTIVE,
		zmac ? zmac->es : NULL, ZEBRA_MACIP_ADD);
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
		vni, macaddr, ip, flags, 0, state, NULL, ZEBRA_MACIP_DEL);
}

static void zebra_evpn_neigh_send_add_del_to_client(zebra_neigh_t *n,
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
void zebra_evpn_sync_neigh_static_chg(zebra_neigh_t *n, bool old_n_static,
				      bool new_n_static, bool defer_n_dp,
				      bool defer_mac_dp, const char *caller)
{
	zebra_mac_t *mac = n->mac;
	bool old_mac_static;
	bool new_mac_static;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];

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
			"sync-neigh ref-chg vni %u ip %s mac %s f 0x%x %d%s%s%s%s by %s",
			n->zevpn->vni, ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
			n->flags, mac->sync_neigh_cnt,
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
static int zebra_evpn_neigh_hold_exp_cb(struct thread *t)
{
	zebra_neigh_t *n;
	bool old_bgp_ready;
	bool new_bgp_ready;
	bool old_n_static;
	bool new_n_static;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];

	n = THREAD_ARG(t);
	/* the purpose of the hold timer is to age out the peer-active
	 * flag
	 */
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
		return 0;

	old_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	old_n_static = zebra_evpn_neigh_is_static(n);
	UNSET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);
	new_bgp_ready = zebra_evpn_neigh_is_ready_for_bgp(n);
	new_n_static = zebra_evpn_neigh_is_static(n);

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug("sync-neigh vni %u ip %s mac %s 0x%x hold expired",
			   n->zevpn->vni,
			   ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			   prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
			   n->flags);

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

	return 0;
}

static inline void zebra_evpn_neigh_start_hold_timer(zebra_neigh_t *n)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];

	if (n->hold_timer)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug("sync-neigh vni %u ip %s mac %s 0x%x hold start",
			   n->zevpn->vni,
			   ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			   prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
			   n->flags);
	thread_add_timer(zrouter.master, zebra_evpn_neigh_hold_exp_cb, n,
			 zmh_info->neigh_hold_time, &n->hold_timer);
}

static void zebra_evpn_local_neigh_deref_mac(zebra_neigh_t *n,
					     bool send_mac_update)
{
	zebra_mac_t *mac = n->mac;
	zebra_evpn_t *zevpn = n->zevpn;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
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
				"sync-neigh deref mac vni %u ip %s mac %s ref %d",
				n->zevpn->vni,
				ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
				prefix_mac2str(&n->emac, macbuf,
					       sizeof(macbuf)),
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

bool zebra_evpn_neigh_is_bgp_seq_ok(zebra_evpn_t *zevpn, zebra_neigh_t *n,
				    struct ethaddr *macaddr, uint32_t seq)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	uint32_t tmp_seq;

	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
		tmp_seq = n->loc_seq;
	else
		tmp_seq = n->rem_seq;

	if (seq < tmp_seq) {
		/* if the neigh was never advertised to bgp we must accept
		 * whatever sequence number bgp sends
		 * XXX - check with Vivek
		 */
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)
		    && !zebra_evpn_neigh_is_ready_for_bgp(n)) {
			if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
				zlog_debug(
					"sync-macip accept vni %u mac %s IP %s lower seq %u f 0x%x",
					zevpn->vni,
					prefix_mac2str(macaddr, macbuf,
						       sizeof(macbuf)),
					ipaddr2str(&n->ip, ipbuf,
						   sizeof(ipbuf)),
					tmp_seq, n->flags);
			return true;
		}

		if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
			zlog_debug(
				"sync-macip ignore vni %u mac %s IP %s as existing has higher seq %u f 0x%x",
				zevpn->vni,
				prefix_mac2str(macaddr, macbuf, sizeof(macbuf)),
				ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
				tmp_seq, n->flags);
		return false;
	}

	return true;
}

/*
 * Add neighbor entry.
 */
static zebra_neigh_t *zebra_evpn_neigh_add(zebra_evpn_t *zevpn,
					   struct ipaddr *ip,
					   struct ethaddr *mac,
					   zebra_mac_t *zmac, uint32_t n_flags)
{
	zebra_neigh_t tmp_n;
	zebra_neigh_t *n = NULL;

	memset(&tmp_n, 0, sizeof(zebra_neigh_t));
	memcpy(&tmp_n.ip, ip, sizeof(struct ipaddr));
	n = hash_get(zevpn->neigh_table, &tmp_n, zebra_evpn_neigh_alloc);
	assert(n);

	n->state = ZEBRA_NEIGH_INACTIVE;
	n->zevpn = zevpn;
	n->dad_ip_auto_recovery_timer = NULL;
	n->flags = n_flags;

	if (!zmac)
		zmac = zebra_evpn_mac_lookup(zevpn, mac);
	zebra_evpn_local_neigh_ref_mac(n, mac, zmac,
				       false /* send_mac_update */);

	return n;
}

/*
 * Delete neighbor entry.
 */
int zebra_evpn_neigh_del(zebra_evpn_t *zevpn, zebra_neigh_t *n)
{
	zebra_neigh_t *tmp_n;

	if (n->mac)
		listnode_delete(n->mac->neigh_list, n);

	/* Cancel auto recovery */
	THREAD_OFF(n->dad_ip_auto_recovery_timer);

	/* Free the VNI hash entry and allocated memory. */
	tmp_n = hash_release(zevpn->neigh_table, n);
	XFREE(MTYPE_NEIGH, tmp_n);

	return 0;
}

void zebra_evpn_sync_neigh_del(zebra_neigh_t *n)
{
	bool old_n_static;
	bool new_n_static;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug("sync-neigh del vni %u ip %s mac %s f 0x%x",
			   n->zevpn->vni,
			   ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			   prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
			   n->flags);

	old_n_static = zebra_evpn_neigh_is_static(n);
	UNSET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY);
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
		zebra_evpn_neigh_start_hold_timer(n);
	new_n_static = zebra_evpn_neigh_is_static(n);

	if (old_n_static != new_n_static)
		zebra_evpn_sync_neigh_static_chg(
			n, old_n_static, new_n_static, false /*defer-dp*/,
			false /*defer_mac_dp*/, __func__);
}

zebra_neigh_t *
zebra_evpn_proc_sync_neigh_update(zebra_evpn_t *zevpn, zebra_neigh_t *n,
				  uint16_t ipa_len, struct ipaddr *ipaddr,
				  uint8_t flags, uint32_t seq, esi_t *esi,
				  struct sync_mac_ip_ctx *ctx)
{
	struct interface *ifp = NULL;
	bool is_router;
	zebra_mac_t *mac = ctx->mac;
	uint32_t tmp_seq;
	bool old_router = false;
	bool old_bgp_ready = false;
	bool new_bgp_ready;
	bool inform_dataplane = false;
	bool inform_bgp = false;
	bool old_mac_static;
	bool new_mac_static;
	bool set_dp_inactive = false;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	bool created;
	ifindex_t ifindex = 0;

	/* locate l3-svi */
	ifp = zevpn_map_to_svi(zevpn);
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
			if (n->mac)
				zebra_evpn_local_neigh_deref_mac(
					n, false /*send_mac_update*/);
		}
		/* clear old fwd info */
		n->rem_seq = 0;
		n->r_vtep_ip.s_addr = 0;

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

		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
			SET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY);
		else
			SET_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE);

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
				"sync-neigh vni %u ip %s mac %s old_f 0x%x new_f 0x%x",
				n->zevpn->vni,
				ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
				prefix_mac2str(&n->emac, macbuf,
					       sizeof(macbuf)),
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
	if ((old_mac_static != new_mac_static) || ctx->mac_dp_update_deferred)
		zebra_evpn_sync_mac_dp_install(mac, ctx->mac_inactive,
					       false /* force_clear_static */,
					       __func__);

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		zlog_debug(
			"sync-neigh %s vni %u ip %s mac %s if %s(%d) seq %d f 0x%x%s%s",
			created ? "created" : "updated", n->zevpn->vni,
			ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
			prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)),
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
static int zebra_evpn_neigh_uninstall(zebra_evpn_t *zevpn, zebra_neigh_t *n)
{
	struct interface *vlan_if;

	if (!(n->flags & ZEBRA_NEIGH_REMOTE))
		return 0;

	vlan_if = zevpn_map_to_svi(zevpn);
	if (!vlan_if)
		return -1;

	ZEBRA_NEIGH_SET_INACTIVE(n);
	n->loc_seq = 0;

	dplane_rem_neigh_delete(vlan_if, &n->ip);

	return 0;
}

/*
 * Free neighbor hash entry (callback)
 */
static void zebra_evpn_neigh_del_hash_entry(struct hash_bucket *bucket,
					    void *arg)
{
	struct neigh_walk_ctx *wctx = arg;
	zebra_neigh_t *n = bucket->data;

	if (((wctx->flags & DEL_LOCAL_NEIGH) && (n->flags & ZEBRA_NEIGH_LOCAL))
	    || ((wctx->flags & DEL_REMOTE_NEIGH)
		&& (n->flags & ZEBRA_NEIGH_REMOTE))
	    || ((wctx->flags & DEL_REMOTE_NEIGH_FROM_VTEP)
		&& (n->flags & ZEBRA_NEIGH_REMOTE)
		&& IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip))) {
		if (wctx->upd_client && (n->flags & ZEBRA_NEIGH_LOCAL))
			zebra_evpn_neigh_send_del_to_client(
				wctx->zevpn->vni, &n->ip, &n->emac, n->flags,
				n->state, false /*force*/);

		if (wctx->uninstall) {
			if (zebra_evpn_neigh_is_static(n))
				zebra_evpn_sync_neigh_dp_install(
					n, false /* set_inactive */,
					true /* force_clear_static */,
					__func__);
			if ((n->flags & ZEBRA_NEIGH_REMOTE))
				zebra_evpn_neigh_uninstall(wctx->zevpn, n);
		}

		zebra_evpn_neigh_del(wctx->zevpn, n);
	}

	return;
}

/*
 * Delete all neighbor entries for this EVPN.
 */
void zebra_evpn_neigh_del_all(zebra_evpn_t *zevpn, int uninstall,
			      int upd_client, uint32_t flags)
{
	struct neigh_walk_ctx wctx;

	if (!zevpn->neigh_table)
		return;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zevpn = zevpn;
	wctx.uninstall = uninstall;
	wctx.upd_client = upd_client;
	wctx.flags = flags;

	hash_iterate(zevpn->neigh_table, zebra_evpn_neigh_del_hash_entry,
		     &wctx);
}

/*
 * Look up neighbor hash entry.
 */
zebra_neigh_t *zebra_evpn_neigh_lookup(zebra_evpn_t *zevpn, struct ipaddr *ip)
{
	zebra_neigh_t tmp;
	zebra_neigh_t *n;

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	n = hash_lookup(zevpn->neigh_table, &tmp);

	return n;
}

/*
 * Process all neighbors associated with a MAC upon the MAC being learnt
 * locally or undergoing any other change (such as sequence number).
 */
void zebra_evpn_process_neigh_on_local_mac_change(zebra_evpn_t *zevpn,
						  zebra_mac_t *zmac,
						  bool seq_change,
						  bool es_change)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	struct zebra_vrf *zvrf = NULL;
	char buf[ETHER_ADDR_STRLEN];

	zvrf = vrf_info_lookup(zevpn->vxlan_if->vrf_id);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on local MAC %s %s, VNI %u",
			   prefix_mac2str(&zmac->macaddr, buf, sizeof(buf)),
			   seq_change ? "CHANGE" : "ADD", zevpn->vni);

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
				if (!(zvrf->dup_addr_detect && zvrf->dad_freeze
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
void zebra_evpn_process_neigh_on_local_mac_del(zebra_evpn_t *zevpn,
					       zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on local MAC %s DEL, VNI %u",
			   prefix_mac2str(&zmac->macaddr, buf, sizeof(buf)),
			   zevpn->vni);

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
void zebra_evpn_process_neigh_on_remote_mac_add(zebra_evpn_t *zevpn,
						zebra_mac_t *zmac)
{
	zebra_neigh_t *n = NULL;
	struct listnode *node = NULL;
	char buf[ETHER_ADDR_STRLEN];

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Processing neighbors on remote MAC %s ADD, VNI %u",
			   prefix_mac2str(&zmac->macaddr, buf, sizeof(buf)),
			   zevpn->vni);

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
void zebra_evpn_process_neigh_on_remote_mac_del(zebra_evpn_t *zevpn,
						zebra_mac_t *zmac)
{
	/* NOTE: Currently a NO-OP. */
}

static inline void zebra_evpn_local_neigh_update_log(
	const char *pfx, zebra_neigh_t *n, bool is_router, bool local_inactive,
	bool old_bgp_ready, bool new_bgp_ready, bool inform_dataplane,
	bool inform_bgp, const char *sfx)
{
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];

	if (!IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		return;

	zlog_debug("%s neigh vni %u ip %s mac %s f 0x%x%s%s%s%s%s%s %s", pfx,
		   n->zevpn->vni, ipaddr2str(&n->ip, ipbuf, sizeof(ipbuf)),
		   prefix_mac2str(&n->emac, macbuf, sizeof(macbuf)), n->flags,
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
					      zebra_mac_t *old_zmac,
					      zebra_mac_t *new_zmac,
					      zebra_neigh_t *nbr)
{
	bool is_old_mac_dup = false;
	bool is_new_mac_dup = false;

	if (!zvrf->dup_addr_detect)
		return 0;
	/* Check old or new MAC is detected as duplicate
	 * mark this neigh as duplicate
	 */
	if (old_zmac)
		is_old_mac_dup =
			CHECK_FLAG(old_zmac->flags, ZEBRA_MAC_DUPLICATE);
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

static int zebra_evpn_dad_ip_auto_recovery_exp(struct thread *t)
{
	struct zebra_vrf *zvrf = NULL;
	zebra_neigh_t *nbr = NULL;
	zebra_evpn_t *zevpn = NULL;
	char buf1[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];

	nbr = THREAD_ARG(t);

	/* since this is asynchronous we need sanity checks*/
	zvrf = vrf_info_lookup(nbr->zevpn->vrf_id);
	if (!zvrf)
		return 0;

	zevpn = zebra_evpn_lookup(nbr->zevpn->vni);
	if (!zevpn)
		return 0;

	nbr = zebra_evpn_neigh_lookup(zevpn, &nbr->ip);
	if (!nbr)
		return 0;

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%s: duplicate addr MAC %s IP %s flags 0x%x learn count %u vni %u auto recovery expired",
			__func__,
			prefix_mac2str(&nbr->emac, buf2, sizeof(buf2)),
			ipaddr2str(&nbr->ip, buf1, sizeof(buf1)), nbr->flags,
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

	return 0;
}

static void
zebra_evpn_dup_addr_detect_for_neigh(struct zebra_vrf *zvrf, zebra_neigh_t *nbr,
				     struct in_addr vtep_ip, bool do_dad,
				     bool *is_dup_detect, bool is_local)
{

	struct timeval elapsed = {0, 0};
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	bool reset_params = false;

	if (!zvrf->dup_addr_detect)
		return;

	/* IP is detected as duplicate or inherit dup
	 * state, hold on to install as remote entry
	 * only if freeze is enabled.
	 */
	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE)) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: duplicate addr MAC %s IP %s flags 0x%x skip installing, learn count %u recover time %u",
				__func__,
				prefix_mac2str(&nbr->emac, buf, sizeof(buf)),
				ipaddr2str(&nbr->ip, buf1, sizeof(buf1)),
				nbr->flags, nbr->dad_count,
				zvrf->dad_freeze_time);

		if (zvrf->dad_freeze)
			*is_dup_detect = true;

		/* warn-only action, neigh will be installed.
		 * freeze action, it wil not be installed.
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
				"%s: duplicate addr MAC %s IP %s flags 0x%x detection time passed, reset learn count %u",
				__func__,
				prefix_mac2str(&nbr->emac, buf, sizeof(buf)),
				ipaddr2str(&nbr->ip, buf1, sizeof(buf1)),
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
		flog_warn(
			EC_ZEBRA_DUP_IP_DETECTED,
			"VNI %u: MAC %s IP %s detected as duplicate during %s VTEP %s",
			nbr->zevpn->vni,
			prefix_mac2str(&nbr->emac, buf, sizeof(buf)),
			ipaddr2str(&nbr->ip, buf1, sizeof(buf1)),
			is_local ? "local update, last" : "remote update, from",
			inet_ntoa(vtep_ip));

		SET_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE);

		/* Capture Duplicate detection time */
		nbr->dad_dup_detect_time = monotime(NULL);

		/* Start auto recovery timer for this IP */
		THREAD_OFF(nbr->dad_ip_auto_recovery_timer);
		if (zvrf->dad_freeze && zvrf->dad_freeze_time) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s: duplicate addr MAC %s IP %s flags 0x%x auto recovery time %u start",
					__func__,
					prefix_mac2str(&nbr->emac, buf,
						       sizeof(buf)),
					ipaddr2str(&nbr->ip, buf1,
						   sizeof(buf1)),
					nbr->flags, zvrf->dad_freeze_time);

			thread_add_timer(zrouter.master,
					 zebra_evpn_dad_ip_auto_recovery_exp,
					 nbr, zvrf->dad_freeze_time,
					 &nbr->dad_ip_auto_recovery_timer);
		}
		if (zvrf->dad_freeze)
			*is_dup_detect = true;
	}
}

int zebra_evpn_local_neigh_update(zebra_evpn_t *zevpn, struct interface *ifp,
				  struct ipaddr *ip, struct ethaddr *macaddr,
				  bool is_router, bool local_inactive,
				  bool dp_static)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct zebra_vrf *zvrf;
	zebra_neigh_t *n = NULL;
	zebra_mac_t *zmac = NULL, *old_zmac = NULL;
	uint32_t old_mac_seq = 0, mac_new_seq = 0;
	bool upd_mac_seq = false;
	bool neigh_mac_change = false;
	bool neigh_on_hold = false;
	bool neigh_was_remote = false;
	bool do_dad = false;
	struct in_addr vtep_ip = {.s_addr = 0};
	bool inform_dataplane = false;
	bool created = false;
	bool new_static = false;
	bool old_bgp_ready = false;
	bool new_bgp_ready;

	/* Check if the MAC exists. */
	zmac = zebra_evpn_mac_lookup(zevpn, macaddr);
	if (!zmac) {
		/* create a dummy MAC if the MAC is not already present */
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("AUTO MAC %s created for neigh %s on VNI %u",
				   prefix_mac2str(macaddr, buf, sizeof(buf)),
				   ipaddr2str(ip, buf2, sizeof(buf2)),
				   zevpn->vni);

		zmac = zebra_evpn_mac_add(zevpn, macaddr);
		if (!zmac) {
			zlog_debug("Failed to add MAC %s VNI %u",
				   prefix_mac2str(macaddr, buf, sizeof(buf)),
				   zevpn->vni);
			return -1;
		}

		memset(&zmac->fwd_info, 0, sizeof(zmac->fwd_info));
		memset(&zmac->flags, 0, sizeof(uint32_t));
		SET_FLAG(zmac->flags, ZEBRA_MAC_AUTO);
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

	zvrf = vrf_info_lookup(zevpn->vxlan_if->vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("        Unable to find vrf for: %d",
				   zevpn->vxlan_if->vrf_id);
		return -1;
	}

	/* Check if the neighbor exists. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		/* New neighbor - create */
		n = zebra_evpn_neigh_add(zevpn, ip, macaddr, zmac, 0);
		if (!n) {
			flog_err(
				EC_ZEBRA_MAC_ADD_FAILED,
				"Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
				ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, zevpn->vni);
			return -1;
		}
		/* Set "local" forwarding info. */
		SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
		n->ifindex = ifp->ifindex;
		created = true;
	} else {
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

				/* Neigh is in freeze state and freeze action
				 * is enabled, do not send update to client.
				 */
				is_neigh_freezed =
					(zvrf->dup_addr_detect
					 && zvrf->dad_freeze
					 && CHECK_FLAG(n->flags,
						       ZEBRA_NEIGH_DUPLICATE));

				zebra_evpn_local_neigh_update_log(
					"local", n, is_router, local_inactive,
					old_bgp_ready, new_bgp_ready, false,
					false, "flag-update");

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
			n->r_vtep_ip.s_addr = INADDR_ANY;
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

	/* if the dataplane thinks that this is a sync entry but
	 * zebra doesn't we need to re-concile the diff
	 * by re-installing the dataplane entry
	 */
	if (dp_static) {
		new_static = zebra_evpn_neigh_is_static(n);
		if (!new_static)
			inform_dataplane = true;
	}

	/* Check old and/or new MAC detected as duplicate mark
	 * the neigh as duplicate
	 */
	if (zebra_evpn_ip_inherit_dad_from_mac(zvrf, old_zmac, zmac, n)) {
		flog_warn(
			EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
			"VNI %u: MAC %s IP %s detected as duplicate during local update, inherit duplicate from MAC",
			zevpn->vni, prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(&n->ip, buf2, sizeof(buf2)));
	}

	/* For IP Duplicate Address Detection (DAD) is trigger,
	 * when the event is extended mobility based on scenario-B
	 * from the draft, IP/Neigh's MAC binding changed and
	 * neigh's previous state was remote.
	 */
	if (neigh_mac_change && neigh_was_remote)
		do_dad = true;

	zebra_evpn_dup_addr_detect_for_neigh(zvrf, n, vtep_ip, do_dad,
					     &neigh_on_hold, true);

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
				"Seq changed for MAC %s VNI %u - old %u new %u",
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				zevpn->vni, zmac->loc_seq, mac_new_seq);
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

int zebra_evpn_remote_neigh_update(zebra_evpn_t *zevpn, struct interface *ifp,
				   struct ipaddr *ip, struct ethaddr *macaddr,
				   uint16_t state)
{
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	zebra_neigh_t *n = NULL;
	zebra_mac_t *zmac = NULL;

	/* If the neighbor is unknown, there is no further action. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n)
		return 0;

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
				"Ignore remote neigh %s (MAC %s) on L2-VNI %u - MAC unknown or local",
				ipaddr2str(&n->ip, buf2, sizeof(buf2)),
				prefix_mac2str(macaddr, buf, sizeof(buf)),
				zevpn->vni);
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
static void
zebra_evpn_send_neigh_hash_entry_to_client(struct hash_bucket *bucket,
					   void *arg)
{
	struct mac_walk_ctx *wctx = arg;
	zebra_neigh_t *zn = bucket->data;
	zebra_mac_t *zmac = NULL;

	if (CHECK_FLAG(zn->flags, ZEBRA_NEIGH_DEF_GW))
		return;

	if (CHECK_FLAG(zn->flags, ZEBRA_NEIGH_LOCAL)
	    && IS_ZEBRA_NEIGH_ACTIVE(zn)) {
		zmac = zebra_evpn_mac_lookup(wctx->zevpn, &zn->emac);
		if (!zmac)
			return;

		zebra_evpn_neigh_send_add_to_client(wctx->zevpn->vni, &zn->ip,
						    &zn->emac, zn->mac,
						    zn->flags, zn->loc_seq);
	}
}

/* Iterator of a specific EVPN */
void zebra_evpn_send_neigh_to_client(zebra_evpn_t *zevpn)
{
	struct neigh_walk_ctx wctx;

	memset(&wctx, 0, sizeof(struct neigh_walk_ctx));
	wctx.zevpn = zevpn;

	hash_iterate(zevpn->neigh_table,
		     zebra_evpn_send_neigh_hash_entry_to_client, &wctx);
}

void zebra_evpn_clear_dup_neigh_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct neigh_walk_ctx *wctx = ctxt;
	zebra_neigh_t *nbr;
	zebra_evpn_t *zevpn;
	char buf[INET6_ADDRSTRLEN];

	nbr = (zebra_neigh_t *)bucket->data;
	if (!nbr)
		return;

	zevpn = wctx->zevpn;

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
	THREAD_OFF(nbr->dad_ip_auto_recovery_timer);

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
void zebra_evpn_print_neigh(zebra_neigh_t *n, void *ctxt, json_object *json)
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
	char thread_buf[THREAD_TIMER_STRLEN];

	zvrf = zebra_vrf_get_evpn();
	if (!zvrf)
		return;

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
		vty_out(vty, " MAC: %s\n",
			prefix_mac2str(&n->emac, buf1, sizeof(buf1)));
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
		if (n->hold_timer) {
			vty_out(vty, " (ht: %s)",
				thread_timer_to_hhmmss(thread_buf,
						       sizeof(thread_buf),
						       n->hold_timer));
			sync_info = true;
		}
		if (!sync_info)
			vty_out(vty, " -");
		vty_out(vty, "\n");
	} else {
		json_object_string_add(json, "ip", buf2);
		json_object_string_add(json, "type", type_str);
		json_object_string_add(json, "state", state_str);
		json_object_string_add(json, "mac", buf1);
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL_INACTIVE))
			json_object_boolean_true_add(json, "localInactive");
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_PROXY))
			json_object_boolean_true_add(json, "peerProxy");
		if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_ES_PEER_ACTIVE))
			json_object_boolean_true_add(json, "peerActive");
		if (n->hold_timer)
			json_object_string_add(
				json, "peerActiveHold",
				thread_timer_to_hhmmss(thread_buf,
						       sizeof(thread_buf),
						       n->hold_timer));
	}
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)) {
		if (n->mac->es) {
			if (json)
				json_object_string_add(json, "remoteEs",
						       n->mac->es->esi_str);
			else
				vty_out(vty, " Remote ES: %s\n",
					n->mac->es->esi_str);
		} else {
			if (json)
				json_object_string_add(json, "remoteVtep",
						       inet_ntoa(n->r_vtep_ip));
			else
				vty_out(vty, " Remote VTEP: %s\n",
					inet_ntoa(n->r_vtep_ip));
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

void zebra_evpn_print_neigh_hdr(struct vty *vty, struct neigh_walk_ctx *wctx)
{
	vty_out(vty, "Flags: I=local-inactive, P=peer-active, X=peer-proxy\n");
	vty_out(vty, "%*s %-6s %-5s %-8s %-17s %-30s %s\n", -wctx->addr_width,
		"Neighbor", "Type", "Flags", "State", "MAC", "Remote ES/VTEP",
		"Seq #'s");
}

static char *zebra_evpn_print_neigh_flags(zebra_neigh_t *n, char *flags_buf,
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
void zebra_evpn_print_neigh_hash(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json_evpn = NULL, *json_row = NULL;
	zebra_neigh_t *n;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;
	const char *state_str;
	char flags_buf[6];

	vty = wctx->vty;
	json_evpn = wctx->json;
	n = (zebra_neigh_t *)bucket->data;

	if (json_evpn)
		json_row = json_object_new_object();

	prefix_mac2str(&n->emac, buf1, sizeof(buf1));
	ipaddr2str(&n->ip, buf2, sizeof(buf2));
	state_str = IS_ZEBRA_NEIGH_ACTIVE(n) ? "active" : "inactive";
	if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
		if (wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
			return;

		if (json_evpn == NULL) {
			vty_out(vty, "%*s %-6s %-5s %-8s %-17s %-30s %u/%u\n",
				-wctx->addr_width, buf2, "local",
				zebra_evpn_print_neigh_flags(n, flags_buf,
                    sizeof(flags_buf)), state_str, buf1,
                    "", n->loc_seq, n->rem_seq);
		} else {
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
		if ((wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
		    && !IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip))
			return;

		if (json_evpn == NULL) {
			if ((wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
			    && (wctx->count == 0))
				zebra_evpn_print_neigh_hdr(vty, wctx);
			vty_out(vty, "%*s %-6s %-5s %-8s %-17s %-30s %u/%u\n",
				-wctx->addr_width, buf2, "remote",
				zebra_evpn_print_neigh_flags(n, flags_buf,
				sizeof(flags_buf)), state_str, buf1,
				n->mac->es ? n->mac->es->esi_str
					   : inet_ntoa(n->r_vtep_ip),
				n->loc_seq, n->rem_seq);
		} else {
			json_object_string_add(json_row, "type", "remote");
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(json_row, "mac", buf1);
			if (n->mac->es)
				json_object_string_add(json_row, "remoteEs",
						       n->mac->es->esi_str);
			else
				json_object_string_add(json_row, "remoteVtep",
						       inet_ntoa(n->r_vtep_ip));
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
void zebra_evpn_print_neigh_hash_detail(struct hash_bucket *bucket, void *ctxt)
{
	struct vty *vty;
	json_object *json_evpn = NULL, *json_row = NULL;
	zebra_neigh_t *n;
	char buf[INET6_ADDRSTRLEN];
	struct neigh_walk_ctx *wctx = ctxt;

	vty = wctx->vty;
	json_evpn = wctx->json;
	n = (zebra_neigh_t *)bucket->data;
	if (!n)
		return;

	ipaddr2str(&n->ip, buf, sizeof(buf));
	if (json_evpn)
		json_row = json_object_new_object();

	zebra_evpn_print_neigh(n, vty, json_row);

	if (json_evpn)
		json_object_object_add(json_evpn, buf, json_row);
}

void zebra_evpn_print_dad_neigh_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_neigh_t *nbr;

	nbr = (zebra_neigh_t *)bucket->data;
	if (!nbr)
		return;

	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
		zebra_evpn_print_neigh_hash(bucket, ctxt);
}

void zebra_evpn_print_dad_neigh_hash_detail(struct hash_bucket *bucket,
					    void *ctxt)
{
	zebra_neigh_t *nbr;

	nbr = (zebra_neigh_t *)bucket->data;
	if (!nbr)
		return;

	if (CHECK_FLAG(nbr->flags, ZEBRA_NEIGH_DUPLICATE))
		zebra_evpn_print_neigh_hash_detail(bucket, ctxt);
}

void process_neigh_remote_macip_add(zebra_evpn_t *zevpn, struct zebra_vrf *zvrf,
				    struct ipaddr *ipaddr, zebra_mac_t *mac,
				    struct in_addr vtep_ip, uint8_t flags,
				    uint32_t seq)
{
	zebra_neigh_t *n;
	int update_neigh = 0;
	uint32_t tmp_seq;
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];
	zebra_mac_t *old_mac = NULL;
	bool old_static = false;
	bool do_dad = false;
	bool is_dup_detect = false;
	bool is_router;

	is_router = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

	/* Check if the remote neighbor itself is unknown or has a
	 * change. If so, create or update and then install the entry.
	 */
	n = zebra_evpn_neigh_lookup(zevpn, ipaddr);
	if (!n || !CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)
	    || is_router != !!CHECK_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG)
	    || (memcmp(&n->emac, &mac->macaddr, sizeof(struct ethaddr)) != 0)
	    || !IPV4_ADDR_SAME(&n->r_vtep_ip, &vtep_ip) || seq != n->rem_seq)
		update_neigh = 1;

	if (update_neigh) {
		if (!n) {
			n = zebra_evpn_neigh_add(zevpn, ipaddr, &mac->macaddr,
						 mac, 0);
			if (!n) {
				zlog_warn(
					"Failed to add Neigh %s MAC %s VNI %u Remote VTEP %s",
					ipaddr2str(ipaddr, buf1, sizeof(buf1)),
					prefix_mac2str(&mac->macaddr, buf,
						       sizeof(buf)),
					zevpn->vni, inet_ntoa(vtep_ip));
				return;
			}

		} else {
			const char *n_type;

			/* When host moves but changes its (MAC,IP)
			 * binding, BGP may install a MACIP entry that
			 * corresponds to "older" location of the host
			 * in transient situations (because {IP1,M1}
			 * is a different route from {IP1,M2}). Check
			 * the sequence number and ignore this update
			 * if appropriate.
			 */
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
				tmp_seq = n->loc_seq;
				n_type = "local";
			} else {
				tmp_seq = n->rem_seq;
				n_type = "remote";
			}
			if (seq < tmp_seq) {
				if (IS_ZEBRA_DEBUG_VXLAN)
					zlog_debug(
						"Ignore remote MACIP ADD VNI %u MAC %s%s%s as existing %s Neigh has higher seq %u",
						zevpn->vni,
						prefix_mac2str(&mac->macaddr,
							       buf,
							       sizeof(buf)),
						" IP ",
						ipaddr2str(ipaddr, buf1,
							   sizeof(buf1)),
						n_type, tmp_seq);
				return;
			}
			if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL)) {
				old_static = zebra_evpn_neigh_is_static(n);
				if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
					zlog_debug(
						"sync->remote neigh vni %u ip %s mac %s seq %d f0x%x",
						n->zevpn->vni,
						ipaddr2str(&n->ip, buf1,
							   sizeof(buf1)),
						prefix_mac2str(&n->emac, buf,
							       sizeof(buf)),
						seq, n->flags);
				zebra_evpn_neigh_clear_sync_info(n);
				if (IS_ZEBRA_NEIGH_ACTIVE(n))
					zebra_evpn_mac_send_del_to_client(
						zevpn->vni, &mac->macaddr,
						mac->flags, false /*force*/);
			}
			if (memcmp(&n->emac, &mac->macaddr,
				   sizeof(struct ethaddr))
			    != 0) {
				/* update neigh list for macs */
				old_mac =
					zebra_evpn_mac_lookup(zevpn, &n->emac);
				if (old_mac) {
					listnode_delete(old_mac->neigh_list, n);
					n->mac = NULL;
					zebra_evpn_deref_ip2mac(zevpn, old_mac);
				}
				n->mac = mac;
				listnode_add_sort(mac->neigh_list, n);
				memcpy(&n->emac, &mac->macaddr, ETH_ALEN);

				/* Check Neigh's curent state is local
				 * (this is the case where neigh/host has  moved
				 * from L->R) and check previous detction
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
		n->r_vtep_ip = vtep_ip;
		SET_FLAG(n->flags, ZEBRA_NEIGH_REMOTE);

		/* Set router flag (R-bit) to this Neighbor entry */
		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG))
			SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);
		else
			UNSET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

		/* Check old or new MAC detected as duplicate,
		 * inherit duplicate flag to this neigh.
		 */
		if (zebra_evpn_ip_inherit_dad_from_mac(zvrf, old_mac, mac, n)) {
			flog_warn(
				EC_ZEBRA_DUP_IP_INHERIT_DETECTED,
				"VNI %u: MAC %s IP %s detected as duplicate during remote update, inherit duplicate from MAC",
				zevpn->vni,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				ipaddr2str(&n->ip, buf1, sizeof(buf1)));
		}

		/* Check duplicate address detection for IP */
		zebra_evpn_dup_addr_detect_for_neigh(
			zvrf, n, n->r_vtep_ip, do_dad, &is_dup_detect, false);
		/* Install the entry. */
		if (!is_dup_detect)
			zebra_evpn_rem_neigh_install(zevpn, n, old_static);
	}

	/* Update seq number. */
	n->rem_seq = seq;
}

int zebra_evpn_neigh_gw_macip_add(struct interface *ifp, zebra_evpn_t *zevpn,
				  struct ipaddr *ip, zebra_mac_t *mac)
{
	zebra_neigh_t *n;
	char buf[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];


	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n) {
		n = zebra_evpn_neigh_add(zevpn, ip, &mac->macaddr, mac, 0);
		if (!n) {
			flog_err(
				EC_ZEBRA_MAC_ADD_FAILED,
				"Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
				ipaddr2str(ip, buf2, sizeof(buf2)),
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				ifp->name, ifp->ifindex, zevpn->vni);
			return -1;
		}
	}

	/* Set "local" forwarding info. */
	SET_FLAG(n->flags, ZEBRA_NEIGH_LOCAL);
	ZEBRA_NEIGH_SET_ACTIVE(n);
	memcpy(&n->emac, &mac->macaddr, ETH_ALEN);
	n->ifindex = ifp->ifindex;

	/* Only advertise in BGP if the knob is enabled */
	if (advertise_gw_macip_enabled(zevpn)) {

		SET_FLAG(mac->flags, ZEBRA_MAC_DEF_GW);
		SET_FLAG(n->flags, ZEBRA_NEIGH_DEF_GW);
		/* Set Router flag (R-bit) */
		if (ip->ipa_type == IPADDR_V6)
			SET_FLAG(n->flags, ZEBRA_NEIGH_ROUTER_FLAG);

		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"SVI %s(%u) L2-VNI %u, sending GW MAC %s IP %s add to BGP with flags 0x%x",
				ifp->name, ifp->ifindex, zevpn->vni,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				ipaddr2str(ip, buf2, sizeof(buf2)), n->flags);

		zebra_evpn_neigh_send_add_to_client(
			zevpn->vni, ip, &n->emac, n->mac, n->flags, n->loc_seq);
	} else if (advertise_svi_macip_enabled(zevpn)) {

		SET_FLAG(n->flags, ZEBRA_NEIGH_SVI_IP);
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"SVI %s(%u) L2-VNI %u, sending SVI MAC %s IP %s add to BGP with flags 0x%x",
				ifp->name, ifp->ifindex, zevpn->vni,
				prefix_mac2str(&mac->macaddr, buf, sizeof(buf)),
				ipaddr2str(ip, buf2, sizeof(buf2)), n->flags);

		zebra_evpn_neigh_send_add_to_client(
			zevpn->vni, ip, &n->emac, n->mac, n->flags, n->loc_seq);
	}

	return 0;
}

void zebra_evpn_neigh_remote_uninstall(zebra_evpn_t *zevpn,
				       struct zebra_vrf *zvrf, zebra_neigh_t *n,
				       zebra_mac_t *mac, struct ipaddr *ipaddr)
{
	char buf1[INET6_ADDRSTRLEN];

	if (zvrf->dad_freeze && CHECK_FLAG(n->flags, ZEBRA_NEIGH_DUPLICATE)
	    && CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE)
	    && (memcmp(n->emac.octet, mac->macaddr.octet, ETH_ALEN) == 0)) {
		struct interface *vlan_if;

		vlan_if = zevpn_map_to_svi(zevpn);
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"%s: IP %s (flags 0x%x intf %s) is remote and duplicate, read kernel for local entry",
				__func__,
				ipaddr2str(ipaddr, buf1, sizeof(buf1)),
				n->flags, vlan_if ? vlan_if->name : "Unknown");
		if (vlan_if)
			neigh_read_specific_ip(ipaddr, vlan_if);
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
	}
}

int zebra_evpn_neigh_del_ip(zebra_evpn_t *zevpn, struct ipaddr *ip)
{
	zebra_neigh_t *n;
	zebra_mac_t *zmac;
	bool old_bgp_ready;
	bool new_bgp_ready;
	char buf[INET6_ADDRSTRLEN];
	char buf2[ETHER_ADDR_STRLEN];
	struct zebra_vrf *zvrf;

	/* If entry doesn't exist, nothing to do. */
	n = zebra_evpn_neigh_lookup(zevpn, ip);
	if (!n)
		return 0;

	zmac = zebra_evpn_mac_lookup(zevpn, &n->emac);
	if (!zmac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Trying to del a neigh %s without a mac %s on VNI %u",
				ipaddr2str(ip, buf, sizeof(buf)),
				prefix_mac2str(&n->emac, buf2, sizeof(buf2)),
				zevpn->vni);

		return 0;
	}

	/* If it is a remote entry, the kernel has aged this out or someone has
	 * deleted it, it needs to be re-installed as Quagga is the owner.
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
			zlog_debug("re-add sync neigh vni %u ip %s mac %s 0x%x",
				   n->zevpn->vni,
				   ipaddr2str(&n->ip, buf, sizeof(buf)),
				   prefix_mac2str(&n->emac, buf2, sizeof(buf2)),
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

	zvrf = vrf_info_lookup(zevpn->vxlan_if->vrf_id);
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
	    && !listcount(zmac->neigh_list))
		zebra_evpn_mac_del(zevpn, zmac);

	return 0;
}
