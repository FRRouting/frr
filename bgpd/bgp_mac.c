/*
 * BGPd - Mac hash code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <jhash.h>
#include <hash.h>
#include <prefix.h>
#include <memory.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn_private.h"

DEFINE_MTYPE_STATIC(BGPD, BSM, "Mac Hash Entry");
DEFINE_MTYPE_STATIC(BGPD, BSM_STRING, "Mac Hash Entry Interface String");

struct bgp_self_mac {
	struct ethaddr macaddr;
	struct list *ifp_list;
};

static unsigned int bgp_mac_hash_key_make(void *data)
{
	struct bgp_self_mac *bsm = data;

	return jhash(&bsm->macaddr, ETH_ALEN, 0xa5a5dead);
}

static bool bgp_mac_hash_cmp(const void *d1, const void *d2)
{
	const struct bgp_self_mac *bsm1 = d1;
	const struct bgp_self_mac *bsm2 = d2;

	if (memcmp(&bsm1->macaddr, &bsm2->macaddr, ETH_ALEN) == 0)
		return true;

	return false;
}

void bgp_mac_init(void)
{
	bm->self_mac_hash = hash_create(bgp_mac_hash_key_make, bgp_mac_hash_cmp,
					"BGP MAC Hash");
}

static void bgp_mac_hash_free(void *data)
{
	struct bgp_self_mac *bsm = data;

	if (bsm->ifp_list)
		list_delete(&bsm->ifp_list);

	XFREE(MTYPE_BSM, bsm);
}

void bgp_mac_finish(void)
{
	hash_clean(bm->self_mac_hash, bgp_mac_hash_free);
	hash_free(bm->self_mac_hash);
}

static void bgp_mac_hash_interface_string_del(void *val)
{
	char *data = val;

	XFREE(MTYPE_BSM_STRING, data);
}

static void *bgp_mac_hash_alloc(void *p)
{
	const struct bgp_self_mac *orig = p;
	struct bgp_self_mac *bsm;

	bsm = XCALLOC(MTYPE_BSM, sizeof(struct bgp_self_mac));
	memcpy(&bsm->macaddr, &orig->macaddr, ETH_ALEN);

	bsm->ifp_list = list_new();
	bsm->ifp_list->del = bgp_mac_hash_interface_string_del;

	return bsm;
}

struct bgp_mac_find_internal {
	struct bgp_self_mac *bsm;
	const char *ifname;
};

static void bgp_mac_find_ifp_internal(struct hash_bucket *bucket, void *arg)
{
	struct bgp_mac_find_internal *bmfi = arg;
	struct bgp_self_mac *bsm = bucket->data;
	struct listnode *node;
	char *name;

	for (ALL_LIST_ELEMENTS_RO(bsm->ifp_list, node, name)) {
		if (strcmp(name, bmfi->ifname) == 0) {
			bmfi->bsm = bsm;
			return;
		}
	}
}

static struct bgp_self_mac *bgp_mac_find_interface_name(const char *ifname)
{
	struct bgp_mac_find_internal bmfi;

	bmfi.bsm = NULL;
	bmfi.ifname = ifname;
	hash_iterate(bm->self_mac_hash, bgp_mac_find_ifp_internal, &bmfi);

	return bmfi.bsm;
}

static void bgp_process_mac_rescan_table(struct bgp *bgp, struct peer *peer,
					 struct bgp_table *table)
{
	struct bgp_node *prn, *rn;
	struct bgp_path_info *pi;
	uint32_t count = 0;

	for (prn = bgp_table_top(table); prn; prn = bgp_route_next(prn)) {
		struct bgp_table *sub = prn->info;

		if (!sub)
			continue;

		for (rn = bgp_table_top(sub); rn; rn = bgp_route_next(rn)) {
			struct prefix_rd prd;
			uint32_t num_labels = 0;
			mpls_label_t *label_pnt = NULL;
			struct bgp_route_evpn evpn;

			count++;
			for (pi = rn->info; pi; pi = pi->next) {
				if (pi->peer == peer)
					break;
			}

			if (!pi)
				continue;

			if (pi->extra)
				num_labels = pi->extra->num_labels;
			if (num_labels)
				label_pnt = &pi->extra->label[0];

			prd.family = AF_UNSPEC;
			prd.prefixlen = 64;
			memcpy(&prd.val, &prn->p.u.val, 8);

			memcpy(&evpn, &pi->attr->evpn_overlay, sizeof(evpn));
			int32_t ret = bgp_update(peer, &rn->p,
						 pi->addpath_rx_id,
						 pi->attr, AFI_L2VPN, SAFI_EVPN,
						 ZEBRA_ROUTE_BGP,
						 BGP_ROUTE_NORMAL, &prd,
						 label_pnt, num_labels,
						 1, &evpn);

			if (ret < 0)
				bgp_unlock_node(rn);
		}
	}
}

static void bgp_mac_rescan_evpn_table(struct bgp *bgp)
{
	struct listnode *node;
	struct peer *peer;
	safi_t safi;
	afi_t afi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
			continue;

		if (peer->status != Established)
			continue;

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_SOFT_RECONFIG)) {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug("Processing EVPN MAC interface change on peer %s (inbound, soft-reconfig)",
					   peer->host);

			bgp_soft_reconfig_in(peer, afi, safi);
		} else {
			struct bgp_table *table = bgp->rib[afi][safi];

			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug("Processing EVPN MAC interface change on peer %s",
					   peer->host);
			bgp_process_mac_rescan_table(bgp, peer, table);
		}
	}
}

static void bgp_mac_rescan_all_evpn_tables(void)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_table *table = bgp->rib[AFI_L2VPN][SAFI_EVPN];

		if (table)
			bgp_mac_rescan_evpn_table(bgp);
	}
}

static void bgp_mac_remove_ifp_internal(struct bgp_self_mac *bsm, char *ifname)
{
	struct listnode *node = NULL;
	char *name;

	for (ALL_LIST_ELEMENTS_RO(bsm->ifp_list, node, name)) {
		if (strcmp(name, ifname) == 0)
			break;
	}

	if (node) {
		list_delete_node(bsm->ifp_list, node);
		XFREE(MTYPE_BSM_STRING, name);
	}

	if (bsm->ifp_list->count == 0) {
		hash_release(bm->self_mac_hash, bsm);
		list_delete(&bsm->ifp_list);
		XFREE(MTYPE_BSM, bsm);

		bgp_mac_rescan_all_evpn_tables();
	}
}

void bgp_mac_add_mac_entry(struct interface *ifp)
{
	struct bgp_self_mac lookup;
	struct bgp_self_mac *bsm;
	struct bgp_self_mac *old_bsm;
	char *ifname;

	memcpy(&lookup.macaddr, &ifp->hw_addr, ETH_ALEN);
	bsm = hash_get(bm->self_mac_hash, &lookup, bgp_mac_hash_alloc);

	/*
	 * Does this happen to be a move
	 */
	old_bsm = bgp_mac_find_interface_name(ifp->name);
	ifname = XSTRDUP(MTYPE_BSM_STRING, ifp->name);

	if (bsm->ifp_list->count == 0) {

		listnode_add(bsm->ifp_list, ifname);
		if (old_bsm)
			bgp_mac_remove_ifp_internal(old_bsm, ifname);
	} else {
		/*
		 * If old mac address is the same as the new,
		 * then there is nothing to do here
		 */
		if (old_bsm == bsm)
			return;

		if (old_bsm)
			bgp_mac_remove_ifp_internal(old_bsm, ifp->name);

		listnode_add(bsm->ifp_list, ifname);
	}

	bgp_mac_rescan_all_evpn_tables();
}

void bgp_mac_del_mac_entry(struct interface *ifp)
{
	struct bgp_self_mac lookup;
	struct bgp_self_mac *bsm;

	memcpy(&lookup.macaddr, &ifp->hw_addr, ETH_ALEN);
	bsm = hash_lookup(bm->self_mac_hash, &lookup);
	if (!bsm)
		return;

	/*
	 * Write code to allow old mac address to no-longer
	 * win if we happen to have received it from a peer.
	 */
	bgp_mac_remove_ifp_internal(bsm, ifp->name);
}

bool bgp_mac_entry_exists(struct prefix *p)
{
	struct prefix_evpn *pevpn = (struct prefix_evpn *)p;
	struct bgp_self_mac lookup;
	struct bgp_self_mac *bsm;

	if (pevpn->family != AF_EVPN)
		return false;

	if (pevpn->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return false;

	memcpy(&lookup.macaddr, &p->u.prefix_evpn.macip_addr.mac, ETH_ALEN);
	bsm = hash_lookup(bm->self_mac_hash, &lookup);
	if (!bsm)
		return false;

	return true;
}

static void bgp_mac_show_mac_entry(struct hash_bucket *bucket, void *arg)
{
	struct vty *vty = arg;
	struct bgp_self_mac *bsm = bucket->data;
	struct listnode *node;
	char *name;
	char buf_mac[ETHER_ADDR_STRLEN];

	vty_out(vty, "Mac Address: %s ",
		prefix_mac2str(&bsm->macaddr, buf_mac, sizeof(buf_mac)));

	for (ALL_LIST_ELEMENTS_RO(bsm->ifp_list, node, name))
		vty_out(vty, "%s ", name);

	vty_out(vty, "\n");
}

void bgp_mac_dump_table(struct vty *vty)
{
	hash_iterate(bm->self_mac_hash, bgp_mac_show_mac_entry, vty);
}
