// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGPd - Mac hash code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include <jhash.h>
#include <hash.h>
#include <prefix.h>
#include <memory.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn_private.h"

DEFINE_MTYPE_STATIC(BGPD, BSM, "Mac Hash Entry");
DEFINE_MTYPE_STATIC(BGPD, BSM_STRING, "Mac Hash Entry Intf String");

struct bgp_self_mac {
	struct ethaddr macaddr;
	struct list *ifp_list;
};

static unsigned int bgp_mac_hash_key_make(const void *data)
{
	const struct bgp_self_mac *bsm = data;

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
	hash_clean_and_free(&bm->self_mac_hash, bgp_mac_hash_free);
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
					 struct bgp_table *table,
					 struct ethaddr *macaddr)
{
	struct bgp_dest *pdest, *dest;
	struct bgp_path_info *pi;
	uint8_t num_labels;
	mpls_label_t *label_pnt;

	for (pdest = bgp_table_top(table); pdest;
	     pdest = bgp_route_next(pdest)) {
		struct bgp_table *sub = pdest->info;
		const struct prefix *pdest_p = bgp_dest_get_prefix(pdest);

		if (!sub)
			continue;

		for (dest = bgp_table_top(sub); dest;
		     dest = bgp_route_next(dest)) {
			bool dest_affected;
			const struct prefix *p = bgp_dest_get_prefix(dest);
			struct prefix_evpn *pevpn = (struct prefix_evpn *)dest;
			struct prefix_rd prd;
			struct bgp_route_evpn *evpn;

			if (pevpn->family == AF_EVPN
			    && pevpn->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
			    && memcmp(&p->u.prefix_evpn.macip_addr.mac, macaddr,
				      ETH_ALEN)
				       == 0)
				dest_affected = true;
			else
				dest_affected = false;

			for (pi = dest->info; pi; pi = pi->next) {
				if (pi->peer == peer)
					break;
			}

			if (!pi)
				continue;

			/*
			 * If the mac address is not the same then
			 * we don't care and since we are looking
			 */
			if ((memcmp(&pi->attr->rmac, macaddr, ETH_ALEN) != 0)
			    && !dest_affected)
				continue;

			num_labels = BGP_PATH_INFO_NUM_LABELS(pi);
			label_pnt = num_labels ? &pi->extra->labels->label[0]
					       : NULL;

			prd.family = AF_UNSPEC;
			prd.prefixlen = 64;
			memcpy(&prd.val, pdest_p->u.val, 8);

			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
				if (bgp_debug_update(peer, p, NULL, 1)) {
					char pfx_buf[BGP_PRD_PATH_STRLEN];

					bgp_debug_rdpfxpath2str(
						AFI_L2VPN, SAFI_EVPN, &prd,
						p, label_pnt, num_labels,
						pi->addpath_rx_id ? 1 : 0,
						pi->addpath_rx_id, NULL,
						pfx_buf, sizeof(pfx_buf));
					zlog_debug(
						   "%s skip update of %s marked as removed",
						   peer->host, pfx_buf);
				}
				continue;
			}

			memcpy(&evpn, bgp_attr_get_evpn_overlay(pi->attr),
			       sizeof(evpn));
			bgp_update(peer, p, pi->addpath_rx_id, pi->attr,
				   AFI_L2VPN, SAFI_EVPN, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, &prd, label_pnt,
				   num_labels, 1, evpn);
		}
	}
}

static void bgp_mac_rescan_evpn_table(struct bgp *bgp, struct ethaddr *macaddr)
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

		if (!peer_established(peer->connection))
			continue;

		if (bgp_debug_update(peer, NULL, NULL, 1))
			zlog_debug(
				"Processing EVPN MAC interface change on peer %s %s",
				peer->host,
				CHECK_FLAG(peer->af_flags[afi][safi],
					   PEER_FLAG_SOFT_RECONFIG)
					? "(inbound, soft-reconfig)"
					: "");

		if (!bgp_soft_reconfig_in(peer, afi, safi)) {
			struct bgp_table *table = bgp->rib[afi][safi];

			bgp_process_mac_rescan_table(bgp, peer, table, macaddr);
		}
	}
}

static void bgp_mac_rescan_all_evpn_tables(struct ethaddr *macaddr)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bgp_table *table = bgp->rib[AFI_L2VPN][SAFI_EVPN];

		if (table)
			bgp_mac_rescan_evpn_table(bgp, macaddr);
	}
}

static void bgp_mac_remove_ifp_internal(struct bgp_self_mac *bsm, char *ifname,
					struct ethaddr *macaddr)
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
		struct ethaddr mac = *macaddr;

		hash_release(bm->self_mac_hash, bsm);
		list_delete(&bsm->ifp_list);
		XFREE(MTYPE_BSM, bsm);

		bgp_mac_rescan_all_evpn_tables(&mac);
	}
}

/* Add/Update entry of the 'bgp mac hash' table.
 * A rescan of the EVPN tables is only needed if
 * a new hash bucket is allocated.
 * Learning an existing mac on a new interface (or
 * having an existing mac move from one interface to
 * another) does not result in changes to self mac
 * state, so we shouldn't trigger a rescan.
 */
void bgp_mac_add_mac_entry(struct interface *ifp)
{
	struct bgp_self_mac lookup;
	struct bgp_self_mac *bsm;
	struct bgp_self_mac *old_bsm;
	char *ifname;
	bool mac_added = false;

	memcpy(&lookup.macaddr, &ifp->hw_addr, ETH_ALEN);
	bsm = hash_lookup(bm->self_mac_hash, &lookup);
	if (!bsm) {
		bsm = hash_get(bm->self_mac_hash, &lookup, bgp_mac_hash_alloc);
		/* mac is new, rescan needs to be triggered */
		mac_added = true;
	}

	/*
	 * Does this happen to be a move
	 */
	old_bsm = bgp_mac_find_interface_name(ifp->name);
	ifname = XSTRDUP(MTYPE_BSM_STRING, ifp->name);

	if (bsm->ifp_list->count == 0) {

		listnode_add(bsm->ifp_list, ifname);
		if (old_bsm)
			bgp_mac_remove_ifp_internal(old_bsm, ifname,
						    &old_bsm->macaddr);
	} else {
		/*
		 * If old mac address is the same as the new,
		 * then there is nothing to do here
		 */
		if (old_bsm == bsm) {
			XFREE(MTYPE_BSM_STRING, ifname);
			return;
		}

		if (old_bsm)
			bgp_mac_remove_ifp_internal(old_bsm, ifp->name,
						    &old_bsm->macaddr);

		listnode_add(bsm->ifp_list, ifname);
	}

	if (mac_added)
		bgp_mac_rescan_all_evpn_tables(&bsm->macaddr);
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
	bgp_mac_remove_ifp_internal(bsm, ifp->name, &bsm->macaddr);
}

/* This API checks MAC address against any of local
 * assigned (SVIs) MAC address.
 * An example: router-mac attribute in any of evpn update
 * requires to compare against local mac.
 */
bool bgp_mac_exist(const struct ethaddr *mac)
{
	struct bgp_self_mac lookup;
	struct bgp_self_mac *bsm;
	static uint8_t tmp [ETHER_ADDR_STRLEN] = {0};

	if (memcmp(mac, &tmp, ETH_ALEN) == 0)
		return false;

	memcpy(&lookup.macaddr, mac, ETH_ALEN);
	bsm = hash_lookup(bm->self_mac_hash, &lookup);
	if (!bsm)
		return false;

	return true;
}

/* This API checks EVPN type-2 prefix and compares
 * mac against any of local assigned (SVIs) MAC
 * address.
 */
bool bgp_mac_entry_exists(const struct prefix *p)
{
	const struct prefix_evpn *pevpn = (const struct prefix_evpn *)p;

	if (pevpn->family != AF_EVPN)
		return false;

	if (pevpn->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return false;

	return bgp_mac_exist(&p->u.prefix_evpn.macip_addr.mac);
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
