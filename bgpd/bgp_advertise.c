/* BGP advertisement and adjacency
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "thread.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_updgrp.h"

/* BGP advertise attribute is used for pack same attribute update into
   one packet.  To do that we maintain attribute hash in struct
   peer.  */
struct bgp_advertise_attr *baa_new(void)
{
	return (struct bgp_advertise_attr *)XCALLOC(
		MTYPE_BGP_ADVERTISE_ATTR, sizeof(struct bgp_advertise_attr));
}

static void baa_free(struct bgp_advertise_attr *baa)
{
	XFREE(MTYPE_BGP_ADVERTISE_ATTR, baa);
}

static void *baa_hash_alloc(void *p)
{
	struct bgp_advertise_attr *ref = (struct bgp_advertise_attr *)p;
	struct bgp_advertise_attr *baa;

	baa = baa_new();
	baa->attr = ref->attr;
	return baa;
}

unsigned int baa_hash_key(void *p)
{
	struct bgp_advertise_attr *baa = (struct bgp_advertise_attr *)p;

	return attrhash_key_make(baa->attr);
}

int baa_hash_cmp(const void *p1, const void *p2)
{
	const struct bgp_advertise_attr *baa1 = p1;
	const struct bgp_advertise_attr *baa2 = p2;

	return attrhash_cmp(baa1->attr, baa2->attr);
}

/* BGP update and withdraw information is stored in BGP advertise
   structure.  This structure is referred from BGP adjacency
   information.  */
struct bgp_advertise *bgp_advertise_new(void)
{
	return (struct bgp_advertise *)XCALLOC(MTYPE_BGP_ADVERTISE,
					       sizeof(struct bgp_advertise));
}

void bgp_advertise_free(struct bgp_advertise *adv)
{
	if (adv->binfo)
		bgp_info_unlock(
			adv->binfo); /* bgp_advertise bgp_info reference */
	XFREE(MTYPE_BGP_ADVERTISE, adv);
}

void bgp_advertise_add(struct bgp_advertise_attr *baa,
		       struct bgp_advertise *adv)
{
	adv->next = baa->adv;
	if (baa->adv)
		baa->adv->prev = adv;
	baa->adv = adv;
}

void bgp_advertise_delete(struct bgp_advertise_attr *baa,
			  struct bgp_advertise *adv)
{
	if (adv->next)
		adv->next->prev = adv->prev;
	if (adv->prev)
		adv->prev->next = adv->next;
	else
		baa->adv = adv->next;
}

struct bgp_advertise_attr *bgp_advertise_intern(struct hash *hash,
						struct attr *attr)
{
	struct bgp_advertise_attr ref;
	struct bgp_advertise_attr *baa;

	ref.attr = bgp_attr_intern(attr);
	baa = (struct bgp_advertise_attr *)hash_get(hash, &ref, baa_hash_alloc);
	baa->refcnt++;

	return baa;
}

void bgp_advertise_unintern(struct hash *hash, struct bgp_advertise_attr *baa)
{
	if (baa->refcnt)
		baa->refcnt--;

	if (baa->refcnt && baa->attr)
		bgp_attr_unintern(&baa->attr);
	else {
		if (baa->attr) {
			hash_release(hash, baa);
			bgp_attr_unintern(&baa->attr);
		}
		baa_free(baa);
	}
}

int bgp_adj_out_lookup(struct peer *peer, struct bgp_node *rn,
		       uint32_t addpath_tx_id)
{
	struct bgp_adj_out *adj;
	struct peer_af *paf;
	afi_t afi;
	safi_t safi;
	int addpath_capable;

	for (adj = rn->adj_out; adj; adj = adj->next)
		SUBGRP_FOREACH_PEER (adj->subgroup, paf)
			if (paf->peer == peer) {
				afi = SUBGRP_AFI(adj->subgroup);
				safi = SUBGRP_SAFI(adj->subgroup);
				addpath_capable =
					bgp_addpath_encode_tx(peer, afi, safi);

				/* Match on a specific addpath_tx_id if we are
				 * using addpath for
				 * this
				 * peer and if an addpath_tx_id was specified */
				if (addpath_capable && addpath_tx_id
				    && adj->addpath_tx_id != addpath_tx_id)
					continue;

				return (adj->adv ? (adj->adv->baa ? 1 : 0)
						 : (adj->attr ? 1 : 0));
			}

	return 0;
}


void bgp_adj_in_set(struct bgp_node *rn, struct peer *peer, struct attr *attr,
		    uint32_t addpath_id)
{
	struct bgp_adj_in *adj;

	for (adj = rn->adj_in; adj; adj = adj->next) {
		if (adj->peer == peer && adj->addpath_rx_id == addpath_id) {
			if (adj->attr != attr) {
				bgp_attr_unintern(&adj->attr);
				adj->attr = bgp_attr_intern(attr);
			}
			return;
		}
	}
	adj = XCALLOC(MTYPE_BGP_ADJ_IN, sizeof(struct bgp_adj_in));
	adj->peer = peer_lock(peer); /* adj_in peer reference */
	adj->attr = bgp_attr_intern(attr);
	adj->addpath_rx_id = addpath_id;
	BGP_ADJ_IN_ADD(rn, adj);
	bgp_lock_node(rn);
}

void bgp_adj_in_remove(struct bgp_node *rn, struct bgp_adj_in *bai)
{
	bgp_attr_unintern(&bai->attr);
	BGP_ADJ_IN_DEL(rn, bai);
	peer_unlock(bai->peer); /* adj_in peer reference */
	XFREE(MTYPE_BGP_ADJ_IN, bai);
}

int bgp_adj_in_unset(struct bgp_node *rn, struct peer *peer,
		     uint32_t addpath_id)
{
	struct bgp_adj_in *adj;
	struct bgp_adj_in *adj_next;

	adj = rn->adj_in;

	if (!adj)
		return 0;

	while (adj) {
		adj_next = adj->next;

		if (adj->peer == peer && adj->addpath_rx_id == addpath_id) {
			bgp_adj_in_remove(rn, adj);
			bgp_unlock_node(rn);
		}

		adj = adj_next;
	}

	return 1;
}

void bgp_sync_init(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct bgp_synchronize *sync;

	FOREACH_AFI_SAFI (afi, safi) {
		sync = XCALLOC(MTYPE_BGP_SYNCHRONISE,
			       sizeof(struct bgp_synchronize));
		BGP_ADV_FIFO_INIT(&sync->update);
		BGP_ADV_FIFO_INIT(&sync->withdraw);
		BGP_ADV_FIFO_INIT(&sync->withdraw_low);
		peer->sync[afi][safi] = sync;
	}
}

void bgp_sync_delete(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->sync[afi][safi])
			XFREE(MTYPE_BGP_SYNCHRONISE, peer->sync[afi][safi]);
		peer->sync[afi][safi] = NULL;
	}
}
