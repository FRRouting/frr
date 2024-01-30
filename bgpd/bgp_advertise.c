// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP advertisement and adjacency
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "frrevent.h"
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
struct bgp_advertise_attr *bgp_advertise_attr_new(void)
{
	return XCALLOC(MTYPE_BGP_ADVERTISE_ATTR,
		       sizeof(struct bgp_advertise_attr));
}

void bgp_advertise_attr_free(struct bgp_advertise_attr *baa)
{
	bgp_advertise_attr_fifo_fini(&baa->fifo);

	XFREE(MTYPE_BGP_ADVERTISE_ATTR, baa);
}

static void *bgp_advertise_attr_hash_alloc(void *p)
{
	struct bgp_advertise_attr *ref = (struct bgp_advertise_attr *)p;
	struct bgp_advertise_attr *baa;

	baa = bgp_advertise_attr_new();
	baa->attr = ref->attr;

	bgp_advertise_attr_fifo_init(&baa->fifo);

	return baa;
}

unsigned int bgp_advertise_attr_hash_key(const void *p)
{
	const struct bgp_advertise_attr *baa = p;

	return attrhash_key_make(baa->attr);
}

bool bgp_advertise_attr_hash_cmp(const void *p1, const void *p2)
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
	return XCALLOC(MTYPE_BGP_ADVERTISE, sizeof(struct bgp_advertise));
}

void bgp_advertise_free(struct bgp_advertise *adv)
{
	if (adv->pathi)
		/* bgp_advertise bgp_path_info reference */
		bgp_path_info_unlock(adv->pathi);
	XFREE(MTYPE_BGP_ADVERTISE, adv);
}

void bgp_advertise_add(struct bgp_advertise_attr *baa,
		       struct bgp_advertise *adv)
{
	bgp_advertise_attr_fifo_add_tail(&baa->fifo, adv);
}

void bgp_advertise_delete(struct bgp_advertise_attr *baa,
			  struct bgp_advertise *adv)
{
	bgp_advertise_attr_fifo_del(&baa->fifo, adv);
}

struct bgp_advertise_attr *bgp_advertise_attr_intern(struct hash *hash,
						     struct attr *attr)
{
	struct bgp_advertise_attr ref;
	struct bgp_advertise_attr *baa;

	ref.attr = bgp_attr_intern(attr);
	baa = (struct bgp_advertise_attr *)hash_get(
		hash, &ref, bgp_advertise_attr_hash_alloc);
	baa->refcnt++;

	return baa;
}

void bgp_advertise_attr_unintern(struct hash *hash,
				 struct bgp_advertise_attr *baa)
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
		bgp_advertise_attr_free(baa);
	}
}

bool bgp_adj_out_lookup(struct peer *peer, struct bgp_dest *dest,
			uint32_t addpath_tx_id)
{
	struct bgp_adj_out *adj;
	struct peer_af *paf;
	afi_t afi;
	safi_t safi;
	bool addpath_capable;

	RB_FOREACH (adj, bgp_adj_out_rb, &dest->adj_out)
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

				return (adj->adv
						? (adj->adv->baa ? true : false)
						: (adj->attr ? true : false));
			}

	return false;
}


void bgp_adj_in_set(struct bgp_dest *dest, struct peer *peer, struct attr *attr,
		    uint32_t addpath_id)
{
	struct bgp_adj_in *adj;

	for (adj = dest->adj_in; adj; adj = adj->next) {
		if (adj->peer == peer && adj->addpath_rx_id == addpath_id) {
			if (!attrhash_cmp(adj->attr, attr)) {
				bgp_attr_unintern(&adj->attr);
				adj->attr = bgp_attr_intern(attr);
			}
			return;
		}
	}
	adj = XCALLOC(MTYPE_BGP_ADJ_IN, sizeof(struct bgp_adj_in));
	adj->peer = peer_lock(peer); /* adj_in peer reference */
	adj->attr = bgp_attr_intern(attr);
	adj->uptime = monotime(NULL);
	adj->addpath_rx_id = addpath_id;
	BGP_ADJ_IN_ADD(dest, adj);
	bgp_dest_lock_node(dest);
}

void bgp_adj_in_remove(struct bgp_dest **dest, struct bgp_adj_in *bai)
{
	bgp_attr_unintern(&bai->attr);
	BGP_ADJ_IN_DEL(*dest, bai);
	*dest = bgp_dest_unlock_node(*dest);
	peer_unlock(bai->peer); /* adj_in peer reference */
	XFREE(MTYPE_BGP_ADJ_IN, bai);
}

bool bgp_adj_in_unset(struct bgp_dest **dest, struct peer *peer,
		      uint32_t addpath_id)
{
	struct bgp_adj_in *adj;
	struct bgp_adj_in *adj_next;

	adj = (*dest)->adj_in;

	if (!adj)
		return false;

	while (adj) {
		adj_next = adj->next;

		if (adj->peer == peer && adj->addpath_rx_id == addpath_id)
			bgp_adj_in_remove(dest, adj);

		adj = adj_next;

		assert(*dest);
	}

	return true;
}
