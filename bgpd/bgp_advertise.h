// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP advertisement and adjacency
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_ADVERTISE_H
#define _QUAGGA_BGP_ADVERTISE_H

#include "lib/typesafe.h"

PREDECL_DLIST(bgp_adv_fifo);

struct update_subgroup;
struct bgp_advertise;

PREDECL_DLIST(bgp_advertise_attr_fifo);

struct bgp_advertise_attr;

/* BGP advertise attribute.  */
struct bgp_advertise {
	/* FIFO for advertisement.  */
	struct bgp_adv_fifo_item fifo;

	/* FIFO for this item in the bgp_advertise_attr fifo */
	struct bgp_advertise_attr_fifo_item item;

	/* Prefix information.  */
	struct bgp_dest *dest;

	/* Reference pointer.  */
	struct bgp_adj_out *adj;

	/* Advertisement attribute.  */
	struct bgp_advertise_attr *baa;

	/* BGP info.  */
	struct bgp_path_info *pathi;
};

DECLARE_DLIST(bgp_advertise_attr_fifo, struct bgp_advertise, item);
DECLARE_DLIST(bgp_adv_fifo, struct bgp_advertise, fifo);

/* BGP advertise attribute.  */
struct bgp_advertise_attr {
	/* Head of advertisement pointer. */
	struct bgp_advertise_attr_fifo_head fifo;

	/* Reference counter.  */
	unsigned long refcnt;

	/* Attribute pointer to be announced.  */
	struct attr *attr;
};

/* BGP adjacency out.  */
struct bgp_adj_out {
	/* RB Tree of adjacency entries */
	RB_ENTRY(bgp_adj_out) adj_entry;

	/* Advertised subgroup.  */
	struct update_subgroup *subgroup;

	/* Threading that makes the adj part of subgroup's adj queue */
	TAILQ_ENTRY(bgp_adj_out) subgrp_adj_train;

	/* Prefix information.  */
	struct bgp_dest *dest;

	uint32_t addpath_tx_id;

	/* Attribute hash */
	uint32_t attr_hash;

	/* Advertised attribute.  */
	struct attr *attr;

	/* Advertisement information.  */
	struct bgp_advertise *adv;
};

RB_HEAD(bgp_adj_out_rb, bgp_adj_out);
RB_PROTOTYPE(bgp_adj_out_rb, bgp_adj_out, adj_entry,
	     bgp_adj_out_compare);

/* BGP adjacency in. */
struct bgp_adj_in {
	/* Linked list pointer.  */
	struct bgp_adj_in *next;
	struct bgp_adj_in *prev;

	/* Received peer.  */
	struct peer *peer;

	/* Received attribute.  */
	struct attr *attr;

	/* timestamp (monotime) */
	time_t uptime;

	/* Addpath identifier */
	uint32_t addpath_rx_id;
};

/* BGP advertisement list.  */
struct bgp_synchronize {
	struct bgp_adv_fifo_head update;
	struct bgp_adv_fifo_head withdraw;
};

/* BGP adjacency linked list.  */
#define BGP_PATH_INFO_ADD(N, A, TYPE)                                          \
	do {                                                                   \
		(A)->prev = NULL;                                              \
		(A)->next = (N)->TYPE;                                         \
		if ((N)->TYPE)                                                 \
			(N)->TYPE->prev = (A);                                 \
		(N)->TYPE = (A);                                               \
	} while (0)

#define BGP_PATH_INFO_DEL(N, A, TYPE)                                          \
	do {                                                                   \
		if ((A)->next)                                                 \
			(A)->next->prev = (A)->prev;                           \
		if ((A)->prev)                                                 \
			(A)->prev->next = (A)->next;                           \
		else                                                           \
			(N)->TYPE = (A)->next;                                 \
	} while (0)

#define BGP_ADJ_IN_ADD(N, A) BGP_PATH_INFO_ADD(N, A, adj_in)
#define BGP_ADJ_IN_DEL(N, A) BGP_PATH_INFO_DEL(N, A, adj_in)

/* Prototypes.  */
extern bool bgp_adj_out_lookup(struct peer *peer, struct bgp_dest *dest,
			       uint32_t addpath_tx_id);
extern void bgp_adj_in_set(struct bgp_dest *dest, struct peer *peer,
			   struct attr *attr, uint32_t addpath_id);
extern bool bgp_adj_in_unset(struct bgp_dest **dest, struct peer *peer,
			     uint32_t addpath_id);
extern void bgp_adj_in_remove(struct bgp_dest **dest, struct bgp_adj_in *bai);

extern unsigned int bgp_advertise_attr_hash_key(const void *p);
extern bool bgp_advertise_attr_hash_cmp(const void *p1, const void *p2);
extern void bgp_advertise_add(struct bgp_advertise_attr *baa,
			      struct bgp_advertise *adv);
extern struct bgp_advertise *bgp_advertise_new(void);
extern void bgp_advertise_free(struct bgp_advertise *adv);
extern struct bgp_advertise_attr *bgp_advertise_attr_intern(struct hash *hash,
							    struct attr *attr);
extern struct bgp_advertise_attr *bgp_advertise_attr_new(void);
extern void bgp_advertise_delete(struct bgp_advertise_attr *baa,
				 struct bgp_advertise *adv);
extern void bgp_advertise_attr_unintern(struct hash *hash,
					struct bgp_advertise_attr *baa);
extern void bgp_advertise_attr_free(struct bgp_advertise_attr *baa);

#endif /* _QUAGGA_BGP_ADVERTISE_H */
