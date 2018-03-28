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

#ifndef _QUAGGA_BGP_ADVERTISE_H
#define _QUAGGA_BGP_ADVERTISE_H

#include <lib/fifo.h>

struct update_subgroup;

/* BGP advertise FIFO.  */
struct bgp_advertise_fifo {
	struct bgp_advertise *next;
	struct bgp_advertise *prev;
	uint32_t count;
};

/* BGP advertise attribute.  */
struct bgp_advertise_attr {
	/* Head of advertisement pointer. */
	struct bgp_advertise *adv;

	/* Reference counter.  */
	unsigned long refcnt;

	/* Attribute pointer to be announced.  */
	struct attr *attr;
};

struct bgp_advertise {
	/* FIFO for advertisement.  */
	struct bgp_advertise_fifo fifo;

	/* Link list for same attribute advertise.  */
	struct bgp_advertise *next;
	struct bgp_advertise *prev;

	/* Prefix information.  */
	struct bgp_node *rn;

	/* Reference pointer.  */
	struct bgp_adj_out *adj;

	/* Advertisement attribute.  */
	struct bgp_advertise_attr *baa;

	/* BGP info.  */
	struct bgp_info *binfo;
};

/* BGP adjacency out.  */
struct bgp_adj_out {
	/* Lined list pointer.  */
	struct bgp_adj_out *next;
	struct bgp_adj_out *prev;

	/* Advertised subgroup.  */
	struct update_subgroup *subgroup;

	/* Threading that makes the adj part of subgroup's adj queue */
	TAILQ_ENTRY(bgp_adj_out) subgrp_adj_train;

	/* Prefix information.  */
	struct bgp_node *rn;

	uint32_t addpath_tx_id;

	/* Advertised attribute.  */
	struct attr *attr;

	/* Advertisement information.  */
	struct bgp_advertise *adv;
};

/* BGP adjacency in. */
struct bgp_adj_in {
	/* Linked list pointer.  */
	struct bgp_adj_in *next;
	struct bgp_adj_in *prev;

	/* Received peer.  */
	struct peer *peer;

	/* Received attribute.  */
	struct attr *attr;

	/* Addpath identifier */
	uint32_t addpath_rx_id;
};

/* BGP advertisement list.  */
struct bgp_synchronize {
	struct bgp_advertise_fifo update;
	struct bgp_advertise_fifo withdraw;
	struct bgp_advertise_fifo withdraw_low;
};

/* BGP adjacency linked list.  */
#define BGP_INFO_ADD(N, A, TYPE)                                               \
	do {                                                                   \
		(A)->prev = NULL;                                              \
		(A)->next = (N)->TYPE;                                         \
		if ((N)->TYPE)                                                 \
			(N)->TYPE->prev = (A);                                 \
		(N)->TYPE = (A);                                               \
	} while (0)

#define BGP_INFO_DEL(N, A, TYPE)                                               \
	do {                                                                   \
		if ((A)->next)                                                 \
			(A)->next->prev = (A)->prev;                           \
		if ((A)->prev)                                                 \
			(A)->prev->next = (A)->next;                           \
		else                                                           \
			(N)->TYPE = (A)->next;                                 \
	} while (0)

#define BGP_ADJ_IN_ADD(N,A)    BGP_INFO_ADD(N,A,adj_in)
#define BGP_ADJ_IN_DEL(N,A)    BGP_INFO_DEL(N,A,adj_in)
#define BGP_ADJ_OUT_ADD(N,A)   BGP_INFO_ADD(N,A,adj_out)
#define BGP_ADJ_OUT_DEL(N,A)   BGP_INFO_DEL(N,A,adj_out)

#define BGP_ADV_FIFO_ADD(F, N)                                                 \
	do {                                                                   \
		FIFO_ADD((F), (N));                                            \
		(F)->count++;                                                  \
	} while (0)

#define BGP_ADV_FIFO_DEL(F, N)                                                 \
	do {                                                                   \
		FIFO_DEL((N));                                                 \
		(F)->count--;                                                  \
	} while (0)

#define BGP_ADV_FIFO_INIT(F)                                                   \
	do {                                                                   \
		FIFO_INIT((F));                                                \
		(F)->count = 0;                                                \
	} while (0)

#define BGP_ADV_FIFO_COUNT(F) (F)->count

#define BGP_ADV_FIFO_EMPTY(F)                                                  \
	(((struct bgp_advertise_fifo *)(F))->next                              \
	 == (struct bgp_advertise *)(F))

#define BGP_ADV_FIFO_HEAD(F)                                                   \
	((((struct bgp_advertise_fifo *)(F))->next                             \
	  == (struct bgp_advertise *)(F))                                      \
		 ? NULL                                                        \
		 : (F)->next)

/* Prototypes.  */
extern int bgp_adj_out_lookup(struct peer *, struct bgp_node *, uint32_t);
extern void bgp_adj_in_set(struct bgp_node *, struct peer *, struct attr *,
			   uint32_t);
extern int bgp_adj_in_unset(struct bgp_node *, struct peer *, uint32_t);
extern void bgp_adj_in_remove(struct bgp_node *, struct bgp_adj_in *);

extern void bgp_sync_init(struct peer *);
extern void bgp_sync_delete(struct peer *);
extern unsigned int baa_hash_key(void *p);
extern int baa_hash_cmp(const void *p1, const void *p2);
extern void bgp_advertise_add(struct bgp_advertise_attr *baa,
			      struct bgp_advertise *adv);
extern struct bgp_advertise *bgp_advertise_new(void);
extern void bgp_advertise_free(struct bgp_advertise *adv);
extern struct bgp_advertise_attr *bgp_advertise_intern(struct hash *hash,
						       struct attr *attr);
extern struct bgp_advertise_attr *baa_new(void);
extern void bgp_advertise_delete(struct bgp_advertise_attr *baa,
				 struct bgp_advertise *adv);
extern void bgp_advertise_unintern(struct hash *hash,
				   struct bgp_advertise_attr *baa);

#endif /* _QUAGGA_BGP_ADVERTISE_H */
