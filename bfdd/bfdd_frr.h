/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
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

#ifndef _BFDD_FRR_H_
#define _BFDD_FRR_H_

#include "lib/command.h"
#include "lib/prefix.h"
#include "lib/qobj.h"
#include "lib/vty.h"

#include "lib/bfdd_adapter.h"

/*
 * Data structures
 */
struct bpc_node {
	TAILQ_ENTRY(bpc_node) bn_entry;
	struct bfd_peer_cfg bn_bpc;
	QOBJ_FIELDS
};
TAILQ_HEAD(bnlist, bpc_node);
DECLARE_QOBJ_TYPE(bpc_node);

struct bfdd_config {
	/* Peer configuration list. */
	struct bnlist bc_bnlist;

	/* FRR main thread event. */
	int bc_csock;
};


/* bfdd.c */
extern struct bfdd_config bc;


/* bfdd_frr.c */
void prefix2sa(const struct prefix *p, struct sockaddr_any *sa);
int bfd_configure_peer(struct bfd_peer_cfg *bpc,
		       const struct sockaddr_any *peer,
		       const struct sockaddr_any *local, const char *ifname,
		       const char *vrfname, char *ebuf, size_t ebuflen);

int bfdd_add_peer(struct vty *vty, struct bfd_peer_cfg *bpc);
int _bfdd_update_peer(struct vty *vty, struct bfd_peer_cfg *bpc,
		      bool use_label);
int bfdd_update_peer(struct vty *vty, struct bfd_peer_cfg *bpc);
int bfdd_delete_peer(struct vty *vty, struct bfd_peer_cfg *bpc);

int bpc_set_detectmultiplier(struct bfd_peer_cfg *bpc,
			     uint8_t detectmultiplier);
int bpc_set_recvinterval(struct bfd_peer_cfg *bpc, uint64_t recvinterval);
int bpc_set_txinterval(struct bfd_peer_cfg *bpc, uint64_t txinterval);

struct bpc_node *bn_find(struct bnlist *bnlist, struct bfd_peer_cfg *bpc);
struct bpc_node *bn_new(struct bnlist *bnlist, struct bfd_peer_cfg *bpc);
void bn_free(struct bpc_node *bn, struct bnlist *bnlist);


/* bfdctl.c */
int bfdd_receive_notification(struct bfd_control_msg *bcm, bool *repeat,
			      void *arg);
int bfdd_receive_id(struct bfd_control_msg *bcm, bool *repeat, void *arg);


/* bfdd_vty.c */
void bfdd_vty_init(void);

#endif /* _BFDD_FRR_H_ */
