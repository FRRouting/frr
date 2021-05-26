/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
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

#ifndef _LDPD_RLFA_H_
#define _LDPD_RLFA_H_

#include "openbsd-tree.h"
#include "zclient.h"

struct ldp_rlfa_client {
	RB_ENTRY(ldp_rlfa_client) entry;

	/* IGP instance data. */
	struct zapi_rlfa_igp igp;

	/* Backpointer to RLFA node. */
	struct ldp_rlfa_node *node;
};
RB_HEAD(ldp_rlfa_client_head, ldp_rlfa_client);
RB_PROTOTYPE(ldp_rlfa_client_head, ldp_rlfa_client, entry,
	     ldp_rlfa_client_compare);

struct ldp_rlfa_node {
	RB_ENTRY(ldp_rlfa_node) entry;

	/* Destination prefix. */
	struct prefix destination;

	/* PQ node address. */
	struct in_addr pq_address;

	/* RLFA clients. */
	struct ldp_rlfa_client_head clients;

	/* Label allocated by the PQ node to the RLFA destination. */
	mpls_label_t pq_label;
};
RB_HEAD(ldp_rlfa_node_head, ldp_rlfa_node);
RB_PROTOTYPE(ldp_rlfa_node_head, ldp_rlfa_node, entry, ldp_rlfa_node_compare);

extern struct ldp_rlfa_node_head rlfa_node_tree;

/* prototypes */
struct		 ldp_rlfa_client *rlfa_client_new(struct ldp_rlfa_node *rnode,
		    struct zapi_rlfa_igp *igp);
void		 rlfa_client_del(struct ldp_rlfa_client *rclient);
struct ldp_rlfa_client *rlfa_client_find(struct ldp_rlfa_node *rnode,
		    struct zapi_rlfa_igp *igp);
struct ldp_rlfa_node *rlfa_node_new(const struct prefix *destination,
		    struct in_addr pq_address);
void rlfa_node_del(struct ldp_rlfa_node *rnode);
struct ldp_rlfa_node *rlfa_node_find(const struct prefix *destination,
		    struct in_addr pq_address);
void		 lde_rlfa_check(struct ldp_rlfa_client *rclient);
void		 lde_rlfa_client_send(struct ldp_rlfa_client *rclient);
void		 lde_rlfa_label_update(const struct fec *fec);
void		 lde_rlfa_update_clients(struct fec *fec, struct lde_nbr *ln,
		    uint32_t label);
void		 ldpe_rlfa_init(struct ldp_rlfa_client *rclient);
void		 ldpe_rlfa_exit(struct ldp_rlfa_client *rclient);

#endif /* _LDPD_RLFA_H_ */
