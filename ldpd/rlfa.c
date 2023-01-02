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

#include <zebra.h>

#include "ldpd.h"
#include "lde.h"
#include "ldpe.h"
#include "log.h"
#include "ldp_debug.h"
#include "rlfa.h"

#include <lib/log.h>

struct ldp_rlfa_node_head rlfa_node_tree;

static int ldp_rlfa_client_compare(const struct ldp_rlfa_client *a,
				   const struct ldp_rlfa_client *b)
{
	if (a->igp.vrf_id < b->igp.vrf_id)
		return -1;
	if (a->igp.vrf_id > b->igp.vrf_id)
		return 1;

	if (a->igp.protocol < b->igp.protocol)
		return -1;
	if (a->igp.protocol > b->igp.protocol)
		return 1;

	if (a->igp.isis.spf.tree_id < b->igp.isis.spf.tree_id)
		return -1;
	if (a->igp.isis.spf.tree_id > b->igp.isis.spf.tree_id)
		return 1;

	if (a->igp.isis.spf.level < b->igp.isis.spf.level)
		return -1;
	if (a->igp.isis.spf.level > b->igp.isis.spf.level)
		return 1;

	return 0;
}
RB_GENERATE(ldp_rlfa_client_head, ldp_rlfa_client, entry,
	    ldp_rlfa_client_compare)

static int ldp_rlfa_node_compare(const struct ldp_rlfa_node *a,
				 const struct ldp_rlfa_node *b)
{
	if (ntohl(a->pq_address.s_addr) < ntohl(b->pq_address.s_addr))
		return -1;
	if (ntohl(a->pq_address.s_addr) > ntohl(b->pq_address.s_addr))
		return 1;

	return prefix_cmp(&a->destination, &b->destination);
}
RB_GENERATE(ldp_rlfa_node_head, ldp_rlfa_node, entry, ldp_rlfa_node_compare)

struct ldp_rlfa_client *rlfa_client_new(struct ldp_rlfa_node *rnode,
					struct zapi_rlfa_igp *igp)
{
	struct ldp_rlfa_client *rclient;

	if ((rclient = calloc(1, sizeof(*rclient))) == NULL)
		fatal(__func__);

	rclient->igp = *igp;
	rclient->node = rnode;
	RB_INSERT(ldp_rlfa_client_head, &rnode->clients, rclient);

	return rclient;
}

void rlfa_client_del(struct ldp_rlfa_client *rclient)
{
	struct ldp_rlfa_node *rnode = rclient->node;

	RB_REMOVE(ldp_rlfa_client_head, &rnode->clients, rclient);
	free(rclient);

	/* Delete RLFA node if it's empty. */
	if (RB_EMPTY(ldp_rlfa_client_head, &rnode->clients))
		rlfa_node_del(rnode);
}

struct ldp_rlfa_client *rlfa_client_find(struct ldp_rlfa_node *rnode,
					 struct zapi_rlfa_igp *igp)
{
	struct ldp_rlfa_client rclient;

	rclient.igp = *igp;
	return RB_FIND(ldp_rlfa_client_head, &rnode->clients, &rclient);
}

struct ldp_rlfa_node *rlfa_node_new(const struct prefix *destination,
				    struct in_addr pq_address)
{
	struct ldp_rlfa_node *rnode;

	if ((rnode = calloc(1, sizeof(*rnode))) == NULL)
		fatal(__func__);

	rnode->destination = *destination;
	rnode->pq_address = pq_address;
	rnode->pq_label = MPLS_INVALID_LABEL;
	RB_INIT(ldp_rlfa_client_head, &rnode->clients);
	RB_INSERT(ldp_rlfa_node_head, &rlfa_node_tree, rnode);

	return rnode;
}

void rlfa_node_del(struct ldp_rlfa_node *rnode)
{
	/* Delete RLFA clients. */
	while (!RB_EMPTY(ldp_rlfa_client_head, &rnode->clients)) {
		struct ldp_rlfa_client *rclient;

		rclient = RB_ROOT(ldp_rlfa_client_head, &rnode->clients);
		rlfa_client_del(rclient);
	}

	RB_REMOVE(ldp_rlfa_node_head, &rlfa_node_tree, rnode);
	free(rnode);
}

struct ldp_rlfa_node *rlfa_node_find(const struct prefix *destination,
				     struct in_addr pq_address)
{
	struct ldp_rlfa_node rnode = {};

	rnode.destination = *destination;
	rnode.pq_address = pq_address;
	return RB_FIND(ldp_rlfa_node_head, &rlfa_node_tree, &rnode);
}

void lde_rlfa_client_send(struct ldp_rlfa_client *rclient)
{
	struct ldp_rlfa_node		*rnode = rclient->node;
	struct zapi_rlfa_response	 rlfa_labels = {};
	struct fec			 fec;
	struct fec_node			*fn;
	struct fec_nh			*fnh;
	int				 i = 0;

	/* Fill in inner label (allocated by PQ node). */
	rlfa_labels.igp = rclient->igp;
	rlfa_labels.destination = rnode->destination;
	rlfa_labels.pq_label = rnode->pq_label;

	/* Fill in outer label(s) (allocated by the nexthop routers). */
	fec.type = FEC_TYPE_IPV4;
	fec.u.ipv4.prefix = rnode->pq_address;
	fec.u.ipv4.prefixlen = IPV4_MAX_BITLEN;
	fn = (struct fec_node *)fec_find(&ft, &fec);
	if (!fn)
		return;
	LIST_FOREACH(fnh, &fn->nexthops, entry) {
		if (fnh->remote_label == NO_LABEL)
			continue;

		rlfa_labels.nexthops[i].family = fnh->af;
		switch (fnh->af) {
		case AF_INET:
			rlfa_labels.nexthops[i].gate.ipv4 = fnh->nexthop.v4;
			break;
		case AF_INET6:
			rlfa_labels.nexthops[i].gate.ipv6 = fnh->nexthop.v6;
			break;
		default:
			continue;
		}
		rlfa_labels.nexthops[i].label = fnh->remote_label;
		i++;
	}
	rlfa_labels.nexthop_num = i;

	lde_imsg_compose_parent(IMSG_RLFA_LABELS, 0, &rlfa_labels,
				sizeof(rlfa_labels));
}

void lde_rlfa_label_update(const struct fec *fec)
{
	struct ldp_rlfa_node *rnode;

	if (fec->type != FEC_TYPE_IPV4
	    || fec->u.ipv4.prefixlen != IPV4_MAX_BITLEN)
		return;

	/*
	 * TODO: use an rb-tree lookup to restrict the iteration to the RLFAs
	 * that were effectivelly affected by the label update.
	 */
	RB_FOREACH (rnode, ldp_rlfa_node_head, &rlfa_node_tree) {
		struct ldp_rlfa_client *rclient;

		if (!IPV4_ADDR_SAME(&rnode->pq_address, &fec->u.ipv4.prefix))
			continue;

		RB_FOREACH (rclient, ldp_rlfa_client_head, &rnode->clients)
			lde_rlfa_client_send(rclient);
	}
}

void lde_rlfa_check(struct ldp_rlfa_client *rclient)
{
	struct lde_nbr *ln;
	struct lde_map *me;
	struct fec fec;
	union ldpd_addr pq_address = {};

	pq_address.v4 = rclient->node->pq_address;
	ln = lde_nbr_find_by_addr(AF_INET, &pq_address);
	if (!ln)
		return;

	lde_prefix2fec(&rclient->node->destination, &fec);
	me = (struct lde_map *)fec_find(&ln->recv_map, &fec);
	if (!me)
		return;

	rclient->node->pq_label = me->map.label;
	lde_rlfa_client_send(rclient);
}

/*
 * Check if there's any registered RLFA client for this prefix/neighbor (PQ
 * node) and notify about the updated label.
 */
void lde_rlfa_update_clients(struct fec *fec, struct lde_nbr *ln,
			     uint32_t label)
{
	struct prefix		 rlfa_dest;
	struct ldp_rlfa_node	*rnode;

	lde_fec2prefix(fec, &rlfa_dest);
	rnode = rlfa_node_find(&rlfa_dest, ln->id);
	if (rnode) {
		struct ldp_rlfa_client *rclient;

		rnode->pq_label = label;
		RB_FOREACH (rclient, ldp_rlfa_client_head, &rnode->clients)
			lde_rlfa_client_send(rclient);
	} else
		lde_rlfa_label_update(fec);
}

void ldpe_rlfa_init(struct ldp_rlfa_client *rclient)
{
	struct tnbr *tnbr;
	union ldpd_addr pq_address = {};

	pq_address.v4 = rclient->node->pq_address;
	tnbr = tnbr_find(leconf, AF_INET, &pq_address);
	if (tnbr == NULL) {
		tnbr = tnbr_new(AF_INET, &pq_address);
		tnbr_update(tnbr);
		RB_INSERT(tnbr_head, &leconf->tnbr_tree, tnbr);
	}

	tnbr->rlfa_count++;
}

void ldpe_rlfa_exit(struct ldp_rlfa_client *rclient)
{
	struct tnbr *tnbr;
	union ldpd_addr pq_address = {};

	pq_address.v4 = rclient->node->pq_address;
	tnbr = tnbr_find(leconf, AF_INET, &pq_address);
	if (tnbr) {
		tnbr->rlfa_count--;
		tnbr_check(leconf, tnbr);
	}
}
