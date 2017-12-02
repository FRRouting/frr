/* Zebra MPLS code
 * Copyright (C) 2013 Cumulus Networks, Inc.
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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"
#include "lib/json.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"

DEFINE_MTYPE_STATIC(ZEBRA, LSP, "MPLS LSP object")
DEFINE_MTYPE_STATIC(ZEBRA, FEC, "MPLS FEC object")
DEFINE_MTYPE_STATIC(ZEBRA, SLSP, "MPLS static LSP config")
DEFINE_MTYPE_STATIC(ZEBRA, NHLFE, "MPLS nexthop object")
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE, "MPLS static nexthop object")
DEFINE_MTYPE_STATIC(ZEBRA, SNHLFE_IFNAME, "MPLS static nexthop ifname")

int mpls_enabled;

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* static function declarations */

static void fec_evaluate(struct zebra_vrf *zvrf);
static u_int32_t fec_derive_label_from_index(struct zebra_vrf *vrf,
					     zebra_fec_t *fec);
static int lsp_install(struct zebra_vrf *zvrf, mpls_label_t label,
		       struct route_node *rn, struct route_entry *re);
static int lsp_uninstall(struct zebra_vrf *zvrf, mpls_label_t label);
static int fec_change_update_lsp(struct zebra_vrf *zvrf, zebra_fec_t *fec,
				 mpls_label_t old_label);
static int fec_send(zebra_fec_t *fec, struct zserv *client);
static void fec_update_clients(zebra_fec_t *fec);
static void fec_print(zebra_fec_t *fec, struct vty *vty);
static zebra_fec_t *fec_find(struct route_table *table, struct prefix *p);
static zebra_fec_t *fec_add(struct route_table *table, struct prefix *p,
			    mpls_label_t label, u_int32_t flags,
			    u_int32_t label_index);
static int fec_del(zebra_fec_t *fec);

static unsigned int label_hash(void *p);
static int label_cmp(const void *p1, const void *p2);
static int nhlfe_nexthop_active_ipv4(zebra_nhlfe_t *nhlfe,
				     struct nexthop *nexthop);
static int nhlfe_nexthop_active_ipv6(zebra_nhlfe_t *nhlfe,
				     struct nexthop *nexthop);
static int nhlfe_nexthop_active(zebra_nhlfe_t *nhlfe);

static void lsp_select_best_nhlfe(zebra_lsp_t *lsp);
static void lsp_uninstall_from_kernel(struct hash_backet *backet, void *ctxt);
static void lsp_schedule(struct hash_backet *backet, void *ctxt);
static wq_item_status lsp_process(struct work_queue *wq, void *data);
static void lsp_processq_del(struct work_queue *wq, void *data);
static void lsp_processq_complete(struct work_queue *wq);
static int lsp_processq_add(zebra_lsp_t *lsp);
static void *lsp_alloc(void *p);

static char *nhlfe2str(zebra_nhlfe_t *nhlfe, char *buf, int size);
static int nhlfe_nhop_match(zebra_nhlfe_t *nhlfe, enum nexthop_types_t gtype,
			    union g_addr *gate, ifindex_t ifindex);
static zebra_nhlfe_t *nhlfe_find(zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
				 enum nexthop_types_t gtype, union g_addr *gate,
				 ifindex_t ifindex);
static zebra_nhlfe_t *nhlfe_add(zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
				enum nexthop_types_t gtype, union g_addr *gate,
				ifindex_t ifindex, mpls_label_t out_label);
static int nhlfe_del(zebra_nhlfe_t *snhlfe);
static void nhlfe_out_label_update(zebra_nhlfe_t *nhlfe,
				   struct mpls_label_stack *nh_label);
static int mpls_lsp_uninstall_all(struct hash *lsp_table, zebra_lsp_t *lsp,
				  enum lsp_types_t type);
static int mpls_static_lsp_uninstall_all(struct zebra_vrf *zvrf,
					 mpls_label_t in_label);
static void nhlfe_print(zebra_nhlfe_t *nhlfe, struct vty *vty);
static void lsp_print(zebra_lsp_t *lsp, void *ctxt);
static void *slsp_alloc(void *p);
static int snhlfe_match(zebra_snhlfe_t *snhlfe, enum nexthop_types_t gtype,
			union g_addr *gate, ifindex_t ifindex);
static zebra_snhlfe_t *snhlfe_find(zebra_slsp_t *slsp,
				   enum nexthop_types_t gtype,
				   union g_addr *gate, ifindex_t ifindex);
static zebra_snhlfe_t *snhlfe_add(zebra_slsp_t *slsp,
				  enum nexthop_types_t gtype,
				  union g_addr *gate, ifindex_t ifindex,
				  mpls_label_t out_label);
static int snhlfe_del(zebra_snhlfe_t *snhlfe);
static int snhlfe_del_all(zebra_slsp_t *slsp);
static char *snhlfe2str(zebra_snhlfe_t *snhlfe, char *buf, int size);
static int mpls_processq_init(struct zebra_t *zebra);


/* Static functions */

/*
 * Handle failure in LSP install, clear flags for NHLFE.
 */
static void clear_nhlfe_installed(zebra_lsp_t *lsp)
{
	zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop;

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
	}
}

/*
 * Install label forwarding entry based on labeled-route entry.
 */
static int lsp_install(struct zebra_vrf *zvrf, mpls_label_t label,
		       struct route_node *rn, struct route_entry *re)
{
	struct hash *lsp_table;
	zebra_ile_t tmp_ile;
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop;
	enum lsp_types_t lsp_type;
	char buf[BUFSIZ];
	int added, changed;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	lsp_type = lsp_type_from_re_type(re->type);
	added = changed = 0;

	/* Locate or allocate LSP entry. */
	tmp_ile.in_label = label;
	lsp = hash_get(lsp_table, &tmp_ile, lsp_alloc);
	if (!lsp)
		return -1;

	/* For each active nexthop, create NHLFE. Note that we deliberately skip
	 * recursive nexthops right now, because intermediate hops won't
	 * understand
	 * the label advertised by the recursive nexthop (plus we don't have the
	 * logic yet to push multiple labels).
	 */
	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
		/* Skip inactive and recursive entries. */
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		nhlfe = nhlfe_find(lsp, lsp_type, nexthop->type, &nexthop->gate,
				   nexthop->ifindex);
		if (nhlfe) {
			/* Clear deleted flag (in case it was set) */
			UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
			if (nexthop_labels_match(nhlfe->nexthop, nexthop))
				/* No change */
				continue;


			if (IS_ZEBRA_DEBUG_MPLS) {
				nhlfe2str(nhlfe, buf, BUFSIZ);
				zlog_debug(
					"LSP in-label %u type %d nexthop %s "
					"out-label changed",
					lsp->ile.in_label, lsp_type, buf);
			}

			/* Update out label, trigger processing. */
			nhlfe_out_label_update(nhlfe, nexthop->nh_label);
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			changed++;
		} else {
			/* Add LSP entry to this nexthop */
			nhlfe = nhlfe_add(lsp, lsp_type, nexthop->type,
					  &nexthop->gate, nexthop->ifindex,
					  nexthop->nh_label->label[0]);
			if (!nhlfe)
				return -1;

			if (IS_ZEBRA_DEBUG_MPLS) {
				nhlfe2str(nhlfe, buf, BUFSIZ);
				zlog_debug(
					"Add LSP in-label %u type %d nexthop %s "
					"out-label %u",
					lsp->ile.in_label, lsp_type, buf,
					nexthop->nh_label->label[0]);
			}

			lsp->addr_family = NHLFE_FAMILY(nhlfe);

			/* Mark NHLFE as changed. */
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			added++;
		}
	}

	/* Queue LSP for processing if necessary. If no NHLFE got added (special
	 * case), delete the LSP entry; this case results in somewhat ugly
	 * logging.
	 */
	if (added || changed) {
		if (lsp_processq_add(lsp))
			return -1;
	} else if (!lsp->nhlfe_list
		   && !CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Free LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);

		lsp = hash_release(lsp_table, &lsp->ile);
		if (lsp)
			XFREE(MTYPE_LSP, lsp);
	}

	return 0;
}

/*
 * Uninstall all non-static NHLFEs of a label forwarding entry. If all
 * NHLFEs are removed, the entire entry is deleted.
 */
static int lsp_uninstall(struct zebra_vrf *zvrf, mpls_label_t label)
{
	struct hash *lsp_table;
	zebra_ile_t tmp_ile;
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *nhlfe, *nhlfe_next;
	char buf[BUFSIZ];

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp || !lsp->nhlfe_list)
		return 0;

	/* Mark NHLFEs for delete or directly delete, as appropriate. */
	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe_next) {
		nhlfe_next = nhlfe->next;

		/* Skip static NHLFEs */
		if (nhlfe->type == ZEBRA_LSP_STATIC)
			continue;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, BUFSIZ);
			zlog_debug(
				"Del LSP in-label %u type %d nexthop %s flags 0x%x",
				label, nhlfe->type, buf, nhlfe->flags);
		}

		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)) {
			UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
		} else {
			nhlfe_del(nhlfe);
		}
	}

	/* Queue LSP for processing, if needed, else delete. */
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED)) {
		if (lsp_processq_add(lsp))
			return -1;
	} else if (!lsp->nhlfe_list
		   && !CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Del LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);

		lsp = hash_release(lsp_table, &lsp->ile);
		if (lsp)
			XFREE(MTYPE_LSP, lsp);
	}

	return 0;
}

/*
 * This function is invoked upon change to label block configuration; it
 * will walk all registered FECs with label-index and appropriately update
 * their local labels and trigger client updates.
 */
static void fec_evaluate(struct zebra_vrf *zvrf)
{
	struct route_node *rn;
	zebra_fec_t *fec;
	u_int32_t old_label, new_label;
	int af;
	char buf[BUFSIZ];

	for (af = AFI_IP; af < AFI_MAX; af++) {
		if (zvrf->fec_table[af] == NULL)
			continue;

		for (rn = route_top(zvrf->fec_table[af]); rn;
		     rn = route_next(rn)) {
			if ((fec = rn->info) == NULL)
				continue;

			/* Skip configured FECs and those without a label index.
			 */
			if (fec->flags & FEC_FLAG_CONFIGURED
			    || fec->label_index == MPLS_INVALID_LABEL_INDEX)
				continue;

			if (IS_ZEBRA_DEBUG_MPLS)
				prefix2str(&rn->p, buf, BUFSIZ);

			/* Save old label, determine new label. */
			old_label = fec->label;
			new_label =
				zvrf->mpls_srgb.start_label + fec->label_index;
			if (new_label >= zvrf->mpls_srgb.end_label)
				new_label = MPLS_INVALID_LABEL;

			/* If label has changed, update FEC and clients. */
			if (new_label == old_label)
				continue;

			if (IS_ZEBRA_DEBUG_MPLS)
				zlog_debug(
					"Update fec %s new label %u upon label block",
					buf, new_label);

			fec->label = new_label;
			fec_update_clients(fec);

			/* Update label forwarding entries appropriately */
			fec_change_update_lsp(zvrf, fec, old_label);
		}
	}
}

/*
 * Derive (if possible) and update the local label for the FEC based on
 * its label index. The index is "acceptable" if it falls within the
 * globally configured label block (SRGB).
 */
static u_int32_t fec_derive_label_from_index(struct zebra_vrf *zvrf,
					     zebra_fec_t *fec)
{
	u_int32_t label;

	if (fec->label_index != MPLS_INVALID_LABEL_INDEX
	    && zvrf->mpls_srgb.start_label
	    && ((label = zvrf->mpls_srgb.start_label + fec->label_index)
		< zvrf->mpls_srgb.end_label))
		fec->label = label;
	else
		fec->label = MPLS_INVALID_LABEL;

	return fec->label;
}

/*
 * There is a change for this FEC. Install or uninstall label forwarding
 * entries, as appropriate.
 */
static int fec_change_update_lsp(struct zebra_vrf *zvrf, zebra_fec_t *fec,
				 mpls_label_t old_label)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	afi_t afi;

	/* Uninstall label forwarding entry, if previously installed. */
	if (old_label != MPLS_INVALID_LABEL && old_label != MPLS_IMP_NULL_LABEL)
		lsp_uninstall(zvrf, old_label);

	/* Install label forwarding entry corr. to new label, if needed. */
	if (fec->label == MPLS_INVALID_LABEL
	    || fec->label == MPLS_IMP_NULL_LABEL)
		return 0;

	afi = family2afi(PREFIX_FAMILY(&fec->rn->p));
	table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(zvrf));
	if (!table)
		return 0;

	/* See if labeled route exists. */
	rn = route_node_lookup(table, &fec->rn->p);
	if (!rn)
		return 0;

	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
			break;
	}

	if (!re || !zebra_rib_labeled_unicast(re))
		return 0;

	if (lsp_install(zvrf, fec->label, rn, re))
		return -1;

	return 0;
}

/*
 * Inform about FEC to a registered client.
 */
static int fec_send(zebra_fec_t *fec, struct zserv *client)
{
	struct stream *s;
	struct route_node *rn;

	rn = fec->rn;

	/* Get output stream. */
	s = client->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_FEC_UPDATE, VRF_DEFAULT);

	stream_putw(s, rn->p.family);
	stream_put_prefix(s, &rn->p);
	stream_putl(s, fec->label);
	stream_putw_at(s, 0, stream_get_endp(s));
	return zebra_server_send_message(client);
}

/*
 * Update all registered clients about this FEC. Caller should've updated
 * FEC and ensure no duplicate updates.
 */
static void fec_update_clients(zebra_fec_t *fec)
{
	struct listnode *node;
	struct zserv *client;

	for (ALL_LIST_ELEMENTS_RO(fec->client_list, node, client)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Update client %s",
				   zebra_route_string(client->proto));
		fec_send(fec, client);
	}
}


/*
 * Print a FEC-label binding entry.
 */
static void fec_print(zebra_fec_t *fec, struct vty *vty)
{
	struct route_node *rn;
	struct listnode *node;
	struct zserv *client;
	char buf[BUFSIZ];

	rn = fec->rn;
	prefix2str(&rn->p, buf, BUFSIZ);
	vty_out(vty, "%s\n", buf);
	vty_out(vty, "  Label: %s", label2str(fec->label, buf, BUFSIZ));
	if (fec->label_index != MPLS_INVALID_LABEL_INDEX)
		vty_out(vty, ", Label Index: %u", fec->label_index);
	vty_out(vty, "\n");
	if (!list_isempty(fec->client_list)) {
		vty_out(vty, "  Client list:");
		for (ALL_LIST_ELEMENTS_RO(fec->client_list, node, client))
			vty_out(vty, " %s(fd %d)",
				zebra_route_string(client->proto),
				client->sock);
		vty_out(vty, "\n");
	}
}

/*
 * Locate FEC-label binding that matches with passed info.
 */
static zebra_fec_t *fec_find(struct route_table *table, struct prefix *p)
{
	struct route_node *rn;

	apply_mask(p);
	rn = route_node_lookup(table, p);
	if (!rn)
		return NULL;

	route_unlock_node(rn);
	return (rn->info);
}

/*
 * Add a FEC. This may be upon a client registering for a binding
 * or when a binding is configured.
 */
static zebra_fec_t *fec_add(struct route_table *table, struct prefix *p,
			    mpls_label_t label, u_int32_t flags,
			    u_int32_t label_index)
{
	struct route_node *rn;
	zebra_fec_t *fec;

	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(table, p);
	if (!rn)
		return NULL;

	fec = rn->info;

	if (!fec) {
		fec = XCALLOC(MTYPE_FEC, sizeof(zebra_fec_t));
		if (!fec)
			return NULL;

		rn->info = fec;
		fec->rn = rn;
		fec->label = label;
		fec->client_list = list_new();
	} else
		route_unlock_node(rn); /* for the route_node_get */

	fec->label_index = label_index;
	fec->flags = flags;

	return fec;
}

/*
 * Delete a FEC. This may be upon the last client deregistering for
 * a FEC and no binding exists or when the binding is deleted and there
 * are no registered clients.
 */
static int fec_del(zebra_fec_t *fec)
{
	list_delete_and_null(&fec->client_list);
	fec->rn->info = NULL;
	route_unlock_node(fec->rn);
	XFREE(MTYPE_FEC, fec);
	return 0;
}

/*
 * Hash function for label.
 */
static unsigned int label_hash(void *p)
{
	const zebra_ile_t *ile = p;

	return (jhash_1word(ile->in_label, 0));
}

/*
 * Compare 2 LSP hash entries based on in-label.
 */
static int label_cmp(const void *p1, const void *p2)
{
	const zebra_ile_t *ile1 = p1;
	const zebra_ile_t *ile2 = p2;

	return (ile1->in_label == ile2->in_label);
}

/*
 * Check if an IPv4 nexthop for a NHLFE is active. Update nexthop based on
 * the passed flag.
 * NOTE: Looking only for connected routes right now.
 */
static int nhlfe_nexthop_active_ipv4(zebra_nhlfe_t *nhlfe,
				     struct nexthop *nexthop)
{
	struct route_table *table;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct route_entry *match;
	struct nexthop *match_nh;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return 0;

	/* Lookup nexthop in IPv4 routing table. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_PREFIXLEN;
	p.prefix = nexthop->gate.ipv4;

	rn = route_node_match(table, (struct prefix *)&p);
	if (!rn)
		return 0;

	route_unlock_node(rn);

	/* Locate a valid connected route. */
	RNODE_FOREACH_RE (rn, match) {
		if (CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED)
		    || !CHECK_FLAG(match->flags, ZEBRA_FLAG_SELECTED))
			continue;

		for (match_nh = match->nexthop; match_nh;
		     match_nh = match_nh->next) {
			if (match->type == ZEBRA_ROUTE_CONNECT
			    || nexthop->ifindex == match_nh->ifindex) {
				nexthop->ifindex = match_nh->ifindex;
				return 1;
			}
		}
	}

	return 0;
}


/*
 * Check if an IPv6 nexthop for a NHLFE is active. Update nexthop based on
 * the passed flag.
 * NOTE: Looking only for connected routes right now.
 */
static int nhlfe_nexthop_active_ipv6(zebra_nhlfe_t *nhlfe,
				     struct nexthop *nexthop)
{
	struct route_table *table;
	struct prefix_ipv6 p;
	struct route_node *rn;
	struct route_entry *match;

	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return 0;

	/* Lookup nexthop in IPv6 routing table. */
	memset(&p, 0, sizeof(struct prefix_ipv6));
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_PREFIXLEN;
	p.prefix = nexthop->gate.ipv6;

	rn = route_node_match(table, (struct prefix *)&p);
	if (!rn)
		return 0;

	route_unlock_node(rn);

	/* Locate a valid connected route. */
	RNODE_FOREACH_RE (rn, match) {
		if ((match->type == ZEBRA_ROUTE_CONNECT)
		    && !CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED)
		    && CHECK_FLAG(match->flags, ZEBRA_FLAG_SELECTED))
			break;
	}

	if (!match || !match->nexthop)
		return 0;

	nexthop->ifindex = match->nexthop->ifindex;
	return 1;
}


/*
 * Check the nexthop reachability for a NHLFE and return if valid (reachable)
 * or not.
 * NOTE: Each NHLFE points to only 1 nexthop.
 */
static int nhlfe_nexthop_active(zebra_nhlfe_t *nhlfe)
{
	struct nexthop *nexthop;
	struct interface *ifp;

	nexthop = nhlfe->nexthop;
	if (!nexthop) // unexpected
		return 0;

	/* Check on nexthop based on type. */
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (nhlfe_nexthop_active_ipv4(nhlfe, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;

	case NEXTHOP_TYPE_IPV6:
		if (nhlfe_nexthop_active_ipv6(nhlfe, nexthop))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;

	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (IN6_IS_ADDR_LINKLOCAL(&nexthop->gate.ipv6)) {
			ifp = if_lookup_by_index(nexthop->ifindex, VRF_DEFAULT);
			if (ifp && if_is_operative(ifp))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		} else {
			if (nhlfe_nexthop_active_ipv6(nhlfe, nexthop))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		}
		break;

	default:
		break;
	}

	return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/*
 * Walk through NHLFEs for a LSP forwarding entry, verify nexthop
 * reachability and select the best. Multipath entries are also
 * marked. This is invoked when an LSP scheduled for processing (due
 * to some change) is examined.
 */
static void lsp_select_best_nhlfe(zebra_lsp_t *lsp)
{
	zebra_nhlfe_t *nhlfe;
	zebra_nhlfe_t *best;
	struct nexthop *nexthop;
	int changed = 0;

	if (!lsp)
		return;

	best = NULL;
	lsp->num_ecmp = 0;
	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);

	/*
	 * First compute the best path, after checking nexthop status. We are
	 * only
	 * concerned with non-deleted NHLFEs.
	 */
	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		/* Clear selection flags. */
		UNSET_FLAG(nhlfe->flags,
			   (NHLFE_FLAG_SELECTED | NHLFE_FLAG_MULTIPATH));

		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED)
		    && nhlfe_nexthop_active(nhlfe)) {
			if (!best || (nhlfe->distance < best->distance))
				best = nhlfe;
		}
	}

	lsp->best_nhlfe = best;
	if (!lsp->best_nhlfe)
		return;

	/* Mark best NHLFE as selected. */
	SET_FLAG(lsp->best_nhlfe->flags, NHLFE_FLAG_SELECTED);

	/*
	 * If best path exists, see if there is ECMP. While doing this, note if
	 * a
	 * new (uninstalled) NHLFE has been selected, an installed entry that is
	 * still selected has a change or an installed entry is to be removed.
	 */
	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		int nh_chg, nh_sel, nh_inst;

		nexthop = nhlfe->nexthop;
		if (!nexthop) // unexpected
			continue;

		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED)
		    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)
		    && (nhlfe->distance == lsp->best_nhlfe->distance)) {
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED);
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_MULTIPATH);
			lsp->num_ecmp++;
		}

		if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED) && !changed) {
			nh_chg = CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			nh_sel = CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED);
			nh_inst =
				CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);

			if ((nh_sel && !nh_inst)
			    || (nh_sel && nh_inst && nh_chg)
			    || (nh_inst && !nh_sel))
				changed = 1;
		}

		/* We have finished examining, clear changed flag. */
		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
	}

	if (changed)
		SET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
}

/*
 * Delete LSP forwarding entry from kernel, if installed. Called upon
 * process exit.
 */
static void lsp_uninstall_from_kernel(struct hash_backet *backet, void *ctxt)
{
	zebra_lsp_t *lsp;

	lsp = (zebra_lsp_t *)backet->data;
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		kernel_del_lsp(lsp);
}

/*
 * Schedule LSP forwarding entry for processing. Called upon changes
 * that may impact LSPs such as nexthop / connected route changes.
 */
static void lsp_schedule(struct hash_backet *backet, void *ctxt)
{
	zebra_lsp_t *lsp;

	lsp = (zebra_lsp_t *)backet->data;
	(void)lsp_processq_add(lsp);
}

/*
 * Process a LSP entry that is in the queue. Recalculate best NHLFE and
 * any multipaths and update or delete from the kernel, as needed.
 */
static wq_item_status lsp_process(struct work_queue *wq, void *data)
{
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *oldbest, *newbest;
	char buf[BUFSIZ], buf2[BUFSIZ];
	struct zebra_vrf *zvrf = vrf_info_lookup(VRF_DEFAULT);

	lsp = (zebra_lsp_t *)data;
	if (!lsp) // unexpected
		return WQ_SUCCESS;

	oldbest = lsp->best_nhlfe;

	/* Select best NHLFE(s) */
	lsp_select_best_nhlfe(lsp);

	newbest = lsp->best_nhlfe;

	if (IS_ZEBRA_DEBUG_MPLS) {
		if (oldbest)
			nhlfe2str(oldbest, buf, BUFSIZ);
		if (newbest)
			nhlfe2str(newbest, buf2, BUFSIZ);
		zlog_debug(
			"Process LSP in-label %u oldbest %s newbest %s "
			"flags 0x%x ecmp# %d",
			lsp->ile.in_label, oldbest ? buf : "NULL",
			newbest ? buf2 : "NULL", lsp->flags, lsp->num_ecmp);
	}

	if (!CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED)) {
		/* Not already installed */
		if (newbest) {

			UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
			kernel_add_lsp(lsp);

			zvrf->lsp_installs++;
		}
	} else {
		/* Installed, may need an update and/or delete. */
		if (!newbest) {

			kernel_del_lsp(lsp);

			zvrf->lsp_removals++;
		} else if (CHECK_FLAG(lsp->flags, LSP_FLAG_CHANGED)) {
			zebra_nhlfe_t *nhlfe;
			struct nexthop *nexthop;

			UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
			UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

			/*
			 * Any NHLFE that was installed but is not
			 * selected now needs to have its flags updated.
			 */
			for (nhlfe = lsp->nhlfe_list;
			     nhlfe; nhlfe = nhlfe->next) {
				nexthop = nhlfe->nexthop;
				if (!nexthop)
					continue;

				if (CHECK_FLAG(nhlfe->flags,
					       NHLFE_FLAG_INSTALLED) &&
				    !CHECK_FLAG(nhlfe->flags,
						NHLFE_FLAG_SELECTED)) {
					UNSET_FLAG(nhlfe->flags,
						   NHLFE_FLAG_INSTALLED);
					UNSET_FLAG(nexthop->flags,
						   NEXTHOP_FLAG_FIB);
				}
			}

			kernel_upd_lsp(lsp);

			zvrf->lsp_installs++;
		}
	}

	return WQ_SUCCESS;
}


/*
 * Callback upon processing completion of a LSP forwarding entry.
 */
static void lsp_processq_del(struct work_queue *wq, void *data)
{
	struct zebra_vrf *zvrf;
	zebra_lsp_t *lsp;
	struct hash *lsp_table;
	zebra_nhlfe_t *nhlfe, *nhlfe_next;

	zvrf = vrf_info_lookup(VRF_DEFAULT);
	assert(zvrf);

	lsp_table = zvrf->lsp_table;
	if (!lsp_table) // unexpected
		return;

	lsp = (zebra_lsp_t *)data;
	if (!lsp) // unexpected
		return;

	/* Clear flag, remove any NHLFEs marked for deletion. If no NHLFEs
	 * exist,
	 * delete LSP entry also.
	 */
	UNSET_FLAG(lsp->flags, LSP_FLAG_SCHEDULED);

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe_next) {
		nhlfe_next = nhlfe->next;
		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			nhlfe_del(nhlfe);
	}

	if (!lsp->nhlfe_list) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Free LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);

		lsp = hash_release(lsp_table, &lsp->ile);
		if (lsp)
			XFREE(MTYPE_LSP, lsp);
	}
}

/*
 * Callback upon finishing the processing of all scheduled
 * LSP forwarding entries.
 */
static void lsp_processq_complete(struct work_queue *wq)
{
	/* Nothing to do for now. */
}

/*
 * Add LSP forwarding entry to queue for subsequent processing.
 */
static int lsp_processq_add(zebra_lsp_t *lsp)
{
	/* If already scheduled, exit. */
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED))
		return 0;

	if (zebrad.lsp_process_q == NULL) {
		zlog_err("%s: work_queue does not exist!", __func__);
		return -1;
	}

	work_queue_add(zebrad.lsp_process_q, lsp);
	SET_FLAG(lsp->flags, LSP_FLAG_SCHEDULED);
	return 0;
}

/*
 * Callback to allocate LSP forwarding table entry.
 */
static void *lsp_alloc(void *p)
{
	const zebra_ile_t *ile = p;
	zebra_lsp_t *lsp;

	lsp = XCALLOC(MTYPE_LSP, sizeof(zebra_lsp_t));
	lsp->ile = *ile;

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("Alloc LSP in-label %u", lsp->ile.in_label);

	return ((void *)lsp);
}

/*
 * Create printable string for NHLFE entry.
 */
static char *nhlfe2str(zebra_nhlfe_t *nhlfe, char *buf, int size)
{
	struct nexthop *nexthop;

	buf[0] = '\0';
	nexthop = nhlfe->nexthop;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &nexthop->gate.ipv4, buf, size);
		break;
	case NEXTHOP_TYPE_IPV6:
		inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, size);
		break;
	default:
		break;
	}

	return buf;
}

/*
 * Check if NHLFE matches with search info passed.
 */
static int nhlfe_nhop_match(zebra_nhlfe_t *nhlfe, enum nexthop_types_t gtype,
			    union g_addr *gate, ifindex_t ifindex)
{
	struct nexthop *nhop;
	int cmp = 1;

	nhop = nhlfe->nexthop;
	if (!nhop)
		return 1;

	if (nhop->type != gtype)
		return 1;

	switch (nhop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		cmp = memcmp(&(nhop->gate.ipv4), &(gate->ipv4),
			     sizeof(struct in_addr));
		if (!cmp && nhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
			cmp = !(nhop->ifindex == ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		cmp = memcmp(&(nhop->gate.ipv6), &(gate->ipv6),
			     sizeof(struct in6_addr));
		if (!cmp && nhop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
			cmp = !(nhop->ifindex == ifindex);
		break;
	default:
		break;
	}

	return cmp;
}


/*
 * Locate NHLFE that matches with passed info.
 */
static zebra_nhlfe_t *nhlfe_find(zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
				 enum nexthop_types_t gtype, union g_addr *gate,
				 ifindex_t ifindex)
{
	zebra_nhlfe_t *nhlfe;

	if (!lsp)
		return NULL;

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		if (nhlfe->type != lsp_type)
			continue;
		if (!nhlfe_nhop_match(nhlfe, gtype, gate, ifindex))
			break;
	}

	return nhlfe;
}

/*
 * Add NHLFE. Base entry must have been created and duplicate
 * check done.
 */
static zebra_nhlfe_t *nhlfe_add(zebra_lsp_t *lsp, enum lsp_types_t lsp_type,
				enum nexthop_types_t gtype, union g_addr *gate,
				ifindex_t ifindex, mpls_label_t out_label)
{
	zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop;

	if (!lsp)
		return NULL;

	nhlfe = XCALLOC(MTYPE_NHLFE, sizeof(zebra_nhlfe_t));
	if (!nhlfe)
		return NULL;

	nhlfe->lsp = lsp;
	nhlfe->type = lsp_type;
	nhlfe->distance = lsp_distance(lsp_type);

	nexthop = nexthop_new();
	if (!nexthop) {
		XFREE(MTYPE_NHLFE, nhlfe);
		return NULL;
	}
	nexthop_add_labels(nexthop, lsp_type, 1, &out_label);

	nexthop->type = gtype;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		nexthop->gate.ipv4 = gate->ipv4;
		if (ifindex)
			nexthop->ifindex = ifindex;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		nexthop->gate.ipv6 = gate->ipv6;
		if (ifindex)
			nexthop->ifindex = ifindex;
		break;
	default:
		nexthop_free(nexthop);
		XFREE(MTYPE_NHLFE, nhlfe);
		return NULL;
		break;
	}

	nhlfe->nexthop = nexthop;
	if (lsp->nhlfe_list)
		lsp->nhlfe_list->prev = nhlfe;
	nhlfe->next = lsp->nhlfe_list;
	lsp->nhlfe_list = nhlfe;

	return nhlfe;
}

/*
 * Delete NHLFE. Entry must be present on list.
 */
static int nhlfe_del(zebra_nhlfe_t *nhlfe)
{
	zebra_lsp_t *lsp;

	if (!nhlfe)
		return -1;

	lsp = nhlfe->lsp;
	if (!lsp)
		return -1;

	/* Free nexthop. */
	if (nhlfe->nexthop)
		nexthop_free(nhlfe->nexthop);

	/* Unlink from LSP */
	if (nhlfe->next)
		nhlfe->next->prev = nhlfe->prev;
	if (nhlfe->prev)
		nhlfe->prev->next = nhlfe->next;
	else
		lsp->nhlfe_list = nhlfe->next;

	if (nhlfe == lsp->best_nhlfe)
		lsp->best_nhlfe = NULL;

	XFREE(MTYPE_NHLFE, nhlfe);

	return 0;
}

/*
 * Update label for NHLFE entry.
 */
static void nhlfe_out_label_update(zebra_nhlfe_t *nhlfe,
				   struct mpls_label_stack *nh_label)
{
	nhlfe->nexthop->nh_label->label[0] = nh_label->label[0];
}

static int mpls_lsp_uninstall_all(struct hash *lsp_table, zebra_lsp_t *lsp,
				  enum lsp_types_t type)
{
	zebra_nhlfe_t *nhlfe, *nhlfe_next;
	int schedule_lsp = 0;
	char buf[BUFSIZ];

	/* Mark NHLFEs for delete or directly delete, as appropriate. */
	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe_next) {
		nhlfe_next = nhlfe->next;

		/* Skip non-static NHLFEs */
		if (nhlfe->type != type)
			continue;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, BUFSIZ);
			zlog_debug(
				"Del LSP in-label %u type %d nexthop %s flags 0x%x",
				lsp->ile.in_label, type, buf, nhlfe->flags);
		}

		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)) {
			UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
			schedule_lsp = 1;
		} else {
			nhlfe_del(nhlfe);
		}
	}

	/* Queue LSP for processing, if needed, else delete. */
	if (schedule_lsp) {
		if (lsp_processq_add(lsp))
			return -1;
	} else if (!lsp->nhlfe_list
		   && !CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED)) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Free LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);

		lsp = hash_release(lsp_table, &lsp->ile);
		if (lsp)
			XFREE(MTYPE_LSP, lsp);
	}

	return 0;
}

/*
 * Uninstall all static NHLFEs for a particular LSP forwarding entry.
 * If no other NHLFEs exist, the entry would be deleted.
 */
static int mpls_static_lsp_uninstall_all(struct zebra_vrf *zvrf,
					 mpls_label_t in_label)
{
	struct hash *lsp_table;
	zebra_ile_t tmp_ile;
	zebra_lsp_t *lsp;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp || !lsp->nhlfe_list)
		return 0;

	return mpls_lsp_uninstall_all(lsp_table, lsp, ZEBRA_LSP_STATIC);
}

static json_object *nhlfe_json(zebra_nhlfe_t *nhlfe)
{
	char buf[BUFSIZ];
	json_object *json_nhlfe = NULL;
	struct nexthop *nexthop = nhlfe->nexthop;

	json_nhlfe = json_object_new_object();
	json_object_string_add(json_nhlfe, "type", nhlfe_type2str(nhlfe->type));
	json_object_int_add(json_nhlfe, "outLabel",
			    nexthop->nh_label->label[0]);
	json_object_int_add(json_nhlfe, "distance", nhlfe->distance);

	if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED))
		json_object_boolean_true_add(json_nhlfe, "installed");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		json_object_string_add(json_nhlfe, "nexthop",
				       inet_ntoa(nexthop->gate.ipv4));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		json_object_string_add(
			json_nhlfe, "nexthop",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));

		if (nexthop->ifindex)
			json_object_string_add(
				json_nhlfe, "interface",
				ifindex2ifname(nexthop->ifindex, VRF_DEFAULT));
		break;
	default:
		break;
	}
	return json_nhlfe;
}

/*
 * Print the NHLFE for a LSP forwarding entry.
 */
static void nhlfe_print(zebra_nhlfe_t *nhlfe, struct vty *vty)
{
	struct nexthop *nexthop;
	char buf[BUFSIZ];

	nexthop = nhlfe->nexthop;
	if (!nexthop || !nexthop->nh_label) // unexpected
		return;

	vty_out(vty, " type: %s remote label: %s distance: %d\n",
		nhlfe_type2str(nhlfe->type),
		label2str(nexthop->nh_label->label[0], buf, BUFSIZ),
		nhlfe->distance);
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, "  via %s", inet_ntoa(nexthop->gate.ipv4));
		if (nexthop->ifindex)
			vty_out(vty, " dev %s",
				ifindex2ifname(nexthop->ifindex, VRF_DEFAULT));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, "  via %s",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
		if (nexthop->ifindex)
			vty_out(vty, " dev %s",
				ifindex2ifname(nexthop->ifindex, VRF_DEFAULT));
		break;
	default:
		break;
	}
	vty_out(vty, "%s", CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)
				   ? " (installed)"
				   : "");
	vty_out(vty, "\n");
}

/*
 * Print an LSP forwarding entry.
 */
static void lsp_print(zebra_lsp_t *lsp, void *ctxt)
{
	zebra_nhlfe_t *nhlfe;
	struct vty *vty;

	vty = (struct vty *)ctxt;

	vty_out(vty, "Local label: %u%s\n", lsp->ile.in_label,
		CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED) ? " (installed)"
							   : "");

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
		nhlfe_print(nhlfe, vty);
}

/*
 * JSON objects for an LSP forwarding entry.
 */
static json_object *lsp_json(zebra_lsp_t *lsp)
{
	zebra_nhlfe_t *nhlfe = NULL;
	json_object *json = json_object_new_object();
	json_object *json_nhlfe_list = json_object_new_array();

	json_object_int_add(json, "inLabel", lsp->ile.in_label);

	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		json_object_boolean_true_add(json, "installed");

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next)
		json_object_array_add(json_nhlfe_list, nhlfe_json(nhlfe));

	json_object_object_add(json, "nexthops", json_nhlfe_list);
	return json;
}


/* Return a sorted linked list of the hash contents */
static struct list *hash_get_sorted_list(struct hash *hash, void *cmp)
{
	unsigned int i;
	struct hash_backet *hb;
	struct list *sorted_list = list_new();

	sorted_list->cmp = (int (*)(void *, void *))cmp;

	for (i = 0; i < hash->size; i++)
		for (hb = hash->index[i]; hb; hb = hb->next)
			listnode_add_sort(sorted_list, hb->data);

	return sorted_list;
}

/*
 * Compare two LSPs based on their label values.
 */
static int lsp_cmp(zebra_lsp_t *lsp1, zebra_lsp_t *lsp2)
{
	if (lsp1->ile.in_label < lsp2->ile.in_label)
		return -1;

	if (lsp1->ile.in_label > lsp2->ile.in_label)
		return 1;

	return 0;
}

/*
 * Callback to allocate static LSP.
 */
static void *slsp_alloc(void *p)
{
	const zebra_ile_t *ile = p;
	zebra_slsp_t *slsp;

	slsp = XCALLOC(MTYPE_SLSP, sizeof(zebra_slsp_t));
	slsp->ile = *ile;
	return ((void *)slsp);
}

/*
 * Compare two static LSPs based on their label values.
 */
static int slsp_cmp(zebra_slsp_t *slsp1, zebra_slsp_t *slsp2)
{
	if (slsp1->ile.in_label < slsp2->ile.in_label)
		return -1;

	if (slsp1->ile.in_label > slsp2->ile.in_label)
		return 1;

	return 0;
}

/*
 * Check if static NHLFE matches with search info passed.
 */
static int snhlfe_match(zebra_snhlfe_t *snhlfe, enum nexthop_types_t gtype,
			union g_addr *gate, ifindex_t ifindex)
{
	int cmp = 1;

	if (snhlfe->gtype != gtype)
		return 1;

	switch (snhlfe->gtype) {
	case NEXTHOP_TYPE_IPV4:
		cmp = memcmp(&(snhlfe->gate.ipv4), &(gate->ipv4),
			     sizeof(struct in_addr));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		cmp = memcmp(&(snhlfe->gate.ipv6), &(gate->ipv6),
			     sizeof(struct in6_addr));
		if (!cmp && snhlfe->gtype == NEXTHOP_TYPE_IPV6_IFINDEX)
			cmp = !(snhlfe->ifindex == ifindex);
		break;
	default:
		break;
	}

	return cmp;
}

/*
 * Locate static NHLFE that matches with passed info.
 */
static zebra_snhlfe_t *snhlfe_find(zebra_slsp_t *slsp,
				   enum nexthop_types_t gtype,
				   union g_addr *gate, ifindex_t ifindex)
{
	zebra_snhlfe_t *snhlfe;

	if (!slsp)
		return NULL;

	for (snhlfe = slsp->snhlfe_list; snhlfe; snhlfe = snhlfe->next) {
		if (!snhlfe_match(snhlfe, gtype, gate, ifindex))
			break;
	}

	return snhlfe;
}


/*
 * Add static NHLFE. Base LSP config entry must have been created
 * and duplicate check done.
 */
static zebra_snhlfe_t *snhlfe_add(zebra_slsp_t *slsp,
				  enum nexthop_types_t gtype,
				  union g_addr *gate, ifindex_t ifindex,
				  mpls_label_t out_label)
{
	zebra_snhlfe_t *snhlfe;

	if (!slsp)
		return NULL;

	snhlfe = XCALLOC(MTYPE_SNHLFE, sizeof(zebra_snhlfe_t));
	snhlfe->slsp = slsp;
	snhlfe->out_label = out_label;
	snhlfe->gtype = gtype;
	switch (gtype) {
	case NEXTHOP_TYPE_IPV4:
		snhlfe->gate.ipv4 = gate->ipv4;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		snhlfe->gate.ipv6 = gate->ipv6;
		if (ifindex)
			snhlfe->ifindex = ifindex;
		break;
	default:
		XFREE(MTYPE_SNHLFE, snhlfe);
		return NULL;
	}

	if (slsp->snhlfe_list)
		slsp->snhlfe_list->prev = snhlfe;
	snhlfe->next = slsp->snhlfe_list;
	slsp->snhlfe_list = snhlfe;

	return snhlfe;
}

/*
 * Delete static NHLFE. Entry must be present on list.
 */
static int snhlfe_del(zebra_snhlfe_t *snhlfe)
{
	zebra_slsp_t *slsp;

	if (!snhlfe)
		return -1;

	slsp = snhlfe->slsp;
	if (!slsp)
		return -1;

	if (snhlfe->next)
		snhlfe->next->prev = snhlfe->prev;
	if (snhlfe->prev)
		snhlfe->prev->next = snhlfe->next;
	else
		slsp->snhlfe_list = snhlfe->next;

	snhlfe->prev = snhlfe->next = NULL;
	if (snhlfe->ifname)
		XFREE(MTYPE_SNHLFE_IFNAME, snhlfe->ifname);
	XFREE(MTYPE_SNHLFE, snhlfe);

	return 0;
}

/*
 * Delete all static NHLFE entries for this LSP (in label).
 */
static int snhlfe_del_all(zebra_slsp_t *slsp)
{
	zebra_snhlfe_t *snhlfe, *snhlfe_next;

	if (!slsp)
		return -1;

	for (snhlfe = slsp->snhlfe_list; snhlfe; snhlfe = snhlfe_next) {
		snhlfe_next = snhlfe->next;
		snhlfe_del(snhlfe);
	}

	return 0;
}

/*
 * Create printable string for NHLFE configuration.
 */
static char *snhlfe2str(zebra_snhlfe_t *snhlfe, char *buf, int size)
{
	buf[0] = '\0';
	switch (snhlfe->gtype) {
	case NEXTHOP_TYPE_IPV4:
		inet_ntop(AF_INET, &snhlfe->gate.ipv4, buf, size);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &snhlfe->gate.ipv6, buf, size);
		if (snhlfe->ifindex)
			strcat(buf,
			       ifindex2ifname(snhlfe->ifindex, VRF_DEFAULT));
		break;
	default:
		break;
	}

	return buf;
}

/*
 * Initialize work queue for processing changed LSPs.
 */
static int mpls_processq_init(struct zebra_t *zebra)
{
	zebra->lsp_process_q = work_queue_new(zebra->master, "LSP processing");
	if (!zebra->lsp_process_q) {
		zlog_err("%s: could not initialise work queue!", __func__);
		return -1;
	}

	zebra->lsp_process_q->spec.workfunc = &lsp_process;
	zebra->lsp_process_q->spec.del_item_data = &lsp_processq_del;
	zebra->lsp_process_q->spec.errorfunc = NULL;
	zebra->lsp_process_q->spec.completion_func = &lsp_processq_complete;
	zebra->lsp_process_q->spec.max_retries = 0;
	zebra->lsp_process_q->spec.hold = 10;

	return 0;
}


/* Public functions */

void kernel_lsp_pass_fail(zebra_lsp_t *lsp,
			  enum southbound_results res)
{
	struct nexthop *nexthop;
	zebra_nhlfe_t *nhlfe;

	if (!lsp)
		return;

	switch (res) {
	case SOUTHBOUND_INSTALL_FAILURE:
		UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
		clear_nhlfe_installed(lsp);
		zlog_warn("LSP Install Failure: %u", lsp->ile.in_label);
		break;
	case SOUTHBOUND_INSTALL_SUCCESS:
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
		for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
			nexthop = nhlfe->nexthop;
			if (!nexthop)
				continue;

			SET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
		}
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
		UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
		clear_nhlfe_installed(lsp);
		break;
	case SOUTHBOUND_DELETE_FAILURE:
		zlog_warn("LSP Deletion Failure: %u", lsp->ile.in_label);
		break;
	}
}

/*
 * String to label conversion, labels separated by '/'.
 *
 * @param label_str labels separated by /
 * @param num_labels number of labels; zero if conversion was unsuccessful
 * @param labels preallocated mpls_label_t array of size MPLS_MAX_LABELS; only
 *               modified if the conversion succeeded
 * @return  0 on success
 *         -1 if the string could not be parsed as integers
 *         -2 if a label was inside the reserved range (0-15)
 *         -3 if the number of labels given exceeds MPLS_MAX_LABELS
 */
int mpls_str2label(const char *label_str, u_int8_t *num_labels,
		   mpls_label_t *labels)
{
	char *ostr;			  // copy of label string (start)
	char *lstr;			  // copy of label string
	char *nump;			  // pointer to next segment
	char *endp;			  // end pointer
	int i;				  // for iterating label_str
	int rc;				  // return code
	mpls_label_t pl[MPLS_MAX_LABELS]; // parsed labels

	/* labels to zero until we have a successful parse */
	ostr = lstr = XSTRDUP(MTYPE_TMP, label_str);
	*num_labels = 0;
	rc = 0;

	for (i = 0; i < MPLS_MAX_LABELS && lstr && !rc; i++) {
		nump = strsep(&lstr, "/");
		pl[i] = strtoul(nump, &endp, 10);

		/* format check */
		if (*endp != '\0')
			rc = -1;
		/* validity check */
		else if (!IS_MPLS_UNRESERVED_LABEL(pl[i]))
			rc = -2;
	}

	/* excess labels */
	if (!rc && i == MPLS_MAX_LABELS && lstr)
		rc = -3;

	if (!rc) {
		*num_labels = i;
		memcpy(labels, pl, *num_labels * sizeof(mpls_label_t));
	}

	XFREE(MTYPE_TMP, ostr);

	return rc;
}

/*
 * Label to string conversion, labels in string separated by '/'.
 */
char *mpls_label2str(u_int8_t num_labels, mpls_label_t *labels, char *buf,
		     int len, int pretty)
{
	char label_buf[BUFSIZ];
	int i;

	buf[0] = '\0';
	for (i = 0; i < num_labels; i++) {
		if (i != 0)
			strlcat(buf, "/", len);
		if (pretty)
			label2str(labels[i], label_buf, sizeof(label_buf));
		else
			snprintf(label_buf, sizeof(label_buf), "%u", labels[i]);
		strlcat(buf, label_buf, len);
	}

	return buf;
}

/*
 * Install dynamic LSP entry.
 */
int zebra_mpls_lsp_install(struct zebra_vrf *zvrf, struct route_node *rn,
			   struct route_entry *re)
{
	struct route_table *table;
	zebra_fec_t *fec;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(&rn->p))];
	if (!table)
		return -1;

	/* See if there is a configured label binding for this FEC. */
	fec = fec_find(table, &rn->p);
	if (!fec || fec->label == MPLS_INVALID_LABEL)
		return 0;

	/* We cannot install a label forwarding entry if local label is the
	 * implicit-null label.
	 */
	if (fec->label == MPLS_IMP_NULL_LABEL)
		return 0;

	if (lsp_install(zvrf, fec->label, rn, re))
		return -1;

	return 0;
}

/*
 * Uninstall dynamic LSP entry, if any.
 */
int zebra_mpls_lsp_uninstall(struct zebra_vrf *zvrf, struct route_node *rn,
			     struct route_entry *re)
{
	struct route_table *table;
	zebra_fec_t *fec;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(&rn->p))];
	if (!table)
		return -1;

	/* See if there is a configured label binding for this FEC. */
	fec = fec_find(table, &rn->p);
	if (!fec || fec->label == MPLS_INVALID_LABEL)
		return 0;

	/* Uninstall always removes all dynamic NHLFEs. */
	return lsp_uninstall(zvrf, fec->label);
}

/*
 * Registration from a client for the label binding for a FEC. If a binding
 * already exists, it is informed to the client.
 * NOTE: If there is a manually configured label binding, that is used.
 * Otherwise, if a label index is specified, it means we have to allocate the
 * label from a locally configured label block (SRGB), if one exists and index
 * is acceptable.
 */
int zebra_mpls_fec_register(struct zebra_vrf *zvrf, struct prefix *p,
			    u_int32_t label_index, struct zserv *client)
{
	struct route_table *table;
	zebra_fec_t *fec;
	char buf[BUFSIZ];
	int new_client;
	int label_change = 0;
	u_int32_t old_label;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	if (IS_ZEBRA_DEBUG_MPLS)
		prefix2str(p, buf, BUFSIZ);

	/* Locate FEC */
	fec = fec_find(table, p);
	if (!fec) {
		fec = fec_add(table, p, MPLS_INVALID_LABEL, 0, label_index);
		if (!fec) {
			prefix2str(p, buf, BUFSIZ);
			zlog_err(
				"Failed to add FEC %s upon register, client %s",
				buf, zebra_route_string(client->proto));
			return -1;
		}

		old_label = MPLS_INVALID_LABEL;
		new_client = 1;
	} else {
		/* Client may register same FEC with different label index. */
		new_client =
			(listnode_lookup(fec->client_list, client) == NULL);
		if (!new_client && fec->label_index == label_index)
			/* Duplicate register */
			return 0;

		/* Save current label, update label index */
		old_label = fec->label;
		fec->label_index = label_index;
	}

	if (new_client)
		listnode_add(fec->client_list, client);

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("FEC %s Label Index %u %s by client %s", buf,
			   label_index, new_client ? "registered" : "updated",
			   zebra_route_string(client->proto));

	/* If not a configured FEC, derive the local label (from label index)
	 * or reset it.
	 */
	if (!(fec->flags & FEC_FLAG_CONFIGURED)) {
		fec_derive_label_from_index(zvrf, fec);

		/* If no label change, exit. */
		if (fec->label == old_label)
			return 0;

		label_change = 1;
	}

	/* If new client or label change, update client and install or uninstall
	 * label forwarding entry as needed.
	 */
	/* Inform client of label, if needed. */
	if ((new_client && fec->label != MPLS_INVALID_LABEL) || label_change) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Update client label %u", fec->label);
		fec_send(fec, client);
	}

	if (new_client || label_change)
		return fec_change_update_lsp(zvrf, fec, old_label);

	return 0;
}

/*
 * Deregistration from a client for the label binding for a FEC. The FEC
 * itself is deleted if no other registered clients exist and there is no
 * label bound to the FEC.
 */
int zebra_mpls_fec_unregister(struct zebra_vrf *zvrf, struct prefix *p,
			      struct zserv *client)
{
	struct route_table *table;
	zebra_fec_t *fec;
	char buf[BUFSIZ];

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	if (IS_ZEBRA_DEBUG_MPLS)
		prefix2str(p, buf, BUFSIZ);

	fec = fec_find(table, p);
	if (!fec) {
		prefix2str(p, buf, BUFSIZ);
		zlog_err("Failed to find FEC %s upon unregister, client %s",
			 buf, zebra_route_string(client->proto));
		return -1;
	}

	listnode_delete(fec->client_list, client);

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("FEC %s unregistered by client %s", buf,
			   zebra_route_string(client->proto));

	/* If not a configured entry, delete the FEC if no other clients. Before
	 * deleting, see if any LSP needs to be uninstalled.
	 */
	if (!(fec->flags & FEC_FLAG_CONFIGURED)
	    && list_isempty(fec->client_list)) {
		mpls_label_t old_label = fec->label;
		fec->label = MPLS_INVALID_LABEL; /* reset */
		fec_change_update_lsp(zvrf, fec, old_label);
		fec_del(fec);
	}

	return 0;
}

/*
 * Cleanup any FECs registered by this client.
 */
int zebra_mpls_cleanup_fecs_for_client(struct zebra_vrf *zvrf,
				       struct zserv *client)
{
	struct route_node *rn;
	zebra_fec_t *fec;
	struct listnode *node;
	struct zserv *fec_client;
	int af;

	for (af = AFI_IP; af < AFI_MAX; af++) {
		if (zvrf->fec_table[af] == NULL)
			continue;

		for (rn = route_top(zvrf->fec_table[af]); rn;
		     rn = route_next(rn)) {
			fec = rn->info;
			if (!fec || list_isempty(fec->client_list))
				continue;

			for (ALL_LIST_ELEMENTS_RO(fec->client_list, node,
						  fec_client)) {
				if (fec_client == client) {
					listnode_delete(fec->client_list,
							fec_client);
					if (!(fec->flags & FEC_FLAG_CONFIGURED)
					    && list_isempty(fec->client_list))
						fec_del(fec);
					break;
				}
			}
		}
	}

	return 0;
}

/*
 * Return FEC (if any) to which this label is bound.
 * Note: Only works for per-prefix binding and when the label is not
 * implicit-null.
 * TODO: Currently walks entire table, can optimize later with another
 * hash..
 */
zebra_fec_t *zebra_mpls_fec_for_label(struct zebra_vrf *zvrf,
				      mpls_label_t label)
{
	struct route_node *rn;
	zebra_fec_t *fec;
	int af;

	for (af = AFI_IP; af < AFI_MAX; af++) {
		if (zvrf->fec_table[af] == NULL)
			continue;

		for (rn = route_top(zvrf->fec_table[af]); rn;
		     rn = route_next(rn)) {
			if (!rn->info)
				continue;
			fec = rn->info;
			if (fec->label == label)
				return fec;
		}
	}

	return NULL;
}

/*
 * Inform if specified label is currently bound to a FEC or not.
 */
int zebra_mpls_label_already_bound(struct zebra_vrf *zvrf, mpls_label_t label)
{
	return (zebra_mpls_fec_for_label(zvrf, label) ? 1 : 0);
}

/*
 * Add static FEC to label binding. If there are clients registered for this
 * FEC, notify them. If there are labeled routes for this FEC, install the
 * label forwarding entry.
*/
int zebra_mpls_static_fec_add(struct zebra_vrf *zvrf, struct prefix *p,
			      mpls_label_t in_label)
{
	struct route_table *table;
	zebra_fec_t *fec;
	char buf[BUFSIZ];
	mpls_label_t old_label;
	int ret = 0;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	if (IS_ZEBRA_DEBUG_MPLS)
		prefix2str(p, buf, BUFSIZ);

	/* Update existing FEC or create a new one. */
	fec = fec_find(table, p);
	if (!fec) {
		fec = fec_add(table, p, in_label, FEC_FLAG_CONFIGURED,
			      MPLS_INVALID_LABEL_INDEX);
		if (!fec) {
			prefix2str(p, buf, BUFSIZ);
			zlog_err("Failed to add FEC %s upon config", buf);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Add fec %s label %u", buf, in_label);
	} else {
		fec->flags |= FEC_FLAG_CONFIGURED;
		if (fec->label == in_label)
			/* Duplicate config */
			return 0;

		/* Label change, update clients. */
		old_label = fec->label;
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Update fec %s new label %u", buf, in_label);

		fec->label = in_label;
		fec_update_clients(fec);

		/* Update label forwarding entries appropriately */
		ret = fec_change_update_lsp(zvrf, fec, old_label);
	}

	return ret;
}

/*
 * Remove static FEC to label binding. If there are no clients registered
 * for this FEC, delete the FEC; else notify clients
 * Note: Upon delete of static binding, if label index exists for this FEC,
 * client may need to be updated with derived label.
 */
int zebra_mpls_static_fec_del(struct zebra_vrf *zvrf, struct prefix *p)
{
	struct route_table *table;
	zebra_fec_t *fec;
	mpls_label_t old_label;
	char buf[BUFSIZ];

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	fec = fec_find(table, p);
	if (!fec) {
		prefix2str(p, buf, BUFSIZ);
		zlog_err("Failed to find FEC %s upon delete", buf);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_MPLS) {
		prefix2str(p, buf, BUFSIZ);
		zlog_debug("Delete fec %s label index %u", buf,
			   fec->label_index);
	}

	old_label = fec->label;
	fec->flags &= ~FEC_FLAG_CONFIGURED;
	fec->label = MPLS_INVALID_LABEL;

	/* If no client exists, just delete the FEC. */
	if (list_isempty(fec->client_list)) {
		fec_del(fec);
		return 0;
	}

	/* Derive the local label (from label index) or reset it. */
	fec_derive_label_from_index(zvrf, fec);

	/* If there is a label change, update clients. */
	if (fec->label == old_label)
		return 0;
	fec_update_clients(fec);

	/* Update label forwarding entries appropriately */
	return fec_change_update_lsp(zvrf, fec, old_label);
}

/*
 * Display MPLS FEC to label binding configuration (VTY command handler).
 */
int zebra_mpls_write_fec_config(struct vty *vty, struct zebra_vrf *zvrf)
{
	struct route_node *rn;
	int af;
	zebra_fec_t *fec;
	char buf[BUFSIZ];
	int write = 0;

	for (af = AFI_IP; af < AFI_MAX; af++) {
		if (zvrf->fec_table[af] == NULL)
			continue;

		for (rn = route_top(zvrf->fec_table[af]); rn;
		     rn = route_next(rn)) {
			if (!rn->info)
				continue;

			char lstr[BUFSIZ];
			fec = rn->info;

			if (!(fec->flags & FEC_FLAG_CONFIGURED))
				continue;

			write = 1;
			prefix2str(&rn->p, buf, BUFSIZ);
			vty_out(vty, "mpls label bind %s %s\n", buf,
				label2str(fec->label, lstr, BUFSIZ));
		}
	}

	return write;
}

/*
 * Display MPLS FEC to label binding (VTY command handler).
 */
void zebra_mpls_print_fec_table(struct vty *vty, struct zebra_vrf *zvrf)
{
	struct route_node *rn;
	int af;

	for (af = AFI_IP; af < AFI_MAX; af++) {
		if (zvrf->fec_table[af] == NULL)
			continue;

		for (rn = route_top(zvrf->fec_table[af]); rn;
		     rn = route_next(rn)) {
			if (!rn->info)
				continue;
			fec_print(rn->info, vty);
		}
	}
}

/*
 * Display MPLS FEC to label binding for a specific FEC (VTY command handler).
 */
void zebra_mpls_print_fec(struct vty *vty, struct zebra_vrf *zvrf,
			  struct prefix *p)
{
	struct route_table *table;
	struct route_node *rn;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return;

	apply_mask(p);
	rn = route_node_lookup(table, p);
	if (!rn)
		return;

	route_unlock_node(rn);
	if (!rn->info)
		return;

	fec_print(rn->info, vty);
}

/*
 * Install/uninstall a FEC-To-NHLFE (FTN) binding.
 */
int mpls_ftn_update(int add, struct zebra_vrf *zvrf, enum lsp_types_t type,
		    struct prefix *prefix, enum nexthop_types_t gtype,
		    union g_addr *gate, ifindex_t ifindex, u_int8_t distance,
		    mpls_label_t out_label)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;

	/* Lookup table.  */
	table = zebra_vrf_table(family2afi(prefix->family), SAFI_UNICAST,
				zvrf_id(zvrf));
	if (!table)
		return -1;

	/* Lookup existing route */
	rn = route_node_get(table, prefix);
	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;
		if (re->distance == distance)
			break;
	}

	if (re == NULL)
		return -1;

	for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			if (gtype != NEXTHOP_TYPE_IPV4
			    && gtype != NEXTHOP_TYPE_IPV4_IFINDEX)
				continue;
			if (!IPV4_ADDR_SAME(&nexthop->gate.ipv4, &gate->ipv4))
				continue;
			if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX
			    && nexthop->ifindex != ifindex)
				continue;
			goto found;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (gtype != NEXTHOP_TYPE_IPV6
			    && gtype != NEXTHOP_TYPE_IPV6_IFINDEX)
				continue;
			if (!IPV6_ADDR_SAME(&nexthop->gate.ipv6, &gate->ipv6))
				continue;
			if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX
			    && nexthop->ifindex != ifindex)
				continue;
			goto found;
		default:
			break;
		}
	}
	/* nexthop not found */
	return -1;

found:
	if (add && nexthop->nh_label_type == ZEBRA_LSP_NONE)
		nexthop_add_labels(nexthop, type, 1, &out_label);
	else if (!add && nexthop->nh_label_type == type)
		nexthop_del_labels(nexthop);
	else
		return 0;

	SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	SET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);
	rib_queue_add(rn);

	return 0;
}

/*
 * Install/update a NHLFE for an LSP in the forwarding table. This may be
 * a new LSP entry or a new NHLFE for an existing in-label or an update of
 * the out-label for an existing NHLFE (update case).
 */
int mpls_lsp_install(struct zebra_vrf *zvrf, enum lsp_types_t type,
		     mpls_label_t in_label, mpls_label_t out_label,
		     enum nexthop_types_t gtype, union g_addr *gate,
		     ifindex_t ifindex)
{
	struct hash *lsp_table;
	zebra_ile_t tmp_ile;
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *nhlfe;
	char buf[BUFSIZ];

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_get(lsp_table, &tmp_ile, lsp_alloc);
	if (!lsp)
		return -1;
	nhlfe = nhlfe_find(lsp, type, gtype, gate, ifindex);
	if (nhlfe) {
		struct nexthop *nh = nhlfe->nexthop;

		assert(nh);
		assert(nh->nh_label);

		/* Clear deleted flag (in case it was set) */
		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
		if (nh->nh_label->label[0] == out_label)
			/* No change */
			return 0;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, BUFSIZ);
			zlog_debug(
				"LSP in-label %u type %d nexthop %s "
				"out-label changed to %u (old %u)",
				in_label, type, buf, out_label,
				nh->nh_label->label[0]);
		}

		/* Update out label, trigger processing. */
		nh->nh_label->label[0] = out_label;
	} else {
		/* Add LSP entry to this nexthop */
		nhlfe = nhlfe_add(lsp, type, gtype, gate, ifindex, out_label);
		if (!nhlfe)
			return -1;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, BUFSIZ);
			zlog_debug(
				"Add LSP in-label %u type %d nexthop %s "
				"out-label %u",
				in_label, type, buf, out_label);
		}

		lsp->addr_family = NHLFE_FAMILY(nhlfe);
	}

	/* Mark NHLFE, queue LSP for processing. */
	SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
	if (lsp_processq_add(lsp))
		return -1;

	return 0;
}

/*
 * Uninstall a particular NHLFE in the forwarding table. If this is
 * the only NHLFE, the entire LSP forwarding entry has to be deleted.
 */
int mpls_lsp_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
		       mpls_label_t in_label, enum nexthop_types_t gtype,
		       union g_addr *gate, ifindex_t ifindex)
{
	struct hash *lsp_table;
	zebra_ile_t tmp_ile;
	zebra_lsp_t *lsp;
	zebra_nhlfe_t *nhlfe;
	char buf[BUFSIZ];

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp)
		return 0;
	nhlfe = nhlfe_find(lsp, type, gtype, gate, ifindex);
	if (!nhlfe)
		return 0;

	if (IS_ZEBRA_DEBUG_MPLS) {
		nhlfe2str(nhlfe, buf, BUFSIZ);
		zlog_debug("Del LSP in-label %u type %d nexthop %s flags 0x%x",
			   in_label, type, buf, nhlfe->flags);
	}

	/* Mark NHLFE for delete or directly delete, as appropriate. */
	if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)) {
		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
		SET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
		if (lsp_processq_add(lsp))
			return -1;
	} else {
		nhlfe_del(nhlfe);

		/* Free LSP entry if no other NHLFEs and not scheduled. */
		if (!lsp->nhlfe_list
		    && !CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED)) {
			if (IS_ZEBRA_DEBUG_MPLS)
				zlog_debug("Free LSP in-label %u flags 0x%x",
					   lsp->ile.in_label, lsp->flags);

			lsp = hash_release(lsp_table, &lsp->ile);
			if (lsp)
				XFREE(MTYPE_LSP, lsp);
		}
	}
	return 0;
}

/*
 * Uninstall all LDP NHLFEs for a particular LSP forwarding entry.
 * If no other NHLFEs exist, the entry would be deleted.
 */
void mpls_ldp_lsp_uninstall_all(struct hash_backet *backet, void *ctxt)
{
	zebra_lsp_t *lsp;
	struct hash *lsp_table;

	lsp = (zebra_lsp_t *)backet->data;
	if (!lsp || !lsp->nhlfe_list)
		return;

	lsp_table = ctxt;
	if (!lsp_table)
		return;

	mpls_lsp_uninstall_all(lsp_table, lsp, ZEBRA_LSP_LDP);
}

/*
 * Uninstall all LDP FEC-To-NHLFE (FTN) bindings of the given address-family.
 */
void mpls_ldp_ftn_uninstall_all(struct zebra_vrf *zvrf, int afi)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
	int update;

	/* Process routes of interested address-families. */
	table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(zvrf));
	if (!table)
		return;

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		update = 0;
		RNODE_FOREACH_RE (rn, re) {
			for (nexthop = re->nexthop; nexthop;
			     nexthop = nexthop->next) {
				if (nexthop->nh_label_type != ZEBRA_LSP_LDP)
					continue;

				nexthop_del_labels(nexthop);
				SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
				SET_FLAG(re->status,
					 ROUTE_ENTRY_LABELS_CHANGED);
				update = 1;
			}
		}

		if (update)
			rib_queue_add(rn);
	}
}

#if defined(HAVE_CUMULUS)
/*
 * Check that the label values used in LSP creation are consistent. The
 * main criteria is that if there is ECMP, the label operation must still
 * be consistent - i.e., all paths either do a swap or do PHP. This is due
 * to current HW restrictions.
 */
int zebra_mpls_lsp_label_consistent(struct zebra_vrf *zvrf,
				    mpls_label_t in_label,
				    mpls_label_t out_label,
				    enum nexthop_types_t gtype,
				    union g_addr *gate, ifindex_t ifindex)
{
	struct hash *slsp_table;
	zebra_ile_t tmp_ile;
	zebra_slsp_t *slsp;
	zebra_snhlfe_t *snhlfe;

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return 0;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	slsp = hash_lookup(slsp_table, &tmp_ile);
	if (!slsp)
		return 1;

	snhlfe = snhlfe_find(slsp, gtype, gate, ifindex);
	if (snhlfe) {
		if (snhlfe->out_label == out_label)
			return 1;

		/* If not only NHLFE, cannot allow label change. */
		if (snhlfe != slsp->snhlfe_list || snhlfe->next)
			return 0;
	} else {
		/* If other NHLFEs exist, label operation must match. */
		if (slsp->snhlfe_list) {
			int cur_op, new_op;

			cur_op = (slsp->snhlfe_list->out_label
				  == MPLS_IMP_NULL_LABEL);
			new_op = (out_label == MPLS_IMP_NULL_LABEL);
			if (cur_op != new_op)
				return 0;
		}
	}

	/* Label values are good. */
	return 1;
}
#endif /* HAVE_CUMULUS */

/*
 * Add static LSP entry. This may be the first entry for this incoming label
 * or an additional nexthop; an existing entry may also have outgoing label
 * changed.
 * Note: The label operation (swap or PHP) is common for the LSP entry (all
 * NHLFEs).
 */
int zebra_mpls_static_lsp_add(struct zebra_vrf *zvrf, mpls_label_t in_label,
			      mpls_label_t out_label,
			      enum nexthop_types_t gtype, union g_addr *gate,
			      ifindex_t ifindex)
{
	struct hash *slsp_table;
	zebra_ile_t tmp_ile;
	zebra_slsp_t *slsp;
	zebra_snhlfe_t *snhlfe;
	char buf[BUFSIZ];

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return -1;

	/* If entry is present, exit. */
	tmp_ile.in_label = in_label;
	slsp = hash_get(slsp_table, &tmp_ile, slsp_alloc);
	if (!slsp)
		return -1;
	snhlfe = snhlfe_find(slsp, gtype, gate, ifindex);
	if (snhlfe) {
		if (snhlfe->out_label == out_label)
			/* No change */
			return 0;

		if (IS_ZEBRA_DEBUG_MPLS) {
			snhlfe2str(snhlfe, buf, BUFSIZ);
			zlog_debug(
				"Upd static LSP in-label %u nexthop %s "
				"out-label %u (old %u)",
				in_label, buf, out_label, snhlfe->out_label);
		}
		snhlfe->out_label = out_label;
	} else {
		/* Add static LSP entry to this nexthop */
		snhlfe = snhlfe_add(slsp, gtype, gate, ifindex, out_label);
		if (!snhlfe)
			return -1;

		if (IS_ZEBRA_DEBUG_MPLS) {
			snhlfe2str(snhlfe, buf, BUFSIZ);
			zlog_debug(
				"Add static LSP in-label %u nexthop %s out-label %u",
				in_label, buf, out_label);
		}
	}

	/* (Re)Install LSP in the main table. */
	if (mpls_lsp_install(zvrf, ZEBRA_LSP_STATIC, in_label, out_label, gtype,
			     gate, ifindex))
		return -1;

	return 0;
}

/*
 * Delete static LSP entry. This may be the delete of one particular
 * NHLFE for this incoming label or the delete of the entire entry (i.e.,
 * all NHLFEs).
 * NOTE: Delete of the only NHLFE will also end up deleting the entire
 * LSP configuration.
 */
int zebra_mpls_static_lsp_del(struct zebra_vrf *zvrf, mpls_label_t in_label,
			      enum nexthop_types_t gtype, union g_addr *gate,
			      ifindex_t ifindex)
{
	struct hash *slsp_table;
	zebra_ile_t tmp_ile;
	zebra_slsp_t *slsp;
	zebra_snhlfe_t *snhlfe;

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	slsp = hash_lookup(slsp_table, &tmp_ile);
	if (!slsp)
		return 0;

	/* Is it delete of entire LSP or a specific NHLFE? */
	if (gtype == NEXTHOP_TYPE_BLACKHOLE) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Del static LSP in-label %u", in_label);

		/* Uninstall entire LSP from the main table. */
		mpls_static_lsp_uninstall_all(zvrf, in_label);

		/* Delete all static NHLFEs */
		snhlfe_del_all(slsp);
	} else {
		/* Find specific NHLFE, exit if not found. */
		snhlfe = snhlfe_find(slsp, gtype, gate, ifindex);
		if (!snhlfe)
			return 0;

		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf[BUFSIZ];
			snhlfe2str(snhlfe, buf, BUFSIZ);
			zlog_debug("Del static LSP in-label %u nexthop %s",
				   in_label, buf);
		}

		/* Uninstall LSP from the main table. */
		mpls_lsp_uninstall(zvrf, ZEBRA_LSP_STATIC, in_label, gtype,
				   gate, ifindex);

		/* Delete static LSP NHLFE */
		snhlfe_del(snhlfe);
	}

	/* Remove entire static LSP entry if no NHLFE - valid in either case
	 * above. */
	if (!slsp->snhlfe_list) {
		slsp = hash_release(slsp_table, &tmp_ile);
		if (slsp)
			XFREE(MTYPE_SLSP, slsp);
	}

	return 0;
}

/*
 * Schedule all MPLS label forwarding entries for processing.
 * Called upon changes that may affect one or more of them such as
 * interface or nexthop state changes.
 */
void zebra_mpls_lsp_schedule(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	hash_iterate(zvrf->lsp_table, lsp_schedule, NULL);
}

/*
 * Display MPLS label forwarding table for a specific LSP
 * (VTY command handler).
 */
void zebra_mpls_print_lsp(struct vty *vty, struct zebra_vrf *zvrf,
			  mpls_label_t label, u_char use_json)
{
	struct hash *lsp_table;
	zebra_lsp_t *lsp;
	zebra_ile_t tmp_ile;
	json_object *json = NULL;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return;

	/* If entry is not present, exit. */
	tmp_ile.in_label = label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp)
		return;

	if (use_json) {
		json = lsp_json(lsp);
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else
		lsp_print(lsp, (void *)vty);
}

/*
 * Display MPLS label forwarding table (VTY command handler).
 */
void zebra_mpls_print_lsp_table(struct vty *vty, struct zebra_vrf *zvrf,
				u_char use_json)
{
	char buf[BUFSIZ];
	json_object *json = NULL;
	zebra_lsp_t *lsp = NULL;
	zebra_nhlfe_t *nhlfe = NULL;
	struct nexthop *nexthop = NULL;
	struct listnode *node = NULL;
	struct list *lsp_list = hash_get_sorted_list(zvrf->lsp_table, lsp_cmp);

	if (use_json) {
		json = json_object_new_object();

		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp))
			json_object_object_add(
				json, label2str(lsp->ile.in_label, buf, BUFSIZ),
				lsp_json(lsp));

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		vty_out(vty, " Inbound                            Outbound\n");
		vty_out(vty, "   Label     Type          Nexthop     Label\n");
		vty_out(vty, "--------  -------  ---------------  --------\n");

		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp)) {
			for (nhlfe = lsp->nhlfe_list; nhlfe;
			     nhlfe = nhlfe->next) {
				vty_out(vty, "%8d  %7s  ", lsp->ile.in_label,
					nhlfe_type2str(nhlfe->type));
				nexthop = nhlfe->nexthop;

				switch (nexthop->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					vty_out(vty, "%15s",
						inet_ntoa(nexthop->gate.ipv4));
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					vty_out(vty, "%15s",
						inet_ntop(AF_INET6,
							  &nexthop->gate.ipv6,
							  buf, BUFSIZ));
					break;
				default:
					break;
				}

				vty_out(vty, "  %8d\n",
					nexthop->nh_label->label[0]);
			}
		}

		vty_out(vty, "\n");
	}

	list_delete_and_null(&lsp_list);
}

/*
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int zebra_mpls_write_lsp_config(struct vty *vty, struct zebra_vrf *zvrf)
{
	zebra_slsp_t *slsp;
	zebra_snhlfe_t *snhlfe;
	struct listnode *node;
	struct list *slsp_list =
		hash_get_sorted_list(zvrf->slsp_table, slsp_cmp);

	for (ALL_LIST_ELEMENTS_RO(slsp_list, node, slsp)) {
		for (snhlfe = slsp->snhlfe_list; snhlfe;
		     snhlfe = snhlfe->next) {
			char buf[BUFSIZ];
			char lstr[30];

			snhlfe2str(snhlfe, buf, sizeof(buf));
			switch (snhlfe->out_label) {
			case MPLS_V4_EXP_NULL_LABEL:
			case MPLS_V6_EXP_NULL_LABEL:
				strlcpy(lstr, "explicit-null", sizeof(lstr));
				break;
			case MPLS_IMP_NULL_LABEL:
				strlcpy(lstr, "implicit-null", sizeof(lstr));
				break;
			default:
				sprintf(lstr, "%u", snhlfe->out_label);
				break;
			}

			vty_out(vty, "mpls lsp %u %s %s\n", slsp->ile.in_label,
				buf, lstr);
		}
	}

	list_delete_and_null(&slsp_list);
	return (zvrf->slsp_table->count ? 1 : 0);
}

/*
 * Add/update global label block.
 */
int zebra_mpls_label_block_add(struct zebra_vrf *zvrf, u_int32_t start_label,
			       u_int32_t end_label)
{
	zvrf->mpls_srgb.start_label = start_label;
	zvrf->mpls_srgb.end_label = end_label;

	/* Evaluate registered FECs to see if any get a label or not. */
	fec_evaluate(zvrf);
	return 0;
}

/*
 * Delete global label block.
 */
int zebra_mpls_label_block_del(struct zebra_vrf *zvrf)
{
	zvrf->mpls_srgb.start_label = MPLS_DEFAULT_MIN_SRGB_LABEL;
	zvrf->mpls_srgb.end_label = MPLS_DEFAULT_MAX_SRGB_LABEL;

	/* Process registered FECs to clear their local label, if needed. */
	fec_evaluate(zvrf);
	return 0;
}

/*
 * Display MPLS global label block configuration (VTY command handler).
 */
int zebra_mpls_write_label_block_config(struct vty *vty, struct zebra_vrf *zvrf)
{
	if (zvrf->mpls_srgb.start_label == 0)
		return 0;

	if ((zvrf->mpls_srgb.start_label != MPLS_DEFAULT_MIN_SRGB_LABEL)
	    || (zvrf->mpls_srgb.end_label != MPLS_DEFAULT_MAX_SRGB_LABEL)) {
		vty_out(vty, "mpls label global-block %u %u\n",
			zvrf->mpls_srgb.start_label, zvrf->mpls_srgb.end_label);
	}

	return 1;
}

/*
 * Called when VRF becomes inactive, cleans up information but keeps
 * the table itself.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_cleanup_tables(struct zebra_vrf *zvrf)
{
	hash_iterate(zvrf->lsp_table, lsp_uninstall_from_kernel, NULL);
}

/*
 * Called upon process exiting, need to delete LSP forwarding
 * entries from the kernel.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_close_tables(struct zebra_vrf *zvrf)
{
	hash_iterate(zvrf->lsp_table, lsp_uninstall_from_kernel, NULL);
	hash_clean(zvrf->lsp_table, NULL);
	hash_free(zvrf->lsp_table);
	hash_clean(zvrf->slsp_table, NULL);
	hash_free(zvrf->slsp_table);
	route_table_finish(zvrf->fec_table[AFI_IP]);
	route_table_finish(zvrf->fec_table[AFI_IP6]);
}

/*
 * Allocate MPLS tables for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_init_tables(struct zebra_vrf *zvrf)
{
	if (!zvrf)
		return;
	zvrf->slsp_table = hash_create(label_hash,
				       label_cmp,
				       "ZEBRA SLSP table");
	zvrf->lsp_table = hash_create(label_hash,
				      label_cmp,
				      "ZEBRA LSP table");
	zvrf->fec_table[AFI_IP] = route_table_init();
	zvrf->fec_table[AFI_IP6] = route_table_init();
	zvrf->mpls_flags = 0;
	zvrf->mpls_srgb.start_label = MPLS_DEFAULT_MIN_SRGB_LABEL;
	zvrf->mpls_srgb.end_label = MPLS_DEFAULT_MAX_SRGB_LABEL;
}

/*
 * Global MPLS initialization.
 */
void zebra_mpls_init(void)
{
	mpls_enabled = 0;

	if (mpls_kernel_init() < 0) {
		zlog_warn("Disabling MPLS support (no kernel support)");
		return;
	}

	if (!mpls_processq_init(&zebrad))
		mpls_enabled = 1;
}
