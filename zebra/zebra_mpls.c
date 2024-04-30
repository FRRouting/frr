// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra MPLS code
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include "frrevent.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"
#include "termtable.h"
#include "lib/json.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_errors.h"

DEFINE_MTYPE_STATIC(ZEBRA, LSP, "MPLS LSP object");
DEFINE_MTYPE_STATIC(ZEBRA, FEC, "MPLS FEC object");
DEFINE_MTYPE_STATIC(ZEBRA, NHLFE, "MPLS nexthop object");

bool mpls_enabled;
bool mpls_pw_reach_strict; /* Strict reachability checking */

/* static function declarations */

static void fec_evaluate(struct zebra_vrf *zvrf);
static uint32_t fec_derive_label_from_index(struct zebra_vrf *vrf,
					    struct zebra_fec *fec);
static int lsp_install(struct zebra_vrf *zvrf, mpls_label_t label,
		       struct route_node *rn, struct route_entry *re);
static int lsp_uninstall(struct zebra_vrf *zvrf, mpls_label_t label);
static int fec_change_update_lsp(struct zebra_vrf *zvrf, struct zebra_fec *fec,
				 mpls_label_t old_label);
static int fec_send(struct zebra_fec *fec, struct zserv *client);
static void fec_update_clients(struct zebra_fec *fec);
static void fec_print(struct zebra_fec *fec, struct vty *vty);
static struct zebra_fec *fec_find(struct route_table *table, struct prefix *p);
static struct zebra_fec *fec_add(struct route_table *table, struct prefix *p,
				 mpls_label_t label, uint32_t flags,
				 uint32_t label_index);
static int fec_del(struct zebra_fec *fec);

static unsigned int label_hash(const void *p);
static bool label_cmp(const void *p1, const void *p2);
static int nhlfe_nexthop_active_ipv4(struct zebra_nhlfe *nhlfe,
				     struct nexthop *nexthop);
static int nhlfe_nexthop_active_ipv6(struct zebra_nhlfe *nhlfe,
				     struct nexthop *nexthop);
static int nhlfe_nexthop_active(struct zebra_nhlfe *nhlfe);

static void lsp_select_best_nhlfe(struct zebra_lsp *lsp);
static void lsp_uninstall_from_kernel(struct hash_bucket *bucket, void *ctxt);
static void lsp_schedule(struct hash_bucket *bucket, void *ctxt);
static wq_item_status lsp_process(struct work_queue *wq, void *data);
static void lsp_processq_del(struct work_queue *wq, void *data);
static void lsp_processq_complete(struct work_queue *wq);
static int lsp_processq_add(struct zebra_lsp *lsp);
static void *lsp_alloc(void *p);

/* Check whether lsp can be freed - no nhlfes, e.g., and call free api */
static void lsp_check_free(struct hash *lsp_table, struct zebra_lsp **plsp);

/* Free lsp; sets caller's pointer to NULL */
static void lsp_free(struct hash *lsp_table, struct zebra_lsp **plsp);

static char *nhlfe2str(const struct zebra_nhlfe *nhlfe, char *buf, int size);
static char *nhlfe_config_str(const struct zebra_nhlfe *nhlfe, char *buf,
			      int size);
static int nhlfe_nhop_match(struct zebra_nhlfe *nhlfe,
			    enum nexthop_types_t gtype,
			    const union g_addr *gate, ifindex_t ifindex);
static struct zebra_nhlfe *nhlfe_find(struct nhlfe_list_head *list,
				      enum lsp_types_t lsp_type,
				      enum nexthop_types_t gtype,
				      const union g_addr *gate,
				      ifindex_t ifindex);
static struct zebra_nhlfe *
nhlfe_add(struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
	  enum nexthop_types_t gtype, const union g_addr *gate,
	  ifindex_t ifindex, vrf_id_t vrf_id, uint8_t num_labels,
	  const mpls_label_t *labels, bool is_backup);
static int nhlfe_del(struct zebra_nhlfe *nhlfe);
static void nhlfe_free(struct zebra_nhlfe *nhlfe);
static void nhlfe_out_label_update(struct zebra_nhlfe *nhlfe,
				   struct mpls_label_stack *nh_label);
static int mpls_lsp_uninstall_all(struct hash *lsp_table, struct zebra_lsp *lsp,
				  enum lsp_types_t type);
static int mpls_static_lsp_uninstall_all(struct zebra_vrf *zvrf,
					 mpls_label_t in_label);
static void nhlfe_print(struct zebra_nhlfe *nhlfe, struct vty *vty,
			const char *indent);
static void lsp_print(struct vty *vty, struct zebra_lsp *lsp);
static void mpls_lsp_uninstall_all_type(struct hash_bucket *bucket, void *ctxt);
static void mpls_ftn_uninstall_all(struct zebra_vrf *zvrf,
				   int afi, enum lsp_types_t lsp_type);
static int lsp_znh_install(struct zebra_lsp *lsp, enum lsp_types_t type,
			   const struct zapi_nexthop *znh);
static int lsp_backup_znh_install(struct zebra_lsp *lsp, enum lsp_types_t type,
				  const struct zapi_nexthop *znh);

/* Static functions */

/*
 * Handle failure in LSP install, clear flags for NHLFE.
 */
static void clear_nhlfe_installed(struct zebra_lsp *lsp)
{
	struct zebra_nhlfe *nhlfe;
	struct nexthop *nexthop;

	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
	}

	frr_each_safe(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
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

	/* For each active nexthop, create NHLFE. Note that we deliberately skip
	 * recursive nexthops right now, because intermediate hops won't
	 * understand
	 * the label advertised by the recursive nexthop (plus we don't have the
	 * logic yet to push multiple labels).
	 */
	for (nexthop = re->nhe->nhg.nexthop;
	     nexthop; nexthop = nexthop->next) {
		/* Skip inactive and recursive entries. */
		if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		nhlfe = nhlfe_find(&lsp->nhlfe_list, lsp_type,
				   nexthop->type, &nexthop->gate,
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
					"LSP in-label %u type %d nexthop %s out-label changed",
					lsp->ile.in_label, lsp_type, buf);
			}

			/* Update out label, trigger processing. */
			nhlfe_out_label_update(nhlfe, nexthop->nh_label);
			SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);
			changed++;
		} else {
			/* Add LSP entry to this nexthop */
			nhlfe = nhlfe_add(
				lsp, lsp_type, nexthop->type, &nexthop->gate,
				nexthop->ifindex, nexthop->vrf_id,
				nexthop->nh_label->num_labels,
				nexthop->nh_label->label, false /*backup*/);
			if (!nhlfe)
				return -1;

			if (IS_ZEBRA_DEBUG_MPLS) {
				nhlfe2str(nhlfe, buf, BUFSIZ);
				zlog_debug(
					"Add LSP in-label %u type %d nexthop %s out-label %u",
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
	} else {
		lsp_check_free(lsp_table, &lsp);
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	char buf[BUFSIZ];

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp || (nhlfe_list_first(&lsp->nhlfe_list) == NULL))
		return 0;

	/* Mark NHLFEs for delete or directly delete, as appropriate. */
	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {

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
	} else {
		lsp_check_free(lsp_table, &lsp);
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
	struct zebra_fec *fec;
	uint32_t old_label, new_label;
	int af;

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
					"Update fec %pRN new label %u upon label block",
					rn, new_label);

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
static uint32_t fec_derive_label_from_index(struct zebra_vrf *zvrf,
					    struct zebra_fec *fec)
{
	uint32_t label;

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
static int fec_change_update_lsp(struct zebra_vrf *zvrf, struct zebra_fec *fec,
				 mpls_label_t old_label)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	afi_t afi;

	/* Uninstall label forwarding entry, if previously installed. */
	if (old_label != MPLS_INVALID_LABEL
	    && old_label != MPLS_LABEL_IMPLICIT_NULL)
		lsp_uninstall(zvrf, old_label);

	/* Install label forwarding entry corr. to new label, if needed. */
	if (fec->label == MPLS_INVALID_LABEL
	    || fec->label == MPLS_LABEL_IMPLICIT_NULL)
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
static int fec_send(struct zebra_fec *fec, struct zserv *client)
{
	struct stream *s;
	struct route_node *rn;

	rn = fec->rn;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_FEC_UPDATE, VRF_DEFAULT);

	stream_putw(s, rn->p.family);
	stream_put_prefix(s, &rn->p);
	stream_putl(s, fec->label);
	stream_putw_at(s, 0, stream_get_endp(s));
	return zserv_send_message(client, s);
}

/*
 * Update all registered clients about this FEC. Caller should've updated
 * FEC and ensure no duplicate updates.
 */
static void fec_update_clients(struct zebra_fec *fec)
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
static void fec_print(struct zebra_fec *fec, struct vty *vty)
{
	struct route_node *rn;
	struct listnode *node;
	struct zserv *client;
	char buf[BUFSIZ];

	rn = fec->rn;
	vty_out(vty, "%pRN\n", rn);
	vty_out(vty, "  Label: %s", label2str(fec->label, 0, buf, BUFSIZ));
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
static struct zebra_fec *fec_find(struct route_table *table, struct prefix *p)
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
static struct zebra_fec *fec_add(struct route_table *table, struct prefix *p,
				 mpls_label_t label, uint32_t flags,
				 uint32_t label_index)
{
	struct route_node *rn;
	struct zebra_fec *fec;

	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(table, p);
	if (!rn)
		return NULL;

	fec = rn->info;

	if (!fec) {
		fec = XCALLOC(MTYPE_FEC, sizeof(struct zebra_fec));

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
static int fec_del(struct zebra_fec *fec)
{
	list_delete(&fec->client_list);
	fec->rn->info = NULL;
	route_unlock_node(fec->rn);
	XFREE(MTYPE_FEC, fec);
	return 0;
}

/*
 * Hash function for label.
 */
static unsigned int label_hash(const void *p)
{
	const struct zebra_ile *ile = p;

	return (jhash_1word(ile->in_label, 0));
}

/*
 * Compare 2 LSP hash entries based on in-label.
 */
static bool label_cmp(const void *p1, const void *p2)
{
	const struct zebra_ile *ile1 = p1;
	const struct zebra_ile *ile2 = p2;

	return (ile1->in_label == ile2->in_label);
}

/*
 * Check if an IPv4 nexthop for a NHLFE is active. Update nexthop based on
 * the passed flag.
 * NOTE: Looking only for connected routes right now.
 */
static int nhlfe_nexthop_active_ipv4(struct zebra_nhlfe *nhlfe,
				     struct nexthop *nexthop)
{
	struct route_table *table;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct route_entry *match;
	struct nexthop *match_nh;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, nexthop->vrf_id);
	if (!table)
		return 0;

	/* Lookup nexthop in IPv4 routing table. */
	memset(&p, 0, sizeof(p));
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
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

		for (match_nh = match->nhe->nhg.nexthop; match_nh;
		     match_nh = match_nh->next) {
			if ((match->type == ZEBRA_ROUTE_CONNECT ||
			     match->type == ZEBRA_ROUTE_LOCAL) ||
			    nexthop->ifindex == match_nh->ifindex) {
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
static int nhlfe_nexthop_active_ipv6(struct zebra_nhlfe *nhlfe,
				     struct nexthop *nexthop)
{
	struct route_table *table;
	struct prefix_ipv6 p;
	struct route_node *rn;
	struct route_entry *match;

	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, nexthop->vrf_id);
	if (!table)
		return 0;

	/* Lookup nexthop in IPv6 routing table. */
	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = nexthop->gate.ipv6;

	rn = route_node_match(table, (struct prefix *)&p);
	if (!rn)
		return 0;

	route_unlock_node(rn);

	/* Locate a valid connected route. */
	RNODE_FOREACH_RE (rn, match) {
		if (((match->type == ZEBRA_ROUTE_CONNECT ||
		      match->type == ZEBRA_ROUTE_LOCAL)) &&
		    !CHECK_FLAG(match->status, ROUTE_ENTRY_REMOVED) &&
		    CHECK_FLAG(match->flags, ZEBRA_FLAG_SELECTED))
			break;
	}

	if (!match || !match->nhe->nhg.nexthop)
		return 0;

	nexthop->ifindex = match->nhe->nhg.nexthop->ifindex;
	return 1;
}


/*
 * Check the nexthop reachability for a NHLFE and return if valid (reachable)
 * or not.
 * NOTE: Each NHLFE points to only 1 nexthop.
 */
static int nhlfe_nexthop_active(struct zebra_nhlfe *nhlfe)
{
	struct nexthop *nexthop;
	struct interface *ifp;
	struct zebra_ns *zns;

	nexthop = nhlfe->nexthop;
	if (!nexthop) // unexpected
		return 0;

	/* Check on nexthop based on type. */
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		/*
		 * Lookup if this type is special.  The
		 * NEXTHOP_TYPE_IFINDEX is a pop and
		 * forward into a different table for
		 * processing.  As such this ifindex
		 * passed to us may be a VRF device
		 * which will not be in the default
		 * VRF.  So let's look in all of them
		 */
		zns = zebra_ns_lookup(NS_DEFAULT);
		ifp = if_lookup_by_index_per_ns(zns, nexthop->ifindex);
		if (ifp && if_is_operative(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
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
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);
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

	case NEXTHOP_TYPE_BLACKHOLE:
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
static void lsp_select_best_nhlfe(struct zebra_lsp *lsp)
{
	struct zebra_nhlfe *nhlfe;
	struct zebra_nhlfe *best;
	struct nexthop *nexthop;
	int changed = 0;

	if (!lsp)
		return;

	best = NULL;
	lsp->num_ecmp = 0;
	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);

	/*
	 * First compute the best path, after checking nexthop status. We are
	 * only concerned with non-deleted NHLFEs.
	 */
	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
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

	/*
	 * Check the active status of backup nhlfes also
	 */
	frr_each_safe(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			(void)nhlfe_nexthop_active(nhlfe);
	}

	/* Mark best NHLFE as selected. */
	SET_FLAG(lsp->best_nhlfe->flags, NHLFE_FLAG_SELECTED);

	/*
	 * If best path exists, see if there is ECMP. While doing this, note if
	 * a
	 * new (uninstalled) NHLFE has been selected, an installed entry that is
	 * still selected has a change or an installed entry is to be removed.
	 */
	frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
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
static void lsp_uninstall_from_kernel(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_lsp *lsp;

	lsp = (struct zebra_lsp *)bucket->data;
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		(void)dplane_lsp_delete(lsp);
}

/*
 * Schedule LSP forwarding entry for processing. Called upon changes
 * that may impact LSPs such as nexthop / connected route changes.
 */
static void lsp_schedule(struct hash_bucket *bucket, void *ctxt)
{
	struct zebra_lsp *lsp;

	lsp = (struct zebra_lsp *)bucket->data;

	/* In the common flow, this is used when external events occur. For
	 * LSPs with backup nhlfes, we'll assume that the forwarding
	 * plane will use the backups to handle these events, until the
	 * owning protocol can react.
	 */
	if (ctxt == NULL) {
		/* Skip LSPs with backups */
		if (nhlfe_list_first(&lsp->backup_nhlfe_list) != NULL) {
			if (IS_ZEBRA_DEBUG_MPLS_DETAIL)
				zlog_debug("%s: skip LSP in-label %u",
					   __func__, lsp->ile.in_label);
			return;
		}
	}

	(void)lsp_processq_add(lsp);
}

/*
 * Process a LSP entry that is in the queue. Recalculate best NHLFE and
 * any multipaths and update or delete from the kernel, as needed.
 */
static wq_item_status lsp_process(struct work_queue *wq, void *data)
{
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *oldbest, *newbest;
	char buf[BUFSIZ], buf2[BUFSIZ];
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	enum zebra_dplane_result res;

	lsp = (struct zebra_lsp *)data;
	if (!lsp) // unexpected
		return WQ_SUCCESS;

	oldbest = lsp->best_nhlfe;

	/* Select best NHLFE(s) */
	lsp_select_best_nhlfe(lsp);

	newbest = lsp->best_nhlfe;

	if (IS_ZEBRA_DEBUG_MPLS) {
		if (oldbest)
			nhlfe2str(oldbest, buf, sizeof(buf));
		if (newbest)
			nhlfe2str(newbest, buf2, sizeof(buf2));
		zlog_debug(
			"Process LSP in-label %u oldbest %s newbest %s flags 0x%x ecmp# %d",
			lsp->ile.in_label, oldbest ? buf : "NULL",
			newbest ? buf2 : "NULL", lsp->flags, lsp->num_ecmp);
	}

	if (!CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED)) {
		/* Not already installed */
		if (newbest) {

			UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);

			switch (dplane_lsp_add(lsp)) {
			case ZEBRA_DPLANE_REQUEST_QUEUED:
				/* Set 'installed' flag so we will know
				 * that an install is in-flight.
				 */
				SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

				zvrf->lsp_installs_queued++;
				break;
			case ZEBRA_DPLANE_REQUEST_FAILURE:
				flog_warn(EC_ZEBRA_LSP_INSTALL_FAILURE,
					  "LSP Install Failure: %u",
					  lsp->ile.in_label);
				break;
			case ZEBRA_DPLANE_REQUEST_SUCCESS:
				zvrf->lsp_installs++;
				break;
			}
		}
	} else {
		/* Installed, may need an update and/or delete. */
		if (!newbest) {
			res = dplane_lsp_delete(lsp);

			/* We do some of the lsp cleanup immediately for
			 * deletes.
			 */
			UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
			clear_nhlfe_installed(lsp);

			switch (res) {
			case ZEBRA_DPLANE_REQUEST_QUEUED:
				zvrf->lsp_removals_queued++;
				break;
			case ZEBRA_DPLANE_REQUEST_FAILURE:
				flog_warn(EC_ZEBRA_LSP_DELETE_FAILURE,
					  "LSP Deletion Failure: %u",
					  lsp->ile.in_label);
				break;
			case ZEBRA_DPLANE_REQUEST_SUCCESS:
				zvrf->lsp_removals++;
				break;
			}
		} else if (CHECK_FLAG(lsp->flags, LSP_FLAG_CHANGED)) {
			struct zebra_nhlfe *nhlfe;
			struct nexthop *nexthop;

			UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);

			/* We leave the INSTALLED flag set here
			 * so we know an update is in-flight.
			 */

			/*
			 * Any NHLFE that was installed but is not
			 * selected now needs to have its flags updated.
			 */
			frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
				nexthop = nhlfe->nexthop;
				if (!nexthop)
					continue;

				if (CHECK_FLAG(nhlfe->flags,
					       NHLFE_FLAG_INSTALLED)
				    && !CHECK_FLAG(nhlfe->flags,
						   NHLFE_FLAG_SELECTED)) {
					UNSET_FLAG(nhlfe->flags,
						   NHLFE_FLAG_INSTALLED);
					UNSET_FLAG(nexthop->flags,
						   NEXTHOP_FLAG_FIB);
				}
			}

			switch (dplane_lsp_update(lsp)) {
			case ZEBRA_DPLANE_REQUEST_QUEUED:
				zvrf->lsp_installs_queued++;
				break;
			case ZEBRA_DPLANE_REQUEST_FAILURE:
				flog_warn(EC_ZEBRA_LSP_INSTALL_FAILURE,
					  "LSP Update Failure: %u",
					  lsp->ile.in_label);
				break;
			case ZEBRA_DPLANE_REQUEST_SUCCESS:
				zvrf->lsp_installs++;
				break;
			}
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
	struct zebra_lsp *lsp;
	struct hash *lsp_table;
	struct zebra_nhlfe *nhlfe;

	/* If zebra is shutting down, don't delete any structs,
	 * just ignore this callback. The LSPs will be cleaned up
	 * during the shutdown processing.
	 */
	if (zebra_router_in_shutdown())
		return;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	lsp_table = zvrf->lsp_table;
	if (!lsp_table) // unexpected
		return;

	lsp = (struct zebra_lsp *)data;
	if (!lsp) // unexpected
		return;

	/* Clear flag, remove any NHLFEs marked for deletion. If no NHLFEs
	 * exist,
	 * delete LSP entry also.
	 */
	UNSET_FLAG(lsp->flags, LSP_FLAG_SCHEDULED);

	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			nhlfe_del(nhlfe);
	}

	frr_each_safe(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
		if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			nhlfe_del(nhlfe);
	}

	lsp_check_free(lsp_table, &lsp);
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
static int lsp_processq_add(struct zebra_lsp *lsp)
{
	/* If already scheduled, exit. */
	if (CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED))
		return 0;

	if (zrouter.lsp_process_q == NULL) {
		flog_err(EC_ZEBRA_WQ_NONEXISTENT,
			 "%s: work_queue does not exist!", __func__);
		return -1;
	}

	work_queue_add(zrouter.lsp_process_q, lsp);
	SET_FLAG(lsp->flags, LSP_FLAG_SCHEDULED);
	return 0;
}

/*
 * Callback to allocate LSP forwarding table entry.
 */
static void *lsp_alloc(void *p)
{
	const struct zebra_ile *ile = p;
	struct zebra_lsp *lsp;

	lsp = XCALLOC(MTYPE_LSP, sizeof(struct zebra_lsp));
	lsp->ile = *ile;
	nhlfe_list_init(&lsp->nhlfe_list);
	nhlfe_list_init(&lsp->backup_nhlfe_list);

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("Alloc LSP in-label %u", lsp->ile.in_label);

	return ((void *)lsp);
}

/*
 * Check whether lsp can be freed - no nhlfes, e.g., and call free api
 */
static void lsp_check_free(struct hash *lsp_table, struct zebra_lsp **plsp)
{
	struct zebra_lsp *lsp;

	if (plsp == NULL || *plsp == NULL)
		return;

	lsp = *plsp;

	if ((nhlfe_list_first(&lsp->nhlfe_list) == NULL) &&
	    (nhlfe_list_first(&lsp->backup_nhlfe_list) == NULL) &&
	    !CHECK_FLAG(lsp->flags, LSP_FLAG_SCHEDULED))
		lsp_free(lsp_table, plsp);
}

static void lsp_free_nhlfe(struct zebra_lsp *lsp)
{
	struct zebra_nhlfe *nhlfe;

	while ((nhlfe = nhlfe_list_first(&lsp->nhlfe_list))) {
		nhlfe_list_del(&lsp->nhlfe_list, nhlfe);
		nhlfe_free(nhlfe);
	}

	while ((nhlfe = nhlfe_list_first(&lsp->backup_nhlfe_list))) {
		nhlfe_list_del(&lsp->backup_nhlfe_list, nhlfe);
		nhlfe_free(nhlfe);
	}
}

/*
 * Dtor for an LSP: remove from ile hash, release any internal allocations,
 * free LSP object.
 */
static void lsp_free(struct hash *lsp_table, struct zebra_lsp **plsp)
{
	struct zebra_lsp *lsp;

	if (plsp == NULL || *plsp == NULL)
		return;

	lsp = *plsp;

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("Free LSP in-label %u flags 0x%x",
			   lsp->ile.in_label, lsp->flags);

	lsp_free_nhlfe(lsp);

	hash_release(lsp_table, &lsp->ile);
	XFREE(MTYPE_LSP, lsp);

	*plsp = NULL;
}

/*
 * Create printable string for NHLFE entry.
 */
static char *nhlfe2str(const struct zebra_nhlfe *nhlfe, char *buf, int size)
{
	const struct nexthop *nexthop;

	buf[0] = '\0';
	nexthop = nhlfe->nexthop;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &nexthop->gate.ipv4, buf, size);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, size);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		snprintf(buf, size, "Ifindex: %u", nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	return buf;
}

/*
 * Check if NHLFE matches with search info passed.
 */
static int nhlfe_nhop_match(struct zebra_nhlfe *nhlfe,
			    enum nexthop_types_t gtype,
			    const union g_addr *gate, ifindex_t ifindex)
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
	case NEXTHOP_TYPE_IFINDEX:
		cmp = !(nhop->ifindex == ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	return cmp;
}


/*
 * Locate NHLFE that matches with passed info.
 * TODO: handle vrf_id if vrf backend is netns based
 */
static struct zebra_nhlfe *nhlfe_find(struct nhlfe_list_head *list,
				      enum lsp_types_t lsp_type,
				      enum nexthop_types_t gtype,
				      const union g_addr *gate,
				      ifindex_t ifindex)
{
	struct zebra_nhlfe *nhlfe;

	frr_each_safe(nhlfe_list, list, nhlfe) {
		if (nhlfe->type != lsp_type)
			continue;
		if (!nhlfe_nhop_match(nhlfe, gtype, gate, ifindex))
			break;
	}

	return nhlfe;
}

/*
 * Allocate and init new NHLFE.
 */
static struct zebra_nhlfe *
nhlfe_alloc(struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
	    enum nexthop_types_t gtype, const union g_addr *gate,
	    ifindex_t ifindex, vrf_id_t vrf_id, uint8_t num_labels,
	    const mpls_label_t *labels)
{
	struct zebra_nhlfe *nhlfe;
	struct nexthop *nexthop;

	assert(lsp);

	nhlfe = XCALLOC(MTYPE_NHLFE, sizeof(struct zebra_nhlfe));

	nhlfe->lsp = lsp;
	nhlfe->type = lsp_type;
	nhlfe->distance = lsp_distance(lsp_type);

	nexthop = nexthop_new();

	nexthop_add_labels(nexthop, lsp_type, num_labels, labels);

	nexthop->vrf_id = vrf_id;
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
	case NEXTHOP_TYPE_IFINDEX:
		nexthop->ifindex = ifindex;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("%s: invalid: blackhole nexthop", __func__);

		nexthop_free(nexthop);
		XFREE(MTYPE_NHLFE, nhlfe);
		return NULL;
	}
	nhlfe->nexthop = nexthop;

	return nhlfe;
}

/*
 * Add primary or backup NHLFE. Base entry must have been created and
 * duplicate check done.
 */
static struct zebra_nhlfe *
nhlfe_add(struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
	  enum nexthop_types_t gtype, const union g_addr *gate,
	  ifindex_t ifindex, vrf_id_t vrf_id, uint8_t num_labels,
	  const mpls_label_t *labels, bool is_backup)
{
	struct zebra_nhlfe *nhlfe;

	if (!lsp)
		return NULL;

	/* Allocate new object */
	nhlfe = nhlfe_alloc(lsp, lsp_type, gtype, gate, ifindex, vrf_id,
			    num_labels, labels);

	if (!nhlfe)
		return NULL;

	/* Enqueue to LSP: primaries at head of list, backups at tail */
	if (is_backup) {
		SET_FLAG(nhlfe->flags, NHLFE_FLAG_IS_BACKUP);
		nhlfe_list_add_tail(&lsp->backup_nhlfe_list, nhlfe);
	} else
		nhlfe_list_add_head(&lsp->nhlfe_list, nhlfe);

	return nhlfe;
}

/*
 * Common delete for NHLFEs.
 */
static void nhlfe_free(struct zebra_nhlfe *nhlfe)
{
	if (!nhlfe)
		return;

	/* Free nexthop. */
	if (nhlfe->nexthop)
		nexthop_free(nhlfe->nexthop);

	nhlfe->nexthop = NULL;

	XFREE(MTYPE_NHLFE, nhlfe);
}


/*
 * Disconnect NHLFE from LSP, and free. Entry must be present on LSP's list.
 */
static int nhlfe_del(struct zebra_nhlfe *nhlfe)
{
	struct zebra_lsp *lsp;

	if (!nhlfe)
		return -1;

	lsp = nhlfe->lsp;
	if (!lsp)
		return -1;

	if (nhlfe == lsp->best_nhlfe)
		lsp->best_nhlfe = NULL;

	/* Unlink from LSP */
	if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_IS_BACKUP))
		nhlfe_list_del(&lsp->backup_nhlfe_list, nhlfe);
	else
		nhlfe_list_del(&lsp->nhlfe_list, nhlfe);

	nhlfe->lsp = NULL;

	nhlfe_free(nhlfe);

	return 0;
}

/*
 * Update label for NHLFE entry.
 */
static void nhlfe_out_label_update(struct zebra_nhlfe *nhlfe,
				   struct mpls_label_stack *nh_label)
{
	nhlfe->nexthop->nh_label->label[0] = nh_label->label[0];
}

static int mpls_lsp_uninstall_all(struct hash *lsp_table, struct zebra_lsp *lsp,
				  enum lsp_types_t type)
{
	struct zebra_nhlfe *nhlfe;
	int schedule_lsp = 0;
	char buf[BUFSIZ];

	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		schedule_lsp = 1;

	/* Mark NHLFEs for delete or directly delete, as appropriate. */
	frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		/* Skip non-static NHLFEs */
		if (nhlfe->type != type)
			continue;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, sizeof(buf));
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

	frr_each_safe(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
		/* Skip non-static NHLFEs */
		if (nhlfe->type != type)
			continue;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, sizeof(buf));
			zlog_debug(
				"Del backup LSP in-label %u type %d nexthop %s flags 0x%x",
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
		if (IS_ZEBRA_DEBUG_MPLS) {
			zlog_debug("Schedule LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);
		}
		if (lsp_processq_add(lsp))
			return -1;
	} else {
		lsp_check_free(lsp_table, &lsp);
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp || (nhlfe_list_first(&lsp->nhlfe_list) == NULL))
		return 0;

	return mpls_lsp_uninstall_all(lsp_table, lsp, ZEBRA_LSP_STATIC);
}

static json_object *nhlfe_json(struct zebra_nhlfe *nhlfe)
{
	json_object *json_nhlfe = NULL;
	json_object *json_backups = NULL;
	json_object *json_label_stack;
	struct nexthop *nexthop = nhlfe->nexthop;
	int i;

	json_nhlfe = json_object_new_object();
	json_object_string_add(json_nhlfe, "type", nhlfe_type2str(nhlfe->type));
	if (nexthop->nh_label) {
		json_object_int_add(json_nhlfe, "outLabel",
				    nexthop->nh_label->label[0]);
		json_label_stack = json_object_new_array();
		json_object_object_add(json_nhlfe, "outLabelStack",
				       json_label_stack);
		for (i = 0; i < nexthop->nh_label->num_labels; i++)
			json_object_array_add(
				json_label_stack,
				json_object_new_int(
					nexthop->nh_label->label[i]));
	}
	json_object_int_add(json_nhlfe, "distance", nhlfe->distance);

	if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED))
		json_object_boolean_true_add(json_nhlfe, "installed");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		json_object_string_addf(json_nhlfe, "nexthop", "%pI4",
					&nexthop->gate.ipv4);
		if (nexthop->ifindex)
			json_object_string_add(json_nhlfe, "interface",
					       ifindex2ifname(nexthop->ifindex,
							      nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		json_object_string_addf(json_nhlfe, "nexthop", "%pI6",
					&nexthop->gate.ipv6);

		if (nexthop->ifindex)
			json_object_string_add(json_nhlfe, "interface",
					       ifindex2ifname(nexthop->ifindex,
							      nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IFINDEX:
		if (nexthop->ifindex)
			json_object_string_add(json_nhlfe, "interface",
					       ifindex2ifname(nexthop->ifindex,
							      nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		json_backups = json_object_new_array();
		for (i = 0; i < nexthop->backup_num; i++) {
			json_object_array_add(
				json_backups,
				json_object_new_int(nexthop->backup_idx[i]));
		}

		json_object_object_add(json_nhlfe, "backupIndex",
				       json_backups);
	}

	return json_nhlfe;
}

/*
 * Print the NHLFE for a LSP forwarding entry.
 */
static void nhlfe_print(struct zebra_nhlfe *nhlfe, struct vty *vty,
			const char *indent)
{
	struct nexthop *nexthop;
	char buf[MPLS_LABEL_STRLEN];

	nexthop = nhlfe->nexthop;
	if (!nexthop || !nexthop->nh_label) // unexpected
		return;

	vty_out(vty, " type: %s remote label: %s distance: %d\n",
		nhlfe_type2str(nhlfe->type),
		mpls_label2str(nexthop->nh_label->num_labels,
			       nexthop->nh_label->label, buf, sizeof(buf),
			       nexthop->nh_label_type, 0),
		nhlfe->distance);

	if (indent)
		vty_out(vty, "%s", indent);

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, "  via %pI4", &nexthop->gate.ipv4);
		if (nexthop->ifindex)
			vty_out(vty, " dev %s",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, "  via %s",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf,
				  sizeof(buf)));
		if (nexthop->ifindex)
			vty_out(vty, " dev %s",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_IFINDEX:
		if (nexthop->ifindex)
			vty_out(vty, "  dev %s",
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}
	vty_out(vty, "%s",
		CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_IS_BACKUP) ? " (backup)"
							       : "");
	vty_out(vty, "%s",
		CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED) ? " (installed)"
							       : "");
	vty_out(vty, "\n");
}

/*
 * Print an LSP forwarding entry.
 */
static void lsp_print(struct vty *vty, struct zebra_lsp *lsp)
{
	struct zebra_nhlfe *nhlfe, *backup;
	int i, j;

	vty_out(vty, "Local label: %u%s\n", lsp->ile.in_label,
		CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED) ? " (installed)"
							   : "");

	frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
		nhlfe_print(nhlfe, vty, NULL);

		if (nhlfe->nexthop == NULL ||
		    !CHECK_FLAG(nhlfe->nexthop->flags,
				NEXTHOP_FLAG_HAS_BACKUP))
			continue;

		/* Backup nhlfes: find backups in backup list */

		for (j = 0; j < nhlfe->nexthop->backup_num; j++) {
			i = 0;
			backup = NULL;
			frr_each(nhlfe_list, &lsp->backup_nhlfe_list, backup) {
				if (i == nhlfe->nexthop->backup_idx[j])
					break;
				i++;
			}

			if (backup) {
				vty_out(vty, "   [backup %d]", i);
				nhlfe_print(backup, vty, "   ");
			}
		}
	}
}

/*
 * JSON objects for an LSP forwarding entry.
 */
static json_object *lsp_json(struct zebra_lsp *lsp)
{
	struct zebra_nhlfe *nhlfe = NULL;
	json_object *json = json_object_new_object();
	json_object *json_nhlfe_list = json_object_new_array();

	json_object_int_add(json, "inLabel", lsp->ile.in_label);

	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		json_object_boolean_true_add(json, "installed");

	frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe)
		json_object_array_add(json_nhlfe_list, nhlfe_json(nhlfe));

	json_object_object_add(json, "nexthops", json_nhlfe_list);
	json_nhlfe_list = NULL;


	frr_each(nhlfe_list, &lsp->backup_nhlfe_list, nhlfe) {
		if (json_nhlfe_list == NULL)
			json_nhlfe_list = json_object_new_array();

		json_object_array_add(json_nhlfe_list, nhlfe_json(nhlfe));
	}

	if (json_nhlfe_list)
		json_object_object_add(json, "backupNexthops", json_nhlfe_list);

	return json;
}


/* Return a sorted linked list of the hash contents */
static struct list *hash_get_sorted_list(struct hash *hash, void *cmp)
{
	unsigned int i;
	struct hash_bucket *hb;
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
static int lsp_cmp(const struct zebra_lsp *lsp1, const struct zebra_lsp *lsp2)
{
	if (lsp1->ile.in_label < lsp2->ile.in_label)
		return -1;

	if (lsp1->ile.in_label > lsp2->ile.in_label)
		return 1;

	return 0;
}

/*
 * Initialize work queue for processing changed LSPs.
 */
static void mpls_processq_init(void)
{
	zrouter.lsp_process_q = work_queue_new(zrouter.master, "LSP processing");

	zrouter.lsp_process_q->spec.workfunc = &lsp_process;
	zrouter.lsp_process_q->spec.del_item_data = &lsp_processq_del;
	zrouter.lsp_process_q->spec.completion_func = &lsp_processq_complete;
	zrouter.lsp_process_q->spec.max_retries = 0;
	zrouter.lsp_process_q->spec.hold = 10;
}


/*
 * Process LSP update results from zebra dataplane.
 */
void zebra_mpls_lsp_dplane_result(struct zebra_dplane_ctx *ctx)
{
	struct zebra_vrf *zvrf;
	mpls_label_t label;
	struct zebra_ile tmp_ile;
	struct hash *lsp_table;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	struct nexthop *nexthop;
	enum dplane_op_e op;
	enum zebra_dplane_result status;
	enum zebra_sr_policy_update_label_mode update_mode;

	op = dplane_ctx_get_op(ctx);
	status = dplane_ctx_get_status(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug("LSP dplane ctx %p, op %s, in-label %u, result %s",
			   ctx, dplane_op2str(op),
			   dplane_ctx_get_in_label(ctx),
			   dplane_res2str(status));

	label = dplane_ctx_get_in_label(ctx);

	if (op == DPLANE_OP_LSP_INSTALL || op == DPLANE_OP_LSP_UPDATE) {
		/* Look for zebra LSP object */
		zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
		lsp_table = zvrf->lsp_table;

		tmp_ile.in_label = label;
		lsp = hash_lookup(lsp_table, &tmp_ile);
		if (lsp == NULL) {
			if (IS_ZEBRA_DEBUG_DPLANE)
				zlog_debug("LSP ctx %p: in-label %u not found",
					   ctx, dplane_ctx_get_in_label(ctx));
			return;
		}

		/* TODO -- Confirm that this result is still 'current' */

		if (status != ZEBRA_DPLANE_REQUEST_SUCCESS) {
			UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
			clear_nhlfe_installed(lsp);
			flog_warn(EC_ZEBRA_LSP_INSTALL_FAILURE,
				  "LSP Install Failure: in-label %u",
				  lsp->ile.in_label);
			return;
		}

		/* Update zebra object */
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
		frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
			nexthop = nhlfe->nexthop;
			if (!nexthop)
				continue;

			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED) &&
			    CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				SET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			}
		}

		update_mode = (op == DPLANE_OP_LSP_INSTALL)
				      ? ZEBRA_SR_POLICY_LABEL_CREATED
				      : ZEBRA_SR_POLICY_LABEL_UPDATED;
		zebra_sr_policy_label_update(label, update_mode);
	} else if (op == DPLANE_OP_LSP_DELETE) {
		if (status != ZEBRA_DPLANE_REQUEST_SUCCESS) {
			flog_warn(EC_ZEBRA_LSP_DELETE_FAILURE,
				  "LSP Deletion Failure: in-label %u",
				  dplane_ctx_get_in_label(ctx));
			return;
		}
		zebra_sr_policy_label_update(label,
					     ZEBRA_SR_POLICY_LABEL_REMOVED);
	}
}

/*
 * Process LSP installation info from two sets of nhlfes: a set from
 * a dplane notification, and a set from the zebra LSP object. Update
 * counters of installed nexthops, and return whether the LSP has changed.
 */
static bool compare_notif_nhlfes(const struct nhlfe_list_head *ctx_head,
				 struct nhlfe_list_head *nhlfe_head,
				 int *start_counter, int *end_counter)
{
	struct zebra_nhlfe *nhlfe;
	const struct zebra_nhlfe *ctx_nhlfe;
	struct nexthop *nexthop;
	const struct nexthop *ctx_nexthop;
	int start_count = 0, end_count = 0;
	bool changed_p = false;
	bool is_debug = (IS_ZEBRA_DEBUG_DPLANE | IS_ZEBRA_DEBUG_MPLS);

	frr_each_safe(nhlfe_list, nhlfe_head, nhlfe) {
		char buf[NEXTHOP_STRLEN];

		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))
			start_count++;

		ctx_nhlfe = NULL;
		ctx_nexthop = NULL;
		frr_each(nhlfe_list_const, ctx_head, ctx_nhlfe) {
			ctx_nexthop = ctx_nhlfe->nexthop;
			if (!ctx_nexthop)
				continue;

			if ((ctx_nexthop->type == nexthop->type) &&
			    nexthop_same(ctx_nexthop, nexthop)) {
				/* Matched */
				break;
			}
		}

		if (is_debug)
			nexthop2str(nexthop, buf, sizeof(buf));

		if (ctx_nhlfe && ctx_nexthop) {
			if (is_debug) {
				const char *tstr = "";

				if (!CHECK_FLAG(ctx_nhlfe->flags,
						NHLFE_FLAG_INSTALLED))
					tstr = "not ";

				zlog_debug("LSP dplane notif: matched nh %s (%sinstalled)",
					   buf, tstr);
			}

			/* Test zebra nhlfe install state */
			if (CHECK_FLAG(ctx_nhlfe->flags,
				       NHLFE_FLAG_INSTALLED)) {

				if (!CHECK_FLAG(nhlfe->flags,
						NHLFE_FLAG_INSTALLED))
					changed_p = true;

				/* Update counter */
				end_count++;
			} else {

				if (CHECK_FLAG(nhlfe->flags,
					       NHLFE_FLAG_INSTALLED))
					changed_p = true;
			}

		} else {
			/* Not mentioned in lfib set -> uninstalled */
			if (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED) ||
			    CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) ||
			    CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
				changed_p = true;
			}

			if (is_debug)
				zlog_debug("LSP dplane notif: no match, nh %s",
					   buf);
		}
	}

	if (start_counter)
		*start_counter += start_count;
	if (end_counter)
		*end_counter += end_count;

	return changed_p;
}

/*
 * Update an lsp nhlfe list from a dplane context, typically an async
 * notification context. Update the LSP list to match the installed
 * status from the context's list.
 */
static int update_nhlfes_from_ctx(struct nhlfe_list_head *nhlfe_head,
				  const struct nhlfe_list_head *ctx_head)
{
	int ret = 0;
	struct zebra_nhlfe *nhlfe;
	const struct zebra_nhlfe *ctx_nhlfe;
	struct nexthop *nexthop;
	const struct nexthop *ctx_nexthop;
	bool is_debug = (IS_ZEBRA_DEBUG_DPLANE | IS_ZEBRA_DEBUG_MPLS);

	frr_each_safe(nhlfe_list, nhlfe_head, nhlfe) {
		char buf[NEXTHOP_STRLEN];

		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		ctx_nhlfe = NULL;
		ctx_nexthop = NULL;
		frr_each(nhlfe_list_const, ctx_head, ctx_nhlfe) {
			ctx_nexthop = ctx_nhlfe->nexthop;
			if (!ctx_nexthop)
				continue;

			if ((ctx_nexthop->type == nexthop->type) &&
			    nexthop_same(ctx_nexthop, nexthop)) {
				/* Matched */
				break;
			}
		}

		if (is_debug)
			nexthop2str(nexthop, buf, sizeof(buf));

		if (ctx_nhlfe && ctx_nexthop) {

			/* Bring zebra nhlfe install state into sync */
			if (CHECK_FLAG(ctx_nhlfe->flags,
				       NHLFE_FLAG_INSTALLED)) {
				if (is_debug)
					zlog_debug("%s: matched lsp nhlfe %s (installed)",
						   __func__, buf);

				SET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
				SET_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED);

			} else {
				if (is_debug)
					zlog_debug("%s: matched lsp nhlfe %s (not installed)",
						   __func__, buf);

				UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
				UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED);
			}

			if (CHECK_FLAG(ctx_nhlfe->nexthop->flags,
				       NEXTHOP_FLAG_FIB)) {
				SET_FLAG(nhlfe->nexthop->flags,
					 NEXTHOP_FLAG_ACTIVE);
				SET_FLAG(nhlfe->nexthop->flags,
					 NEXTHOP_FLAG_FIB);
			} else {
				UNSET_FLAG(nhlfe->nexthop->flags,
					 NEXTHOP_FLAG_ACTIVE);
				UNSET_FLAG(nhlfe->nexthop->flags,
					   NEXTHOP_FLAG_FIB);
			}

		} else {
			/* Not mentioned in lfib set -> uninstalled */
			if (is_debug)
				zlog_debug("%s: no match for lsp nhlfe %s",
					   __func__, buf);
			UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
			UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED);
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		}
	}

	return ret;
}

/*
 * Process async dplane notifications.
 */
void zebra_mpls_process_dplane_notify(struct zebra_dplane_ctx *ctx)
{
	struct zebra_vrf *zvrf;
	struct zebra_ile tmp_ile;
	struct hash *lsp_table;
	struct zebra_lsp *lsp;
	const struct nhlfe_list_head *ctx_list;
	int start_count = 0, end_count = 0; /* Installed counts */
	bool changed_p = false;
	bool is_debug = (IS_ZEBRA_DEBUG_DPLANE | IS_ZEBRA_DEBUG_MPLS);
	enum zebra_sr_policy_update_label_mode update_mode;

	if (is_debug)
		zlog_debug("LSP dplane notif, in-label %u",
			   dplane_ctx_get_in_label(ctx));

	/* Look for zebra LSP object */
	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	lsp_table = zvrf->lsp_table;

	tmp_ile.in_label = dplane_ctx_get_in_label(ctx);
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (lsp == NULL) {
		if (is_debug)
			zlog_debug("dplane LSP notif: in-label %u not found",
				   dplane_ctx_get_in_label(ctx));
		return;
	}

	/*
	 * The dataplane/forwarding plane is notifying zebra about the state
	 * of the nexthops associated with this LSP. First, we take a
	 * pre-scan pass to determine whether the LSP has transitioned
	 * from installed -> uninstalled. In that case, we need to have
	 * the existing state of the LSP objects available before making
	 * any changes.
	 */
	ctx_list = dplane_ctx_get_nhlfe_list(ctx);

	changed_p = compare_notif_nhlfes(ctx_list, &lsp->nhlfe_list,
					 &start_count, &end_count);

	if (is_debug)
		zlog_debug("LSP dplane notif: lfib start_count %d, end_count %d%s",
			   start_count, end_count,
			   changed_p ? ", changed" : "");

	ctx_list = dplane_ctx_get_backup_nhlfe_list(ctx);

	if (compare_notif_nhlfes(ctx_list, &lsp->backup_nhlfe_list,
				 &start_count, &end_count))
		/* Avoid accidentally setting back to 'false' */
		changed_p = true;

	if (is_debug)
		zlog_debug("LSP dplane notif: lfib backups, start_count %d, end_count %d%s",
			   start_count, end_count,
			   changed_p ? ", changed" : "");

	/*
	 * Has the LSP become uninstalled? We need the existing state of the
	 * nexthops/nhlfes at this point so we know what to delete.
	 */
	if (start_count > 0 && end_count == 0) {
		/* Inform other lfibs */
		dplane_lsp_notif_update(lsp, DPLANE_OP_LSP_DELETE, ctx);
	}

	/*
	 * Now we take a second pass and bring the zebra
	 * nexthop state into sync with the forwarding-plane state.
	 */
	ctx_list = dplane_ctx_get_nhlfe_list(ctx);
	update_nhlfes_from_ctx(&lsp->nhlfe_list, ctx_list);

	ctx_list = dplane_ctx_get_backup_nhlfe_list(ctx);
	update_nhlfes_from_ctx(&lsp->backup_nhlfe_list, ctx_list);

	if (end_count > 0) {
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

		/* SR-TE update too */
		if (start_count == 0)
			update_mode = ZEBRA_SR_POLICY_LABEL_CREATED;
		else
			update_mode = ZEBRA_SR_POLICY_LABEL_UPDATED;
		zebra_sr_policy_label_update(lsp->ile.in_label, update_mode);

		if (changed_p)
			dplane_lsp_notif_update(lsp, DPLANE_OP_LSP_UPDATE, ctx);

	} else {
		/* SR-TE update too */
		zebra_sr_policy_label_update(lsp->ile.in_label,
					     ZEBRA_SR_POLICY_LABEL_REMOVED);

		UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
		clear_nhlfe_installed(lsp);
	}
}

/*
 * Install dynamic LSP entry.
 */
int zebra_mpls_lsp_install(struct zebra_vrf *zvrf, struct route_node *rn,
			   struct route_entry *re)
{
	struct route_table *table;
	struct zebra_fec *fec;

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
	if (fec->label == MPLS_LABEL_IMPLICIT_NULL)
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
	struct zebra_fec *fec;

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
 * Add an NHLFE to an LSP, return the newly-added object. This path only changes
 * the LSP object - nothing is scheduled for processing, for example.
 */
struct zebra_nhlfe *
zebra_mpls_lsp_add_nhlfe(struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
			 enum nexthop_types_t gtype, const union g_addr *gate,
			 ifindex_t ifindex, uint8_t num_labels,
			 const mpls_label_t *out_labels)
{
	/* Just a public pass-through to the internal implementation */
	return nhlfe_add(lsp, lsp_type, gtype, gate, ifindex, VRF_DEFAULT,
			 num_labels, out_labels, false /*backup*/);
}

/*
 * Add a backup NHLFE to an LSP, return the newly-added object.
 * This path only changes the LSP object - nothing is scheduled for
 * processing, for example.
 */
struct zebra_nhlfe *zebra_mpls_lsp_add_backup_nhlfe(
	struct zebra_lsp *lsp, enum lsp_types_t lsp_type,
	enum nexthop_types_t gtype, const union g_addr *gate, ifindex_t ifindex,
	uint8_t num_labels, const mpls_label_t *out_labels)
{
	/* Just a public pass-through to the internal implementation */
	return nhlfe_add(lsp, lsp_type, gtype, gate, ifindex, VRF_DEFAULT,
			 num_labels, out_labels, true);
}

/*
 * Add an NHLFE to an LSP based on a nexthop; return the newly-added object
 */
struct zebra_nhlfe *zebra_mpls_lsp_add_nh(struct zebra_lsp *lsp,
					  enum lsp_types_t lsp_type,
					  const struct nexthop *nh)
{
	struct zebra_nhlfe *nhlfe;

	nhlfe = nhlfe_add(
		lsp, lsp_type, nh->type, &nh->gate, nh->ifindex, nh->vrf_id,
		nh->nh_label ? nh->nh_label->num_labels : 0,
		nh->nh_label ? nh->nh_label->label : NULL, false /*backup*/);

	return nhlfe;
}

/*
 * Add a backup NHLFE to an LSP based on a nexthop;
 * return the newly-added object.
 */
struct zebra_nhlfe *zebra_mpls_lsp_add_backup_nh(struct zebra_lsp *lsp,
						 enum lsp_types_t lsp_type,
						 const struct nexthop *nh)
{
	struct zebra_nhlfe *nhlfe;

	nhlfe = nhlfe_add(lsp, lsp_type, nh->type, &nh->gate, nh->ifindex,
			  nh->vrf_id,
			  nh->nh_label ? nh->nh_label->num_labels : 0,
			  nh->nh_label ? nh->nh_label->label : NULL, true);

	return nhlfe;
}

/*
 * Free an allocated NHLFE
 */
void zebra_mpls_nhlfe_free(struct zebra_nhlfe *nhlfe)
{
	/* Just a pass-through to the internal implementation */
	nhlfe_free(nhlfe);
}

/*
 * Registration from a client for the label binding for a FEC. If a binding
 * already exists, it is informed to the client.
 * NOTE: If there is a manually configured label binding, that is used.
 * Otherwise, if a label index is specified, it means we have to allocate the
 * label from a locally configured label block (SRGB), if one exists and index
 * is acceptable. If no label index then just register the specified label.
 * NOTE2: Either label or label_index is expected to be set to MPLS_INVALID_*
 * by the calling function. Register requests with both will be rejected.
 */
int zebra_mpls_fec_register(struct zebra_vrf *zvrf, struct prefix *p,
			    uint32_t label, uint32_t label_index,
			    struct zserv *client)
{
	struct route_table *table;
	struct zebra_fec *fec;
	bool new_client;
	bool label_change = false;
	uint32_t old_label;
	bool have_label_index = (label_index != MPLS_INVALID_LABEL_INDEX);
	bool is_configured_fec = false; /* indicate statically configured FEC */

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	if (label != MPLS_INVALID_LABEL && have_label_index) {
		flog_err(
			EC_ZEBRA_FEC_LABEL_INDEX_LABEL_CONFLICT,
			"Rejecting FEC register for %pFX with both label %u and Label Index %u specified, client %s",
			p, label, label_index,
			zebra_route_string(client->proto));
		return -1;
	}

	/* Locate FEC */
	fec = fec_find(table, p);
	if (!fec) {
		fec = fec_add(table, p, label, 0, label_index);
		if (!fec) {
			flog_err(
				EC_ZEBRA_FEC_ADD_FAILED,
				"Failed to add FEC %pFX upon register, client %s",
				p, zebra_route_string(client->proto));
			return -1;
		}

		old_label = MPLS_INVALID_LABEL;
		new_client = true;
	} else {
		/* Check if the FEC has been statically defined in the config */
		is_configured_fec = fec->flags & FEC_FLAG_CONFIGURED;
		/* Client may register same FEC with different label index. */
		new_client =
			(listnode_lookup(fec->client_list, client) == NULL);
		if (!new_client && fec->label_index == label_index
		    && fec->label == label)
			/* Duplicate register */
			return 0;

		/* Save current label, update the FEC */
		old_label = fec->label;
		fec->label_index = label_index;
	}

	if (new_client)
		listnode_add(fec->client_list, client);

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("FEC %pFX label%s %u %s by client %s%s", p,
			   have_label_index ? " index" : "",
			   have_label_index ? label_index : label,
			   new_client ? "registered" : "updated",
			   zebra_route_string(client->proto),
			   is_configured_fec
				   ? ", but using statically configured label"
				   : "");

	/* If not a statically configured FEC, derive the local label
	 * from label index or use the provided label
	 */
	if (!is_configured_fec) {
		if (have_label_index)
			fec_derive_label_from_index(zvrf, fec);
		else
			fec->label = label;

		/* If no label change, exit. */
		if (fec->label == old_label)
			return 0;

		label_change = true;
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
	struct zebra_fec *fec;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	fec = fec_find(table, p);
	if (!fec) {
		flog_err(EC_ZEBRA_FEC_RM_FAILED,
			 "Failed to find FEC %pFX upon unregister, client %s",
			 p, zebra_route_string(client->proto));
		return -1;
	}

	listnode_delete(fec->client_list, client);

	if (IS_ZEBRA_DEBUG_MPLS)
		zlog_debug("FEC %pFX unregistered by client %s", p,
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
static int zebra_mpls_cleanup_fecs_for_client(struct zserv *client)
{
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);
	struct route_node *rn;
	struct zebra_fec *fec;
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

struct lsp_uninstall_args {
	struct hash *lsp_table;
	enum lsp_types_t type;
};

/*
 * Cleanup MPLS labels registered by this client.
 */
static int zebra_mpls_cleanup_zclient_labels(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct lsp_uninstall_args args;

		zvrf = vrf->info;
		if (!zvrf)
			continue;

		/* Cleanup LSPs. */
		args.lsp_table = zvrf->lsp_table;
		args.type = lsp_type_from_re_type(client->proto);
		hash_iterate(zvrf->lsp_table, mpls_lsp_uninstall_all_type,
			     &args);

		/* Cleanup FTNs. */
		mpls_ftn_uninstall_all(zvrf, AFI_IP,
				       lsp_type_from_re_type(client->proto));
		mpls_ftn_uninstall_all(zvrf, AFI_IP6,
				       lsp_type_from_re_type(client->proto));
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
struct zebra_fec *zebra_mpls_fec_for_label(struct zebra_vrf *zvrf,
					   mpls_label_t label)
{
	struct route_node *rn;
	struct zebra_fec *fec;
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
	struct zebra_fec *fec;
	mpls_label_t old_label;
	int ret = 0;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	/* Update existing FEC or create a new one. */
	fec = fec_find(table, p);
	if (!fec) {
		fec = fec_add(table, p, in_label, FEC_FLAG_CONFIGURED,
			      MPLS_INVALID_LABEL_INDEX);
		if (!fec) {
			flog_err(EC_ZEBRA_FEC_ADD_FAILED,
				 "Failed to add FEC %pFX upon config", p);
			return -1;
		}

		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Add fec %pFX label %u", p, in_label);
	} else {
		fec->flags |= FEC_FLAG_CONFIGURED;
		if (fec->label == in_label)
			/* Duplicate config */
			return 0;

		/* Label change, update clients. */
		old_label = fec->label;
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Update fec %pFX new label %u", p, in_label);

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
	struct zebra_fec *fec;
	mpls_label_t old_label;

	table = zvrf->fec_table[family2afi(PREFIX_FAMILY(p))];
	if (!table)
		return -1;

	fec = fec_find(table, p);
	if (!fec) {
		flog_err(EC_ZEBRA_FEC_RM_FAILED,
			 "Failed to find FEC %pFX upon delete", p);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_MPLS) {
		zlog_debug("Delete fec %pFX label %u label index %u", p,
			   fec->label, fec->label_index);
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
	struct zebra_fec *fec;
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
			vty_out(vty, "mpls label bind %pFX %s\n", &rn->p,
				label2str(fec->label, 0, lstr, BUFSIZ));
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

static void mpls_zebra_nhe_update(struct route_entry *re, afi_t afi,
				  struct nhg_hash_entry *new_nhe)
{
	struct nhg_hash_entry *nhe;

	nhe = zebra_nhg_rib_find_nhe(new_nhe, afi);

	route_entry_update_nhe(re, nhe);
}

static bool ftn_update_nexthop(bool add_p, struct nexthop *nexthop,
			       enum lsp_types_t type,
			       const struct zapi_nexthop *znh)
{
	if (add_p && nexthop->nh_label_type == ZEBRA_LSP_NONE)
		nexthop_add_labels(nexthop, type, znh->label_num, znh->labels);
	else if (!add_p && nexthop->nh_label_type == type)
		nexthop_del_labels(nexthop);
	else
		return false;

	return true;
}

void zebra_mpls_ftn_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
			      struct prefix *prefix, uint8_t route_type,
			      uint8_t route_instance)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nhg_hash_entry *new_nhe;
	afi_t afi = family2afi(prefix->family);

	/* Lookup table.  */
	table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(zvrf));
	if (!table)
		return;

	/* Lookup existing route */
	rn = route_node_get(table, prefix);
	RNODE_FOREACH_RE (rn, re) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;
		if (re->type == route_type && re->instance == route_instance)
			break;
	}
	if (re == NULL)
		return;

	/*
	 * Nexthops are now shared by multiple routes, so we have to make
	 * a local copy, modify the copy, then update the route.
	 */
	new_nhe = zebra_nhe_copy(re->nhe, 0);

	for (nexthop = new_nhe->nhg.nexthop; nexthop; nexthop = nexthop->next)
		nexthop_del_labels(nexthop);

	/* Update backup routes/nexthops also, if present. */
	if (zebra_nhg_get_backup_nhg(new_nhe) != NULL) {
		for (nexthop = new_nhe->backup_info->nhe->nhg.nexthop; nexthop;
		     nexthop = nexthop->next)
			nexthop_del_labels(nexthop);
	}

	SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	SET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);

	/* This will create (or ref) a new nhe, so we will discard the local
	 * temporary nhe
	 */
	mpls_zebra_nhe_update(re, afi, new_nhe);

	zebra_nhg_free(new_nhe);

	rib_queue_add(rn);
}

/*
 * Iterate through a list of nexthops, for a match for 'znh'. If found,
 * update its labels according to 'add_p', and return 'true' if successful.
 */
static bool ftn_update_znh(bool add_p, enum lsp_types_t type,
			   struct nexthop *head, const struct zapi_nexthop *znh)
{
	bool found = false, success = false;
	struct nexthop *nexthop;

	for (nexthop = head; nexthop; nexthop = nexthop->next) {
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			if (znh->type != NEXTHOP_TYPE_IPV4
			    && znh->type != NEXTHOP_TYPE_IPV4_IFINDEX)
				continue;
			if (!IPV4_ADDR_SAME(&nexthop->gate.ipv4,
					    &znh->gate.ipv4))
				continue;
			if (nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX
			    && nexthop->ifindex != znh->ifindex)
				continue;

			found = true;

			if (!ftn_update_nexthop(add_p, nexthop, type, znh))
				break;

			success = true;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			if (znh->type != NEXTHOP_TYPE_IPV6
			    && znh->type != NEXTHOP_TYPE_IPV6_IFINDEX)
				continue;
			if (!IPV6_ADDR_SAME(&nexthop->gate.ipv6,
					    &znh->gate.ipv6))
				continue;
			if (nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX
			    && nexthop->ifindex != znh->ifindex)
				continue;

			found = true;

			if (!ftn_update_nexthop(add_p, nexthop, type, znh))
				break;
			success = true;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			if (znh->type != NEXTHOP_TYPE_IFINDEX)
				continue;
			if (nexthop->ifindex != znh->ifindex)
				continue;

			found = true;

			if (!ftn_update_nexthop(add_p, nexthop, type, znh))
				break;
			success = true;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			/* Not valid */
			continue;
		}

		if (found)
			break;
	}

	return success;
}

/*
 * Install/uninstall LSP and (optionally) FEC-To-NHLFE (FTN) bindings,
 * using zapi message info.
 * There are several changes that need to be made, in several zebra
 * data structures, so we want to do all the work required at once.
 */
void zebra_mpls_zapi_labels_process(bool add_p, struct zebra_vrf *zvrf,
				    const struct zapi_labels *zl)
{
	int i, counter, ret = 0;
	char buf[NEXTHOP_STRLEN];
	const struct zapi_nexthop *znh;
	struct route_table *table;
	struct route_node *rn = NULL;
	struct route_entry *re = NULL;
	struct nhg_hash_entry *new_nhe = NULL;
	bool found;
	afi_t afi = AFI_IP;
	const struct prefix *prefix = NULL;
	struct hash *lsp_table;
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp = NULL;

	/* Prep LSP for add case */
	if (add_p) {
		/* Lookup table. */
		lsp_table = zvrf->lsp_table;
		if (!lsp_table)
			return;

		/* Find or create LSP object */
		tmp_ile.in_label = zl->local_label;
		lsp = hash_get(lsp_table, &tmp_ile, lsp_alloc);
	}

	/* Prep for route/FEC update if requested */
	if (CHECK_FLAG(zl->message, ZAPI_LABELS_FTN)) {
		prefix = &zl->route.prefix;

		afi = family2afi(prefix->family);

		/* Lookup table.  */
		table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(zvrf));
		if (table) {
			/* Lookup existing route */
			rn = route_node_get(table, prefix);
			RNODE_FOREACH_RE(rn, re) {
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;
				if (re->type == zl->route.type &&
				    re->instance == zl->route.instance)
					break;
			}
		}

		if (re) {
			/*
			 * Copy over current nexthops into a temporary group.
			 * We can't just change the values here since the nhgs
			 * are shared and if the labels change, we'll need
			 * to find or create a new nhg. We need to create
			 * a whole temporary group, make changes to it,
			 * then attach that to the route.
			 */
			new_nhe = zebra_nhe_copy(re->nhe, 0);

		} else {
			/*
			 * The old version of the zapi code
			 * attempted to manage LSPs before trying to
			 * find a route/FEC, so we'll continue that way.
			 */
			if (IS_ZEBRA_DEBUG_RECV || IS_ZEBRA_DEBUG_MPLS)
				zlog_debug(
					"%s: FTN update requested: no route for prefix %pFX",
					__func__, prefix);
		}
	}

	/*
	 * Use info from the zapi nexthops to add/replace/remove LSP/FECs
	 */

	counter = 0;
	for (i = 0; i < zl->nexthop_num; i++) {

		znh = &zl->nexthops[i];

		/* Attempt LSP update */
		if (add_p)
			ret = lsp_znh_install(lsp, zl->type, znh);
		else
			ret = mpls_lsp_uninstall(zvrf, zl->type,
						 zl->local_label, znh->type,
						 &znh->gate, znh->ifindex,
						 false);
		if (ret < 0) {
			if (IS_ZEBRA_DEBUG_RECV || IS_ZEBRA_DEBUG_MPLS) {
				zapi_nexthop2str(znh, buf, sizeof(buf));
				zlog_debug("%s: Unable to %sinstall LSP: label %u, znh %s",
					   __func__, (add_p ? "" : "un"),
					   zl->local_label, buf);
			}
			continue;
		}

		/* Attempt route/FEC update if requested */
		if (re == NULL)
			continue;

		/* Search the route's nexthops for a match, and update it. */
		found = ftn_update_znh(add_p, zl->type, new_nhe->nhg.nexthop,
				       znh);
		if (found) {
			counter++;
		} else if (IS_ZEBRA_DEBUG_RECV | IS_ZEBRA_DEBUG_MPLS) {
			zapi_nexthop2str(znh, buf, sizeof(buf));
			zlog_debug(
				"%s: Unable to update FEC: prefix %pFX, label %u, znh %s",
				__func__, prefix, zl->local_label, buf);
		}
	}

	/*
	 * Process backup LSPs/nexthop entries also. We associate backup
	 * LSP info with backup nexthops.
	 */
	if (!CHECK_FLAG(zl->message, ZAPI_LABELS_HAS_BACKUPS))
		goto znh_done;

	for (i = 0; i < zl->backup_nexthop_num; i++) {

		znh = &zl->backup_nexthops[i];

		if (add_p)
			ret = lsp_backup_znh_install(lsp, zl->type, znh);
		else
			ret = mpls_lsp_uninstall(zvrf, zl->type,
						 zl->local_label,
						 znh->type, &znh->gate,
						 znh->ifindex, true);

		if (ret < 0) {
			if (IS_ZEBRA_DEBUG_RECV ||
			    IS_ZEBRA_DEBUG_MPLS) {
				zapi_nexthop2str(znh, buf, sizeof(buf));
				zlog_debug("%s: Unable to %sinstall backup LSP: label %u, znh %s",
					   __func__, (add_p ? "" : "un"),
					   zl->local_label, buf);
			}
			continue;
		}

		/* Attempt backup nexthop/FEC update if requested */
		if (re == NULL || zebra_nhg_get_backup_nhg(new_nhe) == NULL)
			continue;

		/* Search the route's backup nexthops for a match
		 * and update it.
		 */
		found = ftn_update_znh(add_p, zl->type,
				       new_nhe->backup_info->nhe->nhg.nexthop,
				       znh);
		if (found) {
			counter++;
		} else if (IS_ZEBRA_DEBUG_RECV | IS_ZEBRA_DEBUG_MPLS) {
			zapi_nexthop2str(znh, buf, sizeof(buf));
			zlog_debug(
				"%s: Unable to update backup FEC: prefix %pFX, label %u, znh %s",
				__func__, prefix, zl->local_label, buf);
		}
	}

znh_done:

	/*
	 * If we made changes, update the route, and schedule it
	 * for rib processing
	 */
	if (re != NULL && counter > 0) {
		assert(rn != NULL);

		SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
		SET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);

		mpls_zebra_nhe_update(re, afi, new_nhe);

		rib_queue_add(rn);
	}

	if (new_nhe)
		zebra_nhg_free(new_nhe);
}

/*
 * Install/update a NHLFE for an LSP in the forwarding table. This may be
 * a new LSP entry or a new NHLFE for an existing in-label or an update of
 * the out-label for an existing NHLFE (update case).
 */
static struct zebra_nhlfe *
lsp_add_nhlfe(struct zebra_lsp *lsp, enum lsp_types_t type,
	      uint8_t num_out_labels, const mpls_label_t *out_labels,
	      enum nexthop_types_t gtype, const union g_addr *gate,
	      ifindex_t ifindex, vrf_id_t vrf_id, bool is_backup)
{
	struct zebra_nhlfe *nhlfe;
	char buf[MPLS_LABEL_STRLEN];
	const char *backup_str;

	if (is_backup) {
		nhlfe = nhlfe_find(&lsp->backup_nhlfe_list, type, gtype,
				   gate, ifindex);
		backup_str = "backup ";
	} else {
		nhlfe = nhlfe_find(&lsp->nhlfe_list, type, gtype, gate,
				   ifindex);
		backup_str = "";
	}

	if (nhlfe) {
		struct nexthop *nh = nhlfe->nexthop;

		assert(nh);

		/* Clear deleted flag (in case it was set) */
		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);

		if (!nh->nh_label || num_out_labels == 0)
			/* No change */
			return nhlfe;

		if (nh->nh_label &&
		    nh->nh_label->num_labels == num_out_labels &&
		    !memcmp(nh->nh_label->label, out_labels,
			    sizeof(mpls_label_t) * num_out_labels))
			/* No change */
			return nhlfe;

		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf2[MPLS_LABEL_STRLEN];
			char buf3[MPLS_LABEL_STRLEN];

			nhlfe2str(nhlfe, buf, sizeof(buf));
			mpls_label2str(num_out_labels, out_labels, buf2,
				       sizeof(buf2), 0, 0);
			mpls_label2str(nh->nh_label->num_labels,
				       nh->nh_label->label, buf3, sizeof(buf3),
				       nh->nh_label_type, 0);

			zlog_debug("LSP in-label %u type %d %snexthop %s out-label(s) changed to %s (old %s)",
				   lsp->ile.in_label, type, backup_str, buf,
				   buf2, buf3);
		}

		/* Update out label(s), trigger processing. */
		if (nh->nh_label && nh->nh_label->num_labels == num_out_labels)
			memcpy(nh->nh_label->label, out_labels,
			       sizeof(mpls_label_t) * num_out_labels);
		else {
			nexthop_del_labels(nh);
			nexthop_add_labels(nh, type, num_out_labels,
					   out_labels);
		}
	} else {
		/* Add LSP entry to this nexthop */
		nhlfe = nhlfe_add(lsp, type, gtype, gate, ifindex, vrf_id,
				  num_out_labels, out_labels, is_backup);
		if (!nhlfe)
			return NULL;

		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf2[MPLS_LABEL_STRLEN];

			nhlfe2str(nhlfe, buf, sizeof(buf));
			if (num_out_labels)
				mpls_label2str(num_out_labels, out_labels, buf2,
					       sizeof(buf2), 0, 0);
			else
				snprintf(buf2, sizeof(buf2), "-");

			zlog_debug("Add LSP in-label %u type %d %snexthop %s out-label(s) %s",
				   lsp->ile.in_label, type, backup_str, buf,
				   buf2);
		}

		lsp->addr_family = NHLFE_FAMILY(nhlfe);
	}

	/* Mark NHLFE, queue LSP for processing. */
	SET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);

	return nhlfe;
}

/*
 * Install an LSP and forwarding entry; used primarily
 * from vrf zapi message processing.
 * TODO: handle vrf_id parameter when mpls API extends to interface or SRTE
 * changes
 */
int mpls_lsp_install(struct zebra_vrf *zvrf, enum lsp_types_t type,
		     mpls_label_t in_label, uint8_t num_out_labels,
		     const mpls_label_t *out_labels, enum nexthop_types_t gtype,
		     const union g_addr *gate, ifindex_t ifindex)
{
	struct hash *lsp_table;
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* Find or create LSP object */
	tmp_ile.in_label = in_label;
	lsp = hash_get(lsp_table, &tmp_ile, lsp_alloc);

	nhlfe = lsp_add_nhlfe(lsp, type, num_out_labels, out_labels, gtype,
			      gate, ifindex, VRF_DEFAULT, false /*backup*/);
	if (nhlfe == NULL)
		return -1;

	/* Queue LSP for processing. */
	if (lsp_processq_add(lsp))
		return -1;

	return 0;
}

/*
 * Install or replace NHLFE, using info from zapi nexthop
 */
static int lsp_znh_install(struct zebra_lsp *lsp, enum lsp_types_t type,
			   const struct zapi_nexthop *znh)
{
	struct zebra_nhlfe *nhlfe;

	nhlfe = lsp_add_nhlfe(lsp, type, znh->label_num, znh->labels, znh->type,
			      &znh->gate, znh->ifindex, znh->vrf_id,
			      false /*backup*/);
	if (nhlfe == NULL)
		return -1;

	/* Update backup info if present */
	if (CHECK_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_HAS_BACKUP)) {
		if (znh->backup_num > NEXTHOP_MAX_BACKUPS) {
			nhlfe_del(nhlfe);
			return -1;
		}

		nhlfe->nexthop->backup_num = znh->backup_num;
		memcpy(nhlfe->nexthop->backup_idx, znh->backup_idx,
		       znh->backup_num);
		SET_FLAG(nhlfe->nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP);
	} else {
		/* Ensure there's no stale backup info */
		UNSET_FLAG(nhlfe->nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP);
		nhlfe->nexthop->backup_num = 0;
	}

	/* Queue LSP for processing. */
	if (lsp_processq_add(lsp))
		return -1;

	return 0;
}

/*
 * Install/update backup NHLFE for an LSP, using info from a zapi message.
 */
static int lsp_backup_znh_install(struct zebra_lsp *lsp, enum lsp_types_t type,
				  const struct zapi_nexthop *znh)
{
	struct zebra_nhlfe *nhlfe;

	nhlfe = lsp_add_nhlfe(lsp, type, znh->label_num, znh->labels, znh->type,
			      &znh->gate, znh->ifindex, znh->vrf_id,
			      true /*backup*/);
	if (nhlfe == NULL) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("%s: unable to add backup nhlfe, label: %u",
				   __func__, lsp->ile.in_label);
		return -1;
	}

	/* Queue LSP for processing. */
	if (lsp_processq_add(lsp))
		return -1;

	return 0;
}

struct zebra_lsp *mpls_lsp_find(struct zebra_vrf *zvrf, mpls_label_t in_label)
{
	struct hash *lsp_table;
	struct zebra_ile tmp_ile;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return NULL;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	return hash_lookup(lsp_table, &tmp_ile);
}

/*
 * Uninstall a particular NHLFE in the forwarding table. If this is
 * the only NHLFE, the entire LSP forwarding entry has to be deleted.
 */
int mpls_lsp_uninstall(struct zebra_vrf *zvrf, enum lsp_types_t type,
		       mpls_label_t in_label, enum nexthop_types_t gtype,
		       const union g_addr *gate, ifindex_t ifindex,
		       bool backup_p)
{
	struct hash *lsp_table;
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	char buf[NEXTHOP_STRLEN];
	bool schedule_lsp = false;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp)
		return 0;

	if (backup_p)
		nhlfe = nhlfe_find(&lsp->backup_nhlfe_list, type, gtype,
				   gate, ifindex);
	else
		nhlfe = nhlfe_find(&lsp->nhlfe_list, type, gtype, gate,
				   ifindex);
	if (!nhlfe)
		return 0;

	if (IS_ZEBRA_DEBUG_MPLS) {
		nhlfe2str(nhlfe, buf, sizeof(buf));
		zlog_debug("Del LSP in-label %u type %d nexthop %s flags 0x%x",
			   in_label, type, buf, nhlfe->flags);
	}

	if (CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED) ||
	    CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED))
		schedule_lsp = true;

	/* Mark NHLFE for delete or directly delete, as appropriate. */
	if (schedule_lsp) {
		SET_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED);
		UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_CHANGED);

		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Schedule LSP in-label %u flags 0x%x",
				   lsp->ile.in_label, lsp->flags);
		if (lsp_processq_add(lsp))
			return -1;
	} else {
		nhlfe_del(nhlfe);

		/* Free LSP entry if no other NHLFEs and not scheduled. */
		lsp_check_free(lsp_table, &lsp);
	}
	return 0;
}

int mpls_lsp_uninstall_all_vrf(struct zebra_vrf *zvrf, enum lsp_types_t type,
			       mpls_label_t in_label)
{
	struct hash *lsp_table;
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp)
		return 0;

	return mpls_lsp_uninstall_all(lsp_table, lsp, type);
}

/*
 * Uninstall all NHLFEs for a particular LSP forwarding entry.
 * If no other NHLFEs exist, the entry would be deleted.
 */
static void mpls_lsp_uninstall_all_type(struct hash_bucket *bucket, void *ctxt)
{
	struct lsp_uninstall_args *args = ctxt;
	struct zebra_lsp *lsp;
	struct hash *lsp_table;

	lsp = (struct zebra_lsp *)bucket->data;
	if (nhlfe_list_first(&lsp->nhlfe_list) == NULL)
		return;

	lsp_table = args->lsp_table;
	if (!lsp_table)
		return;

	mpls_lsp_uninstall_all(lsp_table, lsp, args->type);
}

/*
 * Uninstall all FEC-To-NHLFE (FTN) bindings of the given address-family and
 * LSP type.
 */
static void mpls_ftn_uninstall_all(struct zebra_vrf *zvrf,
				   int afi, enum lsp_types_t lsp_type)
{
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;
	bool update;

	/* Process routes of interested address-families. */
	table = zebra_vrf_table(afi, SAFI_UNICAST, zvrf_id(zvrf));
	if (!table)
		return;

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		update = false;

		RNODE_FOREACH_RE (rn, re) {
			struct nhg_hash_entry *new_nhe;

			new_nhe = zebra_nhe_copy(re->nhe, 0);

			nhg = &new_nhe->nhg;
			for (nexthop = nhg->nexthop; nexthop;
			     nexthop = nexthop->next) {
				if (nexthop->nh_label_type != lsp_type)
					continue;

				nexthop_del_labels(nexthop);
				SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
				SET_FLAG(re->status,
					 ROUTE_ENTRY_LABELS_CHANGED);
				update = true;
			}

			/* Check for backup info and update that also */
			nhg = zebra_nhg_get_backup_nhg(new_nhe);
			if (nhg != NULL) {
				for (nexthop = nhg->nexthop; nexthop;
				     nexthop = nexthop->next) {
					if (nexthop->nh_label_type != lsp_type)
						continue;

					nexthop_del_labels(nexthop);
					SET_FLAG(re->status,
						 ROUTE_ENTRY_CHANGED);
					SET_FLAG(re->status,
						 ROUTE_ENTRY_LABELS_CHANGED);
					update = true;
				}
			}

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED))
				mpls_zebra_nhe_update(re, afi, new_nhe);

			zebra_nhg_free(new_nhe);
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	const struct nexthop *nh;

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return 0;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(slsp_table, &tmp_ile);
	if (!lsp)
		return 1;

	nhlfe = nhlfe_find(&lsp->nhlfe_list, ZEBRA_LSP_STATIC,
			   gtype, gate, ifindex);
	if (nhlfe) {
		nh = nhlfe->nexthop;

		if (nh == NULL || nh->nh_label == NULL)
			return 0;

		if (nh->nh_label->label[0] == out_label)
			return 1;

		/* If not only NHLFE, cannot allow label change. */
		if (nhlfe != nhlfe_list_first(&lsp->nhlfe_list) ||
		    nhlfe_list_next(&lsp->nhlfe_list, nhlfe) != NULL)
			return 0;
	} else {
		/* If other NHLFEs exist, label operation must match. */
		nhlfe = nhlfe_list_first(&lsp->nhlfe_list);
		if (nhlfe != NULL) {
			int cur_op, new_op;

			nh = nhlfe->nexthop;

			if (nh == NULL || nh->nh_label == NULL)
				return 0;

			cur_op = (nh->nh_label->label[0] ==
				  MPLS_LABEL_IMPLICIT_NULL);
			new_op = (out_label == MPLS_LABEL_IMPLICIT_NULL);
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	char buf[BUFSIZ];

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return -1;

	/* Find or create LSP. */
	tmp_ile.in_label = in_label;
	lsp = hash_get(slsp_table, &tmp_ile, lsp_alloc);

	nhlfe = nhlfe_find(&lsp->nhlfe_list, ZEBRA_LSP_STATIC, gtype, gate,
			   ifindex);
	if (nhlfe) {
		struct nexthop *nh = nhlfe->nexthop;

		assert(nh);
		assert(nh->nh_label);

		/* Compare existing nexthop */
		if (nh->nh_label->num_labels == 1 &&
		    nh->nh_label->label[0] == out_label)
			/* No change */
			return 0;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, sizeof(buf));
			zlog_debug(
				"Upd static LSP in-label %u nexthop %s out-label %u (old %u)",
				in_label, buf, out_label,
				nh->nh_label->label[0]);
		}
		if (nh->nh_label->num_labels == 1)
			nh->nh_label->label[0] = out_label;
		else {
			nexthop_del_labels(nh);
			nexthop_add_labels(nh, ZEBRA_LSP_STATIC, 1, &out_label);
		}

	} else {
		/* Add static LSP entry to this nexthop */
		nhlfe = nhlfe_add(lsp, ZEBRA_LSP_STATIC, gtype, gate, ifindex,
				  VRF_DEFAULT, 1, &out_label, false /*backup*/);
		if (!nhlfe)
			return -1;

		if (IS_ZEBRA_DEBUG_MPLS) {
			nhlfe2str(nhlfe, buf, sizeof(buf));
			zlog_debug(
				"Add static LSP in-label %u nexthop %s out-label %u",
				in_label, buf, out_label);
		}
	}

	/* (Re)Install LSP in the main table. */
	if (mpls_lsp_install(zvrf, ZEBRA_LSP_STATIC, in_label, 1, &out_label,
			     gtype, gate, ifindex))
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
	struct zebra_ile tmp_ile;
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;

	/* Lookup table. */
	slsp_table = zvrf->slsp_table;
	if (!slsp_table)
		return -1;

	/* If entry is not present, exit. */
	tmp_ile.in_label = in_label;
	lsp = hash_lookup(slsp_table, &tmp_ile);
	if (!lsp)
		return 0;

	/* Is it delete of entire LSP or a specific NHLFE? */
	if (gtype == NEXTHOP_TYPE_BLACKHOLE) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug("Del static LSP in-label %u", in_label);

		/* Uninstall entire LSP from the main table. */
		mpls_static_lsp_uninstall_all(zvrf, in_label);

		/* Delete all static NHLFEs */
		frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
			nhlfe_del(nhlfe);
		}
	} else {
		/* Find specific NHLFE, exit if not found. */
		nhlfe = nhlfe_find(&lsp->nhlfe_list, ZEBRA_LSP_STATIC,
				   gtype, gate, ifindex);
		if (!nhlfe)
			return 0;

		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf[BUFSIZ];
			nhlfe2str(nhlfe, buf, sizeof(buf));
			zlog_debug("Del static LSP in-label %u nexthop %s",
				   in_label, buf);
		}

		/* Uninstall LSP from the main table. */
		mpls_lsp_uninstall(zvrf, ZEBRA_LSP_STATIC, in_label, gtype,
				   gate, ifindex, false);

		/* Delete static LSP NHLFE */
		nhlfe_del(nhlfe);
	}

	/* Remove entire static LSP entry if no NHLFE - valid in either case
	 * above.
	 */
	if (nhlfe_list_first(&lsp->nhlfe_list) == NULL) {
		lsp = hash_release(slsp_table, &tmp_ile);
		lsp_free_nhlfe(lsp);
		XFREE(MTYPE_LSP, lsp);
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
			  mpls_label_t label, bool use_json)
{
	struct hash *lsp_table;
	struct zebra_lsp *lsp;
	struct zebra_ile tmp_ile;
	json_object *json = NULL;

	/* Lookup table. */
	lsp_table = zvrf->lsp_table;
	if (!lsp_table) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	/* If entry is not present, exit. */
	tmp_ile.in_label = label;
	lsp = hash_lookup(lsp_table, &tmp_ile);
	if (!lsp) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	if (use_json) {
		json = lsp_json(lsp);
		vty_json(vty, json);
	} else
		lsp_print(vty, lsp);
}

/*
 * Display MPLS label forwarding table (VTY command handler).
 */
void zebra_mpls_print_lsp_table(struct vty *vty, struct zebra_vrf *zvrf,
				bool use_json)
{
	char buf[BUFSIZ];
	json_object *json = NULL;
	struct zebra_lsp *lsp = NULL;
	struct zebra_nhlfe *nhlfe = NULL;
	struct listnode *node = NULL;
	struct list *lsp_list = hash_get_sorted_list(zvrf->lsp_table, lsp_cmp);

	if (use_json) {
		json = json_object_new_object();

		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp))
			json_object_object_add(json,
					       label2str(lsp->ile.in_label, 0,
							 buf, sizeof(buf)),
					       lsp_json(lsp));

		vty_json(vty, json);
	} else {
		struct ttable *tt;

		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Inbound Label|Type|Nexthop|Outbound Label");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
		ttable_rowseps(tt, 0, BOTTOM, true, '-');

		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp)) {
			frr_each_safe(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
				struct nexthop *nexthop;
				const char *out_label_str;
				char nh_buf[NEXTHOP_STRLEN];

				nexthop = nhlfe->nexthop;

				switch (nexthop->type) {
				case NEXTHOP_TYPE_IFINDEX: {
					struct zebra_ns *zns;
					struct interface *ifp;

					zns = zebra_ns_lookup(NS_DEFAULT);
					ifp = if_lookup_by_index_per_ns(
						zns, nexthop->ifindex);
					snprintf(nh_buf, sizeof(nh_buf), "%s",
						 ifp ? ifp->name : "Null");
					break;
				}
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					inet_ntop(AF_INET, &nexthop->gate.ipv4,
						  nh_buf, sizeof(nh_buf));
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					inet_ntop(AF_INET6, &nexthop->gate.ipv6,
						  nh_buf, sizeof(nh_buf));
					break;
				case NEXTHOP_TYPE_BLACKHOLE:
					break;
				}

				if (nexthop->type != NEXTHOP_TYPE_IFINDEX &&
				    nexthop->nh_label)
					out_label_str = mpls_label2str(
						nexthop->nh_label->num_labels,
						&nexthop->nh_label->label[0],
						buf, sizeof(buf),
						nexthop->nh_label_type, 1);
				else
					out_label_str = "-";

				ttable_add_row(tt, "%u|%s|%s|%s",
					       lsp->ile.in_label,
					       nhlfe_type2str(nhlfe->type),
					       nh_buf, out_label_str);
			}
		}

		/* Dump the generated table. */
		if (tt->nrows > 1) {
			char *table = ttable_dump(tt, "\n");
			vty_out(vty, "%s\n", table);
			XFREE(MTYPE_TMP, table);
		}
		ttable_del(tt);
	}

	list_delete(&lsp_list);
}

/*
 * Create printable string for static LSP configuration.
 */
static char *nhlfe_config_str(const struct zebra_nhlfe *nhlfe, char *buf,
			      int size)
{
	const struct nexthop *nh;

	nh = nhlfe->nexthop;

	buf[0] = '\0';
	switch (nh->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		inet_ntop(AF_INET, &nh->gate.ipv4, buf, size);
		if (nh->ifindex)
			strlcat(buf, ifindex2ifname(nh->ifindex, VRF_DEFAULT),
				size);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		inet_ntop(AF_INET6, &nh->gate.ipv6, buf, size);
		if (nh->ifindex)
			strlcat(buf,
				ifindex2ifname(nh->ifindex, VRF_DEFAULT),
				size);
		break;
	case NEXTHOP_TYPE_IFINDEX:
		if (nh->ifindex)
			strlcat(buf,
				ifindex2ifname(nh->ifindex, VRF_DEFAULT),
				size);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	return buf;
}

/*
 * Display MPLS LSP configuration of all static LSPs (VTY command handler).
 */
int zebra_mpls_write_lsp_config(struct vty *vty, struct zebra_vrf *zvrf)
{
	struct zebra_lsp *lsp;
	struct zebra_nhlfe *nhlfe;
	struct nexthop *nh;
	struct listnode *node;
	struct list *slsp_list =
		hash_get_sorted_list(zvrf->slsp_table, lsp_cmp);

	for (ALL_LIST_ELEMENTS_RO(slsp_list, node, lsp)) {
		frr_each(nhlfe_list, &lsp->nhlfe_list, nhlfe) {
			char buf[BUFSIZ];
			char lstr[30];

			nh = nhlfe->nexthop;
			if (nh == NULL || nh->nh_label == NULL)
				continue;

			nhlfe_config_str(nhlfe, buf, sizeof(buf));

			switch (nh->nh_label->label[0]) {
			case MPLS_LABEL_IPV4_EXPLICIT_NULL:
			case MPLS_LABEL_IPV6_EXPLICIT_NULL:
				strlcpy(lstr, "explicit-null", sizeof(lstr));
				break;
			case MPLS_LABEL_IMPLICIT_NULL:
				strlcpy(lstr, "implicit-null", sizeof(lstr));
				break;
			default:
				snprintf(lstr, sizeof(lstr), "%u",
					 nh->nh_label->label[0]);
				break;
			}

			vty_out(vty, "mpls lsp %u %s %s\n", lsp->ile.in_label,
				buf, lstr);
		}
	}

	list_delete(&slsp_list);
	return (zvrf->slsp_table->count ? 1 : 0);
}

/*
 * Add/update global label block.
 */
int zebra_mpls_label_block_add(struct zebra_vrf *zvrf, uint32_t start_label,
			       uint32_t end_label)
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
 */
void zebra_mpls_cleanup_tables(struct zebra_vrf *zvrf)
{
	struct zebra_vrf *def_zvrf;
	afi_t afi;

	if (zvrf_id(zvrf) == VRF_DEFAULT)
		hash_iterate(zvrf->lsp_table, lsp_uninstall_from_kernel, NULL);
	else {
		/*
		 * For other vrfs, we try to remove associated LSPs; we locate
		 * the LSPs in the default vrf.
		 */
		def_zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

		/* At shutdown, the default may be gone already */
		if (def_zvrf == NULL)
			return;

		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (zvrf->label[afi] != MPLS_LABEL_NONE)
				lsp_uninstall(def_zvrf, zvrf->label[afi]);
		}
	}
}

/*
 * When a vrf label is assigned and the client goes away
 * we should cleanup the vrf labels associated with
 * that zclient.
 */
void zebra_mpls_client_cleanup_vrf_label(uint8_t proto)
{
	struct vrf *vrf;
	struct zebra_vrf *def_zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	if (def_zvrf == NULL)
		return;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct zebra_vrf *zvrf = vrf->info;
		afi_t afi;

		if (!zvrf)
			continue;

		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (zvrf->label_proto[afi] == proto
			    && zvrf->label[afi] != MPLS_LABEL_NONE)
				lsp_uninstall(def_zvrf, zvrf->label[afi]);

			/*
			 * Cleanup data structures by fiat
			 */
			zvrf->label_proto[afi] = 0;
			zvrf->label[afi] = MPLS_LABEL_NONE;
		}
	}
}

static void lsp_table_free(void *p)
{
	struct zebra_lsp *lsp = p;

	lsp_free_nhlfe(lsp);

	XFREE(MTYPE_LSP, lsp);
}

/*
 * Called upon process exiting, need to delete LSP forwarding
 * entries from the kernel.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_close_tables(struct zebra_vrf *zvrf)
{
	hash_iterate(zvrf->lsp_table, lsp_uninstall_from_kernel, NULL);
	hash_clean_and_free(&zvrf->lsp_table, lsp_table_free);
	hash_clean_and_free(&zvrf->slsp_table, lsp_table_free);
	route_table_finish(zvrf->fec_table[AFI_IP]);
	route_table_finish(zvrf->fec_table[AFI_IP6]);
}

/*
 * Allocate MPLS tables for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void zebra_mpls_init_tables(struct zebra_vrf *zvrf)
{
	char buffer[80];

	if (!zvrf)
		return;

	snprintf(buffer, sizeof(buffer), "ZEBRA SLSP table: %s",
		 zvrf->vrf->name);
	zvrf->slsp_table = hash_create_size(8, label_hash, label_cmp, buffer);

	snprintf(buffer, sizeof(buffer), "ZEBRA LSP table: %s",
		 zvrf->vrf->name);
	zvrf->lsp_table = hash_create_size(8, label_hash, label_cmp, buffer);
	zvrf->fec_table[AFI_IP] = route_table_init();
	zvrf->fec_table[AFI_IP6] = route_table_init();
	zvrf->mpls_flags = 0;
	zvrf->mpls_srgb.start_label = MPLS_DEFAULT_MIN_SRGB_LABEL;
	zvrf->mpls_srgb.end_label = MPLS_DEFAULT_MAX_SRGB_LABEL;
}

void zebra_mpls_turned_on(void)
{
	if (!mpls_enabled) {
		mpls_processq_init();
		mpls_enabled = true;

		hook_register(zserv_client_close,
			      zebra_mpls_cleanup_fecs_for_client);
		hook_register(zserv_client_close,
			      zebra_mpls_cleanup_zclient_labels);
	}
}

/*
 * Global MPLS initialization.
 */
void zebra_mpls_init(void)
{
	mpls_enabled = false;
	mpls_pw_reach_strict = false;

	if (mpls_kernel_init() < 0) {
		flog_warn(EC_ZEBRA_MPLS_SUPPORT_DISABLED,
			  "Disabling MPLS support (no kernel support)");
		return;
	}

	zebra_mpls_turned_on();
}

void zebra_mpls_terminate(void)
{
	hook_unregister(zserv_client_close, zebra_mpls_cleanup_fecs_for_client);
	hook_unregister(zserv_client_close, zebra_mpls_cleanup_zclient_labels);
}
