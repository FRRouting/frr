/*
 * This is an implementation of Segment Routing for IS-IS
 * as per draft draft-ietf-isis-segment-routing-extensions-25
 *
 * Module name: Segment Routing
 *
 * Copyright (C) 2019 Orange Labs http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <zebra.h>

#include "command.h"
#include "hash.h"
#include "if.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "prefix.h"
#include "sockunion.h"
#include "stream.h"
#include "table.h"
#include "thread.h"
#include "vty.h"
#include "zclient.h"
#include "sbuf.h"
#include "lib/json.h"
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_route.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_dynhn.h"

const char *sr_status2str[] = {"Idle", "Added", "Updated", "Unchanged"};
const char *lsp_event2str[] = {"Add", "Update", "Delete", "Tick", "Increment"};

static int sr_prefix_update_lfib(int cmd, struct sr_prefix *srp);
static int sr_adjacency_update_lfib(int cmd, struct sr_adjacency *sra);

/*
 * Segment Routing Data Base functions
 */

/* Declaration of SR Node RB Tree */
static inline int sr_node_cmp(const struct sr_node *srn1,
			      const struct sr_node *srn2)
{
	return memcmp(srn1->sysid, srn2->sysid, ISIS_SYS_ID_LEN);
}

RB_GENERATE(srdb_node_head, sr_node, entry, sr_node_cmp)

/* Declaration of SR Prefix RB Tree */
static inline int sr_prefix_cmp(const struct sr_prefix *srp1,
				const struct sr_prefix *srp2)
{
	// TODO: Add SID or FLAGS or Algo comparison
	return prefix_cmp(&srp1->prefix, &srp2->prefix);
}

RB_GENERATE(srdb_prefix_head, sr_prefix, srdb, sr_prefix_cmp)
RB_GENERATE(srnode_prefix_head, sr_prefix, srnode, sr_prefix_cmp)

/* Functions to remove an SR Adjacency */
static void del_sr_adj(void *val)
{
	struct sr_adjacency *sra = (struct sr_adjacency *)val;

	sr_debug("    |- Remove Adjacency for interface %s",
		 sra->adj->circuit->interface->name);

	if (sra->adj_sid)
		isis_tlvs_del_adj_sid(sra->adj->circuit->ext, sra->adj_sid);
	if (sra->lan_sid)
		isis_tlvs_del_lan_adj_sid(sra->adj->circuit->ext, sra->lan_sid);

	sr_adjacency_update_lfib(ZEBRA_MPLS_LABELS_DELETE, sra);
	isis_zebra_release_dynamic_label(sra->label);

	XFREE(MTYPE_ISIS_SR, sra);
}

/*
 * Functions to manage an SR Prefix
 */

/* Create new nexthop for the given SR Prefix */
static struct isis_nexthop *sr_nexthop_new(struct sr_prefix *srp)
{
	struct isis_nexthop *nh;

	/* Create list if needed */
	if (srp->nexthops == NULL) {
		srp->nexthops = list_new();
	}

	nh = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_nexthop));
	listnode_add(srp->nexthops, nh);

	return nh;
}

/* Create new SR Prefix */
static struct sr_prefix *sr_prefix_new(struct sr_node *srn,
				       const struct prefix *prefix)
{
	struct sr_prefix *srp;

	srp = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_prefix));
	memcpy(&srp->prefix, prefix, sizeof(struct prefix));

	/* Set back pointer and add this prefix to self SR-Node and SR-DB */
	srp->srn = srn;
	RB_INSERT(srdb_prefix_head,
		  &srn->area->srdb.prefix_sids[srn->level - 1], srp);
	RB_INSERT(srnode_prefix_head, &srn->pref_sids, srp);

	return srp;
}

/* Remove Prefix SID from the given SR Node */
static void sr_prefix_del(struct sr_node *srn, struct sr_prefix *srp)
{
	struct isis_area *area;

	sr_debug("    |- Remove Prefix-SID %pFX from SR-Node %s",
		 &srp->prefix, print_sys_hostname(srn->sysid));

	/* Remove NHLFE associated to this SR prefix */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);

	/* Remove SRP from SR Node & SR-DB */
	area = srn->area;
	RB_REMOVE(srdb_prefix_head, &area->srdb.prefix_sids[srn->level - 1],
		  srp);
	RB_REMOVE(srnode_prefix_head, &srn->pref_sids, srp);
	XFREE(MTYPE_ISIS_SR, srp);
}

/*
 * Functions to manage SR Node
 */

/* Allocate new Segment Routine Node */
static struct sr_node *sr_node_new(uint8_t *sysid)
{
	struct sr_node *new;

	if (sysid == NULL)
		return NULL;

	/* Allocate Segment Routing node memory */
	new = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_node));

	/* Default Algorithm, SRGB and MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		new->cap.algo[i] = SR_ALGORITHM_UNSET;

	new->cap.srgb.lower_bound = 0;
	new->cap.srgb.range_size = 0;
	new->cap.msd = 0;
	new->active = false;

	/* Initialise RB Tree for Prefix */
	RB_INIT(srnode_prefix_head, &new->pref_sids);

	/* Initialise List of Adjacency */
	new->adj_sids = list_new();
	new->adj_sids->del = del_sr_adj;

	memcpy(new->sysid, sysid, ISIS_SYS_ID_LEN);
	new->neighbor = NULL;

	sr_debug("   |- Created new SR node for %s",
		 print_sys_hostname(new->sysid));

	return new;
}

/* Deactivate Segment Routing node */
static void sr_node_deactivate(struct sr_node *srn)
{
	struct sr_prefix *srp;

	/* Sanity Check */
	if (srn == NULL)
		return;

	sr_debug("  |- Deactivate SR Node %s", print_sys_hostname(srn->sysid));

	/* Clean Adjacency List */
	list_delete(&srn->adj_sids);

	/* Clean Prefix RB Tree */
	while (!RB_EMPTY(srnode_prefix_head, &srn->pref_sids)) {
		srp = RB_ROOT(srnode_prefix_head, &srn->pref_sids);
		sr_prefix_del(srn, srp);
	}

	/* deactivate the SR-Node */
	srn->active = false;
}

/* Remove Segment Routing node */
static void sr_node_del(struct isis_sr_db *srdb, struct sr_node *srn)
{

	/* First deactive the SR Node if already active */
	if (srn->active)
		sr_node_deactivate(srn);

	/* Remove the SR Node from the SRDB */
	RB_REMOVE(srdb_node_head, &srdb->sr_nodes[srn->level - 1], srn);
	XFREE(MTYPE_ISIS_SR, srn);
}

/* Get SR Node self */
static struct sr_node *get_self_by_area(const struct isis_area *area)
{
	return area->srdb.self;
}

static struct sr_node *get_self_by_node(struct sr_node *srn)
{
	return srn ? get_self_by_area(srn->area) : NULL;
}

/* Get SR-Node from SRDB. Create new one if not found */
static struct sr_node *get_sr_node_from_lsp(struct isis_lsp *lsp)
{
	struct isis_area * area;
	struct sr_node *srn;
	struct sr_node key = {};

	if (lsp == NULL)
		return NULL;

	/* Get SR Node in SRDB from ID */
	area = lsp->area;
	memcpy(&key.sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes[lsp->level - 1],
		      &key);

	if (srn)
		return srn;

	/* Create new one */
	srn = sr_node_new(lsp->hdr.lsp_id);

	/* Sanity check in case of */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_DB,
			 "SR (%s): Abort! can't create SR node in SRDB",
			 __func__);
		return NULL;
	}
	srn->level = lsp->level;
	srn->area = area;

	RB_INSERT(srdb_node_head, &area->srdb.sr_nodes[lsp->level - 1], srn);

	return srn;
}

/*
 * Functions to install MPLS entry corresponding to Prefix or Adjacency SID
 */

/* pretty print function for MPLS label*/
static char *sr_op2str(char *buf, size_t size, mpls_label_t label_in,
		       mpls_label_t label_out)
{
	if (size < 24)
		return NULL;

	switch (label_out) {
	case MPLS_LABEL_IMPLICIT_NULL:
		snprintf(buf, size, "Pop(%u)", label_in);
		break;
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		snprintf(buf, size, "Swap(%u, null)", label_in);
		break;
	case MPLS_INVALID_LABEL:
		snprintf(buf, size, "no-op.");
		break;
	default:
		snprintf(buf, size, "Swap(%u, %u)", label_in, label_out);
		break;
	}
	return buf;
}

/* Compute label from index */
static mpls_label_t index2label(uint32_t index, struct isis_srgb srgb)
{
	mpls_label_t label;

	label = srgb.lower_bound + index;
	if (label > (srgb.lower_bound + srgb.range_size))
		return MPLS_INVALID_LABEL;
	else
		return label;
}

/* Send MPLS Labels of given SR Prefix to Zebra for installation or deletion */
static int sr_prefix_update_lfib(int cmd, struct sr_prefix *srp)
{
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;
	struct listnode *node;
	struct isis_nexthop *nh;

	/* Check that input label is valid */
	if ((srp->label <= MPLS_LABEL_RESERVED_MAX)
	    || (srp->label == MPLS_INVALID_LABEL))
		return 0;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;
	zl.local_label = srp->label;
	SET_FLAG(zl.message, ZAPI_LABELS_FTN);
	zl.route.prefix = srp->prefix;
	zl.route.type = ZEBRA_ROUTE_ISIS;
	zl.route.instance = 0;

	/* Add MPLS entries */
	if (cmd == ZEBRA_MPLS_LABELS_REPLACE) {
		for (ALL_LIST_ELEMENTS_RO(srp->nexthops, node, nh)) {

			/* Skip NOP config or invalid label */
			if ((nh->nhlfe.config == NOP)
			    || (nh->nhlfe.label == MPLS_INVALID_LABEL))
				continue;

			znh = &zl.nexthops[zl.nexthop_num++];
			if (nh->nhlfe.config == POP_TO_IFINDEX) {
				znh->type = NEXTHOP_TYPE_IFINDEX;
			} else {
				znh->type = (srp->prefix.family == AF_INET)
						    ? NEXTHOP_TYPE_IPV4_IFINDEX
						    : NEXTHOP_TYPE_IPV6_IFINDEX;
			}
			znh->family = nh->family;
			znh->address = nh->ip;
			znh->ifindex = nh->ifindex;
			znh->label = nh->nhlfe.label;
		}
		/* Is there at least one valid output label to configure? */
		if (zl.nexthop_num == 0)
			return 0;
	}

	sr_debug("      |-  %s MPLS entry %u for prefix %pFX",
		 cmd == ZEBRA_MPLS_LABELS_REPLACE ? "Update" : "Delete",
		 srp->label, &srp->prefix);

	return zebra_send_mpls_labels(zclient, cmd, &zl);
}

/* Send MPLS Labels of given SR Adj. to Zebra for installation or deletion */
static int sr_adjacency_update_lfib(int cmd, struct sr_adjacency *sra)
{
	struct zapi_labels zl;
	struct zapi_nexthop_label *znh;

	/* Prepare message. */
	memset(&zl, 0, sizeof(zl));
	zl.type = ZEBRA_LSP_ISIS_SR;

	/* Add MPLS entry */
	zl.local_label = sra->label;
	zl.nexthop_num = 1;
	znh = &zl.nexthops[0];
	znh->family = sra->nexthop.family;
	znh->address = sra->nexthop.ip;
	znh->type = (sra->nexthop.family == AF_INET)
			    ? NEXTHOP_TYPE_IPV4_IFINDEX
			    : NEXTHOP_TYPE_IPV6_IFINDEX;
	znh->ifindex = sra->nexthop.ifindex;
	znh->label = sra->nexthop.label;

	sr_debug("      |-  %s MPLS entry %u for Adjacency index %d",
		 cmd == ZEBRA_MPLS_LABELS_ADD ? "Add" : "Delete",
		 sra->label, sra->nexthop.ifindex);

	return zebra_send_mpls_labels(zclient, cmd, &zl);
}

/* Compute incoming label for a given prefix and sr-node */
static mpls_label_t sr_prefix_get_input_label(const struct sr_prefix *srp,
					      const struct sr_node *self)
{
	if ((srp->srn == self)
	    && (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL))) {
		if (srp->prefix.family == AF_INET)
			return MPLS_LABEL_IPV4_EXPLICIT_NULL;
		else
			return MPLS_LABEL_IPV6_EXPLICIT_NULL;
	}

	if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE))
		return srp->sid.value;

	return index2label(srp->sid.value, self->cap.srgb);

}

/* Compute outgoing label for a given prefix and sr-node */
static mpls_label_t sr_prefix_get_out_label(const struct sr_prefix *srp,
					    const struct sr_node *srnext)
{

	/* Is it the Self SR-Node (srnext is null)? */
	if (srnext == NULL) {
		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)
		    && !CHECK_FLAG(srp->sid.flags,
				   ISIS_PREFIX_SID_EXPLICIT_NULL))
			return MPLS_LABEL_IMPLICIT_NULL;
		else
			return MPLS_INVALID_LABEL;
	}

	/* Is the next SR node the last hop? */
	if (srnext == srp->srn) {
		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE)) {
			if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
				return srp->sid.value;
			else
				return MPLS_INVALID_LABEL;
		}

		if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
			return MPLS_LABEL_IMPLICIT_NULL;

		if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_EXPLICIT_NULL)) {
			if (srp->prefix.family == AF_INET)
				return MPLS_LABEL_IPV4_EXPLICIT_NULL;
			else
				return MPLS_LABEL_IPV6_EXPLICIT_NULL;
		}
	}

	/* Absolute SID value. */
	if (CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE))
		return MPLS_INVALID_LABEL;

	/* Index SID value. */
	return index2label(srp->sid.value, srnext->cap.srgb);
}

/* Compute and configure NHLFE output label for a given prefix and nexthop */
static void nhlfe_update_out_label(struct sr_prefix *srp,
				   struct isis_nexthop *nh)
{
	struct sr_node *self = get_self_by_node(srp->srn);
	struct sr_node *srnext = nh->nhlfe.srnext;
	char buf[32];

	/* Skip nexthop SR-Node which is not active */
	if (srnext && !srnext->active) {
		sr_debug("    |-  Nexthop %s is not yet SR ready",
			 print_sys_hostname(srnext->sysid));
		nh->nhlfe.config = NOP;
		return;
	}

	/*
	 * Set Output Label with:
	 *  - Implicit Null label if it is the self node and request NO-PHP,
	 *    MPLS_INVALIDE_LABEL otherwise
	 *  - Implicit / Explicit Null label if next hop is the destination and
	 *    request NO_PHP / EXPLICIT NULL label
	 *  - Value label or SID in Next hop SR Node SRGB for other cases
	 */
	nh->nhlfe.label = sr_prefix_get_out_label(srp, nh->nhlfe.srnext);

	/* Determine the MPLS configuration to apply */
	switch (nh->nhlfe.label) {
	case MPLS_INVALID_LABEL:
		nh->nhlfe.config = NOP;
		if (srp->srn != self)
			flog_warn(
				EC_ISIS_SID_OVERFLOW,
				"%s: SID index %u falls outside remote SRGB range",
				__func__, srp->sid.value);
		break;
	case MPLS_LABEL_IMPLICIT_NULL:
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		if (srp->srn == self)
			nh->nhlfe.config = POP_TO_IFINDEX;
		else
			nh->nhlfe.config = SWAP;
		break;
	default:
		nh->nhlfe.config = SWAP;
		break;
	}

	sr_debug("    |-  Computed new SR operation: %s",
		 sr_op2str(buf, 32, srp->label, nh->nhlfe.label));
}

/* Functions to manage ADJ-SID:
 *  - isis_sr_circuit_update_sid_adjs() call when isis adjacency is up
 *    to update ADJ-SID for the given circuit
 *  - isis_sr_circuit_unset_sid_adjs() call when SR is stop to remove ADJ-SID
 *  - isis_sr_if_new_hook() hook trigger to complete Prefix SID for the
 *    Loopback interface
 *  - isis_sr_update_adj_hook() call when isis adjacency is up to create
 *    ADJ-SID and configure corresponding MPLS entries
 */

/* Get Label for (LAN-)Adj-SID from the Label Manager */
static uint32_t sr_get_local_label(void)
{
	return isis_zebra_request_dynamic_label();
}

/* Create new Adjacency SID for the given circuit and adjacency */
static struct sr_adjacency *sr_adj_add(struct isis_circuit *circuit,
				       struct isis_adjacency *isis_adj,
				       struct prefix *nexthop, bool backup)
{
	struct sr_adjacency *sra;
	struct isis_adj_sid *adj;

	/* Create new Adjacency subTLVs */
	adj = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_adj_sid));
	adj->family = nexthop->family;
	adj->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
		      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	if (backup)
		SET_FLAG(adj->flags, EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	adj->weight = 0;
	adj->sid = sr_get_local_label();
	sr_debug(
		"  |- Set %s Adj-SID %d for %s",
		backup ? "Backup" : "Primary",
		adj->sid, rawlspid_print(isis_adj->sysid));
	isis_tlvs_add_adj_sid(circuit->ext, adj);

	/* Create corresponding SR Adjacency */
	sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
	sra->adj_sid = adj;
	sra->adj = isis_adj;

	/* Set Nexthop info. */
	sra->nexthop.ifindex = circuit->interface->ifindex;
	sra->nexthop.family = nexthop->family;
	if (nexthop->family == AF_INET)
		IPV4_ADDR_COPY(&sra->nexthop.ip.ipv4, &nexthop->u.prefix4);
	if (nexthop->family == AF_INET6)
		IPV6_ADDR_COPY(&sra->nexthop.ip.ipv6, &nexthop->u.prefix6);

	/* Set Input & Output Label */
	sra->label = sra->adj_sid->sid;
	sra->nexthop.label = MPLS_LABEL_IMPLICIT_NULL;

	/* Finish by configuring MPLS entry */
	sr_adjacency_update_lfib(ZEBRA_MPLS_LABELS_ADD, sra);

	return sra;
}

/* Create new LAN Adjacency SID for the given circuit and adjacency */
static struct sr_adjacency *sr_lan_adj_add(struct isis_circuit *circuit,
					   struct isis_adjacency *isis_adj,
					   struct prefix *nexthop, bool backup)
{
	struct sr_adjacency *sra;
	struct isis_lan_adj_sid *lan;

	/* Create new LAN Adjacency subTLVs */
	lan = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct isis_lan_adj_sid));
	lan->family = nexthop->family;
	lan->flags = EXT_SUBTLV_LINK_ADJ_SID_VFLG
		      | EXT_SUBTLV_LINK_ADJ_SID_LFLG;
	if (backup)
		SET_FLAG(lan->flags, EXT_SUBTLV_LINK_ADJ_SID_BFLG);
	lan->weight = 0;
	memcpy(lan->neighbor_id, isis_adj->sysid, ISIS_SYS_ID_LEN);
	lan->sid = sr_get_local_label();
	sr_debug(
		"  |- Set %s LAN-Adj-SID %d for %s",
		backup ? "Backup" : "Primary",
		lan->sid, rawlspid_print(isis_adj->sysid));
	isis_tlvs_add_lan_adj_sid(circuit->ext, lan);

	/* Create corresponding SR Adjacency */
	sra = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct sr_adjacency));
	sra->lan_sid = lan;
	sra->adj = isis_adj;

	/* Set NHLFE info. */
	sra->nexthop.ifindex = circuit->interface->ifindex;
	sra->nexthop.family = nexthop->family;
	if (nexthop->family == AF_INET)
		IPV4_ADDR_COPY(&sra->nexthop.ip.ipv4, &nexthop->u.prefix4);
	if (nexthop->family == AF_INET6)
		IPV6_ADDR_COPY(&sra->nexthop.ip.ipv6, &nexthop->u.prefix6);

	/* Set Input & Output Label */
	sra->label = sra->lan_sid->sid;
	sra->nexthop.label = MPLS_LABEL_IMPLICIT_NULL;

	/* Finish by configuring MPLS entry */
	sr_adjacency_update_lfib(ZEBRA_MPLS_LABELS_ADD, sra);

	return sra;
}

/* Update Adjacency & LAN Adjacency SID for the given isis adjacency */
static void sr_circuit_update_sid_adjs(struct isis_adjacency *adj,
				       struct prefix *nexthop)
{
	struct isis_circuit *circuit;
	struct sr_node *self;
	struct sr_adjacency *sra;

	circuit = adj->circuit;
	self = get_self_by_area(circuit->area);

	sr_debug("SR(%s): Update Adj-SID for interface %s",
		 __func__, circuit->interface->name);

	if (circuit->ext == NULL) {
		sr_debug("  |- Allocated new Extended subTLVs");
		circuit->ext = isis_alloc_ext_subtlvs();
	}

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Set LAN Adj SID for each neighbors */
		/* Install Primary SID ... */
		sra = sr_lan_adj_add(circuit, adj, nexthop, false);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
#ifdef BACKUP_SID
		/* ... then Backup SID */
		sra = sr_lan_adj_add(circuit, adj, nexthop, true);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
#endif
		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		/* Install Primary SID ... */
		sra = sr_adj_add(circuit, adj, nexthop, false);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
#ifdef BACKUP_SID
		/* ... then Backup SID */
		sra = sr_adj_add(circuit, adj, nexthop, true);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
#endif
		break;
	default:
		break;
	}
}

/* Remove Adjacency SID when isis adjacency state goes DOWN */
static int sr_remove_adj(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit;
	struct sr_node *self;
	struct listnode *node, *nnode;
	struct sr_adjacency *sra;

	/* Process Only Adjacency when goes Down */
	if (adj->adj_state != ISIS_ADJ_DOWN)
		return 0;

	circuit = adj->circuit;
	if (!IS_SR(circuit->area) || (circuit->ext == NULL))
		return 0;

	sr_debug("SR(%s): Adjacency with %s goes DOWN", __func__,
		 print_sys_hostname(adj->sysid));

	/* remove corresponding SR Adjacency */
	self = get_self_by_area(circuit->area);
	for (ALL_LIST_ELEMENTS(self->adj_sids, node, nnode, sra)) {
		if (sra->adj == adj) {
			list_delete_node(self->adj_sids, node);
			del_sr_adj((void *)sra);
			break;
		}
	}

	return 0;
}

/* Master function to install / remove (LAN) Adjacency SID */
void isis_sr_update_adj(struct isis_adjacency *adj, uint8_t family, bool adj_up)
{

	struct prefix nexthop = {};

	/* Sanity Check */
	if (adj == NULL || adj->circuit == NULL)
		return;

	/* Skip loopback */
	if (if_is_loopback(adj->circuit->interface))
		return;

	/* Check is SR is enable */
	if (!IS_SR(adj->circuit->area))
		return;

	sr_debug("SR(%s): %s Adjacency with %s", __func__,
		 adj_up ? "Add" : "Delete", print_sys_hostname(adj->sysid));

	if (adj_up) {
		/* IPv4 */
		if (family == AF_INET) {
			nexthop.family = AF_INET;
			IPV4_ADDR_COPY(&nexthop.u.prefix4,
				       &adj->ipv4_addresses[0]);
			sr_circuit_update_sid_adjs(adj, &nexthop);
		}
		/* and IPv6 */
		if (family == AF_INET6) {
			nexthop.family = AF_INET6;
			IPV6_ADDR_COPY(&nexthop.u.prefix6,
				       &adj->ipv6_addresses[0]);
			sr_circuit_update_sid_adjs(adj, &nexthop);
		}
	} else {
		sr_remove_adj(adj);
	}
}

/* Used by isis_sr_start() to add (LAN) Adjacency SID */
static inline void sr_add_adj(struct isis_adjacency *adj)
{
	if (!adj)
		return;

	if (adj->ipv4_address_count > 0)
		isis_sr_update_adj(adj, AF_INET, true);
	if (adj->ipv6_address_count > 0)
		isis_sr_update_adj(adj, AF_INET6, true);
}

/*
 * Functions that manage local Prefix SID
 *  - update_local_nhlfe() call to compute NHLFE for local prefix
 *  - sr_if_new_hook() call when interface is attached to the isis area
 *  - isis_sr_prefix_add() call by isis_northbound.c when a prefix SID is
 *    configured
 *  - isis_sr_prefix_commit() to finalyse the prefix configuration
 *  - isis_sr_prefix_del() to remove a local prefix SID
 *  - isis_sr_prefix_find() to get SR prefix from a given IPv4 or IPv6 prefix
 */

/* Update NHLFE for local Prefix SID */
static void sr_prefix_update_local_nhlfe(struct sr_prefix *srp,
					 ifindex_t ifindex)
{
	struct isis_nexthop *nh;

	sr_debug("  |- Set Node SID to prefix %pFX ifindex %d",
		 &srp->prefix, ifindex);

	SET_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NODE);

	/* Set NHLFE entries */
	if (srp->nexthops == NULL
	    || listcount(srp->nexthops) == 0)
		nh = sr_nexthop_new(srp);
	else
		nh = (struct isis_nexthop *)listgetdata(
			(struct listnode *)listhead(
				srp->nexthops));
	nh->ifindex = ifindex;
	nh->nhlfe.srnext = NULL;

	/* Set Input and Output Labels */
	srp->label = sr_prefix_get_input_label(srp, srp->srn);
	nhlfe_update_out_label(srp, nh);

	/* Configure LFIB */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
}

/* Update Prefix SID of self Node if interface is the loopback */
static int sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		return 0;

	area = circuit->area;
	if (!IS_SR(area))
		return 0;

	/*
	 * Update the Node-SID flag of the configured Prefix-SID mappings if
	 * necessary. This needs to be done here since isisd reads the startup
	 * configuration before receiving interface information from zebra.
	 */
	if (!if_is_loopback(ifp))
		return 0;

	sr_debug("SR(%s): Update Loopback interface %s", __func__, ifp->name);
	FOR_ALL_INTERFACES_ADDRESSES(ifp, connected, node) {
		struct sr_prefix *srp;

		srp = isis_sr_prefix_find(area, connected->address);
		if (srp)
			sr_prefix_update_local_nhlfe(srp, ifp->ifindex);
	}
	return 0;
}

/* Add Prefix SID to self SR Node */
struct sr_prefix *isis_sr_prefix_add(struct isis_area *area,
				     const struct prefix *prefix)
{
	struct sr_prefix *srp;
	struct sr_node *self;

	self = get_self_by_area(area);

	srp = sr_prefix_new(self, prefix);

	sr_debug("SR(%s): Added Prefix-SID %pFX to self SR-Node %s", __func__,
		 &srp->prefix, print_sys_hostname(self->sysid));

	return srp;
}

/* Once all yang values for Prefix SID are set, commit the configuration */
void isis_sr_prefix_commit(struct sr_prefix *srp)
{
	struct interface *ifp;
	struct isis_area *area;

	/* Sanity Check */
	if ((srp == NULL) || (srp->srn == NULL))
		return;

	area = srp->srn->area;
	if (!IS_SR(area))
		return;

	/* Set flags & NHLFE if interface is Loopback */
	ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp)) {
		sr_prefix_update_local_nhlfe(srp, ifp->ifindex);

		lsp_regenerate_schedule(area, area->is_type, 0);
	}
}

/* Remove Prefix SID from the self SR-Node */
void isis_sr_prefix_del(struct sr_prefix *srp)
{
	struct isis_area *area;

	area = srp->srn->area;
	sr_prefix_del(srp->srn, srp);

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/* Search SR prefix in Self node for the given prefix */
struct sr_prefix *isis_sr_prefix_find(const struct isis_area *area,
				      const struct prefix *prefix)
{
	struct sr_node *self;
	struct sr_prefix key = {};

	if (!IS_SR(area))
		return NULL;

	prefix_copy(&key.prefix, prefix);
	self = get_self_by_area(area);

	return RB_FIND(srnode_prefix_head, &self->pref_sids, &key);
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Get ISIS Route from prefix address */
static struct list *get_route_by_prefix(struct isis_area *area, int level,
					struct prefix p)
{
	struct route_node *rn = NULL;
	struct isis_route_info *rinfo;
	enum spf_tree_id tree_id;

	tree_id = (p.family == AF_INET) ? SPFTREE_IPV4 : SPFTREE_IPV6;

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	tree_id = (p.family == AF_INET) ? SPFTREE_IPV4 : SPFTREE_IPV6;
	rn = route_node_lookup(area->spftree[tree_id][level - 1]->route_table,
			       (struct prefix *)&p);
	/*
	 * Check if we found an ISIS route. May be NULL if SPF has not
	 * yet populate routing table for this prefix.
	 */
	if (rn) {
		route_unlock_node(rn);
		rinfo = rn->info;
		if (rinfo)
			return rinfo->nexthops;
	}

	return NULL;

}

/*
 * L1 routes are preferred over the L2 ones. Check:
 *  - if L2 prefix must be removed for L1 prefix
 *  - or if L1 prefix is already in place for L2 prefix
 */
static int levels_route_precedence(struct isis_area *area,
				      struct sr_prefix *srp)
{
	struct sr_prefix *srp_l1, *srp_l2, key = {};
	struct sr_node *srn = srp->srn;

	/* L1 routes are preferred over the L2 ones. */
	if (area->is_type == IS_LEVEL_1_AND_2) {
		prefix_copy(&key.prefix, &srp->prefix);
		switch (srn->level) {
		case ISIS_LEVEL1:
			srp_l2 = RB_FIND(srdb_prefix_head,
					 &area->srdb.prefix_sids[1], &key);
			if (srp_l2) {
				sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE,
						      srp_l2);
				srp_l2->label = MPLS_INVALID_LABEL;
				srp_l2->nexthops = NULL;
			}
			break;
		case ISIS_LEVEL2:
			srp_l1 = RB_FIND(srdb_prefix_head,
					 &area->srdb.prefix_sids[0], &key);
			if (srp_l1)
				return 1;
			break;
		default:
			break;
		}
	}
	return 0;
}

/* Compute NHLFE entry for Extended Prefix */
static void sr_prefix_update_nhlfe(struct isis_area *area,
				   struct sr_prefix *srp)
{
	struct listnode *node;
	struct isis_nexthop *nh;
	struct sr_node *srnext;
	struct sr_node key = {};
	struct sr_node *self = get_self_by_area(area);

	sr_debug("    |-  Update NHLFE for prefix %pFX", &srp->prefix);

	/* Check L1 route precedence over L2 */
	if (levels_route_precedence(area, srp))
		return;

	/* First determine the route for this prefix */
	srp->nexthops = get_route_by_prefix(area, srp->srn->level, srp->prefix);

	/* Check if SPF has converged for this prefix */
	if (srp->nexthops == NULL)
		return;

	/* Set Input Label with self SRGB */
	srp->label = sr_prefix_get_input_label(srp, self);
	if (srp->label == MPLS_INVALID_LABEL) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, srp->sid.value);
		return;
	}

	/* Process Nexthop list */
	for (ALL_LIST_ELEMENTS_RO(srp->nexthops, node, nh)) {

		/* Search SR node for this nexthop */
		memcpy(key.sysid, nh->adj->sysid, ISIS_SYS_ID_LEN);
		srnext = RB_FIND(srdb_node_head,
				 &area->srdb.sr_nodes[srp->srn->level - 1],
				 &key);
		if (!srnext)
			continue;

		nh->nhlfe.srnext = srnext;
		srnext->neighbor = self;

		if ((nh->family == AF_INET && !IS_SR_IPV4(srnext->cap.srgb))
		    || (nh->family == AF_INET6
			&& !IS_SR_IPV6(srnext->cap.srgb)))
			continue;

		/* then update MPLS labels */
		nhlfe_update_out_label(srp, nh);
	}

	/* Configure LFIB */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
}

/*
 * Functions to manipulate Segment Routing Adjacency & Prefix structures
 */

/*
 * When change the FRR Self SRGB, update the NHLFE Input Label
 * for all Extended Prefix with SID index
 */
static void sr_prefix_update_input_nhlfe(struct sr_node *self,
					 struct sr_prefix *srp)
{
	/* Process Self SR-Node only if NO-PHP is requested */
	if ((srp->srn == self)
	    && !CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP))
		return;

	/*
	 * Route replace semantics can't be used to update the Prefix-SID in
	 * the LFIB. We must first uninstalled the old incoming label.
	 */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);

	/* OK. Now, we could update the incoming label and reinstall LFIB */
	srp->label = index2label(srp->sid.value, self->cap.srgb);
	if (srp->label == MPLS_INVALID_LABEL) {
		flog_warn(EC_ISIS_SID_OVERFLOW,
			  "%s: SID index %u falls outside local SRGB range",
			  __func__, srp->sid.value);
		return;
	}
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
}

/*
 * When a SR-Node becoming active or changed its SRGB, update Output Label for
 * all Extended Prefix with SID index which use the given SR-Node as nexthop
 */
static void sr_prefix_update_out_nhlfe(struct isis_area *area,
				       struct sr_node *srn)
{
	struct isis_nexthop *nh;
	struct listnode *node;
	struct sr_prefix *srp;
	bool update;

	sr_debug("SR(%s): Update all output NHLFE for SR-Node %s", __func__,
		 print_sys_hostname(srn->sysid));

	/* Process only direct neighbor */
	if (srn->neighbor != area->srdb.self)
		return;

	RB_FOREACH(srp, srdb_prefix_head,
		    &area->srdb.prefix_sids[srn->level - 1]) {
		update = false;
		for (ALL_LIST_ELEMENTS_RO(srp->nexthops, node, nh)) {
			/* Process only SID for nexthop equal to SR Node */
			if (nh->nhlfe.srnext != srn)
				continue;

			/* Skip Active SID without NO_PHP flag */
			if ((nh->nhlfe.config != NOP)
			    && (!CHECK_FLAG(srp->sid.flags,
					    ISIS_PREFIX_SID_NO_PHP)))
				continue;

			nhlfe_update_out_label(srp, nh);
			update = true;
		}

		/* Finally, Update LFIB if something change */
		if (update)
			sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
	}
}

/*
 * Following functions are call when new LSPs are received to update SR-DB
 *  - Router Information: sr_cap_update()
 *  - Extended IP Reachability: sr_prefix_update()
 *  - Commit changed for modified SR Prefix: srdb_commit_prefix()
 */
/*
 * Update Segment Routing from Router Information LSA. Return:
 *  -1 if SR node is not active or deactivate
 *  0 if there is no modification
 *  1 if SR node become active or change its SRGB
 */
static int sr_cap_update(struct sr_node *srn, struct isis_router_cap *cap)
{
	int rc = -1;

	/* Check if there is a valid SR capabilities */
	if ((cap == NULL) || (cap->srgb.range_size == 0)
	     || (cap->srgb.lower_bound <= MPLS_LABEL_RESERVED_MAX)) {
		/* Disable active SR-Node */
		if (srn->active)
			sr_node_deactivate(srn);
		return rc;
	}

	rc = 1;

	/* Check if SR-Node is active or not */
	if (!srn->active) {
		srn->active = true;

		/* Copy Router Capabilities */
		memcpy(&srn->cap, cap, sizeof(struct isis_router_cap));

		/* Set Default Algorithm if unset */
		if (srn->cap.algo[0] == SR_ALGORITHM_UNSET)
			srn->cap.algo[0] = SR_ALGORITHM_SPF;

		return rc;
	}

	/* Update Algorithm and MSD if set */
	if (cap->algo[0] != SR_ALGORITHM_UNSET)
		srn->cap.algo[0] = cap->algo[0];

	if (srn->cap.msd != cap->msd)
		srn->cap.msd = cap->msd;

	/* Check if SRGB has changed */
	if (memcmp(&srn->cap.srgb, &cap->srgb, sizeof(struct isis_srgb)) != 0) {
		/* Update SRGB */
		srn->cap.srgb = cap->srgb;

		return rc;
	}

	rc = 0;
	return rc;
}

/* Update Segment Routing prefix SID from Extended IP Reachability TLV */
static void sr_prefix_update(struct sr_node *srn, union prefixconstptr prefix,
			     struct isis_item_list *psids)
{
	struct sr_prefix *srp = NULL;
	struct sr_prefix key = {};
	struct isis_item *i;
	struct isis_prefix_sid *psid = NULL;

	sr_debug("  |- Process Extended IP LSP for Node %s",
		 print_sys_hostname(srn->sysid));

	/* Search for valid Flags & Algorithm */
	for (i = psids->head; i; i = i->next) {
		struct isis_prefix_sid *p = (struct isis_prefix_sid *)i;

		if (CHECK_FLAG(p->flags,
			       ISIS_PREFIX_SID_VALUE | ISIS_PREFIX_SID_LOCAL))
			continue;

		if (p->algorithm != SR_ALGORITHM_SPF)
			continue;
	        /*
	         * Stop the Prefix-SID iteration since we only support the SPF
	         * algorithm for now.
	         */
		psid = p;
	        break;
	}
	/* Check if we got a valid Prefix SID */
	if (!psid)
		return;

	/* Search for existing SR Prefix & create a new one if not found */
	prefix_copy(&key.prefix, prefix.p);
	srp = RB_FIND(srnode_prefix_head, &srn->pref_sids, &key);
	if (!srp) {
		/* Create new Prefix SID information */
		srp = sr_prefix_new(srn, prefix.p);
		srp->status = NEW_SID;
		srp->sid = *psid;
	} else {
		/* Update Prefix SID information if there is new values */
		if ((srp->sid.value != psid->value)
		    || (srp->sid.flags != psid->flags)
		    || (srp->sid.algorithm != psid->algorithm)) {
			srp->sid = *psid;
			srp->status = MODIFIED_SID;
		} else {
			srp->status = ACTIVE_SID;
		}
	}
}

/* Commit all Prefix SID for the Given SR Node */
static void srdb_commit_prefix(struct sr_node *srn)
{
	struct sr_prefix *srp, *next;

	RB_FOREACH_SAFE(srp, srnode_prefix_head, &srn->pref_sids, next) {
		switch (srp->status) {
		case INACTIVE_SID:
			sr_prefix_del(srn, srp);
			break;
		case MODIFIED_SID:
		case NEW_SID:
			/* Update the SR Prefix & NHLFE */
			sr_prefix_update_nhlfe(srn->area, srp);
			break;
		case ACTIVE_SID:
		default:
			break;
		}
		/* Reset status for next update */
		srp->status = INACTIVE_SID;
	}
}

/* Parse Segment Routing prefix from the LSP */
static void srdb_parse_lsp_prefix(struct isis_lsp *lsp, struct sr_node *srn)
{
	struct isis_extended_ip_reach *ipr;
	struct isis_ipv6_reach *ipr6;
	struct isis_item_list *items;
	struct isis_item *i;

	/* Then, Extended IP Reachability */
	for (i = lsp->tlvs->extended_ip_reach.head; i; i = i->next) {
		ipr = (struct isis_extended_ip_reach *)i;
		/* Check that there is a Prefix SID */
		if (!ipr->subtlvs || ipr->subtlvs->prefix_sids.count == 0)
			continue;

		sr_prefix_update(srn, &ipr->prefix, &ipr->subtlvs->prefix_sids);
	}

	/* And, Multi Topology Reachable IPv6 Prefixes */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	for (i = items ? items->head : NULL; i; i = i->next) {
		ipr6 = (struct isis_ipv6_reach *)i;
		/* Check that there is a Prefix SID */
		if (!ipr6->subtlvs || ipr6->subtlvs->prefix_sids.count == 0)
			continue;

		sr_prefix_update(srn, &ipr6->prefix,
				 &ipr6->subtlvs->prefix_sids);
	}
}

/* Parse Segment Routing information from the LSP */
static int srdb_parse_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct sr_node *srn;
	struct listnode *node;
	struct isis_lsp *frag;

	/* First Process Router Capability for remote LSP */
	sr_debug(" |- Process Segment Routing Capability for %s",
		 print_sys_hostname(lsp->hdr.lsp_id));

	/* get SR-Node from LSP */
	srn = get_sr_node_from_lsp(lsp);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_DB,
			 "SR (%s): Abort! can't get SR node in SRDB",
			 __func__);
		return rc;
	}

	/* Parse Router Capabilities */
	rc = sr_cap_update(srn, lsp->tlvs->router_cap);

	/* Update NHLFE if SR-Node is new or update its SRGB */
	if (rc == 1)
		sr_prefix_update_out_nhlfe(lsp->area, srn);

	/* Skip Prefix for inactive SR-Node */
	if (!srn->active)
		return rc;

	/* Parse prefix of the initial LSP, then Fragment if any */
	srdb_parse_lsp_prefix(lsp, srn);
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag))
		srdb_parse_lsp_prefix(frag, srn);

	/* Finally, commit new Prefix SID configuration */
	sr_debug("  |- Commit Prefix SID for SR Node %s",
		 print_sys_hostname(lsp->hdr.lsp_id));
	srdb_commit_prefix(srn);

	rc = 0;
	return rc;
}

/* Remove Segment Routing Node associated to the given LSP from the srdb */
static int srdb_del_srnode_by_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct sr_node *srn;
	struct sr_node key = {};

	/* Self Node is managed by CLI or Northbound interface */
	if (lsp->own_lsp)
		return 0;

	/* Get SR Node in SRDB from LSP ID */
	memcpy(&key.sysid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &lsp->area->srdb.sr_nodes[lsp->level - 1],
		      &key);

	/* Node may not be in SRDB if it has never announced SR capabilities */
	if (srn == NULL)
		return rc;

	/* OK. Let's proceed to SR node de-activation */
	sr_debug(" |- Deactivate SR node %s from LSP %s",
		 print_sys_hostname(srn->sysid),
		 rawlspid_print(lsp->hdr.lsp_id));

	sr_node_deactivate(srn);

	rc = 0;
	return rc;
}

/* Function call by the different LSP Hook to parse LSP */
static int srdb_lsp_event(struct isis_lsp *lsp, lsp_event_t event)
{
	int rc = 0;

	/* Sanity Check */
	if (lsp == NULL || lsp->tlvs == NULL)
		return rc;

	/* Check that SR is initialized and enabled */
	if (!IS_SR(lsp->area))
		return rc;

	/* Pseudo LSP usually not carry SR information. Skip them */
	if (LSP_PSEUDO_ID(lsp->hdr.lsp_id) != 0) {
		sr_debug("SR (%s): Skip Pseudo LSP %s", __func__,
			 rawlspid_print(lsp->hdr.lsp_id));
		return rc;
	}

	/* Skip own lsp as self SR-Node is managed directly */
	if (lsp->own_lsp)
		return rc;

	sr_debug("SR (%s): Process LSP event %s for id %s", __func__,
		 lsp_event2str[event], rawlspid_print(lsp->hdr.lsp_id));

	switch (event) {
	case LSP_ADD:
	case LSP_UPD:
	case LSP_TICK:
		rc = srdb_parse_lsp(lsp);
		break;
	case LSP_DEL:
		rc = srdb_del_srnode_by_lsp(lsp);
		break;
	case LSP_INC:
		/* Self SR-Node is process directly */
		break;
	default:
		rc = 1;
		break;
	}

	return rc;
}

/*
 * Following function is used to update MPLS LFIB after a SPF run and
 * update route for a given prefix
 */
int isis_sr_route_update(struct isis_area *area, struct prefix *prefix,
			 struct isis_route_info *route_info)
{
	struct sr_prefix key = {};
	struct sr_prefix *srp;

	if (!IS_SR(area))
		return 0;

	prefix_copy(&key.prefix, prefix);
	switch (area->is_type) {
	case IS_LEVEL_1:
		srp = RB_FIND(srdb_prefix_head,
			      &area->srdb.prefix_sids[IS_LEVEL_1 - 1], &key);
		break;
	case IS_LEVEL_2:
		srp = RB_FIND(srdb_prefix_head,
			      &area->srdb.prefix_sids[IS_LEVEL_2 - 1], &key);
		break;
	case IS_LEVEL_1_AND_2:
		srp = RB_FIND(srdb_prefix_head,
			      &area->srdb.prefix_sids[IS_LEVEL_1 - 1], &key);
		if (!srp)
			srp = RB_FIND(srdb_prefix_head,
				      &area->srdb.prefix_sids[IS_LEVEL_2 - 1],
				      &key);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown area level",
			 __func__);
		exit(1);
	}

	if (!srp || srp->srn == get_self_by_area(area))
		return 0;

	sr_debug("SR (%s): Update route for prefix %pFX", __func__, prefix);
	if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE)) {
		if (!CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
			/* Update the NHLFE */
			sr_prefix_update_nhlfe(area, srp);
	} else {
		if (CHECK_FLAG(route_info->flag,
			       ISIS_ROUTE_FLAG_ZEBRA_SYNCED)) {
			sr_debug(" |-  Route is inactive. Remove all NHLFE");
			sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);
			srp->nexthops = NULL;
		}
	}

	return 0;
}

/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */
static struct sr_node *get_sr_node_by_id(struct isis_area *area, char *id)
{
	struct sr_node *srn = NULL;
	struct isis_dynhn *dynhn;
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* Convert SR_ID to SYS_ID */
	memset(sysid, 0, ISIS_SYS_ID_LEN);
	if (sysid2buff(sysid, id) == 0) {
		dynhn = dynhn_find_by_name(id);
		if (dynhn == NULL)
			if (memcmp(id, cmd_hostname_get(), strlen(id)) == 0)
				memcpy(sysid, isis->sysid, ISIS_SYS_ID_LEN);
			else
				/* Unknown SR-ID */
				return srn;
		else
			memcpy(sysid, dynhn->id, ISIS_SYS_ID_LEN);
	}

	/* Search SR-Node in IS_LEVEL_1, then in IS_LEVEL_2 if not found */
	struct sr_node key = {};
	memcpy(&key.sysid, sysid, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes[0], &key);
	if (srn == NULL)
		srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes[1], &key);

	return srn;
}

static void show_sr_prefix(struct sbuf *sbuf, struct sr_prefix *srp)
{
	struct listnode *node;
	struct isis_nexthop *nh;
	struct interface *itf;
	char sid[23];
	char op[32];
	int indent = 0;

	sbuf_push(sbuf, 0, "%22pFX  ", &srp->prefix);
	snprintf(sid, 22, "SR Pfx (idx %u)", srp->sid.value);
	sbuf_push(sbuf, 0, "%21s  ", sid);

	for (ALL_LIST_ELEMENTS_RO(srp->nexthops, node, nh)) {
		itf = if_lookup_by_index(nh->ifindex, VRF_DEFAULT);
		if (nh->family == AF_INET)
			sbuf_push(
				sbuf, indent, "%20s  %9s  %pI4\n",
				sr_op2str(op, 32, srp->label, nh->nhlfe.label),
				itf ? itf->name : "-", &nh->ip.ipv4);
		else
			sbuf_push(
				sbuf, indent, "%20s  %9s  %pI6\n",
				sr_op2str(op, 32, srp->label, nh->nhlfe.label),
				itf ? itf->name : "-", &nh->ip.ipv6);
		indent = 47;
	}
}

static void show_sr_node(struct vty *vty, struct sr_node *srn)
{

	struct listnode *node;
	struct sr_adjacency *sra;
	struct sr_prefix *srp;
	struct interface *itf;
	struct sbuf sbuf;
	char sid[22];
	char op[32];
	int value;

	/* Sanity Check */
	if (srn == NULL || !srn->active)
		return;

	sbuf_init(&sbuf, NULL, 0);

	sbuf_push(&sbuf, 0, "SR-Node: %s", print_sys_hostname(srn->sysid));
	sbuf_push(&sbuf, 0, "\tSRGB: [%u - %u]", srn->cap.srgb.lower_bound,
		  (srn->cap.srgb.lower_bound + srn->cap.srgb.range_size - 1));
	sbuf_push(&sbuf, 0, "\tAlgorithm(s): %s",
		  srn->cap.algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF");
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++) {
		if (srn->cap.algo[i] == SR_ALGORITHM_UNSET)
			continue;
		sbuf_push(&sbuf, 0, "/%s",
			  srn->cap.algo[i] == SR_ALGORITHM_SPF ? "SPF"
							       : "S-SPF");
	}
	if (srn->cap.msd != 0)
		sbuf_push(&sbuf, 0, "\tMSD: %u", srn->cap.msd);

	sbuf_push(&sbuf, 0,
		  "\n\n                Prefix       Node or Adj. SID  "
		  "     Label Operation  Interface  Nexthop\n");
	sbuf_push(&sbuf, 0,
		  "----------------------  ---------------------  "
		  "--------------------  ---------  ----------\n");

	RB_FOREACH(srp, srnode_prefix_head, &srn->pref_sids)
		show_sr_prefix(&sbuf, srp);

	for (ALL_LIST_ELEMENTS_RO(srn->adj_sids, node, sra)) {
		if (sra->adj_sid)
			value = sra->adj_sid->sid;
		else if (sra->lan_sid)
			value = sra->lan_sid->sid;
		else
			value = 0;
		snprintf(sid, 22, "SR Adj. (lbl %u)", value);
		itf = if_lookup_by_index(sra->nexthop.ifindex, VRF_DEFAULT);
		if (sra->nexthop.family == AF_INET)
			sbuf_push(&sbuf, 24, "%21s  %20s  %9s  %pI4\n", sid,
				  sr_op2str(op, 32, sra->label,
					    sra->nexthop.label),
				  itf ? itf->name : "-", &sra->nexthop.ip.ipv4);
		else
			sbuf_push(&sbuf, 24, "%21s  %20s  %9s  %pI6\n", sid,
				  sr_op2str(op, 32, sra->label,
					    sra->nexthop.label),
				  itf ? itf->name : "-", &sra->nexthop.ip.ipv6);
	}

	vty_out(vty, "%s\n", sbuf_buf(&sbuf));

	sbuf_free(&sbuf);
}

DEFUN (show_isis_srdb,
       show_isis_srdb_cmd,
       "show isis database segment-routing [WORD]",
       SHOW_STR
       PROTO_HELP
       "Database summary\n"
       "Show Segment Routing Data Base\n"
       "Advertising SR node ID (as SYS-ID address, node name or 'gdb self' for current node)\n")
{
	int idx = 0;
	struct sr_node *srn;
	char *sr_id;
	struct listnode *node;
	struct isis_area *area;

	if (isis->area_list->count == 0)
		return CMD_SUCCESS;

	sr_id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg : NULL;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		if (!IS_SR(area)) {
			vty_out(vty,
				"    Segment Routing is disabled on this area\n\n");
			continue;
		}

		if (sr_id) {
			if (memcmp(sr_id, "self", 4) == 0)
				srn = get_self_by_area(area);
			else
				srn = get_sr_node_by_id(area, sr_id);

			/* SR Node may be not part of this area */
			if (srn == NULL)
				continue;

			vty_out(vty,
				"ISIS Level-%d Segment Routing database:\n\n",
				srn->level);

			show_sr_node(vty, srn);
			return CMD_SUCCESS;
		}

		/* No node have been provided, Iterate through all the SRDB */
		for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
			if (RB_EMPTY(srdb_node_head,
				     &area->srdb.sr_nodes[level - 1]))
				continue;
			vty_out(vty,
				"ISIS Level-%d Segment Routing database:\n\n",
				level);
			RB_FOREACH(srn, srdb_node_head,
				    &area->srdb.sr_nodes[level - 1])
				show_sr_node(vty, srn);
		}
	}
	return CMD_SUCCESS;
}

/* Install new CLI commands */
static void isis_sr_register_vty(void)
{
	install_element(VIEW_NODE, &show_isis_srdb_cmd);
}

/*
 * Other Segment Routing functions are define in isis_cli.c file which use
 * yang model define in isis_northbound.c file
 */

/*
 * Segment Routing configuration functions call by isis_northbound.c
 *  - isis_sr_srgb_update() call when SRGB is set or modified
 *  - isis_sr_msd_update() call when MSD is set or modified
 */
void isis_sr_srgb_update(struct isis_area *area)
{
	struct sr_prefix *srp;
	struct isis_sr_db *srdb = &area->srdb;
	struct sr_node *self = srdb->self;
	uint32_t size;

	/* Release old Label Range */
	if (srdb->srgb_lm)
		isis_zebra_release_label_range(
			self->cap.srgb.lower_bound,
			self->cap.srgb.lower_bound + self->cap.srgb.range_size
				- 1);

	/* Reserve new range */
	size = srdb->upper_bound - srdb->lower_bound + 1;
	if (isis_zebra_request_label_range(srdb->lower_bound, size) == 0) {
		/* Set SID/Label range SRGB */
		srdb->srgb_lm = true;
		self->cap.srgb.lower_bound = srdb->lower_bound;
		self->cap.srgb.range_size = size;

		sr_debug("SR(%s): Update SRGB with new range %d-%d",
			__func__, srdb->lower_bound, srdb->upper_bound);

		/* Update NHLFE entries for all Prefix SIDs */
		for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
			RB_FOREACH(srp, srdb_prefix_head,
				   &srdb->prefix_sids[level - 1])
				sr_prefix_update_input_nhlfe(self, srp);
		}
	} else {
		flog_err(EC_ISIS_SR_LM,
			 "SR(%s): Error getting MPLS Label Range. Disable SR!",
			 __func__);
		isis_sr_stop(area);
	}

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_msd_update(struct isis_area *area)
{
	struct sr_node *self;

	/* Set this router MSD */
	self = get_self_by_area(area);

	self->cap.msd = area->srdb.msd;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

/*
 * Functions to manage Segment Routing on a per ISIS Area
 *  - isis_sr_create() call when area is created
 *  - isis_sr_destroy() call when area is removed
 *  - isis_sr_start() call when segment routing is activate
 *  - isis_sr_stop() call when segment routing is deactivate
 *  - isis_sr_init() call when isis start
 *  - isis_sr_term() call when isis stop
 */
void isis_sr_create(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR(%s): Creating SRDB for area %s", __func__, area->area_tag);

	memset(srdb, 0, sizeof(struct isis_sr_db));
	srdb->enabled = false;
	srdb->self = NULL;

	/* Initialize SRGB, Algorithms and MSD TLVs */
	/* Only Algorithm SPF is supported */
	srdb->algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < SR_ALGORITHM_COUNT; i++)
		srdb->algo[i] = SR_ALGORITHM_UNSET;

	/* Default values */
	srdb->msd = 0;
	srdb->lower_bound = SRGB_LOWER_BOUND;
	srdb->upper_bound = SRGB_UPPER_BOUND;

	/* Initialize SR Nodes & SR Prefix RB Tree */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		RB_INIT(srdb_node_head, &srdb->sr_nodes[level - 1]);
		RB_INIT(srdb_prefix_head, &srdb->prefix_sids[level - 1]);
	}
}

void isis_sr_destroy(struct isis_area *area)
{

	struct isis_sr_db *srdb = &area->srdb;
	struct sr_node *self = srdb->self;
	struct sr_prefix *srp, *next;

	sr_debug("SR(%s): Deleting SRDB for area %s", __func__, area->area_tag);

	/* First, stop SR if always enabled */
	if (IS_SR(area))
		isis_sr_stop(area);

	/* Remove Self SR Prefix & Self Node */
	RB_FOREACH_SAFE(srp, srnode_prefix_head, &self->pref_sids, next) {
		list_delete(&srp->nexthops);
		RB_REMOVE(srdb_prefix_head, &srdb->prefix_sids[self->level - 1],
			  srp);
		RB_REMOVE(srnode_prefix_head, &self->pref_sids, srp);
		XFREE(MTYPE_ISIS_SR, srp);
	}
	RB_REMOVE(srdb_node_head, &srdb->sr_nodes[self->level - 1], self);
	XFREE(MTYPE_ISIS_SR, self);

	memset(srdb, 0, sizeof(struct isis_sr_db));
	srdb->enabled = false;
	srdb->self = NULL;
}

void isis_sr_start(struct isis_area *area)
{
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *cnode, *anode;
	struct isis_sr_db *srdb = &area->srdb;
	struct sr_node *self;
	struct sr_prefix *srp;
	struct isis_lsp *lsp;
	uint32_t size;

	sr_debug("SR(%s): Starting Segment Routing", __func__);
	srdb->enabled = true;

	/* Reserve Labels Range for SRGB */
	size = srdb->upper_bound - srdb->lower_bound + 1;
	if (isis_zebra_request_label_range(srdb->lower_bound, size) != 0) {
		flog_err(
			EC_ISIS_SR_LM,
			"SR(%s): Can't start SR. Label ranges are not reserved",
			__func__);
		return;
	}
	srdb->srgb_lm = true;

	/* Initialize self SR Node */
	self = srdb->self;
	if (self == NULL) {
		/* Create Self SR-Node and register it in SRDB */
		self = sr_node_new(area->isis->sysid);
		self->area = area;
		srdb->self = self;

		/* Self SR-Node is Level 2 only if area is ISIS L2 Only */
		if (area->is_type == IS_LEVEL_2)
			self->level = ISIS_LEVEL2;
		else
			self->level = ISIS_LEVEL1;

		RB_INSERT(srdb_node_head, &srdb->sr_nodes[self->level - 1],
			  self);
	}
	self->cap.flags = ISIS_SUBTLV_SRGB_FLAG_I | ISIS_SUBTLV_SRGB_FLAG_V;
	self->cap.srgb.lower_bound = area->srdb.lower_bound;
	self->cap.srgb.range_size =
		area->srdb.upper_bound - area->srdb.lower_bound + 1;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		self->cap.algo[i] = area->srdb.algo[i];
	self->cap.msd = area->srdb.msd;
	self->active = true;

	/* Initialize Adjacency for all circuit belongs to this area */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2;
			     level++) {
				struct list *adjdb =
					circuit->u.bc.adjdb[level - 1];
				for (ALL_LIST_ELEMENTS_RO(adjdb, anode, adj))
					sr_add_adj(adj);
			}
		} else if (circuit->circ_type == CIRCUIT_T_P2P)
			sr_add_adj(circuit->u.p2p.neighbor);
	}

	/* Initialize Prefix SID that have been pre-configured in yang */
	RB_FOREACH(srp, srnode_prefix_head, &self->pref_sids) {
		ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
		if (ifp && if_is_loopback(ifp))
			sr_prefix_update_local_nhlfe(srp, ifp->ifindex);
	}

	/*
	 * Parse LSP-DB to handle the case when Segment Routing is enabled
	 * while isis is already running
	 */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++)
		frr_each (lspdb, &area->lspdb[level - 1], lsp)
			srdb_lsp_event(lsp, LSP_UPD);

	/* Flood SR LSP information */
	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_stop(struct isis_area *area)
{
	struct sr_node *srn, *srnext;
	struct sr_prefix *srp, *srp_next;
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR (%s): Stopping Segment Routing", __func__);

	/* Stop SR */
	srdb->enabled = false;

	/*
	 * Remove all SR Nodes from the RB Tree except self SR Node.
	 * Prefix will be removed with the SR-Node deletion: See sr_node_del()
	 */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++) {
		RB_FOREACH_SAFE(srn, srdb_node_head,
				 &srdb->sr_nodes[level - 1], srnext) {
			if (srn != srdb->self)
				sr_node_del(srdb, srn);
		}
	}

	/* Uninstall own Prefix and Adjacency SID */
	sr_debug("  |- Clean Self SR Node %s",
		 print_sys_hostname(srdb->self->sysid));
	srn = srdb->self;
	srn->active = false;

	/* Reset Adjacency list */
	list_delete(&srn->adj_sids);
	srn->adj_sids = list_new();
	srn->adj_sids->del = del_sr_adj;

	/* Uninstall Prefix SID */
	RB_FOREACH_SAFE(srp, srnode_prefix_head, &srn->pref_sids, srp_next)
		sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);

	/* Release Labels range of SRGB */
	if (srdb->srgb_lm)
		isis_zebra_release_label_range(srdb->lower_bound,
					       srdb->upper_bound);

	sr_debug("SR (%s): Segment Routing stopped!\n", __func__);

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_init(void)
{
	/* Register Various event hook */
	hook_register_prio(isis_lsp_event_hook, 100, srdb_lsp_event);
	hook_register(isis_if_new_hook, sr_if_new_hook);
	hook_register(isis_adj_state_change_hook, sr_remove_adj);
	hook_register(isis_route_update_hook, isis_sr_route_update);

	/* Install show command */
	isis_sr_register_vty();
}

void isis_sr_term(void)
{
	/* Unregister various event hook */
	hook_unregister(isis_lsp_event_hook, srdb_lsp_event);
	hook_unregister(isis_if_new_hook, sr_if_new_hook);
	hook_unregister(isis_adj_state_change_hook, sr_remove_adj);
	hook_register(isis_route_update_hook, isis_sr_route_update);
}
