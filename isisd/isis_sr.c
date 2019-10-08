/*
 * This is an implementation of Segment Routing for IS-IS
 * as per draft draft-ietf-isis-segment-routing-extensions-22
 *
 * Module name: Segment Routing
 *
 * Copyright (C) 2019 Orange Labs http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDef
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

	if (sra->adj_sid)
		isis_tlvs_del_adj_sid(sra->adj->circuit->ext, sra->adj_sid);
	if (sra->lan_sid)
		isis_tlvs_del_lan_adj_sid(sra->adj->circuit->ext, sra->lan_sid);

	sr_adjacency_update_lfib(ZEBRA_MPLS_LABELS_DELETE, sra);

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

	nh = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_nhlfe));
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
	RB_INSERT(srdb_prefix_head, &srn->area->srdb.prefix_sids, srp);
	RB_INSERT(srnode_prefix_head, &srn->pref_sids, srp);

	return srp;
}

/* Remove Prefix SID from the given SR Node */
static void sr_prefix_del(struct sr_node *srn, struct sr_prefix *srp)
{
	struct isis_area *area;

	sr_debug("   |- Remove Prefix-SID %pFX from SR-Node %s",
		 &srp->prefix, print_sys_hostname(srn->sysid));

	/* Remove NHLFE associated to this SR prefix */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);

	/* Clean nexthop list if Self Node */
	if (IS_SELF(srn))
		list_delete(&srp->nexthops);

	/* Remove SRP from SR Node & SR-DB */
	area = srn->area;
	RB_REMOVE(srdb_prefix_head, &area->srdb.prefix_sids, srp);
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

/* Delete Segment Routing node */
static void sr_node_del(struct sr_node *srn)
{
	struct sr_prefix *srp;

	/* Sanity Check */
	if (srn == NULL)
		return;

	sr_debug(" |- Remove SR Node %s", print_sys_hostname(srn->sysid));
	/* Clean Adjacency List */
	list_delete(&srn->adj_sids);

	/* Clean Prefix RB Tree */
	while (!RB_EMPTY(srnode_prefix_head, &srn->pref_sids)) {
		srp = RB_ROOT(srnode_prefix_head, &srn->pref_sids);
		sr_prefix_del(srn, srp);
	}

	/* Remove the SR Node from the SRDB */
	if (srn->area != NULL)
		RB_REMOVE(srdb_node_head, &srn->area->srdb.sr_nodes, srn);
	XFREE(MTYPE_ISIS_SR, srn);
}

/* Get SR Node self */
static struct sr_node *get_self_by_area(const struct isis_area *area)
{
	struct sr_node *self = NULL;

	if (IS_SR(area))
		self = area->srdb.self;

	return self;
}

static struct sr_node *get_self_by_node(struct sr_node *srn)
{
	return srn ? get_self_by_area(srn->area) : NULL;
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

		    if (nh->nhlfe.config == NOP)
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
static mpls_label_t sr_prefix_in_label(const struct sr_prefix *srp,
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
static mpls_label_t sr_prefix_out_label(const struct sr_prefix *srp,
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

/* Compute and configure MPLS label for a given prefix and nexthop */
static void update_sr_prefix_labels(struct sr_prefix *srp,
				    struct sr_nhlfe *nhlfe)
{
	struct sr_node *self = get_self_by_node(srp->srn);
	char buf[32];


	/* Set Input Label with self SRGB */
	srp->label = sr_prefix_in_label(srp, self);

	/*
	 * Set Output Label with
	 *  - Implicit Null label if it is the self node and request NO-PHP,
	 *    MPLS_INVALIDE_LABEL otherwise
	 *  - Implicit / Explicit Null label if next hop is the destination and
	 *    request NO_PHP / EXPLICIT NULL label
	 *  - Value label or SID in Next hop SR Node SRGB for other cases
	 */
	nhlfe->label = sr_prefix_out_label(srp, nhlfe->srnext);

	/* Determine the MPLS configuration to apply */
	switch (nhlfe->label) {
	case MPLS_INVALID_LABEL:
		nhlfe->config = NOP;
		break;
	case MPLS_LABEL_IMPLICIT_NULL:
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		if (srp->srn == self)
			nhlfe->config = POP_TO_IFINDEX;
		else
			nhlfe->config = SWAP;
		break;
	default:
		nhlfe->config = SWAP;
		break;
	}

	sr_debug("    |-  Computed new SR operation: %s",
		 sr_op2str(buf, 32, srp->label, nhlfe->label));
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
	lan = XCALLOC(MTYPE_ISIS_SR, sizeof(struct isis_lan_adj_sid));
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
	sra = XCALLOC(MTYPE_ISIS_SR, sizeof(struct sr_adjacency));
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

	sr_debug("SR(%s): Update Adj-SID for interface %s with nexthop %pFX",
		 __func__, circuit->interface->name, nexthop);

	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		sr_debug("  |- Allocated new Extended subTLVs for interface %s",
			 circuit->interface->name);
	}

	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		/* Set LAN Adj SID for each neighbors */
		/* Install Primary SID ... */
		sra = sr_lan_adj_add(circuit, adj, nexthop, false);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
		/* ... then Backup SID */
		sra = sr_lan_adj_add(circuit, adj, nexthop, true);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);

		SET_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID);
		break;
	case CIRCUIT_T_P2P:
		/* Install Primary SID ... */
		sra = sr_adj_add(circuit, adj, nexthop, false);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
		/* ... then Backup SID */
		sra = sr_adj_add(circuit, adj, nexthop, true);
		sra->srn = self;
		listnode_add(self->adj_sids, sra);
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
		}
	}

	return 0;
}

/* Master function to install / remove (LAN) Adjacency SID */
void isis_sr_update_adj(struct isis_adjacency *adj, uint8_t family, bool adj_up)
{

	struct prefix nexthop;

	/* Sanity Check */
	if (adj == NULL || adj->circuit == NULL)
		return;

	/* Skip loopback */
	if (if_is_loopback(adj->circuit->interface))
		return;

	/* Check is SR is enable */
	if (!IS_SR(adj->circuit->area))
		return;

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
	isis_sr_update_adj(adj, AF_INET, true);
	isis_sr_update_adj(adj, AF_INET6, true);
}

/*
 * Functions that manage local Prefix SID
 *  - sr_if_new_hook() call when interface is attached to the isis area
 *  - isis_sr_prefix_add() call by isis_northbound.c when a prefix SID is
 *    configured
 *  - isis_sr_prefix_commit() to finalyse the prefix configuration
 *  - isis_sr_prefix_del() to remove a local prefix SID
 *  - isis_sr_prefix_find() to get SR prefix from a given IPv4 or IPv6 prefix
 */

/* Update Prefix SID of self Node if interface is the loopback */
static int sr_if_new_hook(struct interface *ifp)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct connected *connected;
	struct listnode *node;
	struct isis_nexthop *nh;

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
		if (srp) {
			sr_debug("  |- Set Node SID to prefix %pFX ifindex %d",
				 &srp->prefix, ifp->ifindex);
			SET_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NODE);
			/* Set MPLS entry */
			if (srp->nexthops == NULL
			    || listcount(srp->nexthops) == 0)
				nh = sr_nexthop_new(srp);
			else
				nh = (struct isis_nexthop *)listgetdata(
					(struct listnode *)listhead(
						srp->nexthops));
			nh->ifindex = ifp->ifindex;
			nh->nhlfe.srnext = NULL;
			update_sr_prefix_labels(srp, &nh->nhlfe);
		}
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
	if (self == NULL)
		return NULL;

	srp = sr_prefix_new(self, prefix);

	sr_debug("SR(%s): Added Prefix-SID %pFX to self SR-Node %s", __func__,
		 &srp->prefix, print_sys_hostname(self->sysid));

	return srp;
}

/* Once all yang values for Prefix SID are set, commit the configuration */
void isis_sr_prefix_commit(struct sr_prefix *srp)
{
	struct interface *ifp;
	struct isis_nexthop *nh;
	struct isis_area *area;

	/* Sanity Check */
	if ((srp == NULL) || (srp->srn == NULL))
		return;

	area = srp->srn->area;
	if (!IS_SR(area))
		return;

	/* Verify that SID index is less than SRGB upper bound */
	if (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_VALUE)
	    && (srp->sid.value > srp->srn->area->srdb.upper_bound - 1)) {
		flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
			  "Index is out of SRGB range");
		isis_sr_prefix_del(srp);
		return;
	}

	/* Set flags & NHLFE if interface is Loopback */
	ifp = if_lookup_prefix(&srp->prefix, VRF_DEFAULT);
	if (ifp && if_is_loopback(ifp)) {
		sr_debug("  |- Add this prefix as Node-SID to Loopback");
		SET_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NODE);
		sr_debug("  |- New flags: 0x%x", srp->sid.flags);
		if (srp->nexthops == NULL || listcount(srp->nexthops) == 0)
			nh = sr_nexthop_new(srp);
		else
			nh = (struct isis_nexthop *)listgetdata(
				(struct listnode *)listhead(srp->nexthops));
		nh->ifindex = ifp->ifindex;
		nh->nhlfe.srnext = NULL;
		update_sr_prefix_labels(srp, &nh->nhlfe);

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
	if (!self)
		return NULL;

	return RB_FIND(srnode_prefix_head, &self->pref_sids, &key);
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

#ifdef OLD
/* Merge nexthop IPv4 list and NHLFE for a given SR Prefix */
static void nhlfe_merge_nexthop(struct isis_area *area,
				struct sr_prefix *srp,
				struct list *nexthop)
{
	struct listnode *node, *snode;
	struct isis_nexthop *nh;
	struct sr_nhlfe *nhlfe;
	struct sr_node key = {};
	struct sr_node *srnext;
	bool found;

	/*
	 * Compare both list, mark unchanged if found or create new one
	 * old value will be remove later
	 */
	for (ALL_LIST_ELEMENTS_RO(nexthop, node, nh)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, snode, nhlfe)) {
			/* Mark HLFE Active if found */
			if (IPV4_ADDR_SAME(&nhlfe->nexthop, &nh->ip)) {
				nhlfe->state = UPDATED_NH;
				found = true;
				break;
			}
		}
		if (!found) {
			nhlfe = sr_nhlfe_new(srp);
			IPV4_ADDR_COPY(&nhlfe->nexthop, &nh->ip);
			nhlfe->ifindex = nh->ifindex;
			nhlfe->state = NEW_NH;
			memcpy(key.sysid, nh->adj->sysid, ISIS_SYS_ID_LEN);
			srnext = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
					 &key);
			nhlfe->srnext = srnext;
			srnext->neighbor = get_self_by_area(area);
		}
	}
}

/* Merge nexthop IPv6 list and NHLFE for a given SR Prefix */
static void nhlfe_merge_nexthop6(struct isis_area *area, struct sr_prefix *srp,
				 struct list *nexthop)
{
	struct listnode *node, *snode;
	struct isis_nexthop6 *nh6;
	struct sr_nhlfe *nhlfe;
	struct sr_node key = {};
	struct sr_node *srnext;
	bool found;

	/*
	 * Compare both list, mark unchanged if found or create new one
	 * old value will be remove later
	 */
	for (ALL_LIST_ELEMENTS_RO(nexthop, node, nh6)) {
		found = false;
		for (ALL_LIST_ELEMENTS_RO(srp->nhlfes, snode, nhlfe)) {
			/* Mark HLFE Active if found */
			if (IPV6_ADDR_SAME(&nhlfe->nexthop6, &nh6->ip6)) {
				nhlfe->state = UPDATED_NH;
				found = true;
				break;
			}
		}
		if (!found) {
			nhlfe = sr_nhlfe_new(srp);
			IPV6_ADDR_COPY(&nhlfe->nexthop6, &nh6->ip6);
			nhlfe->ifindex = nh6->ifindex;
			nhlfe->state = NEW_NH;
			memcpy(key.sysid, nh6->adj->sysid, ISIS_SYS_ID_LEN);
			srnext = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
					 &key);
			nhlfe->srnext = srnext;
			srnext->neighbor = get_self_by_area(area);
		}
	}
}
#endif

/* Get ISIS Route from prefix address */
static struct list *get_route_by_prefix(struct isis_area *area,
					struct prefix p)
{
	struct route_node *rn = NULL;
	struct route_table *table;
	struct isis_route_info *rinfo;
	uint8_t tree;

	/* Sanity Check */
	if (area == NULL)
		return NULL;

	switch (p.family) {
	case AF_INET:
		tree = SPFTREE_IPV4;
		break;
	case AF_INET6:
		tree = SPFTREE_IPV6;
		break;
	default:
		return NULL;
	}

	switch (area->is_type) {
	case IS_LEVEL_1:
		table = area->spftree[tree][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_2:
		table = area->spftree[tree][1]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		break;
	case IS_LEVEL_1_AND_2:
		table = area->spftree[tree][0]->route_table;
		rn = route_node_lookup(table, (struct prefix *)&p);
		if (rn == NULL) {
			table = area->spftree[tree][1]->route_table;
			rn = route_node_lookup(table, (struct prefix *)&p);
		}
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unknown ISIS Level",
			 __func__);
		break;
	}

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

/* Compute NHLFE entry for Extended Prefix */
static int update_prefix_nhlfe(struct isis_area *area, struct sr_prefix *srp)
{
	struct listnode *node, *nnode;
	struct isis_nexthop *nh;
	struct sr_node *srnext;
	struct sr_node key = {};
	struct sr_node *self = get_self_by_area(area);
	int rc = -1;

	sr_debug("    |-  Update NHLFE for prefix %pFX", &srp->prefix);

	/* First determine the route for this prefix */
	srp->nexthops = get_route_by_prefix(area, srp->prefix);

	/* Check if SPF has converged for this prefix */
	if (srp->nexthops == NULL)
		return rc;

	/* Process Nexthop list */
	for (ALL_LIST_ELEMENTS(srp->nexthops, node, nnode, nh)) {

		/* Search SR node for this nexthop */
		memcpy(key.sysid, nh->adj->sysid, ISIS_SYS_ID_LEN);
		srnext = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
				 &key);
		if (!srnext)
			continue;

		nh->nhlfe.srnext = srnext;
		srnext->neighbor = self;

		/* then update MPLS labels */
		update_sr_prefix_labels(srp, &nh->nhlfe);
	}

	/* Configure LFIB */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
	rc = 1;
	return rc;
}

/*
 * Functions to manipulate Segment Routing Adjacency & Prefix structures
 */

/*
 * When change the FRR Self SRGB, update the NHLFE Input Label
 * for all Extended Prefix with SID index
 */
static void update_in_nhlfe(struct sr_node *self, struct sr_prefix *srp)
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

	/* OK. Now, we could update the incoming label */
	srp->label = index2label(srp->sid.value, self->cap.srgb);
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
}

/*
 * When SRGB has changed, update NHLFE Output Label for all Extended Prefix
 * with SID index which use the given SR-Node as nexthop
 */
static void update_out_nhlfe(struct sr_prefix *srp, struct sr_node *srnext)
{
	struct isis_nexthop *nh;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srp->nexthops, node, nh)) {
		/*
		 * Process only SID Index for next hop without PHP and equal
		 * to SR Node
		 */
		if ((nh->nhlfe.srnext != srnext)
		    || (!CHECK_FLAG(srp->sid.flags, ISIS_PREFIX_SID_NO_PHP)))
			continue;

		nh->nhlfe.label = index2label(srp->sid.value, srnext->cap.srgb);
	}

	/* Finally, Update LFIB */
	sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_REPLACE, srp);
}

/*
 * Following functions are call when new LSPs are received to update SR-DB
 *  - Router Information: sr_ri_update() & sr_ri_delete()
 *  - Extended IS Reachability: sr_ext_is_update() & sr_ext_is_delete()
 *  - Extended IP Reachability: sr_prefix_update() & sr_prefix_delete()
 */
/* Update Segment Routing from Router Information LSA */
static struct sr_node *sr_cap_update(struct isis_area *area, uint8_t *lspid,
				     struct isis_router_cap *cap)
{
	struct sr_node *srn;
	struct sr_node key = {};

	/* Get SR Node in SRDB from ID */
	memcpy(&key.sysid, lspid, ISIS_SYS_ID_LEN);
	srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes, &key);
	/* Create new one if not found */
	if (srn == NULL) {
		srn = sr_node_new(lspid);
		/* Sanity check in case of */
		if (srn == NULL) {
			flog_err(EC_ISIS_SR_NODE_CREATE,
				 "SR (%s): Abort! can't create SR node in SRDB",
				 __func__);
			return NULL;
		}
		RB_INSERT(srdb_node_head, &area->srdb.sr_nodes, srn);
	}

	/* Update Algorithms and Node MSD */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = cap->algo[i];
	/* Set Default Algorithm if unset */
	if (srn->cap.algo[0] == SR_ALGORITHM_UNSET)
		srn->cap.algo[0] = SR_ALGORITHM_SPF;

	/* Update MSD */
	if (srn->cap.msd != cap->msd)
		srn->cap.msd = cap->msd;

	/* Check if it is a new SR Node or not */
	if (srn->area == NULL) {
		srn->area = area;
		/* Copy SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		return srn;
	}

	/* Check if SRGB has changed */
	if ((srn->cap.srgb.range_size != cap->srgb.range_size)
	    || (srn->cap.srgb.lower_bound != cap->srgb.lower_bound)) {
		/* Update SRGB */
		srn->cap.srgb.range_size = cap->srgb.range_size;
		srn->cap.srgb.lower_bound = cap->srgb.lower_bound;
		/* Update NHLFE if it is a direct neighbor of self SR node */
		if (srn->neighbor == area->srdb.self) {
			struct sr_prefix *srp;

			RB_FOREACH (srp, srdb_prefix_head,
				    &area->srdb.prefix_sids)
				update_out_nhlfe(srp, srn);
		}
	}

	return srn;
}

/* Update Segment Routing prefix SID from Extended IP Reachability TLV */
static void sr_prefix_update(struct sr_node *srn, union prefixconstptr prefix,
			     struct isis_prefix_sid *psid)
{
	struct sr_prefix *srp = NULL;
	struct sr_prefix key = {};

	sr_debug("  |- Process Extended IP LSP for Node %s",
		 print_sys_hostname(srn->sysid));

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

	sr_debug("   |-  %s Prefix SID %pFX for SR-Node %s",
		 sr_status2str[srp->status], &srp->prefix,
		 print_sys_hostname(srn->sysid));
}

/* Commit all Prefix SID for the Given SR Node */
static void srdb_commit_prefix(struct sr_node *srn)
{
	struct sr_prefix *srp, *next;

	RB_FOREACH_SAFE(srp, srnode_prefix_head, &srn->pref_sids, next) {
		sr_debug("   |-  Commit Prefix SID %pFX", &srp->prefix);

		switch (srp->status) {
		case INACTIVE_SID:
			sr_prefix_del(srn, srp);
			break;
		case MODIFIED_SID:
		case NEW_SID:
			/* Update the SR Prefix & NHLFE */
			update_prefix_nhlfe(srn->area, srp);
			break;
		case ACTIVE_SID:
		default:
			break;
		}
		/* Reset status for next update */
		srp->status = INACTIVE_SID;
	}
}

/* Parse Segment Routing information from the LSP */
static int srdb_parse_lsp(struct isis_lsp *lsp)
{
	int rc = 1;
	struct sr_node *srn;
	struct isis_extended_ip_reach *ipr;
	struct isis_ipv6_reach *ipr6;
	struct isis_prefix_sid *psid;
	struct isis_item_list *items;

	/* First Process Router Capability for remote LSP */
	sr_debug(" |- Process Segment Routing Capability for %s",
		 print_sys_hostname(lsp->hdr.lsp_id));

	if (!lsp->own_lsp)
		srn = sr_cap_update(lsp->area, lsp->hdr.lsp_id,
				    lsp->tlvs->router_cap);
	else
		srn = get_self_by_area(lsp->area);

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_ISIS_SR_NODE_CREATE,
			 "SR (%s): Abort! can't get SR node in SRDB",
			 __func__);
		return rc;
	}

	/* Then, Extended IP Reachability */
	for (ipr = (struct isis_extended_ip_reach *)
			   lsp->tlvs->extended_ip_reach.head;
	     ipr != NULL; ipr = ipr->next) {
		/* Check that there is a Prefix SID */
		if (ipr->subtlvs && ipr->subtlvs->prefix_sids.count != 0) {
			psid = (struct isis_prefix_sid *)
				       ipr->subtlvs->prefix_sids.head;
			sr_prefix_update(srn, &ipr->prefix, psid);
		}
	}

	/* And, Multi Topology Reachable IPv6 Prefixes */
	items = isis_lookup_mt_items(&lsp->tlvs->mt_ipv6_reach,
				     ISIS_MT_IPV6_UNICAST);
	if (items != NULL) {
		for (ipr6 = (struct isis_ipv6_reach *)items->head; ipr6;
		     ipr6 = ipr6->next) {
			/* Check that there is a Prefix SID */
			if (ipr6->subtlvs
			    && ipr6->subtlvs->prefix_sids.count != 0) {
				psid = (struct isis_prefix_sid *)
					       ipr6->subtlvs->prefix_sids.head;
				sr_prefix_update(srn, &ipr6->prefix, psid);
			}
		}
	}

	/* Finally, commit new Prefix SID configuration */
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
	srn = RB_FIND(srdb_node_head, &lsp->area->srdb.sr_nodes, &key);

	/* Node may not be in SRDB if it has never announced SR capabilities */
	if (srn == NULL) {
		sr_debug("SR (%s): No entry in SRDB for SR Node %s",
			 __func__, print_sys_hostname(key.sysid));
		return rc;
	}

	/* OK. Let's proceed to SR node removal */
	sr_debug(" |- Remove SR node %s from LSP %s",
		 print_sys_hostname(srn->sysid),
		 rawlspid_print(lsp->hdr.lsp_id));

	sr_node_del(srn);

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

	sr_debug("SR (%s): Process LSP id %s", __func__,
		 rawlspid_print(lsp->hdr.lsp_id));

	/* Fragment usually not carry SR information. Skip them */
	if (LSP_PSEUDO_ID(lsp->hdr.lsp_id) != 0
	    || LSP_FRAGMENT(lsp->hdr.lsp_id) != 0) {
		sr_debug("SR (%s): Skip Pseudo or fragment LSP %s", __func__,
			 rawlspid_print(lsp->hdr.lsp_id));
		return rc;
	}

	sr_debug("SR (%s): Process LSP id %s", __func__,
		 rawlspid_print(lsp->hdr.lsp_id));

	switch (event) {
	case LSP_ADD:
	case LSP_UPD:
	case LSP_TICK:
		/* Check that there is a valid SR info in this LSP */
		if (((lsp->tlvs->router_cap != NULL)
		     && (lsp->tlvs->router_cap->srgb.range_size != 0)
		     && (lsp->tlvs->router_cap->srgb.lower_bound
			 > MPLS_LABEL_RESERVED_MAX)))
			rc = srdb_parse_lsp(lsp);
		else
			rc = srdb_del_srnode_by_lsp(lsp);
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

	sr_debug("SR (%s): Update route for prefix %pFX", __func__, prefix);

	prefix_copy(&key.prefix, prefix);
	srp = RB_FIND(srdb_prefix_head, &area->srdb.prefix_sids, &key);
	if (!srp)
		return 0;

	if (CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ACTIVE)) {
		if (!CHECK_FLAG(route_info->flag, ISIS_ROUTE_FLAG_ZEBRA_SYNCED))
			/* Update the NHLFE */
			update_prefix_nhlfe(area, srp);
	} else {
		if (CHECK_FLAG(route_info->flag,
			       ISIS_ROUTE_FLAG_ZEBRA_SYNCED)) {
			sr_debug(" |-  Route is inactive. Remove all NHLFE");

			sr_prefix_update_lfib(ZEBRA_MPLS_LABELS_DELETE, srp);
		}
	}

	return 0;
}

/*
 * --------------------------------------
 * Followings are vty command functions.
 * --------------------------------------
 */
static void show_sr_prefix(struct sbuf *sbuf, struct sr_prefix *srp)
{
	struct listnode *node;
	struct isis_nexthop *nh;
	struct interface *itf;
	char sid[23];
	char op[32];
	int indent = 0;

	if (srp->prefix.family == AF_INET)
		sbuf_push(sbuf, 0, "%19pFX  ", &srp->prefix);
	else
		sbuf_push(sbuf, 0, "%18pFX  ", &srp->prefix);
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
	if (srn == NULL)
		return;

	sbuf_init(&sbuf, NULL, 0);

	sbuf_push(&sbuf, 0, "SR-Node: %s", print_sys_hostname(srn->sysid));
	sbuf_push(&sbuf, 0, "\tSRGB (Size/Label): %u/%u",
		  srn->cap.srgb.range_size, srn->cap.srgb.lower_bound);
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
       "Advertising SR node ID (as SYS-ID address)\n")
{
	int idx = 0;
	struct sr_node *srn;
	bool alone = false;
	char *sr_id;
	struct isis_dynhn *dynhn;
	uint8_t sysid[ISIS_SYS_ID_LEN];
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

		memset(sysid, 0, ISIS_SYS_ID_LEN);
		if (sr_id) {
			if (sysid2buff(sysid, sr_id) == 0) {
				dynhn = dynhn_find_by_name(sr_id);
				if (dynhn == NULL) {
					if (memcmp(sr_id, cmd_hostname_get(),
						   strlen(sr_id)) == 0) {
						memcpy(sysid, isis->sysid,
						       ISIS_SYS_ID_LEN);
					} else {
						vty_out(vty,
							"Invalid system id %s\n",
							sr_id);
						return CMD_SUCCESS;
					}
				} else
					memcpy(sysid, dynhn->id,
					       ISIS_SYS_ID_LEN);
			}
			alone = true;
		}

		vty_out(vty,
			"\n\t\tISIS Segment Routing database for Node %s\n\n",
			print_sys_hostname(area->srdb.self->sysid));

		if (alone) {
			/* Get the SR Node from the SRDB */
			struct sr_node key = {};

			memcpy(&key.sysid, sysid, ISIS_SYS_ID_LEN);
			srn = RB_FIND(srdb_node_head, &area->srdb.sr_nodes,
				      &key);

			/* SR Node may be not part of this area */
			if (srn == NULL)
				continue;

			show_sr_node(vty, srn);
			return CMD_SUCCESS;
		}

		/* No node have been provided, Iterate through all the SRDB */
		RB_FOREACH (srn, srdb_node_head, &area->srdb.sr_nodes)
			show_sr_node(vty, srn);
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
	struct sr_node *self;
	struct sr_prefix *srp;
	struct isis_sr_db *srdb = &area->srdb;
	uint32_t size;

	/* Sanity check */
	self = get_self_by_area(area);
	if (self == NULL)
		return;

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
		/* Update NHLFE entries */
		RB_FOREACH (srp, srdb_prefix_head, &srdb->prefix_sids)
			update_in_nhlfe(self, srp);
	} else {
		flog_err(EC_ISIS_SR_LABEL_MANAGER,
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
	if (self == NULL)
		return;

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
	uint32_t size;

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
#ifndef FABRICD
	srdb->lower_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/lower-bound");
	srdb->upper_bound = yang_get_default_uint32(
		"/frr-isisd:isis/instance/segment-routing/srgb/upper-bound");
#endif /* ifndef FABRICD */

	/* Reserve Labels Range for SRGB */
	size = srdb->upper_bound - srdb->lower_bound + 1;
	if (isis_zebra_request_label_range(srdb->lower_bound, size) == 0)
		srdb->srgb_lm = true;
}

void isis_sr_destroy(struct isis_area *area)
{
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR(%s): Deleting SRDB for area %s", __func__, area->area_tag);
	isis_sr_stop(area);

	/* Release Labels range of SRGB */
	if (srdb->srgb_lm)
		isis_zebra_release_label_range(srdb->lower_bound,
					       srdb->upper_bound);
}

void isis_sr_start(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct listnode *cnode, *anode;
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR(%s): Starting Segment Routing", __func__);

	if (!srdb->srgb_lm) {
		flog_err(
			EC_ISIS_SR_LABEL_MANAGER,
			"SR(%s): Can't start SR. Label ranges are not reserved",
			__func__);
		return;
	}

	/* Initialize RB Tree for neighbor SR nodes */
	RB_INIT(srdb_node_head, &srdb->sr_nodes);

	/* Initialize self SR Node */
	srn = sr_node_new(area->isis->sysid);

	/* Complete & Store self SR Node */
	srn->cap.flags = ISIS_SUBTLV_SRGB_FLAG_I | ISIS_SUBTLV_SRGB_FLAG_V;
	srn->cap.srgb.lower_bound = area->srdb.lower_bound;
	srn->cap.srgb.range_size =
		area->srdb.upper_bound - area->srdb.lower_bound + 1;
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		srn->cap.algo[i] = area->srdb.algo[i];
	srn->cap.msd = area->srdb.msd;
	area->srdb.self = srn;
	srn->area = area;
	RB_INSERT(srdb_node_head, &area->srdb.sr_nodes, srn);
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

	/* Enable SR and regenerate LSP */
	area->srdb.enabled = true;

	lsp_regenerate_schedule(area, area->is_type, 0);
}

void isis_sr_stop(struct isis_area *area)
{
	struct sr_node *srn;
	struct isis_sr_db *srdb = &area->srdb;

	sr_debug("SR (%s): Stopping Segment Routing", __func__);

	/* Stop SR */
	srdb->enabled = false;
	srdb->self = NULL;

	/*
	 * Remove all SR Nodes from the RB Tree. Prefix and Link SID will
	 * be remove though list_delete() call. See sr_node_del()
	 */
	while (!RB_EMPTY(srdb_node_head, &srdb->sr_nodes)) {
		srn = RB_ROOT(srdb_node_head, &srdb->sr_nodes);
		sr_node_del(srn);
	}

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
