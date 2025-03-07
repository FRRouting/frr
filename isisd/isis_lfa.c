// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "vrf.h"
#include "table.h"
#include "srcdest_table.h"
#include "plist.h"
#include "zclient.h"

#include "isis_common.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_mt.h"
#include "isis_tlvs.h"
#include "isis_spf_private.h"
#include "isis_zebra.h"
#include "isis_errors.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_NODE, "ISIS SPF Node");
DEFINE_MTYPE_STATIC(ISISD, ISIS_LFA_TIEBREAKER, "ISIS LFA Tiebreaker");
DEFINE_MTYPE_STATIC(ISISD, ISIS_LFA_EXCL_IFACE, "ISIS LFA Excluded Interface");
DEFINE_MTYPE_STATIC(ISISD, ISIS_RLFA, "ISIS Remote LFA");
DEFINE_MTYPE(ISISD, ISIS_NEXTHOP_LABELS, "ISIS nexthop MPLS labels");

static inline int isis_spf_node_compare(const struct isis_spf_node *a,
					const struct isis_spf_node *b)
{
	return memcmp(a->sysid, b->sysid, sizeof(a->sysid));
}
RB_GENERATE(isis_spf_nodes, isis_spf_node, entry, isis_spf_node_compare)

/**
 * Initialize list of SPF nodes.
 *
 * @param nodes		List of SPF nodes
 */
void isis_spf_node_list_init(struct isis_spf_nodes *nodes)
{
	RB_INIT(isis_spf_nodes, nodes);
}

/**
 * Clear list of SPF nodes, releasing all allocated memory.
 *
 * @param nodes		List of SPF nodes
 */
void isis_spf_node_list_clear(struct isis_spf_nodes *nodes)
{
	while (!RB_EMPTY(isis_spf_nodes, nodes)) {
		struct isis_spf_node *node = RB_ROOT(isis_spf_nodes, nodes);

		if (node->adjacencies)
			list_delete(&node->adjacencies);
		if (node->lfa.spftree)
			isis_spftree_del(node->lfa.spftree);
		if (node->lfa.spftree_reverse)
			isis_spftree_del(node->lfa.spftree_reverse);
		isis_spf_node_list_clear(&node->lfa.p_space);
		RB_REMOVE(isis_spf_nodes, nodes, node);
		XFREE(MTYPE_ISIS_SPF_NODE, node);
	}
}

/**
 * Add new node to list of SPF nodes.
 *
 * @param nodes		List of SPF nodes
 * @param sysid		Node System ID
 *
 * @return		Pointer to new IS-IS SPF node structure.
 */
struct isis_spf_node *isis_spf_node_new(struct isis_spf_nodes *nodes,
					const uint8_t *sysid)
{
	struct isis_spf_node *node;

	node = XCALLOC(MTYPE_ISIS_SPF_NODE, sizeof(*node));
	memcpy(node->sysid, sysid, sizeof(node->sysid));
	node->adjacencies = list_new();
	isis_spf_node_list_init(&node->lfa.p_space);
	RB_INSERT(isis_spf_nodes, nodes, node);

	return node;
}

/**
 * Lookup SPF node by its System ID on the given list.
 *
 * @param nodes		List of SPF nodes
 * @param sysid		Node System ID
 *
 * @return		Pointer to SPF node if found, NULL otherwise
 */
struct isis_spf_node *isis_spf_node_find(const struct isis_spf_nodes *nodes,
					 const uint8_t *sysid)
{
	struct isis_spf_node node = {};

	memcpy(node.sysid, sysid, sizeof(node.sysid));
	return RB_FIND(isis_spf_nodes, nodes, &node);
}

/**
 * LFA tiebreaker RB-tree comparison function.
 *
 * @param a	First LFA tiebreaker
 * @param b	Second LFA tiebreaker
 *
 * @return	-1 (a < b), 0 (a == b) or +1 (a > b)
 */
int lfa_tiebreaker_cmp(const struct lfa_tiebreaker *a,
		       const struct lfa_tiebreaker *b)
{
	if (a->index < b->index)
		return -1;
	if (a->index > b->index)
		return 1;

	return a->type - b->type;
}

/**
 * Initialize list of LFA tie-breakers.
 *
 * @param area		IS-IS area
 * @param level		IS-IS level
 */
void isis_lfa_tiebreakers_init(struct isis_area *area, int level)
{
	lfa_tiebreaker_tree_init(&area->lfa_tiebreakers[level - 1]);
}

/**
 * Clear list of LFA tie-breakers, releasing all allocated memory.
 *
 * @param area		IS-IS area
 * @param level		IS-IS level
 */
void isis_lfa_tiebreakers_clear(struct isis_area *area, int level)
{
	while (lfa_tiebreaker_tree_count(&area->lfa_tiebreakers[level - 1])
	       > 0) {
		struct lfa_tiebreaker *tie_b;

		tie_b = lfa_tiebreaker_tree_first(
			&area->lfa_tiebreakers[level - 1]);
		isis_lfa_tiebreaker_delete(area, level, tie_b);
	}
}

/**
 * Add new LFA tie-breaker to list of LFA tie-breakers.
 *
 * @param area		IS-IS area
 * @param level		IS-IS level
 * @param index		LFA tie-breaker index
 * @param type		LFA tie-breaker type
 *
 * @return		Pointer to new LFA tie-breaker structure.
 */
struct lfa_tiebreaker *isis_lfa_tiebreaker_add(struct isis_area *area,
					       int level, uint8_t index,
					       enum lfa_tiebreaker_type type)
{
	struct lfa_tiebreaker *tie_b;

	tie_b = XCALLOC(MTYPE_ISIS_LFA_TIEBREAKER, sizeof(*tie_b));
	tie_b->index = index;
	tie_b->type = type;
	tie_b->area = area;
	lfa_tiebreaker_tree_add(&area->lfa_tiebreakers[level - 1], tie_b);

	return tie_b;
}

/**
 * Remove LFA tie-breaker from list of LFA tie-breakers.
 *
 * @param area		IS-IS area
 * @param level		IS-IS level
 * @param tie_b		Pointer to LFA tie-breaker structure
 */
void isis_lfa_tiebreaker_delete(struct isis_area *area, int level,
				struct lfa_tiebreaker *tie_b)
{
	lfa_tiebreaker_tree_del(&area->lfa_tiebreakers[level - 1], tie_b);
	XFREE(MTYPE_ISIS_LFA_TIEBREAKER, tie_b);
}

static bool lfa_excl_interface_hash_cmp(const void *value1, const void *value2)
{
	return strmatch(value1, value2);
}

static unsigned int lfa_excl_interface_hash_make(const void *value)
{
	return string_hash_make(value);
}

static void *lfa_excl_interface_hash_alloc(void *p)
{
	return XSTRDUP(MTYPE_ISIS_LFA_EXCL_IFACE, p);
}

static void lfa_excl_interface_hash_free(void *arg)
{
	XFREE(MTYPE_ISIS_LFA_EXCL_IFACE, arg);
}

/**
 * Initialize hash table of LFA excluded interfaces.
 *
 * @param circuit	IS-IS interface
 * @param level		IS-IS level
 */
void isis_lfa_excluded_ifaces_init(struct isis_circuit *circuit, int level)
{
	circuit->lfa_excluded_ifaces[level - 1] = hash_create(
		lfa_excl_interface_hash_make, lfa_excl_interface_hash_cmp,
		"LFA Excluded Interfaces");
}

/**
 * Clear hash table of LFA excluded interfaces, releasing all allocated memory.
 *
 * @param nodes		List of SPF nodes
 */
void isis_lfa_excluded_ifaces_delete(struct isis_circuit *circuit, int level)
{
	hash_clean_and_free(&circuit->lfa_excluded_ifaces[level - 1],
			    lfa_excl_interface_hash_free);
}

/**
 * Add new interface to hash table of excluded interfaces.
 *
 * @param circuit	IS-IS interface
 * @param level		IS-IS level
 * @param ifname	Excluded interface name
 */
void isis_lfa_excluded_iface_add(struct isis_circuit *circuit, int level,
				 const char *ifname)
{
	(void)hash_get(circuit->lfa_excluded_ifaces[level - 1], (char *)ifname,
		       lfa_excl_interface_hash_alloc);
}

/**
 * Remove interface from hash table of excluded interfaces.
 *
 * @param circuit	IS-IS interface
 * @param level		IS-IS level
 * @param ifname	Excluded interface name
 */
void isis_lfa_excluded_iface_delete(struct isis_circuit *circuit, int level,
				    const char *ifname)
{
	char *found;

	found = hash_lookup(circuit->lfa_excluded_ifaces[level - 1],
			    (char *)ifname);
	if (found) {
		hash_release(circuit->lfa_excluded_ifaces[level - 1], found);
		lfa_excl_interface_hash_free(found);
	}
}

/**
 * Lookup excluded interface.
 *
 * @param circuit	IS-IS interface
 * @param level		IS-IS level
 * @param ifname	Excluded interface name
 */
bool isis_lfa_excluded_iface_check(struct isis_circuit *circuit, int level,
				   const char *ifname)
{
	return hash_lookup(circuit->lfa_excluded_ifaces[level - 1],
			   (char *)ifname);
}

/**
 * Check if a given IS-IS adjacency needs to be excised when computing the SPF
 * post-convergence tree.
 *
 * @param spftree	IS-IS SPF tree
 * @param id		Adjacency System ID (or LAN ID of the designated router
 * 			for broadcast interfaces)
 *
 * @return		true if the adjacency needs to be excised, false
 * 			otherwise
 */
bool isis_lfa_excise_adj_check(const struct isis_spftree *spftree,
			       const uint8_t *id)
{
	const struct lfa_protected_resource *resource;

	if (spftree->type != SPF_TYPE_RLFA && spftree->type != SPF_TYPE_TI_LFA)
		return false;

	/*
	 * Adjacencies formed over the failed interface should be excised both
	 * when using link and node protection.
	 */
	resource = &spftree->lfa.protected_resource;
	if (!memcmp(resource->adjacency, id, ISIS_SYS_ID_LEN + 1))
		return true;

	return false;
}

/**
 * Check if a given IS-IS node needs to be excised when computing the SPF
 * post-convergence tree.
 *
 * @param spftree	IS-IS SPF tree
 * @param id		Node System ID
 *
 * @return		true if the node needs to be excised, false otherwise
 */
bool isis_lfa_excise_node_check(const struct isis_spftree *spftree,
				const uint8_t *id)
{
	const struct lfa_protected_resource *resource;

	if (spftree->type != SPF_TYPE_TI_LFA)
		return false;

	/*
	 * When using node protection, nodes reachable over the failed interface
	 * must be excised.
	 */
	resource = &spftree->lfa.protected_resource;
	if (resource->type == LFA_LINK_PROTECTION)
		return false;

	if (isis_spf_node_find(&resource->nodes, id))
		return true;

	return false;
}

struct tilfa_find_pnode_prefix_sid_args {
	uint32_t sid_index;
	int algorithm;
};

static int tilfa_find_pnode_prefix_sid_cb(const struct prefix *prefix,
					  uint32_t metric, bool external,
					  struct isis_subtlvs *subtlvs,
					  void *arg)
{
	struct tilfa_find_pnode_prefix_sid_args *args = arg;
	struct isis_prefix_sid *psid;

	if (!subtlvs || subtlvs->prefix_sids.count == 0)
		return LSP_ITER_CONTINUE;

	for (psid = (struct isis_prefix_sid *)subtlvs->prefix_sids.head; psid;
	     psid = psid->next) {
		/* Require the node flag to be set. */
		if (!CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_NODE))
			continue;
		if (psid->algorithm != args->algorithm)
			continue;
		args->sid_index = psid->value;
		return LSP_ITER_STOP;
	}
	return LSP_ITER_CONTINUE;
}

/* Find Prefix-SID associated to a System ID. */
static uint32_t tilfa_find_pnode_prefix_sid(struct isis_spftree *spftree,
					    const uint8_t *sysid)
{
	struct isis_lsp *lsp;
	struct tilfa_find_pnode_prefix_sid_args args;

	lsp = isis_root_system_lsp(spftree->lspdb, sysid);
	if (!lsp)
		return UINT32_MAX;

	args.algorithm = spftree->algorithm;

	args.sid_index = UINT32_MAX;
	isis_lsp_iterate_ip_reach(lsp, spftree->family, spftree->mtid,
				  tilfa_find_pnode_prefix_sid_cb, &args);

	return args.sid_index;
}

struct tilfa_find_qnode_adj_sid_args {
	const uint8_t *qnode_sysid;
	mpls_label_t label;
};

static int tilfa_find_qnode_adj_sid_cb(const uint8_t *id, uint32_t metric,
				       bool oldmetric,
				       struct isis_ext_subtlvs *subtlvs,
				       void *arg)
{
	struct tilfa_find_qnode_adj_sid_args *args = arg;
	struct isis_adj_sid *adj_sid;

	if (memcmp(id, args->qnode_sysid, ISIS_SYS_ID_LEN))
		return LSP_ITER_CONTINUE;
	if (!subtlvs || subtlvs->adj_sid.count == 0)
		return LSP_ITER_CONTINUE;

	adj_sid = (struct isis_adj_sid *)subtlvs->adj_sid.head;
	args->label = adj_sid->sid;

	return LSP_ITER_STOP;
}

/* Find Adj-SID associated to a pair of System IDs. */
static mpls_label_t tilfa_find_qnode_adj_sid(struct isis_spftree *spftree,
					     const uint8_t *source_sysid,
					     const uint8_t *qnode_sysid)
{
	struct isis_lsp *lsp;
	struct tilfa_find_qnode_adj_sid_args args;

	lsp = isis_root_system_lsp(spftree->lspdb, source_sysid);
	if (!lsp)
		return MPLS_INVALID_LABEL;

	args.qnode_sysid = qnode_sysid;
	args.label = MPLS_INVALID_LABEL;
	isis_lsp_iterate_is_reach(lsp, spftree->mtid,
				  tilfa_find_qnode_adj_sid_cb, &args);

	return args.label;
}

/*
 * Compute the MPLS label stack associated to a TI-LFA repair list. This
 * needs to be computed separately for each adjacency since different
 * neighbors can have different SRGBs.
 */
static struct mpls_label_stack *
tilfa_compute_label_stack(struct lspdb_head *lspdb,
			  const struct isis_spf_adj *sadj,
			  const struct list *repair_list)
{
	struct mpls_label_stack *label_stack;
	struct isis_tilfa_sid *sid;
	struct listnode *node;
	size_t i = 0;

	/* Allocate label stack. */
	label_stack = XCALLOC(MTYPE_ISIS_NEXTHOP_LABELS,
			      sizeof(struct mpls_label_stack)
				      + listcount(repair_list)
						* sizeof(mpls_label_t));
	label_stack->num_labels = listcount(repair_list);

	for (ALL_LIST_ELEMENTS_RO(repair_list, node, sid)) {
		const uint8_t *target_node;
		struct isis_sr_block *srgb;
		mpls_label_t label;

		switch (sid->type) {
		case TILFA_SID_PREFIX:
			if (sid->value.index.remote)
				target_node = sid->value.index.remote_sysid;
			else
				target_node = sadj->id;
			srgb = isis_sr_find_srgb(lspdb, target_node);
			if (!srgb) {
				zlog_warn("%s: SRGB not found for node %s",
					  __func__,
					  print_sys_hostname(target_node));
				goto error;
			}

			/* Check if the SID index falls inside the SRGB. */
			if (sid->value.index.value >= srgb->range_size) {
				flog_warn(
					EC_ISIS_SID_OVERFLOW,
					"%s: SID index %u falls outside remote SRGB range",
					__func__, sid->value.index.value);
				goto error;
			}

			/*
			 * Prefix-SID: map SID index to label value within the
			 * SRGB.
			 */
			label = srgb->lower_bound + sid->value.index.value;
			break;
		case TILFA_SID_ADJ:
			/* Adj-SID: absolute label value can be used directly */
			label = sid->value.label;
			break;
		default:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown TI-LFA SID type [%u]", __func__,
				 sid->type);
			exit(1);
		}
		label_stack->label[i++] = label;
	}

	return label_stack;

error:
	XFREE(MTYPE_ISIS_NEXTHOP_LABELS, label_stack);
	return NULL;
}

static int tilfa_repair_list_apply(struct isis_spftree *spftree,
				   struct isis_vertex *vertex_dest,
				   const struct isis_vertex *vertex_pnode,
				   const struct list *repair_list)
{
	struct isis_vertex_adj *vadj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(vertex_dest->Adj_N, node, vadj)) {
		struct isis_spf_adj *sadj = vadj->sadj;
		struct mpls_label_stack *label_stack;

		/*
		 * Don't try to apply the repair list if one was already applied
		 * before (can't have ECMP past the P-node).
		 */
		if (vadj->label_stack)
			continue;

		if (!isis_vertex_adj_exists(spftree, vertex_pnode, sadj))
			continue;

		label_stack = tilfa_compute_label_stack(spftree->lspdb, sadj,
							repair_list);
		if (!label_stack) {
			char buf[VID2STR_BUFFER];

			vid2string(vertex_dest, buf, sizeof(buf));
			zlog_warn(
				"%s: %s %s adjacency %s: failed to compute label stack",
				__func__, vtype2string(vertex_dest->type), buf,
				print_sys_hostname(sadj->id));
			return -1;
		}

		vadj->label_stack = label_stack;
	}

	return 0;
}

/*
 * Check if a node belongs to the extended P-space corresponding to a given
 * destination.
 */
static bool lfa_ext_p_space_check(const struct isis_spftree *spftree_pc,
				  const struct isis_vertex *vertex_dest,
				  const struct isis_vertex *vertex)
{
	struct isis_spftree *spftree_old = spftree_pc->lfa.old.spftree;
	struct isis_vertex_adj *vadj;
	struct listnode *node;

	/* Check the local P-space first. */
	if (isis_spf_node_find(&spftree_pc->lfa.p_space, vertex->N.id))
		return true;

	/*
	 * Check the P-space of the adjacent routers used to reach the
	 * destination.
	 */
	for (ALL_LIST_ELEMENTS_RO(vertex_dest->Adj_N, node, vadj)) {
		struct isis_spf_adj *sadj = vadj->sadj;
		struct isis_spf_node *adj_node;

		adj_node =
			isis_spf_node_find(&spftree_old->adj_nodes, sadj->id);
		if (!adj_node)
			continue;

		if (isis_spf_node_find(&adj_node->lfa.p_space, vertex->N.id))
			return true;
	}

	return false;
}

/* Check if a node belongs to the Q-space. */
static bool lfa_q_space_check(const struct isis_spftree *spftree_pc,
			      const struct isis_vertex *vertex)
{
	return isis_spf_node_find(&spftree_pc->lfa.q_space, vertex->N.id);
}

/* This is a recursive function. */
static int tilfa_build_repair_list(struct isis_spftree *spftree_pc,
				   struct isis_vertex *vertex_dest,
				   const struct isis_vertex *vertex,
				   const struct isis_vertex *vertex_child,
				   struct isis_spf_nodes *used_pnodes,
				   struct list *repair_list)
{
	struct isis_vertex *pvertex;
	struct listnode *node;
	bool is_pnode, is_qnode;
	char buf[VID2STR_BUFFER];
	struct isis_tilfa_sid sid_dest = {}, sid_qnode = {}, sid_pnode = {};
	uint32_t sid_index;
	mpls_label_t label_qnode;

	if (IS_DEBUG_LFA) {
		vid2string(vertex, buf, sizeof(buf));
		zlog_debug("ISIS-LFA: vertex %s %s", vtype2string(vertex->type),
			   buf);
	}

	/* Push original Prefix-SID label when necessary. */
	if (VTYPE_IP(vertex->type) && vertex->N.ip.sr.present) {
		pvertex = listnode_head(vertex->parents);
		assert(pvertex);

		sid_index = vertex->N.ip.sr.sid.value;
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: pushing Prefix-SID to %pFX (index %u)",
				&vertex->N.ip.p.dest, sid_index);
		sid_dest.type = TILFA_SID_PREFIX;
		sid_dest.value.index.value = sid_index;
		sid_dest.value.index.remote = true;
		memcpy(sid_dest.value.index.remote_sysid, pvertex->N.id,
		       sizeof(sid_dest.value.index.remote_sysid));
		listnode_add_head(repair_list, &sid_dest);
	}

	if (!vertex_child)
		goto parents;
	if (vertex->type != VTYPE_NONPSEUDO_IS
	    && vertex->type != VTYPE_NONPSEUDO_TE_IS)
		goto parents;
	if (!VTYPE_IS(vertex_child->type))
		vertex_child = NULL;

	/* Check if node is part of the extended P-space and/or Q-space. */
	is_pnode = lfa_ext_p_space_check(spftree_pc, vertex_dest, vertex);
	is_qnode = lfa_q_space_check(spftree_pc, vertex);

	/* Push Adj-SID label when necessary. */
	if ((!is_qnode
	     || spftree_pc->lfa.protected_resource.type == LFA_NODE_PROTECTION)
	    && vertex_child) {
		/*
		 * If vertex is the penultimate hop router, then pushing an
		 * Adj-SID towards the final hop means that the No-PHP flag of
		 * the original Prefix-SID must be honored. We do that by
		 * removing the previously added Prefix-SID from the repair list
		 * when those conditions are met.
		 */
		if (vertex->depth == (vertex_dest->depth - 2)
		    && VTYPE_IP(vertex_dest->type)
		    && vertex_dest->N.ip.sr.present
		    && !CHECK_FLAG(vertex_dest->N.ip.sr.sid.flags,
				   ISIS_PREFIX_SID_NO_PHP)) {
			list_delete_all_node(repair_list);
		}

		label_qnode = tilfa_find_qnode_adj_sid(spftree_pc, vertex->N.id,
						       vertex_child->N.id);
		if (label_qnode == MPLS_INVALID_LABEL) {
			zlog_warn("ISIS-LFA: failed to find %s->%s Adj-SID",
				  print_sys_hostname(vertex->N.id),
				  print_sys_hostname(vertex_child->N.id));
			return -1;
		}
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: pushing %s->%s Adj-SID (label %u)",
				print_sys_hostname(vertex->N.id),
				print_sys_hostname(vertex_child->N.id),
				label_qnode);
		sid_qnode.type = TILFA_SID_ADJ;
		sid_qnode.value.label = label_qnode;
		listnode_add_head(repair_list, &sid_qnode);
	}

	/* Push Prefix-SID label when necessary. */
	if (is_pnode) {
		/* The same P-node can't be used more than once. */
		if (isis_spf_node_find(used_pnodes, vertex->N.id)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: skipping already used P-node");
			return 0;
		}
		isis_spf_node_new(used_pnodes, vertex->N.id);

		if (!vertex_child) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: destination is within Ext-P-Space");
			return 0;
		}

		sid_index =
			tilfa_find_pnode_prefix_sid(spftree_pc, vertex->N.id);
		if (sid_index == UINT32_MAX) {
			zlog_warn(
				"ISIS-LFA: failed to find Prefix-SID corresponding to PQ-node %s",
				print_sys_hostname(vertex->N.id));
			return -1;
		}

		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: pushing Node-SID to %s (index %u)",
				print_sys_hostname(vertex->N.id), sid_index);
		sid_pnode.type = TILFA_SID_PREFIX;
		sid_pnode.value.index.value = sid_index;
		listnode_add_head(repair_list, &sid_pnode);

		/* Apply repair list. */
		if (spftree_pc->area->srdb.config.msd
		    && listcount(repair_list)
			       > spftree_pc->area->srdb.config.msd) {
			zlog_warn(
				"ISIS-LFA: list of repair segments exceeds locally configured MSD (%u > %u)",
				listcount(repair_list),
				spftree_pc->area->srdb.config.msd);
			return -1;
		}
		if (tilfa_repair_list_apply(spftree_pc, vertex_dest, vertex,
					    repair_list)
		    != 0)
			return -1;
		return 0;
	}

parents:
	for (ALL_LIST_ELEMENTS_RO(vertex->parents, node, pvertex)) {
		struct list *repair_list_parent;
		bool ecmp;
		int ret;

		ecmp = (listcount(vertex->parents) > 1) ? true : false;
		repair_list_parent = ecmp ? list_dup(repair_list) : repair_list;
		ret = tilfa_build_repair_list(spftree_pc, vertex_dest, pvertex,
					      vertex, used_pnodes,
					      repair_list_parent);
		if (ecmp)
			list_delete(&repair_list_parent);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static const char *lfa_protection_type2str(enum lfa_protection_type type)
{
	switch (type) {
	case LFA_LINK_PROTECTION:
		return "link protection";
	case LFA_NODE_PROTECTION:
		return "node protection";
	default:
		return "unknown protection type";
	}
}

static const char *
lfa_protected_resource2str(const struct lfa_protected_resource *resource)
{
	const uint8_t *fail_id;
	static char buffer[128];

	fail_id = resource->adjacency;
	snprintf(buffer, sizeof(buffer), "%s.%u's failure (%s)",
		 print_sys_hostname(fail_id), LSP_PSEUDO_ID(fail_id),
		 lfa_protection_type2str(resource->type));

	return buffer;
}

static bool
spf_adj_check_is_affected(const struct isis_spf_adj *sadj,
			  const struct lfa_protected_resource *resource,
			  const uint8_t *root_sysid, bool reverse)
{
	if (!!CHECK_FLAG(sadj->flags, F_ISIS_SPF_ADJ_BROADCAST)
	    != !!LSP_PSEUDO_ID(resource->adjacency))
		return false;

	if (CHECK_FLAG(sadj->flags, F_ISIS_SPF_ADJ_BROADCAST)) {
		if (!memcmp(sadj->lan.desig_is_id, resource->adjacency,
			    ISIS_SYS_ID_LEN + 1))
			return true;
	} else {
		if (!reverse
		    && !memcmp(sadj->id, resource->adjacency, ISIS_SYS_ID_LEN))
			return true;
		if (reverse && !memcmp(sadj->id, root_sysid, ISIS_SYS_ID_LEN))
			return true;
	}

	return false;
}

/* Check if the given vertex is affected by a given local failure. */
static bool
spf_vertex_check_is_affected(const struct isis_vertex *vertex,
			     const uint8_t *root_sysid,
			     const struct lfa_protected_resource *resource)
{
	struct isis_vertex_adj *vadj;
	struct listnode *node;
	size_t affected_nhs = 0;

	/* Local routes don't need protection. */
	if (VTYPE_IP(vertex->type) && vertex->depth == 1)
		return false;

	for (ALL_LIST_ELEMENTS_RO(vertex->Adj_N, node, vadj)) {
		struct isis_spf_adj *sadj = vadj->sadj;

		if (spf_adj_check_is_affected(sadj, resource, root_sysid,
					      false))
			affected_nhs++;
	}

	/*
	 * No need to compute backup paths for ECMP routes, except if all
	 * primary nexthops share the same broadcast interface.
	 */
	if (listcount(vertex->Adj_N) == affected_nhs)
		return true;

	return false;
}

/* Check if a given RLFA/TI-LFA post-convergence SPF vertex needs protection. */
static bool lfa_check_needs_protection(const struct isis_spftree *spftree_pc,
				       const struct isis_vertex *vertex)
{
	struct isis_vertex *vertex_old;

	/* Only local adjacencies need TI-LFA Adj-SID protection. */
	if (spftree_pc->type == SPF_TYPE_TI_LFA && VTYPE_IS(vertex->type)
	    && !isis_adj_find(spftree_pc->area, spftree_pc->level,
			      vertex->N.id))
		return false;

	vertex_old = isis_find_vertex(&spftree_pc->lfa.old.spftree->paths,
				      &vertex->N, vertex->type);
	if (!vertex_old)
		return false;

	/* Skip vertex if it's already protected by local LFA. */
	if (CHECK_FLAG(vertex_old->flags, F_ISIS_VERTEX_LFA_PROTECTED))
		return false;

	return spf_vertex_check_is_affected(
		vertex_old, spftree_pc->sysid,
		&spftree_pc->lfa.protected_resource);
}

/**
 * Check if the given SPF vertex needs protection and, if so, compute and
 * install the corresponding repair paths.
 *
 * @param spftree_pc	The post-convergence SPF tree
 * @param vertex	IS-IS SPF vertex to check
 *
 * @return		0 if the vertex needs to be protected, -1 otherwise
 */
int isis_tilfa_check(struct isis_spftree *spftree_pc,
		     struct isis_vertex *vertex)
{
	struct isis_spf_nodes used_pnodes;
	char buf[VID2STR_BUFFER];
	struct list *repair_list;
	int ret;

	if (!spftree_pc->area->srdb.enabled)
		return -1;

	if (!lfa_check_needs_protection(spftree_pc, vertex)) {
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: %s %s unaffected by %s",
				vtype2string(vertex->type),
				vid2string(vertex, buf, sizeof(buf)),
				lfa_protected_resource2str(
					&spftree_pc->lfa.protected_resource));

		return -1;
	}

	/*
	 * Check if the route/adjacency was already covered by node protection.
	 */
	if (VTYPE_IS(vertex->type)) {
		struct isis_adjacency *adj;

		adj = isis_adj_find(spftree_pc->area, spftree_pc->level,
				    vertex->N.id);
		if (adj && isis_sr_adj_sid_find(adj, spftree_pc->family,
						ISIS_SR_ADJ_BACKUP)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s %s already covered by node protection",
					vtype2string(vertex->type),
					vid2string(vertex, buf, sizeof(buf)));

			return -1;
		}
	}
	if (VTYPE_IP(vertex->type)) {
		struct route_table *route_table;

		route_table = spftree_pc->lfa.old.spftree->route_table_backup;
		if (route_node_lookup(route_table, &vertex->N.ip.p.dest)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s %s already covered by node protection",
					vtype2string(vertex->type),
					vid2string(vertex, buf, sizeof(buf)));

			return -1;
		}
	}

	if (IS_DEBUG_LFA)
		zlog_debug(
			"ISIS-LFA: computing repair path(s) of %s %s w.r.t %s",
			vtype2string(vertex->type),
			vid2string(vertex, buf, sizeof(buf)),
			lfa_protected_resource2str(
				&spftree_pc->lfa.protected_resource));

	/* Create base repair list. */
	repair_list = list_new();

	isis_spf_node_list_init(&used_pnodes);
	ret = tilfa_build_repair_list(spftree_pc, vertex, vertex, NULL,
				      &used_pnodes, repair_list);
	isis_spf_node_list_clear(&used_pnodes);
	list_delete(&repair_list);
	if (ret != 0)
		zlog_warn(
			"ISIS-LFA: failed to compute repair path(s) of %s %s w.r.t %s",
			vtype2string(vertex->type),
			vid2string(vertex, buf, sizeof(buf)),
			lfa_protected_resource2str(
				&spftree_pc->lfa.protected_resource));

	return ret;
}

static bool
spf_adj_node_is_affected(struct isis_spf_node *adj_node,
			 const struct lfa_protected_resource *resource,
			 const uint8_t *root_sysid)
{
	struct isis_spf_adj *sadj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj_node->adjacencies, node, sadj)) {
		if (sadj->metric != adj_node->best_metric)
			continue;
		if (spf_adj_check_is_affected(sadj, resource, root_sysid,
					      false))
			return true;
	}

	return false;
}

static bool vertex_is_affected(struct isis_spftree *spftree_root,
			       const struct isis_spf_nodes *adj_nodes,
			       bool p_space, const struct isis_vertex *vertex,
			       const struct lfa_protected_resource *resource)
{
	struct isis_vertex *pvertex;
	struct listnode *node, *vnode;

	for (ALL_LIST_ELEMENTS_RO(vertex->parents, node, pvertex)) {
		struct isis_spftree *spftree_parent;
		struct isis_vertex *vertex_child;
		struct isis_vertex_adj *vadj;
		bool reverse = false;

		if (p_space && resource->type == LFA_NODE_PROTECTION) {
			if (isis_spf_node_find(&resource->nodes, vertex->N.id))
				return true;
			goto parents;
		}

		/* Check if either the vertex or its parent is the root node. */
		if (memcmp(vertex->N.id, spftree_root->sysid, ISIS_SYS_ID_LEN)
		    && memcmp(pvertex->N.id, spftree_root->sysid,
			      ISIS_SYS_ID_LEN))
			goto parents;

		/* Get SPT of the parent vertex. */
		if (!memcmp(pvertex->N.id, spftree_root->sysid,
			    ISIS_SYS_ID_LEN))
			spftree_parent = spftree_root;
		else {
			struct isis_spf_node *adj_node;

			adj_node = isis_spf_node_find(adj_nodes, pvertex->N.id);
			assert(adj_node);
			spftree_parent = adj_node->lfa.spftree;
			assert(spftree_parent);
			reverse = true;
		}

		/* Get paths pvertex uses to reach vertex. */
		vertex_child = isis_find_vertex(&spftree_parent->paths,
						&vertex->N, vertex->type);
		if (!vertex_child)
			goto parents;

		/* Check if any of these paths use the protected resource. */
		for (ALL_LIST_ELEMENTS_RO(vertex_child->Adj_N, vnode, vadj))
			if (spf_adj_check_is_affected(vadj->sadj, resource,
						      spftree_root->sysid,
						      reverse))
				return true;

	parents:
		if (vertex_is_affected(spftree_root, adj_nodes, p_space,
				       pvertex, resource))
			return true;
	}

	return false;
}

/* Calculate set of nodes reachable without using the protected interface. */
static void lfa_calc_reach_nodes(struct isis_spftree *spftree,
				 struct isis_spftree *spftree_root,
				 const struct isis_spf_nodes *adj_nodes,
				 bool p_space,
				 const struct lfa_protected_resource *resource,
				 struct isis_spf_nodes *nodes)
{
	struct isis_vertex *vertex;
	struct listnode *node;

	for (ALL_QUEUE_ELEMENTS_RO(&spftree->paths, node, vertex)) {
		char buf[VID2STR_BUFFER];

		if (vertex->type != VTYPE_NONPSEUDO_IS && vertex->type != VTYPE_NONPSEUDO_TE_IS)
			continue;

		/* Skip root node. */
		if (!memcmp(vertex->N.id, spftree_root->sysid, ISIS_SYS_ID_LEN))
			continue;

		/* Don't add the same node twice. */
		if (isis_spf_node_find(nodes, vertex->N.id))
			continue;

		if (!vertex_is_affected(spftree_root, adj_nodes, p_space,
					vertex, resource)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: adding %s",
					vid2string(vertex, buf, sizeof(buf)));

			isis_spf_node_new(nodes, vertex->N.id);
		}
	}
}

/**
 * Helper function used to create an SPF tree structure and run reverse SPF on
 * it.
 *
 * @param spftree	IS-IS SPF tree
 *
 * @return		Pointer to new SPF tree structure.
 */
struct isis_spftree *isis_spf_reverse_run(const struct isis_spftree *spftree)
{
	struct isis_spftree *spftree_reverse;

	spftree_reverse = isis_spftree_new(
		spftree->area, spftree->lspdb, spftree->sysid, spftree->level,
		spftree->tree_id, SPF_TYPE_REVERSE,
		F_SPFTREE_NO_ADJACENCIES | F_SPFTREE_NO_ROUTES,
		spftree->algorithm);
	isis_run_spf(spftree_reverse);

	return spftree_reverse;
}

/*
 * Calculate the Extended P-space and Q-space associated to a given link
 * failure.
 */
static void lfa_calc_pq_spaces(struct isis_spftree *spftree_pc,
			       const struct lfa_protected_resource *resource)
{
	struct isis_spftree *spftree;
	struct isis_spftree *spftree_reverse;
	struct isis_spf_nodes *adj_nodes;
	struct isis_spf_node *adj_node;

	/* Obtain pre-failure SPTs and list of adjacent nodes. */
	spftree = spftree_pc->lfa.old.spftree;
	spftree_reverse = spftree_pc->lfa.old.spftree_reverse;
	adj_nodes = &spftree->adj_nodes;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: computing P-space (self)");
	lfa_calc_reach_nodes(spftree, spftree, adj_nodes, true, resource,
			     &spftree_pc->lfa.p_space);

	RB_FOREACH (adj_node, isis_spf_nodes, adj_nodes) {
		if (spf_adj_node_is_affected(adj_node, resource,
					     spftree->sysid)) {
			if (IS_DEBUG_LFA)
				zlog_debug("ISIS-LFA: computing Q-space (%s)",
					   print_sys_hostname(adj_node->sysid));

			/*
			 * Compute the reverse SPF in the behalf of the node
			 * adjacent to the failure, if we haven't done that
			 * before
			 */
			if (!adj_node->lfa.spftree_reverse)
				adj_node->lfa.spftree_reverse =
					isis_spf_reverse_run(
						adj_node->lfa.spftree);

			lfa_calc_reach_nodes(adj_node->lfa.spftree_reverse,
					     spftree_reverse, adj_nodes, false,
					     resource,
					     &spftree_pc->lfa.q_space);
		} else {
			if (IS_DEBUG_LFA)
				zlog_debug("ISIS-LFA: computing P-space (%s)",
					   print_sys_hostname(adj_node->sysid));
			lfa_calc_reach_nodes(adj_node->lfa.spftree, spftree,
					     adj_nodes, true, resource,
					     &adj_node->lfa.p_space);
		}
	}
}

/**
 * Compute the TI-LFA backup paths for a given protected interface.
 *
 * @param area		  IS-IS area
 * @param spftree	  IS-IS SPF tree
 * @param spftree_reverse IS-IS Reverse SPF tree
 * @param resource	  Protected resource
 *
 * @return		  Pointer to the post-convergence SPF tree
 */
struct isis_spftree *isis_tilfa_compute(struct isis_area *area,
					struct isis_spftree *spftree,
					struct isis_spftree *spftree_reverse,
					struct lfa_protected_resource *resource)
{
	struct isis_spftree *spftree_pc;
	struct isis_spf_node *adj_node;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: computing TI-LFAs for %s",
			   lfa_protected_resource2str(resource));

	/* Populate list of nodes affected by link failure. */
	if (resource->type == LFA_NODE_PROTECTION) {
		isis_spf_node_list_init(&resource->nodes);
		RB_FOREACH (adj_node, isis_spf_nodes, &spftree->adj_nodes) {
			if (spf_adj_node_is_affected(adj_node, resource,
						     spftree->sysid))
				isis_spf_node_new(&resource->nodes,
						  adj_node->sysid);
		}
	}

	/* Create post-convergence SPF tree. */
	spftree_pc = isis_spftree_new(area, spftree->lspdb, spftree->sysid,
				      spftree->level, spftree->tree_id,
				      SPF_TYPE_TI_LFA, spftree->flags,
				      spftree->algorithm);
	spftree_pc->lfa.old.spftree = spftree;
	spftree_pc->lfa.old.spftree_reverse = spftree_reverse;
	spftree_pc->lfa.protected_resource = *resource;

	/* Compute the extended P-space and Q-space. */
	lfa_calc_pq_spaces(spftree_pc, resource);

	if (IS_DEBUG_LFA)
		zlog_debug(
			"ISIS-LFA: computing the post convergence SPT w.r.t. %s",
			lfa_protected_resource2str(resource));

	/* Re-run SPF in the local node to find the post-convergence paths. */
	isis_run_spf(spftree_pc);

	/* Clear list of nodes affeted by link failure. */
	if (resource->type == LFA_NODE_PROTECTION)
		isis_spf_node_list_clear(&resource->nodes);

	return spftree_pc;
}

/**
 * Run forward SPF on all adjacent routers.
 *
 * @param spftree	IS-IS SPF tree
 *
 * @return		0 on success, -1 otherwise
 */
int isis_spf_run_neighbors(struct isis_spftree *spftree)
{
	struct isis_lsp *lsp;
	struct isis_spf_node *adj_node;

	lsp = isis_root_system_lsp(spftree->lspdb, spftree->sysid);
	if (!lsp)
		return -1;

	RB_FOREACH (adj_node, isis_spf_nodes, &spftree->adj_nodes) {
		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: running SPF on neighbor %s",
				   print_sys_hostname(adj_node->sysid));

		/* Compute the SPT on behalf of the neighbor. */
		adj_node->lfa.spftree = isis_spftree_new(
			spftree->area, spftree->lspdb, adj_node->sysid,
			spftree->level, spftree->tree_id, SPF_TYPE_FORWARD,
			F_SPFTREE_NO_ADJACENCIES | F_SPFTREE_NO_ROUTES,
			spftree->algorithm);
		isis_run_spf(adj_node->lfa.spftree);
	}

	return 0;
}

/* Find Router ID of PQ node. */
static struct in_addr *rlfa_pq_node_rtr_id(struct isis_spftree *spftree,
					   const struct isis_vertex *vertex_pq)
{
	struct isis_lsp *lsp;

	lsp = isis_root_system_lsp(spftree->lspdb, vertex_pq->N.id);
	if (!lsp)
		return NULL;

	if (lsp->tlvs->router_cap->router_id.s_addr == INADDR_ANY)
		return NULL;

	return &lsp->tlvs->router_cap->router_id;
}

/* Find PQ node by intersecting the P/Q spaces. This is a recursive function. */
static const struct in_addr *
rlfa_find_pq_node(struct isis_spftree *spftree_pc,
		  struct isis_vertex *vertex_dest,
		  const struct isis_vertex *vertex,
		  const struct isis_vertex *vertex_child)
{
	struct isis_area *area = spftree_pc->area;
	int level = spftree_pc->level;
	struct isis_vertex *pvertex;
	struct listnode *node;
	bool is_pnode, is_qnode;

	if (!vertex_child)
		goto parents;
	if (vertex->type != VTYPE_NONPSEUDO_IS
	    && vertex->type != VTYPE_NONPSEUDO_TE_IS)
		goto parents;
	if (!VTYPE_IS(vertex_child->type))
		vertex_child = NULL;

	/* Check if node is part of the extended P-space and/or Q-space. */
	is_pnode = lfa_ext_p_space_check(spftree_pc, vertex_dest, vertex);
	is_qnode = lfa_q_space_check(spftree_pc, vertex);

	if (is_pnode && is_qnode) {
		const struct in_addr *rtr_id_pq;
		uint32_t max_metric;
		struct prefix_list *plist = NULL;

		rtr_id_pq = rlfa_pq_node_rtr_id(spftree_pc, vertex);
		if (!rtr_id_pq) {
			if (IS_DEBUG_LFA) {
				char buf[VID2STR_BUFFER];

				vid2string(vertex, buf, sizeof(buf));
				zlog_debug(
					"ISIS-LFA: tentative PQ node (%s %s) doesn't have a router-ID",
					vtype2string(vertex->type), buf);
			}
			goto parents;
		}

		max_metric = spftree_pc->lfa.remote.max_metric;
		if (max_metric && vertex->d_N > max_metric) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: skipping PQ node %pI4 (maximum metric)",
					rtr_id_pq);
			goto parents;
		}

		plist = area->rlfa_plist[level - 1];
		if (plist) {
			struct prefix p;

			p.family = AF_INET;
			p.prefixlen = IPV4_MAX_BITLEN;
			p.u.prefix4 = *rtr_id_pq;
			if (prefix_list_apply(plist, &p) == PREFIX_DENY) {
				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: PQ node %pI4 filtered by prefix-list",
						rtr_id_pq);
				goto parents;
			}
		}

		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: found PQ node: %pI4", rtr_id_pq);

		return rtr_id_pq;
	}

parents:
	for (ALL_LIST_ELEMENTS_RO(vertex->parents, node, pvertex)) {
		const struct in_addr *rtr_id_pq;

		rtr_id_pq = rlfa_find_pq_node(spftree_pc, vertex_dest, pvertex,
					      vertex);
		if (rtr_id_pq)
			return rtr_id_pq;
	}

	return NULL;
}

int rlfa_cmp(const struct rlfa *a, const struct rlfa *b)
{
	return prefix_cmp(&a->prefix, &b->prefix);
}

static struct rlfa *rlfa_add(struct isis_spftree *spftree,
			     struct isis_vertex *vertex,
			     struct in_addr pq_address)
{
	struct rlfa *rlfa;

	assert(VTYPE_IP(vertex->type));
	rlfa = XCALLOC(MTYPE_ISIS_RLFA, sizeof(*rlfa));
	rlfa->prefix = vertex->N.ip.p.dest;
	rlfa->vertex = vertex;
	rlfa->pq_address = pq_address;
	rlfa_tree_add(&spftree->lfa.remote.rlfas, rlfa);

	return rlfa;
}

static void rlfa_delete(struct isis_spftree *spftree, struct rlfa *rlfa)
{
	rlfa_tree_del(&spftree->lfa.remote.rlfas, rlfa);
	XFREE(MTYPE_ISIS_RLFA, rlfa);
}

static struct rlfa *rlfa_lookup(struct isis_spftree *spftree,
				union prefixconstptr pu)
{
	struct rlfa s = {};

	s.prefix = *pu.p;
	return rlfa_tree_find(&spftree->lfa.remote.rlfas, &s);
}

static void isis_area_verify_routes_cb(struct event *thread)
{
	struct isis_area *area = EVENT_ARG(thread);

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: updating RLFAs in the RIB");

	isis_area_verify_routes(area);
}

static mpls_label_t rlfa_nexthop_label(struct isis_spftree *spftree,
				       struct isis_vertex_adj *vadj,
				       struct zapi_rlfa_response *response)
{
	struct isis_spf_adj *sadj = vadj->sadj;
	struct isis_adjacency *adj = sadj->adj;

	/*
	 * Special case to make unit tests work (use implicit-null labels
	 * instead of artifical ones).
	 */
	if (CHECK_FLAG(spftree->flags, F_SPFTREE_NO_ADJACENCIES))
		return MPLS_LABEL_IMPLICIT_NULL;

	for (unsigned int i = 0; i < response->nexthop_num; i++) {
		switch (response->nexthops[i].family) {
		case AF_INET:
			for (unsigned int j = 0; j < adj->ipv4_address_count;
			     j++) {
				struct in_addr addr = adj->ipv4_addresses[j];

				if (!IPV4_ADDR_SAME(
					    &addr,
					    &response->nexthops[i].gate.ipv4))
					continue;

				return response->nexthops[i].label;
			}
			break;
		case AF_INET6:
			for (unsigned int j = 0; j < adj->ll_ipv6_count; j++) {
				struct in6_addr addr = adj->ll_ipv6_addrs[j];

				if (!IPV6_ADDR_SAME(
					    &addr,
					    &response->nexthops[i].gate.ipv6))
					continue;

				return response->nexthops[i].label;
			}
			break;

		default:
			break;
		}
	}

	return MPLS_INVALID_LABEL;
}

int isis_rlfa_activate(struct isis_spftree *spftree, struct rlfa *rlfa,
		       struct zapi_rlfa_response *response)
{
	struct isis_area *area = spftree->area;
	struct isis_vertex *vertex = rlfa->vertex;
	struct isis_vertex_adj *vadj;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(vertex->Adj_N, node, vadj)) {
		mpls_label_t ldp_label;
		struct mpls_label_stack *label_stack;
		size_t num_labels = 0;
		size_t i = 0;

		ldp_label = rlfa_nexthop_label(spftree, vadj, response);
		if (ldp_label == MPLS_INVALID_LABEL) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: failed to activate RLFA: missing LDP label to reach PQ node through %pSY",
					vadj->sadj->id);
			return -1;
		}

		if (ldp_label != MPLS_LABEL_IMPLICIT_NULL)
			num_labels++;
		if (response->pq_label != MPLS_LABEL_IMPLICIT_NULL)
			num_labels++;
		if (vadj->sr.present
		    && vadj->sr.label != MPLS_LABEL_IMPLICIT_NULL)
			num_labels++;

		/* Allocate label stack. */
		label_stack =
			XCALLOC(MTYPE_ISIS_NEXTHOP_LABELS,
				sizeof(struct mpls_label_stack)
					+ num_labels * sizeof(mpls_label_t));
		label_stack->num_labels = num_labels;

		/* Push label allocated by the nexthop (outer label). */
		if (ldp_label != MPLS_LABEL_IMPLICIT_NULL)
			label_stack->label[i++] = ldp_label;
		/* Push label allocated by the PQ node (inner label). */
		if (response->pq_label != MPLS_LABEL_IMPLICIT_NULL)
			label_stack->label[i++] = response->pq_label;
		/* Preserve the original Prefix-SID label when it's present. */
		if (vadj->sr.present
		    && vadj->sr.label != MPLS_LABEL_IMPLICIT_NULL)
			label_stack->label[i++] = vadj->sr.label;

		vadj->label_stack = label_stack;
	}

	isis_route_create(&vertex->N.ip.p.dest, &vertex->N.ip.p.src,
			  vertex->d_N, vertex->depth, &vertex->N.ip.sr,
			  vertex->Adj_N, true, area,
			  spftree->route_table_backup);
	spftree->lfa.protection_counters.rlfa[vertex->N.ip.priority] += 1;

	EVENT_OFF(area->t_rlfa_rib_update);
	event_add_timer(master, isis_area_verify_routes_cb, area, 2,
			&area->t_rlfa_rib_update);

	return 0;
}

void isis_rlfa_deactivate(struct isis_spftree *spftree, struct rlfa *rlfa)
{
	struct isis_area *area = spftree->area;
	struct isis_vertex *vertex = rlfa->vertex;
	struct route_node *rn;

	rn = route_node_lookup(spftree->route_table_backup, &rlfa->prefix);
	if (!rn)
		return;
	isis_route_delete(area, rn, spftree->route_table_backup);
	spftree->lfa.protection_counters.rlfa[vertex->N.ip.priority] -= 1;

	EVENT_OFF(area->t_rlfa_rib_update);
	event_add_timer(master, isis_area_verify_routes_cb, area, 2,
			&area->t_rlfa_rib_update);
}

void isis_rlfa_list_init(struct isis_spftree *spftree)
{
	rlfa_tree_init(&spftree->lfa.remote.rlfas);
}

void isis_rlfa_list_clear(struct isis_spftree *spftree)
{
	while (rlfa_tree_count(&spftree->lfa.remote.rlfas) > 0) {
		struct rlfa *rlfa;

		rlfa = rlfa_tree_first(&spftree->lfa.remote.rlfas);
		isis_rlfa_deactivate(spftree, rlfa);
		rlfa_delete(spftree, rlfa);
	}
}

void isis_rlfa_process_ldp_response(struct zapi_rlfa_response *response)
{
	struct isis *isis;
	struct isis_area *area;
	struct isis_spftree *spftree;
	struct rlfa *rlfa;
	enum spf_tree_id tree_id;
	uint32_t spf_run_id;
	int level;

	if (response->igp.protocol != ZEBRA_ROUTE_ISIS)
		return;

	isis = isis_lookup_by_vrfid(response->igp.vrf_id);
	if (!isis)
		return;

	area = isis_area_lookup(response->igp.isis.area_tag,
				response->igp.vrf_id);
	if (!area)
		return;

	tree_id = response->igp.isis.spf.tree_id;
	if (tree_id != SPFTREE_IPV4 && tree_id != SPFTREE_IPV6) {
		zlog_warn("ISIS-LFA: invalid SPF tree ID received from LDP");
		return;
	}

	level = response->igp.isis.spf.level;
	if (level != ISIS_LEVEL1 && level != ISIS_LEVEL2) {
		zlog_warn("ISIS-LFA: invalid IS-IS level received from LDP");
		return;
	}

	spf_run_id = response->igp.isis.spf.run_id;
	spftree = area->spftree[tree_id][level - 1];
	if (spftree->runcount != spf_run_id)
		/* Outdated RLFA, ignore... */
		return;

	rlfa = rlfa_lookup(spftree, &response->destination);
	if (!rlfa) {
		zlog_warn(
			"ISIS-LFA: couldn't find Remote-LFA %pFX received from LDP",
			&response->destination);
		return;
	}

	if (response->pq_label != MPLS_INVALID_LABEL) {
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: activating/updating RLFA for %pFX",
				&rlfa->prefix);

		if (isis_rlfa_activate(spftree, rlfa, response) != 0)
			isis_rlfa_deactivate(spftree, rlfa);
	} else {
		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: deactivating RLFA for %pFX",
				   &rlfa->prefix);

		isis_rlfa_deactivate(spftree, rlfa);
	}
}

void isis_ldp_rlfa_handle_client_close(struct zapi_client_close_info *info)
{
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	struct isis_area *area;
	struct listnode *node;

	if (!isis)
		return;

	/* Check if the LDP main client session closed */
	if (info->proto != ZEBRA_ROUTE_LDP || info->session_id == 0)
		return;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: LDP is down, deactivating all RLFAs");

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++) {
				struct isis_spftree *spftree;

				if (!(area->is_type & level))
					continue;
				if (!area->spftree[tree][level - 1])
					continue;

				spftree = area->spftree[tree][level - 1];
				isis_rlfa_list_clear(spftree);
			}
		}
	}
}

/**
 * Check if the given SPF vertex needs protection and, if so, attempt to
 * compute a Remote LFA for it.
 *
 * @param spftree_pc	The post-convergence SPF tree
 * @param vertex	IS-IS SPF vertex to check
 */
void isis_rlfa_check(struct isis_spftree *spftree_pc,
		     struct isis_vertex *vertex)
{
	struct isis_spftree *spftree_old = spftree_pc->lfa.old.spftree;
	struct rlfa *rlfa;
	const struct in_addr *rtr_id_pq;
	char buf[VID2STR_BUFFER];

	if (!lfa_check_needs_protection(spftree_pc, vertex)) {
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: %s %s unaffected by %s",
				vtype2string(vertex->type),
				vid2string(vertex, buf, sizeof(buf)),
				lfa_protected_resource2str(
					&spftree_pc->lfa.protected_resource));

		return;
	}

	if (IS_DEBUG_LFA)
		zlog_debug(
			"ISIS-LFA: computing repair path(s) of %s %s w.r.t %s",
			vtype2string(vertex->type),
			vid2string(vertex, buf, sizeof(buf)),
			lfa_protected_resource2str(
				&spftree_pc->lfa.protected_resource));

	/* Find PQ node. */
	rtr_id_pq = rlfa_find_pq_node(spftree_pc, vertex, vertex, NULL);
	if (!rtr_id_pq) {
		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: no acceptable PQ node found");
		return;
	}

	/* Store valid RLFA and store LDP label for the PQ node. */
	rlfa = rlfa_add(spftree_old, vertex, *rtr_id_pq);

	/* Register RLFA with LDP. */
	if (isis_zebra_rlfa_register(spftree_old, rlfa) != 0)
		rlfa_delete(spftree_old, rlfa);
}

/**
 * Compute the Remote LFA backup paths for a given protected interface.
 *
 * @param area		  IS-IS area
 * @param spftree	  IS-IS SPF tree
 * @param spftree_reverse IS-IS Reverse SPF tree
 * @param max_metric	  Remote LFA maximum metric
 * @param resource	  Protected resource
 *
 * @return		  Pointer to the post-convergence SPF tree
 */
struct isis_spftree *isis_rlfa_compute(struct isis_area *area,
				       struct isis_spftree *spftree,
				       struct isis_spftree *spftree_reverse,
				       uint32_t max_metric,
				       struct lfa_protected_resource *resource)
{
	struct isis_spftree *spftree_pc;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: computing remote LFAs for %s",
			   lfa_protected_resource2str(resource));

	/* Create post-convergence SPF tree. */
	spftree_pc = isis_spftree_new(area, spftree->lspdb, spftree->sysid,
				      spftree->level, spftree->tree_id,
				      SPF_TYPE_RLFA, spftree->flags,
				      spftree->algorithm);
	spftree_pc->lfa.old.spftree = spftree;
	spftree_pc->lfa.old.spftree_reverse = spftree_reverse;
	spftree_pc->lfa.remote.max_metric = max_metric;
	spftree_pc->lfa.protected_resource = *resource;

	/* Compute the extended P-space and Q-space. */
	lfa_calc_pq_spaces(spftree_pc, resource);

	if (IS_DEBUG_LFA)
		zlog_debug(
			"ISIS-LFA: computing the post convergence SPT w.r.t. %s",
			lfa_protected_resource2str(resource));

	/* Re-run SPF in the local node to find the post-convergence paths. */
	isis_run_spf(spftree_pc);

	return spftree_pc;
}

/* Calculate the distance from the root node to the given IP destination. */
static int lfa_calc_dist_destination(struct isis_spftree *spftree,
				     const struct isis_vertex *vertex_N,
				     uint32_t *distance)
{
	struct isis_vertex *vertex, *vertex_best = NULL;

	switch (spftree->family) {
	case AF_INET:
		for (int vtype = VTYPE_IPREACH_INTERNAL;
		     vtype <= VTYPE_IPREACH_TE; vtype++) {
			vertex = isis_find_vertex(
				&spftree->paths, &vertex_N->N.ip.p.dest, vtype);
			if (!vertex)
				continue;

			/* Pick vertex with the best metric. */
			if (!vertex_best || vertex_best->d_N > vertex->d_N)
				vertex_best = vertex;
		}
		break;
	case AF_INET6:
		for (int vtype = VTYPE_IP6REACH_INTERNAL;
		     vtype <= VTYPE_IP6REACH_EXTERNAL; vtype++) {
			vertex = isis_find_vertex(
				&spftree->paths, &vertex_N->N.ip.p.dest, vtype);
			if (!vertex)
				continue;

			/* Pick vertex with the best metric. */
			if (!vertex_best || vertex_best->d_N > vertex->d_N)
				vertex_best = vertex;
		}
		break;
	default:
		break;
	}

	if (!vertex_best)
		return -1;

	assert(VTYPE_IP(vertex_best->type));
	vertex_best = listnode_head(vertex_best->parents);
	*distance = vertex_best->d_N;

	return 0;
}

/* Calculate the distance from the root node to the given node. */
static int lfa_calc_dist_node(struct isis_spftree *spftree,
			      const uint8_t *sysid, uint32_t *distance)
{
	struct isis_vertex *vertex, *vertex_best = NULL;

	for (int vtype = VTYPE_PSEUDO_IS; vtype <= VTYPE_NONPSEUDO_TE_IS;
	     vtype++) {
		vertex = isis_find_vertex(&spftree->paths, sysid, vtype);
		if (!vertex)
			continue;

		/* Pick vertex with the best metric. */
		if (!vertex_best || vertex_best->d_N > vertex->d_N)
			vertex_best = vertex;
	}

	if (!vertex_best)
		return -1;

	*distance = vertex_best->d_N;

	return 0;
}

/*
 * Check loop-free criterion (RFC 5286's inequality 1):
 * - Dist_opt(N, D) < Dist_opt(N, S) + Dist_opt(S, D)
 */
static bool clfa_loop_free_check(struct isis_spftree *spftree,
				 struct isis_vertex *vertex_S_D,
				 struct isis_spf_adj *sadj_primary,
				 struct isis_spf_adj *sadj_N,
				 uint32_t *path_metric)
{
	struct isis_spf_node *node_N;
	uint32_t dist_N_D;
	uint32_t dist_N_S;
	uint32_t dist_S_D;

	node_N = isis_spf_node_find(&spftree->adj_nodes, sadj_N->id);
	assert(node_N);

	/* Distance from N to D. */
	if (lfa_calc_dist_destination(node_N->lfa.spftree, vertex_S_D,
				      &dist_N_D)
	    != 0)
		return false;

	/* Distance from N to S (or PN). */
	if (CHECK_FLAG(sadj_primary->flags, F_ISIS_SPF_ADJ_BROADCAST)) {
		static uint8_t pn_sysid[ISIS_SYS_ID_LEN + 1];

		memcpy(pn_sysid, sadj_primary->id, ISIS_SYS_ID_LEN + 1);
		if (lfa_calc_dist_node(node_N->lfa.spftree, pn_sysid, &dist_N_S)
		    != 0)
			return false;
	} else {
		static uint8_t root_sysid[ISIS_SYS_ID_LEN + 1];

		memcpy(root_sysid, spftree->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(root_sysid) = 0;
		if (lfa_calc_dist_node(node_N->lfa.spftree, root_sysid,
				       &dist_N_S)
		    != 0)
			return false;
	}

	/* Distance from S (or PN) to D. */
	vertex_S_D = listnode_head(vertex_S_D->parents);
	dist_S_D = vertex_S_D->d_N;
	if (CHECK_FLAG(sadj_primary->flags, F_ISIS_SPF_ADJ_BROADCAST))
		dist_S_D -= sadj_primary->metric;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: loop-free check: %u < %u + %u", dist_N_D,
			   dist_N_S, dist_S_D);

	if (dist_N_D < (dist_N_S + dist_S_D)) {
		*path_metric = sadj_N->metric + dist_N_D;
		return true;
	}

	return false;
}

/*
 * Check loop-free criterion (RFC 5286's inequality 2):
 * - Distance_opt(N, D) < Distance_opt(S, D)
 */
static bool clfa_downstream_check(struct isis_spftree *spftree,
				  struct isis_vertex *vertex_S_D,
				  struct isis_spf_adj *sadj_N)
{
	struct isis_spf_node *node_N;
	uint32_t dist_N_D;
	uint32_t dist_S_D;

	node_N = isis_spf_node_find(&spftree->adj_nodes, sadj_N->id);
	assert(node_N);

	/* Distance from N to D. */
	if (lfa_calc_dist_destination(node_N->lfa.spftree, vertex_S_D,
				      &dist_N_D)
	    != 0)
		return false;

	/* Distance from S (or PN) to D. */
	vertex_S_D = listnode_head(vertex_S_D->parents);
	dist_S_D = vertex_S_D->d_N;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: downstream check: %u < %u", dist_N_D,
			   dist_S_D);

	if (dist_N_D < dist_S_D)
		return true;

	return false;
}

/*
 * Check loop-free criterion (RFC 5286's inequality 3):
 * - Dist_opt(N, D) < Dist_opt(N, E) + Dist_opt(E, D)
 */
static bool clfa_node_protecting_check(struct isis_spftree *spftree,
				       struct isis_vertex *vertex_S_D,
				       struct isis_spf_adj *sadj_N,
				       struct isis_spf_adj *sadj_E)
{
	struct isis_spf_node *node_N, *node_E;
	uint32_t dist_N_D;
	uint32_t dist_N_E;
	uint32_t dist_E_D;

	node_N = isis_spf_node_find(&spftree->adj_nodes, sadj_N->id);
	assert(node_N);
	node_E = isis_spf_node_find(&spftree->adj_nodes, sadj_E->id);
	assert(node_E);

	/* Distance from N to D. */
	if (lfa_calc_dist_destination(node_N->lfa.spftree, vertex_S_D,
				      &dist_N_D)
	    != 0)
		return false;

	/* Distance from N to E. */
	if (lfa_calc_dist_node(node_N->lfa.spftree, node_E->sysid, &dist_N_E)
	    != 0)
		return false;

	/* Distance from E to D. */
	if (lfa_calc_dist_destination(node_E->lfa.spftree, vertex_S_D,
				      &dist_E_D)
	    != 0)
		return false;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: node protecting check: %u < %u + %u",
			   dist_N_D, dist_N_E, dist_E_D);

	return (dist_N_D < (dist_N_E + dist_E_D));
}

static struct list *
isis_lfa_tiebreakers(struct isis_area *area, struct isis_spftree *spftree,
		     struct lfa_protected_resource *resource,
		     struct isis_vertex *vertex,
		     struct isis_spf_adj *sadj_primary, struct list *lfa_list)
{
	struct lfa_tiebreaker *tie_b;
	int level = spftree->level;
	struct list *filtered_lfa_list;
	struct list *tent_lfa_list;

	filtered_lfa_list = list_dup(lfa_list);
	filtered_lfa_list->del = NULL;

	if (listcount(filtered_lfa_list) == 1)
		return filtered_lfa_list;

	/* Check tiebreakers in ascending order by index. */
	frr_each (lfa_tiebreaker_tree, &area->lfa_tiebreakers[level - 1],
		  tie_b) {
		struct isis_vertex_adj *lfa;
		struct listnode *node, *nnode;
		uint32_t best_metric = UINT32_MAX;

		tent_lfa_list = list_dup(filtered_lfa_list);

		switch (tie_b->type) {
		case LFA_TIEBREAKER_DOWNSTREAM:
			for (ALL_LIST_ELEMENTS(tent_lfa_list, node, nnode,
					       lfa)) {
				if (clfa_downstream_check(spftree, vertex,
							  lfa->sadj))
					continue;

				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: LFA %s doesn't satisfy the downstream condition",
						print_sys_hostname(
							lfa->sadj->id));
				listnode_delete(tent_lfa_list, lfa);
			}
			break;
		case LFA_TIEBREAKER_LOWEST_METRIC:
			/* Find the best metric first. */
			for (ALL_LIST_ELEMENTS_RO(tent_lfa_list, node, lfa)) {
				if (lfa->lfa_metric < best_metric)
					best_metric = lfa->lfa_metric;
			}

			/* Remove LFAs that don't have the best metric. */
			for (ALL_LIST_ELEMENTS(tent_lfa_list, node, nnode,
					       lfa)) {
				if (lfa->lfa_metric == best_metric)
					continue;

				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: LFA %s doesn't have the lowest cost metric",
						print_sys_hostname(
							lfa->sadj->id));
				listnode_delete(tent_lfa_list, lfa);
			}
			break;
		case LFA_TIEBREAKER_NODE_PROTECTING:
			for (ALL_LIST_ELEMENTS(tent_lfa_list, node, nnode,
					       lfa)) {
				if (clfa_node_protecting_check(spftree, vertex,
							       lfa->sadj,
							       sadj_primary))
					continue;

				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: LFA %s doesn't provide node protection",
						print_sys_hostname(
							lfa->sadj->id));
				listnode_delete(tent_lfa_list, lfa);
			}
			break;
		}

		/*
		 * Decide what to do next based on the number of remaining LFAs.
		 */
		switch (listcount(tent_lfa_list)) {
		case 0:
			/*
			 * Ignore this tie-breaker since it excluded all LFAs.
			 * Move on to the next one (if any).
			 */
			list_delete(&tent_lfa_list);
			break;
		case 1:
			/* Finish tie-breaking once we get a single LFA. */
			list_delete(&filtered_lfa_list);
			filtered_lfa_list = tent_lfa_list;
			return filtered_lfa_list;
		default:
			/*
			 * We still have two or more LFAs. Move on to the next
			 * tie-breaker (if any).
			 */
			list_delete(&filtered_lfa_list);
			filtered_lfa_list = tent_lfa_list;
			break;
		}
	}

	return filtered_lfa_list;
}

void isis_lfa_compute(struct isis_area *area, struct isis_circuit *circuit,
		      struct isis_spftree *spftree,
		      struct lfa_protected_resource *resource)
{
	struct isis_vertex *vertex, *parent_vertex;
	struct listnode *vnode, *snode;
	int level = spftree->level;

	resource->type = LFA_LINK_PROTECTION;

	if (IS_DEBUG_LFA)
		zlog_debug("ISIS-LFA: computing local LFAs for %s",
			   lfa_protected_resource2str(resource));

	for (ALL_QUEUE_ELEMENTS_RO(&spftree->paths, vnode, vertex)) {
		struct list *lfa_list;
		struct list *filtered_lfa_list;
		struct isis_spf_adj *sadj_N;
		struct isis_vertex_adj *vadj_primary;
		struct isis_spf_adj *sadj_primary;
		bool allow_ecmp;
		uint32_t prefix_metric, best_metric = UINT32_MAX;
		char buf[VID2STR_BUFFER];

		if (!VTYPE_IP(vertex->type))
			continue;

		vid2string(vertex, buf, sizeof(buf));

		if (!spf_vertex_check_is_affected(vertex, spftree->sysid,
						  resource)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s %s unaffected by %s",
					vtype2string(vertex->type), buf,
					lfa_protected_resource2str(resource));
			continue;
		}

		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: checking %s %s w.r.t %s",
				   vtype2string(vertex->type), buf,
				   lfa_protected_resource2str(resource));

		if (vertex->N.ip.priority
		    > area->lfa_priority_limit[level - 1]) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: skipping computing LFAs due to low prefix priority");
			continue;
		}

		vadj_primary = listnode_head(vertex->Adj_N);
		if (!vadj_primary) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: skipping computing LFAs due to no adjacencies");
			continue;
		}
		sadj_primary = vadj_primary->sadj;

		parent_vertex = listnode_head(vertex->parents);
		assert(parent_vertex);
		prefix_metric = vertex->d_N - parent_vertex->d_N;

		/*
		 * Loop over list of SPF adjacencies and compute a list of
		 * preliminary LFAs.
		 */
		lfa_list = list_new();
		lfa_list->del = isis_vertex_adj_free;
		for (ALL_LIST_ELEMENTS_RO(spftree->sadj_list, snode, sadj_N)) {
			uint32_t lfa_metric, path_metric;
			struct isis_vertex_adj *lfa;
			struct isis_prefix_sid *psid = NULL;
			bool last_hop = false;

			/* Skip pseudonodes. */
			if (LSP_PSEUDO_ID(sadj_N->id))
				continue;

			/*
			 * Skip nexthops that are along a link whose cost is
			 * infinite.
			 */
			if (CHECK_FLAG(sadj_N->flags,
				       F_ISIS_SPF_ADJ_METRIC_INFINITY))
				continue;

			/* Skip nexthops that have the overload bit set. */
			if (spftree->mtid != ISIS_MT_IPV4_UNICAST) {
				struct isis_mt_router_info *mt_router_info;

				mt_router_info =
					isis_tlvs_lookup_mt_router_info(
						sadj_N->lsp->tlvs,
						spftree->mtid);
				if (mt_router_info && mt_router_info->overload)
					continue;
			} else if (ISIS_MASK_LSP_OL_BIT(
					   sadj_N->lsp->hdr.lsp_bits))
				continue;

			/* Skip primary nexthop. */
			if (spf_adj_check_is_affected(sadj_N, resource, NULL,
						      false))
				continue;

			/* Skip excluded interfaces as per the configuration. */
			if (circuit
			    && isis_lfa_excluded_iface_check(
				       circuit, level,
				       sadj_N->adj->circuit->interface->name))
				continue;

			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: checking candidate LFA %s",
					print_sys_hostname(sadj_N->id));

			/* Check loop-free criterion. */
			if (!clfa_loop_free_check(spftree, vertex, sadj_primary,
						  sadj_N, &path_metric)) {
				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: LFA condition not met for %s",
						print_sys_hostname(sadj_N->id));
				continue;
			}

			lfa_metric = path_metric + prefix_metric;
			if (lfa_metric < best_metric)
				best_metric = lfa_metric;

			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s is a valid loop-free alternate",
					print_sys_hostname(sadj_N->id));

			if (vertex->N.ip.sr.present) {
				psid = &vertex->N.ip.sr.sid;
				if (path_metric == sadj_N->metric)
					last_hop = true;
			}
			lfa = isis_vertex_adj_add(spftree, vertex, lfa_list,
						  sadj_N, psid, last_hop);
			lfa->lfa_metric = lfa_metric;
		}

		if (list_isempty(lfa_list)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: no valid local LFAs found");
			list_delete(&lfa_list);
			continue;
		}

		SET_FLAG(vertex->flags, F_ISIS_VERTEX_LFA_PROTECTED);

		/* Check tie-breakers. */
		filtered_lfa_list =
			isis_lfa_tiebreakers(area, spftree, resource, vertex,
					     sadj_primary, lfa_list);

		/* Create backup route using the best LFAs. */
		allow_ecmp = area->lfa_load_sharing[level - 1];
		isis_route_create(&vertex->N.ip.p.dest, &vertex->N.ip.p.src,
				  best_metric, vertex->depth, &vertex->N.ip.sr,
				  filtered_lfa_list, allow_ecmp, area,
				  spftree->route_table_backup);
		spftree->lfa.protection_counters.lfa[vertex->N.ip.priority] +=
			1;

		list_delete(&filtered_lfa_list);
		list_delete(&lfa_list);
	}
}

static void isis_spf_run_tilfa(struct isis_area *area,
			       struct isis_circuit *circuit,
			       struct isis_spftree *spftree,
			       struct isis_spftree *spftree_reverse,
			       struct lfa_protected_resource *resource)
{
	struct isis_spftree *spftree_pc_link;
	struct isis_spftree *spftree_pc_node;

	/* Compute node protecting repair paths first (if necessary). */
	if (circuit->tilfa_node_protection[spftree->level - 1]) {
		resource->type = LFA_NODE_PROTECTION;
		spftree_pc_node = isis_tilfa_compute(area, spftree,
						     spftree_reverse, resource);
		isis_spftree_del(spftree_pc_node);

		/* don't do link protection unless link-fallback is configured
		 */
		if (!circuit->tilfa_link_fallback[spftree->level - 1])
			return;
	}

	/* Compute link protecting repair paths. */
	resource->type = LFA_LINK_PROTECTION;
	spftree_pc_link =
		isis_tilfa_compute(area, spftree, spftree_reverse, resource);
	isis_spftree_del(spftree_pc_link);
}

/**
 * Run the LFA/RLFA/TI-LFA algorithms for all protected interfaces.
 *
 * @param area		IS-IS area
 * @param spftree	IS-IS SPF tree
 */
void isis_spf_run_lfa(struct isis_area *area, struct isis_spftree *spftree)
{
	struct isis_spftree *spftree_reverse = NULL;
	struct isis_circuit *circuit;
	struct listnode *node;
	int level = spftree->level;

	/* Run reverse SPF locally. */
	if (area->rlfa_protected_links[level - 1] > 0
	    || area->tilfa_protected_links[level - 1] > 0)
		spftree_reverse = isis_spf_reverse_run(spftree);

	/* Run forward SPF on all adjacent routers. */
	isis_spf_run_neighbors(spftree);

	/* Check which interfaces are protected. */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		struct lfa_protected_resource resource = {};
		struct isis_adjacency *adj;
		static uint8_t null_sysid[ISIS_SYS_ID_LEN + 1];

		if (!(circuit->is_type & level))
			continue;

		if (!circuit->lfa_protection[level - 1]
		    && !circuit->tilfa_protection[level - 1])
			continue;

		/* Fill in the protected resource. */
		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			if (level == ISIS_LEVEL1)
				memcpy(resource.adjacency,
				       circuit->u.bc.l1_desig_is,
				       ISIS_SYS_ID_LEN + 1);
			else
				memcpy(resource.adjacency,
				       circuit->u.bc.l2_desig_is,
				       ISIS_SYS_ID_LEN + 1);
			/* Do nothing if no DR was elected yet. */
			if (!memcmp(resource.adjacency, null_sysid,
				    ISIS_SYS_ID_LEN + 1))
				continue;
			break;
		case CIRCUIT_T_P2P:
			adj = circuit->u.p2p.neighbor;
			if (!adj)
				continue;
			memcpy(resource.adjacency, adj->sysid, ISIS_SYS_ID_LEN);
			LSP_PSEUDO_ID(resource.adjacency) = 0;
			break;
		default:
			continue;
		}

		if (circuit->lfa_protection[level - 1]) {
			/* Run local LFA. */
			isis_lfa_compute(area, circuit, spftree, &resource);

			if (circuit->rlfa_protection[level - 1]) {
				struct isis_spftree *spftree_pc;
				uint32_t max_metric;

				/* Run remote LFA. */
				assert(spftree_reverse);
				max_metric =
					circuit->rlfa_max_metric[level - 1];
				spftree_pc = isis_rlfa_compute(
					area, spftree, spftree_reverse,
					max_metric, &resource);
				listnode_add(spftree->lfa.remote.pc_spftrees,
					     spftree_pc);
			}
		} else if (circuit->tilfa_protection[level - 1]) {
			/* Run TI-LFA. */
			assert(spftree_reverse);
			isis_spf_run_tilfa(area, circuit, spftree,
					   spftree_reverse, &resource);
		}
	}

	if (spftree_reverse)
		isis_spftree_del(spftree_reverse);
}
