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

#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "vrf.h"
#include "table.h"
#include "srcdest_table.h"

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
#include "isisd/isis_errors.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_NODE, "ISIS SPF Node");
DEFINE_MTYPE_STATIC(ISISD, ISIS_LFA_TIEBREAKER, "ISIS LFA Tiebreaker");
DEFINE_MTYPE_STATIC(ISISD, ISIS_LFA_EXCL_IFACE, "ISIS LFA Excluded Interface");

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
void isis_lfa_excluded_ifaces_clear(struct isis_circuit *circuit, int level)
{
	hash_clean(circuit->lfa_excluded_ifaces[level - 1],
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
	hash_get(circuit->lfa_excluded_ifaces[level - 1], (char *)ifname,
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

	if (spftree->type != SPF_TYPE_TI_LFA)
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

	psid = (struct isis_prefix_sid *)subtlvs->prefix_sids.head;

	/* Require the node flag to be set. */
	if (!CHECK_FLAG(psid->flags, ISIS_PREFIX_SID_NODE))
		return LSP_ITER_CONTINUE;

	args->sid_index = psid->value;

	return LSP_ITER_STOP;
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

		if (!isis_vertex_adj_exists(spftree, vertex_pnode, sadj))
			continue;

		assert(!vadj->label_stack);
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

/* Check if a given TI-LFA post-convergence SPF vertex needs protection. */
static bool tilfa_check_needs_protection(const struct isis_spftree *spftree_pc,
					 const struct isis_vertex *vertex)
{
	struct isis_vertex *vertex_old;

	/* Only local adjacencies need Adj-SID protection. */
	if (VTYPE_IS(vertex->type)
	    && !isis_adj_find(spftree_pc->area, spftree_pc->level,
			      vertex->N.id))
		return false;

	vertex_old = isis_find_vertex(&spftree_pc->lfa.old.spftree->paths,
				      &vertex->N, vertex->type);
	if (!vertex_old)
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

	if (IS_DEBUG_LFA)
		vid2string(vertex, buf, sizeof(buf));

	if (!tilfa_check_needs_protection(spftree_pc, vertex)) {
		if (IS_DEBUG_LFA)
			zlog_debug(
				"ISIS-LFA: %s %s unaffected by %s",
				vtype2string(vertex->type), buf,
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
		if (adj
		    && isis_sr_adj_sid_find(adj, spftree_pc->family,
					    ISIS_SR_LAN_BACKUP)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s %s already covered by node protection",
					vtype2string(vertex->type), buf);

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
					vtype2string(vertex->type), buf);

			return -1;
		}
	}

	if (IS_DEBUG_LFA)
		zlog_debug(
			"ISIS-LFA: computing repair path(s) of %s %s w.r.t %s",
			vtype2string(vertex->type), buf,
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
			vtype2string(vertex->type), buf,
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
		char buf1[VID2STR_BUFFER];
		char buf2[VID2STR_BUFFER];

		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: vertex %s parent %s",
				   vid2string(vertex, buf1, sizeof(buf1)),
				   vid2string(pvertex, buf2, sizeof(buf2)));

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

		if (!VTYPE_IS(vertex->type))
			continue;

		/* Skip root node. */
		if (!memcmp(vertex->N.id, spftree_root->sysid, ISIS_SYS_ID_LEN))
			continue;

		/* Don't add the same node twice. */
		if (isis_spf_node_find(nodes, vertex->N.id))
			continue;

		if (IS_DEBUG_LFA)
			zlog_debug("ISIS-LFA: checking %s",
				   vid2string(vertex, buf, sizeof(buf)));

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
		F_SPFTREE_NO_ADJACENCIES | F_SPFTREE_NO_ROUTES);
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
			 * adjacent to the failure.
			 */
			adj_node->lfa.spftree_reverse =
				isis_spf_reverse_run(adj_node->lfa.spftree);

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
		zlog_debug("ISIS-LFA: computing the P/Q spaces w.r.t. %s",
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
				      SPF_TYPE_TI_LFA, spftree->flags);
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
			F_SPFTREE_NO_ADJACENCIES | F_SPFTREE_NO_ROUTES);
		isis_run_spf(adj_node->lfa.spftree);
	}

	return 0;
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
				 uint32_t *lfa_metric)
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
		*lfa_metric = sadj_N->metric + dist_N_D;
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
isis_lfa_tiebreakers(struct isis_area *area, struct isis_circuit *circuit,
		     struct isis_spftree *spftree,
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
	struct isis_vertex *vertex;
	struct listnode *vnode, *snode;
	int level = spftree->level;

	resource->type = LFA_LINK_PROTECTION;

	for (ALL_QUEUE_ELEMENTS_RO(&spftree->paths, vnode, vertex)) {
		struct list *lfa_list;
		struct list *filtered_lfa_list;
		struct isis_spf_adj *sadj_N;
		struct isis_vertex_adj *vadj_primary;
		struct isis_spf_adj *sadj_primary;
		bool allow_ecmp;
		uint32_t best_metric = UINT32_MAX;
		char buf[VID2STR_BUFFER];

		if (!VTYPE_IP(vertex->type))
			continue;

		vid2string(vertex, buf, sizeof(buf));

		if (!spf_vertex_check_is_affected(vertex, spftree->sysid,
						  resource)) {
			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: route unaffected by %s",
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
		sadj_primary = vadj_primary->sadj;

		/*
		 * Loop over list of SPF adjacencies and compute a list of
		 * preliminary LFAs.
		 */
		lfa_list = list_new();
		lfa_list->del = isis_vertex_adj_free;
		for (ALL_LIST_ELEMENTS_RO(spftree->sadj_list, snode, sadj_N)) {
			uint32_t lfa_metric;
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
						  sadj_N, &lfa_metric)) {
				if (IS_DEBUG_LFA)
					zlog_debug(
						"ISIS-LFA: LFA condition not met for %s",
						print_sys_hostname(sadj_N->id));
				continue;
			}

			if (lfa_metric < best_metric)
				best_metric = lfa_metric;

			if (IS_DEBUG_LFA)
				zlog_debug(
					"ISIS-LFA: %s is a valid loop-free alternate",
					print_sys_hostname(sadj_N->id));

			if (vertex->N.ip.sr.present) {
				psid = &vertex->N.ip.sr.sid;
				if (lfa_metric == sadj_N->metric)
					last_hop = true;
			}
			lfa = isis_vertex_adj_add(spftree, vertex, lfa_list,
						  sadj_N, psid, last_hop);
			lfa->lfa_metric = lfa_metric;
		}

		if (list_isempty(lfa_list)) {
			if (IS_DEBUG_LFA)
				zlog_debug("ISIS-LFA: no valid LFAs found");
			list_delete(&lfa_list);
			continue;
		}

		/* Check tie-breakers. */
		filtered_lfa_list =
			isis_lfa_tiebreakers(area, circuit, spftree, resource,
					     vertex, sadj_primary, lfa_list);

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
	}

	/* Compute link protecting repair paths. */
	resource->type = LFA_LINK_PROTECTION;
	spftree_pc_link =
		isis_tilfa_compute(area, spftree, spftree_reverse, resource);
	isis_spftree_del(spftree_pc_link);
}

/**
 * Run the LFA/TI-LFA algorithms for all protected interfaces.
 *
 * @param area		IS-IS area
 * @param spftree	IS-IS SPF tree
 */
void isis_spf_run_lfa(struct isis_area *area, struct isis_spftree *spftree)
{
	struct isis_spftree *spftree_reverse = NULL;
	struct isis_circuit *circuit;
	struct listnode *node;
	bool tilfa_configured;
	int level = spftree->level;

	tilfa_configured = (area->tilfa_protected_links[level - 1] > 0);

	/* Run reverse SPF locally. */
	if (tilfa_configured)
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

		if (circuit->lfa_protection[level - 1])
			isis_lfa_compute(area, circuit, spftree, &resource);
		else if (circuit->tilfa_protection[level - 1]) {
			assert(spftree_reverse);
			isis_spf_run_tilfa(area, circuit, spftree,
					   spftree_reverse, &resource);
		}
	}

	if (tilfa_configured)
		isis_spftree_del(spftree_reverse);
}
