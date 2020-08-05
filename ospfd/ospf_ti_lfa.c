/*
 * OSPF TI-LFA
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Sascha Kattelmann
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ti_lfa.h"


DECLARE_RBTREE_UNIQ(p_spaces, struct p_space, p_spaces_item,
		    p_spaces_compare_func)
DECLARE_RBTREE_UNIQ(q_spaces, struct q_space, q_spaces_item,
		    q_spaces_compare_func)


static void ospf_ti_lfa_find_p_node(struct vertex *pc_node,
				    struct p_space *p_space,
				    struct q_space *q_space,
				    struct ospf_ti_lfa_node_info *node_info)
{
	struct listnode *node;
	struct vertex *p_node = NULL, *p_node_pc_parent;
	struct vertex_parent *pc_vertex_parent;

	node_info->type = OSPF_TI_LFA_UNDEFINED_NODE;

	for (ALL_LIST_ELEMENTS_RO(pc_node->parents, node, pc_vertex_parent)) {
		p_node = ospf_spf_vertex_find(pc_vertex_parent->parent->id,
					      p_space->vertex_list);

		/* Just take the first discovered P node */
		if (p_node)
			break;
	}

	if (!p_node)
		return;

	node_info->node = p_node;
	node_info->type = OSPF_TI_LFA_P_NODE;

	/* For the nexthop we just use the first vertex parent */
	p_node_pc_parent =
		ospf_spf_vertex_find(p_node->id, p_space->pc_vertex_list);
	pc_vertex_parent = listnode_head(p_node_pc_parent->parents);

	/*
	 * It can happen that the P node is the root node itself (hence there
	 * can be no parents). In this case we don't need to set a nexthop.
	 */
	node_info->nexthop.s_addr = INADDR_ANY;
	if (pc_vertex_parent)
		node_info->nexthop = pc_vertex_parent->nexthop->router;
}

static void ospf_ti_lfa_find_q_node(struct vertex *pc_node,
				    struct p_space *p_space,
				    struct q_space *q_space,
				    struct ospf_ti_lfa_node_info *node_info)
{
	struct listnode *node;
	struct vertex *p_node, *q_node, *q_space_parent = NULL;
	struct vertex_parent *pc_vertex_parent;

	p_node = ospf_spf_vertex_find(pc_node->id, p_space->vertex_list);
	q_node = ospf_spf_vertex_find(pc_node->id, q_space->vertex_list);

	/*
	 * If we don't find the node in the Q space then there's really
	 * something wrong (since we check the parent, see below).
	 */
	assert(q_node);

	node_info->type = OSPF_TI_LFA_UNDEFINED_NODE;

	if (p_node && q_node) {
		node_info->node = pc_node;
		node_info->type = OSPF_TI_LFA_PQ_NODE;

		/* For the nexthop we just use the first vertex parent */
		pc_vertex_parent = listnode_head(pc_node->parents);
		node_info->nexthop = pc_vertex_parent->nexthop->router;
		return;
	}

	if (pc_node->parents->count == 0)
		return;

	/* First check if the same link also exists in the Q space */
	for (ALL_LIST_ELEMENTS_RO(pc_node->parents, node, pc_vertex_parent)) {
		/*
		 * Note that the Q space has the 'reverse' direction of the PC
		 * SPF. Hence compare PC SPF parents to Q space children.
		 */
		q_space_parent = ospf_spf_vertex_find(
			pc_vertex_parent->parent->id, q_node->children);
		if (q_space_parent)
			break;
	}

	/*
	 * If the Q space parent doesn't exist we 'hit' the border to the P
	 * space and hence got our Q node.
	 */
	if (!q_space_parent) {
		node_info->node = pc_node;
		node_info->type = OSPF_TI_LFA_Q_NODE;

		/* For the nexthop we just use the first vertex parent */
		pc_vertex_parent = listnode_head(pc_node->parents);
		node_info->nexthop = pc_vertex_parent->nexthop->router;
		return;
	}

	return ospf_ti_lfa_find_q_node(pc_vertex_parent->parent, p_space,
				       q_space, node_info);
}

static struct mpls_label_stack *
ospf_ti_lfa_create_label_stack(mpls_label_t labels[], uint32_t num_labels)
{
	struct mpls_label_stack *label_stack;
	uint32_t i;

	/* Sanity check */
	for (i = 0; i < num_labels; i++) {
		if (labels[i] == MPLS_INVALID_LABEL)
			return NULL;
	}

	label_stack = XCALLOC(MTYPE_OSPF_Q_SPACE,
			      sizeof(struct mpls_label_stack)
				      + num_labels * sizeof(mpls_label_t));
	label_stack->num_labels = num_labels;

	for (i = 0; i < num_labels; i++)
		label_stack->label[i] = labels[i];

	return label_stack;
}

static void ospf_ti_lfa_generate_label_stack(struct p_space *p_space,
					     struct q_space *q_space)
{
	struct ospf_ti_lfa_node_info p_node_info, q_node_info;
	mpls_label_t labels[2];
	struct vertex *pc_node;

	zlog_debug("%s: Generating Label stack for src %pI4 and dest %pI4.",
		   __func__, &p_space->root->id, &q_space->root->id);

	pc_node = ospf_spf_vertex_find(q_space->root->id,
				       p_space->pc_vertex_list);
	if (!pc_node) {
		zlog_debug(
			"%s: There seems to be no post convergence path (yet).",
			__func__);
		return;
	}

	ospf_ti_lfa_find_q_node(pc_node, p_space, q_space, &q_node_info);
	if (q_node_info.type == OSPF_TI_LFA_UNDEFINED_NODE) {
		zlog_debug("%s: Q node not found!", __func__);
		return;
	}

	/* Found a PQ node? Then we are done here. */
	if (q_node_info.type == OSPF_TI_LFA_PQ_NODE) {
		labels[0] = ospf_sr_get_prefix_sid_by_id(&q_node_info.node->id);
		q_space->label_stack =
			ospf_ti_lfa_create_label_stack(labels, 1);
		q_space->nexthop = q_node_info.nexthop;
		return;
	}

	/* Otherwise find the adjacent P node. */
	pc_node = ospf_spf_vertex_find(q_node_info.node->id,
				       p_space->pc_vertex_list);
	ospf_ti_lfa_find_p_node(pc_node, p_space, q_space, &p_node_info);
	if (p_node_info.type == OSPF_TI_LFA_UNDEFINED_NODE) {
		zlog_debug("%s: P node not found!", __func__);
		return;
	}

	/*
	 * It can happen that the P node is the root itself, therefore we don't
	 * need a label for it.
	 */
	if (p_node_info.node->id.s_addr == p_space->root->id.s_addr) {
		labels[0] = ospf_sr_get_prefix_sid_by_id(&q_node_info.node->id);
		q_space->label_stack =
			ospf_ti_lfa_create_label_stack(labels, 1);
		q_space->nexthop = q_node_info.nexthop;
		return;
	}

	/* Otherwise we have a P and also a Q node which we need labels for. */
	labels[0] = ospf_sr_get_prefix_sid_by_id(&p_node_info.node->id);
	labels[1] = ospf_sr_get_prefix_sid_by_id(&q_node_info.node->id);
	q_space->label_stack = ospf_ti_lfa_create_label_stack(labels, 2);
	q_space->nexthop = p_node_info.nexthop;
}

static void ospf_ti_lfa_generate_q_spaces(struct ospf_area *area,
					  struct p_space *p_space,
					  struct vertex *dest)
{
	struct listnode *node;
	struct vertex *child;
	struct route_table *new_table, *new_rtrs;
	struct q_space *q_space, q_space_search;
	char buf[MPLS_LABEL_STRLEN];

	/* Check if we already have a Q space for this destination */
	q_space_search.root = dest;
	if (q_spaces_find(p_space->q_spaces, &q_space_search))
		return;

	q_space = XCALLOC(MTYPE_OSPF_Q_SPACE, sizeof(struct q_space));

	new_table = route_table_init();
	new_rtrs = route_table_init();

	/*
	 * Generate a new SPF tree for this vertex,
	 * dry run true, root node false
	 */
	ospf_spf_calculate(area, dest->lsa_p, new_table, new_rtrs, true, false);

	q_space->root = area->spf;
	q_space->vertex_list = area->spf_vertex_list;
	q_space->label_stack = NULL;

	/* 'Cut' the branch of the protected link out of the new SPF tree */
	ospf_spf_remove_link(q_space->root, q_space->vertex_list,
			     p_space->protected_link);

	/*
	 * Generate the smallest possible label stack from the root of the P
	 * space to the root of the Q space.
	 */
	ospf_ti_lfa_generate_label_stack(p_space, q_space);

	if (q_space->label_stack) {
		mpls_label2str(q_space->label_stack->num_labels,
			       q_space->label_stack->label, buf,
			       MPLS_LABEL_STRLEN, true);
		zlog_info(
			"%s: Generated label stack %s for root %pI4 and destination %pI4 for protected link %pI4",
			__func__, buf, &p_space->root->id, &q_space->root->id,
			&p_space->protected_link->link_id);
	} else {
		zlog_info(
			"%s: NO label stack generated for root %pI4 and destination %pI4 for protected link %pI4",
			__func__, &p_space->root->id, &q_space->root->id,
			&p_space->protected_link->link_id);
	}

	/* We are finished, store the new Q space in the P space struct */
	q_spaces_add(p_space->q_spaces, q_space);

	/* Recursively generate Q spaces for all children */
	for (ALL_LIST_ELEMENTS_RO(dest->children, node, child))
		ospf_ti_lfa_generate_q_spaces(area, p_space, child);
}

static void ospf_ti_lfa_generate_post_convergence_spf(struct ospf_area *area,
						      struct p_space *p_space)
{
	struct route_table *new_table, *new_rtrs;

	new_table = route_table_init();
	new_rtrs = route_table_init();

	area->spf_protected_link = p_space->protected_link;

	/*
	 * The 'post convergence' SPF tree is generated here
	 * dry run true, root node false
	 *
	 * So how does this work? During the SPF calculation the algorithm
	 * checks if a link belongs to a protected stub and then just ignores
	 * it. This is actually _NOT_ a good way to calculate the post
	 * convergence SPF tree. The preferred way would be to delete the
	 * relevant links from a copy of the LSDB and then just run the SPF
	 * algorithm on that as usual. However, removing links from router
	 * LSAs appears to be its own endeavour (because LSAs are stored as a
	 * 'raw' stream), so we go with this rather hacky way for now.
	 */
	ospf_spf_calculate(area, area->router_lsa_self, new_table, new_rtrs,
			   true, false);

	p_space->pc_spf = area->spf;
	p_space->pc_vertex_list = area->spf_vertex_list;

	area->spf_protected_link = NULL;
}

static void ospf_ti_lfa_generate_p_space(struct ospf_area *area,
					 struct vertex *child,
					 struct router_lsa_link *link)
{
	struct vertex *spf_orig;
	struct list *vertex_list, *vertex_list_orig;
	struct p_space *p_space;

	p_space = XCALLOC(MTYPE_OSPF_P_SPACE, sizeof(struct p_space));
	vertex_list = list_new();

	/* The P-space will get its own SPF tree, so copy the old one */
	ospf_spf_copy(area->spf, vertex_list);
	p_space->root = listnode_head(vertex_list);
	p_space->vertex_list = vertex_list;
	p_space->protected_link = link;

	/* Initialize the Q spaces for this P space and protected link */
	p_space->q_spaces =
		XCALLOC(MTYPE_OSPF_Q_SPACE, sizeof(struct q_spaces_head));
	q_spaces_init(p_space->q_spaces);

	/* 'Cut' the child branch out of the new SPF tree */
	ospf_spf_remove_link(p_space->root, p_space->vertex_list,
			     p_space->protected_link);

	/*
	 * Since we are going to calculate more SPF trees for Q spaces, keep the
	 * 'original' one here temporarily
	 */
	spf_orig = area->spf;
	vertex_list_orig = area->spf_vertex_list;

	/* Generate the post convergence SPF as a blueprint for backup paths */
	ospf_ti_lfa_generate_post_convergence_spf(area, p_space);

	/* Generate the relevant Q spaces for this particular P space */
	ospf_ti_lfa_generate_q_spaces(area, p_space, child);

	/* Put the 'original' SPF tree back in place */
	area->spf = spf_orig;
	area->spf_vertex_list = vertex_list_orig;

	/* We are finished, store the new P space */
	p_spaces_add(area->p_spaces, p_space);
}

void ospf_ti_lfa_generate_p_spaces(struct ospf_area *area)
{
	struct listnode *node, *inner_node;
	struct vertex *root, *child;
	struct vertex_parent *vertex_parent;
	uint8_t *p, *lim;
	struct router_lsa_link *l = NULL;
	struct prefix stub_prefix, child_prefix;

	area->p_spaces =
		XCALLOC(MTYPE_OSPF_P_SPACE, sizeof(struct p_spaces_head));
	p_spaces_init(area->p_spaces);

	root = area->spf;

	/* Root or its router LSA was not created yet? */
	if (!root || !root->lsa)
		return;

	stub_prefix.family = AF_INET;
	child_prefix.family = AF_INET;
	child_prefix.prefixlen = IPV4_MAX_PREFIXLEN;

	p = ((uint8_t *)root->lsa) + OSPF_LSA_HEADER_SIZE + 4;
	lim = ((uint8_t *)root->lsa) + ntohs(root->lsa->length);

	zlog_info("%s: Generating P spaces for area %pI4", __func__,
		  &area->area_id);

	/*
	 * Iterate over all stub networks which target other OSPF neighbors.
	 * Check the nexthop of the child vertex if a stub network is relevant.
	 */
	while (p < lim) {
		l = (struct router_lsa_link *)p;
		p += (OSPF_ROUTER_LSA_LINK_SIZE
		      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

		if (l->m[0].type != LSA_LINK_TYPE_STUB)
			continue;

		stub_prefix.prefixlen = ip_masklen(l->link_data);
		stub_prefix.u.prefix4 = l->link_id;

		for (ALL_LIST_ELEMENTS_RO(root->children, node, child)) {

			if (child->type != OSPF_VERTEX_ROUTER)
				continue;

			for (ALL_LIST_ELEMENTS_RO(child->parents, inner_node,
						  vertex_parent)) {

				child_prefix.u.prefix4 =
					vertex_parent->nexthop->router;

				/*
				 * If there's a link for that stub network then
				 * we will protect it. Hence generate a P space
				 * for that particular link including the
				 * Q spaces so we can later on generate a
				 * backup path for the link.
				 */
				if (prefix_match(&stub_prefix, &child_prefix)) {
					zlog_info(
						"%s: Generating P space for %pI4",
						__func__, &l->link_id);
					ospf_ti_lfa_generate_p_space(area,
								     child, l);
				}
			}
		}
	}
}

static struct p_space *
ospf_ti_lfa_get_p_space_by_nexthop(struct ospf_area *area,
				   struct in_addr *nexthop)
{
	struct p_space *p_space;
	struct router_lsa_link *link;

	frr_each(p_spaces, area->p_spaces, p_space) {
		link = p_space->protected_link;
		if ((nexthop->s_addr & link->link_data.s_addr)
		    == (link->link_id.s_addr & link->link_data.s_addr))
			return p_space;
	}

	return NULL;
}

void ospf_ti_lfa_insert_backup_paths(struct ospf_area *area,
				     struct route_table *new_table)
{
	struct route_node *rn;
	struct ospf_route *or;
	struct ospf_path *path;
	struct listnode *node;
	struct p_space *p_space;
	struct q_space *q_space, q_space_search;
	struct vertex root_search;

	for (rn = route_top(new_table); rn; rn = route_next(rn)) {
		or = rn->info;
		if (or == NULL)
			continue;

		/* Insert a backup path for all OSPF paths */
		for (ALL_LIST_ELEMENTS_RO(or->paths, node, path)) {
			p_space = ospf_ti_lfa_get_p_space_by_nexthop(
				area, &path->nexthop);
			if (!p_space) {
				zlog_debug(
					"%s: P space not found for nexthop %pI4.",
					__func__, &path->nexthop);
				continue;
			}

			root_search.id = path->adv_router;
			q_space_search.root = &root_search;
			q_space = q_spaces_find(p_space->q_spaces,
						&q_space_search);
			if (!q_space) {
				zlog_debug(
					"%s: Q space not found for advertising router %pI4.",
					__func__, &path->adv_router);
				continue;
			}

			path->srni.backup_label_stack = q_space->label_stack;
			path->srni.backup_nexthop = q_space->nexthop;
		}
	}
}

void ospf_ti_lfa_free_p_spaces(struct ospf_area *area)
{
	struct p_space *p_space;
	struct q_space *q_space;

	while ((p_space = p_spaces_pop(area->p_spaces))) {
		while ((q_space = q_spaces_pop(p_space->q_spaces))) {
			ospf_spf_cleanup(q_space->root, q_space->vertex_list);

			/*
			 * TODO: label stack is used for route installation
			 * XFREE(MTYPE_OSPF_Q_SPACE, q_space->label_stack);
			 */

			XFREE(MTYPE_OSPF_Q_SPACE, q_space);
		}
		ospf_spf_cleanup(p_space->root, p_space->vertex_list);
		ospf_spf_cleanup(p_space->pc_spf, p_space->pc_vertex_list);

		q_spaces_fini(p_space->q_spaces);
		XFREE(MTYPE_OSPF_Q_SPACE, p_space->q_spaces);
	}

	p_spaces_fini(area->p_spaces);
	XFREE(MTYPE_OSPF_P_SPACE, area->p_spaces);
}

void ospf_ti_lfa_compute(struct ospf_area *area, struct route_table *new_table)
{
	/*
	 * Generate P spaces per protected link and their respective Q spaces,
	 * generate backup paths (MPLS label stacks) by finding P/Q nodes.
	 */
	ospf_ti_lfa_generate_p_spaces(area);

	/* Insert the generated backup paths into the routing table. */
	ospf_ti_lfa_insert_backup_paths(area, new_table);

	/* Cleanup P spaces and related datastructures including Q spaces. */
	ospf_ti_lfa_free_p_spaces(area);
}
