// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF TI-LFA
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Sascha Kattelmann
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "printfrr.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ti_lfa.h"
#include "ospfd/ospf_dump.h"


DECLARE_RBTREE_UNIQ(p_spaces, struct p_space, p_spaces_item,
		    p_spaces_compare_func);
DECLARE_RBTREE_UNIQ(q_spaces, struct q_space, q_spaces_item,
		    q_spaces_compare_func);

static void
ospf_ti_lfa_generate_p_space(struct ospf_area *area, struct vertex *child,
			     struct protected_resource *protected_resource,
			     bool recursive, struct list *pc_path);

void ospf_print_protected_resource(
	struct protected_resource *protected_resource, char *buf)
{
	struct router_lsa_link *link;

	switch (protected_resource->type) {
	case OSPF_TI_LFA_LINK_PROTECTION:
		link = protected_resource->link;
		snprintfrr(buf, PROTECTED_RESOURCE_STRLEN,
			   "protected link: %pI4 %pI4", &link->link_id,
			   &link->link_data);
		break;
	case OSPF_TI_LFA_NODE_PROTECTION:
		snprintfrr(buf, PROTECTED_RESOURCE_STRLEN,
			   "protected node: %pI4",
			   &protected_resource->router_id);
		break;
	case OSPF_TI_LFA_UNDEFINED_PROTECTION:
		snprintfrr(buf, PROTECTED_RESOURCE_STRLEN,
			   "undefined protected resource");
		break;
	}
}

static enum ospf_ti_lfa_p_q_space_adjacency
ospf_ti_lfa_find_p_node(struct vertex *pc_node, struct p_space *p_space,
			struct q_space *q_space)
{
	struct listnode *curr_node;
	struct vertex *p_node = NULL, *pc_node_parent, *p_node_pc_parent;
	struct vertex_parent *pc_vertex_parent;

	curr_node = listnode_lookup(q_space->pc_path, pc_node);
	assert(curr_node);
	pc_node_parent = listgetdata(curr_node->next);

	q_space->p_node_info->type = OSPF_TI_LFA_UNDEFINED_NODE;

	p_node = ospf_spf_vertex_find(pc_node_parent->id, p_space->vertex_list);

	if (p_node) {
		q_space->p_node_info->node = p_node;
		q_space->p_node_info->type = OSPF_TI_LFA_P_NODE;

		if (curr_node->next->next) {
			p_node_pc_parent = listgetdata(curr_node->next->next);
			pc_vertex_parent = ospf_spf_vertex_parent_find(
				p_node_pc_parent->id, pc_node_parent);
			q_space->p_node_info->nexthop =
				pc_vertex_parent->nexthop->router;
		} else {
			/*
			 * It can happen that the P node is the root node itself
			 * (hence there can be no parents). In this case we
			 * don't need to set a nexthop.
			 */
			q_space->p_node_info->nexthop.s_addr = INADDR_ANY;
		}

		return OSPF_TI_LFA_P_Q_SPACE_ADJACENT;
	}

	ospf_ti_lfa_find_p_node(pc_node_parent, p_space, q_space);
	return OSPF_TI_LFA_P_Q_SPACE_NON_ADJACENT;
}

static void ospf_ti_lfa_find_q_node(struct vertex *pc_node,
				    struct p_space *p_space,
				    struct q_space *q_space)
{
	struct listnode *curr_node, *next_node;
	struct vertex *p_node, *q_node, *q_space_parent = NULL, *pc_node_parent;
	struct vertex_parent *pc_vertex_parent;

	curr_node = listnode_lookup(q_space->pc_path, pc_node);
	assert(curr_node);
	next_node = curr_node->next;
	pc_node_parent = listgetdata(next_node);
	pc_vertex_parent =
		ospf_spf_vertex_parent_find(pc_node_parent->id, pc_node);

	p_node = ospf_spf_vertex_find(pc_node->id, p_space->vertex_list);
	q_node = ospf_spf_vertex_find(pc_node->id, q_space->vertex_list);

	/* The Q node is always present. */
	assert(q_node);

	q_space->q_node_info->type = OSPF_TI_LFA_UNDEFINED_NODE;

	if (p_node && q_node) {
		q_space->q_node_info->node = pc_node;
		q_space->q_node_info->type = OSPF_TI_LFA_PQ_NODE;
		q_space->q_node_info->nexthop =
			pc_vertex_parent->nexthop->router;
		return;
	}

	/*
	 * Note that the Q space has the 'reverse' direction of the PC
	 * SPF. Hence compare PC SPF parent to Q space children.
	 */
	q_space_parent =
		ospf_spf_vertex_find(pc_node_parent->id, q_node->children);

	/*
	 * If the Q space parent doesn't exist we 'hit' the border to the P
	 * space and hence got our Q node.
	 */
	if (!q_space_parent) {
		q_space->q_node_info->node = pc_node;
		q_space->q_node_info->type = OSPF_TI_LFA_Q_NODE;
		q_space->q_node_info->nexthop =
			pc_vertex_parent->nexthop->router;
		return;
	}

	return ospf_ti_lfa_find_q_node(pc_node_parent, p_space, q_space);
}

static void ospf_ti_lfa_append_label_stack(struct mpls_label_stack *label_stack,
					   mpls_label_t labels[],
					   uint32_t num_labels)
{
	int i, offset, limit;

	limit = label_stack->num_labels + num_labels;
	offset = label_stack->num_labels;

	for (i = label_stack->num_labels; i < limit; i++) {
		label_stack->label[i] = labels[i - offset];
		label_stack->num_labels++;
	}
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
				      + MPLS_MAX_LABELS * sizeof(mpls_label_t));
	label_stack->num_labels = num_labels;

	for (i = 0; i < num_labels; i++)
		label_stack->label[i] = labels[i];

	return label_stack;
}

static struct list *
ospf_ti_lfa_map_path_to_pc_vertices(struct list *path,
				    struct list *pc_vertex_list)
{
	struct listnode *node;
	struct vertex *vertex, *pc_vertex;
	struct list *pc_path;

	pc_path = list_new();

	for (ALL_LIST_ELEMENTS_RO(path, node, vertex)) {
		pc_vertex = ospf_spf_vertex_find(vertex->id, pc_vertex_list);
		listnode_add(pc_path, pc_vertex);
	}

	return pc_path;
}

static struct list *ospf_ti_lfa_cut_out_pc_path(struct list *pc_vertex_list,
						struct list *pc_path,
						struct vertex *p_node,
						struct vertex *q_node)
{
	struct list *inner_pc_path;
	struct vertex *current_vertex;
	struct listnode *current_listnode;

	inner_pc_path = list_new();
	current_vertex = ospf_spf_vertex_find(q_node->id, pc_vertex_list);
	current_listnode = listnode_lookup(pc_path, current_vertex);

	/* Note that the post-convergence paths are reversed. */
	while (current_listnode) {
		current_vertex = listgetdata(current_listnode);
		listnode_add(inner_pc_path, current_vertex);

		if (current_vertex->id.s_addr == p_node->id.s_addr)
			break;

		current_listnode = current_listnode->next;
	}

	return inner_pc_path;
}

static void ospf_ti_lfa_generate_inner_label_stack(
	struct ospf_area *area, struct p_space *p_space,
	struct q_space *q_space,
	struct ospf_ti_lfa_inner_backup_path_info *inner_backup_path_info)
{
	struct route_table *new_table;
	struct vertex *q_node;
	struct vertex *start_vertex, *end_vertex;
	struct vertex_parent *vertex_parent;
	struct listnode *pc_p_node, *pc_q_node;
	struct vertex *spf_orig;
	struct list *vertex_list_orig;
	struct p_spaces_head *p_spaces_orig;
	struct p_space *inner_p_space;
	struct q_space *inner_q_space;
	struct ospf_ti_lfa_node_info *p_node_info, *q_node_info;
	struct protected_resource *protected_resource;
	struct list *inner_pc_path;
	mpls_label_t start_label, end_label;

	p_node_info = q_space->p_node_info;
	q_node_info = q_space->q_node_info;
	protected_resource = p_space->protected_resource;

	start_vertex = p_node_info->node;
	end_vertex = q_node_info->node;

	/*
	 * It can happen that the P node and/or the Q node are the root or
	 * the destination, therefore we need to force one step forward (resp.
	 * backward) using an Adjacency-SID.
	 */
	start_label = MPLS_INVALID_LABEL;
	end_label = MPLS_INVALID_LABEL;
	if (p_node_info->node->id.s_addr == p_space->root->id.s_addr) {
		pc_p_node = listnode_lookup(q_space->pc_path, p_space->pc_spf);
		assert(pc_p_node);
		start_vertex = listgetdata(pc_p_node->prev);
		start_label = ospf_sr_get_adj_sid_by_id(&p_node_info->node->id,
							&start_vertex->id);
	}
	if (q_node_info->node->id.s_addr == q_space->root->id.s_addr) {
		pc_q_node = listnode_lookup(q_space->pc_path,
					    listnode_head(q_space->pc_path));
		assert(pc_q_node);
		end_vertex = listgetdata(pc_q_node->next);
		end_label = ospf_sr_get_adj_sid_by_id(&end_vertex->id,
						      &q_node_info->node->id);
	}

	/* Corner case: inner path is just one node */
	if (start_vertex->id.s_addr == end_vertex->id.s_addr) {
		inner_backup_path_info->label_stack =
			ospf_ti_lfa_create_label_stack(&start_label, 1);
		inner_backup_path_info->q_node_info.node = end_vertex;
		inner_backup_path_info->q_node_info.type = OSPF_TI_LFA_PQ_NODE;
		inner_backup_path_info->p_node_info.type =
			OSPF_TI_LFA_UNDEFINED_NODE;
		vertex_parent = ospf_spf_vertex_parent_find(p_space->root->id,
							    end_vertex);
		inner_backup_path_info->p_node_info.nexthop =
			vertex_parent->nexthop->router;
		return;
	}

	inner_pc_path = ospf_ti_lfa_cut_out_pc_path(p_space->pc_vertex_list,
						    q_space->pc_path,
						    start_vertex, end_vertex);

	new_table = route_table_init();

	/* Copy the current state ... */
	spf_orig = area->spf;
	vertex_list_orig = area->spf_vertex_list;
	p_spaces_orig = area->p_spaces;

	area->p_spaces =
		XCALLOC(MTYPE_OSPF_P_SPACE, sizeof(struct p_spaces_head));

	/* dry run true, root node false */
	ospf_spf_calculate(area, start_vertex->lsa_p, new_table, NULL, NULL,
			   true, false);

	q_node = ospf_spf_vertex_find(end_vertex->id, area->spf_vertex_list);

	ospf_ti_lfa_generate_p_space(area, q_node, protected_resource, false,
				     inner_pc_path);

	/* There's just one P and Q space */
	inner_p_space = p_spaces_pop(area->p_spaces);
	inner_q_space = q_spaces_pop(inner_p_space->q_spaces);

	/* Copy over inner backup path information from the inner q_space */

	/* In case the outer P node is also the root of the P space */
	if (start_label != MPLS_INVALID_LABEL) {
		inner_backup_path_info->label_stack =
			ospf_ti_lfa_create_label_stack(&start_label, 1);
		ospf_ti_lfa_append_label_stack(
			inner_backup_path_info->label_stack,
			inner_q_space->label_stack->label,
			inner_q_space->label_stack->num_labels);
		inner_backup_path_info->p_node_info.node = start_vertex;
		inner_backup_path_info->p_node_info.type = OSPF_TI_LFA_P_NODE;
		vertex_parent = ospf_spf_vertex_parent_find(p_space->root->id,
							    start_vertex);
		inner_backup_path_info->p_node_info.nexthop =
			vertex_parent->nexthop->router;
	} else {
		memcpy(inner_backup_path_info->label_stack,
		       inner_q_space->label_stack,
		       sizeof(struct mpls_label_stack)
			       + sizeof(mpls_label_t)
					 * inner_q_space->label_stack
						   ->num_labels);
		memcpy(&inner_backup_path_info->p_node_info,
		       inner_q_space->p_node_info,
		       sizeof(struct ospf_ti_lfa_node_info));
	}

	/* In case the outer Q node is also the root of the Q space */
	if (end_label != MPLS_INVALID_LABEL) {
		inner_backup_path_info->q_node_info.node = end_vertex;
		inner_backup_path_info->q_node_info.type = OSPF_TI_LFA_Q_NODE;
	} else {
		memcpy(&inner_backup_path_info->q_node_info,
		       inner_q_space->q_node_info,
		       sizeof(struct ospf_ti_lfa_node_info));
	}

	/* Cleanup */
	ospf_ti_lfa_free_p_spaces(area);
	ospf_spf_cleanup(area->spf, area->spf_vertex_list);

	/* ... and copy the current state back. */
	area->spf = spf_orig;
	area->spf_vertex_list = vertex_list_orig;
	area->p_spaces = p_spaces_orig;
}

static void ospf_ti_lfa_generate_label_stack(struct ospf_area *area,
					     struct p_space *p_space,
					     struct q_space *q_space)
{
	enum ospf_ti_lfa_p_q_space_adjacency adjacency_result;
	mpls_label_t labels[MPLS_MAX_LABELS];
	struct vertex *pc_node;
	struct ospf_ti_lfa_inner_backup_path_info inner_backup_path_info;

	if (IS_DEBUG_OSPF_TI_LFA)
		zlog_debug(
			"%s: Generating Label stack for src %pI4 and dest %pI4.",
			__func__, &p_space->root->id, &q_space->root->id);

	pc_node = listnode_head(q_space->pc_path);

	if (!pc_node) {
		if (IS_DEBUG_OSPF_TI_LFA)
			zlog_debug(
				"%s: There seems to be no post convergence path (yet).",
				__func__);
		return;
	}

	ospf_ti_lfa_find_q_node(pc_node, p_space, q_space);
	if (q_space->q_node_info->type == OSPF_TI_LFA_UNDEFINED_NODE) {
		if (IS_DEBUG_OSPF_TI_LFA)
			zlog_debug("%s: Q node not found!", __func__);
		return;
	}

	/* Found a PQ node? Then we are done here. */
	if (q_space->q_node_info->type == OSPF_TI_LFA_PQ_NODE) {
		/*
		 * If the PQ node is a child of the root, then we can use an
		 * adjacency SID instead of a prefix SID for the backup path.
		 */
		if (ospf_spf_vertex_parent_find(p_space->root->id,
						q_space->q_node_info->node))
			labels[0] = ospf_sr_get_adj_sid_by_id(
				&p_space->root->id,
				&q_space->q_node_info->node->id);
		else
			labels[0] = ospf_sr_get_prefix_sid_by_id(
				&q_space->q_node_info->node->id);

		q_space->label_stack =
			ospf_ti_lfa_create_label_stack(labels, 1);
		q_space->nexthop = q_space->q_node_info->nexthop;

		return;
	}

	/* Otherwise find a (hopefully adjacent) P node. */
	pc_node = ospf_spf_vertex_find(q_space->q_node_info->node->id,
				       p_space->pc_vertex_list);
	adjacency_result = ospf_ti_lfa_find_p_node(pc_node, p_space, q_space);

	if (q_space->p_node_info->type == OSPF_TI_LFA_UNDEFINED_NODE) {
		if (IS_DEBUG_OSPF_TI_LFA)
			zlog_debug("%s: P node not found!", __func__);
		return;
	}

	/*
	 * This should be the regular case: P and Q space are adjacent or even
	 * overlapping. This is guaranteed for link protection when used with
	 * symmetric weights.
	 */
	if (adjacency_result == OSPF_TI_LFA_P_Q_SPACE_ADJACENT) {
		/*
		 * It can happen that the P node is the root itself, therefore
		 * we don't need a label for it. So just one adjacency SID for
		 * the Q node.
		 */
		if (q_space->p_node_info->node->id.s_addr
		    == p_space->root->id.s_addr) {
			labels[0] = ospf_sr_get_adj_sid_by_id(
				&p_space->root->id,
				&q_space->q_node_info->node->id);
			q_space->label_stack =
				ospf_ti_lfa_create_label_stack(labels, 1);
			q_space->nexthop = q_space->q_node_info->nexthop;
			return;
		}

		/*
		 * Otherwise we have a P and also a Q node (which are adjacent).
		 *
		 * It can happen that the P node is a child of the root,
		 * therefore we might just need the adjacency SID for the P node
		 * instead of the prefix SID. For the Q node always take the
		 * adjacency SID.
		 */
		if (ospf_spf_vertex_parent_find(p_space->root->id,
						q_space->p_node_info->node))
			labels[0] = ospf_sr_get_adj_sid_by_id(
				&p_space->root->id,
				&q_space->p_node_info->node->id);
		else
			labels[0] = ospf_sr_get_prefix_sid_by_id(
				&q_space->p_node_info->node->id);

		labels[1] = ospf_sr_get_adj_sid_by_id(
			&q_space->p_node_info->node->id,
			&q_space->q_node_info->node->id);

		q_space->label_stack =
			ospf_ti_lfa_create_label_stack(labels, 2);
		q_space->nexthop = q_space->p_node_info->nexthop;

	} else {
		/*
		 * It can happen that the P and Q space are not adjacent when
		 * e.g. node protection or asymmetric weights are used. In this
		 * case the found P and Q nodes are used as a reference for
		 * another run of the algorithm!
		 *
		 * After having found the inner label stack it is stitched
		 * together with the outer labels.
		 */
		inner_backup_path_info.label_stack = XCALLOC(
			MTYPE_OSPF_PATH,
			sizeof(struct mpls_label_stack)
				+ sizeof(mpls_label_t) * MPLS_MAX_LABELS);
		ospf_ti_lfa_generate_inner_label_stack(area, p_space, q_space,
						       &inner_backup_path_info);

		/*
		 * First stitch together the outer P node label with the inner
		 * label stack.
		 */
		if (q_space->p_node_info->node->id.s_addr
		    == p_space->root->id.s_addr) {
			/*
			 * It can happen that the P node is the root itself,
			 * therefore we don't need a label for it. Just take
			 * the inner label stack first.
			 */
			q_space->label_stack = ospf_ti_lfa_create_label_stack(
				inner_backup_path_info.label_stack->label,
				inner_backup_path_info.label_stack->num_labels);

			/* Use the inner P or Q node for the nexthop */
			if (inner_backup_path_info.p_node_info.type
			    != OSPF_TI_LFA_UNDEFINED_NODE)
				q_space->nexthop = inner_backup_path_info
							   .p_node_info.nexthop;
			else
				q_space->nexthop = inner_backup_path_info
							   .q_node_info.nexthop;

		} else if (ospf_spf_vertex_parent_find(
				   p_space->root->id,
				   q_space->p_node_info->node)) {
			/*
			 * It can happen that the outer P node is a child of
			 * the root, therefore we might just need the
			 * adjacency SID for the outer P node instead of the
			 * prefix SID. Then just append the inner label stack.
			 */
			labels[0] = ospf_sr_get_adj_sid_by_id(
				&p_space->root->id,
				&q_space->p_node_info->node->id);
			q_space->label_stack =
				ospf_ti_lfa_create_label_stack(labels, 1);
			ospf_ti_lfa_append_label_stack(
				q_space->label_stack,
				inner_backup_path_info.label_stack->label,
				inner_backup_path_info.label_stack->num_labels);
			q_space->nexthop = q_space->p_node_info->nexthop;
		} else {
			/* The outer P node needs a Prefix-SID here */
			labels[0] = ospf_sr_get_prefix_sid_by_id(
				&q_space->p_node_info->node->id);
			q_space->label_stack =
				ospf_ti_lfa_create_label_stack(labels, 1);
			ospf_ti_lfa_append_label_stack(
				q_space->label_stack,
				inner_backup_path_info.label_stack->label,
				inner_backup_path_info.label_stack->num_labels);
			q_space->nexthop = q_space->p_node_info->nexthop;
		}

		/* Now the outer Q node needs to be considered */
		if (ospf_spf_vertex_parent_find(
			    inner_backup_path_info.q_node_info.node->id,
			    q_space->q_node_info->node)) {
			/*
			 * The outer Q node can be a child of the inner Q node,
			 * hence just add an Adjacency-SID.
			 */
			labels[0] = ospf_sr_get_adj_sid_by_id(
				&inner_backup_path_info.q_node_info.node->id,
				&q_space->q_node_info->node->id);
			ospf_ti_lfa_append_label_stack(q_space->label_stack,
						       labels, 1);
		} else {
			/* Otherwise a Prefix-SID is needed */
			labels[0] = ospf_sr_get_prefix_sid_by_id(
				&q_space->q_node_info->node->id);
			ospf_ti_lfa_append_label_stack(q_space->label_stack,
						       labels, 1);
		}
		/*
		 * Note that there's also the case where the inner and outer Q
		 * node are the same, but then there's nothing to do!
		 */
	}
}

static struct list *
ospf_ti_lfa_generate_post_convergence_path(struct list *pc_vertex_list,
					   struct vertex *dest)
{
	struct list *pc_path;
	struct vertex *current_vertex;
	struct vertex_parent *parent;

	current_vertex = ospf_spf_vertex_find(dest->id, pc_vertex_list);
	if (!current_vertex) {
		if (IS_DEBUG_OSPF_TI_LFA)
			zlog_debug(
				"%s: There seems to be no post convergence path (yet).",
				__func__);
		return NULL;
	}

	pc_path = list_new();
	listnode_add(pc_path, current_vertex);

	/* Generate a backup path in reverse order */
	for (;;) {
		parent = listnode_head(current_vertex->parents);
		if (!parent)
			break;

		listnode_add(pc_path, parent->parent);
		current_vertex = parent->parent;
	}

	return pc_path;
}

static void ospf_ti_lfa_generate_q_spaces(struct ospf_area *area,
					  struct p_space *p_space,
					  struct vertex *dest, bool recursive,
					  struct list *pc_path)
{
	struct listnode *node;
	struct vertex *child;
	struct route_table *new_table;
	struct q_space *q_space, q_space_search;
	char label_buf[MPLS_LABEL_STRLEN];
	char res_buf[PROTECTED_RESOURCE_STRLEN];
	bool node_protected;

	ospf_print_protected_resource(p_space->protected_resource, res_buf);
	node_protected =
		p_space->protected_resource->type == OSPF_TI_LFA_NODE_PROTECTION
		&& dest->id.s_addr
			   == p_space->protected_resource->router_id.s_addr;

	/*
	 * If node protection is used, don't build a Q space for the protected
	 * node of that particular P space. Move on with children instead.
	 */
	if (node_protected) {
		if (recursive) {
			/* Recursively generate Q spaces for all children */
			for (ALL_LIST_ELEMENTS_RO(dest->children, node, child))
				ospf_ti_lfa_generate_q_spaces(area, p_space,
							      child, recursive,
							      pc_path);
		}
		return;
	}

	/* Check if we already have a Q space for this destination */
	q_space_search.root = dest;
	if (q_spaces_find(p_space->q_spaces, &q_space_search))
		return;

	q_space = XCALLOC(MTYPE_OSPF_Q_SPACE, sizeof(struct q_space));
	q_space->p_node_info = XCALLOC(MTYPE_OSPF_Q_SPACE,
				       sizeof(struct ospf_ti_lfa_node_info));
	q_space->q_node_info = XCALLOC(MTYPE_OSPF_Q_SPACE,
				       sizeof(struct ospf_ti_lfa_node_info));

	new_table = route_table_init();

	/*
	 * Generate a new (reversed!) SPF tree for this vertex,
	 * dry run true, root node false
	 */
	area->spf_reversed = true;
	ospf_spf_calculate(area, dest->lsa_p, new_table, NULL, NULL, true,
			   false);

	/* Reset the flag for reverse SPF */
	area->spf_reversed = false;

	q_space->root = area->spf;
	q_space->vertex_list = area->spf_vertex_list;
	q_space->label_stack = NULL;

	if (pc_path)
		q_space->pc_path = ospf_ti_lfa_map_path_to_pc_vertices(
			pc_path, p_space->pc_vertex_list);
	else
		q_space->pc_path = ospf_ti_lfa_generate_post_convergence_path(
			p_space->pc_vertex_list, q_space->root);

	/* If there's no backup path available then we are done here. */
	if (!q_space->pc_path) {
		zlog_info(
			"%s: NO backup path found for root %pI4 and destination %pI4 for %s, aborting ...",
			__func__, &p_space->root->id, &q_space->root->id,
			res_buf);

		list_delete(&q_space->vertex_list);
		XFREE(MTYPE_OSPF_Q_SPACE, q_space->p_node_info);
		XFREE(MTYPE_OSPF_Q_SPACE, q_space->q_node_info);
		XFREE(MTYPE_OSPF_Q_SPACE, q_space);

		return;
	}

	/* 'Cut' the protected resource out of the new SPF tree */
	ospf_spf_remove_resource(q_space->root, q_space->vertex_list,
				 p_space->protected_resource);

	/*
	 * Generate the smallest possible label stack from the root of the P
	 * space to the root of the Q space.
	 */
	ospf_ti_lfa_generate_label_stack(area, p_space, q_space);

	if (q_space->label_stack) {
		mpls_label2str(q_space->label_stack->num_labels,
			       q_space->label_stack->label, label_buf,
			       MPLS_LABEL_STRLEN, 0, true);
		zlog_info(
			"%s: Generated label stack %s for root %pI4 and destination %pI4 for %s",
			__func__, label_buf, &p_space->root->id,
			&q_space->root->id, res_buf);
	} else {
		zlog_info(
			"%s: NO label stack generated for root %pI4 and destination %pI4 for %s",
			__func__, &p_space->root->id, &q_space->root->id,
			res_buf);
	}

	/* We are finished, store the new Q space in the P space struct */
	q_spaces_add(p_space->q_spaces, q_space);

	/* Recursively generate Q spaces for all children */
	if (recursive) {
		for (ALL_LIST_ELEMENTS_RO(dest->children, node, child))
			ospf_ti_lfa_generate_q_spaces(area, p_space, child,
						      recursive, pc_path);
	}
}

static void ospf_ti_lfa_generate_post_convergence_spf(struct ospf_area *area,
						      struct p_space *p_space)
{
	struct route_table *new_table;

	new_table = route_table_init();

	area->spf_protected_resource = p_space->protected_resource;

	/*
	 * The 'post convergence' SPF tree is generated here
	 * dry run true, root node false
	 *
	 * So how does this work? During the SPF calculation the algorithm
	 * checks if a link belongs to a protected resource and then just
	 * ignores it.
	 * This is actually _NOT_ a good way to calculate the post
	 * convergence SPF tree. The preferred way would be to delete the
	 * relevant links (and nodes) from a copy of the LSDB and then just run
	 * the SPF algorithm on that as usual.
	 * However, removing links from router LSAs appears to be its own
	 * endeavour (because LSAs are stored as a 'raw' stream), so we go with
	 * this rather hacky way for now.
	 */
	ospf_spf_calculate(area, area->router_lsa_self, new_table, NULL, NULL,
			   true, false);

	p_space->pc_spf = area->spf;
	p_space->pc_vertex_list = area->spf_vertex_list;

	area->spf_protected_resource = NULL;
}

static void
ospf_ti_lfa_generate_p_space(struct ospf_area *area, struct vertex *child,
			     struct protected_resource *protected_resource,
			     bool recursive, struct list *pc_path)
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
	p_space->protected_resource = protected_resource;

	/* Initialize the Q spaces for this P space and protected resource */
	p_space->q_spaces =
		XCALLOC(MTYPE_OSPF_Q_SPACE, sizeof(struct q_spaces_head));
	q_spaces_init(p_space->q_spaces);

	/* 'Cut' the protected resource out of the new SPF tree */
	ospf_spf_remove_resource(p_space->root, p_space->vertex_list,
				 p_space->protected_resource);

	/*
	 * Since we are going to calculate more SPF trees for Q spaces, keep the
	 * 'original' one here temporarily
	 */
	spf_orig = area->spf;
	vertex_list_orig = area->spf_vertex_list;

	/* Generate the post convergence SPF as a blueprint for backup paths */
	ospf_ti_lfa_generate_post_convergence_spf(area, p_space);

	/* Generate the relevant Q spaces for this particular P space */
	ospf_ti_lfa_generate_q_spaces(area, p_space, child, recursive, pc_path);

	/* Put the 'original' SPF tree back in place */
	area->spf = spf_orig;
	area->spf_vertex_list = vertex_list_orig;

	/* We are finished, store the new P space */
	p_spaces_add(area->p_spaces, p_space);
}

void ospf_ti_lfa_generate_p_spaces(struct ospf_area *area,
				   enum protection_type protection_type)
{
	struct listnode *node, *inner_node;
	struct vertex *root, *child;
	struct vertex_parent *vertex_parent;
	uint8_t *p, *lim;
	struct router_lsa_link *l = NULL;
	struct prefix stub_prefix, child_prefix;
	struct protected_resource *protected_resource;

	area->p_spaces =
		XCALLOC(MTYPE_OSPF_P_SPACE, sizeof(struct p_spaces_head));
	p_spaces_init(area->p_spaces);

	root = area->spf;

	/* Root or its router LSA was not created yet? */
	if (!root || !root->lsa)
		return;

	stub_prefix.family = AF_INET;
	child_prefix.family = AF_INET;
	child_prefix.prefixlen = IPV4_MAX_BITLEN;

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

		/* First comes node protection */
		if (protection_type == OSPF_TI_LFA_NODE_PROTECTION) {
			if (l->m[0].type == LSA_LINK_TYPE_POINTOPOINT) {
				protected_resource = XCALLOC(
					MTYPE_OSPF_P_SPACE,
					sizeof(struct protected_resource));
				protected_resource->type = protection_type;
				protected_resource->router_id = l->link_id;
				child = ospf_spf_vertex_find(
					protected_resource->router_id,
					root->children);
				if (child)
					ospf_ti_lfa_generate_p_space(
						area, child, protected_resource,
						true, NULL);
			}

			continue;
		}

		/* The rest is about link protection */
		if (protection_type != OSPF_TI_LFA_LINK_PROTECTION)
			continue;

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

					protected_resource = XCALLOC(
						MTYPE_OSPF_P_SPACE,
						sizeof(struct
						       protected_resource));
					protected_resource->type =
						protection_type;
					protected_resource->link = l;

					ospf_ti_lfa_generate_p_space(
						area, child, protected_resource,
						true, NULL);
				}
			}
		}
	}
}

static struct p_space *ospf_ti_lfa_get_p_space_by_path(struct ospf_area *area,
						       struct ospf_path *path)
{
	struct p_space *p_space;
	struct router_lsa_link *link;
	struct vertex *child;
	int type;

	frr_each(p_spaces, area->p_spaces, p_space) {
		type = p_space->protected_resource->type;

		if (type == OSPF_TI_LFA_LINK_PROTECTION) {
			link = p_space->protected_resource->link;
			if ((path->nexthop.s_addr & link->link_data.s_addr)
			    == (link->link_id.s_addr & link->link_data.s_addr))
				return p_space;
		}

		if (type == OSPF_TI_LFA_NODE_PROTECTION) {
			child = ospf_spf_vertex_by_nexthop(area->spf,
							   &path->nexthop);
			if (child
			    && p_space->protected_resource->router_id.s_addr
				       == child->id.s_addr)
				return p_space;
		}
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
	char label_buf[MPLS_LABEL_STRLEN];

	for (rn = route_top(new_table); rn; rn = route_next(rn)) {
		or = rn->info;
		if (or == NULL)
			continue;

		/* Insert a backup path for all OSPF paths */
		for (ALL_LIST_ELEMENTS_RO(or->paths, node, path)) {

			if (path->adv_router.s_addr == INADDR_ANY
			    || path->nexthop.s_addr == INADDR_ANY)
				continue;

			if (IS_DEBUG_OSPF_TI_LFA)
				zlog_debug(
					"%s: attempting to insert backup path for prefix %pFX, router id %pI4 and nexthop %pI4.",
					__func__, &rn->p, &path->adv_router,
					&path->nexthop);

			p_space = ospf_ti_lfa_get_p_space_by_path(area, path);
			if (!p_space) {
				if (IS_DEBUG_OSPF_TI_LFA)
					zlog_debug(
						"%s: P space not found for router id %pI4 and nexthop %pI4.",
						__func__, &path->adv_router,
						&path->nexthop);
				continue;
			}

			root_search.id = path->adv_router;
			q_space_search.root = &root_search;
			q_space = q_spaces_find(p_space->q_spaces,
						&q_space_search);
			if (!q_space) {
				if (IS_DEBUG_OSPF_TI_LFA)
					zlog_debug(
						"%s: Q space not found for advertising router %pI4.",
						__func__, &path->adv_router);
				continue;
			}

			/* If there's a backup label stack, insert it*/
			if (q_space->label_stack) {
				/* Init the backup path data in path */
				path->srni.backup_label_stack = XCALLOC(
					MTYPE_OSPF_PATH,
					sizeof(struct mpls_label_stack)
						+ sizeof(mpls_label_t)
							  * q_space->label_stack
								    ->num_labels);

				/* Copy over the label stack */
				path->srni.backup_label_stack->num_labels =
					q_space->label_stack->num_labels;
				memcpy(path->srni.backup_label_stack->label,
				       q_space->label_stack->label,
				       sizeof(mpls_label_t)
					       * q_space->label_stack
							 ->num_labels);

				/* Set the backup nexthop too */
				path->srni.backup_nexthop = q_space->nexthop;
			}

			if (path->srni.backup_label_stack) {
				mpls_label2str(
					path->srni.backup_label_stack
						->num_labels,
					path->srni.backup_label_stack->label,
					label_buf, MPLS_LABEL_STRLEN, 0, true);
				if (IS_DEBUG_OSPF_TI_LFA)
					zlog_debug(
						"%s: inserted backup path %s for prefix %pFX, router id %pI4 and nexthop %pI4.",
						__func__, label_buf, &rn->p,
						&path->adv_router,
						&path->nexthop);
			} else {
				if (IS_DEBUG_OSPF_TI_LFA)
					zlog_debug(
						"%s: inserted NO backup path for prefix %pFX, router id %pI4 and nexthop %pI4.",
						__func__, &rn->p,
						&path->adv_router,
						&path->nexthop);
			}
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

			if (q_space->pc_path)
				list_delete(&q_space->pc_path);

			XFREE(MTYPE_OSPF_Q_SPACE, q_space->p_node_info);
			XFREE(MTYPE_OSPF_Q_SPACE, q_space->q_node_info);
			XFREE(MTYPE_OSPF_Q_SPACE, q_space->label_stack);
			XFREE(MTYPE_OSPF_Q_SPACE, q_space);
		}

		ospf_spf_cleanup(p_space->root, p_space->vertex_list);
		ospf_spf_cleanup(p_space->pc_spf, p_space->pc_vertex_list);
		XFREE(MTYPE_OSPF_P_SPACE, p_space->protected_resource);

		q_spaces_fini(p_space->q_spaces);
		XFREE(MTYPE_OSPF_Q_SPACE, p_space->q_spaces);
		XFREE(MTYPE_OSPF_P_SPACE, p_space);
	}

	p_spaces_fini(area->p_spaces);
	XFREE(MTYPE_OSPF_P_SPACE, area->p_spaces);
}

void ospf_ti_lfa_compute(struct ospf_area *area, struct route_table *new_table,
			 enum protection_type protection_type)
{
	/*
	 * Generate P spaces per protected link/node and their respective Q
	 * spaces, generate backup paths (MPLS label stacks) by finding P/Q
	 * nodes.
	 */
	ospf_ti_lfa_generate_p_spaces(area, protection_type);

	/* Insert the generated backup paths into the routing table. */
	ospf_ti_lfa_insert_backup_paths(area, new_table);

	/* Cleanup P spaces and related datastructures including Q spaces. */
	ospf_ti_lfa_free_p_spaces(area);
}
