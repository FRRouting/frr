/* OSPF SPF calculation.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#include "monotime.h"
#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "log.h"
#include "sockunion.h" /* for inet_ntop () */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ti_lfa.h"
#include "ospfd/ospf_errors.h"

#ifdef SUPPORT_OSPF_API
#include "ospfd/ospf_apiserver.h"
#endif

/* Variables to ensure a SPF scheduled log message is printed only once */

static unsigned int spf_reason_flags = 0;

/* dummy vertex to flag "in spftree" */
static const struct vertex vertex_in_spftree = {};
#define LSA_SPF_IN_SPFTREE	(struct vertex *)&vertex_in_spftree
#define LSA_SPF_NOT_EXPLORED	NULL

static void ospf_clear_spf_reason_flags(void)
{
	spf_reason_flags = 0;
}

static void ospf_spf_set_reason(ospf_spf_reason_t reason)
{
	spf_reason_flags |= 1 << reason;
}

static void ospf_vertex_free(void *);

/*
 * Heap related functions, for the managment of the candidates, to
 * be used with pqueue.
 */
static int vertex_cmp(const struct vertex *v1, const struct vertex *v2)
{
	if (v1->distance != v2->distance)
		return v1->distance - v2->distance;

	if (v1->type != v2->type) {
		switch (v1->type) {
		case OSPF_VERTEX_NETWORK:
			return -1;
		case OSPF_VERTEX_ROUTER:
			return 1;
		}
	}
	return 0;
}
DECLARE_SKIPLIST_NONUNIQ(vertex_pqueue, struct vertex, pqi, vertex_cmp);

static void lsdb_clean_stat(struct ospf_lsdb *lsdb)
{
	struct route_table *table;
	struct route_node *rn;
	struct ospf_lsa *lsa;
	int i;

	for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
		table = lsdb->type[i].db;
		for (rn = route_top(table); rn; rn = route_next(rn))
			if ((lsa = (rn->info)) != NULL)
				lsa->stat = LSA_SPF_NOT_EXPLORED;
	}
}

static struct vertex_nexthop *vertex_nexthop_new(void)
{
	return XCALLOC(MTYPE_OSPF_NEXTHOP, sizeof(struct vertex_nexthop));
}

static void vertex_nexthop_free(struct vertex_nexthop *nh)
{
	XFREE(MTYPE_OSPF_NEXTHOP, nh);
}

/*
 * Free the canonical nexthop objects for an area, ie the nexthop objects
 * attached to the first-hop router vertices, and any intervening network
 * vertices.
 */
static void ospf_canonical_nexthops_free(struct vertex *root)
{
	struct listnode *node, *nnode;
	struct vertex *child;

	for (ALL_LIST_ELEMENTS(root->children, node, nnode, child)) {
		struct listnode *n2, *nn2;
		struct vertex_parent *vp;

		/*
		 * router vertices through an attached network each
		 * have a distinct (canonical / not inherited) nexthop
		 * which must be freed.
		 *
		 * A network vertex can only have router vertices as its
		 * children, so only one level of recursion is possible.
		 */
		if (child->type == OSPF_VERTEX_NETWORK)
			ospf_canonical_nexthops_free(child);

		/* Free child nexthops pointing back to this root vertex */
		for (ALL_LIST_ELEMENTS(child->parents, n2, nn2, vp)) {
			if (vp->parent == root && vp->nexthop) {
				vertex_nexthop_free(vp->nexthop);
				vp->nexthop = NULL;
				if (vp->local_nexthop) {
					vertex_nexthop_free(vp->local_nexthop);
					vp->local_nexthop = NULL;
				}
			}
		}
	}
}

/*
 * TODO: Parent list should be excised, in favour of maintaining only
 * vertex_nexthop, with refcounts.
 */
static struct vertex_parent *vertex_parent_new(struct vertex *v, int backlink,
					       struct vertex_nexthop *hop,
					       struct vertex_nexthop *lhop)
{
	struct vertex_parent *new;

	new = XMALLOC(MTYPE_OSPF_VERTEX_PARENT, sizeof(struct vertex_parent));

	new->parent = v;
	new->backlink = backlink;
	new->nexthop = hop;
	new->local_nexthop = lhop;

	return new;
}

static void vertex_parent_free(struct vertex_parent *p)
{
	vertex_nexthop_free(p->local_nexthop);
	vertex_nexthop_free(p->nexthop);
	XFREE(MTYPE_OSPF_VERTEX_PARENT, p);
}

int vertex_parent_cmp(void *aa, void *bb)
{
	struct vertex_parent *a = aa, *b = bb;
	return IPV4_ADDR_CMP(&a->nexthop->router, &b->nexthop->router);
}

static struct vertex *ospf_vertex_new(struct ospf_area *area,
				      struct ospf_lsa *lsa)
{
	struct vertex *new;

	new = XCALLOC(MTYPE_OSPF_VERTEX, sizeof(struct vertex));

	new->flags = 0;
	new->type = lsa->data->type;
	new->id = lsa->data->id;
	new->lsa = lsa->data;
	new->children = list_new();
	new->parents = list_new();
	new->parents->del = (void (*)(void *))vertex_parent_free;
	new->parents->cmp = vertex_parent_cmp;
	new->lsa_p = lsa;

	lsa->stat = new;

	listnode_add(area->spf_vertex_list, new);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Created %s vertex %pI4", __func__,
			   new->type == OSPF_VERTEX_ROUTER ? "Router"
							   : "Network",
			   &new->lsa->id);

	return new;
}

static void ospf_vertex_free(void *data)
{
	struct vertex *v = data;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Free %s vertex %pI4", __func__,
			   v->type == OSPF_VERTEX_ROUTER ? "Router" : "Network",
			   &v->lsa->id);

	if (v->children)
		list_delete(&v->children);

	if (v->parents)
		list_delete(&v->parents);

	v->lsa = NULL;

	XFREE(MTYPE_OSPF_VERTEX, v);
}

static void ospf_vertex_dump(const char *msg, struct vertex *v,
			     int print_parents, int print_children)
{
	if (!IS_DEBUG_OSPF_EVENT)
		return;

	zlog_debug("%s %s vertex %pI4  distance %u flags %u", msg,
		   v->type == OSPF_VERTEX_ROUTER ? "Router" : "Network",
		   &v->lsa->id, v->distance, (unsigned int)v->flags);

	if (print_parents) {
		struct listnode *node;
		struct vertex_parent *vp;

		for (ALL_LIST_ELEMENTS_RO(v->parents, node, vp)) {
			if (vp) {
				zlog_debug(
					"parent %pI4 backlink %d nexthop %pI4 lsa pos %d",
					&vp->parent->lsa->id, vp->backlink,
					&vp->nexthop->router,
					vp->nexthop->lsa_pos);
			}
		}
	}

	if (print_children) {
		struct listnode *cnode;
		struct vertex *cv;

		for (ALL_LIST_ELEMENTS_RO(v->children, cnode, cv))
			ospf_vertex_dump(" child:", cv, 0, 0);
	}
}


/* Add a vertex to the list of children in each of its parents. */
static void ospf_vertex_add_parent(struct vertex *v)
{
	struct vertex_parent *vp;
	struct listnode *node;

	assert(v && v->parents);

	for (ALL_LIST_ELEMENTS_RO(v->parents, node, vp)) {
		assert(vp->parent && vp->parent->children);

		/* No need to add two links from the same parent. */
		if (listnode_lookup(vp->parent->children, v) == NULL)
			listnode_add(vp->parent->children, v);
	}
}

/* Find a vertex according to its router id */
struct vertex *ospf_spf_vertex_find(struct in_addr id, struct list *vertex_list)
{
	struct listnode *node;
	struct vertex *found;

	for (ALL_LIST_ELEMENTS_RO(vertex_list, node, found)) {
		if (found->id.s_addr == id.s_addr)
			return found;
	}

	return NULL;
}

/* Find a vertex parent according to its router id */
struct vertex_parent *ospf_spf_vertex_parent_find(struct in_addr id,
						  struct vertex *vertex)
{
	struct listnode *node;
	struct vertex_parent *found;

	for (ALL_LIST_ELEMENTS_RO(vertex->parents, node, found)) {
		if (found->parent->id.s_addr == id.s_addr)
			return found;
	}

	return NULL;
}

struct vertex *ospf_spf_vertex_by_nexthop(struct vertex *root,
					  struct in_addr *nexthop)
{
	struct listnode *node;
	struct vertex *child;
	struct vertex_parent *vertex_parent;

	for (ALL_LIST_ELEMENTS_RO(root->children, node, child)) {
		vertex_parent = ospf_spf_vertex_parent_find(root->id, child);
		if (vertex_parent->nexthop->router.s_addr == nexthop->s_addr)
			return child;
	}

	return NULL;
}

/* Create a deep copy of a SPF vertex without children and parents */
static struct vertex *ospf_spf_vertex_copy(struct vertex *vertex)
{
	struct vertex *copy;

	copy = XCALLOC(MTYPE_OSPF_VERTEX, sizeof(struct vertex));

	memcpy(copy, vertex, sizeof(struct vertex));
	copy->parents = list_new();
	copy->parents->del = (void (*)(void *))vertex_parent_free;
	copy->parents->cmp = vertex_parent_cmp;
	copy->children = list_new();

	return copy;
}

/* Create a deep copy of a SPF vertex_parent */
static struct vertex_parent *
ospf_spf_vertex_parent_copy(struct vertex_parent *vertex_parent)
{
	struct vertex_parent *vertex_parent_copy;
	struct vertex_nexthop *nexthop_copy, *local_nexthop_copy;

	vertex_parent_copy =
		XCALLOC(MTYPE_OSPF_VERTEX, sizeof(struct vertex_parent));

	nexthop_copy = vertex_nexthop_new();
	local_nexthop_copy = vertex_nexthop_new();

	memcpy(vertex_parent_copy, vertex_parent, sizeof(struct vertex_parent));
	memcpy(nexthop_copy, vertex_parent->nexthop,
	       sizeof(struct vertex_nexthop));
	memcpy(local_nexthop_copy, vertex_parent->local_nexthop,
	       sizeof(struct vertex_nexthop));

	vertex_parent_copy->nexthop = nexthop_copy;
	vertex_parent_copy->local_nexthop = local_nexthop_copy;

	return vertex_parent_copy;
}

/* Create a deep copy of a SPF tree */
void ospf_spf_copy(struct vertex *vertex, struct list *vertex_list)
{
	struct listnode *node;
	struct vertex *vertex_copy, *child, *child_copy, *parent_copy;
	struct vertex_parent *vertex_parent, *vertex_parent_copy;

	/* First check if the node is already in the vertex list */
	vertex_copy = ospf_spf_vertex_find(vertex->id, vertex_list);
	if (!vertex_copy) {
		vertex_copy = ospf_spf_vertex_copy(vertex);
		listnode_add(vertex_list, vertex_copy);
	}

	/* Copy all parents, create parent nodes if necessary */
	for (ALL_LIST_ELEMENTS_RO(vertex->parents, node, vertex_parent)) {
		parent_copy = ospf_spf_vertex_find(vertex_parent->parent->id,
						   vertex_list);
		if (!parent_copy) {
			parent_copy =
				ospf_spf_vertex_copy(vertex_parent->parent);
			listnode_add(vertex_list, parent_copy);
		}
		vertex_parent_copy = ospf_spf_vertex_parent_copy(vertex_parent);
		vertex_parent_copy->parent = parent_copy;
		listnode_add(vertex_copy->parents, vertex_parent_copy);
	}

	/* Copy all children, create child nodes if necessary */
	for (ALL_LIST_ELEMENTS_RO(vertex->children, node, child)) {
		child_copy = ospf_spf_vertex_find(child->id, vertex_list);
		if (!child_copy) {
			child_copy = ospf_spf_vertex_copy(child);
			listnode_add(vertex_list, child_copy);
		}
		listnode_add(vertex_copy->children, child_copy);
	}

	/* Finally continue copying with child nodes */
	for (ALL_LIST_ELEMENTS_RO(vertex->children, node, child))
		ospf_spf_copy(child, vertex_list);
}

static void ospf_spf_remove_branch(struct vertex_parent *vertex_parent,
				   struct vertex *child,
				   struct list *vertex_list)
{
	struct listnode *node, *nnode, *inner_node, *inner_nnode;
	struct vertex *grandchild;
	struct vertex_parent *vertex_parent_found;
	bool has_more_links = false;

	/*
	 * First check if there are more nexthops for that parent to that child
	 */
	for (ALL_LIST_ELEMENTS_RO(child->parents, node, vertex_parent_found)) {
		if (vertex_parent_found->parent->id.s_addr
			    == vertex_parent->parent->id.s_addr
		    && vertex_parent_found->nexthop->router.s_addr
			       != vertex_parent->nexthop->router.s_addr)
			has_more_links = true;
	}

	/*
	 * No more links from that parent? Then delete the child from its
	 * children list.
	 */
	if (!has_more_links)
		listnode_delete(vertex_parent->parent->children, child);

	/*
	 * Delete the vertex_parent from the child parents list, this needs to
	 * be done anyway.
	 */
	listnode_delete(child->parents, vertex_parent);

	/*
	 * Are there actually more parents left? If not, then delete the child!
	 * This is done by recursively removing the links to the grandchildren,
	 * such that finally the child can be removed without leaving unused
	 * partial branches.
	 */
	if (child->parents->count == 0) {
		for (ALL_LIST_ELEMENTS(child->children, node, nnode,
				       grandchild)) {
			for (ALL_LIST_ELEMENTS(grandchild->parents, inner_node,
					       inner_nnode,
					       vertex_parent_found)) {
				ospf_spf_remove_branch(vertex_parent_found,
						       grandchild, vertex_list);
			}
		}
		listnode_delete(vertex_list, child);
		ospf_vertex_free(child);
	}
}

static int ospf_spf_remove_link(struct vertex *vertex, struct list *vertex_list,
				struct router_lsa_link *link)
{
	struct listnode *node, *inner_node;
	struct vertex *child;
	struct vertex_parent *vertex_parent;

	/*
	 * Identify the node who shares a subnet (given by the link) with a
	 * child and remove the branch of this particular child.
	 */
	for (ALL_LIST_ELEMENTS_RO(vertex->children, node, child)) {
		for (ALL_LIST_ELEMENTS_RO(child->parents, inner_node,
					  vertex_parent)) {
			if ((vertex_parent->local_nexthop->router.s_addr
			     & link->link_data.s_addr)
			    == (link->link_id.s_addr
				& link->link_data.s_addr)) {
				ospf_spf_remove_branch(vertex_parent, child,
						       vertex_list);
				return 0;
			}
		}
	}

	/* No link found yet, move on recursively */
	for (ALL_LIST_ELEMENTS_RO(vertex->children, node, child)) {
		if (ospf_spf_remove_link(child, vertex_list, link) == 0)
			return 0;
	}

	/* link was not removed yet */
	return 1;
}

void ospf_spf_remove_resource(struct vertex *vertex, struct list *vertex_list,
			      struct protected_resource *resource)
{
	struct listnode *node, *nnode;
	struct vertex *found;
	struct vertex_parent *vertex_parent;

	switch (resource->type) {
	case OSPF_TI_LFA_LINK_PROTECTION:
		ospf_spf_remove_link(vertex, vertex_list, resource->link);
		break;
	case OSPF_TI_LFA_NODE_PROTECTION:
		found = ospf_spf_vertex_find(resource->router_id, vertex_list);
		if (!found)
			break;

		/*
		 * Remove the node by removing all links from its parents. Note
		 * that the child is automatically removed here with the last
		 * link from a parent, hence no explicit removal of the node.
		 */
		for (ALL_LIST_ELEMENTS(found->parents, node, nnode,
				       vertex_parent))
			ospf_spf_remove_branch(vertex_parent, found,
					       vertex_list);

		break;
	default:
		/* do nothing */
		break;
	}
}

static void ospf_spf_init(struct ospf_area *area, struct ospf_lsa *root_lsa,
			  bool is_dry_run, bool is_root_node)
{
	struct list *vertex_list;
	struct vertex *v;

	/* Create vertex list */
	vertex_list = list_new();
	vertex_list->del = ospf_vertex_free;
	area->spf_vertex_list = vertex_list;

	/* Create root node. */
	v = ospf_vertex_new(area, root_lsa);
	area->spf = v;

	area->spf_dry_run = is_dry_run;
	area->spf_root_node = is_root_node;

	/* Reset ABR and ASBR router counts. */
	area->abr_count = 0;
	area->asbr_count = 0;
}

/* return index of link back to V from W, or -1 if no link found */
static int ospf_lsa_has_link(struct lsa_header *w, struct lsa_header *v)
{
	unsigned int i, length;
	struct router_lsa *rl;
	struct network_lsa *nl;

	/* In case of W is Network LSA. */
	if (w->type == OSPF_NETWORK_LSA) {
		if (v->type == OSPF_NETWORK_LSA)
			return -1;

		nl = (struct network_lsa *)w;
		length = (ntohs(w->length) - OSPF_LSA_HEADER_SIZE - 4) / 4;

		for (i = 0; i < length; i++)
			if (IPV4_ADDR_SAME(&nl->routers[i], &v->id))
				return i;
		return -1;
	}

	/* In case of W is Router LSA. */
	if (w->type == OSPF_ROUTER_LSA) {
		rl = (struct router_lsa *)w;

		length = ntohs(w->length);

		for (i = 0; i < ntohs(rl->links)
			    && length >= sizeof(struct router_lsa);
		     i++, length -= 12) {
			switch (rl->link[i].type) {
			case LSA_LINK_TYPE_POINTOPOINT:
			case LSA_LINK_TYPE_VIRTUALLINK:
				/* Router LSA ID. */
				if (v->type == OSPF_ROUTER_LSA
				    && IPV4_ADDR_SAME(&rl->link[i].link_id,
						      &v->id)) {
					return i;
				}
				break;
			case LSA_LINK_TYPE_TRANSIT:
				/* Network LSA ID. */
				if (v->type == OSPF_NETWORK_LSA
				    && IPV4_ADDR_SAME(&rl->link[i].link_id,
						      &v->id)) {
					return i;
				}
				break;
			case LSA_LINK_TYPE_STUB:
				/* Stub can't lead anywhere, carry on */
				continue;
			default:
				break;
			}
		}
	}
	return -1;
}

/*
 * Find the next link after prev_link from v to w.  If prev_link is
 * NULL, return the first link from v to w.  Ignore stub and virtual links;
 * these link types will never be returned.
 */
static struct router_lsa_link *
ospf_get_next_link(struct vertex *v, struct vertex *w,
		   struct router_lsa_link *prev_link)
{
	uint8_t *p;
	uint8_t *lim;
	uint8_t lsa_type = LSA_LINK_TYPE_TRANSIT;
	struct router_lsa_link *l;

	if (w->type == OSPF_VERTEX_ROUTER)
		lsa_type = LSA_LINK_TYPE_POINTOPOINT;

	if (prev_link == NULL)
		p = ((uint8_t *)v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
	else {
		p = (uint8_t *)prev_link;
		p += (OSPF_ROUTER_LSA_LINK_SIZE
		      + (prev_link->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));
	}

	lim = ((uint8_t *)v->lsa) + ntohs(v->lsa->length);

	while (p < lim) {
		l = (struct router_lsa_link *)p;

		p += (OSPF_ROUTER_LSA_LINK_SIZE
		      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

		if (l->m[0].type != lsa_type)
			continue;

		if (IPV4_ADDR_SAME(&l->link_id, &w->id))
			return l;
	}

	return NULL;
}

static void ospf_spf_flush_parents(struct vertex *w)
{
	struct vertex_parent *vp;
	struct listnode *ln, *nn;

	/* delete the existing nexthops */
	for (ALL_LIST_ELEMENTS(w->parents, ln, nn, vp)) {
		list_delete_node(w->parents, ln);
		vertex_parent_free(vp);
	}
}

/*
 * Consider supplied next-hop for inclusion to the supplied list of
 * equal-cost next-hops, adjust list as necessary.
 *
 * Returns vertex parent pointer if created otherwise `NULL` if it already
 * exists.
 */
static struct vertex_parent *ospf_spf_add_parent(struct vertex *v,
						 struct vertex *w,
						 struct vertex_nexthop *newhop,
						 struct vertex_nexthop *newlhop,
						 unsigned int distance)
{
	struct vertex_parent *vp, *wp;
	struct listnode *node;

	/* we must have a newhop, and a distance */
	assert(v && w && newhop);
	assert(distance);

	/*
	 * IFF w has already been assigned a distance, then we shouldn't get
	 * here unless callers have determined V(l)->W is shortest /
	 * equal-shortest path (0 is a special case distance (no distance yet
	 * assigned)).
	 */
	if (w->distance)
		assert(distance <= w->distance);
	else
		w->distance = distance;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Adding %pI4 as parent of %pI4", __func__,
			   &v->lsa->id, &w->lsa->id);

	/*
	 * Adding parent for a new, better path: flush existing parents from W.
	 */
	if (distance < w->distance) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: distance %d better than %d, flushing existing parents",
				__func__, distance, w->distance);
		ospf_spf_flush_parents(w);
		w->distance = distance;
	}

	/*
	 * new parent is <= existing parents, add it to parent list (if nexthop
	 * not on parent list)
	 */
	for (ALL_LIST_ELEMENTS_RO(w->parents, node, wp)) {
		if (memcmp(newhop, wp->nexthop, sizeof(*newhop)) == 0) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: ... nexthop already on parent list, skipping add",
					__func__);

			return NULL;
		}
	}

	vp = vertex_parent_new(v, ospf_lsa_has_link(w->lsa, v->lsa), newhop,
			       newlhop);
	listnode_add_sort(w->parents, vp);

	return vp;
}

static int match_stub_prefix(struct lsa_header *lsa, struct in_addr v_link_addr,
			     struct in_addr w_link_addr)
{
	uint8_t *p, *lim;
	struct router_lsa_link *l = NULL;
	struct in_addr masked_lsa_addr;

	if (lsa->type != OSPF_ROUTER_LSA)
		return 0;

	p = ((uint8_t *)lsa) + OSPF_LSA_HEADER_SIZE + 4;
	lim = ((uint8_t *)lsa) + ntohs(lsa->length);

	while (p < lim) {
		l = (struct router_lsa_link *)p;
		p += (OSPF_ROUTER_LSA_LINK_SIZE
		      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

		if (l->m[0].type != LSA_LINK_TYPE_STUB)
			continue;

		masked_lsa_addr.s_addr =
			(l->link_id.s_addr & l->link_data.s_addr);

		/* check that both links belong to the same stub subnet */
		if ((masked_lsa_addr.s_addr
		     == (v_link_addr.s_addr & l->link_data.s_addr))
		    && (masked_lsa_addr.s_addr
			== (w_link_addr.s_addr & l->link_data.s_addr)))
			return 1;
	}

	return 0;
}

/*
 * 16.1.1.  Calculate nexthop from root through V (parent) to
 * vertex W (destination), with given distance from root->W.
 *
 * The link must be supplied if V is the root vertex. In all other cases
 * it may be NULL.
 *
 * Note that this function may fail, hence the state of the destination
 * vertex, W, should /not/ be modified in a dependent manner until
 * this function returns. This function will update the W vertex with the
 * provided distance as appropriate.
 */
static unsigned int ospf_nexthop_calculation(struct ospf_area *area,
					     struct vertex *v, struct vertex *w,
					     struct router_lsa_link *l,
					     unsigned int distance, int lsa_pos)
{
	struct listnode *node, *nnode;
	struct vertex_nexthop *nh, *lnh;
	struct vertex_parent *vp;
	unsigned int added = 0;

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug("%s: Start", __func__);
		ospf_vertex_dump("V (parent):", v, 1, 1);
		ospf_vertex_dump("W (dest)  :", w, 1, 1);
		zlog_debug("V->W distance: %d", distance);
	}

	if (v == area->spf) {
		/*
		 * 16.1.1 para 4.  In the first case, the parent vertex (V) is
		 * the root (the calculating router itself).  This means that
		 * the destination is either a directly connected network or
		 * directly connected router.  The outgoing interface in this
		 * case is simply the OSPF interface connecting to the
		 * destination network/router.
		 */

		/* we *must* be supplied with the link data */
		assert(l != NULL);

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: considering link type:%d link_id:%pI4 link_data:%pI4",
				__func__, l->m[0].type, &l->link_id,
				&l->link_data);

		if (w->type == OSPF_VERTEX_ROUTER) {
			/*
			 * l is a link from v to w l2 will be link from w to v
			 */
			struct router_lsa_link *l2 = NULL;

			if (l->m[0].type == LSA_LINK_TYPE_POINTOPOINT) {
				struct ospf_interface *oi = NULL;
				struct in_addr nexthop = {.s_addr = 0};

				if (area->spf_root_node) {
					oi = ospf_if_lookup_by_lsa_pos(area,
								       lsa_pos);
					if (!oi) {
						zlog_debug(
							"%s: OI not found in LSA: lsa_pos: %d link_id:%pI4 link_data:%pI4",
							__func__, lsa_pos,
							&l->link_id,
							&l->link_data);
						return 0;
					}
				}

				/*
				 * If the destination is a router which connects
				 * to the calculating router via a
				 * Point-to-MultiPoint network, the
				 * destination's next hop IP address(es) can be
				 * determined by examining the destination's
				 * router-LSA: each link pointing back to the
				 * calculating router and having a Link Data
				 * field belonging to the Point-to-MultiPoint
				 * network provides an IP address of the next
				 * hop router.
				 *
				 * At this point l is a link from V to W, and V
				 * is the root ("us"). If it is a point-to-
				 * multipoint interface, then look through the
				 * links in the opposite direction (W to V).
				 * If any of them have an address that lands
				 * within the subnet declared by the PtMP link,
				 * then that link is a constituent of the PtMP
				 * link, and its address is a nexthop address
				 * for V.
				 *
				 * Note for point-to-point interfaces:
				 *
				 * Having nexthop = 0 (as proposed in the RFC)
				 * is tempting, but NOT acceptable. It breaks
				 * AS-External routes with a forwarding address,
				 * since ospf_ase_complete_direct_routes() will
				 * mistakenly assume we've reached the last hop
				 * and should place the forwarding address as
				 * nexthop. Also, users may configure multi-
				 * access links in p2p mode, so we need the IP
				 * to ARP the nexthop.
				 *
				 * If the calculating router is the SPF root
				 * node and the link is P2P then access the
				 * interface information directly. This can be
				 * crucial when e.g. IP unnumbered is used
				 * where 'correct' nexthop information are not
				 * available via Router LSAs.
				 *
				 * Otherwise handle P2P and P2MP the same way
				 * as described above using a reverse lookup to
				 * figure out the nexthop.
				 */

				/*
				 * HACK: we don't know (yet) how to distinguish
				 * between P2P and P2MP interfaces by just
				 * looking at LSAs, which is important for
				 * TI-LFA since you want to do SPF calculations
				 * from the perspective of other nodes. Since
				 * TI-LFA is currently not implemented for P2MP
				 * we just check here if it is enabled and then
				 * blindly assume that P2P is used. Ultimately
				 * the interface code needs to be removed
				 * somehow.
				 */
				if (area->ospf->ti_lfa_enabled
				    || (oi && oi->type == OSPF_IFTYPE_POINTOPOINT)
				    || (oi && oi->type == OSPF_IFTYPE_POINTOMULTIPOINT
					   && oi->address->prefixlen == IPV4_MAX_BITLEN)) {
					struct ospf_neighbor *nbr_w = NULL;

					/* Calculating node is root node, link
					 * is P2P */
					if (area->spf_root_node) {
						nbr_w = ospf_nbr_lookup_by_routerid(
							oi->nbrs, &l->link_id);
						if (nbr_w) {
							added = 1;
							nexthop = nbr_w->src;
						}
					}

					/* Reverse lookup */
					if (!added) {
						while ((l2 = ospf_get_next_link(
								w, v, l2))) {
							if (match_stub_prefix(
								    v->lsa,
								    l->link_data,
								    l2->link_data)) {
								added = 1;
								nexthop =
									l2->link_data;
								break;
							}
						}
					}
				} else if (oi && oi->type
					   == OSPF_IFTYPE_POINTOMULTIPOINT) {
					struct prefix_ipv4 la;

					la.family = AF_INET;
					la.prefixlen = oi->address->prefixlen;

					/*
					 * V links to W on PtMP interface;
					 * find the interface address on W
					 */
					while ((l2 = ospf_get_next_link(w, v,
									l2))) {
						la.prefix = l2->link_data;

						if (prefix_cmp((struct prefix
									*)&la,
							       oi->address)
						    != 0)
							continue;
						added = 1;
						nexthop = l2->link_data;
						break;
					}
				}

				if (added) {
					nh = vertex_nexthop_new();
					nh->router = nexthop;
					nh->lsa_pos = lsa_pos;

					/*
					 * Since v is the root the nexthop and
					 * local nexthop are the same.
					 */
					lnh = vertex_nexthop_new();
					memcpy(lnh, nh,
					       sizeof(struct vertex_nexthop));

					if (ospf_spf_add_parent(v, w, nh, lnh,
								distance) ==
					    NULL) {
						vertex_nexthop_free(nh);
						vertex_nexthop_free(lnh);
					}
					return 1;
				} else
					zlog_info(
						"%s: could not determine nexthop for link %s",
						__func__, oi ? oi->ifp->name : "");
			} /* end point-to-point link from V to W */
			else if (l->m[0].type == LSA_LINK_TYPE_VIRTUALLINK) {
				/*
				 * VLink implementation limitations:
				 * a) vl_data can only reference one nexthop,
				 *    so no ECMP to backbone through VLinks.
				 *    Though transit-area summaries may be
				 *    considered, and those can be ECMP.
				 * b) We can only use /one/ VLink, even if
				 *    multiple ones exist this router through
				 *    multiple transit-areas.
				 */

				struct ospf_vl_data *vl_data;

				vl_data = ospf_vl_lookup(area->ospf, NULL,
							 l->link_id);

				if (vl_data
				    && CHECK_FLAG(vl_data->flags,
						  OSPF_VL_FLAG_APPROVED)) {
					nh = vertex_nexthop_new();
					nh->router = vl_data->nexthop.router;
					nh->lsa_pos = vl_data->nexthop.lsa_pos;

					/*
					 * Since v is the root the nexthop and
					 * local nexthop are the same.
					 */
					lnh = vertex_nexthop_new();
					memcpy(lnh, nh,
					       sizeof(struct vertex_nexthop));

					if (ospf_spf_add_parent(v, w, nh, lnh,
								distance) ==
					    NULL) {
						vertex_nexthop_free(nh);
						vertex_nexthop_free(lnh);
					}

					return 1;
				} else
					zlog_info(
						"%s: vl_data for VL link not found",
						__func__);
			} /* end virtual-link from V to W */
			return 0;
		} /* end W is a Router vertex */
		else {
			assert(w->type == OSPF_VERTEX_NETWORK);

			nh = vertex_nexthop_new();
			nh->router.s_addr = 0; /* Nexthop not required */
			nh->lsa_pos = lsa_pos;

			/*
			 * Since v is the root the nexthop and
			 * local nexthop are the same.
			 */
			lnh = vertex_nexthop_new();
			memcpy(lnh, nh, sizeof(struct vertex_nexthop));

			if (ospf_spf_add_parent(v, w, nh, lnh, distance) ==
			    NULL) {
				vertex_nexthop_free(nh);
				vertex_nexthop_free(lnh);
			}

			return 1;
		}
	} /* end V is the root */
	/* Check if W's parent is a network connected to root. */
	else if (v->type == OSPF_VERTEX_NETWORK) {
		/* See if any of V's parents are the root. */
		for (ALL_LIST_ELEMENTS(v->parents, node, nnode, vp)) {
			if (vp->parent == area->spf) {
				/*
				 * 16.1.1 para 5. ...the parent vertex is a
				 * network that directly connects the
				 * calculating router to the destination
				 * router. The list of next hops is then
				 * determined by examining the destination's
				 * router-LSA ...
				 */

				assert(w->type == OSPF_VERTEX_ROUTER);
				while ((l = ospf_get_next_link(w, v, l))) {
					/*
					 * ... For each link in the router-LSA
					 * that points back to the parent
					 * network, the link's Link Data field
					 * provides the IP address of a next hop
					 * router. The outgoing interface to use
					 * can then be derived from the next
					 * hop IP address (or it can be
					 * inherited from the parent network).
					 */
					nh = vertex_nexthop_new();
					nh->router = l->link_data;
					nh->lsa_pos = vp->nexthop->lsa_pos;

					/*
					 * Since v is the root the nexthop and
					 * local nexthop are the same.
					 */
					lnh = vertex_nexthop_new();
					memcpy(lnh, nh,
					       sizeof(struct vertex_nexthop));

					added = 1;
					if (ospf_spf_add_parent(v, w, nh, lnh,
								distance) ==
					    NULL) {
						vertex_nexthop_free(nh);
						vertex_nexthop_free(lnh);
					}
				}
				/*
				 * Note lack of return is deliberate. See next
				 * comment.
				 */
			}
		}
		/*
		 * NB: This code is non-trivial.
		 *
		 * E.g. it is not enough to know that V connects to the root. It
		 * is also important that the while above, looping through all
		 * links from W->V found at least one link, so that we know
		 * there is bi-directional connectivity between V and W (which
		 * need not be the case, e.g.  when OSPF has not yet converged
		 * fully). Otherwise, if we /always/ return here, without having
		 * checked that root->V->-W actually resulted in a valid nexthop
		 * being created, then we we will prevent SPF from finding/using
		 * higher cost paths.
		 *
		 * It is important, if root->V->W has not been added, that we
		 * continue through to the intervening-router nexthop code
		 * below. So as to ensure other paths to V may be used. This
		 * avoids unnecessary blackholes while OSPF is converging.
		 *
		 * I.e. we may have arrived at this function, examining V -> W,
		 * via workable paths other than root -> V, and it's important
		 * to avoid getting "confused" by non-working root->V->W path
		 * - it's important to *not* lose the working non-root paths,
		 * just because of a non-viable root->V->W.
		 */
		if (added)
			return added;
	}

	/*
	 * 16.1.1 para 4.  If there is at least one intervening router in the
	 * current shortest path between the destination and the root, the
	 * destination simply inherits the set of next hops from the
	 * parent.
	 */
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Intervening routers, adding parent(s)",
			   __func__);

	for (ALL_LIST_ELEMENTS(v->parents, node, nnode, vp)) {
		added = 1;

		/*
		 * The nexthop is inherited, but the local nexthop still needs
		 * to be created.
		 */
		if (l) {
			lnh = vertex_nexthop_new();
			lnh->router = l->link_data;
			lnh->lsa_pos = lsa_pos;
		} else {
			lnh = NULL;
		}

		nh = vertex_nexthop_new();
		*nh = *vp->nexthop;

		if (ospf_spf_add_parent(v, w, nh, lnh, distance) == NULL) {
			vertex_nexthop_free(nh);
			vertex_nexthop_free(lnh);
		}
	}

	return added;
}

static int ospf_spf_is_protected_resource(struct ospf_area *area,
					  struct router_lsa_link *link,
					  struct lsa_header *lsa)
{
	uint8_t *p, *lim;
	struct router_lsa_link *p_link;
	struct router_lsa_link *l = NULL;
	struct in_addr router_id;
	int link_type;

	if (!area->spf_protected_resource)
		return 0;

	link_type = link->m[0].type;

	switch (area->spf_protected_resource->type) {
	case OSPF_TI_LFA_LINK_PROTECTION:
		p_link = area->spf_protected_resource->link;
		if (!p_link)
			return 0;

		/* For P2P: check if the link belongs to the same subnet */
		if (link_type == LSA_LINK_TYPE_POINTOPOINT
		    && (p_link->link_id.s_addr & p_link->link_data.s_addr)
			       == (link->link_data.s_addr
				   & p_link->link_data.s_addr))
			return 1;

		/* For stub: check if this the same subnet */
		if (link_type == LSA_LINK_TYPE_STUB
		    && (p_link->link_id.s_addr == link->link_id.s_addr)
		    && (p_link->link_data.s_addr == link->link_data.s_addr))
			return 1;

		break;
	case OSPF_TI_LFA_NODE_PROTECTION:
		router_id = area->spf_protected_resource->router_id;
		if (router_id.s_addr == INADDR_ANY)
			return 0;

		/* For P2P: check if the link leads to the protected node */
		if (link_type == LSA_LINK_TYPE_POINTOPOINT
		    && link->link_id.s_addr == router_id.s_addr)
			return 1;

		/* The rest is about stub links! */
		if (link_type != LSA_LINK_TYPE_STUB)
			return 0;

		/*
		 * Check if there's a P2P link in the router LSA with the
		 * corresponding link data in the same subnet.
		 */

		p = ((uint8_t *)lsa) + OSPF_LSA_HEADER_SIZE + 4;
		lim = ((uint8_t *)lsa) + ntohs(lsa->length);

		while (p < lim) {
			l = (struct router_lsa_link *)p;
			p += (OSPF_ROUTER_LSA_LINK_SIZE
			      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

			/* We only care about P2P with the proper link id */
			if ((l->m[0].type != LSA_LINK_TYPE_POINTOPOINT)
			    || (l->link_id.s_addr != router_id.s_addr))
				continue;

			/* Link data in the subnet given by the link? */
			if ((link->link_id.s_addr & link->link_data.s_addr)
			    == (l->link_data.s_addr & link->link_data.s_addr))
				return 1;
		}

		break;
	case OSPF_TI_LFA_UNDEFINED_PROTECTION:
		break;
	}

	return 0;
}

/*
 * For TI-LFA we need the reverse SPF for Q spaces. The reverse SPF is created
 * by honoring the weight of the reverse 'edge', e.g. the edge from W to V, and
 * NOT the weight of the 'edge' from V to W as usual. Hence we need to find the
 * corresponding link in the LSA of W and extract the particular weight.
 *
 * TODO: Only P2P supported by now!
 */
static uint16_t get_reverse_distance(struct vertex *v,
				     struct router_lsa_link *l,
				     struct ospf_lsa *w_lsa)
{
	uint8_t *p, *lim;
	struct router_lsa_link *w_link;
	uint16_t distance = 0;

	assert(w_lsa && w_lsa->data);

	p = ((uint8_t *)w_lsa->data) + OSPF_LSA_HEADER_SIZE + 4;
	lim = ((uint8_t *)w_lsa->data) + ntohs(w_lsa->data->length);

	while (p < lim) {
		w_link = (struct router_lsa_link *)p;
		p += (OSPF_ROUTER_LSA_LINK_SIZE
		      + (w_link->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

		/* Only care about P2P with link ID equal to V's router id */
		if (w_link->m[0].type == LSA_LINK_TYPE_POINTOPOINT
		    && w_link->link_id.s_addr == v->id.s_addr) {
			distance = ntohs(w_link->m[0].metric);
			break;
		}
	}

	/*
	 * This might happen if the LSA for W is not complete yet. In this
	 * case we take the weight of the 'forward' link from V. When the LSA
	 * for W is completed the reverse SPF is run again anyway.
	 */
	if (distance == 0)
		distance = ntohs(l->m[0].metric);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: reversed distance is %u", __func__, distance);

	return distance;
}

/*
 * RFC2328 16.1 (2).
 * v is on the SPF tree. Examine the links in v's LSA. Update the list of
 * candidates with any vertices not already on the list. If a lower-cost path
 * is found to a vertex already on the candidate list, store the new cost.
 */
static void ospf_spf_next(struct vertex *v, struct ospf_area *area,
			  struct vertex_pqueue_head *candidate)
{
	struct ospf_lsa *w_lsa = NULL;
	uint8_t *p;
	uint8_t *lim;
	struct router_lsa_link *l = NULL;
	struct in_addr *r;
	int type = 0, lsa_pos = -1, lsa_pos_next = 0;
	uint16_t link_distance;

	/*
	 * If this is a router-LSA, and bit V of the router-LSA (see Section
	 * A.4.2:RFC2328) is set, set Area A's TransitCapability to true.
	 */
	if (v->type == OSPF_VERTEX_ROUTER) {
		if (IS_ROUTER_LSA_VIRTUAL((struct router_lsa *)v->lsa))
			area->transit = OSPF_TRANSIT_TRUE;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Next vertex of %s vertex %pI4", __func__,
			   v->type == OSPF_VERTEX_ROUTER ? "Router" : "Network",
			   &v->lsa->id);

	p = ((uint8_t *)v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
	lim = ((uint8_t *)v->lsa) + ntohs(v->lsa->length);

	while (p < lim) {
		struct vertex *w;
		unsigned int distance;

		/* In case of V is Router-LSA. */
		if (v->lsa->type == OSPF_ROUTER_LSA) {
			l = (struct router_lsa_link *)p;

			lsa_pos = lsa_pos_next; /* LSA link position */
			lsa_pos_next++;

			p += (OSPF_ROUTER_LSA_LINK_SIZE
			      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

			/*
			 * (a) If this is a link to a stub network, examine the
			 * next link in V's LSA. Links to stub networks will
			 * be considered in the second stage of the shortest
			 * path calculation.
			 */
			if ((type = l->m[0].type) == LSA_LINK_TYPE_STUB)
				continue;

			/*
			 * Don't process TI-LFA protected resources.
			 *
			 * TODO: Replace this by a proper solution, e.g. remove
			 * corresponding links from the LSDB and run the SPF
			 * algo with the stripped-down LSDB.
			 */
			if (ospf_spf_is_protected_resource(area, l, v->lsa))
				continue;

			/*
			 * (b) Otherwise, W is a transit vertex (router or
			 * transit network). Look up the vertex W's LSA
			 * (router-LSA or network-LSA) in Area A's link state
			 * database.
			 */
			switch (type) {
			case LSA_LINK_TYPE_POINTOPOINT:
			case LSA_LINK_TYPE_VIRTUALLINK:
				if (type == LSA_LINK_TYPE_VIRTUALLINK
				    && IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"looking up LSA through VL: %pI4",
						&l->link_id);
				w_lsa = ospf_lsa_lookup(area->ospf, area,
							OSPF_ROUTER_LSA,
							l->link_id, l->link_id);
				if (w_lsa && IS_DEBUG_OSPF_EVENT)
					zlog_debug("found Router LSA %pI4",
						   &l->link_id);
				break;
			case LSA_LINK_TYPE_TRANSIT:
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"Looking up Network LSA, ID: %pI4",
						&l->link_id);
				w_lsa = ospf_lsa_lookup_by_id(
					area, OSPF_NETWORK_LSA, l->link_id);
				if (w_lsa && IS_DEBUG_OSPF_EVENT)
					zlog_debug("found the LSA");
				break;
			default:
				flog_warn(EC_OSPF_LSA,
					  "Invalid LSA link type %d", type);
				continue;
			}

			/*
			 * For TI-LFA we might need the reverse SPF.
			 * Currently only works with P2P!
			 */
			if (type == LSA_LINK_TYPE_POINTOPOINT
			    && area->spf_reversed)
				link_distance =
					get_reverse_distance(v, l, w_lsa);
			else
				link_distance = ntohs(l->m[0].metric);

			/* step (d) below */
			distance = v->distance + link_distance;
		} else {
			/* In case of V is Network-LSA. */
			r = (struct in_addr *)p;
			p += sizeof(struct in_addr);

			/* Lookup the vertex W's LSA. */
			w_lsa = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
						      *r);
			if (w_lsa && IS_DEBUG_OSPF_EVENT)
				zlog_debug("found Router LSA %pI4",
					   &w_lsa->data->id);

			/* step (d) below */
			distance = v->distance;
		}

		/*
		 * (b cont.) If the LSA does not exist, or its LS age is equal
		 * to MaxAge, or it does not have a link back to vertex V,
		 * examine the next link in V's LSA.[23]
		 */
		if (w_lsa == NULL) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("No LSA found");
			continue;
		}

		if (IS_LSA_MAXAGE(w_lsa)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("LSA is MaxAge");
			continue;
		}

		if (ospf_lsa_has_link(w_lsa->data, v->lsa) < 0) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("The LSA doesn't have a link back");
			continue;
		}

		/*
		 * (c) If vertex W is already on the shortest-path tree, examine
		 * the next link in the LSA.
		 */
		if (w_lsa->stat == LSA_SPF_IN_SPFTREE) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("The LSA is already in SPF");
			continue;
		}

		/*
		 * (d) Calculate the link state cost D of the resulting path
		 * from the root to vertex W.  D is equal to the sum of the link
		 * state cost of the (already calculated) shortest path to
		 * vertex V and the advertised cost of the link between vertices
		 * V and W.  If D is:
		 */

		/* calculate link cost D -- moved above */

		/* Is there already vertex W in candidate list? */
		if (w_lsa->stat == LSA_SPF_NOT_EXPLORED) {
			/* prepare vertex W. */
			w = ospf_vertex_new(area, w_lsa);

			/* Calculate nexthop to W. */
			if (ospf_nexthop_calculation(area, v, w, l, distance,
						     lsa_pos))
				vertex_pqueue_add(candidate, w);
			else {
				listnode_delete(area->spf_vertex_list, w);
				ospf_vertex_free(w);
				w_lsa->stat = LSA_SPF_NOT_EXPLORED;
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug("Nexthop Calc failed");
			}
		} else if (w_lsa->stat != LSA_SPF_IN_SPFTREE) {
			w = w_lsa->stat;
			if (w->distance < distance) {
				continue;
			}
			else if (w->distance == distance) {
				/*
				 * Found an equal-cost path to W.
				 * Calculate nexthop of to W from V.
				 */
				ospf_nexthop_calculation(area, v, w, l,
							 distance, lsa_pos);
			}
			else {
				/*
				 * Found a lower-cost path to W.
				 * nexthop_calculation is conditional, if it
				 * finds valid nexthop it will call
				 * spf_add_parents, which will flush the old
				 * parents.
				 */
				vertex_pqueue_del(candidate, w);
				ospf_nexthop_calculation(area, v, w, l,
							 distance, lsa_pos);
				vertex_pqueue_add(candidate, w);
			}
		} /* end W is already on the candidate list */
	}	 /* end loop over the links in V's LSA */
}

static void ospf_spf_dump(struct vertex *v, int i)
{
	struct listnode *cnode;
	struct listnode *nnode;
	struct vertex_parent *parent;

	if (v->type == OSPF_VERTEX_ROUTER) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("SPF Result: %d [R] %pI4", i,
				   &v->lsa->id);
	} else {
		struct network_lsa *lsa = (struct network_lsa *)v->lsa;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("SPF Result: %d [N] %pI4/%d", i,
				   &v->lsa->id,
				   ip_masklen(lsa->mask));
	}

	if (IS_DEBUG_OSPF_EVENT)
		for (ALL_LIST_ELEMENTS_RO(v->parents, nnode, parent)) {
			zlog_debug(" nexthop %p %pI4 %d",
				   (void *)parent->nexthop,
				   &parent->nexthop->router,
				   parent->nexthop->lsa_pos);
		}

	i++;

	for (ALL_LIST_ELEMENTS_RO(v->children, cnode, v))
		ospf_spf_dump(v, i);
}

void ospf_spf_print(struct vty *vty, struct vertex *v, int i)
{
	struct listnode *cnode;
	struct listnode *nnode;
	struct vertex_parent *parent;

	if (v->type == OSPF_VERTEX_ROUTER) {
		vty_out(vty, "SPF Result: depth %d [R] %pI4\n", i, &v->lsa->id);
	} else {
		struct network_lsa *lsa = (struct network_lsa *)v->lsa;
		vty_out(vty, "SPF Result: depth %d [N] %pI4/%d\n", i,
			&v->lsa->id, ip_masklen(lsa->mask));
	}

	for (ALL_LIST_ELEMENTS_RO(v->parents, nnode, parent)) {
		vty_out(vty,
			" nexthop %pI4 lsa pos %d -- local nexthop %pI4 lsa pos %d\n",
			&parent->nexthop->router, parent->nexthop->lsa_pos,
			&parent->local_nexthop->router,
			parent->local_nexthop->lsa_pos);
	}

	i++;

	for (ALL_LIST_ELEMENTS_RO(v->children, cnode, v))
		ospf_spf_print(vty, v, i);
}

/* Second stage of SPF calculation. */
static void ospf_spf_process_stubs(struct ospf_area *area, struct vertex *v,
				   struct route_table *rt, int parent_is_root)
{
	struct listnode *cnode, *cnnode;
	struct vertex *child;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: processing stubs for area %pI4", __func__,
			   &area->area_id);

	if (v->type == OSPF_VERTEX_ROUTER) {
		uint8_t *p;
		uint8_t *lim;
		struct router_lsa_link *l;
		struct router_lsa *router_lsa;
		int lsa_pos = 0;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: processing router LSA, id: %pI4",
				   __func__, &v->lsa->id);

		router_lsa = (struct router_lsa *)v->lsa;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: we have %d links to process", __func__,
				   ntohs(router_lsa->links));

		p = ((uint8_t *)v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
		lim = ((uint8_t *)v->lsa) + ntohs(v->lsa->length);

		while (p < lim) {
			l = (struct router_lsa_link *)p;

			p += (OSPF_ROUTER_LSA_LINK_SIZE
			      + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

			/* Don't process TI-LFA protected resources */
			if (l->m[0].type == LSA_LINK_TYPE_STUB
			    && !ospf_spf_is_protected_resource(area, l, v->lsa))
				ospf_intra_add_stub(rt, l, v, area,
						    parent_is_root, lsa_pos);
			lsa_pos++;
		}
	}

	ospf_vertex_dump("ospf_process_stubs(): after examining links: ", v, 1,
			 1);

	for (ALL_LIST_ELEMENTS(v->children, cnode, cnnode, child)) {
		if (CHECK_FLAG(child->flags, OSPF_VERTEX_PROCESSED))
			continue;

		/*
		 * The first level of routers connected to the root
		 * should have 'parent_is_root' set, including those
		 * connected via a network vertex.
		 */
		if (area->spf == v)
			parent_is_root = 1;
		else if (v->type == OSPF_VERTEX_ROUTER)
			parent_is_root = 0;

		ospf_spf_process_stubs(area, child, rt, parent_is_root);

		SET_FLAG(child->flags, OSPF_VERTEX_PROCESSED);
	}
}

void ospf_rtrs_free(struct route_table *rtrs)
{
	struct route_node *rn;
	struct list *or_list;
	struct ospf_route * or ;
	struct listnode *node, *nnode;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Route: Router Routing Table free");

	for (rn = route_top(rtrs); rn; rn = route_next(rn))
		if ((or_list = rn->info) != NULL) {
			for (ALL_LIST_ELEMENTS(or_list, node, nnode, or))
				ospf_route_free(or);

			list_delete(&or_list);

			/* Unlock the node. */
			rn->info = NULL;
			route_unlock_node(rn);
		}

	route_table_finish(rtrs);
}

void ospf_spf_cleanup(struct vertex *spf, struct list *vertex_list)
{
	/*
	 * Free nexthop information, canonical versions of which are
	 * attached the first level of router vertices attached to the
	 * root vertex, see ospf_nexthop_calculation.
	 */
	if (spf)
		ospf_canonical_nexthops_free(spf);

	/* Free SPF vertices list with deconstructor ospf_vertex_free. */
	if (vertex_list)
		list_delete(&vertex_list);
}

/* Calculating the shortest-path tree for an area, see RFC2328 16.1. */
void ospf_spf_calculate(struct ospf_area *area, struct ospf_lsa *root_lsa,
			struct route_table *new_table,
			struct route_table *all_rtrs,
			struct route_table *new_rtrs, bool is_dry_run,
			bool is_root_node)
{
	struct vertex_pqueue_head candidate;
	struct vertex *v;

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug("%s: Start: running Dijkstra for area %pI4",
			   __func__, &area->area_id);
	}

	/*
	 * If the router LSA of the root is not yet allocated, return this
	 * area's calculation. In the 'usual' case the root_lsa is the
	 * self-originated router LSA of the node itself.
	 */
	if (!root_lsa) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: Skip area %pI4's calculation due to empty root LSA",
				__func__, &area->area_id);
		return;
	}

	/* Initialize the algorithm's data structures, see RFC2328 16.1. (1). */

	/*
	 * This function scans all the LSA database and set the stat field to
	 * LSA_SPF_NOT_EXPLORED.
	 */
	lsdb_clean_stat(area->lsdb);

	/* Create a new heap for the candidates. */
	vertex_pqueue_init(&candidate);

	/*
	 * Initialize the shortest-path tree to only the root (which is usually
	 * the router doing the calculation).
	 */
	ospf_spf_init(area, root_lsa, is_dry_run, is_root_node);

	/* Set Area A's TransitCapability to false. */
	area->transit = OSPF_TRANSIT_FALSE;
	area->shortcut_capability = 1;

	/*
	 * Use the root vertex for the start of the SPF algorithm and make it
	 * part of the tree.
	 */
	v = area->spf;
	v->lsa_p->stat = LSA_SPF_IN_SPFTREE;

	for (;;) {
		/* RFC2328 16.1. (2). */
		ospf_spf_next(v, area, &candidate);

		/* RFC2328 16.1. (3). */
		v = vertex_pqueue_pop(&candidate);
		if (!v)
			/* No more vertices left. */
			break;

		v->lsa_p->stat = LSA_SPF_IN_SPFTREE;

		ospf_vertex_add_parent(v);

		/* RFC2328 16.1. (4). */
		if (v->type != OSPF_VERTEX_ROUTER)
			ospf_intra_add_transit(new_table, v, area);
		else {
			if (new_rtrs)
				ospf_intra_add_router(new_rtrs, v, area, false);
			if (all_rtrs)
				ospf_intra_add_router(all_rtrs, v, area, true);
		}

		/* Iterate back to (2), see RFC2328 16.1. (5). */
	}

	if (IS_DEBUG_OSPF_EVENT) {
		ospf_spf_dump(area->spf, 0);
		ospf_route_table_dump(new_table);
		if (all_rtrs)
			ospf_router_route_table_dump(all_rtrs);
	}

	/*
	 * Second stage of SPF calculation procedure's, add leaves to the tree
	 * for stub networks.
	 */
	ospf_spf_process_stubs(area, area->spf, new_table, 0);

	ospf_vertex_dump(__func__, area->spf, 0, 1);

	/* Increment SPF Calculation Counter. */
	area->spf_calculation++;

	monotime(&area->ospf->ts_spf);
	area->ts_spf = area->ospf->ts_spf;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop. %zd vertices", __func__,
			   mtype_stats_alloc(MTYPE_OSPF_VERTEX));
}

void ospf_spf_calculate_area(struct ospf *ospf, struct ospf_area *area,
			     struct route_table *new_table,
			     struct route_table *all_rtrs,
			     struct route_table *new_rtrs)
{
	ospf_spf_calculate(area, area->router_lsa_self, new_table, all_rtrs,
			   new_rtrs, false, true);

	if (ospf->ti_lfa_enabled)
		ospf_ti_lfa_compute(area, new_table,
				    ospf->ti_lfa_protection_type);

	ospf_spf_cleanup(area->spf, area->spf_vertex_list);

	area->spf = NULL;
	area->spf_vertex_list = NULL;
}

void ospf_spf_calculate_areas(struct ospf *ospf, struct route_table *new_table,
			      struct route_table *all_rtrs,
			      struct route_table *new_rtrs)
{
	struct ospf_area *area;
	struct listnode *node, *nnode;

	/* Calculate SPF for each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		/* Do backbone last, so as to first discover intra-area paths
		 * for any back-bone virtual-links */
		if (ospf->backbone && ospf->backbone == area)
			continue;

		ospf_spf_calculate_area(ospf, area, new_table, all_rtrs,
					new_rtrs);
	}

	/* SPF for backbone, if required */
	if (ospf->backbone)
		ospf_spf_calculate_area(ospf, ospf->backbone, new_table,
					all_rtrs, new_rtrs);
}

/* Worker for SPF calculation scheduler. */
static void ospf_spf_calculate_schedule_worker(struct thread *thread)
{
	struct ospf *ospf = THREAD_ARG(thread);
	struct route_table *new_table, *new_rtrs;
	struct route_table *all_rtrs = NULL;
	struct timeval start_time, spf_start_time;
	unsigned long ia_time, prune_time, rt_time;
	unsigned long abr_time, total_spf_time, spf_time;
	char rbuf[32]; /* reason_buf */

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("SPF: Timer (SPF calculation expire)");

	ospf->t_spf_calc = NULL;

	ospf_vl_unapprove(ospf);

	/* Execute SPF for each area including backbone, see RFC 2328 16.1. */
	monotime(&spf_start_time);
	new_table = route_table_init(); /* routing table */
	new_rtrs = route_table_init();  /* ABR/ASBR routing table */

	/* If we have opaque enabled then track all router reachability */
	if (CHECK_FLAG(ospf->opaque, OPAQUE_OPERATION_READY_BIT))
		all_rtrs = route_table_init();

	ospf_spf_calculate_areas(ospf, new_table, all_rtrs, new_rtrs);
	spf_time = monotime_since(&spf_start_time, NULL);

	ospf_vl_shut_unapproved(ospf);

	/* Calculate inter-area routes, see RFC 2328 16.2. */
	monotime(&start_time);
	ospf_ia_routing(ospf, new_table, new_rtrs);
	ia_time = monotime_since(&start_time, NULL);

	/* Get rid of transit networks and routers we cannot reach anyway. */
	monotime(&start_time);
	ospf_prune_unreachable_networks(new_table);
	if (all_rtrs)
		ospf_prune_unreachable_routers(all_rtrs);
	ospf_prune_unreachable_routers(new_rtrs);
	prune_time = monotime_since(&start_time, NULL);

	/* Note: RFC 2328 16.3. is apparently missing. */

	/*
	 * Calculate AS external routes, see RFC 2328 16.4.
	 * There is a dedicated routing table for external routes which is not
	 * handled here directly
	 */
	ospf_ase_calculate_schedule(ospf);
	ospf_ase_calculate_timer_add(ospf);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s: ospf install new route, vrf %s id %u new_table count %lu",
			__func__, ospf_vrf_id_to_name(ospf->vrf_id),
			ospf->vrf_id, new_table->count);

	/* Update routing table. */
	monotime(&start_time);
	ospf_route_install(ospf, new_table);
	rt_time = monotime_since(&start_time, NULL);

	/* Free old all routers routing table */
	if (ospf->oall_rtrs) {
		ospf_rtrs_free(ospf->oall_rtrs);
		ospf->oall_rtrs = NULL;
	}

	/* Update all routers routing table */
	ospf->oall_rtrs = ospf->all_rtrs;
	ospf->all_rtrs = all_rtrs;
#ifdef SUPPORT_OSPF_API
	ospf_apiserver_notify_reachable(ospf->oall_rtrs, ospf->all_rtrs);
#endif

	/* Free old ABR/ASBR routing table */
	if (ospf->old_rtrs) {
		ospf_rtrs_free(ospf->old_rtrs);
		ospf->old_rtrs = NULL;
	}

	/* Update ABR/ASBR routing table */
	ospf->old_rtrs = ospf->new_rtrs;
	ospf->new_rtrs = new_rtrs;

	/* ABRs may require additional changes, see RFC 2328 16.7. */
	monotime(&start_time);
	if (IS_OSPF_ABR(ospf)) {
		if (ospf->anyNSSA)
			ospf_abr_nssa_check_status(ospf);
		ospf_abr_task(ospf);
	}
	abr_time = monotime_since(&start_time, NULL);

	/* Schedule Segment Routing update */
	ospf_sr_update_task(ospf);

	total_spf_time =
		monotime_since(&spf_start_time, &ospf->ts_spf_duration);

	rbuf[0] = '\0';
	if (spf_reason_flags) {
		if (spf_reason_flags & (1 << SPF_FLAG_ROUTER_LSA_INSTALL))
			strlcat(rbuf, "R, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_NETWORK_LSA_INSTALL))
			strlcat(rbuf, "N, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_SUMMARY_LSA_INSTALL))
			strlcat(rbuf, "S, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_ASBR_SUMMARY_LSA_INSTALL))
			strlcat(rbuf, "AS, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_ABR_STATUS_CHANGE))
			strlcat(rbuf, "ABR, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_ASBR_STATUS_CHANGE))
			strlcat(rbuf, "ASBR, ",	sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_MAXAGE))
			strlcat(rbuf, "M, ", sizeof(rbuf));
		if (spf_reason_flags & (1 << SPF_FLAG_GR_FINISH))
			strlcat(rbuf, "GR, ", sizeof(rbuf));

		size_t rbuflen = strlen(rbuf);
		if (rbuflen >= 2)
			rbuf[rbuflen - 2] = '\0'; /* skip the last ", " */
		else
			rbuf[0] = '\0';
	}

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_info("SPF Processing Time(usecs): %ld", total_spf_time);
		zlog_info("            SPF Time: %ld", spf_time);
		zlog_info("           InterArea: %ld", ia_time);
		zlog_info("               Prune: %ld", prune_time);
		zlog_info("        RouteInstall: %ld", rt_time);
		if (IS_OSPF_ABR(ospf))
			zlog_info("                 ABR: %ld (%d areas)",
				  abr_time, ospf->areas->count);
		zlog_info("Reason(s) for SPF: %s", rbuf);
	}

	ospf_clear_spf_reason_flags();
}

/*
 * Add schedule for SPF calculation. To avoid frequenst SPF calc, we set timer
 * for SPF calc.
 */
void ospf_spf_calculate_schedule(struct ospf *ospf, ospf_spf_reason_t reason)
{
	unsigned long delay, elapsed, ht;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("SPF: calculation timer scheduled");

	/* OSPF instance does not exist. */
	if (ospf == NULL)
		return;

	ospf_spf_set_reason(reason);

	/* SPF calculation timer is already scheduled. */
	if (ospf->t_spf_calc) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"SPF: calculation timer is already scheduled: %p",
				(void *)ospf->t_spf_calc);
		return;
	}

	elapsed = monotime_since(&ospf->ts_spf, NULL) / 1000;

	ht = ospf->spf_holdtime * ospf->spf_hold_multiplier;

	if (ht > ospf->spf_max_holdtime)
		ht = ospf->spf_max_holdtime;

	/* Get SPF calculation delay time. */
	if (elapsed < ht) {
		/*
		 * Got an event within the hold time of last SPF. We need to
		 * increase the hold_multiplier, if it's not already at/past
		 * maximum value, and wasn't already increased.
		 */
		if (ht < ospf->spf_max_holdtime)
			ospf->spf_hold_multiplier++;

		/* always honour the SPF initial delay */
		if ((ht - elapsed) < ospf->spf_delay)
			delay = ospf->spf_delay;
		else
			delay = ht - elapsed;
	} else {
		/* Event is past required hold-time of last SPF */
		delay = ospf->spf_delay;
		ospf->spf_hold_multiplier = 1;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("SPF: calculation timer delay = %ld msec", delay);

	ospf->t_spf_calc = NULL;
	thread_add_timer_msec(master, ospf_spf_calculate_schedule_worker, ospf,
			      delay, &ospf->t_spf_calc);
}

/* Restart OSPF SPF algorithm*/
void ospf_restart_spf(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Restart SPF.", __func__);

	/* Handling inter area and intra area routes*/
	if (ospf->new_table) {
		ospf_route_delete(ospf, ospf->new_table);
		ospf_route_table_free(ospf->new_table);
		ospf->new_table = route_table_init();
	}

	/* Handling of TYPE-5 lsa(external routes) */
	if (ospf->old_external_route) {
		ospf_route_delete(ospf, ospf->old_external_route);
		ospf_route_table_free(ospf->old_external_route);
		ospf->old_external_route = route_table_init();
	}

	/* Trigger SPF */
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
}
