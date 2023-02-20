// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Routing Table functions.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#define FRR_COMPILING_TABLE_C

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "sockunion.h"
#include "libfrr_trace.h"

DEFINE_MTYPE_STATIC(LIB, ROUTE_TABLE, "Route table");
DEFINE_MTYPE(LIB, ROUTE_NODE, "Route node");

static void route_table_free(struct route_table *);

static int route_table_hash_cmp(const struct route_node *a,
				const struct route_node *b)
{
	return prefix_cmp(&a->p, &b->p);
}

DECLARE_HASH(rn_hash_node, struct route_node, nodehash, route_table_hash_cmp,
	     prefix_hash_key);
/*
 * route_table_init_with_delegate
 */
struct route_table *
route_table_init_with_delegate(route_table_delegate_t *delegate)
{
	struct route_table *rt;

	rt = XCALLOC(MTYPE_ROUTE_TABLE, sizeof(struct route_table));
	rt->delegate = delegate;
	rn_hash_node_init(&rt->hash);
	return rt;
}

void route_table_finish(struct route_table *rt)
{
	route_table_free(rt);
}

/* Allocate new route node. */
static struct route_node *route_node_new(struct route_table *table)
{
	return table->delegate->create_node(table->delegate, table);
}

/* Allocate new route node with prefix set. */
static struct route_node *route_node_set(struct route_table *table,
					 const struct prefix *prefix)
{
	struct route_node *node;

	node = route_node_new(table);

	prefix_copy(&node->p, prefix);
	node->table = table;

	rn_hash_node_add(&node->table->hash, node);

	return node;
}

/* Free route node. */
static void route_node_free(struct route_table *table, struct route_node *node)
{
	if (table->cleanup)
		table->cleanup(table, node);
	table->delegate->destroy_node(table->delegate, table, node);
}

/* Free route table. */
static void route_table_free(struct route_table *rt)
{
	struct route_node *tmp_node;
	struct route_node *node;

	if (rt == NULL)
		return;

	node = rt->top;

	/* Bulk deletion of nodes remaining in this table.  This function is not
	   called until workers have completed their dependency on this table.
	   A final route_unlock_node() will not be called for these nodes. */
	while (node) {
		if (node->l_left) {
			node = node->l_left;
			continue;
		}

		if (node->l_right) {
			node = node->l_right;
			continue;
		}

		tmp_node = node;
		node = node->parent;

		tmp_node->table->count--;
		tmp_node->lock =
			0; /* to cause assert if unlocked after this */
		rn_hash_node_del(&rt->hash, tmp_node);
		route_node_free(rt, tmp_node);

		if (node != NULL) {
			if (node->l_left == tmp_node)
				node->l_left = NULL;
			else
				node->l_right = NULL;
		} else {
			break;
		}
	}

	assert(rt->count == 0);

	rn_hash_node_fini(&rt->hash);
	XFREE(MTYPE_ROUTE_TABLE, rt);
	return;
}

/* Utility mask array. */
static const uint8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
				  0xf8, 0xfc, 0xfe, 0xff};

/* Common prefix route genaration. */
static void route_common(const struct prefix *n, const struct prefix *p,
			 struct prefix *new)
{
	int i;
	uint8_t diff;
	uint8_t mask;
	const uint8_t *np;
	const uint8_t *pp;
	uint8_t *newp;

	if (n->family == AF_FLOWSPEC)
		return prefix_copy(new, p);
	np = (const uint8_t *)&n->u.prefix;
	pp = (const uint8_t *)&p->u.prefix;

	newp = &new->u.prefix;

	for (i = 0; i < p->prefixlen / 8; i++) {
		if (np[i] == pp[i])
			newp[i] = np[i];
		else
			break;
	}

	new->prefixlen = i * 8;

	if (new->prefixlen != p->prefixlen) {
		diff = np[i] ^ pp[i];
		mask = 0x80;
		while (new->prefixlen < p->prefixlen && !(mask & diff)) {
			mask >>= 1;
			new->prefixlen++;
		}
		newp[i] = np[i] & maskbit[new->prefixlen % 8];
	}
}

static void set_link(struct route_node *node, struct route_node *new)
{
	unsigned int bit = prefix_bit(&new->p.u.prefix, node->p.prefixlen);

	node->link[bit] = new;
	new->parent = node;
}

/* Find matched prefix. */
struct route_node *route_node_match(struct route_table *table,
				    union prefixconstptr pu)
{
	const struct prefix *p = pu.p;
	struct route_node *node;
	struct route_node *matched;

	matched = NULL;
	node = table->top;

	/* Walk down tree.  If there is matched route then store it to
	   matched. */
	while (node && node->p.prefixlen <= p->prefixlen
	       && prefix_match(&node->p, p)) {
		if (node->info)
			matched = node;

		if (node->p.prefixlen == p->prefixlen)
			break;

		node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
	}

	/* If matched route found, return it. */
	if (matched)
		return route_lock_node(matched);

	return NULL;
}

struct route_node *route_node_match_ipv4(struct route_table *table,
					 const struct in_addr *addr)
{
	struct prefix_ipv4 p;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = *addr;

	return route_node_match(table, (struct prefix *)&p);
}

struct route_node *route_node_match_ipv6(struct route_table *table,
					 const struct in6_addr *addr)
{
	struct prefix_ipv6 p;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	p.prefix = *addr;

	return route_node_match(table, &p);
}

/* Lookup same prefix node.  Return NULL when we can't find route. */
struct route_node *route_node_lookup(struct route_table *table,
				     union prefixconstptr pu)
{
	struct route_node rn, *node;
	prefix_copy(&rn.p, pu.p);
	apply_mask(&rn.p);

	node = rn_hash_node_find(&table->hash, &rn);
	return (node && node->info) ? route_lock_node(node) : NULL;
}

/* Lookup same prefix node.  Return NULL when we can't find route. */
struct route_node *route_node_lookup_maynull(struct route_table *table,
					     union prefixconstptr pu)
{
	struct route_node rn, *node;
	prefix_copy(&rn.p, pu.p);
	apply_mask(&rn.p);

	node = rn_hash_node_find(&table->hash, &rn);
	return node ? route_lock_node(node) : NULL;
}

/* Add node to routing table. */
struct route_node *route_node_get(struct route_table *table,
				  union prefixconstptr pu)
{
	if (frrtrace_enabled(frr_libfrr, route_node_get)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(pu, buf, sizeof(buf));
		frrtrace(2, frr_libfrr, route_node_get, table, buf);
	}

	struct route_node search;
	struct prefix *p = &search.p;

	prefix_copy(p, pu.p);
	apply_mask(p);

	struct route_node *new;
	struct route_node *node;
	struct route_node *match;
	uint16_t prefixlen = p->prefixlen;
	const uint8_t *prefix = &p->u.prefix;

	node = rn_hash_node_find(&table->hash, &search);
	if (node && node->info)
		return route_lock_node(node);

	match = NULL;
	node = table->top;
	while (node && node->p.prefixlen <= prefixlen
	       && prefix_match(&node->p, p)) {
		if (node->p.prefixlen == prefixlen)
			return route_lock_node(node);

		match = node;
		node = node->link[prefix_bit(prefix, node->p.prefixlen)];
	}

	if (node == NULL) {
		new = route_node_set(table, p);
		if (match)
			set_link(match, new);
		else
			table->top = new;
	} else {
		new = route_node_new(table);
		route_common(&node->p, p, &new->p);
		new->p.family = p->family;
		new->table = table;
		set_link(new, node);
		rn_hash_node_add(&table->hash, new);

		if (match)
			set_link(match, new);
		else
			table->top = new;

		if (new->p.prefixlen != p->prefixlen) {
			match = new;
			new = route_node_set(table, p);
			set_link(match, new);
			table->count++;
		}
	}
	table->count++;
	route_lock_node(new);

	return new;
}

/* Delete node from the routing table. */
void route_node_delete(struct route_node *node)
{
	struct route_node *child;
	struct route_node *parent;

	assert(node->lock == 0);
	assert(node->info == NULL);

	if (node->l_left && node->l_right)
		return;

	if (node->l_left)
		child = node->l_left;
	else
		child = node->l_right;

	parent = node->parent;

	if (child)
		child->parent = parent;

	if (parent) {
		if (parent->l_left == node)
			parent->l_left = child;
		else
			parent->l_right = child;
	} else
		node->table->top = child;

	node->table->count--;

	rn_hash_node_del(&node->table->hash, node);

	/* WARNING: FRAGILE CODE!
	 * route_node_free may have the side effect of free'ing the entire
	 * table.
	 * this is permitted only if table->count got decremented to zero above,
	 * because in that case parent will also be NULL, so that we won't try
	 * to
	 * delete a now-stale parent below.
	 *
	 * cf. srcdest_srcnode_destroy() in zebra/zebra_rib.c */

	route_node_free(node->table, node);

	/* If parent node is stub then delete it also. */
	if (parent && parent->lock == 0)
		route_node_delete(parent);
}

/* Get first node and lock it.  This function is useful when one wants
   to lookup all the node exist in the routing table. */
struct route_node *route_top(struct route_table *table)
{
	/* If there is no node in the routing table return NULL. */
	if (table->top == NULL)
		return NULL;

	/* Lock the top node and return it. */
	route_lock_node(table->top);
	return table->top;
}

/* Unlock current node and lock next node then return it. */
struct route_node *route_next(struct route_node *node)
{
	struct route_node *next;
	struct route_node *start;

	/* Node may be deleted from route_unlock_node so we have to preserve
	   next node's pointer. */

	if (node->l_left) {
		next = node->l_left;
		route_lock_node(next);
		route_unlock_node(node);
		return next;
	}
	if (node->l_right) {
		next = node->l_right;
		route_lock_node(next);
		route_unlock_node(node);
		return next;
	}

	start = node;
	while (node->parent) {
		if (node->parent->l_left == node && node->parent->l_right) {
			next = node->parent->l_right;
			route_lock_node(next);
			route_unlock_node(start);
			return next;
		}
		node = node->parent;
	}
	route_unlock_node(start);
	return NULL;
}

/* Unlock current node and lock next node until limit. */
struct route_node *route_next_until(struct route_node *node,
				    const struct route_node *limit)
{
	struct route_node *next;
	struct route_node *start;

	/* Node may be deleted from route_unlock_node so we have to preserve
	   next node's pointer. */

	if (node->l_left) {
		next = node->l_left;
		route_lock_node(next);
		route_unlock_node(node);
		return next;
	}
	if (node->l_right) {
		next = node->l_right;
		route_lock_node(next);
		route_unlock_node(node);
		return next;
	}

	start = node;
	while (node->parent && node != limit) {
		if (node->parent->l_left == node && node->parent->l_right) {
			next = node->parent->l_right;
			route_lock_node(next);
			route_unlock_node(start);
			return next;
		}
		node = node->parent;
	}
	route_unlock_node(start);
	return NULL;
}

unsigned long route_table_count(struct route_table *table)
{
	return table->count;
}

/**
 * route_node_create
 *
 * Default function for creating a route node.
 */
struct route_node *route_node_create(route_table_delegate_t *delegate,
				     struct route_table *table)
{
	struct route_node *node;
	node = XCALLOC(MTYPE_ROUTE_NODE, sizeof(struct route_node));
	return node;
}

/**
 * route_node_destroy
 *
 * Default function for destroying a route node.
 */
void route_node_destroy(route_table_delegate_t *delegate,
			struct route_table *table, struct route_node *node)
{
	XFREE(MTYPE_ROUTE_NODE, node);
}

/*
 * Default delegate.
 */
static route_table_delegate_t default_delegate = {
	.create_node = route_node_create,
	.destroy_node = route_node_destroy};

route_table_delegate_t *route_table_get_default_delegate(void)
{
	return &default_delegate;
}

/*
 * route_table_init
 */
struct route_table *route_table_init(void)
{
	return route_table_init_with_delegate(&default_delegate);
}

/**
 * route_table_prefix_iter_cmp
 *
 * Compare two prefixes according to the order in which they appear in
 * an iteration over a tree.
 *
 * @return -1 if p1 occurs before p2 (p1 < p2)
 *          0 if the prefixes are identical (p1 == p2)
 *         +1 if p1 occurs after p2 (p1 > p2)
 */
int route_table_prefix_iter_cmp(const struct prefix *p1,
				const struct prefix *p2)
{
	struct prefix common_space;
	struct prefix *common = &common_space;

	if (p1->prefixlen <= p2->prefixlen) {
		if (prefix_match(p1, p2)) {

			/*
			 * p1 contains p2, or is equal to it.
			 */
			return (p1->prefixlen == p2->prefixlen) ? 0 : -1;
		}
	} else {

		/*
		 * Check if p2 contains p1.
		 */
		if (prefix_match(p2, p1))
			return 1;
	}

	route_common(p1, p2, common);
	assert(common->prefixlen < p1->prefixlen);
	assert(common->prefixlen < p2->prefixlen);

	/*
	 * Both prefixes are longer than the common prefix.
	 *
	 * We need to check the bit after the common prefixlen to determine
	 * which one comes later.
	 */
	if (prefix_bit(&p1->u.prefix, common->prefixlen)) {

		/*
		 * We branch to the right to get to p1 from the common prefix.
		 */
		assert(!prefix_bit(&p2->u.prefix, common->prefixlen));
		return 1;
	}

	/*
	 * We branch to the right to get to p2 from the common prefix.
	 */
	assert(prefix_bit(&p2->u.prefix, common->prefixlen));
	return -1;
}

/*
 * route_get_subtree_next
 *
 * Helper function that returns the first node that follows the nodes
 * in the sub-tree under 'node' in iteration order.
 */
static struct route_node *route_get_subtree_next(struct route_node *node)
{
	while (node->parent) {
		if (node->parent->l_left == node && node->parent->l_right)
			return node->parent->l_right;

		node = node->parent;
	}

	return NULL;
}

/**
 * route_table_get_next_internal
 *
 * Helper function to find the node that occurs after the given prefix in
 * order of iteration.
 *
 * @see route_table_get_next
 */
static struct route_node *
route_table_get_next_internal(struct route_table *table,
			      const struct prefix *p)
{
	struct route_node *node, *tmp_node;
	int cmp;

	node = table->top;

	while (node) {
		int match;

		if (node->p.prefixlen < p->prefixlen)
			match = prefix_match(&node->p, p);
		else
			match = prefix_match(p, &node->p);

		if (match) {
			if (node->p.prefixlen == p->prefixlen) {

				/*
				 * The prefix p exists in the tree, just return
				 * the next
				 * node.
				 */
				route_lock_node(node);
				node = route_next(node);
				if (node)
					route_unlock_node(node);

				return (node);
			}

			if (node->p.prefixlen > p->prefixlen) {

				/*
				 * Node is in the subtree of p, and hence
				 * greater than p.
				 */
				return node;
			}

			/*
			 * p is in the sub-tree under node.
			 */
			tmp_node = node->link[prefix_bit(&p->u.prefix,
							 node->p.prefixlen)];

			if (tmp_node) {
				node = tmp_node;
				continue;
			}

			/*
			 * There are no nodes in the direction where p should
			 * be. If
			 * node has a right child, then it must be greater than
			 * p.
			 */
			if (node->l_right)
				return node->l_right;

			/*
			 * No more children to follow, go upwards looking for
			 * the next
			 * node.
			 */
			return route_get_subtree_next(node);
		}

		/*
		 * Neither node prefix nor 'p' contains the other.
		 */
		cmp = route_table_prefix_iter_cmp(&node->p, p);
		if (cmp > 0) {

			/*
			 * Node follows p in iteration order. Return it.
			 */
			return node;
		}

		assert(cmp < 0);

		/*
		 * Node and the subtree under it come before prefix p in
		 * iteration order. Prefix p and its sub-tree are not present in
		 * the tree. Go upwards and find the first node that follows the
		 * subtree. That node will also succeed p.
		 */
		return route_get_subtree_next(node);
	}

	return NULL;
}

/**
 * route_table_get_next
 *
 * Find the node that occurs after the given prefix in order of
 * iteration.
 */
struct route_node *route_table_get_next(struct route_table *table,
					union prefixconstptr pu)
{
	const struct prefix *p = pu.p;
	struct route_node *node;

	node = route_table_get_next_internal(table, p);
	if (node) {
		assert(route_table_prefix_iter_cmp(&node->p, p) > 0);
		route_lock_node(node);
	}
	return node;
}

/*
 * route_table_iter_init
 */
void route_table_iter_init(route_table_iter_t *iter, struct route_table *table)
{
	memset(iter, 0, sizeof(*iter));
	iter->state = RT_ITER_STATE_INIT;
	iter->table = table;
}

/*
 * route_table_iter_pause
 *
 * Pause an iteration over the table. This allows the iteration to be
 * resumed point after arbitrary additions/deletions from the table.
 * An iteration can be resumed by just calling route_table_iter_next()
 * on the iterator.
 */
void route_table_iter_pause(route_table_iter_t *iter)
{
	switch (iter->state) {

	case RT_ITER_STATE_INIT:
	case RT_ITER_STATE_PAUSED:
	case RT_ITER_STATE_DONE:
		return;

	case RT_ITER_STATE_ITERATING:

		/*
		 * Save the prefix that we are currently at. The next call to
		 * route_table_iter_next() will return the node after this
		 * prefix
		 * in the tree.
		 */
		prefix_copy(&iter->pause_prefix, &iter->current->p);
		route_unlock_node(iter->current);
		iter->current = NULL;
		iter->state = RT_ITER_STATE_PAUSED;
		return;

	default:
		assert(0);
	}
}

/*
 * route_table_iter_cleanup
 *
 * Release any resources held by the iterator.
 */
void route_table_iter_cleanup(route_table_iter_t *iter)
{
	if (iter->state == RT_ITER_STATE_ITERATING) {
		route_unlock_node(iter->current);
		iter->current = NULL;
	}
	assert(!iter->current);

	/*
	 * Set the state to RT_ITER_STATE_DONE to make any
	 * route_table_iter_next() calls on this iterator return NULL.
	 */
	iter->state = RT_ITER_STATE_DONE;
}
