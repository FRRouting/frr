// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Constraints Shortest Path First algorithms - cspf.c
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2022 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "log.h"
#include "hash.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "printfrr.h"
#include "link_state.h"
#include "cspf.h"

/* Link State Memory allocation */
DEFINE_MTYPE_STATIC(LIB, PCA, "Path Computation Algorithms");

/**
 * Create new Constrained Path. Memory is dynamically allocated.
 *
 * @param key	Vertex key of the destination of this path
 *
 * @return	Pointer to a new Constrained Path structure
 */
static struct c_path *cpath_new(uint64_t key)
{
	struct c_path *path;

	/* Sanity Check */
	if (key == 0)
		return NULL;

	path = XCALLOC(MTYPE_PCA, sizeof(struct c_path));
	path->dst = key;
	path->status = IN_PROGRESS;
	path->edges = list_new();
	path->weight = MAX_COST;

	return path;
}

/**
 * Copy src Constrained Path into dst Constrained Path. A new Constrained Path
 * structure is dynamically allocated if dst is NULL. If src is NULL, the
 * function return the dst disregarding if it is NULL or not.
 *
 * @param dest	Destination Constrained Path structure
 * @param src	Source Constrained Path structure
 *
 * @return	Pointer to the destination Constrained Path structure
 */
static struct c_path *cpath_copy(struct c_path *dest, const struct c_path *src)
{
	struct c_path *new_path;

	if (!src)
		return dest;

	if (!dest) {
		new_path = XCALLOC(MTYPE_PCA, sizeof(struct c_path));
	} else {
		new_path = dest;
		if (dest->edges)
			list_delete(&new_path->edges);
	}

	new_path->dst = src->dst;
	new_path->weight = src->weight;
	new_path->edges = list_dup(src->edges);
	new_path->status = src->status;

	return new_path;
}

/**
 * Delete Constrained Path structure. Previous allocated memory is freed.
 *
 * @param path	Constrained Path structure to be deleted
 */
void cpath_del(struct c_path *path)
{
	if (!path)
		return;

	if (path->edges)
		list_delete(&path->edges);

	XFREE(MTYPE_PCA, path);
	path = NULL;
}

/**
 * Replace the list of edges in the next Constrained Path by the list of edges
 * in the current Constrained Path.
 *
 * @param next_path	next Constrained Path structure
 * @param cur_path	current Constrained Path structure
 */
static void cpath_replace(struct c_path *next_path, struct c_path *cur_path)
{

	if (next_path->edges)
		list_delete(&next_path->edges);

	next_path->edges = list_dup(cur_path->edges);
}

/**
 * Create a new Visited Node structure from the provided Vertex. Structure is
 * dynamically allocated.
 *
 * @param vertex	Vertex structure
 *
 * @return		Pointer to the new Visited Node structure
 */
static struct v_node *vnode_new(struct ls_vertex *vertex)
{
	struct v_node *vnode;

	if (!vertex)
		return NULL;

	vnode = XCALLOC(MTYPE_PCA, sizeof(struct v_node));
	vnode->vertex = vertex;
	vnode->key = vertex->key;

	return vnode;
}

/**
 * Delete Visited Node structure. Previous allocated memory is freed.
 *
 * @param vnode		Visited Node structure to be deleted
 */
static void vnode_del(struct v_node *vnode)
{
	if (!vnode)
		return;

	XFREE(MTYPE_PCA, vnode);
	vnode = NULL;
}

/**
 * Search Vertex in TED by IPv4 address. The function search vertex by browsing
 * the subnets table. It allows to find not only vertex by router ID, but also
 * vertex by interface IPv4 address.
 *
 * @param ted	Traffic Engineering Database
 * @param ipv4	IPv4 address
 *
 * @return	Vertex if found, NULL otherwise
 */
static struct ls_vertex *get_vertex_by_ipv4(struct ls_ted *ted,
					    struct in_addr ipv4)
{
	struct ls_subnet *subnet;
	struct prefix p;

	p.family = AF_INET;
	p.u.prefix4 = ipv4;

	frr_each (subnets, &ted->subnets, subnet) {
		if (subnet->key.family != AF_INET)
			continue;
		p.prefixlen = subnet->key.prefixlen;
		if (prefix_same(&subnet->key, &p))
			return subnet->vertex;
	}

	return NULL;
}

/**
 * Search Vertex in TED by IPv6 address. The function search vertex by browsing
 * the subnets table. It allows to find not only vertex by router ID, but also
 * vertex by interface IPv6 address.
 *
 * @param ted	Traffic Engineering Database
 * @param ipv6	IPv6 address
 *
 * @return	Vertex if found, NULL otherwise
 */
static struct ls_vertex *get_vertex_by_ipv6(struct ls_ted *ted,
					    struct in6_addr ipv6)
{
	struct ls_subnet *subnet;
	struct prefix p;

	p.family = AF_INET6;
	p.u.prefix6 = ipv6;

	frr_each (subnets, &ted->subnets, subnet) {
		if (subnet->key.family != AF_INET6)
			continue;
		p.prefixlen = subnet->key.prefixlen;
		if (prefix_cmp(&subnet->key, &p) == 0)
			return subnet->vertex;
	}

	return NULL;
}

struct cspf *cspf_new(void)
{
	struct cspf *algo;

	/* Allocate New CSPF structure */
	algo = XCALLOC(MTYPE_PCA, sizeof(struct cspf));

	/* Initialize RB-Trees */
	processed_init(&algo->processed);
	visited_init(&algo->visited);
	pqueue_init(&algo->pqueue);

	algo->path = NULL;
	algo->pdst = NULL;

	return algo;
}

struct cspf *cspf_init(struct cspf *algo, const struct ls_vertex *src,
		       const struct ls_vertex *dst, struct constraints *csts)
{
	struct cspf *new_algo;
	struct c_path *psrc;

	if (!csts)
		return NULL;

	if (!algo)
		new_algo = cspf_new();
	else
		new_algo = algo;

	/* Initialize Processed Path and Priority Queue with Src & Dst */
	if (src) {
		psrc = cpath_new(src->key);
		psrc->weight = 0;
		processed_add(&new_algo->processed, psrc);
		pqueue_add(&new_algo->pqueue, psrc);
		new_algo->path = psrc;
	}
	if (dst) {
		new_algo->pdst = cpath_new(dst->key);
		processed_add(&new_algo->processed, new_algo->pdst);
	}

	memcpy(&new_algo->csts, csts, sizeof(struct constraints));

	return new_algo;
}

struct cspf *cspf_init_v4(struct cspf *algo, struct ls_ted *ted,
			  const struct in_addr src, const struct in_addr dst,
			  struct constraints *csts)
{
	struct ls_vertex *vsrc;
	struct ls_vertex *vdst;
	struct cspf *new_algo;

	/* Sanity Check */
	if (!ted)
		return algo;

	if (!algo)
		new_algo = cspf_new();
	else
		new_algo = algo;

	/* Got Source and Destination Vertex from TED */
	vsrc = get_vertex_by_ipv4(ted, src);
	vdst = get_vertex_by_ipv4(ted, dst);
	csts->family = AF_INET;

	return cspf_init(new_algo, vsrc, vdst, csts);
}

struct cspf *cspf_init_v6(struct cspf *algo, struct ls_ted *ted,
			  const struct in6_addr src, const struct in6_addr dst,
			  struct constraints *csts)
{
	struct ls_vertex *vsrc;
	struct ls_vertex *vdst;
	struct cspf *new_algo;

	/* Sanity Check */
	if (!ted)
		return algo;

	if (!algo)
		new_algo = cspf_new();
	else
		new_algo = algo;

	/* Got Source and Destination Vertex from TED */
	vsrc = get_vertex_by_ipv6(ted, src);
	vdst = get_vertex_by_ipv6(ted, dst);
	csts->family = AF_INET6;

	return cspf_init(new_algo, vsrc, vdst, csts);
}

void cspf_clean(struct cspf *algo)
{
	struct c_path *path;
	struct v_node *vnode;

	if (!algo)
		return;

	/* Normally, Priority Queue is empty. Clean it in case of. */
	if (pqueue_count(&algo->pqueue)) {
		frr_each_safe (pqueue, &algo->pqueue, path) {
			pqueue_del(&algo->pqueue, path);
		}
	}

	/* Empty Processed Path tree and associated Path */
	if (processed_count(&algo->processed)) {
		frr_each_safe (processed, &algo->processed, path) {
			processed_del(&algo->processed, path);
			if (path == algo->pdst)
				algo->pdst = NULL;
			cpath_del(path);
		}
	}

	/* Empty visited Vertex tree and associated Node */
	if (visited_count(&algo->visited)) {
		frr_each_safe (visited, &algo->visited, vnode) {
			visited_del(&algo->visited, vnode);
			vnode_del(vnode);
		}
	}

	if (algo->pdst)
		cpath_del(algo->pdst);

	memset(&algo->csts, 0, sizeof(struct constraints));
	algo->path = NULL;
	algo->pdst = NULL;
}

void cspf_del(struct cspf *algo)
{
	if (!algo)
		return;

	/* Empty Priority Queue and Processes Path */
	cspf_clean(algo);

	/* Then, reset Priority Queue, Processed Path and Visited RB-Tree */
	pqueue_fini(&algo->pqueue);
	processed_fini(&algo->processed);
	visited_fini(&algo->visited);

	XFREE(MTYPE_PCA, algo);
	algo = NULL;
}

/**
 * Prune Edge if constraints are not met by testing Edge Attributes against
 * given constraints and cumulative cost of the given constrained path.
 *
 * @param path	On-going Computed Path with cumulative cost constraints
 * @param edge	Edge to be validate against Constraints
 * @param csts	Constraints for this path
 *
 * @return	True if Edge should be prune, false if Edge is valid
 */
static bool prune_edge(const struct c_path *path, const struct ls_edge *edge,
		       const struct constraints *csts)
{
	struct ls_vertex *dst;
	struct ls_attributes *attr;

	/* Check that Path, Edge and Constraints are valid */
	if (!path || !edge || !csts)
		return true;

	/* Check that Edge has a valid destination */
	if (!edge->destination)
		return true;
	dst = edge->destination;

	/* Check that Edge has valid attributes */
	if (!edge->attributes)
		return true;
	attr = edge->attributes;

	/* Check that Edge belongs to the requested Address Family and type */
	if (csts->family == AF_INET) {
		if (IPV4_NET0(attr->standard.local.s_addr))
			return true;
		if (csts->type == SR_TE)
			if (!CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID) ||
			    !CHECK_FLAG(dst->node->flags, LS_NODE_SR))
				return true;
	}
	if (csts->family == AF_INET6) {
		if (IN6_IS_ADDR_UNSPECIFIED(&attr->standard.local6))
			return true;
		if (csts->type == SR_TE)
			if (!CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID6) ||
			    !CHECK_FLAG(dst->node->flags, LS_NODE_SR))
				return true;
	}

	/*
	 * Check that total cost, up to this edge, respects the initial
	 * constraints
	 */
	switch (csts->ctype) {
	case CSPF_METRIC:
		if (!CHECK_FLAG(attr->flags, LS_ATTR_METRIC))
			return true;
		if ((attr->metric + path->weight) > csts->cost)
			return true;
		break;

	case CSPF_TE_METRIC:
		if (!CHECK_FLAG(attr->flags, LS_ATTR_TE_METRIC))
			return true;
		if ((attr->standard.te_metric + path->weight) > csts->cost)
			return true;
		break;

	case CSPF_DELAY:
		if (!CHECK_FLAG(attr->flags, LS_ATTR_DELAY))
			return true;
		if ((attr->extended.delay + path->weight) > csts->cost)
			return true;
		break;
	}

	/* If specified, check that Edge meet Bandwidth constraint */
	if (csts->bw > 0.0) {
		if (attr->standard.max_bw < csts->bw ||
		    attr->standard.max_rsv_bw < csts->bw ||
		    attr->standard.unrsv_bw[csts->cos] < csts->bw)
			return true;
	}

	/* All is fine. We can consider this Edge valid, so not to be prune */
	return false;
}

/**
 * Relax constraints of the current path up to the destination vertex of the
 * provided Edge. This function progress in the network topology by validating
 * the next vertex on the computed path. If Vertex has not already been visited,
 * list of edges of the current path is augmented with this edge if the new cost
 * is lower than prior path up to this vertex. Current path is re-inserted in
 * the Priority Queue with its new cost i.e. current cost + edge cost.
 *
 * @param algo	CSPF structure
 * @param edge	Next Edge to be added to the current computed path
 *
 * @return	True if current path reach destination, false otherwise
 */
static bool relax_constraints(struct cspf *algo, struct ls_edge *edge)
{

	struct c_path pkey = {};
	struct c_path *next_path;
	struct v_node vnode = {};
	uint32_t total_cost = MAX_COST;

	/* Verify that we have a current computed path */
	if (!algo->path)
		return false;

	/* Verify if we have not visited the next Vertex to avoid loop */
	vnode.key = edge->destination->key;
	if (visited_member(&algo->visited, &vnode)) {
		return false;
	}

	/*
	 * Get Next Computed Path from next vertex key
	 * or create a new one if it has not yet computed.
	 */
	pkey.dst = edge->destination->key;
	next_path = processed_find(&algo->processed, &pkey);
	if (!next_path) {
		next_path = cpath_new(pkey.dst);
		processed_add(&algo->processed, next_path);
	}

	/*
	 * Add or update the Computed Path in the Priority Queue if total cost
	 * is lower than cost associated to this next Vertex. This could occurs
	 * if we process a Vertex that as not yet been visited in the Graph
	 * or if we found a shortest path up to this Vertex.
	 */
	switch (algo->csts.ctype) {
	case CSPF_METRIC:
		total_cost = edge->attributes->metric + algo->path->weight;
		break;
	case CSPF_TE_METRIC:
		total_cost = edge->attributes->standard.te_metric +
			     algo->path->weight;
		break;
	case CSPF_DELAY:
		total_cost =
			edge->attributes->extended.delay + algo->path->weight;
		break;
	default:
		break;
	}
	if (total_cost < next_path->weight) {
		/*
		 * It is not possible to directly update the q_path in the
		 * Priority Queue. Indeed, if we modify the path weight, the
		 * Priority Queue must be re-ordered. So, we need fist to remove
		 * the q_path if it is present in the Priority Queue, then,
		 * update the Path, in particular the Weight, and finally
		 * (re-)insert it in the Priority Queue.
		 */
		struct c_path *path;
		frr_each_safe (pqueue, &algo->pqueue, path) {
			if (path->dst == pkey.dst) {
				pqueue_del(&algo->pqueue, path);
				break;
			}
		}
		next_path->weight = total_cost;
		cpath_replace(next_path, algo->path);
		listnode_add(next_path->edges, edge);
		pqueue_add(&algo->pqueue, next_path);
	}

	/* Return True if we reach the destination */
	return (next_path->dst == algo->pdst->dst);
}

struct c_path *compute_p2p_path(struct cspf *algo, struct ls_ted *ted)
{
	struct listnode *node;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct c_path *optim_path;
	struct v_node *vnode;
	uint32_t cur_cost;

	optim_path = cpath_new(0xFFFFFFFFFFFFFFFF);
	optim_path->status = FAILED;

	/* Check that all is correctly initialized */
	if (!algo)
		return optim_path;

	if (!algo->csts.ctype)
		return optim_path;

	if (!algo->pdst) {
		optim_path->status = NO_DESTINATION;
		return optim_path;
	}

	if (!algo->path) {
		optim_path->status = NO_SOURCE;
		return optim_path;
	}

	if (algo->pdst->dst == algo->path->dst) {
		optim_path->status = SAME_SRC_DST;
		return optim_path;
	}

	optim_path->dst = algo->pdst->dst;
	optim_path->status = IN_PROGRESS;

	/*
	 * Process all Connected Vertex until priority queue becomes empty.
	 * Connected Vertices are added into the priority queue when
	 * processing the next Connected Vertex: see relax_constraints()
	 */
	cur_cost = MAX_COST;
	while (pqueue_count(&algo->pqueue) != 0) {
		/* Got shortest current Path from the Priority Queue */
		algo->path = pqueue_pop(&algo->pqueue);

		/* Add destination Vertex of this path to the visited RB Tree */
		vertex = ls_find_vertex_by_key(ted, algo->path->dst);
		if (!vertex)
			continue;
		vnode = vnode_new(vertex);
		visited_add(&algo->visited, vnode);

		/* Process all outgoing links from this Vertex */
		for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge)) {
			/*
			 * Skip Connected Edges that must be prune i.e.
			 * Edges that not satisfy the given constraints,
			 * in particular the Bandwidth, TE Metric and Delay.
			 */
			if (prune_edge(algo->path, edge, &algo->csts))
				continue;

			/*
			 * Relax constraints and check if we got a shorter
			 * candidate path
			 */
			if (relax_constraints(algo, edge) &&
			    algo->pdst->weight < cur_cost) {
				cur_cost = algo->pdst->weight;
				cpath_copy(optim_path, algo->pdst);
				optim_path->status = SUCCESS;
			}
		}
	}

	/*
	 * The priority queue is empty => all the possible (vertex, path)
	 * elements have been explored. The optim_path contains the optimal
	 * path if it exists. Otherwise an empty path with status failed is
	 * returned.
	 */
	if (optim_path->status == IN_PROGRESS ||
	    listcount(optim_path->edges) == 0)
		optim_path->status = FAILED;
	cspf_clean(algo);

	return optim_path;
}
