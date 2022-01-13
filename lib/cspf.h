/*
 * Constraints Shortest Path First algorithms definition - cspf.h
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2022 Orange http://www.orange.com
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_CSPF_H_
#define _FRR_CSPF_H_

#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file defines the different structure used for Path Computation with
 * various constrained. Up to now, standard metric, TE metric, delay and
 * bandwidth constraints are supported.
 * All proposed algorithms used the same principle:
 *  - A pruning function that keeps only links that meet constraints
 *  - A priority Queue that keeps the shortest on-going computed path
 *  - A main loop over all vertices to find the shortest path
 */

#define MAX_COST	0xFFFFFFFF

/* Status of the path */
enum path_status {
	FAILED = 0,
	NO_SOURCE,
	NO_DESTINATION,
	SAME_SRC_DST,
	IN_PROGRESS,
	SUCCESS
};
enum path_type {RSVP_TE = 1, SR_TE, SRV6_TE};
enum metric_type {CSPF_METRIC = 1, CSPF_TE_METRIC, CSPF_DELAY};

/* Constrained metrics structure */
struct constraints {
	uint32_t cost;		/* total cost (metric) of the path */
	enum metric_type ctype;	/* Metric Type: standard, TE or Delay */
	float bw;		/* bandwidth of the path */
	uint8_t cos;		/* Class of Service of the path */
	enum path_type type;	/* RSVP-TE or SR-TE path */
	uint8_t family;		/* AF_INET or AF_INET6 address family */
};

/* Priority Queue for Constrained Path Computation */
PREDECL_RBTREE_NONUNIQ(pqueue);

/* Processed Path for Constrained Path Computation */
PREDECL_RBTREE_UNIQ(processed);

/* Constrained Path structure */
struct c_path {
	struct pqueue_item q_itm;    /* entry in the Priority Queue */
	uint32_t weight;             /* Weight to sort path in Priority Queue */
	struct processed_item p_itm; /* entry in the Processed RB Tree */
	uint64_t dst;                /* Destination vertex key of this path */
	struct list *edges;          /* List of Edges that compose this path */
	enum path_status status;     /* status of the computed path */
};

macro_inline int q_cmp(const struct c_path *p1, const struct c_path *p2)
{
	return numcmp(p1->weight, p2->weight);
}
DECLARE_RBTREE_NONUNIQ(pqueue, struct c_path, q_itm, q_cmp);

macro_inline int p_cmp(const struct c_path *p1, const struct c_path *p2)
{
	return numcmp(p1->dst, p2->dst);
}
DECLARE_RBTREE_UNIQ(processed, struct c_path, p_itm, p_cmp);

/* List of visited node */
PREDECL_RBTREE_UNIQ(visited);
struct v_node {
	struct visited_item item; /* entry in the Processed RB Tree */
	uint64_t key;
	struct ls_vertex *vertex;
};

macro_inline int v_cmp(const struct v_node *p1, const struct v_node *p2)
{
	return numcmp(p1->key, p2->key);
}
DECLARE_RBTREE_UNIQ(visited, struct v_node, item, v_cmp);

/* Path Computation algorithms structure */
struct cspf {
	struct pqueue_head pqueue;       /* Priority Queue */
	struct processed_head processed; /* Paths that have been processed */
	struct visited_head visited;     /* Vertices that have been visited */
	struct constraints csts;         /* Constraints of the path */
	struct c_path *path;             /* Current Computed Path */
	struct c_path *pdst;             /* Computed Path to the destination */
};

/**
 * Create a new CSPF structure. Memory is dynamically allocated.
 *
 * @return	pointer to the new cspf structure
 */
extern struct cspf *cspf_new(void);

/**
 * Initialize CSPF structure prior to compute a constrained path. If CSPF
 * structure is NULL, a new CSPF is dynamically allocated prior to the
 * configuration itself.
 *
 * @param algo	CSPF structure, may be null if a new CSPF must be created
 * @param src	Source vertex of the requested path
 * @param dst	Destination vertex of the requested path
 * @param csts	Constraints of the requested path
 *
 * @return	pointer to the initialized CSPF structure
 */
extern struct cspf *cspf_init(struct cspf *algo, const struct ls_vertex *src,
			      const struct ls_vertex *dst,
			      struct constraints *csts);

/**
 * Initialize CSPF structure prior to compute a constrained path. If CSPF
 * structure is NULL, a new CSPF is dynamically allocated prior to the
 * configuration itself. This function starts by searching source and
 * destination vertices from the IPv4 addresses in the provided TED.
 *
 * @param algo	CSPF structure, may be null if a new CSPF must be created
 * @param ted	Traffic Engineering Database
 * @param src	Source IPv4 address of the requested path
 * @param dst	Destination IPv4 address of the requested path
 * @param csts	Constraints of the requested path
 *
 * @return	pointer to the initialized CSPF structure
 */
extern struct cspf *cspf_init_v4(struct cspf *algo, struct ls_ted *ted,
				 const struct in_addr src,
				 const struct in_addr dst,
				 struct constraints *csts);

/**
 * Initialize CSPF structure prior to compute a constrained path. If CSPF
 * structure is NULL, a new CSPF is dynamically allocated prior to the
 * configuration itself. This function starts by searching source and
 * destination vertices from the IPv6 addresses in the provided TED.
 *
 * @param algo	CSPF structure, may be null if a new CSPF must be created
 * @param ted	Traffic Engineering Database
 * @param src	Source IPv6 address of the requested path
 * @param dst	Destination IPv6 address of the requested path
 * @param csts	Constraints of the requested path
 *
 * @return	pointer to the initialized CSPF structure
 */
extern struct cspf *cspf_init_v6(struct cspf *algo, struct ls_ted *ted,
				 const struct in6_addr src,
				 const struct in6_addr dst,
				 struct constraints *csts);

/**
 * Clean CSPF structure. Reset all internal list and priority queue for latter
 * initialization of the CSPF structure and new path computation.
 *
 * @param algo	CSPF structure
 */
extern void cspf_clean(struct cspf *algo);

/**
 * Delete CSPF structure, internal list and priority queue.
 *
 * @param algo	CSPF structure
 */
extern void cspf_del(struct cspf *algo);

/**
 * Compute point-to-point constrained path. cspf_init() function must be call
 * prior to call this function.
 *
 * @param algo	CSPF structure
 * @param ted	Traffic Engineering Database
 *
 * @return	Constrained Path with status to indicate computation success
 */
extern struct c_path *compute_p2p_path(struct cspf *algo, struct ls_ted *ted);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CSPF_H_ */
