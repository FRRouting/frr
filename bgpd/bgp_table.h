// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP routing table
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_TABLE_H
#define _QUAGGA_BGP_TABLE_H

#include "mpls.h"
#include "table.h"
#include "queue.h"
#include "linklist.h"
#include "bgpd.h"
#include "bgp_advertise.h"

struct bgp_table {
	/* table belongs to this instance */
	struct bgp *bgp;

	/* afi/safi of this table */
	afi_t afi;
	safi_t safi;

	int lock;

	/* soft_reconfig_table in progress */
	bool soft_reconfig_init;
	struct event *soft_reconfig_thread;

	/* list of peers on which soft_reconfig_table has to run */
	struct list *soft_reconfig_peers;

	struct route_table *route_table;
	uint64_t version;
};

enum bgp_path_selection_reason {
	bgp_path_selection_none,
	bgp_path_selection_first,
	bgp_path_selection_evpn_sticky_mac,
	bgp_path_selection_evpn_seq,
	bgp_path_selection_evpn_local_path,
	bgp_path_selection_evpn_non_proxy,
	bgp_path_selection_evpn_lower_ip,
	bgp_path_selection_weight,
	bgp_path_selection_local_pref,
	bgp_path_selection_accept_own,
	bgp_path_selection_local_route,
	bgp_path_selection_aigp,
	bgp_path_selection_confed_as_path,
	bgp_path_selection_as_path,
	bgp_path_selection_origin,
	bgp_path_selection_med,
	bgp_path_selection_peer,
	bgp_path_selection_confed,
	bgp_path_selection_igp_metric,
	bgp_path_selection_older,
	bgp_path_selection_router_id,
	bgp_path_selection_cluster_length,
	bgp_path_selection_stale,
	bgp_path_selection_local_configured,
	bgp_path_selection_neighbor_ip,
	bgp_path_selection_default,
};

struct bgp_dest {
	struct route_node *rn;

	void *info;

	struct bgp_adj_out_rb adj_out;

	struct bgp_adj_in *adj_in;

	struct bgp_dest *pdest;

	STAILQ_ENTRY(bgp_dest) pq;

	uint64_t version;

	mpls_label_t local_label;

	uint16_t flags;
#define BGP_NODE_PROCESS_SCHEDULED	(1 << 0)
#define BGP_NODE_USER_CLEAR             (1 << 1)
#define BGP_NODE_LABEL_CHANGED          (1 << 2)
#define BGP_NODE_REGISTERED_FOR_LABEL   (1 << 3)
#define BGP_NODE_SELECT_DEFER           (1 << 4)
#define BGP_NODE_FIB_INSTALL_PENDING    (1 << 5)
#define BGP_NODE_FIB_INSTALLED          (1 << 6)
#define BGP_NODE_LABEL_REQUESTED        (1 << 7)
#define BGP_NODE_SOFT_RECONFIG (1 << 8)
#define BGP_NODE_PROCESS_CLEAR (1 << 9)

	struct bgp_addpath_node_data tx_addpath;

	enum bgp_path_selection_reason reason;
};

extern void bgp_delete_listnode(struct bgp_dest *dest);
/*
 * bgp_table_iter_t
 *
 * Structure that holds state for iterating over a bgp table.
 */
typedef struct bgp_table_iter_t_ {
	struct bgp_table *table;
	route_table_iter_t rt_iter;
} bgp_table_iter_t;

extern struct bgp_table *bgp_table_init(struct bgp *bgp, afi_t, safi_t);
extern void bgp_table_lock(struct bgp_table *);
extern void bgp_table_unlock(struct bgp_table *);
extern void bgp_table_finish(struct bgp_table **);
extern struct bgp_dest *bgp_dest_unlock_node(struct bgp_dest *dest);
extern struct bgp_dest *bgp_dest_lock_node(struct bgp_dest *dest);
extern const char *bgp_dest_get_prefix_str(struct bgp_dest *dest);


/*
 * bgp_dest_from_rnode
 *
 * Returns the bgp_dest structure corresponding to a route_node.
 */
static inline struct bgp_dest *bgp_dest_from_rnode(struct route_node *rnode)
{
	return (rnode && rnode->info) ? (struct bgp_dest *)rnode->info : NULL;
}

/*
 * bgp_dest_to_rnode
 *
 * Returns the route_node structure corresponding to a bgp_dest.
 */
static inline struct route_node *bgp_dest_to_rnode(const struct bgp_dest *dest)
{
	return dest ? dest->rn : NULL;
}

/*
 * bgp_dest_table
 *
 * Returns the bgp_table that the given dest is in.
 */
static inline struct bgp_table *bgp_dest_table(struct bgp_dest *dest)
{
	return route_table_get_info(bgp_dest_to_rnode(dest)->table);
}

/*
 * bgp_dest_parent_nolock
 *
 * Gets the parent dest of the given node without locking it.
 */
static inline struct bgp_dest *bgp_dest_parent_nolock(struct bgp_dest *dest)
{
	struct route_node *rn = bgp_dest_to_rnode(dest)->parent;

	while (rn && !rn->info)
		rn = rn->parent;

	return bgp_dest_from_rnode(rn);
}

/*
 * bgp_table_top_nolock
 *
 * Gets the top dest in the table without locking it.
 *
 * @see bgp_table_top
 */
static inline struct bgp_dest *
bgp_table_top_nolock(const struct bgp_table *const table)
{
	struct route_node *top;
	struct route_node *rn = top = table->route_table->top;

	while (rn && !rn->info) {
		if (rn == top)
			route_lock_node(rn);
		rn = route_next(rn);
	}
	if (rn && rn != top)
		route_unlock_node(rn);
	return rn ? rn->info : NULL;
}

/*
 * bgp_table_top
 */
static inline struct bgp_dest *
bgp_table_top(const struct bgp_table *const table)
{
	struct route_node *rn = route_top(table->route_table);

	while (rn && !rn->info)
		rn = route_next(rn);
	return rn ? rn->info : NULL;
}

/*
 * bgp_route_next
 */
static inline struct bgp_dest *bgp_route_next(struct bgp_dest *dest)
{
	struct route_node *rn = route_next(bgp_dest_to_rnode(dest));

	while (rn && !rn->info)
		rn = route_next(rn);
	return bgp_dest_from_rnode(rn);
}

/*
 * bgp_route_next_until
 */
static inline struct bgp_dest *bgp_route_next_until(struct bgp_dest *dest,
						    struct bgp_dest *limit)
{
	struct route_node *rnode;

	rnode = route_next_until(bgp_dest_to_rnode(dest),
			bgp_dest_to_rnode(limit));

	while (rnode && !rnode->info)
		rnode = route_next_until(rnode, bgp_dest_to_rnode(limit));

	return bgp_dest_from_rnode(rnode);
}

/*
 * bgp_node_get
 */
static inline struct bgp_dest *bgp_node_get(struct bgp_table *const table,
					    const struct prefix *p)
{
	struct route_node *rn = route_node_get(table->route_table, p);

	if (!rn->info) {
		struct bgp_dest *dest = XCALLOC(MTYPE_BGP_NODE,
						sizeof(struct bgp_dest));

		RB_INIT(bgp_adj_out_rb, &dest->adj_out);
		rn->info = dest;
		dest->rn = rn;
	}
	return rn->info;
}

/*
 * bgp_node_lookup
 */
static inline struct bgp_dest *
bgp_node_lookup(const struct bgp_table *const table, const struct prefix *p)
{
	struct route_node *rn = route_node_lookup(table->route_table, p);

	return bgp_dest_from_rnode(rn);
}

/*
 * bgp_node_match
 */
static inline struct bgp_dest *bgp_node_match(const struct bgp_table *table,
					      const struct prefix *p)
{
	struct route_node *rn = route_node_match(table->route_table, p);

	return bgp_dest_from_rnode(rn);
}

static inline unsigned long bgp_table_count(const struct bgp_table *const table)
{
	return route_table_count(table->route_table);
}

/*
 * bgp_table_get_next
 */
static inline struct bgp_dest *bgp_table_get_next(const struct bgp_table *table,
						  const struct prefix *p)
{
	struct route_node *rn = route_table_get_next(table->route_table, p);

	while (rn && !rn->info)
		rn = route_next(rn);
	return bgp_dest_from_rnode(rn);
}

/* This would benefit from a real atomic operation...
 * until then. */
static inline uint64_t bgp_table_next_version(struct bgp_table *table)
{
	return ++table->version;
}

static inline uint64_t bgp_table_version(struct bgp_table *table)
{
	return table->version;
}

/* Find the subtree of the prefix p
 *
 * This will return the first node that belongs the the subtree of p. Including
 * p itself, if it is in the tree.
 *
 * If the subtree is not present in the table, NULL is returned.
 */
struct bgp_dest *bgp_table_subtree_lookup(const struct bgp_table *table,
					  const struct prefix *p);

static inline struct bgp_aggregate *
bgp_dest_get_bgp_aggregate_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void
bgp_dest_set_bgp_aggregate_info(struct bgp_dest *dest,
				struct bgp_aggregate *aggregate)
{
	dest->info = aggregate;
}

static inline struct bgp_distance *
bgp_dest_get_bgp_distance_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void bgp_dest_set_bgp_distance_info(struct bgp_dest *dest,
						  struct bgp_distance *distance)
{
	dest->info = distance;
}

static inline struct bgp_static *
bgp_dest_get_bgp_static_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void bgp_dest_set_bgp_static_info(struct bgp_dest *dest,
						struct bgp_static *bgp_static)
{
	dest->info = bgp_static;
}

static inline struct bgp_connected_ref *
bgp_dest_get_bgp_connected_ref_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void
bgp_dest_set_bgp_connected_ref_info(struct bgp_dest *dest,
				    struct bgp_connected_ref *bc)
{
	dest->info = bc;
}

static inline struct bgp_nexthop_cache *
bgp_dest_get_bgp_nexthop_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void bgp_dest_set_bgp_nexthop_info(struct bgp_dest *dest,
						 struct bgp_nexthop_cache *bnc)
{
	dest->info = bnc;
}

static inline struct bgp_path_info *
bgp_dest_get_bgp_path_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void bgp_dest_set_bgp_path_info(struct bgp_dest *dest,
					      struct bgp_path_info *bi)
{
	dest->info = bi;
}

static inline struct bgp_table *
bgp_dest_get_bgp_table_info(struct bgp_dest *dest)
{
	return dest ? dest->info : NULL;
}

static inline void bgp_dest_set_bgp_table_info(struct bgp_dest *dest,
					       struct bgp_table *table)
{
	dest->info = table;
}

static inline bool bgp_dest_has_bgp_path_info_data(struct bgp_dest *dest)
{
	return dest ? !!dest->info : false;
}

static inline const struct prefix *bgp_dest_get_prefix(const struct bgp_dest *dest)
{
	return dest ? &dest->rn->p : NULL;
}

static inline unsigned int bgp_dest_get_lock_count(const struct bgp_dest *dest)
{
	return dest ? dest->rn->lock : 0;
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pRN"  (struct bgp_node *)
#pragma FRR printfrr_ext "%pBD"  (struct bgp_dest *)
#endif

#endif /* _QUAGGA_BGP_TABLE_H */
