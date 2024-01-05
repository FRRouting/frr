// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Nexthop Group Private Functions.
 * Copyright (C) 2023 6WIND
 */

/**
 * These functions should only be used internally for BGP NHG handling
 * manipulation and in certain special cases.
 *
 * Please use `bgpd/bgp_nhg.h` for any general BGP NHG api need
 */

#ifndef __BGP_NHG_PRIVATE_H__
#define __BGP_NHG_PRIVATE_H__

#include "bgpd/bgp_nhg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Abstraction for BGP connected trees */
struct bgp_nhg_connected {
	struct bgp_nhg_connected_tree_item tree_item;
	struct bgp_nhg_cache *nhg;
};

static int bgp_nhg_connected_cmp(const struct bgp_nhg_connected *con1,
				 const struct bgp_nhg_connected *con2)
{
	return (con1->nhg->id - con2->nhg->id);
}

DECLARE_RBTREE_UNIQ(bgp_nhg_connected_tree, struct bgp_nhg_connected, tree_item,
		    bgp_nhg_connected_cmp);

/* bgp nhg connected tree direct access functions */
extern void bgp_nhg_connected_tree_init(struct bgp_nhg_connected_tree_head *head);
extern void bgp_nhg_connected_tree_free(struct bgp_nhg_connected_tree_head *head);

/* I realize _add/_del returns are backwords.
 *
 * Currently the list APIs are not standardized for what happens in
 * the _del() function when the item isn't present.
 *
 * We are choosing to return NULL if not found in the _del case for now.
 */

/* Delete NHE from the tree. On success, return the NHE, otherwise NULL. */
extern struct bgp_nhg_cache *
bgp_nhg_connected_tree_del_nhg(struct bgp_nhg_connected_tree_head *head,
			       struct bgp_nhg_cache *nhg);
/* ADD NHE to the tree. On success, return NULL, otherwise return the NHE. */
extern struct bgp_nhg_cache *
bgp_nhg_connected_tree_add_nhg(struct bgp_nhg_connected_tree_head *head,
			       struct bgp_nhg_cache *nhe);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NHG_PRIVATE_H__ */
