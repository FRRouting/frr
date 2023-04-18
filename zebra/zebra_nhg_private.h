// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Nexthop Group Private Functions.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
 */

/**
 * These functions should only be used internally for nhg_hash_entry
 * manipulation and in certain special cases.
 *
 * Please use `zebra/zebra_nhg.h` for any general nhg_hash_entry api needs.
 */

#ifndef __ZEBRA_NHG_PRIVATE_H__
#define __ZEBRA_NHG_PRIVATE_H__

#include "zebra/zebra_nhg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Abstraction for connected trees */
struct nhg_connected {
	struct nhg_connected_tree_item tree_item;
	struct nhg_hash_entry *nhe;
};

static int nhg_connected_cmp(const struct nhg_connected *con1,
			     const struct nhg_connected *con2)
{
	return (con1->nhe->id - con2->nhe->id);
}

DECLARE_RBTREE_UNIQ(nhg_connected_tree, struct nhg_connected, tree_item,
		    nhg_connected_cmp);

/* nhg connected tree direct access functions */
extern void nhg_connected_tree_init(struct nhg_connected_tree_head *head);
extern void nhg_connected_tree_free(struct nhg_connected_tree_head *head);
extern bool
nhg_connected_tree_is_empty(const struct nhg_connected_tree_head *head);
extern struct nhg_connected *
nhg_connected_tree_root(struct nhg_connected_tree_head *head);

/* I realize _add/_del returns are backwords.
 *
 * Currently the list APIs are not standardized for what happens in
 * the _del() function when the item isn't present.
 *
 * We are choosing to return NULL if not found in the _del case for now.
 */

/* Delete NHE from the tree. On success, return the NHE, otherwise NULL. */
extern struct nhg_hash_entry *
nhg_connected_tree_del_nhe(struct nhg_connected_tree_head *head,
			   struct nhg_hash_entry *nhe);
/* ADD NHE to the tree. On success, return NULL, otherwise return the NHE. */
extern struct nhg_hash_entry *
nhg_connected_tree_add_nhe(struct nhg_connected_tree_head *head,
			   struct nhg_hash_entry *nhe);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NHG_PRIVATE_H__ */
