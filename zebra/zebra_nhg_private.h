/*
 * Nexthop Group Private Functions.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
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

/**
 * These functions should only be used internally for nhg_hash_entry
 * manipulation and in certain special cases.
 *
 * Please use `zebra/zebra_nhg.h` for any general nhg_hash_entry api needs.
 */

#ifndef __ZEBRA_NHG_PRIVATE_H__
#define __ZEBRA_NHG_PRIVATE_H__

#include "zebra/zebra_nhg.h"

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
extern void nhg_connected_tree_del_nhe(struct nhg_connected_tree_head *head,
				       struct nhg_hash_entry *nhe);
extern void nhg_connected_tree_add_nhe(struct nhg_connected_tree_head *head,
				       struct nhg_hash_entry *nhe);

extern void zebra_nhg_free(void *arg);

#endif /* __ZEBRA_NHG_PRIVATE_H__ */
