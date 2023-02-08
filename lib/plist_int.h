// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Prefix list internal definitions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_PLIST_INT_H
#define _QUAGGA_PLIST_INT_H

#ifdef __cplusplus
extern "C" {
#endif

struct pltrie_table;

PREDECL_RBTREE_UNIQ(plist);

struct prefix_list {
	char *name;
	char *desc;

	struct prefix_master *master;

	int count;
	int rangecount;

	struct plist_item plist_item;

	struct prefix_list_entry *head;
	struct prefix_list_entry *tail;

	struct pltrie_table *trie;
};

/* Each prefix-list's entry. */
struct prefix_list_entry {
	int64_t seq;

	int le;
	int ge;

	enum prefix_list_type type;

	bool any;
	struct prefix prefix;

	unsigned long refcnt;
	unsigned long hitcnt;

	struct prefix_list *pl;

	struct prefix_list_entry *next;
	struct prefix_list_entry *prev;

	/* up the chain for best match search */
	struct prefix_list_entry *next_best;

	/* Flag to track trie/list installation status. */
	bool installed;
};

extern void prefix_list_entry_free(struct prefix_list_entry *pentry);
extern void prefix_list_entry_delete2(struct prefix_list_entry *ple);
extern void prefix_list_entry_update_start(struct prefix_list_entry *ple);
extern void prefix_list_entry_update_finish(struct prefix_list_entry *ple);

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_PLIST_INT_H */
