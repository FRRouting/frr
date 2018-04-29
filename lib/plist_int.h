/*
 * Prefix list internal definitions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _QUAGGA_PLIST_INT_H
#define _QUAGGA_PLIST_INT_H

enum prefix_name_type { PREFIX_TYPE_STRING, PREFIX_TYPE_NUMBER };

struct pltrie_table;

struct prefix_list {
	char *name;
	char *desc;

	struct prefix_master *master;

	enum prefix_name_type type;

	int count;
	int rangecount;

	struct prefix_list_entry *head;
	struct prefix_list_entry *tail;

	struct pltrie_table *trie;

	struct prefix_list *next;
	struct prefix_list *prev;
};

/* Each prefix-list's entry. */
struct prefix_list_entry {
	int64_t seq;

	int le;
	int ge;

	enum prefix_list_type type;

	int any;
	struct prefix prefix;

	unsigned long refcnt;
	unsigned long hitcnt;

	struct prefix_list_entry *next;
	struct prefix_list_entry *prev;

	/* up the chain for best match search */
	struct prefix_list_entry *next_best;
};

#endif /* _QUAGGA_PLIST_INT_H */
