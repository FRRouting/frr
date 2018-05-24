/* Hash routine.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_HASH_H
#define _ZEBRA_HASH_H

#include "memory.h"
#include "frratomic.h"

DECLARE_MTYPE(HASH)
DECLARE_MTYPE(HASH_BACKET)

/* Default hash table size.  */
#define HASH_INITIAL_SIZE 256
/* Expansion threshold */
#define HASH_THRESHOLD(used, size) ((used) > (size))

#define HASHWALK_CONTINUE 0
#define HASHWALK_ABORT -1

struct hash_backet {
	/* if this backet is the head of the linked listed, len denotes the
	 * number of
	 * elements in the list */
	int len;

	/* Linked list.  */
	struct hash_backet *next;

	/* Hash key. */
	unsigned int key;

	/* Data.  */
	void *data;
};

struct hashstats {
	/* number of empty hash buckets */
	_Atomic uint_fast32_t empty;
	/* sum of squares of bucket length */
	_Atomic uint_fast32_t ssq;
};

struct hash {
	/* Hash backet. */
	struct hash_backet **index;

	/* Hash table size. Must be power of 2 */
	unsigned int size;

	/* If max_size is 0 there is no limit */
	unsigned int max_size;

	/* Key make function. */
	unsigned int (*hash_key)(void *);

	/* Data compare function. */
	int (*hash_cmp)(const void *, const void *);

	/* Backet alloc. */
	unsigned long count;

	struct hashstats stats;

	/* hash name */
	char *name;
};

#define hashcount(X) ((X)->count)

extern struct hash *hash_create(unsigned int (*)(void *),
				int (*)(const void *, const void *),
				const char *);
extern struct hash *hash_create_size(unsigned int, unsigned int (*)(void *),
				     int (*)(const void *, const void *),
				     const char *);

extern void *hash_get(struct hash *, void *, void *(*)(void *));
extern void *hash_alloc_intern(void *);
extern void *hash_lookup(struct hash *, void *);
extern void *hash_release(struct hash *, void *);

extern void hash_iterate(struct hash *, void (*)(struct hash_backet *, void *),
			 void *);

extern void hash_walk(struct hash *, int (*)(struct hash_backet *, void *),
		      void *);

extern void hash_clean(struct hash *, void (*)(void *));
extern void hash_free(struct hash *);

/*
 * Converts a hash table to an unsorted linked list.
 * Does not modify the hash table in any way.
 *
 * hash
 *    the hash to convert
 */
extern struct list *hash_to_list(struct hash *hash);

extern unsigned int string_hash_make(const char *);

extern void hash_cmd_init(void);

#endif /* _ZEBRA_HASH_H */
