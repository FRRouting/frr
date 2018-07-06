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
	/*
	 * if this backet is the head of the linked listed, len denotes the
	 * number of elements in the list
	 */
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

/*
 * Create a hash table.
 *
 * The created hash table uses chaining and a user-provided comparator function
 * to resolve collisions. For best performance use a perfect hash function.
 * Worst case lookup time is O(N) when using a constant hash function. Best
 * case lookup time is O(1) when using a perfect hash function.
 *
 * The initial size of the created hash table is HASH_INITIAL_SIZE.
 *
 * hash_key
 *    hash function to use; should return a unique unsigned integer when called
 *    with a data item. Collisions are acceptable.
 *
 * hash_cmp
 *    comparison function used for resolving collisions; when called with two
 *    data items, should return nonzero if the two items are equal and 0
 *    otherwise
 *
 * name
 *    optional name for the hashtable; this is used when displaying global
 *    hashtable statistics. If this parameter is NULL the hash's name will be
 *    set to NULL and the default name will be displayed when showing
 *    statistics.
 *
 * Returns:
 *    a new hash table
 */
extern struct hash *hash_create(unsigned int (*hash_key)(void *),
				int (*hash_cmp)(const void *, const void *),
				const char *name);

/*
 * Create a hash table.
 *
 * The created hash table uses chaining and a user-provided comparator function
 * to resolve collisions. For best performance use a perfect hash function.
 * Worst case lookup time is O(N) when using a constant hash function. Best
 * case lookup time is O(1) when using a perfect hash function.
 *
 * size
 *    initial number of hash buckets to allocate; must be a power of 2 or the
 *    program will assert
 *
 * hash_key
 *    hash function to use; should return a unique unsigned integer when called
 *    with a data item. Collisions are acceptable.
 *
 * hash_cmp
 *    comparison function used for resolving collisions; when called with two
 *    data items, should return nonzero if the two items are equal and 0
 *    otherwise
 *
 * name
 *    optional name for the hashtable; this is used when displaying global
 *    hashtable statistics. If this parameter is NULL the hash's name will be
 *    set to NULL and the default name will be displayed when showing
 *    statistics.
 *
 * Returns:
 *    a new hash table
 */
extern struct hash *
hash_create_size(unsigned int size, unsigned int (*hash_key)(void *),
		 int (*hash_cmp)(const void *, const void *), const char *name);

/*
 * Retrieve or insert data from / into a hash table.
 *
 * This function is somewhat counterintuitive in its usage. In order to look up
 * an element from its key, you must provide the data item itself, with the
 * portions used in the hash function set to the same values as the data item
 * to retrieve. To insert a data element, either provide the key as just
 * described and provide alloc_func as descrbied below to allocate the full
 * data element, or provide the full data element and pass 'hash_alloc_intern'
 * to alloc_func.
 *
 * hash
 *    hash table to operate on
 *
 * data
 *    data to insert or retrieve
 *
 * alloc_func
 *    function to call if the item is not found in the hash table. This
 *    function is called with the value of 'data' and should create the data
 *    item to insert and return a pointer to it. If the data has already been
 *    completely created and provided in the 'data' parameter, passing
 *    'hash_alloc_intern' to this parameter will cause 'data' to be inserted.
 *    If this parameter is NULL, then this call to hash_get is equivalent to
 *    hash_lookup.
 *
 * Returns:
 *    the data item found or inserted, or NULL if alloc_func is NULL and the
 *    data is not found
 */
extern void *hash_get(struct hash *hash, void *data,
		      void *(*alloc_func)(void *));

/*
 * Dummy element allocation function.
 *
 * See hash_get for details.
 *
 * data
 *    data to insert into the hash table
 *
 * Returns:
 *    data
 */
extern void *hash_alloc_intern(void *data);

/*
 * Retrieve an item from a hash table.
 *
 * This function is equivalent to calling hash_get with alloc_func set to NULL.
 *
 * hash
 *    hash table to operate on
 *
 * data
 *    data element with values used for key computation set
 *
 * Returns:
 *    the data element if found, or NULL if not found
 */
extern void *hash_lookup(struct hash *hash, void *data);

/*
 * Remove an element from a hash table.
 *
 * hash
 *    hash table to operate on
 *
 * data
 *    data element to remove with values used for key computation set
 *
 * Returns:
 *    the removed element if found, or NULL if not found
 */
extern void *hash_release(struct hash *hash, void *data);

/*
 * Iterate over the elements in a hash table.
 *
 * It is safe to delete items passed to the iteration function from the hash
 * table during iteration.  Please note that adding entries to the hash
 * during the walk will cause undefined behavior in that some new entries
 * will be walked and some will not.  So do not do this.
 *
 * hash
 *    hash table to operate on
 *
 * func
 *    function to call with each data item
 *
 * arg
 *    arbitrary argument passed as the second parameter in each call to 'func'
 */
extern void hash_iterate(struct hash *hash,
			 void (*func)(struct hash_backet *, void *), void *arg);

/*
 * Iterate over the elements in a hash table, stopping on condition.
 *
 * It is safe to delete items passed to the iteration function from the hash
 * table during iteration.  Please note that adding entries to the hash
 * during the walk will cause undefined behavior in that some new entries
 * will be walked and some will not.  So do not do this.
 *
 * hash
 *    hash table to operate on
 *
 * func
 *    function to call with each data item. If this function returns
 *    HASHWALK_ABORT then the iteration stops.
 *
 * arg
 *    arbitrary argument passed as the second parameter in each call to 'func'
 */
extern void hash_walk(struct hash *hash,
		      int (*func)(struct hash_backet *, void *), void *arg);

/*
 * Remove all elements from a hash table.
 *
 * hash
 *    hash table to operate on
 *
 * free_func
 *    function to call with each removed item; intended to free the data
 */
extern void hash_clean(struct hash *hash, void (*free_func)(void *));

/*
 * Delete a hash table.
 *
 * This function assumes the table is empty. Call hash_clean to delete the
 * hashtable contents if necessary.
 *
 * hash
 *    hash table to delete
 */
extern void hash_free(struct hash *hash);

/*
 * Converts a hash table to an unsorted linked list.
 * Does not modify the hash table in any way.
 *
 * hash
 *    hash table to convert
 */
extern struct list *hash_to_list(struct hash *hash);

/*
 * Hash a string using the modified Bernstein hash.
 *
 * This is not a perfect hash function.
 *
 * str
 *    string to hash
 *
 * Returns:
 *    modified Bernstein hash of the string
 */
extern unsigned int string_hash_make(const char *);

/*
 * Install CLI commands for viewing global hash table statistics.
 */
extern void hash_cmd_init(void);

#endif /* _ZEBRA_HASH_H */
