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

DECLARE_MTYPE(HASH)
DECLARE_MTYPE(HASH_BACKET)

/* Default hash table size.  */ 
#define HASH_INITIAL_SIZE     256	/* initial number of backets. */
#define HASH_THRESHOLD	      10	/* expand when backet. */

#define HASHWALK_CONTINUE 0
#define HASHWALK_ABORT -1

struct hash_backet
{
  /* Linked list.  */
  struct hash_backet *next;

  /* Hash key. */
  unsigned int key;

  /* Data.  */
  void *data;
};

struct hash
{
  /* Hash backet. */
  struct hash_backet **index;

  /* Hash table size. Must be power of 2 */
  unsigned int size;

  /* If expansion failed. */
  int no_expand;

  /* Key make function. */
  unsigned int (*hash_key) (void *);

  /* Data compare function. */
  int (*hash_cmp) (const void *, const void *);

  /* Backet alloc. */
  unsigned long count;

  /* hash name */
  const char *name;
};

extern struct hash *hash_create (unsigned int (*) (void *), 
				 int (*) (const void *, const void *));
extern struct hash *hash_create_size (unsigned int, unsigned int (*) (void *), 
				      int (*) (const void *, const void *));

extern void *hash_get (struct hash *, void *, void * (*) (void *));
extern void *hash_alloc_intern (void *);
extern void *hash_lookup (struct hash *, void *);
extern void *hash_release (struct hash *, void *);

extern void hash_iterate (struct hash *, 
		   void (*) (struct hash_backet *, void *), void *);

extern void hash_walk (struct hash *,
		   int (*) (struct hash_backet *, void *), void *);

extern void hash_clean (struct hash *, void (*) (void *));
extern void hash_free (struct hash *);

extern unsigned int string_hash_make (const char *);

extern void hash_stats (struct hash *, double *, double *, int *, int *, int *, double *);
extern void hash_cmd_init (void);
extern void hash_register (struct hash *, const char *);
extern void hash_unregister (struct hash *);

#endif /* _ZEBRA_HASH_H */
