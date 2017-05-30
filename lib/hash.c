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

#include <zebra.h>
#include <math.h>

#include "hash.h"
#include "memory.h"
#include "linklist.h"
#include "termtable.h"
#include "vty.h"
#include "command.h"

DEFINE_MTYPE(       LIB, HASH,        "Hash")
DEFINE_MTYPE(       LIB, HASH_BACKET, "Hash Bucket")
DEFINE_MTYPE_STATIC(LIB, HASH_INDEX,  "Hash Index")

static struct list *_hashes;

/* Allocate a new hash.  */
struct hash *
hash_create_size (unsigned int size, unsigned int (*hash_key) (void *),
		  int (*hash_cmp) (const void *, const void *))
{
  struct hash *hash;

  assert ((size & (size-1)) == 0);
  hash = XMALLOC (MTYPE_HASH, sizeof (struct hash));
  hash->index = XCALLOC (MTYPE_HASH_INDEX,
			 sizeof (struct hash_backet *) * size);
  hash->size = size;
  hash->no_expand = 0;
  hash->hash_key = hash_key;
  hash->hash_cmp = hash_cmp;
  hash->count = 0;
  hash->name = NULL;

  return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *
hash_create (unsigned int (*hash_key) (void *), 
             int (*hash_cmp) (const void *, const void *))
{
  return hash_create_size (HASH_INITIAL_SIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void *
hash_alloc_intern (void *arg)
{
  return arg;
}

/* Expand hash if the chain length exceeds the threshold. */
static void hash_expand (struct hash *hash)
{
  unsigned int i, new_size, losers;
  struct hash_backet *hb, *hbnext, **new_index;

  new_size = hash->size * 2;
  new_index = XCALLOC(MTYPE_HASH_INDEX, sizeof(struct hash_backet *) * new_size);
  if (new_index == NULL)
    return;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hbnext)
      {
	unsigned int h = hb->key & (new_size - 1);

	hbnext = hb->next;
	hb->next = new_index[h];
	new_index[h] = hb;
      }

  /* Switch to new table */
  XFREE(MTYPE_HASH_INDEX, hash->index);
  hash->size = new_size;
  hash->index = new_index;

  /* Ideally, new index should have chains half as long as the original.
     If expansion didn't help, then not worth expanding again,
     the problem is the hash function. */
  losers = 0;
  for (i = 0; i < hash->size; i++)
    {
      unsigned int len = 0;
      for (hb = hash->index[i]; hb; hb = hb->next)
	{
	  if (++len > HASH_THRESHOLD/2)
	    ++losers;
	  if (len >= HASH_THRESHOLD)
	    hash->no_expand = 1;
	}
    }

  if (losers > hash->count / 2)
    hash->no_expand = 1;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void *
hash_get (struct hash *hash, void *data, void * (*alloc_func) (void *))
{
  unsigned int key;
  unsigned int index;
  void *newdata;
  unsigned int len;
  struct hash_backet *backet;

  key = (*hash->hash_key) (data);
  index = key & (hash->size - 1);
  len = 0;

  for (backet = hash->index[index]; backet != NULL; backet = backet->next)
    {
      if (backet->key == key && (*hash->hash_cmp) (backet->data, data))
	return backet->data;
      ++len;
    }

  if (alloc_func)
    {
      newdata = (*alloc_func) (data);
      if (newdata == NULL)
	return NULL;

      if (len > HASH_THRESHOLD && !hash->no_expand)
	{
	  hash_expand (hash);
	  index = key & (hash->size - 1);
	}

      backet = XMALLOC (MTYPE_HASH_BACKET, sizeof (struct hash_backet));
      backet->data = newdata;
      backet->key = key;
      backet->next = hash->index[index];
      hash->index[index] = backet;
      hash->count++;
      return backet->data;
    }
  return NULL;
}

/* Hash lookup.  */
void *
hash_lookup (struct hash *hash, void *data)
{
  return hash_get (hash, data, NULL);
}

/* Simple Bernstein hash which is simple and fast for common case */
unsigned int string_hash_make (const char *str)
{
  unsigned int hash = 0;

  while (*str)
    hash = (hash * 33) ^ (unsigned int) *str++;

  return hash;
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *
hash_release (struct hash *hash, void *data)
{
  void *ret;
  unsigned int key;
  unsigned int index;
  struct hash_backet *backet;
  struct hash_backet *pp;

  key = (*hash->hash_key) (data);
  index = key & (hash->size - 1);

  for (backet = pp = hash->index[index]; backet; backet = backet->next)
    {
      if (backet->key == key && (*hash->hash_cmp) (backet->data, data)) 
	{
	  if (backet == pp) 
	    hash->index[index] = backet->next;
	  else 
	    pp->next = backet->next;

	  ret = backet->data;
	  XFREE (MTYPE_HASH_BACKET, backet);
	  hash->count--;
	  return ret;
	}
      pp = backet;
    }
  return NULL;
}

/* Iterator function for hash.  */
void
hash_iterate (struct hash *hash, 
	      void (*func) (struct hash_backet *, void *), void *arg)
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *hbnext;

  for (i = 0; i < hash->size; i++)
    for (hb = hash->index[i]; hb; hb = hbnext)
      {
	/* get pointer to next hash backet here, in case (*func)
	 * decides to delete hb by calling hash_release
	 */
	hbnext = hb->next;
	(*func) (hb, arg);
      }
}

/* Iterator function for hash.  */
void
hash_walk (struct hash *hash,
	   int (*func) (struct hash_backet *, void *), void *arg)
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *hbnext;
  int ret = HASHWALK_CONTINUE;

  for (i = 0; i < hash->size; i++)
    {
      for (hb = hash->index[i]; hb; hb = hbnext)
	{
	  /* get pointer to next hash backet here, in case (*func)
	   * decides to delete hb by calling hash_release
	   */
	  hbnext = hb->next;
	  ret = (*func) (hb, arg);
	  if (ret == HASHWALK_ABORT)
	    return;
	}
    }
}

/* Clean up hash.  */
void
hash_clean (struct hash *hash, void (*free_func) (void *))
{
  unsigned int i;
  struct hash_backet *hb;
  struct hash_backet *next;

  for (i = 0; i < hash->size; i++)
    {
      for (hb = hash->index[i]; hb; hb = next)
	{
	  next = hb->next;
	      
	  if (free_func)
	    (*free_func) (hb->data);

	  XFREE (MTYPE_HASH_BACKET, hb);
	  hash->count--;
	}
      hash->index[i] = NULL;
    }
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
void
hash_free (struct hash *hash)
{
  hash_unregister (hash);
  XFREE (MTYPE_HASH_INDEX, hash->index);
  XFREE (MTYPE_HASH, hash);
}

/**
 * Calculates some statistics on the given hash table that can be used to
 * evaluate performance.
 *
 * Summary statistics calculated are:
 *
 * - Load factor: This is the number of elements in the table divided by the
 *   number of buckets. Since this hash table implementation uses chaining,
 *   this value can be greater than 1. This number provides information on how
 *   'full' the table is, but does not provide information on how evenly
 *   distributed the elements are. Notably, a load factor >= 1 does not imply
 *   that every bucket has an element; with a pathological hash function, all
 *   elements could be in a single bucket.
 *
 * - Std. Dev.: This is the standard deviation from the load factor. If the LF
 *   is the mean of number of elements per bucket, the standard deviation
 *   measures how much any particular bucket is likely to deviate from the
 *   mean. As a rule of thumb this number should be less than 2, and ideally
 *   less than 1 for optimal performance. A number larger than 3 generally
 *   indicates a poor hash function.
 *
 * - Max: Number of elements in the most overloaded bucket(s).
 * - Min: Number of elements in the most underloaded bucket(s).
 *
 * - Empty: Number of empty buckets
 * - Avg: average number of elements among the set of full buckets (like load factor but without empty buckets)
 *
 * Total number of buckets is precomputed and resides in h->size.
 * Total number of elements is precomputed and resides in h->count.
 */
void
hash_stats (struct hash *h, double *lf, double *stddev, int *max, int *min, int *empty, double *avg)
{
  struct hash_backet *hb;   // iteration pointer
  struct hash_backet *next; // iteration pointer
  unsigned int backets = 0; // total number of items in ht
  int buckets[h->size];     // # items per bucket
  unsigned int full;        // # buckets with items

  *max = *min = *lf = *stddev = *avg = 0;
  *empty = h->size;

  if (h->size == 0 || h->count == 0)
    return;

  *empty = 0;

  memset (buckets, 0x00, h->size * sizeof (int));

  /* collect some important info */
  for (unsigned int i = 0; i < h->size; i++)
    {
      for (hb = h->index[i]; hb; hb = next)
        {
          buckets[i]++;
          next = hb->next;
          backets++;
        }
      *max = MAX (buckets[i], *max);
      *min = MIN (buckets[i], *min);

      if (buckets[i] == 0)
        *empty += 1;
    }

  assert (backets == h->count);
  full = h->size - *empty;

  *lf = h->count / (double) h->size;
  *avg = h->count / (double) full;

  if (h->count == 0)
    return;

  /* compute population stddev */
  for (unsigned int i = 0; i < h->size; i++) {
    if (buckets[i] > 0)
      *stddev += pow(((double) buckets[i] - *avg), 2.0);
  }

  *stddev = sqrt((1.0/h->size) * *stddev);
}

void
hash_register (struct hash *h, const char *name)
{
  h->name = name;
  listnode_add (_hashes, h);
}

void
hash_unregister (struct hash *h)
{
  listnode_delete (_hashes, h);
}

DEFUN(show_hash_stats,
      show_hash_stats_cmd,
      "show hashtable <statistics>",
      SHOW_STR
      "Statistics about critical hash tables\n"
      "Statistics about critical hash tables\n")
{
  struct hash *h;
  struct listnode *ln;
  struct ttable *tt = ttable_new (&ttable_styles[TTSTYLE_BLANK]);
  double lf, stddev, avg;
  int max, min, empty;

  ttable_add_row (tt, "Hash table|Buckets|Entries|Empty|LF|Mean|SD|Max|Min");
  tt->style.cell.lpad = 1;
  tt->style.cell.rpad = 2;
  ttable_restyle (tt);
  ttable_rowseps (tt, 0, BOTTOM, true, '-');

  for (ALL_LIST_ELEMENTS_RO (_hashes, ln, h))
    {
      if (h->name == NULL)
        continue;

      hash_stats (h, &lf, &stddev, &max, &min, &empty, &avg);
      ttable_add_row (tt, "%s|%d|%d|%.0f%%|%.2f|%.2f|%.2f|%d|%d", h->name,
          h->size, h->count, (empty / (double) h->size)*100, lf, avg, stddev,
          max, min);
    }

  char *table = ttable_dump (tt, VTY_NEWLINE);
  vty_out (vty, "%s%s%s", VTY_NEWLINE, table, VTY_NEWLINE);
  XFREE (MTYPE_TMP, table);
  ttable_del (tt);

  return CMD_SUCCESS;
}

void
hash_cmd_init ()
{
  _hashes = list_new();
  install_element (ENABLE_NODE, &show_hash_stats_cmd);
}
