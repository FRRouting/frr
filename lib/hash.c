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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "hash.h"
#include "memory.h"

DEFINE_MTYPE(LIB, HASH, "Hash")
DEFINE_MTYPE(LIB, HASH_BACKET, "Hash Bucket")
DEFINE_MTYPE_STATIC(LIB, HASH_INDEX, "Hash Index")

/* Allocate a new hash.  */
struct hash *hash_create_size(unsigned int size,
                              unsigned int (*hash_key) (void *),
                              int (*hash_cmp) (const void *, const void *))
{
        struct hash *hash;

        assert((size & (size - 1)) == 0);
        hash = XMALLOC(MTYPE_HASH, sizeof(struct hash));
        hash->index = XCALLOC(MTYPE_HASH_INDEX,
                              sizeof(struct hash_backet *) * size);
        hash->size = size;
        hash->no_expand = 0;
        hash->hash_key = hash_key;
        hash->hash_cmp = hash_cmp;
        hash->count = 0;

        return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *hash_create(unsigned int (*hash_key) (void *),
                         int (*hash_cmp) (const void *, const void *))
{
        return hash_create_size(HASH_INITIAL_SIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void *hash_alloc_intern(void *arg)
{
        return arg;
}

/* Expand hash if the chain length exceeds the threshold. */
static void hash_expand(struct hash *hash)
{
        unsigned int i, new_size, losers;
        struct hash_backet *hb, *hbnext, **new_index;

        new_size = hash->size * 2;
        new_index =
            XCALLOC(MTYPE_HASH_INDEX,
                    sizeof(struct hash_backet *) * new_size);
        if (new_index == NULL)
                return;

        for (i = 0; i < hash->size; i++)
                for (hb = hash->index[i]; hb; hb = hbnext) {
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
        for (i = 0; i < hash->size; i++) {
                unsigned int len = 0;
                for (hb = hash->index[i]; hb; hb = hb->next) {
                        if (++len > HASH_THRESHOLD / 2)
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
void *hash_get(struct hash *hash, void *data, void *(*alloc_func) (void *))
{
        unsigned int key;
        unsigned int index;
        void *newdata;
        unsigned int len;
        struct hash_backet *backet;

        key = (*hash->hash_key) (data);
        index = key & (hash->size - 1);
        len = 0;

        for (backet = hash->index[index]; backet != NULL;
             backet = backet->next) {
                if (backet->key == key
                    && (*hash->hash_cmp) (backet->data, data))
                        return backet->data;
                ++len;
        }

        if (alloc_func) {
                newdata = (*alloc_func) (data);
                if (newdata == NULL)
                        return NULL;

                if (len > HASH_THRESHOLD && !hash->no_expand) {
                        hash_expand(hash);
                        index = key & (hash->size - 1);
                }

                backet =
                    XMALLOC(MTYPE_HASH_BACKET, sizeof(struct hash_backet));
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
void *hash_lookup(struct hash *hash, void *data)
{
        return hash_get(hash, data, NULL);
}

/* Simple Bernstein hash which is simple and fast for common case */
unsigned int string_hash_make(const char *str)
{
        unsigned int hash = 0;

        while (*str)
                hash = (hash * 33) ^ (unsigned int) *str++;

        return hash;
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *hash_release(struct hash *hash, void *data)
{
        void *ret;
        unsigned int key;
        unsigned int index;
        struct hash_backet *backet;
        struct hash_backet *pp;

        key = (*hash->hash_key) (data);
        index = key & (hash->size - 1);

        for (backet = pp = hash->index[index]; backet;
             backet = backet->next) {
                if (backet->key == key
                    && (*hash->hash_cmp) (backet->data, data)) {
                        if (backet == pp)
                                hash->index[index] = backet->next;
                        else
                                pp->next = backet->next;

                        ret = backet->data;
                        XFREE(MTYPE_HASH_BACKET, backet);
                        hash->count--;
                        return ret;
                }
                pp = backet;
        }
        return NULL;
}

/* Iterator function for hash.  */
void
hash_iterate(struct hash *hash,
             void (*func) (struct hash_backet *, void *), void *arg)
{
        unsigned int i;
        struct hash_backet *hb;
        struct hash_backet *hbnext;

        for (i = 0; i < hash->size; i++)
                for (hb = hash->index[i]; hb; hb = hbnext) {
                        /* get pointer to next hash backet here, in case (*func)
                         * decides to delete hb by calling hash_release
                         */
                        hbnext = hb->next;
                        (*func) (hb, arg);
                }
}

/* Iterator function for hash.  */
void
hash_walk(struct hash *hash,
          int (*func) (struct hash_backet *, void *), void *arg)
{
        unsigned int i;
        struct hash_backet *hb;
        struct hash_backet *hbnext;
        int ret = HASHWALK_CONTINUE;

        for (i = 0; i < hash->size; i++) {
                for (hb = hash->index[i]; hb; hb = hbnext) {
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
void hash_clean(struct hash *hash, void (*free_func) (void *))
{
        unsigned int i;
        struct hash_backet *hb;
        struct hash_backet *next;

        for (i = 0; i < hash->size; i++) {
                for (hb = hash->index[i]; hb; hb = next) {
                        next = hb->next;

                        if (free_func)
                                (*free_func) (hb->data);

                        XFREE(MTYPE_HASH_BACKET, hb);
                        hash->count--;
                }
                hash->index[i] = NULL;
        }
}

/* Free hash memory.  You may call hash_clean before call this
   function.  */
void hash_free(struct hash *hash)
{
        XFREE(MTYPE_HASH_INDEX, hash->index);
        XFREE(MTYPE_HASH, hash);
}
