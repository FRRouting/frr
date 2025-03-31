// SPDX-License-Identifier: GPL-2.0-or-later
/* Hash routine.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <math.h>

#include "hash.h"
#include "memory.h"
#include "linklist.h"
#include "termtable.h"
#include "vty.h"
#include "command.h"
#include "libfrr.h"
#include "frr_pthread.h"
#include "libfrr_trace.h"

DEFINE_MTYPE_STATIC(LIB, HASH, "Hash");
DEFINE_MTYPE_STATIC(LIB, HASH_BUCKET, "Hash Bucket");
DEFINE_MTYPE_STATIC(LIB, HASH_INDEX, "Hash Index");

static pthread_mutex_t _hashes_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct list *_hashes;

struct hash *hash_create_size(unsigned int size,
			      unsigned int (*hash_key)(const void *),
			      bool (*hash_cmp)(const void *, const void *),
			      const char *name)
{
	struct hash *hash;

	assert((size & (size - 1)) == 0);
	hash = XCALLOC(MTYPE_HASH, sizeof(struct hash));
	hash->index =
		XCALLOC(MTYPE_HASH_INDEX, sizeof(struct hash_bucket *) * size);
	hash->size = size;
	hash->hash_key = hash_key;
	hash->hash_cmp = hash_cmp;
	hash->count = 0;
	hash->name = name ? XSTRDUP(MTYPE_HASH, name) : NULL;
	hash->stats.empty = hash->size;

	frr_with_mutex (&_hashes_mtx) {
		if (!_hashes)
			_hashes = list_new();

		listnode_add(_hashes, hash);
	}

	return hash;
}

struct hash *hash_create(unsigned int (*hash_key)(const void *),
			 bool (*hash_cmp)(const void *, const void *),
			 const char *name)
{
	return hash_create_size(HASH_INITIAL_SIZE, hash_key, hash_cmp, name);
}

void *hash_alloc_intern(void *arg)
{
	return arg;
}

/*
 * ssq = ssq + (new^2 - old^2)
 *     = ssq + ((new + old) * (new - old))
 */
#define hash_update_ssq(hz, old, new)                                          \
	do {                                                                   \
		int _adjust = (new + old) * (new - old);                       \
		if (_adjust < 0)                                               \
			atomic_fetch_sub_explicit(&hz->stats.ssq, -_adjust,    \
						  memory_order_relaxed);       \
		else                                                           \
			atomic_fetch_add_explicit(&hz->stats.ssq, _adjust,     \
						  memory_order_relaxed);       \
	} while (0)

/* Expand hash if the chain length exceeds the threshold. */
static void hash_expand(struct hash *hash)
{
	unsigned int i, new_size;
	struct hash_bucket *hb, *hbnext, **new_index;

	new_size = hash->size * 2;

	if (hash->max_size && new_size > hash->max_size)
		return;

	new_index = XCALLOC(MTYPE_HASH_INDEX,
			    sizeof(struct hash_bucket *) * new_size);

	hash->stats.empty = new_size;

	for (i = 0; i < hash->size; i++)
		for (hb = hash->index[i]; hb; hb = hbnext) {
			unsigned int h = hb->key & (new_size - 1);

			hbnext = hb->next;
			hb->next = new_index[h];

			int oldlen = hb->next ? hb->next->len : 0;
			int newlen = oldlen + 1;

			if (newlen == 1)
				hash->stats.empty--;
			else
				hb->next->len = 0;

			hb->len = newlen;

			hash_update_ssq(hash, oldlen, newlen);

			new_index[h] = hb;
		}

	/* Switch to new table */
	XFREE(MTYPE_HASH_INDEX, hash->index);
	hash->size = new_size;
	hash->index = new_index;
}

void *hash_get(struct hash *hash, void *data, void *(*alloc_func)(void *))
{
	frrtrace(2, frr_libfrr, hash_get, hash, data);

	unsigned int key;
	unsigned int index;
	void *newdata;
	struct hash_bucket *bucket;

	if (!alloc_func && !hash->count)
		return NULL;

	key = (*hash->hash_key)(data);
	index = key & (hash->size - 1);

	for (bucket = hash->index[index]; bucket != NULL;
	     bucket = bucket->next) {
		if (bucket->key == key && (*hash->hash_cmp)(bucket->data, data))
			return bucket->data;
	}

	if (alloc_func) {
		newdata = (*alloc_func)(data);
		if (newdata == NULL)
			return NULL;

		if (HASH_THRESHOLD(hash->count + 1, hash->size)) {
			hash_expand(hash);
			index = key & (hash->size - 1);
		}

		bucket = XCALLOC(MTYPE_HASH_BUCKET, sizeof(struct hash_bucket));
		bucket->data = newdata;
		bucket->key = key;
		bucket->next = hash->index[index];
		hash->index[index] = bucket;
		hash->count++;

		frrtrace(3, frr_libfrr, hash_insert, hash, data, key);

		int oldlen = bucket->next ? bucket->next->len : 0;
		int newlen = oldlen + 1;

		if (newlen == 1)
			hash->stats.empty--;
		else
			bucket->next->len = 0;

		bucket->len = newlen;

		hash_update_ssq(hash, oldlen, newlen);

		return bucket->data;
	}
	return NULL;
}

void *hash_lookup(struct hash *hash, void *data)
{
	return hash_get(hash, data, NULL);
}

unsigned int string_hash_make(const char *str)
{
	unsigned int hash = 0;

	while (*str)
		hash = (hash * 33) ^ (unsigned int)*str++;

	return hash;
}

void *hash_release(struct hash *hash, void *data)
{
	void *ret = NULL;
	unsigned int key;
	unsigned int index;
	struct hash_bucket *bucket;
	struct hash_bucket *pp;

	key = (*hash->hash_key)(data);
	index = key & (hash->size - 1);

	for (bucket = pp = hash->index[index]; bucket; bucket = bucket->next) {
		if (bucket->key == key
		    && (*hash->hash_cmp)(bucket->data, data)) {
			int oldlen = hash->index[index]->len;
			int newlen = oldlen - 1;

			if (bucket == pp)
				hash->index[index] = bucket->next;
			else
				pp->next = bucket->next;

			if (hash->index[index])
				hash->index[index]->len = newlen;
			else
				hash->stats.empty++;

			hash_update_ssq(hash, oldlen, newlen);

			ret = bucket->data;
			XFREE(MTYPE_HASH_BUCKET, bucket);
			hash->count--;
			break;
		}
		pp = bucket;
	}

	frrtrace(3, frr_libfrr, hash_release, hash, data, ret);

	return ret;
}

void hash_iterate(struct hash *hash, void (*func)(struct hash_bucket *, void *),
		  void *arg)
{
	unsigned int i;
	struct hash_bucket *hb;
	struct hash_bucket *hbnext;

	for (i = 0; i < hash->size; i++)
		for (hb = hash->index[i]; hb; hb = hbnext) {
			/* get pointer to next hash bucket here, in case (*func)
			 * decides to delete hb by calling hash_release
			 */
			hbnext = hb->next;
			(*func)(hb, arg);
		}
}

void hash_walk(struct hash *hash, int (*func)(struct hash_bucket *, void *),
	       void *arg)
{
	unsigned int i;
	struct hash_bucket *hb;
	struct hash_bucket *hbnext;
	int ret = HASHWALK_CONTINUE;

	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = hbnext) {
			/* get pointer to next hash bucket here, in case (*func)
			 * decides to delete hb by calling hash_release
			 */
			hbnext = hb->next;
			ret = (*func)(hb, arg);
			if (ret == HASHWALK_ABORT)
				return;
		}
	}
}

void hash_clean(struct hash *hash, void (*free_func)(void *))
{
	unsigned int i;
	struct hash_bucket *hb;
	struct hash_bucket *next;

	for (i = 0; i < hash->size; i++) {
		for (hb = hash->index[i]; hb; hb = next) {
			next = hb->next;

			if (free_func)
				(*free_func)(hb->data);

			XFREE(MTYPE_HASH_BUCKET, hb);
			hash->count--;
		}
		hash->index[i] = NULL;
	}

	hash->stats.ssq = 0;
	hash->stats.empty = hash->size;
}

void hash_clean_and_free(struct hash **hash, void (*free_func)(void *))
{
	if (!*hash)
		return;

	hash_clean(*hash, free_func);
	hash_free(*hash);
	*hash = NULL;
}

static void hash_to_list_iter(struct hash_bucket *hb, void *arg)
{
	struct list *list = arg;

	listnode_add(list, hb->data);
}

struct list *hash_to_list(struct hash *hash)
{
	struct list *list = list_new();

	hash_iterate(hash, hash_to_list_iter, list);
	return list;
}

void hash_free(struct hash *hash)
{
	frr_with_mutex (&_hashes_mtx) {
		if (_hashes) {
			listnode_delete(_hashes, hash);
			if (_hashes->count == 0) {
				list_delete(&_hashes);
			}
		}
	}

	XFREE(MTYPE_HASH, hash->name);

	XFREE(MTYPE_HASH_INDEX, hash->index);
	XFREE(MTYPE_HASH, hash);
}


/* CLI commands ------------------------------------------------------------ */

DEFUN_NOSH(show_hash_stats,
           show_hash_stats_cmd,
           "show debugging hashtable [statistics]",
           SHOW_STR
           DEBUG_STR
           "Statistics about hash tables\n"
           "Statistics about hash tables\n")
{
	struct hash *h;
	struct listnode *ln;
	struct ttable *tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);

	ttable_add_row(tt, "Hash table|Buckets|Entries|Empty|LF|SD|FLF|SD");
	tt->style.cell.lpad = 2;
	tt->style.cell.rpad = 1;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	/* Summary statistics calculated are:
	 *
	 * - Load factor: This is the number of elements in the table divided
	 *   by the number of buckets. Since this hash table implementation
	 *   uses chaining, this value can be greater than 1.
	 *   This number provides information on how 'full' the table is, but
	 *   does not provide information on how evenly distributed the
	 *   elements are.
	 *   Notably, a load factor >= 1 does not imply that every bucket has
	 *   an element; with a pathological hash function, all elements could
	 *   be in a single bucket.
	 *
	 * - Full load factor: this is the number of elements in the table
	 *   divided by the number of buckets that have some elements in them.
	 *
	 * - Std. Dev.: This is the standard deviation calculated from the
	 *   relevant load factor. If the load factor is the mean of number of
	 *   elements per bucket, the standard deviation measures how much any
	 *   particular bucket is likely to deviate from the mean.
	 *   As a rule of thumb this number should be less than 2, and ideally
	 *   <= 1 for optimal performance. A number larger than 3 generally
	 *   indicates a poor hash function.
	 */

	double lf;    // load factor
	double flf;   // full load factor
	double var;   // overall variance
	double fvar;  // full variance
	double stdv;  // overall stddev
	double fstdv; // full stddev

	long double x2;   // h->count ^ 2
	long double ldc;  // (long double) h->count
	long double full; // h->size - h->stats.empty
	long double ssq;  // ssq casted to long double

	pthread_mutex_lock(&_hashes_mtx);
	if (!_hashes) {
		pthread_mutex_unlock(&_hashes_mtx);
		ttable_del(tt);
		vty_out(vty, "No hash tables in use.\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(_hashes, ln, h)) {
		if (!h->name)
			continue;

		ssq = (long double)h->stats.ssq;
		x2 = h->count * h->count;
		ldc = (long double)h->count;
		full = h->size - h->stats.empty;
		lf = h->count / (double)h->size;
		flf = full ? h->count / (double)(full) : 0;
		var = ldc ? (1.0 / ldc) * (ssq - x2 / ldc) : 0;
		fvar = full ? (1.0 / full) * (ssq - x2 / full) : 0;
		var = (var < .0001) ? 0 : var;
		fvar = (fvar < .0001) ? 0 : fvar;
		stdv = sqrt(var);
		fstdv = sqrt(fvar);

		ttable_add_row(tt, "%s|%d|%ld|%.0f%%|%.2lf|%.2lf|%.2lf|%.2lf",
			       h->name, h->size, h->count,
			       (h->stats.empty / (double)h->size) * 100, lf,
			       stdv, flf, fstdv);
	}
	pthread_mutex_unlock(&_hashes_mtx);

	/* display header */
	char header[] = "Showing hash table statistics for ";
	char underln[sizeof(header) + strlen(frr_protonameinst)];
	memset(underln, '-', sizeof(underln));
	underln[sizeof(underln) - 1] = '\0';
	vty_out(vty, "%s%s\n", header, frr_protonameinst);
	vty_out(vty, "%s\n", underln);

	vty_out(vty, "# allocated: %d\n", _hashes->count);
	vty_out(vty, "# named:     %d\n\n", tt->nrows - 1);

	if (tt->nrows > 1) {
		ttable_colseps(tt, 0, RIGHT, true, '|');
		char *table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP_TTABLE, table);
	} else
		vty_out(vty, "No named hash tables to display.\n");

	ttable_del(tt);

	return CMD_SUCCESS;
}

void hash_cmd_init(void)
{
	install_element(ENABLE_NODE, &show_hash_stats_cmd);
}
