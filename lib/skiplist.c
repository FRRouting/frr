/*
 * Copyright 1990 William Pugh
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Permission to include in quagga provide on March 31, 2016
 */

/*
 * Skip List impementation based on code from William Pugh.
 * ftp://ftp.cs.umd.edu/pub/skipLists/
 *
 * Skip Lists are a probabilistic alternative to balanced trees, as
 * described in the June 1990 issue of CACM and were invented by
 * William Pugh in 1987.
 *
 * This file contains source code to implement a dictionary using
 * skip lists and a test driver to test the routines.
 *
 * A couple of comments about this implementation:
 *   The routine randomLevel has been hard-coded to generate random
 *   levels using p=0.25. It can be easily changed.
 *
 *   The insertion routine has been implemented so as to use the
 *   dirty hack described in the CACM paper: if a random level is
 *   generated that is more than the current maximum level, the
 *   current maximum level plus one is used instead.
 *
 *   Levels start at zero and go up to MaxLevel (which is equal to
 * 	(MaxNumberOfLevels-1).
 *
 * The run-time flag SKIPLIST_FLAG_ALLOW_DUPLICATES determines whether or
 * not duplicates are allowed for a given list. If set, duplicates are
 * allowed and act in a FIFO manner. If not set, an insertion of a value
 * already in the list updates the previously existing binding.
 *
 * BitsInRandom is defined to be the number of bits returned by a call to
 * random(). For most all machines with 32-bit integers, this is 31 bits
 * as currently set.
 */


#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "vty.h"
#include "skiplist.h"

DEFINE_MTYPE_STATIC(LIB, SKIP_LIST, "Skip List")
DEFINE_MTYPE_STATIC(LIB, SKIP_LIST_NODE, "Skip Node")

#define BitsInRandom 31

#define MaxNumberOfLevels 16
#define MaxLevel (MaxNumberOfLevels-1)
#define newNodeOfLevel(l) XCALLOC(MTYPE_SKIP_LIST_NODE, sizeof(struct skiplistnode)+(l)*sizeof(struct skiplistnode *))

static int randomsLeft;
static int randomBits;
static struct skiplist *skiplist_last_created; /* debugging hack */

#if 1
#define CHECKLAST(sl)                                                          \
	do {                                                                   \
		if ((sl)->header->forward[0] && !(sl)->last)                   \
			assert(0);                                             \
		if (!(sl)->header->forward[0] && (sl)->last)                   \
			assert(0);                                             \
	} while (0)
#else
#define CHECKLAST(sl)
#endif


static int randomLevel()
{
	register int level = 0;
	register int b;

	do {
		if (randomsLeft <= 0) {
			randomBits = random();
			randomsLeft = BitsInRandom / 2;
		}
		b = randomBits & 3;
		randomBits >>= 2;
		--randomsLeft;

		if (!b) {
			level++;
			if (level >= MaxLevel)
				return MaxLevel;
		}
	} while (!b);

	return level;
}

static int default_cmp(void *key1, void *key2)
{
	if (key1 < key2)
		return -1;
	if (key1 > key2)
		return 1;
	return 0;
}

unsigned int skiplist_count(struct skiplist *l)
{
	return l->count;
}

struct skiplist *skiplist_new(int flags, int (*cmp)(void *key1, void *key2),
			      void (*del)(void *val))
{
	struct skiplist *new;

	new = XCALLOC(MTYPE_SKIP_LIST, sizeof(struct skiplist));
	assert(new);

	new->level = 0;
	new->count = 0;
	new->header = newNodeOfLevel(MaxNumberOfLevels);
	new->stats = newNodeOfLevel(MaxNumberOfLevels);

	new->flags = flags;
	if (cmp)
		new->cmp = cmp;
	else
		new->cmp = default_cmp;

	if (del)
		new->del = del;

	skiplist_last_created = new; /* debug */

	return new;
}

void skiplist_free(struct skiplist *l)
{
	register struct skiplistnode *p, *q;

	p = l->header;

	do {
		q = p->forward[0];
		if (l->del && p != l->header)
			(*l->del)(p->value);
		XFREE(MTYPE_SKIP_LIST_NODE, p);
		p = q;
	} while (p);

	XFREE(MTYPE_SKIP_LIST_NODE, l->stats);
	XFREE(MTYPE_SKIP_LIST, l);
}


int skiplist_insert(register struct skiplist *l, register void *key,
		    register void *value)
{
	register int k;
	struct skiplistnode *update[MaxNumberOfLevels];
	register struct skiplistnode *p, *q;

	CHECKLAST(l);

	/* DEBUG */
	if (!key) {
		zlog_err("%s: key is 0, value is %p", __func__, value);
	}

	p = l->header;
	k = l->level;
	do {
		while (q = p->forward[k], q && (*l->cmp)(q->key, key) < 0)
			p = q;
		update[k] = p;
	} while (--k >= 0);

	if (!(l->flags & SKIPLIST_FLAG_ALLOW_DUPLICATES) && q
	    && ((*l->cmp)(q->key, key) == 0)) {

		return -1;
	}

	k = randomLevel();
	if (k > l->level) {
		k = ++l->level;
		update[k] = l->header;
	}

	q = newNodeOfLevel(k);
	q->key = key;
	q->value = value;
#if SKIPLIST_0TIMER_DEBUG
	q->flags = SKIPLIST_NODE_FLAG_INSERTED; /* debug */
#endif

	++(l->stats->forward[k]);
#if SKIPLIST_DEBUG
	zlog_debug("%s: incremented stats @%p:%d, now %ld", __func__, l, k,
		   l->stats->forward[k] - (struct skiplistnode *)NULL);
#endif

	do {
		p = update[k];
		q->forward[k] = p->forward[k];
		p->forward[k] = q;
	} while (--k >= 0);

	/*
	 * If this is the last item in the list, update the "last" pointer
	 */
	if (!q->forward[0]) {
		l->last = q;
	}

	++(l->count);

	CHECKLAST(l);

	return 0;
}

int skiplist_delete(register struct skiplist *l, register void *key,
		    register void *value) /* used only if duplicates allowed */
{
	register int k, m;
	struct skiplistnode *update[MaxNumberOfLevels];
	register struct skiplistnode *p, *q;

	CHECKLAST(l);

	/* to make debugging easier */
	for (k = 0; k < MaxNumberOfLevels; ++k)
		update[k] = NULL;

	p = l->header;
	k = m = l->level;
	do {
		while (q = p->forward[k], q && (*l->cmp)(q->key, key) < 0)
			p = q;
		update[k] = p;
	} while (--k >= 0);

	if (l->flags & SKIPLIST_FLAG_ALLOW_DUPLICATES) {
		while (q && ((*l->cmp)(q->key, key) == 0)
		       && (q->value != value)) {
			int i;
			for (i = 0; i <= l->level; ++i) {
				if (update[i]->forward[i] == q)
					update[i] = q;
			}
			q = q->forward[0];
		}
	}

	if (q && (*l->cmp)(q->key, key) == 0) {
		if (!(l->flags & SKIPLIST_FLAG_ALLOW_DUPLICATES)
		    || (q->value == value)) {

/*
 * found node to delete
 */
#if SKIPLIST_0TIMER_DEBUG
			q->flags &= ~SKIPLIST_NODE_FLAG_INSERTED;
#endif
			/*
			 * If we are deleting the last element of the list,
			 * update the list's "last" pointer.
			 */
			if (l->last == q) {
				if (update[0] == l->header)
					l->last = NULL;
				else
					l->last = update[0];
			}

			for (k = 0; k <= m && (p = update[k])->forward[k] == q;
			     k++) {
				p->forward[k] = q->forward[k];
			}
			--(l->stats->forward[k - 1]);
#if SKIPLIST_DEBUG
			zlog_debug("%s: decremented stats @%p:%d, now %ld",
				   __func__, l, k - 1,
				   l->stats->forward[k - 1]
					   - (struct skiplistnode *)NULL);
#endif
			if (l->del)
				(*l->del)(q->value);
			XFREE(MTYPE_SKIP_LIST_NODE, q);
			while (l->header->forward[m] == NULL && m > 0)
				m--;
			l->level = m;
			CHECKLAST(l);
			--(l->count);
			return 0;
		}
	}

	CHECKLAST(l);
	return -1;
}

/*
 * Obtain first value matching "key". Unless SKIPLIST_FLAG_ALLOW_DUPLICATES
 * is set, this will also be the only value matching "key".
 *
 * Also set a cursor for use with skiplist_next_value.
 */
int skiplist_first_value(register struct skiplist *l, /* in */
			 register void *key,	  /* in */
			 void **valuePointer,	 /* out */
			 void **cursor)		      /* out */
{
	register int k;
	register struct skiplistnode *p, *q;

	p = l->header;
	k = l->level;

	do {
		while (q = p->forward[k], q && (*l->cmp)(q->key, key) < 0)
			p = q;

	} while (--k >= 0);

	if (!q || (*l->cmp)(q->key, key))
		return -1;

	if (valuePointer)
		*valuePointer = q->value;

	if (cursor)
		*cursor = q;

	return 0;
}

int skiplist_search(register struct skiplist *l, register void *key,
		    void **valuePointer)
{
	return skiplist_first_value(l, key, valuePointer, NULL);
}


/*
 * Caller supplies key and value of an existing item in the list.
 * Function returns the value of the next list item that has the
 * same key (useful when SKIPLIST_FLAG_ALLOW_DUPLICATES is set).
 *
 * Returns 0 on success. If the caller-supplied key and value
 * do not correspond to a list element, or if they specify the
 * last element with the given key, -1 is returned.
 */
int skiplist_next_value(register struct skiplist *l, /* in */
			register void *key,	  /* in */
			void **valuePointer,	 /* in/out */
			void **cursor)		     /* in/out */
{
	register int k, m;
	register struct skiplistnode *p, *q;

	CHECKLAST(l);

	if (!(l->flags & SKIPLIST_FLAG_ALLOW_DUPLICATES)) {
		return -1;
	}

	if (!cursor || !*cursor) {
		p = l->header;
		k = m = l->level;

		/*
		 * Find matching key
		 */
		do {
			while (q = p->forward[k],
			       q && (*l->cmp)(q->key, key) < 0)
				p = q;
		} while (--k >= 0);

		/*
		 * Find matching value
		 */
		while (q && ((*l->cmp)(q->key, key) == 0)
		       && (q->value != *valuePointer)) {
			q = q->forward[0];
		}

		if (!q || ((*l->cmp)(q->key, key) != 0)
		    || (q->value != *valuePointer)) {
			/*
			 * No matching value
			 */
			CHECKLAST(l);
			return -1;
		}
	} else {
		q = (struct skiplistnode *)*cursor;
	}

	/*
	 * Advance cursor
	 */
	q = q->forward[0];

	/*
	 * If we reached end-of-list or if the key is no longer the same,
	 * then return error
	 */
	if (!q || ((*l->cmp)(q->key, key) != 0))
		return -1;

	*valuePointer = q->value;
	if (cursor)
		*cursor = q;
	CHECKLAST(l);
	return 0;
}

int skiplist_first(register struct skiplist *l, void **keyPointer,
		   void **valuePointer)
{
	register struct skiplistnode *p;

	CHECKLAST(l);
	p = l->header->forward[0];
	if (!p)
		return -1;

	if (keyPointer)
		*keyPointer = p->key;

	if (valuePointer)
		*valuePointer = p->value;

	CHECKLAST(l);

	return 0;
}

int skiplist_last(register struct skiplist *l, void **keyPointer,
		  void **valuePointer)
{
	CHECKLAST(l);
	if (l->last) {
		if (keyPointer)
			*keyPointer = l->last->key;
		if (valuePointer)
			*valuePointer = l->last->value;
		return 0;
	}
	return -1;
}

/*
 * true = empty
 */
int skiplist_empty(register struct skiplist *l)
{
	CHECKLAST(l);
	if (l->last)
		return 0;
	return 1;
}

/*
 * Use this to walk the list. Caller sets *cursor to NULL to obtain
 * first element. Return value of 0 indicates valid cursor/element
 * returned, otherwise NULL cursor arg or EOL.
 */
int skiplist_next(register struct skiplist *l, /* in */
		  void **keyPointer,	   /* out */
		  void **valuePointer,	 /* out */
		  void **cursor)	       /* in/out */
{
	struct skiplistnode *p;

	if (!cursor)
		return -1;

	CHECKLAST(l);

	if (!*cursor) {
		p = l->header->forward[0];
	} else {
		p = *cursor;
		p = p->forward[0];
	}
	*cursor = p;

	if (!p)
		return -1;

	if (keyPointer)
		*keyPointer = p->key;

	if (valuePointer)
		*valuePointer = p->value;

	CHECKLAST(l);

	return 0;
}

int skiplist_delete_first(register struct skiplist *l)
{
	register int k;
	register struct skiplistnode *p, *q;
	int nodelevel = 0;

	CHECKLAST(l);

	p = l->header;
	q = l->header->forward[0];

	if (!q)
		return -1;

	for (k = l->level; k >= 0; --k) {
		if (p->forward[k] == q) {
			p->forward[k] = q->forward[k];
			if ((k == l->level) && (p->forward[k] == NULL)
			    && (l->level > 0))
				--(l->level);
			if (!nodelevel)
				nodelevel = k;
		}
	}

#if SKIPLIST_0TIMER_DEBUG
	q->flags &= ~SKIPLIST_NODE_FLAG_INSERTED;
#endif
	/*
	 * If we are deleting the last element of the list,
	 * update the list's "last" pointer.
	 */
	if (l->last == q) {
		l->last = NULL;
	}

	--(l->stats->forward[nodelevel]);
#if SKIPLIST_DEBUG
	zlog_debug("%s: decremented stats @%p:%d, now %ld", __func__, l,
		   nodelevel,
		   l->stats->forward[nodelevel] - (struct skiplistnode *)NULL);
#endif

	if (l->del)
		(*l->del)(q->value);

	XFREE(MTYPE_SKIP_LIST_NODE, q);

	CHECKLAST(l);

	--(l->count);

	return 0;
}

void skiplist_debug(struct vty *vty, struct skiplist *l)
{
	int i;

	if (!l)
		l = skiplist_last_created;
	vty_out(vty, "Skiplist %p has max level %d\n", l, l->level);
	for (i = l->level; i >= 0; --i)
		vty_out(vty, "  @%d: %ld\n", i,
			(long)((l->stats->forward[i])
			       - (struct skiplistnode *)NULL));
}

static void *scramble(int i)
{
	uintptr_t result;

	result = (unsigned)(i & 0xff) << 24;
	result |= (unsigned)i >> 8;

	return (void *)result;
}

#define sampleSize 65536
void skiplist_test(struct vty *vty)
{
	struct skiplist *l;
	register int i, k;
	void *keys[sampleSize];
	void *v;

	zlog_debug("%s: entry", __func__);

	l = skiplist_new(SKIPLIST_FLAG_ALLOW_DUPLICATES, NULL, NULL);

	zlog_debug("%s: skiplist_new returned %p", __func__, l);

	for (i = 0; i < 4; i++) {

		for (k = 0; k < sampleSize; k++) {
			if (!(k % 1000)) {
				zlog_debug("%s: (%d:%d)", __func__, i, k);
			}
			// keys[k] = (void *)random();
			keys[k] = (void *)scramble(k);
			if (skiplist_insert(l, keys[k], keys[k]))
				zlog_debug("error in insert #%d,#%d", i, k);
		}

		zlog_debug("%s: inserts done", __func__);

		for (k = 0; k < sampleSize; k++) {

			if (!(k % 1000))
				zlog_debug("[%d:%d]", i, k);
			if (skiplist_search(l, keys[k], &v))
				zlog_debug("error in search #%d,#%d", i, k);

			if (v != keys[k])
				zlog_debug("search returned wrong value");
		}


		for (k = 0; k < sampleSize; k++) {

			if (!(k % 1000))
				zlog_debug("<%d:%d>", i, k);
			if (skiplist_delete(l, keys[k], keys[k]))
				zlog_debug("error in delete");
			keys[k] = (void *)scramble(k ^ 0xf0f0f0f0);
			if (skiplist_insert(l, keys[k], keys[k]))
				zlog_debug("error in insert #%d,#%d", i, k);
		}

		for (k = 0; k < sampleSize; k++) {

			if (!(k % 1000))
				zlog_debug("{%d:%d}", i, k);
			if (skiplist_delete_first(l))
				zlog_debug("error in delete_first");
		}
	}

	skiplist_free(l);
}
