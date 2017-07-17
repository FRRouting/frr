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
 */

/* skiplist.h */


#ifndef _ZEBRA_SKIPLIST_H
#define _ZEBRA_SKIPLIST_H

#define SKIPLIST_0TIMER_DEBUG 1

/*
 * skiplistnodes must always contain data to be valid. Adding an
 * empty node to a list is invalid
 */
struct skiplistnode {
	void *key;
	void *value;
#if SKIPLIST_0TIMER_DEBUG
	int flags;
#define SKIPLIST_NODE_FLAG_INSERTED 0x00000001
#endif

	struct skiplistnode *forward[1]; /* variable sized */
};

struct skiplist {
	int flags;

#define SKIPLIST_FLAG_ALLOW_DUPLICATES	0x00000001

	int level; /* max lvl (1 + current # of levels in list) */
	unsigned int count;
	struct skiplistnode *header;
	struct skiplistnode *stats;
	struct skiplistnode
		*last; /* last real list item (NULL if empty list) */

	/*
	 * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
	 * Used as definition of sorted for listnode_add_sort
	 */
	int (*cmp)(void *val1, void *val2);

	/* callback to free user-owned data when listnode is deleted. supplying
	 * this callback is very much encouraged!
	 */
	void (*del)(void *val);
};


/* Prototypes. */
extern struct skiplist *
skiplist_new(/* encouraged: set list.del callback on new lists */
	     int flags,
	     int (*cmp)(void *key1, void *key2), /* NULL => default cmp */
	     void (*del)(void *val));		 /* NULL => no auto val free */

extern void skiplist_free(struct skiplist *);

extern int skiplist_insert(register struct skiplist *l, register void *key,
			   register void *value);

extern int skiplist_delete(register struct skiplist *l, register void *key,
			   register void *value);

extern int skiplist_search(register struct skiplist *l, register void *key,
			   void **valuePointer);

extern int skiplist_first_value(register struct skiplist *l, /* in */
				register void *key,	  /* in */
				void **valuePointer,	 /* in/out */
				void **cursor);		     /* out */

extern int skiplist_next_value(register struct skiplist *l, /* in */
			       register void *key,	  /* in */
			       void **valuePointer,	 /* in/out */
			       void **cursor);		    /* in/out */

extern int skiplist_first(register struct skiplist *l, void **keyPointer,
			  void **valuePointer);

extern int skiplist_last(register struct skiplist *l, void **keyPointer,
			 void **valuePointer);

extern int skiplist_delete_first(register struct skiplist *l);

extern int skiplist_next(register struct skiplist *l, /* in */
			 void **keyPointer,	   /* out */
			 void **valuePointer,	 /* out */
			 void **cursor);	      /* in/out */

extern int skiplist_empty(register struct skiplist *l); /* in */

extern unsigned int skiplist_count(register struct skiplist *l); /* in */

extern void skiplist_debug(struct vty *vty, struct skiplist *l);

extern void skiplist_test(struct vty *vty);

#endif /* _ZEBRA_SKIPLIST_H */
