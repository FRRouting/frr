/* Generic linked list
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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

#ifndef _ZEBRA_LINKLIST_H
#define _ZEBRA_LINKLIST_H

/* listnodes must always contain data to be valid. Adding an empty node
 * to a list is invalid
 */
struct listnode {
	struct listnode *next;
	struct listnode *prev;

	/* private member, use getdata() to retrieve, do not access directly */
	void *data;
};

typedef enum { LIST_DEBUG_DEFAULT, LIST_DEBUG_PRE_DELETE, LIST_DEBUG_POST_DELETE, LIST_DEBUG_PRE_INSERT, LIST_DEBUG_POST_INSERT } list_debug_stage_t;
extern const char * const list_debug_stage_s[];

struct list {
	struct listnode *head;
	struct listnode *tail;

	/* invariant: count is the number of listnodes in the list */
	unsigned int count;

	/*
	 * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
	 * Used as definition of sorted for listnode_add_sort
	 */
	int (*cmp)(void *val1, void *val2);

	/* callback to free user-owned data when listnode is deleted. supplying
	 * this callback is very much encouraged!
	 */
	void (*del)(void *val);

	/*
	 * callback for debugging list inserts and deletes
	 */
	void (*debug)(list_debug_stage_t, struct list *, struct listnode*, void *val, const char *, const char *, int);

	int debug_on;
};

#define listnextnode(X) ((X) ? ((X)->next) : NULL)
#define listhead(X) ((X) ? ((X)->head) : NULL)
#define listtail(X) ((X) ? ((X)->tail) : NULL)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
/* return X->data only if X and X->data are not NULL */
#define listgetdata(X) (assert(X), assert((X)->data != NULL), (X)->data)

/*
 * Create a new linked list.
 * 		_cb provides callbacks (NULL values okay)
 * 		_cb_cf provides calling function information and debugging when callback functions are installed and debug is enabled
 *
 * Returns:
 *    the created linked list
 */
#define list_new()		list_new_cb_cf(NULL,NULL,NULL,0,__FILE__,__PRETTY_FUNCTION__,__LINE__)
#define list_new_cb(cmp,del,dfunc,dflag)	list_new_cb_cf(cmp,del,dfunc,dflag,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern struct list *list_new_cb_cf(
		int (*cmp)(void *val1, void *val2),
		void (*del)(void *val),
		void (*debug)(list_debug_stage_t, struct list *, struct listnode*, void *val, const char *, const char *, int),
		int debug_val,
		const char *, const char *, int);

/*
 * Add a new element to the tail of a list.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * data
 *    element to add
 */
#define listnode_add(list,data)		listnode_add_cf(list,data,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void listnode_add_cf(struct list *list, void *val, const char *, const char *, int);

/*
 * Insert a new element into a list with insertion sort.
 *
 * If list->cmp is set, this function is used to determine the position to
 * insert the new element. If it is not set, this function is equivalent to
 * listnode_add.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * val
 *    element to add
 */
#define listnode_add_sort(list,data)		listnode_add_sort_cf(list,data,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void listnode_add_sort_cf(struct list *list, void *val, const char *, const char *, int);

/*
 * Insert a new element into a list after another element.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * pp
 *    listnode to insert after
 *
 * data
 *    data to insert
 *
 * Returns:
 *    pointer to newly created listnode that contains the inserted data
 */
#define listnode_add_after(l,p,d)		listnode_add_after_cf(l,p,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern struct listnode *listnode_add_after_cf(struct list *list,
					   struct listnode *pp, void *data,
						const char *, const char *, int);
/*
 * Insert a new element into a list before another element.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * pp
 *    listnode to insert before
 *
 * data
 *    data to insert
 *
 * Returns:
 *    pointer to newly created listnode that contains the inserted data
 */
#define listnode_add_before(l,p,d)		listnode_add_before_cf(l,p,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern struct listnode *listnode_add_before_cf(struct list *list,
					    struct listnode *pp, void *data,
						const char *, const char *, int);

/*
 * Move a node to the tail of a list.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * node
 *    node to move to tail
 */
extern void listnode_move_to_tail(struct list *list, struct listnode *node);

/*
 * Delete an element from a list. List node is deleted. Data is not.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * data
 *    data to insert into list
 */
#define listnode_delete(l,d)		listnode_delete_cf(l,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void listnode_delete_cf(struct list *list, void *data,
		const char *, const char *, int);

/*
 * Destroy an element from a list. If there is a delete callback, the
 * data is destroyed with it, otherwise it is freed with free();
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * data
 *    data to insert into list
 */
#define listnode_destroy(l,d)		listnode_delete_cf(l,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void listnode_destroy_cf(struct list *list, void *data,
		const char *, const char *, int);

/*
 * Find the listnode corresponding to an element in a list.
 *
 * list
 *    list to operate on
 *
 * data
 *    data to search for
 *
 * Returns:
 *    pointer to listnode storing the given data if found, NULL otherwise
 */
extern struct listnode *listnode_lookup(struct list *list, void *data);

/*
 * Retrieve the element at the head of a list.
 *
 * list
 *    list to operate on
 *
 * Returns:
 *    data at head of list, or NULL if list is empty
 */
extern void *listnode_head(struct list *list);

/*
 * Duplicate a list.
 *
 * list
 *    list to duplicate
 *
 * Returns:
 *    copy of the list
 */
extern struct list *list_dup(struct list *l);

/*
 * Sort a list in place.
 *
 * The sorting algorithm used is quicksort. Runtimes are equivalent to those of
 * quicksort plus N. The sort is not stable.
 *
 * For portability reasons, the comparison function takes a pointer to pointer
 * to void. This pointer should be dereferenced to get the actual data pointer.
 * It is always safe to do this.
 *
 * list
 *    list to sort
 *
 * cmp
 *    comparison function for quicksort. Should return less than, equal to or
 *    greater than zero if the first argument is less than, equal to or greater
 *    than the second argument.
 */
extern void list_sort(struct list *list,
		      int (*cmp)(const void **, const void **));

/*
 * The usage of list_delete is being transitioned to pass in
 * the double pointer to remove use after free's.
 * list_free usage is deprecated, it leads to memory leaks
 * of the linklist nodes.  Please use list_delete_and_null
 *
 * In Oct of 2018, rename list_delete_and_null to list_delete
 * and remove list_delete_original and the list_delete #define
 * Additionally remove list_free entirely
 */
#if defined(VERSION_TYPE_DEV) && CONFDATE > 20181001
CPP_NOTICE("list_delete without double pointer is deprecated, please fixup")
#endif

/*
 * Delete a list and NULL its pointer.
 *
 * If non-null, list->del is called with each data element.
 *
 * plist
 *    pointer to list pointer; this will be set to NULL after the list has been
 *    deleted
 */
extern void list_delete_and_null(struct list **plist);

/*
 * Delete a list.
 *
 * If non-null, list->del is called with each data element.
 *
 * plist
 *    pointer to list pointer
 */
extern void list_delete_original(struct list *list);
#define list_delete(X)                                                         \
	list_delete_original((X))                                              \
		CPP_WARN("Please transition to using list_delete_and_null")
#define list_free(X)                                                           \
	list_delete_original((X))                                              \
		CPP_WARN("Please transition tousing list_delete_and_null")

/*
 * Delete all nodes from a list without deleting the list itself.
 *
 * If non-null, list->del is called with each data element.
 *
 * list
 *    list to operate on
 */
#define list_delete_all_node(l)			list_delete_all_node_cf(l,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void list_delete_all_node_cf(struct list *list,
		const char *, const char *, int);

/*
 * Delete a node from a list.
 *
 * list->del is not called with the data associated with the node.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * node
 *    the node to delete
 */
#define list_delete_node(l,n)		list_delete_node_cf(l,n,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void list_delete_node_cf(struct list *list, struct listnode *node,
		const char *, const char *, int);

/*
 * Append a list to an existing list.
 *
 * Runtime is O(N) where N = listcount(add).
 *
 * list
 *    list to append to
 *
 * add
 *    list to append
 */
extern void list_add_list(struct list *list, struct list *add);

/* List iteration macro.
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define ALL_LIST_ELEMENTS(list, node, nextnode, data)                          \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), (nextnode) = node->next, 1);   \
	(node) = (nextnode), ((data) = NULL)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the listnode Only
 * use this macro when it is *immediately obvious* the listnode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define ALL_LIST_ELEMENTS_RO(list, node, data)                                 \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), 1);                     \
	(node) = listnextnode(node), ((data) = NULL)

/* these *do not* cleanup list nodes and referenced data, as the functions
 * do - these macros simply {de,at}tach a listnode from/to a list.
 */

/* List node attach macro.  */
#define LISTNODE_ATTACH(L, N)                                                  \
	do {                                                                   \
		(N)->prev = (L)->tail;                                         \
		(N)->next = NULL;                                              \
		if ((L)->head == NULL)                                         \
			(L)->head = (N);                                       \
		else                                                           \
			(L)->tail->next = (N);                                 \
		(L)->tail = (N);                                               \
		(L)->count++;                                                  \
	} while (0)

/* List node detach macro.  */
#define LISTNODE_DETACH(L, N)                                                  \
	do {                                                                   \
		if ((N)->prev)                                                 \
			(N)->prev->next = (N)->next;                           \
		else                                                           \
			(L)->head = (N)->next;                                 \
		if ((N)->next)                                                 \
			(N)->next->prev = (N)->prev;                           \
		else                                                           \
			(L)->tail = (N)->prev;                                 \
		(L)->count--;                                                  \
	} while (0)

#endif /* _ZEBRA_LINKLIST_H */
