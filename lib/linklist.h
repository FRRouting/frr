// SPDX-License-Identifier: GPL-2.0-or-later
/* Generic linked list
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_LINKLIST_H
#define _ZEBRA_LINKLIST_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOTICE:
 *
 * If you are reading this file in an effort to add a new list structure
 * this is the wrong place to be using it.  Please see the typesafe
 * data structures, or ask one of the other developers.
 *
 * If you are reading this file as a way to update an existing usage
 * of this data structure, please consider just converting the data
 * structure to one of the typesafe data structures instead.
 */

/* listnodes must always contain data to be valid. Adding an empty node
 * to a list is invalid
 */
struct listnode {
	struct listnode *next;
	struct listnode *prev;

	/* private member, use getdata() to retrieve, do not access directly */
	void *data;
};

struct list {
	struct listnode *head;
	struct listnode *tail;

	/* invariant: count is the number of listnodes in the list */
	unsigned int count;

	uint8_t flags;
/* Indicates that listnode memory is managed by the application and
 * doesn't need to be freed by this library via listnode_delete etc.
 */
#define LINKLIST_FLAG_NODE_MEM_BY_APP (1 << 0)

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

#define listnextnode(X) ((X) ? ((X)->next) : NULL)
#define listnextnode_unchecked(X) ((X)->next)
#define listhead(X) ((X) ? ((X)->head) : NULL)
#define listhead_unchecked(X) ((X)->head)
#define listtail(X) ((X) ? ((X)->tail) : NULL)
#define listtail_unchecked(X) ((X)->tail)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
/* return X->data only if X and X->data are not NULL */
#define listgetdata(X) (assert(X), assert((X)->data != NULL), (X)->data)
/* App is going to manage listnode memory */
#define listset_app_node_mem(X) ((X)->flags |= LINKLIST_FLAG_NODE_MEM_BY_APP)
#define listnode_init(X, val) ((X)->data = (val))

/*
 * Create a new linked list.
 *
 * Returns:
 *    the created linked list
 */
extern struct list *list_new(void);

/*
 * Add a new element to the tail of a list.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * data
 *    element to add
 */
extern struct listnode *listnode_add(struct list *list, void *data);

/*
 * Add a new element to the beginning of a list.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * data
 *    If MEM_BY_APP is set this is listnode. Otherwise it is element to add.
 */
extern void listnode_add_head(struct list *list, void *data);

/*
 * Insert a new element into a list with insertion sort.
 *
 * If list->cmp is set, this function is used to determine the position to
 * insert the new element. If it is not set, this function is equivalent to
 * listnode_add.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * val
 *    If MEM_BY_APP is set this is listnode. Otherwise it is element to add.
 */
extern void listnode_add_sort(struct list *list, void *val);

/*
 * Insert a new element into a list after another element.
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
 *    If MEM_BY_APP is set this is listnode. Otherwise it is element to add.
 *
 * Returns:
 *    pointer to newly created listnode that contains the inserted data
 */
extern struct listnode *listnode_add_after(struct list *list,
					   struct listnode *pp, void *data);

/*
 * Insert a new element into a list before another element.
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
 *    If MEM_BY_APP is set this is listnode. Otherwise it is element to add.
 *
 * Returns:
 *    pointer to newly created listnode that contains the inserted data
 */
extern struct listnode *listnode_add_before(struct list *list,
					    struct listnode *pp, void *data);

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
 * Delete an element from a list.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * data
 *    data to insert into list
 */
extern void listnode_delete(struct list *list, const void *data);

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
extern struct listnode *listnode_lookup(struct list *list, const void *data);

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
 * Convert a list to an array of void pointers.
 *
 * Starts from the list head and ends either on the last node of the list or
 * when the provided array cannot store any more elements.
 *
 * list
 *    list to convert
 *
 * arr
 *    Pre-allocated array of void *
 *
 * arrlen
 *    Number of elements in arr
 *
 * Returns:
 *    arr
 */
void **list_to_array(struct list *list, void **arr, size_t arrlen);

/*
 * Delete a list and NULL its pointer.
 *
 * If non-null, list->del is called with each data element.
 *
 * plist
 *    pointer to list pointer; this will be set to NULL after the list has been
 *    deleted
 */
extern void list_delete(struct list **plist);

/*
 * Delete all nodes from a list without deleting the list itself.
 *
 * If non-null, list->del is called with each data element.
 *
 * list
 *    list to operate on
 */
extern void list_delete_all_node(struct list *list);

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
extern void list_delete_node(struct list *list, struct listnode *node);

/*
 * Insert a new element into a list with insertion sort if there is no
 * duplicate element present in the list. This assumes the input list is
 * sorted. If unsorted, it will check for duplicate until it finds out
 * the position to do insertion sort with the unsorted list.
 *
 * If list->cmp is set, this function is used to determine the position to
 * insert the new element. If it is not set, this function is equivalent to
 * listnode_add. duplicate element is determined by cmp function returning 0.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * val
 *    If MEM_BY_APP is set this is listnode. Otherwise it is element to add.
 */

extern bool listnode_add_sort_nodup(struct list *list, void *val);

/*
 * Duplicate the specified list, creating a shallow copy of each of its
 * elements.
 *
 * list
 *    list to duplicate
 *
 * Returns:
 *    the duplicated list
 */
extern struct list *list_dup(struct list *list);

/* List iteration macro.
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the listnode using this macro.
 */
#define ALL_LIST_ELEMENTS(list, node, nextnode, data)                          \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL                                                         \
		&& ((data) = static_cast(data, listgetdata(node)),             \
		    (nextnode) = node->next, 1);                               \
	(node) = (nextnode), ((data) = NULL)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the listnode Only
 * use this macro when it is *immediately obvious* the listnode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define ALL_LIST_ELEMENTS_RO(list, node, data)                                 \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = static_cast(data, listgetdata(node)), 1);  \
	(node) = listnextnode(node), ((data) = NULL)

extern struct listnode *listnode_lookup_nocheck(struct list *list, void *data);

/*
 * Add a node to *list, if non-NULL. Otherwise, allocate a new list, mail
 * it back in *list, and add a new node.
 *
 * Return: the new node.
 */
extern struct listnode *listnode_add_force(struct list **list, void *val);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LINKLIST_H */
