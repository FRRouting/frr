// SPDX-License-Identifier: GPL-2.0-or-later
/* Generic linked list routine.
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <stdlib.h>

#include "linklist.h"
#include "memory.h"
#include "libfrr_trace.h"

DEFINE_MTYPE_STATIC(LIB, LINK_LIST, "Link List");
DEFINE_MTYPE_STATIC(LIB, LINK_NODE, "Link Node");

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

struct list *list_new(void)
{
	return XCALLOC(MTYPE_LINK_LIST, sizeof(struct list));
}

/* Free list. */
static void list_free_internal(struct list *l)
{
	XFREE(MTYPE_LINK_LIST, l);
}


/* Allocate new listnode.  Internal use only. */
static struct listnode *listnode_new(struct list *list, void *val)
{
	struct listnode *node;

	/* if listnode memory is managed by the app then the val
	 * passed in is the listnode
	 */
	if (list->flags & LINKLIST_FLAG_NODE_MEM_BY_APP) {
		node = val;
		node->prev = node->next = NULL;
	} else {
		node = XCALLOC(MTYPE_LINK_NODE, sizeof(struct listnode));
		node->data = val;
	}
	return node;
}

/* Free listnode. */
static void listnode_free(struct list *list, struct listnode *node)
{
	if (!(list->flags & LINKLIST_FLAG_NODE_MEM_BY_APP))
		XFREE(MTYPE_LINK_NODE, node);
}

struct listnode *listnode_add(struct list *list, void *val)
{
	frrtrace(2, frr_libfrr, list_add, list, val);

	struct listnode *node;

	assert(val != NULL);

	node = listnode_new(list, val);

	node->prev = list->tail;

	if (list->head == NULL)
		list->head = node;
	else
		list->tail->next = node;
	list->tail = node;

	list->count++;

	return node;
}

void listnode_add_head(struct list *list, void *val)
{
	struct listnode *node;

	assert(val != NULL);

	node = listnode_new(list, val);

	node->next = list->head;

	if (list->head == NULL) {
		list->head = node;
		list->tail = node;
	} else
		list->head->prev = node;
	list->head = node;

	list->count++;
}

bool listnode_add_sort_nodup(struct list *list, void *val)
{
	struct listnode *n;
	struct listnode *new;
	int ret;
	void *data;

	assert(val != NULL);

	if (list->flags & LINKLIST_FLAG_NODE_MEM_BY_APP) {
		n = val;
		data = n->data;
	} else {
		data = val;
	}

	if (list->cmp) {
		for (n = list->head; n; n = n->next) {
			ret = (*list->cmp)(data, n->data);
			if (ret < 0) {
				new = listnode_new(list, val);

				new->next = n;
				new->prev = n->prev;

				if (n->prev)
					n->prev->next = new;
				else
					list->head = new;
				n->prev = new;
				list->count++;
				return true;
			}
			/* found duplicate return false */
			if (ret == 0)
				return false;
		}
	}

	new = listnode_new(list, val);

	LISTNODE_ATTACH(list, new);

	return true;
}

struct list *list_dup(struct list *list)
{
	struct list *dup;
	struct listnode *node;
	void *data;

	assert(list);

	dup = list_new();
	dup->cmp = list->cmp;
	dup->del = list->del;
	for (ALL_LIST_ELEMENTS_RO(list, node, data))
		listnode_add(dup, data);

	return dup;
}

void listnode_add_sort(struct list *list, void *val)
{
	struct listnode *n;
	struct listnode *new;

	assert(val != NULL);

	new = listnode_new(list, val);
	val = new->data;

	if (list->cmp) {
		for (n = list->head; n; n = n->next) {
			if ((*list->cmp)(val, n->data) < 0) {
				new->next = n;
				new->prev = n->prev;

				if (n->prev)
					n->prev->next = new;
				else
					list->head = new;
				n->prev = new;
				list->count++;
				return;
			}
		}
	}

	new->prev = list->tail;

	if (list->tail)
		list->tail->next = new;
	else
		list->head = new;

	list->tail = new;
	list->count++;
}

struct listnode *listnode_add_after(struct list *list, struct listnode *pp,
				    void *val)
{
	struct listnode *nn;

	assert(val != NULL);

	nn = listnode_new(list, val);

	if (pp == NULL) {
		if (list->head)
			list->head->prev = nn;
		else
			list->tail = nn;

		nn->next = list->head;
		nn->prev = pp;

		list->head = nn;
	} else {
		if (pp->next)
			pp->next->prev = nn;
		else
			list->tail = nn;

		nn->next = pp->next;
		nn->prev = pp;

		pp->next = nn;
	}
	list->count++;
	return nn;
}

struct listnode *listnode_add_before(struct list *list, struct listnode *pp,
				     void *val)
{
	struct listnode *nn;

	assert(val != NULL);

	nn = listnode_new(list, val);

	if (pp == NULL) {
		if (list->tail)
			list->tail->next = nn;
		else
			list->head = nn;

		nn->prev = list->tail;
		nn->next = pp;

		list->tail = nn;
	} else {
		if (pp->prev)
			pp->prev->next = nn;
		else
			list->head = nn;

		nn->prev = pp->prev;
		nn->next = pp;

		pp->prev = nn;
	}
	list->count++;
	return nn;
}

void listnode_move_to_tail(struct list *l, struct listnode *n)
{
	LISTNODE_DETACH(l, n);
	LISTNODE_ATTACH(l, n);
}

void listnode_delete(struct list *list, const void *val)
{
	frrtrace(2, frr_libfrr, list_remove, list, val);

	struct listnode *node = listnode_lookup(list, val);

	if (node)
		list_delete_node(list, node);
}

void *listnode_head(struct list *list)
{
	struct listnode *node;

	assert(list);
	node = list->head;

	if (node)
		return node->data;
	return NULL;
}

void list_delete_all_node(struct list *list)
{
	struct listnode *node;
	struct listnode *next;

	assert(list);
	for (node = list->head; node; node = next) {
		next = node->next;
		if (*list->del)
			(*list->del)(node->data);
		listnode_free(list, node);
	}
	list->head = list->tail = NULL;
	list->count = 0;
}

void list_delete(struct list **list)
{
	assert(*list);
	list_delete_all_node(*list);
	list_free_internal(*list);
	*list = NULL;
}

struct listnode *listnode_lookup(struct list *list, const void *data)
{
	struct listnode *node;

	assert(list);
	for (node = listhead(list); node; node = listnextnode(node))
		if (data == listgetdata(node))
			return node;
	return NULL;
}

struct listnode *listnode_lookup_nocheck(struct list *list, void *data)
{
	if (!list)
		return NULL;
	return listnode_lookup(list, data);
}

void list_delete_node(struct list *list, struct listnode *node)
{
	frrtrace(2, frr_libfrr, list_delete_node, list, node);

	if (node->prev)
		node->prev->next = node->next;
	else
		list->head = node->next;
	if (node->next)
		node->next->prev = node->prev;
	else
		list->tail = node->prev;
	list->count--;
	listnode_free(list, node);
}

void list_sort(struct list *list, int (*cmp)(const void **, const void **))
{
	frrtrace(1, frr_libfrr, list_sort, list);

	struct listnode *ln, *nn;
	int i = -1;
	void *data;
	size_t n = list->count;
	void **items;
	int (*realcmp)(const void *, const void *) =
		(int (*)(const void *, const void *))cmp;

	if (!n)
		return;

	items = XCALLOC(MTYPE_TMP, (sizeof(void *)) * n);

	for (ALL_LIST_ELEMENTS(list, ln, nn, data)) {
		items[++i] = data;
		list_delete_node(list, ln);
	}

	qsort(items, n, sizeof(void *), realcmp);

	for (unsigned int j = 0; j < n; ++j)
		listnode_add(list, items[j]);

	XFREE(MTYPE_TMP, items);
}

struct listnode *listnode_add_force(struct list **list, void *val)
{
	if (*list == NULL)
		*list = list_new();
	return listnode_add(*list, val);
}

void **list_to_array(struct list *list, void **arr, size_t arrlen)
{
	struct listnode *ln;
	void *vp;
	size_t idx = 0;

	for (ALL_LIST_ELEMENTS_RO(list, ln, vp)) {
		arr[idx++] = vp;
		if (idx == arrlen)
			break;
	}

	return arr;
}
