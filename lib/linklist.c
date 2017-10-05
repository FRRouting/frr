/* Generic linked list routine.
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

#include <zebra.h>

#include "linklist.h"
#include "memory.h"

DEFINE_MTYPE_STATIC(LIB, LINK_LIST, "Link List")
DEFINE_MTYPE_STATIC(LIB, LINK_NODE, "Link Node")

/* Allocate new list. */
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
static struct listnode *listnode_new(void)
{
	return XCALLOC(MTYPE_LINK_NODE, sizeof(struct listnode));
}

/* Free listnode. */
static void listnode_free(struct listnode *node)
{
	XFREE(MTYPE_LINK_NODE, node);
}

/* Add new data to the list. */
void listnode_add(struct list *list, void *val)
{
	struct listnode *node;

	assert(val != NULL);

	node = listnode_new();

	node->prev = list->tail;
	node->data = val;

	if (list->head == NULL)
		list->head = node;
	else
		list->tail->next = node;
	list->tail = node;

	list->count++;
}

/*
 * Add a node to the list.  If the list was sorted according to the
 * cmp function, insert a new node with the given val such that the
 * list remains sorted.  The new node is always inserted; there is no
 * notion of omitting duplicates.
 */
void listnode_add_sort(struct list *list, void *val)
{
	struct listnode *n;
	struct listnode *new;

	assert(val != NULL);

	new = listnode_new();
	new->data = val;

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

	nn = listnode_new();
	nn->data = val;

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

	nn = listnode_new();
	nn->data = val;

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

/* Move given listnode to tail of the list */
void listnode_move_to_tail(struct list *l, struct listnode *n)
{
	LISTNODE_DETACH(l, n);
	LISTNODE_ATTACH(l, n);
}

/* Delete specific date pointer from the list. */
void listnode_delete(struct list *list, void *val)
{
	struct listnode *node;

	assert(list);
	for (node = list->head; node; node = node->next) {
		if (node->data == val) {
			if (node->prev)
				node->prev->next = node->next;
			else
				list->head = node->next;

			if (node->next)
				node->next->prev = node->prev;
			else
				list->tail = node->prev;

			list->count--;
			listnode_free(node);
			return;
		}
	}
}

/* Return first node's data if it is there.  */
void *listnode_head(struct list *list)
{
	struct listnode *node;

	assert(list);
	node = list->head;

	if (node)
		return node->data;
	return NULL;
}

/* Delete all listnode from the list. */
void list_delete_all_node(struct list *list)
{
	struct listnode *node;
	struct listnode *next;

	assert(list);
	for (node = list->head; node; node = next) {
		next = node->next;
		if (*list->del)
			(*list->del)(node->data);
		listnode_free(node);
	}
	list->head = list->tail = NULL;
	list->count = 0;
}

/* Delete all listnode then free list itself. */
void list_delete_and_null(struct list **list)
{
	assert(*list);
	list_delete_all_node(*list);
	list_free_internal(*list);
	*list = NULL;
}

void list_delete_original(struct list *list)
{
	list_delete_and_null(&list);
}

/* Lookup the node which has given data. */
struct listnode *listnode_lookup(struct list *list, void *data)
{
	struct listnode *node;

	assert(list);
	for (node = listhead(list); node; node = listnextnode(node))
		if (data == listgetdata(node))
			return node;
	return NULL;
}

/* Delete the node from list.  For ospfd and ospf6d. */
void list_delete_node(struct list *list, struct listnode *node)
{
	if (node->prev)
		node->prev->next = node->next;
	else
		list->head = node->next;
	if (node->next)
		node->next->prev = node->prev;
	else
		list->tail = node->prev;
	list->count--;
	listnode_free(node);
}

/* ospf_spf.c */
void list_add_list(struct list *l, struct list *m)
{
	struct listnode *n;

	for (n = listhead(m); n; n = listnextnode(n))
		listnode_add(l, n->data);
}
