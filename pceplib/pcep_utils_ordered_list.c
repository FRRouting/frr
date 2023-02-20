// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"
#include "pcep_utils_ordered_list.h"

/* Compare function that simply compares pointers.
 * return:
 *   < 0  if new_entry  < list_entry
 *   == 0 if new_entry == list_entry (new_entry will be inserted after
 * list_entry) > 0  if new_entry  > list_entry
 */
int pointer_compare_function(void *list_entry, void *new_entry)
{
	return (char *)new_entry - (char *)list_entry;
}

ordered_list_handle *ordered_list_initialize(ordered_compare_function func_ptr)
{
	ordered_list_handle *handle =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(ordered_list_handle));
	memset(handle, 0, sizeof(ordered_list_handle));
	handle->head = NULL;
	handle->num_entries = 0;
	handle->compare_function = func_ptr;

	return handle;
}


/* free all the ordered_list_node resources and the ordered_list_handle.
 * it is assumed that the user is responsible fore freeing the data
 * pointed to by the nodes.
 */
void ordered_list_destroy(ordered_list_handle *handle)
{
	if (handle == NULL) {
		return;
	}

	ordered_list_node *node = handle->head;
	ordered_list_node *next;

	while (node != NULL) {
		next = node->next_node;
		pceplib_free(PCEPLIB_INFRA, node);
		node = next;
	}

	pceplib_free(PCEPLIB_INFRA, handle);
}


ordered_list_node *ordered_list_add_node(ordered_list_handle *handle,
					 void *data)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_add_node, the list has not been initialized",
			__func__);
		return NULL;
	}
	handle->num_entries++;

	ordered_list_node *new_node =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(ordered_list_node));
	memset(new_node, 0, sizeof(ordered_list_node));
	new_node->data = data;
	new_node->next_node = NULL;

	/* check if its an empty list */
	if (handle->head == NULL) {
		handle->head = new_node;

		return new_node;
	}

	ordered_list_node *prev_node = handle->head;
	ordered_list_node *node = prev_node;
	int compare_result;

	while (node != NULL) {
		compare_result = handle->compare_function(node->data, data);
		if (compare_result < 0) {
			/* insert the node */
			new_node->next_node = node;
			if (handle->head == node) {
				/* add it at the beginning of the list */
				handle->head = new_node;
			} else {
				prev_node->next_node = new_node;
			}

			return new_node;
		}

		/* keep searching with the next node in the list */
		prev_node = node;
		node = node->next_node;
	}

	/* at the end of the list, add it here */
	prev_node->next_node = new_node;

	return new_node;
}


ordered_list_node *ordered_list_find2(ordered_list_handle *handle, void *data,
				      ordered_compare_function compare_func)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_find2, the list has not been initialized",
			__func__);
		return NULL;
	}

	ordered_list_node *node = handle->head;
	int compare_result;

	while (node != NULL) {
		compare_result = compare_func(node->data, data);
		if (compare_result == 0) {
			return node;
		} else {
			node = node->next_node;
		}
	}

	return NULL;
}


ordered_list_node *ordered_list_find(ordered_list_handle *handle, void *data)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_find, the list has not been initialized",
			__func__);
		return NULL;
	}

	return ordered_list_find2(handle, data, handle->compare_function);
}


void *ordered_list_remove_first_node(ordered_list_handle *handle)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_remove_first_node, the list has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->head == NULL) {
		return NULL;
	}
	handle->num_entries--;

	void *data = handle->head->data;
	ordered_list_node *next_node = handle->head->next_node;
	pceplib_free(PCEPLIB_INFRA, handle->head);
	handle->head = next_node;

	return data;
}


void *
ordered_list_remove_first_node_equals2(ordered_list_handle *handle, void *data,
				       ordered_compare_function compare_func)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_remove_first_node_equals2, the list has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->head == NULL) {
		return NULL;
	}

	ordered_list_node *prev_node = handle->head;
	ordered_list_node *node = prev_node;
	bool keep_walking = true;
	void *return_data = NULL;
	int compare_result;

	while (node != NULL && keep_walking) {
		compare_result = compare_func(node->data, data);
		if (compare_result == 0) {
			return_data = node->data;
			keep_walking = false;
			handle->num_entries--;

			/* adjust the corresponding pointers accordingly */
			if (handle->head == node) {
				/* its the first node in the list */
				handle->head = node->next_node;
			} else {
				prev_node->next_node = node->next_node;
			}

			pceplib_free(PCEPLIB_INFRA, node);
		} else {
			prev_node = node;
			node = node->next_node;
		}
	}

	return return_data;
}


void *ordered_list_remove_first_node_equals(ordered_list_handle *handle,
					    void *data)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_remove_first_node_equals, the list has not been initialized",
			__func__);
		return NULL;
	}

	return ordered_list_remove_first_node_equals2(handle, data,
						      handle->compare_function);
}


void *ordered_list_remove_node(ordered_list_handle *handle,
			       ordered_list_node *prev_node,
			       ordered_list_node *node_toRemove)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_remove_node, the list has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->head == NULL) {
		return NULL;
	}

	void *return_data = node_toRemove->data;
	handle->num_entries--;

	if (node_toRemove == handle->head) {
		handle->head = node_toRemove->next_node;
	} else {
		prev_node->next_node = node_toRemove->next_node;
	}

	pceplib_free(PCEPLIB_INFRA, node_toRemove);

	return return_data;
}

void *ordered_list_remove_node2(ordered_list_handle *handle,
				ordered_list_node *node_to_remove)
{
	if (handle == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: ordered_list_remove_node2, the list has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->head == NULL) {
		return NULL;
	}

	ordered_list_node *node = handle->head;
	ordered_list_node *prev_node = handle->head;

	while (node != NULL) {
		if (node == node_to_remove) {
			return (ordered_list_remove_node(handle, prev_node,
							 node));
		} else {
			prev_node = node;
			node = node->next_node;
		}
	}

	return NULL;
}
