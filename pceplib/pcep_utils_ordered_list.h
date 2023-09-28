// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifndef INCLUDE_PCEPUTILSORDEREDLIST_H_
#define INCLUDE_PCEPUTILSORDEREDLIST_H_

#include <stdbool.h>

typedef struct ordered_list_node_ {
	struct ordered_list_node_ *next_node;
	void *data;

} ordered_list_node;

/* The implementation of this function will receive a pointer to the
 * new data to be inserted and a pointer to the list_entry, and should
 * return:
 *   < 0  if new_entry  < list_entry
 *   == 0 if new_entry == list_entry (new_entry will be inserted after
 * list_entry) > 0  if new_entry  > list_entry
 */
typedef int (*ordered_compare_function)(void *list_entry, void *new_entry);

/* Compare function that compares pointers */
int pointer_compare_function(void *list_entry, void *new_entry);

typedef struct ordered_list_handle_ {
	ordered_list_node *head;
	unsigned int num_entries;
	ordered_compare_function compare_function;

} ordered_list_handle;

ordered_list_handle *ordered_list_initialize(ordered_compare_function func_ptr);
void ordered_list_destroy(ordered_list_handle *handle);

/* Add a new ordered_list_node to the list, using the ordered_compare_function
 * to determine where in the list to add it. The newly created ordered_list_node
 * will be returned.
 */
ordered_list_node *ordered_list_add_node(ordered_list_handle *handle,
					 void *data);

/* Find an entry in the ordered_list using the ordered_compare_function to
 * compare the data passed in.
 * Return the node if found, NULL otherwise.
 */
ordered_list_node *ordered_list_find(ordered_list_handle *handle, void *data);

/* The same as the previous function, but with a specific orderedComparefunction
 */
ordered_list_node *ordered_list_find2(ordered_list_handle *handle, void *data,
				      ordered_compare_function compare_func);

/* Remove the first entry in the list and return the data it points to.
 * Will return NULL if the handle is NULL or if the list is empty.
 */
void *ordered_list_remove_first_node(ordered_list_handle *handle);

/* Remove the first entry in the list that has the same data, using the
 * ordered_compare_function, and return the data it points to.
 * Will return NULL if the handle is NULL or if the list is empty or
 * if no entry is found that equals data.
 */
void *ordered_list_remove_first_node_equals(ordered_list_handle *handle,
					    void *data);

/* The same as the previous function, but with a specific orderedComparefunction
 */
void *ordered_list_remove_first_node_equals2(ordered_list_handle *handle,
					     void *data,
					     ordered_compare_function func_ptr);

/* Remove the node "node_to_remove" and adjust the "prev_node" pointers
 * accordingly, returning the data pointed to by "node_to_remove". Will return
 * NULL if the handle is NULL or if the list is empty.
 */
void *ordered_list_remove_node(ordered_list_handle *handle,
			       ordered_list_node *prev_node,
			       ordered_list_node *node_to_remove);

/* Remove the node "node_to_remove" by searching for it in the entire list,
 * returning the data pointed to by "node_to_remove".
 * Will return NULL if the handle is NULL or if the list is empty.
 */
void *ordered_list_remove_node2(ordered_list_handle *handle,
				ordered_list_node *node_to_remove);

#endif /* INCLUDE_PCEPUTILSORDEREDLIST_H_ */
