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

#include <assert.h>
#include <CUnit/CUnit.h>

#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_double_linked_list_test.h"

typedef struct dll_node_data_ {
	int int_data;

} dll_node_data;

void test_empty_dl_list()
{
	double_linked_list *handle = dll_initialize();

	CU_ASSERT_PTR_NULL(dll_delete_first_node(handle));
	CU_ASSERT_PTR_NULL(dll_delete_last_node(handle));
	CU_ASSERT_PTR_NULL(dll_delete_node(handle, NULL));

	dll_destroy(handle);
}

void test_null_dl_list_handle()
{
	dll_destroy(NULL);
	CU_ASSERT_PTR_NULL(dll_prepend(NULL, NULL));
	CU_ASSERT_PTR_NULL(dll_append(NULL, NULL));
	CU_ASSERT_PTR_NULL(dll_delete_first_node(NULL));
	CU_ASSERT_PTR_NULL(dll_delete_last_node(NULL));
	CU_ASSERT_PTR_NULL(dll_delete_node(NULL, NULL));
}

void test_dll_prepend_data()
{
	dll_node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	double_linked_list *handle = dll_initialize();

	CU_ASSERT_PTR_NOT_NULL(dll_prepend(handle, &data3));
	CU_ASSERT_PTR_NOT_NULL(dll_prepend(handle, &data2));
	CU_ASSERT_PTR_NOT_NULL(dll_prepend(handle, &data1));

	CU_ASSERT_EQUAL(handle->num_entries, 3);

	double_linked_list_node *node = handle->head;
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data1);
	CU_ASSERT_PTR_NULL(node->prev_node);
	CU_ASSERT_PTR_NOT_NULL(node->next_node);

	node = node->next_node;
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data2);
	CU_ASSERT_PTR_NOT_NULL(node->prev_node);
	CU_ASSERT_PTR_NOT_NULL(node->next_node);

	node = node->next_node;
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data3);
	CU_ASSERT_PTR_NOT_NULL(node->prev_node);
	CU_ASSERT_PTR_NULL(node->next_node);
	CU_ASSERT_PTR_EQUAL(handle->tail, node);

	dll_destroy(handle);
}


void test_dll_append_data()
{
	dll_node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	double_linked_list *handle = dll_initialize();

	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data1));
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data2));
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data3));

	CU_ASSERT_EQUAL(handle->num_entries, 3);

	double_linked_list_node *node = handle->head;
	CU_ASSERT_PTR_EQUAL(node->data, &data1);
	CU_ASSERT_PTR_NULL(node->prev_node);
	CU_ASSERT_PTR_NOT_NULL(node->next_node);

	node = node->next_node;
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data2);
	CU_ASSERT_PTR_NOT_NULL(node->prev_node);
	CU_ASSERT_PTR_NOT_NULL(node->next_node);

	node = node->next_node;
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data3);
	CU_ASSERT_PTR_NOT_NULL(node->prev_node);
	CU_ASSERT_PTR_NULL(node->next_node);
	CU_ASSERT_PTR_EQUAL(handle->tail, node);

	dll_destroy(handle);
}


void test_dll_delete_first_node()
{
	dll_node_data data1, data2;
	data1.int_data = 1;
	data2.int_data = 2;

	double_linked_list *handle = dll_initialize();

	/* Test deleting with just 1 node in the list */
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data1));
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	void *deleted_data = dll_delete_first_node(handle);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data1, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 0);
	CU_ASSERT_PTR_NULL(handle->head);
	CU_ASSERT_PTR_NULL(handle->tail);

	/* Test deleting with 2 nodes in the list */
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data1));
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data2));
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	deleted_data = dll_delete_first_node(handle);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data1, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 1);
	CU_ASSERT_PTR_EQUAL(handle->head->data, &data2);
	CU_ASSERT_PTR_EQUAL(handle->head, handle->tail);
	CU_ASSERT_PTR_NULL(handle->head->prev_node);
	CU_ASSERT_PTR_NULL(handle->head->next_node);

	dll_destroy(handle);
}


void test_dll_delete_last_node()
{
	dll_node_data data1, data2;
	data1.int_data = 1;
	data2.int_data = 2;

	double_linked_list *handle = dll_initialize();

	/* Test deleting with just 1 node in the list */
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data1));
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	void *deleted_data = dll_delete_last_node(handle);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data1, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 0);
	CU_ASSERT_PTR_NULL(handle->head);
	CU_ASSERT_PTR_NULL(handle->tail);

	/* Test deleting with 2 nodes in the list */
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data1));
	CU_ASSERT_PTR_NOT_NULL(dll_append(handle, &data2));
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	deleted_data = dll_delete_last_node(handle);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data2, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 1);
	CU_ASSERT_PTR_EQUAL(handle->head->data, &data1);
	CU_ASSERT_PTR_EQUAL(handle->head, handle->tail);
	CU_ASSERT_PTR_NULL(handle->head->prev_node);
	CU_ASSERT_PTR_NULL(handle->head->next_node);

	dll_destroy(handle);
}


void test_dll_delete_node()
{
	dll_node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;
	double_linked_list_node *node1, *node2, *node3;
	double_linked_list *handle;

	/* Test deleting with just 1 node in the list */
	handle = dll_initialize();
	node1 = dll_append(handle, &data1);
	CU_ASSERT_PTR_NOT_NULL(node1);
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	void *deleted_data = dll_delete_node(handle, node1);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data1, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 0);
	CU_ASSERT_PTR_NULL(handle->head);
	CU_ASSERT_PTR_NULL(handle->tail);

	/*
	 * Test deleting the head with 2 nodes in the list
	 */
	node1 = dll_append(handle, &data1);
	node2 = dll_append(handle, &data2);
	CU_ASSERT_PTR_NOT_NULL(node1);
	CU_ASSERT_PTR_NOT_NULL(node2);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	/* Delete the head entry */
	deleted_data = dll_delete_node(handle, node1);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data1, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 1);
	CU_ASSERT_PTR_EQUAL(handle->head->data, &data2);
	CU_ASSERT_PTR_EQUAL(handle->head, handle->tail);
	CU_ASSERT_PTR_NULL(handle->head->prev_node);
	CU_ASSERT_PTR_NULL(handle->head->next_node);
	dll_destroy(handle);

	/*
	 * Test deleting the tail with 2 nodes in the list
	 */
	handle = dll_initialize();
	node1 = dll_append(handle, &data1);
	node2 = dll_append(handle, &data2);
	CU_ASSERT_PTR_NOT_NULL(node1);
	CU_ASSERT_PTR_NOT_NULL(node2);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	/* Delete the tail entry */
	deleted_data = dll_delete_node(handle, node2);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data2, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 1);
	CU_ASSERT_PTR_EQUAL(handle->head->data, &data1);
	CU_ASSERT_PTR_EQUAL(handle->head, handle->tail);
	CU_ASSERT_PTR_NULL(handle->head->prev_node);
	CU_ASSERT_PTR_NULL(handle->head->next_node);
	dll_destroy(handle);

	/*
	 * Test deleting in the middle with 3 nodes in the list
	 */
	handle = dll_initialize();
	node1 = dll_append(handle, &data1);
	node2 = dll_append(handle, &data2);
	node3 = dll_append(handle, &data3);
	CU_ASSERT_PTR_NOT_NULL(node1);
	assert(node1 != NULL);
	CU_ASSERT_PTR_NOT_NULL(node2);
	assert(node2 != NULL);
	CU_ASSERT_PTR_NOT_NULL(node3);
	assert(node3 != NULL);
	CU_ASSERT_EQUAL(handle->num_entries, 3);

	/* Delete the middle entry */
	deleted_data = dll_delete_node(handle, node2);
	CU_ASSERT_PTR_NOT_NULL(deleted_data);
	CU_ASSERT_PTR_EQUAL(&data2, deleted_data);

	CU_ASSERT_EQUAL(handle->num_entries, 2);
	CU_ASSERT_PTR_EQUAL(handle->head, node1);
	CU_ASSERT_PTR_EQUAL(handle->tail, node3);
	CU_ASSERT_PTR_EQUAL(node1->data, &data1);
	CU_ASSERT_PTR_EQUAL(node3->data, &data3);
	CU_ASSERT_PTR_EQUAL(node1->next_node, node3);
	CU_ASSERT_PTR_EQUAL(node3->prev_node, node1);
	CU_ASSERT_PTR_NULL(node1->prev_node);
	CU_ASSERT_PTR_NULL(node3->next_node);

	dll_destroy(handle);
}
