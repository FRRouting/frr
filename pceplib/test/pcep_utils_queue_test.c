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

#include "pcep_utils_queue.h"
#include "pcep_utils_queue_test.h"

typedef struct node_data_ {
	int int_data;

} node_data;


void test_empty_queue()
{
	queue_handle *handle = queue_initialize();

	CU_ASSERT_PTR_NOT_NULL(handle);
	assert(handle != NULL);
	CU_ASSERT_PTR_NULL(handle->head);
	CU_ASSERT_EQUAL(handle->num_entries, 0);

	queue_destroy(handle);
}


void test_null_queue_handle()
{
	/* test each method handles a NULL handle without crashing */
	node_data data;
	queue_destroy(NULL);
	void *ptr = queue_enqueue(NULL, &data);
	CU_ASSERT_PTR_NULL(ptr);

	ptr = queue_dequeue(NULL);
	CU_ASSERT_PTR_NULL(ptr);
}


void test_enqueue()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	queue_handle *handle = queue_initialize();

	queue_enqueue(handle, &data1);
	queue_enqueue(handle, &data2);
	queue_enqueue(handle, &data3);

	CU_ASSERT_EQUAL(handle->num_entries, 3);

	queue_node *node = handle->head;
	CU_ASSERT_PTR_EQUAL(node->data, &data1);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node->data, &data2);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node->data, &data3);

	node = node->next_node;
	CU_ASSERT_PTR_NULL(node);

	queue_destroy(handle);
}


void test_enqueue_with_limit()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	queue_handle *handle = queue_initialize_with_size(2);

	queue_node *node = queue_enqueue(handle, &data1);
	CU_ASSERT_PTR_NOT_NULL(node);

	node = queue_enqueue(handle, &data2);
	CU_ASSERT_PTR_NOT_NULL(node);

	node = queue_enqueue(handle, &data3);
	CU_ASSERT_PTR_NULL(node);

	CU_ASSERT_EQUAL(handle->num_entries, 2);

	node = handle->head;
	CU_ASSERT_PTR_EQUAL(node->data, &data1);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node->data, &data2);

	node = node->next_node;
	CU_ASSERT_PTR_NULL(node);

	queue_destroy(handle);
}


void test_dequeue()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	queue_handle *handle = queue_initialize();

	/* first test dequeue handles an empty queue */
	void *node_data = queue_dequeue(handle);
	CU_ASSERT_PTR_NULL(node_data);

	queue_enqueue(handle, &data1);
	queue_enqueue(handle, &data2);
	queue_enqueue(handle, &data3);

	node_data = queue_dequeue(handle);
	CU_ASSERT_PTR_EQUAL(node_data, &data1);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	node_data = queue_dequeue(handle);
	CU_ASSERT_PTR_EQUAL(node_data, &data2);
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	node_data = queue_dequeue(handle);
	CU_ASSERT_PTR_EQUAL(node_data, &data3);
	CU_ASSERT_EQUAL(handle->num_entries, 0);

	node_data = queue_dequeue(handle);
	CU_ASSERT_PTR_NULL(node_data);

	queue_destroy(handle);
}
