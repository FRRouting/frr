/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <CUnit/CUnit.h>

#include "pcep_utils_ordered_list.h"
#include "pcep_utils_ordered_list_test.h"

typedef struct node_data_ {
	int int_data;

} node_data;


int node_data_compare(void *list_entry, void *new_entry)
{
	/*
	 *   < 0  if new_entry  < list_entry
	 *   == 0 if new_entry == list_entry (new_entry will be inserted after
	 * list_entry) > 0  if new_entry  > list_entry
	 */

	return ((node_data *)new_entry)->int_data
	       - ((node_data *)list_entry)->int_data;
}


void test_empty_list()
{
	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	CU_ASSERT_PTR_NOT_NULL(handle);
	assert(handle != NULL);
	CU_ASSERT_PTR_NULL(handle->head);
	CU_ASSERT_PTR_NOT_NULL(handle->compare_function);
	CU_ASSERT_EQUAL(handle->num_entries, 0);

	ordered_list_destroy(handle);
}


void test_null_list_handle()
{
	node_data data;
	ordered_list_node node_data;

	void *ptr = ordered_list_add_node(NULL, &data);
	CU_ASSERT_PTR_NULL(ptr);

	ptr = ordered_list_find(NULL, &data);
	CU_ASSERT_PTR_NULL(ptr);

	ptr = ordered_list_remove_first_node(NULL);
	CU_ASSERT_PTR_NULL(ptr);

	ptr = ordered_list_remove_first_node_equals(NULL, &data);
	CU_ASSERT_PTR_NULL(ptr);

	ptr = ordered_list_remove_node(NULL, &node_data, &node_data);
	CU_ASSERT_PTR_NULL(ptr);
}


void test_add_to_list()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	ordered_list_add_node(handle, &data3);
	ordered_list_add_node(handle, &data1);
	ordered_list_add_node(handle, &data2);

	CU_ASSERT_EQUAL(handle->num_entries, 3);

	ordered_list_node *node = handle->head;
	CU_ASSERT_PTR_EQUAL(node->data, &data1);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node->data, &data2);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node->data, &data3);

	node = node->next_node;
	CU_ASSERT_PTR_EQUAL(node, NULL);

	ordered_list_destroy(handle);
}


void test_find()
{
	node_data data1, data2, data3, data_not_inList;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;
	data_not_inList.int_data = 5;

	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	ordered_list_add_node(handle, &data3);
	ordered_list_add_node(handle, &data2);
	ordered_list_add_node(handle, &data1);

	ordered_list_node *node = ordered_list_find(handle, &data1);
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data1);

	node = ordered_list_find(handle, &data2);
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data2);

	node = ordered_list_find(handle, &data3);
	CU_ASSERT_PTR_NOT_NULL(node);
	assert(node != NULL);
	CU_ASSERT_PTR_EQUAL(node->data, &data3);

	node = ordered_list_find(handle, &data_not_inList);
	CU_ASSERT_PTR_NULL(node);

	ordered_list_destroy(handle);
}


void test_remove_first_node()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	ordered_list_add_node(handle, &data1);
	ordered_list_add_node(handle, &data2);
	ordered_list_add_node(handle, &data3);

	void *node_data = ordered_list_remove_first_node(handle);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data1);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	node_data = ordered_list_remove_first_node(handle);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data2);
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	node_data = ordered_list_remove_first_node(handle);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data3);
	CU_ASSERT_EQUAL(handle->num_entries, 0);
	CU_ASSERT_PTR_NULL(handle->head);

	node_data = ordered_list_remove_first_node(handle);
	CU_ASSERT_PTR_NULL(node_data);

	ordered_list_destroy(handle);
}


void test_remove_first_node_equals()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	ordered_list_add_node(handle, &data1);
	ordered_list_add_node(handle, &data2);
	ordered_list_add_node(handle, &data3);

	void *node_data = ordered_list_remove_first_node_equals(handle, &data2);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data2);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	node_data = ordered_list_remove_first_node_equals(handle, &data3);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data3);
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	node_data = ordered_list_remove_first_node_equals(handle, &data1);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data1);
	CU_ASSERT_EQUAL(handle->num_entries, 0);

	node_data = ordered_list_remove_first_node_equals(handle, &data1);
	CU_ASSERT_PTR_NULL(node_data);

	ordered_list_destroy(handle);
}


void test_remove_node()
{
	node_data data1, data2, data3;
	data1.int_data = 1;
	data2.int_data = 2;
	data3.int_data = 3;

	ordered_list_handle *handle =
		ordered_list_initialize(node_data_compare);

	ordered_list_node *node1 = ordered_list_add_node(handle, &data1);
	ordered_list_node *node2 = ordered_list_add_node(handle, &data2);
	ordered_list_node *node3 = ordered_list_add_node(handle, &data3);

	void *node_data = ordered_list_remove_node(handle, node2, node3);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data3);
	CU_ASSERT_EQUAL(handle->num_entries, 2);

	node_data = ordered_list_remove_node(handle, node1, node2);
	CU_ASSERT_PTR_NOT_NULL(node_data);
	CU_ASSERT_PTR_EQUAL(node_data, &data2);
	CU_ASSERT_EQUAL(handle->num_entries, 1);

	ordered_list_destroy(handle);
}
