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

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>
#include "pcep_utils_ordered_list_test.h"
#include "pcep_utils_queue_test.h"
#include "pcep_utils_double_linked_list_test.h"
#include "pcep_utils_counters_test.h"
#include "pcep_utils_memory_test.h"


int main(int argc, char **argv)
{
	/* Unused parameters cause compilation warnings */
	(void)argc;
	(void)argv;

	CU_initialize_registry();

	CU_pSuite test_queue_suite =
		CU_add_suite("PCEP Utils Queue Test Suite", NULL, NULL);
	CU_add_test(test_queue_suite, "test_empty_queue", test_empty_queue);
	CU_add_test(test_queue_suite, "test_null_queue_handle",
		    test_null_queue_handle);
	CU_add_test(test_queue_suite, "test_enqueue", test_enqueue);
	CU_add_test(test_queue_suite, "test_enqueue_with_limit",
		    test_enqueue_with_limit);
	CU_add_test(test_queue_suite, "test_dequeue", test_dequeue);

	CU_pSuite test_list_suite =
		CU_add_suite("PCEP Utils Ordered List Test Suite", NULL, NULL);
	CU_add_test(test_list_suite, "test_empty_list", test_empty_list);
	CU_add_test(test_list_suite, "test_null_handle", test_null_list_handle);
	CU_add_test(test_list_suite, "test_add_toList", test_add_to_list);
	CU_add_test(test_list_suite, "test_find", test_find);
	CU_add_test(test_list_suite, "test_remove_first_node",
		    test_remove_first_node);
	CU_add_test(test_list_suite, "test_remove_first_node_equals",
		    test_remove_first_node_equals);
	CU_add_test(test_list_suite, "test_remove_node", test_remove_node);

	CU_pSuite test_dl_list_suite = CU_add_suite(
		"PCEP Utils Double Linked List Test Suite", NULL, NULL);
	CU_add_test(test_dl_list_suite, "test_empty_dl_list",
		    test_empty_dl_list);
	CU_add_test(test_dl_list_suite, "test_null_dl_handle",
		    test_null_dl_list_handle);
	CU_add_test(test_dl_list_suite, "test_dll_prepend_data",
		    test_dll_prepend_data);
	CU_add_test(test_dl_list_suite, "test_dll_append_data",
		    test_dll_append_data);
	CU_add_test(test_dl_list_suite, "test_dll_delete_first_node",
		    test_dll_delete_first_node);
	CU_add_test(test_dl_list_suite, "test_dll_delete_last_node",
		    test_dll_delete_last_node);
	CU_add_test(test_dl_list_suite, "test_dll_delete_node",
		    test_dll_delete_node);

	CU_pSuite test_counters_suite =
		CU_add_suite("PCEP Utils Counters Test Suite", NULL, NULL);
	CU_add_test(test_counters_suite, "test_create_counters_group",
		    test_create_counters_group);
	CU_add_test(test_counters_suite, "test_create_counters_subgroup",
		    test_create_counters_subgroup);
	CU_add_test(test_counters_suite, "test_add_counters_subgroup",
		    test_add_counters_subgroup);
	CU_add_test(test_counters_suite, "test_create_subgroup_counter",
		    test_create_subgroup_counter);
	CU_add_test(test_counters_suite, "test_delete_counters_group",
		    test_delete_counters_group);
	CU_add_test(test_counters_suite, "test_delete_counters_subgroup",
		    test_delete_counters_subgroup);
	CU_add_test(test_counters_suite, "test_reset_group_counters",
		    test_reset_group_counters);
	CU_add_test(test_counters_suite, "test_reset_subgroup_counters",
		    test_reset_subgroup_counters);
	CU_add_test(test_counters_suite, "test_increment_counter",
		    test_increment_counter);
	CU_add_test(test_counters_suite, "test_increment_subgroup_counter",
		    test_increment_subgroup_counter);
	CU_add_test(test_counters_suite, "test_dump_counters_group_to_log",
		    test_dump_counters_group_to_log);
	CU_add_test(test_counters_suite, "test_dump_counters_subgroup_to_log",
		    test_dump_counters_subgroup_to_log);

	CU_pSuite test_memory_suite =
		CU_add_suite("PCEP Utils Memory Test Suite", NULL, NULL);
	CU_add_test(test_memory_suite, "test_memory_internal_impl",
		    test_memory_internal_impl);
	CU_add_test(test_memory_suite, "test_memory_external_impl",
		    test_memory_external_impl);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_FailureRecord *failure_record = CU_get_failure_list();
	if (failure_record != NULL) {
		printf("\nFailed tests:\n\t [Suite] [Test] [File:line-number]\n");
		do {
			printf("\t [%s] [%s] [%s:%d]\n",
			       failure_record->pSuite->pName,
			       failure_record->pTest->pName,
			       failure_record->strFileName,
			       failure_record->uiLineNumber);
			failure_record = failure_record->pNext;

		} while (failure_record != NULL);
	}

	CU_pRunSummary run_summary = CU_get_run_summary();
	int result = run_summary->nTestsFailed;
	CU_cleanup_registry();

	return result;
}
