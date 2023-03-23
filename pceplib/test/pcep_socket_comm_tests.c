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

#include "pcep_socket_comm_loop_test.h"
#include "pcep_socket_comm_test.h"


int main(int argc, char **argv)
{
	/* Unused parameters cause compilation warnings */
	(void)argc;
	(void)argv;

	CU_initialize_registry();

	/*
	 * Tests defined in pcep_socket_comm_test.c
	 */
	CU_pSuite test_socket_comm_suite = CU_add_suite_with_setup_and_teardown(
		"PCEP Socket Comm Test Suite", NULL,
		NULL, // suite setup and cleanup function pointers
		pcep_socket_comm_test_setup, // test case setup function pointer
		pcep_socket_comm_test_teardown); // test case teardown function
						 // pointer

	CU_add_test(test_socket_comm_suite, "test_pcep_socket_comm_initialize",
		    test_pcep_socket_comm_initialize);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_ipv6",
		    test_pcep_socket_comm_initialize_ipv6);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_with_src",
		    test_pcep_socket_comm_initialize_with_src);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_with_src_ipv6",
		    test_pcep_socket_comm_initialize_with_src_ipv6);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_tcpmd5",
		    test_pcep_socket_comm_initialize_tcpmd5);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_ipv6_tcpmd5",
		    test_pcep_socket_comm_initialize_ipv6_tcpmd5);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_initialize_handlers",
		    test_pcep_socket_comm_initialize_handlers);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_session_not_initialized",
		    test_pcep_socket_comm_session_not_initialized);
	CU_add_test(test_socket_comm_suite,
		    "test_pcep_socket_comm_session_destroy",
		    test_pcep_socket_comm_session_destroy);

	/*
	 * Tests defined in pcep_socket_comm_loop_test.c
	 */
	CU_pSuite test_socket_comm_loop_suite =
		CU_add_suite_with_setup_and_teardown(
			"PCEP Socket Comm Loop Test Suite", NULL, NULL,
			pcep_socket_comm_loop_test_setup, // suite setup
							  // function pointer
			pcep_socket_comm_loop_test_teardown); // suite cleanup
							      // function
							      // pointer

	CU_add_test(test_socket_comm_loop_suite,
		    "test_socket_comm_loop_null_handle",
		    test_socket_comm_loop_null_handle);
	CU_add_test(test_socket_comm_loop_suite,
		    "test_socket_comm_loop_not_active",
		    test_socket_comm_loop_not_active);
	CU_add_test(test_socket_comm_loop_suite, "test_handle_reads_no_read",
		    test_handle_reads_no_read);
	CU_add_test(test_socket_comm_loop_suite,
		    "test_handle_reads_read_message",
		    test_handle_reads_read_message);
	CU_add_test(test_socket_comm_loop_suite,
		    "test_handle_reads_read_message_close",
		    test_handle_reads_read_message_close);

	/*
	 * Run the tests and cleanup.
	 */
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
