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

#include "pcep_pcc_api_test.h"

int main(int argc, char **argv)
{
	/* Unused parameters cause compilation warnings */
	(void)argc;
	(void)argv;

	CU_initialize_registry();

	/*
	 * Tests defined in pcep_socket_comm_test.c
	 */
	CU_pSuite test_pcc_api_suite = CU_add_suite_with_setup_and_teardown(
		"PCEP PCC API Test Suite",
		pcep_pcc_api_test_suite_setup, // suite setup and cleanup
					       // function pointers
		pcep_pcc_api_test_suite_teardown,
		pcep_pcc_api_test_setup,     // test case setup function pointer
		pcep_pcc_api_test_teardown); // test case teardown function
					     // pointer

	CU_add_test(test_pcc_api_suite, "test_initialize_pcc",
		    test_initialize_pcc);
	CU_add_test(test_pcc_api_suite, "test_connect_pce", test_connect_pce);
	CU_add_test(test_pcc_api_suite, "test_connect_pce_ipv6",
		    test_connect_pce_ipv6);
	CU_add_test(test_pcc_api_suite, "test_connect_pce_with_src_ip",
		    test_connect_pce_with_src_ip);
	CU_add_test(test_pcc_api_suite, "test_disconnect_pce",
		    test_disconnect_pce);
	CU_add_test(test_pcc_api_suite, "test_send_message", test_send_message);
	CU_add_test(test_pcc_api_suite, "test_event_queue", test_event_queue);
	CU_add_test(test_pcc_api_suite, "test_get_event_type_str",
		    test_get_event_type_str);

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
