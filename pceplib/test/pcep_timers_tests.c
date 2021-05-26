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

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestDB.h>

#include "pcep_timers_test.h"
#include "pcep_timers_event_loop_test.h"


int main(int argc, char **argv)
{
	/* Unused parameters cause compilation warnings */
	(void)argc;
	(void)argv;

	CU_initialize_registry();

	/*
	 * Tests defined in pcep_timers_test.c
	 */
	CU_pSuite test_timers_suite = CU_add_suite_with_setup_and_teardown(
		"PCEP Timers Test Suite", NULL,
		NULL, // suite setup and cleanup function pointers
		NULL, pcep_timers_test_teardown); // test case setup and
						  // teardown function pointers
	CU_add_test(test_timers_suite, "test_double_initialization",
		    test_double_initialization);
	CU_add_test(test_timers_suite, "test_initialization_null_callback",
		    test_initialization_null_callback);
	CU_add_test(test_timers_suite, "test_not_initialized",
		    test_not_initialized);
	CU_add_test(test_timers_suite, "test_create_timer", test_create_timer);
	CU_add_test(test_timers_suite, "test_cancel_timer", test_cancel_timer);
	CU_add_test(test_timers_suite, "test_cancel_timer_invalid",
		    test_cancel_timer_invalid);
	CU_add_test(test_timers_suite, "test_reset_timer", test_reset_timer);
	CU_add_test(test_timers_suite, "test_reset_timer_invalid",
		    test_reset_timer_invalid);

	/*
	 * Tests defined in pcep_timers_event_loop_test.c
	 */
	CU_pSuite test_timers_event_loop_suite =
		CU_add_suite_with_setup_and_teardown(
			"PCEP Timers Event Loop Test Suite", NULL,
			NULL, // suite setup and cleanup function pointers
			pcep_timers_event_loop_test_setup, // test case setup
							   // function pointer
			pcep_timers_event_loop_test_teardown); // test case
							       // teardown
							       // function
							       // pointer
	CU_add_test(test_timers_event_loop_suite,
		    "test_walk_and_process_timers_no_timers",
		    test_walk_and_process_timers_no_timers);
	CU_add_test(test_timers_event_loop_suite,
		    "test_walk_and_process_timers_timer_not_expired",
		    test_walk_and_process_timers_timer_not_expired);
	CU_add_test(test_timers_event_loop_suite,
		    "test_walk_and_process_timers_timer_expired",
		    test_walk_and_process_timers_timer_expired);
	CU_add_test(test_timers_event_loop_suite, "test_event_loop_null_handle",
		    test_event_loop_null_handle);
	CU_add_test(test_timers_event_loop_suite, "test_event_loop_not_active",
		    test_event_loop_not_active);

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
