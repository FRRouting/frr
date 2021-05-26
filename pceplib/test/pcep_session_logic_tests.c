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

#include "pcep_session_logic_loop_test.h"
#include "pcep_session_logic_states_test.h"
#include "pcep_session_logic_test.h"


int main(int argc, char **argv)
{
	/* Unused parameters cause compilation warnings */
	(void)argc;
	(void)argv;

	CU_initialize_registry();

	/*
	 * Tests defined in pcep_socket_comm_test.c
	 */
	CU_pSuite test_session_logic_suite =
		CU_add_suite_with_setup_and_teardown(
			"PCEP Session Logic Test Suite",
			pcep_session_logic_test_suite_setup, // suite setup and
							     // cleanup function
							     // pointers
			pcep_session_logic_test_suite_teardown,
			pcep_session_logic_test_setup,	   // test case setup
							   // function pointer
			pcep_session_logic_test_teardown); // test case teardown
							   // function pointer

	CU_add_test(test_session_logic_suite, "test_run_stop_session_logic",
		    test_run_stop_session_logic);
	CU_add_test(test_session_logic_suite, "test_run_session_logic_twice",
		    test_run_session_logic_twice);
	CU_add_test(test_session_logic_suite, "test_session_logic_without_run",
		    test_session_logic_without_run);
	CU_add_test(test_session_logic_suite,
		    "test_create_pcep_session_null_params",
		    test_create_pcep_session_null_params);
	CU_add_test(test_session_logic_suite,
		    "test_create_destroy_pcep_session",
		    test_create_destroy_pcep_session);
	CU_add_test(test_session_logic_suite,
		    "test_create_destroy_pcep_session_ipv6",
		    test_create_destroy_pcep_session_ipv6);
	CU_add_test(test_session_logic_suite,
		    "test_create_pcep_session_open_tlvs",
		    test_create_pcep_session_open_tlvs);
	CU_add_test(test_session_logic_suite,
		    "test_destroy_pcep_session_null_session",
		    test_destroy_pcep_session_null_session);

	CU_pSuite test_session_logic_loop_suite =
		CU_add_suite_with_setup_and_teardown(
			"PCEP Session Logic Loop Test Suite",
			pcep_session_logic_loop_test_suite_setup, // suite setup
								  // and cleanup
								  // function
								  // pointers
			pcep_session_logic_loop_test_suite_teardown,
			pcep_session_logic_loop_test_setup, // test case setup
							    // function pointer
			pcep_session_logic_loop_test_teardown); // test case
								// teardown
								// function
								// pointer

	CU_add_test(test_session_logic_loop_suite,
		    "test_session_logic_loop_null_data",
		    test_session_logic_loop_null_data);
	CU_add_test(test_session_logic_loop_suite,
		    "test_session_logic_loop_inactive",
		    test_session_logic_loop_inactive);
	CU_add_test(test_session_logic_loop_suite,
		    "test_session_logic_msg_ready_handler",
		    test_session_logic_msg_ready_handler);
	CU_add_test(test_session_logic_loop_suite,
		    "test_session_logic_conn_except_notifier",
		    test_session_logic_conn_except_notifier);
	CU_add_test(test_session_logic_loop_suite,
		    "test_session_logic_timer_expire_handler",
		    test_session_logic_timer_expire_handler);

	CU_pSuite test_session_logic_states_suite =
		CU_add_suite_with_setup_and_teardown(
			"PCEP Session Logic States Test Suite",
			pcep_session_logic_states_test_suite_setup, // suite
								    // setup and
								    // cleanup
								    // function
								    // pointers
			pcep_session_logic_states_test_suite_teardown,
			pcep_session_logic_states_test_setup, // test case setup
							      // function
							      // pointer
			pcep_session_logic_states_test_teardown); // test case
								  // teardown
								  // function
								  // pointer

	CU_add_test(test_session_logic_states_suite,
		    "test_handle_timer_event_dead_timer",
		    test_handle_timer_event_dead_timer);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_timer_event_keep_alive",
		    test_handle_timer_event_keep_alive);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_timer_event_open_keep_wait",
		    test_handle_timer_event_open_keep_wait);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_null_params",
		    test_handle_socket_comm_event_null_params);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_close",
		    test_handle_socket_comm_event_close);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_open",
		    test_handle_socket_comm_event_open);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_open_error",
		    test_handle_socket_comm_event_open_error);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_keep_alive",
		    test_handle_socket_comm_event_keep_alive);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_pcrep",
		    test_handle_socket_comm_event_pcrep);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_pcreq",
		    test_handle_socket_comm_event_pcreq);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_report",
		    test_handle_socket_comm_event_report);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_update",
		    test_handle_socket_comm_event_update);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_initiate",
		    test_handle_socket_comm_event_initiate);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_notify",
		    test_handle_socket_comm_event_notify);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_error",
		    test_handle_socket_comm_event_error);
	CU_add_test(test_session_logic_states_suite,
		    "test_handle_socket_comm_event_unknown_msg",
		    test_handle_socket_comm_event_unknown_msg);
	CU_add_test(test_session_logic_states_suite, "test_connection_failure",
		    test_connection_failure);

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
