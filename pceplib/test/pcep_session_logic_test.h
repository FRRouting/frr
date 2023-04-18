// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Javier Garcia <javier.garcia@voltanet.io>
 *
 */

/*
 *  Timer definitions to be used internally by the pcep_timers library.
 */

#ifndef PCEP_SESSION_LOGIC_TEST_H_
#define PCEP_SESSION_LOGIC_TEST_H_

int pcep_session_logic_test_suite_setup(void);
int pcep_session_logic_test_suite_teardown(void);
void pcep_session_logic_test_setup(void);
void pcep_session_logic_test_teardown(void);
void test_run_stop_session_logic(void);
void test_run_session_logic_twice(void);
void test_session_logic_without_run(void);
void test_create_pcep_session_null_params(void);
void test_create_destroy_pcep_session(void);
void test_create_destroy_pcep_session_ipv6(void);
void test_create_pcep_session_open_tlvs(void);
void test_destroy_pcep_session_null_session(void);

#endif /* PCEPTIMERINTERNALS_H_ */
