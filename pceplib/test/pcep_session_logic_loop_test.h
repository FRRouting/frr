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

#ifndef PCEP_SESSION_LOGIC_LOOP_TEST_H_
#define PCEP_SESSION_LOGIC_LOOP_TEST_H_

int pcep_session_logic_loop_test_suite_setup(void);
int pcep_session_logic_loop_test_suite_teardown(void);
void pcep_session_logic_loop_test_setup(void);
void pcep_session_logic_loop_test_teardown(void);
void test_session_logic_loop_null_data(void);
void test_session_logic_loop_inactive(void);
void test_session_logic_msg_ready_handler(void);
void test_session_logic_conn_except_notifier(void);
void test_session_logic_timer_expire_handler(void);

#endif /* PCEPTIMERINTERNALS_H_ */
