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
