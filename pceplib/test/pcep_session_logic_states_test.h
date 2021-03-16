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

#ifndef PCEP_SESSION_LOGIC_STATES_TEST_H
#define PCEP_SESSION_LOGIC_STATES_TEST_H

int pcep_session_logic_states_test_suite_setup(void);
int pcep_session_logic_states_test_suite_teardown(void);
void pcep_session_logic_states_test_setup(void);
void pcep_session_logic_states_test_teardown(void);
void test_handle_timer_event_dead_timer(void);
void test_handle_timer_event_keep_alive(void);
void test_handle_timer_event_open_keep_wait(void);
void test_handle_socket_comm_event_null_params(void);
void test_handle_socket_comm_event_close(void);
void test_handle_socket_comm_event_open(void);
void test_handle_socket_comm_event_open_error(void);
void test_handle_socket_comm_event_keep_alive(void);
void test_handle_socket_comm_event_pcrep(void);
void test_handle_socket_comm_event_pcreq(void);
void test_handle_socket_comm_event_report(void);
void test_handle_socket_comm_event_update(void);
void test_handle_socket_comm_event_initiate(void);
void test_handle_socket_comm_event_notify(void);
void test_handle_socket_comm_event_error(void);
void test_handle_socket_comm_event_unknown_msg(void);
void test_connection_failure(void);

#endif /* PCEPTIMERINTERNALS_H_ */
