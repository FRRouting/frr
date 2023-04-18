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

#ifndef PCEP_SOCKET_COMM_LOOP_TEST_H_
#define PCEP_SOCKET_COMM_LOOP_TEST_H_

void pcep_socket_comm_loop_test_setup(void);
void pcep_socket_comm_loop_test_teardown(void);
void test_socket_comm_loop_null_handle(void);
void test_socket_comm_loop_not_active(void);
void test_handle_reads_no_read(void);
void test_handle_reads_read_message(void);
void test_handle_reads_read_message_close(void);

#endif /* PCEPTIMERINTERNALS_H_ */
