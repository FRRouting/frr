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

#ifndef PCEP_SOCKET_COMM_TEST_H_
#define PCEP_SOCKET_COMM_TEST_H_

void pcep_socket_comm_test_teardown(void);
void pcep_socket_comm_test_setup(void);
void test_pcep_socket_comm_initialize(void);
void test_pcep_socket_comm_initialize_ipv6(void);
void test_pcep_socket_comm_initialize_with_src(void);
void test_pcep_socket_comm_initialize_with_src_ipv6(void);
void test_pcep_socket_comm_initialize_tcpmd5(void);
void test_pcep_socket_comm_initialize_ipv6_tcpmd5(void);
void test_pcep_socket_comm_initialize_handlers(void);
void test_pcep_socket_comm_session_not_initialized(void);
void test_pcep_socket_comm_session_destroy(void);

#endif
