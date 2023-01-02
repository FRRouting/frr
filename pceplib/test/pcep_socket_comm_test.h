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
