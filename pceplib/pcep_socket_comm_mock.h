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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */

/*
 * This module is built into a separate library, and is used by several
 * other modules for unit testing, so that real sockets dont have to be
 * created.
 */

#ifndef PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_
#define PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_

#include <stdbool.h>

#include "pcep_utils_double_linked_list.h"

typedef struct mock_socket_comm_info_ {
	int socket_comm_initialize_external_infra_times_called;
	int socket_comm_session_initialize_times_called;
	int socket_comm_session_initialize_src_times_called;
	int socket_comm_session_teardown_times_called;
	int socket_comm_session_connect_tcp_times_called;
	int socket_comm_session_send_message_times_called;
	int socket_comm_session_close_tcp_after_write_times_called;
	int socket_comm_session_close_tcp_times_called;
	int destroy_socket_comm_loop_times_called;

	/* TODO later if necessary, we can add return values for
	 *      those functions that return something */

	/* Used to access messages sent with socket_comm_session_send_message()
	 */
	bool send_message_save_message;
	double_linked_list *sent_message_list;

} mock_socket_comm_info;

void setup_mock_socket_comm_info(void);
void teardown_mock_socket_comm_info(void);
void reset_mock_socket_comm_info(void);
bool destroy_socket_comm_loop(void);

mock_socket_comm_info *get_mock_socket_comm_info(void);
void verify_socket_comm_times_called(int initialized, int teardown, int connect,
				     int send_message, int close_after_write,
				     int close, int destroy);

#endif /* PCEP_SOCKET_COMM_MOCK_SOCKET_COMM_H_ */
