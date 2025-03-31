// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * This module is built into a separate library, and is used by several
 * other modules for unit testing, so that real sockets dont have to be
 * created.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm.h"
#include "pcep_socket_comm_mock.h"
#include "pcep_utils_queue.h"

/* reset_mock_socket_comm_info() should be used before each test */
mock_socket_comm_info mock_socket_metadata;

void setup_mock_socket_comm_info(void)
{
	mock_socket_metadata.socket_comm_session_initialize_times_called = 0;
	mock_socket_metadata.socket_comm_session_initialize_src_times_called =
		0;
	mock_socket_metadata.socket_comm_session_teardown_times_called = 0;
	mock_socket_metadata.socket_comm_session_connect_tcp_times_called = 0;
	mock_socket_metadata.socket_comm_session_send_message_times_called = 0;
	mock_socket_metadata
		.socket_comm_session_close_tcp_after_write_times_called = 0;
	mock_socket_metadata.socket_comm_session_close_tcp_times_called = 0;
	mock_socket_metadata.destroy_socket_comm_loop_times_called = 0;
	mock_socket_metadata.send_message_save_message = false;
	mock_socket_metadata.sent_message_list = dll_initialize();
}

void teardown_mock_socket_comm_info(void)
{
	dll_destroy(mock_socket_metadata.sent_message_list);
}

void reset_mock_socket_comm_info(void)
{
	teardown_mock_socket_comm_info();
	setup_mock_socket_comm_info();
}

mock_socket_comm_info *get_mock_socket_comm_info(void)
{
	return &mock_socket_metadata;
}

void verify_socket_comm_times_called(int initialized, int teardown, int connect,
				     int send_message,
				     int close_tcp_after_write, int close_tcp,
				     int destroy)
{
	CU_ASSERT_EQUAL(initialized,
			mock_socket_metadata
				.socket_comm_session_initialize_times_called);
	CU_ASSERT_EQUAL(
		teardown,
		mock_socket_metadata.socket_comm_session_teardown_times_called);
	CU_ASSERT_EQUAL(connect,
			mock_socket_metadata
				.socket_comm_session_connect_tcp_times_called);
	CU_ASSERT_EQUAL(send_message,
			mock_socket_metadata
				.socket_comm_session_send_message_times_called);
	CU_ASSERT_EQUAL(
		close_tcp_after_write,
		mock_socket_metadata
			.socket_comm_session_close_tcp_after_write_times_called);
	CU_ASSERT_EQUAL(close_tcp,
			mock_socket_metadata
				.socket_comm_session_close_tcp_times_called);
	CU_ASSERT_EQUAL(
		destroy,
		mock_socket_metadata.destroy_socket_comm_loop_times_called);
}


/*
 * Mock the socket_comm functions used by session_logic for Unit Testing
 */

bool initialize_socket_comm_external_infra(
	void *external_infra_data, ext_socket_read socket_read_cb,
	ext_socket_write socket_write_cb,
	ext_socket_pthread_create_callback thread_create_func)
{
	(void)external_infra_data;
	(void)socket_read_cb;
	(void)socket_write_cb;
	(void)thread_create_func;

	mock_socket_metadata
		.socket_comm_initialize_external_infra_times_called++;

	return true;
}

bool destroy_socket_comm_loop(void)
{
	mock_socket_metadata.destroy_socket_comm_loop_times_called++;

	return false;
}

pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler msg_rcv_handler,
			       message_ready_to_read_handler msg_ready_handler,
			       message_sent_notifier msg_sent_notifier,
			       connection_except_notifier notifier,
			       struct in_addr *dst_ip, short dst_port,
			       uint32_t connect_timeout_millis,
			       const char *tcp_authentication_str,
			       bool is_tcp_auth_md5, void *session_data)
{
	(void)msg_sent_notifier;
	(void)tcp_authentication_str;
	(void)is_tcp_auth_md5;

	mock_socket_metadata.socket_comm_session_initialize_times_called++;

	pcep_socket_comm_session *comm_session =
		malloc(sizeof(pcep_socket_comm_session));
	memset(comm_session, 0, sizeof(pcep_socket_comm_session));

	comm_session->message_handler = msg_rcv_handler;
	comm_session->message_ready_to_read_handler = msg_ready_handler;
	comm_session->conn_except_notifier = notifier;
	comm_session->message_queue = queue_initialize();
	comm_session->session_data = session_data;
	comm_session->close_after_write = false;
	comm_session->connect_timeout_millis = connect_timeout_millis;
	comm_session->is_ipv6 = false;
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_family = AF_INET;
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_port =
		htons(dst_port);
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_addr.s_addr =
		dst_ip->s_addr;

	return comm_session;
}

pcep_socket_comm_session *socket_comm_session_initialize_ipv6(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *dst_ip,
	short dst_port, uint32_t connect_timeout_millis,
	const char *tcp_authentication_str, bool is_tcp_auth_md5,
	void *session_data)
{
	(void)msg_sent_notifier;
	(void)tcp_authentication_str;
	(void)is_tcp_auth_md5;

	mock_socket_metadata.socket_comm_session_initialize_times_called++;

	pcep_socket_comm_session *comm_session =
		malloc(sizeof(pcep_socket_comm_session));
	memset(comm_session, 0, sizeof(pcep_socket_comm_session));

	comm_session->message_handler = msg_rcv_handler;
	comm_session->message_ready_to_read_handler = msg_ready_handler;
	comm_session->conn_except_notifier = notifier;
	comm_session->message_queue = queue_initialize();
	comm_session->session_data = session_data;
	comm_session->close_after_write = false;
	comm_session->connect_timeout_millis = connect_timeout_millis;
	comm_session->is_ipv6 = true;
	comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_family = AF_INET6;
	comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_port =
		htons(dst_port);
	memcpy(&comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_addr,
	       dst_ip, sizeof(struct in6_addr));

	return comm_session;
}

pcep_socket_comm_session *socket_comm_session_initialize_with_src(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in_addr *src_ip,
	short src_port, struct in_addr *dst_ip, short dst_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data)
{
	(void)msg_sent_notifier;
	(void)tcp_authentication_str;
	(void)is_tcp_auth_md5;

	mock_socket_metadata.socket_comm_session_initialize_src_times_called++;

	pcep_socket_comm_session *comm_session =
		malloc(sizeof(pcep_socket_comm_session));
	memset(comm_session, 0, sizeof(pcep_socket_comm_session));

	comm_session->message_handler = msg_rcv_handler;
	comm_session->message_ready_to_read_handler = msg_ready_handler;
	comm_session->conn_except_notifier = notifier;
	comm_session->message_queue = queue_initialize();
	comm_session->session_data = session_data;
	comm_session->close_after_write = false;
	comm_session->connect_timeout_millis = connect_timeout_millis;
	comm_session->is_ipv6 = false;
	comm_session->src_sock_addr.src_sock_addr_ipv4.sin_family = AF_INET;
	comm_session->src_sock_addr.src_sock_addr_ipv4.sin_port =
		htons(src_port);
	comm_session->src_sock_addr.src_sock_addr_ipv4.sin_addr.s_addr =
		((src_ip == NULL) ? INADDR_ANY : src_ip->s_addr);
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_family = AF_INET;
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_port =
		htons(dst_port);
	comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_addr.s_addr =
		dst_ip->s_addr;

	return comm_session;
}

pcep_socket_comm_session *socket_comm_session_initialize_with_src_ipv6(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *src_ip,
	short src_port, struct in6_addr *dst_ip, short dst_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data)
{
	(void)msg_sent_notifier;
	(void)tcp_authentication_str;
	(void)is_tcp_auth_md5;

	mock_socket_metadata.socket_comm_session_initialize_src_times_called++;

	pcep_socket_comm_session *comm_session =
		malloc(sizeof(pcep_socket_comm_session));
	memset(comm_session, 0, sizeof(pcep_socket_comm_session));

	comm_session->message_handler = msg_rcv_handler;
	comm_session->message_ready_to_read_handler = msg_ready_handler;
	comm_session->conn_except_notifier = notifier;
	comm_session->message_queue = queue_initialize();
	comm_session->session_data = session_data;
	comm_session->close_after_write = false;
	comm_session->connect_timeout_millis = connect_timeout_millis;
	comm_session->is_ipv6 = true;
	comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_family = AF_INET6;
	comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_port =
		htons(src_port);
	if (src_ip == NULL) {
		comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_addr =
			in6addr_any;
	} else {
		memcpy(&comm_session->src_sock_addr.src_sock_addr_ipv6
				.sin6_addr,
		       src_ip, sizeof(struct in6_addr));
	}
	comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_family = AF_INET6;
	comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_port =
		htons(dst_port);
	memcpy(&comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_addr,
	       dst_ip, sizeof(struct in6_addr));

	return comm_session;
}

bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session)
{
	mock_socket_metadata.socket_comm_session_teardown_times_called++;

	if (socket_comm_session != NULL) {
		queue_destroy(socket_comm_session->message_queue);
		free(socket_comm_session);
	}

	return true;
}


bool socket_comm_session_connect_tcp(
	pcep_socket_comm_session *socket_comm_session)
{
	(void)socket_comm_session;

	mock_socket_metadata.socket_comm_session_connect_tcp_times_called++;

	return true;
}


void socket_comm_session_send_message(
	pcep_socket_comm_session *socket_comm_session,
	const char *encoded_message, unsigned int msg_length,
	bool delete_after_send)
{
	(void)socket_comm_session;
	(void)msg_length;

	mock_socket_metadata.socket_comm_session_send_message_times_called++;

	if (mock_socket_metadata.send_message_save_message == true) {
		/* the caller/test case is responsible for freeing the message
		 */
		dll_append(mock_socket_metadata.sent_message_list,
			   (char *)encoded_message);
	} else {
		if (delete_after_send == true) {
			free((void *)encoded_message);
		}
	}

	return;
}


bool socket_comm_session_close_tcp_after_write(
	pcep_socket_comm_session *socket_comm_session)
{
	(void)socket_comm_session;

	mock_socket_metadata
		.socket_comm_session_close_tcp_after_write_times_called++;

	return true;
}


bool socket_comm_session_close_tcp(
	pcep_socket_comm_session *socket_comm_session)
{
	(void)socket_comm_session;

	mock_socket_metadata.socket_comm_session_close_tcp_times_called++;

	return true;
}
