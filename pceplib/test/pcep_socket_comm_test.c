// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <netinet/in.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm.h"
#include "pcep_socket_comm_internals.h"
#include "pcep_socket_comm_test.h"

extern pcep_socket_comm_handle *socket_comm_handle_;

static pcep_socket_comm_session *test_session = NULL;
static struct in_addr test_host_ip;
static struct in_addr test_src_ip;
static struct in6_addr test_host_ipv6;
static struct in6_addr test_src_ipv6;
static short test_port = 4789;
static short test_src_port = 4999;
static uint32_t connect_timeout_millis = 500;

/*
 * Unit Test Basic pcep_socket_comm API usage.
 * Testing sending messages, etc via sockets should be done
 * with integration tests, not unit tests.
 */

/*
 * Different socket_comm handler test implementations
 */
static void test_message_received_handler(void *session_data,
					  const char *message_data,
					  unsigned int message_length)
{
	(void)session_data;
	(void)message_data;
	(void)message_length;
}

static int test_message_ready_to_read_handler(void *session_data, int socket_fd)
{
	(void)session_data;
	(void)socket_fd;
	return 1;
}

static void test_message_sent_handler(void *session_data, int socket_fd)
{
	(void)session_data;
	(void)socket_fd;
	return;
}

static void test_connection_except_notifier(void *session_data, int socket_fd)
{
	(void)session_data;
	(void)socket_fd;
}


/*
 * Test case setup and teardown called before AND after each test.
 */
void pcep_socket_comm_test_setup()
{
	inet_pton(AF_INET, "127.0.0.1", &(test_host_ip));
	inet_pton(AF_INET, "127.0.0.1", &(test_src_ip));
	inet_pton(AF_INET6, "::1", &(test_host_ipv6));
	inet_pton(AF_INET6, "::1", &(test_src_ipv6));
}

void pcep_socket_comm_test_teardown()
{
	socket_comm_session_teardown(test_session);
	test_session = NULL;
}


/*
 * Test cases
 */

void test_pcep_socket_comm_initialize()
{
	test_session = socket_comm_session_initialize(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ip, test_port,
		connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_FALSE(test_session->is_ipv6);
}


void test_pcep_socket_comm_initialize_ipv6()
{
	test_session = socket_comm_session_initialize_ipv6(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ipv6, test_port,
		connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_TRUE(test_session->is_ipv6);
}


void test_pcep_socket_comm_initialize_with_src()
{
	/* Test that INADDR_ANY will be used when src_ip is NULL */
	test_session = socket_comm_session_initialize_with_src(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, NULL, 0, &test_host_ip,
		test_port, connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(
		test_session->src_sock_addr.src_sock_addr_ipv4.sin_addr.s_addr,
		INADDR_ANY);
	CU_ASSERT_FALSE(test_session->is_ipv6);

	socket_comm_session_teardown(test_session);
	test_session = socket_comm_session_initialize_with_src(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_src_ip, test_src_port,
		&test_host_ip, test_port, connect_timeout_millis, NULL, false,
		NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(
		test_session->src_sock_addr.src_sock_addr_ipv4.sin_addr.s_addr,
		test_src_ip.s_addr);
	CU_ASSERT_EQUAL(test_session->src_sock_addr.src_sock_addr_ipv4.sin_port,
			ntohs(test_src_port));
	CU_ASSERT_FALSE(test_session->is_ipv6);
}


void test_pcep_socket_comm_initialize_with_src_ipv6()
{
	/* Test that INADDR6_ANY will be used when src_ip is NULL */
	test_session = socket_comm_session_initialize_with_src_ipv6(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, NULL, 0, &test_host_ipv6,
		test_port, connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(memcmp(&test_session->src_sock_addr.src_sock_addr_ipv6
					.sin6_addr,
			       &in6addr_any, sizeof(struct in6_addr)),
			0);
	CU_ASSERT_TRUE(test_session->is_ipv6);

	socket_comm_session_teardown(test_session);
	test_session = socket_comm_session_initialize_with_src_ipv6(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_src_ipv6, test_src_port,
		&test_host_ipv6, test_port, connect_timeout_millis, NULL, false,
		NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(memcmp(&test_session->src_sock_addr.src_sock_addr_ipv6
					.sin6_addr,
			       &test_src_ipv6, sizeof(struct in6_addr)),
			0);
	CU_ASSERT_EQUAL(
		test_session->src_sock_addr.src_sock_addr_ipv6.sin6_port,
		ntohs(test_src_port));
	CU_ASSERT_TRUE(test_session->is_ipv6);
}


void test_pcep_socket_comm_initialize_tcpmd5()
{
	char tcp_md5_str[] = "hello";
	int tcp_md5_strlen = strlen(tcp_md5_str);

	test_session = socket_comm_session_initialize(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ip, test_port, 1,
		tcp_md5_str, true, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(0, strncmp(tcp_md5_str,
				   test_session->tcp_authentication_str,
				   tcp_md5_strlen));
	CU_ASSERT_TRUE(test_session->is_tcp_auth_md5);
	CU_ASSERT_FALSE(socket_comm_session_connect_tcp(test_session));
	/* This call does not work, it returns errno=92, Protocol not available
	getsockopt(test_session->socket_fd, SOL_SOCKET, TCP_MD5SIG, &sig,
	&siglen);*/

	socket_comm_session_teardown(test_session);
	test_session = socket_comm_session_initialize(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ip, test_port, 1,
		tcp_md5_str, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(0, strncmp(tcp_md5_str,
				   test_session->tcp_authentication_str,
				   tcp_md5_strlen));
	CU_ASSERT_FALSE(test_session->is_tcp_auth_md5);
	CU_ASSERT_FALSE(socket_comm_session_connect_tcp(test_session));
}


void test_pcep_socket_comm_initialize_ipv6_tcpmd5()
{
	char tcp_md5_str[] = "hello";
	int tcp_md5_strlen = strlen(tcp_md5_str);

	test_session = socket_comm_session_initialize_ipv6(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ipv6, test_port, 1,
		tcp_md5_str, true, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(0, strncmp(tcp_md5_str,
				   test_session->tcp_authentication_str,
				   tcp_md5_strlen));
	CU_ASSERT_TRUE(test_session->is_tcp_auth_md5);
	CU_ASSERT_FALSE(socket_comm_session_connect_tcp(test_session));
	/* This call does not work, it returns errno=92, Protocol not available
	getsockopt(test_session->socket_fd, SOL_SOCKET, TCP_MD5SIG, &sig,
	&siglen);*/

	socket_comm_session_teardown(test_session);
	test_session = socket_comm_session_initialize_ipv6(
		test_message_received_handler, NULL, NULL,
		test_connection_except_notifier, &test_host_ipv6, test_port, 1,
		tcp_md5_str, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_EQUAL(0, strncmp(tcp_md5_str,
				   test_session->tcp_authentication_str,
				   tcp_md5_strlen));
	CU_ASSERT_FALSE(test_session->is_tcp_auth_md5);
	CU_ASSERT_FALSE(socket_comm_session_connect_tcp(test_session));
}


void test_pcep_socket_comm_initialize_handlers()
{
	/* Verify incorrect handler usage is correctly handled */

	/* Both receive handlers cannot be NULL */
	test_session = socket_comm_session_initialize(
		NULL, NULL, NULL, test_connection_except_notifier,
		&test_host_ip, test_port, connect_timeout_millis, NULL, false,
		NULL);
	CU_ASSERT_PTR_NULL(test_session);

	/* Both receive handlers cannot be set */
	test_session = socket_comm_session_initialize(
		test_message_received_handler,
		test_message_ready_to_read_handler, test_message_sent_handler,
		test_connection_except_notifier, &test_host_ip, test_port,
		connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NULL(test_session);

	/* Only one receive handler can be set */
	test_session = socket_comm_session_initialize(
		NULL, test_message_ready_to_read_handler,
		test_message_sent_handler, test_connection_except_notifier,
		&test_host_ip, test_port, connect_timeout_millis, NULL, false,
		NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
}


void test_pcep_socket_comm_session_not_initialized()
{
	CU_ASSERT_FALSE(socket_comm_session_connect_tcp(NULL));
	CU_ASSERT_FALSE(socket_comm_session_close_tcp(NULL));
	CU_ASSERT_FALSE(socket_comm_session_close_tcp_after_write(NULL));
	socket_comm_session_send_message(NULL, NULL, 0, true);
	CU_ASSERT_FALSE(socket_comm_session_teardown(NULL));
}


void test_pcep_socket_comm_session_destroy()
{
	test_session = socket_comm_session_initialize(
		test_message_received_handler, NULL, test_message_sent_handler,
		test_connection_except_notifier, &test_host_ip, test_port,
		connect_timeout_millis, NULL, false, NULL);
	CU_ASSERT_PTR_NOT_NULL(test_session);
	assert(test_session != NULL);
	CU_ASSERT_PTR_NOT_NULL(socket_comm_handle_);
	assert(socket_comm_handle_ != NULL);
	CU_ASSERT_EQUAL(socket_comm_handle_->num_active_sessions, 1);

	CU_ASSERT_TRUE(socket_comm_session_teardown(test_session));
	test_session = NULL;
	CU_ASSERT_PTR_NOT_NULL(socket_comm_handle_);

	CU_ASSERT_TRUE(destroy_socket_comm_loop());
	CU_ASSERT_PTR_NULL(socket_comm_handle_);
}
