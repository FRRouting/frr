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

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm_internals.h"
#include "pcep_socket_comm_loop.h"
#include "pcep_socket_comm_loop_test.h"
#include "pcep_socket_comm.h"
#include "pcep_utils_memory.h"

void test_loop_conn_except_notifier(void *session_data, int socket_fd);

/*
 * Functions to be tested, implemented in pcep_socket_comm_loop.c
 */

typedef struct ready_to_read_handler_info_ {
	bool handler_called;
	bool except_handler_called;
	void *data;
	int socket_fd;
	int bytes_read;

} ready_to_read_handler_info;

static ready_to_read_handler_info read_handler_info;
static pcep_socket_comm_session *test_comm_session;
static pcep_socket_comm_handle *test_socket_comm_handle = NULL;

static int test_loop_message_ready_to_read_handler(void *session_data,
						   int socket_fd)
{
	read_handler_info.handler_called = true;
	read_handler_info.data = session_data;
	read_handler_info.socket_fd = socket_fd;

	return read_handler_info.bytes_read;
}


void test_loop_conn_except_notifier(void *session_data, int socket_fd)
{
	(void)session_data;
	(void)socket_fd;
	read_handler_info.except_handler_called = true;
}


/*
 * Test case setup and teardown called before AND after each test.
 */
void pcep_socket_comm_loop_test_setup()
{
	test_socket_comm_handle =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_socket_comm_handle));
	memset(test_socket_comm_handle, 0, sizeof(pcep_socket_comm_handle));
	test_socket_comm_handle->active = false;
	test_socket_comm_handle->read_list =
		ordered_list_initialize(socket_fd_node_compare);
	test_socket_comm_handle->write_list =
		ordered_list_initialize(socket_fd_node_compare);
	test_socket_comm_handle->session_list =
		ordered_list_initialize(pointer_compare_function);
	pthread_mutex_init(&test_socket_comm_handle->socket_comm_mutex, NULL);
	test_socket_comm_handle->num_active_sessions = 0;

	test_comm_session =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_socket_comm_session));
	memset(test_comm_session, 0, sizeof(pcep_socket_comm_session));
	test_comm_session->message_ready_to_read_handler =
		test_loop_message_ready_to_read_handler;
	ordered_list_add_node(test_socket_comm_handle->session_list,
			      test_comm_session);

	read_handler_info.handler_called = false;
	read_handler_info.except_handler_called = false;
	read_handler_info.data = NULL;
	read_handler_info.socket_fd = -1;
	read_handler_info.bytes_read = 0;
}


void pcep_socket_comm_loop_test_teardown()
{
	pthread_mutex_destroy(&test_socket_comm_handle->socket_comm_mutex);
	ordered_list_destroy(test_socket_comm_handle->read_list);
	ordered_list_destroy(test_socket_comm_handle->write_list);
	ordered_list_destroy(test_socket_comm_handle->session_list);
	pceplib_free(PCEPLIB_INFRA, test_socket_comm_handle);
	test_socket_comm_handle = NULL;

	if (test_comm_session != NULL) {
		pceplib_free(PCEPLIB_INFRA, test_comm_session);
		test_comm_session = NULL;
	}
}


/*
 * Test cases
 */

void test_socket_comm_loop_null_handle()
{
	/* Verify that socket_comm_loop() correctly handles a NULL
	 * timers_context */
	socket_comm_loop(NULL);
}


void test_socket_comm_loop_not_active()
{
	/* Verify that event_loop() correctly handles an inactive flag */
	pcep_socket_comm_handle handle;
	handle.active = false;
	socket_comm_loop(&handle);
}


void test_handle_reads_no_read()
{
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);

	handle_reads(test_socket_comm_handle);

	CU_ASSERT_FALSE(read_handler_info.handler_called);
	CU_ASSERT_FALSE(read_handler_info.except_handler_called);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);
}


void test_handle_reads_read_message()
{
	/* Setup the comm session so that it can read.
	 * It should read 100 bytes, which simulates a successful read */
	test_comm_session->socket_fd = 10;
	read_handler_info.bytes_read = 100;
	FD_SET(test_comm_session->socket_fd,
	       &test_socket_comm_handle->read_master_set);
	ordered_list_add_node(test_socket_comm_handle->read_list,
			      test_comm_session);

	handle_reads(test_socket_comm_handle);

	CU_ASSERT_TRUE(read_handler_info.handler_called);
	CU_ASSERT_FALSE(read_handler_info.except_handler_called);
	CU_ASSERT_EQUAL(test_comm_session->received_bytes,
			read_handler_info.bytes_read);
}


void test_handle_reads_read_message_close()
{
	/* Setup the comm session so that it can read.
	 * It should read 0 bytes, which simulates that the socket closed */
	test_comm_session->socket_fd = 11;
	read_handler_info.bytes_read = 0;
	FD_SET(test_comm_session->socket_fd,
	       &test_socket_comm_handle->read_master_set);
	ordered_list_add_node(test_socket_comm_handle->read_list,
			      test_comm_session);

	handle_reads(test_socket_comm_handle);

	CU_ASSERT_TRUE(read_handler_info.handler_called);
	CU_ASSERT_FALSE(read_handler_info.except_handler_called);
	CU_ASSERT_EQUAL(test_comm_session->received_bytes,
			read_handler_info.bytes_read);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);
}


/* Tears its own comm session down, as another thread could during a read */
static int test_loop_teardown_read_handler(void *session_data, int socket_fd)
{
	(void)session_data;

	read_handler_info.handler_called = true;
	CU_ASSERT_TRUE(socket_comm_session_teardown(test_comm_session));
	/* Not freed yet, and its socket is closed by handle_reads() */
	CU_ASSERT_EQUAL(test_comm_session->socket_fd, -1);
	CU_ASSERT_NOT_EQUAL(fcntl(socket_fd, F_GETFD), -1);

	return 1;
}


/* Closes its own socket, then tears its comm session down */
static int test_loop_close_read_handler(void *session_data, int socket_fd)
{
	(void)session_data;

	read_handler_info.handler_called = true;
	CU_ASSERT_TRUE(socket_comm_session_close_tcp(test_comm_session));
	/* Still open: handle_reads() closes it, so its number is not reused */
	CU_ASSERT_NOT_EQUAL(fcntl(socket_fd, F_GETFD), -1);
	CU_ASSERT_TRUE(socket_comm_session_teardown(test_comm_session));
	CU_ASSERT_NOT_EQUAL(fcntl(socket_fd, F_GETFD), -1);

	return 1;
}


void test_handle_reads_teardown_during_read(void)
{
	int fds[2];

	CU_ASSERT_EQUAL_FATAL(pipe(fds), 0);
	socket_comm_handle_ = test_socket_comm_handle;
	test_comm_session->socket_fd = fds[0];
	test_comm_session->message_queue = queue_initialize();
	test_comm_session->message_ready_to_read_handler = test_loop_teardown_read_handler;
	test_socket_comm_handle->num_active_sessions = 1;
	ordered_list_add_node(test_socket_comm_handle->read_list, test_comm_session);
	FD_SET(fds[0], &test_socket_comm_handle->read_master_set);

	handle_reads(test_socket_comm_handle);

	CU_ASSERT_TRUE(read_handler_info.handler_called);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->session_list->head);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->read_list->head);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->reading_session);
	/* handle_reads() closed the socket and freed the comm session */
	CU_ASSERT_EQUAL(fcntl(fds[0], F_GETFD), -1);
	test_comm_session = NULL;
	socket_comm_handle_ = NULL;
	close(fds[1]);
}


void test_handle_reads_close_during_read(void)
{
	int fds[2];

	CU_ASSERT_EQUAL_FATAL(pipe(fds), 0);
	socket_comm_handle_ = test_socket_comm_handle;
	test_comm_session->socket_fd = fds[0];
	test_comm_session->message_queue = queue_initialize();
	test_comm_session->message_ready_to_read_handler = test_loop_close_read_handler;
	test_socket_comm_handle->num_active_sessions = 1;
	ordered_list_add_node(test_socket_comm_handle->read_list, test_comm_session);
	FD_SET(fds[0], &test_socket_comm_handle->read_master_set);

	handle_reads(test_socket_comm_handle);

	CU_ASSERT_TRUE(read_handler_info.handler_called);
	CU_ASSERT_PTR_NULL(test_socket_comm_handle->session_list->head);
	/* handle_reads() closed the socket once and freed the comm session */
	CU_ASSERT_EQUAL(fcntl(fds[0], F_GETFD), -1);
	test_comm_session = NULL;
	socket_comm_handle_ = NULL;
	close(fds[1]);
}
