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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <CUnit/CUnit.h>

#include "pcep_msg_encoding.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_memory.h"
#include "pcep_session_logic_loop_test.h"


extern pcep_session_logic_handle *session_logic_handle_;
extern pcep_event_queue *session_logic_event_queue_;

/*
 * Test suite setup and teardown called before AND after the test suite.
 */

int pcep_session_logic_loop_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_session_logic_loop_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}


/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_loop_test_setup()
{
	/* We need to setup the session_logic_handle_ without starting the
	 * thread */
	session_logic_handle_ = pceplib_malloc(
		PCEPLIB_INFRA, sizeof(pcep_session_logic_handle));
	memset(session_logic_handle_, 0, sizeof(pcep_session_logic_handle));
	session_logic_handle_->active = true;
	session_logic_handle_->session_list =
		ordered_list_initialize(pointer_compare_function);
	session_logic_handle_->session_event_queue = queue_initialize();
	pthread_cond_init(&(session_logic_handle_->session_logic_cond_var),
			  NULL);
	pthread_mutex_init(&(session_logic_handle_->session_logic_mutex), NULL);
	pthread_mutex_init(&(session_logic_handle_->session_list_mutex), NULL);

	pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
	session_logic_handle_->session_logic_condition = true;
	pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
	pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

	session_logic_event_queue_ =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_event_queue));
	memset(session_logic_event_queue_, 0, sizeof(pcep_event_queue));
	session_logic_event_queue_->event_queue = queue_initialize();
}


void pcep_session_logic_loop_test_teardown()
{
	ordered_list_destroy(session_logic_handle_->session_list);
	queue_destroy(session_logic_handle_->session_event_queue);
	pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
	pthread_mutex_destroy(&(session_logic_handle_->session_logic_mutex));
	pthread_mutex_destroy(&(session_logic_handle_->session_list_mutex));
	pceplib_free(PCEPLIB_INFRA, session_logic_handle_);
	session_logic_handle_ = NULL;

	queue_destroy(session_logic_event_queue_->event_queue);
	pceplib_free(PCEPLIB_INFRA, session_logic_event_queue_);
	session_logic_event_queue_ = NULL;
}


/*
 * Test cases
 */

void test_session_logic_loop_null_data()
{
	/* Just testing that it does not core dump */
	session_logic_loop(NULL);
}


void test_session_logic_loop_inactive()
{
	session_logic_handle_->active = false;

	session_logic_loop(session_logic_handle_);
}


void test_session_logic_msg_ready_handler()
{
	/* Just testing that it does not core dump */
	CU_ASSERT_EQUAL(session_logic_msg_ready_handler(NULL, 0), -1);

	/* Read from an empty file should return 0, thus
	 * session_logic_msg_ready_handler returns -1 */
	mode_t oldumask;
	oldumask = umask(S_IXUSR | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
	/* Set umask before anything for security */
	umask(0027);
	char tmpfile[] = "/tmp/pceplib_XXXXXX";
	int fd = mkstemp(tmpfile);
	umask(oldumask);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	pcep_session session;
	memset(&session, 0, sizeof(pcep_session));
	session.session_id = 100;
	CU_ASSERT_EQUAL(session_logic_msg_ready_handler(&session, fd), 0);
	CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries,
			1);
	pcep_event *e = queue_dequeue(session_logic_event_queue_->event_queue);
	CU_ASSERT_EQUAL(PCE_CLOSED_SOCKET, e->event_type);
	pceplib_free(PCEPLIB_INFRA, e);
	pcep_session_event *socket_event = (pcep_session_event *)queue_dequeue(
		session_logic_handle_->session_event_queue);
	CU_ASSERT_PTR_NOT_NULL(socket_event);
	assert(socket_event != NULL);
	CU_ASSERT_TRUE(socket_event->socket_closed);
	pceplib_free(PCEPLIB_INFRA, socket_event);

	/* A pcep_session_event should be created */
	struct pcep_versioning *versioning = create_default_pcep_versioning();
	struct pcep_message *keep_alive_msg = pcep_msg_create_keepalive();
	pcep_encode_message(keep_alive_msg, versioning);
	int retval = write(fd, (char *)keep_alive_msg->encoded_message,
			   keep_alive_msg->encoded_message_length);
	CU_ASSERT_TRUE(retval > 0);
	lseek(fd, 0, SEEK_SET);
	CU_ASSERT_EQUAL(session_logic_msg_ready_handler(&session, fd),
			keep_alive_msg->encoded_message_length);
	CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries,
			1);
	socket_event = (pcep_session_event *)queue_dequeue(
		session_logic_handle_->session_event_queue);
	CU_ASSERT_PTR_NOT_NULL(socket_event);
	assert(socket_event != NULL);
	CU_ASSERT_FALSE(socket_event->socket_closed);
	CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
	CU_ASSERT_EQUAL(socket_event->expired_timer_id, TIMER_ID_NOT_SET);
	CU_ASSERT_PTR_NOT_NULL(socket_event->received_msg_list);
	pcep_msg_free_message_list(socket_event->received_msg_list);
	pcep_msg_free_message(keep_alive_msg);
	destroy_pcep_versioning(versioning);
	pceplib_free(PCEPLIB_INFRA, socket_event);
	close(fd);
	unlink(tmpfile);
}


void test_session_logic_conn_except_notifier()
{
	/* Just testing that it does not core dump */
	session_logic_conn_except_notifier(NULL, 1);

	/* A pcep_session_event should be created */
	pcep_session session;
	memset(&session, 0, sizeof(pcep_session));
	session.session_id = 100;
	session_logic_conn_except_notifier(&session, 10);
	CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries,
			1);
	pcep_session_event *socket_event = (pcep_session_event *)queue_dequeue(
		session_logic_handle_->session_event_queue);
	CU_ASSERT_PTR_NOT_NULL_FATAL(socket_event);
	assert(socket_event != NULL);
	CU_ASSERT_TRUE(socket_event->socket_closed);
	CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
	CU_ASSERT_EQUAL(socket_event->expired_timer_id, TIMER_ID_NOT_SET);
	CU_ASSERT_PTR_NULL(socket_event->received_msg_list);

	pceplib_free(PCEPLIB_INFRA, socket_event);
}


void test_session_logic_timer_expire_handler()
{
	/* Just testing that it does not core dump */
	session_logic_timer_expire_handler(NULL, 42);

	/* A pcep_session_event should be created */
	pcep_session session;
	memset(&session, 0, sizeof(pcep_session));
	session.session_id = 100;
	session_logic_timer_expire_handler(&session, 42);
	CU_ASSERT_EQUAL(session_logic_handle_->session_event_queue->num_entries,
			1);
	pcep_session_event *socket_event = (pcep_session_event *)queue_dequeue(
		session_logic_handle_->session_event_queue);
	CU_ASSERT_PTR_NOT_NULL_FATAL(socket_event);
	assert(socket_event != NULL);
	CU_ASSERT_FALSE(socket_event->socket_closed);
	CU_ASSERT_PTR_EQUAL(socket_event->session, &session);
	CU_ASSERT_EQUAL(socket_event->expired_timer_id, 42);
	CU_ASSERT_PTR_NULL(socket_event->received_msg_list);

	pceplib_free(PCEPLIB_INFRA, socket_event);
}
