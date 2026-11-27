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
#include <netdb.h> // gethostbyname
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>

#include "pcep_pcc_api.h"
#include "pcep_session_logic_internals.h"
#include "pcep_pcc_api_test.h"
#include "pcep_socket_comm_mock.h"
#include "pcep_utils_memory.h"

extern pcep_event_queue *session_logic_event_queue_;
extern const char MESSAGE_RECEIVED_STR[];
extern const char UNKNOWN_EVENT_STR[];

/*
 * Test suite setup and teardown called before AND after the test suite.
 */

int pcep_pcc_api_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_pcc_api_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_pcc_api_test_setup(void)
{
	setup_mock_socket_comm_info();
}


void pcep_pcc_api_test_teardown(void)
{
	teardown_mock_socket_comm_info();
}

/*
 * Unit test cases
 */

void test_initialize_pcc(void)
{
	CU_ASSERT_TRUE(initialize_pcc());
	/* Give the PCC time to initialize */
	sleep(1);
	CU_ASSERT_TRUE(destroy_pcc());
}

void test_connect_pce(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;
	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;

	initialize_pcc();

	pcep_session *session = connect_pce(config, &dest_address);

	CU_ASSERT_PTR_NOT_NULL(session);
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
	/* What gets saved in the mock is the msg byte buffer. The msg struct
	 * was deleted when it was sent. Instead of inspecting the msg byte
	 * buffer, lets just decode it. */
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	struct pcep_message *open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	assert(open_msg->msg_header != NULL);
	CU_ASSERT_EQUAL(open_msg->msg_header->type, PCEP_TYPE_OPEN);

	pcep_msg_free_message(open_msg);
	destroy_pcep_session(session);
	destroy_pcep_configuration(config);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	destroy_pcc();
}

void test_connect_pce_ipv6(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct in6_addr dest_address;
	dest_address.__in6_u.__u6_addr32[0] = 0;
	dest_address.__in6_u.__u6_addr32[1] = 0;
	dest_address.__in6_u.__u6_addr32[2] = 0;
	dest_address.__in6_u.__u6_addr32[3] = htonl(1);
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;

	initialize_pcc();

	pcep_session *session = connect_pce_ipv6(config, &dest_address);

	CU_ASSERT_PTR_NOT_NULL(session);
	assert(session != NULL);
	CU_ASSERT_TRUE(session->socket_comm_session->is_ipv6);
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
	/* What gets saved in the mock is the msg byte buffer. The msg struct
	 * was deleted when it was sent. Instead of inspecting the msg byte
	 * buffer, lets just decode it. */
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	struct pcep_message *open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	CU_ASSERT_EQUAL(open_msg->msg_header->type, PCEP_TYPE_OPEN);

	pcep_msg_free_message(open_msg);
	destroy_pcep_session(session);
	destroy_pcep_configuration(config);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	destroy_pcc();
}

void test_connect_pce_with_src_ip(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;
	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	config->src_ip.src_ipv4.s_addr = 0x0a0a0102;

	initialize_pcc();

	pcep_session *session = connect_pce(config, &dest_address);

	CU_ASSERT_PTR_NOT_NULL(session);
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	struct pcep_message *open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	assert(open_msg->msg_header != NULL);
	CU_ASSERT_EQUAL(open_msg->msg_header->type, PCEP_TYPE_OPEN);

	pcep_msg_free_message(open_msg);
	destroy_pcep_session(session);
	destroy_pcep_configuration(config);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	destroy_pcc();
}

/* disconnect_pce() is handled by the session logic thread */
static bool wait_session_destroyed(pcep_session *session)
{
	for (int i = 0; i < 200; i++) {
		if (!session_exists(session))
			return true;
		usleep(10000);
	}
	return false;
}

/* The session logic thread handles events holding session_logic_mutex */
static void wait_events_handled(void)
{
	for (int i = 0; i < 200; i++) {
		pthread_mutex_lock(&session_logic_handle_->session_logic_mutex);
		bool done = session_logic_handle_->session_event_queue->num_entries == 0;

		pthread_mutex_unlock(&session_logic_handle_->session_logic_mutex);
		if (done)
			return;
		usleep(10000);
	}
}

static void check_sent_message(mock_socket_comm_info *mock_info, enum pcep_message_types type)
{
	uint8_t *encoded_msg = dll_delete_first_node(mock_info->sent_message_list);

	CU_ASSERT_PTR_NOT_NULL_FATAL(encoded_msg);
	assert(encoded_msg != NULL);
	struct pcep_message *msg = pcep_decode_message(encoded_msg);

	CU_ASSERT_PTR_NOT_NULL_FATAL(msg);
	assert(msg != NULL);
	CU_ASSERT_EQUAL(msg->msg_header->type, type);
	pcep_msg_free_message(msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);
}

void test_disconnect_pce(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();

	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	mock_info->send_message_save_message = true;

	initialize_pcc();

	/* Not established: no Close (RFC 5440 4.2.7), destroyed at once */
	pcep_session *session = connect_pce(config, &dest_address);
	disconnect_pce(session);
	CU_ASSERT_TRUE(wait_session_destroyed(session));
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 1);
	check_sent_message(mock_info, PCEP_TYPE_OPEN);

	/* Established: one Close, destroyed once it is written */
	session = connect_pce(config, &dest_address);
	session->session_state = SESSION_STATE_PCEP_CONNECTED;
	disconnect_pce(session);
	wait_events_handled();
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 2);
	CU_ASSERT_TRUE(session_exists(session));
	session_logic_message_sent_handler(session, 0);
	CU_ASSERT_TRUE(wait_session_destroyed(session));
	check_sent_message(mock_info, PCEP_TYPE_OPEN);
	check_sent_message(mock_info, PCEP_TYPE_CLOSE);

	/* pceplib already closed it: no second Close (RFC 5440 6.9) */
	session = connect_pce(config, &dest_address);
	session->session_state = SESSION_STATE_PCEP_CONNECTED;
	close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_UNREC_MSG);
	disconnect_pce(session);
	CU_ASSERT_TRUE(wait_session_destroyed(session));
	CU_ASSERT_EQUAL(mock_info->sent_message_list->num_entries, 2);
	check_sent_message(mock_info, PCEP_TYPE_OPEN);
	check_sent_message(mock_info, PCEP_TYPE_CLOSE);

	destroy_pcep_configuration(config);
	destroy_pcc();
}


/* destroy_pcc() right after disconnect_pce() still frees the session */
void test_destroy_pcc_after_disconnect(void)
{
	struct pceplib_memory_type *infra = PCEPLIB_INFRA;
	struct pceplib_memory_type *msgs = PCEPLIB_MESSAGES;
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	uint8_t *encoded_msg;

	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	mock_info->send_message_save_message = true;
	uint32_t infra_allocs = infra->num_allocates;
	uint32_t infra_frees = infra->num_frees;
	uint32_t msg_allocs = msgs->num_allocates;
	uint32_t msg_frees = msgs->num_frees;

	initialize_pcc();
	pcep_session *session = connect_pce(config, &dest_address);

	session->session_state = SESSION_STATE_PCEP_CONNECTED;
	disconnect_pce(session);
	destroy_pcc();

	while ((encoded_msg = dll_delete_first_node(mock_info->sent_message_list)))
		pceplib_free(PCEPLIB_MESSAGES, encoded_msg);
	CU_ASSERT_EQUAL(infra->num_allocates - infra_allocs, infra->num_frees - infra_frees);
	CU_ASSERT_EQUAL(msgs->num_allocates - msg_allocs, msgs->num_frees - msg_frees);
	destroy_pcep_configuration(config);
}


/* Plays socket comm: an unknown message, then a sent notification, until stopped */
struct stress_args {
	pcep_session *session;
	int rd_fd;
	int wr_fd;
	atomic_bool stop;
};

static void *stress_socket_thread(void *data)
{
	struct stress_args *args = data;
	/* Version 0: no message decodes, each read is an unknown message */
	const uint8_t garbage[MESSAGE_HEADER_LENGTH] = { 0, 0, 0, 4 };

	while (!atomic_load(&args->stop)) {
		if (write(args->wr_fd, garbage, sizeof(garbage)) != sizeof(garbage))
			break;
		session_logic_msg_ready_handler(args->session, args->rd_fd);
		session_logic_message_sent_handler(args->session, args->rd_fd);
	}
	return NULL;
}

/* Consumes the API events, returns how many are of this type */
static int drain_events(enum pcep_event_type type)
{
	struct pcep_event *event;
	int count = 0;

	while ((event = event_queue_get_event()) != NULL) {
		if (event->event_type == type)
			count++;
		destroy_pcep_event(event);
	}
	return count;
}

static int count_sent_messages(mock_socket_comm_info *mock_info, enum pcep_message_types type)
{
	int count = 0;
	uint8_t *encoded_msg;

	while ((encoded_msg = dll_delete_first_node(mock_info->sent_message_list))) {
		struct pcep_message *msg = pcep_decode_message(encoded_msg);

		if (msg != NULL && msg->msg_header->type == type)
			count++;
		pcep_msg_free_message(msg);
		pceplib_free(PCEPLIB_MESSAGES, encoded_msg);
	}
	return count;
}

/* Unknown messages close the session while pathd disconnects it: exactly
 * one Close, and the session is destroyed once.
 */
void test_disconnect_pce_unknown_messages_stress(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();

	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	mock_info->send_message_save_message = true;
	config->max_unknown_messages = 3;

	initialize_pcc();

	for (int round = 0; round < 50; round++) {
		int fds[2];
		pthread_t thread;
		struct stress_args args = { .stop = false };

		CU_ASSERT_EQUAL_FATAL(pipe(fds), 0);
		pcep_session *session = connect_pce(config, &dest_address);

		session->session_state = SESSION_STATE_PCEP_CONNECTED;
		args.session = session;
		args.rd_fd = fds[0];
		args.wr_fd = fds[1];
		pthread_create(&thread, NULL, stress_socket_thread, &args);

		usleep(1000 * (round % 5));
		disconnect_pce(session);
		CU_ASSERT_TRUE(wait_session_destroyed(session));

		atomic_store(&args.stop, true);
		pthread_join(thread, NULL);
		close(fds[0]);
		close(fds[1]);
		CU_ASSERT_EQUAL(count_sent_messages(mock_info, PCEP_TYPE_CLOSE), 1);
		/* none if the disconnect sent the Close first */
		CU_ASSERT_TRUE(drain_events(PCC_RCVD_MAX_UNKOWN_MSGS) <= 1);
	}

	destroy_pcep_configuration(config);
	destroy_pcc();
}


void test_send_message(void)
{
	pcep_configuration *config = create_default_pcep_configuration();
	struct hostent *host_info = gethostbyname("localhost");
	struct in_addr dest_address;

	initialize_pcc();

	memcpy(&dest_address, host_info->h_addr, host_info->h_length);
	pcep_session *session = connect_pce(config, &dest_address);
	verify_socket_comm_times_called(0, 0, 1, 1, 0, 0, 0);

	struct pcep_message *msg = pcep_msg_create_keepalive();
	send_message(session, msg, false);

	verify_socket_comm_times_called(0, 0, 1, 2, 0, 0, 0);

	/* Nothing may follow a Close (RFC 5440 6.9) */
	close_pcep_session(session);
	verify_socket_comm_times_called(0, 0, 1, 3, 1, 0, 0);
	send_message(session, msg, false);
	verify_socket_comm_times_called(0, 0, 1, 3, 1, 0, 0);

	pcep_msg_free_message(msg);
	destroy_pcep_session(session);
	destroy_pcep_configuration(config);

	destroy_pcc();
}

void test_event_queue(void)
{
	/* This initializes the event_queue */
	CU_ASSERT_TRUE(initialize_pcc());

	/* Verify correct behavior when the queue is empty */
	CU_ASSERT_TRUE(event_queue_is_empty());
	CU_ASSERT_EQUAL(event_queue_num_events_available(), 0);
	CU_ASSERT_PTR_NULL(event_queue_get_event());
	destroy_pcep_event(NULL);

	/* Create an empty event and put it on the queue */
	pcep_event *event = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_event));
	memset(event, 0, sizeof(pcep_event));
	pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
	queue_enqueue(session_logic_event_queue_->event_queue, event);
	pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

	/* Verify correct behavior when there is an entry in the queue */
	CU_ASSERT_FALSE(event_queue_is_empty());
	CU_ASSERT_EQUAL(event_queue_num_events_available(), 1);
	pcep_event *queued_event = event_queue_get_event();
	CU_ASSERT_PTR_NOT_NULL(queued_event);
	CU_ASSERT_PTR_EQUAL(event, queued_event);
	destroy_pcep_event(queued_event);

	CU_ASSERT_TRUE(destroy_pcc());
}

void test_get_event_type_str(void)
{
	CU_ASSERT_EQUAL(strcmp(get_event_type_str(MESSAGE_RECEIVED),
			       MESSAGE_RECEIVED_STR),
			0);
	CU_ASSERT_EQUAL(strcmp(get_event_type_str(1000), UNKNOWN_EVENT_STR), 0);
}
