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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <CUnit/CUnit.h>

#include "pcep_socket_comm_mock.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_test.h"

/*
 * Test suite setup and teardown called before AND after the test suite.
 */

int pcep_session_logic_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_session_logic_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

/*
 * Test case setup and teardown called before AND after each test.
 */

void pcep_session_logic_test_setup()
{
	setup_mock_socket_comm_info();
}


void pcep_session_logic_test_teardown()
{
	stop_session_logic();
	teardown_mock_socket_comm_info();
}


/*
 * Test cases
 */

void test_run_stop_session_logic()
{
	CU_ASSERT_TRUE(run_session_logic());
	CU_ASSERT_TRUE(stop_session_logic());
}


void test_run_session_logic_twice()
{
	CU_ASSERT_TRUE(run_session_logic());
	CU_ASSERT_FALSE(run_session_logic());
}


void test_session_logic_without_run()
{
	/* Verify the functions that depend on run_session_logic() being called
	 */
	CU_ASSERT_FALSE(stop_session_logic());
}


void test_create_pcep_session_null_params()
{
	pcep_configuration config;
	struct in_addr pce_ip;

	CU_ASSERT_PTR_NULL(create_pcep_session(NULL, NULL));
	CU_ASSERT_PTR_NULL(create_pcep_session(NULL, &pce_ip));
	CU_ASSERT_PTR_NULL(create_pcep_session(&config, NULL));
}


void test_create_destroy_pcep_session()
{
	pcep_session *session;
	pcep_configuration config;
	struct in_addr pce_ip;

	run_session_logic();

	memset(&config, 0, sizeof(pcep_configuration));
	config.keep_alive_seconds = 5;
	config.dead_timer_seconds = 5;
	config.request_time_seconds = 5;
	config.max_unknown_messages = 5;
	config.max_unknown_requests = 5;
	inet_pton(AF_INET, "127.0.0.1", &(pce_ip));

	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	session = create_pcep_session(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	/* What gets saved in the mock is the msg byte buffer. The msg struct
	 * was deleted when it was sent. Instead of inspecting the msg byte
	 * buffer, lets just decode it. */
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	struct pcep_message *open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	/* Should be an Open, with no TLVs: length = 12 */
	CU_ASSERT_EQUAL(open_msg->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(open_msg->encoded_message_length, 12);
	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	stop_session_logic();
}


void test_create_destroy_pcep_session_ipv6()
{
	pcep_session *session;
	pcep_configuration config;
	struct in6_addr pce_ip;

	run_session_logic();

	memset(&config, 0, sizeof(pcep_configuration));
	config.keep_alive_seconds = 5;
	config.dead_timer_seconds = 5;
	config.request_time_seconds = 5;
	config.max_unknown_messages = 5;
	config.max_unknown_requests = 5;
	config.is_src_ipv6 = true;
	inet_pton(AF_INET6, "::1", &pce_ip);

	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	session = create_pcep_session_ipv6(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	assert(session != NULL);
	CU_ASSERT_TRUE(session->socket_comm_session->is_ipv6);
	/* What gets saved in the mock is the msg byte buffer. The msg struct
	 * was deleted when it was sent. Instead of inspecting the msg byte
	 * buffer, lets just decode it. */
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	struct pcep_message *open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	/* Should be an Open, with no TLVs: length = 12 */
	CU_ASSERT_EQUAL(open_msg->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(open_msg->encoded_message_length, 12);
	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	stop_session_logic();
}


void test_create_pcep_session_open_tlvs()
{
	pcep_session *session;
	struct in_addr pce_ip;
	struct pcep_message *open_msg;
	struct pcep_object_header *open_obj;
	pcep_configuration config;
	memset(&config, 0, sizeof(pcep_configuration));
	config.pcep_msg_versioning = create_default_pcep_versioning();
	inet_pton(AF_INET, "127.0.0.1", &(pce_ip));

	run_session_logic();

	/* Verify the created Open message only has 1 TLV:
	 *   pcep_tlv_create_stateful_pce_capability() */
	mock_socket_comm_info *mock_info = get_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	config.support_stateful_pce_lsp_update = true;
	config.pcep_msg_versioning->draft_ietf_pce_segment_routing_07 = false;
	config.support_sr_te_pst = false;

	session = create_pcep_session(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	/* Get and verify the Open Message */
	uint8_t *encoded_msg =
		dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	/* Get and verify the Open Message objects */
	CU_ASSERT_PTR_NOT_NULL(open_msg->obj_list);
	assert(open_msg->obj_list != NULL);
	CU_ASSERT_TRUE(open_msg->obj_list->num_entries > 0);
	/* Get and verify the Open object */
	open_obj = pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_PTR_NOT_NULL(open_obj);
	/* Get and verify the Open object TLVs */
	CU_ASSERT_PTR_NOT_NULL(open_obj->tlv_list);
	assert(open_obj->tlv_list != NULL);
	CU_ASSERT_EQUAL(open_obj->tlv_list->num_entries, 1);
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)
				 open_obj->tlv_list->head->data)
				->type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);

	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	/* Verify the created Open message only has 2 TLVs:
	 *   pcep_tlv_create_stateful_pce_capability()
	 *   pcep_tlv_create_lsp_db_version() */
	reset_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	config.support_include_db_version = true;
	config.lsp_db_version = 100;

	session = create_pcep_session(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	/* Get and verify the Open Message */
	encoded_msg = dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	/* Get and verify the Open Message objects */
	CU_ASSERT_PTR_NOT_NULL(open_msg->obj_list);
	assert(open_msg != NULL);
	CU_ASSERT_TRUE(open_msg->obj_list->num_entries > 0);
	/* Get and verify the Open object */
	open_obj = pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_PTR_NOT_NULL(open_obj);
	/* Get and verify the Open object TLVs */
	CU_ASSERT_PTR_NOT_NULL(open_obj->tlv_list);
	assert(open_obj->tlv_list != NULL);
	CU_ASSERT_EQUAL(open_obj->tlv_list->num_entries, 2);
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)
				 open_obj->tlv_list->head->data)
				->type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)
				 open_obj->tlv_list->head->next_node->data)
				->type,
			PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);

	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);


	/* Verify the created Open message only has 4 TLVs:
	 *   pcep_tlv_create_stateful_pce_capability()
	 *   pcep_tlv_create_lsp_db_version()
	 *   pcep_tlv_create_sr_pce_capability()
	 *   pcep_tlv_create_path_setup_type_capability() */
	reset_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	config.support_sr_te_pst = true;

	session = create_pcep_session(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	/* Get and verify the Open Message */
	encoded_msg = dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	/* Get and verify the Open Message objects */
	CU_ASSERT_PTR_NOT_NULL(open_msg->obj_list);
	assert(open_msg->obj_list != NULL);
	CU_ASSERT_TRUE(open_msg->obj_list->num_entries > 0);
	/* Get and verify the Open object */
	open_obj = pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_PTR_NOT_NULL(open_obj);
	/* Get and verify the Open object TLVs */
	CU_ASSERT_PTR_NOT_NULL(open_obj->tlv_list);
	assert(open_obj->tlv_list != NULL);
	CU_ASSERT_EQUAL(open_obj->tlv_list->num_entries, 3);
	double_linked_list_node *tlv_node = open_obj->tlv_list->head;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	tlv_node = tlv_node->next_node;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
	tlv_node = tlv_node->next_node;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);

	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	/* Verify the created Open message only has 4 TLVs:
	 *   pcep_tlv_create_stateful_pce_capability()
	 *   pcep_tlv_create_lsp_db_version()
	 *   pcep_tlv_create_sr_pce_capability()
	 *   pcep_tlv_create_path_setup_type_capability() */
	reset_mock_socket_comm_info();
	mock_info->send_message_save_message = true;
	config.pcep_msg_versioning->draft_ietf_pce_segment_routing_07 = true;

	session = create_pcep_session(&config, &pce_ip);
	CU_ASSERT_PTR_NOT_NULL(session);
	/* Get and verify the Open Message */
	encoded_msg = dll_delete_first_node(mock_info->sent_message_list);
	CU_ASSERT_PTR_NOT_NULL(encoded_msg);
	assert(encoded_msg != NULL);
	open_msg = pcep_decode_message(encoded_msg);
	CU_ASSERT_PTR_NOT_NULL(open_msg);
	assert(open_msg != NULL);
	/* Get and verify the Open Message objects */
	CU_ASSERT_PTR_NOT_NULL(open_msg->obj_list);
	assert(open_msg->obj_list != NULL);
	CU_ASSERT_TRUE(open_msg->obj_list->num_entries > 0);
	/* Get and verify the Open object */
	open_obj = pcep_obj_get(open_msg->obj_list, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_PTR_NOT_NULL(open_obj);
	assert(open_obj != NULL);
	/* Get and verify the Open object TLVs */
	CU_ASSERT_PTR_NOT_NULL(open_obj->tlv_list);
	assert(open_obj->tlv_list != NULL);
	CU_ASSERT_EQUAL(open_obj->tlv_list->num_entries, 4);
	tlv_node = open_obj->tlv_list->head;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	tlv_node = tlv_node->next_node;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
	tlv_node = tlv_node->next_node;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
	tlv_node = tlv_node->next_node;
	CU_ASSERT_EQUAL(((struct pcep_object_tlv_header *)tlv_node->data)->type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);

	destroy_pcep_versioning(config.pcep_msg_versioning);
	destroy_pcep_session(session);
	pcep_msg_free_message(open_msg);
	pceplib_free(PCEPLIB_MESSAGES, encoded_msg);

	stop_session_logic();
}


void test_destroy_pcep_session_null_session()
{
	/* Just testing that it does not core dump */
	destroy_pcep_session(NULL);
}
