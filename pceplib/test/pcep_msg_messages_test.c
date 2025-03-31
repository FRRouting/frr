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

#include <stdlib.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_messages.h"
#include "pcep_msg_objects.h"
#include "pcep_msg_tools.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_memory.h"
#include "pcep_msg_messages_test.h"

/*
 * Notice:
 * All of these message Unit Tests encode the created messages by explicitly
 * calling pcep_encode_message() thus testing the message creation and the
 * message encoding.
 */

static struct pcep_versioning *versioning = NULL;

int pcep_messages_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_messages_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

void pcep_messages_test_setup(void)
{
	versioning = create_default_pcep_versioning();
}

void pcep_messages_test_teardown(void)
{
	destroy_pcep_versioning(versioning);
}

void test_pcep_msg_create_open(void)
{
	uint8_t keepalive = 30;
	uint8_t deadtimer = 60;
	uint8_t sid = 255;

	struct pcep_message *message =
		pcep_msg_create_open(keepalive, deadtimer, sid);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ pcep_object_get_length(PCEP_OBJ_CLASS_OPEN,
							 PCEP_OBJ_TYPE_OPEN));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	/* Just check the class and type, the rest of the hdr fields
	 * are verified in pcep-objects-test.c */
	struct pcep_object_open *open_obj =
		(struct pcep_object_open *)message->obj_list->head->data;
	CU_ASSERT_EQUAL(open_obj->header.object_class, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_EQUAL(open_obj->header.object_type, PCEP_OBJ_TYPE_OPEN);

	CU_ASSERT_EQUAL(open_obj->open_deadtimer, deadtimer);
	CU_ASSERT_EQUAL(open_obj->open_keepalive, keepalive);
	CU_ASSERT_EQUAL(open_obj->open_sid, sid);
	CU_ASSERT_EQUAL(open_obj->open_version, PCEP_OBJECT_OPEN_VERSION);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_request(void)
{
	/* First test with NULL objects */
	struct pcep_message *message =
		pcep_msg_create_request(NULL, NULL, NULL);
	CU_ASSERT_PTR_NULL(message);

	/* Test IPv4 */
	struct pcep_object_rp *rp_obj =
		pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	struct in_addr src_addr = {}, dst_addr = {};
	struct pcep_object_endpoints_ipv4 *ipv4_obj =
		pcep_obj_create_endpoint_ipv4(&src_addr, &dst_addr);
	message = pcep_msg_create_request(rp_obj, ipv4_obj, NULL);

	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
	CU_ASSERT_EQUAL(
		message->encoded_message_length,
		MESSAGE_HEADER_LENGTH
			+ pcep_object_get_length_by_hdr(&rp_obj->header)
			+ pcep_object_get_length_by_hdr(&ipv4_obj->header));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREQ);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);

	/* Test IPv6 */
	rp_obj = pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	struct in6_addr src_addr_ipv6 = {}, dst_addr_ipv6 = {};
	struct pcep_object_endpoints_ipv6 *ipv6_obj =
		pcep_obj_create_endpoint_ipv6(&src_addr_ipv6, &dst_addr_ipv6);
	message = pcep_msg_create_request_ipv6(rp_obj, ipv6_obj, NULL);

	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
	CU_ASSERT_EQUAL(
		message->encoded_message_length,
		MESSAGE_HEADER_LENGTH
			+ pcep_object_get_length_by_hdr(&rp_obj->header)
			+ pcep_object_get_length_by_hdr(&ipv6_obj->header));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREQ);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);

	/* The objects get deleted with the message, so they need to be created
	 * again */
	rp_obj = pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	ipv4_obj = pcep_obj_create_endpoint_ipv4(&src_addr, &dst_addr);
	struct pcep_object_bandwidth *bandwidth_obj =
		pcep_obj_create_bandwidth(4.2);
	double_linked_list *obj_list = dll_initialize();
	dll_append(obj_list, bandwidth_obj);
	message = pcep_msg_create_request(rp_obj, ipv4_obj, obj_list);

	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
	CU_ASSERT_EQUAL(
		message->encoded_message_length,
		MESSAGE_HEADER_LENGTH
			+ pcep_object_get_length_by_hdr(&rp_obj->header)
			+ pcep_object_get_length_by_hdr(&ipv4_obj->header)
			+ pcep_object_get_length_by_hdr(
				&bandwidth_obj->header));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREQ);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_request_svec(void)
{
}

void test_pcep_msg_create_reply_nopath(void)
{
	struct pcep_object_rp *rp_obj =
		pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	struct pcep_object_nopath *nopath_obj = pcep_obj_create_nopath(
		false, false, PCEP_NOPATH_TLV_ERR_NO_TLV);
	double_linked_list *obj_list = dll_initialize();
	dll_append(obj_list, nopath_obj);

	struct pcep_message *message = pcep_msg_create_reply(rp_obj, obj_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			(MESSAGE_HEADER_LENGTH
			 + pcep_object_get_length_by_hdr(&rp_obj->header)
			 + pcep_object_get_length_by_hdr(&nopath_obj->header)));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREP);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_reply(void)
{
	/* First test with NULL ero and rp objects */
	struct pcep_message *message = pcep_msg_create_reply(NULL, NULL);

	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 0);
	CU_ASSERT_EQUAL(message->encoded_message_length, MESSAGE_HEADER_LENGTH);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREP);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);

	double_linked_list *ero_subobj_list = dll_initialize();
	struct pcep_object_ro_subobj *ero_subobj =
		(struct pcep_object_ro_subobj *)
			pcep_obj_create_ro_subobj_32label(true, 1, 10);
	dll_append(ero_subobj_list, ero_subobj);
	struct pcep_object_ro *ero = pcep_obj_create_ero(ero_subobj_list);

	double_linked_list *object_list = dll_initialize();
	dll_append(object_list, ero);
	struct pcep_object_rp *rp_obj =
		pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	message = pcep_msg_create_reply(rp_obj, object_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ pcep_object_get_length_by_hdr(&rp_obj->header)
				+ OBJECT_HEADER_LENGTH
				+ OBJECT_RO_SUBOBJ_HEADER_LENGTH
				+ 6 /* size of the 32label */);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCREP);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_close(void)
{
	uint8_t reason = PCEP_CLOSE_REASON_UNREC_MSG;

	struct pcep_message *message = pcep_msg_create_close(reason);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ pcep_object_get_length(PCEP_OBJ_CLASS_CLOSE,
							 PCEP_OBJ_TYPE_CLOSE));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_CLOSE);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	/* Just check the class and type, the rest of the hdr fields
	 * are verified in pcep-objects-test.c */
	struct pcep_object_close *close_obj =
		(struct pcep_object_close *)message->obj_list->head->data;
	assert(close_obj != NULL);
	CU_ASSERT_EQUAL(close_obj->header.object_class, PCEP_OBJ_CLASS_CLOSE);
	CU_ASSERT_EQUAL(close_obj->header.object_type, PCEP_OBJ_TYPE_CLOSE);
	CU_ASSERT_EQUAL(close_obj->reason, reason);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_error(void)
{
	uint8_t error_type = PCEP_ERRT_RECEPTION_OF_INV_OBJECT;
	uint8_t error_value = PCEP_ERRV_KEEPALIVEWAIT_TIMED_OUT;

	struct pcep_message *message =
		pcep_msg_create_error(error_type, error_value);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ pcep_object_get_length(PCEP_OBJ_CLASS_ERROR,
							 PCEP_OBJ_TYPE_ERROR));
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_ERROR);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	/* Just check the class and type, the rest of the hdr fields
	 * are verified in pcep-objects-test.c */
	struct pcep_object_error *error_obj =
		(struct pcep_object_error *)message->obj_list->head->data;
	CU_ASSERT_EQUAL(error_obj->header.object_class, PCEP_OBJ_CLASS_ERROR);
	CU_ASSERT_EQUAL(error_obj->header.object_type, PCEP_OBJ_TYPE_ERROR);

	CU_ASSERT_EQUAL(error_obj->error_type, error_type);
	CU_ASSERT_EQUAL(error_obj->error_value, error_value);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_keepalive(void)
{
	struct pcep_message *message = pcep_msg_create_keepalive();
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 0);
	CU_ASSERT_EQUAL(message->encoded_message_length, MESSAGE_HEADER_LENGTH);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_KEEPALIVE);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);
	pcep_msg_free_message(message);
}

void test_pcep_msg_create_report(void)
{
	double_linked_list *obj_list = dll_initialize();

	/* Should return NULL if obj_list is empty */
	struct pcep_message *message = pcep_msg_create_report(NULL);
	CU_ASSERT_PTR_NULL(message);

	struct pcep_object_lsp *lsp =
		pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true,
				    true, true, true, NULL);
	dll_append(obj_list, lsp);
	message = pcep_msg_create_report(obj_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ lsp->header.encoded_object_length);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_REPORT);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	pcep_msg_free_message(message);
}

void test_pcep_msg_create_update(void)
{
	double_linked_list *obj_list = dll_initialize();
	double_linked_list *ero_subobj_list = dll_initialize();

	struct pcep_message *message = pcep_msg_create_update(NULL);
	CU_ASSERT_PTR_NULL(message);

	/* Should return NULL if obj_list is empty */
	message = pcep_msg_create_update(obj_list);
	CU_ASSERT_PTR_NULL(message);
	if (message != NULL)
		pcep_msg_free_message(message);

	struct pcep_object_srp *srp = pcep_obj_create_srp(false, 100, NULL);
	struct pcep_object_lsp *lsp =
		pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true,
				    true, true, true, NULL);
	dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
	struct pcep_object_ro *ero = pcep_obj_create_ero(ero_subobj_list);

	/* Should return NULL if obj_list does not have 3 entries */
	dll_append(obj_list, srp);
	dll_append(obj_list, lsp);
	message = pcep_msg_create_update(obj_list);
	CU_ASSERT_PTR_NULL(message);

	dll_append(obj_list, ero);
	if (message != NULL)
		pcep_msg_free_message(message);

	message = pcep_msg_create_update(obj_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ srp->header.encoded_object_length
				+ lsp->header.encoded_object_length
				+ ero->header.encoded_object_length);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_UPDATE);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	pcep_msg_free_message(message);
}

void test_pcep_msg_create_initiate(void)
{
	double_linked_list *obj_list = dll_initialize();
	double_linked_list *ero_subobj_list = dll_initialize();

	/* Should return NULL if obj_list is empty */
	struct pcep_message *message = pcep_msg_create_initiate(NULL);
	CU_ASSERT_PTR_NULL(message);
	if (message != NULL)
		pcep_msg_free_message(message);

	struct pcep_object_srp *srp = pcep_obj_create_srp(false, 100, NULL);
	struct pcep_object_lsp *lsp =
		pcep_obj_create_lsp(100, PCEP_LSP_OPERATIONAL_UP, true, true,
				    true, true, true, NULL);
	dll_append(ero_subobj_list, pcep_obj_create_ro_subobj_asn(0x0102));
	struct pcep_object_ro *ero = pcep_obj_create_ero(ero_subobj_list);

	/* Should return NULL if obj_list does not have 2 entries */
	dll_append(obj_list, srp);
	message = pcep_msg_create_initiate(obj_list);
	CU_ASSERT_PTR_NULL(message);
	if (message != NULL)
		pcep_msg_free_message(message);

	dll_append(obj_list, lsp);
	dll_append(obj_list, ero);
	message = pcep_msg_create_initiate(obj_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->msg_header);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 3);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ srp->header.encoded_object_length
				+ lsp->header.encoded_object_length
				+ ero->header.encoded_object_length);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_INITIATE);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	pcep_msg_free_message(message);
}

void test_pcep_msg_create_notify(void)
{
	struct pcep_object_notify *notify_obj = pcep_obj_create_notify(
		PCEP_NOTIFY_TYPE_PENDING_REQUEST_CANCELLED,
		PCEP_NOTIFY_VALUE_PCC_CANCELLED_REQUEST);

	/* Should return NULL if the notify obj is empty */
	struct pcep_message *message = pcep_msg_create_notify(NULL, NULL);
	CU_ASSERT_PTR_NULL(message);

	message = pcep_msg_create_notify(notify_obj, NULL);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ notify_obj->header.encoded_object_length);
	assert(message->msg_header != NULL);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCNOTF);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	pcep_msg_free_message(message);

	struct pcep_object_rp *rp_obj =
		pcep_obj_create_rp(0, false, false, false, false, 10, NULL);
	double_linked_list *obj_list = dll_initialize();
	dll_append(obj_list, rp_obj);
	notify_obj = pcep_obj_create_notify(
		PCEP_NOTIFY_TYPE_PENDING_REQUEST_CANCELLED,
		PCEP_NOTIFY_VALUE_PCC_CANCELLED_REQUEST);

	message = pcep_msg_create_notify(notify_obj, obj_list);
	CU_ASSERT_PTR_NOT_NULL(message);
	pcep_encode_message(message, versioning);
	assert(message != NULL);
	CU_ASSERT_PTR_NOT_NULL(message->obj_list);
	assert(message->obj_list != NULL);
	CU_ASSERT_EQUAL(message->obj_list->num_entries, 2);
	CU_ASSERT_EQUAL(message->encoded_message_length,
			MESSAGE_HEADER_LENGTH
				+ notify_obj->header.encoded_object_length
				+ rp_obj->header.encoded_object_length);
	CU_ASSERT_EQUAL(message->msg_header->type, PCEP_TYPE_PCNOTF);
	CU_ASSERT_EQUAL(message->msg_header->pcep_version,
			PCEP_MESSAGE_HEADER_VERSION);

	pcep_msg_free_message(message);
}
