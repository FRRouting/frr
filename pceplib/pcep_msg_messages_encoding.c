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
 * Encoding and decoding for PCEP messages.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_messages.h"
#include "pcep_msg_objects.h"
#include "pcep_msg_tools.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

#define ANY_OBJECT 0
#define NO_OBJECT -1
#define NUM_CHECKED_OBJECTS 4
/* It wont compile with this definition:
   static const int
   MANDATORY_MESSAGE_OBJECT_CLASSES[PCEP_TYPE_INITIATE+1][NUM_CHECKED_OBJECTS]
 */
static const enum pcep_object_classes MANDATORY_MESSAGE_OBJECT_CLASSES[13][4] =
	{
		{NO_OBJECT, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* unsupported message ID = 0 */
		{PCEP_OBJ_CLASS_OPEN, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* PCEP_TYPE_OPEN = 1 */
		{NO_OBJECT, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* PCEP_TYPE_KEEPALIVE = 2 */
		{PCEP_OBJ_CLASS_RP, PCEP_OBJ_CLASS_ENDPOINTS, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_PCREQ = 3 */
		{PCEP_OBJ_CLASS_RP, ANY_OBJECT, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_PCREP = 4 */
		{PCEP_OBJ_CLASS_NOTF, ANY_OBJECT, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_PCNOTF = 5 */
		{PCEP_OBJ_CLASS_ERROR, ANY_OBJECT, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_ERROR = 6 */
		{PCEP_OBJ_CLASS_CLOSE, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* PCEP_TYPE_CLOSE = 7 */
		{NO_OBJECT, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* unsupported message ID = 8 */
		{NO_OBJECT, NO_OBJECT, NO_OBJECT,
		 NO_OBJECT}, /* unsupported message ID = 9 */
		{PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_REPORT = 10 */
		{PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_UPDATE = 11 */
		{PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT,
		 ANY_OBJECT}, /* PCEP_TYPE_INITIATE = 12 */
};

/* PCEP Message Common Header, According to RFC 5440
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Ver |  Flags  |  Message-Type |       Message-Length          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Ver (Version - 3 bits):  PCEP version number. Current version is version 1.
 *
 * Flags (5 bits):  No flags are currently defined. Unassigned bits are
 *    considered as reserved.  They MUST be set to zero on transmission
 *    and MUST be ignored on receipt.
 */
void pcep_encode_message(struct pcep_message *message,
			 struct pcep_versioning *versioning)
{
	if (message == NULL) {
		return;
	}

	if (message->msg_header == NULL) {
		return;
	}

	/* Internal buffer used for the entire message. Later, once the entire
	 * length is known, memory will be allocated and this buffer will be
	 * copied. */
	uint8_t message_buffer[PCEP_MESSAGE_LENGTH] = {0};

	/* Write the message header. The message header length will be
	 * written when the entire length is known. */
	uint32_t message_length = MESSAGE_HEADER_LENGTH;
	uint16_t net_order_length = 0;
	message_buffer[0] = (message->msg_header->pcep_version << 5) & 0xf0;
	message_buffer[1] = message->msg_header->type;

	if (message->obj_list == NULL) {
		net_order_length = htons(message_length);
		memcpy(message_buffer + 2, &net_order_length,
		       sizeof(net_order_length));
		message->encoded_message =
			pceplib_malloc(PCEPLIB_MESSAGES, message_length);
		memcpy(message->encoded_message, message_buffer,
		       message_length);
		message->encoded_message_length = message_length;

		return;
	}

	/* Encode each of the objects */
	double_linked_list_node *node = message->obj_list->head;
	for (; node != NULL; node = node->next_node) {
		message_length +=
			pcep_encode_object(node->data, versioning,
					   message_buffer + message_length);
		if (message_length >= PCEP_MESSAGE_LENGTH) {
			message->encoded_message = NULL;
			message->encoded_message_length = 0;
			return;
		}
	}

	net_order_length = htons(message_length);
	memcpy(message_buffer + 2, &net_order_length, sizeof(net_order_length));
	message->encoded_message =
		pceplib_malloc(PCEPLIB_MESSAGES, message_length);
	memcpy(message->encoded_message, message_buffer, message_length);
	message->encoded_message_length = message_length;
}

/*
 * Decoding functions
 */

/* Expecting Host byte ordered header */
static bool validate_msg_header(uint8_t msg_version, uint8_t msg_flags,
				uint8_t msg_type, uint16_t msg_length)
{
	/* Invalid message if the length is less than the header
	 * size or if its not a multiple of 4 */
	if (msg_length < MESSAGE_HEADER_LENGTH || (msg_length % 4) != 0) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PCEP message header length [%d]",
			 __func__, msg_length);
		return false;
	}

	if (msg_version != PCEP_MESSAGE_HEADER_VERSION) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PCEP message header version [0x%x] expected version [0x%x]",
			__func__, msg_version, PCEP_MESSAGE_HEADER_VERSION);
		return false;
	}

	if (msg_flags != 0) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PCEP message header flags [0x%x]",
			 __func__, msg_flags);
		return false;
	}

	switch (msg_type) {
	/* Supported message types */
	case PCEP_TYPE_OPEN:
	case PCEP_TYPE_KEEPALIVE:
	case PCEP_TYPE_PCREQ:
	case PCEP_TYPE_PCREP:
	case PCEP_TYPE_PCNOTF:
	case PCEP_TYPE_ERROR:
	case PCEP_TYPE_CLOSE:
	case PCEP_TYPE_REPORT:
	case PCEP_TYPE_UPDATE:
	case PCEP_TYPE_INITIATE:
		break;
	default:
		pcep_log(LOG_INFO, "%s: Invalid PCEP message header type [%d]",
			 __func__, msg_type);
		return false;
		break;
	}

	return true;
}

/* Internal util function */
static uint16_t pcep_decode_msg_header(const uint8_t *msg_buf,
				       uint8_t *msg_version, uint8_t *msg_flags,
				       uint8_t *msg_type)
{
	// Check RFC 5440 for version and flags position.
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//| Ver | Flags   | Message-Type  |  Message-Length               |
	//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*msg_version = (msg_buf[0] >> 5) & 0x07;
	*msg_flags = (msg_buf[0] & 0x1f);
	*msg_type = msg_buf[1];
	uint16_t host_order_length;
	memcpy(&host_order_length, msg_buf + 2, sizeof(host_order_length));
	return ntohs(host_order_length);
}

/* Decode the message header and return the message length */
int32_t pcep_decode_validate_msg_header(const uint8_t *msg_buf)
{
	uint8_t msg_version;
	uint8_t msg_flags;
	uint8_t msg_type;
	uint32_t msg_length;

	msg_length = pcep_decode_msg_header(msg_buf, &msg_version, &msg_flags,
					    &msg_type);

	return ((validate_msg_header(msg_version, msg_flags, msg_type,
				     msg_length)
		 == false)
			? -1
			: (int32_t)msg_length);
}

bool validate_message_objects(struct pcep_message *msg)
{
	if (msg->msg_header->type >= PCEP_TYPE_START_TLS) {
		pcep_log(
			LOG_INFO,
			"%s: Rejecting received message: Unknown message type [%d]",
			__func__, msg->msg_header->type);
		return false;
	}

	const enum pcep_object_classes *object_classes =
		MANDATORY_MESSAGE_OBJECT_CLASSES[msg->msg_header->type];
	double_linked_list_node *node;
	int index;
	for (node = (msg->obj_list == NULL ? NULL : msg->obj_list->head),
	    index = 0;
	     index < NUM_CHECKED_OBJECTS;
	     index++, (node = (node == NULL ? NULL : node->next_node))) {
		struct pcep_object_header *obj =
			((node == NULL)
				 ? NULL
				 : (struct pcep_object_header *)node->data);

		if ((int)object_classes[index] == NO_OBJECT) {
			if (node != NULL) {
				pcep_log(
					LOG_INFO,
					"%s: Rejecting received message: Unexpected object [%d] present",
					__func__, obj->object_class);
				return false;
			}
		} else if (object_classes[index] != ANY_OBJECT) {
			if (node == NULL) {
				pcep_log(
					LOG_INFO,
					"%s: Rejecting received message: Expecting object in position [%d], but none received",
					__func__, index);
				return false;
			} else if (object_classes[index] != obj->object_class) {
				pcep_log(
					LOG_INFO,
					"%s: Rejecting received message: Unexpected Object Class received [%d]",
					__func__, object_classes[index]);
				return false;
			}
		}
	}

	return true;
}

struct pcep_message *pcep_decode_message(const uint8_t *msg_buf)
{
	uint8_t msg_version;
	uint8_t msg_flags;
	uint8_t msg_type;
	uint16_t msg_length;

	msg_length = pcep_decode_msg_header(msg_buf, &msg_version, &msg_flags,
					    &msg_type);
	if (msg_length == 0) {
		pcep_log(LOG_INFO, "%s: Discarding empty message", __func__);
		return NULL;
	}
	if (msg_length >= PCEP_MESSAGE_LENGTH) {
		pcep_log(LOG_INFO, "%s: Discarding message too big", __func__);
		return NULL;
	}

	struct pcep_message *msg =
		pceplib_calloc(PCEPLIB_MESSAGES, sizeof(struct pcep_message));

	msg->msg_header = pceplib_malloc(PCEPLIB_MESSAGES,
					 sizeof(struct pcep_message_header));
	msg->msg_header->pcep_version = msg_version;
	msg->msg_header->type = msg_type;

	msg->obj_list = dll_initialize();
	msg->encoded_message = pceplib_malloc(PCEPLIB_MESSAGES, msg_length);
	memcpy(msg->encoded_message, msg_buf, msg_length);
	msg->encoded_message_length = msg_length;

	uint16_t bytes_read = MESSAGE_HEADER_LENGTH;
	while ((msg_length - bytes_read) >= OBJECT_HEADER_LENGTH) {
		struct pcep_object_header *obj_hdr =
			pcep_decode_object(msg_buf + bytes_read);

		if (obj_hdr == NULL) {
			pcep_log(LOG_INFO, "%s: Discarding invalid message",
				 __func__);
			pcep_msg_free_message(msg);

			return NULL;
		}

		dll_append(msg->obj_list, obj_hdr);
		bytes_read += obj_hdr->encoded_object_length;
	}

	if (validate_message_objects(msg) == false) {
		pcep_log(LOG_INFO, "%s: Discarding invalid message", __func__);
		pcep_msg_free_message(msg);

		return NULL;
	}

	return msg;
}

struct pcep_versioning *create_default_pcep_versioning(void)
{
	struct pcep_versioning *versioning =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(struct pcep_versioning));
	memset(versioning, 0, sizeof(struct pcep_versioning));

	return versioning;
}

void destroy_pcep_versioning(struct pcep_versioning *versioning)
{
	pceplib_free(PCEPLIB_INFRA, versioning);
}
