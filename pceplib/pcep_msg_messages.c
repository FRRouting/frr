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
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * This is the implementation of a High Level PCEP message API.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <unistd.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_messages.h"
#include "pcep_msg_objects.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

static struct pcep_message *
pcep_msg_create_common_with_obj_list(enum pcep_message_types msg_type,
				     double_linked_list *obj_list)
{
	struct pcep_message *message =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct pcep_message));
	memset(message, 0, sizeof(struct pcep_message));
	message->msg_header = pceplib_malloc(
		PCEPLIB_MESSAGES, sizeof(struct pcep_message_header));
	memset(message->msg_header, 0, sizeof(struct pcep_message_header));
	message->msg_header->type = msg_type;
	message->msg_header->pcep_version = PCEP_MESSAGE_HEADER_VERSION;
	message->obj_list = ((obj_list == NULL) ? dll_initialize() : obj_list);

	return message;
}

static struct pcep_message *
pcep_msg_create_common(enum pcep_message_types msg_type)
{
	return pcep_msg_create_common_with_obj_list(msg_type, NULL);
}

struct pcep_message *pcep_msg_create_open(uint8_t keepalive, uint8_t deadtimer,
					  uint8_t sid)
{
	struct pcep_message *message = pcep_msg_create_common(PCEP_TYPE_OPEN);
	dll_append(message->obj_list,
		   pcep_obj_create_open(keepalive, deadtimer, sid, NULL));

	return message;
}

struct pcep_message *
pcep_msg_create_open_with_tlvs(uint8_t keepalive, uint8_t deadtimer,
			       uint8_t sid, double_linked_list *tlv_list)
{
	struct pcep_message *message = pcep_msg_create_common(PCEP_TYPE_OPEN);
	dll_append(message->obj_list,
		   pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list));

	return message;
}


struct pcep_message *
pcep_msg_create_request(struct pcep_object_rp *rp,
			struct pcep_object_endpoints_ipv4 *endpoints,
			double_linked_list *object_list)
{
	if ((rp == NULL) || (endpoints == NULL)) {
		return NULL;
	}

	struct pcep_message *message = pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_PCREQ, object_list);
	dll_prepend(message->obj_list, endpoints);
	dll_prepend(message->obj_list, rp);

	return message;
}

struct pcep_message *
pcep_msg_create_request_ipv6(struct pcep_object_rp *rp,
			     struct pcep_object_endpoints_ipv6 *endpoints,
			     double_linked_list *object_list)
{
	if ((rp == NULL) || (endpoints == NULL)) {
		return NULL;
	}

	struct pcep_message *message = pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_PCREQ, object_list);
	dll_prepend(message->obj_list, endpoints);
	dll_prepend(message->obj_list, rp);

	return message;
}

struct pcep_message *pcep_msg_create_reply(struct pcep_object_rp *rp,
					   double_linked_list *object_list)
{
	struct pcep_message *message = pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_PCREP, object_list);

	if (rp != NULL) {
		dll_prepend(message->obj_list, rp);
	}

	return message;
}

struct pcep_message *pcep_msg_create_close(uint8_t reason)
{
	struct pcep_message *message = pcep_msg_create_common(PCEP_TYPE_CLOSE);
	dll_append(message->obj_list, pcep_obj_create_close(reason));

	return message;
}

struct pcep_message *pcep_msg_create_error(uint8_t error_type,
					   uint8_t error_value)
{
	struct pcep_message *message = pcep_msg_create_common(PCEP_TYPE_ERROR);
	dll_append(message->obj_list,
		   pcep_obj_create_error(error_type, error_value));

	return message;
}

struct pcep_message *
pcep_msg_create_error_with_objects(uint8_t error_type, uint8_t error_value,
				   double_linked_list *object_list)
{
	struct pcep_message *message = pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_ERROR, object_list);
	dll_prepend(message->obj_list,
		    pcep_obj_create_error(error_type, error_value));

	return message;
}

struct pcep_message *pcep_msg_create_keepalive(void)
{
	return (pcep_msg_create_common(PCEP_TYPE_KEEPALIVE));
}

struct pcep_message *
pcep_msg_create_report(double_linked_list *state_report_object_list)
{
	return (state_report_object_list == NULL
			? NULL
			: pcep_msg_create_common_with_obj_list(
				PCEP_TYPE_REPORT, state_report_object_list));
}

struct pcep_message *
pcep_msg_create_update(double_linked_list *update_request_object_list)
{
	if (update_request_object_list == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_update NULL update_request_object_list",
			__func__);
		return NULL;
	}

	/* There must be at least 3 objects:
	 * These 3 are mandatory: SRP, LSP, and ERO. The ERO may be empty */
	if (update_request_object_list->num_entries < 3) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_update there must be at least 3 update objects",
			__func__);
		return NULL;
	}

	double_linked_list_node *node = update_request_object_list->head;
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)node->data;

	/* Check for the mandatory first SRP object */
	if (obj_hdr->object_class != PCEP_OBJ_CLASS_SRP) {
		/* If the SRP object is missing, the receiving PCC MUST send a
		 * PCErr message with Error-type=6 (Mandatory Object missing)
		 * and Error-value=10 (SRP object missing). */
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_update missing mandatory first SRP object",
			__func__);
		return NULL;
	}

	/* Check for the mandatory 2nd LSP object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	if (obj_hdr->object_class != PCEP_OBJ_CLASS_LSP) {
		/* If the LSP object is missing, the receiving PCC MUST send a
		 * PCErr message with Error-type=6 (Mandatory Object missing)
		 * and Error-value=8 (LSP object missing). */
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_update missing mandatory second LSP object",
			__func__);
		return NULL;
	}

	/* Check for the mandatory 3rd ERO object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	if (obj_hdr->object_class != PCEP_OBJ_CLASS_ERO) {
		/* If the ERO object is missing, the receiving PCC MUST send a
		 * PCErr message with Error-type=6 (Mandatory Object missing)
		 * and Error-value=9 (ERO object missing). */
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_update missing mandatory third ERO object",
			__func__);
		return NULL;
	}

	return (pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_UPDATE, update_request_object_list));
}

struct pcep_message *
pcep_msg_create_initiate(double_linked_list *lsp_object_list)
{
	if (lsp_object_list == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_initiate NULL update_request_object_list",
			__func__);
		return NULL;
	}

	/* There must be at least 2 objects: SRP and LSP. */
	if (lsp_object_list->num_entries < 2) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_initiate there must be at least 2 objects",
			__func__);
		return NULL;
	}

	double_linked_list_node *node = lsp_object_list->head;
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)node->data;

	/* Check for the mandatory first SRP object */
	if (obj_hdr->object_class != PCEP_OBJ_CLASS_SRP) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_initiate missing mandatory first SRP object",
			__func__);
		return NULL;
	}

	/* Check for the mandatory 2nd LSP object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	if (obj_hdr->object_class != PCEP_OBJ_CLASS_LSP) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_create_initiate missing mandatory second LSP object",
			__func__);
		return NULL;
	}

	return (pcep_msg_create_common_with_obj_list(PCEP_TYPE_INITIATE,
						     lsp_object_list));
}

struct pcep_message *pcep_msg_create_notify(struct pcep_object_notify *notify,
					    double_linked_list *object_list)
{
	if (notify == NULL) {
		pcep_log(LOG_INFO,
			 "%s: pcep_msg_create_notify NULL notify object",
			 __func__);
		return NULL;
	}

	struct pcep_message *message = pcep_msg_create_common_with_obj_list(
		PCEP_TYPE_PCNOTF, object_list);
	dll_prepend(message->obj_list, notify);

	return message;
}
