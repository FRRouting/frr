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
 */


/*
 * This is a High Level PCEP message API.
 */

#ifndef PCEP_MESSAGES_H
#define PCEP_MESSAGES_H

#include <stdint.h>
#include <netinet/in.h> /* struct in_addr */

#include "pcep_utils_double_linked_list.h"
#include "pcep_msg_objects.h"

#ifdef __cplusplus
extern "C" {
#endif

enum pcep_message_types {
	PCEP_TYPE_OPEN = 1,
	PCEP_TYPE_KEEPALIVE = 2,
	PCEP_TYPE_PCREQ = 3,
	PCEP_TYPE_PCREP = 4,
	PCEP_TYPE_PCNOTF = 5,
	PCEP_TYPE_ERROR = 6,
	PCEP_TYPE_CLOSE = 7,
	PCEP_TYPE_REPORT = 10,
	PCEP_TYPE_UPDATE = 11,
	PCEP_TYPE_INITIATE = 12,
	PCEP_TYPE_START_TLS = 13,
	PCEP_TYPE_MAX,
};

#define PCEP_MESSAGE_HEADER_VERSION 1

struct pcep_message_header {
	uint8_t pcep_version; /* Current version is 1. */
	enum pcep_message_types
		type; /* Defines message type:
			 OPEN/KEEPALIVE/PCREQ/PCREP/PCNOTF/ERROR/CLOSE */
};

/* The obj_list is a double_linked_list of struct pcep_object_header pointers.
 */
struct pcep_message {
	struct pcep_message_header *msg_header;
	double_linked_list *obj_list;
	uint8_t *encoded_message;
	uint16_t encoded_message_length;
};


/*
 * Regarding memory usage:
 * When creating messages, any objects and tlvs passed into these APIs will be
 * free'd when the pcep_message is free'd. That includes the
 * double_linked_list's. So, just create the objects and TLVs, put them in their
 * double_linked_list's, and everything will be managed internally. The message
 * will be deleted by pcep_msg_free_message() or pcep_msg_free_message_list()
 * which, in turn will call one of: pcep_obj_free_object() and
 * pcep_obj_free_tlv(). For received messages, call pcep_msg_free_message() to
 * free them.
 */

struct pcep_message *pcep_msg_create_open(uint8_t keepalive, uint8_t deadtimer,
					  uint8_t sid);
struct pcep_message *
pcep_msg_create_open_with_tlvs(uint8_t keepalive, uint8_t deadtimer,
			       uint8_t sid, double_linked_list *tlv_list);
struct pcep_message *
pcep_msg_create_request(struct pcep_object_rp *rp,
			struct pcep_object_endpoints_ipv4 *endpoints,
			double_linked_list *object_list);
struct pcep_message *
pcep_msg_create_request_ipv6(struct pcep_object_rp *rp,
			     struct pcep_object_endpoints_ipv6 *endpoints,
			     double_linked_list *object_list);
struct pcep_message *pcep_msg_create_reply(struct pcep_object_rp *rp,
					   double_linked_list *object_list);
struct pcep_message *pcep_msg_create_close(uint8_t reason);
struct pcep_message *pcep_msg_create_error(uint8_t error_type,
					   uint8_t error_value);
struct pcep_message *pcep_msg_create_error_with_objects(
	uint8_t error_type, uint8_t error_value,
	double_linked_list *object_list); /* include the offending objects */
struct pcep_message *pcep_msg_create_keepalive(void);
struct pcep_message *pcep_msg_create_notify(struct pcep_object_notify *notify,
					    double_linked_list *object_list);

/* Message defined in RFC 8231 section 6.1. Expecting double_linked_list of
 * struct pcep_object_header* objects of type SRP, LSP, or path (ERO, Bandwidth,
 * metrics, and RRO objects). */
struct pcep_message *
pcep_msg_create_report(double_linked_list *state_report_object_list);
/* Message defined in RFC 8231. Expecting double_linked_list of at least 3
 * struct pcep_object_header* objects of type SRP, LSP, and path (ERO and
 * intended-attribute-list). The ERO must be present, but may be empty if
 * the PCE cannot find a valid path for a delegated LSP. */
struct pcep_message *
pcep_msg_create_update(double_linked_list *update_request_object_list);
/* Message defined in RFC 8281. Expecting double_linked_list of at least 2
 * struct pcep_object_header* objects of type SRP and LSP for LSP deletion, and
 * may also contain Endpoints, ERO and an attribute list for LSP creation. */
struct pcep_message *
pcep_msg_create_initiate(double_linked_list *lsp_object_list);

#ifdef __cplusplus
}
#endif

#endif
