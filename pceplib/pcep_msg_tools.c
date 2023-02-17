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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pcep_msg_tools.h"
#include "pcep_msg_encoding.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

static const char *message_type_strs[] = {"NOT_IMPLEMENTED0",
					  "OPEN",
					  "KEEPALIVE",
					  "PCREQ",
					  "PCREP",
					  "PCNOTF",
					  "ERROR",
					  "CLOSE",
					  "NOT_IMPLEMENTED8",
					  "NOT_IMPLEMENTED9",
					  "REPORT",
					  "UPDATE",
					  "INITIATE",
					  "UNKOWN_MESSAGE_TYPE"};

static const char *object_class_strs[] = {"NOT_IMPLEMENTED0",
					  "OPEN",
					  "RP",
					  "NOPATH",
					  "ENDPOINTS",
					  "BANDWIDTH",
					  "METRIC",
					  "ERO",
					  "RRO",
					  "LSPA",
					  "IRO",
					  "SVEC",
					  "NOTF",
					  "ERROR",
					  "NOT_IMPLEMENTED14",
					  "CLOSE",
					  "NOT_IMPLEMENTED16",
					  "NOT_IMPLEMENTED17",
					  "NOT_IMPLEMENTED18",
					  "NOT_IMPLEMENTED19",
					  "NOT_IMPLEMENTED20",
					  "OBJECTIVE_FUNCTION",
					  "NOT_IMPLEMENTED22",
					  "NOT_IMPLEMENTED23",
					  "NOT_IMPLEMENTED24",
					  "NOT_IMPLEMENTED25",
					  "NOT_IMPLEMENTED26",
					  "NOT_IMPLEMENTED27",
					  "NOT_IMPLEMENTED28",
					  "NOT_IMPLEMENTED29",
					  "NOT_IMPLEMENTED30",
					  "NOT_IMPLEMENTED31",
					  "LSP",
					  "SRP",
					  "VENDOR_INFO",
					  "NOT_IMPLEMENTED35",
					  "INTER_LAYER",
					  "SWITCH_LAYER",
					  "REQ_ADAP_CAP",
					  "SERVER_IND",
					  "ASSOCIATION", /* 40 */
					  "UNKNOWN_MESSAGE_TYPE"};


double_linked_list *pcep_msg_read(int sock_fd)
{
	int ret;
	uint8_t buffer[PCEP_MESSAGE_LENGTH] = {0};
	uint16_t buffer_read = 0;


	ret = read(sock_fd, &buffer, PCEP_MESSAGE_LENGTH);

	if (ret < 0) {
		pcep_log(
			LOG_INFO,
			"%s: pcep_msg_read: Failed to read from socket fd [%d] errno [%d %s]",
			__func__, sock_fd, errno, strerror(errno));
		return NULL;
	} else if (ret == 0) {
		pcep_log(LOG_INFO, "%s: pcep_msg_read: Remote shutdown fd [%d]",
			 __func__, sock_fd);
		return NULL;
	}

	double_linked_list *msg_list = dll_initialize();
	struct pcep_message *msg = NULL;

	while (((uint16_t)ret - buffer_read) >= MESSAGE_HEADER_LENGTH) {

		/* Get the Message header, validate it, and return the msg
		 * length */
		int32_t msg_length =
			pcep_decode_validate_msg_header(buffer + buffer_read);
		if (msg_length < 0 || msg_length > PCEP_MESSAGE_LENGTH) {
			/* If the message header is invalid, we cant keep
			 * reading since the length may be invalid */
			pcep_log(
				LOG_INFO,
				"%s: pcep_msg_read: Received an invalid message fd [%d]",
				__func__, sock_fd);
			return msg_list;
		}

		/* Check if the msg_length is longer than what was read,
		 * in which case, we need to read the rest of the message. */
		if ((ret - buffer_read) < msg_length) {
			int read_len = (msg_length - (ret - buffer_read));
			int read_ret = 0;
			pcep_log(
				LOG_INFO,
				"%s: pcep_msg_read: Message not fully read! Trying to read %d bytes more, fd [%d]",
				__func__, read_len, sock_fd);

			if (PCEP_MESSAGE_LENGTH - ret - buffer_read >= read_len)
				read_ret =
					read(sock_fd, &buffer[ret], read_len);
			else {
				pcep_log(
					LOG_ERR,
					"%s: Trying to read size (%d) offset (%d) in a buff of size (%d)",
					__func__, read_len, ret,
					PCEP_MESSAGE_LENGTH);
				return msg_list;
			}

			if (read_ret != read_len) {
				pcep_log(
					LOG_INFO,
					"%s: pcep_msg_read: Did not manage to read enough data (%d != %d) fd [%d]",
					__func__, read_ret, read_len, sock_fd);
				return msg_list;
			}
		}

		msg = pcep_decode_message(buffer + buffer_read);
		buffer_read += msg_length;

		if (msg == NULL) {
			return msg_list;
		} else {
			dll_append(msg_list, msg);
		}
	}

	return msg_list;
}

struct pcep_message *pcep_msg_get(double_linked_list *msg_list, uint8_t type)
{
	if (msg_list == NULL) {
		return NULL;
	}

	double_linked_list_node *node;
	for (node = msg_list->head; node != NULL; node = node->next_node) {
		if (((struct pcep_message *)node->data)->msg_header->type
		    == type) {
			return (struct pcep_message *)node->data;
		}
	}

	return NULL;
}

struct pcep_message *pcep_msg_get_next(double_linked_list *list,
				       struct pcep_message *current,
				       uint8_t type)
{
	if (list == NULL || current == NULL) {
		return NULL;
	}

	if (list->head == NULL) {
		return NULL;
	}

	double_linked_list_node *node;
	for (node = list->head; node != NULL; node = node->next_node) {
		if (node->data == current) {
			continue;
		}

		if (((struct pcep_message *)node->data)->msg_header->type
		    == type) {
			return (struct pcep_message *)node->data;
		}
	}

	return NULL;
}

struct pcep_object_header *pcep_obj_get(double_linked_list *list,
					uint8_t object_class)
{
	if (list == NULL) {
		return NULL;
	}

	if (list->head == NULL) {
		return NULL;
	}

	double_linked_list_node *obj_item;
	for (obj_item = list->head; obj_item != NULL;
	     obj_item = obj_item->next_node) {
		if (((struct pcep_object_header *)obj_item->data)->object_class
		    == object_class) {
			return (struct pcep_object_header *)obj_item->data;
		}
	}

	return NULL;
}

struct pcep_object_header *pcep_obj_get_next(double_linked_list *list,
					     struct pcep_object_header *current,
					     uint8_t object_class)
{
	if (list == NULL || current == NULL) {
		return NULL;
	}

	if (list->head == NULL) {
		return NULL;
	}

	double_linked_list_node *node;
	for (node = list->head; node != NULL; node = node->next_node) {
		if (node->data == current) {
			continue;
		}

		if (((struct pcep_object_header *)node->data)->object_class
		    == object_class) {
			return (struct pcep_object_header *)node->data;
		}
	}

	return NULL;
}

void pcep_obj_free_tlv(struct pcep_object_tlv_header *tlv)
{
	/* Specific TLV freeing */
	switch (tlv->type) {
	case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
		if (((struct pcep_object_tlv_speaker_entity_identifier *)tlv)
			    ->speaker_entity_id_list
		    != NULL) {
			dll_destroy_with_data_memtype(
				((struct
				  pcep_object_tlv_speaker_entity_identifier *)
					 tlv)
					->speaker_entity_id_list,
				PCEPLIB_MESSAGES);
		}
		break;

	case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
		if (((struct pcep_object_tlv_path_setup_type_capability *)tlv)
			    ->pst_list
		    != NULL) {
			dll_destroy_with_data_memtype(
				((struct
				  pcep_object_tlv_path_setup_type_capability *)
					 tlv)
					->pst_list,
				PCEPLIB_MESSAGES);
		}

		if (((struct pcep_object_tlv_path_setup_type_capability *)tlv)
			    ->sub_tlv_list
		    != NULL) {
			dll_destroy_with_data_memtype(
				((struct
				  pcep_object_tlv_path_setup_type_capability *)
					 tlv)
					->sub_tlv_list,
				PCEPLIB_MESSAGES);
		}
		break;

	case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
	case PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST:
	case PCEP_OBJ_TLV_TYPE_VENDOR_INFO:
	case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
	case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
	case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
	case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
	case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
	case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
	case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
	case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
	case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID:
	case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE:
	case PCEP_OBJ_TLV_TYPE_UNKNOWN:
	case PCEP_OBJ_TYPE_CISCO_BSID:
	case PCEP_OBJ_TLV_TYPE_ARBITRARY:
		break;
	}

	pceplib_free(PCEPLIB_MESSAGES, tlv);
}

void pcep_obj_free_object(struct pcep_object_header *obj)
{
	/* Iterate the TLVs and free each one */
	if (obj->tlv_list != NULL) {
		struct pcep_object_tlv_header *tlv;
		while ((tlv = (struct pcep_object_tlv_header *)
				dll_delete_first_node(obj->tlv_list))
		       != NULL) {
			pcep_obj_free_tlv(tlv);
		}

		dll_destroy(obj->tlv_list);
	}

	/* Specific object freeing */
	switch (obj->object_class) {
	case PCEP_OBJ_CLASS_ERO:
	case PCEP_OBJ_CLASS_IRO:
	case PCEP_OBJ_CLASS_RRO: {
		if (((struct pcep_object_ro *)obj)->sub_objects != NULL) {
			double_linked_list_node *node =
				((struct pcep_object_ro *)obj)
					->sub_objects->head;
			for (; node != NULL; node = node->next_node) {
				struct pcep_object_ro_subobj *ro_subobj =
					(struct pcep_object_ro_subobj *)
						node->data;
				if (ro_subobj->ro_subobj_type
				    == RO_SUBOBJ_TYPE_SR) {
					if (((struct pcep_ro_subobj_sr *)
						     ro_subobj)
						    ->nai_list
					    != NULL) {
						dll_destroy_with_data_memtype(
							((struct
							  pcep_ro_subobj_sr *)
								 ro_subobj)
								->nai_list,
							PCEPLIB_MESSAGES);
					}
				}
			}
			dll_destroy_with_data_memtype(
				((struct pcep_object_ro *)obj)->sub_objects,
				PCEPLIB_MESSAGES);
		}
	} break;

	case PCEP_OBJ_CLASS_SVEC:
		if (((struct pcep_object_svec *)obj)->request_id_list != NULL) {
			dll_destroy_with_data_memtype(
				((struct pcep_object_svec *)obj)
					->request_id_list,
				PCEPLIB_MESSAGES);
		}
		break;

	case PCEP_OBJ_CLASS_SWITCH_LAYER:
		if (((struct pcep_object_switch_layer *)obj)->switch_layer_rows
		    != NULL) {
			dll_destroy_with_data_memtype(
				((struct pcep_object_switch_layer *)obj)
					->switch_layer_rows,
				PCEPLIB_MESSAGES);
		}
		break;

	case PCEP_OBJ_CLASS_OPEN:
	case PCEP_OBJ_CLASS_RP:
	case PCEP_OBJ_CLASS_NOPATH:
	case PCEP_OBJ_CLASS_ENDPOINTS:
	case PCEP_OBJ_CLASS_BANDWIDTH:
	case PCEP_OBJ_CLASS_METRIC:
	case PCEP_OBJ_CLASS_LSPA:
	case PCEP_OBJ_CLASS_NOTF:
	case PCEP_OBJ_CLASS_ERROR:
	case PCEP_OBJ_CLASS_CLOSE:
	case PCEP_OBJ_CLASS_OF:
	case PCEP_OBJ_CLASS_LSP:
	case PCEP_OBJ_CLASS_SRP:
	case PCEP_OBJ_CLASS_VENDOR_INFO:
	case PCEP_OBJ_CLASS_INTER_LAYER:
	case PCEP_OBJ_CLASS_REQ_ADAP_CAP:
	case PCEP_OBJ_CLASS_SERVER_IND:
	case PCEP_OBJ_CLASS_ASSOCIATION:
	case PCEP_OBJ_CLASS_MAX:
		break;
	}

	pceplib_free(PCEPLIB_MESSAGES, obj);
}

void pcep_msg_free_message(struct pcep_message *message)
{
	/* Iterate the objects and free each one */
	if (message->obj_list != NULL) {
		struct pcep_object_header *obj;
		while ((obj = (struct pcep_object_header *)
				dll_delete_first_node(message->obj_list))
		       != NULL) {
			pcep_obj_free_object(obj);
		}

		dll_destroy(message->obj_list);
	}

	if (message->msg_header != NULL) {
		pceplib_free(PCEPLIB_MESSAGES, message->msg_header);
	}

	if (message->encoded_message != NULL) {
		pceplib_free(PCEPLIB_MESSAGES, message->encoded_message);
	}

	pceplib_free(PCEPLIB_MESSAGES, message);
}

void pcep_msg_free_message_list(double_linked_list *list)
{
	/* Iterate the messages and free each one */
	struct pcep_message *msg;
	while ((msg = (struct pcep_message *)dll_delete_first_node(list))
	       != NULL) {
		pcep_msg_free_message(msg);
	}

	dll_destroy(list);
}

const char *get_message_type_str(uint8_t type)
{
	uint8_t msg_type =
		(type > PCEP_TYPE_INITIATE) ? PCEP_TYPE_INITIATE + 1 : type;

	return message_type_strs[msg_type];
}

const char *get_object_class_str(uint8_t class)
{
	uint8_t object_class =
		(class > PCEP_OBJ_CLASS_SRP) ? PCEP_OBJ_CLASS_SRP + 1 : class;

	return object_class_strs[object_class];
}

/* Expecting a list of struct pcep_message pointers */
void pcep_msg_print(double_linked_list *msg_list)
{
	double_linked_list_node *node;
	for (node = msg_list->head; node != NULL; node = node->next_node) {
		struct pcep_message *msg = (struct pcep_message *)node->data;
		pcep_log(LOG_INFO, "%s: PCEP_MSG %s", __func__,
			 get_message_type_str(msg->msg_header->type));

		double_linked_list_node *obj_node =
			(msg->obj_list == NULL ? NULL : msg->obj_list->head);
		for (; obj_node != NULL; obj_node = obj_node->next_node) {
			struct pcep_object_header *obj_header =
				((struct pcep_object_header *)obj_node->data);
			pcep_log(
				LOG_INFO, "%s: PCEP_OBJ %s", __func__,
				get_object_class_str(obj_header->object_class));
		}
	}
}

int pcep_msg_send(int sock_fd, struct pcep_message *msg)
{
	if (msg == NULL) {
		return 0;
	}
	int msg_length = ntohs(msg->encoded_message_length);
	if (msg_length > PCEP_MESSAGE_LENGTH) {
		pcep_log(LOG_ERR, "%s: Not sended, size(% d) exceed max(% d) ",
			 __func__, msg_length, PCEP_MESSAGE_LENGTH);
		return 0;
	}

	return write(sock_fd, msg->encoded_message, msg_length);
}
