// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 */

#ifndef PCEP_TOOLS_H
#define PCEP_TOOLS_H

#include <stdint.h>
#include <netinet/in.h> // struct in_addr

#include "pcep_utils_double_linked_list.h"
#include "pcep_msg_messages.h"
#include "pcep_msg_objects.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PCEP_MAX_SIZE 6000

/* Returns a double linked list of PCEP messages */
double_linked_list *pcep_msg_read(int sock_fd);
/*
 * Read from socket into the caller's reassembly buffer, which holds
 * buffer_len bytes of an earlier partial message, and
 * decode every complete message in it. The bytes of a trailing partial
 * message are kept in the buffer for the next call. Every message that
 * fails to decode is counted in invalid_msgs; an invalid message header
 * discards the buffer, since the length of what follows is unknown.
 * Returns NULL if the socket was closed or the read failed, otherwise
 * the list of decoded messages.
 */
double_linked_list *pcep_msg_read_buffered(int sock_fd, uint8_t *buffer, uint32_t buffer_size,
					   uint32_t *buffer_len, int *invalid_msgs);
/* Given a double linked list of PCEP messages, return the first node that has
 * the same message type */
struct pcep_message *pcep_msg_get(double_linked_list *msg_list, uint8_t type);
/* Given a double linked list of PCEP messages, return the next node after
 * current node that has the same message type */
struct pcep_message *pcep_msg_get_next(double_linked_list *msg_list,
				       struct pcep_message *current,
				       uint8_t type);
struct pcep_object_header *pcep_obj_get(double_linked_list *list,
					uint8_t object_class);
struct pcep_object_header *pcep_obj_get_next(double_linked_list *list,
					     struct pcep_object_header *current,
					     uint8_t object_class);
struct pcep_object_tlv_header *pcep_tlv_get(double_linked_list *list,
					    uint16_t type);
struct pcep_object_tlv_header *
pcep_tlv_get_next(double_linked_list *list,
		  struct pcep_object_tlv_header *current, uint16_t type);
void pcep_obj_free_tlv(struct pcep_object_tlv_header *tlv);
void pcep_obj_free_object(struct pcep_object_header *obj);
void pcep_msg_free_message(struct pcep_message *message);
void pcep_msg_free_message_list(double_linked_list *list);
void pcep_msg_print(double_linked_list *list);
const char *get_message_type_str(uint8_t type);
const char *get_object_class_str(uint8_t class);
int pcep_msg_send(int sock_fd, struct pcep_message *hdr);

#ifdef __cplusplus
}
#endif

#endif
