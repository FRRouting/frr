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
 * Definitions for encoding and decoding PCEP messages, objects, and TLVs.
 */

#ifndef PCEP_ENCODING_H
#define PCEP_ENCODING_H

#include <stdbool.h>

#include "pcep_msg_messages.h"
#include "pcep_msg_objects.h"
#include "pcep_msg_tlvs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pcep_versioning {
	bool draft_ietf_pce_segment_routing_07; /* If false, use draft16 */
	/* As more draft versions are incorporated, add appropriate attributes
	 */
};

#define MESSAGE_HEADER_LENGTH 4
#define PCEP_MESSAGE_LENGTH 65535
#define OBJECT_HEADER_LENGTH 4
#define OBJECT_RO_SUBOBJ_HEADER_LENGTH 2
#define TLV_HEADER_LENGTH 4
#define LENGTH_1WORD sizeof(uint32_t)
#define LENGTH_2WORDS sizeof(uint32_t) * 2
#define LENGTH_3WORDS sizeof(uint32_t) * 3
#define LENGTH_4WORDS sizeof(uint32_t) * 4
#define LENGTH_5WORDS sizeof(uint32_t) * 5
#define LENGTH_6WORDS sizeof(uint32_t) * 6
#define LENGTH_7WORDS sizeof(uint32_t) * 7
#define LENGTH_8WORDS sizeof(uint32_t) * 8
#define LENGTH_9WORDS sizeof(uint32_t) * 9
#define LENGTH_10WORDS sizeof(uint32_t) * 10
#define LENGTH_11WORDS sizeof(uint32_t) * 11
#define LENGTH_12WORDS sizeof(uint32_t) * 12
#define LENGTH_13WORDS sizeof(uint32_t) * 13

/* When iterating sub-objects or TLVs, limit to 10 in case corrupt data is
 * received */
#define MAX_ITERATIONS 10

struct pcep_versioning *create_default_pcep_versioning(void);
void destroy_pcep_versioning(struct pcep_versioning *versioning);

/*
 * Message encoding / decoding functions
 */

/* Called before sending messages to encode the message to a byte buffer in
 * Network byte order. This function will also encode all the objects and their
 * TLVs in the message. The result will be stored in the encoded_message field
 * in the pcep_message. Implemented in pcep-messages-encoding.c */
void pcep_encode_message(struct pcep_message *message,
			 struct pcep_versioning *versioning);

/* Decode the message header and return the message length.
 * Returns < 0 for invalid message headers. */
int32_t pcep_decode_validate_msg_header(const uint8_t *msg_buf);

/* Decode the entire message */
struct pcep_message *pcep_decode_message(const uint8_t *message_buffer);


/*
 * Object encoding / decoding functions
 */

/* Implemented in pcep-objects-encoding.c
 * Encode the object in struct pcep_object_header* into the uint8_t *buf,
 * and return the encoded object_length. */
uint16_t pcep_encode_object(struct pcep_object_header *object_hdr,
			    struct pcep_versioning *versioning, uint8_t *buf);

/* Implemented in pcep-objects-encoding.c
 * Decode the object, including the TLVs (if any) and return the object.
 * Returns object on success, NULL otherwise. */
struct pcep_object_header *pcep_decode_object(const uint8_t *msg_buf);

/* Internal util functions implemented in pcep-objects-encoding.c */
void encode_ipv6(struct in6_addr *src_ipv6, uint32_t *dst);
void decode_ipv6(const uint32_t *src, struct in6_addr *dst_ipv6);
uint16_t normalize_pcep_tlv_length(uint16_t length);
bool pcep_object_has_tlvs(struct pcep_object_header *object_hdr);
uint16_t pcep_object_get_length_by_hdr(struct pcep_object_header *object_hdr);
uint16_t pcep_object_get_length(enum pcep_object_classes object_class,
				enum pcep_object_types object_type);


/*
 * TLV encoding / decoding functions
 */

/* Implemented in pcep-tlv-encoding.c
 * Encode the tlv in struct pcep_tlv_header* into the uint8_t *buf,
 * and return the encoded tlv_length. */
uint16_t pcep_encode_tlv(struct pcep_object_tlv_header *tlv_hdr,
			 struct pcep_versioning *versioning, uint8_t *buf);

/* Decode the TLV in tlv_buf and return a pointer to the object */
struct pcep_object_tlv_header *pcep_decode_tlv(const uint8_t *tlv_buf);


/*
 * utils mainly for testing purposes
 */
bool validate_message_objects(struct pcep_message *msg);

#ifdef __cplusplus
}
#endif

#endif
