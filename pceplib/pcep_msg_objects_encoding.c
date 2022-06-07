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
 * Encoding and decoding for PCEP Objects.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "pcep_msg_objects.h"
#include "pcep_msg_encoding.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

void write_object_header(struct pcep_object_header *object_hdr,
			 uint16_t object_length, uint8_t *buf);
void pcep_decode_object_hdr(const uint8_t *obj_buf,
			    struct pcep_object_header *obj_hdr);
void set_ro_subobj_fields(struct pcep_object_ro_subobj *subobj, bool flag_l,
			  uint8_t subobj_type);

/*
 * forward declarations for initialize_object_encoders()
 */
uint16_t pcep_encode_obj_open(struct pcep_object_header *obj,
			      struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_rp(struct pcep_object_header *obj,
			    struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_nopath(struct pcep_object_header *obj,
				struct pcep_versioning *versioning,
				uint8_t *buf);
uint16_t pcep_encode_obj_endpoints(struct pcep_object_header *obj,
				   struct pcep_versioning *versioning,
				   uint8_t *buf);
uint16_t pcep_encode_obj_association(struct pcep_object_header *obj,
				     struct pcep_versioning *versioning,
				     uint8_t *buf);
uint16_t pcep_encode_obj_bandwidth(struct pcep_object_header *obj,
				   struct pcep_versioning *versioning,
				   uint8_t *buf);
uint16_t pcep_encode_obj_metric(struct pcep_object_header *obj,
				struct pcep_versioning *versioning,
				uint8_t *buf);
uint16_t pcep_encode_obj_ro(struct pcep_object_header *obj,
			    struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_lspa(struct pcep_object_header *obj,
			      struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_svec(struct pcep_object_header *obj,
			      struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_notify(struct pcep_object_header *obj,
				struct pcep_versioning *versioning,
				uint8_t *buf);
uint16_t pcep_encode_obj_error(struct pcep_object_header *error,
			       struct pcep_versioning *versioning,
			       uint8_t *buf);
uint16_t pcep_encode_obj_close(struct pcep_object_header *close,
			       struct pcep_versioning *versioning,
			       uint8_t *buf);
uint16_t pcep_encode_obj_srp(struct pcep_object_header *obj,
			     struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_lsp(struct pcep_object_header *obj,
			     struct pcep_versioning *versioning, uint8_t *buf);
uint16_t pcep_encode_obj_vendor_info(struct pcep_object_header *obj,
				     struct pcep_versioning *versioning,
				     uint8_t *buf);
uint16_t pcep_encode_obj_inter_layer(struct pcep_object_header *obj,
				     struct pcep_versioning *versioning,
				     uint8_t *buf);
uint16_t pcep_encode_obj_switch_layer(struct pcep_object_header *obj,
				      struct pcep_versioning *versioning,
				      uint8_t *buf);
uint16_t pcep_encode_obj_req_adap_cap(struct pcep_object_header *obj,
				      struct pcep_versioning *versioning,
				      uint8_t *buf);
uint16_t pcep_encode_obj_server_ind(struct pcep_object_header *obj,
				    struct pcep_versioning *versioning,
				    uint8_t *buf);
uint16_t pcep_encode_obj_objective_function(struct pcep_object_header *obj,
					    struct pcep_versioning *versioning,
					    uint8_t *buf);
typedef uint16_t (*object_encoder_funcptr)(struct pcep_object_header *,
					   struct pcep_versioning *versioning,
					   uint8_t *buf);

#define MAX_OBJECT_ENCODER_INDEX 64

#define PCEP_ENCODERS_ARGS                                                     \
	struct pcep_object_header *, struct pcep_versioning *versioning,       \
		uint8_t *buf
uint16_t (*const object_encoders[MAX_OBJECT_ENCODER_INDEX])(
	PCEP_ENCODERS_ARGS) = {
	[PCEP_OBJ_CLASS_OPEN] = pcep_encode_obj_open,
	[PCEP_OBJ_CLASS_RP] = pcep_encode_obj_rp,
	[PCEP_OBJ_CLASS_NOPATH] = pcep_encode_obj_nopath,
	[PCEP_OBJ_CLASS_ENDPOINTS] = pcep_encode_obj_endpoints,
	[PCEP_OBJ_CLASS_BANDWIDTH] = pcep_encode_obj_bandwidth,
	[PCEP_OBJ_CLASS_METRIC] = pcep_encode_obj_metric,
	[PCEP_OBJ_CLASS_ERO] = pcep_encode_obj_ro,
	[PCEP_OBJ_CLASS_RRO] = pcep_encode_obj_ro,
	[PCEP_OBJ_CLASS_LSPA] = pcep_encode_obj_lspa,
	[PCEP_OBJ_CLASS_IRO] = pcep_encode_obj_ro,
	[PCEP_OBJ_CLASS_SVEC] = pcep_encode_obj_svec,
	[PCEP_OBJ_CLASS_NOTF] = pcep_encode_obj_notify,
	[PCEP_OBJ_CLASS_ERROR] = pcep_encode_obj_error,
	[PCEP_OBJ_CLASS_CLOSE] = pcep_encode_obj_close,
	[PCEP_OBJ_CLASS_LSP] = pcep_encode_obj_lsp,
	[PCEP_OBJ_CLASS_SRP] = pcep_encode_obj_srp,
	[PCEP_OBJ_CLASS_ASSOCIATION] = pcep_encode_obj_association,
	[PCEP_OBJ_CLASS_INTER_LAYER] = pcep_encode_obj_inter_layer,
	[PCEP_OBJ_CLASS_SWITCH_LAYER] = pcep_encode_obj_switch_layer,
	[PCEP_OBJ_CLASS_REQ_ADAP_CAP] = pcep_encode_obj_req_adap_cap,
	[PCEP_OBJ_CLASS_SERVER_IND] = pcep_encode_obj_server_ind,
	[PCEP_OBJ_CLASS_VENDOR_INFO] = pcep_encode_obj_vendor_info,
	[PCEP_OBJ_CLASS_OF] = pcep_encode_obj_objective_function,
};
/*
 * forward declarations for initialize_object_decoders()
 */
struct pcep_object_header *pcep_decode_obj_open(struct pcep_object_header *hdr,
						const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_rp(struct pcep_object_header *hdr,
					      const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_nopath(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_endpoints(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_association(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_bandwidth(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_metric(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_ro(struct pcep_object_header *hdr,
					      const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_lspa(struct pcep_object_header *hdr,
						const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_svec(struct pcep_object_header *hdr,
						const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_notify(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_error(struct pcep_object_header *hdr,
						 const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_close(struct pcep_object_header *hdr,
						 const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_srp(struct pcep_object_header *hdr,
					       const uint8_t *buf);
struct pcep_object_header *pcep_decode_obj_lsp(struct pcep_object_header *hdr,
					       const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_vendor_info(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_inter_layer(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_switch_layer(struct pcep_object_header *hdr,
			     const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_req_adap_cap(struct pcep_object_header *hdr,
			     const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_server_ind(struct pcep_object_header *hdr, const uint8_t *buf);
struct pcep_object_header *
pcep_decode_obj_objective_function(struct pcep_object_header *hdr,
				   const uint8_t *buf);
typedef struct pcep_object_header *(*object_decoder_funcptr)(
	struct pcep_object_header *, const uint8_t *buf);

#define PCEP_DECODERS_ARGS struct pcep_object_header *, const uint8_t *buf

struct pcep_object_header *(*const object_decoders[MAX_OBJECT_ENCODER_INDEX])(
	PCEP_DECODERS_ARGS) = {
	[PCEP_OBJ_CLASS_OPEN] = pcep_decode_obj_open,
	[PCEP_OBJ_CLASS_RP] = pcep_decode_obj_rp,
	[PCEP_OBJ_CLASS_NOPATH] = pcep_decode_obj_nopath,
	[PCEP_OBJ_CLASS_ENDPOINTS] = pcep_decode_obj_endpoints,
	[PCEP_OBJ_CLASS_BANDWIDTH] = pcep_decode_obj_bandwidth,
	[PCEP_OBJ_CLASS_METRIC] = pcep_decode_obj_metric,
	[PCEP_OBJ_CLASS_ERO] = pcep_decode_obj_ro,
	[PCEP_OBJ_CLASS_RRO] = pcep_decode_obj_ro,
	[PCEP_OBJ_CLASS_LSPA] = pcep_decode_obj_lspa,
	[PCEP_OBJ_CLASS_IRO] = pcep_decode_obj_ro,
	[PCEP_OBJ_CLASS_SVEC] = pcep_decode_obj_svec,
	[PCEP_OBJ_CLASS_NOTF] = pcep_decode_obj_notify,
	[PCEP_OBJ_CLASS_ERROR] = pcep_decode_obj_error,
	[PCEP_OBJ_CLASS_CLOSE] = pcep_decode_obj_close,
	[PCEP_OBJ_CLASS_LSP] = pcep_decode_obj_lsp,
	[PCEP_OBJ_CLASS_SRP] = pcep_decode_obj_srp,
	[PCEP_OBJ_CLASS_ASSOCIATION] = pcep_decode_obj_association,
	[PCEP_OBJ_CLASS_INTER_LAYER] = pcep_decode_obj_inter_layer,
	[PCEP_OBJ_CLASS_SWITCH_LAYER] = pcep_decode_obj_switch_layer,
	[PCEP_OBJ_CLASS_REQ_ADAP_CAP] = pcep_decode_obj_req_adap_cap,
	[PCEP_OBJ_CLASS_SERVER_IND] = pcep_decode_obj_server_ind,
	[PCEP_OBJ_CLASS_VENDOR_INFO] = pcep_decode_obj_vendor_info,
	[PCEP_OBJ_CLASS_OF] = pcep_decode_obj_objective_function,
};

/* Object lengths, including the Object Header.
 * Used by pcep_object_get_length() and pcep_object_has_tlvs() */
static uint8_t pcep_object_class_lengths[] = {
	0,  /* Object class 0 unused */
	8,  /* PCEP_OBJ_CLASS_OPEN = 1 */
	12, /* PCEP_OBJ_CLASS_RP = 2 */
	16, /* PCEP_OBJ_CLASS_NOPATH = 3, includes 8 for mandatory TLV */
	0,  /* PCEP_OBJ_CLASS_ENDPOINTS = 4, could be ipv4 or ipv6, setting to 0
	     */
	8,  /* PCEP_OBJ_CLASS_BANDWIDTH = 5 */
	12, /* PCEP_OBJ_CLASS_METRIC = 6 */
	0,  /* PCEP_OBJ_CLASS_ERO = 7, setting 0, ROs cannot have TLVs */
	0,  /* PCEP_OBJ_CLASS_RRO = 8, setting 0, ROs cannot have TLVs */
	20, /* PCEP_OBJ_CLASS_LSPA = 9 */
	0,  /* PCEP_OBJ_CLASS_IRO = 10, setting 0, ROs cannot have TLVs */
	0,  /* PCEP_OBJ_CLASS_SVEC = 11, SVECs cannot have TLVs */
	8,  /* PCEP_OBJ_CLASS_NOTF = 12 */
	8,  /* PCEP_OBJ_CLASS_ERROR = 13 */
	0,  /* Object class 14 unused */
	8,  /* PCEP_OBJ_CLASS_CLOSE = 15 */
	0,  0, 0, 0, 0, /* Object classes 16 - 20 are not used */
	8,		/* PCEP_OBJ_CLASS_OF = 21 */
	0,  0, 0, 0, 0, /* Object classes 22 - 26 are not used */
	0,  0, 0, 0, 0, /* Object classes 27 - 31 are not used */
	8,		/* PCEP_OBJ_CLASS_LSP = 32 */
	12,		/* PCEP_OBJ_CLASS_SRP = 33 */
	12,		/* PCEP_OBJ_CLASS_VENDOR_INFO = 34 */
	0,		/* Object class 35 unused */
	0,		/* PCEP_OBJ_CLASS_INTER_LAYER = 36, cannot have TLVs */
	0,		/* PCEP_OBJ_CLASS_SWITCH_LAYER = 37, cannot have TLVs */
	0,		/* PCEP_OBJ_CLASS_REQ_ADAP_CAP = 38, cannot have TLVs*/
	8,		/* PCEP_OBJ_CLASS_SERVER_IND = 39 */
	0,		/* PCEP_OBJ_CLASS_ASSOCIATION = 40, cannot have TLVs */
};

/*
 * The TLVs can have strange length values, since they do not include padding in
 * the TLV header length, but that extra padding must be taken into account by
 * the enclosing object by rounding up to the next 4 byte boundary.
 * Example returned lengths:
 *   normalize_length(4)  =  4, normalize_length(5)  =  8, normalize_length(6)
 * =  8, normalize_length(7)  =  8, normalize_length(8)  =  8
 * normalize_length(9)  = 12, normalize_length(10) = 12, normalize_length(11) =
 * 12, normalize_length(12) = 12, normalize_length(13) = 13...
 */
uint16_t normalize_pcep_tlv_length(uint16_t length)
{
	return (length % 4 == 0) ? length : (length + (4 - (length % 4)));
}

/*
 * Encoding functions
 */
uint16_t pcep_encode_object(struct pcep_object_header *object_hdr,
			    struct pcep_versioning *versioning, uint8_t *buf)
{

	if (object_hdr->object_class >= MAX_OBJECT_ENCODER_INDEX) {
		pcep_log(LOG_INFO,
			 "%s: Cannot encode unknown Object class [%d]",
			 __func__, object_hdr->object_class);
		return 0;
	}

	object_encoder_funcptr obj_encoder =
		object_encoders[object_hdr->object_class];
	if (obj_encoder == NULL) {
		pcep_log(LOG_INFO,
			 "%s: No object encoder found for Object class [%d]",
			 __func__, object_hdr->object_class);
		return 0;
	}

	uint16_t object_length = OBJECT_HEADER_LENGTH
				 + obj_encoder(object_hdr, versioning,
					       buf + OBJECT_HEADER_LENGTH);
	double_linked_list_node *node =
		(object_hdr->tlv_list == NULL ? NULL
					      : object_hdr->tlv_list->head);
	for (; node != NULL; node = node->next_node) {
		/* Returns the length of the TLV, including the TLV header */
		object_length += pcep_encode_tlv(
			(struct pcep_object_tlv_header *)node->data, versioning,
			buf + object_length);
	}
	object_length = normalize_pcep_tlv_length(object_length);
	write_object_header(object_hdr, object_length, buf);
	object_hdr->encoded_object = buf;
	object_hdr->encoded_object_length = object_length;

	return object_length;
}


/* Object Header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  //                        (Object body)                        //
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

void write_object_header(struct pcep_object_header *object_hdr,
			 uint16_t object_length, uint8_t *buf)
{
	buf[0] = object_hdr->object_class;
	buf[1] = ((object_hdr->object_type << 4)
		  | (object_hdr->flag_p ? OBJECT_HEADER_FLAG_P : 0x00)
		  | (object_hdr->flag_i ? OBJECT_HEADER_FLAG_I : 0x00));
	uint16_t net_order_length = htons(object_length);
	memcpy(buf + 2, &net_order_length, sizeof(net_order_length));
}


/*
 * Functions to encode objects
 * - they will be passed a pointer to a buffer to write the object body,
 *   which is past the object header.
 * - they should return the object body length, not including the object header
 * length.
 */

uint16_t pcep_encode_obj_open(struct pcep_object_header *hdr,
			      struct pcep_versioning *versioning,
			      uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_open *open = (struct pcep_object_open *)hdr;
	obj_body_buf[0] = (open->open_version << 5) & 0xe0;
	obj_body_buf[1] = open->open_keepalive;
	obj_body_buf[2] = open->open_deadtimer;
	obj_body_buf[3] = open->open_sid;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_rp(struct pcep_object_header *hdr,
			    struct pcep_versioning *versioning,
			    uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_rp *rp = (struct pcep_object_rp *)hdr;
	obj_body_buf[3] = ((rp->flag_strict ? OBJECT_RP_FLAG_O : 0x00)
			   | (rp->flag_bidirectional ? OBJECT_RP_FLAG_B : 0x00)
			   | (rp->flag_reoptimization ? OBJECT_RP_FLAG_R : 0x00)
			   | (rp->flag_of ? OBJECT_RP_FLAG_OF : 0x00)
			   | (rp->priority & 0x07));
	uint32_t *uint32_ptr = (uint32_t *)(obj_body_buf + 4);
	*uint32_ptr = htonl(rp->request_id);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_obj_notify(struct pcep_object_header *hdr,
				struct pcep_versioning *versioning,
				uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_notify *notify = (struct pcep_object_notify *)hdr;
	obj_body_buf[2] = notify->notification_type;
	obj_body_buf[3] = notify->notification_value;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_nopath(struct pcep_object_header *hdr,
				struct pcep_versioning *versioning,
				uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_nopath *nopath = (struct pcep_object_nopath *)hdr;
	obj_body_buf[0] = nopath->ni;
	obj_body_buf[1] = ((nopath->flag_c) ? OBJECT_NOPATH_FLAG_C : 0x00);

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_association(struct pcep_object_header *hdr,
				     struct pcep_versioning *versioning,
				     uint8_t *obj_body_buf)
{
	(void)versioning;
	uint16_t *uint16_ptr = (uint16_t *)obj_body_buf;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	if (hdr->object_type == PCEP_OBJ_TYPE_ASSOCIATION_IPV4) {
		struct pcep_object_association_ipv4 *ipv4 =
			(struct pcep_object_association_ipv4 *)hdr;
		obj_body_buf[3] =
			(ipv4->R_flag ? OBJECT_ASSOCIATION_FLAG_R : 0x00);
		uint16_ptr[2] = htons(ipv4->association_type);
		uint16_ptr[3] = htons(ipv4->association_id);
		uint32_ptr[2] = ipv4->src.s_addr;

		return LENGTH_3WORDS;
	} else {
		struct pcep_object_association_ipv6 *ipv6 =
			(struct pcep_object_association_ipv6 *)hdr;
		obj_body_buf[3] =
			(ipv6->R_flag ? OBJECT_ASSOCIATION_FLAG_R : 0x00);
		uint16_ptr[2] = htons(ipv6->association_type);
		uint16_ptr[3] = htons(ipv6->association_id);
		memcpy(uint32_ptr, &ipv6->src, sizeof(struct in6_addr));

		return LENGTH_6WORDS;
	}
}

uint16_t pcep_encode_obj_endpoints(struct pcep_object_header *hdr,
				   struct pcep_versioning *versioning,
				   uint8_t *obj_body_buf)
{
	(void)versioning;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	if (hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
		struct pcep_object_endpoints_ipv4 *ipv4 =
			(struct pcep_object_endpoints_ipv4 *)hdr;
		uint32_ptr[0] = ipv4->src_ipv4.s_addr;
		uint32_ptr[1] = ipv4->dst_ipv4.s_addr;

		return LENGTH_2WORDS;
	} else {
		struct pcep_object_endpoints_ipv6 *ipv6 =
			(struct pcep_object_endpoints_ipv6 *)hdr;
		memcpy(uint32_ptr, &ipv6->src_ipv6, sizeof(struct in6_addr));
		memcpy(&uint32_ptr[4], &ipv6->dst_ipv6,
		       sizeof(struct in6_addr));

		return LENGTH_8WORDS;
	}
}

uint16_t pcep_encode_obj_bandwidth(struct pcep_object_header *hdr,
				   struct pcep_versioning *versioning,
				   uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_bandwidth *bandwidth =
		(struct pcep_object_bandwidth *)hdr;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	/* Seems like the compiler doesn't correctly copy the float, so memcpy()
	 * it */
	memcpy(uint32_ptr, &(bandwidth->bandwidth), sizeof(uint32_t));
	*uint32_ptr = htonl(*uint32_ptr);

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_metric(struct pcep_object_header *hdr,
				struct pcep_versioning *versioning,
				uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_metric *metric = (struct pcep_object_metric *)hdr;
	obj_body_buf[2] = ((metric->flag_c ? OBJECT_METRIC_FLAC_C : 0x00)
			   | (metric->flag_b ? OBJECT_METRIC_FLAC_B : 0x00));
	obj_body_buf[3] = metric->type;
	uint32_t *uint32_ptr = (uint32_t *)(obj_body_buf + 4);
	/* Seems like the compiler doesn't correctly copy the float, so memcpy()
	 * it */
	memcpy(uint32_ptr, &(metric->value), sizeof(uint32_t));
	*uint32_ptr = htonl(*uint32_ptr);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_obj_lspa(struct pcep_object_header *hdr,
			      struct pcep_versioning *versioning,
			      uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_lspa *lspa = (struct pcep_object_lspa *)hdr;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	uint32_ptr[0] = htonl(lspa->lspa_exclude_any);
	uint32_ptr[1] = htonl(lspa->lspa_include_any);
	uint32_ptr[2] = htonl(lspa->lspa_include_all);
	obj_body_buf[12] = lspa->setup_priority;
	obj_body_buf[13] = lspa->holding_priority;
	obj_body_buf[14] =
		(lspa->flag_local_protection ? OBJECT_LSPA_FLAG_L : 0x00);

	return LENGTH_4WORDS;
}

uint16_t pcep_encode_obj_svec(struct pcep_object_header *hdr,
			      struct pcep_versioning *versioning,
			      uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_svec *svec = (struct pcep_object_svec *)hdr;
	obj_body_buf[3] =
		((svec->flag_srlg_diverse ? OBJECT_SVEC_FLAG_S : 0x00)
		 | (svec->flag_node_diverse ? OBJECT_SVEC_FLAG_N : 0x00)
		 | (svec->flag_link_diverse ? OBJECT_SVEC_FLAG_L : 0x00));

	if (svec->request_id_list == NULL) {
		return LENGTH_1WORD;
	}

	int index = 1;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	double_linked_list_node *node = svec->request_id_list->head;
	for (; node != NULL; node = node->next_node) {
		uint32_ptr[index++] = htonl(*((uint32_t *)(node->data)));
	}

	return LENGTH_1WORD
	       + (svec->request_id_list->num_entries * sizeof(uint32_t));
}

uint16_t pcep_encode_obj_error(struct pcep_object_header *hdr,
			       struct pcep_versioning *versioning,
			       uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_error *error = (struct pcep_object_error *)hdr;
	obj_body_buf[2] = error->error_type;
	obj_body_buf[3] = error->error_value;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_close(struct pcep_object_header *hdr,
			       struct pcep_versioning *versioning,
			       uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_close *close = (struct pcep_object_close *)hdr;
	obj_body_buf[3] = close->reason;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_srp(struct pcep_object_header *hdr,
			     struct pcep_versioning *versioning,
			     uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_srp *srp = (struct pcep_object_srp *)hdr;
	obj_body_buf[3] = (srp->flag_lsp_remove ? OBJECT_SRP_FLAG_R : 0x00);
	uint32_t *uint32_ptr = (uint32_t *)(obj_body_buf + 4);
	*uint32_ptr = htonl(srp->srp_id_number);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_obj_lsp(struct pcep_object_header *hdr,
			     struct pcep_versioning *versioning,
			     uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_lsp *lsp = (struct pcep_object_lsp *)hdr;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	uint32_ptr[0] = htonl((lsp->plsp_id << 12) & 0xfffff000);
	obj_body_buf[3] = ((lsp->flag_c ? OBJECT_LSP_FLAG_C : 0x00)
			   | ((lsp->operational_status << 4) & 0x70)
			   | (lsp->flag_a ? OBJECT_LSP_FLAG_A : 0x00)
			   | (lsp->flag_r ? OBJECT_LSP_FLAG_R : 0x00)
			   | (lsp->flag_s ? OBJECT_LSP_FLAG_S : 0x00)
			   | (lsp->flag_d ? OBJECT_LSP_FLAG_D : 0x00));

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_vendor_info(struct pcep_object_header *hdr,
				     struct pcep_versioning *versioning,
				     uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_vendor_info *obj =
		(struct pcep_object_vendor_info *)hdr;
	uint32_t *uint32_ptr = (uint32_t *)obj_body_buf;
	uint32_ptr[0] = htonl(obj->enterprise_number);
	uint32_ptr[1] = htonl(obj->enterprise_specific_info);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_obj_inter_layer(struct pcep_object_header *hdr,
				     struct pcep_versioning *versioning,
				     uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_inter_layer *obj =
		(struct pcep_object_inter_layer *)hdr;
	obj_body_buf[3] = ((obj->flag_i ? OBJECT_INTER_LAYER_FLAG_I : 0x00)
			   | (obj->flag_m ? OBJECT_INTER_LAYER_FLAG_M : 0x00)
			   | (obj->flag_t ? OBJECT_INTER_LAYER_FLAG_T : 0x00));

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_switch_layer(struct pcep_object_header *hdr,
				      struct pcep_versioning *versioning,
				      uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_switch_layer *obj =
		(struct pcep_object_switch_layer *)hdr;
	uint8_t buf_index = 0;

	double_linked_list_node *node = obj->switch_layer_rows->head;
	while (node != NULL) {
		struct pcep_object_switch_layer_row *row = node->data;
		if (row == NULL) {
			break;
		}

		obj_body_buf[buf_index] = row->lsp_encoding_type;
		obj_body_buf[buf_index + 1] = row->switching_type;
		obj_body_buf[buf_index + 3] =
			(row->flag_i ? OBJECT_SWITCH_LAYER_FLAG_I : 0x00);

		buf_index += LENGTH_1WORD;
	}

	return buf_index;
}

uint16_t pcep_encode_obj_req_adap_cap(struct pcep_object_header *hdr,
				      struct pcep_versioning *versioning,
				      uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_req_adap_cap *obj =
		(struct pcep_object_req_adap_cap *)hdr;

	obj_body_buf[0] = obj->switching_capability;
	obj_body_buf[1] = obj->encoding;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_server_ind(struct pcep_object_header *hdr,
				    struct pcep_versioning *versioning,
				    uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_server_indication *obj =
		(struct pcep_object_server_indication *)hdr;

	obj_body_buf[0] = obj->switching_capability;
	obj_body_buf[1] = obj->encoding;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_objective_function(struct pcep_object_header *hdr,
					    struct pcep_versioning *versioning,
					    uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_objective_function *obj =
		(struct pcep_object_objective_function *)hdr;

	uint16_t *uint16_ptr = (uint16_t *)obj_body_buf;
	*uint16_ptr = htons(obj->of_code);

	return LENGTH_1WORD;
}

uint16_t pcep_encode_obj_ro(struct pcep_object_header *hdr,
			    struct pcep_versioning *versioning,
			    uint8_t *obj_body_buf)
{
	(void)versioning;
	struct pcep_object_ro *ro = (struct pcep_object_ro *)hdr;
	if (ro == NULL || ro->sub_objects == NULL) {
		return 0;
	}

	/* RO Subobject format
	 *
	 *  0                   1
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
	 *  |L|    Type     |     Length    | (Subobject contents)          |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
	 */

	uint16_t index = 0;
	double_linked_list_node *node = ro->sub_objects->head;
	for (; node != NULL; node = node->next_node) {
		struct pcep_object_ro_subobj *ro_subobj = node->data;
		obj_body_buf[index++] =
			((ro_subobj->flag_subobj_loose_hop ? 0x80 : 0x00)
			 | (ro_subobj->ro_subobj_type));
		/* The length will be written below, depending on the subobj
		 * type */
		uint8_t *length_ptr = &(obj_body_buf[index++]);
		uint32_t *uint32_ptr = (uint32_t *)(obj_body_buf + index);

		/* - The index has already been incremented past the header,
		 *   and now points to the ro_subobj body. Below it just needs
		 *   to be incremented past the body.
		 *
		 * - Each section below needs to write the total length,
		 *   including the 2 byte subobj header. */

		switch (ro_subobj->ro_subobj_type) {
		case RO_SUBOBJ_TYPE_IPV4: {
			struct pcep_ro_subobj_ipv4 *ipv4 =
				(struct pcep_ro_subobj_ipv4 *)ro_subobj;
			uint32_ptr[0] = ipv4->ip_addr.s_addr;
			index += LENGTH_1WORD;
			obj_body_buf[index++] = ipv4->prefix_length;
			obj_body_buf[index++] =
				(ipv4->flag_local_protection
					 ? OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT
					 : 0x00);
			*length_ptr = LENGTH_2WORDS;
		} break;

		case RO_SUBOBJ_TYPE_IPV6: {
			struct pcep_ro_subobj_ipv6 *ipv6 =
				(struct pcep_ro_subobj_ipv6 *)ro_subobj;
			encode_ipv6(&ipv6->ip_addr, uint32_ptr);
			index += LENGTH_4WORDS;
			obj_body_buf[index++] = ipv6->prefix_length;
			obj_body_buf[index++] =
				(ipv6->flag_local_protection
					 ? OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT
					 : 0x00);
			*length_ptr = LENGTH_5WORDS;
		} break;

		case RO_SUBOBJ_TYPE_LABEL: {
			struct pcep_ro_subobj_32label *label =
				(struct pcep_ro_subobj_32label *)ro_subobj;
			obj_body_buf[index++] =
				(label->flag_global_label
					 ? OBJECT_SUBOBJ_LABEL_FLAG_GLOGAL
					 : 0x00);
			obj_body_buf[index++] = label->class_type;
			uint32_ptr = (uint32_t *)(obj_body_buf + index);
			*uint32_ptr = htonl(label->label);
			*length_ptr = LENGTH_2WORDS;
			index += LENGTH_1WORD;
		} break;

		case RO_SUBOBJ_TYPE_UNNUM: {
			struct pcep_ro_subobj_unnum *unum =
				(struct pcep_ro_subobj_unnum *)ro_subobj;
			index += 2; /* increment past 2 reserved bytes */
			uint32_ptr = (uint32_t *)(obj_body_buf + index);
			uint32_ptr[0] = unum->router_id.s_addr;
			uint32_ptr[1] = htonl(unum->interface_id);
			*length_ptr = LENGTH_3WORDS;
			index += LENGTH_2WORDS;
		} break;

		case RO_SUBOBJ_TYPE_ASN: {
			struct pcep_ro_subobj_asn *asn =
				(struct pcep_ro_subobj_asn *)ro_subobj;
			uint16_t *uint16_ptr =
				(uint16_t *)(obj_body_buf + index);
			*uint16_ptr = htons(asn->asn);
			*length_ptr = LENGTH_1WORD;
			index += 2;
		} break;

		case RO_SUBOBJ_TYPE_SR: {
			/* SR-ERO subobject format
			 *
			 * 0                   1                   2 3 0 1 2 3 4
			 * 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |L|   Type=36   |     Length    |  NT   |     Flags
			 * |F|S|C|M|
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |                         SID (optional) |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * //                   NAI (variable, optional) //
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */

			struct pcep_ro_subobj_sr *sr_subobj =
				(struct pcep_ro_subobj_sr *)ro_subobj;
			obj_body_buf[index++] =
				((sr_subobj->nai_type << 4) & 0xf0);
			obj_body_buf[index++] =
				((sr_subobj->flag_f ? OBJECT_SUBOBJ_SR_FLAG_F
						    : 0x00)
				 | (sr_subobj->flag_s ? OBJECT_SUBOBJ_SR_FLAG_S
						      : 0x00)
				 | (sr_subobj->flag_c ? OBJECT_SUBOBJ_SR_FLAG_C
						      : 0x00)
				 | (sr_subobj->flag_m ? OBJECT_SUBOBJ_SR_FLAG_M
						      : 0x00));
			uint32_ptr = (uint32_t *)(obj_body_buf + index);
			/* Start with LENGTH_1WORD for the SubObj HDR + NT +
			 * Flags */
			uint8_t sr_base_length = LENGTH_1WORD;
			/* If the sid_absent flag is true, then dont convert the
			 * sid */
			if (sr_subobj->flag_s == false) {
				uint32_ptr[0] = htonl(sr_subobj->sid);
				index += LENGTH_1WORD;
				uint32_ptr = (uint32_t *)(obj_body_buf + index);
				sr_base_length += LENGTH_1WORD;
			}

			/* The lengths below need to include:
			 * - sr_base_length: set above to include SR SubObj Hdr
			 * and the SID if present
			 * - Number of bytes written to the NAI
			 * The index will only be incremented below by the
			 * number of bytes written to the NAI, since the RO SR
			 * subobj header and the SID have already been written.
			 */

			double_linked_list_node *nai_node =
				(sr_subobj->nai_list == NULL
					 ? NULL
					 : sr_subobj->nai_list->head);
			if (nai_node == NULL) {
				if (sr_subobj->nai_type
				    == PCEP_SR_SUBOBJ_NAI_ABSENT) {
					*length_ptr = sr_base_length;
					continue;
				} else {
					return 0;
				}
			}
			switch (sr_subobj->nai_type) {
			case PCEP_SR_SUBOBJ_NAI_IPV4_NODE:
				uint32_ptr[0] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				*length_ptr = sr_base_length + LENGTH_1WORD;
				index += LENGTH_1WORD;
				break;

			case PCEP_SR_SUBOBJ_NAI_IPV6_NODE:
				encode_ipv6((struct in6_addr *)nai_node->data,
					    uint32_ptr);
				*length_ptr = sr_base_length + LENGTH_4WORDS;
				index += LENGTH_4WORDS;
				break;

			case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY:
				uint32_ptr[0] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				nai_node = nai_node->next_node;
				uint32_ptr[1] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				nai_node = nai_node->next_node;
				uint32_ptr[2] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				nai_node = nai_node->next_node;
				uint32_ptr[3] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				*length_ptr = sr_base_length + LENGTH_4WORDS;
				index += LENGTH_4WORDS;
				break;

			case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY:
				uint32_ptr[0] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				nai_node = nai_node->next_node;
				uint32_ptr[1] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				*length_ptr = sr_base_length + LENGTH_2WORDS;
				index += LENGTH_2WORDS;
				break;

			case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY:
				encode_ipv6((struct in6_addr *)nai_node->data,
					    uint32_ptr);
				nai_node = nai_node->next_node;
				encode_ipv6((struct in6_addr *)nai_node->data,
					    uint32_ptr + 4);
				*length_ptr = sr_base_length + LENGTH_8WORDS;
				index += LENGTH_8WORDS;
				break;

			case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY:
				encode_ipv6((struct in6_addr *)nai_node->data,
					    uint32_ptr);
				nai_node = nai_node->next_node;
				uint32_ptr[4] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				nai_node = nai_node->next_node;
				encode_ipv6((struct in6_addr *)nai_node->data,
					    uint32_ptr + 5);
				nai_node = nai_node->next_node;
				uint32_ptr[9] =
					((struct in_addr *)nai_node->data)
						->s_addr;
				*length_ptr = sr_base_length + LENGTH_10WORDS;
				index += LENGTH_10WORDS;
				break;

			default:
				break;
			}
		} break;

		default:
			break;
		}
	}

	return index;
}

void encode_ipv6(struct in6_addr *src_ipv6, uint32_t *dst)
{
	memcpy(dst, src_ipv6, sizeof(struct in6_addr));
}

/*
 * Decoding functions.
 */

void pcep_decode_object_hdr(const uint8_t *obj_buf,
			    struct pcep_object_header *obj_hdr)
{
	memset(obj_hdr, 0, sizeof(struct pcep_object_header));

	obj_hdr->object_class = obj_buf[0];
	obj_hdr->object_type = (obj_buf[1] >> 4) & 0x0f;
	obj_hdr->flag_p = (obj_buf[1] & OBJECT_HEADER_FLAG_P);
	obj_hdr->flag_i = (obj_buf[1] & OBJECT_HEADER_FLAG_I);
	uint16_t net_order_length;
	memcpy(&net_order_length, obj_buf + 2, sizeof(net_order_length));
	obj_hdr->encoded_object_length = ntohs(net_order_length);
	obj_hdr->encoded_object = obj_buf;
}

uint16_t pcep_object_get_length(enum pcep_object_classes object_class,
				enum pcep_object_types object_type)
{
	uint8_t object_length = pcep_object_class_lengths[object_class];
	if (object_length == 0) {
		if (object_class == PCEP_OBJ_CLASS_ENDPOINTS) {
			if (object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
				return 12;
			} else if (object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
				return 36;
			}
		}

		return 0;
	}

	return object_length;
}

uint16_t pcep_object_get_length_by_hdr(struct pcep_object_header *object_hdr)
{
	return (pcep_object_get_length(object_hdr->object_class,
				       object_hdr->object_type));
}

bool pcep_object_has_tlvs(struct pcep_object_header *object_hdr)
{
	uint8_t object_length = pcep_object_get_length_by_hdr(object_hdr);
	if (object_length == 0) {
		return false;
	}

	return (object_hdr->encoded_object_length - object_length) > 0;
}

struct pcep_object_header *pcep_decode_object(const uint8_t *obj_buf)
{

	struct pcep_object_header object_hdr;
	/* Only initializes and decodes the Object Header: class, type, flags,
	 * and length */
	pcep_decode_object_hdr(obj_buf, &object_hdr);

	if (object_hdr.object_class >= MAX_OBJECT_ENCODER_INDEX) {
		pcep_log(LOG_INFO,
			 "%s: Cannot decode unknown Object class [%d]",
			 __func__, object_hdr.object_class);
		return NULL;
	}

	object_decoder_funcptr obj_decoder =
		object_decoders[object_hdr.object_class];
	if (obj_decoder == NULL) {
		pcep_log(LOG_INFO,
			 "%s: No object decoder found for Object class [%d]",
			 __func__, object_hdr.object_class);
		return NULL;
	}

	/* The object decoders will start decoding the object body, if
	 * anything from the header is needed, they have the object_hdr */
	struct pcep_object_header *object =
		obj_decoder(&object_hdr, obj_buf + OBJECT_HEADER_LENGTH);
	if (object == NULL) {
		pcep_log(LOG_INFO, "%s: Unable to decode Object class [%d].",
			 __func__, object_hdr.object_class);
		return NULL;
	}

	if (pcep_object_has_tlvs(&object_hdr)) {
		object->tlv_list = dll_initialize();
		int num_iterations = 0;
		uint16_t tlv_index = pcep_object_get_length_by_hdr(&object_hdr);
		while ((object->encoded_object_length - tlv_index) > 0
		       && num_iterations++ < MAX_ITERATIONS) {
			struct pcep_object_tlv_header *tlv =
				pcep_decode_tlv(obj_buf + tlv_index);
			if (tlv == NULL) {
				/* TODO should we do anything else here ? */
				return object;
			}

			/* The TLV length does not include the TLV header */
			tlv_index += normalize_pcep_tlv_length(
				tlv->encoded_tlv_length + TLV_HEADER_LENGTH);
			dll_append(object->tlv_list, tlv);
		}
	}

	return object;
}

static struct pcep_object_header *
common_object_create(struct pcep_object_header *hdr, uint16_t new_obj_length)
{
	struct pcep_object_header *new_object =
		pceplib_malloc(PCEPLIB_MESSAGES, new_obj_length);
	memset(new_object, 0, new_obj_length);
	memcpy(new_object, hdr, sizeof(struct pcep_object_header));

	return new_object;
}

/*
 * Decoders
 */

struct pcep_object_header *pcep_decode_obj_open(struct pcep_object_header *hdr,
						const uint8_t *obj_buf)
{
	struct pcep_object_open *obj =
		(struct pcep_object_open *)common_object_create(
			hdr, sizeof(struct pcep_object_open));

	obj->open_version = (obj_buf[0] >> 5) & 0x07;
	obj->open_keepalive = obj_buf[1];
	obj->open_deadtimer = obj_buf[2];
	obj->open_sid = obj_buf[3];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_rp(struct pcep_object_header *hdr,
					      const uint8_t *obj_buf)
{
	struct pcep_object_rp *obj =
		(struct pcep_object_rp *)common_object_create(
			hdr, sizeof(struct pcep_object_rp));

	obj->flag_reoptimization = (obj_buf[3] & OBJECT_RP_FLAG_R);
	obj->flag_bidirectional = (obj_buf[3] & OBJECT_RP_FLAG_B);
	obj->flag_strict = (obj_buf[3] & OBJECT_RP_FLAG_O);
	obj->flag_of = (obj_buf[3] & OBJECT_RP_FLAG_OF);
	obj->priority = (obj_buf[3] & 0x07);
	obj->request_id = ntohl(*((uint32_t *)(obj_buf + 4)));

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_notify(struct pcep_object_header *hdr, const uint8_t *obj_buf)
{
	struct pcep_object_notify *obj =
		(struct pcep_object_notify *)common_object_create(
			hdr, sizeof(struct pcep_object_notify));

	obj->notification_type = obj_buf[2];
	obj->notification_value = obj_buf[3];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_nopath(struct pcep_object_header *hdr, const uint8_t *obj_buf)
{
	struct pcep_object_nopath *obj =
		(struct pcep_object_nopath *)common_object_create(
			hdr, sizeof(struct pcep_object_nopath));

	obj->ni = (obj_buf[0] >> 1);
	obj->flag_c = (obj_buf[0] & OBJECT_NOPATH_FLAG_C);

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_association(struct pcep_object_header *hdr,
			    const uint8_t *obj_buf)
{
	uint16_t *uint16_ptr = (uint16_t *)obj_buf;
	uint32_t *uint32_ptr = (uint32_t *)obj_buf;

	if (hdr->object_type == PCEP_OBJ_TYPE_ASSOCIATION_IPV4) {
		struct pcep_object_association_ipv4 *obj =
			(struct pcep_object_association_ipv4 *)
				common_object_create(
					hdr,
					sizeof(struct
					       pcep_object_association_ipv4));
		obj->R_flag = (obj_buf[3] & OBJECT_ASSOCIATION_FLAG_R);
		obj->association_type = ntohs(uint16_ptr[2]);
		obj->association_id = ntohs(uint16_ptr[3]);
		obj->src.s_addr = uint32_ptr[2];

		return (struct pcep_object_header *)obj;
	} else if (hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
		struct pcep_object_association_ipv6 *obj =
			(struct pcep_object_association_ipv6 *)
				common_object_create(
					hdr,
					sizeof(struct
					       pcep_object_association_ipv6));

		obj->R_flag = (obj_buf[3] & OBJECT_ASSOCIATION_FLAG_R);
		obj->association_type = ntohs(uint16_ptr[2]);
		obj->association_id = ntohs(uint16_ptr[3]);
		memcpy(&obj->src, &uint32_ptr[2], sizeof(struct in6_addr));

		return (struct pcep_object_header *)obj;
	}

	return NULL;
}
struct pcep_object_header *
pcep_decode_obj_endpoints(struct pcep_object_header *hdr,
			  const uint8_t *obj_buf)
{
	uint32_t *uint32_ptr = (uint32_t *)obj_buf;

	if (hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV4) {
		struct pcep_object_endpoints_ipv4 *obj =
			(struct pcep_object_endpoints_ipv4 *)
				common_object_create(
					hdr,
					sizeof(struct
					       pcep_object_endpoints_ipv4));
		obj->src_ipv4.s_addr = uint32_ptr[0];
		obj->dst_ipv4.s_addr = uint32_ptr[1];

		return (struct pcep_object_header *)obj;
	} else if (hdr->object_type == PCEP_OBJ_TYPE_ENDPOINT_IPV6) {
		struct pcep_object_endpoints_ipv6 *obj =
			(struct pcep_object_endpoints_ipv6 *)
				common_object_create(
					hdr,
					sizeof(struct
					       pcep_object_endpoints_ipv6));

		memcpy(&obj->src_ipv6, &uint32_ptr[0], sizeof(struct in6_addr));
		memcpy(&obj->dst_ipv6, &uint32_ptr[4], sizeof(struct in6_addr));

		return (struct pcep_object_header *)obj;
	}

	return NULL;
}

struct pcep_object_header *
pcep_decode_obj_bandwidth(struct pcep_object_header *hdr,
			  const uint8_t *obj_buf)
{
	struct pcep_object_bandwidth *obj =
		(struct pcep_object_bandwidth *)common_object_create(
			hdr, sizeof(struct pcep_object_bandwidth));

	uint32_t value = ntohl(*((uint32_t *)obj_buf));
	/* Seems like the compiler doesn't correctly copy to the float, so
	 * memcpy() it */
	memcpy(&obj->bandwidth, &value, sizeof(uint32_t));

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_metric(struct pcep_object_header *hdr, const uint8_t *obj_buf)
{
	struct pcep_object_metric *obj =
		(struct pcep_object_metric *)common_object_create(
			hdr, sizeof(struct pcep_object_metric));
	obj->flag_b = (obj_buf[2] & OBJECT_METRIC_FLAC_B);
	obj->flag_c = (obj_buf[2] & OBJECT_METRIC_FLAC_C);
	obj->type = obj_buf[3];
	uint32_t value = ntohl(*((uint32_t *)(obj_buf + 4)));
	/* Seems like the compiler doesn't correctly copy to the float, so
	 * memcpy() it */
	memcpy(&obj->value, &value, sizeof(uint32_t));

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_lspa(struct pcep_object_header *hdr,
						const uint8_t *obj_buf)
{
	struct pcep_object_lspa *obj =
		(struct pcep_object_lspa *)common_object_create(
			hdr, sizeof(struct pcep_object_lspa));
	uint32_t *uint32_ptr = (uint32_t *)obj_buf;

	obj->lspa_exclude_any = ntohl(uint32_ptr[0]);
	obj->lspa_include_any = ntohl(uint32_ptr[1]);
	obj->lspa_include_all = ntohl(uint32_ptr[2]);
	obj->setup_priority = obj_buf[12];
	obj->holding_priority = obj_buf[13];
	obj->flag_local_protection = (obj_buf[14] & OBJECT_LSPA_FLAG_L);

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_svec(struct pcep_object_header *hdr,
						const uint8_t *obj_buf)
{
	struct pcep_object_svec *obj =
		(struct pcep_object_svec *)common_object_create(
			hdr, sizeof(struct pcep_object_svec));

	obj->flag_link_diverse = (obj_buf[3] & OBJECT_SVEC_FLAG_L);
	obj->flag_node_diverse = (obj_buf[3] & OBJECT_SVEC_FLAG_N);
	obj->flag_srlg_diverse = (obj_buf[3] & OBJECT_SVEC_FLAG_S);

	if (hdr->encoded_object_length > LENGTH_2WORDS) {
		obj->request_id_list = dll_initialize();
		uint16_t index = 1;
		uint32_t *uint32_ptr = (uint32_t *)obj_buf;
		for (;
		     index < ((hdr->encoded_object_length - LENGTH_2WORDS) / 4);
		     index++) {
			uint32_t *req_id_ptr = pceplib_malloc(PCEPLIB_MESSAGES,
							      sizeof(uint32_t));
			*req_id_ptr = uint32_ptr[index];
			dll_append(obj->request_id_list, req_id_ptr);
		}
	}

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_error(struct pcep_object_header *hdr,
						 const uint8_t *obj_buf)
{
	struct pcep_object_error *obj =
		(struct pcep_object_error *)common_object_create(
			hdr, sizeof(struct pcep_object_error));

	obj->error_type = obj_buf[2];
	obj->error_value = obj_buf[3];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_close(struct pcep_object_header *hdr,
						 const uint8_t *obj_buf)
{
	struct pcep_object_close *obj =
		(struct pcep_object_close *)common_object_create(
			hdr, sizeof(struct pcep_object_close));

	obj->reason = obj_buf[3];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_srp(struct pcep_object_header *hdr,
					       const uint8_t *obj_buf)
{
	struct pcep_object_srp *obj =
		(struct pcep_object_srp *)common_object_create(
			hdr, sizeof(struct pcep_object_srp));

	obj->flag_lsp_remove = (obj_buf[3] & OBJECT_SRP_FLAG_R);
	obj->srp_id_number = ntohl(*((uint32_t *)(obj_buf + 4)));

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *pcep_decode_obj_lsp(struct pcep_object_header *hdr,
					       const uint8_t *obj_buf)
{
	struct pcep_object_lsp *obj =
		(struct pcep_object_lsp *)common_object_create(
			hdr, sizeof(struct pcep_object_lsp));

	obj->flag_d = (obj_buf[3] & OBJECT_LSP_FLAG_D);
	obj->flag_s = (obj_buf[3] & OBJECT_LSP_FLAG_S);
	obj->flag_r = (obj_buf[3] & OBJECT_LSP_FLAG_R);
	obj->flag_a = (obj_buf[3] & OBJECT_LSP_FLAG_A);
	obj->flag_c = (obj_buf[3] & OBJECT_LSP_FLAG_C);
	obj->operational_status = ((obj_buf[3] >> 4) & 0x07);
	obj->plsp_id = ((ntohl(*((uint32_t *)obj_buf)) >> 12) & 0x000fffff);

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_vendor_info(struct pcep_object_header *hdr,
			    const uint8_t *obj_buf)
{
	struct pcep_object_vendor_info *obj =
		(struct pcep_object_vendor_info *)common_object_create(
			hdr, sizeof(struct pcep_object_vendor_info));

	obj->enterprise_number = ntohl(*((uint32_t *)(obj_buf)));
	obj->enterprise_specific_info = ntohl(*((uint32_t *)(obj_buf + 4)));
	if (obj->enterprise_number == ENTERPRISE_NUMBER_CISCO
	    && obj->enterprise_specific_info == ENTERPRISE_COLOR_CISCO)
		obj->enterprise_specific_info1 =
			ntohl(*((uint32_t *)(obj_buf + 8)));
	else
		obj->enterprise_specific_info1 = 0;

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_inter_layer(struct pcep_object_header *hdr,
			    const uint8_t *obj_buf)
{
	struct pcep_object_inter_layer *obj =
		(struct pcep_object_inter_layer *)common_object_create(
			hdr, sizeof(struct pcep_object_inter_layer));
	obj->flag_t = (obj_buf[3] & OBJECT_INTER_LAYER_FLAG_T);
	obj->flag_m = (obj_buf[3] & OBJECT_INTER_LAYER_FLAG_M);
	obj->flag_i = (obj_buf[3] & OBJECT_INTER_LAYER_FLAG_I);

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_switch_layer(struct pcep_object_header *hdr,
			     const uint8_t *obj_buf)
{
	struct pcep_object_switch_layer *obj =
		(struct pcep_object_switch_layer *)common_object_create(
			hdr, sizeof(struct pcep_object_switch_layer));
	obj->switch_layer_rows = dll_initialize();
	int num_rows = ((hdr->encoded_object_length - 4) / 4);
	uint8_t buf_index = 0;

	int i = 0;
	for (; i < num_rows; i++) {
		struct pcep_object_switch_layer_row *row = pceplib_malloc(
			PCEPLIB_MESSAGES,
			sizeof(struct pcep_object_switch_layer_row));
		row->lsp_encoding_type = obj_buf[buf_index];
		row->switching_type = obj_buf[buf_index + 1];
		row->flag_i =
			(obj_buf[buf_index + 3] & OBJECT_SWITCH_LAYER_FLAG_I);
		dll_append(obj->switch_layer_rows, row);

		buf_index += LENGTH_1WORD;
	}

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_req_adap_cap(struct pcep_object_header *hdr,
			     const uint8_t *obj_buf)
{
	struct pcep_object_req_adap_cap *obj =
		(struct pcep_object_req_adap_cap *)common_object_create(
			hdr, sizeof(struct pcep_object_req_adap_cap));

	obj->switching_capability = obj_buf[0];
	obj->encoding = obj_buf[1];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_server_ind(struct pcep_object_header *hdr,
			   const uint8_t *obj_buf)
{
	struct pcep_object_server_indication *obj =
		(struct pcep_object_server_indication *)common_object_create(
			hdr, sizeof(struct pcep_object_server_indication));

	obj->switching_capability = obj_buf[0];
	obj->encoding = obj_buf[1];

	return (struct pcep_object_header *)obj;
}

struct pcep_object_header *
pcep_decode_obj_objective_function(struct pcep_object_header *hdr,
				   const uint8_t *obj_buf)
{
	struct pcep_object_objective_function *obj =
		(struct pcep_object_objective_function *)common_object_create(
			hdr, sizeof(struct pcep_object_objective_function));

	uint16_t *uint16_ptr = (uint16_t *)obj_buf;
	obj->of_code = ntohs(*uint16_ptr);

	return (struct pcep_object_header *)obj;
}

void set_ro_subobj_fields(struct pcep_object_ro_subobj *subobj, bool flag_l,
			  uint8_t subobj_type)
{
	subobj->flag_subobj_loose_hop = flag_l;
	subobj->ro_subobj_type = subobj_type;
}

void decode_ipv6(const uint32_t *src, struct in6_addr *dst_ipv6)
{
	memcpy(dst_ipv6, src, sizeof(struct in6_addr));
}
struct pcep_object_header *pcep_decode_obj_ro(struct pcep_object_header *hdr,
					      const uint8_t *obj_buf)
{
	struct pcep_object_ro *obj =
		(struct pcep_object_ro *)common_object_create(
			hdr, sizeof(struct pcep_object_ro));
	obj->sub_objects = dll_initialize();

	/* RO Subobject format
	 *
	 *  0                   1
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
	 *  |L|    Type     |     Length    | (Subobject contents)          |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------//----------------+
	 */

	uint16_t read_count = 0;
	int num_sub_objects = 1;
	uint32_t *uint32_ptr;
	uint16_t obj_body_length =
		hdr->encoded_object_length - OBJECT_HEADER_LENGTH;

	while ((obj_body_length - read_count) > OBJECT_RO_SUBOBJ_HEADER_LENGTH
	       && num_sub_objects < MAX_ITERATIONS) {
		num_sub_objects++;
		/* Read the Sub-Object Header */
		bool flag_l = (obj_buf[read_count] & 0x80);
		uint8_t subobj_type = (obj_buf[read_count++] & 0x7f);
		uint8_t subobj_length = obj_buf[read_count++];

		if (subobj_length <= OBJECT_RO_SUBOBJ_HEADER_LENGTH) {
			pcep_log(LOG_INFO,
				 "%s: Invalid ro subobj type [%d] length [%d]",
				 __func__, subobj_type, subobj_length);
			pceplib_free(PCEPLIB_MESSAGES, obj);
			return NULL;
		}

		switch (subobj_type) {
		case RO_SUBOBJ_TYPE_IPV4: {
			struct pcep_ro_subobj_ipv4 *ipv4 = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_ipv4));
			ipv4->ro_subobj.flag_subobj_loose_hop = flag_l;
			ipv4->ro_subobj.ro_subobj_type = subobj_type;
			uint32_ptr = (uint32_t *)(obj_buf + read_count);
			ipv4->ip_addr.s_addr = *uint32_ptr;
			read_count += LENGTH_1WORD;
			ipv4->prefix_length = obj_buf[read_count++];
			ipv4->flag_local_protection =
				(obj_buf[read_count++]
				 & OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT);

			dll_append(obj->sub_objects, ipv4);
		} break;

		case RO_SUBOBJ_TYPE_IPV6: {
			struct pcep_ro_subobj_ipv6 *ipv6 = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_ipv6));
			ipv6->ro_subobj.flag_subobj_loose_hop = flag_l;
			ipv6->ro_subobj.ro_subobj_type = subobj_type;
			decode_ipv6((uint32_t *)obj_buf, &ipv6->ip_addr);
			read_count += LENGTH_4WORDS;
			ipv6->prefix_length = obj_buf[read_count++];
			ipv6->flag_local_protection =
				(obj_buf[read_count++]
				 & OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT);

			dll_append(obj->sub_objects, ipv6);
		} break;

		case RO_SUBOBJ_TYPE_LABEL: {
			struct pcep_ro_subobj_32label *label = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_32label));
			label->ro_subobj.flag_subobj_loose_hop = flag_l;
			label->ro_subobj.ro_subobj_type = subobj_type;
			label->flag_global_label =
				(obj_buf[read_count++]
				 & OBJECT_SUBOBJ_LABEL_FLAG_GLOGAL);
			label->class_type = obj_buf[read_count++];
			label->label = ntohl(obj_buf[read_count]);
			read_count += LENGTH_1WORD;

			dll_append(obj->sub_objects, label);
		} break;

		case RO_SUBOBJ_TYPE_UNNUM: {
			struct pcep_ro_subobj_unnum *unum = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_unnum));
			unum->ro_subobj.flag_subobj_loose_hop = flag_l;
			unum->ro_subobj.ro_subobj_type = subobj_type;
			set_ro_subobj_fields(
				(struct pcep_object_ro_subobj *)unum, flag_l,
				subobj_type);
			uint32_ptr = (uint32_t *)(obj_buf + read_count);
			unum->interface_id = ntohl(uint32_ptr[0]);
			unum->router_id.s_addr = uint32_ptr[1];
			read_count += 2;

			dll_append(obj->sub_objects, unum);
		} break;

		case RO_SUBOBJ_TYPE_ASN: {
			struct pcep_ro_subobj_asn *asn = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_asn));
			asn->ro_subobj.flag_subobj_loose_hop = flag_l;
			asn->ro_subobj.ro_subobj_type = subobj_type;
			uint16_t *uint16_ptr =
				(uint16_t *)(obj_buf + read_count);
			asn->asn = ntohs(*uint16_ptr);
			read_count += 2;

			dll_append(obj->sub_objects, asn);
		} break;

		case RO_SUBOBJ_TYPE_SR: {
			/* SR-ERO subobject format
			 *
			 * 0                   1                   2 3 0 1 2 3 4
			 * 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |L|   Type=36   |     Length    |  NT   |     Flags
			 * |F|S|C|M|
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * |                         SID (optional) |
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 * //                   NAI (variable, optional) //
			 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */

			struct pcep_ro_subobj_sr *sr_subobj = pceplib_malloc(
				PCEPLIB_MESSAGES,
				sizeof(struct pcep_ro_subobj_sr));
			sr_subobj->ro_subobj.flag_subobj_loose_hop = flag_l;
			sr_subobj->ro_subobj.ro_subobj_type = subobj_type;
			dll_append(obj->sub_objects, sr_subobj);

			sr_subobj->nai_list = dll_initialize();
			sr_subobj->nai_type =
				((obj_buf[read_count++] >> 4) & 0x0f);
			sr_subobj->flag_f =
				(obj_buf[read_count] & OBJECT_SUBOBJ_SR_FLAG_F);
			sr_subobj->flag_s =
				(obj_buf[read_count] & OBJECT_SUBOBJ_SR_FLAG_S);
			sr_subobj->flag_c =
				(obj_buf[read_count] & OBJECT_SUBOBJ_SR_FLAG_C);
			sr_subobj->flag_m =
				(obj_buf[read_count] & OBJECT_SUBOBJ_SR_FLAG_M);
			read_count++;

			/* If the sid_absent flag is true, then dont decode the
			 * sid */
			uint32_ptr = (uint32_t *)(obj_buf + read_count);
			if (sr_subobj->flag_s == false) {
				sr_subobj->sid = ntohl(*uint32_ptr);
				read_count += LENGTH_1WORD;
				uint32_ptr += 1;
			}

			switch (sr_subobj->nai_type) {
			case PCEP_SR_SUBOBJ_NAI_IPV4_NODE: {
				struct in_addr *ipv4 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in_addr));
				ipv4->s_addr = *uint32_ptr;
				dll_append(sr_subobj->nai_list, ipv4);
				read_count += LENGTH_1WORD;
			} break;

			case PCEP_SR_SUBOBJ_NAI_IPV6_NODE: {
				struct in6_addr *ipv6 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in6_addr));
				decode_ipv6(uint32_ptr, ipv6);
				dll_append(sr_subobj->nai_list, ipv6);
				read_count += LENGTH_4WORDS;
			} break;

			case PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY: {
				struct in_addr *ipv4 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[0];
				dll_append(sr_subobj->nai_list, ipv4);

				ipv4 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[1];
				dll_append(sr_subobj->nai_list, ipv4);

				ipv4 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[2];
				dll_append(sr_subobj->nai_list, ipv4);

				ipv4 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[3];
				dll_append(sr_subobj->nai_list, ipv4);

				read_count += LENGTH_4WORDS;
			} break;

			case PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY: {
				struct in_addr *ipv4 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[0];
				dll_append(sr_subobj->nai_list, ipv4);

				ipv4 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[1];
				dll_append(sr_subobj->nai_list, ipv4);

				read_count += LENGTH_2WORDS;
			} break;

			case PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY: {
				struct in6_addr *ipv6 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in6_addr));
				decode_ipv6(uint32_ptr, ipv6);
				dll_append(sr_subobj->nai_list, ipv6);

				ipv6 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in6_addr));
				decode_ipv6(uint32_ptr + 4, ipv6);
				dll_append(sr_subobj->nai_list, ipv6);

				read_count += LENGTH_8WORDS;
			} break;

			case PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY: {
				struct in6_addr *ipv6 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in6_addr));
				decode_ipv6(uint32_ptr, ipv6);
				dll_append(sr_subobj->nai_list, ipv6);

				struct in_addr *ipv4 =
					pceplib_malloc(PCEPLIB_MESSAGES,
						       sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[4];
				dll_append(sr_subobj->nai_list, ipv4);

				ipv6 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in6_addr));
				decode_ipv6(uint32_ptr + 5, ipv6);
				dll_append(sr_subobj->nai_list, ipv6);

				ipv4 = pceplib_malloc(PCEPLIB_MESSAGES,
						      sizeof(struct in_addr));
				ipv4->s_addr = uint32_ptr[9];
				dll_append(sr_subobj->nai_list, ipv4);

				read_count += LENGTH_10WORDS;
			} break;

			case PCEP_SR_SUBOBJ_NAI_ABSENT:
			default:
				break;
			}
		} break;

		default:
			pcep_log(
				LOG_INFO,
				"%s: pcep_decode_obj_ro skipping unrecognized sub-object type [%d]",
				__func__, subobj_type);
			read_count += subobj_length;
			break;
		}
	}

	return (struct pcep_object_header *)obj;
}
