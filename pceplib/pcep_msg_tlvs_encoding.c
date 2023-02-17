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
 * Encoding and decoding for PCEP Object TLVs.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif /* __FreeBSD__ */
#include <stdlib.h>
#include <string.h>

#include "pcep.h"
#include "pcep_msg_encoding.h"
#include "pcep_msg_tlvs.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

void write_tlv_header(struct pcep_object_tlv_header *tlv_hdr,
		      uint16_t tlv_length, struct pcep_versioning *versioning,
		      uint8_t *buf);
void pcep_decode_tlv_hdr(const uint8_t *tlv_buf,
			 struct pcep_object_tlv_header *tlv_hdr);

/*
 * forward declarations for initialize_tlv_encoders()
 */
uint16_t pcep_encode_tlv_no_path_vector(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf);
uint16_t
pcep_encode_tlv_stateful_pce_capability(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_symbolic_path_name(struct pcep_object_tlv_header *tlv,
					    struct pcep_versioning *versioning,
					    uint8_t *tlv_body_buf);
uint16_t
pcep_encode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf);
uint16_t
pcep_encode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_lsp_error_code(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_rsvp_error_spec(struct pcep_object_tlv_header *tlv,
					 struct pcep_versioning *versioning,
					 uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_lsp_db_version(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_speaker_entity_id(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_sr_pce_capability(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_path_setup_type(struct pcep_object_tlv_header *tlv,
					 struct pcep_versioning *versioning,
					 uint8_t *tlv_body_buf);
uint16_t
pcep_encode_tlv_path_setup_type_capability(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_pol_id(struct pcep_object_tlv_header *tlv,
				struct pcep_versioning *versioning,
				uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_pol_name(struct pcep_object_tlv_header *tlv,
				  struct pcep_versioning *versioning,
				  uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_cpath_id(struct pcep_object_tlv_header *tlv,
				  struct pcep_versioning *versioning,
				  uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_cpath_preference(struct pcep_object_tlv_header *tlv,
					  struct pcep_versioning *versioning,
					  uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_vendor_info(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_arbitrary(struct pcep_object_tlv_header *tlv,
				   struct pcep_versioning *versioning,
				   uint8_t *tlv_body_buf);
uint16_t pcep_encode_tlv_of_list(struct pcep_object_tlv_header *tlv,
				 struct pcep_versioning *versioning,
				 uint8_t *tlv_body_buf);
typedef uint16_t (*tlv_encoder_funcptr)(struct pcep_object_tlv_header *,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf);

#define MAX_TLV_ENCODER_INDEX 65533 + 1 // 65

#define PCEP_TLV_ENCODERS_ARGS                                                 \
	struct pcep_object_tlv_header *, struct pcep_versioning *versioning,   \
		uint8_t *tlv_body_buf
uint16_t (*const tlv_encoders[MAX_TLV_ENCODER_INDEX])(
	PCEP_TLV_ENCODERS_ARGS) = {
	[PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR] = pcep_encode_tlv_no_path_vector,
	[PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY] =
		pcep_encode_tlv_stateful_pce_capability,
	[PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME] =
		pcep_encode_tlv_symbolic_path_name,
	[PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS] =
		pcep_encode_tlv_ipv4_lsp_identifiers,
	[PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS] =
		pcep_encode_tlv_ipv6_lsp_identifiers,
	[PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE] = pcep_encode_tlv_lsp_error_code,
	[PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC] = pcep_encode_tlv_rsvp_error_spec,
	[PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION] = pcep_encode_tlv_lsp_db_version,
	[PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID] =
		pcep_encode_tlv_speaker_entity_id,
	[PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY] =
		pcep_encode_tlv_sr_pce_capability,
	[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE] = pcep_encode_tlv_path_setup_type,
	[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY] =
		pcep_encode_tlv_path_setup_type_capability,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID] = pcep_encode_tlv_pol_id,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME] = pcep_encode_tlv_pol_name,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID] = pcep_encode_tlv_cpath_id,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE] =
		pcep_encode_tlv_cpath_preference,
	[PCEP_OBJ_TLV_TYPE_VENDOR_INFO] = pcep_encode_tlv_vendor_info,
	[PCEP_OBJ_TLV_TYPE_ARBITRARY] = pcep_encode_tlv_arbitrary,
	[PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST] = pcep_encode_tlv_of_list,
};
/*
 * forward declarations for initialize_tlv_decoders()
 */
struct pcep_object_tlv_header *
pcep_decode_tlv_no_path_vector(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_stateful_pce_capability(struct pcep_object_tlv_header *tlv_hdr,
					const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_symbolic_path_name(struct pcep_object_tlv_header *tlv_hdr,
				   const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv_header *tlv_hdr,
				     const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv_header *tlv_hdr,
				     const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_lsp_error_code(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_rsvp_error_spec(struct pcep_object_tlv_header *tlv_hdr,
				const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_lsp_db_version(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_speaker_entity_id(struct pcep_object_tlv_header *tlv_hdr,
				  const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_sr_pce_capability(struct pcep_object_tlv_header *tlv_hdr,
				  const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_path_setup_type(struct pcep_object_tlv_header *tlv_hdr,
				const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *pcep_decode_tlv_path_setup_type_capability(
	struct pcep_object_tlv_header *tlv_hdr, const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_pol_id(struct pcep_object_tlv_header *tlv_hdr,
		       const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_pol_name(struct pcep_object_tlv_header *tlv_hdr,
			 const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_cpath_id(struct pcep_object_tlv_header *tlv_hdr,
			 const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_cpath_preference(struct pcep_object_tlv_header *tlv_hdr,
				 const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_vendor_info(struct pcep_object_tlv_header *tlv_hdr,
			    const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_arbitrary(struct pcep_object_tlv_header *tlv_hdr,
			  const uint8_t *tlv_body_buf);
struct pcep_object_tlv_header *
pcep_decode_tlv_of_list(struct pcep_object_tlv_header *tlv_hdr,
			const uint8_t *tlv_body_buf);
typedef struct pcep_object_tlv_header *(*tlv_decoder_funcptr)(
	struct pcep_object_tlv_header *tlv_hdr, const uint8_t *tlv_body_buf);

// tlv_decoder_funcptr tlv_decoders[MAX_TLV_ENCODER_INDEX];

#define PCEP_TLV_DECODERS_ARGS                                                 \
	struct pcep_object_tlv_header *tlv_hdr, const uint8_t *tlv_body_buf

struct pcep_object_tlv_header *(*const tlv_decoders[MAX_TLV_ENCODER_INDEX])(
	PCEP_TLV_DECODERS_ARGS) = {
	[PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR] = pcep_decode_tlv_no_path_vector,
	[PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY] =
		pcep_decode_tlv_stateful_pce_capability,
	[PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME] =
		pcep_decode_tlv_symbolic_path_name,
	[PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS] =
		pcep_decode_tlv_ipv4_lsp_identifiers,
	[PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS] =
		pcep_decode_tlv_ipv6_lsp_identifiers,
	[PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE] = pcep_decode_tlv_lsp_error_code,
	[PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC] = pcep_decode_tlv_rsvp_error_spec,
	[PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION] = pcep_decode_tlv_lsp_db_version,
	[PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID] =
		pcep_decode_tlv_speaker_entity_id,
	[PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY] =
		pcep_decode_tlv_sr_pce_capability,
	[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE] = pcep_decode_tlv_path_setup_type,
	[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY] =
		pcep_decode_tlv_path_setup_type_capability,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID] = pcep_decode_tlv_pol_id,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME] = pcep_decode_tlv_pol_name,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID] = pcep_decode_tlv_cpath_id,
	[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE] =
		pcep_decode_tlv_cpath_preference,
	[PCEP_OBJ_TLV_TYPE_VENDOR_INFO] = pcep_decode_tlv_vendor_info,
	[PCEP_OBJ_TLV_TYPE_ARBITRARY] = pcep_decode_tlv_arbitrary,
	[PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST] = pcep_decode_tlv_of_list,
};

static void initialize_tlv_coders(void)
{
	static bool initialized = false;

	if (initialized == true) {
		return;
	}

	initialized = true;

	/* Encoders */
	/*
	memset(tlv_encoders, 0, sizeof(tlv_encoder_funcptr) *
	MAX_TLV_ENCODER_INDEX); tlv_encoders[PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR] =
	pcep_encode_tlv_no_path_vector;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY]     =
	pcep_encode_tlv_stateful_pce_capability;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME]          =
	pcep_encode_tlv_symbolic_path_name;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS]        =
	pcep_encode_tlv_ipv4_lsp_identifiers;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS]        =
	pcep_encode_tlv_ipv6_lsp_identifiers;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE]              =
	pcep_encode_tlv_lsp_error_code;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC]             =
	pcep_encode_tlv_rsvp_error_spec;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION]              =
	pcep_encode_tlv_lsp_db_version;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID]           =
	pcep_encode_tlv_speaker_entity_id;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY]           =
	pcep_encode_tlv_sr_pce_capability;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE]             =
	pcep_encode_tlv_path_setup_type;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY]  =
	pcep_encode_tlv_path_setup_type_capability;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID]             =
	pcep_encode_tlv_pol_id;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME] =
	pcep_encode_tlv_pol_name;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID] =
	pcep_encode_tlv_cpath_id;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE]   =
	pcep_encode_tlv_cpath_preference;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_VENDOR_INFO]                 =
	pcep_encode_tlv_vendor_info; tlv_encoders[PCEP_OBJ_TLV_TYPE_ARBITRARY] =
	pcep_encode_tlv_arbitrary;
	tlv_encoders[PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST]     =
	pcep_encode_tlv_of_list;
	*/

	/* Decoders */
	/*
	memset(tlv_decoders, 0, sizeof(tlv_decoder_funcptr) *
	MAX_TLV_ENCODER_INDEX); tlv_decoders[PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR] =
	pcep_decode_tlv_no_path_vector;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY]     =
	pcep_decode_tlv_stateful_pce_capability;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME]          =
	pcep_decode_tlv_symbolic_path_name;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS]        =
	pcep_decode_tlv_ipv4_lsp_identifiers;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS]        =
	pcep_decode_tlv_ipv6_lsp_identifiers;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE]              =
	pcep_decode_tlv_lsp_error_code;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC]             =
	pcep_decode_tlv_rsvp_error_spec;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION]              =
	pcep_decode_tlv_lsp_db_version;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID]           =
	pcep_decode_tlv_speaker_entity_id;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY]           =
	pcep_decode_tlv_sr_pce_capability;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE]             =
	pcep_decode_tlv_path_setup_type;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY]  =
	pcep_decode_tlv_path_setup_type_capability;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID]             =
	pcep_decode_tlv_pol_id;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME] =
	pcep_decode_tlv_pol_name;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID] =
	pcep_decode_tlv_cpath_id;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE]   =
	pcep_decode_tlv_cpath_preference;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_VENDOR_INFO]                 =
	pcep_decode_tlv_vendor_info; tlv_decoders[PCEP_OBJ_TLV_TYPE_ARBITRARY] =
	pcep_decode_tlv_arbitrary;
	tlv_decoders[PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST]     =
	pcep_decode_tlv_of_list;
	*/
}

uint16_t pcep_encode_tlv(struct pcep_object_tlv_header *tlv_hdr,
			 struct pcep_versioning *versioning, uint8_t *buf)
{
	initialize_tlv_coders();

	if (tlv_hdr->type >= MAX_TLV_ENCODER_INDEX) {
		pcep_log(LOG_INFO,
			 "%s: Cannot encode unknown Object class [%d]",
			 __func__, tlv_hdr->type);
		return 0;
	}

	tlv_encoder_funcptr tlv_encoder = tlv_encoders[tlv_hdr->type];
	if (tlv_encoder == NULL) {
		pcep_log(LOG_INFO,
			 "%s: No object encoder found for Object class [%d]",
			 __func__, tlv_hdr->type);
		return 0;
	}

	/* Notice: The length in the TLV header does not include the TLV header,
	 * so the length returned from the tlv_encoder() is only the TLV body.
	 */
	uint16_t tlv_length =
		tlv_encoder(tlv_hdr, versioning, buf + TLV_HEADER_LENGTH);
	write_tlv_header(tlv_hdr, tlv_length, versioning, buf);
	tlv_hdr->encoded_tlv = buf;
	tlv_hdr->encoded_tlv_length = tlv_length;

	return normalize_pcep_tlv_length(tlv_length + TLV_HEADER_LENGTH);
}

/* TLV Header format
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Type (2 bytes)        |         Length (2 bytes)      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Value (Variable)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

void write_tlv_header(struct pcep_object_tlv_header *tlv_hdr,
		      uint16_t tlv_length, struct pcep_versioning *versioning,
		      uint8_t *buf)
{
	(void)versioning;
	uint16_t *uint16_ptr = (uint16_t *)buf;
	uint16_ptr[0] = htons(tlv_hdr->type);
	uint16_ptr[1] = htons(tlv_length);
}

/*
 * Functions to encode TLVs
 */

uint16_t pcep_encode_tlv_no_path_vector(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_nopath_vector *nopath_tlv =
		(struct pcep_object_tlv_nopath_vector *)tlv;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	*uint32_ptr = htonl(nopath_tlv->error_code);

	return LENGTH_1WORD;
}

uint16_t
pcep_encode_tlv_stateful_pce_capability(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_stateful_pce_capability *spc_tlv =
		(struct pcep_object_tlv_stateful_pce_capability *)tlv;
	tlv_body_buf[3] =
		((spc_tlv->flag_f_triggered_initial_sync == true
			  ? TLV_STATEFUL_PCE_CAP_FLAG_F
			  : 0x00)
		 | (spc_tlv->flag_d_delta_lsp_sync == true
			    ? TLV_STATEFUL_PCE_CAP_FLAG_D
			    : 0x00)
		 | (spc_tlv->flag_t_triggered_resync == true
			    ? TLV_STATEFUL_PCE_CAP_FLAG_T
			    : 0x00)
		 | (spc_tlv->flag_i_lsp_instantiation_capability == true
			    ? TLV_STATEFUL_PCE_CAP_FLAG_I
			    : 0x00)
		 | (spc_tlv->flag_s_include_db_version == true
			    ? TLV_STATEFUL_PCE_CAP_FLAG_S
			    : 0x00)
		 | (spc_tlv->flag_u_lsp_update_capability == true
			    ? TLV_STATEFUL_PCE_CAP_FLAG_U
			    : 0x00));

	return LENGTH_1WORD;
}

uint16_t pcep_encode_tlv_symbolic_path_name(struct pcep_object_tlv_header *tlv,
					    struct pcep_versioning *versioning,
					    uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_symbolic_path_name *spn_tlv =
		(struct pcep_object_tlv_symbolic_path_name *)tlv;
	memcpy(tlv_body_buf, spn_tlv->symbolic_path_name,
	       spn_tlv->symbolic_path_name_length);

	return spn_tlv->symbolic_path_name_length;
}

uint16_t
pcep_encode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_ipv4_lsp_identifier *ipv4_lsp =
		(struct pcep_object_tlv_ipv4_lsp_identifier *)tlv;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	uint32_ptr[0] = ipv4_lsp->ipv4_tunnel_sender.s_addr;
	/* uint32_t[1] is lsp_id and tunnel_id, below */
	uint32_ptr[2] = ipv4_lsp->extended_tunnel_id.s_addr;
	uint32_ptr[3] = ipv4_lsp->ipv4_tunnel_endpoint.s_addr;

	uint16_t *uint16_ptr = (uint16_t *)(tlv_body_buf + LENGTH_1WORD);
	uint16_ptr[0] = htons(ipv4_lsp->lsp_id);
	uint16_ptr[1] = htons(ipv4_lsp->tunnel_id);

	return LENGTH_4WORDS;
}

uint16_t
pcep_encode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_ipv6_lsp_identifier *ipv6_lsp =
		(struct pcep_object_tlv_ipv6_lsp_identifier *)tlv;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	encode_ipv6(&ipv6_lsp->ipv6_tunnel_sender, uint32_ptr);
	encode_ipv6(&ipv6_lsp->extended_tunnel_id, uint32_ptr + 5);
	encode_ipv6(&ipv6_lsp->ipv6_tunnel_endpoint, uint32_ptr + 9);

	uint16_t *uint16_ptr = (uint16_t *)(tlv_body_buf + LENGTH_4WORDS);
	uint16_ptr[0] = htons(ipv6_lsp->lsp_id);
	uint16_ptr[1] = htons(ipv6_lsp->tunnel_id);

	return LENGTH_13WORDS;
}

uint16_t pcep_encode_tlv_lsp_error_code(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_lsp_error_code *lsp_error_tlv =
		(struct pcep_object_tlv_lsp_error_code *)tlv;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	*uint32_ptr = htonl(lsp_error_tlv->lsp_error_code);

	return LENGTH_1WORD;
}

uint16_t pcep_encode_tlv_rsvp_error_spec(struct pcep_object_tlv_header *tlv,
					 struct pcep_versioning *versioning,
					 uint8_t *tlv_body_buf)
{
	/* Same decode tlv function for both types:
	   pcep_create_tlv_rsvp_ipv4_error_spec(tlv);
	   pcep_create_tlv_rsvp_ipv6_error_spec(tlv); */

	/*  RSVP Object Header
	 *
	 *       0             1              2             3
	 *  +-------------+-------------+-------------+-------------+
	 *  |       Length (bytes)      |  Class-Num  |   C-Type    |
	 *  +-------------+-------------+-------------+-------------+
	 *  |                                                       |
	 *  //                  (Object contents)                   //
	 *  |                                                       |
	 *  +-------------+-------------+-------------+-------------+
	 *
	 * IPv4 ERROR_SPEC object: Class = 6, C-Type = 1
	 *  +-------------+-------------+-------------+-------------+
	 *  |            IPv4 Error Node Address (4 bytes)          |
	 *  +-------------+-------------+-------------+-------------+
	 *  |    Flags    |  Error Code |        Error Value        |
	 *  +-------------+-------------+-------------+-------------+
	 *
	 * IPv6 ERROR_SPEC object: Class = 6, C-Type = 2
	 *  +-------------+-------------+-------------+-------------+
	 *  |            IPv6 Error Node Address (16 bytes)         |
	 *  +-------------+-------------+-------------+-------------+
	 *  |    Flags    |  Error Code |        Error Value        |
	 *  +-------------+-------------+-------------+-------------+
	 */

	(void)versioning;
	struct pcep_object_tlv_rsvp_error_spec *rsvp_hdr =
		(struct pcep_object_tlv_rsvp_error_spec *)tlv;
	tlv_body_buf[2] = rsvp_hdr->class_num;
	tlv_body_buf[3] = rsvp_hdr->c_type;

	uint16_t *length_ptr = (uint16_t *)tlv_body_buf;
	uint32_t *uint32_ptr = (uint32_t *)(tlv_body_buf + LENGTH_1WORD);
	if (rsvp_hdr->c_type == RSVP_ERROR_SPEC_IPV4_CTYPE) {
		*length_ptr = htons(LENGTH_3WORDS);
		*uint32_ptr =
			rsvp_hdr->error_spec_ip.ipv4_error_node_address.s_addr;
		tlv_body_buf[LENGTH_2WORDS + 1] = rsvp_hdr->error_code;
		uint16_t *uint16_ptr =
			(uint16_t *)(tlv_body_buf + LENGTH_2WORDS + 2);
		*uint16_ptr = htons(rsvp_hdr->error_value);

		return LENGTH_3WORDS;
	} else if (rsvp_hdr->c_type == RSVP_ERROR_SPEC_IPV6_CTYPE) {
		*length_ptr = htons(LENGTH_6WORDS);
		encode_ipv6(&rsvp_hdr->error_spec_ip.ipv6_error_node_address,
			    uint32_ptr);
		tlv_body_buf[LENGTH_5WORDS + 1] = rsvp_hdr->error_code;
		uint16_t *uint16_ptr =
			(uint16_t *)(tlv_body_buf + LENGTH_5WORDS + 2);
		*uint16_ptr = htons(rsvp_hdr->error_value);

		return LENGTH_6WORDS;
	}

	return 0;
}

uint16_t pcep_encode_tlv_lsp_db_version(struct pcep_object_tlv_header *tlv,
					struct pcep_versioning *versioning,
					uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_lsp_db_version *lsp_db_ver =
		(struct pcep_object_tlv_lsp_db_version *)tlv;
	*((uint64_t *)tlv_body_buf) = htobe64(lsp_db_ver->lsp_db_version);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_tlv_speaker_entity_id(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_speaker_entity_identifier *speaker_id =
		(struct pcep_object_tlv_speaker_entity_identifier *)tlv;
	if (speaker_id->speaker_entity_id_list == NULL) {
		return 0;
	}

	int index = 0;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	double_linked_list_node *node =
		speaker_id->speaker_entity_id_list->head;
	for (; node != NULL; node = node->next_node) {
		uint32_ptr[index++] = htonl(*((uint32_t *)node->data));
	}

	return speaker_id->speaker_entity_id_list->num_entries * LENGTH_1WORD;
}

uint16_t pcep_encode_tlv_sr_pce_capability(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_sr_pce_capability *sr_pce_cap =
		(struct pcep_object_tlv_sr_pce_capability *)tlv;
	tlv_body_buf[2] =
		((sr_pce_cap->flag_n == true ? TLV_SR_PCE_CAP_FLAG_N : 0x00)
		 | (sr_pce_cap->flag_x == true ? TLV_SR_PCE_CAP_FLAG_X : 0x00));
	tlv_body_buf[3] = sr_pce_cap->max_sid_depth;

	return LENGTH_1WORD;
}

uint16_t pcep_encode_tlv_path_setup_type(struct pcep_object_tlv_header *tlv,
					 struct pcep_versioning *versioning,
					 uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_path_setup_type *pst =
		(struct pcep_object_tlv_path_setup_type *)tlv;
	tlv_body_buf[3] = pst->path_setup_type;

	return LENGTH_1WORD;
}

uint16_t
pcep_encode_tlv_path_setup_type_capability(struct pcep_object_tlv_header *tlv,
					   struct pcep_versioning *versioning,
					   uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_path_setup_type_capability *pst_cap =
		(struct pcep_object_tlv_path_setup_type_capability *)tlv;
	if (pst_cap->pst_list == NULL) {
		return 0;
	}

	tlv_body_buf[3] = pst_cap->pst_list->num_entries;

	/* Index past the reserved and NumPSTs fields */
	int index = 4;
	double_linked_list_node *node = pst_cap->pst_list->head;
	for (; node != NULL; node = node->next_node) {
		tlv_body_buf[index++] = *((uint8_t *)node->data);
	}

	uint16_t pst_length = normalize_pcep_tlv_length(
		LENGTH_1WORD + pst_cap->pst_list->num_entries);
	if (pst_cap->sub_tlv_list == NULL) {
		return pst_length;
	}

	/* Any padding used for the PSTs should not be included in the tlv
	 * header length */
	index = normalize_pcep_tlv_length(index);
	uint16_t sub_tlvs_length = 0;
	node = pst_cap->sub_tlv_list->head;
	for (; node != NULL; node = node->next_node) {
		struct pcep_object_tlv_header *sub_tlv =
			(struct pcep_object_tlv_header *)node->data;
		uint16_t sub_tlv_length = pcep_encode_tlv(sub_tlv, versioning,
							  tlv_body_buf + index);
		index += sub_tlv_length;
		sub_tlvs_length += sub_tlv_length;
	}

	return sub_tlvs_length + pst_length;
}
uint16_t pcep_encode_tlv_pol_id(struct pcep_object_tlv_header *tlv,
				struct pcep_versioning *versioning,
				uint8_t *tlv_body_buf)
{
	(void)versioning;
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	struct pcep_object_tlv_srpag_pol_id *ipv4 =
		(struct pcep_object_tlv_srpag_pol_id *)tlv;
	if (ipv4->is_ipv4) {
		uint32_ptr[0] = htonl(ipv4->color);
		uint32_ptr[1] = ipv4->end_point.ipv4.s_addr;
		return LENGTH_2WORDS;
	} else {
		struct pcep_object_tlv_srpag_pol_id *ipv6 =
			(struct pcep_object_tlv_srpag_pol_id *)tlv;
		uint32_ptr[0] = htonl(ipv6->color);
		encode_ipv6(&ipv6->end_point.ipv6, &uint32_ptr[1]);
		return LENGTH_5WORDS;
	}
}

uint16_t pcep_encode_tlv_pol_name(struct pcep_object_tlv_header *tlv,
				  struct pcep_versioning *versioning,
				  uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_srpag_pol_name *pol_name_tlv =
		(struct pcep_object_tlv_srpag_pol_name *)tlv;
	memcpy(tlv_body_buf, pol_name_tlv->name, pol_name_tlv->name_length);

	return normalize_pcep_tlv_length(pol_name_tlv->name_length);
}

uint16_t pcep_encode_tlv_cpath_id(struct pcep_object_tlv_header *tlv,
				  struct pcep_versioning *versioning,
				  uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_srpag_cp_id *cpath_id_tlv =
		(struct pcep_object_tlv_srpag_cp_id *)tlv;

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	tlv_body_buf[0] = cpath_id_tlv->proto;
	uint32_ptr[1] = htonl(cpath_id_tlv->orig_asn);
	encode_ipv6(&cpath_id_tlv->orig_addres, &uint32_ptr[2]);
	uint32_ptr[6] = htonl(cpath_id_tlv->discriminator);

	return sizeof(cpath_id_tlv->proto) + sizeof(cpath_id_tlv->orig_asn)
	       + sizeof(cpath_id_tlv->orig_addres)
	       + sizeof(cpath_id_tlv->discriminator);
}

uint16_t pcep_encode_tlv_cpath_preference(struct pcep_object_tlv_header *tlv,
					  struct pcep_versioning *versioning,
					  uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_srpag_cp_pref *cpath_pref_tlv =
		(struct pcep_object_tlv_srpag_cp_pref *)tlv;

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	uint32_ptr[0] = htonl(cpath_pref_tlv->preference);

	return sizeof(cpath_pref_tlv->preference);
}

uint16_t pcep_encode_tlv_vendor_info(struct pcep_object_tlv_header *tlv,
				     struct pcep_versioning *versioning,
				     uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_vendor_info *vendor_info =
		(struct pcep_object_tlv_vendor_info *)tlv;

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	uint32_ptr[0] = htonl(vendor_info->enterprise_number);
	uint32_ptr[1] = htonl(vendor_info->enterprise_specific_info);

	return LENGTH_2WORDS;
}

uint16_t pcep_encode_tlv_arbitrary(struct pcep_object_tlv_header *tlv,
				   struct pcep_versioning *versioning,
				   uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_arbitrary *tlv_arbitrary =
		(struct pcep_object_tlv_arbitrary *)tlv;
	memcpy(tlv_body_buf, tlv_arbitrary->data, tlv_arbitrary->data_length);
	tlv->type = tlv_arbitrary->arbitraty_type;

	return tlv_arbitrary->data_length;
}

uint16_t pcep_encode_tlv_of_list(struct pcep_object_tlv_header *tlv,
				 struct pcep_versioning *versioning,
				 uint8_t *tlv_body_buf)
{
	(void)versioning;
	struct pcep_object_tlv_of_list *of_list =
		(struct pcep_object_tlv_of_list *)tlv;

	if (of_list->of_list == NULL) {
		return 0;
	}

	int index = 0;
	double_linked_list_node *node = of_list->of_list->head;
	while (node != NULL) {
		uint16_t *of_code = (uint16_t *)node->data;
		if (of_code == NULL) {
			return 0;
		}

		uint16_t *uint16_ptr = (uint16_t *)(tlv_body_buf + index);
		*uint16_ptr = *of_code;
		index += 2;

		node = node->next_node;
	}

	return of_list->of_list->num_entries * 2;
}

/*
 * Decoding functions
 */

void pcep_decode_tlv_hdr(const uint8_t *tlv_buf,
			 struct pcep_object_tlv_header *tlv_hdr)
{
	memset(tlv_hdr, 0, sizeof(struct pcep_object_tlv_header));

	uint16_t *uint16_ptr = (uint16_t *)tlv_buf;
	tlv_hdr->type = ntohs(uint16_ptr[0]);
	tlv_hdr->encoded_tlv_length = ntohs(uint16_ptr[1]);
	tlv_hdr->encoded_tlv = tlv_buf;
}

struct pcep_object_tlv_header *pcep_decode_tlv(const uint8_t *tlv_buf)
{
	initialize_tlv_coders();

	struct pcep_object_tlv_header tlv_hdr;
	/* Only initializes and decodes the Object Header: class, type, flags,
	 * and length */
	pcep_decode_tlv_hdr(tlv_buf, &tlv_hdr);

	if (tlv_hdr.type >= MAX_TLV_ENCODER_INDEX) {
		pcep_log(LOG_INFO, "%s: Cannot decode unknown TLV type [%d]",
			 __func__, tlv_hdr.type);
		return NULL;
	}

	tlv_decoder_funcptr tlv_decoder = NULL;
	if (tlv_hdr.type == PCEP_OBJ_TYPE_CISCO_BSID) {
		pcep_log(LOG_INFO,
			 "%s: Cisco BSID TLV decoder found for TLV type [%d]",
			 __func__, tlv_hdr.type);
		tlv_decoder = tlv_decoders[PCEP_OBJ_TLV_TYPE_ARBITRARY];
	} else {
		tlv_decoder = tlv_decoders[tlv_hdr.type];
	}
	if (tlv_decoder == NULL) {
		pcep_log(LOG_INFO, "%s: No TLV decoder found for TLV type [%d]",
			 __func__, tlv_hdr.type);
		return NULL;
	}

	return tlv_decoder(&tlv_hdr, tlv_buf + LENGTH_1WORD);
}

static struct pcep_object_tlv_header *
common_tlv_create(struct pcep_object_tlv_header *hdr, uint16_t new_tlv_length)
{
	struct pcep_object_tlv_header *new_tlv =
		pceplib_malloc(PCEPLIB_MESSAGES, new_tlv_length);
	memset(new_tlv, 0, new_tlv_length);
	memcpy(new_tlv, hdr, sizeof(struct pcep_object_tlv_header));

	return new_tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_no_path_vector(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_nopath_vector *tlv =
		(struct pcep_object_tlv_nopath_vector *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_nopath_vector));

	tlv->error_code = ntohl(*((uint32_t *)tlv_body_buf));

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_stateful_pce_capability(struct pcep_object_tlv_header *tlv_hdr,
					const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_stateful_pce_capability *tlv =
		(struct pcep_object_tlv_stateful_pce_capability *)
			common_tlv_create(
				tlv_hdr,
				sizeof(struct
				       pcep_object_tlv_stateful_pce_capability));

	tlv->flag_f_triggered_initial_sync =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_F);
	tlv->flag_d_delta_lsp_sync =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_D);
	tlv->flag_t_triggered_resync =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_T);
	tlv->flag_i_lsp_instantiation_capability =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_I);
	tlv->flag_s_include_db_version =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_S);
	tlv->flag_u_lsp_update_capability =
		(tlv_body_buf[3] & TLV_STATEFUL_PCE_CAP_FLAG_U);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_symbolic_path_name(struct pcep_object_tlv_header *tlv_hdr,
				   const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_symbolic_path_name *tlv =
		(struct pcep_object_tlv_symbolic_path_name *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_symbolic_path_name));

	uint16_t length = tlv_hdr->encoded_tlv_length;
	if (length > MAX_SYMBOLIC_PATH_NAME) {
		/* TODO should we also reset the tlv_hdr->encoded_tlv_length ?
		 */
		length = MAX_SYMBOLIC_PATH_NAME;
		pcep_log(
			LOG_INFO,
			"%s: Decoding Symbolic Path Name TLV, truncate path name from [%d] to [%d].\",",
			__func__, tlv_hdr->encoded_tlv_length,
			MAX_SYMBOLIC_PATH_NAME);
	}

	tlv->symbolic_path_name_length = length;
	memcpy(tlv->symbolic_path_name, tlv_body_buf, length);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_ipv4_lsp_identifiers(struct pcep_object_tlv_header *tlv_hdr,
				     const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_ipv4_lsp_identifier *tlv =
		(struct pcep_object_tlv_ipv4_lsp_identifier *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_ipv4_lsp_identifier));

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	tlv->ipv4_tunnel_sender.s_addr = uint32_ptr[0];
	/* uint32_t[1] is lsp_id and tunnel_id, below */
	tlv->extended_tunnel_id.s_addr = uint32_ptr[2];
	tlv->ipv4_tunnel_endpoint.s_addr = uint32_ptr[3];

	uint16_t *uint16_ptr = (uint16_t *)(tlv_body_buf + LENGTH_1WORD);
	tlv->lsp_id = ntohs(uint16_ptr[0]);
	tlv->tunnel_id = ntohs(uint16_ptr[1]);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_ipv6_lsp_identifiers(struct pcep_object_tlv_header *tlv_hdr,
				     const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_ipv6_lsp_identifier *tlv =
		(struct pcep_object_tlv_ipv6_lsp_identifier *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_ipv6_lsp_identifier));

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	decode_ipv6(uint32_ptr, &tlv->ipv6_tunnel_sender);
	decode_ipv6(uint32_ptr + 5, &tlv->extended_tunnel_id);
	decode_ipv6(uint32_ptr + 9, &tlv->ipv6_tunnel_endpoint);

	uint16_t *uint16_ptr = (uint16_t *)(tlv_body_buf + LENGTH_4WORDS);
	tlv->lsp_id = htons(uint16_ptr[0]);
	tlv->tunnel_id = htons(uint16_ptr[1]);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_lsp_error_code(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_lsp_error_code *tlv =
		(struct pcep_object_tlv_lsp_error_code *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_lsp_error_code));

	tlv->lsp_error_code = ntohl(*((uint32_t *)tlv_body_buf));

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_rsvp_error_spec(struct pcep_object_tlv_header *tlv_hdr,
				const uint8_t *tlv_body_buf)
{
	uint8_t class_num = tlv_body_buf[2];
	uint8_t ctype = tlv_body_buf[3];

	if (class_num != RSVP_ERROR_SPEC_CLASS_NUM) {
		pcep_log(
			LOG_INFO,
			"%s: Decoding RSVP Error Spec TLV, unknown class num [%d]",
			__func__, class_num);
		return NULL;
	}

	if (ctype != RSVP_ERROR_SPEC_IPV4_CTYPE
	    && ctype != RSVP_ERROR_SPEC_IPV6_CTYPE) {
		pcep_log(LOG_INFO,
			 "%s: Decoding RSVP Error Spec TLV, unknown ctype [%d]",
			 __func__, ctype);
		return NULL;
	}

	struct pcep_object_tlv_rsvp_error_spec *tlv =
		(struct pcep_object_tlv_rsvp_error_spec *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_rsvp_error_spec));

	tlv->class_num = class_num;
	tlv->c_type = ctype;

	uint32_t *uint32_ptr = (uint32_t *)(tlv_body_buf + LENGTH_1WORD);
	if (ctype == RSVP_ERROR_SPEC_IPV4_CTYPE) {
		tlv->error_spec_ip.ipv4_error_node_address.s_addr = *uint32_ptr;
		tlv->error_code = tlv_body_buf[LENGTH_2WORDS + 1];
		tlv->error_value = ntohs(
			*((uint16_t *)(tlv_body_buf + LENGTH_2WORDS + 2)));
	} else /* RSVP_ERROR_SPEC_IPV6_CTYPE */
	{
		decode_ipv6(uint32_ptr,
			    &tlv->error_spec_ip.ipv6_error_node_address);
		tlv->error_code = tlv_body_buf[LENGTH_5WORDS + 1];
		tlv->error_value = ntohs(
			*((uint16_t *)(tlv_body_buf + LENGTH_5WORDS + 2)));
	}

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_lsp_db_version(struct pcep_object_tlv_header *tlv_hdr,
			       const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_lsp_db_version *tlv =
		(struct pcep_object_tlv_lsp_db_version *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_lsp_db_version));

	tlv->lsp_db_version = be64toh(*((uint64_t *)tlv_body_buf));

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_speaker_entity_id(struct pcep_object_tlv_header *tlv_hdr,
				  const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_speaker_entity_identifier *tlv =
		(struct pcep_object_tlv_speaker_entity_identifier *)
			common_tlv_create(
				tlv_hdr,
				sizeof(struct
				       pcep_object_tlv_speaker_entity_identifier));

	uint8_t num_entity_ids = tlv_hdr->encoded_tlv_length / LENGTH_1WORD;
	if (num_entity_ids > MAX_ITERATIONS) {
		num_entity_ids = MAX_ITERATIONS;
		pcep_log(
			LOG_INFO,
			"%s: Decode Speaker Entity ID, truncating num entities from [%d] to [%d].",
			__func__, num_entity_ids, MAX_ITERATIONS);
	}

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	tlv->speaker_entity_id_list = dll_initialize();
	int i;
	for (i = 0; i < num_entity_ids; i++) {
		uint32_t *entity_id =
			pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
		*entity_id = ntohl(uint32_ptr[i]);
		dll_append(tlv->speaker_entity_id_list, entity_id);
	}

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_sr_pce_capability(struct pcep_object_tlv_header *tlv_hdr,
				  const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_sr_pce_capability *tlv =
		(struct pcep_object_tlv_sr_pce_capability *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_sr_pce_capability));

	tlv->flag_n = (tlv_body_buf[2] & TLV_SR_PCE_CAP_FLAG_N);
	tlv->flag_x = (tlv_body_buf[2] & TLV_SR_PCE_CAP_FLAG_X);
	tlv->max_sid_depth = tlv_body_buf[3];

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_path_setup_type(struct pcep_object_tlv_header *tlv_hdr,
				const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_path_setup_type *tlv =
		(struct pcep_object_tlv_path_setup_type *)common_tlv_create(
			tlv_hdr,
			sizeof(struct pcep_object_tlv_path_setup_type));

	tlv->path_setup_type = tlv_body_buf[3];

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *pcep_decode_tlv_path_setup_type_capability(
	struct pcep_object_tlv_header *tlv_hdr, const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_path_setup_type_capability *tlv =
		(struct pcep_object_tlv_path_setup_type_capability *)
			common_tlv_create(
				tlv_hdr,
				sizeof(struct
				       pcep_object_tlv_path_setup_type_capability));

	uint8_t num_psts = tlv_body_buf[3];
	if (num_psts > MAX_ITERATIONS) {
		pcep_log(
			LOG_INFO,
			"%s: Decode Path Setup Type Capability num PSTs [%d] exceeds MAX [%d] continuing anyways",
			__func__, num_psts, MAX_ITERATIONS);
	}

	int i;
	tlv->pst_list = dll_initialize();
	for (i = 0; i < num_psts; i++) {
		uint8_t *pst =
			pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint8_t));
		*pst = tlv_body_buf[i + LENGTH_1WORD];
		dll_append(tlv->pst_list, pst);
	}

	if (tlv->header.encoded_tlv_length
	    == (TLV_HEADER_LENGTH + LENGTH_1WORD + num_psts)) {
		return (struct pcep_object_tlv_header *)tlv;
	}

	uint8_t num_iterations = 0;
	tlv->sub_tlv_list = dll_initialize();
	uint16_t buf_index = normalize_pcep_tlv_length(
		TLV_HEADER_LENGTH + LENGTH_1WORD + num_psts);
	while ((tlv->header.encoded_tlv_length - buf_index) > TLV_HEADER_LENGTH
	       && num_iterations++ < MAX_ITERATIONS) {
		struct pcep_object_tlv_header *sub_tlv =
			pcep_decode_tlv(tlv_body_buf + buf_index);
		if (sub_tlv == NULL) {
			pcep_log(
				LOG_INFO,
				"%s: Decode PathSetupType Capability sub-TLV decode returned NULL",
				__func__);
			return (struct pcep_object_tlv_header *)tlv;
		}

		buf_index +=
			normalize_pcep_tlv_length(sub_tlv->encoded_tlv_length);
		dll_append(tlv->sub_tlv_list, sub_tlv);
	}

	return (struct pcep_object_tlv_header *)tlv;
}
struct pcep_object_tlv_header *
pcep_decode_tlv_pol_id(struct pcep_object_tlv_header *tlv_hdr,
		       const uint8_t *tlv_body_buf)
{
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	struct pcep_object_tlv_srpag_pol_id *ipv4 =
		(struct pcep_object_tlv_srpag_pol_id *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_srpag_pol_id));
	if (tlv_hdr->encoded_tlv_length == 8) {
		ipv4->is_ipv4 = true;
		ipv4->color = ntohl(uint32_ptr[0]);
		ipv4->end_point.ipv4.s_addr = uint32_ptr[1];
		return (struct pcep_object_tlv_header *)ipv4;
	} else {
		ipv4->is_ipv4 = false;
		struct pcep_object_tlv_srpag_pol_id *ipv6 = ipv4;
		ipv6->color = ntohl(uint32_ptr[0]);
		decode_ipv6(&uint32_ptr[1], &ipv6->end_point.ipv6);
		return (struct pcep_object_tlv_header *)ipv6;
	}
}
struct pcep_object_tlv_header *
pcep_decode_tlv_pol_name(struct pcep_object_tlv_header *tlv_hdr,
			 const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_srpag_pol_name *tlv =
		(struct pcep_object_tlv_srpag_pol_name *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_srpag_pol_name));

	memcpy(tlv->name, tlv_body_buf, tlv->header.encoded_tlv_length);

	return (struct pcep_object_tlv_header *)tlv;
}
struct pcep_object_tlv_header *
pcep_decode_tlv_cpath_id(struct pcep_object_tlv_header *tlv_hdr,
			 const uint8_t *tlv_body_buf)
{
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	struct pcep_object_tlv_srpag_cp_id *tlv =
		(struct pcep_object_tlv_srpag_cp_id *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_srpag_cp_id));

	tlv->proto = tlv_body_buf[0];
	tlv->orig_asn = ntohl(uint32_ptr[1]);
	decode_ipv6(&uint32_ptr[2], &tlv->orig_addres);
	tlv->discriminator = ntohl(uint32_ptr[6]);

	return (struct pcep_object_tlv_header *)tlv;
}
struct pcep_object_tlv_header *
pcep_decode_tlv_cpath_preference(struct pcep_object_tlv_header *tlv_hdr,
				 const uint8_t *tlv_body_buf)
{
	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	struct pcep_object_tlv_srpag_cp_pref *tlv =
		(struct pcep_object_tlv_srpag_cp_pref *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_srpag_cp_pref));

	tlv->preference = ntohl(uint32_ptr[0]);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_vendor_info(struct pcep_object_tlv_header *tlv_hdr,
			    const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_vendor_info *tlv =
		(struct pcep_object_tlv_vendor_info *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_vendor_info));

	uint32_t *uint32_ptr = (uint32_t *)tlv_body_buf;
	tlv->enterprise_number = ntohl(uint32_ptr[0]);
	tlv->enterprise_specific_info = ntohl(uint32_ptr[1]);

	return (struct pcep_object_tlv_header *)tlv;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_arbitrary(struct pcep_object_tlv_header *tlv_hdr,
			  const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_arbitrary *tlv_arbitrary =
		(struct pcep_object_tlv_arbitrary *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_arbitrary));

	uint16_t length = tlv_hdr->encoded_tlv_length;
	if (length > MAX_ARBITRARY_SIZE) {
		/* TODO should we also reset the tlv_hdr->encoded_tlv_length ?
		 */
		length = MAX_ARBITRARY_SIZE;
		pcep_log(
			LOG_INFO,
			"%s: Decoding Arbitrary TLV , truncate path name from [%d] to [%d].\",",
			__func__, tlv_hdr->encoded_tlv_length,
			MAX_ARBITRARY_SIZE);
	}

	tlv_arbitrary->data_length = length;
	tlv_arbitrary->arbitraty_type = tlv_hdr->type;
	tlv_hdr->type = PCEP_OBJ_TLV_TYPE_ARBITRARY;
	memcpy(tlv_arbitrary->data, tlv_body_buf, length);

	return (struct pcep_object_tlv_header *)tlv_arbitrary;
}

struct pcep_object_tlv_header *
pcep_decode_tlv_of_list(struct pcep_object_tlv_header *tlv_hdr,
			const uint8_t *tlv_body_buf)
{
	struct pcep_object_tlv_of_list *of_tlv =
		(struct pcep_object_tlv_of_list *)common_tlv_create(
			tlv_hdr, sizeof(struct pcep_object_tlv_of_list));

	of_tlv->of_list = dll_initialize();
	uint16_t *uint16_ptr = (uint16_t *)tlv_body_buf;
	int i = 0;
	for (; i < tlv_hdr->encoded_tlv_length && i < MAX_ITERATIONS; i++) {
		uint16_t *of_code_ptr =
			pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint16_t));
		*of_code_ptr = ntohs(uint16_ptr[i]);
		dll_append(of_tlv->of_list, of_code_ptr);
	}

	return (struct pcep_object_tlv_header *)of_tlv;
}
