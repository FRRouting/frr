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
 * This is the implementation of a High Level PCEP message object TLV API.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "pcep_msg_tlvs.h"
#include "pcep_msg_encoding.h"
#include "pcep_utils_memory.h"

static struct pcep_object_tlv_header *
pcep_tlv_common_create(enum pcep_object_tlv_types type, uint16_t size)
{
	struct pcep_object_tlv_header *tlv =
		pceplib_malloc(PCEPLIB_MESSAGES, size);
	memset(tlv, 0, size);
	tlv->type = type;

	return tlv;
}

/*
 * Open Object TLVs
 */

struct pcep_object_tlv_stateful_pce_capability *
pcep_tlv_create_stateful_pce_capability(
	bool flag_u_lsp_update_capability, bool flag_s_include_db_version,
	bool flag_i_lsp_instantiation_capability, bool flag_t_triggered_resync,
	bool flag_d_delta_lsp_sync, bool flag_f_triggered_initial_sync)
{
	struct pcep_object_tlv_stateful_pce_capability *tlv =
		(struct pcep_object_tlv_stateful_pce_capability *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY,
				sizeof(struct
				       pcep_object_tlv_stateful_pce_capability));
	tlv->flag_u_lsp_update_capability = flag_u_lsp_update_capability;
	tlv->flag_s_include_db_version = flag_s_include_db_version;
	tlv->flag_i_lsp_instantiation_capability =
		flag_i_lsp_instantiation_capability;
	tlv->flag_t_triggered_resync = flag_t_triggered_resync;
	tlv->flag_d_delta_lsp_sync = flag_d_delta_lsp_sync;
	tlv->flag_f_triggered_initial_sync = flag_f_triggered_initial_sync;

	return tlv;
}

struct pcep_object_tlv_lsp_db_version *
pcep_tlv_create_lsp_db_version(uint64_t lsp_db_version)
{
	struct pcep_object_tlv_lsp_db_version *tlv =
		(struct pcep_object_tlv_lsp_db_version *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION,
			sizeof(struct pcep_object_tlv_lsp_db_version));
	tlv->lsp_db_version = lsp_db_version;

	return tlv;
}

struct pcep_object_tlv_speaker_entity_identifier *
pcep_tlv_create_speaker_entity_id(double_linked_list *speaker_entity_id_list)
{
	if (speaker_entity_id_list == NULL) {
		return NULL;
	}

	if (speaker_entity_id_list->num_entries == 0) {
		return NULL;
	}

	struct pcep_object_tlv_speaker_entity_identifier *tlv =
		(struct pcep_object_tlv_speaker_entity_identifier *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID,
				sizeof(struct
				       pcep_object_tlv_speaker_entity_identifier));
	tlv->speaker_entity_id_list = speaker_entity_id_list;

	return tlv;
}

struct pcep_object_tlv_path_setup_type *
pcep_tlv_create_path_setup_type(uint8_t pst)
{
	struct pcep_object_tlv_path_setup_type *tlv =
		(struct pcep_object_tlv_path_setup_type *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE,
				sizeof(struct pcep_object_tlv_path_setup_type));
	tlv->path_setup_type = pst;

	return tlv;
}

struct pcep_object_tlv_path_setup_type_capability *
pcep_tlv_create_path_setup_type_capability(double_linked_list *pst_list,
					   double_linked_list *sub_tlv_list)
{
	if (pst_list == NULL) {
		return NULL;
	}

	if (pst_list->num_entries == 0) {
		return NULL;
	}

	struct pcep_object_tlv_path_setup_type_capability *tlv =
		(struct pcep_object_tlv_path_setup_type_capability *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY,
				sizeof(struct
				       pcep_object_tlv_path_setup_type_capability));

	tlv->pst_list = pst_list;
	tlv->sub_tlv_list = sub_tlv_list;

	return tlv;
}

struct pcep_object_tlv_sr_pce_capability *
pcep_tlv_create_sr_pce_capability(bool flag_n, bool flag_x,
				  uint8_t max_sid_depth)
{
	struct pcep_object_tlv_sr_pce_capability *tlv =
		(struct pcep_object_tlv_sr_pce_capability *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY,
				sizeof(struct
				       pcep_object_tlv_sr_pce_capability));
	tlv->flag_n = flag_n;
	tlv->flag_x = flag_x;
	tlv->max_sid_depth = max_sid_depth;

	return tlv;
}

struct pcep_object_tlv_of_list *
pcep_tlv_create_of_list(double_linked_list *of_list)
{
	if (of_list == NULL) {
		return NULL;
	}

	struct pcep_object_tlv_of_list *tlv =
		(struct pcep_object_tlv_of_list *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST,
			sizeof(struct pcep_object_tlv_of_list));

	tlv->of_list = of_list;

	return tlv;
}

/*
 * LSP Object TLVs
 */

struct pcep_object_tlv_ipv4_lsp_identifier *
pcep_tlv_create_ipv4_lsp_identifiers(struct in_addr *ipv4_tunnel_sender,
				     struct in_addr *ipv4_tunnel_endpoint,
				     uint16_t lsp_id, uint16_t tunnel_id,
				     struct in_addr *extended_tunnel_id)
{
	if (ipv4_tunnel_sender == NULL || ipv4_tunnel_endpoint == NULL) {
		return NULL;
	}

	struct pcep_object_tlv_ipv4_lsp_identifier *tlv =
		(struct pcep_object_tlv_ipv4_lsp_identifier *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS,
				sizeof(struct
				       pcep_object_tlv_ipv4_lsp_identifier));
	tlv->ipv4_tunnel_sender.s_addr = ipv4_tunnel_sender->s_addr;
	tlv->ipv4_tunnel_endpoint.s_addr = ipv4_tunnel_endpoint->s_addr;
	tlv->lsp_id = lsp_id;
	tlv->tunnel_id = tunnel_id;
	tlv->extended_tunnel_id.s_addr =
		(extended_tunnel_id == NULL ? INADDR_ANY
					    : extended_tunnel_id->s_addr);

	return tlv;
}

struct pcep_object_tlv_ipv6_lsp_identifier *
pcep_tlv_create_ipv6_lsp_identifiers(struct in6_addr *ipv6_tunnel_sender,
				     struct in6_addr *ipv6_tunnel_endpoint,
				     uint16_t lsp_id, uint16_t tunnel_id,
				     struct in6_addr *extended_tunnel_id)
{
	if (ipv6_tunnel_sender == NULL || ipv6_tunnel_endpoint == NULL) {
		return NULL;
	}

	struct pcep_object_tlv_ipv6_lsp_identifier *tlv =
		(struct pcep_object_tlv_ipv6_lsp_identifier *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS,
				sizeof(struct
				       pcep_object_tlv_ipv6_lsp_identifier));

	memcpy(&tlv->ipv6_tunnel_sender, ipv6_tunnel_sender,
	       sizeof(struct in6_addr));

	tlv->tunnel_id = tunnel_id;
	tlv->lsp_id = lsp_id;

	memcpy(&tlv->extended_tunnel_id, extended_tunnel_id,
	       sizeof(struct in6_addr));

	memcpy(&tlv->ipv6_tunnel_endpoint, ipv6_tunnel_endpoint,
	       sizeof(struct in6_addr));

	return tlv;
}

struct pcep_object_tlv_symbolic_path_name *
pcep_tlv_create_symbolic_path_name(const char *symbolic_path_name,
				   uint16_t symbolic_path_name_length)
{
	/* symbolic_path_name_length should NOT include the null terminator and
	 * cannot be zero */
	if (symbolic_path_name == NULL || symbolic_path_name_length == 0) {
		return NULL;
	}

	struct pcep_object_tlv_symbolic_path_name *tlv =
		(struct pcep_object_tlv_symbolic_path_name *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME,
				sizeof(struct
				       pcep_object_tlv_symbolic_path_name));

	uint16_t length = (symbolic_path_name_length > MAX_SYMBOLIC_PATH_NAME)
				  ? MAX_SYMBOLIC_PATH_NAME
				  : symbolic_path_name_length;
	memcpy(tlv->symbolic_path_name, symbolic_path_name, length);
	tlv->symbolic_path_name_length = length;

	return tlv;
}

struct pcep_object_tlv_lsp_error_code *
pcep_tlv_create_lsp_error_code(enum pcep_tlv_lsp_error_codes lsp_error_code)
{
	struct pcep_object_tlv_lsp_error_code *tlv =
		(struct pcep_object_tlv_lsp_error_code *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE,
			sizeof(struct pcep_object_tlv_lsp_error_code));
	tlv->lsp_error_code = lsp_error_code;

	return tlv;
}

struct pcep_object_tlv_rsvp_error_spec *
pcep_tlv_create_rsvp_ipv4_error_spec(struct in_addr *error_node_ip,
				     uint8_t error_code, uint16_t error_value)
{
	if (error_node_ip == NULL) {
		return NULL;
	}

	struct pcep_object_tlv_rsvp_error_spec *tlv =
		(struct pcep_object_tlv_rsvp_error_spec *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC,
				sizeof(struct pcep_object_tlv_rsvp_error_spec));

	tlv->c_type = RSVP_ERROR_SPEC_IPV4_CTYPE;
	tlv->class_num = RSVP_ERROR_SPEC_CLASS_NUM;
	tlv->error_code = error_code;
	tlv->error_value = error_value;
	tlv->error_spec_ip.ipv4_error_node_address.s_addr =
		error_node_ip->s_addr;

	return tlv;
}

struct pcep_object_tlv_rsvp_error_spec *
pcep_tlv_create_rsvp_ipv6_error_spec(struct in6_addr *error_node_ip,
				     uint8_t error_code, uint16_t error_value)
{
	if (error_node_ip == NULL) {
		return NULL;
	}

	struct pcep_object_tlv_rsvp_error_spec *tlv =
		(struct pcep_object_tlv_rsvp_error_spec *)
			pcep_tlv_common_create(
				PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC,
				sizeof(struct pcep_object_tlv_rsvp_error_spec));

	tlv->c_type = RSVP_ERROR_SPEC_IPV6_CTYPE;
	tlv->class_num = RSVP_ERROR_SPEC_CLASS_NUM;
	tlv->error_code = error_code;
	tlv->error_value = error_value;
	memcpy(&tlv->error_spec_ip, error_node_ip, sizeof(struct in6_addr));

	return tlv;
}

struct pcep_object_tlv_nopath_vector *
pcep_tlv_create_nopath_vector(uint32_t error_code)
{
	struct pcep_object_tlv_nopath_vector *tlv =
		(struct pcep_object_tlv_nopath_vector *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR,
			sizeof(struct pcep_object_tlv_nopath_vector));

	tlv->error_code = error_code;

	return tlv;
}

struct pcep_object_tlv_vendor_info *
pcep_tlv_create_vendor_info(uint32_t enterprise_number,
			    uint32_t enterprise_specific_info)
{
	struct pcep_object_tlv_vendor_info *tlv =
		(struct pcep_object_tlv_vendor_info *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_VENDOR_INFO,
			sizeof(struct pcep_object_tlv_vendor_info));

	tlv->enterprise_number = enterprise_number;
	tlv->enterprise_specific_info = enterprise_specific_info;

	return tlv;
}

/*
 * SRPAG (SR Association Group) TLVs
 */

struct pcep_object_tlv_srpag_pol_id *
pcep_tlv_create_srpag_pol_id_ipv4(uint32_t color, struct in_addr *ipv4)
{
	struct pcep_object_tlv_srpag_pol_id *tlv =
		(struct pcep_object_tlv_srpag_pol_id *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID,
			sizeof(struct pcep_object_tlv_srpag_pol_id));
	tlv->color = color;
	tlv->is_ipv4 = true;
	memcpy(&tlv->end_point.ipv4.s_addr, ipv4, sizeof(struct in_addr));

	return tlv;
}

struct pcep_object_tlv_srpag_pol_id *
pcep_tlv_create_srpag_pol_id_ipv6(uint32_t color, struct in6_addr *ipv6)
{
	struct pcep_object_tlv_srpag_pol_id *tlv =
		(struct pcep_object_tlv_srpag_pol_id *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID,
			sizeof(struct pcep_object_tlv_srpag_pol_id));
	tlv->color = color;
	tlv->is_ipv4 = false;
	memcpy(&tlv->end_point.ipv6, ipv6, sizeof(struct in6_addr));

	return tlv;
}


struct pcep_object_tlv_srpag_pol_name *
pcep_tlv_create_srpag_pol_name(const char *pol_name, uint16_t pol_name_length)
{
	if (pol_name == NULL) {
		return NULL;
	}
	struct pcep_object_tlv_srpag_pol_name *tlv =
		(struct pcep_object_tlv_srpag_pol_name *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME,
			sizeof(struct pcep_object_tlv_srpag_pol_name));
	uint16_t length =
		(normalize_pcep_tlv_length(pol_name_length) > MAX_POLICY_NAME)
			? MAX_POLICY_NAME
			: pol_name_length;
	memcpy(tlv->name, pol_name, length);
	tlv->name_length = length;

	return tlv;
}
struct pcep_object_tlv_srpag_cp_id *
pcep_tlv_create_srpag_cp_id(uint8_t proto_origin, uint32_t asn,
			    struct in6_addr *in6_addr_with_mapped_ipv4,
			    uint32_t discriminator)
{
	if (!in6_addr_with_mapped_ipv4) {
		return NULL;
	}

	struct pcep_object_tlv_srpag_cp_id *tlv =
		(struct pcep_object_tlv_srpag_cp_id *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID,
			sizeof(struct pcep_object_tlv_srpag_cp_id));
	tlv->proto = proto_origin;
	tlv->orig_asn = asn;
	memcpy(&(tlv->orig_addres), in6_addr_with_mapped_ipv4,
	       sizeof(*in6_addr_with_mapped_ipv4));
	tlv->discriminator = discriminator;

	return tlv;
}
struct pcep_object_tlv_srpag_cp_pref *
pcep_tlv_create_srpag_cp_pref(uint32_t pref)
{

	struct pcep_object_tlv_srpag_cp_pref *tlv =
		(struct pcep_object_tlv_srpag_cp_pref *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE,
			sizeof(struct pcep_object_tlv_srpag_cp_pref));
	tlv->preference = pref;

	return tlv;
}

struct pcep_object_tlv_arbitrary *
pcep_tlv_create_tlv_arbitrary(const char *data, uint16_t data_length,
			      int tlv_id)
{
	if (data == NULL || data_length == 0) {
		return NULL;
	}

	struct pcep_object_tlv_arbitrary *tlv =
		(struct pcep_object_tlv_arbitrary *)pcep_tlv_common_create(
			PCEP_OBJ_TLV_TYPE_ARBITRARY,
			sizeof(struct pcep_object_tlv_arbitrary));

	uint16_t length = (data_length > MAX_ARBITRARY_SIZE)
				  ? MAX_ARBITRARY_SIZE
				  : data_length;
	memcpy(tlv->data, data, length);
	tlv->data_length = length;
	tlv->arbitraty_type = tlv_id;

	return tlv;
}
