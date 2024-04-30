// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 */


/*
 * This is a High Level PCEP message object TLV API.
 */

#ifndef PCEP_TLVS_H_
#define PCEP_TLVS_H_

#include <arpa/inet.h>
#include <stdint.h>

#include "pcep.h"
#include "pcep_utils_double_linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Regarding memory usage:
 * When creating TLVs, any TLVs passed into messages or objects with these APIs
 * will be free'd when the the enclosing pcep_message is free'd. That includes
 * the double_linked_list's. So, just create the objects and TLVs, put them in
 * their double_linked_list's, and everything will be managed internally. The
 * enclosing message will be deleted by pcep_msg_free_message() or
 * pcep_msg_free_message_list() which, * in turn will call one of:
 * pcep_obj_free_object() and pcep_obj_free_tlv().
 * For received messages, call pcep_msg_free_message() to free them.
 */

/* These numbers can be found here:
 * https://www.iana.org/assignments/pcep/pcep.xhtml */
enum pcep_object_tlv_types {
	PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR = 1,
	PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST = 4,  /* RFC 5541 */
	PCEP_OBJ_TLV_TYPE_VENDOR_INFO = 7,		/* RFC 7470 */
	PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY = 16, /* RFC 8231 */
	PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME = 17,      /* RFC 8232 */
	PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS = 18,    /* RFC 8231 */
	PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS = 19,    /* RFC 8231 */
	PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE = 20,		/* RFC 8232 */
	PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC = 21,		/* RFC 8232 */
	PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION = 23,		/* RFC 8232 */
	PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID = 24,       /* RFC 8232 */
	PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY =
		26, /* draft-ietf-pce-segment-routing-16 */
	PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE = 28, /* RFC 8408 */
	PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY =
		34, /* RFC 8408, draft-ietf-pce-segment-routing-16 */
	PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID =
		60, /*TDB2 draft-barth-pce-segment-routing-policy-cp-04 */
	PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME =
		61, /*TDB3 draft-barth-pce-segment-routing-policy-cp-04 */
	PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID =
		62, /*TDB4 draft-barth-pce-segment-routing-policy-cp-04 */
	PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE =
		63, /*TDB5 draft-barth-pce-segment-routing-policy-cp-04 */
	PCEP_OBJ_TLV_TYPE_UNKNOWN = 128,
	PCEP_OBJ_TYPE_CISCO_BSID = 65505,
	/* Max IANA To write arbitrary data */
	PCEP_OBJ_TLV_TYPE_ARBITRARY = 65533
};


struct pcep_object_tlv_header {
	enum pcep_object_tlv_types type;
	/* Pointer into encoded_message field from the pcep_message */
	const uint8_t *encoded_tlv;
	uint16_t encoded_tlv_length;
};

/* STATEFUL-PCE-CAPABILITY TLV, Used in Open Object. RFCs: 8231, 8232, 8281 */
#define TLV_STATEFUL_PCE_CAP_FLAG_U 0x01
#define TLV_STATEFUL_PCE_CAP_FLAG_S 0x02
#define TLV_STATEFUL_PCE_CAP_FLAG_I 0x04
#define TLV_STATEFUL_PCE_CAP_FLAG_T 0x08
#define TLV_STATEFUL_PCE_CAP_FLAG_D 0x10
#define TLV_STATEFUL_PCE_CAP_FLAG_F 0x20

struct pcep_object_tlv_stateful_pce_capability {
	struct pcep_object_tlv_header header;
	bool flag_u_lsp_update_capability;	  /* RFC 8231 */
	bool flag_s_include_db_version;		  /* RFC 8232 */
	bool flag_i_lsp_instantiation_capability; /* RFC 8281 */
	bool flag_t_triggered_resync;		  /* RFC 8232 */
	bool flag_d_delta_lsp_sync;		  /* RFC 8232 */
	bool flag_f_triggered_initial_sync;	  /* RFC 8232 */
};

/* NOPATH-VECTOR TLV, Used in the Reply NoPath Object. */
struct pcep_object_tlv_nopath_vector {
	struct pcep_object_tlv_header header;
	uint32_t error_code;
};

/* STATEFUL-PCE-CAPABILITY TLV, Used in Open Object. RFCs: 8232 */
struct pcep_object_tlv_lsp_db_version {
	struct pcep_object_tlv_header header;
	uint64_t lsp_db_version;
};

/* Speaker Entity Identifier TLV, Used in Open Object. RFCs: 8232 */
struct pcep_object_tlv_speaker_entity_identifier {
	struct pcep_object_tlv_header header;
	double_linked_list *speaker_entity_id_list; /* list of uint32_t speaker
						       entity ids */
};

/* Ipv4 LSP Identifier TLV, Used in LSP Object. RFCs: 8231 */
struct pcep_object_tlv_ipv4_lsp_identifier {
	struct pcep_object_tlv_header header;
	struct in_addr ipv4_tunnel_sender;
	uint16_t lsp_id;
	uint16_t tunnel_id;
	struct in_addr extended_tunnel_id;
	struct in_addr ipv4_tunnel_endpoint;
};

/* Ipv6 LSP Identifier TLV, Used in LSP Object. RFCs: 8231 */
struct pcep_object_tlv_ipv6_lsp_identifier {
	struct pcep_object_tlv_header header;
	struct in6_addr ipv6_tunnel_sender;
	uint16_t lsp_id;
	uint16_t tunnel_id;
	struct in6_addr extended_tunnel_id;
	struct in6_addr ipv6_tunnel_endpoint;
};

/* Symbolic Path Name TLV, Used in LSP Object. RFCs: 8231 */
#define MAX_SYMBOLIC_PATH_NAME 256

struct pcep_object_tlv_symbolic_path_name {
	struct pcep_object_tlv_header header;
	uint16_t symbolic_path_name_length;
	char symbolic_path_name[MAX_SYMBOLIC_PATH_NAME];
};

/* LSP Error Code TLV, Used in LSP Object. RFCs: 8231 */
enum pcep_tlv_lsp_error_codes {
	PCEP_TLV_LSP_ERROR_CODE_UNKNOWN = 1,
	PCEP_TLV_LSP_ERROR_CODE_LSP_LIMIT_REACHED = 2,
	PCEP_TLV_LSP_ERROR_CODE_TOO_MANY_PENDING_LSP_UPDATES = 3,
	PCEP_TLV_LSP_ERROR_CODE_UNACCEPTABLE_PARAMS = 4,
	PCEP_TLV_LSP_ERROR_CODE_INTERNAL_ERROR = 5,
	PCEP_TLV_LSP_ERROR_CODE_LSP_BROUGHT_DOWN = 6,
	PCEP_TLV_LSP_ERROR_CODE_LSP_PREEMPTED = 7,
	PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR = 8,
};

struct pcep_object_tlv_lsp_error_code {
	struct pcep_object_tlv_header header;
	enum pcep_tlv_lsp_error_codes lsp_error_code;
};

/* Path Setup Type TLV, Used in RP and SRP Object. RFCs: 8408,
 * draft-ietf-pce-segment-routing-16 */
#define SR_TE_PST 1

struct pcep_object_tlv_path_setup_type {
	struct pcep_object_tlv_header header;
	uint8_t path_setup_type;
};

/* Path Setup Type Capability TLV, Used in Open Object. RFCs: 8408,
 * draft-ietf-pce-segment-routing-16 */
struct pcep_object_tlv_path_setup_type_capability {
	struct pcep_object_tlv_header header;
	double_linked_list *pst_list;	  /* list of uint8_t PSTs */
	double_linked_list *sub_tlv_list; /* list of sub_tlvs */
};

/* SR PCE Capability sub-TLV, Used in Open Object. RFCs:
 * draft-ietf-pce-segment-routing-16 */
#define TLV_SR_PCE_CAP_FLAG_X 0x01
#define TLV_SR_PCE_CAP_FLAG_N 0x02

struct pcep_object_tlv_sr_pce_capability {
	struct pcep_object_tlv_header header;
	bool flag_n;
	bool flag_x;
	uint8_t max_sid_depth;
};


/* RSVP Error Spec TLV, Used in LSP Object. RFCs: 8231, 2205 */
#define RSVP_ERROR_SPEC_IPV4_CTYPE 1
#define RSVP_ERROR_SPEC_IPV6_CTYPE 2
#define RSVP_ERROR_SPEC_CLASS_NUM 6

struct pcep_object_tlv_rsvp_error_spec {
	struct pcep_object_tlv_header header;
	uint8_t class_num;
	uint8_t c_type;
	uint8_t error_code;
	uint16_t error_value;
	/* Use the c_type to determine which union entry to use */
	union error_spec_ip {
		struct in_addr ipv4_error_node_address;
		struct in6_addr ipv6_error_node_address;
	} error_spec_ip;
};

/* SR Policy Identifier TLV Used in Association Object.
 * draft-barth-pce-segment-routing-policy-cp-04*/
struct pcep_object_tlv_srpag_pol_id {
	struct pcep_object_tlv_header header;
	uint32_t color;
	bool is_ipv4;
	union end_point_ {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} end_point;
};

/*draft-ietf-spring-segment-routing-policy-06*/
#define MAX_POLICY_NAME 256

/* SR Policy Name TLV Used in Association Object.
 * draft-barth-pce-segment-routing-policy-cp-04*/
struct pcep_object_tlv_srpag_pol_name {
	struct pcep_object_tlv_header header;
	uint16_t name_length;
	char name[MAX_POLICY_NAME];
};

/* SR Candidate Path Id  TLV Used in Association Object.
 * draft-barth-pce-segment-routing-policy-cp-04*/
struct pcep_object_tlv_srpag_cp_id {
	struct pcep_object_tlv_header header;
	uint8_t proto;
	uint32_t orig_asn;
	struct in6_addr orig_addres; /*With ipv4 embedded*/
	uint32_t discriminator;
};

/* SR Candidate Preference TLV Used in Association Object.
 * draft-barth-pce-segment-routing-policy-cp-04*/
struct pcep_object_tlv_srpag_cp_pref {
	struct pcep_object_tlv_header header;
	uint32_t preference;
};

struct pcep_object_tlv_vendor_info {
	struct pcep_object_tlv_header header;
	uint32_t enterprise_number;
	uint32_t enterprise_specific_info;
};

/* arbitrary TLV 65535 */
#define MAX_ARBITRARY_SIZE 256
struct pcep_object_tlv_arbitrary {
	struct pcep_object_tlv_header header;
	enum pcep_object_tlv_types arbitraty_type;
	uint16_t data_length;
	char data[MAX_ARBITRARY_SIZE];
};

/* Objective Functions List RFC 5541
 * At least the following 6 OF codes must be supported */
enum objective_function_codes {
	PCEP_OF_CODE_MINIMUM_COST_PATH = 1,		 /* MCP */
	PCEP_OF_CODE_MINIMUM_LOAD_PATH = 2,		 /* MLP */
	PCEP_OF_CODE_MAXIMUM_BW_PATH = 3,		 /* MBP */
	PCEP_OF_CODE_MINIMIZE_AGGR_BW_CONSUMPTION = 4,	 /* MBC */
	PCEP_OF_CODE_MINIMIZE_MOST_LOADED_LINK = 5,	 /* MLL */
	PCEP_OF_CODE_MINIMIZE_CUMULATIVE_COST_PATHS = 6, /* MCC */
};

struct pcep_object_tlv_of_list {
	struct pcep_object_tlv_header header;
	double_linked_list *of_list; /* list of uint16_t OF code points */
};

/*
 * TLV creation functions
 */

/*
 * Open Object TLVs
 */

struct pcep_object_tlv_stateful_pce_capability *
pcep_tlv_create_stateful_pce_capability(
	bool flag_u_lsp_update_capability, bool flag_s_include_db_version,
	bool flag_i_lsp_instantiation_capability, bool flag_t_triggered_resync,
	bool flag_d_delta_lsp_sync, bool flag_f_triggered_initial_sync);
struct pcep_object_tlv_lsp_db_version *
pcep_tlv_create_lsp_db_version(uint64_t lsp_db_version);
struct pcep_object_tlv_speaker_entity_identifier *
pcep_tlv_create_speaker_entity_id(double_linked_list *speaker_entity_id_list);
struct pcep_object_tlv_path_setup_type *
pcep_tlv_create_path_setup_type(uint8_t pst);
struct pcep_object_tlv_path_setup_type_capability *
pcep_tlv_create_path_setup_type_capability(double_linked_list *pst_list,
					   double_linked_list *sub_tlv_list);
struct pcep_object_tlv_sr_pce_capability *
pcep_tlv_create_sr_pce_capability(bool flag_n, bool flag_x,
				  uint8_t max_sid_depth);
struct pcep_object_tlv_of_list *
pcep_tlv_create_of_list(double_linked_list *of_list);

/*
 * LSP Object TLVs
 */

struct pcep_object_tlv_ipv4_lsp_identifier *
pcep_tlv_create_ipv4_lsp_identifiers(struct in_addr *ipv4_tunnel_sender,
				     struct in_addr *ipv4_tunnel_endpoint,
				     uint16_t lsp_id, uint16_t tunnel_id,
				     struct in_addr *extended_tunnel_id);
struct pcep_object_tlv_ipv6_lsp_identifier *
pcep_tlv_create_ipv6_lsp_identifiers(struct in6_addr *ipv6_tunnel_sender,
				     struct in6_addr *extended_tunnel_id,
				     uint16_t lsp_id, uint16_t tunnel_id,
				     struct in6_addr *ipv6_tunnel_endpoint);
/* symbolic_path_name_length should NOT include the null terminator and cannot
 * be zero */
struct pcep_object_tlv_symbolic_path_name *
pcep_tlv_create_symbolic_path_name(const char *symbolic_path_name,
				   uint16_t symbolic_path_name_length);
struct pcep_object_tlv_lsp_error_code *
pcep_tlv_create_lsp_error_code(enum pcep_tlv_lsp_error_codes lsp_error_code);
struct pcep_object_tlv_rsvp_error_spec *
pcep_tlv_create_rsvp_ipv4_error_spec(struct in_addr *error_node_ip,
				     uint8_t error_code, uint16_t error_value);
struct pcep_object_tlv_rsvp_error_spec *
pcep_tlv_create_rsvp_ipv6_error_spec(struct in6_addr *error_node_ip,
				     uint8_t error_code, uint16_t error_value);

struct pcep_object_tlv_nopath_vector *
pcep_tlv_create_nopath_vector(uint32_t error_code);
struct pcep_object_tlv_vendor_info *
pcep_tlv_create_vendor_info(uint32_t enterprise_number,
			    uint32_t enterprise_specific_info);

struct pcep_object_tlv_arbitrary *
pcep_tlv_create_tlv_arbitrary(const char *data, uint16_t data_length,
			      int tlv_id);
/*
 * SRPAG (SR Association Group) TLVs
 */

struct pcep_object_tlv_srpag_pol_id *
pcep_tlv_create_srpag_pol_id_ipv4(uint32_t color, struct in_addr *ipv4);
struct pcep_object_tlv_srpag_pol_id *
pcep_tlv_create_srpag_pol_id_ipv6(uint32_t color, struct in6_addr *ipv6);
struct pcep_object_tlv_srpag_pol_name *
pcep_tlv_create_srpag_pol_name(const char *pol_name, uint16_t pol_name_length);
struct pcep_object_tlv_srpag_cp_id *
pcep_tlv_create_srpag_cp_id(uint8_t proto_origin, uint32_t asn,
			    struct in6_addr *in6_addr_with_mapped_ipv4,
			    uint32_t discriminator);
struct pcep_object_tlv_srpag_cp_pref *
pcep_tlv_create_srpag_cp_pref(uint32_t pref);


#ifdef __cplusplus
}
#endif

#endif /* PCEP_TLVS_H_ */
