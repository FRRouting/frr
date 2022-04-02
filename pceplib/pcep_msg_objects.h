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
 * This is a High Level PCEP message object API.
 */

#ifndef PCEP_OBJECTS_H
#define PCEP_OBJECTS_H

#include <stdbool.h>
#include <stdint.h>

#include "pcep.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_msg_object_error_types.h"
#include "pcep_msg_tlvs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Regarding memory usage:
 * When creating objects, any objects passed into these APIs will be free'd when
 * the enclosing pcep_message is free'd. That includes the double_linked_list's.
 * So, just create the objects and TLVs, put them in their double_linked_list's,
 * and everything will be managed internally. The enclosing message will be
 * deleted by pcep_msg_free_message() or pcep_msg_free_message_list() which,
 * in turn will call one of: pcep_obj_free_object() and pcep_obj_free_tlv().
 * For received messages with objects, call pcep_msg_free_message() to free
 * them.
 */

enum pcep_object_classes {
	PCEP_OBJ_CLASS_OPEN = 1,
	PCEP_OBJ_CLASS_RP = 2,
	PCEP_OBJ_CLASS_NOPATH = 3,
	PCEP_OBJ_CLASS_ENDPOINTS = 4,
	PCEP_OBJ_CLASS_BANDWIDTH = 5,
	PCEP_OBJ_CLASS_METRIC = 6,
	PCEP_OBJ_CLASS_ERO = 7,
	PCEP_OBJ_CLASS_RRO = 8,
	PCEP_OBJ_CLASS_LSPA = 9,
	PCEP_OBJ_CLASS_IRO = 10,
	PCEP_OBJ_CLASS_SVEC = 11,
	PCEP_OBJ_CLASS_NOTF = 12,
	PCEP_OBJ_CLASS_ERROR = 13,
	PCEP_OBJ_CLASS_CLOSE = 15,
	PCEP_OBJ_CLASS_OF = 21,
	PCEP_OBJ_CLASS_LSP = 32,
	PCEP_OBJ_CLASS_SRP = 33,
	PCEP_OBJ_CLASS_VENDOR_INFO = 34,
	PCEP_OBJ_CLASS_INTER_LAYER = 36,  /* RFC 8282 */
	PCEP_OBJ_CLASS_SWITCH_LAYER = 37, /* RFC 8282 */
	PCEP_OBJ_CLASS_REQ_ADAP_CAP = 38, /* RFC 8282 */
	PCEP_OBJ_CLASS_SERVER_IND = 39,	  /* RFC 8282 */
	PCEP_OBJ_CLASS_ASSOCIATION = 40, /*draft-ietf-pce-association-group-10*/
	PCEP_OBJ_CLASS_MAX,
};

enum pcep_object_types {
	PCEP_OBJ_TYPE_OPEN = 1,
	PCEP_OBJ_TYPE_RP = 1,
	PCEP_OBJ_TYPE_NOPATH = 1,
	PCEP_OBJ_TYPE_ENDPOINT_IPV4 = 1,
	PCEP_OBJ_TYPE_ENDPOINT_IPV6 = 2,
	PCEP_OBJ_TYPE_BANDWIDTH_REQ = 1,
	PCEP_OBJ_TYPE_BANDWIDTH_TELSP = 2,
	PCEP_OBJ_TYPE_BANDWIDTH_CISCO =
		5, /* IANA unassigned, but rcvd from Cisco PCE */
	PCEP_OBJ_TYPE_SRP = 1,
	PCEP_OBJ_TYPE_VENDOR_INFO = 1,
	PCEP_OBJ_TYPE_LSP = 1,
	PCEP_OBJ_TYPE_METRIC = 1,
	PCEP_OBJ_TYPE_ERO = 1,
	PCEP_OBJ_TYPE_RRO = 1,
	PCEP_OBJ_TYPE_LSPA = 1,
	PCEP_OBJ_TYPE_IRO = 1,
	PCEP_OBJ_TYPE_SVEC = 1,
	PCEP_OBJ_TYPE_NOTF = 1,
	PCEP_OBJ_TYPE_ERROR = 1,
	PCEP_OBJ_TYPE_CLOSE = 1,
	PCEP_OBJ_TYPE_INTER_LAYER = 1,
	PCEP_OBJ_TYPE_SWITCH_LAYER = 1,
	PCEP_OBJ_TYPE_REQ_ADAP_CAP = 1,
	PCEP_OBJ_TYPE_SERVER_IND = 1,
	PCEP_OBJ_TYPE_ASSOCIATION_IPV4 =
		1, /*draft-ietf-pce-association-group-10*/
	PCEP_OBJ_TYPE_ASSOCIATION_IPV6 =
		2, /*draft-ietf-pce-association-group-10*/
	PCEP_OBJ_TYPE_OF = 1,
	PCEP_OBJ_TYPE_MAX = 2,
};

#define OBJECT_HEADER_FLAG_I 0x01
#define OBJECT_HEADER_FLAG_P 0x02

/* The flag_p and flag_i arent set via the APIs, if they need to be set, just
 * set them on the returned object once it has been created. */
struct pcep_object_header {
	enum pcep_object_classes object_class;
	enum pcep_object_types object_type;
	bool flag_p; /* PCC Processing rule bit: When set, the object MUST be
			taken into account, when cleared the object is optional.
		      */
	bool flag_i; /* PCE Ignore bit: indicates to a PCC whether or not an
			optional object was processed */
	double_linked_list *tlv_list;
	/* Pointer into encoded_message field from the pcep_message */
	const uint8_t *encoded_object;
	uint16_t encoded_object_length;
};

#define PCEP_OBJECT_OPEN_VERSION 1

struct pcep_object_open {
	struct pcep_object_header header;
	uint8_t open_version;	/* PCEP version. Current version is 1 */
	uint8_t open_keepalive; /* Maximum period of time between two
				   consecutive PCEP messages sent by the sender.
				 */
	uint8_t open_deadtimer; /* Specifies the amount of time before closing
				   the session down. */
	uint8_t open_sid; /* PCEP session number that identifies the current
			     session. */
};

#define OBJECT_RP_FLAG_R 0x08
#define OBJECT_RP_FLAG_B 0x10
#define OBJECT_RP_FLAG_O 0x20
#define OBJECT_RP_FLAG_OF 0x80
#define OBJECT_RP_MAX_PRIORITY 0x07

struct pcep_object_rp {
	struct pcep_object_header header;
	uint8_t priority; /* 3 bit priority, max priority is 7 */
	bool flag_reoptimization;
	bool flag_bidirectional;
	bool flag_strict;    /* when set, a loose path is acceptable */
	bool flag_of;	     /* Supply Objective Function on Response */
	uint32_t request_id; /* The Request-id-number value combined with the
				source for PCC & PCE creates a uniquely number.
			      */
};

enum pcep_notification_types {
	PCEP_NOTIFY_TYPE_PENDING_REQUEST_CANCELLED = 1,
	PCEP_NOTIFY_TYPE_PCE_OVERLOADED = 2
};

enum pcep_notification_values {
	PCEP_NOTIFY_VALUE_PCC_CANCELLED_REQUEST = 1,
	PCEP_NOTIFY_VALUE_PCE_CANCELLED_REQUEST = 2,
	PCEP_NOTIFY_VALUE_PCE_CURRENTLY_OVERLOADED = 1,
	PCEP_NOTIFY_VALUE_PCE_NO_LONGER_OVERLOADED = 2
};

struct pcep_object_notify {
	struct pcep_object_header header;
	enum pcep_notification_types notification_type;
	enum pcep_notification_values notification_value;
};

enum pcep_association_type {
	PCEP_ASSOCIATION_TYPE_PATH_PROTECTION_ASSOCIATION =
		1, // iana unique value define as 2020-01-08!
	PCEP_ASSOCIATION_TYPE_SR_POLICY_ASSOCIATION_TYPE =
		65535 // TBD1  draft-barth-pce-segment-routing-policy-cp-04
};
#define OBJECT_ASSOCIATION_FLAG_R 0x01
struct pcep_object_association_ipv4 { // draft-ietf-pce-association-group-10
	struct pcep_object_header header;
	bool R_flag;
	uint16_t association_type;
	uint16_t association_id;
	struct in_addr src;
};

struct pcep_object_association_ipv6 { // draft-ietf-pce-association-group-10
	struct pcep_object_header header;
	bool R_flag;
	uint16_t association_type;
	uint16_t association_id;
	struct in6_addr src;
};


enum pcep_nopath_nature_of_issue {
	PCEP_NOPATH_NI_NO_PATH_FOUND = 0,
	PCEP_NOPATH_NI_PCE_CHAIN_BROKEN = 1,
};

enum pcep_nopath_tlv_err_codes {
	PCEP_NOPATH_TLV_ERR_NO_TLV = 0,
	PCEP_NOPATH_TLV_ERR_PCE_UNAVAILABLE = 1,
	PCEP_NOPATH_TLV_ERR_UNKNOWN_DST = 2,
	PCEP_NOPATH_TLV_ERR_UNKNOWN_SRC = 3
};

#define OBJECT_NOPATH_FLAG_C 0x80

struct pcep_object_nopath {
	struct pcep_object_header header;
	uint8_t ni; /* Nature of Issue, reports the nature of the issue that led
		       to a negative reply */
	bool flag_c; /* when set, indicates the unsatisfied constraints by
			including relevant PCEP objects. */
	enum pcep_nopath_tlv_err_codes
		err_code; /* When set other than 0, an appropriate TLV will be
			     included */
};

struct pcep_object_endpoints_ipv4 {
	struct pcep_object_header header;
	struct in_addr src_ipv4;
	struct in_addr dst_ipv4;
};

struct pcep_object_endpoints_ipv6 {
	struct pcep_object_header header;
	struct in6_addr src_ipv6;
	struct in6_addr dst_ipv6;
};

/* PCEP floats are encoded according to:
 *   https://en.wikipedia.org/wiki/IEEE_754-1985
 * Luckily, this is the same encoding used by C */
struct pcep_object_bandwidth {
	struct pcep_object_header header;
	float bandwidth;
};

enum pcep_metric_types {
	/* RFC 5440 */
	PCEP_METRIC_IGP = 1,
	PCEP_METRIC_TE = 2,
	PCEP_METRIC_HOP_COUNT = 3,
	/* RFC 5541 */
	PCEP_METRIC_AGGREGATE_BW = 4,
	PCEP_METRIC_MOST_LOADED_LINK = 5,
	PCEP_METRIC_CUMULATIVE_IGP = 6,
	PCEP_METRIC_CUMULATIVE_TE = 7,
	/* RFC 8306 */
	PCEP_METRIC_P2MP_IGP = 8,
	PCEP_METRIC_P2MP_TE = 9,
	PCEP_METRIC_P2MP_HOP_COUNT = 10,
	/* RFC 8864 */
	PCEP_METRIC_SEGMENT_ID_DEPTH = 11,
	/* RFC 8233 */
	PCEP_METRIC_PATH_DELAY = 12,
	PCEP_METRIC_PATH_DELAY_VARIATION = 13,
	PCEP_METRIC_PATH_LOSS = 14,
	PCEP_METRIC_P2MP_PATH_DELAY = 15,
	PCEP_METRIC_P2MP_PATH_DELAY_VARIATION = 16,
	PCEP_METRIC_P2MP_PATH_LOSS = 17,
	/* RFC 8282 */
	PCEP_METRIC_NUM_PATH_ADAPTATIONS = 18,
	PCEP_METRIC_NUM_PATH_LAYERS = 19,
	/* RFC 8685 */
	PCEP_METRIC_DOMAIN_COUNT = 20,
	PCEP_METRIC_BORDER_NODE_COUNT = 21,
};

#define OBJECT_METRIC_FLAC_B 0x01
#define OBJECT_METRIC_FLAC_C 0x02

/* PCEP floats are encoded according to:
 *   https://en.wikipedia.org/wiki/IEEE_754-1985
 * Luckily, this is the same encoding used by C */
struct pcep_object_metric {
	struct pcep_object_header header;
	enum pcep_metric_types type;
	bool flag_b; /* Bound flag */
	bool flag_c; /* Computed metric */
	float value; /* Metric value in 32 bits */
};

#define OBJECT_LSPA_FLAG_L 0x01

struct pcep_object_lspa {
	struct pcep_object_header header;
	uint32_t lspa_exclude_any;
	uint32_t lspa_include_any;
	uint32_t lspa_include_all;
	uint8_t setup_priority;
	uint8_t holding_priority;
	bool flag_local_protection; /* Local protection desired bit */
};

/* The SVEC object with some custom extensions. */
#define OBJECT_SVEC_FLAG_L 0x01
#define OBJECT_SVEC_FLAG_N 0x02
#define OBJECT_SVEC_FLAG_S 0x04

struct pcep_object_svec {
	struct pcep_object_header header;
	bool flag_link_diverse;
	bool flag_node_diverse;
	bool flag_srlg_diverse;
	double_linked_list
		*request_id_list; /* list of 32-bit request ID pointers */
};

struct pcep_object_error {
	struct pcep_object_header header;
	enum pcep_error_type error_type;
	enum pcep_error_value error_value;
};

struct pcep_object_load_balancing {
	struct pcep_object_header header;
	uint8_t load_maxlsp;   /* Maximum number of TE LSPs in the set */
	uint32_t load_minband; /* Specifies the minimum bandwidth of each
				  element */
};

enum pcep_close_reason {
	PCEP_CLOSE_REASON_NO = 1,
	PCEP_CLOSE_REASON_DEADTIMER = 2,
	PCEP_CLOSE_REASON_FORMAT = 3,
	PCEP_CLOSE_REASON_UNKNOWN_REQ = 4,
	PCEP_CLOSE_REASON_UNREC_MSG = 5
};

struct pcep_object_close {
	struct pcep_object_header header;
	enum pcep_close_reason reason;
};

/* Stateful PCE Request Parameters RFC 8231, 8281 */

#define OBJECT_SRP_FLAG_R 0x01

struct pcep_object_srp {
	struct pcep_object_header header;
	bool flag_lsp_remove; /* RFC 8281 */
	uint32_t srp_id_number;
};

/* Label Switched Path Object RFC 8231 */
enum pcep_lsp_operational_status {
	PCEP_LSP_OPERATIONAL_DOWN = 0,
	PCEP_LSP_OPERATIONAL_UP = 1,
	PCEP_LSP_OPERATIONAL_ACTIVE = 2,
	PCEP_LSP_OPERATIONAL_GOING_DOWN = 3,
	PCEP_LSP_OPERATIONAL_GOING_UP = 4,
};

#define MAX_PLSP_ID 0x000fffff /* The plsp_id is only 20 bits */
#define MAX_LSP_STATUS 0x0007  /* The status is only 3 bits */
#define OBJECT_LSP_FLAG_D 0x01
#define OBJECT_LSP_FLAG_S 0x02
#define OBJECT_LSP_FLAG_R 0x04
#define OBJECT_LSP_FLAG_A 0x08
#define OBJECT_LSP_FLAG_C 0x80

struct pcep_object_lsp {
	struct pcep_object_header header;
	uint32_t plsp_id; /* plsp_id is 20 bits, must be <= MAX_PLSP_ID*/
	enum pcep_lsp_operational_status operational_status; /* max 3 bits */
	bool flag_d;
	bool flag_s;
	bool flag_r;
	bool flag_a;
	bool flag_c;
};

#define ENTERPRISE_NUMBER_CISCO 9
#define ENTERPRISE_COLOR_CISCO 65540
/* RFC 7470 */
struct pcep_object_vendor_info {
	struct pcep_object_header header;
	uint32_t enterprise_number;
	uint32_t enterprise_specific_info;
	uint32_t enterprise_specific_info1; /* cisco sends color for PcInit */
	uint32_t enterprise_specific_info2;
	uint32_t enterprise_specific_info3;
};

/* RFC 8282 */
#define OBJECT_INTER_LAYER_FLAG_I 0x01
#define OBJECT_INTER_LAYER_FLAG_M 0x02
#define OBJECT_INTER_LAYER_FLAG_T 0x04

struct pcep_object_inter_layer {
	struct pcep_object_header header;
	bool flag_i;
	bool flag_m;
	bool flag_t;
};

/* RFC 8282 */
#define OBJECT_SWITCH_LAYER_FLAG_I 0x01
enum pcep_lsp_encoding_type {
	/* Values taken from RFC 3471 as suggested by RFC 8282 */
	PCEP_LSP_ENC_PACKET = 1,
	PCEP_LSP_ENC_ETHERNET = 2,
	PCEP_LSP_ENC_PDH = 3,
	PCEP_LSP_ENC_RESERVED4 = 4,
	PCEP_LSP_ENC_SDH_SONET = 5,
	PCEP_LSP_ENC_RESERVED6 = 6,
	PCEP_LSP_ENC_DIG_WRAPPER = 7,
	PCEP_LSP_ENC_LAMBDA = 8,
	PCEP_LSP_ENC_FIBER = 9,
	PCEP_LSP_ENC_RESERVED10 = 10,
	PCEP_LSP_ENC_FIBER_CHAN = 11
};

enum pcep_switching_capability {
	/* Switching capability values taken from RFC 4203/3471 as suggested by
	   RFC 8282 */
	PCEP_SW_CAP_PSC1 = 1, /* Packet-Switch Capable-1 (PSC-1) */
	PCEP_SW_CAP_PSC2 = 2,
	PCEP_SW_CAP_PSC3 = 3,
	PCEP_SW_CAP_PSC4 = 4,
	PCEP_SW_CAP_L2SC = 51, /* Layer-2 Switch Capable */
	PCEP_SW_CAP_TDM = 100, /* Time-Division-Multiplex Capable */
	PCEP_SW_CAP_LSC = 150, /* Lambda-Switch Capable */
	PCEP_SW_CAP_FSC = 200  /* Fiber-Switch Capable */
};

struct pcep_object_switch_layer_row {
	enum pcep_lsp_encoding_type lsp_encoding_type;
	enum pcep_switching_capability switching_type;
	bool flag_i;
};

struct pcep_object_switch_layer {
	struct pcep_object_header header;
	double_linked_list
		*switch_layer_rows; /* list of struct
				       pcep_object_switch_layer_row */
};

/* RFC 8282
 * Requested Adaptation capability */

struct pcep_object_req_adap_cap {
	struct pcep_object_header header;
	enum pcep_switching_capability switching_capability;
	enum pcep_lsp_encoding_type encoding;
};

/* RFC 8282 */

struct pcep_object_server_indication {
	struct pcep_object_header header;
	enum pcep_switching_capability switching_capability;
	enum pcep_lsp_encoding_type encoding;
	/* This object is identical to req_adap_cap, except it allows TLVs */
};

/* Objective Function Object: RFC 5541 */

struct pcep_object_objective_function {
	struct pcep_object_header header;
	uint16_t of_code;
};

/*
 * Common Route Object sub-object definitions
 * used by ERO, IRO, and RRO
 */

/* Common Route Object sub-object types
 * used by ERO, IRO, and RRO */
enum pcep_ro_subobj_types {
	RO_SUBOBJ_TYPE_IPV4 = 1,  /* RFC 3209 */
	RO_SUBOBJ_TYPE_IPV6 = 2,  /* RFC 3209 */
	RO_SUBOBJ_TYPE_LABEL = 3, /* RFC 3209 */
	RO_SUBOBJ_TYPE_UNNUM = 4, /* RFC 3477 */
	RO_SUBOBJ_TYPE_ASN = 32,  /* RFC 3209, Section 4.3.3.4 */
	RO_SUBOBJ_TYPE_SR = 36, /* RFC 8408, draft-ietf-pce-segment-routing-16.
				   Type 5 for draft07 has been assigned to
				   something else. */
	RO_SUBOBJ_UNKNOWN
};

struct pcep_object_ro {
	struct pcep_object_header header;
	double_linked_list
		*sub_objects; /* list of struct pcep_object_ro_subobj */
};

struct pcep_object_ro_subobj {
	bool flag_subobj_loose_hop; /* L subobj flag */
	enum pcep_ro_subobj_types ro_subobj_type;
};

#define OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT 0x01

struct pcep_ro_subobj_ipv4 {
	struct pcep_object_ro_subobj ro_subobj;
	struct in_addr ip_addr;
	uint8_t prefix_length;
	bool flag_local_protection;
};

struct pcep_ro_subobj_ipv6 {
	struct pcep_object_ro_subobj ro_subobj;
	struct in6_addr ip_addr;
	uint8_t prefix_length;
	bool flag_local_protection;
};

struct pcep_ro_subobj_unnum {
	struct pcep_object_ro_subobj ro_subobj;
	struct in_addr router_id;
	uint32_t interface_id;
};

#define OBJECT_SUBOBJ_LABEL_FLAG_GLOGAL 0x01
struct pcep_ro_subobj_32label {
	struct pcep_object_ro_subobj ro_subobj;
	bool flag_global_label;
	uint8_t class_type; /* label class-type (generalized label = 2) */
	uint32_t label;	    /* label supported */
};

struct pcep_ro_subobj_asn {
	struct pcep_object_ro_subobj ro_subobj;
	uint16_t asn; /* Autonomous system number */
};

/* The SR ERO and SR RRO subobjects are the same, except
 * the SR-RRO does not have the L flag in the Type field.
 * Defined in draft-ietf-pce-segment-routing-16 */
enum pcep_sr_subobj_nai {
	PCEP_SR_SUBOBJ_NAI_ABSENT = 0,
	PCEP_SR_SUBOBJ_NAI_IPV4_NODE = 1,
	PCEP_SR_SUBOBJ_NAI_IPV6_NODE = 2,
	PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY = 3,
	PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY = 4,
	PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY = 5,
	PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY = 6,
	PCEP_SR_SUBOBJ_NAI_UNKNOWN
};

#define OBJECT_SUBOBJ_SR_FLAG_M 0x01
#define OBJECT_SUBOBJ_SR_FLAG_C 0x02
#define OBJECT_SUBOBJ_SR_FLAG_S 0x04
#define OBJECT_SUBOBJ_SR_FLAG_F 0x08

struct pcep_ro_subobj_sr {
	struct pcep_object_ro_subobj ro_subobj;
	enum pcep_sr_subobj_nai nai_type;
	bool flag_f;
	bool flag_s;
	bool flag_c;
	bool flag_m;

	/* The SID and NAI are optional depending on the flags,
	 * and the NAI can be variable length */
	uint32_t sid;
	double_linked_list
		*nai_list; /* double linked list of in_addr or in6_addr */
};

/* Macros to make a SID Label
 *
 * 0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Label
   |                Label                  | TC  |S|       TTL     | Stack
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Entry
 */
#define ENCODE_SR_ERO_SID(label_20bits, tc_3bits, stack_bottom_bit, ttl_8bits) \
	((((label_20bits) << 12) & 0xfffff000)                                 \
	 | (((tc_3bits) << 9) & 0x00000e00)                                    \
	 | (((stack_bottom_bit) << 8) & 0x00000100) | ((ttl_8bits)&0xff))
#define GET_SR_ERO_SID_LABEL(SID) ((SID & 0xfffff000) >> 12)
#define GET_SR_ERO_SID_TC(SID) ((SID & 0x00000e00) >> 9)
#define GET_SR_ERO_SID_S(SID) ((SID & 0x00000100) >> 8)
#define GET_SR_ERO_SID_TTL(SID) ((SID & 0x000000ff))

/*
 * All created objects will be in Host byte order, except for IPs.
 * All IP addresses are expected to be passed-in in Network byte order,
 * and any objects received will have their IPs in Network byte order.
 * The message containing the objects should be converted to Network byte order
 * with pcep_encode_msg_header() before sending, which will also convert the
 * Objects, TLVs, and sub-objects.
 */

struct pcep_object_open *pcep_obj_create_open(uint8_t keepalive,
					      uint8_t deadtimer, uint8_t sid,
					      double_linked_list *tlv_list);
struct pcep_object_rp *pcep_obj_create_rp(uint8_t priority, bool flag_r,
					  bool flag_b, bool flag_s,
					  bool flag_of, uint32_t reqid,
					  double_linked_list *tlv_list);
struct pcep_object_notify *
pcep_obj_create_notify(enum pcep_notification_types notification_type,
		       enum pcep_notification_values notification_value);
struct pcep_object_nopath *
pcep_obj_create_nopath(uint8_t ni, bool flag_c,
		       enum pcep_nopath_tlv_err_codes error_code);
struct pcep_object_association_ipv4 *
pcep_obj_create_association_ipv4(bool r_flag, uint16_t association_type,
				 uint16_t association_id, struct in_addr src);
struct pcep_object_association_ipv6 *
pcep_obj_create_association_ipv6(bool r_flag, uint16_t association_type,
				 uint16_t association_id, struct in6_addr src);
struct pcep_object_endpoints_ipv4 *
pcep_obj_create_endpoint_ipv4(const struct in_addr *src_ipv4,
			      const struct in_addr *dst_ipv4);
struct pcep_object_endpoints_ipv6 *
pcep_obj_create_endpoint_ipv6(const struct in6_addr *src_ipv6,
			      const struct in6_addr *dst_ipv6);
struct pcep_object_bandwidth *pcep_obj_create_bandwidth(float bandwidth);
struct pcep_object_metric *pcep_obj_create_metric(enum pcep_metric_types type,
						  bool flag_b, bool flag_c,
						  float value);
struct pcep_object_lspa *
pcep_obj_create_lspa(uint32_t exclude_any, uint32_t include_any,
		     uint32_t include_all, uint8_t setup_priority,
		     uint8_t holding_priority, bool flag_local_protection);
struct pcep_object_svec *
pcep_obj_create_svec(bool srlg, bool node, bool link,
		     double_linked_list *request_id_list);
struct pcep_object_error *
pcep_obj_create_error(enum pcep_error_type error_type,
		      enum pcep_error_value error_value);
struct pcep_object_close *pcep_obj_create_close(enum pcep_close_reason reason);
struct pcep_object_srp *pcep_obj_create_srp(bool lsp_remove,
					    uint32_t srp_id_number,
					    double_linked_list *tlv_list);
struct pcep_object_lsp *
pcep_obj_create_lsp(uint32_t plsp_id, enum pcep_lsp_operational_status status,
		    bool c_flag, bool a_flag, bool r_flag, bool s_flag,
		    bool d_flag, double_linked_list *tlv_list);
struct pcep_object_vendor_info *
pcep_obj_create_vendor_info(uint32_t enterprise_number,
			    uint32_t enterprise_spec_info);
struct pcep_object_inter_layer *
pcep_obj_create_inter_layer(bool flag_i, bool flag_m, bool flag_t);
struct pcep_object_switch_layer *
pcep_obj_create_switch_layer(double_linked_list *switch_layer_rows);
struct pcep_object_req_adap_cap *
pcep_obj_create_req_adap_cap(enum pcep_switching_capability sw_cap,
			     enum pcep_lsp_encoding_type encoding);
struct pcep_object_server_indication *
pcep_obj_create_server_indication(enum pcep_switching_capability sw_cap,
				  enum pcep_lsp_encoding_type encoding,
				  double_linked_list *tlv_list);
struct pcep_object_objective_function *
pcep_obj_create_objective_function(uint16_t of_code,
				   double_linked_list *tlv_list);

/* Route Object (Explicit ero, Reported rro, and Include iro) functions
 * First, the sub-objects should be created and appended to a
 * double_linked_list, then call one of these Route Object creation functions
 * with the subobj list */
struct pcep_object_ro *pcep_obj_create_ero(double_linked_list *ero_list);
struct pcep_object_ro *pcep_obj_create_rro(double_linked_list *rro_list);
struct pcep_object_ro *pcep_obj_create_iro(double_linked_list *iro_list);
/* Route Object sub-object creation functions */
struct pcep_ro_subobj_ipv4 *
pcep_obj_create_ro_subobj_ipv4(bool loose_hop, const struct in_addr *ro_ipv4,
			       uint8_t prefix_len, bool flag_local_prot);
struct pcep_ro_subobj_ipv6 *
pcep_obj_create_ro_subobj_ipv6(bool loose_hop, const struct in6_addr *ro_ipv6,
			       uint8_t prefix_len, bool flag_local_prot);
struct pcep_ro_subobj_unnum *
pcep_obj_create_ro_subobj_unnum(struct in_addr *router_id, uint32_t if_id);
struct pcep_ro_subobj_32label *
pcep_obj_create_ro_subobj_32label(bool flag_global_label, uint8_t class_type,
				  uint32_t label);
struct pcep_ro_subobj_asn *pcep_obj_create_ro_subobj_asn(uint16_t asn);

/* SR ERO and SR RRO creation functions for different NAI (Node/Adj ID) types.
 *  - The loose_hop is only used for sr ero and must always be false for sr rro.
 *  - The NAI value will be set internally, depending on which function is used.
 * m_flag:
 *  - If this flag is true, the SID value represents an MPLS label stack
 *    entry as specified in [RFC3032].  Otherwise, the SID value is an
 *    administratively configured value which represents an index into
 *    an MPLS label space (either SRGB or SRLB) per [RFC8402].
 * c_flag:
 *  - If the M flag and the C flag are both true, then the TC, S, and TTL
 *    fields in the MPLS label stack entry are specified by the PCE.  However,
 *    a PCC MAY choose to override these values according to its local policy
 *    and MPLS forwarding rules.
 *  - If the M flag is true but the C flag is false, then the TC, S, and TTL
 *    fields MUST be ignored by the PCC.
 *  - The PCC MUST set these fields according to its local policy and MPLS
 *    forwarding rules.
 *  - If the M flag is false then the C bit MUST be false. */
struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_nonai(bool loose_hop,
							     uint32_t sid,
							     bool c_flag,
							     bool m_flag);

/* The ipv4_node_id will be copied internally */
struct pcep_ro_subobj_sr *
pcep_obj_create_ro_subobj_sr_ipv4_node(bool loose_hop, bool sid_absent,
				       bool c_flag, bool m_flag, uint32_t sid,
				       struct in_addr *ipv4_node_id);
/* The ipv6_node_id will be copied internally */
struct pcep_ro_subobj_sr *
pcep_obj_create_ro_subobj_sr_ipv6_node(bool loose_hop, bool sid_absent,
				       bool c_flag, bool m_flag, uint32_t sid,
				       struct in6_addr *ipv6_node_id);
/* The local_ipv4 and remote_ipv4 will be copied internally */
struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_ipv4_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in_addr *local_ipv4, struct in_addr *remote_ipv4);
/* The local_ipv6 and remote_ipv6 will be copied internally */
struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_ipv6_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in6_addr *local_ipv6, struct in6_addr *remote_ipv6);
struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	uint32_t local_node_id, uint32_t local_if_id, uint32_t remote_node_id,
	uint32_t remote_if_id);
/* The local_ipv6 and remote_ipv6 will be copied internally */
struct pcep_ro_subobj_sr *pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
	bool loose_hop, bool sid_absent, bool c_flag, bool m_flag, uint32_t sid,
	struct in6_addr *local_ipv6, uint32_t local_if_id,
	struct in6_addr *remote_ipv6, uint32_t remote_if_id);

#ifdef __cplusplus
}
#endif

#endif
