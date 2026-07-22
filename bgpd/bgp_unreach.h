// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#ifndef _QUAGGA_BGP_UNREACH_H
#define _QUAGGA_BGP_UNREACH_H

#include "prefix.h"
#include "lib/json.h"
#include "bgpd.h"
#include "bgpd/bgp_route.h"

extern const char *bgp_origin_str[];
extern const char *bgp_origin_long_str[];

/* Status codes for SAFI_UNREACH (informational only, not installed in RIB/FIB) */
#define BGP_UNREACH_SHOW_SCODE_HEADER                                                              \
	"Status codes:  s suppressed, d damped, h history, u unsorted, * valid, > best,\n"         \
	"               i internal, S Stale, R Removed\n"

/* Display headers for SAFI_UNREACH (similar to BGP_SHOW_HEADER in bgp_route.h) */
#define BGP_UNREACH_SHOW_HEADER                                                                    \
	"    %-18s %7s %7s %7s %-19s %-17s %s\n", "Network", "Metric", "LocPrf", "Weight",         \
		"Reason", "Reporter", "Path"

#define BGP_UNREACH_SHOW_HEADER_WIDE                                                               \
	"    %-48s %7s %7s %7s %-19s %-17s %s\n", "Network", "Metric", "LocPrf", "Weight",         \
		"Reason", "Reporter", "Path"

/* Reporter TLV Type (Section 3.4 of draft) */
#define BGP_UNREACH_TLV_TYPE_REPORTER 1

/* Sub-TLV Types (Section 3.5) - nested inside Reporter TLV */
#define BGP_UNREACH_SUBTLV_TYPE_REASON_CODE 1
#define BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP   2

/* Wire format length constants - Per RFC draft Section 3.4-3.5 */
#define BGP_UNREACH_TLV_HEADER_LEN    3 /* Type(1) + Length(2) */
#define BGP_UNREACH_SUBTLV_HEADER_LEN 3 /* Sub-Type(1) + Sub-Length(2) */

/*
 * Per-NLRI Length field (draft -06, length-prefixed NLRI envelope).
 *
 * Each Unreachability NLRI is framed as:
 *   [NLRI Length (2 octets)][Prefix Length (1)][Prefix][Reporter TLVs]
 * where NLRI Length counts every octet after itself, i.e. the Prefix
 * Length octet, the Prefix, and all Reporter TLVs (zero on withdraw).
 * The AddPath Path Identifier, when present, precedes the NLRI Length
 * field and is NOT counted in it.
 *
 * This explicit bound aligns with the EVPN IP Prefix Unreachability
 * Route (draft-tantsura-bess-evpn-unreachability), which inherits the
 * RFC 7432 length-prefixed NLRI envelope, and removes the -05 wire
 * ambiguity where the byte after a Reporter TLV could be either a
 * continuation Reporter TLV or the next NLRI's Prefix Length.
 */
#define BGP_UNREACH_NLRI_LEN_SIZE 2

/* TLV header field offsets */
#define BGP_UNREACH_TLV_TYPE_OFFSET 0 /* TLV Type field */
#define BGP_UNREACH_TLV_LEN_OFFSET  1 /* TLV Length field (2 bytes) */

/* Reporter TLV (Type 1) fixed fields */
#define BGP_UNREACH_REPORTER_ID_LEN 4 /* BGP Router ID */
#define BGP_UNREACH_REPORTER_AS_LEN 4 /* AS Number (4-octet) */
#define BGP_UNREACH_REPORTER_FIXED_LEN                                                             \
	(BGP_UNREACH_REPORTER_ID_LEN + BGP_UNREACH_REPORTER_AS_LEN) /* 8 bytes */

/* Sub-TLV payload lengths */
#define BGP_UNREACH_REASON_CODE_LEN 2 /* Sub-TLV Type 1 payload */
#define BGP_UNREACH_TIMESTAMP_LEN   8 /* Sub-TLV Type 2 payload */

/* Minimum Reporter TLV size (no Sub-TLVs) */
#define BGP_UNREACH_REPORTER_TLV_MIN_LEN                                                           \
	(BGP_UNREACH_TLV_HEADER_LEN + BGP_UNREACH_REPORTER_FIXED_LEN) /* 3+8=11 */

/* Maximum reasonable TLV sizes (sanity checks) */
#define BGP_UNREACH_TLV_MAX_LEN 255 /* Reasonable upper bound for single TLV */

/*
 * Maximum Reporter TLVs accepted per NLRI (draft Section 4.8, RECOMMENDED
 * 50) to bound UI-RIB state from a misbehaving or aggregating peer.
 */
#define BGP_UNREACH_REPORTER_TLV_MAX_PER_ROUTE 50

/*
 * Reporter TLV parse error identifiers (used by the unreach_tlv_parse_error
 * LTTng tracepoint to label which validation rejected the TLV). Values must
 * match the unreach_tlv_error TRACEPOINT_ENUM in bgpd/bgp_trace.h.
 */
enum bgp_unreach_tlv_error {
	UNREACH_TLV_ERR_NLRI_TOO_SHORT = 1,
	UNREACH_TLV_ERR_TRUNCATED_TLV_HEADER = 2,
	UNREACH_TLV_ERR_INVALID_TLV_TYPE = 3,
	UNREACH_TLV_ERR_REPORTER_TLV_TOO_SHORT = 4,
	UNREACH_TLV_ERR_REPORTER_TLV_OVERFLOW = 5,
	UNREACH_TLV_ERR_TRUNCATED_REPORTER_ID = 6,
	UNREACH_TLV_ERR_TRUNCATED_REPORTER_AS = 7,
	UNREACH_TLV_ERR_TRUNCATED_SUBTLV_HEADER = 8,
	UNREACH_TLV_ERR_SUBTLV_LENGTH_OVERFLOW = 9,
	UNREACH_TLV_ERR_ZERO_LENGTH_SUBTLV = 10,
	UNREACH_TLV_ERR_INVALID_REASON_CODE_LEN = 11,
	UNREACH_TLV_ERR_INVALID_TIMESTAMP_LEN = 12,
	UNREACH_TLV_ERR_LENGTH_EXCEEDS_LIMIT = 13,
	UNREACH_TLV_ERR_TOO_MANY_REPORTER_TLVS = 14,
};

/*
 * NLRI parse error identifiers (used by the unreach_nlri_parse_error LTTng
 * tracepoint). Numbered from 101 so TLV and NLRI errors share one trace
 * field type without value collisions. Values must match the
 * unreach_nlri_error TRACEPOINT_ENUM in bgpd/bgp_trace.h.
 */
enum bgp_unreach_nlri_error {
	UNREACH_NLRI_ERR_ADDPATH_OVERFLOW = 101,
	UNREACH_NLRI_ERR_PREMATURE_END = 102,
	UNREACH_NLRI_ERR_INVALID_PREFIX_LEN = 103,
	UNREACH_NLRI_ERR_PREFIX_OVERFLOW = 104,
	UNREACH_NLRI_ERR_REPORTER_TLV_TOO_SHORT = 106,
	UNREACH_NLRI_ERR_REPORTER_TLV_EXCEEDS_PKT = 107,
	UNREACH_NLRI_ERR_REPORTER_TLV_PARSE_FAIL = 108,
	UNREACH_NLRI_ERR_REPORTER_TLV_LENGTH_EXCEEDS_LIMIT = 109,
	UNREACH_NLRI_ERR_TRUNCATED_NLRI_LEN = 110,
	UNREACH_NLRI_ERR_NLRI_LEN_OVERFLOW = 111,
};

/* Unreachability Reason Code values (Sub-TLV Type 1) */
enum bgp_unreach_reason_code {
	BGP_UNREACH_REASON_UNSPECIFIED = 0,
	BGP_UNREACH_REASON_POLICY_BLOCKED = 1,
	BGP_UNREACH_REASON_SECURITY_FILTERED = 2,
	BGP_UNREACH_REASON_RPKI_INVALID = 3,
	BGP_UNREACH_REASON_NO_EXPORT_POLICY = 4,
	BGP_UNREACH_REASON_MARTIAN_ADDRESS = 5,
	BGP_UNREACH_REASON_BOGON_PREFIX = 6,
	BGP_UNREACH_REASON_MAINTENANCE = 7,
	BGP_UNREACH_REASON_LOCAL_ADMIN_ACTION = 8,
	BGP_UNREACH_REASON_LOCAL_LINK_DOWN = 9,
	/* 10-64535: Reserved */
	/* 64536-65535: Reserved for Private Use */
};

/* Unreachability Information NLRI */
struct bgp_unreach_nlri {
	struct prefix prefix;
	struct in_addr reporter; /* BGP Router ID */
	uint32_t reporter_as;	 /* Reporter AS Number (4-octet) */
	uint16_t reason_code;	 /* Reason code (Sub-TLV Type 1) */
	uint64_t timestamp;	 /* Unix timestamp (Sub-TLV Type 2) */
	bool has_reporter;
	bool has_reporter_as;
	bool has_reason_code;
	bool has_timestamp;
	/*
	 * True if reason_code was filled in by the parser using the spec
	 * default (Unspecified / 0) because the Reason Code Sub-TLV was
	 * absent. Set independently of has_reason_code so that show output
	 * can distinguish "peer sent code 0" from "Sub-TLV absent, treated
	 * as Unspecified per draft-tantsura-idr-unreachability-safi §3.5.1".
	 */
	bool defaulted_reason_code;
};

/* Function prototypes */

/* NLRI encoding/decoding */
extern int bgp_nlri_parse_unreach(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
				  bool withdraw);

/* TLV handling */
extern int bgp_unreach_tlv_parse(uint8_t *data, uint16_t len, struct bgp_unreach_nlri *unreach);
extern int bgp_unreach_tlv_encode(struct stream *s, struct bgp_unreach_nlri *unreach);

/* UI-RIB helpers for self-originated unreachability information */
extern int bgp_unreach_info_add(struct bgp *bgp, afi_t afi, struct bgp_unreach_nlri *nlri,
				struct attr *attr);
extern void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, const struct prefix *prefix);

/* Reason code / display API */
extern const char *bgp_unreach_reason_str(uint16_t code);
extern int bgp_unreach_reason_str2code(const char *str, uint16_t *code);
extern void bgp_unreach_show(struct vty *vty, struct bgp *bgp, afi_t afi,
			     struct prefix *prefix, bool use_json, bool detail,
			     enum bgp_show_type type, void *output_arg);

/*
 * Emit a Reporter TLV as a JSON sub-object on json_path with the schema:
 *   "reporters": { "<reporter_ip>": { "AS": <as>,
 *                                    "subtlv": { "reason": "<str>",
 *                                                "timestamp": {...} } } }
 * brief omits the subtlv; include_timestamp gates inclusion of the
 * timestamp Sub-TLV when present.
 */
extern void bgp_unreach_reporters_to_json(struct bgp_path_info_extra_unreach *unreach,
					  json_object *json_path, bool brief,
					  bool include_timestamp);

extern void bgp_unreach_vty_init(void);

#endif /* _QUAGGA_BGP_UNREACH_H */
