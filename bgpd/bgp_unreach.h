// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#ifndef _QUAGGA_BGP_UNREACH_H
#define _QUAGGA_BGP_UNREACH_H

#include "prefix.h"
#include "bgpd.h"

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
};

/* Function prototypes */

/* NLRI encoding/decoding */
extern int bgp_nlri_parse_unreach(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
				  bool withdraw);

/* TLV handling */
extern int bgp_unreach_tlv_parse(uint8_t *data, uint16_t len, struct bgp_unreach_nlri *unreach);
extern int bgp_unreach_tlv_encode(struct stream *s, struct bgp_unreach_nlri *unreach);


#endif /* _QUAGGA_BGP_UNREACH_H */
