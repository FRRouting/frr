// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 *
 * Wire format per draft-tantsura-idr-unreachability-safi:
 *
 * NLRI Format (Section 3.2-3.3):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Prefix Length |           Prefix (variable)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Reporter TLV (variable)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Reporter TLV Format (Section 3.4):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type=1    |            Length             |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |              Reporter Identifier (4 octets)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Reporter AS Number (4 octets)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sub-TLVs (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Sub-TLV Format (Section 3.5):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Sub-Type    |         Sub-Length            |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |                   Sub-Value (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Implementation notes:
 * - Multiple NLRIs can be packed in single UPDATE message
 * - Current implementation: 1 Reporter TLV per NLRI (no aggregation)
 * - Unknown Sub-TLV types are silently ignored (forward compatibility)
 */

#include <zebra.h>

#include "prefix.h"
#include "log.h"
#include "stream.h"
#include "memory.h"
#include "command.h"
#include "json.h"
#include "frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"

/* Helper function to convert reason code to string */
const char *bgp_unreach_reason_str(uint16_t code)
{
	static const char *const reason_names[] = {
		"Unspecified",	      /* 0 */
		"Policy-Blocked",     /* 1 */
		"Security-Filtered",  /* 2 */
		"RPKI-Invalid",	      /* 3 */
		"No-Export-Policy",   /* 4 */
		"Martian-Address",    /* 5 */
		"Bogon-Prefix",	      /* 6 */
		"Maintenance",        /* 7 */
		"Local-Admin-Action", /* 8 */
		"Local-Link-Down"     /* 9 */
	};

	if (code <= 9)
		return reason_names[code];
	else if (code >= 64536)
		return "Private-Use";
	else
		return "Reserved";
}

/* Helper function to convert reason string to code
 * Returns 0 on success, -1 if the string is not recognized
 */
int bgp_unreach_reason_str2code(const char *str, uint16_t *code)
{
	if (strmatch(str, "unspecified"))
		*code = BGP_UNREACH_REASON_UNSPECIFIED;
	else if (strmatch(str, "policy-blocked"))
		*code = BGP_UNREACH_REASON_POLICY_BLOCKED;
	else if (strmatch(str, "security-filtered"))
		*code = BGP_UNREACH_REASON_SECURITY_FILTERED;
	else if (strmatch(str, "rpki-invalid"))
		*code = BGP_UNREACH_REASON_RPKI_INVALID;
	else if (strmatch(str, "no-export-policy"))
		*code = BGP_UNREACH_REASON_NO_EXPORT_POLICY;
	else if (strmatch(str, "martian-address"))
		*code = BGP_UNREACH_REASON_MARTIAN_ADDRESS;
	else if (strmatch(str, "bogon-prefix"))
		*code = BGP_UNREACH_REASON_BOGON_PREFIX;
	else if (strmatch(str, "maintenance"))
		*code = BGP_UNREACH_REASON_MAINTENANCE;
	else if (strmatch(str, "local-admin-action"))
		*code = BGP_UNREACH_REASON_LOCAL_ADMIN_ACTION;
	else if (strmatch(str, "local-link-down"))
		*code = BGP_UNREACH_REASON_LOCAL_LINK_DOWN;
	else
		return -1;

	return 0;
}

int bgp_unreach_tlv_encode(struct stream *s, struct bgp_unreach_nlri *unreach)
{
	/* Calculate Reporter TLV total length:
	 * - Reporter ID (4 bytes) + Reporter AS (4 bytes) = 8 bytes fixed
	 * - Sub-TLV Type 1 (Reason): 3 + 2 = 5 bytes (if present)
	 * - Sub-TLV Type 2 (Timestamp): 3 + 8 = 11 bytes (if present)
	 */
	uint16_t reporter_tlv_len = BGP_UNREACH_REPORTER_FIXED_LEN;
	size_t needed;

	if (unreach->has_reason_code)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_REASON_CODE_LEN;

	if (unreach->has_timestamp)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_TIMESTAMP_LEN;

	/*
	 * Verify the stream has room for header + value before any writes.
	 * FRR's stream_put* primitives assert-fail on overflow which would
	 * abort bgpd; refuse to encode and let the caller propagate failure
	 * instead.
	 */
	needed = (size_t)BGP_UNREACH_TLV_HEADER_LEN + reporter_tlv_len;
	if (STREAM_WRITEABLE(s) < needed)
		return -1;

	/* Encode Reporter TLV header */
	stream_putc(s, BGP_UNREACH_TLV_TYPE_REPORTER);
	stream_putw(s, reporter_tlv_len);

	/* Reporter Identifier (4 bytes) - mandatory */
	stream_put(s, &unreach->reporter, BGP_UNREACH_REPORTER_ID_LEN);

	/* Reporter AS Number (4 bytes) - mandatory */
	stream_putl(s, unreach->reporter_as);

	/* Sub-TLV Type 1: Reason Code (optional) */
	if (unreach->has_reason_code) {
		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_REASON_CODE);
		stream_putw(s, BGP_UNREACH_REASON_CODE_LEN);
		stream_putw(s, unreach->reason_code);
	}

	/* Sub-TLV Type 2: Timestamp (optional) */
	if (unreach->has_timestamp) {
		uint64_t ts = htobe64(unreach->timestamp);

		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP);
		stream_putw(s, BGP_UNREACH_TIMESTAMP_LEN);
		stream_put(s, &ts, BGP_UNREACH_TIMESTAMP_LEN);
	}

	return 0;
}

/* Show unreachability information */
