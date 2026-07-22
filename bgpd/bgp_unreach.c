// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 *
 * Wire format per draft-tantsura-idr-unreachability-safi:
 *
 * NLRI Format (length-prefixed envelope, draft -06):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              NLRI Length (2 octets)           | Prefix Length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Prefix (variable)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Reporter TLV(s) (variable)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * NLRI Length counts every octet after itself (Prefix Length octet,
 * Prefix, and all Reporter TLVs). With AddPath the 4-octet Path
 * Identifier precedes NLRI Length and is not counted. The explicit
 * length bounds the Reporter TLV region so the next NLRI boundary is
 * unambiguous even when multiple Reporter TLVs follow a prefix
 * (aggregation), mirroring the EVPN IP Prefix Unreachability Route's
 * RFC 7432 length-prefixed envelope.
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
 * - This implementation encodes exactly 1 Reporter TLV per NLRI (no
 *   aggregation). On receive it parses the first Reporter TLV (which
 *   the draft pins to the best path) and skips any additional Reporter
 *   TLVs in the NLRI's bounded region without resetting the session.
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
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_trace.h"

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

/*
 * ctime_r() returns a string terminated by '\n', which then ends up
 * embedded inside JSON values. Wrap it so every JSON timestamp string
 * in this file is newline-stripped at the source.
 */
static char *unreach_ctime_r(const time_t *t, char *buf)
{
	char *s = ctime_r(t, buf);
	size_t l;

	if (!s)
		return s;
	l = strlen(s);
	if (l && s[l - 1] == '\n')
		s[l - 1] = '\0';
	return s;
}

/*
 * Emit the Reporter TLV recorded on a SAFI_UNREACH path as a JSON
 * sub-object hanging off json_path. The schema is:
 *
 *   "reporters": {
 *       "<reporter_ip>": {
 *           "AS": <reporter_as>,
 *           "subtlv": {
 *               "reason": "<reason_str>",
 *               "timestamp": { "epoch": N, "string": "..." }
 *           }
 *       }
 *   }
 *
 * The reporter IP is the object key so future support for multiple
 * Reporter TLVs per route (draft-tantsura-idr-unreachability-safi
 * Section 3.4) can be modelled as additional sibling entries. brief
 * omits the subtlv container. include_timestamp gates inclusion of
 * the Timestamp Sub-TLV when present.
 */
void bgp_unreach_reporters_to_json(struct bgp_path_info_extra_unreach *unreach,
				   json_object *json_path, bool brief,
				   bool include_timestamp)
{
	json_object *json_reporters;
	json_object *json_rep;
	json_object *json_subtlv = NULL;
	char reporter_str[INET_ADDRSTRLEN];

	if (!unreach)
		return;

	/*
	 * Avoid emitting an empty "reporters": {"unknown": {}} object when
	 * the path carries no Reporter information at all. Brief callers
	 * only render the reporter identity; non-brief callers also render
	 * reason/timestamp, so the guard widens accordingly.
	 */
	if (brief && !unreach->has_reporter && !unreach->has_reporter_as)
		return;
	if (!brief && !unreach->has_reporter && !unreach->has_reporter_as &&
	    !unreach->has_reason_code &&
	    (!include_timestamp || !unreach->has_timestamp))
		return;

	if (unreach->has_reporter)
		inet_ntop(AF_INET, &unreach->reporter, reporter_str,
			  sizeof(reporter_str));
	else
		snprintf(reporter_str, sizeof(reporter_str), "unknown");

	json_reporters = json_object_new_object();
	json_rep = json_object_new_object();

	if (unreach->has_reporter_as)
		json_object_int_add(json_rep, "AS", unreach->reporter_as);

	if (!brief &&
	    (unreach->has_reason_code ||
	     (include_timestamp && unreach->has_timestamp))) {
		json_subtlv = json_object_new_object();

		if (unreach->has_reason_code)
			json_object_string_add(json_subtlv, "reason",
					       bgp_unreach_reason_str(
						       unreach->reason_code));

		if (include_timestamp && unreach->has_timestamp) {
			time_t ts = (time_t)unreach->timestamp;
			char timebuf[64];
			json_object *json_ts = json_object_new_object();

			json_object_int_add(json_ts, "epoch", (int64_t)ts);
			json_object_string_add(json_ts, "string",
					       unreach_ctime_r(&ts, timebuf));
			json_object_object_add(json_subtlv, "timestamp",
					       json_ts);
		}

		json_object_object_add(json_rep, "subtlv", json_subtlv);
	}

	json_object_object_add(json_reporters, reporter_str, json_rep);
	json_object_object_add(json_path, "reporters", json_reporters);
}

/*
 * Path iteration filter for "show bgp <afi> unreachability neighbors
 * <peer> routes": skip paths not learned from output_arg.
 */
static inline bool bgp_unreach_skip_for_neighbor(struct bgp_path_info *pi,
						 enum bgp_show_type type,
						 void *output_arg)
{
	union sockunion *su;

	if (type != bgp_show_type_neighbor)
		return false;

	su = output_arg;
	if (!su || !pi->peer || !pi->peer->connection ||
	    !pi->peer->connection->su_remote ||
	    !sockunion_same(pi->peer->connection->su_remote, su))
		return true;

	return false;
}

/* Parse Reporter TLV from unreachability NLRI
 *
 * Extracts Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 *
 * Parameters:
 *   data - Pointer to start of ONE Reporter TLV (Type + Length + payload)
 *   len  - Length of THIS Reporter TLV only (caller pre-calculated)
 *   unreach - Output structure to store parsed fields
 *
 * Returns:
 *   0 on success
 *   -1 on parse error
 */
int bgp_unreach_tlv_parse(uint8_t *data, uint16_t len, struct bgp_unreach_nlri *unreach)
{
	uint8_t *pnt = data;
	uint8_t *end = data + len;
	uint8_t *reporter_end;
	uint8_t tlv_type;
	uint16_t tlv_len;

	/* Initialize */
	memset(&unreach->reporter, 0, sizeof(unreach->reporter));
	unreach->reporter_as = 0;
	unreach->reason_code = 0;
	unreach->timestamp = 0;
	unreach->has_reason_code = false;
	unreach->has_timestamp = false;
	unreach->has_reporter = false;
	unreach->has_reporter_as = false;
	unreach->defaulted_reason_code = false;

	/*
	 * All bounds checks below use (end - pnt) subtraction form rather
	 * than pnt + N > end to avoid pointer-arithmetic UB on hostile
	 * inputs where the addition could overflow.
	 */

	/* Validate minimum length for Reporter TLV */
	if (len < BGP_UNREACH_REPORTER_TLV_MIN_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
			 "[UNREACH] Unreachability TLV too short: %u bytes (min %u)", len,
			 BGP_UNREACH_REPORTER_TLV_MIN_LEN);
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_NLRI_TOO_SHORT, 0, len, 0, 0,
			 BGP_UNREACH_REPORTER_TLV_MIN_LEN);
		return -1;
	}

	/* Parse Reporter TLV header (Type 1 - mandatory container) */
	if ((size_t)(end - pnt) < BGP_UNREACH_TLV_HEADER_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE, "Truncated Reporter TLV header");
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_TRUNCATED_TLV_HEADER, 0, (uint16_t)(end - pnt), 0,
			 0, BGP_UNREACH_TLV_HEADER_LEN);
		return -1;
	}

	tlv_type = *pnt++;
	tlv_len = ((uint16_t)*pnt++ << 8);
	tlv_len |= *pnt++;

	/* Validate Reporter TLV Type */
	if (tlv_type != BGP_UNREACH_TLV_TYPE_REPORTER) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
			 "Invalid TLV type: expected %u (Reporter), got %u",
			 BGP_UNREACH_TLV_TYPE_REPORTER, tlv_type);
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_INVALID_TLV_TYPE, tlv_type, tlv_len, 0, 0,
			 BGP_UNREACH_TLV_TYPE_REPORTER);
		return -1;
	}

	/* Validate Reporter TLV length against the spec-defined minimum */
	if (tlv_len < BGP_UNREACH_REPORTER_FIXED_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
			 "Reporter TLV too short: %u bytes (min %u)", tlv_len,
			 BGP_UNREACH_REPORTER_FIXED_LEN);
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_REPORTER_TLV_TOO_SHORT, tlv_type, tlv_len, 0, 0,
			 BGP_UNREACH_REPORTER_FIXED_LEN);
		return -1;
	}

	/*
	 * Enforce an implementation upper bound on a single Reporter TLV
	 * (draft Section 4.8 - bound resource usage from misbehaving peers).
	 */
	if (tlv_len > BGP_UNREACH_TLV_MAX_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
			 "Reporter TLV length %u exceeds limit %u", tlv_len,
			 BGP_UNREACH_TLV_MAX_LEN);
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_LENGTH_EXCEEDS_LIMIT, tlv_type, tlv_len, 0, 0,
			 BGP_UNREACH_TLV_MAX_LEN);
		return -1;
	}

	if ((size_t)(end - pnt) < tlv_len) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
			 "Reporter TLV length %u exceeds remaining %td", tlv_len,
			 (end - pnt));
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_REPORTER_TLV_OVERFLOW, tlv_type, tlv_len, 0, 0,
			 (uint16_t)(end - pnt));
		return -1;
	}

	reporter_end = pnt + tlv_len;

	/* Extract Reporter Identifier (4 bytes) - mandatory */
	if ((size_t)(reporter_end - pnt) < BGP_UNREACH_REPORTER_ID_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE, "Truncated Reporter Identifier");
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_TRUNCATED_REPORTER_ID, tlv_type, tlv_len, 0, 0,
			 BGP_UNREACH_REPORTER_ID_LEN);
		return -1;
	}
	memcpy(&unreach->reporter, pnt, BGP_UNREACH_REPORTER_ID_LEN);
	unreach->has_reporter = true;
	pnt += BGP_UNREACH_REPORTER_ID_LEN;

	/* Extract Reporter AS Number (4 bytes) - mandatory */
	if ((size_t)(reporter_end - pnt) < BGP_UNREACH_REPORTER_AS_LEN) {
		flog_err(EC_BGP_UNREACH_PARSE_FAILURE, "Truncated Reporter AS Number");
		frrtrace(6, frr_bgp, unreach_tlv_parse_error,
			 UNREACH_TLV_ERR_TRUNCATED_REPORTER_AS, tlv_type, tlv_len, 0, 0,
			 BGP_UNREACH_REPORTER_AS_LEN);
		return -1;
	}
	unreach->reporter_as = ((uint32_t)*pnt++ << 24);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 16);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 8);
	unreach->reporter_as |= *pnt++;
	unreach->has_reporter_as = true;

	/*
	 * Parse Sub-TLVs.
	 *
	 * Per draft-tantsura-idr-unreachability-safi Sections 3.5 and 5.4,
	 * duplicate Sub-TLVs of the same Sub-Type within a single Reporter
	 * TLV MUST keep only the first occurrence; later duplicates are
	 * discarded but their length is still validated.
	 */
	while (pnt < reporter_end) {
		uint8_t sub_type;
		uint16_t sub_len;

		/*
		 * Draft Section 5.4: a Sub-TLV whose Sub-Length is
		 * inconsistent with the data available within the enclosing
		 * Reporter TLV MUST be discarded. A truncated header or a
		 * bogus Sub-Length makes the next Sub-TLV boundary
		 * unknowable, so stop parsing Sub-TLVs while keeping the
		 * already-parsed (well-formed) Reporter TLV.
		 */
		if ((size_t)(reporter_end - pnt) < BGP_UNREACH_SUBTLV_HEADER_LEN) {
			frrtrace(6, frr_bgp, unreach_tlv_parse_error,
				 UNREACH_TLV_ERR_TRUNCATED_SUBTLV_HEADER, tlv_type, tlv_len,
				 0, 0, BGP_UNREACH_SUBTLV_HEADER_LEN);
			break;
		}

		sub_type = *pnt++;
		sub_len = ((uint16_t)*pnt++ << 8);
		sub_len |= *pnt++;

		if ((size_t)(reporter_end - pnt) < sub_len) {
			frrtrace(6, frr_bgp, unreach_tlv_parse_error,
				 UNREACH_TLV_ERR_SUBTLV_LENGTH_OVERFLOW, tlv_type, tlv_len,
				 sub_type, sub_len, (uint16_t)(reporter_end - pnt));
			break;
		}

		/* Zero-length Sub-TLV: malformed and cannot be advanced past. */
		if (sub_len == 0) {
			frrtrace(6, frr_bgp, unreach_tlv_parse_error,
				 UNREACH_TLV_ERR_ZERO_LENGTH_SUBTLV, tlv_type, tlv_len,
				 sub_type, sub_len, 1);
			break;
		}

		switch (sub_type) {
		case BGP_UNREACH_SUBTLV_TYPE_REASON_CODE:
			if (sub_len != BGP_UNREACH_REASON_CODE_LEN) {
				/*
				 * Draft Section 5.4: a recognized Sub-TLV with
				 * an inconsistent length is discarded; the
				 * length fits in the Reporter TLV so processing
				 * of the remaining Sub-TLVs continues.
				 */
				frrtrace(6, frr_bgp, unreach_tlv_parse_error,
					 UNREACH_TLV_ERR_INVALID_REASON_CODE_LEN, tlv_type,
					 tlv_len, sub_type, sub_len,
					 BGP_UNREACH_REASON_CODE_LEN);
				break;
			}
			/*
			 * Draft Sections 3.5 / 5.4: keep first occurrence
			 * only. Length was already validated above so a
			 * later malformed duplicate still gets caught.
			 */
			if (!unreach->has_reason_code) {
				unreach->reason_code = ((uint16_t)*pnt << 8);
				unreach->reason_code |= *(pnt + 1);
				unreach->has_reason_code = true;
			}
			break;

		case BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP:
			if (sub_len != BGP_UNREACH_TIMESTAMP_LEN) {
				/*
				 * Draft Section 5.4: a recognized Sub-TLV with
				 * an inconsistent length is discarded; the
				 * length fits in the Reporter TLV so processing
				 * of the remaining Sub-TLVs continues.
				 */
				frrtrace(6, frr_bgp, unreach_tlv_parse_error,
					 UNREACH_TLV_ERR_INVALID_TIMESTAMP_LEN, tlv_type,
					 tlv_len, sub_type, sub_len,
					 BGP_UNREACH_TIMESTAMP_LEN);
				break;
			}
			if (!unreach->has_timestamp) {
				unreach->timestamp = ((uint64_t)*pnt << 56);
				unreach->timestamp |= ((uint64_t)*(pnt + 1) << 48);
				unreach->timestamp |= ((uint64_t)*(pnt + 2) << 40);
				unreach->timestamp |= ((uint64_t)*(pnt + 3) << 32);
				unreach->timestamp |= ((uint64_t)*(pnt + 4) << 24);
				unreach->timestamp |= ((uint64_t)*(pnt + 5) << 16);
				unreach->timestamp |= ((uint64_t)*(pnt + 6) << 8);
				unreach->timestamp |= *(pnt + 7);
				unreach->has_timestamp = true;
			}
			break;

		default:
			/*
			 * Unknown Sub-TLV: silently ignore per draft
			 * Sections 3.5 / 5.4 (extensibility). Advance
			 * past it using the length field.
			 */
			break;
		}

		pnt += sub_len;
	}

	/*
	 * Draft Section 3.5.1: a Reporter TLV with no Reason Code Sub-TLV
	 * is valid and MUST be treated as Unspecified (code 0). Track that
	 * we applied the default in 'defaulted_reason_code' so callers /
	 * display can distinguish "peer sent 0" from "Sub-TLV absent".
	 */
	if (!unreach->has_reason_code) {
		unreach->reason_code = BGP_UNREACH_REASON_UNSPECIFIED;
		unreach->defaulted_reason_code = true;
	}

	return 0;
}

/* Encode Reporter TLV into stream
 *
 * Encodes Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 */
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

/* Parse unreachability NLRI
 *
 * Parses one or more UNREACH NLRIs from UPDATE message.
 * Wire format documented at top of file.
 */
int bgp_nlri_parse_unreach(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			   bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize = 0;
	uint8_t prefixlen;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	struct bgp_unreach_nlri unreach;

	/* Start processing the NLRI */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	while (pnt < lim) {
		bool treat_as_withdraw = false;
		uint16_t nlri_len;
		uint8_t *nlri_end;

		/* Clear structures */
		memset(&p, 0, sizeof(p));
		memset(&unreach, 0, sizeof(unreach));

		/* Get AddPath ID if applicable */
		if (addpath_capable) {
			if ((size_t)(lim - pnt) < BGP_ADDPATH_ID_LEN) {
				frrtrace(4, frr_bgp, unreach_nlri_parse_error,
					 UNREACH_NLRI_ERR_ADDPATH_OVERFLOW, peer->host,
					 peer->bgp->name_pretty, &p);
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			}

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/*
		 * Read the per-NLRI Length field (draft -06). It bounds the
		 * Prefix Length octet, the Prefix, and any Reporter TLVs, so
		 * the next NLRI starts exactly at nlri_end regardless of how
		 * many Reporter TLVs this NLRI carries. The AddPath Path ID
		 * (consumed above) is not counted in nlri_len.
		 */
		if ((size_t)(lim - pnt) < BGP_UNREACH_NLRI_LEN_SIZE) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "%s: Truncated unreachability NLRI Length field",
				 peer->host);
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_TRUNCATED_NLRI_LEN, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		nlri_len = ((uint16_t)pnt[0] << 8) | pnt[1];
		pnt += BGP_UNREACH_NLRI_LEN_SIZE;

		if ((size_t)(lim - pnt) < nlri_len) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "%s: NLRI Length %u overflows packet (remaining %td)",
				 peer->host, nlri_len, (lim - pnt));
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_NLRI_LEN_OVERFLOW, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		nlri_end = pnt + nlri_len;

		/* Fetch prefix length (must lie within this NLRI's bound) */
		if (pnt >= nlri_end) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "[UNREACH] %s: Premature end of unreachability NLRI", peer->host);
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_PREMATURE_END, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		prefixlen = *pnt++;
		p.family = afi2family(afi);
		p.prefixlen = prefixlen;

		/* Prefix length check */
		if (prefixlen > prefix_blen(&p) * 8) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "%s: Invalid prefix length %d for AFI %u", peer->host,
				 prefixlen, afi);
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_INVALID_PREFIX_LEN, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* Calculate size of prefix in bytes */
		psize = PSIZE(prefixlen);

		/* Prefix must fit inside this NLRI's bounded region */
		if ((size_t)(nlri_end - pnt) < (size_t)psize) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "%s: Prefix length %d overflows NLRI", peer->host,
				 prefixlen);
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_PREFIX_OVERFLOW, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Copy prefix and advance pointer */
		if (psize > 0)
			memcpy(&p.u.prefix, pnt, psize);
		pnt += psize;

		/*
		 * Wire layout per draft-tantsura-idr-unreachability-safi
		 * (length-prefixed envelope, draft -06):
		 *   [NLRI Length][prefix len][prefix][Reporter TLV(s)]
		 *
		 * The explicit NLRI Length already fixed nlri_end, so the
		 * next NLRI begins there regardless of how many Reporter
		 * TLVs this NLRI carries. MP_UNREACH withdrawals carry the
		 * prefix only (no Reporter TLV); pnt is simply advanced to
		 * nlri_end below.
		 */
		if (!withdraw) {
			/*
			 * Iterate the Reporter TLV(s) inside this NLRI's
			 * bounded region [pnt, nlri_end). Per
			 * draft-tantsura-idr-unreachability-safi Section 5.3
			 * (and the RFC 9552 Section 5.1 principle), a malformed
			 * or unknown Reporter TLV MUST NOT make the enclosing
			 * NLRI malformed:
			 *
			 *   - unrecognized Reporter TLV Type: ignored, parsing
			 *     resumes at the next TLV boundary (Length field);
			 *   - malformed Reporter TLV: discarded, scanning
			 *     continues looking for a well-formed one;
			 *   - Reporter TLV count beyond the implementation
			 *     limit (Section 4.8): the excess is discarded;
			 *   - if no well-formed Reporter TLV remains the NLRI
			 *     is treat-as-withdraw (Section 5.2 / 5.3), never
			 *     a session reset.
			 *
			 * Per draft Section 3.1 (single-reporter handling),
			 * only the first well-formed Reporter TLV is retained.
			 * Bounds checks use the (nlri_end - ptr) subtraction
			 * form to avoid pointer-arithmetic UB on hostile input.
			 */
			uint8_t *scan = pnt;
			uint32_t reporter_count = 0;
			bool have_reporter = false;

			while ((size_t)(nlri_end - scan) >=
			       BGP_UNREACH_TLV_HEADER_LEN) {
				uint8_t t = scan[0];
				uint16_t l = ((uint16_t)scan[1] << 8) | scan[2];
				uint8_t *val = scan + BGP_UNREACH_TLV_HEADER_LEN;
				uint16_t tlv_total = BGP_UNREACH_TLV_HEADER_LEN + l;

				/*
				 * Length inconsistent with the remaining NLRI
				 * data (Section 5.3): the TLV is discarded. A
				 * bogus length makes the next TLV boundary
				 * unknowable, so stop scanning this NLRI.
				 */
				if ((size_t)(nlri_end - val) < l)
					break;

				if (t == BGP_UNREACH_TLV_TYPE_REPORTER)
					reporter_count++;

				/*
				 * Draft Section 4.8 / 5.3: Reporter TLVs beyond
				 * the per-route limit are discarded (not a
				 * session reset); the first well-formed one is
				 * already retained. The discard is recorded via
				 * the unreach_tlv_parse_error tracepoint.
				 */
				if (reporter_count > BGP_UNREACH_REPORTER_TLV_MAX_PER_ROUTE) {
					frrtrace(6, frr_bgp, unreach_tlv_parse_error,
						 UNREACH_TLV_ERR_TOO_MANY_REPORTER_TLVS,
						 t, l, 0, 0,
						 BGP_UNREACH_REPORTER_TLV_MAX_PER_ROUTE);
					break;
				}

				/*
				 * Retain the first well-formed Reporter TLV. A
				 * malformed one is discarded (Section 5.3); keep
				 * scanning for a well-formed Reporter TLV.
				 * Unrecognized Reporter TLV Types are ignored
				 * and skipped past using the Length field.
				 */
				if (t == BGP_UNREACH_TLV_TYPE_REPORTER && !have_reporter &&
				    bgp_unreach_tlv_parse(scan, tlv_total, &unreach) == 0)
					have_reporter = true;

				scan += tlv_total;
			}

			if (!have_reporter) {
				/*
				 * No well-formed Reporter TLV after the prefix
				 * (Section 5.2 / 5.3): recover the NLRI via
				 * treat-as-withdraw rather than reset the
				 * session.
				 */
				flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
					 "%s: SAFI_UNREACH NLRI for %pFX has no well-formed Reporter TLV; treating as withdraw",
					 peer->host, &p);
				frrtrace(4, frr_bgp, unreach_nlri_parse_error,
					 UNREACH_NLRI_ERR_REPORTER_TLV_PARSE_FAIL,
					 peer->host, peer->bgp->name_pretty, &p);
				treat_as_withdraw = true;
			}
		}

		/*
		 * Advance to the next NLRI. The explicit NLRI Length makes
		 * this boundary unambiguous for withdraw, single-reporter,
		 * and (skipped) multi-reporter NLRIs alike.
		 */
		pnt = nlri_end;

		/* Store prefix in unreach structure */
		prefix_copy(&unreach.prefix, &p);

		if (withdraw || treat_as_withdraw) {
			if (BGP_DEBUG(unreachability, UNREACHABILITY))
				zlog_debug("[UNREACH] %s: Withdraw unreachability %pFX", peer->host,
					   &p);
			frrtrace(3, frr_bgp, unreach_nlri_withdraw_received,
				 peer->bgp->name_pretty, peer->host, &p);
			bgp_withdraw(peer, &p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		} else if (attr) {
			if (BGP_DEBUG(unreachability, UNREACHABILITY))
				zlog_debug("[UNREACH] %s: Receive unreachability %pFX reporter %pI4%s",
					   peer->host, &p, &unreach.reporter,
					   unreach.has_reporter_as ? " AS present" : "");
			/*
			 * Pass the stack-allocated Reporter TLV data as an
			 * explicit parameter to bgp_update(). bgp_update()
			 * consumes the data synchronously (copies into the
			 * path's extra->unreach) and never retains the
			 * pointer past return, so a stack address is safe
			 * and we avoid attaching a heap pointer to struct
			 * attr.
			 */
			frrtrace(7, frr_bgp, unreach_nlri_received, peer->bgp->name_pretty,
				 peer->host, &p, &unreach.reporter, unreach.reporter_as,
				 unreach.reason_code, unreach.timestamp);
			bgp_update(peer, &p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL, &unreach);
		} else {
			if (BGP_DEBUG(update, UPDATE_IN) ||
			    BGP_DEBUG(unreachability, UNREACHABILITY))
				zlog_debug("[UNREACH] %s: Missing attributes for unreachability update %pFX, skipping",
					   peer->host, &p);
		}

		if (BGP_DEBUG(update, UPDATE_IN) || BGP_DEBUG(unreachability, UNREACHABILITY))
			zlog_debug("[UNREACH] %s: Processed unreachability info for %pFX via %s",
				   peer->host, &p,
				   (withdraw || treat_as_withdraw) ? "bgp_withdraw()"
								   : "bgp_update()");
	}

	return 0;
}

/* Add unreachability information to the UI-RIB.
 *
 * Self-originated helper used by callers that locally synthesize an
 * Unreachability NLRI (e.g. the 'bgp inject unreachability' test CLI).
 * Looks up or creates a path owned by peer_self for the prefix in the
 * SAFI_UNREACH RIB and stores the Reporter TLV / Sub-TLV data on the
 * path's bgp_path_info_extra_unreach.
 */
int bgp_unreach_info_add(struct bgp *bgp, afi_t afi, struct bgp_unreach_nlri *nlri,
			 struct attr *attr)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct attr attr_new;
	struct attr *attr_interned;

	if (!bgp || !nlri)
		return -1;

	/* Get/create destination node */
	dest = bgp_node_get(bgp->rib[afi][SAFI_UNREACH], &nlri->prefix);

	/* Check for existing path */
	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self)
			break;
	}

	/* Create new path or update existing */
	if (!bpi) {
		if (BGP_DEBUG(unreachability, UNREACHABILITY))
			zlog_debug("[UNREACH] %s: UNREACH INFO ADD %pFX (new path)",
				   bgp->name_pretty, &nlri->prefix);
		/* Initialize attributes (no TLV data in attr) */
		if (attr) {
			attr_new = *attr;
		} else {
			/* Set default attributes for locally originated route */
			bgp_attr_default_set(&attr_new, bgp, BGP_ORIGIN_INCOMPLETE);
		}

		/* Set nexthop length to 0 for SAFI_UNREACH (no nexthop, like Flowspec) */
		attr_new.mp_nexthop_len = 0;

		/* Intern the attributes */
		attr_interned = bgp_attr_intern(&attr_new);

		new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_interned,
				dest);

		if (!new->extra)
			new->extra = bgp_path_info_extra_get(new);

		new->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
					      sizeof(struct bgp_path_info_extra_unreach));

		new->extra->unreach->timestamp = nlri->timestamp;
		new->extra->unreach->has_timestamp = nlri->has_timestamp;
		new->extra->unreach->reason_code = nlri->reason_code;
		new->extra->unreach->has_reason_code = nlri->has_reason_code;
		new->extra->unreach->reporter = nlri->reporter;
		new->extra->unreach->has_reporter = nlri->has_reporter;
		new->extra->unreach->reporter_as = nlri->reporter_as;
		new->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
		bgp_path_info_add(dest, new);
		frrtrace(7, frr_bgp, unreach_info_add, bgp->name_pretty, &nlri->prefix,
			 &nlri->reporter, nlri->reporter_as, nlri->reason_code,
			 nlri->timestamp, 1);
		bgp_process(bgp, dest, new, afi, SAFI_UNREACH);
	} else {
		/* Update existing path with new TLV data */
		if (!bpi->extra)
			bpi->extra = bgp_path_info_extra_get(bpi);

		if (!bpi->extra->unreach)
			bpi->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
						      sizeof(struct bgp_path_info_extra_unreach));

		if (bgp_debug_update(NULL, &nlri->prefix, NULL, 0) ||
		    BGP_DEBUG(unreachability, UNREACHABILITY)) {
			zlog_debug("[UNREACH] UNREACH UPDATE %pFX: old reason=%u new reason=%u",
				   &nlri->prefix,
				   bpi->extra->unreach->reason_code,
				   nlri->reason_code);
		}

		bpi->extra->unreach->timestamp = nlri->timestamp;
		bpi->extra->unreach->has_timestamp = nlri->has_timestamp;
		bpi->extra->unreach->reason_code = nlri->reason_code;
		bpi->extra->unreach->has_reason_code = nlri->has_reason_code;
		bpi->extra->unreach->reporter = nlri->reporter;
		bpi->extra->unreach->has_reporter = nlri->has_reporter;
		bpi->extra->unreach->reporter_as = nlri->reporter_as;
		bpi->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bpi->uptime = monotime(NULL);
		bgp_path_info_set_flag(dest, bpi, BGP_PATH_ATTR_CHANGED);
		frrtrace(7, frr_bgp, unreach_info_add, bgp->name_pretty, &nlri->prefix,
			 &nlri->reporter, nlri->reporter_as, nlri->reason_code,
			 nlri->timestamp, 0);
		bgp_process(bgp, dest, bpi, afi, SAFI_UNREACH);
	}

	bgp_dest_unlock_node(dest);

	return 0;
}

/* Remove a self-originated unreachability path from the UI-RIB. */
void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, const struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;

	if (!bgp || !prefix)
		return;

	dest = bgp_node_lookup(bgp->rib[afi][SAFI_UNREACH], prefix);
	if (!dest)
		return;

	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self) {
			if (BGP_DEBUG(unreachability, UNREACHABILITY))
				zlog_debug("[UNREACH] %s: UNREACH INFO DELETE %pFX",
					   bgp->name_pretty, prefix);
			frrtrace(2, frr_bgp, unreach_info_delete, bgp->name_pretty, prefix);
			bgp_rib_remove(dest, bpi, bgp->peer_self, afi, SAFI_UNREACH);
			break;
		}
	}

	bgp_dest_unlock_node(dest);
}

/*
 * Populate a JSON path object with detailed fields for one
 * unreachability path (TLVs, peer, origin, flags, communities, aspath).
 */
static void bgp_unreach_path_detail_json(json_object *json_path,
					 struct bgp_path_info *pi)
{
	struct bgp_path_info_extra_unreach *ud =
		(pi->extra) ? pi->extra->unreach : NULL;

	bgp_unreach_reporters_to_json(ud, json_path, false, true);

	if (pi->peer) {
		json_object *json_peer = json_object_new_object();

		if (pi->peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       pi->peer->hostname);
		if (pi->peer->conf_if)
			json_object_string_add(json_peer, "interface",
					       pi->peer->conf_if);
		else
			json_object_string_addf(json_peer, "peerId", "%pSU",
						&pi->peer->connection->su);
		json_object_string_addf(json_peer, "routerId", "%pI4",
					&pi->peer->remote_id);
		json_object_object_add(json_path, "peer", json_peer);
	}

	if (pi->attr)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[pi->attr->origin]);

	json_object_boolean_add(json_path, "valid",
				CHECK_FLAG(pi->flags, BGP_PATH_VALID));
	json_object_boolean_add(json_path, "best",
				CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	json_object_boolean_add(json_path, "stale",
				CHECK_FLAG(pi->flags, BGP_PATH_STALE));
	json_object_boolean_add(json_path, "multipath",
				CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));

	if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
		json_object_string_add(json_path, "pathFrom", "internal");
	else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
		json_object_string_add(json_path, "pathFrom", "external");

	{
		time_t tbuf = time(NULL) - (monotime(NULL) - pi->uptime);
		char timebuf[64];
		json_object *json_last_update = json_object_new_object();

		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       unreach_ctime_r(&tbuf, timebuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	}

	if (pi->attr &&
	    (pi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES))) {
		struct community *comm = bgp_attr_get_community(pi->attr);

		if (comm) {
			if (!comm->json)
				community_str(comm, true, true);
			json_object_lock(comm->json);
			json_object_object_add(json_path, "community",
					       comm->json);
		}
	}

	if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
		struct ecommunity *ecomm =
			bgp_attr_get_ecommunity(pi->attr);
		json_object *json_ecomm = json_object_new_object();

		json_object_string_add(json_ecomm, "string", ecomm->str);
		json_object_object_add(json_path, "extendedCommunity",
				       json_ecomm);
	}

	if (pi->attr && pi->attr->aspath) {
		json_object *json_aspath = json_object_new_object();

		json_object_string_add(json_aspath, "string",
				       aspath_print(pi->attr->aspath));
		json_object_int_add(json_aspath, "length",
				    aspath_count_hops(pi->attr->aspath));
		json_object_object_add(json_path, "aspath", json_aspath);
	}
}

/*
 * Populate a JSON path object with summary fields for one
 * unreachability path (metric, locPrf, weight, reason, reporter,
 * origin, flags, pathFrom, lastUpdate, ecommunity, peer).
 */
static void bgp_unreach_path_summary_json(json_object *json_path,
					   struct bgp_path_info *pi,
					   struct bgp_path_info_extra_unreach *ud)
{
	if (pi->attr)
		json_object_int_add(json_path, "metric", pi->attr->med);

	if (pi->attr &&
	    (pi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
		json_object_int_add(json_path, "locPrf",
				    pi->attr->local_pref);

	if (pi->attr)
		json_object_int_add(json_path, "weight",
				    pi->attr->weight);

	bgp_unreach_reporters_to_json(ud, json_path, false, false);

	if (pi->attr && pi->attr->aspath)
		json_object_string_add(json_path, "path",
				       pi->attr->aspath->str);

	if (pi->attr)
		json_object_string_add(json_path, "origin",
				       bgp_origin_long_str[pi->attr->origin]);

	json_object_boolean_add(json_path, "valid",
				CHECK_FLAG(pi->flags, BGP_PATH_VALID));
	json_object_boolean_add(json_path, "best",
				CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	json_object_boolean_add(json_path, "stale",
				CHECK_FLAG(pi->flags, BGP_PATH_STALE));
	json_object_boolean_add(json_path, "multipath",
				CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));

	if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
		json_object_string_add(json_path, "pathFrom", "internal");
	else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
		json_object_string_add(json_path, "pathFrom", "external");

	{
		time_t tbuf = time(NULL) - (monotime(NULL) - pi->uptime);
		char timebuf[64];
		json_object *json_last_update = json_object_new_object();

		json_object_int_add(json_last_update, "epoch", tbuf);
		json_object_string_add(json_last_update, "string",
				       unreach_ctime_r(&tbuf, timebuf));
		json_object_object_add(json_path, "lastUpdate",
				       json_last_update);
	}

	if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
		json_object *json_ecomm = json_object_new_object();

		json_object_string_add(json_ecomm, "string",
				       bgp_attr_get_ecommunity(pi->attr)->str);
		json_object_object_add(json_path, "extendedCommunity",
				       json_ecomm);
	}

	if (pi->peer) {
		json_object *json_peer = json_object_new_object();

		if (pi->peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       pi->peer->hostname);
		if (pi->peer->conf_if)
			json_object_string_add(json_peer, "interface",
					       pi->peer->conf_if);
		else
			json_object_string_addf(json_peer, "peerId",
						"%pSU",
						&pi->peer->connection->su);
		json_object_string_addf(json_peer, "routerId", "%pI4",
					&pi->peer->remote_id);
		json_object_object_add(json_path, "peer", json_peer);
	}
}

/*
 * Print one VTY summary line for an unreachability path
 * (status codes, prefix, metric, locPrf, weight, reason, reporter,
 * aspath, origin).
 */
static void bgp_unreach_path_summary_vty(
	struct vty *vty, struct bgp_path_info *pi,
	struct bgp_path_info_extra_unreach *unreach_data,
	afi_t afi, const char *prefix_display)
{
	char reporter_str[32] = "-";
	char aspath_str[256] = "";
	const char *reason_str = "";
	char origin_str[2] = "";

	if (unreach_data) {
		char reporter_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &unreach_data->reporter,
			  reporter_ip, sizeof(reporter_ip));
		snprintf(reporter_str, sizeof(reporter_str),
			 "%s/%u", reporter_ip,
			 unreach_data->reporter_as);

		if (unreach_data->has_reason_code)
			reason_str = bgp_unreach_reason_str(
				unreach_data->reason_code);
	}

	if (pi->attr && pi->attr->aspath) {
		const char *aspath_tmp = aspath_print(pi->attr->aspath);

		if (aspath_tmp)
			snprintf(aspath_str, sizeof(aspath_str),
				 "%s", aspath_tmp);
	}

	if (pi->attr)
		snprintf(origin_str, sizeof(origin_str), "%s",
			 bgp_origin_str[pi->attr->origin]);

	/* Status codes */
	vty_out(vty, " ");

	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
		vty_out(vty, "R");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_STALE))
		vty_out(vty, "S");
	else if (bgp_path_suppressed(pi))
		vty_out(vty, "s");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
		 !CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
		vty_out(vty, "*");
	else
		vty_out(vty, " ");

	if (CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
		vty_out(vty, "h");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_UNSORTED))
		vty_out(vty, "u");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_DAMPED))
		vty_out(vty, "d");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
		vty_out(vty, ">");
	else if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
		vty_out(vty, "=");
	else
		vty_out(vty, " ");

	if (pi->peer && (pi->peer->as) &&
	    (pi->peer->as == pi->peer->local_as))
		vty_out(vty, "i");
	else
		vty_out(vty, " ");

	if (afi == AFI_IP) {
		if (pi->attr &&
		    (pi->attr->flag &
		     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
			vty_out(vty,
				" %-18s %7u %7u %7u %-19s %-17s %s %s\n",
				prefix_display, pi->attr->med,
				pi->attr->local_pref,
				pi->attr->weight, reason_str,
				reporter_str, aspath_str,
				origin_str);
		else
			vty_out(vty,
				" %-18s %7u        %7u %-19s %-17s %s %s\n",
				prefix_display,
				pi->attr ? pi->attr->med : 0,
				pi->attr ? pi->attr->weight : 0,
				reason_str, reporter_str,
				aspath_str, origin_str);
	} else {
		if (pi->attr &&
		    (pi->attr->flag &
		     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
			vty_out(vty,
				" %-48s %7u %7u %7u %-19s %-17s %s %s\n",
				prefix_display, pi->attr->med,
				pi->attr->local_pref,
				pi->attr->weight, reason_str,
				reporter_str, aspath_str,
				origin_str);
		else
			vty_out(vty,
				" %-48s %7u        %7u %-19s %-17s %s %s\n",
				prefix_display,
				pi->attr ? pi->attr->med : 0,
				pi->attr ? pi->attr->weight : 0,
				reason_str, reporter_str,
				aspath_str, origin_str);
	}
}

/*
 * Build an "advertisedTo" JSON object for a destination.
 * Returns NULL if no peers advertise this route.
 */
static json_object *bgp_unreach_advertised_to_json(struct bgp *bgp,
						   struct bgp_dest *dest)
{
	json_object *json_adv_to = NULL;
	struct peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (bgp_adj_out_lookup(peer, dest, 0)) {
			json_object *json_peer;

			if (!json_adv_to)
				json_adv_to = json_object_new_object();
			json_peer = json_object_new_object();

			if (peer->hostname)
				json_object_string_add(json_peer, "hostname",
						       peer->hostname);
			if (peer->conf_if)
				json_object_object_add(json_adv_to,
						       peer->conf_if,
						       json_peer);
			else {
				char peer_str[SU_ADDRSTRLEN];

				sockunion2str(&peer->connection->su,
					      peer_str, sizeof(peer_str));
				json_object_object_add(json_adv_to,
						       peer_str, json_peer);
			}
		}
	}

	return json_adv_to;
}

/*
 * Emit detail-mode JSON paths for one destination into json_paths,
 * honouring the optional bgp_show_type_neighbor filter. Returns the
 * number of paths emitted.
 */
static int bgp_unreach_show_detail_json_dest(struct bgp_dest *dest,
					     json_object *json_paths,
					     enum bgp_show_type type,
					     void *output_arg)
{
	struct bgp_path_info *pi;
	int path_count = 0;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		json_object *json_path;

		if (bgp_unreach_skip_for_neighbor(pi, type, output_arg))
			continue;

		json_path = json_object_new_object();
		bgp_unreach_path_detail_json(json_path, pi);
		json_object_array_add(json_paths, json_path);
		path_count++;
	}
	return path_count;
}

/*
 * Emit detail-mode VTY output for one destination, honouring the
 * optional bgp_show_type_neighbor filter. Returns the number of
 * paths emitted.
 */
static int bgp_unreach_show_detail_vty_dest(struct vty *vty, struct bgp *bgp,
					    struct bgp_dest *dest,
					    const struct prefix *p, afi_t afi,
					    enum bgp_show_type type,
					    void *output_arg)
{
	struct bgp_path_info *pi;
	int path_count = 0;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (bgp_unreach_skip_for_neighbor(pi, type, output_arg))
			continue;

		route_vty_out_detail_header(vty, bgp, dest, p, NULL, afi,
					    SAFI_UNREACH, NULL, false, false);
		route_vty_out_detail(vty, bgp, dest, p, pi, afi, SAFI_UNREACH,
				     RPKI_NOT_BEING_USED, NULL, NULL, 0);
		path_count++;
	}
	return path_count;
}

/* Show unreachability information */
void bgp_unreach_show(struct vty *vty, struct bgp *bgp, afi_t afi, struct prefix *prefix,
		      bool use_json, bool detail, enum bgp_show_type type, void *output_arg)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	json_object *json = NULL;
	json_object *json_paths = NULL;
	int count = 0;

	if (!bgp) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	table = bgp->rib[afi][SAFI_UNREACH];
	if (!table) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No unreachability information\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	/* Show specific prefix or all */
	if (prefix) {
		dest = bgp_node_lookup(table, prefix);
		if (!dest) {
			if (use_json)
				vty_json(vty, json);
			else
				vty_out(vty, "%% Network not in table\n");
			return;
		}

		if (use_json)
			json_paths = json_object_new_array();
		else {
			/* Print header once before looping through paths */
			route_vty_out_detail_header(vty, bgp, dest, prefix,
						    NULL, afi, SAFI_UNREACH,
						    NULL, false, false);
		}

		int multi_path_count = 0;

		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (bgp_unreach_skip_for_neighbor(pi, type, output_arg))
				continue;

			count++;
			if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
				multi_path_count++;

			if (use_json) {
				json_object *json_path = json_object_new_object();

				bgp_unreach_path_detail_json(json_path, pi);
				json_object_array_add(json_paths, json_path);
			} else {
				/* Use standard BGP route detail display for single prefix */
				route_vty_out_detail(vty, bgp, dest, prefix,
						     pi, afi, SAFI_UNREACH,
						     RPKI_NOT_BEING_USED,
						     NULL, NULL, 0);
			}
		}

		if (use_json) {
			json_object_object_add(json, "paths", json_paths);
			json_object_int_add(json, "pathCount", count);
			json_object_int_add(json, "multiPathCount", multi_path_count);

			json_object *json_adv_to =
				bgp_unreach_advertised_to_json(bgp, dest);

			if (json_adv_to)
				json_object_object_add(json, "advertisedTo",
						       json_adv_to);

			vty_json(vty, json);
		}

		bgp_dest_unlock_node(dest);
	} else {
		/* Show all unreachability information */

		/* If detail flag, use detailed output per route */
		if (detail) {
			int prefix_count = 0;

			for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
				const struct prefix *p = bgp_dest_get_prefix(dest);
				int path_count;

				if (use_json) {
					char prefix_str[PREFIX2STR_BUFFER];

					json_paths = json_object_new_array();
					prefix2str(p, prefix_str, sizeof(prefix_str));
					path_count = bgp_unreach_show_detail_json_dest(
						dest, json_paths, type, output_arg);
					json_object_object_add(json, prefix_str, json_paths);
				} else {
					path_count = bgp_unreach_show_detail_vty_dest(
						vty, bgp, dest, p, afi, type, output_arg);
				}

				count += path_count;
				if (path_count > 0)
					prefix_count++;
			}

			if (use_json) {
				vty_json(vty, json);
			} else {
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
			}
			return;
		}

		/* Summary view */
		if (!use_json) {
			/* Print table header with status code legends (same as ipv4 unicast) */
			vty_out(vty,
				"BGP table version is %" PRIu64
				", local router ID is %pI4, vrf id %u\n",
				table->version, &bgp->router_id,
				bgp->vrf_id);
			vty_out(vty, "Default local pref %u, local AS %u\n",
				bgp->default_local_pref, bgp->as);
			vty_out(vty, BGP_UNREACH_SHOW_SCODE_HEADER);
			vty_out(vty, BGP_SHOW_OCODE_HEADER);
			vty_out(vty, BGP_SHOW_RPKI_HEADER);

			/* SAFI_UNREACH specific information */
			vty_out(vty,
				"Note: Unreachability routes are informational only and not installed in RIB/FIB\n");
			vty_out(vty, "Reason: Unreachability reason code\n");
			vty_out(vty, "Reporter: BGP router ID of the original reporter\n\n");

			/* Column header - use macros to match standard BGP style */
			if (afi == AFI_IP)
				vty_out(vty, BGP_UNREACH_SHOW_HEADER);
			else
				vty_out(vty, BGP_UNREACH_SHOW_HEADER_WIDE);
		}

		int prefix_count = 0; /* Count unique prefixes */

		for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
			const struct prefix *p = bgp_dest_get_prefix(dest);
			char buf[PREFIX2STR_BUFFER];
			bool first_path = true;
			int prefix_path_count = 0;
			int multi_path_count = 0;
			json_object *json_route_for_prefix = NULL;
			bool has_paths = false;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
				struct bgp_path_info_extra_unreach *unreach_data = NULL;

				if (bgp_unreach_skip_for_neighbor(pi, type, output_arg))
					continue;

				if (pi->extra && pi->extra->unreach)
					unreach_data = pi->extra->unreach;

				count++; /* Count total paths/entries */
				prefix_path_count++;
				has_paths = true;

				/* Count multipath routes */
				if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
					multi_path_count++;

				if (use_json) {
					json_object *json_route = NULL;
					json_object *json_path = NULL;

					json_paths = NULL;
					char prefix_str[PREFIX2STR_BUFFER];

					/* Get or create route object for this prefix */
					prefix2str(p, prefix_str, sizeof(prefix_str));
					if (!json_object_object_get_ex(
						    json, prefix_str,
						    &json_route)) {
						json_route =
							json_object_new_object();
						json_object_string_add(
							json_route, "prefix",
							prefix_str);
						json_paths =
							json_object_new_array();
						json_object_object_add(
							json_route, "paths",
							json_paths);
						json_object_object_add(
							json, prefix_str,
							json_route);
					} else {
						json_object_object_get_ex(
							json_route, "paths",
							&json_paths);
					}

					json_path = json_object_new_object();
					bgp_unreach_path_summary_json(
						json_path, pi, unreach_data);
					json_object_array_add(json_paths, json_path);

					/* Save reference for adding counts after loop */
					json_route_for_prefix = json_route;
				} else {
					const char *prefix_display =
						first_path
							? prefix2str(p, buf,
								     sizeof(buf))
							: "";

					bgp_unreach_path_summary_vty(
						vty, pi, unreach_data,
						afi, prefix_display);
					first_path = false;
				}
			}

			/* Add route-level fields */
			if (use_json && json_route_for_prefix) {
				json_object_int_add(json_route_for_prefix, "pathCount",
						    prefix_path_count);
				json_object_int_add(json_route_for_prefix, "multiPathCount",
						    multi_path_count);

				/* Add flags object */
				json_object *json_flags = json_object_new_object();
				struct bgp_path_info *pi_check;
				bool has_bestpath = false;

				for (pi_check = bgp_dest_get_bgp_path_info(dest); pi_check;
				     pi_check = pi_check->next) {
					if (CHECK_FLAG(pi_check->flags, BGP_PATH_SELECTED)) {
						has_bestpath = true;
						break;
					}
				}
				json_object_string_add(json_flags, "bestPathExists",
						       has_bestpath ? "true" : "false");
				json_object_object_add(json_route_for_prefix, "flags", json_flags);

				json_object *json_adv_to =
					bgp_unreach_advertised_to_json(bgp,
								       dest);

				if (json_adv_to)
					json_object_object_add(
						json_route_for_prefix,
						"advertisedTo", json_adv_to);
			}

			if (has_paths)
				prefix_count++;
		}

		if (use_json) {
			/* Add numPrefixes (consistent with unicast) */
			json_object_int_add(json, "numPrefixes", prefix_count);
			vty_json(vty, json);
		} else {
			if (count == 0)
				vty_out(vty, "No unreachability information\n");
			else
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
		}
	}
}
