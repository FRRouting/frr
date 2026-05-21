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
			 "Unreachability TLV too short: %u bytes (min %u)", len,
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
			 "Reporter TLV length %u exceeds remaining %zu", tlv_len,
			 (size_t)(end - pnt));
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
				 "%s: NLRI Length %u overflows packet (remaining %zu)",
				 peer->host, nlri_len, (size_t)(lim - pnt));
			frrtrace(4, frr_bgp, unreach_nlri_parse_error,
				 UNREACH_NLRI_ERR_NLRI_LEN_OVERFLOW, peer->host,
				 peer->bgp->name_pretty, &p);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		nlri_end = pnt + nlri_len;

		/* Fetch prefix length (must lie within this NLRI's bound) */
		if (pnt >= nlri_end) {
			flog_err(EC_BGP_UNREACH_PARSE_FAILURE,
				 "%s: Premature end of unreachability NLRI", peer->host);
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
			frrtrace(3, frr_bgp, unreach_nlri_withdraw_received,
				 peer->bgp->name_pretty, peer->host, &p);
			bgp_withdraw(peer, &p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		} else if (attr) {
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
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("%s: Missing attributes for unreachability update %pFX, skipping",
					   peer->host, &p);
		}

		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("%s: Processed unreachability info for %pFX via %s",
				   peer->host, &p,
				   (withdraw || treat_as_withdraw) ? "bgp_withdraw()"
								   : "bgp_update()");
	}

	return 0;
}

/* Show unreachability information */
