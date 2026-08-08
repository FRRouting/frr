// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for bgp_nlri_parse_mup (draft-ietf-bess-mup-safi route types 1..4).
 * Copyright (C) 2026 Yuya Kusakabe
 */

#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mup.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;

/*
 * Wire format: arch_type(1) | route_type(2 BE) | length(1) | body(length)
 *
 * AFI for all tests: AFI_IP unless noted.
 */

#define MUP_ARCH    0x01       /* BGP_MUP_ARCH_3GPP_5G */
#define MUP_ISD_RT  0x00, 0x01 /* BGP_MUP_ISD_ROUTE  big-endian */
#define MUP_DSD_RT  0x00, 0x02 /* BGP_MUP_DSD_ROUTE  big-endian */
#define MUP_T1ST_RT 0x00, 0x03 /* BGP_MUP_T1ST_ROUTE big-endian */
#define MUP_T2ST_RT 0x00, 0x04 /* BGP_MUP_T2ST_ROUTE big-endian */

/* RD type 0 (AS:value): 0x00 0x00 <AS2> <val4> */
#define RD0 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01

struct nlri_test {
	const char *name;
	const char *desc;
	const uint8_t data[256];
	int len;
	afi_t afi;
	int expect; /* expected bgp_nlri_parse_mup return code */
};

/* clang-format off */
static struct nlri_test mup_segments[] = {
	/* ------------------------------------------------------------------ */
	/* Happy path: one well-formed PDU per route type                      */
	/* ------------------------------------------------------------------ */
	{
		"isd-v4-ok",
		"ISD IPv4, /24 prefix, well-formed",
		{
			/* arch | route-type | length */
			MUP_ARCH, MUP_ISD_RT,
			/* body length = RD(8) + pfxlen(1) + pfx-octets(3) = 12 */
			12,
			/* RD type-0: AS 100 : value 1 */
			RD0,
			/* prefix length (bits) */
			24,
			/* prefix 192.168.1.0/24 */
			192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"dsd-v4-ok",
		"DSD IPv4, PE address 10.0.0.1, well-formed",
		{
			MUP_ARCH, MUP_DSD_RT,
			/* body = RD(8) + IPv4(4) = 12 */
			12,
			RD0,
			/* PE address 10.0.0.1 */
			10, 0, 0, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-v4-ok",
		"T1ST IPv4, /0 UE prefix, TEID 1, QFI 9, EP 10.1.2.3/32, no SA, well-formed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body = RD(8) + pfxlen(1) + pfx-octets(0) +
			 *        TEID(4) + QFI(1) + ep_len(1) + ep(4) +
			 *        src_len(1) = 20
			 */
			20,
			RD0,
			/* UE prefix length 0 (no bytes follow) */
			0,
			/* TEID = 1 (non-zero, big-endian) */
			0x00, 0x00, 0x00, 0x01,
			/* QFI */
			9,
			/* endpoint address length in bits = 32 */
			32,
			/* endpoint 10.1.2.3 */
			10, 1, 2, 3,
			/* source address length = 0 (absent) */
			0,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v4-ok",
		"T2ST IPv4, EP 10.2.0.1, TEID 2, ea_len=64, well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/*
			 * body = RD(8) + ea_len(1) + addr(4) + teid_octets(4)
			 * ea_len=64: 32 addr bits + 32 TEID bits => teid_octets=4
			 * total = 8+1+4+4 = 17
			 */
			17,
			RD0,
			/* ea_len = 64 bits */
			64,
			/* endpoint address 10.2.0.1 */
			10, 2, 0, 1,
			/* TEID = 2 (non-zero, big-endian, packed in 4 bytes) */
			0x00, 0x00, 0x00, 0x02,
		},
		.len = 4 + 17,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: outer header too short -- returns MUP_MISSING_TYPE        */
	/* ------------------------------------------------------------------ */
	{
		"truncated-header",
		"NLRI truncated before 4-byte header completes",
		{
			/* Only 3 bytes: arch + route_type(2 bytes) -- no length */
			MUP_ARCH, MUP_ISD_RT,
		},
		.len = 3,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: body length overflows outer NLRI -- returns PACKET_OVERFLOW */
	/* ------------------------------------------------------------------ */
	{
		"body-overflow",
		"Route-type length field claims more bytes than the NLRI holds",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* claim 20 bytes in body, but only 12 follow */
			20,
			RD0,
			24, 192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW,
	},
	/* ------------------------------------------------------------------ */
	/* Negative: leftover bytes after consuming NLRI                      */
	/*                                                                    */
	/* A single trailing byte looks like the start of a new header; the  */
	/* loop's 4-byte-header check fires first -> MUP_MISSING_TYPE.        */
	/* PACKET_LENGTH would require pnt to step *past* lim, which cannot  */
	/* happen because psize is always <= (lim - pnt) after the overflow  */
	/* guard.  Test the reachable path.                                   */
	/* ------------------------------------------------------------------ */
	{
		"trailing-garbage",
		"Single trailing byte re-enters header check, returns MUP_MISSING_TYPE",
		{
			MUP_ARCH, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
			/* extra garbage byte -- triggers partial-header path */
			0xff,
		},
		.len = 4 + 12 + 1,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): prefix length > AFI max -- outer returns OK       */
	/* (inner decoder logs and skips the NLRI per RFC 7606 treat-as-withdraw) */
	/* ------------------------------------------------------------------ */
	{
		"isd-prefix-len-overflow",
		"ISD IPv4, prefix_len=33 (>32) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* body: RD(8) + pfxlen(1) + pfx-octets for /33 = PSIZE(33)=5 */
			14,
			RD0,
			/* prefix length 33 -- exceeds IPv4 max */
			33,
			192, 168, 1, 0, 0,
		},
		.len = 4 + 14,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T1ST with TEID=0 -- inner skips, outer returns OK */
	/* ------------------------------------------------------------------ */
	{
		"t1st-teid-zero",
		"T1ST IPv4, TEID=0 -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			20,
			RD0,
			0,
			/* TEID = 0 (forbidden) */
			0x00, 0x00, 0x00, 0x00,
			9,
			32,
			10, 1, 2, 3,
			0,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T1ST endpoint length > AFI max -- inner skips     */
	/* ------------------------------------------------------------------ */
	{
		"t1st-ep-len-overflow",
		"T1ST IPv4, endpoint_length=33 (not 32) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body: RD(8)+pfxlen(1)+teid(4)+qfi(1)+ep_len(1) = 15,
			 * plus 1 spare byte so psize reaches the 16-octet
			 * minimum.  The parser rejects any ep_len other than
			 * 32 for AFI_IP before reading the endpoint bytes.
			 */
			16,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			/* endpoint_length = 33 bits -- exceeds IPv4 max */
			33,
		},
		.len = 4 + 16,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): T2ST with TEID=0 -- inner skips, outer returns OK */
	/* ------------------------------------------------------------------ */
	{
		"t2st-teid-zero",
		"T2ST IPv4, TEID=0 -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T2ST_RT,
			17,
			RD0,
			64,
			10, 2, 0, 1,
			/* TEID = 0 (forbidden) */
			0x00, 0x00, 0x00, 0x00,
		},
		.len = 4 + 17,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Negative (inner): DSD with wrong body size for AFI -- inner skips   */
	/* ------------------------------------------------------------------ */
	{
		"dsd-wrong-size",
		"DSD IPv4, body=13 (not 12) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_DSD_RT,
			13,
			RD0,
			10, 0, 0, 1,
			/* one extra byte makes psize 13 != 12 for AFI_IP */
			0x00,
		},
		.len = 4 + 13,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Unknown arch_type -- outer silently skips, returns OK               */
	/* ------------------------------------------------------------------ */
	{
		"unknown-arch-type",
		"Unknown arch_type=0xFF -- outer loop skips, returns OK",
		{
			/* arch_type = 0xFF (undefined) */
			0xFF, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
		},
		.len = 4 + 12,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* IPv6 (AFI=2) happy path: one well-formed PDU per route type         */
	/* ------------------------------------------------------------------ */
	{
		"isd-v6-ok",
		"ISD IPv6, /64 prefix, well-formed",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* body = RD(8) + pfxlen(1) + pfx-octets(8) = 17 */
			17,
			RD0,
			64,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		},
		.len = 4 + 17,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"dsd-v6-ok",
		"DSD IPv6, PE address 2001:db8::1, well-formed",
		{
			MUP_ARCH, MUP_DSD_RT,
			/* body = RD(8) + IPv6(16) = 24 */
			24,
			RD0,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		},
		.len = 4 + 24,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-v6-ok",
		"T1ST IPv6, /0 UE prefix, TEID 1, QFI 9, EP 2001:db8::5/128, no SA, well-formed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body = RD(8) + pfxlen(1) + TEID(4) + QFI(1) +
			 *        ep_len(1) + ep(16) + src_len(1) = 32
			 */
			32,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			128,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
			0,
		},
		.len = 4 + 32,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v6-ok",
		"T2ST IPv6, EP 2001:db8::9, TEID 2, ea_len=160, well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = RD(8) + ea_len(1) + addr(16) + teid(4) = 29 */
			29,
			RD0,
			160,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
			0x00, 0x00, 0x00, 0x02,
		},
		.len = 4 + 29,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* T2ST endpoint-level aggregate: Endpoint Length of exactly 32/128    */
	/* means the TEID field is absent (0 octets) -- valid                  */
	/* ------------------------------------------------------------------ */
	{
		"t2st-v4-ea32-no-teid",
		"T2ST IPv4, ea_len=32, no TEID field (endpoint aggregate), well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = RD(8) + ea_len(1) + addr(4) = 13 */
			13,
			RD0,
			32,
			10, 2, 0, 1,
		},
		.len = 4 + 13,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v6-ea128-no-teid",
		"T2ST IPv6, ea_len=128, no TEID field (endpoint aggregate), well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = RD(8) + ea_len(1) + addr(16) = 25 */
			25,
			RD0,
			128,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
		},
		.len = 4 + 25,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* T2ST partial TEID: ea_len=35 leaves 3 TEID bits in one trailing     */
	/* octet; the low 5 bits of that octet are padding.  Padding must not  */
	/* reach the route key nor defeat the TEID=0 check (see                */
	/* test_t2st_teid_padding for the table-level assertions).             */
	/* ------------------------------------------------------------------ */
	{
		"t2st-v4-teid-padded",
		"T2ST IPv4, ea_len=35, TEID octet 0xff -- significant bits 0b111, padding masked",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = RD(8) + ea_len(1) + addr(4) + teid(1) = 14 */
			14,
			RD0,
			35,
			10, 2, 0, 1,
			0xff,
		},
		.len = 4 + 14,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v4-teid-pad-only",
		"T2ST IPv4, ea_len=35, TEID octet 0x1f -- significant bits 0, skipped as TEID=0",
		{
			MUP_ARCH, MUP_T2ST_RT,
			14,
			RD0,
			35,
			10, 2, 0, 1,
			0x1f,
		},
		.len = 4 + 14,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* IPv6 inner malformed -- skipped (treat-as-withdraw)                 */
	/* ------------------------------------------------------------------ */
	{
		"isd-v6-prefix-len-overflow",
		"ISD IPv6, prefix_len=129 (>128) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_ISD_RT,
			/* body = RD(8) + pfxlen(1) + PSIZE(129)=17 -> 26 */
			26,
			RD0,
			129,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		.len = 4 + 26,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"dsd-v6-wrong-size",
		"DSD IPv6, body=25 (not 24) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_DSD_RT,
			25,
			RD0,
			0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0x00,
		},
		.len = 4 + 25,
		.afi = AFI_IP6,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* T1ST with a Source Address                                          */
	/* ------------------------------------------------------------------ */
	{
		"t1st-v4-with-sa",
		"T1ST IPv4 with SA 10.9.9.9/32, well-formed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/*
			 * body = RD(8) + pfxlen(1) + TEID(4) + QFI(1) +
			 *        ep_len(1) + ep(4) + src_len(1) + src(4) = 24
			 */
			24,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			32,
			10, 1, 2, 3,
			32,
			10, 9, 9, 9,
		},
		.len = 4 + 24,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-src-truncated",
		"T1ST IPv4, src_len=32 but only 2 SA bytes -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/* body = 20 + 2 = 22; src_len demands 4 more bytes */
			22,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			32,
			10, 1, 2, 3,
			32,
			10, 9,
		},
		.len = 4 + 22,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Endpoint/Source Address Length must be exactly 32 or 128            */
	/* ------------------------------------------------------------------ */
	{
		"t1st-ep-len-24",
		"T1ST IPv4, endpoint_length=24 (not 32) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/* body = 15 + 1 pad = 16; parser rejects at ep_len */
			16,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			24,
			0x00,
		},
		.len = 4 + 16,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-src-len-24",
		"T1ST IPv4, source_length=24 (not 0 or 32) -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/* body = 20 + 3 = 23; parser rejects at src_len */
			23,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			32,
			10, 1, 2, 3,
			24,
			10, 9, 9,
		},
		.len = 4 + 23,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Unknown route type for 3gpp-5g -- silently ignored (draft sec 3.1)  */
	/* ------------------------------------------------------------------ */
	{
		"unknown-route-type",
		"Unknown route_type=5 -- outer loop skips, returns OK",
		{
			MUP_ARCH, 0x00, 0x05,
			4,
			0xde, 0xad, 0xbe, 0xef,
		},
		.len = 4 + 4,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Multiple NLRIs in one attribute                                     */
	/* ------------------------------------------------------------------ */
	{
		"two-valid-nlris",
		"ISD + DSD concatenated -- both parsed, returns OK",
		{
			MUP_ARCH, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
			MUP_ARCH, MUP_DSD_RT,
			12,
			RD0,
			10, 0, 0, 1,
		},
		.len = 16 + 16,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"malformed-then-valid",
		"T1ST TEID=0 then valid ISD -- malformed one skipped, rest processed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			20,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x00,
			9,
			32,
			10, 1, 2, 3,
			0,
			MUP_ARCH, MUP_ISD_RT,
			12,
			RD0,
			24, 192, 168, 1,
		},
		.len = 24 + 16,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* ------------------------------------------------------------------ */
	/* Optional TLVs after the mandatory fields (draft -01)                */
	/* ------------------------------------------------------------------ */
	{
		"t2st-v4-with-tlvs",
		"T2ST IPv4 with Session Parameters and Interwork Endpoint TLVs, well-formed",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = mandatory(17) + TLV(2+5) + TLV(2+4) = 30 */
			30,
			RD0,
			64,
			10, 2, 0, 1,
			0x00, 0x00, 0x00, 0x02,
			/* Session Parameters TLV: TEID 0x30, QFI 7 */
			1, 5, 0x00, 0x00, 0x00, 0x30, 7,
			/* Interwork Endpoint TLV: 10.99.0.5 */
			2, 4, 10, 99, 0, 5,
		},
		.len = 4 + 30,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v4-tlv-remaining-1",
		"T2ST IPv4, one trailing octet cannot hold a TLV -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T2ST_RT,
			18,
			RD0,
			64,
			10, 2, 0, 1,
			0x00, 0x00, 0x00, 0x02,
			0xff,
		},
		.len = 4 + 18,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t2st-v4-tlv-overrun",
		"T2ST IPv4, TLV value runs past the declared body -- skipped (treat-as-withdraw)",
		{
			MUP_ARCH, MUP_T2ST_RT,
			/* body = mandatory(17) + TLV header(2) + 1 value byte,
			 * but the TLV claims 9 value bytes
			 */
			20,
			RD0,
			64,
			10, 2, 0, 1,
			0x00, 0x00, 0x00, 0x02,
			9, 9, 0xaa,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-v4-teid2",
		"T1ST IPv4, same key as t1st-v4-ok but TEID 2, well-formed",
		{
			MUP_ARCH, MUP_T1ST_RT,
			20,
			RD0,
			0,
			/* TEID = 2 */
			0x00, 0x00, 0x00, 0x02,
			9,
			32,
			10, 1, 2, 3,
			0,
		},
		.len = 4 + 20,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	{
		"t1st-v4-with-unknown-tlv",
		"T1ST IPv4 with an unknown type 250 TLV -- structurally valid, accepted",
		{
			MUP_ARCH, MUP_T1ST_RT,
			/* body = mandatory(20) + TLV(2+3) = 25 */
			25,
			RD0,
			0,
			0x00, 0x00, 0x00, 0x01,
			9,
			32,
			10, 1, 2, 3,
			0,
			250, 3, 0xaa, 0xbb, 0xcc,
		},
		.len = 4 + 25,
		.afi = AFI_IP,
		.expect = BGP_NLRI_PARSE_OK,
	},
	/* sentinel */
	{ NULL, NULL, { 0 }, 0, 0, 0 },
};

/* clang-format on */

static void run_test(struct peer *peer, struct nlri_test *t)
{
	struct bgp_nlri packet = {};
	int ret;

	packet.afi = t->afi;
	packet.safi = SAFI_MUP;
	packet.nlri = (uint8_t *)t->data;
	packet.length = t->len;

	ret = bgp_nlri_parse_mup(peer, NULL, &packet, 0);

	printf("%s: %s\n", t->name, t->desc);
	printf("  got=%d expected=%d\n", ret, t->expect);
	if (ret == t->expect) {
		printf("OK\n");
	} else {
		printf("failed\n");
		failed++;
	}
	printf("\n");
}

static const struct nlri_test *find_segment(const char *name)
{
	int i;

	for (i = 0; mup_segments[i].name; i++)
		if (strcmp(mup_segments[i].name, name) == 0)
			return &mup_segments[i];
	assert(!"unknown segment name");
	return NULL;
}

/* Encode `p` and require an exact byte match against the parse-test
 * wire vector of the same name, keeping encode and parse inverse
 * operations for the same NLRI.
 */
static void encode_and_check_attr(const char *name, afi_t afi, const struct prefix_mup *p,
				  const struct attr *attr)
{
	const struct nlri_test *t = find_segment(name);
	struct stream *s = stream_new(BGP_MAX_PACKET_SIZE);

	bgp_mup_encode_prefix(s, afi, (const struct prefix *)p, NULL, attr, false, 0);

	printf("encode-%s: encode matches the %s parse vector\n", name, name);
	if (stream_get_endp(s) == (size_t)t->len && memcmp(STREAM_DATA(s), t->data, t->len) == 0) {
		printf("OK\n");
	} else {
		printf("  endp=%zu expected=%d\n", stream_get_endp(s), t->len);
		printf("failed\n");
		failed++;
	}
	printf("\n");
	stream_free(s);
}

static void encode_and_check(const char *name, afi_t afi, const struct prefix_mup *p)
{
	encode_and_check_attr(name, afi, p, NULL);
}

/* Encode with the TLV region carried on the attr and require the wire
 * vector's TLV bytes to reappear verbatim after the mandatory fields.
 */
static void encode_and_check_tlvs(const char *name, afi_t afi, const struct prefix_mup *p,
				  const uint8_t *tlv_bytes, uint16_t tlv_len)
{
	struct attr attr = {};
	struct bgp_mup_nlri_data *tlvs = mup_nlri_data_intern(mup_nlri_data_new(tlv_bytes, tlv_len));

	bgp_attr_set_mup_nlri_data(&attr, tlvs);
	encode_and_check_attr(name, afi, p, &attr);
	mup_nlri_data_unintern(&tlvs);
}

static void test_encode(void)
{
	static const uint8_t rd0[8] = { RD0 };
	static const uint8_t t2st_tlvs[] = { 1, 5, 0x00, 0x00, 0x00, 0x30, 7, 2, 4, 10, 99, 0, 5 };
	/* T1ST architecture specific regions matching the parse vectors. */
	static const uint8_t t1st_arch_sa[] = { 0x00, 0x00, 0x00, 0x01, 9,	32, 10, 1,
						2,    3,    32,	  10,	9, 9, 9 };
	static const uint8_t t1st_arch_tlv[] = { 0x00, 0x00, 0x00, 0x01, 9,    32,   10, 1,
						 2,    3,    0,	   250,	 3, 0xaa, 0xbb, 0xcc };
	struct prefix_mup p;

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_ISD_ROUTE;
	p.prefix.length = 12;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.isd_route.ip_prefix_length = 24;
	p.prefix.isd_route.ip.ipa_type = IPADDR_V4;
	inet_pton(AF_INET, "192.168.1.0", &p.prefix.isd_route.ip.ip.addr);
	encode_and_check("isd-v4-ok", AFI_IP, &p);

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_ISD_ROUTE;
	p.prefix.length = 17;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.isd_route.ip_prefix_length = 64;
	p.prefix.isd_route.ip.ipa_type = IPADDR_V6;
	inet_pton(AF_INET6, "2001:db8::", &p.prefix.isd_route.ip.ip.addr);
	encode_and_check("isd-v6-ok", AFI_IP6, &p);

	/* The T1ST key is RD + Prefix Length + Prefix; the architecture
	 * specific fields ride on the attr and re-encode verbatim.
	 */
	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T1ST_ROUTE;
	p.prefix.length = 9;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t1st_route.ip_prefix_length = 0;
	p.prefix.t1st_route.ip.ipa_type = IPADDR_V4;
	encode_and_check_tlvs("t1st-v4-with-sa", AFI_IP, &p, t1st_arch_sa, sizeof(t1st_arch_sa));

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;
	p.prefix.length = 17;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t2st_route.endpoint_address_length = 64;
	p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V4;
	inet_pton(AF_INET, "10.2.0.1", &p.prefix.t2st_route.endpoint_address.ip.addr);
	p.prefix.t2st_route.teid = 2;
	encode_and_check("t2st-v4-ok", AFI_IP, &p);

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;
	p.prefix.length = 13;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t2st_route.endpoint_address_length = 32;
	p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V4;
	inet_pton(AF_INET, "10.2.0.1", &p.prefix.t2st_route.endpoint_address.ip.addr);
	encode_and_check("t2st-v4-ea32-no-teid", AFI_IP, &p);

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;
	p.prefix.length = 29;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t2st_route.endpoint_address_length = 160;
	p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V6;
	inet_pton(AF_INET6, "2001:db8::9", &p.prefix.t2st_route.endpoint_address.ip.addr);
	p.prefix.t2st_route.teid = 2;
	encode_and_check("t2st-v6-ok", AFI_IP6, &p);

	/* draft -01: TLVs kept on the attr reappear verbatim after the
	 * mandatory fields, for known and unknown types alike.
	 */
	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T2ST_ROUTE;
	p.prefix.length = 17;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t2st_route.endpoint_address_length = 64;
	p.prefix.t2st_route.endpoint_address.ipa_type = IPADDR_V4;
	inet_pton(AF_INET, "10.2.0.1", &p.prefix.t2st_route.endpoint_address.ip.addr);
	p.prefix.t2st_route.teid = 2;
	encode_and_check_tlvs("t2st-v4-with-tlvs", AFI_IP, &p, t2st_tlvs, sizeof(t2st_tlvs));

	memset(&p, 0, sizeof(p));
	p.prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p.prefix.route_type = BGP_MUP_T1ST_ROUTE;
	p.prefix.length = 9;
	memcpy(p.prefix.rd, rd0, 8);
	p.prefix.t1st_route.ip_prefix_length = 0;
	p.prefix.t1st_route.ip.ipa_type = IPADDR_V4;
	encode_and_check_tlvs("t1st-v4-with-unknown-tlv", AFI_IP, &p, t1st_arch_tlv,
			      sizeof(t1st_arch_tlv));
}

/* bgp_mup_parse_tlvs() cases the outer parse return code cannot
 * distinguish: accept and treat-as-withdraw both yield PARSE_OK.
 */
static void test_parse_tlvs(void)
{
	static const struct {
		const char *desc;
		uint16_t route_type;
		uint8_t buf[24];
		int len;
		int expect;
	} tests[] = {
		{ "empty region", BGP_MUP_T2ST_ROUTE, { 0 }, 0, 0 },
		{ "single octet cannot hold a TLV", BGP_MUP_T2ST_ROUTE, { 0xff }, 1, -1 },
		{ "unknown type, structurally valid", BGP_MUP_T2ST_ROUTE, { 9, 2, 0xaa, 0xbb }, 4,
		  0 },
		{ "unknown zero-length TLV", BGP_MUP_T2ST_ROUTE, { 9, 0 }, 2, 0 },
		{ "value overruns the region", BGP_MUP_T2ST_ROUTE, { 9, 9, 0xaa }, 3, -1 },
		{ "second TLV header truncated", BGP_MUP_T2ST_ROUTE, { 9, 2, 0xaa, 0xbb, 9 }, 5,
		  -1 },
		{ "T2ST session parameters, length 5", BGP_MUP_T2ST_ROUTE, { 1, 5, 0, 0, 0, 1, 9 },
		  7, 0 },
		{ "T2ST session parameters, wrong length", BGP_MUP_T2ST_ROUTE,
		  { 1, 4, 0, 0, 0, 1 }, 6, -1 },
		{ "T2ST interwork endpoint, IPv4 length", BGP_MUP_T2ST_ROUTE, { 2, 4, 10, 0, 0, 1 },
		  6, 0 },
		{ "T2ST interwork endpoint, bad length", BGP_MUP_T2ST_ROUTE, { 2, 5, 1, 2, 3, 4, 5 },
		  7, -1 },
		{ "T2ST source address, IPv6 length", BGP_MUP_T2ST_ROUTE,
		  { 3, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 }, 18, 0 },
		{ "T1ST session parameters not applicable, structural only", BGP_MUP_T1ST_ROUTE,
		  { 1, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 11, 0 },
	};
	unsigned int i;

	for (i = 0; i < array_size(tests); i++) {
		int ret = bgp_mup_parse_tlvs(tests[i].route_type, tests[i].buf, tests[i].len);

		printf("parse-tlvs: %s\n", tests[i].desc);
		printf("  got=%d expected=%d\n", ret, tests[i].expect);
		if (ret == tests[i].expect) {
			printf("OK\n");
		} else {
			printf("failed\n");
			failed++;
		}
		printf("\n");
	}
}

static struct bgp *bgp;
static as_t asn = 100;

/* Parse `name`'s wire vector with a minimal valid attr so an accepted
 * T2ST route is actually installed, then check the TEID that made it
 * into the route key.  This is what catches unmasked padding bits:
 * the outer return code is BGP_NLRI_PARSE_OK whether the NLRI is
 * accepted or skipped as malformed, so run_test cannot tell the two
 * apart.
 */
static void parse_and_check_t2st_teid(struct peer *peer, const char *name, bool want_installed,
				      uint32_t want_teid)
{
	const struct nlri_test *t = find_segment(name);
	struct bgp_nlri packet = {};
	struct attr attr = {};
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	uint32_t got_teid = 0;
	bool installed = false;

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
	inet_pton(AF_INET6, "2001:db8::1", &attr.mp_nexthop_global);

	packet.afi = t->afi;
	packet.safi = SAFI_MUP;
	packet.nlri = (uint8_t *)t->data;
	packet.length = t->len;

	bgp_nlri_parse_mup(peer, &attr, &packet, 0);

	/* A withdrawn path lingers with BGP_PATH_REMOVED set because the
	 * deferred deletion in bgp_process() never runs here; only paths
	 * still valid count as installed.
	 */
	for (dest = bgp_table_top(bgp->rib[t->afi][SAFI_MUP]); dest; dest = bgp_route_next(dest)) {
		const struct prefix_mup *p = (const struct prefix_mup *)bgp_dest_get_prefix(dest);

		if (p->prefix.route_type != BGP_MUP_T2ST_ROUTE)
			continue;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				continue;
			installed = true;
			got_teid = p->prefix.t2st_route.teid;
		}
	}

	printf("teid-padding-%s: route key TEID after parse with attr\n", name);
	printf("  got installed=%d teid=0x%08x, expected installed=%d teid=0x%08x\n", installed,
	       got_teid, want_installed, want_teid);
	if (installed == want_installed && (!installed || got_teid == want_teid)) {
		printf("OK\n");
	} else {
		printf("failed\n");
		failed++;
	}
	printf("\n");

	/* Withdraw so every case starts from an empty MUP table. */
	bgp_nlri_parse_mup(peer, NULL, &packet, 0);
}

static void test_t2st_teid_padding(struct peer *peer)
{
	/* TEID octet 0xff: top 3 bits are TEID, low 5 are padding. */
	parse_and_check_t2st_teid(peer, "t2st-v4-teid-padded", true, 0xe0000000);
	/* TEID octet 0x1f: all TEID bits zero -- draft section 3.1.4.1
	 * malformed (TEID=0), must be skipped despite non-zero padding.
	 */
	parse_and_check_t2st_teid(peer, "t2st-v4-teid-pad-only", false, 0);
}

static void test_t2st_tlvs_install(struct peer *peer)
{
	/* Valid TLVs ride along; the mandatory TEID still keys the route. */
	parse_and_check_t2st_teid(peer, "t2st-v4-with-tlvs", true, 2);
	/* Malformed TLV regions are treat-as-withdraw despite the outer
	 * PARSE_OK.
	 */
	parse_and_check_t2st_teid(peer, "t2st-v4-tlv-remaining-1", false, 0);
	parse_and_check_t2st_teid(peer, "t2st-v4-tlv-overrun", false, 0);
}

/* Announce the same T1ST key with two different TEIDs: the second
 * announcement must replace the first (draft 3.1.3 keys T1ST on RD +
 * Prefix Length + Prefix only), leaving one path whose attr carries the
 * latest architecture specific fields.
 */
static void test_t1st_replacement(struct peer *peer)
{
	const struct nlri_test *t1 = find_segment("t1st-v4-ok");
	const struct nlri_test *t2 = find_segment("t1st-v4-teid2");
	struct bgp_nlri packet = {};
	struct attr attr = {};
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	uint32_t blob_teid = 0;
	int npaths = 0;

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
	inet_pton(AF_INET6, "2001:db8::1", &attr.mp_nexthop_global);

	packet.afi = t1->afi;
	packet.safi = SAFI_MUP;
	packet.nlri = (uint8_t *)t1->data;
	packet.length = t1->len;
	bgp_nlri_parse_mup(peer, &attr, &packet, 0);

	packet.nlri = (uint8_t *)t2->data;
	packet.length = t2->len;
	bgp_nlri_parse_mup(peer, &attr, &packet, 0);

	for (dest = bgp_table_top(bgp->rib[t1->afi][SAFI_MUP]); dest; dest = bgp_route_next(dest)) {
		const struct prefix_mup *p = (const struct prefix_mup *)bgp_dest_get_prefix(dest);

		if (p->prefix.route_type != BGP_MUP_T1ST_ROUTE)
			continue;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			const struct bgp_mup_nlri_data *data;

			if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				continue;
			npaths++;
			data = bgp_attr_get_mup_nlri_data(pi->attr);
			if (data && data->length >= BGP_MUP_TEID_BYTES) {
				memcpy(&blob_teid, data->val, BGP_MUP_TEID_BYTES);
				blob_teid = ntohl(blob_teid);
			}
		}
	}

	printf("t1st-replacement: second TEID replaces the first for the same key\n");
	printf("  got paths=%d teid=%u, expected paths=1 teid=2\n", npaths, blob_teid);
	if (npaths == 1 && blob_teid == 2) {
		printf("OK\n");
	} else {
		printf("failed\n");
		failed++;
	}
	printf("\n");

	bgp_nlri_parse_mup(peer, NULL, &packet, 0);
}

int main(void)
{
	struct interface ifp;
	struct peer *peer;
	int i;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("test bgp mup nlri");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_labels_init();

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return 1;

	peer = peer_create_accept(bgp, NULL);
	peer->host = (char *)"test-peer";
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(BGP_MAX_PACKET_SIZE);

	ifp.ifindex = 0;
	peer->nexthop.ifp = &ifp;

	for (i = AFI_IP; i < AFI_MAX; i++) {
		peer->afc[i][SAFI_MUP] = 1;
		peer->afc_adv[i][SAFI_MUP] = 1;
		peer->afc_nego[i][SAFI_MUP] = 1;
	}

	i = 0;
	while (mup_segments[i].name)
		run_test(peer, &mup_segments[i++]);

	test_encode();
	test_parse_tlvs();
	test_t2st_teid_padding(peer);
	test_t2st_tlvs_install(peer);
	test_t1st_replacement(peer);

	printf("failures: %d\n", failed);
	return failed;
}
