/*
 * MLD protocol definitions
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PIM6_MLD_PROTOCOL_H
#define _PIM6_MLD_PROTOCOL_H

#include <stdalign.h>
#include <stdint.h>

/* There is a struct icmp6_hdr provided by OS, but it includes 4 bytes of data.
 * Not helpful for us if we want to put the MLD struct after it.
 */

struct icmp6_plain_hdr {
	uint8_t icmp6_type;
	uint8_t icmp6_code;
	uint16_t icmp6_cksum;
};
static_assert(sizeof(struct icmp6_plain_hdr) == 4, "struct mismatch");
static_assert(alignof(struct icmp6_plain_hdr) <= 4, "struct mismatch");

/* for MLDv1 query, report and leave all use the same packet format */
struct mld_v1_pkt {
	uint16_t max_resp_code;
	uint16_t rsvd0;
	struct in6_addr grp;
};
static_assert(sizeof(struct mld_v1_pkt) == 20, "struct mismatch");
static_assert(alignof(struct mld_v1_pkt) <= 4, "struct mismatch");


struct mld_v2_query_hdr {
	uint16_t max_resp_code;
	uint16_t rsvd0;
	struct in6_addr grp;
	uint8_t flags;
	uint8_t qqic;
	uint16_t n_src;
	struct in6_addr srcs[0];
};
static_assert(sizeof(struct mld_v2_query_hdr) == 24, "struct mismatch");
static_assert(alignof(struct mld_v2_query_hdr) <= 4, "struct mismatch");


struct mld_v2_report_hdr {
	uint16_t rsvd;
	uint16_t n_records;
};
static_assert(sizeof(struct mld_v2_report_hdr) == 4, "struct mismatch");
static_assert(alignof(struct mld_v2_report_hdr) <= 4, "struct mismatch");


struct mld_v2_rec_hdr {
	uint8_t type;
	uint8_t aux_len;
	uint16_t n_src;
	struct in6_addr grp;
	struct in6_addr srcs[0];
};
static_assert(sizeof(struct mld_v2_rec_hdr) == 20, "struct mismatch");
static_assert(alignof(struct mld_v2_rec_hdr) <= 4, "struct mismatch");

/* clang-format off */
enum icmp6_mld_type {
	ICMP6_MLD_QUERY			= 130,
	ICMP6_MLD_V1_REPORT		= 131,
	ICMP6_MLD_V1_DONE		= 132,
	ICMP6_MLD_V2_REPORT		= 143,
};

enum mld_v2_rec_type {
	MLD_RECTYPE_IS_INCLUDE		= 1,
	MLD_RECTYPE_IS_EXCLUDE		= 2,
	MLD_RECTYPE_CHANGE_TO_INCLUDE	= 3,
	MLD_RECTYPE_CHANGE_TO_EXCLUDE	= 4,
	MLD_RECTYPE_ALLOW_NEW_SOURCES	= 5,
	MLD_RECTYPE_BLOCK_OLD_SOURCES	= 6,
};
/* clang-format on */

/* helper functions */

static inline unsigned int mld_max_resp_decode(uint16_t wire)
{
	uint16_t code = ntohs(wire);
	uint8_t exp;

	if (code < 0x8000)
		return code;
	exp = (code >> 12) & 0x7;
	return ((code & 0xfff) | 0x1000) << (exp + 3);
}

static inline uint16_t mld_max_resp_encode(uint32_t value)
{
	uint16_t code;
	uint8_t exp;

	if (value < 0x8000)
		code = value;
	else {
		exp = 16 - __builtin_clz(value);
		code = (value >> (exp + 3)) & 0xfff;
		code |= 0x8000 | (exp << 12);
	}
	return htons(code);
}

#endif /* _PIM6_MLD_PROTOCOL_H */
