/*
 * SRv6 definitions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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

#ifndef _FRR_SRV6_H
#define _FRR_SRV6_H

#include <zebra.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SRV6_MAX_SIDS 16

#ifdef __cplusplus
extern "C" {
#endif

#define sid2str(sid, str, size) \
	inet_ntop(AF_INET6, sid, str, size)

enum seg6_mode_t {
	INLINE,
	ENCAP,
	L2ENCAP,
};

enum seg6local_action_t {
	ZEBRA_SEG6_LOCAL_ACTION_UNSPEC       = 0,
	ZEBRA_SEG6_LOCAL_ACTION_END          = 1,
	ZEBRA_SEG6_LOCAL_ACTION_END_X        = 2,
	ZEBRA_SEG6_LOCAL_ACTION_END_T        = 3,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX2      = 4,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX6      = 5,
	ZEBRA_SEG6_LOCAL_ACTION_END_DX4      = 6,
	ZEBRA_SEG6_LOCAL_ACTION_END_DT6      = 7,
	ZEBRA_SEG6_LOCAL_ACTION_END_DT4      = 8,
	ZEBRA_SEG6_LOCAL_ACTION_END_B6       = 9,
	ZEBRA_SEG6_LOCAL_ACTION_END_B6_ENCAP = 10,
	ZEBRA_SEG6_LOCAL_ACTION_END_BM       = 11,
	ZEBRA_SEG6_LOCAL_ACTION_END_S        = 12,
	ZEBRA_SEG6_LOCAL_ACTION_END_AS       = 13,
	ZEBRA_SEG6_LOCAL_ACTION_END_AM       = 14,
	ZEBRA_SEG6_LOCAL_ACTION_END_BPF      = 15,
};

struct seg6_segs {
	size_t num_segs;
	struct in6_addr segs[256];
};

struct seg6local_context {
	struct in_addr nh4;
	struct in6_addr nh6;
	uint32_t table;
};

static inline const char *seg6_mode2str(enum seg6_mode_t mode)
{
	switch (mode) {
	case INLINE:
		return "INLINE";
	case ENCAP:
		return "ENCAP";
	case L2ENCAP:
		return "L2ENCAP";
	default:
		return "unknown";
	}
}

static inline bool sid_same(
		const struct in6_addr *a,
		const struct in6_addr *b)
{
	if (!a && !b)
		return true;
	else if (!(a && b))
		return false;
	else
		return memcmp(a, b, sizeof(struct in6_addr)) == 0;
}

static inline bool sid_diff(
		const struct in6_addr *a,
		const struct in6_addr *b)
{
	return !sid_same(a, b);
}

static inline bool sid_zero(
		const struct in6_addr *a)
{
	struct in6_addr zero = {};

	return sid_same(a, &zero);
}

static inline void *sid_copy(struct in6_addr *dst,
		const struct in6_addr *src)
{
	return memcpy(dst, src, sizeof(struct in6_addr));
}

const char *
seg6local_action2str(uint32_t action);

const char *
seg6local_context2str(char *str, size_t size,
		struct seg6local_context *ctx, uint32_t action);

int snprintf_seg6_segs(char *str,
		size_t size, const struct seg6_segs *segs);

#ifdef __cplusplus
}
#endif

#endif
