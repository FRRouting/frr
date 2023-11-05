// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM address generalizations
 * Copyright (C) 2022  David Lamparter for NetDEF, Inc.
 */

#ifndef _PIMD_PIM_ADDR_H
#define _PIMD_PIM_ADDR_H

#include "jhash.h"
#include "prefix.h"

/* clang-format off */

#if PIM_IPV == 4
typedef struct in_addr pim_addr;

#define PIM_ADDRSTRLEN	INET_ADDRSTRLEN
#define PIM_AF		AF_INET
#define PIM_AFI		AFI_IP
#define PIM_PROTO_REG   IPPROTO_RAW
#define PIM_IPADDR	IPADDR_V4
#define ipaddr_pim	ipaddr_v4
#define PIM_MAX_BITLEN	IPV4_MAX_BITLEN
#define PIM_AF_NAME     "ip"
#define PIM_AF_DBG	"pim"
#define GM_AF_DBG	"igmp"
#define PIM_MROUTE_DBG  "mroute"
#define PIMREG          "pimreg"
#define GM              "IGMP"
#define IPPROTO_GM      IPPROTO_IGMP

#define PIM_ADDR_FUNCNAME(name) ipv4_##name

union pimprefixptr {
	uniontype(pimprefixptr, struct prefix,      p)
	uniontype(pimprefixptr, struct prefix_ipv4, p4)
} TRANSPARENT_UNION;

union pimprefixconstptr {
	uniontype(pimprefixconstptr, const struct prefix,      p)
	uniontype(pimprefixconstptr, const struct prefix_ipv4, p4)
} TRANSPARENT_UNION;

#else
typedef struct in6_addr pim_addr;

#define PIM_ADDRSTRLEN	INET6_ADDRSTRLEN
#define PIM_AF		AF_INET6
#define PIM_AFI		AFI_IP6
#define PIM_PROTO_REG   IPPROTO_PIM
#define PIM_IPADDR	IPADDR_V6
#define ipaddr_pim	ipaddr_v6
#define PIM_MAX_BITLEN	IPV6_MAX_BITLEN
#define PIM_AF_NAME     "ipv6"
#define PIM_AF_DBG	"pimv6"
#define GM_AF_DBG	"mld"
#define PIM_MROUTE_DBG  "mroute6"
#define PIMREG          "pim6reg"
#define GM              "MLD"
#define IPPROTO_GM      IPPROTO_ICMPV6

#define PIM_ADDR_FUNCNAME(name) ipv6_##name

union pimprefixptr {
	uniontype(pimprefixptr, struct prefix,      p)
	uniontype(pimprefixptr, struct prefix_ipv6, p6)
} TRANSPARENT_UNION;

union pimprefixconstptr {
	uniontype(pimprefixconstptr, const struct prefix,      p)
	uniontype(pimprefixconstptr, const struct prefix_ipv6, p6)
} TRANSPARENT_UNION;
#endif

/* for assignment/initialization (C99 compound literal)
 * named PIMADDR_ANY (not PIM_ADDR_ANY) to match INADDR_ANY
 */
#define PIMADDR_ANY (pim_addr){ }

/* clang-format on */

static inline bool pim_addr_is_any(pim_addr addr)
{
	pim_addr zero = {};

	return memcmp(&addr, &zero, sizeof(zero)) == 0;
}

static inline int pim_addr_cmp(pim_addr a, pim_addr b)
{
	return memcmp(&a, &b, sizeof(a));
}

static inline void pim_addr_to_prefix(union pimprefixptr out, pim_addr in)
{
	out.p->family = PIM_AF;
	out.p->prefixlen = PIM_MAX_BITLEN;
	memcpy(out.p->u.val, &in, sizeof(in));
}

static inline pim_addr pim_addr_from_prefix(union pimprefixconstptr in)
{
	pim_addr ret;

	if (in.p->family != PIM_AF)
		return PIMADDR_ANY;

	memcpy(&ret, in.p->u.val, sizeof(ret));
	return ret;
}

static inline uint8_t pim_addr_scope(const pim_addr addr)
{
	return PIM_ADDR_FUNCNAME(mcast_scope)(&addr);
}

static inline bool pim_addr_nofwd(const pim_addr addr)
{
	return PIM_ADDR_FUNCNAME(mcast_nofwd)(&addr);
}

static inline bool pim_addr_ssm(const pim_addr addr)
{
	return PIM_ADDR_FUNCNAME(mcast_ssm)(&addr);
}

/* don't use this struct directly, use the pim_sgaddr typedef */
struct _pim_sgaddr {
	pim_addr grp;
	pim_addr src;
};

typedef struct _pim_sgaddr pim_sgaddr;

static inline int pim_sgaddr_cmp(const pim_sgaddr a, const pim_sgaddr b)
{
	/* memcmp over the entire struct = memcmp(grp) + memcmp(src) */
	return memcmp(&a, &b, sizeof(a));
}

static inline uint32_t pim_sgaddr_hash(const pim_sgaddr a, uint32_t initval)
{
	return jhash2((uint32_t *)&a, sizeof(a) / sizeof(uint32_t), initval);
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pPA" (pim_addr *)
#pragma FRR printfrr_ext "%pSG" (pim_sgaddr *)
#endif

/*
 * There is no pim_sgaddr2str().  This is intentional.  Instead, use:
 *	snprintfrr(buf, sizeof(buf), "%pPA", sgaddr)
 * (and note that snprintfrr is implicit for vty_out and zlog_*)
 */

#endif /* _PIMD_PIM_ADDR_H */
