/*
 * PIM address generalizations
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

#ifndef _PIMD_PIM_ADDR_H
#define _PIMD_PIM_ADDR_H

#include "jhash.h"

/* temporarily disable IPv6 types to keep code compiling.
 * Defining PIM_V6_TEMP_BREAK will show a lot of compile errors - they are
 * very useful to see TODOs.
 */
#if PIM_IPV == 4 || !defined(PIM_V6_TEMP_BREAK)
typedef struct in_addr pim_addr;
#define PIM_ADDRSTRLEN INET_ADDRSTRLEN
#else
typedef struct in6_addr pim_addr;
#define PIM_ADDRSTRLEN INET6_ADDRSTRLEN
#endif

static inline bool pim_addr_is_any(pim_addr addr)
{
	pim_addr zero = {};

	return memcmp(&addr, &zero, sizeof(zero)) == 0;
}

static inline int pim_addr_cmp(pim_addr a, pim_addr b)
{
	return memcmp(&a, &b, sizeof(a));
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
