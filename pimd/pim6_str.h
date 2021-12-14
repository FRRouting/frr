
/*
 * PIM for FRR
 * Copyright (C) 2021 Mobashshera Rasool
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM6_STR_H
#define PIM6_STR_H

#include <zebra.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <lib/prefix.h>

typedef struct in6_addr PIM_ADDR;

#define PIM_UN_PFX(p) ((p).u.prefix6)

/*
 * Longest possible length of a (S,G) string is 36 bytes
 * 123.123.123.123 = 16 * 2
 * (,) = 3
 * NULL Character at end = 1
 * (123.123.123.123,123,123,123,123)
 */
#define PIM_SG_LEN PREFIX_SG_STR_LEN
/* TODO: change the below one into common printf statements using
 * format specifier later
 */
/*#define pim_inet4_dump prefix_mcast_inet6_dump*/
#define pim_inet4_dump prefix_mcast_inet4_dump
#define pim_str_sg_set prefix_sg2str

static inline void pim_addr_copy(PIM_ADDR *dest, PIM_ADDR *source)
{
	IPV6_ADDR_COPY(dest, source);
}

static inline int pim_is_addr_any(PIM_ADDR addr)
{
	return IPV6_ADDR_SAME(&addr, &in6addr_any);
}

static inline int pim_addr_ntoh_and_compare(PIM_ADDR addr1,
					    PIM_ADDR addr2)
{
	return IPV6_ADDR_CMP(&addr1, &addr2);
}

static inline int pim_addr_compare(PIM_ADDR addr1, PIM_ADDR addr2)
{
	return IPV6_ADDR_CMP(&addr1, &addr2);
}

static inline int pim_addr_is_same(PIM_ADDR addr1, PIM_ADDR addr2)
{
	return IPV6_ADDR_SAME(&addr1, &addr2);
}

void pim_addr_dump(const char *onfail, struct prefix *p, char *buf,
		   int buf_size);
void pim_inet4_dump(const char *onfail, struct in_addr addr, char *buf,
		    int buf_size);
char *pim_str_sg_dump(const struct prefix_sg *sg);

#endif
