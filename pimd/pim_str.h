/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#ifndef PIM_STR_H
#define PIM_STR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "prefix.h"
#include "pim_addr.h"

#include "pim_addr.h"

/*
 * Longest possible length of a (S,G) string is 36 bytes
 * 123.123.123.123 = 16 * 2
 * (,) = 3
 * NULL Character at end = 1
 * (123.123.123.123,123,123,123,123)
 */
#define PIM_SG_LEN PREFIX_SG_STR_LEN
#define pim_inet4_dump prefix_mcast_inet4_dump

static inline void pim_addr_copy(pim_addr *dest, pim_addr *source)
{
	dest->s_addr = source->s_addr;
}

static inline int pim_is_addr_any(pim_addr addr)
{
	return (addr.s_addr == INADDR_ANY);
}

static inline int pim_addr_cmp(pim_addr addr1, pim_addr addr2)
{
	return IPV4_ADDR_CMP(&addr1, &addr2);
}

void pim_addr_dump(const char *onfail, struct prefix *p, char *buf,
		   int buf_size);
void pim_inet4_dump(const char *onfail, struct in_addr addr, char *buf,
		    int buf_size);
char *pim_str_sg_dump(const pim_sgaddr *sg);

#endif
