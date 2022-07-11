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

#if PIM_IPV == 4
/*
 * Longest possible length of a IPV4 (S,G) string is 34 bytes
 * 123.123.123.123 = 16 * 2
 * (,) = 3
 * NULL Character at end = 1
 * (123.123.123.123,123.123.123.123)
 */
#define PIM_SG_LEN PREFIX_SG_STR_LEN
#else
/*
 * Longest possible length of a IPV6 (S,G) string is 94 bytes
 * INET6_ADDRSTRLEN * 2 = 46 * 2
 * (,) = 3
 * NULL Character at end = 1
 */
#define PIM_SG_LEN 96
#endif

#define pim_inet4_dump prefix_mcast_inet4_dump

void pim_addr_dump(const char *onfail, struct prefix *p, char *buf,
		   int buf_size);
void pim_inet4_dump(const char *onfail, struct in_addr addr, char *buf,
		    int buf_size);

#endif
