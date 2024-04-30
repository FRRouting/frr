// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

void pim_inet4_dump(const char *onfail, struct in_addr addr, char *buf,
		    int buf_size);

#endif
