/*
 * IP address structure (for generic IPv4 or IPv6 address)
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef __IPADDR_H__
#define __IPADDR_H__

#include <zebra.h>

/*
 * Generic IP address - union of IPv4 and IPv6 address.
 */
enum ipaddr_type_t {
	IPADDR_NONE = 0,
	IPADDR_V4 = 1, /* IPv4 */
	IPADDR_V6 = 2, /* IPv6 */
};

struct ipaddr {
	enum ipaddr_type_t ipa_type;
	union {
		u_char addr;
		struct in_addr _v4_addr;
		struct in6_addr _v6_addr;
	} ip;
#define ipaddr_v4 ip._v4_addr
#define ipaddr_v6 ip._v6_addr
};

#define IS_IPADDR_NONE(p) ((p)->ipa_type == IPADDR_NONE)
#define IS_IPADDR_V4(p)   ((p)->ipa_type == IPADDR_V4)
#define IS_IPADDR_V6(p)   ((p)->ipa_type == IPADDR_V6)

#define SET_IPADDR_V4(p)  (p)->ipa_type = IPADDR_V4
#define SET_IPADDR_V6(p)  (p)->ipa_type = IPADDR_V6

static inline int str2ipaddr(const char *str, struct ipaddr *ip)
{
	int ret;

	memset(ip, 0, sizeof(struct ipaddr));

	ret = inet_pton(AF_INET, str, &ip->ipaddr_v4);
	if (ret > 0) /* Valid IPv4 address. */
	{
		ip->ipa_type = IPADDR_V4;
		return 0;
	}
	ret = inet_pton(AF_INET6, str, &ip->ipaddr_v6);
	if (ret > 0) /* Valid IPv6 address. */
	{
		ip->ipa_type = IPADDR_V6;
		return 0;
	}

	return -1;
}

static inline char *ipaddr2str(struct ipaddr *ip, char *buf, int size)
{
	buf[0] = '\0';
	if (ip) {
		if (IS_IPADDR_V4(ip))
			inet_ntop(AF_INET, &ip->ip.addr, buf, size);
		else if (IS_IPADDR_V6(ip))
			inet_ntop(AF_INET6, &ip->ip.addr, buf, size);
	}
	return buf;
}
#endif /* __IPADDR_H__ */
