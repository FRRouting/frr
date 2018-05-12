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
		uint8_t addr;
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

/*
 * Convert IPv4 address to IPv4-mapped IPv6 address which is of the
 * form ::FFFF:<IPv4 address> (RFC 4291). This IPv6 address can then
 * be used to represent the IPv4 address, wherever only an IPv6 address
 * is required.
 */
static inline void ipv4_to_ipv4_mapped_ipv6(struct in6_addr *in6,
					    struct in_addr in)
{
	uint32_t addr_type = htonl(0xFFFF);

	memset(in6, 0, sizeof(struct in6_addr));
	memcpy((char *)in6 + 8, &addr_type, sizeof(addr_type));
	memcpy((char *)in6 + 12, &in, sizeof(struct in_addr));
}

/*
 * convert an ipv4 mapped ipv6 address back to ipv4 address
 */
static inline void ipv4_mapped_ipv6_to_ipv4(struct in6_addr *in6,
					    struct in_addr *in)
{
	memset(in, 0, sizeof(struct in_addr));
	memcpy(in, (char *)in6 + 12, sizeof(struct in_addr));
}

#endif /* __IPADDR_H__ */
