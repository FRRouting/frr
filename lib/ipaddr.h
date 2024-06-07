// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP address structure (for generic IPv4 or IPv6 address)
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

#ifndef __IPADDR_H__
#define __IPADDR_H__

#include <zebra.h>

#include "lib/log.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic IP address - union of IPv4 and IPv6 address.
 */
enum ipaddr_type_t {
	IPADDR_NONE = AF_UNSPEC,
	IPADDR_V4 = AF_INET,
	IPADDR_V6 = AF_INET6,
};

struct ipaddr {
	enum ipaddr_type_t ipa_type;
	union {
		uint8_t addr;
		uint8_t addrbytes[16];
		struct in_addr _v4_addr;
		struct in6_addr _v6_addr;
	} ip;
#define ipaddr_v4 ip._v4_addr
#define ipaddr_v6 ip._v6_addr
};

#define IS_IPADDR_NONE(p) ((p)->ipa_type == IPADDR_NONE)
#define IS_IPADDR_V4(p)   ((p)->ipa_type == IPADDR_V4)
#define IS_IPADDR_V6(p)   ((p)->ipa_type == IPADDR_V6)

#define SET_IPADDR_NONE(p) ((p)->ipa_type = IPADDR_NONE)
#define SET_IPADDR_V4(p)   ((p)->ipa_type = IPADDR_V4)
#define SET_IPADDR_V6(p)   ((p)->ipa_type = IPADDR_V6)

#define IPADDRSZ(p)                                                            \
	(IS_IPADDR_V4((p)) ? sizeof(struct in_addr) : sizeof(struct in6_addr))

#define IPADDR_STRING_SIZE 46

static inline int ipaddr_family(const struct ipaddr *ip)
{
	switch (ip->ipa_type) {
	case IPADDR_V4:
		return AF_INET;
	case IPADDR_V6:
		return AF_INET6;
	case IPADDR_NONE:
		return AF_UNSPEC;
	}

	assert(!"Reached end of function where we should never hit");
}

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

static inline char *ipaddr2str(const struct ipaddr *ip, char *buf, int size)
{
	buf[0] = '\0';
	if (ip)
		inet_ntop(ip->ipa_type, &ip->ip.addr, buf, size);
	return buf;
}

#define IS_MAPPED_IPV6(A)                                                      \
	((A)->s6_addr32[0] == 0x00000000                                       \
		 ? ((A)->s6_addr32[1] == 0x00000000                            \
			    ? (ntohl((A)->s6_addr32[2]) == 0xFFFF ? 1 : 0)     \
			    : 0)                                               \
		 : 0)

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
static inline void ipv4_mapped_ipv6_to_ipv4(const struct in6_addr *in6,
					    struct in_addr *in)
{
	memset(in, 0, sizeof(struct in_addr));
	memcpy(in, (char *)in6 + 12, sizeof(struct in_addr));
}

/*
 * generic ordering comparison between IP addresses
 */
static inline int ipaddr_cmp(const struct ipaddr *a, const struct ipaddr *b)
{
	uint32_t va, vb;
	va = a->ipa_type;
	vb = b->ipa_type;
	if (va != vb)
		return (va < vb) ? -1 : 1;
	switch (a->ipa_type) {
	case IPADDR_V4:
		va = ntohl(a->ipaddr_v4.s_addr);
		vb = ntohl(b->ipaddr_v4.s_addr);
		if (va != vb)
			return (va < vb) ? -1 : 1;
		return 0;
	case IPADDR_V6:
		return memcmp((void *)&a->ipaddr_v6, (void *)&b->ipaddr_v6,
			      sizeof(a->ipaddr_v6));
	case IPADDR_NONE:
		return 0;
	}

	assert(!"Reached end of function we should never hit");
}

static inline bool ipaddr_is_zero(const struct ipaddr *ip)
{
	switch (ip->ipa_type) {
	case IPADDR_NONE:
		return true;
	case IPADDR_V4:
		return ip->ipaddr_v4.s_addr == INADDR_ANY;
	case IPADDR_V6:
		return IN6_IS_ADDR_UNSPECIFIED(&ip->ipaddr_v6);
	}
	return true;
}

static inline bool ipaddr_is_same(const struct ipaddr *ip1,
				  const struct ipaddr *ip2)
{
	return ipaddr_cmp(ip1, ip2) == 0;
}

/* clang-format off */
#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pIA"  (struct ipaddr *)
#endif
/* clang-format on */

#ifdef __cplusplus
}
#endif

#endif /* __IPADDR_H__ */
