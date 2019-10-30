/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_PREFIX_H
#define _ZEBRA_PREFIX_H

#ifdef SUNOS_5
#include <sys/ethernet.h>
#else
#ifdef GNU_LINUX
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
#endif
#endif
#include "sockunion.h"
#include "ipaddr.h"
#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ESI_BYTES 10
#define ESI_STR_LEN (3 * ESI_BYTES)

#define ETHER_ADDR_STRLEN (3*ETH_ALEN)
/*
 * there isn't a portable ethernet address type. We define our
 * own to simplify internal handling
 */
struct ethaddr {
	uint8_t octet[ETH_ALEN];
} __attribute__((packed));


/* length is the number of valuable bits of prefix structure
* 18 bytes is current length in structure, if address is ipv4
* 30 bytes is in case of ipv6
*/
#define PREFIX_LEN_ROUTE_TYPE_5_IPV4 (18*8)
#define PREFIX_LEN_ROUTE_TYPE_5_IPV6 (30*8)

typedef struct esi_t_ {
	uint8_t val[10];
} esi_t;

struct evpn_ead_addr {
	esi_t esi;
	uint32_t eth_tag;
};

struct evpn_macip_addr {
	uint32_t eth_tag;
	uint8_t ip_prefix_length;
	struct ethaddr mac;
	struct ipaddr ip;
};

struct evpn_imet_addr {
	uint32_t eth_tag;
	uint8_t ip_prefix_length;
	struct ipaddr ip;
};

struct evpn_es_addr {
	esi_t esi;
	uint8_t ip_prefix_length;
	struct ipaddr ip;
};

struct evpn_prefix_addr {
	uint32_t eth_tag;
	uint8_t ip_prefix_length;
	struct ipaddr ip;
};

/* EVPN address (RFC 7432) */
struct evpn_addr {
	uint8_t route_type;
	union {
		struct evpn_ead_addr _ead_addr;
		struct evpn_macip_addr _macip_addr;
		struct evpn_imet_addr _imet_addr;
		struct evpn_es_addr _es_addr;
		struct evpn_prefix_addr _prefix_addr;
	} u;
#define ead_addr u._ead_addr
#define macip_addr u._macip_addr
#define imet_addr u._imet_addr
#define es_addr u._es_addr
#define prefix_addr u._prefix_addr
};

/*
 * A struct prefix contains an address family, a prefix length, and an
 * address.  This can represent either a 'network prefix' as defined
 * by CIDR, where the 'host bits' of the prefix are 0
 * (e.g. AF_INET:10.0.0.0/8), or an address and netmask
 * (e.g. AF_INET:10.0.0.9/8), such as might be configured on an
 * interface.
 */

/* different OSes use different names */
#if defined(AF_PACKET)
#define AF_ETHERNET AF_PACKET
#else
#if defined(AF_LINK)
#define AF_ETHERNET AF_LINK
#endif
#endif

/* The 'family' in the prefix structure is internal to FRR and need not
 * map to standard OS AF_ definitions except where needed for interacting
 * with the kernel. However, AF_ definitions are currently in use and
 * prevalent across the code. Define a new FRR-specific AF for EVPN to
 * distinguish between 'ethernet' (MAC-only) and 'evpn' prefixes and
 * ensure it does not conflict with any OS AF_ definition.
 */
#if !defined(AF_EVPN)
#define AF_EVPN (AF_MAX + 1)
#endif

#if !defined(AF_FLOWSPEC)
#define AF_FLOWSPEC (AF_MAX + 2)
#endif

struct flowspec_prefix {
	uint16_t prefixlen; /* length in bytes */
	uintptr_t ptr;
};

/* FRR generic prefix structure. */
struct prefix {
	uint8_t family;
	uint16_t prefixlen;
	union {
		uint8_t prefix;
		struct in_addr prefix4;
		struct in6_addr prefix6;
		struct {
			struct in_addr id;
			struct in_addr adv_router;
		} lp;
		struct ethaddr prefix_eth; /* AF_ETHERNET */
		uint8_t val[16];
		uint32_t val32[4];
		uintptr_t ptr;
		struct evpn_addr prefix_evpn; /* AF_EVPN */
		struct flowspec_prefix prefix_flowspec; /* AF_FLOWSPEC */
	} u __attribute__((aligned(8)));
};

/* IPv4 prefix structure. */
struct prefix_ipv4 {
	uint8_t family;
	uint16_t prefixlen;
	struct in_addr prefix __attribute__((aligned(8)));
};

/* IPv6 prefix structure. */
struct prefix_ipv6 {
	uint8_t family;
	uint16_t prefixlen;
	struct in6_addr prefix __attribute__((aligned(8)));
};

struct prefix_ls {
	uint8_t family;
	uint16_t prefixlen;
	struct in_addr id __attribute__((aligned(8)));
	struct in_addr adv_router;
};

/* Prefix for routing distinguisher. */
struct prefix_rd {
	uint8_t family;
	uint16_t prefixlen;
	uint8_t val[8] __attribute__((aligned(8)));
};

/* Prefix for ethernet. */
struct prefix_eth {
	uint8_t family;
	uint16_t prefixlen;
	struct ethaddr eth_addr __attribute__((aligned(8))); /* AF_ETHERNET */
};

/* EVPN prefix structure. */
struct prefix_evpn {
	uint8_t family;
	uint16_t prefixlen;
	struct evpn_addr prefix __attribute__((aligned(8)));
};

static inline int is_evpn_prefix_ipaddr_none(const struct prefix_evpn *evp)
{
	if (evp->prefix.route_type == 2)
		return IS_IPADDR_NONE(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == 3)
		return IS_IPADDR_NONE(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == 4)
		return IS_IPADDR_NONE(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == 5)
		return IS_IPADDR_NONE(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

static inline int is_evpn_prefix_ipaddr_v4(const struct prefix_evpn *evp)
{
	if (evp->prefix.route_type == 2)
		return IS_IPADDR_V4(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == 3)
		return IS_IPADDR_V4(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == 4)
		return IS_IPADDR_V4(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == 5)
		return IS_IPADDR_V4(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

static inline int is_evpn_prefix_ipaddr_v6(const struct prefix_evpn *evp)
{
	if (evp->prefix.route_type == 2)
		return IS_IPADDR_V6(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == 3)
		return IS_IPADDR_V6(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == 4)
		return IS_IPADDR_V6(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == 5)
		return IS_IPADDR_V6(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

/* Prefix for a generic pointer */
struct prefix_ptr {
	uint8_t family;
	uint16_t prefixlen;
	uintptr_t prefix __attribute__((aligned(8)));
};

/* Prefix for a Flowspec entry */
struct prefix_fs {
	uint8_t family;
	uint16_t prefixlen; /* unused */
	struct flowspec_prefix  prefix __attribute__((aligned(8)));
};

struct prefix_sg {
	uint8_t family;
	uint16_t prefixlen;
	struct in_addr src __attribute__((aligned(8)));
	struct in_addr grp;
};

/* helper to get type safety/avoid casts on calls
 * (w/o this, functions accepting all prefix types need casts on the caller
 * side, which strips type safety since the cast will accept any pointer
 * type.)
 */
#ifndef __cplusplus
#define prefixtype(uname, typename, fieldname) \
	typename *fieldname;
#else
#define prefixtype(uname, typename, fieldname) \
	typename *fieldname; \
	uname(typename *x) { this->fieldname = x; }
#endif

union prefixptr {
	prefixtype(prefixptr, struct prefix,      p)
	prefixtype(prefixptr, struct prefix_ipv4, p4)
	prefixtype(prefixptr, struct prefix_ipv6, p6)
	prefixtype(prefixptr, struct prefix_evpn, evp)
	prefixtype(prefixptr, struct prefix_fs,   fs)
} __attribute__((transparent_union));

union prefixconstptr {
	prefixtype(prefixconstptr, const struct prefix,      p)
	prefixtype(prefixconstptr, const struct prefix_ipv4, p4)
	prefixtype(prefixconstptr, const struct prefix_ipv6, p6)
	prefixtype(prefixconstptr, const struct prefix_evpn, evp)
	prefixtype(prefixconstptr, const struct prefix_fs,   fs)
} __attribute__((transparent_union));

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#ifndef INET6_ADDRSTRLEN
/* dead:beef:dead:beef:dead:beef:dead:beef + \0 */
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

#ifndef INET6_BUFSIZ
#define INET6_BUFSIZ 53
#endif /* INET6_BUFSIZ */

/* Maximum string length of the result of prefix2str */
#define PREFIX_STRLEN 80

/*
 * Longest possible length of a (S,G) string is 36 bytes
 * 123.123.123.123 = 15 * 2
 * (,) = 3
 * NULL Character at end = 1
 * (123.123.123.123,123.123.123.123)
 */
#define PREFIX_SG_STR_LEN 34

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
#define IPV4_MAX_PREFIXLEN 32
#define IPV4_ADDR_CMP(D,S)   memcmp ((D), (S), IPV4_MAX_BYTELEN)

static inline bool ipv4_addr_same(const struct in_addr *a,
				  const struct in_addr *b)
{
	return (a->s_addr == b->s_addr);
}
#define IPV4_ADDR_SAME(A,B)  ipv4_addr_same((A), (B))

static inline void ipv4_addr_copy(struct in_addr *dst,
				  const struct in_addr *src)
{
	dst->s_addr = src->s_addr;
}
#define IPV4_ADDR_COPY(D,S)  ipv4_addr_copy((D), (S))

#define IPV4_NET0(a) ((((uint32_t)(a)) & 0xff000000) == 0x00000000)
#define IPV4_NET127(a) ((((uint32_t)(a)) & 0xff000000) == 0x7f000000)
#define IPV4_LINKLOCAL(a) ((((uint32_t)(a)) & 0xffff0000) == 0xa9fe0000)
#define IPV4_CLASS_DE(a) ((((uint32_t)(a)) & 0xe0000000) == 0xe0000000)
#define IPV4_MC_LINKLOCAL(a) ((((uint32_t)(a)) & 0xffffff00) == 0xe0000000)

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
#define IPV6_MAX_PREFIXLEN 128
#define IPV6_ADDR_CMP(D,S)   memcmp ((D), (S), IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)  memcpy ((D), (S), IPV6_MAX_BYTELEN)

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

#define BSIZE(a) ((a) * (8))

/* Prefix's family member. */
#define PREFIX_FAMILY(p)  ((p)->family)

/* glibc defines s6_addr32 to __in6_u.__u6_addr32 if __USE_{MISC || GNU} */
#ifndef s6_addr32
#if defined(SUNOS_5)
/* Some SunOS define s6_addr32 only to kernel */
#define s6_addr32 _S6_un._S6_u32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif /* SUNOS_5 */
#endif /*s6_addr32*/

/* Prototypes. */
extern int str2family(const char *);
extern int afi2family(afi_t);
extern afi_t family2afi(int);
extern const char *family2str(int family);
extern const char *safi2str(safi_t safi);
extern const char *afi2str(afi_t afi);

/* Check bit of the prefix. */
extern unsigned int prefix_bit(const uint8_t *prefix, const uint16_t prefixlen);
extern unsigned int prefix6_bit(const struct in6_addr *prefix,
				const uint16_t prefixlen);

extern struct prefix *prefix_new(void);
extern void prefix_free(struct prefix **p);
/*
 * Function to handle prefix_free being used as a del function.
 */
extern void prefix_free_lists(void *arg);
extern const char *prefix_family_str(const struct prefix *);
extern int prefix_blen(const struct prefix *);
extern int str2prefix(const char *, struct prefix *);

#define PREFIX2STR_BUFFER  PREFIX_STRLEN

extern void prefix_mcast_inet4_dump(const char *onfail, struct in_addr addr,
				char *buf, int buf_size);
extern const char *prefix_sg2str(const struct prefix_sg *sg, char *str);
extern const char *prefix2str(union prefixconstptr, char *, int);
extern int evpn_type5_prefix_match(const struct prefix *evpn_pfx,
				   const struct prefix *match_pfx);
extern int prefix_match(const struct prefix *, const struct prefix *);
extern int prefix_match_network_statement(const struct prefix *,
					  const struct prefix *);
extern int prefix_same(union prefixconstptr, union prefixconstptr);
extern int prefix_cmp(union prefixconstptr, union prefixconstptr);
extern int prefix_common_bits(const struct prefix *, const struct prefix *);
extern void prefix_copy(union prefixptr, union prefixconstptr);
extern void apply_mask(struct prefix *);

#ifdef __clang_analyzer__
/* clang-SA doesn't understand transparent unions, making it think that the
 * target of prefix_copy is uninitialized.  So just memset the target.
 * cf. https://bugs.llvm.org/show_bug.cgi?id=42811
 */
#define prefix_copy(a, b) ({ memset(a, 0, sizeof(*a)); prefix_copy(a, b); })
#endif

extern struct prefix *sockunion2prefix(const union sockunion *dest,
				       const union sockunion *mask);
extern struct prefix *sockunion2hostprefix(const union sockunion *,
					   struct prefix *p);
extern void prefix2sockunion(const struct prefix *, union sockunion *);

extern int str2prefix_eth(const char *, struct prefix_eth *);

extern struct prefix_ipv4 *prefix_ipv4_new(void);
extern void prefix_ipv4_free(struct prefix_ipv4 **p);
extern int str2prefix_ipv4(const char *, struct prefix_ipv4 *);
extern void apply_mask_ipv4(struct prefix_ipv4 *);

#define PREFIX_COPY(DST, SRC)                                                  \
	*((struct prefix *)(DST)) = *((const struct prefix *)(SRC))
#define PREFIX_COPY_IPV4(DST, SRC)                                             \
	*((struct prefix_ipv4 *)(DST)) = *((const struct prefix_ipv4 *)(SRC));

extern int prefix_ipv4_any(const struct prefix_ipv4 *);
extern void apply_classful_mask_ipv4(struct prefix_ipv4 *);

extern uint8_t ip_masklen(struct in_addr);
extern void masklen2ip(const int, struct in_addr *);
/* returns the network portion of the host address */
extern in_addr_t ipv4_network_addr(in_addr_t hostaddr, int masklen);
/* given the address of a host on a network and the network mask length,
 * calculate the broadcast address for that network;
 * special treatment for /31: returns the address of the other host
 * on the network by flipping the host bit */
extern in_addr_t ipv4_broadcast_addr(in_addr_t hostaddr, int masklen);

extern int netmask_str2prefix_str(const char *, const char *, char *);

extern struct prefix_ipv6 *prefix_ipv6_new(void);
extern void prefix_ipv6_free(struct prefix_ipv6 **p);
extern int str2prefix_ipv6(const char *, struct prefix_ipv6 *);
extern void apply_mask_ipv6(struct prefix_ipv6 *);

#define PREFIX_COPY_IPV6(DST, SRC)                                             \
	*((struct prefix_ipv6 *)(DST)) = *((const struct prefix_ipv6 *)(SRC));

extern int ip6_masklen(struct in6_addr);
extern void masklen2ip6(const int, struct in6_addr *);

extern const char *inet6_ntoa(struct in6_addr);

extern int is_zero_mac(const struct ethaddr *mac);
extern int prefix_str2mac(const char *str, struct ethaddr *mac);
extern char *prefix_mac2str(const struct ethaddr *mac, char *buf, int size);

extern unsigned prefix_hash_key(const void *pp);

extern int str_to_esi(const char *str, esi_t *esi);
extern char *esi_to_str(const esi_t *esi, char *buf, int size);
extern void prefix_hexdump(const struct prefix *p);
extern void prefix_evpn_hexdump(const struct prefix_evpn *p);

static inline int ipv6_martian(struct in6_addr *addr)
{
	struct in6_addr localhost_addr;

	inet_pton(AF_INET6, "::1", &localhost_addr);

	if (IPV6_ADDR_SAME(&localhost_addr, addr))
		return 1;

	return 0;
}

extern int macstr2prefix_evpn(const char *str, struct prefix_evpn *p);

/* NOTE: This routine expects the address argument in network byte order. */
static inline int ipv4_martian(struct in_addr *addr)
{
	in_addr_t ip = ntohl(addr->s_addr);

	if (IPV4_NET0(ip) || IPV4_NET127(ip) || IPV4_CLASS_DE(ip)) {
		return 1;
	}
	return 0;
}

static inline int is_default_prefix(const struct prefix *p)
{
	if (!p)
		return 0;

	if ((p->family == AF_INET) && (p->u.prefix4.s_addr == INADDR_ANY)
	    && (p->prefixlen == 0))
		return 1;

	if ((p->family == AF_INET6) && (p->prefixlen == 0)
	    && (!memcmp(&p->u.prefix6, &in6addr_any, sizeof(struct in6_addr))))
		return 1;

	return 0;
}

static inline int is_host_route(struct prefix *p)
{
	if (p->family == AF_INET)
		return (p->prefixlen == IPV4_MAX_BITLEN);
	else if (p->family == AF_INET6)
		return (p->prefixlen == IPV6_MAX_BITLEN);
	return 0;
}

static inline int is_default_host_route(struct prefix *p)
{
	if (p->family == AF_INET) {
		return (p->u.prefix4.s_addr == INADDR_ANY &&
			p->prefixlen == IPV4_MAX_BITLEN);
	} else if (p->family == AF_INET6) {
		return ((!memcmp(&p->u.prefix6, &in6addr_any,
				 sizeof(struct in6_addr))) &&
			p->prefixlen == IPV6_MAX_BITLEN);
	}
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PREFIX_H */
