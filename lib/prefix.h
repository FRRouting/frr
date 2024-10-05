// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Prefix structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_PREFIX_H
#define _ZEBRA_PREFIX_H

#ifdef GNU_LINUX
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
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

/* EVPN route types. */
typedef enum {
	BGP_EVPN_AD_ROUTE = 1,    /* Ethernet Auto-Discovery (A-D) route */
	BGP_EVPN_MAC_IP_ROUTE,    /* MAC/IP Advertisement route */
	BGP_EVPN_IMET_ROUTE,      /* Inclusive Multicast Ethernet Tag route */
	BGP_EVPN_ES_ROUTE,        /* Ethernet Segment route */
	BGP_EVPN_IP_PREFIX_ROUTE, /* IP Prefix route */
} bgp_evpn_route_type;

/* value of first byte of ESI */
#define ESI_TYPE_ARBITRARY 0  /* */
#define ESI_TYPE_LACP      1  /* <> */
#define ESI_TYPE_BRIDGE    2  /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ESI_TYPE_MAC       3  /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ESI_TYPE_ROUTER    4  /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ESI_TYPE_AS        5  /* <AS-4B>:<Local Discriminator Value-4B> */

#define MAX_ESI {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}


#define EVPN_ETH_TAG_BYTES 4
#define ESI_BYTES 10
#define ESI_STR_LEN (3 * ESI_BYTES)
#define EVPN_DF_ALG_STR_LEN 24

/* Maximum number of VTEPs per-ES -
 * XXX - temporary limit for allocating strings etc.
 */
#define ES_VTEP_MAX_CNT	    10
#define ES_VTEP_LIST_STR_SZ (ES_VTEP_MAX_CNT * IPADDR_STRING_SIZE)

#define ETHER_ADDR_STRLEN (3 * ETH_ALEN)
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
	uint8_t val[ESI_BYTES];
} esi_t;

struct evpn_ead_addr {
	esi_t esi;
	uint32_t eth_tag;
	struct ipaddr ip;
	uint16_t frag_id;
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
	uint8_t family;
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
	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
		return IS_IPADDR_NONE(&(evp)->prefix.ead_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		return IS_IPADDR_NONE(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IMET_ROUTE)
		return IS_IPADDR_NONE(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE)
		return IS_IPADDR_NONE(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		return IS_IPADDR_NONE(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

static inline int is_evpn_prefix_ipaddr_v4(const struct prefix_evpn *evp)
{
	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
		return IS_IPADDR_V4(&(evp)->prefix.ead_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		return IS_IPADDR_V4(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IMET_ROUTE)
		return IS_IPADDR_V4(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE)
		return IS_IPADDR_V4(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		return IS_IPADDR_V4(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

static inline int is_evpn_prefix_ipaddr_v6(const struct prefix_evpn *evp)
{
	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
		return IS_IPADDR_V6(&(evp)->prefix.ead_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		return IS_IPADDR_V6(&(evp)->prefix.macip_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IMET_ROUTE)
		return IS_IPADDR_V6(&(evp)->prefix.imet_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE)
		return IS_IPADDR_V6(&(evp)->prefix.es_addr.ip);
	if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		return IS_IPADDR_V6(&(evp)->prefix.prefix_addr.ip);
	return 0;
}

/* Prefix for a Flowspec entry */
struct prefix_fs {
	uint8_t family;
	uint16_t prefixlen; /* unused */
	struct flowspec_prefix  prefix __attribute__((aligned(8)));
};

struct prefix_sg {
	uint8_t family;
	uint16_t prefixlen;
	struct ipaddr src __attribute__((aligned(8)));
	struct in_addr grp;
};

/* clang-format off */
union prefixptr {
	uniontype(prefixptr, struct prefix,      p)
	uniontype(prefixptr, struct prefix_ipv4, p4)
	uniontype(prefixptr, struct prefix_ipv6, p6)
	uniontype(prefixptr, struct prefix_evpn, evp)
	uniontype(prefixptr, struct prefix_fs,   fs)
	uniontype(prefixptr, struct prefix_rd,   rd)
} TRANSPARENT_UNION;

union prefixconstptr {
	uniontype(prefixconstptr, const struct prefix,      p)
	uniontype(prefixconstptr, const struct prefix_ipv4, p4)
	uniontype(prefixconstptr, const struct prefix_ipv6, p6)
	uniontype(prefixconstptr, const struct prefix_evpn, evp)
	uniontype(prefixconstptr, const struct prefix_fs,   fs)
	uniontype(prefixconstptr, const struct prefix_rd,   rd)
} TRANSPARENT_UNION;
/* clang-format on */

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
 * Longest possible length of a (S,G) string is 34 bytes
 * 123.123.123.123 = 15 * 2
 * (,) = 3
 * NULL Character at end = 1
 * (123.123.123.123,123.123.123.123)
 */
#define PREFIX_SG_STR_LEN 34

/* Max bit/byte length of IPv4 address. */
#define IPV4_MAX_BYTELEN    4
#define IPV4_MAX_BITLEN    32
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
#define IPV4_CLASS_D(a) ((((uint32_t)(a)) & 0xf0000000) == 0xe0000000)
#define IPV4_CLASS_E(a) ((((uint32_t)(a)) & 0xf0000000) == 0xf0000000)
#define IPV4_CLASS_DE(a) ((((uint32_t)(a)) & 0xe0000000) == 0xe0000000)
#define IPV4_MC_LINKLOCAL(a) ((((uint32_t)(a)) & 0xffffff00) == 0xe0000000)

/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN    16
#define IPV6_MAX_BITLEN    128
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
#define s6_addr32 __u6_addr.__u6_addr32
#endif /*s6_addr32*/

/* Prototypes. */
extern int str2family(const char *string);
extern int afi2family(afi_t afi);
extern afi_t family2afi(int family);
extern const char *family2str(int family);
extern const char *safi2str(safi_t safi);
extern const char *afi2str(afi_t afi);
extern const char *afi2str_lower(afi_t afi);

static inline afi_t prefix_afi(union prefixconstptr pu)
{
	return family2afi(pu.p->family);
}

/*
 * Check bit of the prefix.
 *
 * prefix
 *    byte buffer
 *
 * bit_index
 *    which bit to fetch from byte buffer, 0 indexed.
 */
extern unsigned int prefix_bit(const uint8_t *prefix, const uint16_t bit_index);

extern struct prefix *prefix_new(void);
extern void prefix_free(struct prefix **p);
/*
 * Function to handle prefix_free being used as a del function.
 */
extern void prefix_free_lists(void *arg);
extern const char *prefix_family_str(union prefixconstptr pu);
extern int prefix_blen(union prefixconstptr pu);
extern int str2prefix(const char *string, struct prefix *prefix);

#define PREFIX2STR_BUFFER  PREFIX_STRLEN

extern void prefix_mcast_ip_dump(const char *onfail, const struct ipaddr *addr,
				 char *buf, int buf_size);
extern void prefix_mcast_inet4_dump(const char *onfail, struct in_addr addr,
				char *buf, int buf_size);
extern const char *prefix_sg2str(const struct prefix_sg *sg, char *str);
extern const char *prefix2str(union prefixconstptr upfx, char *buffer,
			      int size);
extern int evpn_type5_prefix_match(const struct prefix *evpn_pfx,
				   const struct prefix *match_pfx);
extern int prefix_match(union prefixconstptr unet, union prefixconstptr upfx);
extern int prefix_match_network_statement(union prefixconstptr unet,
					  union prefixconstptr upfx);
extern int prefix_same(union prefixconstptr ua, union prefixconstptr ub);
extern int prefix_cmp(union prefixconstptr ua, union prefixconstptr ub);
extern int prefix_common_bits(union prefixconstptr ua, union prefixconstptr ub);
extern void prefix_copy(union prefixptr udst, union prefixconstptr usrc);
extern void apply_mask(union prefixptr pu);
extern bool evpn_addr_same(const struct evpn_addr *e1, const struct evpn_addr *e2);

#ifdef __clang_analyzer__
/* clang-SA doesn't understand transparent unions, making it think that the
 * target of prefix_copy is uninitialized.  So just memset the target.
 * cf. https://bugs.llvm.org/show_bug.cgi?id=42811
 */
#define prefix_copy(a, b) ({ memset(a, 0, sizeof(*a)); prefix_copy(a, b); })
#endif

extern struct prefix *sockunion2hostprefix(const union sockunion *su,
					   struct prefix *p);
extern void prefix2sockunion(const struct prefix *p, union sockunion *su);

extern int str2prefix_eth(const char *string, struct prefix_eth *p);

extern struct prefix_ipv4 *prefix_ipv4_new(void);
extern void prefix_ipv4_free(struct prefix_ipv4 **p);
extern int str2prefix_ipv4(const char *string, struct prefix_ipv4 *p);
extern void apply_mask_ipv4(struct prefix_ipv4 *p);

extern int prefix_ipv4_any(const struct prefix_ipv4 *p);
extern void apply_classful_mask_ipv4(struct prefix_ipv4 *p);

extern uint8_t ip_masklen(struct in_addr addr);
extern void masklen2ip(const int length, struct in_addr *addr);
/* given the address of a host on a network and the network mask length,
 * calculate the broadcast address for that network;
 * special treatment for /31 according to RFC3021 section 3.3 */
extern in_addr_t ipv4_broadcast_addr(in_addr_t hostaddr, int masklen);

extern int netmask_str2prefix_str(const char *net_str, const char *mask_str,
				  char *prefix_str, size_t prefix_str_len);

extern struct prefix_ipv6 *prefix_ipv6_new(void);
extern void prefix_ipv6_free(struct prefix_ipv6 **p);
extern int str2prefix_ipv6(const char *str, struct prefix_ipv6 *p);
extern void apply_mask_ipv6(struct prefix_ipv6 *p);

extern int ip6_masklen(struct in6_addr netmask);
extern void masklen2ip6(const int masklen, struct in6_addr *netmask);

extern int is_zero_mac(const struct ethaddr *mac);
extern bool is_mcast_mac(const struct ethaddr *mac);
extern bool is_bcast_mac(const struct ethaddr *mac);
extern int prefix_str2mac(const char *str, struct ethaddr *mac);
extern char *prefix_mac2str(const struct ethaddr *mac, char *buf, int size);

extern unsigned prefix_hash_key(const void *pp);

extern int str_to_esi(const char *str, esi_t *esi);
extern char *esi_to_str(const esi_t *esi, char *buf, int size);
extern char *evpn_es_df_alg2str(uint8_t df_alg, char *buf, int buf_len);
extern void prefix_evpn_hexdump(const struct prefix_evpn *p);
extern bool ipv4_unicast_valid(const struct in_addr *addr);
extern int evpn_prefix2prefix(const struct prefix *evpn, struct prefix *to);

static inline int ipv6_martian(const struct in6_addr *addr)
{
	struct in6_addr localhost_addr;

	inet_pton(AF_INET6, "::1", &localhost_addr);

	if (IPV6_ADDR_SAME(&localhost_addr, addr))
		return 1;

	return 0;
}

extern int macstr2prefix_evpn(const char *str, struct prefix_evpn *p);

/* NOTE: This routine expects the address argument in network byte order. */
static inline bool ipv4_martian(const struct in_addr *addr)
{
	if (!ipv4_unicast_valid(addr))
		return true;
	return false;
}

static inline bool is_default_prefix4(const struct prefix_ipv4 *p)
{
	return p && p->family == AF_INET && p->prefixlen == 0
	       && p->prefix.s_addr == INADDR_ANY;
}

static inline bool is_default_prefix6(const struct prefix_ipv6 *p)
{
	return p && p->family == AF_INET6 && p->prefixlen == 0
	       && memcmp(&p->prefix, &in6addr_any, sizeof(struct in6_addr))
			  == 0;
}

static inline bool is_default_prefix(const struct prefix *p)
{
	if (p == NULL)
		return false;

	switch (p->family) {
	case AF_INET:
		return is_default_prefix4((const struct prefix_ipv4 *)p);
	case AF_INET6:
		return is_default_prefix6((const struct prefix_ipv6 *)p);
	}

	return false;
}

static inline int is_host_route(const struct prefix *p)
{
	if (p->family == AF_INET)
		return (p->prefixlen == IPV4_MAX_BITLEN);
	else if (p->family == AF_INET6)
		return (p->prefixlen == IPV6_MAX_BITLEN);
	return 0;
}

static inline int is_default_host_route(const struct prefix *p)
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

static inline bool is_ipv6_global_unicast(const struct in6_addr *p)
{
	if (IN6_IS_ADDR_UNSPECIFIED(p) || IN6_IS_ADDR_LOOPBACK(p) ||
	    IN6_IS_ADDR_LINKLOCAL(p) || IN6_IS_ADDR_MULTICAST(p))
		return false;

	return true;
}

/* IPv6 scope values, usable for IPv4 too (cf. below) */
/* clang-format off */
enum {
	/* 0: reserved */
	MCAST_SCOPE_IFACE  = 0x1,
	MCAST_SCOPE_LINK   = 0x2,
	MCAST_SCOPE_REALM  = 0x3,
	MCAST_SCOPE_ADMIN  = 0x4,
	MCAST_SCOPE_SITE   = 0x5,
	/* 6-7: unassigned */
	MCAST_SCOPE_ORG    = 0x8,
	/* 9-d: unassigned */
	MCAST_SCOPE_GLOBAL = 0xe,
	/* f: reserved */
};
/* clang-format on */

static inline uint8_t ipv6_mcast_scope(const struct in6_addr *addr)
{
	return addr->s6_addr[1] & 0xf;
}

static inline bool ipv6_mcast_nofwd(const struct in6_addr *addr)
{
	return (addr->s6_addr[1] & 0xf) <= MCAST_SCOPE_LINK;
}

static inline bool ipv6_mcast_ssm(const struct in6_addr *addr)
{
	uint32_t bits = ntohl(addr->s6_addr32[0]);

	/* ff3x:0000::/32 */
	return (bits & 0xfff0ffff) == 0xff300000;
}

static inline bool ipv6_mcast_reserved(const struct in6_addr *addr)
{
	uint32_t bits = ntohl(addr->s6_addr32[0]);

	/* ffx2::/16 */
	return (bits & 0xff0fffff) == 0xff020000;
}

static inline uint8_t ipv4_mcast_scope(const struct in_addr *addr)
{
	uint32_t bits = ntohl(addr->s_addr);

	/* 224.0.0.0/24 - link scope */
	if ((bits & 0xffffff00) == 0xe0000000)
		return MCAST_SCOPE_LINK;
	/* 239.0.0.0/8 - org scope */
	if ((bits & 0xff000000) == 0xef000000)
		return MCAST_SCOPE_ORG;

	return MCAST_SCOPE_GLOBAL;
}

static inline bool ipv4_mcast_nofwd(const struct in_addr *addr)
{
	uint32_t bits = ntohl(addr->s_addr);

	/* 224.0.0.0/24 */
	return (bits & 0xffffff00) == 0xe0000000;
}

static inline bool ipv4_mcast_ssm(const struct in_addr *addr)
{
	uint32_t bits = ntohl(addr->s_addr);

	/* 232.0.0.0/8 */
	return (bits & 0xff000000) == 0xe8000000;
}

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pEA"  (struct ethaddr *)

#pragma FRR printfrr_ext "%pI4"  (struct in_addr *)
#pragma FRR printfrr_ext "%pI4"  (in_addr_t *)

#pragma FRR printfrr_ext "%pI6"  (struct in6_addr *)

#pragma FRR printfrr_ext "%pFX"  (struct prefix *)
#pragma FRR printfrr_ext "%pFX"  (struct prefix_ipv4 *)
#pragma FRR printfrr_ext "%pFX"  (struct prefix_ipv6 *)
#pragma FRR printfrr_ext "%pFX"  (struct prefix_eth *)
#pragma FRR printfrr_ext "%pFX"  (struct prefix_evpn *)
#pragma FRR printfrr_ext "%pFX"  (struct prefix_fs *)
#pragma FRR printfrr_ext "%pRDP"  (struct prefix_rd *)
/* RD with AS4B with dot and dot+ format */
#pragma FRR printfrr_ext "%pRDD"  (struct prefix_rd *)
#pragma FRR printfrr_ext "%pRDE"  (struct prefix_rd *)

#pragma FRR printfrr_ext "%pPSG4" (struct prefix_sg *)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PREFIX_H */
