// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra common header.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_H
#define _ZEBRA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "compiler.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif /* HAVE_STROPTS_H */
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_SYS_SYSCTL_H
#ifdef GNU_LINUX
#include <linux/types.h>
#else
#include <sys/sysctl.h>
#endif
#endif /* HAVE_SYS_SYSCTL_H */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif /* HAVE_SYS_CONF_H */
#ifdef HAVE_SYS_KSYM_H
#include <sys/ksym.h>
#endif /* HAVE_SYS_KSYM_H */
#include <syslog.h>
#include <sys/time.h>
#include <time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <limits.h>
#include <inttypes.h>
#include <stdbool.h>
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

/* misc include group */
#include <stdarg.h>

#ifdef HAVE_LCAPS
#include <sys/capability.h>
#include <sys/prctl.h>
#endif /* HAVE_LCAPS */

/* network include group */

#include <sys/socket.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#ifndef HAVE_LIBCRYPT
#ifdef HAVE_LIBCRYPTO
#include <openssl/des.h>
#      define crypt DES_crypt
#endif
#endif

#ifdef CRYPTO_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "openbsd-tree.h"

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifdef HAVE_NET_NETOPT_H
#include <net/netopt.h>
#endif /* HAVE_NET_NETOPT_H */

#include <net/if.h>

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#ifdef HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif /* HAVE_NET_IF_VAR_H */

#include <net/route.h>

#ifdef HAVE_NETLINK
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>
#else
#define RT_TABLE_MAIN		0
#endif /* HAVE_NETLINK */

#include <netdb.h>
#include <arpa/inet.h>

#ifdef HAVE_INET_ND_H
#include <inet/nd.h>
#endif /* HAVE_INET_ND_H */

#ifdef HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif /* HAVE_NETINET_IN_VAR_H */

#ifdef HAVE_NETINET6_IN6_VAR_H
#include <netinet6/in6_var.h>
#endif /* HAVE_NETINET6_IN6_VAR_H */

#ifdef HAVE_NETINET_IN6_VAR_H
#include <netinet/in6_var.h>
#endif /* HAVE_NETINET_IN6_VAR_H */

#ifdef HAVE_NETINET6_IN_H
#include <netinet6/in.h>
#endif /* HAVE_NETINET6_IN_H */


#ifdef HAVE_NETINET6_IP6_H
#include <netinet6/ip6.h>
#endif /* HAVE_NETINET6_IP6_H */

#include <netinet/icmp6.h>

#ifdef HAVE_NETINET6_ND6_H
#include <netinet6/nd6.h>
#endif /* HAVE_NETINET6_ND6_H */

/* Some systems do not define UINT32_MAX, etc.. from inttypes.h
 * e.g. this makes life easier for FBSD 4.11 users.
 */
#ifndef INT16_MAX
#define INT16_MAX	(32767)
#endif
#ifndef INT32_MAX
#define INT32_MAX	(2147483647)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX	(65535U)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX	(4294967295U)
#endif

#ifdef HAVE_GLIBC_BACKTRACE
#include <execinfo.h>
#endif /* HAVE_GLIBC_BACKTRACE */

/* Local includes: */
#if !defined(__GNUC__)
#define __attribute__(x)
#endif /* !__GNUC__ */

#include <assert.h>

/*
 * Add explicit static cast only when using a C++ compiler.
 */
#ifdef __cplusplus
#define static_cast(l, r) static_cast<decltype(l)>((r))
#else
#define static_cast(l, r) (r)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
#endif

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *buf, size_t len);
#endif

#if !defined(HAVE_STRUCT_MMSGHDR_MSG_HDR) || !defined(HAVE_SENDMMSG)
/* avoid conflicts in case we have partial support */
#define mmsghdr frr_mmsghdr
#define sendmmsg frr_sendmmsg

struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int msg_len;
};

/* just go 1 at a time here, the loop this is used in will handle the rest */
static inline int sendmmsg(int fd, struct mmsghdr *mmh, unsigned int len,
			   int flags)
{
	int rv = sendmsg(fd, &mmh->msg_hdr, 0);

	return rv > 0 ? 1 : rv;
}
#endif

/*
 * RFC 3542 defines several macros for using struct cmsghdr.
 * Here, we define those that are not present
 */

/*
 * Internal defines, for use only in this file.
 * These are likely wrong on other than ILP32 machines, so warn.
 */
#ifndef _CMSG_DATA_ALIGN
#define _CMSG_DATA_ALIGN(n)           (((n) + 3) & ~3)
#endif /* _CMSG_DATA_ALIGN */

#ifndef _CMSG_HDR_ALIGN
#define _CMSG_HDR_ALIGN(n)            (((n) + 3) & ~3)
#endif /* _CMSG_HDR_ALIGN */

/*
 * CMSG_SPACE and CMSG_LEN are required in RFC3542, but were new in that
 * version.
 */
#ifndef CMSG_SPACE
#define CMSG_SPACE(l)                                                          \
	(_CMSG_DATA_ALIGN(sizeof(struct cmsghdr)) + _CMSG_HDR_ALIGN(l))
#warning "assuming 4-byte alignment for CMSG_SPACE"
#endif /* CMSG_SPACE */


#ifndef CMSG_LEN
#define CMSG_LEN(l)         (_CMSG_DATA_ALIGN(sizeof(struct cmsghdr)) + (l))
#warning "assuming 4-byte alignment for CMSG_LEN"
#endif /* CMSG_LEN */


/*  The definition of struct in_pktinfo is missing in old version of
    GLIBC 2.1 (Redhat 6.1).  */
#if defined(GNU_LINUX) && !defined(HAVE_STRUCT_IN_PKTINFO)
struct in_pktinfo {
	int ipi_ifindex;
	struct in_addr ipi_spec_dst;
	struct in_addr ipi_addr;
};
#endif

/*
 * IP_HDRINCL / struct ip byte order
 *
 * Linux: network byte order
 * *BSD: network, except for length and offset. (cf Stevens)
 * SunOS: nominally as per BSD. but bug: network order on LE.
 * OpenBSD: network byte order, apart from older versions which are as per
 *          *BSD
 */
#if defined(__NetBSD__)                                                        \
	|| (defined(__FreeBSD__) && (__FreeBSD_version < 1100030))             \
	|| (defined(__OpenBSD__) && (OpenBSD < 200311))                        \
	|| (defined(__APPLE__))
#define HAVE_IP_HDRINCL_BSD_ORDER
#endif

/* autoconf macros for this are deprecated, just find endian.h */
#ifndef BYTE_ORDER
#error please locate an endian.h file appropriate to your platform
#endif

/* For old definition. */
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL IN6_IS_ADDR_EQUAL
#endif /* IN6_ARE_ADDR_EQUAL */

/* default zebra TCP port for zclient */
#define ZEBRA_PORT			2600

/*
 * The compiler.h header is used for anyone using the CPP_NOTICE
 * since this is universally needed, let's add it to zebra.h
 */
#include "compiler.h"

/* Zebra route's types are defined in route_types.h */
#include "lib/route_types.h"

#define strmatch(a,b) (!strcmp((a), (b)))

#if BYTE_ORDER == LITTLE_ENDIAN
#define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif

#ifndef INADDR_LOOPBACK
#define	INADDR_LOOPBACK	0x7f000001	/* Internet address 127.0.0.1.  */
#endif

/* Address family numbers from RFC1700. */
typedef enum {
	AFI_UNSPEC = 0,
	AFI_IP = 1,
	AFI_IP6 = 2,
	AFI_L2VPN = 3,
	AFI_MAX = 4
} afi_t;

#define IS_VALID_AFI(a) ((a) > AFI_UNSPEC && (a) < AFI_MAX)

/* Subsequent Address Family Identifier. */
typedef enum {
	SAFI_UNSPEC = 0,
	SAFI_UNICAST = 1,
	SAFI_MULTICAST = 2,
	SAFI_MPLS_VPN = 3,
	SAFI_ENCAP = 4,
	SAFI_EVPN = 5,
	SAFI_LABELED_UNICAST = 6,
	SAFI_FLOWSPEC = 7,
	SAFI_MAX = 8
} safi_t;

#define FOREACH_AFI_SAFI(afi, safi)                                            \
	for (afi = AFI_IP; afi < AFI_MAX; afi++)                               \
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)

#define FOREACH_AFI_SAFI_NSF(afi, safi)                                        \
	for (afi = AFI_IP; afi < AFI_MAX; afi++)                               \
		for (safi = SAFI_UNICAST; safi <= SAFI_MPLS_VPN; safi++)

/* Default Administrative Distance of each protocol. */
#define ZEBRA_KERNEL_DISTANCE_DEFAULT       0
#define ZEBRA_CONNECT_DISTANCE_DEFAULT      0
#define ZEBRA_STATIC_DISTANCE_DEFAULT       1
#define ZEBRA_RIP_DISTANCE_DEFAULT        120
#define ZEBRA_RIPNG_DISTANCE_DEFAULT      120
#define ZEBRA_OSPF_DISTANCE_DEFAULT       110
#define ZEBRA_OSPF6_DISTANCE_DEFAULT      110
#define ZEBRA_ISIS_DISTANCE_DEFAULT       115
#define ZEBRA_IBGP_DISTANCE_DEFAULT       200
#define ZEBRA_EBGP_DISTANCE_DEFAULT        20
#define ZEBRA_TABLE_DISTANCE_DEFAULT       15
#define ZEBRA_EIGRP_DISTANCE_DEFAULT       90
#define ZEBRA_NHRP_DISTANCE_DEFAULT        10
#define ZEBRA_LDP_DISTANCE_DEFAULT        150
#define ZEBRA_BABEL_DISTANCE_DEFAULT      100
#define ZEBRA_SHARP_DISTANCE_DEFAULT      150
#define ZEBRA_PBR_DISTANCE_DEFAULT        200
#define ZEBRA_OPENFABRIC_DISTANCE_DEFAULT 115
#define ZEBRA_MAX_DISTANCE_DEFAULT        255

/* Flag manipulation macros. */
#define CHECK_FLAG(V,F)      ((V) & (F))
#define SET_FLAG(V,F)        (V) |= (F)
#define UNSET_FLAG(V,F)      (V) &= ~(F)
#define RESET_FLAG(V)        (V) = 0
#define COND_FLAG(V, F, C)   ((C) ? (SET_FLAG(V, F)) : (UNSET_FLAG(V, F)))

/* Atomic flag manipulation macros. */
#define CHECK_FLAG_ATOMIC(PV, F)                                               \
	((atomic_load_explicit(PV, memory_order_seq_cst)) & (F))
#define SET_FLAG_ATOMIC(PV, F)                                                 \
	((atomic_fetch_or_explicit(PV, (F), memory_order_seq_cst)))
#define UNSET_FLAG_ATOMIC(PV, F)                                               \
	((atomic_fetch_and_explicit(PV, ~(F), memory_order_seq_cst)))
#define RESET_FLAG_ATOMIC(PV)                                                  \
	((atomic_store_explicit(PV, 0, memory_order_seq_cst)))

/* VRF ID type. */
typedef uint32_t vrf_id_t;

typedef uint32_t route_tag_t;
#define ROUTE_TAG_MAX UINT32_MAX
#define ROUTE_TAG_PRI PRIu32

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_H */
