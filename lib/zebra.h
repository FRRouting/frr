/* Zebra common header.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002 Kunihiro Ishiguro
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

#ifndef _ZEBRA_H
#define _ZEBRA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "compiler.h"

#ifdef SUNOS_5
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
#endif /* SUNOS_5 */

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
#ifndef GNU_LINUX
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

/* machine dependent includes */
#ifdef SUNOS_5
#include <strings.h>
#endif /* SUNOS_5 */

/* machine dependent includes */
#ifdef HAVE_LINUX_VERSION_H
#include <linux/version.h>
#endif /* HAVE_LINUX_VERSION_H */

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif /* HAVE_ASM_TYPES_H */

/* misc include group */
#include <stdarg.h>
#if !(defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
/* Not C99; do we need to define va_copy? */
#ifndef va_copy
#ifdef __va_copy
#define va_copy(DST,SRC) __va_copy(DST,SRC)
#else
/* Now we are desperate; this should work on many typical platforms.
   But this is slightly dangerous, because the standard does not require
   va_copy to be a macro. */
#define va_copy(DST,SRC) memcpy(&(DST), &(SRC), sizeof(va_list))
#warning "Not C99 and no va_copy macro available, falling back to memcpy"
#endif /* __va_copy */
#endif /* !va_copy */
#endif /* !C99 */


#ifdef HAVE_LCAPS
#include <sys/capability.h>
#include <sys/prctl.h>
#endif /* HAVE_LCAPS */

#ifdef HAVE_SOLARIS_CAPABILITIES
#include <priv.h>
#endif /* HAVE_SOLARIS_CAPABILITIES */

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
#if !(defined(__GNUC__) || defined(VTYSH_EXTRACT_PL))
#define __attribute__(x)
#endif /* !__GNUC__ || VTYSH_EXTRACT_PL */

#include "zassert.h"

/*
 * Add explicit static cast only when using a C++ compiler.
 */
#ifdef __cplusplus
#define static_cast(l, r) static_cast<decltype(l)>((r))
#else
#define static_cast(l, r) (r)
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
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
	|| (defined(__APPLE__))                                                \
	|| (defined(SUNOS_5) && defined(WORDS_BIGENDIAN))
#define HAVE_IP_HDRINCL_BSD_ORDER
#endif

/* Define BYTE_ORDER, if not defined. Useful for compiler conditional
 * code, rather than preprocessor conditional.
 * Not all the world has this BSD define.
 */
#ifndef BYTE_ORDER
#define BIG_ENDIAN	4321	/* least-significant byte first (vax, pc) */
#define LITTLE_ENDIAN	1234	/* most-significant byte first (IBM, net) */
#define PDP_ENDIAN	3412	/* LSB first in word, MSW first in long (pdp) */

#if defined(WORDS_BIGENDIAN)
#define BYTE_ORDER	BIG_ENDIAN
#else  /* !WORDS_BIGENDIAN */
#define BYTE_ORDER	LITTLE_ENDIAN
#endif /* WORDS_BIGENDIAN */

#endif /* ndef BYTE_ORDER */

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
#include "route_types.h"

#define strmatch(a,b) (!strcmp((a), (b)))

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

/* Default Administrative Distance of each protocol. */
#define ZEBRA_KERNEL_DISTANCE_DEFAULT      0
#define ZEBRA_CONNECT_DISTANCE_DEFAULT     0
#define ZEBRA_STATIC_DISTANCE_DEFAULT      1
#define ZEBRA_RIP_DISTANCE_DEFAULT       120
#define ZEBRA_RIPNG_DISTANCE_DEFAULT     120
#define ZEBRA_OSPF_DISTANCE_DEFAULT      110
#define ZEBRA_OSPF6_DISTANCE_DEFAULT     110
#define ZEBRA_ISIS_DISTANCE_DEFAULT      115
#define ZEBRA_IBGP_DISTANCE_DEFAULT      200
#define ZEBRA_EBGP_DISTANCE_DEFAULT       20
#define ZEBRA_TABLE_DISTANCE_DEFAULT      15

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

#endif /* _ZEBRA_H */
