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

#ifdef SUNOS_5
#define _XPG4_2
typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;
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
#ifdef GNU_LINUX
#include <linux/types.h>
#endif
#include <sys/sysctl.h>
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
#   ifdef HAVE_LIBCRYPTO
#      include <openssl/des.h>
#      define crypt DES_crypt
#   endif
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
#ifndef INT8_MAX
#define INT8_MAX	(127)
#endif
#ifndef INT16_MAX
#define INT16_MAX	(32767)
#endif
#ifndef INT32_MAX
#define INT32_MAX	(2147483647)
#endif
#ifndef UINT8_MAX
#define UINT8_MAX	(255U)
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

#ifndef HAVE_STRLCAT
size_t strlcat(char *__restrict dest, const char *__restrict src, size_t size);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *__restrict dest, const char *__restrict src, size_t size);
#endif

#ifdef HAVE_BROKEN_CMSG_FIRSTHDR
/* This bug is present in Solaris 8 and pre-patch Solaris 9 <sys/socket.h>;
   please refer to http://bugzilla.quagga.net/show_bug.cgi?id=142 */

/* Check that msg_controllen is large enough. */
#define ZCMSG_FIRSTHDR(mhdr)                                                   \
	(((size_t)((mhdr)->msg_controllen) >= sizeof(struct cmsghdr))          \
		 ? CMSG_FIRSTHDR(mhdr)                                         \
		 : (struct cmsghdr *)NULL)

#warning "CMSG_FIRSTHDR is broken on this platform, using a workaround"

#else  /* HAVE_BROKEN_CMSG_FIRSTHDR */
#define ZCMSG_FIRSTHDR(M) CMSG_FIRSTHDR(M)
#endif /* HAVE_BROKEN_CMSG_FIRSTHDR */


/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

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

/* MAX / MIN are not commonly defined, but useful */
/* note: glibc sys/param.h has #define MIN(a,b) (((a)<(b))?(a):(b)) */
#ifdef MAX
#undef MAX
#endif
#define MAX(a, b)                                                              \
	({                                                                     \
		typeof(a) _a = (a);                                            \
		typeof(b) _b = (b);                                            \
		_a > _b ? _a : _b;                                             \
	})
#ifdef MIN
#undef MIN
#endif
#define MIN(a, b)                                                              \
	({                                                                     \
		typeof(a) _a = (a);                                            \
		typeof(b) _b = (b);                                            \
		_a < _b ? _a : _b;                                             \
	})

#define ZEBRA_NUM_OF(x) (sizeof (x) / sizeof (x[0]))

/* For old definition. */
#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL IN6_IS_ADDR_EQUAL
#endif /* IN6_ARE_ADDR_EQUAL */

/* default zebra TCP port for zclient */
#define ZEBRA_PORT			2600

/* Marker value used in new Zserv, in the byte location corresponding
 * the command value in the old zserv header. To allow old and new
 * Zserv headers to be distinguished from each other.
 */
#define ZEBRA_HEADER_MARKER              254

/* Zebra route's types are defined in route_types.h */
#include "route_types.h"

/* Note: whenever a new route-type or zserv-command is added the
 * corresponding {command,route}_types[] table in lib/log.c MUST be
 * updated! */

/* Map a route type to a string.  For example, ZEBRA_ROUTE_RIPNG -> "ripng". */
extern const char *zebra_route_string(unsigned int route_type);
/* Map a route type to a char.  For example, ZEBRA_ROUTE_RIPNG -> 'R'. */
extern char zebra_route_char(unsigned int route_type);
/* Map a zserv command type to the same string,
 * e.g. ZEBRA_INTERFACE_ADD -> "ZEBRA_INTERFACE_ADD" */
/* Map a protocol name to its number. e.g. ZEBRA_ROUTE_BGP->9*/
extern int proto_name2num(const char *s);
/* Map redistribute X argument to protocol number.
 * unlike proto_name2num, this accepts shorthands and takes
 * an AFI value to restrict input */
extern int proto_redistnum(int afi, const char *s);

extern const char *zserv_command_string(unsigned int command);

#define strmatch(a,b) (!strcmp((a), (b)))

/* Zebra message flags */
#define ZEBRA_FLAG_INTERNAL           0x01
#define ZEBRA_FLAG_SELFROUTE          0x02
#define ZEBRA_FLAG_IBGP               0x08
#define ZEBRA_FLAG_SELECTED           0x10
#define ZEBRA_FLAG_STATIC             0x40
#define ZEBRA_FLAG_SCOPE_LINK         0x100
#define ZEBRA_FLAG_FIB_OVERRIDE       0x200
#define ZEBRA_FLAG_EVPN_ROUTE         0x400
/* ZEBRA_FLAG_BLACKHOLE was 0x04 */
/* ZEBRA_FLAG_REJECT was 0x80 */

/* Zebra FEC flags. */
#define ZEBRA_FEC_REGISTER_LABEL_INDEX        0x1

#ifndef INADDR_LOOPBACK
#define	INADDR_LOOPBACK	0x7f000001	/* Internet address 127.0.0.1.  */
#endif

/* Address family numbers from RFC1700. */
typedef enum { AFI_IP = 1, AFI_IP6 = 2, AFI_L2VPN = 3, AFI_MAX = 4 } afi_t;

/* Subsequent Address Family Identifier. */
typedef enum {
	SAFI_UNICAST = 1,
	SAFI_MULTICAST = 2,
	SAFI_MPLS_VPN = 3,
	SAFI_ENCAP = 4,
	SAFI_EVPN = 5,
	SAFI_LABELED_UNICAST = 6,
	SAFI_MAX = 7
} safi_t;

/*
 * The above AFI and SAFI definitions are for internal use. The protocol
 * definitions (IANA values) as for example used in BGP protocol packets
 * are defined below and these will get mapped to/from the internal values
 * in the appropriate places.
 * The rationale is that the protocol (IANA) values may be sparse and are
 * not optimal for use in data-structure sizing.
 * Note: Only useful (i.e., supported) values are defined below.
 */
typedef enum {
	IANA_AFI_RESERVED = 0,
	IANA_AFI_IPV4 = 1,
	IANA_AFI_IPV6 = 2,
	IANA_AFI_L2VPN = 25,
	IANA_AFI_IPMR = 128,
	IANA_AFI_IP6MR = 129
} iana_afi_t;

typedef enum {
	IANA_SAFI_RESERVED = 0,
	IANA_SAFI_UNICAST = 1,
	IANA_SAFI_MULTICAST = 2,
	IANA_SAFI_LABELED_UNICAST = 4,
	IANA_SAFI_ENCAP = 7,
	IANA_SAFI_EVPN = 70,
	IANA_SAFI_MPLS_VPN = 128
} iana_safi_t;

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

/* Zebra types. Used in Zserv message header. */
typedef u_int16_t zebra_size_t;
typedef u_int16_t zebra_command_t;

/* VRF ID type. */
typedef uint32_t vrf_id_t;

typedef uint32_t route_tag_t;
#define ROUTE_TAG_MAX UINT32_MAX
#define ROUTE_TAG_PRI PRIu32

static inline afi_t afi_iana2int(iana_afi_t afi)
{
	switch (afi) {
	case IANA_AFI_IPV4:
		return AFI_IP;
	case IANA_AFI_IPV6:
		return AFI_IP6;
	case IANA_AFI_L2VPN:
		return AFI_L2VPN;
	default:
		return AFI_MAX;
	}
}

static inline iana_afi_t afi_int2iana(afi_t afi)
{
	switch (afi) {
	case AFI_IP:
		return IANA_AFI_IPV4;
	case AFI_IP6:
		return IANA_AFI_IPV6;
	case AFI_L2VPN:
		return IANA_AFI_L2VPN;
	default:
		return IANA_AFI_RESERVED;
	}
}

static inline safi_t safi_iana2int(iana_safi_t safi)
{
	switch (safi) {
	case IANA_SAFI_UNICAST:
		return SAFI_UNICAST;
	case IANA_SAFI_MULTICAST:
		return SAFI_MULTICAST;
	case IANA_SAFI_MPLS_VPN:
		return SAFI_MPLS_VPN;
	case IANA_SAFI_ENCAP:
		return SAFI_ENCAP;
	case IANA_SAFI_EVPN:
		return SAFI_EVPN;
	case IANA_SAFI_LABELED_UNICAST:
		return SAFI_LABELED_UNICAST;
	default:
		return SAFI_MAX;
	}
}

static inline iana_safi_t safi_int2iana(safi_t safi)
{
	switch (safi) {
	case SAFI_UNICAST:
		return IANA_SAFI_UNICAST;
	case SAFI_MULTICAST:
		return IANA_SAFI_MULTICAST;
	case SAFI_MPLS_VPN:
		return IANA_SAFI_MPLS_VPN;
	case SAFI_ENCAP:
		return IANA_SAFI_ENCAP;
	case SAFI_EVPN:
		return IANA_SAFI_EVPN;
	case SAFI_LABELED_UNICAST:
		return IANA_SAFI_LABELED_UNICAST;
	default:
		return IANA_SAFI_RESERVED;
	}
}

#endif /* _ZEBRA_H */
