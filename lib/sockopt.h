// SPDX-License-Identifier: GPL-2.0-or-later
/* Router advertisement
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_SOCKOPT_H
#define _ZEBRA_SOCKOPT_H

#include "sockunion.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void setsockopt_so_recvbuf(int sock, int size);
extern void setsockopt_so_sendbuf(const int sock, int size);
extern int getsockopt_so_sendbuf(const int sock);
extern int getsockopt_so_recvbuf(const int sock);

extern int setsockopt_ipv6_pktinfo(int, int);
extern int setsockopt_ipv6_multicast_hops(int, int);
extern int setsockopt_ipv6_unicast_hops(int, int);
extern int setsockopt_ipv6_hoplimit(int, int);
extern int setsockopt_ipv6_multicast_loop(int, int);
extern int setsockopt_ipv6_tclass(int, int);

#define SOPT_SIZE_CMSG_PKTINFO_IPV6() (sizeof(struct in6_pktinfo));

/*
 * Size defines for control messages used to get ifindex.  We define
 * values for each method, and define a macro that can be used by code
 * that is unaware of which method is in use.
 * These values are without any alignment needed (see CMSG_SPACE in RFC3542).
 */
#if defined(IP_PKTINFO)
/* Linux in_pktinfo. */
#define SOPT_SIZE_CMSG_PKTINFO_IPV4()  (CMSG_SPACE(sizeof(struct in_pktinfo)))
/* XXX This should perhaps be defined even if IP_PKTINFO is not. */
#define SOPT_SIZE_CMSG_PKTINFO(af)                                             \
  ((af == AF_INET) ? SOPT_SIZE_CMSG_PKTINFO_IPV4() \
                   : SOPT_SIZE_CMSG_PKTINFO_IPV6()
#endif /* IP_PKTINFO */

#if defined(IP_RECVIF)
/* BSD/Solaris */

#define SOPT_SIZE_CMSG_RECVIF_IPV4()	(sizeof(struct sockaddr_dl))
#endif /* IP_RECVIF */

/* SOPT_SIZE_CMSG_IFINDEX_IPV4 - portable type */
#if defined(SOPT_SIZE_CMSG_PKTINFO)
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() SOPT_SIZE_CMSG_PKTINFO_IPV4()
#elif defined(SOPT_SIZE_CMSG_RECVIF_IPV4)
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() SOPT_SIZE_CMSG_RECVIF_IPV4()
#else  /* Nothing available */
#define SOPT_SIZE_CMSG_IFINDEX_IPV4() (sizeof(char *))
#endif /* SOPT_SIZE_CMSG_IFINDEX_IPV4 */

#define SOPT_SIZE_CMSG_IFINDEX(af)                                             \
  (((af) == AF_INET) : SOPT_SIZE_CMSG_IFINDEX_IPV4() \
                    ? SOPT_SIZE_CMSG_PKTINFO_IPV6())

/*
 * If not defined then define the value for `TCP_MD5SIG_MAXKEYLEN`. This seems
 * to be unavailable for NetBSD 8, FreeBSD 11 and FreeBSD 12.
 *
 * The value below was copied from `linux/tcp.h` from the Linux kernel headers.
 */
#ifndef TCP_MD5SIG_MAXKEYLEN
#define TCP_MD5SIG_MAXKEYLEN 80
#endif

extern int setsockopt_ipv4_multicast_if(int sock, struct in_addr if_addr,
					ifindex_t ifindex);
extern int setsockopt_ipv4_multicast(int sock, int optname,
				     struct in_addr if_addr,
				     unsigned int mcast_addr,
				     ifindex_t ifindex);
extern int setsockopt_ipv4_multicast_loop(int sock, uint8_t val);

extern int setsockopt_ipv4_tos(int sock, int tos);

/* Ask for, and get, ifindex, by whatever method is supported. */
extern int setsockopt_ifindex(int, int, ifindex_t);
extern ifindex_t getsockopt_ifindex(int, struct msghdr *);

/* swab the fields in iph between the host order and system order expected
 * for IP_HDRINCL.
 */
extern void sockopt_iphdrincl_swab_htosys(struct ip *iph);
extern void sockopt_iphdrincl_swab_systoh(struct ip *iph);

extern int sockopt_tcp_rtt(int);

/*
 * TCP MD5 signature option. This option allows TCP MD5 to be enabled on
 * addresses.
 *
 * sock
 *    Socket to enable option on.
 *
 * su
 *    Sockunion specifying address to enable option on.
 *
 * password
 *    MD5 auth password
 */
extern int sockopt_tcp_signature(int sock, union sockunion *su,
				 const char *password);

/*
 * Extended TCP MD5 signature option. This option allows TCP MD5 to be enabled
 * on prefixes.
 *
 * sock
 *    Socket to enable option on.
 *
 * su
 *    Sockunion specifying address (or prefix) to enable option on.
 *
 * prefixlen
 *    0    - su is an address; fall back to non-extended mode
 *    Else - su is a prefix; prefixlen is the mask length
 *
 * password
 *    MD5 auth password
 */
extern int sockopt_tcp_signature_ext(int sock, union sockunion *su,
				     uint16_t prefixlen, const char *password);

/*
 * set TCP max segment size. This option allows user to configure
 * max segment size for TCP session
 *
 * sock
 *    Socket to enable option on.
 *
 * tcp_maxseg
 *    value used for TCP segment size negotiation during SYN
 */
extern int sockopt_tcp_mss_set(int sock, int tcp_maxseg);

/*
 * get TCP max segment size. This option allows user to get
 * the segment size for TCP session
 *
 * sock
 *    Socket to get max segement size.
 */
extern int sockopt_tcp_mss_get(int sock);

/*
 * Configure TCP keepalive for a given socket
 *
 * sock
 *   Socket to enable keepalive option on.
 *
 * keepalive_idle
 *   number of seconds a connection needs to be idle
 *   before sending out keep-alive proves
 *
 * keepalive_intvl
 *   number of seconds between TCP keep-alive probes
 *
 * keepalive_probes
 *   max number of probers to send before giving up
 *   and killing tcp connection
 */
extern int setsockopt_tcp_keepalive(int sock, uint16_t keepalive_idle,
				    uint16_t keepalive_intvl,
				    uint16_t keepalive_probes);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_SOCKOPT_H */
