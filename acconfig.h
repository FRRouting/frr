/* accconfig.h -- `autoheader' will generate config.h.in for zebra.
   Copyright (C) 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org> */

/* Version of GNU Zebra */
#undef VERSION

/* Solaris on x86. */
#undef SOLARIS_X86

/* Package name of GNU Zebra */
#undef PACKAGE

/* Define if host is GNU/Linux */
#undef GNU_LINUX

/* Define if you have the AF_ROUTE socket.  */
#undef HAVE_AF_ROUTE

/* Define if you have the inet_aton function.  */
#undef HAVE_INET_ATON

/* Define if you have the inet_ntop function.  */
#undef HAVE_INET_NTOP

/* Define if you have the inet_pton function.  */
#undef HAVE_INET_PTON

/* Define if you have the setproctitle function.  */
#undef HAVE_SETPROCTITLE

/* Define if you have ipv6 stack.  */
#undef HAVE_IPV6

/* Define if you wish to support ipv6 router advertisment.  */
/* #undef HAVE_RTADV */

/* whether system has GNU regex */
#undef HAVE_GNU_REGEX

/* whether system has SNMP library */
#undef HAVE_SNMP

/* whether sockaddr has a sa_len field */
#undef HAVE_SA_LEN

/* whether sockaddr_in has a sin_len field */
#undef HAVE_SIN_LEN

/* whether sockaddr_un has a sun_len field */
#undef HAVE_SUN_LEN

/* whether sockaddr_in6 has a sin6_scope_id field */
#undef HAVE_SIN6_SCOPE_ID

/* Define if there is socklen_t. */
#undef HAVE_SOCKLEN_T

/* Define if there is sockaddr_dl structure. */
#undef HAVE_SOCKADDR_DL

/* Define if there is ifaliasreq structure. */
#undef HAVE_IFALIASREQ

/* Define if there is in6_aliasreq structure. */
#undef HAVE_IN6_ALIASREQ

/* Define if there is rt_addrinfo structure. */
#undef HAVE_RT_ADDRINFO

/* Define if there is in_pktinfo structure. */
#undef HAVE_INPKTINFO

/* Define if you have the getrusage function. */
#undef HAVE_RUSAGE

/* Define if /proc/net/dev exists. */
#undef HAVE_PROC_NET_DEV

/* Define if /proc/net/if_inet6 exists. */
#undef HAVE_PROC_NET_IF_INET6

/* Define if NET_RT_IFLIST exists in sys/socket.h. */
#undef HAVE_NET_RT_IFLIST

/* Define if you have INRIA ipv6 stack.  */
#undef INRIA_IPV6

/* Define if you have KAME project ipv6 stack.  */
#undef KAME

/* Define if you have Linux ipv6 stack.  */
#undef LINUX_IPV6

/* Define if you have NRL ipv6 stack.  */
#undef NRL

/* Define if you have BSDI NRL IPv6 stack. */
#undef BSDI_NRL

/* Define if one-vty option is specified. */
#undef VTYSH

/* Define if interface aliases don't have distinct indeces */
#undef HAVE_BROKEN_ALIASES

/* Define if disable-bgp-announce option is specified. */
#undef DISABLE_BGP_ANNOUNCE

/* PAM support */
#undef USE_PAM

/* TCP/IP communication between zebra and protocol daemon. */
#undef HAVE_TCP_ZEBRA

/* The OSPF NSSA option (RFC1587). */
#undef HAVE_NSSA

/* The OSPF Opaque LSA option (RFC2370). */
#undef HAVE_OPAQUE_LSA

/* Traffic Engineering Extension to OSPF
   (draft-katz-yeung-ospf-traffic-06.txt). */
#undef HAVE_OSPF_TE

/* Linux netlink. */
#undef HAVE_NETLINK

/* PATHS */
#undef PATH_ZEBRA_PID
#undef PATH_RIPD_PID
#undef PATH_RIPNGD_PID
#undef PATH_BGPD_PID
#undef PATH_OSPFD_PID
#undef PATH_OSPF6D_PID

/* Define if Solaris */
#undef SUNOS_5

/* Define if FreeBSD 3.2 */
#undef FREEBSD_32

/* Define if OpenBSD */
#undef OPEN_BSD

#ifdef HAVE_IPV6
#ifdef KAME
#ifndef INET6
#define INET6
#endif /* INET6 */
#endif /* KAME */
#endif /* HAVE_IPV6 */

#ifdef SUNOS_5
typedef unsigned int u_int32_t; 
typedef unsigned short u_int16_t; 
typedef unsigned short u_int8_t; 
#endif /* SUNOS_5 */

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif /* HAVE_SOCKLEN_T */
