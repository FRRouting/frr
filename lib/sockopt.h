/* Router advertisement
 * Copyright (C) 1999 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_SOCKOPT_H
#define _ZEBRA_SOCKOPT_H

#ifdef HAVE_IPV6
int setsockopt_ipv6_pktinfo (int, int);
int setsockopt_ipv6_checksum (int, int);
int setsockopt_ipv6_multicast_hops (int, int);
int setsockopt_ipv6_unicast_hops (int, int);
int setsockopt_ipv6_hoplimit (int, int);
int setsockopt_ipv6_multicast_loop (int, int);
#endif /* HAVE_IPV6 */

/*
 * It is OK to reference in6_pktinfo here without a protecting #if
 * because this macro will only be used #if HAVE_IPV6, and in6_pktinfo
 * is not optional for HAVE_IPV6.
 */
#define SOPT_SIZE_CMSG_PKTINFO_IPV6() (sizeof (struct in6_pktinfo));

/*
 * Size defines for control messages used to get ifindex.  We define
 * values for each method, and define a macro that can be used by code
 * that is unaware of which method is in use.
 * XXX Needs to use CMSG_DATA and CMSG_ALIGN.
 */
#if defined (IP_PKTINFO)
/* Linux in_pktinfo. */
#define SOPT_SIZE_CMSG_PKTINFO_IPV4()  (sizeof (struct in_pktinfo))

/* XXX This should perhaps be defined even if IP_PKTINFO is not. */
#define SOPT_SIZE_CMSG_PKTINFO(af) \
  ((af == AF_INET) ? SOPT_SIZE_CMSG_PKTINFO_IPV4() \
                   : SOPT_SIZE_CMSG_PKTINFO_IPV6()

#define SOPT_SIZE_CMSG_IFINDEX_IPV4()	SOPT_SIZE_CMSG_PKTINFO_IPV4()

#elif defined (IP_RECVIF)
/* BSD/Solaris.  Arguably these should say RECVIF rather than IFINDEX. */

#if defined (SUNOS_5)
#define SOPT_SIZE_CMSG_IFINDEX_IPV4()  (sizeof (uint_t))
#else
#define SOPT_SIZE_CMSG_IFINDEX_IPV4()	\
	__CMSG_ALIGN((sizeof (struct sockaddr_dl)))
#endif /* SUNOS_5 */

#endif

/*
 * AF-parameterized message size.
 * XXX Why is this here?  Is it used?  The v6 case is not defined. 
 */
#define SOPT_SIZE_CMSG_IFINDEX(af) \
  ((af == AF_INET) ? SOPT_SIZE_CMSG_IFINDEX_IPV4() \
                   : SOPT_SIZE_CMSG_IFINDEX_IPV6()

int setsockopt_multicast_ipv4(int sock, 
			     int optname, 
			     struct in_addr if_addr,
			     unsigned int mcast_addr,
			     unsigned int ifindex);

/*
 * XXX Exactly what is this an interface to?  Specifically, what calls
 * can be made after calling it?
 */
int setsockopt_pktinfo (int, int, int);

/* Ask for, and get, ifindex, by whatever method is supported. */
int setsockopt_ifindex (int, int, int);
int getsockopt_ifindex (int, struct msghdr *);
#endif /*_ZEBRA_SOCKOPT_H */
