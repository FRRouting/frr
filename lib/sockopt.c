/* setsockopt functions
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

#include <zebra.h>
#include "log.h"

static void *
getsockopt_cmsg_data (struct msghdr *msgh, int level, int type)
{
  struct cmsghdr *cmsg;
  void *ptr = NULL;
  
  for (cmsg = CMSG_FIRSTHDR(msgh); 
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(msgh, cmsg))
    if (cmsg->cmsg_level == level && cmsg->cmsg_type)
      return (ptr = CMSG_DATA(cmsg));
}

#ifdef HAVE_IPV6
/* Set IPv6 packet info to the socket. */
int
setsockopt_ipv6_pktinfo (int sock, int val)
{
  int ret;
    
#ifdef IPV6_RECVPKTINFO		/*2292bis-01*/
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_RECVPKTINFO : %s", strerror (errno));
#else	/*RFC2292*/
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_PKTINFO : %s", strerror (errno));
#endif /* INIA_IPV6 */
  return ret;
}

/* Set multicast hops val to the socket. */
int
setsockopt_ipv6_checksum (int sock, int val)
{
  int ret;

#ifdef GNU_LINUX
  ret = setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));
#else
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &val, sizeof(val));
#endif /* GNU_LINUX */
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_CHECKSUM");
  return ret;
}

/* Set multicast hops val to the socket. */
int
setsockopt_ipv6_multicast_hops (int sock, int val)
{
  int ret;

  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_MULTICAST_HOPS");
  return ret;
}

/* Set multicast hops val to the socket. */
int
setsockopt_ipv6_unicast_hops (int sock, int val)
{
  int ret;

  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_UNICAST_HOPS");
  return ret;
}

int
setsockopt_ipv6_hoplimit (int sock, int val)
{
  int ret;

#ifdef IPV6_RECVHOPLIMIT	/*2292bis-01*/
  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_RECVHOPLIMIT");
#else	/*RFC2292*/
  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_HOPLIMIT");
#endif
  return ret;
}

/* Set multicast loop zero to the socket. */
int
setsockopt_ipv6_multicast_loop (int sock, int val)
{
  int ret;
    
  ret = setsockopt (sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val,
		    sizeof (val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_MULTICAST_LOOP");
  return ret;
}

static int
getsockopt_ipv6_pktinfo_ifindex (struct msghdr *msgh)
{
  struct in6_pktinfo *pktinfo;
  
  pktinfo = getsockopt_cmsg_data (msgh, IPPROTO_IPV6, IPV6_PKTINFO);
  
  return pktinfo->ipi6_ifindex;
}
#endif /* HAVE_IPV6 */


/* Set up a multicast socket options for IPv4
   This is here so that people only have to do their OS multicast mess 
   in one place rather than all through zebra, ospfd, and ripd 
   NB: This is a hookpoint for specific OS functionality */
int
setsockopt_multicast_ipv4(int sock, 
			int optname, 
			struct in_addr if_addr,
			unsigned int mcast_addr,
			unsigned int ifindex)
{

  /* Linux 2.2.0 and up */
#if defined(GNU_LINUX) && LINUX_VERSION_CODE > 131584
  /* This is better because it uses ifindex directly */
  struct ip_mreqn mreqn;
  
  switch (optname)
    {
    case IP_MULTICAST_IF:
    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
      memset (&mreqn, 0, sizeof(mreqn));

      if (mcast_addr)
	mreqn.imr_multiaddr.s_addr = mcast_addr;
      
      if (ifindex)
	mreqn.imr_ifindex = ifindex;
      else
	mreqn.imr_address = if_addr;
      
      return setsockopt(sock, IPPROTO_IP, optname, (void *)&mreqn, sizeof(mreqn));
      break;

    default:
      /* Can out and give an understandable error */
      errno = EINVAL;
      return -1;
      break;
    }

  /* Example defines for another OS, boilerplate off other code in this
     function, AND handle optname as per other sections for consistency !! */
  /* #elif  defined(BOGON_NIX) && EXAMPLE_VERSION_CODE > -100000 */
  /* Add your favourite OS here! */

#else /* #if OS_TYPE */ 
  /* default OS support */

  struct in_addr m;
  struct ip_mreq mreq;

  switch (optname)
    {
    case IP_MULTICAST_IF:
      m = if_addr;
      
      return setsockopt (sock, IPPROTO_IP, optname, (void *)&m, sizeof(m)); 
      break;

    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
      memset (&mreq, 0, sizeof(mreq));
      mreq.imr_multiaddr.s_addr = mcast_addr;
      mreq.imr_interface = if_addr;
      
      return setsockopt (sock, 
			 IPPROTO_IP, 
			 optname, 
			 (void *)&mreq, 
			 sizeof(mreq));
      break;
      
    default:
      /* Can out and give an understandable error */
      errno = EINVAL;
      return -1;
      break;
    }
#endif /* #if OS_TYPE */

}

static int
setsockopt_ipv4_pktinfo (int sock, int val)
{
  int ret;

#if defined (IP_PKTINFO)
  ret = setsockopt (sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof (val));
#elif defined (IP_RECVIF)
  ret = setsockopt (sock, IPPROTO_IP, IP_RECVIF, &val, sizeof (val));
#else
#warning "Neither IP_PKTINFO nor IP_RECVIF is available."
#warning "Will not be able to receive link info."
#warning "Things might be seriously broken.."
#endif

  if (ret < 0)
    zlog_warn ("Can't set IP_PKTINFO option");
  return ret;
}

/* set appropriate pktinfo socket option 
 * on systems without PKTINFO, sets RECVIF, which only retrieves
 * interface index.
 */
int 
setsockopt_pktinfo (int af, int sock, int val)
{
  int ret = -1;
  
  switch (af)
    {
      case AF_INET:
        ret = setsockopt_ipv4_pktinfo (sock, val);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        ret = setsockopt_ipv6_pktinfo (sock, val);
        break;
#endif
      default:
        zlog_warn ("setsockopt_pktinfo: unknown address family %d");
    }
  return ret;
}


static int
getsockopt_ipv4_pktinfo_ifindex (struct msghdr *msgh)
{
  int ifindex = 0;
#if defined (IP_PKTINFO)
  struct in_pktinfo *pktinfo;
#elif defined (IP_REVCIF)
#ifndef SUNOS_5
  struct sockaddr_dl *sdl;
#endif /* SUNOS_5 */
#else /* IP_RECVIF */
  char *pktinfo;
#endif /* IP_PKTINFO */
  
#ifdef IP_PKTINFO
  pktinfo = 
    (struct in_pktinfo *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_PKTINFO);
#elif defined (IP_RECVIF)
#ifdef SUNOS_5
  ifindex = *(uint_t *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF);
#else
  pktinfo = 
    (struct sockaddr_dl *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF);
  ifindex = pktinfo->sdl_index;
#endif /* SUNOS_5 */
#else
#warning "getsockopt_ipv4_pktinfo_ifindex: dont have PKTINFO or RECVIF"
        ifindex = 0;
#endif /* IP_PKTINFO */
 
  return ifindex;
}

/* return ifindex, 0 if none found */
int
getsockopt_pktinfo_ifindex (int af, struct msghdr *msgh)
{
  int ifindex = 0;
  
  switch (af)
    {
      case AF_INET:
        return (getsockopt_ipv4_pktinfo_ifindex (msgh));
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        return (getsockopt_ipv6_pktinfo_ifindex (msgh));
        break;
#endif
      default:
        zlog_warn ("getsockopt_pktinfo_ifindex: unknown address family %d");
        return (ifindex = 0);
    }
}

