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
#include "sockopt.h"

int
setsockopt_so_recvbuf (int sock, int size)
{
  int ret;
  
  if ( (ret = setsockopt (sock, SOL_SOCKET, SO_RCVBUF, (char *)
                          &size, sizeof (int))) < 0)
    zlog_err ("fd %d: can't setsockopt SO_RCVBUF to %d: %s",
	      sock,size,safe_strerror(errno));

  return ret;
}

int
setsockopt_so_sendbuf (const int sock, int size)
{
  int ret = setsockopt (sock, SOL_SOCKET, SO_SNDBUF,
    (char *)&size, sizeof (int));
  
  if (ret < 0)
    zlog_err ("fd %d: can't setsockopt SO_SNDBUF to %d: %s",
      sock, size, safe_strerror (errno));

  return ret;
}

int
getsockopt_so_sendbuf (const int sock)
{
  u_int32_t optval;
  socklen_t optlen = sizeof (optval);
  int ret = getsockopt (sock, SOL_SOCKET, SO_SNDBUF,
    (char *)&optval, &optlen);
  if (ret < 0)
  {
    zlog_err ("fd %d: can't getsockopt SO_SNDBUF: %d (%s)",
      sock, errno, safe_strerror (errno));
    return ret;
  }
  return optval;
}

static void *
getsockopt_cmsg_data (struct msghdr *msgh, int level, int type)
{
  struct cmsghdr *cmsg;
  void *ptr = NULL;
  
  for (cmsg = ZCMSG_FIRSTHDR(msgh); 
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(msgh, cmsg))
    if (cmsg->cmsg_level == level && cmsg->cmsg_type)
      return (ptr = CMSG_DATA(cmsg));

  return NULL;
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
    zlog_warn ("can't setsockopt IPV6_RECVPKTINFO : %s", safe_strerror (errno));
#else	/*RFC2292*/
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("can't setsockopt IPV6_PKTINFO : %s", safe_strerror (errno));
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
getsockopt_ipv6_ifindex (struct msghdr *msgh)
{
  struct in6_pktinfo *pktinfo;
  
  pktinfo = getsockopt_cmsg_data (msgh, IPPROTO_IPV6, IPV6_PKTINFO);
  
  return pktinfo->ipi6_ifindex;
}
#endif /* HAVE_IPV6 */


/*
 * Process multicast socket options for IPv4 in an OS-dependent manner.
 * Supported options are IP_MULTICAST_IF and IP_{ADD,DROP}_MEMBERSHIP.
 *
 * Many operating systems have a limit on the number of groups that
 * can be joined per socket (where each group and local address
 * counts).  This impacts OSPF, which joins groups on each interface
 * using a single socket.  The limit is typically 20, derived from the
 * original BSD multicast implementation.  Some systems have
 * mechanisms for increasing this limit.
 *
 * In many 4.4BSD-derived systems, multicast group operations are not
 * allowed on interfaces that are not UP.  Thus, a previous attempt to
 * leave the group may have failed, leaving it still joined, and we
 * drop/join quietly to recover.  This may not be necessary, but aims to
 * defend against unknown behavior in that we will still return an error
 * if the second join fails.  It is not clear how other systems
 * (e.g. Linux, Solaris) behave when leaving groups on down interfaces,
 * but this behavior should not be harmful if they behave the same way,
 * allow leaves, or implicitly leave all groups joined to down interfaces.
 */
int
setsockopt_multicast_ipv4(int sock, 
			int optname, 
			struct in_addr if_addr /* required */,
			unsigned int mcast_addr,
			unsigned int ifindex /* optional: if non-zero, may be
						  used instead of if_addr */)
{

#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
  /* This is better because it uses ifindex directly */
  struct ip_mreqn mreqn;
  int ret;
  
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
      
      ret = setsockopt(sock, IPPROTO_IP, optname,
		       (void *)&mreqn, sizeof(mreqn));
      if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP) && (errno == EADDRINUSE))
        {
	  /* see above: handle possible problem when interface comes back up */
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_info("setsockopt_multicast_ipv4 attempting to drop and "
		    "re-add (fd %d, ifaddr %s, mcast %s, ifindex %u)",
		    sock,
		    inet_ntop(AF_INET, &if_addr, buf[0], sizeof(buf[0])),
		    inet_ntop(AF_INET, &mreqn.imr_multiaddr,
			      buf[1], sizeof(buf[1])), ifindex);
	  setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		     (void *)&mreqn, sizeof(mreqn));
	  ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			   (void *)&mreqn, sizeof(mreqn));
        }
      return ret;
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
  /* standard BSD API */

  struct in_addr m;
  struct ip_mreq mreq;
  int ret;

#ifdef HAVE_BSD_STRUCT_IP_MREQ_HACK
  if (ifindex)
    m.s_addr = htonl(ifindex);
  else
#endif
    m = if_addr;

  switch (optname)
    {
    case IP_MULTICAST_IF:
      return setsockopt (sock, IPPROTO_IP, optname, (void *)&m, sizeof(m)); 
      break;

    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
      memset (&mreq, 0, sizeof(mreq));
      mreq.imr_multiaddr.s_addr = mcast_addr;
      mreq.imr_interface = m;
      
      ret = setsockopt (sock, IPPROTO_IP, optname, (void *)&mreq, sizeof(mreq));
      if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP) && (errno == EADDRINUSE))
        {
	  /* see above: handle possible problem when interface comes back up */
	  char buf[2][INET_ADDRSTRLEN];
	  zlog_info("setsockopt_multicast_ipv4 attempting to drop and "
		    "re-add (fd %d, ifaddr %s, mcast %s, ifindex %u)",
		    sock,
		    inet_ntop(AF_INET, &if_addr, buf[0], sizeof(buf[0])),
		    inet_ntop(AF_INET, &mreq.imr_multiaddr,
			      buf[1], sizeof(buf[1])), ifindex);
	  setsockopt (sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		      (void *)&mreq, sizeof(mreq));
	  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	  		    (void *)&mreq, sizeof(mreq));
        }
      return ret;
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
setsockopt_ipv4_ifindex (int sock, int val)
{
  int ret;

#if defined (IP_PKTINFO)
  if ((ret = setsockopt (sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof (val))) < 0)
    zlog_warn ("Can't set IP_PKTINFO option for fd %d to %d: %s",
	       sock,val,safe_strerror(errno));
#elif defined (IP_RECVIF)
  if ((ret = setsockopt (sock, IPPROTO_IP, IP_RECVIF, &val, sizeof (val))) < 0)
    zlog_warn ("Can't set IP_RECVIF option for fd %d to %d: %s",
	       sock,val,safe_strerror(errno));
#else
#warning "Neither IP_PKTINFO nor IP_RECVIF is available."
#warning "Will not be able to receive link info."
#warning "Things might be seriously broken.."
  /* XXX Does this ever happen?  Should there be a zlog_warn message here? */
  ret = -1;
#endif
  return ret;
}

int
setsockopt_ifindex (int af, int sock, int val)
{
  int ret = -1;
  
  switch (af)
    {
      case AF_INET:
        ret = setsockopt_ipv4_ifindex (sock, val);
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        ret = setsockopt_ipv6_pktinfo (sock, val);
        break;
#endif
      default:
        zlog_warn ("setsockopt_ifindex: unknown address family %d", af);
    }
  return ret;
}
  
/*
 * Requires: msgh is not NULL and points to a valid struct msghdr, which
 * may or may not have control data about the incoming interface.
 *
 * Returns the interface index (small integer >= 1) if it can be
 * determined, or else 0.
 */
static int
getsockopt_ipv4_ifindex (struct msghdr *msgh)
{
  /* XXX: initialize to zero?  (Always overwritten, so just cosmetic.) */
  int ifindex = -1;

#if defined(IP_PKTINFO)
/* Linux pktinfo based ifindex retrieval */
  struct in_pktinfo *pktinfo;
  
  pktinfo = 
    (struct in_pktinfo *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_PKTINFO);
  /* XXX Can pktinfo be NULL?  Clean up post 0.98. */
  ifindex = pktinfo->ipi_ifindex;
  
#elif defined(IP_RECVIF)

  /* retrieval based on IP_RECVIF */

#ifndef SUNOS_5
  /* BSD systems use a sockaddr_dl as the control message payload. */
  struct sockaddr_dl *sdl;
#else
  /* SUNOS_5 uses an integer with the index. */
  int *ifindex_p;
#endif /* SUNOS_5 */

#ifndef SUNOS_5
  /* BSD */
  sdl = 
    (struct sockaddr_dl *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF);
  if (sdl != NULL)
    ifindex = sdl->sdl_index;
  else
    ifindex = 0;
#else
  /*
   * Solaris.  On Solaris 8, IP_RECVIF is defined, but the call to
   * enable it fails with errno=99, and the struct msghdr has
   * controllen 0.
   */
  ifindex_p = (uint_t *)getsockopt_cmsg_data (msgh, IPPROTO_IP, IP_RECVIF); 
  if (ifindex_p != NULL)
    ifindex = *ifindex_p;
  else
    ifindex = 0;
#endif /* SUNOS_5 */

#else
  /*
   * Neither IP_PKTINFO nor IP_RECVIF defined - warn at compile time.
   * XXX Decide if this is a core service, or if daemons have to cope.
   * Since Solaris 8 and OpenBSD seem not to provide it, it seems that
   * daemons have to cope.
   */
#warning "getsockopt_ipv4_ifindex: Neither IP_PKTINFO nor IP_RECVIF defined."
#warning "Some daemons may fail to operate correctly!"
  ifindex = 0;

#endif /* IP_PKTINFO */ 

  return ifindex;
}

/* return ifindex, 0 if none found */
int
getsockopt_ifindex (int af, struct msghdr *msgh)
{
  int ifindex = 0;
  
  switch (af)
    {
      case AF_INET:
        return (getsockopt_ipv4_ifindex (msgh));
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        return (getsockopt_ipv6_ifindex (msgh));
        break;
#endif
      default:
        zlog_warn ("getsockopt_ifindex: unknown address family %d", af);
        return (ifindex = 0);
    }
}

/* swab iph between order system uses for IP_HDRINCL and host order */
void
sockopt_iphdrincl_swab_htosys (struct ip *iph)
{
  /* BSD and derived take iph in network order, except for 
   * ip_len and ip_off
   */
#ifndef HAVE_IP_HDRINCL_BSD_ORDER
  iph->ip_len = htons(iph->ip_len);
  iph->ip_off = htons(iph->ip_off);
#endif /* HAVE_IP_HDRINCL_BSD_ORDER */

  iph->ip_id = htons(iph->ip_id);
}

void
sockopt_iphdrincl_swab_systoh (struct ip *iph)
{
#ifndef HAVE_IP_HDRINCL_BSD_ORDER
  iph->ip_len = ntohs(iph->ip_len);
  iph->ip_off = ntohs(iph->ip_off);
#endif /* HAVE_IP_HDRINCL_BSD_ORDER */

  iph->ip_id = ntohs(iph->ip_id);
}
