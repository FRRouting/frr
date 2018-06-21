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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifdef SUNOS_5
#include <ifaddrs.h>
#endif

#include "log.h"
#include "sockopt.h"
#include "sockunion.h"

void setsockopt_so_recvbuf(int sock, int size)
{
	int orig_req = size;

	while (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))
	       == -1)
		size /= 2;

	if (size != orig_req)
		zlog_warn("%s: fd %d: SO_RCVBUF set to %d (requested %d)",
			  __func__, sock, size, orig_req);
}

void setsockopt_so_sendbuf(const int sock, int size)
{
	int orig_req = size;

	while (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))
	       == -1)
		size /= 2;

	if (size != orig_req)
		zlog_warn("%s: fd %d: SO_SNDBUF set to %d (requested %d)",
			  __func__, sock, size, orig_req);
}

int getsockopt_so_sendbuf(const int sock)
{
	uint32_t optval;
	socklen_t optlen = sizeof(optval);
	int ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&optval,
			     &optlen);
	if (ret < 0) {
		zlog_err("fd %d: can't getsockopt SO_SNDBUF: %d (%s)", sock,
			 errno, safe_strerror(errno));
		return ret;
	}
	return optval;
}

static void *getsockopt_cmsg_data(struct msghdr *msgh, int level, int type)
{
	struct cmsghdr *cmsg;
	void *ptr = NULL;

	for (cmsg = ZCMSG_FIRSTHDR(msgh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msgh, cmsg))
		if (cmsg->cmsg_level == level && cmsg->cmsg_type)
			return (ptr = CMSG_DATA(cmsg));

	return NULL;
}

/* Set IPv6 packet info to the socket. */
int setsockopt_ipv6_pktinfo(int sock, int val)
{
	int ret;

#ifdef IPV6_RECVPKTINFO /*2292bis-01*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_RECVPKTINFO : %s",
			  safe_strerror(errno));
#else  /*RFC2292*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_PKTINFO : %s",
			  safe_strerror(errno));
#endif /* INIA_IPV6 */
	return ret;
}

/* Set multicast hops val to the socket. */
int setsockopt_ipv6_checksum(int sock, int val)
{
	int ret;

#ifdef GNU_LINUX
	ret = setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));
#else
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &val, sizeof(val));
#endif /* GNU_LINUX */
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_CHECKSUM");
	return ret;
}

/* Set multicast hops val to the socket. */
int setsockopt_ipv6_multicast_hops(int sock, int val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_MULTICAST_HOPS");
	return ret;
}

/* Set multicast hops val to the socket. */
int setsockopt_ipv6_unicast_hops(int sock, int val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_UNICAST_HOPS");
	return ret;
}

int setsockopt_ipv6_hoplimit(int sock, int val)
{
	int ret;

#ifdef IPV6_RECVHOPLIMIT /*2292bis-01*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_RECVHOPLIMIT");
#else /*RFC2292*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &val, sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_HOPLIMIT");
#endif
	return ret;
}

/* Set multicast loop zero to the socket. */
int setsockopt_ipv6_multicast_loop(int sock, int val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IPV6_MULTICAST_LOOP");
	return ret;
}

static int getsockopt_ipv6_ifindex(struct msghdr *msgh)
{
	struct in6_pktinfo *pktinfo;

	pktinfo = getsockopt_cmsg_data(msgh, IPPROTO_IPV6, IPV6_PKTINFO);

	return pktinfo->ipi6_ifindex;
}

int setsockopt_ipv6_tclass(int sock, int tclass)
{
	int ret = 0;

#ifdef IPV6_TCLASS /* RFC3542 */
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &tclass,
			 sizeof(tclass));
	if (ret < 0)
		zlog_warn("Can't set IPV6_TCLASS option for fd %d to %#x: %s",
			  sock, tclass, safe_strerror(errno));
#endif
	return ret;
}

/*
 * Process multicast socket options for IPv4 in an OS-dependent manner.
 * Supported options are IP_{ADD,DROP}_MEMBERSHIP.
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
int setsockopt_ipv4_multicast(int sock, int optname, struct in_addr if_addr,
			      unsigned int mcast_addr, ifindex_t ifindex)
{
#ifdef HAVE_RFC3678
	struct group_req gr;
	struct sockaddr_in *si;
	int ret;
	memset(&gr, 0, sizeof(gr));
	si = (struct sockaddr_in *)&gr.gr_group;
	gr.gr_interface = ifindex;
	si->sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	si->sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	si->sin_addr.s_addr = mcast_addr;
	ret = setsockopt(sock, IPPROTO_IP,
			 (optname == IP_ADD_MEMBERSHIP) ? MCAST_JOIN_GROUP
							: MCAST_LEAVE_GROUP,
			 (void *)&gr, sizeof(gr));
	if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP)
	    && (errno == EADDRINUSE)) {
		setsockopt(sock, IPPROTO_IP, MCAST_LEAVE_GROUP, (void *)&gr,
			   sizeof(gr));
		ret = setsockopt(sock, IPPROTO_IP, MCAST_JOIN_GROUP,
				 (void *)&gr, sizeof(gr));
	}
	return ret;

#elif defined(HAVE_STRUCT_IP_MREQN_IMR_IFINDEX) && !defined(__FreeBSD__)
	struct ip_mreqn mreqn;
	int ret;

	assert(optname == IP_ADD_MEMBERSHIP || optname == IP_DROP_MEMBERSHIP);
	memset(&mreqn, 0, sizeof(mreqn));

	mreqn.imr_multiaddr.s_addr = mcast_addr;
	mreqn.imr_ifindex = ifindex;

	ret = setsockopt(sock, IPPROTO_IP, optname, (void *)&mreqn,
			 sizeof(mreqn));
	if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP)
	    && (errno == EADDRINUSE)) {
		/* see above: handle possible problem when interface comes back
		 * up */
		char buf[1][INET_ADDRSTRLEN];
		zlog_info(
			"setsockopt_ipv4_multicast attempting to drop and "
			"re-add (fd %d, mcast %s, ifindex %u)",
			sock, inet_ntop(AF_INET, &mreqn.imr_multiaddr, buf[0],
					sizeof(buf[0])),
			ifindex);
		setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void *)&mreqn,
			   sizeof(mreqn));
		ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 (void *)&mreqn, sizeof(mreqn));
	}
	return ret;

/* Example defines for another OS, boilerplate off other code in this
   function, AND handle optname as per other sections for consistency !! */
/* #elif  defined(BOGON_NIX) && EXAMPLE_VERSION_CODE > -100000 */
/* Add your favourite OS here! */

#elif defined(HAVE_BSD_STRUCT_IP_MREQ_HACK) /* #if OS_TYPE */
	/* standard BSD API */

	struct ip_mreq mreq;
	int ret;

	assert(optname == IP_ADD_MEMBERSHIP || optname == IP_DROP_MEMBERSHIP);


	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = mcast_addr;
#if !defined __OpenBSD__
	mreq.imr_interface.s_addr = htonl(ifindex);
#else
	mreq.imr_interface.s_addr = if_addr.s_addr;
#endif

	ret = setsockopt(sock, IPPROTO_IP, optname, (void *)&mreq,
			 sizeof(mreq));
	if ((ret < 0) && (optname == IP_ADD_MEMBERSHIP)
	    && (errno == EADDRINUSE)) {
		/* see above: handle possible problem when interface comes back
		 * up */
		char buf[1][INET_ADDRSTRLEN];
		zlog_info(
			"setsockopt_ipv4_multicast attempting to drop and "
			"re-add (fd %d, mcast %s, ifindex %u)",
			sock, inet_ntop(AF_INET, &mreq.imr_multiaddr, buf[0],
					sizeof(buf[0])),
			ifindex);
		setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void *)&mreq,
			   sizeof(mreq));
		ret = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				 (void *)&mreq, sizeof(mreq));
	}
	return ret;

#else
#error "Unsupported multicast API"
#endif /* #if OS_TYPE */
}

/*
 * Set IP_MULTICAST_IF socket option in an OS-dependent manner.
 */
int setsockopt_ipv4_multicast_if(int sock, struct in_addr if_addr,
				 ifindex_t ifindex)
{

#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	struct ip_mreqn mreqn;
	memset(&mreqn, 0, sizeof(mreqn));

	mreqn.imr_ifindex = ifindex;
	return setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&mreqn,
			  sizeof(mreqn));

/* Example defines for another OS, boilerplate off other code in this
   function */
/* #elif  defined(BOGON_NIX) && EXAMPLE_VERSION_CODE > -100000 */
/* Add your favourite OS here! */
#elif defined(HAVE_BSD_STRUCT_IP_MREQ_HACK)
	struct in_addr m;

#if !defined __OpenBSD__
	m.s_addr = htonl(ifindex);
#else
	m.s_addr = if_addr.s_addr;
#endif

	return setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&m,
			  sizeof(m));
#elif defined(SUNOS_5)
	char ifname[IF_NAMESIZE];
	struct ifaddrs *ifa, *ifap;
	struct in_addr ifaddr;

	if (if_indextoname(ifindex, ifname) == NULL)
		return -1;

	if (getifaddrs(&ifa) != 0)
		return -1;

	for (ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
		struct sockaddr_in *sa;

		if (strcmp(ifap->ifa_name, ifname) != 0)
			continue;
		if (ifap->ifa_addr->sa_family != AF_INET)
			continue;
		sa = (struct sockaddr_in *)ifap->ifa_addr;
		memcpy(&ifaddr, &sa->sin_addr, sizeof(ifaddr));
		break;
	}

	freeifaddrs(ifa);
	if (!ifap) /* This means we did not find an IP */
		return -1;

	return setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&ifaddr,
			  sizeof(ifaddr));
#else
#error "Unsupported multicast API"
#endif
}

int setsockopt_ipv4_multicast_loop(int sock, uint8_t val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&val,
			 sizeof(val));
	if (ret < 0)
		zlog_warn("can't setsockopt IP_MULTICAST_LOOP");

	return ret;
}

static int setsockopt_ipv4_ifindex(int sock, ifindex_t val)
{
	int ret;

#if defined(IP_PKTINFO)
	if ((ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)))
	    < 0)
		zlog_warn("Can't set IP_PKTINFO option for fd %d to %d: %s",
			  sock, val, safe_strerror(errno));
#elif defined(IP_RECVIF)
	if ((ret = setsockopt(sock, IPPROTO_IP, IP_RECVIF, &val, sizeof(val)))
	    < 0)
		zlog_warn("Can't set IP_RECVIF option for fd %d to %d: %s",
			  sock, val, safe_strerror(errno));
#else
#warning "Neither IP_PKTINFO nor IP_RECVIF is available."
#warning "Will not be able to receive link info."
#warning "Things might be seriously broken.."
	/* XXX Does this ever happen?  Should there be a zlog_warn message here?
	 */
	ret = -1;
#endif
	return ret;
}

int setsockopt_ipv4_tos(int sock, int tos)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	if (ret < 0)
		zlog_warn("Can't set IP_TOS option for fd %d to %#x: %s", sock,
			  tos, safe_strerror(errno));
	return ret;
}


int setsockopt_ifindex(int af, int sock, ifindex_t val)
{
	int ret = -1;

	switch (af) {
	case AF_INET:
		ret = setsockopt_ipv4_ifindex(sock, val);
		break;
	case AF_INET6:
		ret = setsockopt_ipv6_pktinfo(sock, val);
		break;
	default:
		zlog_warn("setsockopt_ifindex: unknown address family %d", af);
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
static ifindex_t getsockopt_ipv4_ifindex(struct msghdr *msgh)
{
	ifindex_t ifindex;

#if defined(IP_PKTINFO)
	/* Linux pktinfo based ifindex retrieval */
	struct in_pktinfo *pktinfo;

	pktinfo = (struct in_pktinfo *)getsockopt_cmsg_data(msgh, IPPROTO_IP,
							    IP_PKTINFO);

	/* getsockopt_ifindex() will forward this, being 0 "not found" */
	if (pktinfo == NULL)
		return 0;

	ifindex = pktinfo->ipi_ifindex;

#elif defined(IP_RECVIF)

/* retrieval based on IP_RECVIF */

#ifndef SUNOS_5
	/* BSD systems use a sockaddr_dl as the control message payload. */
	struct sockaddr_dl *sdl;
#else
	/* SUNOS_5 uses an integer with the index. */
	ifindex_t *ifindex_p;
#endif /* SUNOS_5 */

#ifndef SUNOS_5
	/* BSD */
	sdl = (struct sockaddr_dl *)getsockopt_cmsg_data(msgh, IPPROTO_IP,
							 IP_RECVIF);
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
	ifindex_p = (uint_t *)getsockopt_cmsg_data(msgh, IPPROTO_IP, IP_RECVIF);
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
ifindex_t getsockopt_ifindex(int af, struct msghdr *msgh)
{
	switch (af) {
	case AF_INET:
		return (getsockopt_ipv4_ifindex(msgh));
		break;
	case AF_INET6:
		return (getsockopt_ipv6_ifindex(msgh));
		break;
	default:
		zlog_warn("getsockopt_ifindex: unknown address family %d", af);
		return 0;
	}
}

/* swab iph between order system uses for IP_HDRINCL and host order */
void sockopt_iphdrincl_swab_htosys(struct ip *iph)
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

void sockopt_iphdrincl_swab_systoh(struct ip *iph)
{
#ifndef HAVE_IP_HDRINCL_BSD_ORDER
	iph->ip_len = ntohs(iph->ip_len);
	iph->ip_off = ntohs(iph->ip_off);
#endif /* HAVE_IP_HDRINCL_BSD_ORDER */

	iph->ip_id = ntohs(iph->ip_id);
}

int sockopt_tcp_rtt(int sock)
{
#ifdef TCP_INFO
	struct tcp_info ti;
	socklen_t len = sizeof(ti);

	if (getsockopt(sock, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0)
		return 0;

	return ti.tcpi_rtt / 1000;
#else
	return 0;
#endif
}

int sockopt_tcp_signature(int sock, union sockunion *su, const char *password)
{
#if defined(HAVE_TCP_MD5_LINUX24) && defined(GNU_LINUX)
/* Support for the old Linux 2.4 TCP-MD5 patch, taken from Hasso Tepper's
 * version of the Quagga patch (based on work by Rick Payne, and Bruce
 * Simpson)
 */
#define TCP_MD5_AUTH 13
#define TCP_MD5_AUTH_ADD 1
#define TCP_MD5_AUTH_DEL 2
	struct tcp_rfc2385_cmd {
		uint8_t command;  /* Command - Add/Delete */
		uint32_t address; /* IPV4 address associated */
		uint8_t keylen;   /* MD5 Key len (do NOT assume 0 terminated
				      ascii) */
		void *key;	 /* MD5 Key */
	} cmd;
	struct in_addr *addr = &su->sin.sin_addr;

	cmd.command = (password != NULL ? TCP_MD5_AUTH_ADD : TCP_MD5_AUTH_DEL);
	cmd.address = addr->s_addr;
	cmd.keylen = (password != NULL ? strlen(password) : 0);
	cmd.key = password;

	return setsockopt(sock, IPPROTO_TCP, TCP_MD5_AUTH, &cmd, sizeof cmd);

#elif HAVE_DECL_TCP_MD5SIG
	int ret;
#ifndef GNU_LINUX
	/*
	 * XXX Need to do PF_KEY operation here to add/remove an SA entry,
	 * and add/remove an SP entry for this peer's packet flows also.
	 */
	int md5sig = password && *password ? 1 : 0;
#else
	int keylen = password ? strlen(password) : 0;
	struct tcp_md5sig md5sig;
	union sockunion *su2, *susock;

	/* Figure out whether the socket and the sockunion are the same family..
	 * adding AF_INET to AF_INET6 needs to be v4 mapped, you'd think..
	 */
	if (!(susock = sockunion_getsockname(sock)))
		return -1;

	if (susock->sa.sa_family == su->sa.sa_family)
		su2 = su;
	else {
		/* oops.. */
		su2 = susock;

		if (su2->sa.sa_family == AF_INET) {
			sockunion_free(susock);
			return 0;
		}

		/* If this does not work, then all users of this sockopt will
		 * need to
		 * differentiate between IPv4 and IPv6, and keep seperate
		 * sockets for
		 * each.
		 *
		 * Sadly, it doesn't seem to work at present. It's unknown
		 * whether
		 * this is a bug or not.
		 */
		if (su2->sa.sa_family == AF_INET6
		    && su->sa.sa_family == AF_INET) {
			su2->sin6.sin6_family = AF_INET6;
			/* V4Map the address */
			memset(&su2->sin6.sin6_addr, 0,
			       sizeof(struct in6_addr));
			su2->sin6.sin6_addr.s6_addr32[2] = htonl(0xffff);
			memcpy(&su2->sin6.sin6_addr.s6_addr32[3],
			       &su->sin.sin_addr, 4);
		}
	}

	memset(&md5sig, 0, sizeof(md5sig));
	memcpy(&md5sig.tcpm_addr, su2, sizeof(*su2));
	md5sig.tcpm_keylen = keylen;
	if (keylen)
		memcpy(md5sig.tcpm_key, password, keylen);
	sockunion_free(susock);
#endif /* GNU_LINUX */
	if ((ret = setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig,
			      sizeof md5sig))
	    < 0) {
		/* ENOENT is harmless.  It is returned when we clear a password
		   for which
		   one was not previously set. */
		if (ENOENT == errno)
			ret = 0;
		else
			zlog_err("sockopt_tcp_signature: setsockopt(%d): %s",
				 sock, safe_strerror(errno));
	}
	return ret;
#else  /* HAVE_TCP_MD5SIG */
	return -2;
#endif /* !HAVE_TCP_MD5SIG */
}
