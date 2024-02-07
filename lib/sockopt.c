// SPDX-License-Identifier: GPL-2.0-or-later
/* setsockopt functions
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "log.h"
#include "sockopt.h"
#include "sockunion.h"
#include "lib_errors.h"

#if (defined(__FreeBSD__) &&                                                   \
     ((__FreeBSD_version >= 500022 && __FreeBSD_version < 700000) ||           \
      (__FreeBSD_version < 500000 && __FreeBSD_version >= 440000))) ||         \
	(defined(__NetBSD__) && defined(__NetBSD_Version__) &&                 \
	 __NetBSD_Version__ >= 106010000) ||                                   \
	defined(__OpenBSD__) || defined(__DragonFly__) || defined(__sun)
#define HAVE_BSD_STRUCT_IP_MREQ_HACK
#endif

void setsockopt_so_recvbuf(int sock, int size)
{
	int orig_req = size;

	while (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) ==
	       -1) {
		if (size == 0)
			break;
		size /= 2;
	}

	if (size != orig_req)
		flog_err(EC_LIB_SOCKET,
			 "%s: fd %d: SO_RCVBUF set to %d (requested %d)",
			 __func__, sock, size, orig_req);
}

void setsockopt_so_sendbuf(const int sock, int size)
{
	int orig_req = size;

	while (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) ==
	       -1) {
		if (size == 0)
			break;
		size /= 2;
	}

	if (size != orig_req)
		flog_err(EC_LIB_SOCKET,
			 "%s: fd %d: SO_SNDBUF set to %d (requested %d)",
			 __func__, sock, size, orig_req);
}

int getsockopt_so_sendbuf(const int sock)
{
	uint32_t optval;
	socklen_t optlen = sizeof(optval);
	int ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&optval,
			     &optlen);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "fd %d: can't getsockopt SO_SNDBUF: %d (%s)", sock,
			     errno, safe_strerror(errno));
		return ret;
	}
	return optval;
}

int getsockopt_so_recvbuf(const int sock)
{
	uint32_t optval;
	socklen_t optlen = sizeof(optval);
	int ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&optval,
			     &optlen);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "fd %d: can't getsockopt SO_RCVBUF: %d (%s)", sock,
			     errno, safe_strerror(errno));
		return ret;
	}
	return optval;
}

static void *getsockopt_cmsg_data(struct msghdr *msgh, int level, int type)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msgh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msgh, cmsg))
		if (cmsg->cmsg_level == level && cmsg->cmsg_type == type)
			return CMSG_DATA(cmsg);

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
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IPV6_RECVPKTINFO : %s",
			 safe_strerror(errno));
#else  /*RFC2292*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_PKTINFO : %s",
			 safe_strerror(errno));
#endif /* IANA_IPV6 */
	return ret;
}

/* Set multicast hops val to the socket. */
int setsockopt_ipv6_multicast_hops(int sock, int val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val,
			 sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_MULTICAST_HOPS");
	return ret;
}

/* Set multicast hops val to the socket. */
int setsockopt_ipv6_unicast_hops(int sock, int val)
{
	int ret;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val,
			 sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_UNICAST_HOPS");
	return ret;
}

int setsockopt_ipv6_hoplimit(int sock, int val)
{
	int ret;

#ifdef IPV6_RECVHOPLIMIT /*2292bis-01*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val,
			 sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_RECVHOPLIMIT");
#else /*RFC2292*/
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &val, sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_HOPLIMIT");
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
		flog_err(EC_LIB_SOCKET, "can't setsockopt IPV6_MULTICAST_LOOP");
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
		flog_err(EC_LIB_SOCKET,
			 "Can't set IPV6_TCLASS option for fd %d to %#x: %s",
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
		zlog_info(
			"setsockopt_ipv4_multicast attempting to drop and re-add (fd %d, mcast %pI4, ifindex %u)",
			sock, &mreqn.imr_multiaddr, ifindex);
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
		zlog_info(
			"setsockopt_ipv4_multicast attempting to drop and re-add (fd %d, mcast %pI4, ifindex %u)",
			sock, &mreq.imr_multiaddr, ifindex);
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
		flog_err(EC_LIB_SOCKET, "can't setsockopt IP_MULTICAST_LOOP");

	return ret;
}

static int setsockopt_ipv4_ifindex(int sock, ifindex_t val)
{
	int ret;

#if defined(IP_PKTINFO)
	ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "Can't set IP_PKTINFO option for fd %d to %d: %s",
			 sock, val, safe_strerror(errno));
#elif defined(IP_RECVIF)
	ret = setsockopt(sock, IPPROTO_IP, IP_RECVIF, &val, sizeof(val));
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "Can't set IP_RECVIF option for fd %d to %d: %s", sock,
			 val, safe_strerror(errno));
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
		flog_err(EC_LIB_SOCKET,
			 "Can't set IP_TOS option for fd %d to %#x: %s", sock,
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
		flog_err(EC_LIB_DEVELOPMENT,
			 "setsockopt_ifindex: unknown address family %d", af);
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

	/* BSD systems use a sockaddr_dl as the control message payload. */
	struct sockaddr_dl *sdl;

	/* BSD */
	sdl = (struct sockaddr_dl *)getsockopt_cmsg_data(msgh, IPPROTO_IP,
							 IP_RECVIF);
	if (sdl != NULL)
		ifindex = sdl->sdl_index;
	else
		ifindex = 0;

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
	case AF_INET6:
		return (getsockopt_ipv6_ifindex(msgh));
	default:
		flog_err(EC_LIB_DEVELOPMENT,
			 "getsockopt_ifindex: unknown address family %d", af);
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

int sockopt_tcp_signature_ext(int sock, union sockunion *su, uint16_t prefixlen,
			      const char *password)
{
#ifndef HAVE_DECL_TCP_MD5SIG
	/*
	 * We have been asked to enable MD5 auth for an address, but our
	 * platform doesn't support that
	 */
	return -2;
#endif

#ifndef TCP_MD5SIG_EXT
	/*
	 * We have been asked to enable MD5 auth for a prefix, but our platform
	 * doesn't support that
	 */
	if (prefixlen > 0)
		return -2;
#endif

#if HAVE_DECL_TCP_MD5SIG
	int ret;

	int optname = TCP_MD5SIG;
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
		 * differentiate between IPv4 and IPv6, and keep separate
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

	/*
	 * Handle support for MD5 signatures on prefixes, if available and
	 * requested. Technically the #ifdef check below is not needed because
	 * if prefixlen > 0 and we don't have support for this feature we would
	 * have already returned by now, but leaving it there to be explicit.
	 */
#ifdef TCP_MD5SIG_EXT
	if (prefixlen > 0) {
		md5sig.tcpm_prefixlen = prefixlen;
		md5sig.tcpm_flags = TCP_MD5SIG_FLAG_PREFIX;
		optname = TCP_MD5SIG_EXT;
	}
#endif /* TCP_MD5SIG_EXT */

#endif /* GNU_LINUX */

	ret = setsockopt(sock, IPPROTO_TCP, optname, &md5sig, sizeof(md5sig));
	if (ret < 0) {
		if (ENOENT == errno)
			ret = 0;
		else
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"sockopt_tcp_signature: setsockopt(%d): %s",
				sock, safe_strerror(errno));
	}
	return ret;
#endif /* HAVE_TCP_MD5SIG */

	/*
	 * Making compiler happy.  If we get to this point we probably
	 * have done something really really wrong.
	 */
	return -2;
}

int sockopt_tcp_signature(int sock, union sockunion *su, const char *password)
{
	return sockopt_tcp_signature_ext(sock, su, 0, password);
}

/* set TCP mss value to socket */
int sockopt_tcp_mss_set(int sock, int tcp_maxseg)
{
	int ret = 0;
	socklen_t tcp_maxseg_len = sizeof(tcp_maxseg);

	ret = setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &tcp_maxseg,
			 tcp_maxseg_len);
	if (ret != 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: setsockopt(%d): %s", __func__, sock,
			     safe_strerror(errno));
	}

	return ret;
}

/* get TCP mss value synced by socket */
int sockopt_tcp_mss_get(int sock)
{
	int ret = 0;
	int tcp_maxseg = 0;
	socklen_t tcp_maxseg_len = sizeof(tcp_maxseg);

	if (sock < 0)
		return 0;

	ret = getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &tcp_maxseg,
			 &tcp_maxseg_len);
	if (ret != 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: getsockopt(%d): %s", __func__, sock,
			     safe_strerror(errno));
		return 0;
	}

	return tcp_maxseg;
}

int setsockopt_tcp_keepalive(int sock, uint16_t keepalive_idle,
			     uint16_t keepalive_intvl,
			     uint16_t keepalive_probes)
{
	int val = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: setsockopt SO_KEEPALIVE (%d): %s",
			     __func__, sock, safe_strerror(errno));
		return -1;
	}

#if defined __OpenBSD__
	return 0;
#else
	/* Send first probe after keepalive_idle seconds */
	val = keepalive_idle;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) <
	    0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: setsockopt TCP_KEEPIDLE (%d): %s",
			     __func__, sock, safe_strerror(errno));
		return -1;
	}

	/* Set interval between two probes */
	val = keepalive_intvl;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) <
	    0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: setsockopt TCP_KEEPINTVL (%d): %s",
			     __func__, sock, safe_strerror(errno));
		return -1;
	}

	/* Set maximum probes */
	val = keepalive_probes;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s failed: setsockopt TCP_KEEPCNT (%d): %s",
			     __func__, sock, safe_strerror(errno));
		return -1;
	}

	return 0;
#endif
}
