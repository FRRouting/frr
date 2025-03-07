// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "log.h"
#include "privs.h"
#include "if.h"
#include "vrf.h"
#include "sockopt.h"
#include "lib_errors.h"
#include "network.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_mroute.h"
#include "pim_iface.h"
#include "pim_sock.h"
#include "pim_str.h"

#if PIM_IPV == 4
#define setsockopt_iptos setsockopt_ipv4_tos
#define setsockopt_multicast_loop setsockopt_ipv4_multicast_loop
#else
#define setsockopt_iptos setsockopt_ipv6_tclass
#define setsockopt_multicast_loop setsockopt_ipv6_multicast_loop
#endif

int pim_socket_raw(int protocol)
{
	int fd;

	frr_with_privs(&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, protocol);
	}

	if (fd < 0) {
		zlog_warn("Could not create raw socket: errno=%d: %s", errno,
			  safe_strerror(errno));
		return PIM_SOCK_ERR_SOCKET;
	}

	return fd;
}

void pim_socket_ip_hdr(int fd)
{
	frr_with_privs(&pimd_privs) {
#if PIM_IPV == 4
		const int on = 1;

		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
			zlog_err("%s: Could not turn on IP_HDRINCL option: %m",
				 __func__);
#endif
	}
}

/*
 * Given a socket and a interface,
 * Bind that socket to that interface
 */
int pim_socket_bind(int fd, struct interface *ifp)
{
	int ret = 0;

#ifdef SO_BINDTODEVICE
	frr_with_privs(&pimd_privs) {
		ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifp->name,
				 strlen(ifp->name));
	}
#endif
	return ret;
}

#if PIM_IPV == 4
static inline int pim_setsockopt(int protocol, int fd, struct interface *ifp)
{
	int one = 1;
	int ttl = 1;

#if defined(HAVE_IP_PKTINFO)
	/* Linux and Solaris IP_PKTINFO */
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)))
		zlog_warn("Could not set PKTINFO on socket fd=%d: %m", fd);
#elif defined(HAVE_IP_RECVDSTADDR)
	/* BSD IP_RECVDSTADDR */
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &one, sizeof(one)))
		zlog_warn("Could not set IP_RECVDSTADDR on socket fd=%d: %m",
			  fd);
#else
	flog_err(
		EC_LIB_DEVELOPMENT,
		"Missing IP_PKTINFO and IP_RECVDSTADDR: unable to get dst addr from recvmsg()");
	close(fd);
	return PIM_SOCK_ERR_DSTADDR;
#endif

	/* Set router alert (RFC 2113) for all IGMP messages (RFC
	 * 3376 4. Message Formats)*/
	if (protocol == IPPROTO_IGMP) {
		uint8_t ra[4];

		ra[0] = 148;
		ra[1] = 4;
		ra[2] = 0;
		ra[3] = 0;
		if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, ra, 4)) {
			zlog_warn(
				"Could not set Router Alert Option on socket fd=%d: %m",
				fd);
			close(fd);
			return PIM_SOCK_ERR_RA;
		}
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) {
		zlog_warn("Could not set multicast TTL=%d on socket fd=%d: %m",
			  ttl, fd);
		close(fd);
		return PIM_SOCK_ERR_TTL;
	}

	if (setsockopt_ipv4_multicast_if(fd, PIMADDR_ANY, ifp->ifindex)) {
		zlog_warn(
			"Could not set Outgoing Interface Option on socket fd=%d: %m",
			fd);
		close(fd);
		return PIM_SOCK_ERR_IFACE;
	}

	return 0;
}
#else /* PIM_IPV != 4 */
static inline int pim_setsockopt(int protocol, int fd, struct interface *ifp)
{
	int ttl = 1;
	struct ipv6_mreq mreq = {};

	setsockopt_ipv6_pktinfo(fd, 1);
	setsockopt_ipv6_multicast_hops(fd, ttl);

	mreq.ipv6mr_interface = ifp->ifindex;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mreq,
		       sizeof(mreq))) {
		zlog_warn(
			"Could not set Outgoing Interface Option on socket fd=%d: %m",
			fd);
		close(fd);
		return PIM_SOCK_ERR_IFACE;
	}

	return 0;
}
#endif

int pim_reg_sock(void)
{
	int fd;
	long flags;

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, PIM_PROTO_REG);
	}

	if (fd < 0) {
		zlog_warn("Could not create raw socket: errno=%d: %s", errno,
			  safe_strerror(errno));
		return PIM_SOCK_ERR_SOCKET;
	}

	if (sockopt_reuseaddr(fd)) {
		close(fd);
		return PIM_SOCK_ERR_REUSE;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		zlog_warn(
			"Could not get fcntl(F_GETFL,O_NONBLOCK) on socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_NONBLOCK_GETFL;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		zlog_warn(
			"Could not set fcntl(F_SETFL,O_NONBLOCK) on socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_NONBLOCK_SETFL;
	}

	return fd;
}

int pim_socket_mcast(int protocol, pim_addr ifaddr, struct interface *ifp,
		     uint8_t loop)
{
	int fd;
	int ret;

	fd = pim_socket_raw(protocol);
	if (fd < 0) {
		zlog_warn("Could not create multicast socket: errno=%d: %s",
			  errno, safe_strerror(errno));
		return PIM_SOCK_ERR_SOCKET;
	}

	/* XXX: if SO_BINDTODEVICE isn't available, use IP_PKTINFO / IP_RECVIF
	 * to emulate behaviour?  Or change to only use 1 socket for all
	 * interfaces? */
	ret = pim_socket_bind(fd, ifp);
	if (ret) {
		close(fd);
		zlog_warn("Could not set fd: %d for interface: %s to device",
			  fd, ifp->name);
		return PIM_SOCK_ERR_BIND;
	}

	set_nonblocking(fd);
	sockopt_reuseaddr(fd);
	setsockopt_so_recvbuf(fd, 8 * 1024 * 1024);

	ret = pim_setsockopt(protocol, fd, ifp);
	if (ret) {
		zlog_warn("pim_setsockopt failed for interface: %s to device ",
			  ifp->name);
		return ret;
	}

	/* leftover common sockopts */
	if (setsockopt_multicast_loop(fd, loop)) {
		zlog_warn(
			"Could not %s Multicast Loopback Option on socket fd=%d: %m",
			loop ? "enable" : "disable", fd);
		close(fd);
		return PIM_SOCK_ERR_LOOP;
	}

	/* Set Tx socket DSCP byte */
	if (setsockopt_iptos(fd, IPTOS_PREC_INTERNETCONTROL))
		zlog_warn("can't set sockopt IP[V6]_TOS to socket %d: %m", fd);

	return fd;
}

int pim_socket_join(int fd, pim_addr group, pim_addr ifaddr, ifindex_t ifindex,
		    struct pim_interface *pim_ifp)
{
	int ret;

#if PIM_IPV == 4
	ret = setsockopt_ipv4_multicast(fd, IP_ADD_MEMBERSHIP, ifaddr,
					group.s_addr, ifindex);
#else
	struct ipv6_mreq opt;

	memcpy(&opt.ipv6mr_multiaddr, &group, 16);
	opt.ipv6mr_interface = ifindex;
	ret = setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &opt, sizeof(opt));
#endif

	pim_ifp->igmp_ifstat_joins_sent++;

	if (ret) {
		flog_err(
			EC_LIB_SOCKET,
			"Failure socket joining fd=%d group %pPAs on interface address %pPAs: %m",
			fd, &group, &ifaddr);
		pim_ifp->igmp_ifstat_joins_failed++;
		return ret;
	}

	if (PIM_DEBUG_TRACE)
		zlog_debug(
			"Socket fd=%d joined group %pPAs on interface address %pPAs",
			fd, &group, &ifaddr);
	return ret;
}

int pim_socket_leave(int fd, pim_addr group, pim_addr ifaddr, ifindex_t ifindex,
		     struct pim_interface *pim_ifp)
{
	int ret;

#if PIM_IPV == 4
	ret = setsockopt_ipv4_multicast(fd, IP_DROP_MEMBERSHIP, ifaddr,
					group.s_addr, ifindex);
#else
	struct ipv6_mreq opt;

	memcpy(&opt.ipv6mr_multiaddr, &group, 16);
	opt.ipv6mr_interface = ifindex;
	ret = setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &opt, sizeof(opt));
#endif

	if (ret) {
		flog_err(EC_LIB_SOCKET,
			 "Failure socket leaving fd=%d group %pPAs on interface address %pPAs: %m",
			 fd, &group, &ifaddr);
		pim_ifp->igmp_ifstat_joins_failed++;
		return ret;
	}

	if (PIM_DEBUG_TRACE)
		zlog_debug("Socket fd=%d left group %pPAs on interface address %pPAs",
			   fd, &group, &ifaddr);
	return ret;
}

#if PIM_IPV == 4
static void cmsg_getdstaddr(struct msghdr *mh, struct sockaddr_storage *dst,
			    ifindex_t *ifindex)
{
	struct cmsghdr *cmsg;
	struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(mh, cmsg)) {
#ifdef HAVE_IP_PKTINFO
		if ((cmsg->cmsg_level == IPPROTO_IP) &&
		    (cmsg->cmsg_type == IP_PKTINFO)) {
			struct in_pktinfo *i;

			i = (struct in_pktinfo *)CMSG_DATA(cmsg);
			if (dst4)
				dst4->sin_addr = i->ipi_addr;
			if (ifindex)
				*ifindex = i->ipi_ifindex;

			break;
		}
#endif

#ifdef HAVE_IP_RECVDSTADDR
		if ((cmsg->cmsg_level == IPPROTO_IP) &&
		    (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			struct in_addr *i = (struct in_addr *)CMSG_DATA(cmsg);

			if (dst4)
				dst4->sin_addr = *i;

			break;
		}
#endif

#if defined(HAVE_IP_RECVIF) && defined(CMSG_IFINDEX)
		if (cmsg->cmsg_type == IP_RECVIF)
			if (ifindex)
				*ifindex = CMSG_IFINDEX(cmsg);
#endif
	}
}
#else  /* PIM_IPV != 4 */
static void cmsg_getdstaddr(struct msghdr *mh, struct sockaddr_storage *dst,
			    ifindex_t *ifindex)
{
	struct cmsghdr *cmsg;
	struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(mh, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
		    (cmsg->cmsg_type == IPV6_PKTINFO)) {
			struct in6_pktinfo *i;

			i = (struct in6_pktinfo *)CMSG_DATA(cmsg);

			if (dst6)
				dst6->sin6_addr = i->ipi6_addr;
			if (ifindex)
				*ifindex = i->ipi6_ifindex;
			break;
		}
	}
}
#endif /* PIM_IPV != 4 */

int pim_socket_recvfromto(int fd, uint8_t *buf, size_t len,
			  struct sockaddr_storage *from, socklen_t *fromlen,
			  struct sockaddr_storage *to, socklen_t *tolen,
			  ifindex_t *ifindex)
{
	struct msghdr msgh;
	struct iovec iov;
	char cbuf[1000];
	int err;

	/*
	 * IP_PKTINFO / IP_RECVDSTADDR don't yield sin_port.
	 * Use getsockname() to get sin_port.
	 */
	if (to) {
		socklen_t to_len = sizeof(*to);

		pim_socket_getsockname(fd, (struct sockaddr *)to, &to_len);

		if (tolen)
			*tolen = sizeof(*to);
	}

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len = len;
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_name = from;
	msgh.msg_namelen = fromlen ? *fromlen : 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	err = recvmsg(fd, &msgh, 0);
	if (err < 0)
		return err;

	if (fromlen)
		*fromlen = msgh.msg_namelen;

	cmsg_getdstaddr(&msgh, to, ifindex);

	return err; /* len */
}

int pim_socket_getsockname(int fd, struct sockaddr *name, socklen_t *namelen)
{
	if (getsockname(fd, name, namelen)) {
		int e = errno;
		zlog_warn(
			"Could not get Socket Name for socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		errno = e;
		return PIM_SOCK_ERR_NAME;
	}

	return PIM_SOCK_ERR_NONE;
}
