/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

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

#include "pimd.h"
#include "pim_mroute.h"
#include "pim_sock.h"
#include "pim_str.h"

/* GLOBAL VARS */

int pim_socket_raw(int protocol)
{
	int fd;

	frr_with_privs(&pimd_privs) {

		fd = socket(AF_INET, SOCK_RAW, protocol);

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
	const int on = 1;

	frr_with_privs(&pimd_privs) {

		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
			zlog_err("%s: Could not turn on IP_HDRINCL option: %s",
				 __PRETTY_FUNCTION__, safe_strerror(errno));

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

int pim_socket_mcast(int protocol, struct in_addr ifaddr, struct interface *ifp,
		     uint8_t loop)
{
	int rcvbuf = 1024 * 1024 * 8;
#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	struct ip_mreqn mreq;
#else
	struct ip_mreq mreq;
#endif
	int fd;

	fd = pim_socket_raw(protocol);
	if (fd < 0) {
		zlog_warn("Could not create multicast socket: errno=%d: %s",
			  errno, safe_strerror(errno));
		return PIM_SOCK_ERR_SOCKET;
	}

#ifdef SO_BINDTODEVICE
	if (protocol == IPPROTO_PIM) {
		int ret;

		ret = pim_socket_bind(fd, ifp);
		if (ret) {
			close(fd);
			zlog_warn(
				"Could not set fd: %d for interface: %s to device",
				fd, ifp->name);
			return PIM_SOCK_ERR_BIND;
		}
	}
#else
/* XXX: use IP_PKTINFO / IP_RECVIF to emulate behaviour?  Or change to
 * only use 1 socket for all interfaces? */
#endif

	/* Needed to obtain destination address from recvmsg() */
	{
#if defined(HAVE_IP_PKTINFO)
		/* Linux and Solaris IP_PKTINFO */
		int opt = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt))) {
			zlog_warn(
				"Could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
				fd, errno, safe_strerror(errno));
		}
#elif defined(HAVE_IP_RECVDSTADDR)
		/* BSD IP_RECVDSTADDR */
		int opt = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt,
			       sizeof(opt))) {
			zlog_warn(
				"Could not set IP_RECVDSTADDR on socket fd=%d: errno=%d: %s",
				fd, errno, safe_strerror(errno));
		}
#else
		flog_err(
			EC_LIB_DEVELOPMENT,
			"%s %s: Missing IP_PKTINFO and IP_RECVDSTADDR: unable to get dst addr from recvmsg()",
			__FILE__, __PRETTY_FUNCTION__);
		close(fd);
		return PIM_SOCK_ERR_DSTADDR;
#endif
	}


	/* Set router alert (RFC 2113) for all IGMP messages (RFC 3376 4.
	 * Message Formats)*/
	if (protocol == IPPROTO_IGMP) {
		uint8_t ra[4];
		ra[0] = 148;
		ra[1] = 4;
		ra[2] = 0;
		ra[3] = 0;
		if (setsockopt(fd, IPPROTO_IP, IP_OPTIONS, ra, 4)) {
			zlog_warn(
				"Could not set Router Alert Option on socket fd=%d: errno=%d: %s",
				fd, errno, safe_strerror(errno));
			close(fd);
			return PIM_SOCK_ERR_RA;
		}
	}

	{
		int reuse = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse,
			       sizeof(reuse))) {
			zlog_warn(
				"Could not set Reuse Address Option on socket fd=%d: errno=%d: %s",
				fd, errno, safe_strerror(errno));
			close(fd);
			return PIM_SOCK_ERR_REUSE;
		}
	}

	{
		const int MTTL = 1;
		int ttl = MTTL;
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl,
			       sizeof(ttl))) {
			zlog_warn(
				"Could not set multicast TTL=%d on socket fd=%d: errno=%d: %s",
				MTTL, fd, errno, safe_strerror(errno));
			close(fd);
			return PIM_SOCK_ERR_TTL;
		}
	}

	if (setsockopt_ipv4_multicast_loop(fd, loop)) {
		zlog_warn(
			"Could not %s Multicast Loopback Option on socket fd=%d: errno=%d: %s",
			loop ? "enable" : "disable", fd, errno,
			safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_LOOP;
	}

	memset(&mreq, 0, sizeof(mreq));
#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	mreq.imr_ifindex = ifp->ifindex;
#else
/*
 * I am not sure what to do here yet for *BSD
 */
// mreq.imr_interface = ifindex;
#endif

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (void *)&mreq,
		       sizeof(mreq))) {
		zlog_warn(
			"Could not set Outgoing Interface Option on socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_IFACE;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)))
		zlog_warn("%s: Failure to set buffer size to %d",
			  __PRETTY_FUNCTION__, rcvbuf);

	{
		long flags;

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
	}

	/* Set Tx socket DSCP byte */
	if (setsockopt_ipv4_tos(fd, IPTOS_PREC_INTERNETCONTROL)) {
		zlog_warn("can't set sockopt IP_TOS to PIM/IGMP socket %d: %s",
			  fd, safe_strerror(errno));
	}

	return fd;
}

int pim_socket_join(int fd, struct in_addr group, struct in_addr ifaddr,
		    ifindex_t ifindex)
{
	int ret;

#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	struct ip_mreqn opt;
#else
	struct ip_mreq opt;
#endif

	opt.imr_multiaddr = group;

#ifdef HAVE_STRUCT_IP_MREQN_IMR_IFINDEX
	opt.imr_address = ifaddr;
	opt.imr_ifindex = ifindex;
#else
	opt.imr_interface = ifaddr;
#endif

	ret = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &opt, sizeof(opt));
	if (ret) {
		char group_str[INET_ADDRSTRLEN];
		char ifaddr_str[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, &group, group_str, sizeof(group_str)))
			sprintf(group_str, "<group?>");
		if (!inet_ntop(AF_INET, &ifaddr, ifaddr_str,
			       sizeof(ifaddr_str)))
			sprintf(ifaddr_str, "<ifaddr?>");

		flog_err(
			EC_LIB_SOCKET,
			"Failure socket joining fd=%d group %s on interface address %s: errno=%d: %s",
			fd, group_str, ifaddr_str, errno, safe_strerror(errno));
		return ret;
	}

	if (PIM_DEBUG_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		char ifaddr_str[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, &group, group_str, sizeof(group_str)))
			sprintf(group_str, "<group?>");
		if (!inet_ntop(AF_INET, &ifaddr, ifaddr_str,
			       sizeof(ifaddr_str)))
			sprintf(ifaddr_str, "<ifaddr?>");

		zlog_debug(
			"Socket fd=%d joined group %s on interface address %s",
			fd, group_str, ifaddr_str);
	}

	return ret;
}

int pim_socket_recvfromto(int fd, uint8_t *buf, size_t len,
			  struct sockaddr_in *from, socklen_t *fromlen,
			  struct sockaddr_in *to, socklen_t *tolen,
			  ifindex_t *ifindex)
{
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[1000];
	int err;

	/*
	 * IP_PKTINFO / IP_RECVDSTADDR don't yield sin_port.
	 * Use getsockname() to get sin_port.
	 */
	if (to) {
		struct sockaddr_in si;
		socklen_t si_len = sizeof(si);

		memset(&si, 0, sizeof(si));
		to->sin_family = AF_INET;

		pim_socket_getsockname(fd, (struct sockaddr *)&si, &si_len);

		to->sin_port = si.sin_port;
		to->sin_addr = si.sin_addr;

		if (tolen)
			*tolen = sizeof(si);
	}

	memset(&msgh, 0, sizeof(struct msghdr));
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

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msgh, cmsg)) {

#ifdef HAVE_IP_PKTINFO
		if ((cmsg->cmsg_level == IPPROTO_IP)
		    && (cmsg->cmsg_type == IP_PKTINFO)) {
			struct in_pktinfo *i =
				(struct in_pktinfo *)CMSG_DATA(cmsg);
			if (to)
				((struct sockaddr_in *)to)->sin_addr =
					i->ipi_addr;
			if (tolen)
				*tolen = sizeof(struct sockaddr_in);
			if (ifindex)
				*ifindex = i->ipi_ifindex;

			break;
		}
#endif

#ifdef HAVE_IP_RECVDSTADDR
		if ((cmsg->cmsg_level == IPPROTO_IP)
		    && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			struct in_addr *i = (struct in_addr *)CMSG_DATA(cmsg);
			if (to)
				((struct sockaddr_in *)to)->sin_addr = *i;
			if (tolen)
				*tolen = sizeof(struct sockaddr_in);

			break;
		}
#endif

#if defined(HAVE_IP_RECVIF) && defined(CMSG_IFINDEX)
		if (cmsg->cmsg_type == IP_RECVIF)
			if (ifindex)
				*ifindex = CMSG_IFINDEX(cmsg);
#endif

	} /* for (cmsg) */

	return err; /* len */
}

int pim_socket_mcastloop_get(int fd)
{
	int loop;
	socklen_t loop_len = sizeof(loop);

	if (getsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, &loop_len)) {
		int e = errno;
		zlog_warn(
			"Could not get Multicast Loopback Option on socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		errno = e;
		return PIM_SOCK_ERR_LOOP;
	}

	return loop;
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
