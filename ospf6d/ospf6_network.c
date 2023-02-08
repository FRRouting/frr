// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "sockunion.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"
#include "vrf.h"

#include "libospf.h"
#include "ospf6_proto.h"
#include "ospf6_top.h"
#include "ospf6_network.h"
#include "ospf6d.h"
#include "ospf6_message.h"

struct in6_addr allspfrouters6;
struct in6_addr alldrouters6;

/* setsockopt MulticastLoop to off */
static void ospf6_reset_mcastloop(int ospf6_sock)
{
	unsigned int off = 0;
	if (setsockopt(ospf6_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off,
		       sizeof(unsigned int))
	    < 0)
		zlog_warn("Network: reset IPV6_MULTICAST_LOOP failed: %s",
			  safe_strerror(errno));
}

static void ospf6_set_pktinfo(int ospf6_sock)
{
	setsockopt_ipv6_pktinfo(ospf6_sock, 1);
}

static void ospf6_set_transport_class(int ospf6_sock)
{
#ifdef IPTOS_PREC_INTERNETCONTROL
	setsockopt_ipv6_tclass(ospf6_sock, IPTOS_PREC_INTERNETCONTROL);
#endif
}

void ospf6_serv_close(int *ospf6_sock)
{
	if (*ospf6_sock != -1) {
		close(*ospf6_sock);
		*ospf6_sock = -1;
		return;
	}
}

/* Make ospf6d's server socket. */
int ospf6_serv_sock(struct ospf6 *ospf6)
{
	int ospf6_sock;

	if (ospf6->fd != -1)
		return -1;

	if (ospf6->vrf_id == VRF_UNKNOWN)
		return -1;

	frr_with_privs(&ospf6d_privs) {

		ospf6_sock = vrf_socket(AF_INET6, SOCK_RAW, IPPROTO_OSPFIGP,
					ospf6->vrf_id, ospf6->name);
		if (ospf6_sock < 0) {
			zlog_warn("Network: can't create OSPF6 socket.");
			return -1;
		}
	}

/* set socket options */
#if 1
	sockopt_reuseaddr(ospf6_sock);
#else
	ospf6_set_reuseaddr();
#endif /*1*/
	ospf6_reset_mcastloop(ospf6_sock);
	ospf6_set_pktinfo(ospf6_sock);
	ospf6_set_transport_class(ospf6_sock);

	ospf6->fd = ospf6_sock;
	/* setup global in6_addr, allspf6 and alldr6 for later use */
	inet_pton(AF_INET6, ALLSPFROUTERS6, &allspfrouters6);
	inet_pton(AF_INET6, ALLDROUTERS6, &alldrouters6);

	return 0;
}

/* ospf6 set socket option */
int ospf6_sso(ifindex_t ifindex, struct in6_addr *group, int option, int sockfd)
{
	struct ipv6_mreq mreq6;
	int ret;
	int bufsize = (8 * 1024 * 1024);

	if (sockfd == -1)
		return -1;

	assert(ifindex);
	mreq6.ipv6mr_interface = ifindex;
	memcpy(&mreq6.ipv6mr_multiaddr, group, sizeof(struct in6_addr));

	ret = setsockopt(sockfd, IPPROTO_IPV6, option, &mreq6, sizeof(mreq6));
	if (ret < 0) {
		flog_err_sys(
			EC_LIB_SOCKET,
			"Network: setsockopt (%d) on ifindex %d failed: %s",
			option, ifindex, safe_strerror(errno));
		return ret;
	}

	setsockopt_so_sendbuf(sockfd, bufsize);
	setsockopt_so_recvbuf(sockfd, bufsize);

	return 0;
}

static int iov_count(struct iovec *iov)
{
	int i;
	for (i = 0; iov[i].iov_base; i++)
		;
	return i;
}

static int iov_totallen(struct iovec *iov)
{
	int i;
	int totallen = 0;
	for (i = 0; iov[i].iov_base; i++)
		totallen += iov[i].iov_len;
	return totallen;
}

int ospf6_sendmsg(struct in6_addr *src, struct in6_addr *dst,
		  ifindex_t ifindex, struct iovec *message, int ospf6_sock)
{
	int retval;
	struct msghdr smsghdr;
	struct cmsghdr *scmsgp;
	union {
		struct cmsghdr hdr;
		uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} cmsgbuf;
	struct in6_pktinfo *pktinfo;
	struct sockaddr_in6 dst_sin6;

	assert(dst);

	memset(&cmsgbuf, 0, sizeof(cmsgbuf));
	scmsgp = (struct cmsghdr *)&cmsgbuf;
	pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
	memset(&dst_sin6, 0, sizeof(dst_sin6));

	/* source address */
	pktinfo->ipi6_ifindex = ifindex;
	if (src)
		memcpy(&pktinfo->ipi6_addr, src, sizeof(struct in6_addr));
	else
		memset(&pktinfo->ipi6_addr, 0, sizeof(struct in6_addr));

	/* destination address */
	dst_sin6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	dst_sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /*SIN6_LEN*/
	memcpy(&dst_sin6.sin6_addr, dst, sizeof(struct in6_addr));
	dst_sin6.sin6_scope_id = ifindex;

	/* send control msg */
	scmsgp->cmsg_level = IPPROTO_IPV6;
	scmsgp->cmsg_type = IPV6_PKTINFO;
	scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	/* scmsgp = CMSG_NXTHDR (&smsghdr, scmsgp); */

	/* send msg hdr */
	memset(&smsghdr, 0, sizeof(smsghdr));
	smsghdr.msg_iov = message;
	smsghdr.msg_iovlen = iov_count(message);
	smsghdr.msg_name = (caddr_t)&dst_sin6;
	smsghdr.msg_namelen = sizeof(struct sockaddr_in6);
	smsghdr.msg_control = (caddr_t)&cmsgbuf.buf;
	smsghdr.msg_controllen = sizeof(cmsgbuf.buf);

	retval = sendmsg(ospf6_sock, &smsghdr, 0);
	if (retval != iov_totallen(message))
		zlog_warn("sendmsg failed: source: %pI6 Dest: %pI6 ifindex: %d: %s (%d)",
			  src, dst, ifindex,
			  safe_strerror(errno), errno);

	return retval;
}

int ospf6_recvmsg(struct in6_addr *src, struct in6_addr *dst,
		  ifindex_t *ifindex, struct iovec *message, int ospf6_sock)
{
	int retval;
	struct msghdr rmsghdr;
	struct cmsghdr *rcmsgp;
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct in6_pktinfo *pktinfo;
	struct sockaddr_in6 src_sin6;

	rcmsgp = (struct cmsghdr *)cmsgbuf;
	pktinfo = (struct in6_pktinfo *)(CMSG_DATA(rcmsgp));
	memset(&src_sin6, 0, sizeof(src_sin6));

	/* receive control msg */
	rcmsgp->cmsg_level = IPPROTO_IPV6;
	rcmsgp->cmsg_type = IPV6_PKTINFO;
	rcmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	/* rcmsgp = CMSG_NXTHDR (&rmsghdr, rcmsgp); */

	/* receive msg hdr */
	memset(&rmsghdr, 0, sizeof(rmsghdr));
	rmsghdr.msg_iov = message;
	rmsghdr.msg_iovlen = iov_count(message);
	rmsghdr.msg_name = (caddr_t)&src_sin6;
	rmsghdr.msg_namelen = sizeof(struct sockaddr_in6);
	rmsghdr.msg_control = (caddr_t)cmsgbuf;
	rmsghdr.msg_controllen = sizeof(cmsgbuf);

	retval = recvmsg(ospf6_sock, &rmsghdr, MSG_DONTWAIT);
	if (retval < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			zlog_warn("stream_recvmsg failed: %s",
				  safe_strerror(errno));
		return retval;
	} else if (retval == iov_totallen(message))
		zlog_warn("recvmsg read full buffer size: %d", retval);

	/* source address */
	assert(src);
	memcpy(src, &src_sin6.sin6_addr, sizeof(struct in6_addr));

	/* destination address */
	if (ifindex)
		*ifindex = pktinfo->ipi6_ifindex;
	if (dst)
		memcpy(dst, &pktinfo->ipi6_addr, sizeof(struct in6_addr));

	return retval;
}
