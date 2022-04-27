/*
 *
 * Copyright (C) 2000  Robert Olsson.
 * Swedish University of Agricultural Sciences
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

/*
 * This work includes work with the following copywrite:
 *
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
 *
 */

/*
 * Thanks to Jens Laas at Swedish University of Agricultural Sciences
 * for reviewing and tests.
 */


#include <zebra.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "command.h"
#include "connected.h"
#include "if.h"
#include "ioctl.h"
#include "log.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "sockopt.h"
#include "sockunion.h"
#include "sockunion.h"
#include "stream.h"
#include "thread.h"
#include "vty.h"
#include "zclient.h"
#include "lib_errors.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/redistribute.h"
#include "zebra/irdp.h"
#include "zebra/zebra_errors.h"


/* GLOBAL VARS */

int irdp_sock = -1;

extern struct thread *t_irdp_raw;

static void parse_irdp_packet(char *p, int len, struct interface *ifp)
{
	struct ip *ip = (struct ip *)p;
	struct icmphdr *icmp;
	struct in_addr src;
	int ip_hlen, iplen, datalen;
	struct zebra_if *zi;
	struct irdp_interface *irdp;
	uint16_t saved_chksum;
	char buf[PREFIX_STRLEN];

	zi = ifp->info;
	if (!zi)
		return;

	irdp = zi->irdp;
	if (!irdp)
		return;

	ip_hlen = ip->ip_hl << 2;

	sockopt_iphdrincl_swab_systoh(ip);

	iplen = ip->ip_len;
	datalen = len - ip_hlen;
	src = ip->ip_src;

	if (len != iplen) {
		flog_err(EC_ZEBRA_IRDP_LEN_MISMATCH,
			 "IRDP: RX length doesn't match IP length");
		return;
	}

	if (iplen < ICMP_MINLEN) {
		flog_err(EC_ZEBRA_IRDP_LEN_MISMATCH,
			 "IRDP: RX ICMP packet too short from %pI4",
			 &src);
		return;
	}

	/* XXX: RAW doesn't receive link-layer, surely? ??? */
	/* Check so we don't checksum packets longer than oure RX_BUF - (ethlen
	 +
	 len of IP-header) 14+20 */
	if (iplen > IRDP_RX_BUF - 34) {
		flog_err(EC_ZEBRA_IRDP_LEN_MISMATCH,
			 "IRDP: RX ICMP packet too long from %pI4",
			 &src);
		return;
	}

	icmp = (struct icmphdr *)(p + ip_hlen);

	saved_chksum = icmp->checksum;
	icmp->checksum = 0;
	/* check icmp checksum */
	if (in_cksum(icmp, datalen) != saved_chksum) {
		flog_warn(
			EC_ZEBRA_IRDP_BAD_CHECKSUM,
			"IRDP: RX ICMP packet from %pI4 Bad checksum, silently ignored",
			&src);
		return;
	}

	/* Handle just only IRDP */
	if (!(icmp->type == ICMP_ROUTERADVERT
	      || icmp->type == ICMP_ROUTERSOLICIT))
		return;

	if (icmp->code != 0) {
		flog_warn(
			EC_ZEBRA_IRDP_BAD_TYPE_CODE,
			"IRDP: RX packet type %d from %pI4 Bad ICMP type code, silently ignored",
			icmp->type, &src);
		return;
	}

	if (!((ntohl(ip->ip_dst.s_addr) == INADDR_BROADCAST)
	      && (irdp->flags & IF_BROADCAST))
	    || (ntohl(ip->ip_dst.s_addr) == INADDR_ALLRTRS_GROUP
		&& !(irdp->flags & IF_BROADCAST))) {
		flog_warn(
			EC_ZEBRA_IRDP_BAD_RX_FLAGS,
			"IRDP: RX illegal from %pI4 to %s while %s operates in %s; Please correct settings",
			&src,
			ntohl(ip->ip_dst.s_addr) == INADDR_ALLRTRS_GROUP
				? "multicast"
				: inet_ntop(AF_INET, &ip->ip_dst,
					    buf, sizeof(buf)),
			ifp->name,
			irdp->flags & IF_BROADCAST ? "broadcast" : "multicast");
		return;
	}

	switch (icmp->type) {
	case ICMP_ROUTERADVERT:
		break;

	case ICMP_ROUTERSOLICIT:

		if (irdp->flags & IF_DEBUG_MESSAGES)
			zlog_debug("IRDP: RX Solicit on %s from %pI4",
				   ifp->name, &src);

		process_solicit(ifp);
		break;

	default:
		flog_warn(
			EC_ZEBRA_IRDP_BAD_TYPE_CODE,
			"IRDP: RX packet type %d from %pI4 Bad ICMP type code, silently ignored",
			icmp->type, &src);
	}
}

static int irdp_recvmsg(int sock, uint8_t *buf, int size, int *ifindex)
{
	struct msghdr msg;
	struct iovec iov;
	char adata[CMSG_SPACE(SOPT_SIZE_CMSG_PKTINFO_IPV4())];
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = sizeof(adata);

	iov.iov_base = buf;
	iov.iov_len = size;

	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		flog_warn(EC_LIB_SOCKET, "IRDP: recvmsg: read error %s",
			  safe_strerror(errno));
		return ret;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		flog_warn(EC_LIB_SOCKET, "IRDP: recvmsg: truncated message");
		return ret;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		flog_warn(EC_LIB_SOCKET,
			  "IRDP: recvmsg: truncated control message");
		return ret;
	}

	*ifindex = getsockopt_ifindex(AF_INET, &msg);

	return ret;
}

void irdp_read_raw(struct thread *r)
{
	struct interface *ifp;
	struct zebra_if *zi;
	struct irdp_interface *irdp;
	char buf[IRDP_RX_BUF];
	int ret, ifindex = 0;

	int irdp_sock = THREAD_FD(r);
	thread_add_read(zrouter.master, irdp_read_raw, NULL, irdp_sock,
			&t_irdp_raw);

	ret = irdp_recvmsg(irdp_sock, (uint8_t *)buf, IRDP_RX_BUF, &ifindex);

	if (ret < 0)
		flog_warn(EC_LIB_SOCKET, "IRDP: RX Error length = %d", ret);

	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
	if (!ifp)
		return;

	zi = ifp->info;
	if (!zi)
		return;

	irdp = zi->irdp;
	if (!irdp)
		return;

	if (!(irdp->flags & IF_ACTIVE)) {

		if (irdp->flags & IF_DEBUG_MISC)
			zlog_debug("IRDP: RX ICMP for disabled interface %s",
				   ifp->name);
		return;
	}

	if (irdp->flags & IF_DEBUG_PACKET) {
		int i;
		zlog_debug("IRDP: RX (idx %d) ", ifindex);
		for (i = 0; i < ret; i++)
			zlog_debug("IRDP: RX %x ", buf[i] & 0xFF);
	}

	parse_irdp_packet(buf, ret, ifp);
}

void send_packet(struct interface *ifp, struct stream *s, uint32_t dst,
		 struct prefix *p, uint32_t ttl)
{
	static struct sockaddr_in sockdst = {AF_INET};
	struct ip *ip;
	struct icmphdr *icmp;
	struct msghdr *msg;
	struct cmsghdr *cmsg;
	struct iovec iovector;
	char msgbuf[256];
	char buf[256];
	struct in_pktinfo *pktinfo;
	unsigned long src;
	uint8_t on;

	if (!(ifp->flags & IFF_UP))
		return;

	if (p)
		src = ntohl(p->u.prefix4.s_addr);
	else
		src = 0; /* Is filled in */

	ip = (struct ip *)buf;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_v = IPVERSION;
	ip->ip_tos = 0xC0;
	ip->ip_off = 0L;
	ip->ip_p = 1; /* IP_ICMP */
	ip->ip_ttl = ttl;
	ip->ip_src.s_addr = src;
	ip->ip_dst.s_addr = dst;
	icmp = (struct icmphdr *)(buf + sizeof(struct ip));

	/* Merge IP header with icmp packet */
	assert(stream_get_endp(s) < (sizeof(buf) - sizeof(struct ip)));
	stream_get(icmp, s, stream_get_endp(s));

	/* icmp->checksum is already calculated */
	ip->ip_len = sizeof(struct ip) + stream_get_endp(s);

	on = 1;
	if (setsockopt(irdp_sock, IPPROTO_IP, IP_HDRINCL, (char *)&on,
		       sizeof(on))
	    < 0)
		flog_err(EC_LIB_SOCKET,
			 "IRDP: Cannot set IP_HDRINCLU %s(%d) on %s",
			 safe_strerror(errno), errno, ifp->name);


	if (dst == INADDR_BROADCAST) {
		uint32_t bon = 1;

		if (setsockopt(irdp_sock, SOL_SOCKET, SO_BROADCAST, &bon,
			       sizeof(bon))
		    < 0)
			flog_err(EC_LIB_SOCKET,
				 "IRDP: Cannot set SO_BROADCAST %s(%d) on %s",
				 safe_strerror(errno), errno, ifp->name);
	}

	if (dst != INADDR_BROADCAST)
		setsockopt_ipv4_multicast_loop(irdp_sock, 0);

	memset(&sockdst, 0, sizeof(sockdst));
	sockdst.sin_family = AF_INET;
	sockdst.sin_addr.s_addr = dst;

	cmsg = (struct cmsghdr *)(msgbuf + sizeof(struct msghdr));
	cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(struct in_pktinfo);
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
	pktinfo->ipi_ifindex = ifp->ifindex;
	pktinfo->ipi_spec_dst.s_addr = src;
	pktinfo->ipi_addr.s_addr = src;

	iovector.iov_base = (void *)buf;
	iovector.iov_len = ip->ip_len;
	msg = (struct msghdr *)msgbuf;
	msg->msg_name = &sockdst;
	msg->msg_namelen = sizeof(sockdst);
	msg->msg_iov = &iovector;
	msg->msg_iovlen = 1;
	msg->msg_control = cmsg;
	msg->msg_controllen = cmsg->cmsg_len;

	sockopt_iphdrincl_swab_htosys(ip);

	if (sendmsg(irdp_sock, msg, 0) < 0)
		flog_err(EC_LIB_SOCKET,
			 "IRDP: sendmsg send failure %s(%d) on %s",
			 safe_strerror(errno), errno, ifp->name);
}
