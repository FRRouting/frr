/*
 * OSPF network related functions
 *   Copyright (C) 1999 Toshiaki Takada
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

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "sockunion.h"
#include "log.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"

/* Join to the OSPF ALL SPF ROUTERS multicast group. */
int ospf_if_add_allspfrouters(struct ospf *top, struct prefix *p,
			      ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_ADD_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLSPFROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(
			EC_LIB_SOCKET,
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %s, "
			"ifindex %u, AllSPFRouters): %s; perhaps a kernel limit "
			"on # of multicast group memberships has been exceeded?",
			top->fd, inet_ntoa(p->u.prefix4), ifindex,
			safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %s [%u] join AllSPFRouters Multicast group.",
				inet_ntoa(p->u.prefix4), ifindex);
	}

	return ret;
}

int ospf_if_drop_allspfrouters(struct ospf *top, struct prefix *p,
			       ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_DROP_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLSPFROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %s, "
			 "ifindex %u, AllSPFRouters): %s",
			 top->fd, inet_ntoa(p->u.prefix4), ifindex,
			 safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %s [%u] leave AllSPFRouters Multicast group.",
				inet_ntoa(p->u.prefix4), ifindex);
	}

	return ret;
}

/* Join to the OSPF ALL Designated ROUTERS multicast group. */
int ospf_if_add_alldrouters(struct ospf *top, struct prefix *p,
			    ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_ADD_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLDROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(
			EC_LIB_SOCKET,
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %s, "
			"ifindex %u, AllDRouters): %s; perhaps a kernel limit "
			"on # of multicast group memberships has been exceeded?",
			top->fd, inet_ntoa(p->u.prefix4), ifindex,
			safe_strerror(errno));
	else
		zlog_debug(
			"interface %s [%u] join AllDRouters Multicast group.",
			inet_ntoa(p->u.prefix4), ifindex);

	return ret;
}

int ospf_if_drop_alldrouters(struct ospf *top, struct prefix *p,
			     ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(top->fd, IP_DROP_MEMBERSHIP,
					p->u.prefix4, htonl(OSPF_ALLDROUTERS),
					ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %s, "
			 "ifindex %u, AllDRouters): %s",
			 top->fd, inet_ntoa(p->u.prefix4), ifindex,
			 safe_strerror(errno));
	else
		zlog_debug(
			"interface %s [%u] leave AllDRouters Multicast group.",
			inet_ntoa(p->u.prefix4), ifindex);

	return ret;
}

int ospf_if_ipmulticast(struct ospf *top, struct prefix *p, ifindex_t ifindex)
{
	uint8_t val;
	int ret, len;

	/* Prevent receiving self-origined multicast packets. */
	ret = setsockopt_ipv4_multicast_loop(top->fd, 0);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_LOOP(0) for fd %d: %s",
			 top->fd, safe_strerror(errno));

	/* Explicitly set multicast ttl to 1 -- endo. */
	val = 1;
	len = sizeof(val);
	ret = setsockopt(top->fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&val,
			 len);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_TTL(1) for fd %d: %s",
			 top->fd, safe_strerror(errno));
#ifndef GNU_LINUX
	/* For GNU LINUX ospf_write uses IP_PKTINFO, in_pktinfo to send
	 * packet out of ifindex. Below would be used Non Linux system.
	 */
	ret = setsockopt_ipv4_multicast_if(top->fd, p->u.prefix4, ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_IF(fd %d, addr %s, "
			 "ifindex %u): %s",
			 top->fd, inet_ntoa(p->u.prefix4), ifindex,
			 safe_strerror(errno));
#endif

	return ret;
}

int ospf_sock_init(struct ospf *ospf)
{
	int ospf_sock;
	int ret, hincl = 1;
	int bufsize = (8 * 1024 * 1024);

	/* silently ignore. already done */
	if (ospf->fd > 0)
		return -1;

	if (ospf->vrf_id == VRF_UNKNOWN) {
		/* silently return since VRF is not ready */
		return -1;
	}
	frr_with_privs(&ospfd_privs) {
		ospf_sock = vrf_socket(AF_INET, SOCK_RAW, IPPROTO_OSPFIGP,
				       ospf->vrf_id, ospf->name);
		if (ospf_sock < 0) {
			flog_err(EC_LIB_SOCKET,
				 "ospf_read_sock_init: socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

#ifdef IP_HDRINCL
		/* we will include IP header with packet */
		ret = setsockopt(ospf_sock, IPPROTO_IP, IP_HDRINCL, &hincl,
				 sizeof(hincl));
		if (ret < 0) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 ospf_sock, safe_strerror(errno));
			close(ospf_sock);
			break;
		}
#elif defined(IPTOS_PREC_INTERNETCONTROL)
#warning "IP_HDRINCL not available on this system"
#warning "using IPTOS_PREC_INTERNETCONTROL"
		ret = setsockopt_ipv4_tos(ospf_sock,
					  IPTOS_PREC_INTERNETCONTROL);
		if (ret < 0) {
			flog_err(EC_LIB_SOCKET,
				 "can't set sockopt IP_TOS %d to socket %d: %s",
				 tos, ospf_sock, safe_strerror(errno));
			close(ospf_sock); /* Prevent sd leak. */
			break;
		}
#else /* !IPTOS_PREC_INTERNETCONTROL */
#warning "IP_HDRINCL not available, nor is IPTOS_PREC_INTERNETCONTROL"
		flog_err(EC_LIB_UNAVAILABLE, "IP_HDRINCL option not available");
#endif /* IP_HDRINCL */

		ret = setsockopt_ifindex(AF_INET, ospf_sock, 1);

		if (ret < 0)
			flog_err(EC_LIB_SOCKET,
				 "Can't set pktinfo option for fd %d",
				 ospf_sock);
	}

	setsockopt_so_sendbuf(ospf_sock, bufsize);
	setsockopt_so_recvbuf(ospf_sock, bufsize);

	ospf->fd = ospf_sock;
	return ret;
}
