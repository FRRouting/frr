// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF network related functions
 *   Copyright (C) 1999 Toshiaki Takada
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "sockunion.h"
#include "log.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"
#include "lib/table.h"

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
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllSPFRouters): %s; perhaps a kernel limit on # of multicast group memberships has been exceeded?",
			top->fd, &p->u.prefix4, ifindex,
			safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %pI4 [%u] join AllSPFRouters Multicast group.",
				&p->u.prefix4, ifindex);
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
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllSPFRouters): %s",
			 top->fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %pI4 [%u] leave AllSPFRouters Multicast group.",
				&p->u.prefix4, ifindex);
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
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllDRouters): %s; perhaps a kernel limit on # of multicast group memberships has been exceeded?",
			top->fd, &p->u.prefix4, ifindex,
			safe_strerror(errno));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"interface %pI4 [%u] join AllDRouters Multicast group.",
				&p->u.prefix4, ifindex);
	}
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
			 "can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %pI4, ifindex %u, AllDRouters): %s",
			 top->fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
	else if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"interface %pI4 [%u] leave AllDRouters Multicast group.",
			&p->u.prefix4, ifindex);

	return ret;
}

int ospf_if_ipmulticast(int fd, struct prefix *p, ifindex_t ifindex)
{
	uint8_t val;
	int ret, len;

	/* Prevent receiving self-origined multicast packets. */
	ret = setsockopt_ipv4_multicast_loop(fd, 0);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_LOOP(0) for fd %d: %s",
			 fd, safe_strerror(errno));

	/* Explicitly set multicast ttl to 1 -- endo. */
	val = 1;
	len = sizeof(val);
	ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&val, len);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_TTL(1) for fd %d: %s",
			 fd, safe_strerror(errno));
#ifndef GNU_LINUX
	/* For GNU LINUX ospf_write uses IP_PKTINFO, in_pktinfo to send
	 * packet out of ifindex. Below would be used Non Linux system.
	 */
	ret = setsockopt_ipv4_multicast_if(fd, p->u.prefix4, ifindex);
	if (ret < 0)
		flog_err(EC_LIB_SOCKET,
			 "can't setsockopt IP_MULTICAST_IF(fd %d, addr %pI4, ifindex %u): %s",
			 fd, &p->u.prefix4, ifindex,
			 safe_strerror(errno));
#endif

	return ret;
}

/*
 * Helper to open and set up a socket; returns the new fd on success,
 * -1 on error.
 */
static int sock_init_common(vrf_id_t vrf_id, const char *name, int proto,
			    int *pfd)
{
	int ospf_sock;
	int ret, hincl = 1;

	if (vrf_id == VRF_UNKNOWN) {
		/* silently return since VRF is not ready */
		return -1;
	}

	frr_with_privs(&ospfd_privs) {
		ospf_sock = vrf_socket(AF_INET, SOCK_RAW, proto, vrf_id, name);
		if (ospf_sock < 0) {
			flog_err(EC_LIB_SOCKET, "%s: socket: %s", __func__,
				 safe_strerror(errno));
			return -1;
		}

#ifdef IP_HDRINCL
		/* we will include IP header with packet */
		ret = setsockopt(ospf_sock, IPPROTO_IP, IP_HDRINCL, &hincl,
				 sizeof(hincl));
		if (ret < 0) {
			flog_err(EC_LIB_SOCKET,
				 "Can't set IP_HDRINCL option for fd %d: %s",
				 ospf_sock, safe_strerror(errno));
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

	*pfd = ospf_sock;

	return ret;
}

/*
 * Update a socket bufsize(s), based on its ospf instance
 */
void ospf_sock_bufsize_update(const struct ospf *ospf, int sock,
			      enum ospf_sock_type_e type)
{
	int bufsize;

	if (type == OSPF_SOCK_BOTH || type == OSPF_SOCK_RECV) {
		bufsize = ospf->recv_sock_bufsize;
		setsockopt_so_recvbuf(sock, bufsize);
	}

	if (type == OSPF_SOCK_BOTH || type == OSPF_SOCK_SEND) {
		bufsize = ospf->send_sock_bufsize;
		setsockopt_so_sendbuf(sock, bufsize);
	}
}

int ospf_sock_init(struct ospf *ospf)
{
	int ret;

	/* silently ignore. already done */
	if (ospf->fd > 0)
		return -1;

	ret = sock_init_common(ospf->vrf_id, ospf->name, IPPROTO_OSPFIGP,
			       &(ospf->fd));

	if (ret >= 0) /* Update socket buffer sizes */
		ospf_sock_bufsize_update(ospf, ospf->fd, OSPF_SOCK_BOTH);

	return ret;
}

/*
 * Open per-interface write socket
 */
int ospf_ifp_sock_init(struct interface *ifp)
{
	struct ospf_if_info *oii;
	struct ospf_interface *oi = NULL;
	struct ospf *ospf = NULL;
	struct route_node *rn;
	int ret;

	oii = IF_OSPF_IF_INFO(ifp);
	if (oii == NULL)
		return -1;

	if (oii->oii_fd > 0)
		return 0;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		if (rn && rn->info) {
			oi = rn->info;
			ospf = oi->ospf;
			break;
		}
	}

	if (ospf == NULL)
		return -1;

	ret = sock_init_common(ifp->vrf->vrf_id, ifp->name, IPPROTO_OSPFIGP,
			       &oii->oii_fd);

	if (ret >= 0) { /* Update socket buffer sizes */
		/* Write-only, so no recv buf */
		setsockopt_so_recvbuf(oii->oii_fd, 0);

		ospf_sock_bufsize_update(ospf, oii->oii_fd, OSPF_SOCK_SEND);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: ifp %s, oii %p, fd %d", __func__, ifp->name,
			   oii, oii->oii_fd);

	return ret;
}

/*
 * Close per-interface write socket
 */
int ospf_ifp_sock_close(struct interface *ifp)
{
	struct ospf_if_info *oii;

	oii = IF_OSPF_IF_INFO(ifp);
	if (oii == NULL)
		return 0;

	if (oii->oii_fd > 0) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: ifp %s, oii %p, fd %d", __func__,
				   ifp->name, oii, oii->oii_fd);

		close(oii->oii_fd);
		oii->oii_fd = -1;
	}

	return 0;
}
