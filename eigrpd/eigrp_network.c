/*
 * EIGRP Network Related Functions.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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
#include "table.h"
#include "vty.h"
#include "lib_errors.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"

static int eigrp_network_match_iface(const struct prefix *connected_prefix,
				     const struct prefix *prefix);
static void eigrp_network_run_interface(struct eigrp *, struct prefix *,
					struct interface *);

int eigrp_sock_init(struct vrf *vrf)
{
	int eigrp_sock = -1;
	int ret;
#ifdef IP_HDRINCL
	int hincl = 1;
#endif

	if (!vrf)
		return eigrp_sock;

	frr_with_privs(&eigrpd_privs) {
		eigrp_sock = vrf_socket(
			AF_INET, SOCK_RAW, IPPROTO_EIGRPIGP, vrf->vrf_id,
			vrf->vrf_id != VRF_DEFAULT ? vrf->name : NULL);
		if (eigrp_sock < 0) {
			zlog_err("eigrp_read_sock_init: socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

#ifdef IP_HDRINCL
		/* we will include IP header with packet */
		ret = setsockopt(eigrp_sock, IPPROTO_IP, IP_HDRINCL, &hincl,
				 sizeof(hincl));
		if (ret < 0) {
			zlog_warn("Can't set IP_HDRINCL option for fd %d: %s",
				  eigrp_sock, safe_strerror(errno));
		}
#elif defined(IPTOS_PREC_INTERNETCONTROL)
#warning "IP_HDRINCL not available on this system"
#warning "using IPTOS_PREC_INTERNETCONTROL"
		ret = setsockopt_ipv4_tos(eigrp_sock,
					  IPTOS_PREC_INTERNETCONTROL);
		if (ret < 0) {
			zlog_warn("can't set sockopt IP_TOS %d to socket %d: %s",
				  tos, eigrp_sock, safe_strerror(errno));
			close(eigrp_sock); /* Prevent sd leak. */
			return ret;
		}
#else /* !IPTOS_PREC_INTERNETCONTROL */
#warning "IP_HDRINCL not available, nor is IPTOS_PREC_INTERNETCONTROL"
		zlog_warn("IP_HDRINCL option not available");
#endif /* IP_HDRINCL */

		ret = setsockopt_ifindex(AF_INET, eigrp_sock, 1);
		if (ret < 0)
			zlog_warn("Can't set pktinfo option for fd %d",
				  eigrp_sock);
	}

	return eigrp_sock;
}

void eigrp_adjust_sndbuflen(struct eigrp *eigrp, unsigned int buflen)
{
	int newbuflen;
	/* Check if any work has to be done at all. */
	if (eigrp->maxsndbuflen >= buflen)
		return;

	/* Now we try to set SO_SNDBUF to what our caller has requested
	 * (the MTU of a newly added interface). However, if the OS has
	 * truncated the actual buffer size to somewhat less size, try
	 * to detect it and update our records appropriately. The OS
	 * may allocate more buffer space, than requested, this isn't
	 * a error.
	 */
	setsockopt_so_sendbuf(eigrp->fd, buflen);
	newbuflen = getsockopt_so_sendbuf(eigrp->fd);
	if (newbuflen < 0 || newbuflen < (int)buflen)
		zlog_warn("%s: tried to set SO_SNDBUF to %u, but got %d",
			  __func__, buflen, newbuflen);
	if (newbuflen >= 0)
		eigrp->maxsndbuflen = (unsigned int)newbuflen;
	else
		zlog_warn("%s: failed to get SO_SNDBUF", __func__);
}

int eigrp_if_ipmulticast(struct eigrp *top, struct prefix *p,
			 unsigned int ifindex)
{
	uint8_t val;
	int ret, len;

	val = 0;
	len = sizeof(val);

	/* Prevent receiving self-origined multicast packets. */
	ret = setsockopt(top->fd, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&val,
			 len);
	if (ret < 0)
		zlog_warn(
			"can't setsockopt IP_MULTICAST_LOOP (0) for fd %d: %s",
			top->fd, safe_strerror(errno));

	/* Explicitly set multicast ttl to 1 -- endo. */
	val = 1;
	ret = setsockopt(top->fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&val,
			 len);
	if (ret < 0)
		zlog_warn("can't setsockopt IP_MULTICAST_TTL (1) for fd %d: %s",
			  top->fd, safe_strerror(errno));

	ret = setsockopt_ipv4_multicast_if(top->fd, p->u.prefix4, ifindex);
	if (ret < 0)
		zlog_warn(
			"can't setsockopt IP_MULTICAST_IF (fd %d, addr %s, "
			"ifindex %u): %s",
			top->fd, inet_ntoa(p->u.prefix4), ifindex,
			safe_strerror(errno));

	return ret;
}

/* Join to the EIGRP multicast group. */
int eigrp_if_add_allspfrouters(struct eigrp *top, struct prefix *p,
			       unsigned int ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(
		top->fd, IP_ADD_MEMBERSHIP, p->u.prefix4,
		htonl(EIGRP_MULTICAST_ADDRESS), ifindex);
	if (ret < 0)
		zlog_warn(
			"can't setsockopt IP_ADD_MEMBERSHIP (fd %d, addr %s, "
			"ifindex %u, AllSPFRouters): %s; perhaps a kernel limit "
			"on # of multicast group memberships has been exceeded?",
			top->fd, inet_ntoa(p->u.prefix4), ifindex,
			safe_strerror(errno));
	else
		zlog_debug("interface %s [%u] join EIGRP Multicast group.",
			   inet_ntoa(p->u.prefix4), ifindex);

	return ret;
}

int eigrp_if_drop_allspfrouters(struct eigrp *top, struct prefix *p,
				unsigned int ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(
		top->fd, IP_DROP_MEMBERSHIP, p->u.prefix4,
		htonl(EIGRP_MULTICAST_ADDRESS), ifindex);
	if (ret < 0)
		zlog_warn(
			"can't setsockopt IP_DROP_MEMBERSHIP (fd %d, addr %s, "
			"ifindex %u, AllSPFRouters): %s",
			top->fd, inet_ntoa(p->u.prefix4), ifindex,
			safe_strerror(errno));
	else
		zlog_debug("interface %s [%u] leave EIGRP Multicast group.",
			   inet_ntoa(p->u.prefix4), ifindex);

	return ret;
}

int eigrp_network_set(struct eigrp *eigrp, struct prefix *p)
{
	struct vrf *vrf = vrf_lookup_by_id(eigrp->vrf_id);
	struct route_node *rn;
	struct interface *ifp;

	rn = route_node_get(eigrp->networks, (struct prefix *)p);
	if (rn->info) {
		/* There is already same network statement. */
		route_unlock_node(rn);
		return 0;
	}

	struct prefix *pref = prefix_new();
	PREFIX_COPY_IPV4(pref, p);
	rn->info = (void *)pref;

	/* Schedule Router ID Update. */
	if (eigrp->router_id.s_addr == 0)
		eigrp_router_id_update(eigrp);
	/* Run network config now. */
	/* Get target interface. */
	FOR_ALL_INTERFACES (vrf, ifp) {
		zlog_debug("Setting up %s", ifp->name);
		eigrp_network_run_interface(eigrp, p, ifp);
	}
	return 1;
}

/* Check whether interface matches given network
 * returns: 1, true. 0, false
 */
static int eigrp_network_match_iface(const struct prefix *co_prefix,
				     const struct prefix *net)
{
	/* new approach: more elegant and conceptually clean */
	return prefix_match_network_statement(net, co_prefix);
}

static void eigrp_network_run_interface(struct eigrp *eigrp, struct prefix *p,
					struct interface *ifp)
{
	struct eigrp_interface *ei;
	struct listnode *cnode;
	struct connected *co;

	/* if interface prefix is match specified prefix,
	   then create socket and join multicast group. */
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, co)) {

		if (CHECK_FLAG(co->flags, ZEBRA_IFA_SECONDARY))
			continue;

		if (p->family == co->address->family && !ifp->info
		    && eigrp_network_match_iface(co->address, p)) {

			ei = eigrp_if_new(eigrp, ifp, co->address);

			/* Relate eigrp interface to eigrp instance. */
			ei->eigrp = eigrp;

			/* if router_id is not configured, dont bring up
			 * interfaces.
			 * eigrp_router_id_update() will call eigrp_if_update
			 * whenever r-id is configured instead.
			 */
			if (if_is_operative(ifp))
				eigrp_if_up(ei);
		}
	}
}

void eigrp_if_update(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct route_node *rn;
	struct eigrp *eigrp;

	/*
	 * In the event there are multiple eigrp autonymnous systems running,
	 * we need to check eac one and add the interface as approperate
	 */
	for (ALL_LIST_ELEMENTS(eigrp_om->eigrp, node, nnode, eigrp)) {
		if (ifp->vrf_id != eigrp->vrf_id)
			continue;

		/* EIGRP must be on and Router-ID must be configured. */
		if (eigrp->router_id.s_addr == 0)
			continue;

		/* Run each network for this interface. */
		for (rn = route_top(eigrp->networks); rn; rn = route_next(rn))
			if (rn->info != NULL) {
				eigrp_network_run_interface(eigrp, &rn->p, ifp);
			}
	}
}

int eigrp_network_unset(struct eigrp *eigrp, struct prefix *p)
{
	struct route_node *rn;
	struct listnode *node, *nnode;
	struct eigrp_interface *ei;
	struct prefix *pref;

	rn = route_node_lookup(eigrp->networks, p);
	if (rn == NULL)
		return 0;

	pref = rn->info;
	route_unlock_node(rn);

	if (!IPV4_ADDR_SAME(&pref->u.prefix4, &p->u.prefix4))
		return 0;

	prefix_ipv4_free((struct prefix_ipv4 **)&rn->info);
	route_unlock_node(rn); /* initial reference */

	/* Find interfaces that not configured already.  */
	for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei)) {
		bool found = false;

		for (rn = route_top(eigrp->networks); rn; rn = route_next(rn)) {
			if (rn->info == NULL)
				continue;

			if (eigrp_network_match_iface(&ei->address, &rn->p)) {
				found = true;
				route_unlock_node(rn);
				break;
			}
		}

		if (!found) {
			eigrp_if_free(ei, INTERFACE_DOWN_BY_VTY);
		}
	}

	return 1;
}

uint32_t eigrp_calculate_metrics(struct eigrp *eigrp,
				 struct eigrp_metrics metric)
{
	uint64_t temp_metric;
	temp_metric = 0;

	if (metric.delay == EIGRP_MAX_METRIC)
		return EIGRP_MAX_METRIC;

	// EIGRP Metric =
	// {K1*BW+[(K2*BW)/(256-load)]+(K3*delay)}*{K5/(reliability+K4)}

	if (eigrp->k_values[0])
		temp_metric += (eigrp->k_values[0] * metric.bandwidth);
	if (eigrp->k_values[1])
		temp_metric += ((eigrp->k_values[1] * metric.bandwidth)
				/ (256 - metric.load));
	if (eigrp->k_values[2])
		temp_metric += (eigrp->k_values[2] * metric.delay);
	if (eigrp->k_values[3] && !eigrp->k_values[4])
		temp_metric *= eigrp->k_values[3];
	if (!eigrp->k_values[3] && eigrp->k_values[4])
		temp_metric *= (eigrp->k_values[4] / metric.reliability);
	if (eigrp->k_values[3] && eigrp->k_values[4])
		temp_metric *= ((eigrp->k_values[4] / metric.reliability)
				+ eigrp->k_values[3]);

	if (temp_metric <= EIGRP_MAX_METRIC)
		return (uint32_t)temp_metric;
	else
		return EIGRP_MAX_METRIC;
}

uint32_t eigrp_calculate_total_metrics(struct eigrp *eigrp,
				       struct eigrp_nexthop_entry *entry)
{
	struct eigrp_interface *ei = entry->ei;

	entry->total_metric = entry->reported_metric;
	uint64_t temp_delay =
		(uint64_t)entry->total_metric.delay
		+ (uint64_t)eigrp_delay_to_scaled(ei->params.delay);
	entry->total_metric.delay = temp_delay > EIGRP_MAX_METRIC
					    ? EIGRP_MAX_METRIC
					    : (uint32_t)temp_delay;

	uint32_t bw = eigrp_bandwidth_to_scaled(ei->params.bandwidth);
	entry->total_metric.bandwidth = entry->total_metric.bandwidth > bw
						? bw
						: entry->total_metric.bandwidth;

	return eigrp_calculate_metrics(eigrp, entry->total_metric);
}

uint8_t eigrp_metrics_is_same(struct eigrp_metrics metric1,
			      struct eigrp_metrics metric2)
{
	if ((metric1.bandwidth == metric2.bandwidth)
	    && (metric1.delay == metric2.delay)
	    && (metric1.hop_count == metric2.hop_count)
	    && (metric1.load == metric2.load)
	    && (metric1.reliability == metric2.reliability)
	    && (metric1.mtu[0] == metric2.mtu[0])
	    && (metric1.mtu[1] == metric2.mtu[1])
	    && (metric1.mtu[2] == metric2.mtu[2]))
		return 1;

	return 0; // if different
}

void eigrp_external_routes_refresh(struct eigrp *eigrp, int type)
{
}
