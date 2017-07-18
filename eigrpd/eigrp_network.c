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

extern struct zebra_privs_t eigrpd_privs;

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"

static int eigrp_network_match_iface(const struct connected *,
				     const struct prefix *);
static void eigrp_network_run_interface(struct eigrp *, struct prefix *,
					struct interface *);

int eigrp_sock_init(void)
{
	int eigrp_sock;
	int ret, hincl = 1;

	if (eigrpd_privs.change(ZPRIVS_RAISE))
		zlog_err("eigrp_sock_init: could not raise privs, %s",
			 safe_strerror(errno));

	eigrp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_EIGRPIGP);
	if (eigrp_sock < 0) {
		int save_errno = errno;
		if (eigrpd_privs.change(ZPRIVS_LOWER))
			zlog_err("eigrp_sock_init: could not lower privs, %s",
				 safe_strerror(errno));
		zlog_err("eigrp_read_sock_init: socket: %s",
			 safe_strerror(save_errno));
		exit(1);
	}

#ifdef IP_HDRINCL
	/* we will include IP header with packet */
	ret = setsockopt(eigrp_sock, IPPROTO_IP, IP_HDRINCL, &hincl,
			 sizeof(hincl));
	if (ret < 0) {
		int save_errno = errno;
		if (eigrpd_privs.change(ZPRIVS_LOWER))
			zlog_err("eigrp_sock_init: could not lower privs, %s",
				 safe_strerror(errno));
		zlog_warn("Can't set IP_HDRINCL option for fd %d: %s",
			  eigrp_sock, safe_strerror(save_errno));
	}
#elif defined(IPTOS_PREC_INTERNETCONTROL)
#warning "IP_HDRINCL not available on this system"
#warning "using IPTOS_PREC_INTERNETCONTROL"
	ret = setsockopt_ipv4_tos(eigrp_sock, IPTOS_PREC_INTERNETCONTROL);
	if (ret < 0) {
		int save_errno = errno;
		if (eigrpd_privs.change(ZPRIVS_LOWER))
			zlog_err("eigrpd_sock_init: could not lower privs, %s",
				 safe_strerror(errno));
		zlog_warn("can't set sockopt IP_TOS %d to socket %d: %s", tos,
			  eigrp_sock, safe_strerror(save_errno));
		close(eigrp_sock); /* Prevent sd leak. */
		return ret;
	}
#else /* !IPTOS_PREC_INTERNETCONTROL */
#warning "IP_HDRINCL not available, nor is IPTOS_PREC_INTERNETCONTROL"
	zlog_warn("IP_HDRINCL option not available");
#endif /* IP_HDRINCL */

	ret = setsockopt_ifindex(AF_INET, eigrp_sock, 1);

	if (ret < 0)
		zlog_warn("Can't set pktinfo option for fd %d", eigrp_sock);

	if (eigrpd_privs.change(ZPRIVS_LOWER)) {
		zlog_err("eigrp_sock_init: could not lower privs, %s",
			 safe_strerror(errno));
	}

	return eigrp_sock;
}

void eigrp_adjust_sndbuflen(struct eigrp *eigrp, unsigned int buflen)
{
	int newbuflen;
	/* Check if any work has to be done at all. */
	if (eigrp->maxsndbuflen >= buflen)
		return;
	if (eigrpd_privs.change(ZPRIVS_RAISE))
		zlog_err("%s: could not raise privs, %s", __func__,
			 safe_strerror(errno));

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
	if (eigrpd_privs.change(ZPRIVS_LOWER))
		zlog_err("%s: could not lower privs, %s", __func__,
			 safe_strerror(errno));
}

int eigrp_if_ipmulticast(struct eigrp *top, struct prefix *p,
			 unsigned int ifindex)
{
	u_char val;
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

int eigrp_network_set(struct eigrp *eigrp, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct interface *ifp;
	struct listnode *node;

	rn = route_node_get(eigrp->networks, (struct prefix *)p);
	if (rn->info) {
		/* There is already same network statement. */
		route_unlock_node(rn);
		return 0;
	}

	struct prefix_ipv4 *pref = prefix_ipv4_new();
	PREFIX_COPY_IPV4(pref, p);
	rn->info = (void *)pref;

	/* Schedule Router ID Update. */
	if (eigrp->router_id == 0)
		eigrp_router_id_update(eigrp);
	/* Run network config now. */
	/* Get target interface. */
	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp)) {
		zlog_debug("Setting up %s", ifp->name);
		eigrp_network_run_interface(eigrp, (struct prefix *)p, ifp);
	}
	return 1;
}

/* Check whether interface matches given network
 * returns: 1, true. 0, false
 */
static int eigrp_network_match_iface(const struct connected *co,
				     const struct prefix *net)
{
	/* new approach: more elegant and conceptually clean */
	return prefix_match_network_statement(net, CONNECTED_PREFIX(co));
}

static void eigrp_network_run_interface(struct eigrp *eigrp, struct prefix *p,
					struct interface *ifp)
{
	struct listnode *cnode;
	struct connected *co;

	/* if interface prefix is match specified prefix,
	   then create socket and join multicast group. */
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, co)) {

		if (CHECK_FLAG(co->flags, ZEBRA_IFA_SECONDARY))
			continue;

		if (p->family == co->address->family
		    && !eigrp_if_table_lookup(ifp, co->address)
		    && eigrp_network_match_iface(co, p)) {
			struct eigrp_interface *ei;

			ei = eigrp_if_new(eigrp, ifp, co->address);
			ei->connected = co;

			ei->params = eigrp_lookup_if_params(
				ifp, ei->address->u.prefix4);

			/* Relate eigrp interface to eigrp instance. */
			ei->eigrp = eigrp;

			/* update network type as interface flag */
			/* If network type is specified previously,
			   skip network type setting. */
			ei->type = IF_DEF_PARAMS(ifp)->type;

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
		/* EIGRP must be on and Router-ID must be configured. */
		if (!eigrp || eigrp->router_id == 0)
			continue;

		/* Run each network for this interface. */
		for (rn = route_top(eigrp->networks); rn; rn = route_next(rn))
			if (rn->info != NULL) {
				eigrp_network_run_interface(eigrp, &rn->p, ifp);
			}
	}
}

int eigrp_network_unset(struct eigrp *eigrp, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct listnode *node, *nnode;
	struct eigrp_interface *ei;
	struct prefix *pref;

	rn = route_node_lookup(eigrp->networks, (struct prefix *)p);
	if (rn == NULL)
		return 0;

	pref = rn->info;
	route_unlock_node(rn);

	if (!IPV4_ADDR_SAME(&pref->u.prefix4, &p->prefix))
		return 0;

	prefix_ipv4_free(rn->info);
	rn->info = NULL;
	route_unlock_node(rn); /* initial reference */

	/* Find interfaces that not configured already.  */
	for (ALL_LIST_ELEMENTS(eigrp->eiflist, node, nnode, ei)) {
		int found = 0;
		struct connected *co = ei->connected;

		for (rn = route_top(eigrp->networks); rn; rn = route_next(rn)) {
			if (rn->info == NULL)
				continue;

			if (eigrp_network_match_iface(co, &rn->p)) {
				found = 1;
				route_unlock_node(rn);
				break;
			}
		}

		if (found == 0) {
			eigrp_if_free(ei, INTERFACE_DOWN_BY_VTY);
		}
	}

	return 1;
}

u_int32_t eigrp_calculate_metrics(struct eigrp *eigrp,
				  struct eigrp_metrics metric)
{
	uint64_t temp_metric;
	temp_metric = 0;

	if (metric.delay == EIGRP_MAX_METRIC)
		return EIGRP_MAX_METRIC;

	// EIGRP Metric =
	// {K1*BW+[(K2*BW)/(256-load)]+(K3*delay)}*{K5/(reliability+K4)}

	if (eigrp->k_values[0])
		temp_metric += (eigrp->k_values[0] * metric.bandwith);
	if (eigrp->k_values[1])
		temp_metric += ((eigrp->k_values[1] * metric.bandwith)
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
		return (u_int32_t)temp_metric;
	else
		return EIGRP_MAX_METRIC;
}

u_int32_t eigrp_calculate_total_metrics(struct eigrp *eigrp,
					struct eigrp_neighbor_entry *entry)
{
	entry->total_metric = entry->reported_metric;
	uint64_t temp_delay = (uint64_t)entry->total_metric.delay
			      + (uint64_t)eigrp_delay_to_scaled(
					EIGRP_IF_PARAM(entry->ei, delay));
	entry->total_metric.delay = temp_delay > EIGRP_MAX_METRIC
					    ? EIGRP_MAX_METRIC
					    : (u_int32_t)temp_delay;

	u_int32_t bw =
		eigrp_bandwidth_to_scaled(EIGRP_IF_PARAM(entry->ei, bandwidth));
	entry->total_metric.bandwith = entry->total_metric.bandwith > bw
					       ? bw
					       : entry->total_metric.bandwith;

	return eigrp_calculate_metrics(eigrp, entry->total_metric);
}

u_char eigrp_metrics_is_same(struct eigrp_metrics metric1,
			     struct eigrp_metrics metric2)
{
	if ((metric1.bandwith == metric2.bandwith)
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
