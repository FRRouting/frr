/*
 * Address linked list routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "table.h"
#include "rib.h"
#include "table.h"
#include "log.h"
#include "memory.h"
#include "zebra_memory.h"

#include "vty.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/connected.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/debug.h"

/* communicate the withdrawal of a connected address */
static void connected_withdraw(struct connected *ifc)
{
	if (!ifc)
		return;

	/* Update interface address information to protocol daemon. */
	if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
		zebra_interface_address_delete_update(ifc->ifp, ifc);

		if (ifc->address->family == AF_INET)
			if_subnet_delete(ifc->ifp, ifc);

		if (ifc->address->family == AF_INET)
			connected_down_ipv4(ifc->ifp, ifc);
		else
			connected_down_ipv6(ifc->ifp, ifc);

		UNSET_FLAG(ifc->conf, ZEBRA_IFC_REAL);
	}

	/* The address is not in the kernel anymore, so clear the flag */
	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)) {
		listnode_delete(ifc->ifp->connected, ifc);
		connected_free(ifc);
	}
}

static void connected_announce(struct interface *ifp, struct connected *ifc)
{
	if (!ifc)
		return;

	if (!if_is_loopback(ifp) && ifc->address->family == AF_INET) {
		if (ifc->address->prefixlen == 32)
			SET_FLAG(ifc->flags, ZEBRA_IFA_UNNUMBERED);
		else
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_UNNUMBERED);
	}

	listnode_add(ifp->connected, ifc);

	/* Update interface address information to protocol daemon. */
	if (ifc->address->family == AF_INET)
		if_subnet_add(ifp, ifc);

	zebra_interface_address_add_update(ifp, ifc);

	if (if_is_operative(ifp)) {
		if (ifc->address->family == AF_INET)
			connected_up_ipv4(ifp, ifc);
		else
			connected_up_ipv6(ifp, ifc);
	}
}

/* If same interface address is already exist... */
struct connected *connected_check(struct interface *ifp, struct prefix *p)
{
	struct connected *ifc;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
		if (prefix_same(ifc->address, p))
			return ifc;

	return NULL;
}

/* Check if two ifc's describe the same address in the same state */
static int connected_same(struct connected *ifc1, struct connected *ifc2)
{
	if (ifc1->ifp != ifc2->ifp)
		return 0;

	if (ifc1->destination)
		if (!ifc2->destination)
			return 0;
	if (ifc2->destination)
		if (!ifc1->destination)
			return 0;

	if (ifc1->destination && ifc2->destination)
		if (!prefix_same(ifc1->destination, ifc2->destination))
			return 0;

	if (ifc1->flags != ifc2->flags)
		return 0;

	if (ifc1->conf != ifc2->conf)
		return 0;

	return 1;
}

/* Handle changes to addresses and send the neccesary announcements
 * to clients. */
static void connected_update(struct interface *ifp, struct connected *ifc)
{
	struct connected *current;

	/* Check same connected route. */
	if ((current = connected_check(ifp, (struct prefix *)ifc->address))) {
		if (CHECK_FLAG(current->conf, ZEBRA_IFC_CONFIGURED))
			SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

		/* Avoid spurious withdraws, this might be just the kernel
		 * 'reflecting'
		 * back an address we have already added.
		 */
		if (connected_same(current, ifc)) {
			/* nothing to do */
			connected_free(ifc);
			return;
		}

		/* Clear the configured flag on the old ifc, so it will be freed
		 * by
		 * connected withdraw. */
		UNSET_FLAG(current->conf, ZEBRA_IFC_CONFIGURED);
		connected_withdraw(
			current); /* implicit withdraw - freebsd does this */
	}

	/* If the connected is new or has changed, announce it, if it is usable
	 */
	if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		connected_announce(ifp, ifc);
}

/* Called from if_up(). */
void connected_up_ipv4(struct interface *ifp, struct connected *ifc)
{
	struct prefix p;

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY_IPV4((struct prefix_ipv4 *)&p, CONNECTED_PREFIX(ifc));

	/* Apply mask to the network. */
	apply_mask(&p);

	/* In case of connected address is 0.0.0.0/0 we treat it tunnel
	   address. */
	if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
		return;

	rib_add(AFI_IP, SAFI_UNICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0, 0,
		&p, NULL, NULL, NULL, ifp->ifindex, RT_TABLE_MAIN, ifp->metric,
		0, 0);

	rib_add(AFI_IP, SAFI_MULTICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0, 0,
		&p, NULL, NULL, NULL, ifp->ifindex, RT_TABLE_MAIN, ifp->metric,
		0, 0);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv4 address add/up, scheduling RIB processing",
			ifp->vrf_id, ifp->name);
	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

/* Add connected IPv4 route to the interface. */
void connected_add_ipv4(struct interface *ifp, int flags, struct in_addr *addr,
			u_char prefixlen, struct in_addr *broad,
			const char *label)
{
	struct prefix_ipv4 *p;
	struct connected *ifc;

	if (ipv4_martian(addr))
		return;

	/* Make connected structure. */
	ifc = connected_new();
	ifc->ifp = ifp;
	ifc->flags = flags;
	/* If we get a notification from the kernel,
	 * we can safely assume the address is known to the kernel */
	SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	/* Allocate new connected address. */
	p = prefix_ipv4_new();
	p->family = AF_INET;
	p->prefix = *addr;
	p->prefixlen = prefixlen;
	ifc->address = (struct prefix *)p;

	/* If there is broadcast or peer address. */
	if (broad) {
		p = prefix_ipv4_new();
		p->family = AF_INET;
		p->prefix = *broad;
		p->prefixlen = prefixlen;
		ifc->destination = (struct prefix *)p;

		/* validate the destination address */
		if (CONNECTED_PEER(ifc)) {
			if (IPV4_ADDR_SAME(addr, broad))
				zlog_warn(
					"warning: interface %s has same local and peer "
					"address %s, routing protocols may malfunction",
					ifp->name, inet_ntoa(*addr));
		} else {
			if (broad->s_addr
			    != ipv4_broadcast_addr(addr->s_addr, prefixlen)) {
				char buf[2][INET_ADDRSTRLEN];
				struct in_addr bcalc;
				bcalc.s_addr = ipv4_broadcast_addr(addr->s_addr,
								   prefixlen);
				zlog_warn(
					"warning: interface %s broadcast addr %s/%d != "
					"calculated %s, routing protocols may malfunction",
					ifp->name,
					inet_ntop(AF_INET, broad, buf[0],
						  sizeof(buf[0])),
					prefixlen,
					inet_ntop(AF_INET, &bcalc, buf[1],
						  sizeof(buf[1])));
			}
		}

	} else {
		if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_PEER)) {
			zlog_warn(
				"warning: %s called for interface %s "
				"with peer flag set, but no peer address supplied",
				__func__, ifp->name);
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
		}

		/* no broadcast or destination address was supplied */
		if ((prefixlen == IPV4_MAX_PREFIXLEN) && if_is_pointopoint(ifp))
			zlog_warn(
				"warning: PtP interface %s with addr %s/%d needs a "
				"peer address",
				ifp->name, inet_ntoa(*addr), prefixlen);
	}

	/* Label of this address. */
	if (label)
		ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

	/* For all that I know an IPv4 address is always ready when we receive
	 * the notification. So it should be safe to set the REAL flag here. */
	SET_FLAG(ifc->conf, ZEBRA_IFC_REAL);

	connected_update(ifp, ifc);
}

void connected_down_ipv4(struct interface *ifp, struct connected *ifc)
{
	struct prefix p;

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY_IPV4(&p, CONNECTED_PREFIX(ifc));

	/* Apply mask to the network. */
	apply_mask(&p);

	/* In case of connected address is 0.0.0.0/0 we treat it tunnel
	   address. */
	if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
		return;

	/* Same logic as for connected_up_ipv4(): push the changes into the
	 * head. */
	rib_delete(AFI_IP, SAFI_UNICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0, 0,
		   &p, NULL, NULL, ifp->ifindex, 0);

	rib_delete(AFI_IP, SAFI_MULTICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0,
		   0, &p, NULL, NULL, ifp->ifindex, 0);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv4 address down, scheduling RIB processing",
			ifp->vrf_id, ifp->name);

	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

/* Delete connected IPv4 route to the interface. */
void connected_delete_ipv4(struct interface *ifp, int flags,
			   struct in_addr *addr, u_char prefixlen,
			   struct in_addr *broad)
{
	struct prefix_ipv4 p;
	struct connected *ifc;

	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefix = *addr;
	p.prefixlen = prefixlen;

	ifc = connected_check(ifp, (struct prefix *)&p);
	if (!ifc)
		return;

	connected_withdraw(ifc);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv4 address del, scheduling RIB processing",
			ifp->vrf_id, ifp->name);

	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

void connected_up_ipv6(struct interface *ifp, struct connected *ifc)
{
	struct prefix p;

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY_IPV6((struct prefix_ipv6 *)&p, CONNECTED_PREFIX(ifc));

	/* Apply mask to the network. */
	apply_mask(&p);

#ifndef LINUX
	/* XXX: It is already done by rib_bogus_ipv6 within rib_add */
	if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
		return;
#endif

	rib_add(AFI_IP6, SAFI_UNICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0, 0,
		&p, NULL, NULL, NULL, ifp->ifindex, RT_TABLE_MAIN, ifp->metric,
		0, 0);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv6 address down, scheduling RIB processing",
			ifp->vrf_id, ifp->name);

	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

/* Add connected IPv6 route to the interface. */
void connected_add_ipv6(struct interface *ifp, int flags, struct in6_addr *addr,
			u_char prefixlen, struct in6_addr *broad,
			const char *label)
{
	struct prefix_ipv6 *p;
	struct connected *ifc;

	if (ipv6_martian(addr))
		return;

	/* Make connected structure. */
	ifc = connected_new();
	ifc->ifp = ifp;
	ifc->flags = flags;
	/* If we get a notification from the kernel,
	 * we can safely assume the address is known to the kernel */
	SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	/* Allocate new connected address. */
	p = prefix_ipv6_new();
	p->family = AF_INET6;
	IPV6_ADDR_COPY(&p->prefix, addr);
	p->prefixlen = prefixlen;
	ifc->address = (struct prefix *)p;

	/* If there is broadcast or peer address. */
	if (broad) {
		if (IN6_IS_ADDR_UNSPECIFIED(broad))
			zlog_warn(
				"warning: %s called for interface %s with unspecified "
				"destination address; ignoring!",
				__func__, ifp->name);
		else {
			p = prefix_ipv6_new();
			p->family = AF_INET6;
			IPV6_ADDR_COPY(&p->prefix, broad);
			p->prefixlen = prefixlen;
			ifc->destination = (struct prefix *)p;
		}
	}
	if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_PEER) && !ifc->destination) {
		zlog_warn(
			"warning: %s called for interface %s "
			"with peer flag set, but no peer address supplied",
			__func__, ifp->name);
		UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
	}

	/* Label of this address. */
	if (label)
		ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

	/* On Linux, we only get here when DAD is complete, therefore we can set
	 * ZEBRA_IFC_REAL.
	 *
	 * On BSD, there currently doesn't seem to be a way to check for
	 * completion of
	 * DAD, so we replicate the old behaviour and set ZEBRA_IFC_REAL,
	 * although DAD
	 * might still be running.
	 */
	SET_FLAG(ifc->conf, ZEBRA_IFC_REAL);
	connected_update(ifp, ifc);
}

void connected_down_ipv6(struct interface *ifp, struct connected *ifc)
{
	struct prefix p;

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY_IPV6(&p, CONNECTED_PREFIX(ifc));

	apply_mask(&p);

	if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
		return;

	rib_delete(AFI_IP6, SAFI_UNICAST, ifp->vrf_id, ZEBRA_ROUTE_CONNECT, 0,
		   0, &p, NULL, NULL, ifp->ifindex, 0);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv6 address down, scheduling RIB processing",
			ifp->vrf_id, ifp->name);

	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

void connected_delete_ipv6(struct interface *ifp, struct in6_addr *address,
			   u_char prefixlen, struct in6_addr *broad)
{
	struct prefix_ipv6 p;
	struct connected *ifc;

	memset(&p, 0, sizeof(struct prefix_ipv6));
	p.family = AF_INET6;
	memcpy(&p.prefix, address, sizeof(struct in6_addr));
	p.prefixlen = prefixlen;

	ifc = connected_check(ifp, (struct prefix *)&p);
	if (!ifc)
		return;

	connected_withdraw(ifc);

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: IF %s IPv6 address del, scheduling RIB processing",
			ifp->vrf_id, ifp->name);

	rib_update(ifp->vrf_id, RIB_UPDATE_IF_CHANGE);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IPv4 address add/up, scheduling MPLS processing",
				ifp->vrf_id, ifp->name);
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id));
	}
}

int connected_is_unnumbered(struct interface *ifp)
{
	struct connected *connected;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && connected->address->family == AF_INET)
			return CHECK_FLAG(connected->flags,
					  ZEBRA_IFA_UNNUMBERED);
	}
	return 0;
}
