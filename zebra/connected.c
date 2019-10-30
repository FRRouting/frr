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
#include "zebra/zebra_errors.h"

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

		connected_down(ifc->ifp, ifc);

		UNSET_FLAG(ifc->conf, ZEBRA_IFC_REAL);
	}

	/* The address is not in the kernel anymore, so clear the flag */
	UNSET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)) {
		listnode_delete(ifc->ifp->connected, ifc);
		connected_free(&ifc);
	}
}

static void connected_announce(struct interface *ifp, struct connected *ifc)
{
	if (!ifc)
		return;

	if (!if_is_loopback(ifp) && ifc->address->family == AF_INET &&
	    !IS_ZEBRA_IF_VRF(ifp)) {
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
		connected_up(ifp, ifc);
	}
}

/* If same interface address is already exist... */
struct connected *connected_check(struct interface *ifp,
				  union prefixconstptr pu)
{
	const struct prefix *p = pu.p;
	struct connected *ifc;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc))
		if (prefix_same(ifc->address, p))
			return ifc;

	return NULL;
}

/* same, but with peer address */
struct connected *connected_check_ptp(struct interface *ifp,
				      union prefixconstptr pu,
				      union prefixconstptr du)
{
	const struct prefix *p = pu.p;
	const struct prefix *d = du.p;
	struct connected *ifc;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		if (!prefix_same(ifc->address, p))
			continue;
		if (!CONNECTED_PEER(ifc) && !d)
			return ifc;
		if (CONNECTED_PEER(ifc) && d
		    && prefix_same(ifc->destination, d))
			return ifc;
	}

	return NULL;
}

/* Check if two ifc's describe the same address in the same state */
static int connected_same(struct connected *ifc1, struct connected *ifc2)
{
	if (ifc1->ifp != ifc2->ifp)
		return 0;

	if (ifc1->flags != ifc2->flags)
		return 0;

	if (ifc1->conf != ifc2->conf)
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

	return 1;
}

/* Handle changes to addresses and send the neccesary announcements
 * to clients. */
static void connected_update(struct interface *ifp, struct connected *ifc)
{
	struct connected *current;

	/* Check same connected route. */
	current = connected_check_ptp(ifp, ifc->address, ifc->destination);
	if (current) {
		if (CHECK_FLAG(current->conf, ZEBRA_IFC_CONFIGURED))
			SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);

		/* Avoid spurious withdraws, this might be just the kernel
		 * 'reflecting'
		 * back an address we have already added.
		 */
		if (connected_same(current, ifc)) {
			/* nothing to do */
			connected_free(&ifc);
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
void connected_up(struct interface *ifp, struct connected *ifc)
{
	afi_t afi;
	struct prefix p = {0};
	struct nexthop nh = {
		.type = NEXTHOP_TYPE_IFINDEX,
		.ifindex = ifp->ifindex,
		.vrf_id = ifp->vrf_id,
	};
	struct zebra_vrf *zvrf;
	uint32_t metric;

	zvrf = zebra_vrf_lookup_by_id(ifp->vrf_id);
	if (!zvrf) {
		flog_err(EC_ZEBRA_VRF_NOT_FOUND,
			 "%s: Received Up for interface but no associated zvrf: %d",
			 __PRETTY_FUNCTION__, ifp->vrf_id);
		return;
	}
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY(&p, CONNECTED_PREFIX(ifc));

	/* Apply mask to the network. */
	apply_mask(&p);

	afi = family2afi(p.family);

	switch (afi) {
	case AFI_IP:
		/*
		 * In case of connected address is 0.0.0.0/0 we treat it tunnel
		 * address.
		 */
		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;
		break;
	case AFI_IP6:
#ifndef GNU_LINUX
		/* XXX: It is already done by rib_bogus_ipv6 within rib_add */
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;
#endif
		break;
	default:
		flog_warn(EC_ZEBRA_CONNECTED_AFI_UNKNOWN,
			  "Received unknown AFI: %s", afi2str(afi));
		return;
		break;
	}

	metric = (ifc->metric < (uint32_t)METRIC_MAX) ?
				ifc->metric : ifp->metric;
	rib_add(afi, SAFI_UNICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_CONNECT,
		0, 0, &p, NULL, &nh, 0, zvrf->table_id, metric, 0, 0, 0);

	rib_add(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_CONNECT,
		0, 0, &p, NULL, &nh, 0, zvrf->table_id, metric, 0, 0, 0);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (zvrf->vrf->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf[PREFIX_STRLEN];

			zlog_debug(
				"%u: IF %s IP %s address add/up, scheduling MPLS processing",
				zvrf->vrf->vrf_id, ifp->name,
				prefix2str(&p, buf, sizeof(buf)));
		}
		mpls_mark_lsps_for_processing(zvrf, &p);
	}
}

/* Add connected IPv4 route to the interface. */
void connected_add_ipv4(struct interface *ifp, int flags, struct in_addr *addr,
			uint16_t prefixlen, struct in_addr *dest,
			const char *label, uint32_t metric)
{
	struct prefix_ipv4 *p;
	struct connected *ifc;

	if (ipv4_martian(addr))
		return;

	/* Make connected structure. */
	ifc = connected_new();
	ifc->ifp = ifp;
	ifc->flags = flags;
	ifc->metric = metric;
	/* If we get a notification from the kernel,
	 * we can safely assume the address is known to the kernel */
	SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	/* Allocate new connected address. */
	p = prefix_ipv4_new();
	p->family = AF_INET;
	p->prefix = *addr;
	p->prefixlen = CHECK_FLAG(flags, ZEBRA_IFA_PEER) ? IPV4_MAX_PREFIXLEN
							 : prefixlen;
	ifc->address = (struct prefix *)p;

	/* If there is a peer address. */
	if (CONNECTED_PEER(ifc)) {
		/* validate the destination address */
		if (dest) {
			p = prefix_ipv4_new();
			p->family = AF_INET;
			p->prefix = *dest;
			p->prefixlen = prefixlen;
			ifc->destination = (struct prefix *)p;

			if (IPV4_ADDR_SAME(addr, dest))
				flog_warn(
					EC_ZEBRA_IFACE_SAME_LOCAL_AS_PEER,
					"warning: interface %s has same local and peer "
					"address %s, routing protocols may malfunction",
					ifp->name, inet_ntoa(*addr));
		} else {
			zlog_debug(
				"warning: %s called for interface %s "
				"with peer flag set, but no peer address supplied",
				__func__, ifp->name);
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
		}
	}

	/* no destination address was supplied */
	if (!dest && (prefixlen == IPV4_MAX_PREFIXLEN)
		&& if_is_pointopoint(ifp))
		zlog_debug(
			"warning: PtP interface %s with addr %s/%d needs a "
			"peer address",
			ifp->name, inet_ntoa(*addr), prefixlen);

	/* Label of this address. */
	if (label)
		ifc->label = XSTRDUP(MTYPE_CONNECTED_LABEL, label);

	/* For all that I know an IPv4 address is always ready when we receive
	 * the notification. So it should be safe to set the REAL flag here. */
	SET_FLAG(ifc->conf, ZEBRA_IFC_REAL);

	connected_update(ifp, ifc);
}

void connected_down(struct interface *ifp, struct connected *ifc)
{
	afi_t afi;
	struct prefix p;
	struct nexthop nh = {
		.type = NEXTHOP_TYPE_IFINDEX,
		.ifindex = ifp->ifindex,
		.vrf_id = ifp->vrf_id,
	};
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_lookup_by_id(ifp->vrf_id);
	if (!zvrf) {
		flog_err(EC_ZEBRA_VRF_NOT_FOUND,
			 "%s: Received Up for interface but no associated zvrf: %d",
			 __PRETTY_FUNCTION__, ifp->vrf_id);
		return;
	}

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	PREFIX_COPY(&p, CONNECTED_PREFIX(ifc));

	/* Apply mask to the network. */
	apply_mask(&p);

	afi = family2afi(p.family);

	switch (afi) {
	case AFI_IP:
		/*
		 * In case of connected address is 0.0.0.0/0 we treat it tunnel
		 *  address.
		 */
		if (prefix_ipv4_any((struct prefix_ipv4 *)&p))
			return;
		break;
	case AFI_IP6:
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;
		break;
	default:
		zlog_warn("Unknown AFI: %s", afi2str(afi));
		break;
	}

	/*
	 * Same logic as for connected_up(): push the changes into the
	 * head.
	 */
	rib_delete(afi, SAFI_UNICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_CONNECT, 0,
		   0, &p, NULL, &nh, 0, zvrf->table_id, 0, 0, false);

	rib_delete(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_CONNECT,
		   0, 0, &p, NULL, &nh, 0, zvrf->table_id, 0, 0, false);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (zvrf->vrf->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf[PREFIX_STRLEN];

			zlog_debug(
				"%u: IF %s IP %s address down, scheduling MPLS processing",
				zvrf->vrf->vrf_id, ifp->name,
				prefix2str(&p, buf, sizeof(buf)));
		}
		mpls_mark_lsps_for_processing(zvrf, &p);
	}
}

static void connected_delete_helper(struct connected *ifc, struct prefix *p)
{
	struct interface *ifp;

	if (!ifc)
		return;
	ifp = ifc->ifp;

	connected_withdraw(ifc);

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (ifp->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS) {
			char buf[PREFIX_STRLEN];

			zlog_debug(
				"%u: IF %s IP %s address delete, scheduling MPLS processing",
				ifp->vrf_id, ifp->name,
				prefix2str(p, buf, sizeof(buf)));
		}
		mpls_mark_lsps_for_processing(vrf_info_lookup(ifp->vrf_id), p);
	}
}

/* Delete connected IPv4 route to the interface. */
void connected_delete_ipv4(struct interface *ifp, int flags,
			   struct in_addr *addr, uint16_t prefixlen,
			   struct in_addr *dest)
{
	struct prefix p, d;
	struct connected *ifc;

	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET;
	p.u.prefix4 = *addr;
	p.prefixlen = CHECK_FLAG(flags, ZEBRA_IFA_PEER) ? IPV4_MAX_PREFIXLEN
							: prefixlen;

	if (dest) {
		memset(&d, 0, sizeof(struct prefix));
		d.family = AF_INET;
		d.u.prefix4 = *dest;
		d.prefixlen = prefixlen;
		ifc = connected_check_ptp(ifp, &p, &d);
	} else
		ifc = connected_check_ptp(ifp, &p, NULL);

	connected_delete_helper(ifc, &p);
}

/* Add connected IPv6 route to the interface. */
void connected_add_ipv6(struct interface *ifp, int flags, struct in6_addr *addr,
			struct in6_addr *dest, uint16_t prefixlen,
			const char *label, uint32_t metric)
{
	struct prefix_ipv6 *p;
	struct connected *ifc;

	if (ipv6_martian(addr))
		return;

	/* Make connected structure. */
	ifc = connected_new();
	ifc->ifp = ifp;
	ifc->flags = flags;
	ifc->metric = metric;
	/* If we get a notification from the kernel,
	 * we can safely assume the address is known to the kernel */
	SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);

	/* Allocate new connected address. */
	p = prefix_ipv6_new();
	p->family = AF_INET6;
	IPV6_ADDR_COPY(&p->prefix, addr);
	p->prefixlen = prefixlen;
	ifc->address = (struct prefix *)p;

	if (dest) {
		p = prefix_ipv6_new();
		p->family = AF_INET6;
		IPV6_ADDR_COPY(&p->prefix, dest);
		p->prefixlen = prefixlen;
		ifc->destination = (struct prefix *)p;
	} else {
		if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_PEER)) {
			zlog_debug(
				"warning: %s called for interface %s with peer flag set, but no peer address supplied",
				__func__, ifp->name);
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
		}
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

void connected_delete_ipv6(struct interface *ifp, struct in6_addr *address,
			   struct in6_addr *dest, uint16_t prefixlen)
{
	struct prefix p, d;
	struct connected *ifc;

	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET6;
	memcpy(&p.u.prefix6, address, sizeof(struct in6_addr));
	p.prefixlen = prefixlen;

	if (dest) {
		memset(&d, 0, sizeof(struct prefix));
		d.family = AF_INET6;
		IPV6_ADDR_COPY(&d.u.prefix6, dest);
		d.prefixlen = prefixlen;
		ifc = connected_check_ptp(ifp, &p, &d);
	} else
		ifc = connected_check_ptp(ifp, &p, NULL);

	connected_delete_helper(ifc, &p);
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
	return 1;
}
