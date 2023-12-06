// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Address linked list routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "vty.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/interface.h"
#include "zebra/connected.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_router.h"

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
		if_connected_del(ifc->ifp->connected, ifc);
		connected_free(&ifc);
	}
}

static void connected_announce(struct interface *ifp, struct connected *ifc)
{
	if (!ifc)
		return;

	if (!if_is_loopback(ifp) && ifc->address->family == AF_INET) {
		if (ifc->address->prefixlen == IPV4_MAX_BITLEN)
			SET_FLAG(ifc->flags, ZEBRA_IFA_UNNUMBERED);
		else
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_UNNUMBERED);
	}

	if_connected_add_tail(ifp->connected, ifc);

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

	frr_each (if_connected, ifp->connected, ifc)
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

	frr_each (if_connected, ifp->connected, ifc) {
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
	struct prefix p, plocal;
	struct nexthop nh = {
		.type = NEXTHOP_TYPE_IFINDEX,
		.ifindex = ifp->ifindex,
		.vrf_id = ifp->vrf->vrf_id,
	};
	struct zebra_vrf *zvrf;
	uint32_t metric;
	uint32_t flags = 0;
	uint32_t count = 0;
	struct connected *c;
	bool install_local = true;

	zvrf = ifp->vrf->info;
	if (!zvrf) {
		flog_err(
			EC_ZEBRA_VRF_NOT_FOUND,
			"%s: Received Up for interface but no associated zvrf: %s(%d)",
			__func__, ifp->vrf->name, ifp->vrf->vrf_id);
		return;
	}
	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	/* Ensure 'down' flag is cleared */
	UNSET_FLAG(ifc->conf, ZEBRA_IFC_DOWN);

	prefix_copy(&p, CONNECTED_PREFIX(ifc));
	prefix_copy(&plocal, ifc->address);

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

		plocal.prefixlen = IPV4_MAX_BITLEN;
		break;
	case AFI_IP6:
#ifndef GNU_LINUX
		/* XXX: It is already done by rib_bogus_ipv6 within rib_add */
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;
#endif

		if (IN6_IS_ADDR_LINKLOCAL(&plocal.u.prefix6))
			install_local = false;

		plocal.prefixlen = IPV6_MAX_BITLEN;
		break;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
		flog_warn(EC_ZEBRA_CONNECTED_AFI_UNKNOWN,
			  "Received unknown AFI: %s", afi2str(afi));
		return;
		break;
	}

	metric = (ifc->metric < (uint32_t)METRIC_MAX) ?
				ifc->metric : ifp->metric;

	/*
	 * Since we are hand creating the connected routes
	 * in our main routing table, *if* we are working
	 * in an offloaded environment then we need to
	 * pretend like the route is offloaded so everything
	 * else will work
	 */
	if (zrouter.asic_offloaded)
		flags |= ZEBRA_FLAG_OFFLOADED;

	/*
	 * It's possible to add the same network and mask
	 * to an interface over and over.  This would
	 * result in an equivalent number of connected
	 * routes.  Just add one connected route in
	 * for all the addresses on an interface that
	 * resolve to the same network and mask
	 */
	frr_each (if_connected, ifp->connected, c) {
		struct prefix cp;

		prefix_copy(&cp, CONNECTED_PREFIX(c));
		apply_mask(&cp);

		if (prefix_same(&cp, &p) &&
		    !CHECK_FLAG(c->conf, ZEBRA_IFC_DOWN))
			count++;

		if (count >= 2)
			return;
	}

	if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_NOPREFIXROUTE)) {
		rib_add(afi, SAFI_UNICAST, zvrf->vrf->vrf_id,
			ZEBRA_ROUTE_CONNECT, 0, flags, &p, NULL, &nh, 0,
			zvrf->table_id, metric, 0, 0, 0, false);

		rib_add(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id,
			ZEBRA_ROUTE_CONNECT, 0, flags, &p, NULL, &nh, 0,
			zvrf->table_id, metric, 0, 0, 0, false);
	}

	if (install_local) {
		rib_add(afi, SAFI_UNICAST, zvrf->vrf->vrf_id, ZEBRA_ROUTE_LOCAL,
			0, flags, &plocal, NULL, &nh, 0, zvrf->table_id, 0, 0,
			0, 0, false);
		rib_add(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id,
			ZEBRA_ROUTE_LOCAL, 0, flags, &plocal, NULL, &nh, 0,
			zvrf->table_id, 0, 0, 0, 0, false);
	}

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (zvrf->vrf->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IP %pFX address add/up, scheduling MPLS processing",
				zvrf->vrf->vrf_id, ifp->name, &p);
		mpls_mark_lsps_for_processing(zvrf, &p);
	}
}

/* Add connected IPv4 route to the interface. */
void connected_add_ipv4(struct interface *ifp, int flags,
			const struct in_addr *addr, uint16_t prefixlen,
			const struct in_addr *dest, const char *label,
			uint32_t metric)
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
	if (!if_is_operative(ifp))
		SET_FLAG(ifc->conf, ZEBRA_IFC_DOWN);

	/* Allocate new connected address. */
	p = prefix_ipv4_new();
	p->family = AF_INET;
	p->prefix = *addr;
	p->prefixlen =
		CHECK_FLAG(flags, ZEBRA_IFA_PEER) ? IPV4_MAX_BITLEN : prefixlen;
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
					"interface %s has same local and peer address %pI4, routing protocols may malfunction",
					ifp->name, addr);
		} else {
			zlog_debug(
				"%s called for interface %s with peer flag set, but no peer address supplied",
				__func__, ifp->name);
			UNSET_FLAG(ifc->flags, ZEBRA_IFA_PEER);
		}
	}

	/* no destination address was supplied */
	if (!dest && (prefixlen == IPV4_MAX_BITLEN) && if_is_pointopoint(ifp))
		zlog_debug(
			"PtP interface %s with addr %pI4/%d needs a peer address",
			ifp->name, addr, prefixlen);

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
	struct prefix p, plocal;
	struct nexthop nh = {
		.type = NEXTHOP_TYPE_IFINDEX,
		.ifindex = ifp->ifindex,
		.vrf_id = ifp->vrf->vrf_id,
	};
	struct zebra_vrf *zvrf;
	uint32_t count = 0;
	struct connected *c;
	bool remove_local = true;

	zvrf = ifp->vrf->info;
	if (!zvrf) {
		flog_err(
			EC_ZEBRA_VRF_NOT_FOUND,
			"%s: Received Down for interface but no associated zvrf: %s(%d)",
			__func__, ifp->vrf->name, ifp->vrf->vrf_id);
		return;
	}

	if (!CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL))
		return;

	/* Skip if we've already done this; this can happen if we have a
	 * config change that takes an interface down, then we receive kernel
	 * notifications about the downed interface and its addresses.
	 */
	if (CHECK_FLAG(ifc->conf, ZEBRA_IFC_DOWN)) {
		if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s: ifc %p, %pFX already DOWN",
				   __func__, ifc, ifc->address);
		return;
	}

	prefix_copy(&p, CONNECTED_PREFIX(ifc));
	prefix_copy(&plocal, ifc->address);

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

		plocal.prefixlen = IPV4_MAX_BITLEN;
		break;
	case AFI_IP6:
		if (IN6_IS_ADDR_UNSPECIFIED(&p.u.prefix6))
			return;

		plocal.prefixlen = IPV6_MAX_BITLEN;

		if (IN6_IS_ADDR_LINKLOCAL(&plocal.u.prefix6))
			remove_local = false;

		break;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
		zlog_warn("Unknown AFI: %s", afi2str(afi));
		break;
	}

	/* Mark the address as 'down' */
	SET_FLAG(ifc->conf, ZEBRA_IFC_DOWN);

	/*
	 * It's possible to have X number of addresses
	 * on a interface that all resolve to the same
	 * network and mask.  Find them and just
	 * allow the deletion when are removing the last
	 * one.
	 */
	frr_each (if_connected, ifp->connected, c) {
		struct prefix cp;

		prefix_copy(&cp, CONNECTED_PREFIX(c));
		apply_mask(&cp);

		if (prefix_same(&p, &cp) &&
		    !CHECK_FLAG(c->conf, ZEBRA_IFC_DOWN))
			count++;

		if (count >= 1)
			return;
	}

	/*
	 * Same logic as for connected_up(): push the changes into the
	 * head.
	 */
	if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_NOPREFIXROUTE)) {
		rib_delete(afi, SAFI_UNICAST, zvrf->vrf->vrf_id,
			   ZEBRA_ROUTE_CONNECT, 0, 0, &p, NULL, &nh, 0,
			   zvrf->table_id, 0, 0, false);

		rib_delete(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id,
			   ZEBRA_ROUTE_CONNECT, 0, 0, &p, NULL, &nh, 0,
			   zvrf->table_id, 0, 0, false);
	}

	if (remove_local) {
		rib_delete(afi, SAFI_UNICAST, zvrf->vrf->vrf_id,
			   ZEBRA_ROUTE_LOCAL, 0, 0, &plocal, NULL, &nh, 0,
			   zvrf->table_id, 0, 0, false);

		rib_delete(afi, SAFI_MULTICAST, zvrf->vrf->vrf_id,
			   ZEBRA_ROUTE_LOCAL, 0, 0, &plocal, NULL, &nh, 0,
			   zvrf->table_id, 0, 0, false);
	}

	/* Schedule LSP forwarding entries for processing, if appropriate. */
	if (zvrf->vrf->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IP %pFX address down, scheduling MPLS processing",
				zvrf->vrf->vrf_id, ifp->name, &p);
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
	if (ifp->vrf->vrf_id == VRF_DEFAULT) {
		if (IS_ZEBRA_DEBUG_MPLS)
			zlog_debug(
				"%u: IF %s IP %pFX address delete, scheduling MPLS processing",
				ifp->vrf->vrf_id, ifp->name, p);
		mpls_mark_lsps_for_processing(ifp->vrf->info, p);
	}
}

/* Delete connected IPv4 route to the interface. */
void connected_delete_ipv4(struct interface *ifp, int flags,
			   const struct in_addr *addr, uint16_t prefixlen,
			   const struct in_addr *dest)
{
	struct prefix p, d;
	struct connected *ifc;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;
	p.u.prefix4 = *addr;
	p.prefixlen =
		CHECK_FLAG(flags, ZEBRA_IFA_PEER) ? IPV4_MAX_BITLEN : prefixlen;

	if (dest) {
		memset(&d, 0, sizeof(d));
		d.family = AF_INET;
		d.u.prefix4 = *dest;
		d.prefixlen = prefixlen;
		ifc = connected_check_ptp(ifp, &p, &d);
	} else
		ifc = connected_check_ptp(ifp, &p, NULL);

	connected_delete_helper(ifc, &p);
}

/* Add connected IPv6 route to the interface. */
void connected_add_ipv6(struct interface *ifp, int flags,
			const struct in6_addr *addr,
			const struct in6_addr *dest, uint16_t prefixlen,
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
	if (!if_is_operative(ifp))
		SET_FLAG(ifc->conf, ZEBRA_IFC_DOWN);

	/* Allocate new connected address. */
	p = prefix_ipv6_new();
	p->family = AF_INET6;
	IPV6_ADDR_COPY(&p->prefix, addr);
	p->prefixlen = prefixlen;
	ifc->address = (struct prefix *)p;

	/* Add global ipv6 address to the RA prefix list */
	if (!IN6_IS_ADDR_LINKLOCAL(&p->prefix))
		rtadv_add_prefix(ifp->info, p);

	if (dest) {
		p = prefix_ipv6_new();
		p->family = AF_INET6;
		IPV6_ADDR_COPY(&p->prefix, dest);
		p->prefixlen = prefixlen;
		ifc->destination = (struct prefix *)p;
	} else {
		if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_PEER)) {
			zlog_debug(
				"%s called for interface %s with peer flag set, but no peer address supplied",
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

void connected_delete_ipv6(struct interface *ifp,
			   const struct in6_addr *address,
			   const struct in6_addr *dest, uint16_t prefixlen)
{
	struct prefix p, d;
	struct connected *ifc;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET6;
	memcpy(&p.u.prefix6, address, sizeof(struct in6_addr));
	p.prefixlen = prefixlen;

	/* Delete global ipv6 address from RA prefix list */
	if (!IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
		rtadv_delete_prefix(ifp->info, &p);

	if (dest) {
		memset(&d, 0, sizeof(d));
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

	frr_each (if_connected, ifp->connected, connected) {
		if (CHECK_FLAG(connected->conf, ZEBRA_IFC_REAL)
		    && connected->address->family == AF_INET)
			return CHECK_FLAG(connected->flags,
					  ZEBRA_IFA_UNNUMBERED);
	}
	return 0;
}
