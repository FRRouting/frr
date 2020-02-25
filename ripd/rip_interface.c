/* Interface related function for RIP.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "table.h"
#include "log.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"
#include "filter.h"
#include "sockopt.h"
#include "privs.h"
#include "lib_errors.h"
#include "northbound_cli.h"

#include "zebra/connected.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

DEFINE_MTYPE_STATIC(RIPD, RIP_INTERFACE, "RIP interface")
DEFINE_MTYPE(RIPD, RIP_INTERFACE_STRING, "RIP Interface String")
DEFINE_HOOK(rip_ifaddr_add, (struct connected * ifc), (ifc))
DEFINE_HOOK(rip_ifaddr_del, (struct connected * ifc), (ifc))

/* static prototypes */
static void rip_enable_apply(struct interface *);
static void rip_passive_interface_apply(struct interface *);
static int rip_if_down(struct interface *ifp);
static int rip_enable_if_lookup(struct rip *rip, const char *ifname);
static int rip_enable_network_lookup2(struct connected *connected);
static void rip_enable_apply_all(struct rip *rip);

const struct message ri_version_msg[] = {{RI_RIP_VERSION_1, "1"},
					 {RI_RIP_VERSION_2, "2"},
					 {RI_RIP_VERSION_1_AND_2, "1 2"},
					 {RI_RIP_VERSION_NONE, "none"},
					 {0}};

/* Join to the RIP version 2 multicast group. */
static int ipv4_multicast_join(int sock, struct in_addr group,
			       struct in_addr ifa, ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(sock, IP_ADD_MEMBERSHIP, ifa,
					group.s_addr, ifindex);

	if (ret < 0)
		zlog_info("can't setsockopt IP_ADD_MEMBERSHIP %s",
			  safe_strerror(errno));

	return ret;
}

/* Leave from the RIP version 2 multicast group. */
static int ipv4_multicast_leave(int sock, struct in_addr group,
				struct in_addr ifa, ifindex_t ifindex)
{
	int ret;

	ret = setsockopt_ipv4_multicast(sock, IP_DROP_MEMBERSHIP, ifa,
					group.s_addr, ifindex);

	if (ret < 0)
		zlog_info("can't setsockopt IP_DROP_MEMBERSHIP");

	return ret;
}

static void rip_interface_reset(struct rip_interface *);

/* Allocate new RIP's interface configuration. */
static struct rip_interface *rip_interface_new(void)
{
	struct rip_interface *ri;

	ri = XCALLOC(MTYPE_RIP_INTERFACE, sizeof(struct rip_interface));

	rip_interface_reset(ri);

	return ri;
}

void rip_interface_multicast_set(int sock, struct connected *connected)
{
	struct in_addr addr;

	assert(connected != NULL);

	addr = CONNECTED_ID(connected)->u.prefix4;

	if (setsockopt_ipv4_multicast_if(sock, addr, connected->ifp->ifindex)
	    < 0) {
		zlog_warn(
			"Can't setsockopt IP_MULTICAST_IF on fd %d to "
			"ifindex %d for interface %s",
			sock, connected->ifp->ifindex, connected->ifp->name);
	}

	return;
}

/* Send RIP request packet to specified interface. */
static void rip_request_interface_send(struct interface *ifp, uint8_t version)
{
	struct sockaddr_in to;

	/* RIPv2 support multicast. */
	if (version == RIPv2 && if_is_multicast(ifp)) {

		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("multicast request on %s", ifp->name);

		rip_request_send(NULL, ifp, version, NULL);
		return;
	}

	/* RIPv1 and non multicast interface. */
	if (if_is_pointopoint(ifp) || if_is_broadcast(ifp)) {
		struct listnode *cnode, *cnnode;
		struct connected *connected;

		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("broadcast request to %s", ifp->name);

		for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode,
				       connected)) {
			if (connected->address->family != AF_INET)
				continue;

			memset(&to, 0, sizeof(struct sockaddr_in));
			to.sin_port = htons(RIP_PORT_DEFAULT);
			if (connected->destination)
				/* use specified broadcast or peer
				 * destination addr */
				to.sin_addr = connected->destination->u.prefix4;
			else if (connected->address->prefixlen
				 < IPV4_MAX_PREFIXLEN)
				/* calculate the appropriate broadcast
				 * address */
				to.sin_addr.s_addr = ipv4_broadcast_addr(
					connected->address->u.prefix4.s_addr,
					connected->address->prefixlen);
			else
				/* do not know where to send the packet
				 */
				continue;

			if (IS_RIP_DEBUG_EVENT)
				zlog_debug("SEND request to %s",
					   inet_ntoa(to.sin_addr));

			rip_request_send(&to, ifp, version, connected);
		}
	}
}

/* This will be executed when interface goes up. */
static void rip_request_interface(struct interface *ifp)
{
	struct rip_interface *ri;
	int vsend;

	/* In default ripd doesn't send RIP_REQUEST to the loopback interface.
	 */
	if (if_is_loopback(ifp))
		return;

	/* If interface is down, don't send RIP packet. */
	if (!if_is_operative(ifp))
		return;

	/* Fetch RIP interface information. */
	ri = ifp->info;

	/* If there is no version configuration in the interface,
	   use rip's version setting. */
	vsend = ((ri->ri_send == RI_RIP_UNSPEC) ? ri->rip->version_send
						: ri->ri_send);
	if (vsend & RIPv1)
		rip_request_interface_send(ifp, RIPv1);
	if (vsend & RIPv2)
		rip_request_interface_send(ifp, RIPv2);
}

#if 0
/* Send RIP request to the neighbor. */
static void
rip_request_neighbor (struct in_addr addr)
{
  struct sockaddr_in to;

  memset (&to, 0, sizeof (struct sockaddr_in));
  to.sin_port = htons (RIP_PORT_DEFAULT);
  to.sin_addr = addr;

  rip_request_send (&to, NULL, rip->version_send, NULL);
}

/* Request routes at all interfaces. */
static void
rip_request_neighbor_all (void)
{
  struct route_node *rp;

  if (! rip)
    return;

  if (IS_RIP_DEBUG_EVENT)
    zlog_debug ("request to the all neighbor");

  /* Send request to all neighbor. */
  for (rp = route_top (rip->neighbor); rp; rp = route_next (rp))
    if (rp->info)
      rip_request_neighbor (rp->p.u.prefix4);
}
#endif

/* Multicast packet receive socket. */
static int rip_multicast_join(struct interface *ifp, int sock)
{
	struct listnode *cnode;
	struct connected *ifc;

	if (if_is_operative(ifp) && if_is_multicast(ifp)) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("multicast join at %s", ifp->name);

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, ifc)) {
			struct prefix_ipv4 *p;
			struct in_addr group;

			p = (struct prefix_ipv4 *)ifc->address;

			if (p->family != AF_INET)
				continue;

			group.s_addr = htonl(INADDR_RIP_GROUP);
			if (ipv4_multicast_join(sock, group, p->prefix,
						ifp->ifindex)
			    < 0)
				return -1;
			else
				return 0;
		}
	}
	return 0;
}

/* Leave from multicast group. */
static void rip_multicast_leave(struct interface *ifp, int sock)
{
	struct listnode *cnode;
	struct connected *connected;

	if (if_is_up(ifp) && if_is_multicast(ifp)) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("multicast leave from %s", ifp->name);

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
			struct prefix_ipv4 *p;
			struct in_addr group;

			p = (struct prefix_ipv4 *)connected->address;

			if (p->family != AF_INET)
				continue;

			group.s_addr = htonl(INADDR_RIP_GROUP);
			if (ipv4_multicast_leave(sock, group, p->prefix,
						 ifp->ifindex)
			    == 0)
				return;
		}
	}
}

/* Is there and address on interface that I could use ? */
static int rip_if_ipv4_address_check(struct interface *ifp)
{
	struct listnode *nn;
	struct connected *connected;
	int count = 0;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, nn, connected)) {
		struct prefix *p;

		p = connected->address;

		if (p->family == AF_INET)
			count++;
	}

	return count;
}


/* Does this address belongs to me ? */
int if_check_address(struct rip *rip, struct in_addr addr)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (rip->vrf, ifp) {
		struct listnode *cnode;
		struct connected *connected;

		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
			struct prefix_ipv4 *p;

			p = (struct prefix_ipv4 *)connected->address;

			if (p->family != AF_INET)
				continue;

			if (IPV4_ADDR_CMP(&p->prefix, &addr) == 0)
				return 1;
		}
	}
	return 0;
}

/* Inteface link down message processing. */
static int rip_ifp_down(struct interface *ifp)
{
	rip_interface_sync(ifp);
	rip_if_down(ifp);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface %s vrf %u index %d flags %llx metric %d mtu %d is down",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	return 0;
}

/* Inteface link up message processing */
static int rip_ifp_up(struct interface *ifp)
{
	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface %s vrf %u index %d flags %#llx metric %d mtu %d is up",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	rip_interface_sync(ifp);

	/* Check if this interface is RIP enabled or not.*/
	rip_enable_apply(ifp);

	/* Check for a passive interface */
	rip_passive_interface_apply(ifp);

	/* Apply distribute list to the all interface. */
	rip_distribute_update_interface(ifp);

	return 0;
}

/* Inteface addition message from zebra. */
static int rip_ifp_create(struct interface *ifp)
{
	rip_interface_sync(ifp);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface add %s vrf %u index %d flags %#llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	/* Check if this interface is RIP enabled or not.*/
	rip_enable_apply(ifp);

	/* Check for a passive interface */
	rip_passive_interface_apply(ifp);

	/* Apply distribute list to the all interface. */
	rip_distribute_update_interface(ifp);

	/* rip_request_neighbor_all (); */

	/* Check interface routemap. */
	rip_if_rmap_update_interface(ifp);

	return 0;
}

static int rip_ifp_destroy(struct interface *ifp)
{
	rip_interface_sync(ifp);
	if (if_is_up(ifp)) {
		rip_if_down(ifp);
	}

	zlog_info(
		"interface delete %s vrf %u index %d flags %#llx metric %d mtu %d",
		ifp->name, ifp->vrf_id, ifp->ifindex,
		(unsigned long long)ifp->flags, ifp->metric, ifp->mtu);

	return 0;
}

/* VRF update for an interface. */
int rip_interface_vrf_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	vrf_id_t new_vrf_id;

	ifp = zebra_interface_vrf_update_read(zclient->ibuf, vrf_id,
					      &new_vrf_id);
	if (!ifp)
		return 0;

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug("interface %s VRF change vrf_id %u new vrf id %u",
			   ifp->name, vrf_id, new_vrf_id);

	if_update_to_new_vrf(ifp, new_vrf_id);
	rip_interface_sync(ifp);

	return 0;
}

static void rip_interface_clean(struct rip_interface *ri)
{
	ri->enable_network = 0;
	ri->enable_interface = 0;
	ri->running = 0;

	if (ri->t_wakeup) {
		thread_cancel(ri->t_wakeup);
		ri->t_wakeup = NULL;
	}
}

void rip_interfaces_clean(struct rip *rip)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (rip->vrf, ifp)
		rip_interface_clean(ifp->info);
}

static void rip_interface_reset(struct rip_interface *ri)
{
	ri->auth_type = yang_get_default_enum("%s/authentication-scheme/mode",
					      RIP_IFACE);
	ri->md5_auth_len = yang_get_default_enum(
		"%s/authentication-scheme/md5-auth-length", RIP_IFACE);

	/* Set default split-horizon behavior.  If the interface is Frame
	   Relay or SMDS is enabled, the default value for split-horizon is
	   off.  But currently Zebra does detect Frame Relay or SMDS
	   interface.  So all interface is set to split horizon.  */
	ri->split_horizon =
		yang_get_default_enum("%s/split-horizon", RIP_IFACE);

	ri->ri_send = yang_get_default_enum("%s/version-send", RIP_IFACE);
	ri->ri_receive = yang_get_default_enum("%s/version-receive", RIP_IFACE);
	ri->v2_broadcast = yang_get_default_bool("%s/v2-broadcast", RIP_IFACE);

	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->auth_str);

	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->key_chain);

	ri->list[RIP_FILTER_IN] = NULL;
	ri->list[RIP_FILTER_OUT] = NULL;

	ri->prefix[RIP_FILTER_IN] = NULL;
	ri->prefix[RIP_FILTER_OUT] = NULL;

	ri->recv_badpackets = 0;
	ri->recv_badroutes = 0;
	ri->sent_updates = 0;

	ri->passive = 0;

	rip_interface_clean(ri);
}

int rip_if_down(struct interface *ifp)
{
	struct rip *rip;
	struct route_node *rp;
	struct rip_info *rinfo;
	struct rip_interface *ri = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL, *nextnode = NULL;

	ri = ifp->info;
	rip = ri->rip;
	if (rip) {
		for (rp = route_top(rip->table); rp; rp = route_next(rp))
			if ((list = rp->info) != NULL)
				for (ALL_LIST_ELEMENTS(list, listnode, nextnode,
						       rinfo))
					if (rinfo->nh.ifindex == ifp->ifindex)
						rip_ecmp_delete(rip, rinfo);

		if (ri->running) {
			if (IS_RIP_DEBUG_EVENT)
				zlog_debug("turn off %s", ifp->name);

			/* Leave from multicast group. */
			rip_multicast_leave(ifp, rip->sock);

			ri->running = 0;
		}
	}

	return 0;
}

static void rip_apply_address_add(struct connected *ifc)
{
	struct rip_interface *ri = ifc->ifp->info;
	struct rip *rip = ri->rip;
	struct prefix_ipv4 address;
	struct nexthop nh;
	struct prefix *p;

	if (!rip)
		return;

	if (!if_is_up(ifc->ifp))
		return;

	p = ifc->address;

	memset(&address, 0, sizeof(address));
	memset(&nh, 0, sizeof(nh));

	address.family = p->family;
	address.prefix = p->u.prefix4;
	address.prefixlen = p->prefixlen;
	apply_mask_ipv4(&address);

	nh.ifindex = ifc->ifp->ifindex;
	nh.type = NEXTHOP_TYPE_IFINDEX;

	/* Check if this interface is RIP enabled or not
	   or  Check if this address's prefix is RIP enabled */
	if ((rip_enable_if_lookup(rip, ifc->ifp->name) >= 0)
	    || (rip_enable_network_lookup2(ifc) >= 0))
		rip_redistribute_add(rip, ZEBRA_ROUTE_CONNECT,
				     RIP_ROUTE_INTERFACE, &address, &nh, 0, 0,
				     0);
}

int rip_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;
	struct prefix *p;

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					   zclient->ibuf, vrf_id);

	if (ifc == NULL)
		return 0;

	p = ifc->address;

	if (p->family == AF_INET) {
		if (IS_RIP_DEBUG_ZEBRA)
			zlog_debug("connected address %s/%d is added",
				   inet_ntoa(p->u.prefix4), p->prefixlen);

		rip_enable_apply(ifc->ifp);
		/* Check if this prefix needs to be redistributed */
		rip_apply_address_add(ifc);

		hook_call(rip_ifaddr_add, ifc);
	}

	return 0;
}

static void rip_apply_address_del(struct connected *ifc)
{
	struct rip_interface *ri = ifc->ifp->info;
	struct rip *rip = ri->rip;
	struct prefix_ipv4 address;
	struct prefix *p;

	if (!rip)
		return;

	if (!if_is_up(ifc->ifp))
		return;

	p = ifc->address;

	memset(&address, 0, sizeof(address));
	address.family = p->family;
	address.prefix = p->u.prefix4;
	address.prefixlen = p->prefixlen;
	apply_mask_ipv4(&address);

	rip_redistribute_delete(rip, ZEBRA_ROUTE_CONNECT, RIP_ROUTE_INTERFACE,
				&address, ifc->ifp->ifindex);
}

int rip_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;
	struct prefix *p;

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					   zclient->ibuf, vrf_id);

	if (ifc) {
		p = ifc->address;
		if (p->family == AF_INET) {
			if (IS_RIP_DEBUG_ZEBRA)
				zlog_debug("connected address %s/%d is deleted",
					   inet_ntoa(p->u.prefix4),
					   p->prefixlen);

			hook_call(rip_ifaddr_del, ifc);

			/* Chech wether this prefix needs to be removed */
			rip_apply_address_del(ifc);
		}

		connected_free(&ifc);
	}

	return 0;
}

/* Check interface is enabled by network statement. */
/* Check wether the interface has at least a connected prefix that
 * is within the ripng_enable_network table. */
static int rip_enable_network_lookup_if(struct interface *ifp)
{
	struct rip_interface *ri = ifp->info;
	struct rip *rip = ri->rip;
	struct listnode *node, *nnode;
	struct connected *connected;
	struct prefix_ipv4 address;

	if (!rip)
		return -1;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix *p;
		struct route_node *n;

		p = connected->address;

		if (p->family == AF_INET) {
			address.family = AF_INET;
			address.prefix = p->u.prefix4;
			address.prefixlen = IPV4_MAX_BITLEN;

			n = route_node_match(rip->enable_network,
					     (struct prefix *)&address);
			if (n) {
				route_unlock_node(n);
				return 1;
			}
		}
	}
	return -1;
}

/* Check wether connected is within the ripng_enable_network table. */
static int rip_enable_network_lookup2(struct connected *connected)
{
	struct rip_interface *ri = connected->ifp->info;
	struct rip *rip = ri->rip;
	struct prefix_ipv4 address;
	struct prefix *p;

	p = connected->address;

	if (p->family == AF_INET) {
		struct route_node *node;

		address.family = p->family;
		address.prefix = p->u.prefix4;
		address.prefixlen = IPV4_MAX_BITLEN;

		/* LPM on p->family, p->u.prefix4/IPV4_MAX_BITLEN within
		 * rip->enable_network */
		node = route_node_match(rip->enable_network,
					(struct prefix *)&address);

		if (node) {
			route_unlock_node(node);
			return 1;
		}
	}

	return -1;
}
/* Add RIP enable network. */
int rip_enable_network_add(struct rip *rip, struct prefix *p)
{
	struct route_node *node;

	node = route_node_get(rip->enable_network, p);

	if (node->info) {
		route_unlock_node(node);
		return NB_ERR_INCONSISTENCY;
	} else
		node->info = (void *)1;

	/* XXX: One should find a better solution than a generic one */
	rip_enable_apply_all(rip);

	return NB_OK;
}

/* Delete RIP enable network. */
int rip_enable_network_delete(struct rip *rip, struct prefix *p)
{
	struct route_node *node;

	node = route_node_lookup(rip->enable_network, p);
	if (node) {
		node->info = NULL;

		/* Unlock info lock. */
		route_unlock_node(node);

		/* Unlock lookup lock. */
		route_unlock_node(node);

		/* XXX: One should find a better solution than a generic one */
		rip_enable_apply_all(rip);

		return NB_OK;
	}

	return NB_ERR_INCONSISTENCY;
}

/* Check interface is enabled by ifname statement. */
static int rip_enable_if_lookup(struct rip *rip, const char *ifname)
{
	unsigned int i;
	char *str;

	if (!rip)
		return -1;

	for (i = 0; i < vector_active(rip->enable_interface); i++)
		if ((str = vector_slot(rip->enable_interface, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

/* Add interface to rip_enable_if. */
int rip_enable_if_add(struct rip *rip, const char *ifname)
{
	int ret;

	ret = rip_enable_if_lookup(rip, ifname);
	if (ret >= 0)
		return NB_ERR_INCONSISTENCY;

	vector_set(rip->enable_interface,
		   XSTRDUP(MTYPE_RIP_INTERFACE_STRING, ifname));

	rip_enable_apply_all(rip); /* TODOVJ */

	return NB_OK;
}

/* Delete interface from rip_enable_if. */
int rip_enable_if_delete(struct rip *rip, const char *ifname)
{
	int index;
	char *str;

	index = rip_enable_if_lookup(rip, ifname);
	if (index < 0)
		return NB_ERR_INCONSISTENCY;

	str = vector_slot(rip->enable_interface, index);
	XFREE(MTYPE_RIP_INTERFACE_STRING, str);
	vector_unset(rip->enable_interface, index);

	rip_enable_apply_all(rip); /* TODOVJ */

	return NB_OK;
}

/* Join to multicast group and send request to the interface. */
static int rip_interface_wakeup(struct thread *t)
{
	struct interface *ifp;
	struct rip_interface *ri;

	/* Get interface. */
	ifp = THREAD_ARG(t);

	ri = ifp->info;
	ri->t_wakeup = NULL;

	/* Join to multicast group. */
	if (rip_multicast_join(ifp, ri->rip->sock) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "multicast join failed, interface %s not running",
			     ifp->name);
		return 0;
	}

	/* Set running flag. */
	ri->running = 1;

	/* Send RIP request to the interface. */
	rip_request_interface(ifp);

	return 0;
}

static void rip_connect_set(struct interface *ifp, int set)
{
	struct rip_interface *ri = ifp->info;
	struct rip *rip = ri->rip;
	struct listnode *node, *nnode;
	struct connected *connected;
	struct prefix_ipv4 address;
	struct nexthop nh;

	memset(&nh, 0, sizeof(nh));

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix *p;
		p = connected->address;

		if (p->family != AF_INET)
			continue;

		address.family = AF_INET;
		address.prefix = p->u.prefix4;
		address.prefixlen = p->prefixlen;
		apply_mask_ipv4(&address);

		nh.ifindex = connected->ifp->ifindex;
		nh.type = NEXTHOP_TYPE_IFINDEX;
		if (set) {
			/* Check once more wether this prefix is within a
			 * "network IF_OR_PREF" one */
			if ((rip_enable_if_lookup(rip, connected->ifp->name)
			     >= 0)
			    || (rip_enable_network_lookup2(connected) >= 0))
				rip_redistribute_add(rip, ZEBRA_ROUTE_CONNECT,
						     RIP_ROUTE_INTERFACE,
						     &address, &nh, 0, 0, 0);
		} else {
			rip_redistribute_delete(rip, ZEBRA_ROUTE_CONNECT,
						RIP_ROUTE_INTERFACE, &address,
						connected->ifp->ifindex);
			if (rip_redistribute_check(rip, ZEBRA_ROUTE_CONNECT))
				rip_redistribute_add(rip, ZEBRA_ROUTE_CONNECT,
						     RIP_ROUTE_REDISTRIBUTE,
						     &address, &nh, 0, 0, 0);
		}
	}
}

/* Update interface status. */
void rip_enable_apply(struct interface *ifp)
{
	int ret;
	struct rip_interface *ri = NULL;

	/* Check interface. */
	if (!if_is_operative(ifp))
		return;

	ri = ifp->info;

	/* Check network configuration. */
	ret = rip_enable_network_lookup_if(ifp);

	/* If the interface is matched. */
	if (ret > 0)
		ri->enable_network = 1;
	else
		ri->enable_network = 0;

	/* Check interface name configuration. */
	ret = rip_enable_if_lookup(ri->rip, ifp->name);
	if (ret >= 0)
		ri->enable_interface = 1;
	else
		ri->enable_interface = 0;

	/* any interface MUST have an IPv4 address */
	if (!rip_if_ipv4_address_check(ifp)) {
		ri->enable_network = 0;
		ri->enable_interface = 0;
	}

	/* Update running status of the interface. */
	if (ri->enable_network || ri->enable_interface) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("turn on %s", ifp->name);

		/* Add interface wake up thread. */
		thread_add_timer(master, rip_interface_wakeup, ifp, 1,
				 &ri->t_wakeup);
		rip_connect_set(ifp, 1);
	} else if (ri->running) {
		/* Might as well clean up the route table as well
		 * rip_if_down sets to 0 ri->running, and displays "turn
		 *off %s"
		 **/
		rip_if_down(ifp);

		rip_connect_set(ifp, 0);
	}
}

/* Apply network configuration to all interface. */
static void rip_enable_apply_all(struct rip *rip)
{
	struct interface *ifp;

	/* Check each interface. */
	FOR_ALL_INTERFACES (rip->vrf, ifp)
		rip_enable_apply(ifp);
}

int rip_neighbor_lookup(struct rip *rip, struct sockaddr_in *from)
{
	struct prefix_ipv4 p;
	struct route_node *node;

	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefix = from->sin_addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	node = route_node_lookup(rip->neighbor, (struct prefix *)&p);
	if (node) {
		route_unlock_node(node);
		return 1;
	}
	return 0;
}

/* Add new RIP neighbor to the neighbor tree. */
int rip_neighbor_add(struct rip *rip, struct prefix_ipv4 *p)
{
	struct route_node *node;

	node = route_node_get(rip->neighbor, (struct prefix *)p);

	if (node->info)
		return NB_ERR_INCONSISTENCY;

	node->info = rip->neighbor;

	return NB_OK;
}

/* Delete RIP neighbor from the neighbor tree. */
int rip_neighbor_delete(struct rip *rip, struct prefix_ipv4 *p)
{
	struct route_node *node;

	/* Lock for look up. */
	node = route_node_lookup(rip->neighbor, (struct prefix *)p);
	if (!node)
		return NB_ERR_INCONSISTENCY;

	node->info = NULL;

	/* Unlock lookup lock. */
	route_unlock_node(node);

	/* Unlock real neighbor information lock. */
	route_unlock_node(node);

	return NB_OK;
}

/* Clear all network and neighbor configuration. */
void rip_clean_network(struct rip *rip)
{
	unsigned int i;
	char *str;
	struct route_node *rn;

	/* rip->enable_network. */
	for (rn = route_top(rip->enable_network); rn; rn = route_next(rn))
		if (rn->info) {
			rn->info = NULL;
			route_unlock_node(rn);
		}

	/* rip->enable_interface. */
	for (i = 0; i < vector_active(rip->enable_interface); i++)
		if ((str = vector_slot(rip->enable_interface, i)) != NULL) {
			XFREE(MTYPE_RIP_INTERFACE_STRING, str);
			vector_slot(rip->enable_interface, i) = NULL;
		}
}

/* Utility function for looking up passive interface settings. */
static int rip_passive_nondefault_lookup(struct rip *rip, const char *ifname)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(rip->passive_nondefault); i++)
		if ((str = vector_slot(rip->passive_nondefault, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

static void rip_passive_interface_apply(struct interface *ifp)
{
	struct rip *rip;
	struct rip_interface *ri;

	ri = ifp->info;
	rip = ri->rip;
	if (rip == NULL)
		return;

	ri->passive = ((rip_passive_nondefault_lookup(rip, ifp->name) < 0)
			       ? rip->passive_default
			       : !rip->passive_default);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug("interface %s: passive = %d", ifp->name,
			   ri->passive);
}

static void rip_passive_interface_apply_all(struct rip *rip)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (rip->vrf, ifp)
		rip_passive_interface_apply(ifp);
}

/* Passive interface. */
int rip_passive_nondefault_set(struct rip *rip, const char *ifname)
{
	if (rip_passive_nondefault_lookup(rip, ifname) >= 0)
		/*
		 * Don't return an error, this can happen after changing
		 * 'passive-default'.
		 */
		return NB_OK;

	vector_set(rip->passive_nondefault,
		   XSTRDUP(MTYPE_RIP_INTERFACE_STRING, ifname));

	rip_passive_interface_apply_all(rip);

	return NB_OK;
}

int rip_passive_nondefault_unset(struct rip *rip, const char *ifname)
{
	int i;
	char *str;

	i = rip_passive_nondefault_lookup(rip, ifname);
	if (i < 0)
		/*
		 * Don't return an error, this can happen after changing
		 * 'passive-default'.
		 */
		return NB_OK;

	str = vector_slot(rip->passive_nondefault, i);
	XFREE(MTYPE_RIP_INTERFACE_STRING, str);
	vector_unset(rip->passive_nondefault, i);

	rip_passive_interface_apply_all(rip);

	return NB_OK;
}

/* Free all configured RIP passive-interface settings. */
void rip_passive_nondefault_clean(struct rip *rip)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(rip->passive_nondefault); i++)
		if ((str = vector_slot(rip->passive_nondefault, i)) != NULL) {
			XFREE(MTYPE_RIP_INTERFACE_STRING, str);
			vector_slot(rip->passive_nondefault, i) = NULL;
		}
	rip_passive_interface_apply_all(rip);
}

/* Write rip configuration of each interface. */
static int rip_interface_config_write(struct vty *vty)
{
	struct vrf *vrf;
	int write = 0;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct interface *ifp;

		FOR_ALL_INTERFACES (vrf, ifp) {
			struct lyd_node *dnode;

			dnode = yang_dnode_get(
				running_config->dnode,
				"/frr-interface:lib/interface[name='%s'][vrf='%s']",
				ifp->name, vrf->name);
			if (dnode == NULL)
				continue;

			write = 1;
			nb_cli_show_dnode_cmds(vty, dnode, false);
		}
	}

	return write;
}

int rip_show_network_config(struct vty *vty, struct rip *rip)
{
	unsigned int i;
	char *ifname;
	struct route_node *node;

	/* Network type RIP enable interface statement. */
	for (node = route_top(rip->enable_network); node;
	     node = route_next(node))
		if (node->info)
			vty_out(vty, "    %s/%u\n",
				inet_ntoa(node->p.u.prefix4),
				node->p.prefixlen);

	/* Interface name RIP enable statement. */
	for (i = 0; i < vector_active(rip->enable_interface); i++)
		if ((ifname = vector_slot(rip->enable_interface, i)) != NULL)
			vty_out(vty, "    %s\n", ifname);

	/* RIP neighbors listing. */
	for (node = route_top(rip->neighbor); node; node = route_next(node))
		if (node->info)
			vty_out(vty, "    %s\n", inet_ntoa(node->p.u.prefix4));

	return 0;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1,
};

void rip_interface_sync(struct interface *ifp)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (vrf) {
		struct rip_interface *ri;

		ri = ifp->info;
		if (ri)
			ri->rip = vrf->info;
	}
}

/* Called when interface structure allocated. */
static int rip_interface_new_hook(struct interface *ifp)
{
	ifp->info = rip_interface_new();
	rip_interface_sync(ifp);

	return 0;
}

/* Called when interface structure deleted. */
static int rip_interface_delete_hook(struct interface *ifp)
{
	rip_interface_reset(ifp->info);
	XFREE(MTYPE_RIP_INTERFACE, ifp->info);
	ifp->info = NULL;
	return 0;
}

/* Allocate and initialize interface vector. */
void rip_if_init(void)
{
	/* Default initial size of interface vector. */
	hook_register_prio(if_add, 0, rip_interface_new_hook);
	hook_register_prio(if_del, 0, rip_interface_delete_hook);

	/* Install interface node. */
	install_node(&interface_node, rip_interface_config_write);
	if_cmd_init();
	if_zapi_callbacks(rip_ifp_create, rip_ifp_up,
			  rip_ifp_down, rip_ifp_destroy);
}
