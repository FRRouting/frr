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

#include "zebra/connected.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

DEFINE_HOOK(rip_ifaddr_add, (struct connected * ifc), (ifc))
DEFINE_HOOK(rip_ifaddr_del, (struct connected * ifc), (ifc))

/* static prototypes */
static void rip_enable_apply(struct interface *);
static void rip_passive_interface_apply(struct interface *);
static int rip_if_down(struct interface *ifp);
static int rip_enable_if_lookup(const char *ifname);
static int rip_enable_network_lookup2(struct connected *connected);
static void rip_enable_apply_all(void);

const struct message ri_version_msg[] = {{RI_RIP_VERSION_1, "1"},
					 {RI_RIP_VERSION_2, "2"},
					 {RI_RIP_VERSION_1_AND_2, "1 2"},
					 {RI_RIP_VERSION_NONE, "none"},
					 {0}};

extern struct zebra_privs_t ripd_privs;

/* RIP enabled network vector. */
vector rip_enable_interface;

/* RIP enabled interface table. */
struct route_table *rip_enable_network;

/* Vector to store passive-interface name. */
static int passive_default; /* are we in passive-interface default mode? */
vector Vrip_passive_nondefault;

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
static void rip_request_interface_send(struct interface *ifp, u_char version)
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
			if (connected->address->family == AF_INET) {
				memset(&to, 0, sizeof(struct sockaddr_in));
				to.sin_port = htons(RIP_PORT_DEFAULT);
				if (connected->destination)
					/* use specified broadcast or peer
					 * destination addr */
					to.sin_addr = connected->destination->u
							      .prefix4;
				else if (connected->address->prefixlen
					 < IPV4_MAX_PREFIXLEN)
					/* calculate the appropriate broadcast
					 * address */
					to.sin_addr
						.s_addr = ipv4_broadcast_addr(
						connected->address->u.prefix4
							.s_addr,
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
}

/* This will be executed when interface goes up. */
static void rip_request_interface(struct interface *ifp)
{
	struct rip_interface *ri;

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
	{
		int vsend = ((ri->ri_send == RI_RIP_UNSPEC) ? rip->version_send
							    : ri->ri_send);
		if (vsend & RIPv1)
			rip_request_interface_send(ifp, RIPv1);
		if (vsend & RIPv2)
			rip_request_interface_send(ifp, RIPv2);
	}
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
int if_check_address(struct in_addr addr)
{
	struct listnode *node;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp)) {
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
int rip_interface_down(int command, struct zclient *zclient,
		       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;

	/* zebra_interface_state_read() updates interface structure in
	   iflist. */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	rip_if_down(ifp);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface %s index %d flags %llx metric %d mtu %d is down",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	return 0;
}

/* Inteface link up message processing */
int rip_interface_up(int command, struct zclient *zclient, zebra_size_t length,
		     vrf_id_t vrf_id)
{
	struct interface *ifp;

	/* zebra_interface_state_read () updates interface structure in
	   iflist. */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface %s index %d flags %#llx metric %d mtu %d is up",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	/* Check if this interface is RIP enabled or not.*/
	rip_enable_apply(ifp);

	/* Check for a passive interface */
	rip_passive_interface_apply(ifp);

	/* Apply distribute list to the all interface. */
	rip_distribute_update_interface(ifp);

	return 0;
}

/* Inteface addition message from zebra. */
int rip_interface_add(int command, struct zclient *zclient, zebra_size_t length,
		      vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug(
			"interface add %s index %d flags %#llx metric %d mtu %d",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

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

int rip_interface_delete(int command, struct zclient *zclient,
			 zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;


	s = zclient->ibuf;
	/* zebra_interface_state_read() updates interface structure in iflist */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if (if_is_up(ifp)) {
		rip_if_down(ifp);
	}

	zlog_info("interface delete %s index %d flags %#llx metric %d mtu %d",
		  ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
		  ifp->metric, ifp->mtu);

	/* To support pseudo interface do not free interface structure.  */
	/* if_delete(ifp); */
	ifp->ifindex = IFINDEX_DELETED;

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

void rip_interfaces_clean(void)
{
	struct listnode *node;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp))
		rip_interface_clean(ifp->info);
}

static void rip_interface_reset(struct rip_interface *ri)
{
	/* Default authentication type is simple password for Cisco
	   compatibility. */
	ri->auth_type = RIP_NO_AUTH;
	ri->md5_auth_len = RIP_AUTH_MD5_COMPAT_SIZE;

	/* Set default split-horizon behavior.  If the interface is Frame
	   Relay or SMDS is enabled, the default value for split-horizon is
	   off.  But currently Zebra does detect Frame Relay or SMDS
	   interface.  So all interface is set to split horizon.  */
	ri->split_horizon_default = RIP_SPLIT_HORIZON;
	ri->split_horizon = ri->split_horizon_default;

	ri->ri_send = RI_RIP_UNSPEC;
	ri->ri_receive = RI_RIP_UNSPEC;

	ri->v2_broadcast = 0;

	if (ri->auth_str) {
		free(ri->auth_str);
		ri->auth_str = NULL;
	}
	if (ri->key_chain) {
		free(ri->key_chain);
		ri->key_chain = NULL;
	}

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

void rip_interfaces_reset(void)
{
	struct listnode *node;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp))
		rip_interface_reset(ifp->info);
}

int rip_if_down(struct interface *ifp)
{
	struct route_node *rp;
	struct rip_info *rinfo;
	struct rip_interface *ri = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL, *nextnode = NULL;
	if (rip) {
		for (rp = route_top(rip->table); rp; rp = route_next(rp))
			if ((list = rp->info) != NULL)
				for (ALL_LIST_ELEMENTS(list, listnode, nextnode,
						       rinfo))
					if (rinfo->ifindex == ifp->ifindex)
						rip_ecmp_delete(rinfo);

		ri = ifp->info;

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

/* Needed for stop RIP process. */
void rip_if_down_all()
{
	struct interface *ifp;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(vrf_iflist(VRF_DEFAULT), node, nnode, ifp))
		rip_if_down(ifp);
}

static void rip_apply_address_add(struct connected *ifc)
{
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

	/* Check if this interface is RIP enabled or not
	   or  Check if this address's prefix is RIP enabled */
	if ((rip_enable_if_lookup(ifc->ifp->name) >= 0)
	    || (rip_enable_network_lookup2(ifc) >= 0))
		rip_redistribute_add(ZEBRA_ROUTE_CONNECT, RIP_ROUTE_INTERFACE,
				     &address, ifc->ifp->ifindex, NULL, 0, 0,
				     0);
}

int rip_interface_address_add(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
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

	rip_redistribute_delete(ZEBRA_ROUTE_CONNECT, RIP_ROUTE_INTERFACE,
				&address, ifc->ifp->ifindex);
}

int rip_interface_address_delete(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
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

		connected_free(ifc);
	}

	return 0;
}

/* Check interface is enabled by network statement. */
/* Check wether the interface has at least a connected prefix that
 * is within the ripng_enable_network table. */
static int rip_enable_network_lookup_if(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct connected *connected;
	struct prefix_ipv4 address;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix *p;
		struct route_node *node;

		p = connected->address;

		if (p->family == AF_INET) {
			address.family = AF_INET;
			address.prefix = p->u.prefix4;
			address.prefixlen = IPV4_MAX_BITLEN;

			node = route_node_match(rip_enable_network,
						(struct prefix *)&address);
			if (node) {
				route_unlock_node(node);
				return 1;
			}
		}
	}
	return -1;
}

/* Check wether connected is within the ripng_enable_network table. */
int rip_enable_network_lookup2(struct connected *connected)
{
	struct prefix_ipv4 address;
	struct prefix *p;

	p = connected->address;

	if (p->family == AF_INET) {
		struct route_node *node;

		address.family = p->family;
		address.prefix = p->u.prefix4;
		address.prefixlen = IPV4_MAX_BITLEN;

		/* LPM on p->family, p->u.prefix4/IPV4_MAX_BITLEN within
		 * rip_enable_network */
		node = route_node_match(rip_enable_network,
					(struct prefix *)&address);

		if (node) {
			route_unlock_node(node);
			return 1;
		}
	}

	return -1;
}
/* Add RIP enable network. */
static int rip_enable_network_add(struct prefix *p)
{
	struct route_node *node;

	node = route_node_get(rip_enable_network, p);

	if (node->info) {
		route_unlock_node(node);
		return -1;
	} else
		node->info = (void *)1;

	/* XXX: One should find a better solution than a generic one */
	rip_enable_apply_all();

	return 1;
}

/* Delete RIP enable network. */
static int rip_enable_network_delete(struct prefix *p)
{
	struct route_node *node;

	node = route_node_lookup(rip_enable_network, p);
	if (node) {
		node->info = NULL;

		/* Unlock info lock. */
		route_unlock_node(node);

		/* Unlock lookup lock. */
		route_unlock_node(node);

		/* XXX: One should find a better solution than a generic one */
		rip_enable_apply_all();

		return 1;
	}
	return -1;
}

/* Check interface is enabled by ifname statement. */
static int rip_enable_if_lookup(const char *ifname)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(rip_enable_interface); i++)
		if ((str = vector_slot(rip_enable_interface, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

/* Add interface to rip_enable_if. */
static int rip_enable_if_add(const char *ifname)
{
	int ret;

	ret = rip_enable_if_lookup(ifname);
	if (ret >= 0)
		return -1;

	vector_set(rip_enable_interface, strdup(ifname));

	rip_enable_apply_all(); /* TODOVJ */

	return 1;
}

/* Delete interface from rip_enable_if. */
static int rip_enable_if_delete(const char *ifname)
{
	int index;
	char *str;

	index = rip_enable_if_lookup(ifname);
	if (index < 0)
		return -1;

	str = vector_slot(rip_enable_interface, index);
	free(str);
	vector_unset(rip_enable_interface, index);

	rip_enable_apply_all(); /* TODOVJ */

	return 1;
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
	if (rip_multicast_join(ifp, rip->sock) < 0) {
		zlog_err("multicast join failed, interface %s not running",
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
	struct listnode *node, *nnode;
	struct connected *connected;
	struct prefix_ipv4 address;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix *p;
		p = connected->address;

		if (p->family != AF_INET)
			continue;

		address.family = AF_INET;
		address.prefix = p->u.prefix4;
		address.prefixlen = p->prefixlen;
		apply_mask_ipv4(&address);

		if (set) {
			/* Check once more wether this prefix is within a
			 * "network IF_OR_PREF" one */
			if ((rip_enable_if_lookup(connected->ifp->name) >= 0)
			    || (rip_enable_network_lookup2(connected) >= 0))
				rip_redistribute_add(
					ZEBRA_ROUTE_CONNECT,
					RIP_ROUTE_INTERFACE, &address,
					connected->ifp->ifindex, NULL, 0, 0, 0);
		} else {
			rip_redistribute_delete(ZEBRA_ROUTE_CONNECT,
						RIP_ROUTE_INTERFACE, &address,
						connected->ifp->ifindex);
			if (rip_redistribute_check(ZEBRA_ROUTE_CONNECT))
				rip_redistribute_add(
					ZEBRA_ROUTE_CONNECT,
					RIP_ROUTE_REDISTRIBUTE, &address,
					connected->ifp->ifindex, NULL, 0, 0, 0);
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
	ret = rip_enable_if_lookup(ifp->name);
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
		{
			if (IS_RIP_DEBUG_EVENT)
				zlog_debug("turn on %s", ifp->name);

			/* Add interface wake up thread. */
			thread_add_timer(master, rip_interface_wakeup, ifp, 1,
					 &ri->t_wakeup);
			rip_connect_set(ifp, 1);
		}
	} else {
		if (ri->running) {
			/* Might as well clean up the route table as well
			 * rip_if_down sets to 0 ri->running, and displays "turn
			 *off %s"
			 **/
			rip_if_down(ifp);

			rip_connect_set(ifp, 0);
		}
	}
}

/* Apply network configuration to all interface. */
void rip_enable_apply_all()
{
	struct interface *ifp;
	struct listnode *node, *nnode;

	/* Check each interface. */
	for (ALL_LIST_ELEMENTS(vrf_iflist(VRF_DEFAULT), node, nnode, ifp))
		rip_enable_apply(ifp);
}

int rip_neighbor_lookup(struct sockaddr_in *from)
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
static int rip_neighbor_add(struct prefix_ipv4 *p)
{
	struct route_node *node;

	node = route_node_get(rip->neighbor, (struct prefix *)p);

	if (node->info)
		return -1;

	node->info = rip->neighbor;

	return 0;
}

/* Delete RIP neighbor from the neighbor tree. */
static int rip_neighbor_delete(struct prefix_ipv4 *p)
{
	struct route_node *node;

	/* Lock for look up. */
	node = route_node_lookup(rip->neighbor, (struct prefix *)p);
	if (!node)
		return -1;

	node->info = NULL;

	/* Unlock lookup lock. */
	route_unlock_node(node);

	/* Unlock real neighbor information lock. */
	route_unlock_node(node);

	return 0;
}

/* Clear all network and neighbor configuration. */
void rip_clean_network()
{
	unsigned int i;
	char *str;
	struct route_node *rn;

	/* rip_enable_network. */
	for (rn = route_top(rip_enable_network); rn; rn = route_next(rn))
		if (rn->info) {
			rn->info = NULL;
			route_unlock_node(rn);
		}

	/* rip_enable_interface. */
	for (i = 0; i < vector_active(rip_enable_interface); i++)
		if ((str = vector_slot(rip_enable_interface, i)) != NULL) {
			free(str);
			vector_slot(rip_enable_interface, i) = NULL;
		}
}

/* Utility function for looking up passive interface settings. */
static int rip_passive_nondefault_lookup(const char *ifname)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(Vrip_passive_nondefault); i++)
		if ((str = vector_slot(Vrip_passive_nondefault, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

void rip_passive_interface_apply(struct interface *ifp)
{
	struct rip_interface *ri;

	ri = ifp->info;

	ri->passive = ((rip_passive_nondefault_lookup(ifp->name) < 0)
			       ? passive_default
			       : !passive_default);

	if (IS_RIP_DEBUG_ZEBRA)
		zlog_debug("interface %s: passive = %d", ifp->name,
			   ri->passive);
}

static void rip_passive_interface_apply_all(void)
{
	struct interface *ifp;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(vrf_iflist(VRF_DEFAULT), node, nnode, ifp))
		rip_passive_interface_apply(ifp);
}

/* Passive interface. */
static int rip_passive_nondefault_set(struct vty *vty, const char *ifname)
{
	if (rip_passive_nondefault_lookup(ifname) >= 0)
		return CMD_WARNING_CONFIG_FAILED;

	vector_set(Vrip_passive_nondefault, strdup(ifname));

	rip_passive_interface_apply_all();

	return CMD_SUCCESS;
}

static int rip_passive_nondefault_unset(struct vty *vty, const char *ifname)
{
	int i;
	char *str;

	i = rip_passive_nondefault_lookup(ifname);
	if (i < 0)
		return CMD_WARNING_CONFIG_FAILED;

	str = vector_slot(Vrip_passive_nondefault, i);
	free(str);
	vector_unset(Vrip_passive_nondefault, i);

	rip_passive_interface_apply_all();

	return CMD_SUCCESS;
}

/* Free all configured RIP passive-interface settings. */
void rip_passive_nondefault_clean(void)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(Vrip_passive_nondefault); i++)
		if ((str = vector_slot(Vrip_passive_nondefault, i)) != NULL) {
			free(str);
			vector_slot(Vrip_passive_nondefault, i) = NULL;
		}
	rip_passive_interface_apply_all();
}

/* RIP enable network or interface configuration. */
DEFUN (rip_network,
       rip_network_cmd,
       "network <A.B.C.D/M|WORD>",
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Interface name\n")
{
	int idx_ipv4_word = 1;
	int ret;
	struct prefix_ipv4 p;

	ret = str2prefix_ipv4(argv[idx_ipv4_word]->arg, &p);

	if (ret)
		ret = rip_enable_network_add((struct prefix *)&p);
	else
		ret = rip_enable_if_add(argv[idx_ipv4_word]->arg);

	if (ret < 0) {
		vty_out(vty, "There is a same network configuration %s\n",
			argv[idx_ipv4_word]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* RIP enable network or interface configuration. */
DEFUN (no_rip_network,
       no_rip_network_cmd,
       "no network <A.B.C.D/M|WORD>",
       NO_STR
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Interface name\n")
{
	int idx_ipv4_word = 2;
	int ret;
	struct prefix_ipv4 p;

	ret = str2prefix_ipv4(argv[idx_ipv4_word]->arg, &p);

	if (ret)
		ret = rip_enable_network_delete((struct prefix *)&p);
	else
		ret = rip_enable_if_delete(argv[idx_ipv4_word]->arg);

	if (ret < 0) {
		vty_out(vty, "Can't find network configuration %s\n",
			argv[idx_ipv4_word]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

/* RIP neighbor configuration set. */
DEFUN (rip_neighbor,
       rip_neighbor_cmd,
       "neighbor A.B.C.D",
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	int idx_ipv4 = 1;
	int ret;
	struct prefix_ipv4 p;

	ret = str2prefix_ipv4(argv[idx_ipv4]->arg, &p);

	if (ret <= 0) {
		vty_out(vty, "Please specify address by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rip_neighbor_add(&p);

	return CMD_SUCCESS;
}

/* RIP neighbor configuration unset. */
DEFUN (no_rip_neighbor,
       no_rip_neighbor_cmd,
       "no neighbor A.B.C.D",
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	int idx_ipv4 = 2;
	int ret;
	struct prefix_ipv4 p;

	ret = str2prefix_ipv4(argv[idx_ipv4]->arg, &p);

	if (ret <= 0) {
		vty_out(vty, "Please specify address by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rip_neighbor_delete(&p);

	return CMD_SUCCESS;
}

DEFUN (ip_rip_receive_version,
       ip_rip_receive_version_cmd,
       "ip rip receive version <(1-2)|none>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version\n"
       "None\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_type = 4;
	struct rip_interface *ri;

	ri = ifp->info;

	switch (argv[idx_type]->arg[0]) {
	case '1':
		ri->ri_receive = RI_RIP_VERSION_1;
		return CMD_SUCCESS;
	case '2':
		ri->ri_receive = RI_RIP_VERSION_2;
		return CMD_SUCCESS;
	case 'n':
		ri->ri_receive = RI_RIP_VERSION_NONE;
		return CMD_SUCCESS;
	default:
		break;
	}

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (ip_rip_receive_version_1,
       ip_rip_receive_version_1_cmd,
       "ip rip receive version <1 2|2 1>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	/* Version 1 and 2. */
	ri->ri_receive = RI_RIP_VERSION_1_AND_2;
	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_receive_version,
       no_ip_rip_receive_version_cmd,
       "no ip rip receive version [(1-2)]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->ri_receive = RI_RIP_UNSPEC;
	return CMD_SUCCESS;
}


DEFUN (ip_rip_send_version,
       ip_rip_send_version_cmd,
       "ip rip send version (1-2)",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_type = 4;
	struct rip_interface *ri;

	ri = ifp->info;

	/* Version 1. */
	if (atoi(argv[idx_type]->arg) == 1) {
		ri->ri_send = RI_RIP_VERSION_1;
		return CMD_SUCCESS;
	}
	if (atoi(argv[idx_type]->arg) == 2) {
		ri->ri_send = RI_RIP_VERSION_2;
		return CMD_SUCCESS;
	}
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (ip_rip_send_version_1,
       ip_rip_send_version_1_cmd,
       "ip rip send version <1 2|2 1>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	/* Version 1 and 2. */
	ri->ri_send = RI_RIP_VERSION_1_AND_2;
	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_send_version,
       no_ip_rip_send_version_cmd,
       "no ip rip send version [(1-2)]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->ri_send = RI_RIP_UNSPEC;
	return CMD_SUCCESS;
}


DEFUN (ip_rip_v2_broadcast,
       ip_rip_v2_broadcast_cmd,
       "ip rip v2-broadcast",
       IP_STR
       "Routing Information Protocol\n"
       "Send ip broadcast v2 update\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->v2_broadcast = 1;
	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_v2_broadcast,
       no_ip_rip_v2_broadcast_cmd,
       "no ip rip v2-broadcast",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Send ip broadcast v2 update\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->v2_broadcast = 0;
	return CMD_SUCCESS;
}

DEFUN (ip_rip_authentication_mode,
       ip_rip_authentication_mode_cmd,
       "ip rip authentication mode <md5|text> [auth-length <rfc|old-ripd>]",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "Clear text authentication\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	char *cryptmode = argv[4]->text;
	char *authlen = (argc > 5) ? argv[6]->text : NULL;
	struct rip_interface *ri;
	int auth_type;

	ri = ifp->info;

	if (strmatch("md5", cryptmode))
		auth_type = RIP_AUTH_MD5;
	else {
		assert(strmatch("text", cryptmode));
		auth_type = RIP_AUTH_SIMPLE_PASSWORD;
	}

	ri->auth_type = auth_type;

	if (argc > 5) {
		if (auth_type != RIP_AUTH_MD5) {
			vty_out(vty,
				"auth length argument only valid for md5\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strmatch("rfc", authlen))
			ri->md5_auth_len = RIP_AUTH_MD5_SIZE;
		else {
			assert(strmatch("old-ripd", authlen));
			ri->md5_auth_len = RIP_AUTH_MD5_COMPAT_SIZE;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_authentication_mode,
       no_ip_rip_authentication_mode_cmd,
       "no ip rip authentication mode [<md5|text> [auth-length <rfc|old-ripd>]]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "Clear text authentication\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->auth_type = RIP_NO_AUTH;
	ri->md5_auth_len = RIP_AUTH_MD5_COMPAT_SIZE;

	return CMD_SUCCESS;
}

DEFUN (ip_rip_authentication_string,
       ip_rip_authentication_string_cmd,
       "ip rip authentication string LINE",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_line = 4;
	struct rip_interface *ri;

	ri = ifp->info;

	if (strlen(argv[idx_line]->arg) > 16) {
		vty_out(vty,
			"%% RIPv2 authentication string must be shorter than 16\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ri->key_chain) {
		vty_out(vty, "%% key-chain configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ri->auth_str)
		free(ri->auth_str);

	ri->auth_str = strdup(argv[idx_line]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_authentication_string,
       no_ip_rip_authentication_string_cmd,
       "no ip rip authentication string [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	if (ri->auth_str)
		free(ri->auth_str);

	ri->auth_str = NULL;

	return CMD_SUCCESS;
}


DEFUN (ip_rip_authentication_key_chain,
       ip_rip_authentication_key_chain_cmd,
       "ip rip authentication key-chain LINE",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_line = 4;
	struct rip_interface *ri;

	ri = ifp->info;

	if (ri->auth_str) {
		vty_out(vty, "%% authentication string configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ri->key_chain)
		free(ri->key_chain);

	ri->key_chain = strdup(argv[idx_line]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_authentication_key_chain,
       no_ip_rip_authentication_key_chain_cmd,
       "no ip rip authentication key-chain [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	if (ri->key_chain)
		free(ri->key_chain);

	ri->key_chain = NULL;

	return CMD_SUCCESS;
}


/* CHANGED: ip rip split-horizon
   Cisco and Zebra's command is
   ip split-horizon
 */
DEFUN (ip_rip_split_horizon,
       ip_rip_split_horizon_cmd,
       "ip rip split-horizon",
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->split_horizon = RIP_SPLIT_HORIZON;
	return CMD_SUCCESS;
}

DEFUN (ip_rip_split_horizon_poisoned_reverse,
       ip_rip_split_horizon_poisoned_reverse_cmd,
       "ip rip split-horizon poisoned-reverse",
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n"
       "With poisoned-reverse\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->split_horizon = RIP_SPLIT_HORIZON_POISONED_REVERSE;
	return CMD_SUCCESS;
}

/* CHANGED: no ip rip split-horizon
   Cisco and Zebra's command is
   no ip split-horizon
 */
DEFUN (no_ip_rip_split_horizon,
       no_ip_rip_split_horizon_cmd,
       "no ip rip split-horizon",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	ri->split_horizon = RIP_NO_SPLIT_HORIZON;
	return CMD_SUCCESS;
}

DEFUN (no_ip_rip_split_horizon_poisoned_reverse,
       no_ip_rip_split_horizon_poisoned_reverse_cmd,
       "no ip rip split-horizon poisoned-reverse",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n"
       "With poisoned-reverse\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct rip_interface *ri;

	ri = ifp->info;

	switch (ri->split_horizon) {
	case RIP_SPLIT_HORIZON_POISONED_REVERSE:
		ri->split_horizon = RIP_SPLIT_HORIZON;
	default:
		break;
	}

	return CMD_SUCCESS;
}

DEFUN (rip_passive_interface,
       rip_passive_interface_cmd,
       "passive-interface <IFNAME|default>",
       "Suppress routing updates on an interface\n"
       "Interface name\n"
       "default for all interfaces\n")
{
	if (argv[1]->type == WORD_TKN) { // user passed 'default'
		passive_default = 1;
		rip_passive_nondefault_clean();
		return CMD_SUCCESS;
	}
	if (passive_default)
		return rip_passive_nondefault_unset(vty, argv[1]->arg);
	else
		return rip_passive_nondefault_set(vty, argv[1]->arg);
}

DEFUN (no_rip_passive_interface,
       no_rip_passive_interface_cmd,
       "no passive-interface <IFNAME|default>",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n"
       "default for all interfaces\n")
{
	if (argv[2]->type == WORD_TKN) {
		passive_default = 0;
		rip_passive_nondefault_clean();
		return CMD_SUCCESS;
	}
	if (passive_default)
		return rip_passive_nondefault_set(vty, argv[2]->arg);
	else
		return rip_passive_nondefault_unset(vty, argv[2]->arg);
}

/* Write rip configuration of each interface. */
static int rip_interface_config_write(struct vty *vty)
{
	struct listnode *node;
	struct interface *ifp;

	for (ALL_LIST_ELEMENTS_RO(vrf_iflist(VRF_DEFAULT), node, ifp)) {
		struct rip_interface *ri;

		if (ifp->ifindex == IFINDEX_DELETED)
			continue;

		ri = ifp->info;

		/* Do not display the interface if there is no
		 * configuration about it.
		 **/
		if ((!ifp->desc)
		    && (ri->split_horizon == ri->split_horizon_default)
		    && (ri->ri_send == RI_RIP_UNSPEC)
		    && (ri->ri_receive == RI_RIP_UNSPEC)
		    && (ri->auth_type != RIP_AUTH_MD5) && (!ri->v2_broadcast)
		    && (ri->md5_auth_len != RIP_AUTH_MD5_SIZE)
		    && (!ri->auth_str) && (!ri->key_chain))
			continue;

		vty_out(vty, "interface %s\n", ifp->name);

		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		/* Split horizon. */
		if (ri->split_horizon != ri->split_horizon_default) {
			switch (ri->split_horizon) {
			case RIP_SPLIT_HORIZON:
				vty_out(vty, " ip rip split-horizon\n");
				break;
			case RIP_SPLIT_HORIZON_POISONED_REVERSE:
				vty_out(vty,
					" ip rip split-horizon poisoned-reverse\n");
				break;
			case RIP_NO_SPLIT_HORIZON:
			default:
				vty_out(vty, " no ip rip split-horizon\n");
				break;
			}
		}

		/* RIP version setting. */
		if (ri->ri_send != RI_RIP_UNSPEC)
			vty_out(vty, " ip rip send version %s\n",
				lookup_msg(ri_version_msg, ri->ri_send, NULL));

		if (ri->ri_receive != RI_RIP_UNSPEC)
			vty_out(vty, " ip rip receive version %s \n",
				lookup_msg(ri_version_msg, ri->ri_receive,
					   NULL));

		if (ri->v2_broadcast)
			vty_out(vty, " ip rip v2-broadcast\n");

		/* RIP authentication. */
		if (ri->auth_type == RIP_AUTH_SIMPLE_PASSWORD)
			vty_out(vty, " ip rip authentication mode text\n");

		if (ri->auth_type == RIP_AUTH_MD5) {
			vty_out(vty, " ip rip authentication mode md5");
			if (ri->md5_auth_len == RIP_AUTH_MD5_COMPAT_SIZE)
				vty_out(vty, " auth-length old-ripd");
			else
				vty_out(vty, " auth-length rfc");
			vty_out(vty, "\n");
		}

		if (ri->auth_str)
			vty_out(vty, " ip rip authentication string %s\n",
				ri->auth_str);

		if (ri->key_chain)
			vty_out(vty, " ip rip authentication key-chain %s\n",
				ri->key_chain);

		vty_out(vty, "!\n");
	}
	return 0;
}

int config_write_rip_network(struct vty *vty, int config_mode)
{
	unsigned int i;
	char *ifname;
	struct route_node *node;

	/* Network type RIP enable interface statement. */
	for (node = route_top(rip_enable_network); node;
	     node = route_next(node))
		if (node->info)
			vty_out(vty, "%s%s/%d\n",
				config_mode ? " network " : "    ",
				inet_ntoa(node->p.u.prefix4),
				node->p.prefixlen);

	/* Interface name RIP enable statement. */
	for (i = 0; i < vector_active(rip_enable_interface); i++)
		if ((ifname = vector_slot(rip_enable_interface, i)) != NULL)
			vty_out(vty, "%s%s\n",
				config_mode ? " network " : "    ", ifname);

	/* RIP neighbors listing. */
	for (node = route_top(rip->neighbor); node; node = route_next(node))
		if (node->info)
			vty_out(vty, "%s%s\n",
				config_mode ? " neighbor " : "    ",
				inet_ntoa(node->p.u.prefix4));

	/* RIP passive interface listing. */
	if (config_mode) {
		if (passive_default)
			vty_out(vty, " passive-interface default\n");
		for (i = 0; i < vector_active(Vrip_passive_nondefault); i++)
			if ((ifname = vector_slot(Vrip_passive_nondefault, i))
			    != NULL)
				vty_out(vty, " %spassive-interface %s\n",
					(passive_default ? "no " : ""), ifname);
	}

	return 0;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE,
	"%s(config-if)# ",
	1,
};

/* Called when interface structure allocated. */
static int rip_interface_new_hook(struct interface *ifp)
{
	ifp->info = rip_interface_new();
	return 0;
}

/* Called when interface structure deleted. */
static int rip_interface_delete_hook(struct interface *ifp)
{
	XFREE(MTYPE_RIP_INTERFACE, ifp->info);
	ifp->info = NULL;
	return 0;
}

/* Allocate and initialize interface vector. */
void rip_if_init(void)
{
	/* Default initial size of interface vector. */
	if_add_hook(IF_NEW_HOOK, rip_interface_new_hook);
	if_add_hook(IF_DELETE_HOOK, rip_interface_delete_hook);

	/* RIP network init. */
	rip_enable_interface = vector_init(1);
	rip_enable_network = route_table_init();

	/* RIP passive interface. */
	Vrip_passive_nondefault = vector_init(1);

	/* Install interface node. */
	install_node(&interface_node, rip_interface_config_write);
	if_cmd_init();

	/* Install commands. */
	install_element(RIP_NODE, &rip_network_cmd);
	install_element(RIP_NODE, &no_rip_network_cmd);
	install_element(RIP_NODE, &rip_neighbor_cmd);
	install_element(RIP_NODE, &no_rip_neighbor_cmd);

	install_element(RIP_NODE, &rip_passive_interface_cmd);
	install_element(RIP_NODE, &no_rip_passive_interface_cmd);

	install_element(INTERFACE_NODE, &ip_rip_send_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_send_version_1_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_send_version_cmd);

	install_element(INTERFACE_NODE, &ip_rip_receive_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_receive_version_1_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_receive_version_cmd);

	install_element(INTERFACE_NODE, &ip_rip_v2_broadcast_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_v2_broadcast_cmd);

	install_element(INTERFACE_NODE, &ip_rip_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_mode_cmd);

	install_element(INTERFACE_NODE, &ip_rip_authentication_key_chain_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_rip_authentication_key_chain_cmd);

	install_element(INTERFACE_NODE, &ip_rip_authentication_string_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_string_cmd);

	install_element(INTERFACE_NODE, &ip_rip_split_horizon_cmd);
	install_element(INTERFACE_NODE,
			&ip_rip_split_horizon_poisoned_reverse_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_split_horizon_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_rip_split_horizon_poisoned_reverse_cmd);
}
