/*
 * Interface related function for RIPng.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "filter.h"
#include "log.h"
#include "stream.h"
#include "zclient.h"
#include "command.h"
#include "agg_table.h"
#include "thread.h"
#include "privs.h"
#include "vrf.h"
#include "lib_errors.h"
#include "northbound_cli.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_debug.h"

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP  IPV6_ADD_MEMBERSHIP
#endif
#ifndef IPV6_LEAVE_GROUP
#define IPV6_LEAVE_GROUP IPV6_DROP_MEMBERSHIP
#endif

DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_IF, "ripng interface")

/* Static utility function. */
static void ripng_enable_apply(struct interface *);
static void ripng_passive_interface_apply(struct interface *);
static int ripng_enable_if_lookup(struct ripng *ripng, const char *ifname);
static int ripng_enable_network_lookup2(struct connected *);
static void ripng_enable_apply_all(struct ripng *ripng);

/* Join to the all rip routers multicast group. */
static int ripng_multicast_join(struct interface *ifp, int sock)
{
	int ret;
	struct ipv6_mreq mreq;
	int save_errno;

	if (if_is_multicast(ifp)) {
		memset(&mreq, 0, sizeof(mreq));
		inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = ifp->ifindex;

		/*
		 * NetBSD 1.6.2 requires root to join groups on gif(4).
		 * While this is bogus, privs are available and easy to use
		 * for this call as a workaround.
		 */
		frr_with_privs(&ripngd_privs) {

			ret = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
					 (char *)&mreq, sizeof(mreq));
			save_errno = errno;

		}

		if (ret < 0 && save_errno == EADDRINUSE) {
			/*
			 * Group is already joined.  This occurs due to sloppy
			 * group
			 * management, in particular declining to leave the
			 * group on
			 * an interface that has just gone down.
			 */
			zlog_warn("ripng join on %s EADDRINUSE (ignoring)",
				  ifp->name);
			return 0; /* not an error */
		}

		if (ret < 0)
			zlog_warn("can't setsockopt IPV6_JOIN_GROUP: %s",
				  safe_strerror(save_errno));

		if (IS_RIPNG_DEBUG_EVENT)
			zlog_debug(
				"RIPng %s join to all-rip-routers multicast group",
				ifp->name);

		if (ret < 0)
			return -1;
	}
	return 0;
}

/* Leave from the all rip routers multicast group. */
static int ripng_multicast_leave(struct interface *ifp, int sock)
{
	int ret;
	struct ipv6_mreq mreq;

	if (if_is_multicast(ifp)) {
		memset(&mreq, 0, sizeof(mreq));
		inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);
		mreq.ipv6mr_interface = ifp->ifindex;

		ret = setsockopt(sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
				 (char *)&mreq, sizeof(mreq));
		if (ret < 0)
			zlog_warn("can't setsockopt IPV6_LEAVE_GROUP: %s",
				  safe_strerror(errno));

		if (IS_RIPNG_DEBUG_EVENT)
			zlog_debug(
				"RIPng %s leave from all-rip-routers multicast group",
				ifp->name);

		if (ret < 0)
			return -1;
	}

	return 0;
}

/* How many link local IPv6 address could be used on the interface ? */
static int ripng_if_ipv6_lladdress_check(struct interface *ifp)
{
	struct listnode *nn;
	struct connected *connected;
	int count = 0;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, nn, connected)) {
		struct prefix *p;
		p = connected->address;

		if ((p->family == AF_INET6)
		    && IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
			count++;
	}

	return count;
}

static int ripng_if_down(struct interface *ifp)
{
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_interface *ri;
	struct ripng *ripng;
	struct list *list = NULL;
	struct listnode *listnode = NULL, *nextnode = NULL;

	ri = ifp->info;
	ripng = ri->ripng;

	if (ripng)
		for (rp = agg_route_top(ripng->table); rp;
		     rp = agg_route_next(rp))
			if ((list = rp->info) != NULL)
				for (ALL_LIST_ELEMENTS(list, listnode, nextnode,
						       rinfo))
					if (rinfo->ifindex == ifp->ifindex)
						ripng_ecmp_delete(ripng, rinfo);


	if (ri->running) {
		if (IS_RIPNG_DEBUG_EVENT)
			zlog_debug("turn off %s", ifp->name);

		/* Leave from multicast group. */
		if (ripng)
			ripng_multicast_leave(ifp, ripng->sock);

		ri->running = 0;
	}

	return 0;
}

/* Inteface link up message processing. */
static int ripng_ifp_up(struct interface *ifp)
{
	if (IS_RIPNG_DEBUG_ZEBRA)
		zlog_debug(
			"interface up %s vrf %u index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu6);

	ripng_interface_sync(ifp);

	/* Check if this interface is RIPng enabled or not. */
	ripng_enable_apply(ifp);

	/* Check for a passive interface. */
	ripng_passive_interface_apply(ifp);

	/* Apply distribute list to the all interface. */
	ripng_distribute_update_interface(ifp);

	return 0;
}

/* Inteface link down message processing. */
static int ripng_ifp_down(struct interface *ifp)
{
	ripng_interface_sync(ifp);
	ripng_if_down(ifp);

	if (IS_RIPNG_DEBUG_ZEBRA)
		zlog_debug(
			"interface down %s vrf %u index %d flags %#llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu6);

	return 0;
}

/* Inteface addition message from zebra. */
static int ripng_ifp_create(struct interface *ifp)
{
	ripng_interface_sync(ifp);

	if (IS_RIPNG_DEBUG_ZEBRA)
		zlog_debug(
			"RIPng interface add %s vrf %u index %d flags %#llx metric %d mtu %d",
			ifp->name, ifp->vrf_id, ifp->ifindex,
			(unsigned long long)ifp->flags, ifp->metric, ifp->mtu6);

	/* Check is this interface is RIP enabled or not.*/
	ripng_enable_apply(ifp);

	/* Apply distribute list to the interface. */
	ripng_distribute_update_interface(ifp);

	/* Check interface routemap. */
	ripng_if_rmap_update_interface(ifp);

	return 0;
}

static int ripng_ifp_destroy(struct interface *ifp)
{
	ripng_interface_sync(ifp);
	if (if_is_up(ifp)) {
		ripng_if_down(ifp);
	}

	zlog_info(
		"interface delete %s vrf %u index %d flags %#llx metric %d mtu %d",
		ifp->name, ifp->vrf_id, ifp->ifindex,
		(unsigned long long)ifp->flags, ifp->metric, ifp->mtu6);

	return 0;
}

/* VRF update for an interface. */
int ripng_interface_vrf_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	vrf_id_t new_vrf_id;

	ifp = zebra_interface_vrf_update_read(zclient->ibuf, vrf_id,
					      &new_vrf_id);
	if (!ifp)
		return 0;

	if (IS_RIPNG_DEBUG_ZEBRA)
		zlog_debug("interface %s VRF change vrf_id %u new vrf id %u",
			   ifp->name, vrf_id, new_vrf_id);

	if_update_to_new_vrf(ifp, new_vrf_id);
	ripng_interface_sync(ifp);

	return 0;
}

void ripng_interface_clean(struct ripng *ripng)
{
	struct interface *ifp;
	struct ripng_interface *ri;

	FOR_ALL_INTERFACES (ripng->vrf, ifp) {
		ri = ifp->info;

		ri->enable_network = 0;
		ri->enable_interface = 0;
		ri->running = 0;

		if (ri->t_wakeup) {
			thread_cancel(ri->t_wakeup);
			ri->t_wakeup = NULL;
		}
	}
}

static void ripng_apply_address_add(struct connected *ifc)
{
	struct ripng_interface *ri = ifc->ifp->info;
	struct ripng *ripng = ri->ripng;
	struct prefix_ipv6 address;
	struct prefix *p;

	if (!ripng)
		return;

	if (!if_is_up(ifc->ifp))
		return;

	p = ifc->address;

	memset(&address, 0, sizeof(address));
	address.family = p->family;
	address.prefix = p->u.prefix6;
	address.prefixlen = p->prefixlen;
	apply_mask_ipv6(&address);

	/* Check if this interface is RIP enabled or not
	   or  Check if this address's prefix is RIP enabled */
	if ((ripng_enable_if_lookup(ripng, ifc->ifp->name) >= 0)
	    || (ripng_enable_network_lookup2(ifc) >= 0))
		ripng_redistribute_add(ripng, ZEBRA_ROUTE_CONNECT,
				       RIPNG_ROUTE_INTERFACE, &address,
				       ifc->ifp->ifindex, NULL, 0);
}

int ripng_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	struct prefix *p;

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	p = c->address;

	if (p->family == AF_INET6) {
		struct ripng_interface *ri = c->ifp->info;

		if (IS_RIPNG_DEBUG_ZEBRA)
			zlog_debug("RIPng connected address %s/%d add",
				   inet6_ntoa(p->u.prefix6), p->prefixlen);

		/* Check is this prefix needs to be redistributed. */
		ripng_apply_address_add(c);

		/* Let's try once again whether the interface could be activated
		 */
		if (!ri->running) {
			/* Check if this interface is RIP enabled or not.*/
			ripng_enable_apply(c->ifp);

			/* Apply distribute list to the interface. */
			ripng_distribute_update_interface(c->ifp);

			/* Check interface routemap. */
			ripng_if_rmap_update_interface(c->ifp);
		}
	}

	return 0;
}

static void ripng_apply_address_del(struct connected *ifc)
{
	struct ripng_interface *ri = ifc->ifp->info;
	struct ripng *ripng = ri->ripng;
	struct prefix_ipv6 address;
	struct prefix *p;

	if (!ripng)
		return;

	if (!if_is_up(ifc->ifp))
		return;

	p = ifc->address;

	memset(&address, 0, sizeof(address));
	address.family = p->family;
	address.prefix = p->u.prefix6;
	address.prefixlen = p->prefixlen;
	apply_mask_ipv6(&address);

	ripng_redistribute_delete(ripng, ZEBRA_ROUTE_CONNECT,
				  RIPNG_ROUTE_INTERFACE, &address,
				  ifc->ifp->ifindex);
}

int ripng_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;
	struct prefix *p;
	char buf[INET6_ADDRSTRLEN];

	ifc = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					   zclient->ibuf, vrf_id);

	if (ifc) {
		p = ifc->address;

		if (p->family == AF_INET6) {
			if (IS_RIPNG_DEBUG_ZEBRA)
				zlog_debug(
					"RIPng connected address %s/%d delete",
					inet_ntop(AF_INET6, &p->u.prefix6, buf,
						  INET6_ADDRSTRLEN),
					p->prefixlen);

			/* Check wether this prefix needs to be removed. */
			ripng_apply_address_del(ifc);
		}
		connected_free(&ifc);
	}

	return 0;
}

/* Lookup RIPng enable network. */
/* Check wether the interface has at least a connected prefix that
 * is within the ripng->enable_network table. */
static int ripng_enable_network_lookup_if(struct interface *ifp)
{
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	struct listnode *node;
	struct connected *connected;
	struct prefix_ipv6 address;

	if (!ripng)
		return -1;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		struct prefix *p;
		struct agg_node *n;

		p = connected->address;

		if (p->family == AF_INET6) {
			address.family = AF_INET6;
			address.prefix = p->u.prefix6;
			address.prefixlen = IPV6_MAX_BITLEN;

			n = agg_node_match(ripng->enable_network,
					   (struct prefix *)&address);
			if (n) {
				agg_unlock_node(n);
				return 1;
			}
		}
	}
	return -1;
}

/* Check wether connected is within the ripng->enable_network table. */
static int ripng_enable_network_lookup2(struct connected *connected)
{
	struct ripng_interface *ri = connected->ifp->info;
	struct ripng *ripng = ri->ripng;
	struct prefix_ipv6 address;
	struct prefix *p;

	if (!ripng)
		return -1;

	p = connected->address;

	if (p->family == AF_INET6) {
		struct agg_node *node;

		address.family = p->family;
		address.prefix = p->u.prefix6;
		address.prefixlen = IPV6_MAX_BITLEN;

		/* LPM on p->family, p->u.prefix6/IPV6_MAX_BITLEN within
		 * ripng->enable_network */
		node = agg_node_match(ripng->enable_network,
				      (struct prefix *)&address);

		if (node) {
			agg_unlock_node(node);
			return 1;
		}
	}

	return -1;
}

/* Add RIPng enable network. */
int ripng_enable_network_add(struct ripng *ripng, struct prefix *p)
{
	struct agg_node *node;

	node = agg_node_get(ripng->enable_network, p);

	if (node->info) {
		agg_unlock_node(node);
		return NB_ERR_INCONSISTENCY;
	} else
		node->info = (void *)1;

	/* XXX: One should find a better solution than a generic one */
	ripng_enable_apply_all(ripng);

	return NB_OK;
}

/* Delete RIPng enable network. */
int ripng_enable_network_delete(struct ripng *ripng, struct prefix *p)
{
	struct agg_node *node;

	node = agg_node_lookup(ripng->enable_network, p);
	if (node) {
		node->info = NULL;

		/* Unlock info lock. */
		agg_unlock_node(node);

		/* Unlock lookup lock. */
		agg_unlock_node(node);

		return NB_OK;
	}

	return NB_ERR_INCONSISTENCY;
}

/* Lookup function. */
static int ripng_enable_if_lookup(struct ripng *ripng, const char *ifname)
{
	unsigned int i;
	char *str;

	if (!ripng)
		return -1;

	for (i = 0; i < vector_active(ripng->enable_if); i++)
		if ((str = vector_slot(ripng->enable_if, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

int ripng_enable_if_add(struct ripng *ripng, const char *ifname)
{
	int ret;

	ret = ripng_enable_if_lookup(ripng, ifname);
	if (ret >= 0)
		return NB_ERR_INCONSISTENCY;

	vector_set(ripng->enable_if, strdup(ifname));

	ripng_enable_apply_all(ripng);

	return NB_OK;
}

int ripng_enable_if_delete(struct ripng *ripng, const char *ifname)
{
	int index;
	char *str;

	index = ripng_enable_if_lookup(ripng, ifname);
	if (index < 0)
		return NB_ERR_INCONSISTENCY;

	str = vector_slot(ripng->enable_if, index);
	free(str);
	vector_unset(ripng->enable_if, index);

	ripng_enable_apply_all(ripng);

	return NB_OK;
}

/* Wake up interface. */
static int ripng_interface_wakeup(struct thread *t)
{
	struct interface *ifp;
	struct ripng_interface *ri;

	/* Get interface. */
	ifp = THREAD_ARG(t);

	ri = ifp->info;
	ri->t_wakeup = NULL;

	/* Join to multicast group. */
	if (ripng_multicast_join(ifp, ri->ripng->sock) < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "multicast join failed, interface %s not running",
			     ifp->name);
		return 0;
	}

	/* Set running flag. */
	ri->running = 1;

	/* Send RIP request to the interface. */
	ripng_request(ifp);

	return 0;
}

static void ripng_connect_set(struct interface *ifp, int set)
{
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	struct listnode *node, *nnode;
	struct connected *connected;
	struct prefix_ipv6 address;

	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix *p;
		p = connected->address;

		if (p->family != AF_INET6)
			continue;

		address.family = AF_INET6;
		address.prefix = p->u.prefix6;
		address.prefixlen = p->prefixlen;
		apply_mask_ipv6(&address);

		if (set) {
			/* Check once more wether this prefix is within a
			 * "network IF_OR_PREF" one */
			if ((ripng_enable_if_lookup(ripng, connected->ifp->name)
			     >= 0)
			    || (ripng_enable_network_lookup2(connected) >= 0))
				ripng_redistribute_add(
					ripng, ZEBRA_ROUTE_CONNECT,
					RIPNG_ROUTE_INTERFACE, &address,
					connected->ifp->ifindex, NULL, 0);
		} else {
			ripng_redistribute_delete(ripng, ZEBRA_ROUTE_CONNECT,
						  RIPNG_ROUTE_INTERFACE,
						  &address,
						  connected->ifp->ifindex);
			if (ripng_redistribute_check(ripng,
						     ZEBRA_ROUTE_CONNECT))
				ripng_redistribute_add(
					ripng, ZEBRA_ROUTE_CONNECT,
					RIPNG_ROUTE_REDISTRIBUTE, &address,
					connected->ifp->ifindex, NULL, 0);
		}
	}
}

/* Check RIPng is enabed on this interface. */
void ripng_enable_apply(struct interface *ifp)
{
	int ret;
	struct ripng_interface *ri = NULL;

	/* Check interface. */
	if (!if_is_up(ifp))
		return;

	ri = ifp->info;

	/* Is this interface a candidate for RIPng ? */
	ret = ripng_enable_network_lookup_if(ifp);

	/* If the interface is matched. */
	if (ret > 0)
		ri->enable_network = 1;
	else
		ri->enable_network = 0;

	/* Check interface name configuration. */
	ret = ripng_enable_if_lookup(ri->ripng, ifp->name);
	if (ret >= 0)
		ri->enable_interface = 1;
	else
		ri->enable_interface = 0;

	/* any candidate interface MUST have a link-local IPv6 address */
	if ((!ripng_if_ipv6_lladdress_check(ifp))
	    && (ri->enable_network || ri->enable_interface)) {
		ri->enable_network = 0;
		ri->enable_interface = 0;
		zlog_warn("Interface %s does not have any link-local address",
			  ifp->name);
	}

	/* Update running status of the interface. */
	if (ri->enable_network || ri->enable_interface) {
		zlog_info("RIPng INTERFACE ON %s", ifp->name);

		/* Add interface wake up thread. */
		thread_add_timer(master, ripng_interface_wakeup, ifp, 1,
				 &ri->t_wakeup);

		ripng_connect_set(ifp, 1);
	} else {
		if (ri->running) {
			/* Might as well clean up the route table as well
			 * ripng_if_down sets to 0 ri->running, and displays
			 *"turn off %s"
			 **/
			ripng_if_down(ifp);

			ripng_connect_set(ifp, 0);
		}
	}
}

/* Set distribute list to all interfaces. */
static void ripng_enable_apply_all(struct ripng *ripng)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (ripng->vrf, ifp)
		ripng_enable_apply(ifp);
}

/* Clear all network and neighbor configuration */
void ripng_clean_network(struct ripng *ripng)
{
	unsigned int i;
	char *str;
	struct agg_node *rn;

	/* ripng->enable_network */
	for (rn = agg_route_top(ripng->enable_network); rn;
	     rn = agg_route_next(rn))
		if (rn->info) {
			rn->info = NULL;
			agg_unlock_node(rn);
		}

	/* ripng->enable_if */
	for (i = 0; i < vector_active(ripng->enable_if); i++)
		if ((str = vector_slot(ripng->enable_if, i)) != NULL) {
			free(str);
			vector_slot(ripng->enable_if, i) = NULL;
		}
}

/* Utility function for looking up passive interface settings. */
static int ripng_passive_interface_lookup(struct ripng *ripng,
					  const char *ifname)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(ripng->passive_interface); i++)
		if ((str = vector_slot(ripng->passive_interface, i)) != NULL)
			if (strcmp(str, ifname) == 0)
				return i;
	return -1;
}

void ripng_passive_interface_apply(struct interface *ifp)
{
	int ret;
	struct ripng_interface *ri;
	struct ripng *ripng;

	ri = ifp->info;
	ripng = ri->ripng;
	if (!ripng)
		return;

	ret = ripng_passive_interface_lookup(ripng, ifp->name);
	if (ret < 0)
		ri->passive = 0;
	else
		ri->passive = 1;
}

static void ripng_passive_interface_apply_all(struct ripng *ripng)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (ripng->vrf, ifp)
		ripng_passive_interface_apply(ifp);
}

/* Passive interface. */
int ripng_passive_interface_set(struct ripng *ripng, const char *ifname)
{
	if (ripng_passive_interface_lookup(ripng, ifname) >= 0)
		return NB_ERR_INCONSISTENCY;

	vector_set(ripng->passive_interface, strdup(ifname));

	ripng_passive_interface_apply_all(ripng);

	return NB_OK;
}

int ripng_passive_interface_unset(struct ripng *ripng, const char *ifname)
{
	int i;
	char *str;

	i = ripng_passive_interface_lookup(ripng, ifname);
	if (i < 0)
		return NB_ERR_INCONSISTENCY;

	str = vector_slot(ripng->passive_interface, i);
	free(str);
	vector_unset(ripng->passive_interface, i);

	ripng_passive_interface_apply_all(ripng);

	return NB_OK;
}

/* Free all configured RIP passive-interface settings. */
void ripng_passive_interface_clean(struct ripng *ripng)
{
	unsigned int i;
	char *str;

	for (i = 0; i < vector_active(ripng->passive_interface); i++)
		if ((str = vector_slot(ripng->passive_interface, i)) != NULL) {
			free(str);
			vector_slot(ripng->passive_interface, i) = NULL;
		}
	ripng_passive_interface_apply_all(ripng);
}

/* Write RIPng enable network and interface to the vty. */
int ripng_network_write(struct vty *vty, struct ripng *ripng)
{
	unsigned int i;
	const char *ifname;
	struct agg_node *node;
	char buf[BUFSIZ];

	/* Write enable network. */
	for (node = agg_route_top(ripng->enable_network); node;
	     node = agg_route_next(node))
		if (node->info) {
			struct prefix *p = &node->p;
			vty_out(vty, "    %s/%d\n",
				inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
				p->prefixlen);
		}

	/* Write enable interface. */
	for (i = 0; i < vector_active(ripng->enable_if); i++)
		if ((ifname = vector_slot(ripng->enable_if, i)) != NULL)
			vty_out(vty, "    %s\n", ifname);

	return 0;
}

static struct ripng_interface *ri_new(void)
{
	struct ripng_interface *ri;

	ri = XCALLOC(MTYPE_RIPNG_IF, sizeof(struct ripng_interface));

	/* Set default split-horizon behavior.  If the interface is Frame
	   Relay or SMDS is enabled, the default value for split-horizon is
	   off.  But currently Zebra does detect Frame Relay or SMDS
	   interface.  So all interface is set to split horizon.  */
	ri->split_horizon =
		yang_get_default_enum("%s/split-horizon", RIPNG_IFACE);

	return ri;
}

void ripng_interface_sync(struct interface *ifp)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (vrf) {
		struct ripng_interface *ri;

		ri = ifp->info;
		if (ri)
			ri->ripng = vrf->info;
	}
}

static int ripng_if_new_hook(struct interface *ifp)
{
	ifp->info = ri_new();
	ripng_interface_sync(ifp);

	return 0;
}

/* Called when interface structure deleted. */
static int ripng_if_delete_hook(struct interface *ifp)
{
	XFREE(MTYPE_RIPNG_IF, ifp->info);
	ifp->info = NULL;
	return 0;
}

/* Configuration write function for ripngd. */
static int interface_config_write(struct vty *vty)
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

/* ripngd's interface node. */
static struct cmd_node interface_node = {
	INTERFACE_NODE, "%s(config-if)# ", 1 /* VTYSH */
};

/* Initialization of interface. */
void ripng_if_init(void)
{
	/* Interface initialize. */
	hook_register_prio(if_add, 0, ripng_if_new_hook);
	hook_register_prio(if_del, 0, ripng_if_delete_hook);

	/* Install interface node. */
	install_node(&interface_node, interface_config_write);
	if_cmd_init();
	if_zapi_callbacks(ripng_ifp_create, ripng_ifp_up,
			  ripng_ifp_down, ripng_ifp_destroy);
}
