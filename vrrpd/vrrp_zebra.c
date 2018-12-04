/*
 * Zebra interfacing
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/if.h"
#include "lib/log.h"
#include "lib/prefix.h"
#include "lib/zclient.h"
#include "lib/vty.h"
#include "lib/linklist.h"

#include "vrrp.h"
#include "vrrp_zebra.h"

static struct zclient *zclient = NULL;

static void vrrp_zebra_connected(struct zclient *zclient)
{
	fprintf(stderr, "Zclient connected\n");
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

/* Router-id update message from zebra. */
static int vrrp_router_id_update_zebra(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix router_id;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	return 0;
}

static int vrrp_zebra_if_add(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	/*
	 * zebra api adds/dels interfaces using the same call
	 * interface_add_read below, see comments in lib/zclient.c
	 */
	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

	/* FIXME: handle subinterface creation here */

	return 0;
}

static int vrrp_zebra_if_del(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

#if 0
	if (VRRP_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}
#endif

	return 0;
}

static int vrrp_zebra_if_state_up(int command, struct zclient *zclient,
				  zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	/*
	 * zebra api notifies interface up/down events by using the same call
	 * zebra_interface_state_read below, see comments in lib/zclient.c ifp =
	 * zebra_interface_state_read(zclient->ibuf, vrf_id);
	 */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

#if 0
	if (VRRP_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}
#endif

	return 0;
}

static int vrrp_zebra_if_state_down(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	/*
	 * zebra api notifies interface up/down events by using the same call
	 * zebra_interface_state_read below, see comments in lib/zclient.c
	 */
	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (!ifp)
		return 0;

#if 0
	if (VRRP_DEBUG_ZEBRA) {
		zlog_debug(
			"%s: %s index %d(%u) flags %ld metric %d mtu %d operative %d",
			__PRETTY_FUNCTION__, ifp->name, ifp->ifindex, vrf_id,
			(long)ifp->flags, ifp->metric, ifp->mtu,
			if_is_operative(ifp));
	}
#endif

	return 0;
}

#ifdef VRRP_DEBUG_IFADDR_DUMP
static void dump_if_address(struct interface *ifp)
{
	struct connected *ifc;
	struct listnode *node;

	zlog_debug("%s %s: interface %s addresses:", __FILE__,
		   __PRETTY_FUNCTION__, ifp->name);

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			continue;

		zlog_debug("%s %s: interface %s address %s %s", __FILE__,
			   __PRETTY_FUNCTION__, ifp->name,
			   inet_ntoa(p->u.prefix4),
			   CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");
	}
}
#endif

static int vrrp_zebra_if_address_add(int command, struct zclient *zclient,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	/*
	 * zebra api notifies address adds/dels events by using the same call
	 * interface_add_read below, see comments in lib/zclient.c
	 *
	 * zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
	 * will add address to interface list by calling
	 * connected_add_by_prefix()
	 */
	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (!c)
		return 0;

#if 0
	if (VRRP_DEBUG_ZEBRA) {
		char buf[BUFSIZ];
		prefix2str(p, buf, BUFSIZ);
		zlog_debug("%s: %s(%u) connected IP address %s flags %u %s",
			   __PRETTY_FUNCTION__, c->ifp->name, vrf_id, buf,
			   c->flags,
			   CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)
				   ? "secondary"
				   : "primary");

	}
#endif

	return 0;
}

static int vrrp_zebra_if_address_del(int command, struct zclient *client,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	/*
	 * zebra api notifies address adds/dels events by using the same call
	 * interface_add_read below, see comments in lib/zclient.c
	 *
	 * zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
	 * will remove address from interface list by calling
	 * connected_delete_by_prefix()
	 */
	c = zebra_interface_address_read(command, client->ibuf, vrf_id);
	if (!c)
		return 0;

	return 0;
}

void vrrp_zebra_init(void)
{
	/* Socket for receiving updates from Zebra daemon */
	zclient = zclient_new(master, &zclient_options_default);

	zclient->zebra_connected = vrrp_zebra_connected;
	zclient->router_id_update = vrrp_router_id_update_zebra;
	zclient->interface_add = vrrp_zebra_if_add;
	zclient->interface_delete = vrrp_zebra_if_del;
	zclient->interface_up = vrrp_zebra_if_state_up;
	zclient->interface_down = vrrp_zebra_if_state_down;
	zclient->interface_address_add = vrrp_zebra_if_address_add;
	zclient->interface_address_delete = vrrp_zebra_if_address_del;

	zclient_init(zclient, 0, 0, &vrrp_privs);

	zlog_notice("%s: zclient socket initialized", __PRETTY_FUNCTION__);
}
