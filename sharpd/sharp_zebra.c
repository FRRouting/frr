/*
 * Zebra connect code.
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
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
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"

#include "sharp_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;

static struct interface *zebra_interface_if_lookup(struct stream *s)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name(ifname_tmp, VRF_DEFAULT);
}

/* Inteface addition message from zebra. */
static int interface_add(int command, struct zclient *zclient,
			 zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (!ifp->info)
		return 0;

	return 0;
}

static int interface_delete(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;
	/* zebra_interface_state_read () updates interface structure in iflist
	 */
	ifp = zebra_interface_state_read(s, vrf_id);

	if (ifp == NULL)
		return 0;

	if_set_index(ifp, IFINDEX_INTERNAL);

	return 0;
}

static int interface_address_add(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(c);
	return 0;
}

static int interface_state_up(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_if_lookup(zclient->ibuf);

	return 0;
}

static int interface_state_down(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_state_read(zclient->ibuf, vrf_id);

	return 0;
}

extern uint32_t total_routes;
extern uint32_t installed_routes;
extern uint32_t removed_routes;

static int route_notify_owner(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_INSTALLED:
		installed_routes++;
		if (total_routes == installed_routes)
			zlog_debug("Installed All Items");
		break;
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_debug("Failed install of route");
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_debug("Better Admin Distance won over us");
		break;
	case ZAPI_ROUTE_REMOVED:
		removed_routes++;
		if (total_routes == removed_routes)
			zlog_debug("Removed all Items");
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		zlog_debug("Route removal Failure");
		break;
	}
	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void vrf_label_add(vrf_id_t vrf_id, afi_t afi, mpls_label_t label)
{
	zclient_send_vrf_label(zclient, vrf_id, afi, label, ZEBRA_LSP_SHARP);
}

void route_add(struct prefix *p, uint8_t instance, struct nexthop *nh)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_SHARP;
	api.instance = instance;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	api_nh = &api.nexthops[0];
	api_nh->vrf_id = VRF_DEFAULT;
	api_nh->gate.ipv4 = nh->gate.ipv4;
	api_nh->type = nh->type;
	api_nh->ifindex = nh->ifindex;
	api.nexthop_num = 1;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void route_delete(struct prefix *p, uint8_t instance)
{
	struct zapi_route api;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_SHARP;
	api.safi = SAFI_UNICAST;
	api.instance = instance;
	memcpy(&api.prefix, p, sizeof(*p));
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	return;
}

void sharp_zebra_nexthop_watch(struct prefix *p, bool watch)
{
	int command = ZEBRA_NEXTHOP_REGISTER;

	if (!watch)
		command = ZEBRA_NEXTHOP_UNREGISTER;

	zclient_send_rnh(zclient, command, p, true, VRF_DEFAULT);
}

static int sharp_nexthop_update(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route nhr;
	char buf[PREFIX_STRLEN];
	int i;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("%s: Decode of update failed", __PRETTY_FUNCTION__);

		return 0;
	}

	zlog_debug("Received update for %s",
		   prefix2str(&nhr.prefix, buf, sizeof(buf)));
	for (i = 0; i < nhr.nexthop_num; i++) {
		struct zapi_nexthop *znh = &nhr.nexthops[i];

		switch (znh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			zlog_debug(
				"\tNexthop %s, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				inet_ntop(AF_INET, &znh->gate.ipv4.s_addr, buf,
					  sizeof(buf)),
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6:
			zlog_debug(
				"\tNexthop %s, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				inet_ntop(AF_INET6, &znh->gate.ipv6, buf,
					  sizeof(buf)),
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IFINDEX:
			zlog_debug("\tNexthop IFINDEX: %d, ifindex: %d",
				   znh->type, znh->ifindex);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			zlog_debug("\tNexthop blackhole");
			break;
		}
	}
	return 0;
}

extern struct zebra_privs_t sharp_privs;

void sharp_zebra_init(void)
{
	struct zclient_options opt = {.receive_notify = true};

	zclient = zclient_new_notify(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_SHARP, 0, &sharp_privs);
	zclient->zebra_connected = zebra_connected;
	zclient->interface_add = interface_add;
	zclient->interface_delete = interface_delete;
	zclient->interface_up = interface_state_up;
	zclient->interface_down = interface_state_down;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->route_notify_owner = route_notify_owner;
	zclient->nexthop_update = sharp_nexthop_update;
}
