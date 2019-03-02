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
#include "nexthop_group.h"

#include "sharp_globals.h"
#include "sharp_nht.h"
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

void sharp_install_routes_helper(struct prefix *p, uint8_t instance,
				 struct nexthop_group *nhg,
				 uint32_t routes)
{
	uint32_t temp, i;
	bool v4 = false;

	zlog_debug("Inserting %u routes", routes);

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	monotime(&sg.r.t_start);
	for (i = 0; i < routes; i++) {
		route_add(p, (uint8_t)instance, nhg);
		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);
	}
}

void sharp_remove_routes_helper(struct prefix *p, uint8_t instance,
				uint32_t routes)
{
	uint32_t temp, i;
	bool v4 = false;

	zlog_debug("Removing %u routes", routes);

	if (p->family == AF_INET) {
		v4 = true;
		temp = ntohl(p->u.prefix4.s_addr);
	} else
		temp = ntohl(p->u.val32[3]);

	monotime(&sg.r.t_start);
	for (i = 0; i < routes; i++) {
		route_delete(p, (uint8_t)instance);
		if (v4)
			p->u.prefix4.s_addr = htonl(++temp);
		else
			p->u.val32[3] = htonl(++temp);
	}
}

static void handle_repeated(bool installed)
{
	struct prefix p = sg.r.orig_prefix;
	sg.r.repeat--;

	if (sg.r.repeat <= 0)
		return;

	if (installed) {
		sg.r.removed_routes = 0;
		sharp_remove_routes_helper(&p, sg.r.inst, sg.r.total_routes);
	}

	if (installed) {
		sg.r.installed_routes = 0;
		sharp_install_routes_helper(&p, sg.r.inst, &sg.r.nhop_group,
					    sg.r.total_routes);
	}
}

static int route_notify_owner(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct timeval r;
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_INSTALLED:
		sg.r.installed_routes++;
		if (sg.r.total_routes == sg.r.installed_routes) {
			monotime(&sg.r.t_end);
			timersub(&sg.r.t_end, &sg.r.t_start, &r);
			zlog_debug("Installed All Items %ld.%ld", r.tv_sec,
				   r.tv_usec);
			handle_repeated(true);
		}
		break;
	case ZAPI_ROUTE_FAIL_INSTALL:
		zlog_debug("Failed install of route");
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		zlog_debug("Better Admin Distance won over us");
		break;
	case ZAPI_ROUTE_REMOVED:
		sg.r.removed_routes++;
		if (sg.r.total_routes == sg.r.removed_routes) {
			monotime(&sg.r.t_end);
			timersub(&sg.r.t_end, &sg.r.t_start, &r);
			zlog_debug("Removed all Items %ld.%ld", r.tv_sec,
				   r.tv_usec);
			handle_repeated(false);
		}
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

void route_add(struct prefix *p, uint8_t instance, struct nexthop_group *nhg)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct nexthop *nh;
	int i = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_SHARP;
	api.instance = instance;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	for (ALL_NEXTHOPS_PTR(nhg, nh)) {
		api_nh = &api.nexthops[i];
		api_nh->vrf_id = VRF_DEFAULT;
		api_nh->type = nh->type;
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4:
			api_nh->gate = nh->gate;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			api_nh->gate = nh->gate;
			api_nh->ifindex = nh->ifindex;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			api_nh->ifindex = nh->ifindex;
			break;
		case NEXTHOP_TYPE_IPV6:
			memcpy(&api_nh->gate.ipv6, &nh->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			api_nh->ifindex = nh->ifindex;
			memcpy(&api_nh->gate.ipv6, &nh->gate.ipv6, 16);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			api_nh->bh_type = nh->bh_type;
			break;
		}
		i++;
	}
	api.nexthop_num = i;

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

void sharp_zebra_nexthop_watch(struct prefix *p, bool import,
			       bool watch, bool connected)
{
	int command;

	if (!import) {
		command = ZEBRA_NEXTHOP_REGISTER;

		if (!watch)
			command = ZEBRA_NEXTHOP_UNREGISTER;
	} else {
		command = ZEBRA_IMPORT_ROUTE_REGISTER;

		if (!watch)
			command = ZEBRA_IMPORT_ROUTE_UNREGISTER;
	}

	if (zclient_send_rnh(zclient, command, p, connected, VRF_DEFAULT) < 0)
		zlog_warn("%s: Failure to send nexthop to zebra",
			  __PRETTY_FUNCTION__);
}

static int sharp_nexthop_update(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct sharp_nh_tracker *nht;
	struct zapi_route nhr;
	char buf[PREFIX_STRLEN];
	int i;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("%s: Decode of update failed", __PRETTY_FUNCTION__);

		return 0;
	}

	zlog_debug("Received update for %s",
		   prefix2str(&nhr.prefix, buf, sizeof(buf)));

	nht = sharp_nh_tracker_get(&nhr.prefix);
	nht->nhop_num = nhr.nexthop_num;
	nht->updates++;

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

	zclient = zclient_new(master, &opt);

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
	zclient->import_check_update = sharp_nexthop_update;
}
