/*
 * Zebra connect code for Path Monitoring Daemon
 * Copyright (C) 6WIND 2019
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

#include "pm_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient;

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

	connected_free(&c);
	return 0;
}

static int pm_zebra_ifp_up(struct interface *ifp)
{
	return 0;
}

static int pm_zebra_ifp_down(struct interface *ifp)
{
	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static int pm_nexthop_update(int command, struct zclient *zclient,
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

extern struct zebra_privs_t pm_privs;

static int pm_zebra_ifp_create(struct interface *ifp)
{
	return 0;
}

static int pm_zebra_ifp_destroy(struct interface *ifp)
{
	return 0;
}

void pm_zebra_init(void)
{
	if_zapi_callbacks(pm_zebra_ifp_create, pm_zebra_ifp_up,
			  pm_zebra_ifp_down, pm_zebra_ifp_destroy);

	zclient = zclient_new(master, &zclient_options_default);
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_PM, 0, &pm_privs);

	zclient->zebra_connected = zebra_connected;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->nexthop_update = pm_nexthop_update;
}
