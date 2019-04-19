/*
 * Zebra connect code for Path Monitoring Daemon
 * Copyright 2019 6WIND S.A.
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

#include "frrevent.h"
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

/* For registering events. */
extern struct event_loop *master;

static int pm_interface_address_add(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{

	zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	return 0;
}

static int pm_interface_address_delete(int command, struct zclient *zclient,
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

static void pm_nexthop_update(struct vrf *vrf, struct prefix *matched,
			      struct zapi_route *nhr)
{
	int i;

	zlog_debug("Received update for %pFX", matched);
	for (i = 0; i < nhr->nexthop_num; i++) {
		struct zapi_nexthop *znh = &nhr->nexthops[i];

		switch (znh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			zlog_debug(
				"Nexthop %pI4, type: %d, ifindex: %d, vrf: %d, label_num: %d",
					&znh->gate.ipv4.s_addr,
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6:
			zlog_debug(
				"Nexthop %pI6, type: %d, ifindex: %d, vrf: %d, label_num: %d",
				&znh->gate.ipv6,
				znh->type, znh->ifindex, znh->vrf_id,
				znh->label_num);
			break;
		case NEXTHOP_TYPE_IFINDEX:
			zlog_debug("Nexthop IFINDEX: %d, ifindex: %d",
				   znh->type, znh->ifindex);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			zlog_debug("Nexthop blackhole");
			break;
		}
	}
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


static zclient_handler *const pm_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = pm_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = pm_interface_address_delete,
};

void pm_zebra_init(void)
{
	hook_register_prio(if_real, 0, pm_zebra_ifp_create);
	hook_register_prio(if_up, 0, pm_zebra_ifp_up);
	hook_register_prio(if_down, 0, pm_zebra_ifp_down);
	hook_register_prio(if_unreal, 0, pm_zebra_ifp_destroy);

	zclient = zclient_new(master, &zclient_options_default, pm_handlers,
			      array_size(pm_handlers));
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_PM, 0, &pm_privs);

	zclient->zebra_connected = zebra_connected;
	zclient->nexthop_update = pm_nexthop_update;
}
