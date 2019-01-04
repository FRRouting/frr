/* RIPd and zebra interface.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "log.h"
#include "vrf.h"
#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void rip_zebra_ipv4_send(struct route_node *rp, uint8_t cmd)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct rip_info *rinfo = NULL;
	int count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_RIP;
	api.safi = SAFI_UNICAST;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = VRF_DEFAULT;
		api_nh->gate = rinfo->nh.gate;
		api_nh->type = NEXTHOP_TYPE_IPV4;
		if (cmd == ZEBRA_ROUTE_ADD)
			SET_FLAG(rinfo->flags, RIP_RTF_FIB);
		else
			UNSET_FLAG(rinfo->flags, RIP_RTF_FIB);
		count++;
	}

	api.prefix = rp->p;
	api.nexthop_num = count;

	rinfo = listgetdata(listhead(list));

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = rinfo->metric;

	if (rinfo->distance && rinfo->distance != ZEBRA_RIP_DISTANCE_DEFAULT) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = rinfo->distance;
	}

	if (rinfo->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = rinfo->tag;
	}

	zclient_route_send(cmd, zclient, &api);

	if (IS_RIP_DEBUG_ZEBRA) {
		if (rip->ecmp)
			zlog_debug("%s: %s/%d nexthops %d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   inet_ntoa(rp->p.u.prefix4), rp->p.prefixlen,
				   count);
		else
			zlog_debug("%s: %s/%d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   inet_ntoa(rp->p.u.prefix4), rp->p.prefixlen);
	}

	rip->counters.route_changes++;
}

/* Add/update ECMP routes to zebra. */
void rip_zebra_ipv4_add(struct route_node *rp)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void rip_zebra_ipv4_delete(struct route_node *rp)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int rip_zebra_read_route(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct nexthop nh;

	if (!rip)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	memset(&nh, 0, sizeof(nh));
	nh.type = api.nexthops[0].type;
	nh.gate.ipv4 = api.nexthops[0].gate.ipv4;
	nh.ifindex = api.nexthops[0].ifindex;

	/* Then fetch IPv4 prefixes. */
	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		rip_redistribute_add(api.type, RIP_ROUTE_REDISTRIBUTE,
				     (struct prefix_ipv4 *)&api.prefix, &nh,
				     api.metric, api.distance, api.tag);
	else if (command == ZEBRA_REDISTRIBUTE_ROUTE_DEL)
		rip_redistribute_delete(api.type, RIP_ROUTE_REDISTRIBUTE,
					(struct prefix_ipv4 *)&api.prefix,
					nh.ifindex);

	return 0;
}

void rip_redistribute_conf_update(int type)
{
	zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP, type,
			     0, VRF_DEFAULT);
}

void rip_redistribute_conf_delete(int type)
{
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, type, 0, VRF_DEFAULT);

	/* Remove the routes from RIP table. */
	rip_redistribute_withdraw(type);
}

int rip_redistribute_check(int type)
{
	return vrf_bitmap_check(zclient->redist[AFI_IP][type], VRF_DEFAULT);
}

void rip_redistribute_clean(void)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!vrf_bitmap_check(zclient->redist[AFI_IP][i], VRF_DEFAULT))
			continue;

		if (zclient->sock > 0)
			zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE,
						zclient, AFI_IP, i, 0,
						VRF_DEFAULT);

		vrf_bitmap_unset(zclient->redist[AFI_IP][i], VRF_DEFAULT);
	}
}

void rip_show_redistribute_config(struct vty *vty)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i == zclient->redist_default
		    || !vrf_bitmap_check(zclient->redist[AFI_IP][i],
					 VRF_DEFAULT))
			continue;

		vty_out(vty, " %s", zebra_route_string(i));
	}
}

static void rip_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void rip_zclient_init(struct thread_master *master)
{
	/* Set default value to the zebra client structure. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_RIP, 0, &ripd_privs);
	zclient->zebra_connected = rip_zebra_connected;
	zclient->interface_add = rip_interface_add;
	zclient->interface_delete = rip_interface_delete;
	zclient->interface_address_add = rip_interface_address_add;
	zclient->interface_address_delete = rip_interface_address_delete;
	zclient->interface_up = rip_interface_up;
	zclient->interface_down = rip_interface_down;
	zclient->redistribute_route_add = rip_zebra_read_route;
	zclient->redistribute_route_del = rip_zebra_read_route;
}

void rip_zclient_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
