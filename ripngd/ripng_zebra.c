/*
 * RIPngd and zebra interface.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include "agg_table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_debug.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void ripng_zebra_ipv6_send(struct agg_node *rp, uint8_t cmd)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct ripng_info *rinfo = NULL;
	int count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_RIPNG;
	api.safi = SAFI_UNICAST;
	api.prefix = rp->p;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = VRF_DEFAULT;
		api_nh->gate.ipv6 = rinfo->nexthop;
		api_nh->ifindex = rinfo->ifindex;
		api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
		count++;
		if (cmd == ZEBRA_ROUTE_ADD)
			SET_FLAG(rinfo->flags, RIPNG_RTF_FIB);
		else
			UNSET_FLAG(rinfo->flags, RIPNG_RTF_FIB);
	}

	api.nexthop_num = count;

	rinfo = listgetdata(listhead(list));

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = rinfo->metric;

	if (rinfo->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = rinfo->tag;
	}

	zclient_route_send(cmd, zclient, &api);

	if (IS_RIPNG_DEBUG_ZEBRA) {
		if (ripng->ecmp)
			zlog_debug("%s: %s/%d nexthops %d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   inet6_ntoa(rp->p.u.prefix6), rp->p.prefixlen,
				   count);
		else
			zlog_debug(
				"%s: %s/%d",
				(cmd == ZEBRA_ROUTE_ADD) ? "Install into zebra"
							 : "Delete from zebra",
				inet6_ntoa(rp->p.u.prefix6), rp->p.prefixlen);
	}
}

/* Add/update ECMP routes to zebra. */
void ripng_zebra_ipv6_add(struct agg_node *rp)
{
	ripng_zebra_ipv6_send(rp, ZEBRA_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void ripng_zebra_ipv6_delete(struct agg_node *rp)
{
	ripng_zebra_ipv6_send(rp, ZEBRA_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int ripng_zebra_read_route(int command, struct zclient *zclient,
				  zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct in6_addr nexthop;
	unsigned long ifindex;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	nexthop = api.nexthops[0].gate.ipv6;
	ifindex = api.nexthops[0].ifindex;

	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		ripng_redistribute_add(api.type, RIPNG_ROUTE_REDISTRIBUTE,
				       (struct prefix_ipv6 *)&api.prefix,
				       ifindex, &nexthop, api.tag);
	else
		ripng_redistribute_delete(api.type, RIPNG_ROUTE_REDISTRIBUTE,
					  (struct prefix_ipv6 *)&api.prefix,
					  ifindex);

	return 0;
}

void ripng_redistribute_conf_update(int type)
{
	zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6, type, 0,
			     VRF_DEFAULT);
}

void ripng_redistribute_conf_delete(int type)
{
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, type, 0, VRF_DEFAULT);

	ripng_redistribute_withdraw(type);
}

int ripng_redistribute_check(int type)
{
	return vrf_bitmap_check(zclient->redist[AFI_IP6][type], VRF_DEFAULT);
}

void ripng_redistribute_clean()
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!vrf_bitmap_check(zclient->redist[AFI_IP6][i], VRF_DEFAULT))
			continue;

		if (zclient->sock > 0)
			zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE,
						zclient, AFI_IP6, i, 0,
						VRF_DEFAULT);

		vrf_bitmap_unset(zclient->redist[AFI_IP6][i], VRF_DEFAULT);
	}
}

void ripng_redistribute_write(struct vty *vty)
{
	int i;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i == zclient->redist_default
		    || !vrf_bitmap_check(zclient->redist[AFI_IP6][i],
					 VRF_DEFAULT))
			continue;

		vty_out(vty, "    %s", zebra_route_string(i));
	}
}

static void ripng_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

/* Initialize zebra structure and it's commands. */
void zebra_init(struct thread_master *master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_RIPNG, 0, &ripngd_privs);

	zclient->zebra_connected = ripng_zebra_connected;
	zclient->interface_up = ripng_interface_up;
	zclient->interface_down = ripng_interface_down;
	zclient->interface_add = ripng_interface_add;
	zclient->interface_delete = ripng_interface_delete;
	zclient->interface_address_add = ripng_interface_address_add;
	zclient->interface_address_delete = ripng_interface_address_delete;
	zclient->redistribute_route_add = ripng_zebra_read_route;
	zclient->redistribute_route_del = ripng_zebra_read_route;
}

void ripng_zebra_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
