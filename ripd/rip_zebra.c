// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPd and zebra interface.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "bfd.h"
#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void rip_zebra_ipv4_send(struct rip *rip, struct route_node *rp,
				uint8_t cmd)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct rip_info *rinfo = NULL;
	uint32_t count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = rip->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_RIP;
	api.safi = SAFI_UNICAST;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= zebra_ecmp_count)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = rip->vrf->vrf_id;
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
			zlog_debug("%s: %pFX nexthops %d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   &rp->p, count);
		else
			zlog_debug("%s: %pFX",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra", &rp->p);
	}

	rip->counters.route_changes++;
}

/* Add/update ECMP routes to zebra. */
void rip_zebra_ipv4_add(struct rip *rip, struct route_node *rp)
{
	rip_zebra_ipv4_send(rip, rp, ZEBRA_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void rip_zebra_ipv4_delete(struct rip *rip, struct route_node *rp)
{
	rip_zebra_ipv4_send(rip, rp, ZEBRA_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int rip_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct rip *rip;
	struct zapi_route api;
	struct nexthop nh;

	rip = rip_lookup_by_vrf_id(vrf_id);
	if (!rip)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	memset(&nh, 0, sizeof(nh));
	nh.type = api.nexthops[0].type;
	nh.gate.ipv4 = api.nexthops[0].gate.ipv4;
	nh.ifindex = api.nexthops[0].ifindex;

	/* Then fetch IPv4 prefixes. */
	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		rip_redistribute_add(rip, api.type, RIP_ROUTE_REDISTRIBUTE,
				     (struct prefix_ipv4 *)&api.prefix, &nh,
				     api.metric, api.distance, api.tag);
	else if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_DEL)
		rip_redistribute_delete(rip, api.type, RIP_ROUTE_REDISTRIBUTE,
					(struct prefix_ipv4 *)&api.prefix,
					nh.ifindex);

	return 0;
}

void rip_redistribute_conf_update(struct rip *rip, int type)
{
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
				type, 0, rip->vrf->vrf_id);
}

void rip_redistribute_conf_delete(struct rip *rip, int type)
{
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, type, 0, rip->vrf->vrf_id);

	/* Remove the routes from RIP table. */
	rip_redistribute_withdraw(rip, type);
}

int rip_redistribute_check(struct rip *rip, int type)
{
	return rip->redist[type].enabled;
}

void rip_redistribute_enable(struct rip *rip)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!rip_redistribute_check(rip, i))
			continue;

		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP,
					i, 0, rip->vrf->vrf_id);
	}
}

void rip_redistribute_disable(struct rip *rip)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!rip_redistribute_check(rip, i))
			continue;

		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, i, 0, rip->vrf->vrf_id);
	}
}

void rip_show_redistribute_config(struct vty *vty, struct rip *rip)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i == zclient->redist_default
		    || !rip_redistribute_check(rip, i))
			continue;

		vty_out(vty, " %s", zebra_route_string(i));
	}
}

void rip_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: register VRF %s(%u) to zebra", __func__,
			   vrf->name, vrf->vrf_id);

	zclient_send_reg_requests(zclient, vrf->vrf_id);
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf->vrf_id);
}

void rip_zebra_vrf_deregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: deregister VRF %s(%u) from zebra.", __func__,
			   vrf->name, vrf->vrf_id);

	zclient_send_dereg_requests(zclient, vrf->vrf_id);
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_DEREGISTER, vrf->vrf_id);
}

static void rip_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);
}

zclient_handler *const rip_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = rip_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = rip_interface_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = rip_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = rip_zebra_read_route,
};

static void rip_zebra_capabilities(struct zclient_capabilities *cap)
{
	zebra_ecmp_count = MIN(cap->ecmp, zebra_ecmp_count);
}

void rip_zclient_init(struct event_loop *master)
{
	/* Set default value to the zebra client structure. */
	zclient = zclient_new(master, &zclient_options_default, rip_handlers,
			      array_size(rip_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_RIP, 0, &ripd_privs);
	zclient->zebra_connected = rip_zebra_connected;
	zclient->zebra_capabilities = rip_zebra_capabilities;
}

void rip_zclient_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
