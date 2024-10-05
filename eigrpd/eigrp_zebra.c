// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect library for EIGRP.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#include "eigrpd/eigrp_types.h"
#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_metric.h"

static int eigrp_interface_address_add(ZAPI_CALLBACK_ARGS);
static int eigrp_interface_address_delete(ZAPI_CALLBACK_ARGS);

static int eigrp_zebra_read_route(ZAPI_CALLBACK_ARGS);

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct event_loop *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int eigrp_router_id_update_zebra(ZAPI_CALLBACK_ARGS)
{
	struct eigrp *eigrp;
	struct prefix router_id;
	zebra_router_id_update_read(zclient->ibuf, &router_id);

	router_id_zebra = router_id.u.prefix4;

	eigrp = eigrp_lookup(vrf_id);

	if (eigrp != NULL)
		eigrp_router_id_update(eigrp);

	return 0;
}

static int eigrp_zebra_route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note, NULL,
				      NULL))
		return -1;

	return 0;
}

static void eigrp_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static zclient_handler *const eigrp_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = eigrp_router_id_update_zebra,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = eigrp_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = eigrp_interface_address_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = eigrp_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = eigrp_zebra_read_route,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = eigrp_zebra_route_notify_owner,
};

void eigrp_zebra_init(void)
{
	zclient = zclient_new(master, &zclient_options_default, eigrp_handlers,
			      array_size(eigrp_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_EIGRP, 0, &eigrpd_privs);
	zclient->zebra_connected = eigrp_zebra_connected;
}


/* Zebra route add and delete treatment. */
static int eigrp_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;
	struct eigrp *eigrp;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	if (IPV4_NET127(ntohl(api.prefix.u.prefix4.s_addr)))
		return 0;

	eigrp = eigrp_lookup(vrf_id);
	if (eigrp == NULL)
		return 0;

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD) {

	} else /* if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_DEL) */
	{
	}

	return 0;
}

static int eigrp_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: interface %s address add %pFX", c->ifp->name,
			   c->address);

	eigrp_if_update(c->ifp);

	return 0;
}

static int eigrp_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;
	struct interface *ifp;
	struct eigrp_interface *ei;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: interface %s address delete %pFX",
			   c->ifp->name, c->address);

	ifp = c->ifp;
	ei = ifp->info;
	if (!ei)
		return 0;

	/* Call interface hook functions to clean up */
	if (prefix_cmp(&ei->address, c->address) == 0)
		eigrp_if_free(ei, INTERFACE_DOWN_BY_ZEBRA);

	connected_free(&c);

	return 0;
}

void eigrp_zebra_route_add(struct eigrp *eigrp, struct prefix *p,
			   struct list *successors, uint32_t distance)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct eigrp_route_descriptor *te;
	struct listnode *node;
	int count = 0;

	if (!zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = eigrp->vrf_id;
	api.type = ZEBRA_ROUTE_EIGRP;
	api.safi = SAFI_UNICAST;
	api.metric = distance;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);

	/* Nexthop, ifindex, distance and metric information. */
	for (ALL_LIST_ELEMENTS_RO(successors, node, te)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = eigrp->vrf_id;
		if (te->adv_router->src.s_addr) {
			api_nh->gate.ipv4 = te->adv_router->src;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
		} else
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
		api_nh->ifindex = te->ei->ifp->ifindex;

		count++;
	}
	api.nexthop_num = count;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_REDISTRIBUTE)) {
		zlog_debug("Zebra: Route add %pFX", p);
	}

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void eigrp_zebra_route_delete(struct eigrp *eigrp, struct prefix *p)
{
	struct zapi_route api;

	if (!zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = eigrp->vrf_id;
	api.type = ZEBRA_ROUTE_EIGRP;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_REDISTRIBUTE))
		zlog_debug("Zebra: Route del %pFX", p);

	return;
}

static int eigrp_is_type_redistributed(int type, vrf_id_t vrf_id)
{
	return ((DEFAULT_ROUTE_TYPE(type))
			? vrf_bitmap_check(
				  &zclient->default_information[AFI_IP], vrf_id)
			: vrf_bitmap_check(&zclient->redist[AFI_IP][type],
					   vrf_id));
}

int eigrp_redistribute_set(struct eigrp *eigrp, int type,
			   struct eigrp_metrics metric)
{

	if (eigrp_is_type_redistributed(type, eigrp->vrf_id)) {
		if (eigrp_metrics_is_same(metric, eigrp->dmetric[type])) {
			eigrp->dmetric[type] = metric;
		}

		eigrp_external_routes_refresh(eigrp, type);

		//      if (IS_DEBUG_EIGRP(zebra, ZEBRA_REDISTRIBUTE))
		//        zlog_debug ("Redistribute[%s]: Refresh  Type[%d],
		//        Metric[%d]",
		//                   eigrp_redist_string(type),
		//                   metric_type (eigrp, type), metric_value
		//                   (eigrp, type));
		return CMD_SUCCESS;
	}

	eigrp->dmetric[type] = metric;

	zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP, type, 0,
			     eigrp->vrf_id);

	++eigrp->redistribute;

	return CMD_SUCCESS;
}

int eigrp_redistribute_unset(struct eigrp *eigrp, int type)
{

	if (eigrp_is_type_redistributed(type, eigrp->vrf_id)) {
		memset(&eigrp->dmetric[type], 0, sizeof(struct eigrp_metrics));
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP,
				     type, 0, eigrp->vrf_id);
		--eigrp->redistribute;
	}

	return CMD_SUCCESS;
}
