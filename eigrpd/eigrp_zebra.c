/*
 * Zebra connect library for EIGRP.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

static int eigrp_interface_add(int, struct zclient *, zebra_size_t, vrf_id_t);
static int eigrp_interface_delete(int, struct zclient *, zebra_size_t,
				  vrf_id_t);
static int eigrp_interface_address_add(int, struct zclient *, zebra_size_t,
				       vrf_id_t vrf_id);
static int eigrp_interface_address_delete(int, struct zclient *, zebra_size_t,
					  vrf_id_t vrf_id);
static int eigrp_interface_state_up(int, struct zclient *, zebra_size_t,
				    vrf_id_t vrf_id);
static int eigrp_interface_state_down(int, struct zclient *, zebra_size_t,
				      vrf_id_t vrf_id);
static struct interface *zebra_interface_if_lookup(struct stream *);

static int eigrp_zebra_read_route(int, struct zclient *, zebra_size_t,
				  vrf_id_t vrf_id);

/* Zebra structure to hold current status. */
struct zclient *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;
struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int eigrp_router_id_update_zebra(int command, struct zclient *zclient,
					zebra_size_t length, vrf_id_t vrf_id)
{
	struct eigrp *eigrp;
	struct prefix router_id;
	zebra_router_id_update_read(zclient->ibuf, &router_id);

	router_id_zebra = router_id.u.prefix4;

	eigrp = eigrp_lookup();

	if (eigrp != NULL)
		eigrp_router_id_update(eigrp);

	return 0;
}

static int eigrp_zebra_route_notify_owner(int command, struct zclient *zclient,
					  zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table, &note))
		return -1;

	return 0;
}

static void eigrp_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void eigrp_zebra_init(void)
{
	struct zclient_options opt = {.receive_notify = false};

	zclient = zclient_new_notify(master, &opt);

	zclient_init(zclient, ZEBRA_ROUTE_EIGRP, 0, &eigrpd_privs);
	zclient->zebra_connected = eigrp_zebra_connected;
	zclient->router_id_update = eigrp_router_id_update_zebra;
	zclient->interface_add = eigrp_interface_add;
	zclient->interface_delete = eigrp_interface_delete;
	zclient->interface_up = eigrp_interface_state_up;
	zclient->interface_down = eigrp_interface_state_down;
	zclient->interface_address_add = eigrp_interface_address_add;
	zclient->interface_address_delete = eigrp_interface_address_delete;
	zclient->redistribute_route_add = eigrp_zebra_read_route;
	zclient->redistribute_route_del = eigrp_zebra_read_route;
	zclient->route_notify_owner = eigrp_zebra_route_notify_owner;
}


/* Zebra route add and delete treatment. */
static int eigrp_zebra_read_route(int command, struct zclient *zclient,
				  zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct eigrp *eigrp;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	if (IPV4_NET127(ntohl(api.prefix.u.prefix4.s_addr)))
		return 0;

	eigrp = eigrp_lookup();
	if (eigrp == NULL)
		return 0;

	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD) {

	} else /* if (command == ZEBRA_REDISTRIBUTE_ROUTE_DEL) */
	{
	}

	return 0;
}

/* Inteface addition message from zebra. */
static int eigrp_interface_add(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (!ifp->info)
		return 0;

	ei = ifp->info;

	ei->params.type = eigrp_default_iftype(ifp);

	eigrp_if_update(ifp);

	return 0;
}

static int eigrp_interface_delete(int command, struct zclient *zclient,
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

	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface delete %s index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	if (ifp->info)
		eigrp_if_free(ifp->info, INTERFACE_DOWN_BY_ZEBRA);

	if_set_index(ifp, IFINDEX_INTERNAL);
	return 0;
}

static int eigrp_interface_address_add(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE)) {
		char buf[128];
		prefix2str(c->address, buf, sizeof(buf));
		zlog_debug("Zebra: interface %s address add %s", c->ifp->name,
			   buf);
	}

	eigrp_if_update(c->ifp);

	return 0;
}

static int eigrp_interface_address_delete(int command, struct zclient *zclient,
					  zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct interface *ifp;
	struct eigrp_interface *ei;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE)) {
		char buf[128];
		prefix2str(c->address, buf, sizeof(buf));
		zlog_debug("Zebra: interface %s address delete %s",
			   c->ifp->name, buf);
	}

	ifp = c->ifp;
	ei = ifp->info;
	if (!ei)
		return 0;

	/* Call interface hook functions to clean up */
	eigrp_if_free(ei, INTERFACE_DOWN_BY_ZEBRA);

	connected_free(c);

	return 0;
}

static int eigrp_interface_state_up(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_if_lookup(zclient->ibuf);

	if (ifp == NULL)
		return 0;

	/* Interface is already up. */
	if (if_is_operative(ifp)) {
		/* Temporarily keep ifp values. */
		struct interface if_tmp;
		memcpy(&if_tmp, ifp, sizeof(struct interface));

		zebra_interface_if_set_value(zclient->ibuf, ifp);

		if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
			zlog_debug("Zebra: Interface[%s] state update.",
				   ifp->name);

		if (if_tmp.bandwidth != ifp->bandwidth) {
			if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
				zlog_debug(
					"Zebra: Interface[%s] bandwidth change %d -> %d.",
					ifp->name, if_tmp.bandwidth,
					ifp->bandwidth);

			//          eigrp_if_recalculate_output_cost (ifp);
		}

		if (if_tmp.mtu != ifp->mtu) {
			if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
				zlog_debug(
					"Zebra: Interface[%s] MTU change %u -> %u.",
					ifp->name, if_tmp.mtu, ifp->mtu);

			/* Must reset the interface (simulate down/up) when MTU
			 * changes. */
			eigrp_if_reset(ifp);
		}
		return 0;
	}

	zebra_interface_if_set_value(zclient->ibuf, ifp);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to up.",
			   ifp->name);

	if (ifp->info)
		eigrp_if_up(ifp->info);

	return 0;
}

static int eigrp_interface_state_down(int command, struct zclient *zclient,
				      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to down.",
			   ifp->name);

	if (ifp->info)
		eigrp_if_down(ifp->info);

	return 0;
}

static struct interface *zebra_interface_if_lookup(struct stream *s)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name(ifname_tmp, VRF_DEFAULT);
}

void eigrp_zebra_route_add(struct prefix *p, struct list *successors)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct eigrp_nexthop_entry *te;
	struct listnode *node;
	int count = 0;

	if (!zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_EIGRP;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	/* Nexthop, ifindex, distance and metric information. */
	for (ALL_LIST_ELEMENTS_RO(successors, node, te)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = VRF_DEFAULT;
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
		char buf[2][PREFIX_STRLEN];
		zlog_debug("Zebra: Route add %s nexthop %s",
			   prefix2str(p, buf[0], PREFIX_STRLEN),
			   inet_ntop(AF_INET, 0, buf[1], PREFIX_STRLEN));
	}

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

void eigrp_zebra_route_delete(struct prefix *p)
{
	struct zapi_route api;

	if (!zclient->redist[AFI_IP][ZEBRA_ROUTE_EIGRP])
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_EIGRP;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, p, sizeof(*p));
	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	if (IS_DEBUG_EIGRP(zebra, ZEBRA_REDISTRIBUTE)) {
		char buf[PREFIX_STRLEN];
		zlog_debug("Zebra: Route del %s",
			   prefix2str(p, buf, PREFIX_STRLEN));
	}

	return;
}

int eigrp_is_type_redistributed(int type)
{
	return ((DEFAULT_ROUTE_TYPE(type))
			? vrf_bitmap_check(zclient->default_information,
					   VRF_DEFAULT)
			: vrf_bitmap_check(zclient->redist[AFI_IP][type],
					   VRF_DEFAULT));
}

int eigrp_redistribute_set(struct eigrp *eigrp, int type,
			   struct eigrp_metrics metric)
{

	if (eigrp_is_type_redistributed(type)) {
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
			     VRF_DEFAULT);

	++eigrp->redistribute;

	return CMD_SUCCESS;
}

int eigrp_redistribute_unset(struct eigrp *eigrp, int type)
{

	if (eigrp_is_type_redistributed(type)) {
		memset(&eigrp->dmetric[type], 0, sizeof(struct eigrp_metrics));
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP,
				     type, 0, VRF_DEFAULT);
		--eigrp->redistribute;
	}

	return CMD_SUCCESS;
}
