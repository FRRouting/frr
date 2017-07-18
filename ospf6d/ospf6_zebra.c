/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#include "log.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "memory.h"
#include "lib/bfd.h"

#include "ospf6_proto.h"
#include "ospf6_top.h"
#include "ospf6_interface.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_asbr.h"
#include "ospf6_zebra.h"
#include "ospf6d.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_DISTANCE, "OSPF6 distance")

unsigned char conf_debug_ospf6_zebra = 0;

/* information about zebra. */
struct zclient *zclient = NULL;

struct in_addr router_id_zebra;

/* Router-id update message from zebra. */
static int ospf6_router_id_update_zebra(int command, struct zclient *zclient,
					zebra_size_t length, vrf_id_t vrf_id)
{
	struct prefix router_id;
	struct ospf6 *o = ospf6;

	zebra_router_id_update_read(zclient->ibuf, &router_id);
	router_id_zebra = router_id.u.prefix4;

	if (o == NULL)
		return 0;

	if (o->router_id == 0)
		o->router_id = (u_int32_t)router_id_zebra.s_addr;

	return 0;
}

/* redistribute function */
void ospf6_zebra_redistribute(int type)
{
	if (vrf_bitmap_check(zclient->redist[AFI_IP6][type], VRF_DEFAULT))
		return;
	vrf_bitmap_set(zclient->redist[AFI_IP6][type], VRF_DEFAULT);

	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient,
					AFI_IP6, type, 0, VRF_DEFAULT);
}

void ospf6_zebra_no_redistribute(int type)
{
	if (!vrf_bitmap_check(zclient->redist[AFI_IP6][type], VRF_DEFAULT))
		return;
	vrf_bitmap_unset(zclient->redist[AFI_IP6][type], VRF_DEFAULT);
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, type, 0, VRF_DEFAULT);
}

/* Inteface addition message from zebra. */
static int ospf6_zebra_if_add(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface add: %s index %d mtu %d", ifp->name,
			   ifp->ifindex, ifp->mtu6);
	ospf6_interface_if_add(ifp);
	return 0;
}

static int ospf6_zebra_if_del(int command, struct zclient *zclient,
			      zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	if (!(ifp = zebra_interface_state_read(zclient->ibuf, vrf_id)))
		return 0;

	if (if_is_up(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface delete: %s index %d mtu %d",
			   ifp->name, ifp->ifindex, ifp->mtu6);

#if 0
  /* XXX: ospf6_interface_if_del is not the right way to handle this,
   * because among other thinkable issues, it will also clear all
   * settings as they are contained in the struct ospf6_interface. */
  ospf6_interface_if_del (ifp);
#endif /*0*/

	ifp->ifindex = IFINDEX_DELETED;
	return 0;
}

static int ospf6_zebra_if_state_update(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
	if (ifp == NULL)
		return 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug(
			"Zebra Interface state change: "
			"%s index %d flags %llx metric %d mtu %d bandwidth %d",
			ifp->name, ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu6, ifp->bandwidth);

	ospf6_interface_state_update(ifp);
	return 0;
}

static int ospf6_zebra_if_address_update_add(int command,
					     struct zclient *zclient,
					     zebra_size_t length,
					     vrf_id_t vrf_id)
{
	struct connected *c;
	char buf[128];

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);
	if (c == NULL)
		return 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface address add: %s %5s %s/%d",
			   c->ifp->name, prefix_family_str(c->address),
			   inet_ntop(c->address->family, &c->address->u.prefix,
				     buf, sizeof(buf)),
			   c->address->prefixlen);

	if (c->address->family == AF_INET6) {
		ospf6_interface_state_update(c->ifp);
		ospf6_interface_connected_route_update(c->ifp);
	}
	return 0;
}

static int ospf6_zebra_if_address_update_delete(int command,
						struct zclient *zclient,
						zebra_size_t length,
						vrf_id_t vrf_id)
{
	struct connected *c;
	char buf[128];

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);
	if (c == NULL)
		return 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface address delete: %s %5s %s/%d",
			   c->ifp->name, prefix_family_str(c->address),
			   inet_ntop(c->address->family, &c->address->u.prefix,
				     buf, sizeof(buf)),
			   c->address->prefixlen);

	if (c->address->family == AF_INET6) {
		ospf6_interface_connected_route_update(c->ifp);
		ospf6_interface_state_update(c->ifp);
	}

	connected_free(c);

	return 0;
}

static int ospf6_zebra_read_ipv6(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct stream *s;
	struct zapi_ipv6 api;
	unsigned long ifindex;
	struct prefix p, src_p;
	struct in6_addr *nexthop;

	if (ospf6 == NULL)
		return 0;

	s = zclient->ibuf;
	ifindex = 0;
	nexthop = NULL;
	memset(&api, 0, sizeof(api));

	/* Type, flags, message. */
	api.type = stream_getc(s);
	api.instance = stream_getw(s);
	api.flags = stream_getl(s);
	api.message = stream_getc(s);

	/* IPv6 prefix. */
	memset(&p, 0, sizeof(struct prefix));
	p.family = AF_INET6;
	p.prefixlen = MIN(IPV6_MAX_PREFIXLEN, stream_getc(s));
	stream_get(&p.u.prefix6, s, PSIZE(p.prefixlen));

	memset(&src_p, 0, sizeof(struct prefix));
	src_p.family = AF_INET6;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX)) {
		src_p.prefixlen = stream_getc(s);
		stream_get(&src_p.u.prefix6, s, PSIZE(src_p.prefixlen));
	}

	if (src_p.prefixlen)
		/* we completely ignore srcdest routes for now. */
		return 0;

	/* Nexthop, ifindex, distance, metric. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP)) {
		api.nexthop_num = stream_getc(s);
		nexthop = (struct in6_addr *)malloc(api.nexthop_num
						    * sizeof(struct in6_addr));
		stream_get(nexthop, s,
			   api.nexthop_num * sizeof(struct in6_addr));
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_IFINDEX)) {
		api.ifindex_num = stream_getc(s);
		ifindex = stream_getl(s);
	}
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_DISTANCE))
		api.distance = stream_getc(s);
	else
		api.distance = 0;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_METRIC))
		api.metric = stream_getl(s);
	else
		api.metric = 0;

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_TAG))
		api.tag = stream_getl(s);
	else
		api.tag = 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV)) {
		char prefixstr[PREFIX2STR_BUFFER], nexthopstr[128];
		prefix2str((struct prefix *)&p, prefixstr, sizeof(prefixstr));
		if (nexthop)
			inet_ntop(AF_INET6, nexthop, nexthopstr,
				  sizeof(nexthopstr));
		else
			snprintf(nexthopstr, sizeof(nexthopstr), "::");

		zlog_debug(
			"Zebra Receive route %s: %s %s nexthop %s ifindex %ld tag %" ROUTE_TAG_PRI,
			(command == ZEBRA_REDISTRIBUTE_IPV6_ADD ? "add"
								: "delete"),
			zebra_route_string(api.type), prefixstr, nexthopstr,
			ifindex, api.tag);
	}

	if (command == ZEBRA_REDISTRIBUTE_IPV6_ADD)
		ospf6_asbr_redistribute_add(api.type, ifindex, &p,
					    api.nexthop_num, nexthop, api.tag);
	else
		ospf6_asbr_redistribute_remove(api.type, ifindex, &p);

	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP))
		free(nexthop);

	return 0;
}

DEFUN (show_zebra,
       show_ospf6_zebra_cmd,
       "show ipv6 ospf6 zebra",
       SHOW_STR
       IPV6_STR
       OSPF6_STR
       "Zebra information\n")
{
	int i;
	if (zclient == NULL) {
		vty_out(vty, "Not connected to zebra\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Zebra Infomation\n");
	vty_out(vty, "  enable: %d fail: %d\n", zclient->enable, zclient->fail);
	vty_out(vty, "  redistribute default: %d\n",
		vrf_bitmap_check(zclient->default_information, VRF_DEFAULT));
	vty_out(vty, "  redistribute:");
	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (vrf_bitmap_check(zclient->redist[AFI_IP6][i], VRF_DEFAULT))
			vty_out(vty, " %s", zebra_route_string(i));
	}
	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

/* Zebra configuration write function. */
static int config_write_ospf6_zebra(struct vty *vty)
{
	if (!zclient->enable) {
		vty_out(vty, "no router zebra\n");
		vty_out(vty, "!\n");
	} else if (!vrf_bitmap_check(
			   zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			   VRF_DEFAULT)) {
		vty_out(vty, "router zebra\n");
		vty_out(vty, " no redistribute ospf6\n");
		vty_out(vty, "!\n");
	}
	return 0;
}

/* Zebra node structure. */
static struct cmd_node zebra_node = {
	ZEBRA_NODE,
	"%s(config-zebra)# ",
};

#define ADD    0
#define REM    1
static void ospf6_zebra_route_update(int type, struct ospf6_route *request)
{
	struct zapi_ipv6 api;
	char buf[PREFIX2STR_BUFFER];
	int nhcount;
	struct in6_addr **nexthops;
	ifindex_t *ifindexes;
	int ret = 0;
	struct prefix_ipv6 *dest;

	if (IS_OSPF6_DEBUG_ZEBRA(SEND)) {
		prefix2str(&request->prefix, buf, sizeof(buf));
		zlog_debug("Send %s route: %s",
			   (type == REM ? "remove" : "add"), buf);
	}

	if (zclient->sock < 0) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  Not connected to Zebra");
		return;
	}

	if (request->path.origin.adv_router == ospf6->router_id
	    && (request->path.type == OSPF6_PATH_TYPE_EXTERNAL1
		|| request->path.type == OSPF6_PATH_TYPE_EXTERNAL2)) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  Ignore self-originated external route");
		return;
	}

	/* If removing is the best path and if there's another path,
	   treat this request as add the secondary path */
	if (type == REM && ospf6_route_is_best(request) && request->next
	    && ospf6_route_is_same(request, request->next)) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug(
				"  Best-path removal resulted Sencondary addition");
		type = ADD;
		request = request->next;
	}

	/* Only the best path will be sent to zebra. */
	if (!ospf6_route_is_best(request)) {
		/* this is not preferred best route, ignore */
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  Ignore non-best route");
		return;
	}

	nhcount = ospf6_route_num_nexthops(request);
	if (nhcount == 0) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  No nexthop, ignore");
		return;
	}

	/* allocate memory for nexthop_list */
	nexthops =
		XCALLOC(MTYPE_OSPF6_OTHER, nhcount * sizeof(struct in6_addr *));
	if (nexthops == NULL) {
		zlog_warn("Can't send route to zebra: malloc failed");
		return;
	}

	/* allocate memory for ifindex_list */
	ifindexes = XCALLOC(MTYPE_OSPF6_OTHER, nhcount * sizeof(ifindex_t));
	if (ifindexes == NULL) {
		zlog_warn("Can't send route to zebra: malloc failed");
		XFREE(MTYPE_OSPF6_OTHER, nexthops);
		return;
	}

	ospf6_route_zebra_copy_nexthops(request, ifindexes, nexthops, nhcount);

	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_OSPF6;
	api.instance = 0;
	api.flags = 0;
	api.message = 0;
	api.safi = SAFI_UNICAST;
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	api.nexthop_num = nhcount;
	api.nexthop = nexthops;
	SET_FLAG(api.message, ZAPI_MESSAGE_IFINDEX);
	api.ifindex_num = nhcount;
	api.ifindex = ifindexes;
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = (request->path.metric_type == 2 ? request->path.u.cost_e2
						     : request->path.cost);
	if (request->path.tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = request->path.tag;
	}

	dest = (struct prefix_ipv6 *)&request->prefix;

	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	api.distance = ospf6_distance_apply(dest, request);

	if (type == REM)
		ret = zapi_ipv6_route(ZEBRA_IPV6_ROUTE_DELETE, zclient, dest,
				      NULL, &api);
	else
		ret = zapi_ipv6_route(ZEBRA_IPV6_ROUTE_ADD, zclient, dest, NULL,
				      &api);

	if (ret < 0)
		zlog_err("zapi_ipv6_route() %s failed: %s",
			 (type == REM ? "delete" : "add"),
			 safe_strerror(errno));

	XFREE(MTYPE_OSPF6_OTHER, nexthops);
	XFREE(MTYPE_OSPF6_OTHER, ifindexes);

	return;
}

void ospf6_zebra_route_update_add(struct ospf6_route *request)
{
	if (!vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			      VRF_DEFAULT)) {
		ospf6->route_table->hook_add = NULL;
		ospf6->route_table->hook_remove = NULL;
		return;
	}
	ospf6_zebra_route_update(ADD, request);
}

void ospf6_zebra_route_update_remove(struct ospf6_route *request)
{
	if (!vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			      VRF_DEFAULT)) {
		ospf6->route_table->hook_add = NULL;
		ospf6->route_table->hook_remove = NULL;
		return;
	}
	ospf6_zebra_route_update(REM, request);
}

void ospf6_zebra_add_discard(struct ospf6_route *request)
{
	struct zapi_ipv6 api;
	char buf[INET6_ADDRSTRLEN];
	struct prefix_ipv6 *dest;

	if (vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			     VRF_DEFAULT)) {
		if (!CHECK_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED)) {
			api.vrf_id = VRF_DEFAULT;
			api.type = ZEBRA_ROUTE_OSPF6;
			api.flags = ZEBRA_FLAG_BLACKHOLE;
			api.instance = 0;
			api.message = 0;
			api.safi = SAFI_UNICAST;
			SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
			api.nexthop_num = 0;
			api.ifindex_num = 0;

			dest = (struct prefix_ipv6 *)&request->prefix;

			zapi_ipv6_route(ZEBRA_IPV6_ROUTE_ADD, zclient, dest,
					NULL, &api);

			if (IS_OSPF6_DEBUG_ZEBRA(SEND))
				zlog_debug("Zebra: Route add discard %s/%d",
					   inet_ntop(AF_INET6, &dest->prefix,
						     buf, INET6_ADDRSTRLEN),
					   dest->prefixlen);
			SET_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED);
		} else {
			dest = (struct prefix_ipv6 *)&request->prefix;

			if (IS_OSPF6_DEBUG_ZEBRA(SEND))
				zlog_debug(
					"Zebra: Blackhole route present already %s/%d",
					inet_ntop(AF_INET6, &dest->prefix, buf,
						  INET6_ADDRSTRLEN),
					dest->prefixlen);
		}
	}
}

void ospf6_zebra_delete_discard(struct ospf6_route *request)
{
	struct zapi_ipv6 api;
	char buf[INET6_ADDRSTRLEN];
	struct prefix_ipv6 *dest;

	if (vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			     VRF_DEFAULT)) {
		if (CHECK_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED)) {
			api.vrf_id = VRF_DEFAULT;
			api.type = ZEBRA_ROUTE_OSPF6;
			api.flags = ZEBRA_FLAG_BLACKHOLE;
			api.instance = 0;
			api.message = 0;
			api.safi = SAFI_UNICAST;
			SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
			api.nexthop_num = 0;
			api.ifindex_num = 0;

			dest = (struct prefix_ipv6 *)&request->prefix;

			zapi_ipv6_route(ZEBRA_IPV6_ROUTE_DELETE, zclient, dest,
					NULL, &api);

			if (IS_OSPF6_DEBUG_ZEBRA(SEND))
				zlog_debug("Zebra: Route delete discard %s/%d",
					   inet_ntop(AF_INET6, &dest->prefix,
						     buf, INET6_ADDRSTRLEN),
					   dest->prefixlen);
			UNSET_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED);
		} else {
			dest = (struct prefix_ipv6 *)&request->prefix;
			if (IS_OSPF6_DEBUG_ZEBRA(SEND))
				zlog_debug(
					"Zebra: Blackhole route already deleted %s/%d",
					inet_ntop(AF_INET6, &dest->prefix, buf,
						  INET6_ADDRSTRLEN),
					dest->prefixlen);
		}
	}
}

DEFUN (redistribute_ospf6,
       redistribute_ospf6_cmd,
       "redistribute ospf6",
       "Redistribute control\n"
       "OSPF6 route\n")
{
	struct ospf6_route *route;

	if (vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			     VRF_DEFAULT))
		return CMD_SUCCESS;

	vrf_bitmap_set(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
		       VRF_DEFAULT);

	if (ospf6 == NULL)
		return CMD_SUCCESS;

	/* send ospf6 route to zebra route table */
	for (route = ospf6_route_head(ospf6->route_table); route;
	     route = ospf6_route_next(route))
		ospf6_zebra_route_update_add(route);

	ospf6->route_table->hook_add = ospf6_zebra_route_update_add;
	ospf6->route_table->hook_remove = ospf6_zebra_route_update_remove;

	return CMD_SUCCESS;
}

DEFUN (no_redistribute_ospf6,
       no_redistribute_ospf6_cmd,
       "no redistribute ospf6",
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")
{
	struct ospf6_route *route;

	if (!vrf_bitmap_check(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			      VRF_DEFAULT))
		return CMD_SUCCESS;

	vrf_bitmap_unset(zclient->redist[AFI_IP6][ZEBRA_ROUTE_OSPF6],
			 VRF_DEFAULT);

	if (ospf6 == NULL)
		return CMD_SUCCESS;

	ospf6->route_table->hook_add = NULL;
	ospf6->route_table->hook_remove = NULL;

	/* withdraw ospf6 route from zebra route table */
	for (route = ospf6_route_head(ospf6->route_table); route;
	     route = ospf6_route_next(route))
		ospf6_zebra_route_update_remove(route);

	return CMD_SUCCESS;
}

static struct ospf6_distance *ospf6_distance_new(void)
{
	return XCALLOC(MTYPE_OSPF6_DISTANCE, sizeof(struct ospf6_distance));
}

static void ospf6_distance_free(struct ospf6_distance *odistance)
{
	XFREE(MTYPE_OSPF6_DISTANCE, odistance);
}

int ospf6_distance_set(struct vty *vty, struct ospf6 *o,
		       const char *distance_str, const char *ip_str,
		       const char *access_list_str)
{
	int ret;
	struct prefix_ipv6 p;
	u_char distance;
	struct route_node *rn;
	struct ospf6_distance *odistance;

	ret = str2prefix_ipv6(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	distance = atoi(distance_str);

	/* Get OSPF6 distance node. */
	rn = route_node_get(o->distance_table, (struct prefix *)&p);
	if (rn->info) {
		odistance = rn->info;
		route_unlock_node(rn);
	} else {
		odistance = ospf6_distance_new();
		rn->info = odistance;
	}

	/* Set distance value. */
	odistance->distance = distance;

	/* Reset access-list configuration. */
	if (odistance->access_list) {
		free(odistance->access_list);
		odistance->access_list = NULL;
	}
	if (access_list_str)
		odistance->access_list = strdup(access_list_str);

	return CMD_SUCCESS;
}

int ospf6_distance_unset(struct vty *vty, struct ospf6 *o,
			 const char *distance_str, const char *ip_str,
			 const char *access_list_str)
{
	int ret;
	struct prefix_ipv6 p;
	struct route_node *rn;
	struct ospf6_distance *odistance;

	ret = str2prefix_ipv6(ip_str, &p);
	if (ret == 0) {
		vty_out(vty, "Malformed prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn = route_node_lookup(o->distance_table, (struct prefix *)&p);
	if (!rn) {
		vty_out(vty, "Cant't find specified prefix\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	odistance = rn->info;

	if (odistance->access_list)
		free(odistance->access_list);
	ospf6_distance_free(odistance);

	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);

	return CMD_SUCCESS;
}

void ospf6_distance_reset(struct ospf6 *o)
{
	struct route_node *rn;
	struct ospf6_distance *odistance;

	for (rn = route_top(o->distance_table); rn; rn = route_next(rn))
		if ((odistance = rn->info) != NULL) {
			if (odistance->access_list)
				free(odistance->access_list);
			ospf6_distance_free(odistance);
			rn->info = NULL;
			route_unlock_node(rn);
		}
}

u_char ospf6_distance_apply(struct prefix_ipv6 *p, struct ospf6_route * or)
{
	struct ospf6 *o;

	o = ospf6;
	if (o == NULL)
		return 0;

	if (o->distance_intra)
		if (or->path.type == OSPF6_PATH_TYPE_INTRA)
			return o->distance_intra;

	if (o->distance_inter)
		if (or->path.type == OSPF6_PATH_TYPE_INTER)
			return o->distance_inter;

	if (o->distance_external)
		if (or->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
		    or->path.type == OSPF6_PATH_TYPE_EXTERNAL2)
			return o->distance_external;

	if (o->distance_all)
		return o->distance_all;

	return 0;
}

static void ospf6_zebra_connected(struct zclient *zclient)
{
	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);

	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void ospf6_zebra_init(struct thread_master *master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master);
	zclient_init(zclient, ZEBRA_ROUTE_OSPF6, 0);
	zclient->zebra_connected = ospf6_zebra_connected;
	zclient->router_id_update = ospf6_router_id_update_zebra;
	zclient->interface_add = ospf6_zebra_if_add;
	zclient->interface_delete = ospf6_zebra_if_del;
	zclient->interface_up = ospf6_zebra_if_state_update;
	zclient->interface_down = ospf6_zebra_if_state_update;
	zclient->interface_address_add = ospf6_zebra_if_address_update_add;
	zclient->interface_address_delete =
		ospf6_zebra_if_address_update_delete;
	zclient->redistribute_route_ipv4_add = NULL;
	zclient->redistribute_route_ipv4_del = NULL;
	zclient->redistribute_route_ipv6_add = ospf6_zebra_read_ipv6;
	zclient->redistribute_route_ipv6_del = ospf6_zebra_read_ipv6;

	/* redistribute connected route by default */
	/* ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT); */

	/* Install zebra node. */
	install_node(&zebra_node, config_write_ospf6_zebra);

	/* Install command element for zebra node. */
	install_element(VIEW_NODE, &show_ospf6_zebra_cmd);
	install_default(ZEBRA_NODE);
	install_element(ZEBRA_NODE, &redistribute_ospf6_cmd);
	install_element(ZEBRA_NODE, &no_redistribute_ospf6_cmd);

	return;
}

/* Debug */

DEFUN (debug_ospf6_zebra_sendrecv,
       debug_ospf6_zebra_sendrecv_cmd,
       "debug ospf6 zebra [<send|recv>]",
       DEBUG_STR
       OSPF6_STR
       "Debug connection between zebra\n"
       "Debug Sending zebra\n"
       "Debug Receiving zebra\n"
      )
{
	int idx_send_recv = 3;
	unsigned char level = 0;

	if (argc == 4) {
		if (strmatch(argv[idx_send_recv]->text, "send"))
			level = OSPF6_DEBUG_ZEBRA_SEND;
		else if (strmatch(argv[idx_send_recv]->text, "recv"))
			level = OSPF6_DEBUG_ZEBRA_RECV;
	} else
		level = OSPF6_DEBUG_ZEBRA_SEND | OSPF6_DEBUG_ZEBRA_RECV;

	OSPF6_DEBUG_ZEBRA_ON(level);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_zebra_sendrecv,
       no_debug_ospf6_zebra_sendrecv_cmd,
       "no debug ospf6 zebra [<send|recv>]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug connection between zebra\n"
       "Debug Sending zebra\n"
       "Debug Receiving zebra\n"
      )
{
	int idx_send_recv = 4;
	unsigned char level = 0;

	if (argc == 5) {
		if (strmatch(argv[idx_send_recv]->text, "send"))
			level = OSPF6_DEBUG_ZEBRA_SEND;
		else if (strmatch(argv[idx_send_recv]->text, "recv"))
			level = OSPF6_DEBUG_ZEBRA_RECV;
	} else
		level = OSPF6_DEBUG_ZEBRA_SEND | OSPF6_DEBUG_ZEBRA_RECV;

	OSPF6_DEBUG_ZEBRA_OFF(level);
	return CMD_SUCCESS;
}


int config_write_ospf6_debug_zebra(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_ZEBRA(SEND) && IS_OSPF6_DEBUG_ZEBRA(RECV))
		vty_out(vty, "debug ospf6 zebra\n");
	else {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			vty_out(vty, "debug ospf6 zebra send\n");
		if (IS_OSPF6_DEBUG_ZEBRA(RECV))
			vty_out(vty, "debug ospf6 zebra recv\n");
	}
	return 0;
}

void install_element_ospf6_debug_zebra(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_zebra_sendrecv_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_zebra_sendrecv_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_zebra_sendrecv_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_zebra_sendrecv_cmd);
}
