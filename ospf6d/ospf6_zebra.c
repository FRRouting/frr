// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "memory.h"
#include "route_opaque.h"
#include "lib/bfd.h"
#include "lib_errors.h"

#include "ospf6_proto.h"
#include "ospf6_top.h"
#include "ospf6_interface.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_asbr.h"
#include "ospf6_nssa.h"
#include "ospf6_zebra.h"
#include "ospf6d.h"
#include "ospf6_area.h"
#include "ospf6_gr.h"
#include "lib/json.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_DISTANCE, "OSPF6 distance");

unsigned char conf_debug_ospf6_zebra = 0;

/* information about zebra. */
struct zclient *zclient = NULL;

void ospf6_zebra_vrf_register(struct ospf6 *ospf6)
{
	if (!zclient || zclient->sock < 0 || !ospf6)
		return;

	if (ospf6->vrf_id != VRF_UNKNOWN) {
		if (IS_OSPF6_DEBUG_ZEBRA(RECV)) {
			zlog_debug("%s: Register VRF %s id %u", __func__,
				   ospf6_vrf_id_to_name(ospf6->vrf_id),
				   ospf6->vrf_id);
		}
		zclient_send_reg_requests(zclient, ospf6->vrf_id);
	}
}

void ospf6_zebra_vrf_deregister(struct ospf6 *ospf6)
{
	if (!zclient || zclient->sock < 0 || !ospf6)
		return;

	if (ospf6->vrf_id != VRF_DEFAULT && ospf6->vrf_id != VRF_UNKNOWN) {
		if (IS_OSPF6_DEBUG_ZEBRA(RECV)) {
			zlog_debug("%s: De-Register VRF %s id %u to Zebra.",
				   __func__,
				   ospf6_vrf_id_to_name(ospf6->vrf_id),
				   ospf6->vrf_id);
		}
		/* Deregister for router-id, interfaces,
		 * redistributed routes. */
		zclient_send_dereg_requests(zclient, ospf6->vrf_id);
	}
}

/* Router-id update message from zebra. */
static int ospf6_router_id_update_zebra(ZAPI_CALLBACK_ARGS)
{
	struct prefix router_id;
	struct ospf6 *o;

	zebra_router_id_update_read(zclient->ibuf, &router_id);

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra router-id update %pI4 vrf %s id %u",
			   &router_id.u.prefix4, ospf6_vrf_id_to_name(vrf_id),
			   vrf_id);

	o = ospf6_lookup_by_vrf_id(vrf_id);
	if (o == NULL)
		return 0;

	o->router_id_zebra = router_id.u.prefix4.s_addr;

	ospf6_router_id_update(o, false);

	return 0;
}

/* redistribute function */
void ospf6_zebra_redistribute(int type, vrf_id_t vrf_id)
{
	if (vrf_bitmap_check(&zclient->redist[AFI_IP6][type], vrf_id))
		return;
	vrf_bitmap_set(&zclient->redist[AFI_IP6][type], vrf_id);

	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient,
					AFI_IP6, type, 0, vrf_id);
}

void ospf6_zebra_no_redistribute(int type, vrf_id_t vrf_id)
{
	if (!vrf_bitmap_check(&zclient->redist[AFI_IP6][type], vrf_id))
		return;
	vrf_bitmap_unset(&zclient->redist[AFI_IP6][type], vrf_id);
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, type, 0, vrf_id);
}

void ospf6_zebra_import_default_route(struct ospf6 *ospf6, bool unreg)
{
	struct prefix prefix = {};
	int command;

	if (zclient->sock < 0) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  Not connected to Zebra");
		return;
	}

	prefix.family = AF_INET6;
	prefix.prefixlen = 0;

	if (unreg)
		command = ZEBRA_NEXTHOP_UNREGISTER;
	else
		command = ZEBRA_NEXTHOP_REGISTER;

	if (IS_OSPF6_DEBUG_ZEBRA(SEND))
		zlog_debug("%s: sending cmd %s for %pFX (vrf %u)", __func__,
			   zserv_command_string(command), &prefix,
			   ospf6->vrf_id);

	if (zclient_send_rnh(zclient, command, &prefix, SAFI_UNICAST, false,
			     true, ospf6->vrf_id)
	    == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET, "%s: zclient_send_rnh() failed",
			 __func__);
}

static void ospf6_zebra_import_check_update(struct vrf *vrf,
					    struct prefix *matched,
					    struct zapi_route *nhr)
{
	struct ospf6 *ospf6;

	ospf6 = (struct ospf6 *)vrf->info;
	if (ospf6 == NULL || !IS_OSPF6_ASBR(ospf6))
		return;

	if (matched->family != AF_INET6 || matched->prefixlen != 0 ||
	    nhr->type == ZEBRA_ROUTE_OSPF6)
		return;

	ospf6->nssa_default_import_check.status = !!nhr->nexthop_num;
	ospf6_abr_nssa_type_7_defaults(ospf6);
}

static int ospf6_zebra_if_address_update_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);
	if (c == NULL)
		return 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface address add: %s %5s %pFX",
			   c->ifp->name, prefix_family_str(c->address),
			   c->address);

	if (c->address->family == AF_INET6) {
		ospf6_interface_state_update(c->ifp);
		ospf6_interface_connected_route_update(c->ifp);
	}
	return 0;
}

static int ospf6_zebra_if_address_update_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);
	if (c == NULL)
		return 0;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug("Zebra Interface address delete: %s %5s %pFX",
			   c->ifp->name, prefix_family_str(c->address),
			   c->address);

	if (c->address->family == AF_INET6) {
		ospf6_interface_connected_route_update(c->ifp);
		ospf6_interface_state_update(c->ifp);
	}

	connected_free(&c);

	return 0;
}

static int ospf6_zebra_gr_update(struct ospf6 *ospf6, int command,
				 uint32_t stale_time)
{
	struct zapi_cap api;

	if (!zclient || zclient->sock < 0 || !ospf6)
		return 1;

	memset(&api, 0, sizeof(api));
	api.cap = command;
	api.stale_removal_time = stale_time;
	api.vrf_id = ospf6->vrf_id;

	(void)zclient_capabilities_send(ZEBRA_CLIENT_CAPABILITIES, zclient,
					&api);

	return 0;
}

int ospf6_zebra_gr_enable(struct ospf6 *ospf6, uint32_t stale_time)
{
	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("Zebra enable GR [stale time %u]", stale_time);

	return ospf6_zebra_gr_update(ospf6, ZEBRA_CLIENT_GR_CAPABILITIES,
				     stale_time);
}

int ospf6_zebra_gr_disable(struct ospf6 *ospf6)
{
	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("Zebra disable GR");

	return ospf6_zebra_gr_update(ospf6, ZEBRA_CLIENT_GR_DISABLE, 0);
}

static int ospf6_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;
	unsigned long ifindex;
	const struct in6_addr *nexthop = &in6addr_any;
	struct ospf6 *ospf6;
	struct prefix_ipv6 p;

	ospf6 = ospf6_lookup_by_vrf_id(vrf_id);

	if (ospf6 == NULL)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	if (IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;

	ifindex = api.nexthops[0].ifindex;
	if (api.nexthops[0].type == NEXTHOP_TYPE_IPV6
	    || api.nexthops[0].type == NEXTHOP_TYPE_IPV6_IFINDEX)
		nexthop = &api.nexthops[0].gate.ipv6;

	if (IS_OSPF6_DEBUG_ZEBRA(RECV))
		zlog_debug(
			"Zebra Receive route %s: %s %pFX nexthop %pI6 ifindex %ld tag %" ROUTE_TAG_PRI,
			(cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD ? "add"
							     : "delete"),
			zebra_route_string(api.type), &api.prefix, nexthop,
			ifindex, api.tag);

	memcpy(&p, &api.prefix, sizeof(p));
	if (is_default_prefix6(&p))
		api.type = DEFAULT_ROUTE;

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		ospf6_asbr_redistribute_add(api.type, ifindex, &api.prefix,
					    api.nexthop_num, nexthop, api.tag,
					    ospf6, api.metric);
	else
		ospf6_asbr_redistribute_remove(api.type, ifindex, &api.prefix,
					       ospf6);

	return 0;
}

DEFUN(show_zebra,
      show_ospf6_zebra_cmd,
      "show ipv6 ospf6 zebra [json]",
      SHOW_STR
      IPV6_STR
      OSPF6_STR
      ZEBRA_STR
      JSON_STR)
{
	int i;
	bool uj = use_json(argc, argv);
	json_object *json;
	json_object *json_zebra;
	json_object *json_array;

	if (zclient == NULL) {
		vty_out(vty, "Not connected to zebra\n");
		return CMD_SUCCESS;
	}

	if (uj) {
		json = json_object_new_object();
		json_zebra = json_object_new_object();
		json_array = json_object_new_array();

		json_object_int_add(json_zebra, "fail", zclient->fail);
		json_object_int_add(
			json_zebra, "redistributeDefault",
			vrf_bitmap_check(&zclient->default_information[AFI_IP6],
					 VRF_DEFAULT));
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			if (vrf_bitmap_check(&zclient->redist[AFI_IP6][i],
					     VRF_DEFAULT))
				json_object_array_add(
					json_array,
					json_object_new_string(
						zebra_route_string(i)));
		}
		json_object_object_add(json_zebra, "redistribute", json_array);
		json_object_object_add(json, "zebraInformation", json_zebra);

		vty_json(vty, json);
	} else {
		vty_out(vty, "Zebra Information\n");
		vty_out(vty, "  fail: %d\n", zclient->fail);
		vty_out(vty, "  redistribute default: %d\n",
			vrf_bitmap_check(&zclient->default_information[AFI_IP6],
					 VRF_DEFAULT));
		vty_out(vty, "  redistribute:");
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			if (vrf_bitmap_check(&zclient->redist[AFI_IP6][i],
					     VRF_DEFAULT))
				vty_out(vty, " %s", zebra_route_string(i));
		}
		vty_out(vty, "\n");
	}
	return CMD_SUCCESS;
}

static void ospf6_zebra_append_opaque_attr(struct ospf6_route *request,
					   struct zapi_route *api)
{
	struct ospf_zebra_opaque ospf_opaque = {};

	/* OSPF path type */
	snprintf(ospf_opaque.path_type, sizeof(ospf_opaque.path_type), "%s",
		 OSPF6_PATH_TYPE_NAME(request->path.type));

	switch (request->path.type) {
	case OSPF6_PATH_TYPE_INTRA:
	case OSPF6_PATH_TYPE_INTER:
		/* OSPF area ID */
		(void)inet_ntop(AF_INET, &request->path.area_id,
				ospf_opaque.area_id,
				sizeof(ospf_opaque.area_id));
		break;
	case OSPF6_PATH_TYPE_EXTERNAL1:
	case OSPF6_PATH_TYPE_EXTERNAL2:
		/* OSPF route tag */
		snprintf(ospf_opaque.tag, sizeof(ospf_opaque.tag), "%u",
			 request->path.tag);
		break;
	default:
		break;
	}

	SET_FLAG(api->message, ZAPI_MESSAGE_OPAQUE);
	api->opaque.length = sizeof(struct ospf_zebra_opaque);
	memcpy(api->opaque.data, &ospf_opaque, api->opaque.length);
}

#define ADD    0
#define REM    1
static void ospf6_zebra_route_update(int type, struct ospf6_route *request,
				     struct ospf6 *ospf6)
{
	struct zapi_route api;
	int nhcount;
	int ret = 0;
	struct prefix *dest;

	if (IS_OSPF6_DEBUG_ZEBRA(SEND))
		zlog_debug("Zebra Send %s route: %pFX",
			   (type == REM ? "remove" : "add"), &request->prefix);

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
	 * treat this request as add the secondary path - if there are
	 * nexthops.
	 */
	if (type == REM && ospf6_route_is_best(request) && request->next &&
	    ospf6_route_is_same(request, request->next) &&
	    ospf6_route_num_nexthops(request->next) > 0) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug(
				"  Best-path removal resulted Secondary addition");
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
		if (type == ADD) {
			if (IS_OSPF6_DEBUG_ZEBRA(SEND))
				zlog_debug("  No nexthop, ignore");
			return;
		} else if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("  No nexthop, rem ok");
	}

	dest = &request->prefix;

	memset(&api, 0, sizeof(api));
	api.vrf_id = ospf6->vrf_id;
	api.type = ZEBRA_ROUTE_OSPF6;
	api.safi = SAFI_UNICAST;
	api.prefix = *dest;

	if (nhcount > ospf6->max_multipath) {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug(
				"  Nexthop count is greater than configured maximum-path, hence ignore the extra nexthops");
	}

	api.nexthop_num = MIN(nhcount, ospf6->max_multipath);
	if (api.nexthop_num > 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		ospf6_route_zebra_copy_nexthops(request, api.nexthops,
						api.nexthop_num, api.vrf_id);
	}

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = (request->path.metric_type == 2 ? request->path.u.cost_e2
						     : request->path.cost);
	if (request->path.tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = request->path.tag;
	}

	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	api.distance = ospf6_distance_apply((struct prefix_ipv6 *)dest, request,
					    ospf6);

	if (type == ADD
	    && CHECK_FLAG(ospf6->config_flags, OSPF6_SEND_EXTRA_DATA_TO_ZEBRA))
		ospf6_zebra_append_opaque_attr(request, &api);

	if (type == REM)
		ret = zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
	else
		ret = zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);

	if (ret == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "zclient_route_send() %s failed: %s",
			 (type == REM ? "delete" : "add"),
			 safe_strerror(errno));

	return;
}

void ospf6_zebra_route_update_add(struct ospf6_route *request,
				  struct ospf6 *ospf6)
{
	if (ospf6->gr_info.restart_in_progress
	    || ospf6->gr_info.prepare_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Zebra: Graceful Restart in progress -- not installing %pFX",
				&request->prefix);
		return;
	}

	ospf6_zebra_route_update(ADD, request, ospf6);
}

void ospf6_zebra_route_update_remove(struct ospf6_route *request,
				     struct ospf6 *ospf6)
{
	if (ospf6->gr_info.restart_in_progress
	    || ospf6->gr_info.prepare_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Zebra: Graceful Restart in progress -- not uninstalling %pFX",
				&request->prefix);
		return;
	}

	ospf6_zebra_route_update(REM, request, ospf6);
}

void ospf6_zebra_add_discard(struct ospf6_route *request, struct ospf6 *ospf6)
{
	struct zapi_route api;
	struct prefix *dest = &request->prefix;

	if (ospf6->gr_info.restart_in_progress
	    || ospf6->gr_info.prepare_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Zebra: Graceful Restart in progress -- not installing %pFX",
				&request->prefix);
		return;
	}

	if (!CHECK_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED)) {
		memset(&api, 0, sizeof(api));
		api.vrf_id = ospf6->vrf_id;
		api.type = ZEBRA_ROUTE_OSPF6;
		api.safi = SAFI_UNICAST;
		api.prefix = *dest;
		zapi_route_set_blackhole(&api, BLACKHOLE_NULL);

		zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);

		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("Zebra: Route add discard %pFX", dest);

		SET_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED);
	} else {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug(
				"Zebra: Blackhole route present already %pFX",
				dest);
	}
}

void ospf6_zebra_delete_discard(struct ospf6_route *request,
				struct ospf6 *ospf6)
{
	struct zapi_route api;
	struct prefix *dest = &request->prefix;

	if (ospf6->gr_info.restart_in_progress
	    || ospf6->gr_info.prepare_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Zebra: Graceful Restart in progress -- not uninstalling %pFX",
				&request->prefix);
		return;
	}

	if (CHECK_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED)) {
		memset(&api, 0, sizeof(api));
		api.vrf_id = ospf6->vrf_id;
		api.type = ZEBRA_ROUTE_OSPF6;
		api.safi = SAFI_UNICAST;
		api.prefix = *dest;
		zapi_route_set_blackhole(&api, BLACKHOLE_NULL);

		zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug("Zebra: Route delete discard %pFX", dest);

		UNSET_FLAG(request->flag, OSPF6_ROUTE_BLACKHOLE_ADDED);
	} else {
		if (IS_OSPF6_DEBUG_ZEBRA(SEND))
			zlog_debug(
				"Zebra: Blackhole route already deleted %pFX",
				dest);
	}
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
	uint8_t distance;
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

uint8_t ospf6_distance_apply(struct prefix_ipv6 *p, struct ospf6_route * or,
			     struct ospf6 *ospf6)
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
	struct ospf6 *ospf6;
	struct listnode *node;

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);

	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	/* Activate graceful restart if configured. */
	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (!ospf6->gr_info.restart_support)
			continue;
		(void)ospf6_zebra_gr_enable(ospf6, ospf6->gr_info.grace_period);
	}
}

static zclient_handler *const ospf6_handlers[] = {
	[ZEBRA_ROUTER_ID_UPDATE] = ospf6_router_id_update_zebra,
	[ZEBRA_INTERFACE_ADDRESS_ADD] = ospf6_zebra_if_address_update_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = ospf6_zebra_if_address_update_delete,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = ospf6_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = ospf6_zebra_read_route,
};

void ospf6_zebra_init(struct event_loop *master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master, &zclient_options_default, ospf6_handlers,
			      array_size(ospf6_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_OSPF6, 0, &ospf6d_privs);
	zclient->zebra_connected = ospf6_zebra_connected;
	zclient->nexthop_update = ospf6_zebra_import_check_update;

	/* Install command element for zebra node. */
	install_element(VIEW_NODE, &show_ospf6_zebra_cmd);
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
