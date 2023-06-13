// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPngd and zebra interface.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
static void ripng_zebra_ipv6_send(struct ripng *ripng, struct agg_node *rp,
				  uint8_t cmd)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct ripng_info *rinfo = NULL;
	uint32_t count = 0;
	const struct prefix *p = agg_node_get_prefix(rp);

	memset(&api, 0, sizeof(api));
	api.vrf_id = ripng->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_RIPNG;
	api.safi = SAFI_UNICAST;
	api.prefix = *p;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= zebra_ecmp_count)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = ripng->vrf->vrf_id;
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
			zlog_debug("%s: %pRN nexthops %d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   rp, count);
		else
			zlog_debug("%s: %pRN",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   rp);
	}
}

/* Add/update ECMP routes to zebra. */
void ripng_zebra_ipv6_add(struct ripng *ripng, struct agg_node *rp)
{
	ripng_zebra_ipv6_send(ripng, rp, ZEBRA_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void ripng_zebra_ipv6_delete(struct ripng *ripng, struct agg_node *rp)
{
	ripng_zebra_ipv6_send(ripng, rp, ZEBRA_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int ripng_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct ripng *ripng;
	struct zapi_route api;
	struct in6_addr nexthop;
	unsigned long ifindex;

	ripng = ripng_lookup_by_vrf_id(vrf_id);
	if (!ripng)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	/* we completely ignore srcdest routes for now. */
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;

	if (IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;

	nexthop = api.nexthops[0].gate.ipv6;
	ifindex = api.nexthops[0].ifindex;

	if (cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		ripng_redistribute_add(ripng, api.type,
				       RIPNG_ROUTE_REDISTRIBUTE,
				       (struct prefix_ipv6 *)&api.prefix,
				       ifindex, &nexthop, api.tag);
	else
		ripng_redistribute_delete(
			ripng, api.type, RIPNG_ROUTE_REDISTRIBUTE,
			(struct prefix_ipv6 *)&api.prefix, ifindex);

	return 0;
}

void ripng_redistribute_conf_update(struct ripng *ripng, int type)
{
	zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6,
				type, 0, ripng->vrf->vrf_id);
}

void ripng_redistribute_conf_delete(struct ripng *ripng, int type)
{
	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, type, 0, ripng->vrf->vrf_id);

	ripng_redistribute_withdraw(ripng, type);
}

int ripng_redistribute_check(struct ripng *ripng, int type)
{
	return ripng->redist[type].enabled;
}

void ripng_redistribute_enable(struct ripng *ripng)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!ripng_redistribute_check(ripng, i))
			continue;

		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_ADD, zclient,
					AFI_IP6, i, 0, ripng->vrf->vrf_id);
	}
}

void ripng_redistribute_disable(struct ripng *ripng)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (!ripng_redistribute_check(ripng, i))
			continue;

		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP6, i, 0, ripng->vrf->vrf_id);
	}
}

void ripng_redistribute_write(struct vty *vty, struct ripng *ripng)
{
	int i;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i == zclient->redist_default
		    || !ripng_redistribute_check(ripng, i))
			continue;

		vty_out(vty, "    %s", zebra_route_string(i));
	}
}

void ripng_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: register VRF %s(%u) to zebra", __func__,
			   vrf->name, vrf->vrf_id);

	zclient_send_reg_requests(zclient, vrf->vrf_id);
}

void ripng_zebra_vrf_deregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: deregister VRF %s(%u) from zebra.", __func__,
			   vrf->name, vrf->vrf_id);

	zclient_send_dereg_requests(zclient, vrf->vrf_id);
}

static void ripng_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

static zclient_handler *const ripng_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = ripng_interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = ripng_interface_address_delete,
	[ZEBRA_INTERFACE_VRF_UPDATE] = ripng_interface_vrf_update,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = ripng_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = ripng_zebra_read_route,
};

static void ripng_zebra_capabilities(struct zclient_capabilities *cap)
{
	zebra_ecmp_count = MIN(cap->ecmp, zebra_ecmp_count);
}

/* Initialize zebra structure and it's commands. */
void zebra_init(struct event_loop *master)
{
	/* Allocate zebra structure. */
	zclient = zclient_new(master, &zclient_options_default, ripng_handlers,
			      array_size(ripng_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_RIPNG, 0, &ripngd_privs);

	zclient->zebra_connected = ripng_zebra_connected;
	zclient->zebra_capabilities = ripng_zebra_capabilities;
}

void ripng_zebra_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
