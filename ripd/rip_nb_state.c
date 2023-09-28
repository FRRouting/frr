// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "routemap.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/*
 * XPath: /frr-ripd:ripd/instance
 */
const void *ripd_instance_get_next(struct nb_cb_get_next_args *args)
{
	struct rip *rip = (struct rip *)args->list_entry;

	if (args->list_entry == NULL)
		rip = RB_MIN(rip_instance_head, &rip_instances);
	else
		rip = RB_NEXT(rip_instance_head, rip);

	return rip;
}

int ripd_instance_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct rip *rip = args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], rip->vrf_name, sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripd_instance_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrf_name = args->keys->key[0];

	return rip_lookup_by_vrf_name(vrf_name);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor
 */
const void *ripd_instance_state_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct rip *rip = args->parent_list_entry;
	struct listnode *node;

	if (args->list_entry == NULL)
		node = listhead(rip->peer_list);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

int ripd_instance_state_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct rip_peer *peer = listgetdata(node);

	args->keys->num = 1;
	(void)inet_ntop(AF_INET, &peer->addr, args->keys->key[0],
			sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripd_instance_state_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct rip *rip = args->parent_list_entry;
	struct in_addr address;
	struct rip_peer *peer;
	struct listnode *node;

	yang_str2ipv4(args->keys->key[0], &address);

	for (ALL_LIST_ELEMENTS_RO(rip->peer_list, node, peer)) {
		if (IPV4_ADDR_SAME(&peer->addr, &address))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/address
 */
struct yang_data *ripd_instance_state_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_ipv4(args->xpath, &peer->addr);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/last-update
 */
struct yang_data *ripd_instance_state_neighbors_neighbor_last_update_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: yang:date-and-time is tricky */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/bad-packets-rcvd
 */
struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_uint32(args->xpath, peer->recv_badpackets);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/bad-routes-rcvd
 */
struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_uint32(args->xpath, peer->recv_badroutes);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route
 */
const void *
ripd_instance_state_routes_route_get_next(struct nb_cb_get_next_args *args)
{
	const struct rip *rip = args->parent_list_entry;
	struct route_node *rn;

	if (args->list_entry == NULL)
		rn = route_top(rip->table);
	else
		rn = route_next((struct route_node *)args->list_entry);
	/* Optimization: skip empty route nodes. */
	while (rn && rn->info == NULL)
		rn = route_next(rn);

	return rn;
}

int ripd_instance_state_routes_route_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct route_node *rn = args->list_entry;

	args->keys->num = 1;
	(void)prefix2str(&rn->p, args->keys->key[0],
			 sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripd_instance_state_routes_route_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct rip *rip = args->parent_list_entry;
	struct prefix prefix;
	struct route_node *rn;

	yang_str2ipv4p(args->keys->key[0], &prefix);

	rn = route_node_lookup(rip->table, &prefix);
	if (!rn || !rn->info)
		return NULL;

	route_unlock_node(rn);

	return rn;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/prefix
 */
struct yang_data *ripd_instance_state_routes_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct route_node *rn = args->list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	assert(rinfo);
	return yang_data_new_ipv4p(args->xpath, &rinfo->rp->p);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop
 */
const void *ripd_instance_state_routes_route_nexthops_nexthop_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct route_node *rn = args->parent_list_entry;
	const struct listnode *node = args->list_entry;

	assert(rn);
	if (node)
		return listnextnode(node);
	assert(rn->info);
	return listhead((struct list *)rn->info);
}

static inline const struct rip_info *get_rip_info(const void *info)
{
	return (const struct rip_info *)listgetdata(
		(const struct listnode *)info);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/nh-type
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_nh_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	assert(rinfo);
	return yang_data_new_enum(args->xpath, rinfo->nh.type);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/protocol
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_protocol_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	assert(rinfo);
	return yang_data_new_enum(args->xpath, rinfo->type);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/rip-type
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_rip_type_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	assert(rinfo);
	return yang_data_new_enum(args->xpath, rinfo->sub_type);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/gateway
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_gateway_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	if (rinfo->nh.type != NEXTHOP_TYPE_IPV4 &&
	    rinfo->nh.type != NEXTHOP_TYPE_IPV4_IFINDEX)
		return NULL;

	return yang_data_new_ipv4(args->xpath, &rinfo->nh.gate.ipv4);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/interface
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);
	const struct rip *rip = rip_info_get_instance(rinfo);

	if (rinfo->nh.type != NEXTHOP_TYPE_IFINDEX &&
	    rinfo->nh.type != NEXTHOP_TYPE_IPV4_IFINDEX)
		return NULL;

	return yang_data_new_string(
		args->xpath,
		ifindex2ifname(rinfo->nh.ifindex, rip->vrf->vrf_id));
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/from
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_from_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	if (rinfo->type != ZEBRA_ROUTE_RIP || rinfo->sub_type != RIP_ROUTE_RTE)
		return NULL;

	return yang_data_new_ipv4(args->xpath, &rinfo->from);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/tag
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_tag_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	return yang_data_new_uint32(args->xpath, rinfo->tag);
}

/*
 * XPath:
 * /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/external-metric
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_external_metric_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);

	if ((rinfo->type == ZEBRA_ROUTE_RIP &&
	     rinfo->sub_type == RIP_ROUTE_RTE) ||
	    rinfo->metric == RIP_METRIC_INFINITY || rinfo->external_metric == 0)
		return NULL;
	return yang_data_new_uint32(args->xpath, rinfo->external_metric);
}

/*
 * XPath:
 * /frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/expire-time
 */
struct yang_data *
ripd_instance_state_routes_route_nexthops_nexthop_expire_time_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct rip_info *rinfo = get_rip_info(args->list_entry);
	struct event *event;

	if ((event = rinfo->t_timeout) == NULL)
		event = rinfo->t_garbage_collect;
	if (!event)
		return NULL;

	return yang_data_new_uint32(args->xpath,
				    event_timer_remain_second(event));
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/next-hop
 */
struct yang_data *ripd_instance_state_routes_route_next_hop_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct route_node *rn = args->list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	switch (rinfo->nh.type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return yang_data_new_ipv4(args->xpath, &rinfo->nh.gate.ipv4);
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return NULL;
	}

	assert(!"Reached end of function where we do not expect to reach");
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/interface
 */
struct yang_data *ripd_instance_state_routes_route_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct route_node *rn = args->list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);
	const struct rip *rip = rip_info_get_instance(rinfo);

	switch (rinfo->nh.type) {
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return yang_data_new_string(
			args->xpath,
			ifindex2ifname(rinfo->nh.ifindex, rip->vrf->vrf_id));
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return NULL;
	}

	assert(!"Reached end of function where we do not expect to reach");
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/metric
 */
struct yang_data *ripd_instance_state_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct route_node *rn = args->list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	return yang_data_new_uint8(args->xpath, rinfo->metric);
}
