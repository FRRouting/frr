/*
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "routemap.h"
#include "agg_table.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"
#include "ripngd/ripng_debug.h"
#include "ripngd/ripng_route.h"

/*
 * XPath: /frr-ripngd:ripngd/instance/state/neighbors/neighbor
 */
const void *ripngd_instance_state_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct ripng *ripng = args->parent_list_entry;
	struct listnode *node;

	if (args->list_entry == NULL)
		node = listhead(ripng->peer_list);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

int ripngd_instance_state_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	args->keys->num = 1;
	(void)inet_ntop(AF_INET6, &peer->addr, args->keys->key[0],
			sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripngd_instance_state_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct ripng *ripng = args->parent_list_entry;
	struct in6_addr address;
	struct ripng_peer *peer;
	struct listnode *node;

	yang_str2ipv6(args->keys->key[0], &address);

	for (ALL_LIST_ELEMENTS_RO(ripng->peer_list, node, peer)) {
		if (IPV6_ADDR_SAME(&peer->addr, &address))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/neighbors/neighbor/address
 */
struct yang_data *ripngd_instance_state_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_ipv6(args->xpath, &peer->addr);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/neighbors/neighbor/last-update
 */
struct yang_data *ripngd_instance_state_neighbors_neighbor_last_update_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: yang:date-and-time is tricky */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/neighbors/neighbor/bad-packets-rcvd
 */
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_uint32(args->xpath, peer->recv_badpackets);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/neighbors/neighbor/bad-routes-rcvd
 */
struct yang_data *
ripngd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_uint32(args->xpath, peer->recv_badroutes);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/routes/route
 */
const void *
ripngd_instance_state_routes_route_get_next(struct nb_cb_get_next_args *args)
{
	const struct ripng *ripng = args->parent_list_entry;
	struct agg_node *rn;

	if (args->list_entry == NULL)
		rn = agg_route_top(ripng->table);
	else
		rn = agg_route_next((struct agg_node *)args->list_entry);
	/* Optimization: skip empty route nodes. */
	while (rn && rn->info == NULL)
		rn = agg_route_next(rn);

	return rn;
}

int ripngd_instance_state_routes_route_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct agg_node *rn = args->list_entry;

	args->keys->num = 1;
	(void)prefix2str(agg_node_get_prefix(rn), args->keys->key[0],
			 sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripngd_instance_state_routes_route_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct ripng *ripng = args->parent_list_entry;
	struct prefix prefix;
	struct agg_node *rn;

	yang_str2ipv6p(args->keys->key[0], &prefix);

	rn = agg_node_lookup(ripng->table, &prefix);
	if (!rn || !rn->info)
		return NULL;

	agg_unlock_node(rn);

	return rn;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/routes/route/prefix
 */
struct yang_data *ripngd_instance_state_routes_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct agg_node *rn = args->list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_ipv6p(args->xpath, agg_node_get_prefix(rinfo->rp));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/routes/route/next-hop
 */
struct yang_data *ripngd_instance_state_routes_route_next_hop_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct agg_node *rn = args->list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_ipv6(args->xpath, &rinfo->nexthop);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/routes/route/interface
 */
struct yang_data *ripngd_instance_state_routes_route_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct agg_node *rn = args->list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);
	const struct ripng *ripng = ripng_info_get_instance(rinfo);

	return yang_data_new_string(
		args->xpath,
		ifindex2ifname(rinfo->ifindex, ripng->vrf->vrf_id));
}

/*
 * XPath: /frr-ripngd:ripngd/instance/state/routes/route/metric
 */
struct yang_data *ripngd_instance_state_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct agg_node *rn = args->list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_uint8(args->xpath, rinfo->metric);
}
