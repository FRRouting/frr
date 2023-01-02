/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

	return yang_data_new_ipv4p(args->xpath, &rinfo->rp->p);
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
	default:
		return NULL;
	}
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
	default:
		return NULL;
	}
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
