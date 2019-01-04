/*
 * Copyright (C) 1998 Kunihiro Ishiguro
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
#include "ripngd/ripng_route.h"
#include "ripngd/ripng_cli.h"

/*
 * XPath: /frr-ripngd:ripngd/instance
 */
static int ripngd_instance_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	int socket;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		socket = ripng_make_socket();
		if (socket < 0)
			return NB_ERR_RESOURCE;
		resource->fd = socket;
		break;
	case NB_EV_ABORT:
		socket = resource->fd;
		close(socket);
		break;
	case NB_EV_APPLY:
		socket = resource->fd;
		ripng_create(socket);
		break;
	}

	return NB_OK;
}

static int ripngd_instance_delete(enum nb_event event,
				  const struct lyd_node *dnode)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng_clean();

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/allow-ecmp
 */
static int ripngd_instance_allow_ecmp_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng->ecmp = yang_dnode_get_bool(dnode, NULL);
	if (!ripng->ecmp)
		ripng_ecmp_disable();

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
static int ripngd_instance_default_information_originate_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	bool default_information;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	default_information = yang_dnode_get_bool(dnode, NULL);
	str2prefix_ipv6("::/0", &p);
	if (default_information) {
		ripng_redistribute_add(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_DEFAULT,
				       &p, 0, NULL, 0);
	} else {
		ripng_redistribute_delete(ZEBRA_ROUTE_RIPNG,
					  RIPNG_ROUTE_DEFAULT, &p, 0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-metric
 */
static int ripngd_instance_default_metric_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng->default_metric = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
static int ripngd_instance_network_create(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_add(&p);
}

static int ripngd_instance_network_delete(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_delete(&p);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
static int ripngd_instance_interface_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_enable_if_add(ifname);
}

static int ripngd_instance_interface_delete(enum nb_event event,
					    const struct lyd_node *dnode)
{
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_enable_if_delete(ifname);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
static int ripngd_instance_offset_list_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	const char *ifname;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifname = yang_dnode_get_string(dnode, "./interface");

	offset = ripng_offset_list_new(ifname);
	yang_dnode_set_entry(dnode, offset);

	return NB_OK;
}

static int ripngd_instance_offset_list_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	int direct;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "./direction");

	offset = yang_dnode_get_entry(dnode, true);
	if (offset->direct[direct].alist_name) {
		free(offset->direct[direct].alist_name);
		offset->direct[direct].alist_name = NULL;
	}
	if (offset->direct[RIPNG_OFFSET_LIST_IN].alist_name == NULL
	    && offset->direct[RIPNG_OFFSET_LIST_OUT].alist_name == NULL)
		ripng_offset_list_del(offset);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list/access-list
 */
static int
ripngd_instance_offset_list_access_list_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	int direct;
	struct ripng_offset_list *offset;
	const char *alist_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "../direction");
	alist_name = yang_dnode_get_string(dnode, NULL);

	offset = yang_dnode_get_entry(dnode, true);
	if (offset->direct[direct].alist_name)
		free(offset->direct[direct].alist_name);
	offset->direct[direct].alist_name = strdup(alist_name);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list/metric
 */
static int
ripngd_instance_offset_list_metric_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	int direct;
	uint8_t metric;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "../direction");
	metric = yang_dnode_get_uint8(dnode, NULL);

	offset = yang_dnode_get_entry(dnode, true);
	offset->direct[direct].metric = metric;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/passive-interface
 */
static int
ripngd_instance_passive_interface_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_passive_interface_set(ifname);
}

static int
ripngd_instance_passive_interface_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_passive_interface_unset(ifname);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
static int ripngd_instance_redistribute_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	return NB_OK;
}

static int ripngd_instance_redistribute_delete(enum nb_event event,
					       const struct lyd_node *dnode)
{
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "./protocol");

	ripng_redistribute_conf_delete(type);

	return NB_OK;
}

static void
ripngd_instance_redistribute_apply_finish(const struct lyd_node *dnode)
{
	int type;

	type = yang_dnode_get_enum(dnode, "./protocol");
	ripng_redistribute_conf_update(type);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/route-map
 */
static int
ripngd_instance_redistribute_route_map_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	int type;
	const char *rmap_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "../protocol");
	rmap_name = yang_dnode_get_string(dnode, NULL);

	if (ripng->route_map[type].name)
		free(ripng->route_map[type].name);
	ripng->route_map[type].name = strdup(rmap_name);
	ripng->route_map[type].map = route_map_lookup_by_name(rmap_name);

	return NB_OK;
}

static int
ripngd_instance_redistribute_route_map_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "../protocol");

	free(ripng->route_map[type].name);
	ripng->route_map[type].name = NULL;
	ripng->route_map[type].map = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/metric
 */
static int
ripngd_instance_redistribute_metric_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	int type;
	uint8_t metric;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "../protocol");
	metric = yang_dnode_get_uint8(dnode, NULL);

	ripng->route_map[type].metric_config = true;
	ripng->route_map[type].metric = metric;

	return NB_OK;
}

static int
ripngd_instance_redistribute_metric_delete(enum nb_event event,
					   const struct lyd_node *dnode)
{
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_enum(dnode, "../protocol");

	ripng->route_map[type].metric_config = false;
	ripng->route_map[type].metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
static int ripngd_instance_static_route_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_add(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0,
			       NULL, 0);

	return NB_OK;
}

static int ripngd_instance_static_route_delete(enum nb_event event,
					       const struct lyd_node *dnode)
{
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_delete(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/aggregate-address
 */
static int
ripngd_instance_aggregate_address_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_add((struct prefix *)&p);

	return NB_OK;
}

static int
ripngd_instance_aggregate_address_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_delete((struct prefix *)&p);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers
 */
static void ripngd_instance_timers_apply_finish(const struct lyd_node *dnode)
{
	/* Reset update timer thread. */
	ripng_event(RIPNG_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/flush-interval
 */
static int
ripngd_instance_timers_flush_interval_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng->garbage_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/holddown-interval
 */
static int
ripngd_instance_timers_holddown_interval_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng->timeout_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/update-interval
 */
static int
ripngd_instance_timers_update_interval_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng->update_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor
 */
static const void *
ripngd_state_neighbors_neighbor_get_next(const void *parent_list_entry,
					 const void *list_entry)
{
	struct listnode *node;

	if (!ripng)
		return NULL;

	if (list_entry == NULL)
		node = listhead(ripng->peer_list);
	else
		node = listnextnode((struct listnode *)list_entry);

	return node;
}

static int ripngd_state_neighbors_neighbor_get_keys(const void *list_entry,
						    struct yang_list_keys *keys)
{
	const struct listnode *node = list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	keys->num = 1;
	(void)inet_ntop(AF_INET6, &peer->addr, keys->key[0],
			sizeof(keys->key[0]));

	return NB_OK;
}

static const void *
ripngd_state_neighbors_neighbor_lookup_entry(const void *parent_list_entry,
					     const struct yang_list_keys *keys)
{
	struct in6_addr address;
	struct ripng_peer *peer;
	struct listnode *node;

	yang_str2ipv6(keys->key[0], &address);

	if (!ripng)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(ripng->peer_list, node, peer)) {
		if (IPV6_ADDR_SAME(&peer->addr, &address))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/address
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_address_get_elem(const char *xpath,
						 const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_ipv6(xpath, &peer->addr);
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/last-update
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_last_update_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: yang:date-and-time is tricky */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/bad-packets-rcvd
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_uint32(xpath, peer->recv_badpackets);
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/bad-routes-rcvd
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_bad_routes_rcvd_get_elem(const char *xpath,
							 const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct ripng_peer *peer = listgetdata(node);

	return yang_data_new_uint32(xpath, peer->recv_badroutes);
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route
 */
static const void *
ripngd_state_routes_route_get_next(const void *parent_list_entry,
				   const void *list_entry)
{
	struct agg_node *rn;

	if (ripng == NULL)
		return NULL;

	if (list_entry == NULL)
		rn = agg_route_top(ripng->table);
	else
		rn = agg_route_next((struct agg_node *)list_entry);
	while (rn && rn->info == NULL)
		rn = agg_route_next(rn);

	return rn;
}

static int ripngd_state_routes_route_get_keys(const void *list_entry,
					      struct yang_list_keys *keys)
{
	const struct agg_node *rn = list_entry;

	keys->num = 1;
	(void)prefix2str(&rn->p, keys->key[0], sizeof(keys->key[0]));

	return NB_OK;
}

static const void *
ripngd_state_routes_route_lookup_entry(const void *parent_list_entry,
				       const struct yang_list_keys *keys)
{
	struct prefix prefix;
	struct agg_node *rn;

	yang_str2ipv6p(keys->key[0], &prefix);

	rn = agg_node_lookup(ripng->table, &prefix);
	if (!rn || !rn->info)
		return NULL;

	agg_unlock_node(rn);

	return rn;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/prefix
 */
static struct yang_data *
ripngd_state_routes_route_prefix_get_elem(const char *xpath,
					  const void *list_entry)
{
	const struct agg_node *rn = list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_ipv6p(xpath, &rinfo->rp->p);
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/next-hop
 */
static struct yang_data *
ripngd_state_routes_route_next_hop_get_elem(const char *xpath,
					    const void *list_entry)
{
	const struct agg_node *rn = list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_ipv6(xpath, &rinfo->nexthop);
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/interface
 */
static struct yang_data *
ripngd_state_routes_route_interface_get_elem(const char *xpath,
					     const void *list_entry)
{
	const struct agg_node *rn = list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_string(
		xpath, ifindex2ifname(rinfo->ifindex, VRF_DEFAULT));
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/metric
 */
static struct yang_data *
ripngd_state_routes_route_metric_get_elem(const char *xpath,
					  const void *list_entry)
{
	const struct agg_node *rn = list_entry;
	const struct ripng_info *rinfo = listnode_head(rn->info);

	return yang_data_new_uint8(xpath, rinfo->metric);
}

/*
 * XPath: /frr-ripngd:clear-ripng-route
 */
static int clear_ripng_route_rpc(const char *xpath, const struct list *input,
				 struct list *output)
{
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct list *list;
	struct listnode *listnode;

	if (!ripng)
		return NB_OK;

	/* Clear received RIPng routes */
	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		list = rp->info;
		if (list == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			if (!ripng_route_rte(rinfo))
				continue;

			if (CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
				ripng_zebra_ipv6_delete(rp);
			break;
		}

		if (rinfo) {
			RIPNG_TIMER_OFF(rinfo->t_timeout);
			RIPNG_TIMER_OFF(rinfo->t_garbage_collect);
			listnode_delete(list, rinfo);
			ripng_info_free(rinfo);
		}

		if (list_isempty(list)) {
			list_delete(&list);
			rp->info = NULL;
			agg_unlock_node(rp);
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripngd:ripng/split-horizon
 */
static int
lib_interface_ripng_split_horizon_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct interface *ifp;
	struct ripng_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = yang_dnode_get_entry(dnode, true);
	ri = ifp->info;
	ri->split_horizon = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_ripngd_info = {
	.name = "frr-ripngd",
	.nodes = {
		{
			.xpath = "/frr-ripngd:ripngd/instance",
			.cbs.create = ripngd_instance_create,
			.cbs.delete = ripngd_instance_delete,
			.cbs.cli_show = cli_show_router_ripng,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/allow-ecmp",
			.cbs.modify = ripngd_instance_allow_ecmp_modify,
			.cbs.cli_show = cli_show_ripng_allow_ecmp,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-information-originate",
			.cbs.modify = ripngd_instance_default_information_originate_modify,
			.cbs.cli_show = cli_show_ripng_default_information_originate,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-metric",
			.cbs.modify = ripngd_instance_default_metric_modify,
			.cbs.cli_show = cli_show_ripng_default_metric,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/network",
			.cbs.create = ripngd_instance_network_create,
			.cbs.delete = ripngd_instance_network_delete,
			.cbs.cli_show = cli_show_ripng_network_prefix,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/interface",
			.cbs.create = ripngd_instance_interface_create,
			.cbs.delete = ripngd_instance_interface_delete,
			.cbs.cli_show = cli_show_ripng_network_interface,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list",
			.cbs.create = ripngd_instance_offset_list_create,
			.cbs.delete = ripngd_instance_offset_list_delete,
			.cbs.cli_show = cli_show_ripng_offset_list,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list/access-list",
			.cbs.modify = ripngd_instance_offset_list_access_list_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list/metric",
			.cbs.modify = ripngd_instance_offset_list_metric_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/passive-interface",
			.cbs.create = ripngd_instance_passive_interface_create,
			.cbs.delete = ripngd_instance_passive_interface_delete,
			.cbs.cli_show = cli_show_ripng_passive_interface,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute",
			.cbs.create = ripngd_instance_redistribute_create,
			.cbs.delete = ripngd_instance_redistribute_delete,
			.cbs.apply_finish = ripngd_instance_redistribute_apply_finish,
			.cbs.cli_show = cli_show_ripng_redistribute,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute/route-map",
			.cbs.modify = ripngd_instance_redistribute_route_map_modify,
			.cbs.delete = ripngd_instance_redistribute_route_map_delete,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute/metric",
			.cbs.modify = ripngd_instance_redistribute_metric_modify,
			.cbs.delete = ripngd_instance_redistribute_metric_delete,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/static-route",
			.cbs.create = ripngd_instance_static_route_create,
			.cbs.delete = ripngd_instance_static_route_delete,
			.cbs.cli_show = cli_show_ripng_route,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/aggregate-address",
			.cbs.create = ripngd_instance_aggregate_address_create,
			.cbs.delete = ripngd_instance_aggregate_address_delete,
			.cbs.cli_show = cli_show_ripng_aggregate_address,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers",
			.cbs.apply_finish = ripngd_instance_timers_apply_finish,
			.cbs.cli_show = cli_show_ripng_timers,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/flush-interval",
			.cbs.modify = ripngd_instance_timers_flush_interval_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/holddown-interval",
			.cbs.modify = ripngd_instance_timers_holddown_interval_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/update-interval",
			.cbs.modify = ripngd_instance_timers_update_interval_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/neighbors/neighbor",
			.cbs.get_next = ripngd_state_neighbors_neighbor_get_next,
			.cbs.get_keys = ripngd_state_neighbors_neighbor_get_keys,
			.cbs.lookup_entry = ripngd_state_neighbors_neighbor_lookup_entry,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/neighbors/neighbor/address",
			.cbs.get_elem = ripngd_state_neighbors_neighbor_address_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/neighbors/neighbor/last-update",
			.cbs.get_elem = ripngd_state_neighbors_neighbor_last_update_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/neighbors/neighbor/bad-packets-rcvd",
			.cbs.get_elem = ripngd_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/neighbors/neighbor/bad-routes-rcvd",
			.cbs.get_elem = ripngd_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/routes/route",
			.cbs.get_next = ripngd_state_routes_route_get_next,
			.cbs.get_keys = ripngd_state_routes_route_get_keys,
			.cbs.lookup_entry = ripngd_state_routes_route_lookup_entry,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/routes/route/prefix",
			.cbs.get_elem = ripngd_state_routes_route_prefix_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/routes/route/next-hop",
			.cbs.get_elem = ripngd_state_routes_route_next_hop_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/routes/route/interface",
			.cbs.get_elem = ripngd_state_routes_route_interface_get_elem,
		},
		{
			.xpath = "/frr-ripngd:ripngd/state/routes/route/metric",
			.cbs.get_elem = ripngd_state_routes_route_metric_get_elem,
		},
		{
			.xpath = "/frr-ripngd:clear-ripng-route",
			.cbs.rpc = clear_ripng_route_rpc,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripngd:ripng/split-horizon",
			.cbs.modify = lib_interface_ripng_split_horizon_modify,
			.cbs.cli_show = cli_show_ipv6_ripng_split_horizon,
		},
		{
			.xpath = NULL,
		},
	}
};
