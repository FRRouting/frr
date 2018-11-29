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
#include "northbound.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
static int ripngd_instance_default_information_originate_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-metric
 */
static int ripngd_instance_default_metric_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
static int ripngd_instance_network_create(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripngd_instance_network_delete(enum nb_event event,
					  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
static int ripngd_instance_interface_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripngd_instance_interface_delete(enum nb_event event,
					    const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
static int ripngd_instance_offset_list_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripngd_instance_offset_list_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripngd_instance_passive_interface_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
static int ripngd_instance_redistribute_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripngd_instance_redistribute_delete(enum nb_event event,
					       const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/route-map
 */
static int
ripngd_instance_redistribute_route_map_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripngd_instance_redistribute_route_map_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripngd_instance_redistribute_metric_delete(enum nb_event event,
					   const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
static int ripngd_instance_static_route_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripngd_instance_static_route_delete(enum nb_event event,
					       const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripngd_instance_aggregate_address_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/flush-interval
 */
static int
ripngd_instance_timers_flush_interval_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor
 */
static const void *
ripngd_state_neighbors_neighbor_get_next(const void *parent_list_entry,
					 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

static int ripngd_state_neighbors_neighbor_get_keys(const void *list_entry,
						    struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *
ripngd_state_neighbors_neighbor_lookup_entry(const void *parent_list_entry,
					     const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/address
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_address_get_elem(const char *xpath,
						 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/last-update
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_last_update_get_elem(const char *xpath,
						     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/bad-packets-rcvd
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/neighbors/neighbor/bad-routes-rcvd
 */
static struct yang_data *
ripngd_state_neighbors_neighbor_bad_routes_rcvd_get_elem(const char *xpath,
							 const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route
 */
static const void *
ripngd_state_routes_route_get_next(const void *parent_list_entry,
				   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

static int ripngd_state_routes_route_get_keys(const void *list_entry,
					      struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *
ripngd_state_routes_route_lookup_entry(const void *parent_list_entry,
				       const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/prefix
 */
static struct yang_data *
ripngd_state_routes_route_prefix_get_elem(const char *xpath,
					  const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/next-hop
 */
static struct yang_data *
ripngd_state_routes_route_next_hop_get_elem(const char *xpath,
					    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/interface
 */
static struct yang_data *
ripngd_state_routes_route_interface_get_elem(const char *xpath,
					     const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:ripngd/state/routes/route/metric
 */
static struct yang_data *
ripngd_state_routes_route_metric_get_elem(const char *xpath,
					  const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripngd:clear-ripng-route
 */
static int clear_ripng_route_rpc(const char *xpath, const struct list *input,
				 struct list *output)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-information-originate",
			.cbs.modify = ripngd_instance_default_information_originate_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-metric",
			.cbs.modify = ripngd_instance_default_metric_modify,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/network",
			.cbs.create = ripngd_instance_network_create,
			.cbs.delete = ripngd_instance_network_delete,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/interface",
			.cbs.create = ripngd_instance_interface_create,
			.cbs.delete = ripngd_instance_interface_delete,
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list",
			.cbs.create = ripngd_instance_offset_list_create,
			.cbs.delete = ripngd_instance_offset_list_delete,
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
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute",
			.cbs.create = ripngd_instance_redistribute_create,
			.cbs.delete = ripngd_instance_redistribute_delete,
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
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/aggregate-address",
			.cbs.create = ripngd_instance_aggregate_address_create,
			.cbs.delete = ripngd_instance_aggregate_address_delete,
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
		},
		{
			.xpath = NULL,
		},
	}
};
