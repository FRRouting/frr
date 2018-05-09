/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_cli.h"

/*
 * XPath: /frr-ripd:ripd/instance
 */
static int ripd_instance_create(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	int socket;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		socket = rip_create_socket();
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
		rip_create(socket);
		break;
	}

	return NB_OK;
}

static int ripd_instance_delete(enum nb_event event,
				const struct lyd_node *dnode)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	rip_clean();

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
static int ripd_instance_allow_ecmp_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	if (event != NB_EV_APPLY)
		return NB_OK;

	rip->ecmp = yang_dnode_get_bool(dnode, NULL);
	if (!rip->ecmp)
		rip_ecmp_disable();

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
static int
ripd_instance_default_information_originate_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-metric
 */
static int ripd_instance_default_metric_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
static int ripd_instance_distance_default_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
static int ripd_instance_distance_source_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_distance_source_delete(enum nb_event event,
						const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/distance
 */
static int
ripd_instance_distance_source_distance_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/access-list
 */
static int
ripd_instance_distance_source_access_list_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripd_instance_distance_source_access_list_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
static int ripd_instance_explicit_neighbor_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_explicit_neighbor_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/network
 */
static int ripd_instance_network_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_network_delete(enum nb_event event,
					const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/interface
 */
static int ripd_instance_interface_create(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_interface_delete(enum nb_event event,
					  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
static int ripd_instance_offset_list_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_offset_list_delete(enum nb_event event,
					    const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list/access-list
 */
static int
ripd_instance_offset_list_access_list_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list/metric
 */
static int ripd_instance_offset_list_metric_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
static int ripd_instance_passive_default_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 */
static int ripd_instance_passive_interface_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_passive_interface_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/non-passive-interface
 */
static int
ripd_instance_non_passive_interface_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripd_instance_non_passive_interface_delete(enum nb_event event,
					   const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
static int ripd_instance_redistribute_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_redistribute_delete(enum nb_event event,
					     const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/route-map
 */
static int
ripd_instance_redistribute_route_map_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripd_instance_redistribute_route_map_delete(enum nb_event event,
					    const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/metric
 */
static int
ripd_instance_redistribute_metric_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
ripd_instance_redistribute_metric_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/static-route
 */
static int ripd_instance_static_route_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int ripd_instance_static_route_delete(enum nb_event event,
					     const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/flush-interval
 */
static int
ripd_instance_timers_flush_interval_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/holddown-interval
 */
static int
ripd_instance_timers_holddown_interval_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/update-interval
 */
static int
ripd_instance_timers_update_interval_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/receive
 */
static int ripd_instance_version_receive_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/send
 */
static int ripd_instance_version_send_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/split-horizon
 */
static int lib_interface_rip_split_horizon_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/v2-broadcast
 */
static int lib_interface_rip_v2_broadcast_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-receive
 */
static int
lib_interface_rip_version_receive_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-send
 */
static int lib_interface_rip_version_send_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode
 */
static int lib_interface_rip_authentication_scheme_mode_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length
 */
static int lib_interface_rip_authentication_scheme_md5_auth_length_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_rip_authentication_scheme_md5_auth_length_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-password
 */
static int
lib_interface_rip_authentication_password_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
lib_interface_rip_authentication_password_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain
 */
static int
lib_interface_rip_authentication_key_chain_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
lib_interface_rip_authentication_key_chain_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/state/neighbors/neighbor
 */
static const void *
ripd_state_neighbors_neighbor_get_next(const char *xpath,
				       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

static int ripd_state_neighbors_neighbor_get_keys(const void *list_entry,
						  struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *
ripd_state_neighbors_neighbor_lookup_entry(const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/neighbors/neighbor/address
 */
static struct yang_data *
ripd_state_neighbors_neighbor_address_get_elem(const char *xpath,
					       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/neighbors/neighbor/last-update
 */
static struct yang_data *
ripd_state_neighbors_neighbor_last_update_get_elem(const char *xpath,
						   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/neighbors/neighbor/bad-packets-rcvd
 */
static struct yang_data *
ripd_state_neighbors_neighbor_bad_packets_rcvd_get_elem(const char *xpath,
							const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/neighbors/neighbor/bad-routes-rcvd
 */
static struct yang_data *
ripd_state_neighbors_neighbor_bad_routes_rcvd_get_elem(const char *xpath,
						       const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/routes/route
 */
static const void *ripd_state_routes_route_get_next(const char *xpath,
						    const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

static int ripd_state_routes_route_get_keys(const void *list_entry,
					    struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *
ripd_state_routes_route_lookup_entry(const struct yang_list_keys *keys)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/routes/route/prefix
 */
static struct yang_data *
ripd_state_routes_route_prefix_get_elem(const char *xpath,
					const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/routes/route/next-hop
 */
static struct yang_data *
ripd_state_routes_route_next_hop_get_elem(const char *xpath,
					  const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/routes/route/interface
 */
static struct yang_data *
ripd_state_routes_route_interface_get_elem(const char *xpath,
					   const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/state/routes/route/metric
 */
static struct yang_data *
ripd_state_routes_route_metric_get_elem(const char *xpath,
					const void *list_entry)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ripd:clear-rip-route
 */
static int clear_rip_route_rpc(const char *xpath, const struct list *input,
			       struct list *output)
{
	/* TODO: implement me. */
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_ripd_info = {
	.name = "frr-ripd",
	.nodes = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.cbs.create = ripd_instance_create,
			.cbs.delete = ripd_instance_delete,
			.cbs.cli_show = cli_show_router_rip,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/allow-ecmp",
			.cbs.modify = ripd_instance_allow_ecmp_modify,
			.cbs.cli_show = cli_show_rip_allow_ecmp,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-information-originate",
			.cbs.modify = ripd_instance_default_information_originate_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-metric",
			.cbs.modify = ripd_instance_default_metric_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/default",
			.cbs.modify = ripd_instance_distance_default_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source",
			.cbs.create = ripd_instance_distance_source_create,
			.cbs.delete = ripd_instance_distance_source_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/distance",
			.cbs.modify = ripd_instance_distance_source_distance_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/access-list",
			.cbs.modify = ripd_instance_distance_source_access_list_modify,
			.cbs.delete = ripd_instance_distance_source_access_list_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/explicit-neighbor",
			.cbs.create = ripd_instance_explicit_neighbor_create,
			.cbs.delete = ripd_instance_explicit_neighbor_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/network",
			.cbs.create = ripd_instance_network_create,
			.cbs.delete = ripd_instance_network_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/interface",
			.cbs.create = ripd_instance_interface_create,
			.cbs.delete = ripd_instance_interface_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list",
			.cbs.create = ripd_instance_offset_list_create,
			.cbs.delete = ripd_instance_offset_list_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/access-list",
			.cbs.modify = ripd_instance_offset_list_access_list_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/metric",
			.cbs.modify = ripd_instance_offset_list_metric_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-default",
			.cbs.modify = ripd_instance_passive_default_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-interface",
			.cbs.create = ripd_instance_passive_interface_create,
			.cbs.delete = ripd_instance_passive_interface_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/non-passive-interface",
			.cbs.create = ripd_instance_non_passive_interface_create,
			.cbs.delete = ripd_instance_non_passive_interface_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute",
			.cbs.create = ripd_instance_redistribute_create,
			.cbs.delete = ripd_instance_redistribute_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/route-map",
			.cbs.modify = ripd_instance_redistribute_route_map_modify,
			.cbs.delete = ripd_instance_redistribute_route_map_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/metric",
			.cbs.modify = ripd_instance_redistribute_metric_modify,
			.cbs.delete = ripd_instance_redistribute_metric_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/static-route",
			.cbs.create = ripd_instance_static_route_create,
			.cbs.delete = ripd_instance_static_route_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/flush-interval",
			.cbs.modify = ripd_instance_timers_flush_interval_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/holddown-interval",
			.cbs.modify = ripd_instance_timers_holddown_interval_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/update-interval",
			.cbs.modify = ripd_instance_timers_update_interval_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/receive",
			.cbs.modify = ripd_instance_version_receive_modify,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/send",
			.cbs.modify = ripd_instance_version_send_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/split-horizon",
			.cbs.modify = lib_interface_rip_split_horizon_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/v2-broadcast",
			.cbs.modify = lib_interface_rip_v2_broadcast_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-receive",
			.cbs.modify = lib_interface_rip_version_receive_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-send",
			.cbs.modify = lib_interface_rip_version_send_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode",
			.cbs.modify = lib_interface_rip_authentication_scheme_mode_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length",
			.cbs.modify = lib_interface_rip_authentication_scheme_md5_auth_length_modify,
			.cbs.delete = lib_interface_rip_authentication_scheme_md5_auth_length_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-password",
			.cbs.modify = lib_interface_rip_authentication_password_modify,
			.cbs.delete = lib_interface_rip_authentication_password_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain",
			.cbs.modify = lib_interface_rip_authentication_key_chain_modify,
			.cbs.delete = lib_interface_rip_authentication_key_chain_delete,
		},
		{
			.xpath = "/frr-ripd:ripd/state/neighbors/neighbor",
			.cbs.get_next = ripd_state_neighbors_neighbor_get_next,
			.cbs.get_keys = ripd_state_neighbors_neighbor_get_keys,
			.cbs.lookup_entry = ripd_state_neighbors_neighbor_lookup_entry,
		},
		{
			.xpath = "/frr-ripd:ripd/state/neighbors/neighbor/address",
			.cbs.get_elem = ripd_state_neighbors_neighbor_address_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/neighbors/neighbor/last-update",
			.cbs.get_elem = ripd_state_neighbors_neighbor_last_update_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/neighbors/neighbor/bad-packets-rcvd",
			.cbs.get_elem = ripd_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/neighbors/neighbor/bad-routes-rcvd",
			.cbs.get_elem = ripd_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/routes/route",
			.cbs.get_next = ripd_state_routes_route_get_next,
			.cbs.get_keys = ripd_state_routes_route_get_keys,
			.cbs.lookup_entry = ripd_state_routes_route_lookup_entry,
		},
		{
			.xpath = "/frr-ripd:ripd/state/routes/route/prefix",
			.cbs.get_elem = ripd_state_routes_route_prefix_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/routes/route/next-hop",
			.cbs.get_elem = ripd_state_routes_route_next_hop_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/routes/route/interface",
			.cbs.get_elem = ripd_state_routes_route_interface_get_elem,
		},
		{
			.xpath = "/frr-ripd:ripd/state/routes/route/metric",
			.cbs.get_elem = ripd_state_routes_route_metric_get_elem,
		},
		{
			.xpath = "/frr-ripd:clear-rip-route",
			.cbs.rpc = clear_rip_route_rpc,
		},
		{
			.xpath = NULL,
		},
	}
};
