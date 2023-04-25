// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "ripngd/ripng_nb.h"
#include "lib/if_rmap.h"

/* clang-format off */
const struct frr_yang_module_info frr_ripngd_info = {
	.name = "frr-ripngd",
	.nodes = {
		{
			.xpath = "/frr-ripngd:ripngd/instance",
			.cbs = {
				.cli_show = cli_show_router_ripng,
				.create = ripngd_instance_create,
				.destroy = ripngd_instance_destroy,
				.get_keys = ripngd_instance_get_keys,
				.get_next = ripngd_instance_get_next,
				.lookup_entry = ripngd_instance_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/allow-ecmp",
			.cbs = {
				.cli_show = cli_show_ripng_allow_ecmp,
				.modify = ripngd_instance_allow_ecmp_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-information-originate",
			.cbs = {
				.cli_show = cli_show_ripng_default_information_originate,
				.modify = ripngd_instance_default_information_originate_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/default-metric",
			.cbs = {
				.cli_show = cli_show_ripng_default_metric,
				.modify = ripngd_instance_default_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/network",
			.cbs = {
				.cli_show = cli_show_ripng_network_prefix,
				.create = ripngd_instance_network_create,
				.destroy = ripngd_instance_network_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/interface",
			.cbs = {
				.cli_show = cli_show_ripng_network_interface,
				.create = ripngd_instance_interface_create,
				.destroy = ripngd_instance_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list",
			.cbs = {
				.cli_show = cli_show_ripng_offset_list,
				.create = ripngd_instance_offset_list_create,
				.destroy = ripngd_instance_offset_list_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list/access-list",
			.cbs = {
				.modify = ripngd_instance_offset_list_access_list_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/offset-list/metric",
			.cbs = {
				.modify = ripngd_instance_offset_list_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/passive-interface",
			.cbs = {
				.cli_show = cli_show_ripng_passive_interface,
				.create = ripngd_instance_passive_interface_create,
				.destroy = ripngd_instance_passive_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute",
			.cbs = {
				.apply_finish = ripngd_instance_redistribute_apply_finish,
				.cli_show = cli_show_ripng_redistribute,
				.create = ripngd_instance_redistribute_create,
				.destroy = ripngd_instance_redistribute_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute/route-map",
			.cbs = {
				.destroy = ripngd_instance_redistribute_route_map_destroy,
				.modify = ripngd_instance_redistribute_route_map_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/redistribute/metric",
			.cbs = {
				.destroy = ripngd_instance_redistribute_metric_destroy,
				.modify = ripngd_instance_redistribute_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/if-route-maps/if-route-map",
			.cbs = {
				.create = ripngd_instance_if_route_maps_if_route_map_create,
				.destroy = ripngd_instance_if_route_maps_if_route_map_destroy,
				.cli_show = cli_show_if_route_map,
			}
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/if-route-maps/if-route-map/in-route-map",
			.cbs = {
				.modify = ripngd_instance_if_route_maps_if_route_map_in_route_map_modify,
				.destroy = ripngd_instance_if_route_maps_if_route_map_in_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/if-route-maps/if-route-map/out-route-map",
			.cbs = {
				.modify = ripngd_instance_if_route_maps_if_route_map_out_route_map_modify,
				.destroy = ripngd_instance_if_route_maps_if_route_map_out_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/static-route",
			.cbs = {
				.cli_show = cli_show_ripng_route,
				.create = ripngd_instance_static_route_create,
				.destroy = ripngd_instance_static_route_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/aggregate-address",
			.cbs = {
				.cli_show = cli_show_ripng_aggregate_address,
				.create = ripngd_instance_aggregate_address_create,
				.destroy = ripngd_instance_aggregate_address_destroy,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers",
			.cbs = {
				.apply_finish = ripngd_instance_timers_apply_finish,
				.cli_show = cli_show_ripng_timers,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/flush-interval",
			.cbs = {
				.modify = ripngd_instance_timers_flush_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/holddown-interval",
			.cbs = {
				.modify = ripngd_instance_timers_holddown_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/timers/update-interval",
			.cbs = {
				.modify = ripngd_instance_timers_update_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/neighbors/neighbor",
			.cbs = {
				.get_keys = ripngd_instance_state_neighbors_neighbor_get_keys,
				.get_next = ripngd_instance_state_neighbors_neighbor_get_next,
				.lookup_entry = ripngd_instance_state_neighbors_neighbor_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = ripngd_instance_state_neighbors_neighbor_address_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/neighbors/neighbor/last-update",
			.cbs = {
				.get_elem = ripngd_instance_state_neighbors_neighbor_last_update_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/neighbors/neighbor/bad-packets-rcvd",
			.cbs = {
				.get_elem = ripngd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/neighbors/neighbor/bad-routes-rcvd",
			.cbs = {
				.get_elem = ripngd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/routes/route",
			.cbs = {
				.get_keys = ripngd_instance_state_routes_route_get_keys,
				.get_next = ripngd_instance_state_routes_route_get_next,
				.lookup_entry = ripngd_instance_state_routes_route_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/routes/route/prefix",
			.cbs = {
				.get_elem = ripngd_instance_state_routes_route_prefix_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/routes/route/next-hop",
			.cbs = {
				.get_elem = ripngd_instance_state_routes_route_next_hop_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/routes/route/interface",
			.cbs = {
				.get_elem = ripngd_instance_state_routes_route_interface_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:ripngd/instance/state/routes/route/metric",
			.cbs = {
				.get_elem = ripngd_instance_state_routes_route_metric_get_elem,
			},
		},
		{
			.xpath = "/frr-ripngd:clear-ripng-route",
			.cbs = {
				.rpc = clear_ripng_route_rpc,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripngd:ripng/split-horizon",
			.cbs = {
				.cli_show = cli_show_ipv6_ripng_split_horizon,
				.modify = lib_interface_ripng_split_horizon_modify,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
