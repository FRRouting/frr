// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"

#include "ripd/rip_nb.h"
#include "lib/if_rmap.h"

/* clang-format off */
const struct frr_yang_module_info frr_ripd_info = {
	.name = "frr-ripd",
	.nodes = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.cbs = {
				.cli_show = cli_show_router_rip,
				.create = ripd_instance_create,
				.destroy = ripd_instance_destroy,
				.get_keys = ripd_instance_get_keys,
				.get_next = ripd_instance_get_next,
				.lookup_entry = ripd_instance_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/allow-ecmp",
			.cbs = {
				.cli_show = cli_show_rip_allow_ecmp,
				.modify = ripd_instance_allow_ecmp_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-information-originate",
			.cbs = {
				.cli_show = cli_show_rip_default_information_originate,
				.modify = ripd_instance_default_information_originate_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-metric",
			.cbs = {
				.cli_show = cli_show_rip_default_metric,
				.modify = ripd_instance_default_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/default",
			.cbs = {
				.cli_show = cli_show_rip_distance,
				.modify = ripd_instance_distance_default_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source",
			.cbs = {
				.cli_show = cli_show_rip_distance_source,
				.create = ripd_instance_distance_source_create,
				.destroy = ripd_instance_distance_source_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/distance",
			.cbs = {
				.modify = ripd_instance_distance_source_distance_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/access-list",
			.cbs = {
				.destroy = ripd_instance_distance_source_access_list_destroy,
				.modify = ripd_instance_distance_source_access_list_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/explicit-neighbor",
			.cbs = {
				.cli_show = cli_show_rip_neighbor,
				.create = ripd_instance_explicit_neighbor_create,
				.destroy = ripd_instance_explicit_neighbor_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/network",
			.cbs = {
				.cli_show = cli_show_rip_network_prefix,
				.create = ripd_instance_network_create,
				.destroy = ripd_instance_network_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/interface",
			.cbs = {
				.cli_show = cli_show_rip_network_interface,
				.create = ripd_instance_interface_create,
				.destroy = ripd_instance_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list",
			.cbs = {
				.cli_show = cli_show_rip_offset_list,
				.create = ripd_instance_offset_list_create,
				.destroy = ripd_instance_offset_list_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/access-list",
			.cbs = {
				.modify = ripd_instance_offset_list_access_list_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/metric",
			.cbs = {
				.modify = ripd_instance_offset_list_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-default",
			.cbs = {
				.cli_show = cli_show_rip_passive_default,
				.modify = ripd_instance_passive_default_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-interface",
			.cbs = {
				.cli_show = cli_show_rip_passive_interface,
				.create = ripd_instance_passive_interface_create,
				.destroy = ripd_instance_passive_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/non-passive-interface",
			.cbs = {
				.cli_show = cli_show_rip_non_passive_interface,
				.create = ripd_instance_non_passive_interface_create,
				.destroy = ripd_instance_non_passive_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute",
			.cbs = {
				.apply_finish = ripd_instance_redistribute_apply_finish,
				.cli_show = cli_show_rip_redistribute,
				.create = ripd_instance_redistribute_create,
				.destroy = ripd_instance_redistribute_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/route-map",
			.cbs = {
				.destroy = ripd_instance_redistribute_route_map_destroy,
				.modify = ripd_instance_redistribute_route_map_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/metric",
			.cbs = {
				.destroy = ripd_instance_redistribute_metric_destroy,
				.modify = ripd_instance_redistribute_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/if-route-maps/if-route-map",
			.cbs = {
				.create = ripd_instance_if_route_maps_if_route_map_create,
				.destroy = ripd_instance_if_route_maps_if_route_map_destroy,
				.cli_show = cli_show_if_route_map,
			}
		},
		{
			.xpath = "/frr-ripd:ripd/instance/if-route-maps/if-route-map/in-route-map",
			.cbs = {
				.modify = ripd_instance_if_route_maps_if_route_map_in_route_map_modify,
				.destroy = ripd_instance_if_route_maps_if_route_map_in_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ripd:ripd/instance/if-route-maps/if-route-map/out-route-map",
			.cbs = {
				.modify = ripd_instance_if_route_maps_if_route_map_out_route_map_modify,
				.destroy = ripd_instance_if_route_maps_if_route_map_out_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-ripd:ripd/instance/static-route",
			.cbs = {
				.cli_show = cli_show_rip_route,
				.create = ripd_instance_static_route_create,
				.destroy = ripd_instance_static_route_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers",
			.cbs = {
				.apply_finish = ripd_instance_timers_apply_finish,
				.cli_show = cli_show_rip_timers,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/flush-interval",
			.cbs = {
				.modify = ripd_instance_timers_flush_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/holddown-interval",
			.cbs = {
				.modify = ripd_instance_timers_holddown_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/update-interval",
			.cbs = {
				.modify = ripd_instance_timers_update_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version",
			.cbs = {
				.cli_show = cli_show_rip_version,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/receive",
			.cbs = {
				.modify = ripd_instance_version_receive_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/send",
			.cbs = {
				.modify = ripd_instance_version_send_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-bfd-profile",
			.cbs = {
				.modify = ripd_instance_default_bfd_profile_modify,
				.destroy = ripd_instance_default_bfd_profile_destroy,
				.cli_show = cli_show_ripd_instance_default_bfd_profile,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/split-horizon",
			.cbs = {
				.cli_show = cli_show_ip_rip_split_horizon,
				.modify = lib_interface_rip_split_horizon_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/v2-broadcast",
			.cbs = {
				.cli_show = cli_show_ip_rip_v2_broadcast,
				.modify = lib_interface_rip_v2_broadcast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-receive",
			.cbs = {
				.cli_show = cli_show_ip_rip_receive_version,
				.modify = lib_interface_rip_version_receive_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-send",
			.cbs = {
				.cli_show = cli_show_ip_rip_send_version,
				.modify = lib_interface_rip_version_send_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_scheme,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode",
			.cbs = {
				.modify = lib_interface_rip_authentication_scheme_mode_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length",
			.cbs = {
				.destroy = lib_interface_rip_authentication_scheme_md5_auth_length_destroy,
				.modify = lib_interface_rip_authentication_scheme_md5_auth_length_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-password",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_string,
				.destroy = lib_interface_rip_authentication_password_destroy,
				.modify = lib_interface_rip_authentication_password_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_key_chain,
				.destroy = lib_interface_rip_authentication_key_chain_destroy,
				.modify = lib_interface_rip_authentication_key_chain_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring",
			.cbs = {
				.create = lib_interface_rip_bfd_create,
				.destroy = lib_interface_rip_bfd_destroy,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/enable",
			.cbs = {
				.cli_show = cli_show_ip_rip_bfd_enable,
				.modify = lib_interface_rip_bfd_enable_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/profile",
			.cbs = {
				.cli_show = cli_show_ip_rip_bfd_profile,
				.modify = lib_interface_rip_bfd_profile_modify,
				.destroy = lib_interface_rip_bfd_profile_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor",
			.cbs = {
				.get_keys = ripd_instance_state_neighbors_neighbor_get_keys,
				.get_next = ripd_instance_state_neighbors_neighbor_get_next,
				.lookup_entry = ripd_instance_state_neighbors_neighbor_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_address_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/last-update",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_last_update_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/bad-packets-rcvd",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/bad-routes-rcvd",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route",
			.cbs = {
				.get_keys = ripd_instance_state_routes_route_get_keys,
				.get_next = ripd_instance_state_routes_route_get_next,
				.lookup_entry = ripd_instance_state_routes_route_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/prefix",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_prefix_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/next-hop",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_next_hop_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/interface",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_interface_get_elem,
			},
		},
		{
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop",
                        .cbs = {
                                .get_next = ripd_instance_state_routes_route_nexthops_nexthop_get_next,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/nh-type",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_nh_type_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/protocol",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_protocol_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/rip-type",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_rip_type_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/gateway",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_gateway_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/interface",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_interface_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/from",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_from_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/tag",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_tag_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/external-metric",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_external_metric_get_elem,
                        }
                },
                {
                        .xpath = "/frr-ripd:ripd/instance/state/routes/route/nexthops/nexthop/expire-time",
                        .cbs = {
                                .get_elem = ripd_instance_state_routes_route_nexthops_nexthop_expire_time_get_elem,
                        }
                },
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/metric",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_metric_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:clear-rip-route",
			.cbs = {
				.rpc = clear_rip_route_rpc,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
