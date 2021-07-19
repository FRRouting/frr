/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
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

#include "northbound.h"
#include "libfrr.h"
#include "static_nb.h"


/* clang-format off */

const struct frr_yang_module_info frr_staticd_info = {
	.name = "frr-staticd",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/tag",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_tag_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_destroy,
				.pre_validate = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bh-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/onlink",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srte-color",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy,

			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring",
			.cbs = {
				.create = route_next_hop_bfd_create,
				.destroy = route_next_hop_bfd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/frr-staticd:bfd-monitoring/enable",
			.cbs = {
				.modify = route_next_hop_bfd_monitor_enable_modify,
				.destroy = route_next_hop_bfd_monitor_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/multi-hop",
			.cbs = {
				.modify = route_next_hop_bfd_multi_hop_modify,
				.destroy = route_next_hop_bfd_multi_hop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/profile",
			.cbs = {
				.modify = route_next_hop_bfd_profile_modify,
				.destroy = route_next_hop_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/group",
			.cbs = {
				.modify = route_next_hop_bfd_group_modify,
				.destroy = route_next_hop_bfd_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/tag",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_tag_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_destroy,
				.pre_validate = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/bh-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_bh_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/onlink",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_onlink_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srte-color",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group",
			.cbs = {
				.create = route_group_create,
				.destroy = route_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring",
			.cbs = {
				.create = route_group_bfd_monitor_create,
				.destroy = route_group_bfd_monitor_destroy,
				.cli_show = static_route_group_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/vrf",
			.cbs = {
				.modify = route_group_bfd_vrf_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/peer",
			.cbs = {
				.modify = route_group_bfd_peer_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/source",
			.cbs = {
				.modify = route_group_bfd_source_modify,
				.destroy = route_group_bfd_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/interface",
			.cbs = {
				.modify = route_group_bfd_interface_modify,
				.destroy = route_group_bfd_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/enable",
			.cbs = {
				.modify = route_group_bfd_enable_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/multi-hop",
			.cbs = {
				.modify = route_group_bfd_multi_hop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-group/bfd-monitoring/profile",
			.cbs = {
				.modify = route_group_bfd_profile_modify,
				.destroy = route_group_bfd_profile_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
