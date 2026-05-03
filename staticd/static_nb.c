// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 */
#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "static_nb.h"
#include "static_vty.h"

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
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_apply_finish,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/distance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_distance_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_metric_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bh-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_bh_type_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/weight",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_weight_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_weight_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/onlink",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_onlink_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srte-color",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_color_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_color_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_destroy,

			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/entry/seg",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_seg_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_seg_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/encap-behavior",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_encap_behavior_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_encap_behavior_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_destroy,

			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_traffic_class_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_traffic_class_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bfd-monitoring",
			.cbs = {
				.create = route_next_hop_bfd_create,
				.destroy = route_next_hop_bfd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bfd-monitoring/source",
			.cbs = {
				.modify = route_next_hop_bfd_source_modify,
				.destroy = route_next_hop_bfd_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bfd-monitoring/multi-hop",
			.cbs = {
				.modify = route_next_hop_bfd_multi_hop_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bfd-monitoring/profile",
			.cbs = {
				.modify = route_next_hop_bfd_profile_modify,
				.destroy = route_next_hop_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/behavior",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/vrf-name",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/paths",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/paths/interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/paths/next-hop",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids/sid/locator-name",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
