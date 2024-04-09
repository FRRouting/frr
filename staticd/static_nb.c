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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_destroy,

			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry/seg",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_destroy,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/source",
			.cbs = {
				.modify = route_next_hop_bfd_source_modify,
				.destroy = route_next_hop_bfd_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/multi-hop",
			.cbs = {
				.modify = route_next_hop_bfd_multi_hop_modify,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry/seg",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_destroy,
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
			.xpath = NULL,
		},
	}
};
