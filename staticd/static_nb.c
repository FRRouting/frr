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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/bh-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/onlink",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy,
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
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/bh-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/onlink",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/label",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/ttl",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
