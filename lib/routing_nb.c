#include "northbound.h"
#include "libfrr.h"
#include "routing_nb.h"



/* clang-format off */
const struct frr_yang_module_info frr_routing_info = {
	.name = "frr-routing",
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
