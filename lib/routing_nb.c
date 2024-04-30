// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 */
#include <zebra.h>

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

const struct frr_yang_module_info frr_routing_cli_info = {
	.name = "frr-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = NULL,
		},
	}
};
