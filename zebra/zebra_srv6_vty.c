/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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

#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "nexthop.h"
#include "vrf.h"
#include "srv6.h"
#include "lib/json.h"

#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_srv6_vty.h"
#include "zebra/zebra_rnh.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_dplane.h"

static int zebra_sr_config(struct vty *vty);

static struct cmd_node sr_node = {
	.name = "sr",
	.node = SEGMENT_ROUTING_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-sr)# ",
	.config_write = zebra_sr_config,
};

static struct cmd_node srv6_node = {
	.name = "srv6",
	.node = SRV6_NODE,
	.parent_node = SEGMENT_ROUTING_NODE,
	.prompt = "%s(config-srv6)# ",

};

static struct cmd_node srv6_locs_node = {
	.name = "srv6-locators",
	.node = SRV6_LOCS_NODE,
	.parent_node = SRV6_NODE,
	.prompt = "%s(config-srv6-locators)# ",
};

static struct cmd_node srv6_loc_node = {
	.name = "srv6-locator",
	.node = SRV6_LOC_NODE,
	.parent_node = SRV6_LOCS_NODE,
	.prompt = "%s(config-srv6-locator)# "
};

DEFUN_NOSH (segment_routing,
            segment_routing_cmd,
            "segment-routing",
            "Segment Routing\n")
{
	vty->node = SEGMENT_ROUTING_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6,
            srv6_cmd,
            "srv6",
            "Segment Routing SRv6\n")
{
	vty->node = SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locators,
            srv6_locators_cmd,
            "locators",
            "Segment Routing SRv6 locators\n")
{
	vty->node = SRV6_LOCS_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (srv6_locator,
            srv6_locator_cmd,
            "locator WORD",
            "Segment Routing SRv6 locator\n"
            "Specify locator-name\n")
{
	vty->node = SRV6_LOC_NODE;
	return CMD_SUCCESS;
}

static int zebra_sr_config(struct vty *vty)
{
	return 0;
}

void zebra_srv6_vty_init(void)
{
	/* Install nodes and its default commands */
	install_node(&sr_node);
	install_node(&srv6_node);
	install_node(&srv6_locs_node);
	install_node(&srv6_loc_node);
	install_default(SEGMENT_ROUTING_NODE);
	install_default(SRV6_NODE);
	install_default(SRV6_LOCS_NODE);
	install_default(SRV6_LOC_NODE);

	/* Command for change node */
	install_element(CONFIG_NODE, &segment_routing_cmd);
	install_element(SEGMENT_ROUTING_NODE, &srv6_cmd);
	install_element(SRV6_NODE, &srv6_locators_cmd);
	install_element(SRV6_LOCS_NODE, &srv6_locator_cmd);
}
