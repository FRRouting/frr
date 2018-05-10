/*
 * IS-IS Rout(e)ing protocol - isis_vty_fabricd.c
 *
 * This file contains the CLI that is specific to OpenFabric
 *
 * Copyright (C) 2018        Christian Franke, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "command.h"

#include "isisd.h"
#include "isis_vty_common.h"
#include "fabricd.h"
#include "isis_tlvs.h"

DEFUN (fabric_tier,
       fabric_tier_cmd,
       "fabric-tier (0-14)",
       "Statically configure the tier to advertise\n"
       "Tier to advertise\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	uint8_t tier = atoi(argv[1]->arg);

	fabricd_configure_tier(area, tier);
	return CMD_SUCCESS;
}

DEFUN (no_fabric_tier,
       no_fabric_tier_cmd,
       "no fabric-tier [(0-14)]",
       NO_STR
       "Statically configure the tier to advertise\n"
       "Tier to advertise\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	fabricd_configure_tier(area, ISIS_TIER_UNDEFINED);
	return CMD_SUCCESS;
}

void isis_vty_daemon_init(void)
{
	install_element(ROUTER_NODE, &fabric_tier_cmd);
	install_element(ROUTER_NODE, &no_fabric_tier_cmd);
}
