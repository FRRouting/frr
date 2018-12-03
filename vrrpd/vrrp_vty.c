/*
 * VRRP commands
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
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

#include "command.h"
#include "vty.h"
#include "if.h"

#include "vrrp.h"
#include "vrrp_vty.h"
#include "vrrp_memory.h"
//#ifndef VTYSH_EXTRACT_PL
//#include "vrrp/vrrp_vty_clippy.c"
//#endif


#define VRRP_STR "Virtual Router Redundancy Protocol\n"
#define VRRP_VRID_STR "Virtual Router ID\n"

DEFUN_NOSH (show_debugging_vrrpd,
	    show_debugging_vrrpd_cmd,
	    "show debugging [vrrp]",
	    SHOW_STR
	    DEBUG_STR
	    "VRRP information\n")
{
	vty_out(vty, "VRRP debugging status\n");

	return CMD_SUCCESS;
}

DEFUN(vrrp_vrid,
      vrrp_vrid_cmd,
      "[no] vrrp (1-255)",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	uint8_t vrid;

	argv_find(argv, argc, "(1-255)", &idx);
	vrid = strtoul(argv[idx]->arg, NULL, 10);

	struct vrrp_vrouter *vr = vrrp_vrouter_create(ifp, vrid);
	int ret = vrrp_event(vr, VRRP_EVENT_STARTUP);
	if (ret < 0) {
		vty_out(vty, "%% Failed to start VRRP instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE,
	"%s(config-if)# ", 1
};

void vrrp_vty_init(void)
{
	install_node(&interface_node, NULL);
	if_cmd_init();
	install_element(VIEW_NODE, &show_debugging_vrrpd_cmd);
	install_element(ENABLE_NODE, &show_debugging_vrrpd_cmd);
	install_element(INTERFACE_NODE, &vrrp_vrid_cmd);
}
