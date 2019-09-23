/*
 * bfd_debug.c: Implements the BFD debug functions.
 * Copyright (C) 2019 Broadcom. The term "Broadcom" refers to Broadcom Inc.
 * and/or its subsidiaries.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 (GPLv2) as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License GPLv2
 * License along with this program; see the file COPYING; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include "command.h"
#include "bfd.h"

bool conf_bfd_debug;
bool term_bfd_debug;

DEFUN (debug_bfd,
       debug_bfd_cmd,
       "debug bfd",
       DEBUG_STR
       BFD_STR)
{
	if (vty->node == CONFIG_NODE)
		BFD_DEBUG_ON();
	else {
		BFD_TERM_DEBUG_ON();
		vty_out(vty, "BFD debugging is on\n");
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_bfd,
       no_debug_bfd_cmd,
       "no debug bfd",
       NO_STR
       DEBUG_STR
       BFD_STR)
{
	if (vty->node == CONFIG_NODE)
		BFD_DEBUG_OFF();
	else {
		BFD_TERM_DEBUG_OFF();
		vty_out(vty, "BFD debugging is off\n");
	}
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_bfd,
	    show_debugging_bfd_cmd,
	    "show debugging [bfd]",
	    SHOW_STR
	    DEBUG_STR
	    BFD_STR)
{
	vty_out(vty, "BFD debugging status:\n");

	if (BFD_DEBUG())
		vty_out(vty, "  BFD debugging is on\n");

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

static int bfd_config_write_debug(struct vty *vty)
{
	int write = 0;

	if (CONF_BFD_DEBUG()) {
		vty_out(vty, "debug bfd\n");
		write++;
	}

	return write;
}

static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

void bfd_debug_init(void)
{
	install_node(&debug_node, bfd_config_write_debug);

	install_element(ENABLE_NODE, &show_debugging_bfd_cmd);

	install_element(ENABLE_NODE, &debug_bfd_cmd);
	install_element(CONFIG_NODE, &debug_bfd_cmd);

	install_element(ENABLE_NODE, &no_debug_bfd_cmd);
	install_element(CONFIG_NODE, &no_debug_bfd_cmd);

}


