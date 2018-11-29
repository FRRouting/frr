/*
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_cli.h"
#ifndef VTYSH_EXTRACT_PL
#include "ripngd/ripng_cli_clippy.c"
#endif

/*
 * XPath: /frr-ripngd:ripngd/instance
 */
DEFPY_NOSH (router_ripng,
       router_ripng_cmd,
       "router ripng",
       "Enable a routing process\n"
       "Make RIPng instance command\n")
{
	int ret;

	nb_cli_enqueue_change(vty, "/frr-ripngd:ripngd/instance", NB_OP_CREATE,
			      NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIPNG_NODE, "/frr-ripngd:ripngd/instance");

	return ret;
}

DEFPY (no_router_ripng,
       no_router_ripng_cmd,
       "no router ripng",
       NO_STR
       "Enable a routing process\n"
       "Make RIPng instance command\n")
{
	nb_cli_enqueue_change(vty, "/frr-ripngd:ripngd/instance", NB_OP_DELETE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_router_ripng(struct vty *vty, struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "router ripng\n");
}

void ripng_cli_init(void)
{
	install_element(CONFIG_NODE, &router_ripng_cmd);
	install_element(CONFIG_NODE, &no_router_ripng_cmd);
}
