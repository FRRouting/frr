/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "log.h"
#include "command.h"
#include "mpls.h"
#include "northbound_cli.h"

#include "pathd/pathd.h"
#include "pathd/path_nb.h"
#ifndef VTYSH_EXTRACT_PL
#include "pathd/path_cli_clippy.c"
#endif

static int config_write_paths(struct vty *vty);

/* TE path node structure. */
static struct cmd_node te_path_node = {
        .name = "te-path",
        .node = TE_PATH_NODE,
        .parent_node = CONFIG_NODE,
        .prompt = "%s(config-te-path)# ",
        .config_write = config_write_paths,
};

int config_write_paths(struct vty *vty)
{
	struct lyd_node *dnode;

	dnode = yang_dnode_get(running_config->dnode, "/frr-pathd:pathd");
	assert(dnode);
	nb_cli_show_dnode_cmds(vty, dnode, false);

	return 1;
}

void path_cli_init(void)
{
	install_node(&te_path_node);
	install_default(TE_PATH_NODE);
}
