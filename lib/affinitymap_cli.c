/*
 * Affinity map northbound CLI implementation.
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/northbound_cli.h"
#include "lib/affinitymap.h"
#include "lib/affinitymap_cli_clippy.c"

/* Route map node structure. */
static int affinity_map_config_write(struct vty *vty);
static struct cmd_node affinitymap_node = {
	.name = "affinity-map",
	.node = AFFMAP_NODE,
	.prompt = "",
	.config_write = affinity_map_config_write,
};

/* max value is EXT_ADMIN_GROUP_MAX_POSITIONS - 1 */
DEFPY_YANG_NOSH(affinity_map, affinity_map_cmd,
		"affinity-map NAME$name bit-position (0-1023)$position",
		"Affinity map configuration\n"
		"Affinity attribute name\n"
		"Bit position for affinity attribute value\n"
		"Bit position\n")
{
	char xpathr[XPATH_MAXLEN];

	snprintf(
		xpathr, sizeof(xpathr),
		"/frr-affinity-map:lib/affinity-maps/affinity-map[name='%s']/value",
		name);
	nb_cli_enqueue_change(vty, xpathr, NB_OP_MODIFY, position_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* max value is EXT_ADMIN_GROUP_MAX_POSITIONS - 1 */
DEFPY_YANG_NOSH(no_affinity_map, no_affinity_map_cmd,
		"no affinity-map NAME$name [bit-position (0-1023)$position]",
		NO_STR
		"Affinity map configuration\n"
		"Affinity attribute name\n"
		"Bit position for affinity attribute value\n"
		"Bit position\n")
{
	char xpathr[XPATH_MAXLEN];

	snprintf(xpathr, sizeof(xpathr),
		 "/frr-affinity-map:lib/affinity-maps/affinity-map[name='%s']",
		 name);
	nb_cli_enqueue_change(vty, xpathr, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int affinity_map_config_write(struct vty *vty)
{
	const struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode, "/frr-affinity-map:lib");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

void cli_show_affinity_map(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults __attribute__((__unused__)))
{
	vty_out(vty, "affinity-map %s bit-position %u\n",
		yang_dnode_get_string(dnode, "./name"),
		yang_dnode_get_uint16(dnode, "./value"));
}

/* Initialization of affinity map vector. */
void affinity_map_init(void)
{
	/* CLI commands. */
	install_node(&affinitymap_node);
	install_element(CONFIG_NODE, &affinity_map_cmd);
	install_element(CONFIG_NODE, &no_affinity_map_cmd);
}
