// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 12 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "lib/host_cli_clippy.c"

DEFPY(allow_reserved_ranges,
      allow_reserved_ranges_cmd,
      "[no] allow-reserved-ranges",
      NO_STR
      "Allow using IPv4 (Class E) reserved IP space\n")
{
	nb_cli_enqueue_change(vty, "/frr-host:host/allow-reserved-ranges", NB_OP_MODIFY,
			      no ? "false" : "true");
	nb_cli_apply_changes(vty, NULL);

	return CMD_SUCCESS;
}

static void host_allow_reserved_ranges_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (enable)
		vty_out(vty, "allow-reserved-ranges\n");
	else if (show_defaults)
		vty_out(vty, "no allow-reserved-ranges\n");
}

/* clang-format off */
const struct frr_yang_module_info frr_host_cli_info = {
	.name = "frr-host",
	.ignore_cfg_cbs = true,
	.nodes = {
		{ .xpath = "/frr-host:host/allow-reserved-ranges",
		  .cbs.cli_show = host_allow_reserved_ranges_cli_write
		},
		{ .xpath = NULL },
	}
};
/* clang-format on */

void host_cli_init(void)
{
	install_element(CONFIG_NODE, &allow_reserved_ranges_cmd);
}
