/*
 * Debugging utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 * Quentin Young
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
#include "typesafe.h"
#include "debug.h"
#include "command.h"

static struct debug_cb_list_head cb_head;

DECLARE_LIST(debug_cb_list, struct debug_callbacks, item);

/* All code in this section should be reentrant and MT-safe */

DEFUN_NOSH(debug_all, debug_all_cmd, "[no] debug all",
	   NO_STR DEBUG_STR "Toggle all debugging output\n")
{
	struct debug_callbacks *cb;

	bool set = !strmatch(argv[0]->text, "no");
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	frr_each (debug_cb_list, &cb_head, cb)
		cb->debug_set_all(mode, set);

	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------------- */

void debug_init(struct debug_callbacks *cb)
{
	static bool inited = false;

	if (!inited) {
		inited = true;
		debug_cb_list_init(&cb_head);
	}

	debug_cb_list_add_head(&cb_head, cb);
}

void debug_init_cli(void)
{
	install_element(ENABLE_NODE, &debug_all_cmd);
	install_element(CONFIG_NODE, &debug_all_cmd);
}
