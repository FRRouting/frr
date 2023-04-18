// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Debugging utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 * Quentin Young
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
