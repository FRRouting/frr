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

<<<<<<< HEAD
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
=======
static struct debug_list_head debug_head;

DECLARE_LIST(debug_list, struct debug, item);

/* All code in this section should be reentrant and MT-safe */

DEFUN_NOSH (debug_all,
	    debug_all_cmd,
	    "[no] debug all",
	    NO_STR DEBUG_STR
	    "Toggle all debugging output\n")
{
	struct debug *debug;
	bool set = !strmatch(argv[0]->text, "no");
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	frr_each (debug_list, &debug_head, debug) {
		DEBUG_MODE_SET(debug, mode, set);

		/* If all modes have been turned off, don't preserve options. */
		if (!DEBUG_MODE_CHECK(debug, DEBUG_MODE_ALL))
			DEBUG_CLEAR(debug);
	}
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

	return CMD_SUCCESS;
}

/* ------------------------------------------------------------------------- */

<<<<<<< HEAD
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
=======
void debug_status_write(struct vty *vty)
{
	struct debug *debug;

	frr_each (debug_list, &debug_head, debug) {
		if (DEBUG_MODE_CHECK(debug, DEBUG_MODE_ALL))
			vty_out(vty, "  %s debugging is on\n", debug->desc);
	}
}

static int config_write_debug(struct vty *vty)
{
	struct debug *debug;

	frr_each (debug_list, &debug_head, debug) {
		if (DEBUG_MODE_CHECK(debug, DEBUG_MODE_CONF))
			vty_out(vty, "%s\n", debug->conf);
	}

	return 0;
}

static struct cmd_node debug_node = {
	.name = "debug",
	.node = LIB_DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};

void debug_install(struct debug *debug)
{
	debug_list_add_tail(&debug_head, debug);
}

void debug_init(void)
{
	debug_list_init(&debug_head);

	install_node(&debug_node);

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	install_element(ENABLE_NODE, &debug_all_cmd);
	install_element(CONFIG_NODE, &debug_all_cmd);
}
