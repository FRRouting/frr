/*
 * Staticd debug related functions
 * Copyright (C) 2019 Volta Networks Inc.
 * Mark Stapp
 *
 * This file is part of FRRouting (FRR).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
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
#include "lib/debug.h"

#include "static_debug.h"

/*
 * Debug infra: a debug struct for each category, and a corresponding
 * string.
 */

/* clang-format off */
struct debug static_dbg_events = {0, "Staticd events"};

struct debug *static_debug_arr[] =  {
	&static_dbg_events
};

const char *static_debugs_conflines[] = {
	"debug static events"
};
/* clang-format on */


/*
 * Set or unset all staticd debugs
 *
 * flags
 *    The flags to set
 *
 * set
 *    Whether to set or unset the specified flags
 */
static void static_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(static_debug_arr); i++) {
		DEBUG_FLAGS_SET(static_debug_arr[i], flags, set);

		/* if all modes have been turned off, don't preserve options */
		if (!DEBUG_MODE_CHECK(static_debug_arr[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(static_debug_arr[i]);
	}
}

static int static_debug_config_write_helper(struct vty *vty, bool config)
{
	uint32_t mode = DEBUG_MODE_ALL;

	if (config)
		mode = DEBUG_MODE_CONF;

	for (unsigned int i = 0; i < array_size(static_debug_arr); i++)
		if (DEBUG_MODE_CHECK(static_debug_arr[i], mode))
			vty_out(vty, "%s\n", static_debugs_conflines[i]);

	return 0;
}

int static_config_write_debug(struct vty *vty)
{
	return static_debug_config_write_helper(vty, true);
}

int static_debug_status_write(struct vty *vty)
{
	return static_debug_config_write_helper(vty, false);
}

/*
 * Set debugging status.
 *
 * vtynode
 *    vty->node
 *
 * onoff
 *    Whether to turn the specified debugs on or off
 *
 * events
 *    Debug general internal events
 *
 */
void static_debug_set(int vtynode, bool onoff, bool events)
{
	uint32_t mode = DEBUG_NODE2MODE(vtynode);

	if (events)
		DEBUG_MODE_SET(&static_dbg_events, mode, onoff);
}

/*
 * Debug lib initialization
 */

struct debug_callbacks static_dbg_cbs = {
	.debug_set_all = static_debug_set_all
};

void static_debug_init(void)
{
	debug_init(&static_dbg_cbs);
}
