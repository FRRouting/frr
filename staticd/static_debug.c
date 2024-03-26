// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Staticd debug related functions
 * Copyright (C) 2019 Volta Networks Inc.
 * Mark Stapp
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/debug.h"
#include "lib/bfd.h"

#include "static_debug.h"

/*
 * Debug infra: a debug struct for each category, and a corresponding
 * string.
 */

/* clang-format off */
struct debug static_dbg_events = {0, "Staticd events"};
struct debug static_dbg_route = {0, "Staticd route"};
struct debug static_dbg_bfd = {0, "Staticd bfd"};

struct debug *static_debug_arr[] =  {
	&static_dbg_events,
	&static_dbg_route,
	&static_dbg_bfd
};

const char *static_debugs_conflines[] = {
	"debug static events",
	"debug static route",
	"debug static bfd"
};
/* clang-format on */

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
void static_debug_set(int vtynode, bool onoff, bool events, bool route,
		      bool bfd)
{
	uint32_t mode = DEBUG_NODE2MODE(vtynode);

	if (events)
		DEBUG_MODE_SET(&static_dbg_events, mode, onoff);
	if (route)
		DEBUG_MODE_SET(&static_dbg_route, mode, onoff);
	if (bfd) {
		DEBUG_MODE_SET(&static_dbg_bfd, mode, onoff);
		bfd_protocol_integration_set_debug(onoff);
	}
}

/*
 * Debug lib initialization
 */

void static_debug_init(void)
{
	debug_install(&static_dbg_events);
	debug_install(&static_dbg_route);
	debug_install(&static_dbg_bfd);
}
