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
struct debug static_dbg_events = {0, "debug static events", "Staticd events"};
struct debug static_dbg_route = {0, "debug static route", "Staticd route"};
struct debug static_dbg_bfd = {0, "debug static bfd", "Staticd bfd"};
/* clang-format on */

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
