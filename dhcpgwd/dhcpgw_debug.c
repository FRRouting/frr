// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Dhcpgwd debug related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/debug.h"

#include "dhcpgw_debug.h"

/*
 * Debug infra: a debug struct for each category, and a corresponding
 * string.
 */

/* clang-format off */
struct debug dhcpgw_dbg_events = {0, "debug dhcpgw events", "Dhcpgw events"};
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
extern void dhcpgw_debug_set(int vtynode, bool onoff)
{
	uint32_t mode = DEBUG_NODE2MODE(vtynode);

	DEBUG_MODE_SET(&dhcpgw_dbg_events, mode, onoff);
}

/*
 * Debug lib initialization
 */

void dhcpgw_debug_init(void)
{
	debug_install(&dhcpgw_dbg_events);
}
