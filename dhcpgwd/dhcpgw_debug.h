// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Dhcpgwd debug related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#ifndef _DHCPGW_DEBUG_H
#define _DHCPGW_DEBUG_H

#include <zebra.h>

#include "lib/debug.h"

#ifdef __cplusplus
extern "C" {
#endif

/* staticd debugging records */
extern struct debug dhcpgw_dbg_events;

/*
 * Initialize dhcpgwd debugging.
 *
 * Installs VTY commands and registers callbacks.
 */
void dhcpgw_debug_init(void);

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
void dhcpgw_debug_set(int vtynode, bool onoff);

#ifdef __cplusplus
}
#endif

#endif /* _DHCPGW_DEBUG_H */
