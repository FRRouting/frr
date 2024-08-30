// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Staticd debug related functions
 * Copyright (C) 2019 Volta Networks Inc.
 * Mark Stapp
 */

#ifndef _STATIC_DEBUG_H
#define _STATIC_DEBUG_H

#include <zebra.h>

#include "lib/debug.h"

#ifdef __cplusplus
extern "C" {
#endif

/* staticd debugging records */
extern struct debug static_dbg_events;
extern struct debug static_dbg_route;
extern struct debug static_dbg_bfd;

/*
 * Initialize staticd debugging.
 *
 * Installs VTY commands and registers callbacks.
 */
void static_debug_init(void);

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
		      bool bfd);

#ifdef __cplusplus
}
#endif

#endif /* _STATIC_DEBUG_H */
