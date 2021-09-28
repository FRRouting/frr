/*
 * Staticd debug related functions
 * Copyright (C) 2019 Volta Networks Inc.
 * Mark Stapp
 *
 * This file is part of FRRouting (FRR).
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
 * Print staticd debugging configuration.
 *
 * vty
 *    VTY to print debugging configuration to.
 */
int static_config_write_debug(struct vty *vty);

/*
 * Print staticd debugging configuration, human readable form.
 *
 * vty
 *    VTY to print debugging configuration to.
 */
int static_debug_status_write(struct vty *vty);

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
