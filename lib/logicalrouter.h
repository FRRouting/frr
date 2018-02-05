/*
 * Logical Router related header.
 * Copyright (C) 2018 6WIND S.A.
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

#ifndef _ZEBRA_LOGICAL_ROUTER_H
#define _ZEBRA_LOGICAL_ROUTER_H

/* Logical Router Backend defines */
#define LOGICALROUTER_BACKEND_OFF   0
#define LOGICALROUTER_BACKEND_NETNS 1

/*
 * Logical Router initializer/destructor
 */
extern void logicalrouter_init(int (*writefunc)(struct vty *vty));
extern void logicalrouter_terminate(void);

/* used to configure backend for logical router
 * Currently, the whole NETNS feature is exclusively shared
 * between logical router and VRF backend NETNS
 * However, when logical router feature will be available,
 * one can think of having exclusivity only per NETNS
 */
extern void logicalrouter_configure_backend(int backend_netns);

#endif /*_ZEBRA_LOGICAL_ROUTER_H*/
