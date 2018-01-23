/*
 * PBR - debugging
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Quentin Young
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
#ifndef __PBR_DEBUG_H__
#define __PBR_DEBUG_H__

#include <zebra.h>

#include "debug.h"

/* PBR debugging records */
extern struct debug pbr_dbg_map;
extern struct debug pbr_dbg_zebra;
extern struct debug pbr_dbg_nht;
extern struct debug pbr_dbg_event;

/*
 * Initialize PBR debugging.
 *
 * Installs VTY commands and registers callbacks.
 */
void pbr_debug_init(void);

/*
 * Install PBR debugging VTY commands.
 */
void pbr_debug_init_vty(void);

/*
 * Print PBR debugging configuration.
 *
 * vty
 *    VTY to print debugging configuration to.
 */
int pbr_debug_config_write(struct vty *vty);

#endif /* __PBR_DEBUG_H__ */
