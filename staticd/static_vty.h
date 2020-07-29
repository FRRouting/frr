/*
 * STATICd - vty header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#ifndef __STATIC_VTY_H__
#define __STATIC_VTY_H__

int static_config(struct vty *vty, struct static_vrf *svrf,
		  afi_t afi, safi_t safi, const char *cmd);

void static_vty_init(void);
#endif
