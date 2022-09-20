/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
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

#ifndef _ZEBRA_SRV6_VTY_H
#define _ZEBRA_SRV6_VTY_H

#define ZEBRA_SRV6_LOCATOR_BLOCK_LENGTH 40
#define ZEBRA_SRV6_LOCATOR_NODE_LENGTH 24
#define ZEBRA_SRV6_FUNCTION_LENGTH 16

extern void zebra_srv6_vty_init(void);

#endif /* _ZEBRA_SRV6_VTY_H */
