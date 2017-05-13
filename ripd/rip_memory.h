/* ripd memory type declarations
 *
 * Copyright (C) 2015  David Lamparter
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_RIP_MEMORY_H
#define _QUAGGA_RIP_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(RIPD)
DECLARE_MTYPE(RIP)
DECLARE_MTYPE(RIP_INFO)
DECLARE_MTYPE(RIP_INTERFACE)
DECLARE_MTYPE(RIP_PEER)
DECLARE_MTYPE(RIP_OFFSET_LIST)
DECLARE_MTYPE(RIP_DISTANCE)

#endif /* _QUAGGA_RIP_MEMORY_H */
