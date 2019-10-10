/* zebra memory type declarations
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

#ifndef _QUAGGA_ZEBRA_MEMORY_H
#define _QUAGGA_ZEBRA_MEMORY_H

#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(ZEBRA)
DECLARE_MTYPE(ZEBRA_NS)
DECLARE_MTYPE(RE)
DECLARE_MTYPE(RIB_DEST)

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_ZEBRA_MEMORY_H */
