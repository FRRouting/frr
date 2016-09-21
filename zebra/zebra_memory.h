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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_ZEBRA_MEMORY_H
#define _QUAGGA_ZEBRA_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(ZEBRA)
DECLARE_MTYPE(RTADV_PREFIX)
DECLARE_MTYPE(ZEBRA_NS)
DECLARE_MTYPE(ZEBRA_VRF)
DECLARE_MTYPE(RIB)
DECLARE_MTYPE(RIB_QUEUE)
DECLARE_MTYPE(STATIC_ROUTE)
DECLARE_MTYPE(RIB_DEST)
DECLARE_MTYPE(RIB_TABLE_INFO)
DECLARE_MTYPE(RNH)
DECLARE_MTYPE(NETLINK_NAME)

#endif /* _QUAGGA_ZEBRA_MEMORY_H */
