/* zebra memory type definitions
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "zebra_memory.h"

DEFINE_MGROUP(ZEBRA, "zebra")
DEFINE_MTYPE(ZEBRA, RTADV_PREFIX, "Router Advertisement Prefix")
DEFINE_MTYPE(ZEBRA, ZEBRA_VRF, "ZEBRA VRF")
DEFINE_MTYPE(ZEBRA, RE, "Route Entry")
DEFINE_MTYPE(ZEBRA, RIB_QUEUE, "RIB process work queue")
DEFINE_MTYPE(ZEBRA, STATIC_ROUTE, "Static route")
DEFINE_MTYPE(ZEBRA, RIB_DEST, "RIB destination")
DEFINE_MTYPE(ZEBRA, RIB_TABLE_INFO, "RIB table info")
DEFINE_MTYPE(ZEBRA, RNH, "Nexthop tracking object")
