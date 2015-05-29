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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "zebra_memory.h"

DEFINE_MGROUP(ZEBRA, "zebra")
DEFINE_MTYPE(ZEBRA, RTADV_PREFIX,   "Router Advertisement Prefix")
DEFINE_MTYPE(ZEBRA, ZEBRA_VRF,      "ZEBRA VRF")
DEFINE_MTYPE(ZEBRA, RIB,            "RIB")
DEFINE_MTYPE(ZEBRA, RIB_QUEUE,      "RIB process work queue")
DEFINE_MTYPE(ZEBRA, STATIC_ROUTE,   "Static route")
DEFINE_MTYPE(ZEBRA, RIB_DEST,       "RIB destination")
DEFINE_MTYPE(ZEBRA, RIB_TABLE_INFO, "RIB table info")
DEFINE_MTYPE(ZEBRA, RNH,            "Nexthop tracking object")
