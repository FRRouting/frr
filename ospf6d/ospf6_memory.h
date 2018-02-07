/* ospf6d memory type declarations
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

#ifndef _QUAGGA_OSPF6_MEMORY_H
#define _QUAGGA_OSPF6_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(OSPF6D)
DECLARE_MTYPE(OSPF6_TOP)
DECLARE_MTYPE(OSPF6_AREA)
DECLARE_MTYPE(OSPF6_IF)
DECLARE_MTYPE(OSPF6_NEIGHBOR)
DECLARE_MTYPE(OSPF6_ROUTE)
DECLARE_MTYPE(OSPF6_PREFIX)
DECLARE_MTYPE(OSPF6_MESSAGE)
DECLARE_MTYPE(OSPF6_LSA)
DECLARE_MTYPE(OSPF6_LSA_HEADER)
DECLARE_MTYPE(OSPF6_LSA_SUMMARY)
DECLARE_MTYPE(OSPF6_LSDB)
DECLARE_MTYPE(OSPF6_VERTEX)
DECLARE_MTYPE(OSPF6_SPFTREE)
DECLARE_MTYPE(OSPF6_NEXTHOP)
DECLARE_MTYPE(OSPF6_EXTERNAL_INFO)
DECLARE_MTYPE(OSPF6_PATH)
DECLARE_MTYPE(OSPF6_DIST_ARGS)
DECLARE_MTYPE(OSPF6_OTHER)

#endif /* _QUAGGA_OSPF6_MEMORY_H */
