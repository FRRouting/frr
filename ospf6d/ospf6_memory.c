/* ospf6d memory type definitions
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

#include "ospf6_memory.h"

DEFINE_MGROUP(OSPF6D, "ospf6d")
DEFINE_MTYPE(OSPF6D, OSPF6_TOP, "OSPF6 top")
DEFINE_MTYPE(OSPF6D, OSPF6_AREA, "OSPF6 area")
DEFINE_MTYPE(OSPF6D, OSPF6_IF, "OSPF6 interface")
DEFINE_MTYPE(OSPF6D, OSPF6_NEIGHBOR, "OSPF6 neighbor")
DEFINE_MTYPE(OSPF6D, OSPF6_ROUTE, "OSPF6 route")
DEFINE_MTYPE(OSPF6D, OSPF6_PREFIX, "OSPF6 prefix")
DEFINE_MTYPE(OSPF6D, OSPF6_MESSAGE, "OSPF6 message")
DEFINE_MTYPE(OSPF6D, OSPF6_LSA, "OSPF6 LSA")
DEFINE_MTYPE(OSPF6D, OSPF6_LSA_HEADER, "OSPF6 LSA header")
DEFINE_MTYPE(OSPF6D, OSPF6_LSA_SUMMARY, "OSPF6 LSA summary")
DEFINE_MTYPE(OSPF6D, OSPF6_LSDB, "OSPF6 LSA database")
DEFINE_MTYPE(OSPF6D, OSPF6_VERTEX, "OSPF6 vertex")
DEFINE_MTYPE(OSPF6D, OSPF6_SPFTREE, "OSPF6 SPF tree")
DEFINE_MTYPE(OSPF6D, OSPF6_NEXTHOP, "OSPF6 nexthop")
DEFINE_MTYPE(OSPF6D, OSPF6_EXTERNAL_INFO, "OSPF6 ext. info")
DEFINE_MTYPE(OSPF6D, OSPF6_PATH, "OSPF6 Path")
DEFINE_MTYPE(OSPF6D, OSPF6_DIST_ARGS, "OSPF6 Distribute arguments")
DEFINE_MTYPE(OSPF6D, OSPF6_OTHER, "OSPF6 other")
