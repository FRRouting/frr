/* isisd memory type definitions
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

#include "isis_memory.h"

DEFINE_MGROUP(ISISD, "isisd")
DEFINE_MTYPE(ISISD, ISIS, "ISIS")
DEFINE_MTYPE(ISISD, ISIS_TMP, "ISIS TMP")
DEFINE_MTYPE(ISISD, ISIS_CIRCUIT, "ISIS circuit")
DEFINE_MTYPE(ISISD, ISIS_LSP, "ISIS LSP")
DEFINE_MTYPE(ISISD, ISIS_ADJACENCY, "ISIS adjacency")
DEFINE_MTYPE(ISISD, ISIS_ADJACENCY_INFO, "ISIS adjacency info")
DEFINE_MTYPE(ISISD, ISIS_AREA, "ISIS area")
DEFINE_MTYPE(ISISD, ISIS_AREA_ADDR, "ISIS area address")
DEFINE_MTYPE(ISISD, ISIS_DYNHN, "ISIS dyn hostname")
DEFINE_MTYPE(ISISD, ISIS_SPFTREE, "ISIS SPFtree")
DEFINE_MTYPE(ISISD, ISIS_VERTEX, "ISIS vertex")
DEFINE_MTYPE(ISISD, ISIS_ROUTE_INFO, "ISIS route info")
DEFINE_MTYPE(ISISD, ISIS_NEXTHOP, "ISIS nexthop")
DEFINE_MTYPE(ISISD, ISIS_NEXTHOP6, "ISIS nexthop6")
DEFINE_MTYPE(ISISD, ISIS_DICT, "ISIS dictionary")
DEFINE_MTYPE(ISISD, ISIS_DICT_NODE, "ISIS dictionary node")
DEFINE_MTYPE(ISISD, ISIS_EXT_ROUTE, "ISIS redistributed route")
DEFINE_MTYPE(ISISD, ISIS_EXT_INFO, "ISIS redistributed route info")
DEFINE_MTYPE(ISISD, ISIS_MPLS_TE, "ISIS MPLS_TE parameters")
