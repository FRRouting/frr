/* ospfd memory type declarations
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

#ifndef _QUAGGA_OSPF_MEMORY_H
#define _QUAGGA_OSPF_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(OSPFD)
DECLARE_MTYPE(OSPF_TOP)
DECLARE_MTYPE(OSPF_AREA)
DECLARE_MTYPE(OSPF_AREA_RANGE)
DECLARE_MTYPE(OSPF_NETWORK)
DECLARE_MTYPE(OSPF_NEIGHBOR_STATIC)
DECLARE_MTYPE(OSPF_IF)
DECLARE_MTYPE(OSPF_NEIGHBOR)
DECLARE_MTYPE(OSPF_ROUTE)
DECLARE_MTYPE(OSPF_TMP)
DECLARE_MTYPE(OSPF_LSA)
DECLARE_MTYPE(OSPF_LSA_DATA)
DECLARE_MTYPE(OSPF_LSDB)
DECLARE_MTYPE(OSPF_PACKET)
DECLARE_MTYPE(OSPF_FIFO)
DECLARE_MTYPE(OSPF_VERTEX)
DECLARE_MTYPE(OSPF_VERTEX_PARENT)
DECLARE_MTYPE(OSPF_NEXTHOP)
DECLARE_MTYPE(OSPF_PATH)
DECLARE_MTYPE(OSPF_VL_DATA)
DECLARE_MTYPE(OSPF_CRYPT_KEY)
DECLARE_MTYPE(OSPF_EXTERNAL_INFO)
DECLARE_MTYPE(OSPF_DISTANCE)
DECLARE_MTYPE(OSPF_IF_INFO)
DECLARE_MTYPE(OSPF_IF_PARAMS)
DECLARE_MTYPE(OSPF_MESSAGE)
DECLARE_MTYPE(OSPF_MPLS_TE)
DECLARE_MTYPE(OSPF_PCE_PARAMS)
DECLARE_MTYPE(OSPF_SR_PARAMS)
DECLARE_MTYPE(OSPF_EXT_PARAMS)

#endif /* _QUAGGA_OSPF_MEMORY_H */
