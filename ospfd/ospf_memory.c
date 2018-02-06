/* ospfd memory type definitions
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

#include "ospf_memory.h"

DEFINE_MGROUP(OSPFD, "ospfd")
DEFINE_MTYPE(OSPFD, OSPF_TOP, "OSPF top")
DEFINE_MTYPE(OSPFD, OSPF_AREA, "OSPF area")
DEFINE_MTYPE(OSPFD, OSPF_AREA_RANGE, "OSPF area range")
DEFINE_MTYPE(OSPFD, OSPF_NETWORK, "OSPF network")
DEFINE_MTYPE(OSPFD, OSPF_NEIGHBOR_STATIC, "OSPF static nbr")
DEFINE_MTYPE(OSPFD, OSPF_IF, "OSPF interface")
DEFINE_MTYPE(OSPFD, OSPF_NEIGHBOR, "OSPF neighbor")
DEFINE_MTYPE(OSPFD, OSPF_ROUTE, "OSPF route")
DEFINE_MTYPE(OSPFD, OSPF_TMP, "OSPF tmp mem")
DEFINE_MTYPE(OSPFD, OSPF_LSA, "OSPF LSA")
DEFINE_MTYPE(OSPFD, OSPF_LSA_DATA, "OSPF LSA data")
DEFINE_MTYPE(OSPFD, OSPF_LSDB, "OSPF LSDB")
DEFINE_MTYPE(OSPFD, OSPF_PACKET, "OSPF packet")
DEFINE_MTYPE(OSPFD, OSPF_FIFO, "OSPF FIFO queue")
DEFINE_MTYPE(OSPFD, OSPF_VERTEX, "OSPF vertex")
DEFINE_MTYPE(OSPFD, OSPF_VERTEX_PARENT, "OSPF vertex parent")
DEFINE_MTYPE(OSPFD, OSPF_NEXTHOP, "OSPF nexthop")
DEFINE_MTYPE(OSPFD, OSPF_PATH, "OSPF path")
DEFINE_MTYPE(OSPFD, OSPF_VL_DATA, "OSPF VL data")
DEFINE_MTYPE(OSPFD, OSPF_CRYPT_KEY, "OSPF crypt key")
DEFINE_MTYPE(OSPFD, OSPF_EXTERNAL_INFO, "OSPF ext. info")
DEFINE_MTYPE(OSPFD, OSPF_DISTANCE, "OSPF distance")
DEFINE_MTYPE(OSPFD, OSPF_IF_INFO, "OSPF if info")
DEFINE_MTYPE(OSPFD, OSPF_IF_PARAMS, "OSPF if params")
DEFINE_MTYPE(OSPFD, OSPF_MESSAGE, "OSPF message")
DEFINE_MTYPE(OSPFD, OSPF_MPLS_TE, "OSPF MPLS parameters")
DEFINE_MTYPE(OSPFD, OSPF_PCE_PARAMS, "OSPF PCE parameters")
DEFINE_MTYPE(OSPFD, OSPF_EXT_PARAMS, "OSPF Extended parameters")
DEFINE_MTYPE(OSPFD, OSPF_SR_PARAMS, "OSPF Segment Routing parameters")
