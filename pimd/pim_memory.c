/* pimd memory type definitions
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

#include "pim_memory.h"

DEFINE_MGROUP(PIMD, "pimd")
DEFINE_MTYPE(PIMD, PIM_CHANNEL_OIL, "PIM SSM (S,G) channel OIL")
DEFINE_MTYPE(PIMD, PIM_INTERFACE, "PIM interface")
DEFINE_MTYPE(PIMD, PIM_IGMP_JOIN, "PIM interface IGMP static join")
DEFINE_MTYPE(PIMD, PIM_IGMP_SOCKET, "PIM interface IGMP socket")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP, "PIM interface IGMP group")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP_SOURCE, "PIM interface IGMP source")
DEFINE_MTYPE(PIMD, PIM_NEIGHBOR, "PIM interface neighbor")
DEFINE_MTYPE(PIMD, PIM_IFCHANNEL, "PIM interface (S,G) state")
DEFINE_MTYPE(PIMD, PIM_UPSTREAM, "PIM upstream (S,G) state")
DEFINE_MTYPE(PIMD, PIM_SSMPINGD, "PIM sspimgd socket")
DEFINE_MTYPE(PIMD, PIM_STATIC_ROUTE, "PIM Static Route")
DEFINE_MTYPE(PIMD, PIM_BR, "PIM Bridge Router info")
DEFINE_MTYPE(PIMD, PIM_RP, "PIM RP info")
DEFINE_MTYPE(PIMD, PIM_FILTER_NAME, "PIM RP filter info")
DEFINE_MTYPE(PIMD, PIM_MSDP_PEER, "PIM MSDP peer")
DEFINE_MTYPE(PIMD, PIM_MSDP_MG_NAME, "PIM MSDP mesh-group name")
DEFINE_MTYPE(PIMD, PIM_MSDP_SA, "PIM MSDP source-active cache")
DEFINE_MTYPE(PIMD, PIM_MSDP_MG, "PIM MSDP mesh group")
DEFINE_MTYPE(PIMD, PIM_MSDP_MG_MBR, "PIM MSDP mesh group mbr")
DEFINE_MTYPE(PIMD, PIM_SEC_ADDR, "PIM secondary address")
DEFINE_MTYPE(PIMD, PIM_JP_AGG_GROUP, "PIM JP AGG Group")
DEFINE_MTYPE(PIMD, PIM_JP_AGG_SOURCE, "PIM JP AGG Source")
DEFINE_MTYPE(PIMD, PIM_PIM_INSTANCE, "PIM global state")
DEFINE_MTYPE(PIMD, PIM_NEXTHOP_CACHE, "PIM nexthop cache state")
DEFINE_MTYPE(PIMD, PIM_SSM_INFO, "PIM SSM configuration")
DEFINE_MTYPE(PIMD, PIM_SPT_PLIST_NAME, "PIM SPT Prefix List Name")
