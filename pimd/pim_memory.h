/* pimd memory type declarations
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

#ifndef _QUAGGA_PIM_MEMORY_H
#define _QUAGGA_PIM_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(PIMD)
DECLARE_MTYPE(PIM_CHANNEL_OIL)
DECLARE_MTYPE(PIM_INTERFACE)
DECLARE_MTYPE(PIM_IGMP_JOIN)
DECLARE_MTYPE(PIM_IGMP_SOCKET)
DECLARE_MTYPE(PIM_IGMP_GROUP)
DECLARE_MTYPE(PIM_IGMP_GROUP_SOURCE)
DECLARE_MTYPE(PIM_NEIGHBOR)
DECLARE_MTYPE(PIM_IFCHANNEL)
DECLARE_MTYPE(PIM_UPSTREAM)
DECLARE_MTYPE(PIM_SSMPINGD)
DECLARE_MTYPE(PIM_STATIC_ROUTE)
DECLARE_MTYPE(PIM_BR)
DECLARE_MTYPE(PIM_RP)
DECLARE_MTYPE(PIM_FILTER_NAME)
DECLARE_MTYPE(PIM_MSDP_PEER)
DECLARE_MTYPE(PIM_MSDP_MG_NAME)
DECLARE_MTYPE(PIM_MSDP_SA)
DECLARE_MTYPE(PIM_MSDP_MG)
DECLARE_MTYPE(PIM_MSDP_MG_MBR)
DECLARE_MTYPE(PIM_SEC_ADDR)
DECLARE_MTYPE(PIM_JP_AGG_GROUP)
DECLARE_MTYPE(PIM_JP_AGG_SOURCE)
DECLARE_MTYPE(PIM_PIM_INSTANCE)
DECLARE_MTYPE(PIM_NEXTHOP_CACHE)
DECLARE_MTYPE(PIM_SSM_INFO)
DECLARE_MTYPE(PIM_SPT_PLIST_NAME);

#endif /* _QUAGGA_PIM_MEMORY_H */
