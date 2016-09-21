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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pim_memory.h"

DEFINE_MGROUP(PIMD, "pimd")
DEFINE_MTYPE(PIMD, PIM_CHANNEL_OIL,       "PIM SSM (S,G) channel OIL")
DEFINE_MTYPE(PIMD, PIM_INTERFACE,         "PIM interface")
DEFINE_MTYPE(PIMD, PIM_IGMP_JOIN,         "PIM interface IGMP static join")
DEFINE_MTYPE(PIMD, PIM_IGMP_SOCKET,       "PIM interface IGMP socket")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP,        "PIM interface IGMP group")
DEFINE_MTYPE(PIMD, PIM_IGMP_GROUP_SOURCE, "PIM interface IGMP source")
DEFINE_MTYPE(PIMD, PIM_NEIGHBOR,          "PIM interface neighbor")
DEFINE_MTYPE(PIMD, PIM_IFCHANNEL,         "PIM interface (S,G) state")
DEFINE_MTYPE(PIMD, PIM_UPSTREAM,          "PIM upstream (S,G) state")
DEFINE_MTYPE(PIMD, PIM_SSMPINGD,          "PIM sspimgd socket")
DEFINE_MTYPE(PIMD, PIM_STATIC_ROUTE,      "PIM Static Route")
DEFINE_MTYPE(PIMD, PIM_BR,                "PIM Bridge Router info")
