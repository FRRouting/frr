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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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
DECLARE_MTYPE(OSPF6_LSA_SUMMARY)
DECLARE_MTYPE(OSPF6_LSDB)
DECLARE_MTYPE(OSPF6_VERTEX)
DECLARE_MTYPE(OSPF6_SPFTREE)
DECLARE_MTYPE(OSPF6_NEXTHOP)
DECLARE_MTYPE(OSPF6_EXTERNAL_INFO)
DECLARE_MTYPE(OSPF6_OTHER)

#endif /* _QUAGGA_OSPF6_MEMORY_H */
