/* isisd memory type declarations
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

#ifndef _QUAGGA_ISIS_MEMORY_H
#define _QUAGGA_ISIS_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(ISISD)
DECLARE_MTYPE(ISIS)
DECLARE_MTYPE(ISIS_TMP)
DECLARE_MTYPE(ISIS_CIRCUIT)
DECLARE_MTYPE(ISIS_LSP)
DECLARE_MTYPE(ISIS_ADJACENCY)
DECLARE_MTYPE(ISIS_AREA)
DECLARE_MTYPE(ISIS_AREA_ADDR)
DECLARE_MTYPE(ISIS_TLV)
DECLARE_MTYPE(ISIS_DYNHN)
DECLARE_MTYPE(ISIS_SPFTREE)
DECLARE_MTYPE(ISIS_VERTEX)
DECLARE_MTYPE(ISIS_ROUTE_INFO)
DECLARE_MTYPE(ISIS_NEXTHOP)
DECLARE_MTYPE(ISIS_NEXTHOP6)
DECLARE_MTYPE(ISIS_DICT)
DECLARE_MTYPE(ISIS_DICT_NODE)
DECLARE_MTYPE(ISIS_EXT_ROUTE)
DECLARE_MTYPE(ISIS_EXT_INFO)
DECLARE_MTYPE(ISIS_MPLS_TE)

#endif /* _QUAGGA_ISIS_MEMORY_H */
