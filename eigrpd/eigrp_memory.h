/* eigrpd memory type declarations
 *
 * Copyright (C) 2017  Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_EIGRP_MEMORY_H
#define _FRR_EIGRP_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(EIGRPD)
DECLARE_MTYPE(EIGRP_TOP)
DECLARE_MTYPE(EIGRP_IF)
DECLARE_MTYPE(EIGRP_NEIGHBOR)
DECLARE_MTYPE(EIGRP_IF_PARAMS)
DECLARE_MTYPE(EIGRP_IF_INFO)
DECLARE_MTYPE(EIGRP_FIFO)
DECLARE_MTYPE(EIGRP_PACKET)
DECLARE_MTYPE(EIGRP_IPV4_INT_TLV)
DECLARE_MTYPE(EIGRP_SEQ_TLV)
DECLARE_MTYPE(EIGRP_AUTH_TLV)
DECLARE_MTYPE(EIGRP_AUTH_SHA256_TLV)
DECLARE_MTYPE(EIGRP_PREFIX_ENTRY)
DECLARE_MTYPE(EIGRP_NEXTHOP_ENTRY)
DECLARE_MTYPE(EIGRP_FSM_MSG)

#endif /* _FRR_EIGRP_MEMORY_H */
