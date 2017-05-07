/* eigrpd memory type definitions
 *
 * Copyright (C) 2017  Donald Sharp
 *
 * This file is part of FRR
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eigrp_memory.h"

DEFINE_MGROUP(EIGRPD, "eigrpd")
DEFINE_MTYPE(EIGRPD, EIGRP_TOP,             "EIGRP structure")
DEFINE_MTYPE(EIGRPD, EIGRP_IF,              "EIGRP interface")
DEFINE_MTYPE(EIGRPD, EIGRP_NEIGHBOR,        "EIGRP neighbor")
DEFINE_MTYPE(EIGRPD, EIGRP_IF_PARAMS,       "EIGRP Interface Parameters")
DEFINE_MTYPE(EIGRPD, EIGRP_IF_INFO,         "EIGRP Interface Information")
DEFINE_MTYPE(EIGRPD, EIGRP_FIFO,            "EIGRP FIFO")
DEFINE_MTYPE(EIGRPD, EIGRP_PACKET,          "EIGRP Packet")
DEFINE_MTYPE(EIGRPD, EIGRP_IPV4_INT_TLV,    "EIGRP IPv4 TLV")
DEFINE_MTYPE(EIGRPD, EIGRP_SEQ_TLV,         "EIGRP SEQ TLV")
DEFINE_MTYPE(EIGRPD, EIGRP_AUTH_TLV,        "EIGRP AUTH TLV")
DEFINE_MTYPE(EIGRPD, EIGRP_AUTH_SHA256_TLV, "EIGRP SHA TLV")
DEFINE_MTYPE(EIGRPD, EIGRP_PREFIX_ENTRY,    "EIGRP Prefix")
DEFINE_MTYPE(EIGRPD, EIGRP_NEIGHBOR_ENTRY,  "EIGRP Neighbor Entry")
DEFINE_MTYPE(EIGRPD, EIGRP_FSM_MSG,         "EIGRP FSM Message")
