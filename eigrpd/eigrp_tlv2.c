/*
 * EIGRP Packet Processor for EIGRP TLV2
 * Copyright (C) 2018
 * Authors:
 *   Donnie Savage
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_types.h"
#include "eigrpd/eigrp_structs.h"

#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_topology.h"

static uint16_t eigrp_tlv2_decoder(eigrp_t *eigrp, eigrp_neighbor_t *nbr,
				   eigrp_stream_t *pkt, uint16_t pktlen,
				   eigrp_route_descriptor_t *route)
{
    return 0;
}

static uint16_t eigrp_tlv2_encoder(eigrp_t *eigrp, eigrp_neighbor_t *nbr,
				   eigrp_stream_t *pkt, uint16_t pktlen,
				   eigrp_route_descriptor_t *route)
{
    return 0;
}

void eigrp_tlv2_init(eigrp_neighbor_t *nbr)
{
    // setup vectors for processing Version 2 TLVs
    nbr->tlv_decoder = &eigrp_tlv2_decoder;
    nbr->tlv_encoder = &eigrp_tlv2_encoder;
}

