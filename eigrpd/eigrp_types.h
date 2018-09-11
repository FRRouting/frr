/*
 * EIGRP Definition of Data Types
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

#ifndef _ZEBRA_EIGRP_TYPES_H_
#define _ZEBRA_EIGRP_TYPES_H_

#include "eigrpd/eigrp_const.h"
#include "eigrpd/eigrp_macros.h"


/**
 * Nice type modifers to make code more readable (and maybe portable)
 */
typedef struct in_addr			eigrp_addr_t;
typedef struct stream			eigrp_stream_t;

typedef uint64_t			eigrp_bandwidth_t;
typedef uint64_t			eigrp_delay_t;
typedef uint64_t			eigrp_metric_t;
typedef uint32_t			eigrp_scaled_t;

typedef uint32_t			eigrp_system_metric_t;
typedef uint32_t			eigrp_system_delay_t;
typedef uint32_t			eigrp_system_bandwidth_t;

/**
 * define some primitive types for use in pointer passing. This will allow for
 * better type  checking, especially when dealing with classic metrics (32bit)
 * and wide metrics (64bit).
 *
 * If you need structure details, include the appropriate header file
 */
typedef struct eigrp			eigrp_t;

typedef struct eigrp_interface		eigrp_interface_t;
typedef struct eigrp_neighbor		eigrp_neighbor_t;
typedef struct eigrp_vmetrics		eigrp_vmetrics_t;
typedef struct eigrp_prefix_descriptor	eigrp_prefix_descriptor_t;
typedef struct eigrp_route_descriptor	eigrp_route_descriptor_t;

// basic packet processor definitions
typedef struct eigrp_tlv_header		eigrp_tlv_header_t;
typedef uint16_t (*eigrp_tlv_decoder_t)(eigrp_t *eigrp, eigrp_neighbor_t *nbr,
					eigrp_stream_t *pkt, uint16_t pktlen,
					eigrp_route_descriptor_t *route);
typedef uint16_t (*eigrp_tlv_encoder_t)(eigrp_t *eigrp, eigrp_neighbor_t *nbr,
					eigrp_stream_t *pkt, uint16_t pktlen,
					eigrp_route_descriptor_t *route);

#endif /* _ZEBRA_EIGRP_TYPES_H_ */
