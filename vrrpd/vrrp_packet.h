/*
 * VRRPD packet crafting
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "memory.h"
#include "ipaddr.h"
#include "prefix.h"

#define VRRP_VERSION 3
#define VRRP_TYPE_ADVERTISEMENT 1

struct vrrp_pkt {
	uint8_t version : 4;
	uint8_t type : 4;
	uint8_t vrid;
	uint8_t priority;
	uint8_t num_ip;
	uint16_t rsvd : 4;
	uint16_t max_adver_int : 12;
	uint16_t cksum;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addrs[];
} __attribute((packed, aligned(1)));

/*
 * Builds a VRRP packet.
 */
struct vrrp_pkt *vrrp_pkt_build(uint8_t vrid, uint8_t prio,
				uint16_t max_adver_int, bool v6, uint8_t numip,
				void **ips);
