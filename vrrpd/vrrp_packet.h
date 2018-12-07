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

/*
 * Shared header for VRRPv2/v3 packets.
 */
struct vrrp_hdr {
	/*
	 * H  L H  L
	 * 0000 0000
	 * ver  type
	 */
	uint8_t vertype;
	uint8_t vrid;
	uint8_t priority;
	uint8_t naddr;
	union {
		struct {
			uint8_t auth_type;
			/* advertisement interval (in sec) */
			uint8_t adver_int;
		} v2;
		struct {
			/*
			 * advertisement interval (in centiseconds)
			 * H  L H          L
			 * 0000 000000000000
			 * rsvd adver_int
			 */
			uint16_t adver_int;
		} v3;
	};
	uint16_t chksum;
};

struct vrrp_pkt {
	struct vrrp_hdr hdr;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addrs[];
} __attribute((packed, aligned(1)));

/*
 * Builds a VRRP packet.
 *
 * pkt
 *    Pointer to store pointer to result buffer in
 *
 * vrid
 *    Virtual Router Identifier
 *
 * prio
 *    Virtual Router Priority
 *
 * max_adver_int
 *    time between ADVERTISEMENTs
 *
 * v6
 *    whether 'ips' is an array of v4 or v6 addresses
 *
 * numip
 *    number of IPvX addresses in 'ips'
 *
 * ips
 *    array of pointer to either struct in_addr (v6 = false) or struct in6_addr
 *    (v6 = true)
 */
ssize_t vrrp_pkt_build(struct vrrp_pkt **pkt, uint8_t vrid, uint8_t prio,
		       uint16_t max_adver_int, bool v6, uint8_t numip,
		       void **ips);
