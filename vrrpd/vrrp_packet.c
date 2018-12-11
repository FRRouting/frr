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

#include "lib/memory.h"
#include "lib/ipaddr.h"
#include "lib/checksum.h"

#include "vrrp_packet.h"

ssize_t vrrp_pkt_build(struct vrrp_pkt **pkt, uint8_t vrid, uint8_t prio,
		       uint16_t max_adver_int, uint8_t numip,
		       struct ipaddr **ips)
{
	bool v6 = IS_IPADDR_V6(ips[0]);

	size_t addrsz = v6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	size_t pktsize = sizeof(struct vrrp_hdr) + addrsz * numip;
	*pkt = XCALLOC(MTYPE_TMP, pktsize);

	(*pkt)->hdr.vertype |= VRRP_VERSION << 4;
	(*pkt)->hdr.vertype |= VRRP_TYPE_ADVERTISEMENT;
	(*pkt)->hdr.vrid = vrid;
	(*pkt)->hdr.priority = prio;
	(*pkt)->hdr.naddr = numip;
	(*pkt)->hdr.v3.adver_int = htons(max_adver_int);

	uint8_t *aptr = (void *)(*pkt)->addrs;

	for (int i = 0; i < numip; i++) {
		memcpy(aptr, &ips[i]->ip.addr, addrsz);
		aptr += addrsz;
	}
	(*pkt)->hdr.chksum = 0;

	uint16_t chksum = in_cksum(*pkt, pktsize);
	(*pkt)->hdr.chksum = htons(chksum);

	return pktsize;
}
