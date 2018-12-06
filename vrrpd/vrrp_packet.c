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

#include "vrrp_packet.h"

/*
 * Builds a VRRP packet.
 */
struct vrrp_pkt *vrrp_pkt_build(uint8_t vrid, uint8_t prio,
				uint16_t max_adver_int, bool v6, uint8_t numip,
				void **ips)
{
	size_t addrsz = v6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	struct vrrp_pkt *pkt =
		XCALLOC(MTYPE_TMP, sizeof(struct vrrp_pkt) + addrsz * numip);

	pkt->hdr.version = VRRP_VERSION;
	pkt->hdr.type = VRRP_TYPE_ADVERTISEMENT;
	pkt->hdr.vrid = vrid;
	pkt->hdr.priority = prio;
	pkt->hdr.v3.rsvd = 0;
	pkt->hdr.v3.adver_int = max_adver_int;
	for (uint8_t i = 0; i < numip; i++)
		memcpy(&pkt->addrs[i].v4, ips[i], addrsz);
	/* FIXME */
	pkt->hdr.chksum = 0;

	return pkt;
}
