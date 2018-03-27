/* BGP RD definitions for BGP-based VPNs (IP/EVPN)
 * -- brought over from bgpd/bgp_mplsvpn.h
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_RD_H
#define _QUAGGA_BGP_RD_H

/* RD types */
#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2

#if ENABLE_BGP_VNC
#define RD_TYPE_VNC_ETH	0xff00  /* VNC L2VPN */
#endif

#define RD_ADDRSTRLEN  28

struct rd_as {
	uint16_t type;
	as_t as;
	uint32_t val;
};

struct rd_ip {
	uint16_t type;
	struct in_addr ip;
	uint16_t val;
};

#if ENABLE_BGP_VNC
struct rd_vnc_eth {
	uint16_t type;
	uint8_t local_nve_id;
	struct ethaddr macaddr;
};
#endif

extern uint16_t decode_rd_type(uint8_t *pnt);
extern void encode_rd_type(uint16_t, uint8_t *);

extern void decode_rd_as(uint8_t *pnt, struct rd_as *rd_as);
extern void decode_rd_as4(uint8_t *pnt, struct rd_as *rd_as);
extern void decode_rd_ip(uint8_t *pnt, struct rd_ip *rd_ip);
#if ENABLE_BGP_VNC
extern void decode_rd_vnc_eth(uint8_t *pnt, struct rd_vnc_eth *rd_vnc_eth);
#endif

extern int str2prefix_rd(const char *, struct prefix_rd *);
extern char *prefix_rd2str(struct prefix_rd *, char *, size_t);
extern void form_auto_rd(struct in_addr router_id, uint16_t rd_id,
			 struct prefix_rd *prd);

#endif /* _QUAGGA_BGP_RD_H */
