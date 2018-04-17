/* E-VPN attribute handling structure file
 * Copyright (C) 2016 6WIND
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_ATTR_EVPN_H
#define _QUAGGA_BGP_ATTR_EVPN_H

/* value of first byte of ESI */
#define ESI_TYPE_ARBITRARY 0  /* */
#define ESI_TYPE_LACP      1  /* <> */
#define ESI_TYPE_BRIDGE    2  /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ESI_TYPE_MAC       3  /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ESI_TYPE_ROUTER    4  /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ESI_TYPE_AS        5  /* <AS-4B>:<Local Discriminator Value-4B> */

#define MAX_ESI {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}
#define ESI_LEN 10

#define MAX_ET 0xffffffff

unsigned long eth_tag_id;
struct attr;

/* EVPN ESI */
struct eth_segment_id {
	uint8_t val[ESI_LEN];
};

union gw_addr {
	struct in_addr ipv4;
	struct in6_addr ipv6;
};

struct bgp_route_evpn {
	struct eth_segment_id eth_s_id;
	union gw_addr gw_ip;
};

extern int str2esi(const char *str, struct eth_segment_id *id);
extern char *esi2str(struct eth_segment_id *id);
extern char *ecom_mac2str(char *ecom_mac);

extern void bgp_add_routermac_ecom(struct attr *attr,
				   struct ethaddr *routermac);
extern int bgp_build_evpn_prefix(int type, uint32_t eth_tag,
				 struct prefix *dst);
extern void bgp_attr_rmac(struct attr *attr, struct ethaddr *rmac);
extern uint32_t bgp_attr_mac_mobility_seqnum(struct attr *attr,
					     uint8_t *sticky);
extern uint8_t bgp_attr_default_gw(struct attr *attr);

#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
