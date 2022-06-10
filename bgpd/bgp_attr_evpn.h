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

#define MAX_ET 0xffffffff

struct attr;

enum overlay_index_type {
	OVERLAY_INDEX_TYPE_NONE,
	OVERLAY_INDEX_GATEWAY_IP,
	OVERLAY_INDEX_ESI,
	OVERLAY_INDEX_MAC,
};

/*
 * Structure to store ovrelay index for EVPN type-5 route
 * This structure stores ESI and Gateway IP overlay index.
 * MAC overlay index is stored in the RMAC attribute.
 */
struct bgp_route_evpn {
	enum overlay_index_type type;
	esi_t eth_s_id;
	struct ipaddr gw_ip;
};

extern bool str2esi(const char *str, esi_t *id);
extern char *ecom_mac2str(char *ecom_mac);

extern void bgp_add_routermac_ecom(struct attr *attr,
				   struct ethaddr *routermac);
extern int bgp_build_evpn_prefix(int type, uint32_t eth_tag,
				 struct prefix *dst);
extern bool bgp_attr_rmac(struct attr *attr, struct ethaddr *rmac);
extern uint32_t bgp_attr_mac_mobility_seqnum(struct attr *attr,
					     uint8_t *sticky);
extern uint8_t bgp_attr_default_gw(struct attr *attr);

extern void bgp_attr_evpn_na_flag(struct attr *attr, uint8_t *router_flag,
		bool *proxy);
extern uint16_t bgp_attr_df_pref_from_ec(struct attr *attr, uint8_t *alg);


extern bool bgp_route_evpn_same(const struct bgp_route_evpn *e1,
				const struct bgp_route_evpn *e2);
#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
