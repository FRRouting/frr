// SPDX-License-Identifier: GPL-2.0-or-later
/* E-VPN attribute handling structure file
 * Copyright (C) 2016 6WIND
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
	unsigned long refcnt;
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
extern uint32_t bgp_attr_mac_mobility_seqnum(struct attr *attr);
extern void bgp_attr_default_gw(struct attr *attr);

extern void bgp_attr_evpn_na_flag(struct attr *attr, bool *proxy);
extern uint16_t bgp_attr_df_pref_from_ec(struct attr *attr, uint8_t *alg);


extern bool bgp_route_evpn_same(const struct bgp_route_evpn *e1,
				const struct bgp_route_evpn *e2);
#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
