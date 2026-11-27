// SPDX-License-Identifier: GPL-2.0-or-later
/* E-VPN attribute handling structure file
 * Copyright (C) 2016 6WIND
 */

#ifndef _QUAGGA_BGP_ATTR_EVPN_H
#define _QUAGGA_BGP_ATTR_EVPN_H

#define MAX_ET 0xffffffff

struct attr;

/*
 * The overlay index an EVPN RT-5 carries in its NLRI (RFC 9136, 3.2), as
 * received, or as set locally to be advertised. It selects which NLRI field
 * is encoded, ESI or GW IP. It does not say how the route is resolved. Only
 * a GW IP is resolved recursively, see install_evpn_route_entry_in_vrf().
 * ESI and MAC overlay indices are NOT SUPPORTED.
 */
enum overlay_index_type {
	/*
	 * Neither ESI nor GW IP. The route may still carry a Router's MAC,
	 * which is used without recursive resolution.
	 */
	OVERLAY_INDEX_TYPE_NONE,
	/* GW IP set, resolved recursively via an RT-2. The only one supported. */
	OVERLAY_INDEX_GATEWAY_IP,
	/*
	 * ESSENTIALLY UNSUPPORTED. The ESI is parsed from the NLRI, but never
	 * recursively resolved via RT-1. The route is installed via its BGP
	 * next hop, as without overlay index. Re-advertising encodes
	 * attr->esi, not the parsed ESI.
	 */
	OVERLAY_INDEX_ESI,
	/*
	 * UNUSED and NOT SUPPORTED. Nothing sets it. The Router's MAC is
	 * kept in the RMAC attribute and never resolved as overlay index.
	 */
	OVERLAY_INDEX_MAC,
};

/*
 * Structure to store the overlay index of EVPN type-5 routes
 * This structure stores ESI and Gateway IP overlay index.
 * The Router's MAC is stored in the RMAC attribute.
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
extern bool bgp_attr_esi_label(struct attr *attr, mpls_label_t *label);
extern uint32_t bgp_attr_mac_mobility_seqnum(struct attr *attr);
extern void bgp_attr_default_gw(struct attr *attr);

extern void bgp_attr_evpn_na_flag(struct attr *attr, bool *proxy);
extern uint16_t bgp_attr_df_pref_from_ec(struct attr *attr, uint8_t *alg);


extern bool bgp_route_evpn_same(const struct bgp_route_evpn *e1,
				const struct bgp_route_evpn *e2);
#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
