/* E-VPN header for packet handling
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

#ifndef _QUAGGA_BGP_EVPN_H
#define _QUAGGA_BGP_EVPN_H

#include "vxlan.h"
#include "bgpd.h"

#define EVPN_ROUTE_STRLEN 200 /* Must be >> MAC + IPv6 strings. */

static inline int is_evpn_enabled(void)
{
	struct bgp *bgp = NULL;

	bgp = bgp_get_default();
	return bgp ? bgp->advertise_all_vni : 0;
}

static inline void vni2label(vni_t vni, mpls_label_t *label)
{
	u_char *tag = (u_char *)label;

	tag[0] = (vni >> 16) & 0xFF;
	tag[1] = (vni >> 8) & 0xFF;
	tag[2] = vni & 0xFF;
}

static inline vni_t label2vni(mpls_label_t *label)
{
	u_char *tag = (u_char *)label;
	vni_t vni;

	vni = ((u_int32_t)*tag++ << 16);
	vni |= (u_int32_t)*tag++ << 8;
	vni |= (u_int32_t)(*tag & 0xFF);

	return vni;
}

extern void bgp_evpn_advertise_type5_route(struct bgp *bgp_vrf,
					   struct prefix *p,
					   struct attr *src_attr,
					   afi_t afi, safi_t safi);
extern void bgp_evpn_withdraw_type5_route(struct bgp *bgp_vrf,
					  struct prefix *p,
					  afi_t afi, safi_t safi);
extern void bgp_evpn_withdraw_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_advertise_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					    safi_t safi);
extern void bgp_evpn_vrf_delete(struct bgp *bgp_vrf);
extern void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw);
extern char *bgp_evpn_label2str(mpls_label_t *label, u_int32_t num_labels,
				char *buf, int len);
extern char *bgp_evpn_route2str(struct prefix_evpn *p, char *buf, int len);
extern void bgp_evpn_route2json(struct prefix_evpn *p, json_object *json);
extern void bgp_evpn_encode_prefix(struct stream *s, struct prefix *p,
				   struct prefix_rd *prd,
				   mpls_label_t *label, u_int32_t num_labels,
				   struct attr *attr, int addpath_encode,
				   u_int32_t addpath_tx_id);
extern int bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
			       struct bgp_nlri *packet, int withdraw);
extern int bgp_evpn_import_route(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct prefix *p, struct bgp_info *ri);
extern int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
				   struct prefix *p, struct bgp_info *ri);
extern int bgp_filter_evpn_routes_upon_martian_nh_change(struct bgp *bgp);
extern int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip);
extern int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
				    u_char flags);
extern int bgp_evpn_local_l3vni_add(vni_t vni, vrf_id_t vrf_id,
				    struct ethaddr *rmac,
				    struct in_addr originator_ip);
extern int bgp_evpn_local_l3vni_del(vni_t vni, vrf_id_t vrf_id);
extern int bgp_evpn_local_vni_del(struct bgp *bgp, vni_t vni);
extern int bgp_evpn_local_vni_add(struct bgp *bgp, vni_t vni,
				  struct in_addr originator_ip,
				  vrf_id_t tenant_vrf_id);
extern void bgp_evpn_cleanup_on_disable(struct bgp *bgp);
extern void bgp_evpn_cleanup(struct bgp *bgp);
extern void bgp_evpn_init(struct bgp *bgp);

#endif /* _QUAGGA_BGP_EVPN_H */
