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
#define EVPN_AUTORT_VXLAN 0x10000000

#define EVPN_ENABLED(bgp)  (bgp)->advertise_all_vni
static inline int is_evpn_enabled(void)
{
	struct bgp *bgp = NULL;

	bgp = bgp_get_evpn();
	return bgp ? EVPN_ENABLED(bgp) : 0;
}

static inline void vni2label(vni_t vni, mpls_label_t *label)
{
	uint8_t *tag = (uint8_t *)label;

	tag[0] = (vni >> 16) & 0xFF;
	tag[1] = (vni >> 8) & 0xFF;
	tag[2] = vni & 0xFF;
}

static inline vni_t label2vni(mpls_label_t *label)
{
	uint8_t *tag = (uint8_t *)label;
	vni_t vni;

	vni = ((uint32_t)*tag++ << 16);
	vni |= (uint32_t)*tag++ << 8;
	vni |= (uint32_t)(*tag & 0xFF);

	return vni;
}

static inline int advertise_type5_routes(struct bgp *bgp_vrf,
					 afi_t afi)
{
	if (!bgp_vrf->l3vni)
		return 0;

	if (afi == AFI_IP &&
	    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADVERTISE_IPV4_UNICAST))
		return 1;

	if (afi == AFI_IP6 &&
	    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADVERTISE_IPV6_UNICAST))
		return 1;

	return 0;
}

/* Flag if the route's parent is a EVPN route. */
static inline int is_route_parent_evpn(struct bgp_path_info *ri)
{
	struct bgp_path_info *parent_ri;
	struct bgp_table *table;
	struct bgp_node *rn;

	/* If not imported (or doesn't have a parent), bail. */
	if (ri->sub_type != BGP_ROUTE_IMPORTED ||
	    !ri->extra ||
	    !ri->extra->parent)
		return 0;

	/* Determine parent recursively */
	for (parent_ri = ri->extra->parent;
	     parent_ri->extra && parent_ri->extra->parent;
	     parent_ri = parent_ri->extra->parent)
		;

	/* See if of family L2VPN/EVPN */
	rn = parent_ri->net;
	if (!rn)
		return 0;
	table = bgp_node_table(rn);
	if (table &&
	    table->afi == AFI_L2VPN &&
	    table->safi == SAFI_EVPN)
		return 1;
	return 0;
}

/* Flag if the route path's family is EVPN. */
static inline bool is_pi_family_evpn(struct bgp_path_info *pi)
{
	return is_pi_family_matching(pi, AFI_L2VPN, SAFI_EVPN);
}

/* Flag if the route is injectable into EVPN. This would be either a
 * non-imported route or a non-EVPN imported route.
 */
static inline bool is_route_injectable_into_evpn(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent_pi;
	struct bgp_table *table;
	struct bgp_node *rn;

	if (pi->sub_type != BGP_ROUTE_IMPORTED ||
	    !pi->extra ||
	    !pi->extra->parent)
		return true;

	parent_pi = (struct bgp_path_info *)pi->extra->parent;
	rn = parent_pi->net;
	if (!rn)
		return true;
	table = bgp_node_table(rn);
	if (table &&
	    table->afi == AFI_L2VPN &&
	    table->safi == SAFI_EVPN)
		return false;
	return true;
}

extern void bgp_evpn_advertise_type5_route(struct bgp *bgp_vrf,
					   struct prefix *p,
					   struct attr *src_attr, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_withdraw_type5_route(struct bgp *bgp_vrf, struct prefix *p,
					  afi_t afi, safi_t safi);
extern void bgp_evpn_withdraw_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_advertise_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					    safi_t safi);
extern void bgp_evpn_vrf_delete(struct bgp *bgp_vrf);
extern void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw);
extern char *bgp_evpn_label2str(mpls_label_t *label, uint32_t num_labels,
				char *buf, int len);
extern char *bgp_evpn_route2str(struct prefix_evpn *p, char *buf, int len);
extern void bgp_evpn_route2json(struct prefix_evpn *p, json_object *json);
extern void bgp_evpn_encode_prefix(struct stream *s, struct prefix *p,
				   struct prefix_rd *prd, mpls_label_t *label,
				   uint32_t num_labels, struct attr *attr,
				   int addpath_encode, uint32_t addpath_tx_id);
extern int bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
			       struct bgp_nlri *packet, int withdraw);
extern int bgp_evpn_import_route(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct prefix *p, struct bgp_path_info *ri);
extern int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
				   struct prefix *p, struct bgp_path_info *ri);
extern int bgp_filter_evpn_routes_upon_martian_nh_change(struct bgp *bgp);
extern int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
					int state);
extern int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
				    uint8_t flags, uint32_t seq);
extern int bgp_evpn_local_l3vni_add(vni_t vni, vrf_id_t vrf_id,
				    struct ethaddr *rmac,
				    struct ethaddr *vrr_rmac,
				    struct in_addr originator_ip, int filter,
				    ifindex_t svi_ifindex, bool is_anycast_mac);
extern int bgp_evpn_local_l3vni_del(vni_t vni, vrf_id_t vrf_id);
extern int bgp_evpn_local_vni_del(struct bgp *bgp, vni_t vni);
extern int bgp_evpn_local_vni_add(struct bgp *bgp, vni_t vni,
				  struct in_addr originator_ip,
				  vrf_id_t tenant_vrf_id,
				  struct in_addr mcast_grp);
extern int bgp_evpn_local_es_add(struct bgp *bgp, esi_t *esi,
				 struct ipaddr *originator_ip);
extern int bgp_evpn_local_es_del(struct bgp *bgp, esi_t *esi,
				 struct ipaddr *originator_ip);
extern void bgp_evpn_flood_control_change(struct bgp *bgp);
extern void bgp_evpn_cleanup_on_disable(struct bgp *bgp);
extern void bgp_evpn_cleanup(struct bgp *bgp);
extern void bgp_evpn_init(struct bgp *bgp);
extern int bgp_evpn_get_type5_prefixlen(struct prefix *pfx);
extern bool bgp_evpn_is_prefix_nht_supported(struct prefix *pfx);
extern void update_advertise_vrf_routes(struct bgp *bgp_vrf);

#endif /* _QUAGGA_BGP_EVPN_H */
