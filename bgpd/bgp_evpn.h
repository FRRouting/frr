// SPDX-License-Identifier: GPL-2.0-or-later
/* E-VPN header for packet handling
 * Copyright (C) 2016 6WIND
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

static inline int advertise_type5_routes(struct bgp *bgp_vrf,
					 afi_t afi)
{
	if (!bgp_vrf->l3vni)
		return 0;

	if ((afi == AFI_IP)
	    && ((CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			    BGP_L2VPN_EVPN_ADV_IPV4_UNICAST))
		|| (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP))))
		return 1;

	if ((afi == AFI_IP6)
	    && ((CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			    BGP_L2VPN_EVPN_ADV_IPV6_UNICAST))
		|| (CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))))
		return 1;

	return 0;
}

/* Flag if the route's parent is a EVPN route. */
static inline struct bgp_path_info *
get_route_parent_evpn(struct bgp_path_info *ri)
{
	struct bgp_path_info *parent_ri;

	/* If not imported (or doesn't have a parent), bail. */
	if (ri->sub_type != BGP_ROUTE_IMPORTED || !ri->extra ||
	    !ri->extra->vrfleak || !ri->extra->vrfleak->parent)
		return NULL;

	/* Determine parent recursively */
	for (parent_ri = ri->extra->vrfleak->parent;
	     parent_ri->extra && parent_ri->extra->vrfleak &&
	     parent_ri->extra->vrfleak->parent;
	     parent_ri = parent_ri->extra->vrfleak->parent)
		;

	return parent_ri;
}

/* Flag if the route's parent is a EVPN route. */
static inline int is_route_parent_evpn(struct bgp_path_info *ri)
{
	struct bgp_path_info *parent_ri;
	struct bgp_table *table;
	struct bgp_dest *dest;

	parent_ri = get_route_parent_evpn(ri);
	if (!parent_ri)
		return 0;

	/* See if of family L2VPN/EVPN */
	dest = parent_ri->net;
	if (!dest)
		return 0;
	table = bgp_dest_table(dest);
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

static inline bool evpn_resolve_overlay_index(void)
{
	struct bgp *bgp = NULL;

	bgp = bgp_get_evpn();
	return bgp ? bgp->resolve_overlay_index : false;
}

extern void bgp_evpn_advertise_type5_route(struct bgp *bgp_vrf,
					   const struct prefix *p,
					   struct attr *src_attr, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_withdraw_type5_route(struct bgp *bgp_vrf,
					  const struct prefix *p, afi_t afi,
					  safi_t safi);
extern void bgp_evpn_withdraw_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_advertise_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					    safi_t safi);
extern void bgp_evpn_vrf_delete(struct bgp *bgp_vrf);
extern void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw);
extern char *bgp_evpn_label2str(mpls_label_t *label, uint8_t num_labels,
				char *buf, int len);
extern void bgp_evpn_route2json(const struct prefix_evpn *p, json_object *json);
extern void bgp_evpn_encode_prefix(struct stream *s, const struct prefix *p,
				   const struct prefix_rd *prd,
				   mpls_label_t *label, uint8_t num_labels,
				   struct attr *attr, bool addpath_capable,
				   uint32_t addpath_tx_id);
extern int bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
			       struct bgp_nlri *packet, bool withdraw);
extern int bgp_evpn_import_route(struct bgp *bgp, afi_t afi, safi_t safi,
				 const struct prefix *p,
				 struct bgp_path_info *ri);
extern int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
				   const struct prefix *p,
				   struct bgp_path_info *ri);
extern void
bgp_reimport_evpn_routes_upon_macvrf_soo_change(struct bgp *bgp,
						struct ecommunity *old_soo,
						struct ecommunity *new_soo);
extern void bgp_reimport_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type, void *old_martian,
	void *new_martian);
extern void
bgp_filter_evpn_routes_upon_martian_change(struct bgp *bgp,
					   enum bgp_martian_type martian_type);
extern int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
					int state);
extern int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
				    uint8_t flags, uint32_t seq, esi_t *esi);
extern int bgp_evpn_local_l3vni_add(vni_t vni, vrf_id_t vrf_id,
				    struct ethaddr *rmac,
				    struct ethaddr *vrr_rmac,
				    struct in_addr originator_ip, int filter,
				    ifindex_t svi_ifindex, bool is_anycast_mac);
extern int bgp_evpn_local_l3vni_del(vni_t vni, vrf_id_t vrf_id);
extern void bgp_evpn_instance_down(struct bgp *bgp);
extern int bgp_evpn_local_vni_del(struct bgp *bgp, vni_t vni);
extern int bgp_evpn_local_vni_add(struct bgp *bgp, vni_t vni,
				  struct in_addr originator_ip,
				  vrf_id_t tenant_vrf_id,
				  struct in_addr mcast_grp,
				  ifindex_t svi_ifindex);
extern void bgp_evpn_flood_control_change(struct bgp *bgp);
extern void bgp_evpn_cleanup_on_disable(struct bgp *bgp);
extern void bgp_evpn_cleanup(struct bgp *bgp);
extern void bgp_evpn_init(struct bgp *bgp);
extern int bgp_evpn_get_type5_prefixlen(const struct prefix *pfx);
extern bool bgp_evpn_is_prefix_nht_supported(const struct prefix *pfx);
extern void update_advertise_vrf_routes(struct bgp *bgp_vrf);
extern void bgp_evpn_show_remote_ip_hash(struct hash_bucket *bucket,
					 void *args);
extern void bgp_evpn_show_vni_svi_hash(struct hash_bucket *bucket, void *args);
extern bool bgp_evpn_is_gateway_ip_resolved(struct bgp_nexthop_cache *bnc);
extern void
bgp_evpn_handle_resolve_overlay_index_set(struct hash_bucket *bucket,
					  void *arg);
extern void
bgp_evpn_handle_resolve_overlay_index_unset(struct hash_bucket *bucket,
					    void *arg);
extern mpls_label_t *bgp_evpn_path_info_labels_get_l3vni(mpls_label_t *labels,
							 uint8_t num_labels);
extern vni_t bgp_evpn_path_info_get_l3vni(const struct bgp_path_info *pi);
extern bool bgp_evpn_mpath_has_dvni(const struct bgp *bgp_vrf,
				    struct bgp_path_info *mpinfo);
extern bool is_route_injectable_into_evpn(struct bgp_path_info *pi);
extern bool is_route_injectable_into_evpn_non_supp(struct bgp_path_info *pi);
extern void bgp_aggr_supp_withdraw_from_evpn(struct bgp *bgp, afi_t afi,
					     safi_t safi);

extern enum zclient_send_status evpn_zebra_install(struct bgp *bgp,
						   struct bgpevpn *vpn,
						   const struct prefix_evpn *p,
						   struct bgp_path_info *pi);
extern enum zclient_send_status
evpn_zebra_uninstall(struct bgp *bgp, struct bgpevpn *vpn,
		     const struct prefix_evpn *p, struct bgp_path_info *pi,
		     bool is_sync);
#endif /* _QUAGGA_BGP_EVPN_H */
