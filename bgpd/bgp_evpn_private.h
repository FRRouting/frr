/* BGP EVPN internal definitions
 * Copyright (C) 2017 Cumulus Networks, Inc.
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

#ifndef _BGP_EVPN_PRIVATE_H
#define _BGP_EVPN_PRIVATE_H

#include "vxlan.h"
#include "zebra.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"

#define RT_ADDRSTRLEN 28

/* EVPN prefix lengths. This represents the sizeof struct evpn_addr
 * in bits  */
#define EVPN_ROUTE_PREFIXLEN (sizeof(struct evpn_addr) * 8)

/* EVPN route types. */
typedef enum {
	BGP_EVPN_AD_ROUTE = 1,    /* Ethernet Auto-Discovery (A-D) route */
	BGP_EVPN_MAC_IP_ROUTE,    /* MAC/IP Advertisement route */
	BGP_EVPN_IMET_ROUTE,      /* Inclusive Multicast Ethernet Tag route */
	BGP_EVPN_ES_ROUTE,	/* Ethernet Segment route */
	BGP_EVPN_IP_PREFIX_ROUTE, /* IP Prefix route */
} bgp_evpn_route_type;

/*
 * Hash table of EVIs. Right now, the only type of EVI supported is with
 * VxLAN encapsulation, hence each EVI corresponds to a L2 VNI.
 * The VNIs are not "created" through BGP but through some other interface
 * on the system. This table stores VNIs that BGP comes to know as present
 * on the system (through interaction with zebra) as well as pre-configured
 * VNIs (which need to be defined in the system to become "live").
 */
struct bgpevpn {
	vni_t vni;
	vrf_id_t tenant_vrf_id;
	uint32_t flags;
#define VNI_FLAG_CFGD              0x1  /* VNI is user configured */
#define VNI_FLAG_LIVE              0x2  /* VNI is "live" */
#define VNI_FLAG_RD_CFGD           0x4  /* RD is user configured. */
#define VNI_FLAG_IMPRT_CFGD        0x8  /* Import RT is user configured */
#define VNI_FLAG_EXPRT_CFGD        0x10 /* Export RT is user configured */
#define VNI_FLAG_USE_TWO_LABELS    0x20 /* Attach both L2-VNI and L3-VNI if
					   needed for this VPN */

	struct bgp *bgp_vrf; /* back pointer to the vrf instance */

					   /* Flag to indicate if we are
					    * advertising the g/w mac ip for
					    * this VNI*/
	uint8_t advertise_gw_macip;

	/* Flag to indicate if we are
	 * advertising subnet for this VNI */
	uint8_t advertise_subnet;

	/* Flag to indicate if we are advertising the svi mac ip for this VNI*/
	uint8_t advertise_svi_macip;

	/* Id for deriving the RD
	 * automatically for this VNI */
	uint16_t rd_id;

	/* RD for this VNI. */
	struct prefix_rd prd;

	/* Route type 3 field */
	struct in_addr originator_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* Import and Export RTs. */
	struct list *import_rtl;
	struct list *export_rtl;

	/* Route table for EVPN routes for
	 * this VNI. */
	struct bgp_table *route_table;

	QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(bgpevpn)

struct evpnes {

	/* Ethernet Segment Identifier */
	esi_t esi;

	/* es flags */
	uint16_t flags;
#define EVPNES_LOCAL	0x01
#define EVPNES_REMOTE	0x02

	/*
	 * Id for deriving the RD
	 * automatically for this ESI
	 */
	uint16_t rd_id;

	/* RD for this VNI. */
	struct prefix_rd prd;

	/* originator ip address  */
	struct ipaddr originator_ip;

	/* list of VTEPs in the same site */
	struct list *vtep_list;

	/*
	 * Route table for EVPN routes for
	 * this ESI. - type4 routes
	 */
	struct bgp_table *route_table;

	QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(evpnes)

/* Mapping of Import RT to VNIs.
 * The Import RTs of all VNIs are maintained in a hash table with each
 * RT linking to all VNIs that will import routes matching this RT.
 */
struct irt_node {
	/* RT */
	struct ecommunity_val rt;

	/* List of VNIs importing routes matching this RT. */
	struct list *vnis;
};

/* Mapping of Import RT to VRFs.
 * The Import RTs of all VRFss are maintained in a hash table with each
 * RT linking to all VRFs that will import routes matching this RT.
 */
struct vrf_irt_node {
	/* RT */
	struct ecommunity_val rt;

	/* List of VNIs importing routes matching this RT. */
	struct list *vrfs;
};


#define RT_TYPE_IMPORT 1
#define RT_TYPE_EXPORT 2
#define RT_TYPE_BOTH   3

#define EVPN_DAD_DEFAULT_TIME 180 /* secs */
#define EVPN_DAD_DEFAULT_MAX_MOVES 5 /* default from RFC 7432 */
#define EVPN_DAD_DEFAULT_AUTO_RECOVERY_TIME 1800 /* secs */

struct bgp_evpn_info {
	/* enable disable dup detect */
	bool dup_addr_detect;

	/* Detection time(M) */
	int dad_time;
	/* Detection max moves(N) */
	uint32_t dad_max_moves;
	/* Permanent freeze */
	bool dad_freeze;
	/* Recovery time */
	uint32_t dad_freeze_time;

	/* EVPN enable - advertise svi macip routes */
	int advertise_svi_macip;

	/* PIP feature knob */
	bool advertise_pip;
	/* PIP IP (sys ip) */
	struct in_addr pip_ip;
	struct in_addr pip_ip_static;
	/* PIP MAC (sys MAC) */
	struct ethaddr pip_rmac;
	struct ethaddr pip_rmac_static;
	struct ethaddr pip_rmac_zebra;
	bool is_anycast_mac;
};

static inline int is_vrf_rd_configured(struct bgp *bgp_vrf)
{
	return (CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_RD_CFGD));
}

static inline int bgp_evpn_vrf_rd_matches_existing(struct bgp *bgp_vrf,
						   struct prefix_rd *prd)
{
	return (memcmp(&bgp_vrf->vrf_prd.val, prd->val, ECOMMUNITY_SIZE) == 0);
}

static inline vni_t bgpevpn_get_l3vni(struct bgpevpn *vpn)
{
	return vpn->bgp_vrf ? vpn->bgp_vrf->l3vni : 0;
}

static inline void bgpevpn_get_rmac(struct bgpevpn *vpn, struct ethaddr *rmac)
{
	memset(rmac, 0, sizeof(struct ethaddr));
	if (!vpn->bgp_vrf)
		return;
	memcpy(rmac, &vpn->bgp_vrf->rmac, sizeof(struct ethaddr));
}

static inline struct list *bgpevpn_get_vrf_export_rtl(struct bgpevpn *vpn)
{
	if (!vpn->bgp_vrf)
		return NULL;

	return vpn->bgp_vrf->vrf_export_rtl;
}

static inline struct list *bgpevpn_get_vrf_import_rtl(struct bgpevpn *vpn)
{
	if (!vpn->bgp_vrf)
		return NULL;

	return vpn->bgp_vrf->vrf_import_rtl;
}

static inline void bgpevpn_unlink_from_l3vni(struct bgpevpn *vpn)
{
	/* bail if vpn is not associated to bgp_vrf */
	if (!vpn->bgp_vrf)
		return;

	UNSET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);
	listnode_delete(vpn->bgp_vrf->l2vnis, vpn);

	/* remove the backpointer to the vrf instance */
	bgp_unlock(vpn->bgp_vrf);
	vpn->bgp_vrf = NULL;
}

static inline void bgpevpn_link_to_l3vni(struct bgpevpn *vpn)
{
	struct bgp *bgp_vrf = NULL;

	/* bail if vpn is already associated to vrf */
	if (vpn->bgp_vrf)
		return;

	bgp_vrf = bgp_lookup_by_vrf_id(vpn->tenant_vrf_id);
	if (!bgp_vrf)
		return;

	/* associate the vpn to the bgp_vrf instance */
	vpn->bgp_vrf = bgp_lock(bgp_vrf);
	listnode_add_sort(bgp_vrf->l2vnis, vpn);

	/* check if we are advertising two labels for this vpn */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY))
		SET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);
}

static inline int is_vni_configured(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_CFGD));
}

static inline int is_vni_live(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_LIVE));
}

static inline int is_l3vni_live(struct bgp *bgp_vrf)
{
	return (bgp_vrf->l3vni && bgp_vrf->l3vni_svi_ifindex);
}

static inline int is_rd_configured(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_RD_CFGD));
}

static inline int bgp_evpn_rd_matches_existing(struct bgpevpn *vpn,
					       struct prefix_rd *prd)
{
	return (memcmp(&vpn->prd.val, prd->val, ECOMMUNITY_SIZE) == 0);
}

static inline int is_import_rt_configured(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD));
}

static inline int is_export_rt_configured(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD));
}

static inline int is_vni_param_configured(struct bgpevpn *vpn)
{
	return (is_rd_configured(vpn) || is_import_rt_configured(vpn)
		|| is_export_rt_configured(vpn));
}

static inline void encode_es_rt_extcomm(struct ecommunity_val *eval,
					struct ethaddr *mac)
{
	memset(eval, 0, sizeof(struct ecommunity_val));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT;
	memcpy(&eval->val[2], mac, ETH_ALEN);
}

static inline void encode_rmac_extcomm(struct ecommunity_val *eval,
				       struct ethaddr *rmac)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
	memcpy(&eval->val[2], rmac, ETH_ALEN);
}

static inline void encode_default_gw_extcomm(struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_OPAQUE;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_DEF_GW;
}

static inline void encode_mac_mobility_extcomm(int static_mac, uint32_t seq,
					       struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY;
	if (static_mac)
		eval->val[2] = ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY;
	eval->val[4] = (seq >> 24) & 0xff;
	eval->val[5] = (seq >> 16) & 0xff;
	eval->val[6] = (seq >> 8) & 0xff;
	eval->val[7] = seq & 0xff;
}

static inline void encode_na_flag_extcomm(struct ecommunity_val *eval,
					  uint8_t na_flag)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ND;
	if (na_flag)
		eval->val[2] |= ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG;
}

static inline void ip_prefix_from_type5_prefix(struct prefix_evpn *evp,
					       struct prefix *ip)
{
	memset(ip, 0, sizeof(struct prefix));
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		ip->family = AF_INET;
		ip->prefixlen = evp->prefix.prefix_addr.ip_prefix_length;
		memcpy(&(ip->u.prefix4), &(evp->prefix.prefix_addr.ip.ip),
		       IPV4_MAX_BYTELEN);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		ip->family = AF_INET6;
		ip->prefixlen = evp->prefix.prefix_addr.ip_prefix_length;
		memcpy(&(ip->u.prefix6), &(evp->prefix.prefix_addr.ip.ip),
		       IPV6_MAX_BYTELEN);
	}
}

static inline int is_evpn_prefix_default(const struct prefix *evp)
{
	if (evp->family != AF_EVPN)
		return 0;

	return ((evp->u.prefix_evpn.prefix_addr.ip_prefix_length  == 0) ?
		1 : 0);
}

static inline void ip_prefix_from_type2_prefix(struct prefix_evpn *evp,
					       struct prefix *ip)
{
	memset(ip, 0, sizeof(struct prefix));
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		ip->family = AF_INET;
		ip->prefixlen = IPV4_MAX_BITLEN;
		memcpy(&(ip->u.prefix4), &(evp->prefix.macip_addr.ip.ip),
		       IPV4_MAX_BYTELEN);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		ip->family = AF_INET6;
		ip->prefixlen = IPV6_MAX_BITLEN;
		memcpy(&(ip->u.prefix6), &(evp->prefix.macip_addr.ip.ip),
		       IPV6_MAX_BYTELEN);
	}
}

static inline void ip_prefix_from_evpn_prefix(struct prefix_evpn *evp,
					      struct prefix *ip)
{
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ip_prefix_from_type2_prefix(evp, ip);
	else if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		ip_prefix_from_type5_prefix(evp, ip);
}

static inline void build_evpn_type2_prefix(struct prefix_evpn *p,
					   struct ethaddr *mac,
					   struct ipaddr *ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;
	memcpy(&p->prefix.macip_addr.mac.octet, mac->octet, ETH_ALEN);
	p->prefix.macip_addr.ip.ipa_type = IPADDR_NONE;
	if (ip)
		memcpy(&p->prefix.macip_addr.ip, ip, sizeof(*ip));
}

static inline void build_type5_prefix_from_ip_prefix(struct prefix_evpn *evp,
						     struct prefix *ip_prefix)
{
	struct ipaddr ip;

	memset(&ip, 0, sizeof(struct ipaddr));
	if (ip_prefix->family == AF_INET) {
		ip.ipa_type = IPADDR_V4;
		memcpy(&ip.ipaddr_v4, &ip_prefix->u.prefix4,
		       sizeof(struct in_addr));
	} else {
		ip.ipa_type = IPADDR_V6;
		memcpy(&ip.ipaddr_v6, &ip_prefix->u.prefix6,
		       sizeof(struct in6_addr));
	}

	memset(evp, 0, sizeof(struct prefix_evpn));
	evp->family = AF_EVPN;
	evp->prefixlen = EVPN_ROUTE_PREFIXLEN;
	evp->prefix.route_type = BGP_EVPN_IP_PREFIX_ROUTE;
	evp->prefix.prefix_addr.ip_prefix_length = ip_prefix->prefixlen;
	evp->prefix.prefix_addr.ip.ipa_type = ip.ipa_type;
	memcpy(&evp->prefix.prefix_addr.ip, &ip, sizeof(struct ipaddr));
}

static inline void build_evpn_type3_prefix(struct prefix_evpn *p,
					   struct in_addr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
	p->prefix.imet_addr.ip.ipa_type = IPADDR_V4;
	p->prefix.imet_addr.ip.ipaddr_v4 = originator_ip;
}

static inline void build_evpn_type4_prefix(struct prefix_evpn *p,
					   esi_t *esi,
					   struct in_addr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_ES_ROUTE;
	p->prefix.es_addr.ip_prefix_length = IPV4_MAX_BITLEN;
	p->prefix.es_addr.ip.ipa_type = IPADDR_V4;
	p->prefix.es_addr.ip.ipaddr_v4 = originator_ip;
	memcpy(&p->prefix.es_addr.esi, esi, sizeof(esi_t));
}

static inline int evpn_default_originate_set(struct bgp *bgp, afi_t afi,
					     safi_t safi)
{
	if (afi == AFI_IP &&
	    CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4))
		return 1;
	else if (afi == AFI_IP6 &&
		 CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			    BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6))
		return 1;
	return 0;
}

static inline void es_get_system_mac(esi_t *esi,
				     struct ethaddr *mac)
{
	/*
	 * for type-1 and type-3 ESIs,
	 * the system mac starts at val[1]
	 */
	memcpy(mac, &esi->val[1], ETH_ALEN);
}

static inline int is_es_local(struct evpnes *es)
{
	return CHECK_FLAG(es->flags, EVPNES_LOCAL) ? 1 : 0;
}

static inline bool bgp_evpn_is_svi_macip_enabled(struct bgpevpn *vpn)
{
	struct bgp *bgp_evpn = NULL;

	bgp_evpn = bgp_get_evpn();

	return (bgp_evpn->evpn_info->advertise_svi_macip ||
		vpn->advertise_svi_macip);
}

extern void bgp_evpn_install_uninstall_default_route(struct bgp *bgp_vrf,
						     afi_t afi, safi_t safi,
						     bool add);
extern void evpn_rt_delete_auto(struct bgp *, vni_t, struct list *);
extern void bgp_evpn_configure_export_rt_for_vrf(struct bgp *bgp_vrf,
						 struct ecommunity *ecomadd);
extern void bgp_evpn_unconfigure_export_rt_for_vrf(struct bgp *bgp_vrf,
						   struct ecommunity *ecomdel);
extern void bgp_evpn_configure_import_rt_for_vrf(struct bgp *bgp_vrf,
						 struct ecommunity *ecomadd);
extern void bgp_evpn_unconfigure_import_rt_for_vrf(struct bgp *bgp_vrf,
						   struct ecommunity *ecomdel);
extern int bgp_evpn_handle_export_rt_change(struct bgp *bgp,
					    struct bgpevpn *vpn);
extern void bgp_evpn_handle_autort_change(struct bgp *bgp);
extern void bgp_evpn_handle_vrf_rd_change(struct bgp *bgp_vrf, int withdraw);
extern void bgp_evpn_handle_rd_change(struct bgp *bgp, struct bgpevpn *vpn,
				      int withdraw);
extern int bgp_evpn_install_routes(struct bgp *bgp, struct bgpevpn *vpn);
extern int bgp_evpn_uninstall_routes(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_map_vrf_to_its_rts(struct bgp *bgp_vrf);
extern void bgp_evpn_unmap_vrf_from_its_rts(struct bgp *bgp_vrf);
extern void bgp_evpn_map_vni_to_its_rts(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_unmap_vni_from_its_rts(struct bgp *bgp,
					    struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rt_import(struct bgp *bgp,
					   struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rt_export(struct bgp *bgp,
					   struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rd(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rd_for_vrf(struct bgp *bgp);
extern struct bgpevpn *bgp_evpn_lookup_vni(struct bgp *bgp, vni_t vni);
extern struct bgpevpn *bgp_evpn_new(struct bgp *bgp, vni_t vni,
		struct in_addr originator_ip,
		vrf_id_t tenant_vrf_id,
		struct in_addr mcast_grp);
extern void bgp_evpn_free(struct bgp *bgp, struct bgpevpn *vpn);
extern struct evpnes *bgp_evpn_lookup_es(struct bgp *bgp, esi_t *esi);
extern struct evpnes *bgp_evpn_es_new(struct bgp *bgp, esi_t *esi,
				      struct ipaddr *originator_ip);
extern void bgp_evpn_es_free(struct bgp *bgp, struct evpnes *es);
extern bool bgp_evpn_lookup_l3vni_l2vni_table(vni_t vni);
extern int update_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn);
#endif /* _BGP_EVPN_PRIVATE_H */
