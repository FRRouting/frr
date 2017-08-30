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

/* EVPN prefix lengths. */
#define EVPN_TYPE_2_ROUTE_PREFIXLEN      224
#define EVPN_TYPE_3_ROUTE_PREFIXLEN      224

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
	u_int32_t flags;
#define VNI_FLAG_CFGD              0x1  /* VNI is user configured */
#define VNI_FLAG_LIVE              0x2  /* VNI is "live" */
#define VNI_FLAG_RD_CFGD           0x4  /* RD is user configured. */
#define VNI_FLAG_IMPRT_CFGD        0x8  /* Import RT is user configured */
#define VNI_FLAG_EXPRT_CFGD        0x10 /* Export RT is user configured */

	/* Flag to indicate if we are advertising the g/w mac ip for this VNI*/
	u_int8_t advertise_gw_macip;

	/* Id for deriving the RD automatically for this VNI */
	u_int16_t rd_id;

	/* RD for this VNI. */
	struct prefix_rd prd;

	/* Route type 3 field */
	struct in_addr originator_ip;

	/* Import and Export RTs. */
	struct list *import_rtl;
	struct list *export_rtl;

	/* Route table for EVPN routes for this VNI. */
	struct bgp_table *route_table;

	QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(bgpevpn)

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

#define RT_TYPE_IMPORT 1
#define RT_TYPE_EXPORT 2
#define RT_TYPE_BOTH   3

static inline int is_vni_configured(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_CFGD));
}

static inline int is_vni_live(struct bgpevpn *vpn)
{
	return (CHECK_FLAG(vpn->flags, VNI_FLAG_LIVE));
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

static inline void encode_mac_mobility_extcomm(int static_mac, u_int32_t seq,
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

static inline void build_evpn_type2_prefix(struct prefix_evpn *p,
					   struct ethaddr *mac,
					   struct ipaddr *ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_TYPE_2_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;
	memcpy(&p->prefix.mac.octet, mac->octet, ETH_ALEN);
	p->prefix.ip.ipa_type = IPADDR_NONE;
	if (ip)
		memcpy(&p->prefix.ip, ip, sizeof(*ip));
}

static inline void build_evpn_type3_prefix(struct prefix_evpn *p,
					   struct in_addr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
	p->prefix.ip.ipa_type = IPADDR_V4;
	p->prefix.ip.ipaddr_v4 = originator_ip;
}


extern int bgp_evpn_handle_export_rt_change(struct bgp *bgp,
					    struct bgpevpn *vpn);
extern void bgp_evpn_handle_rd_change(struct bgp *bgp, struct bgpevpn *vpn,
				      int withdraw);
extern int bgp_evpn_install_routes(struct bgp *bgp, struct bgpevpn *vpn);
extern int bgp_evpn_uninstall_routes(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_map_vni_to_its_rts(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_unmap_vni_from_its_rts(struct bgp *bgp,
					    struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rt_import(struct bgp *bgp,
					   struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rt_export(struct bgp *bgp,
					   struct bgpevpn *vpn);
extern void bgp_evpn_derive_auto_rd(struct bgp *bgp, struct bgpevpn *vpn);
extern struct bgpevpn *bgp_evpn_lookup_vni(struct bgp *bgp, vni_t vni);
extern struct bgpevpn *bgp_evpn_new(struct bgp *bgp, vni_t vni,
				    struct in_addr originator_ip);
extern void bgp_evpn_free(struct bgp *bgp, struct bgpevpn *vpn);
#endif /* _BGP_EVPN_PRIVATE_H */
