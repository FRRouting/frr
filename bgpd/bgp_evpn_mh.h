// SPDX-License-Identifier: GPL-2.0-or-later
/* EVPN header for multihoming procedures
 *
 * Copyright (C) 2019 Cumulus Networks
 * Anuradha Karuppiah
 *
 */

#ifndef _FRR_BGP_EVPN_MH_H
#define _FRR_BGP_EVPN_MH_H

#include "vxlan.h"
#include "bgpd.h"
#include "bgp_evpn.h"
#include "bgp_evpn_private.h"

#define BGP_EVPN_AD_ES_ETH_TAG 0xffffffff
#define BGP_EVPN_AD_EVI_ETH_TAG 0

#define BGP_EVPNES_INCONS_STR_SZ 80
#define BGP_EVPN_VTEPS_FLAG_STR_SZ (BGP_EVPN_FLAG_STR_SZ * ES_VTEP_MAX_CNT)

#define BGP_EVPN_CONS_CHECK_INTERVAL 60

#define BGP_EVPN_MH_USE_ES_L3NHG_DEF true

/* XXX - tune this */
#define BGP_EVPN_MAX_EVI_PER_ES_FRAG 128

/* An ES can result in multiple EAD-per-ES route. Each EAD fragment is
 * associated with an unique RD
 */
struct bgp_evpn_es_frag {
	/* frag is associated with a parent ES */
	struct bgp_evpn_es *es;

	/* Id for deriving the RD automatically for this ES fragment */
	uint16_t rd_id;
	/* RD for this ES fragment */
	struct prefix_rd prd;

	/* Memory used for linking bgp_evpn_es_frag to
	 * bgp_evpn_es->es_frag_list
	 */
	struct listnode es_listnode;

	/* List of ES-EVIs associated with this fragment */
	struct list *es_evi_frag_list;
};

/* Ethernet Segment entry -
 * - Local and remote ESs are maintained in a global RB tree,
 *   bgp_mh_info->es_rb_tree using ESI as key
 * - Local ESs are received from zebra (BGP_EVPNES_LOCAL)
 * - Remotes ESs are implicitly created (by reference) by a remote ES-EVI
 *   (BGP_EVPNES_REMOTE)
 * - An ES can be simultaneously LOCAL and REMOTE; infact all LOCAL ESs are
 *   expected to have REMOTE ES peers.
 */
struct bgp_evpn_es {
	/* Ethernet Segment Identifier */
	esi_t esi;
	char esi_str[ESI_STR_LEN];

	/* es flags */
	uint32_t flags;
	/* created via zebra config */
#define BGP_EVPNES_LOCAL           (1 << 0)
	/* created implicitly by a remote ES-EVI reference */
#define BGP_EVPNES_REMOTE          (1 << 1)
	/* local ES link is oper-up */
#define BGP_EVPNES_OPER_UP         (1 << 2)
	/* enable generation of EAD-EVI routes */
#define BGP_EVPNES_ADV_EVI         (1 << 3)
	/* consistency checks pending */
#define BGP_EVPNES_CONS_CHECK_PEND (1 << 4)
	/* ES is in LACP bypass mode - don't advertise EAD-ES or ESR */
#define BGP_EVPNES_BYPASS (1 << 5)
	/* bits needed for printing the flags + null */
#define BGP_EVPN_FLAG_STR_SZ 7

	/* memory used for adding the es to bgp->es_rb_tree */
	RB_ENTRY(bgp_evpn_es) rb_node;

	/* [EVPNES_LOCAL] memory used for linking the es to
	 * bgp_mh_info->local_es_list
	 */
	struct listnode es_listnode;

	/* memory used for linking the es to "processing" pending list
	 * bgp_mh_info->pend_es_list
	 */
	struct listnode pend_es_listnode;

	/* [EVPNES_LOCAL] List of RDs for this ES (bgp_evpn_es_frag) */
	struct list *es_frag_list;
	struct bgp_evpn_es_frag *es_base_frag;

	/* [EVPNES_LOCAL] originator ip address  */
	struct in_addr originator_ip;

	/* [EVPNES_LOCAL] Route table for EVPN routes for this ESI-
	 * - Type-4 local and remote routes
	 * - Type-1 local routes
	 */
	struct bgp_table *route_table;

	/* list of PEs (bgp_evpn_es_vtep) attached to the ES */
	struct list *es_vtep_list;

	/* List of ES-EVIs associated with this ES */
	struct list *es_evi_list;

	/* List of ES-VRFs associated with this ES */
	struct list *es_vrf_list;

	/* List of MAC-IP VNI paths using this ES as destination -
	 * element is bgp_path_info_extra->es_info
	 * Note: Only local/zebra-added MACIP paths in the VNI
	 * routing table are linked to this list
	 */
	struct list *macip_evi_path_list;

	/* List of MAC-IP paths in the global routing table using this
	 * ES as destination - data is bgp_path_info_extra->es_info
	 * Note: Only non-local/imported MACIP paths in the global
	 * routing table are linked to this list
	 */
	struct list *macip_global_path_list;

	/* Number of remote VNIs referencing this ES */
	uint32_t remote_es_evi_cnt;

	uint32_t inconsistencies;
	/* there are one or more EVIs whose VTEP list doesn't match
	 * with the ES's VTEP list
	 */
#define BGP_EVPNES_INCONS_VTEP_LIST (1 << 0)

	/* number of es-evi entries whose VTEP list doesn't match
	 * with the ES's
	 */
	uint32_t incons_evi_vtep_cnt;

	/* preference config for BUM-DF election. advertised via the ESR. */
	uint16_t df_pref;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(bgp_evpn_es);
RB_HEAD(bgp_es_rb_head, bgp_evpn_es);
RB_PROTOTYPE(bgp_es_rb_head, bgp_evpn_es, rb_node, bgp_es_rb_cmp);

/* PE attached to an ES */
struct bgp_evpn_es_vtep {
	struct bgp_evpn_es *es; /* parent ES */
	struct in_addr vtep_ip;

	char vtep_str[INET6_ADDRSTRLEN];

	uint32_t flags;
	/* Rxed a Type4 route from this PE */
#define BGP_EVPNES_VTEP_ESR	   (1 << 0)
	/* Active (rxed EAD-ES and EAD-EVI) and can be included as
	 * a nexthop
	 */
#define BGP_EVPNES_VTEP_ACTIVE (1 << 1)

	uint32_t evi_cnt; /* es_evis referencing this vtep as an active path */

	/* Algorithm and preference for DF election. Rxed via the ESR */
	uint8_t df_alg;
	uint16_t df_pref;

	/* memory used for adding the entry to es->es_vtep_list */
	struct listnode es_listnode;
};

/* ES-VRF element needed for managing L3 NHGs. It is implicitly created
 * when an ES-EVI is associated with a tenant VRF
 */
struct bgp_evpn_es_vrf {
	struct bgp_evpn_es *es;
	struct bgp *bgp_vrf;

	uint32_t flags;
/* NHG can only be activated if there are active VTEPs in the ES and
 * there is a valid L3-VNI associated with the VRF
 */
#define BGP_EVPNES_VRF_NHG_ACTIVE (1 << 0)

	/* memory used for adding the es_vrf to
	 * es_vrf->bgp_vrf->es_vrf_rb_tree
	 */
	RB_ENTRY(bgp_evpn_es_vrf) rb_node;

	/* memory used for linking the es_vrf to es_vrf->es->es_vrf_list */
	struct listnode es_listnode;

	uint32_t nhg_id;
	uint32_t v6_nhg_id;

	/* Number of ES-EVI entries associated with this ES-VRF */
	uint32_t ref_cnt;
};

/* ES per-EVI info
 * - ES-EVIs are maintained per-L2-VNI (vpn->es_evi_rb_tree)
 * - ES-EVIs are also linked to the parent ES (es->es_evi_list)
 * - Local ES-EVIs are created by zebra (via config). They are linked to a
 *   per-VNI list (vpn->local_es_evi_list) for quick access
 * - Remote ES-EVIs are created implicitly when a bgp_evpn_es_evi_vtep
 *   references it.
 */
struct bgp_evpn_es_evi {
	struct bgp_evpn_es *es;
	/* Only applicableif EVI_LOCAL */
	struct bgp_evpn_es_frag *es_frag;
	struct bgpevpn *vpn;

	/* ES-EVI flags */
	uint32_t flags;
/* local ES-EVI, created by zebra */
#define BGP_EVPNES_EVI_LOCAL            (1 << 0)
/* created via a remote VTEP imported by BGP */
#define BGP_EVPNES_EVI_REMOTE           (1 << 1)
#define BGP_EVPNES_EVI_INCONS_VTEP_LIST (1 << 2)

	/* memory used for adding the es_evi to es_evi->vpn->es_evi_rb_tree */
	RB_ENTRY(bgp_evpn_es_evi) rb_node;
	/* memory used for linking the es_evi to
	 * es_evi->vpn->local_es_evi_list
	 */
	struct listnode l2vni_listnode;
	/* memory used for linking the es_evi to
	 * es_evi->es->es_evi_list
	 */
	struct listnode es_listnode;

	/* memory used for linking the es_evi to
	 * es_evi->es_frag->es_evi_frag_list
	 */
	struct listnode es_frag_listnode;
	/* list of PEs (bgp_evpn_es_evi_vtep) attached to the ES for this VNI */
	struct list *es_evi_vtep_list;

	struct bgp_evpn_es_vrf *es_vrf;
};

/* PE attached to an ES for a VNI. This entry is created when an EAD-per-ES
 * or EAD-per-EVI Type1 route is imported into the VNI.
 */
struct bgp_evpn_es_evi_vtep {
	struct bgp_evpn_es_evi *es_evi; /* parent ES-EVI */
	struct in_addr vtep_ip;

	uint32_t flags;
	/* Rxed an EAD-per-ES route from the PE */
#define BGP_EVPN_EVI_VTEP_EAD_PER_ES  (1 << 0) /* rxed EAD-per-ES */
	/* Rxed an EAD-per-EVI route from the PE */
#define BGP_EVPN_EVI_VTEP_EAD_PER_EVI (1 << 1) /* rxed EAD-per-EVI */
	/* VTEP is active i.e. will result in the creation of an es-vtep */
#define BGP_EVPN_EVI_VTEP_ACTIVE      (1 << 2)
#define BGP_EVPN_EVI_VTEP_EAD         (BGP_EVPN_EVI_VTEP_EAD_PER_ES |\
		BGP_EVPN_EVI_VTEP_EAD_PER_EVI)

	/* memory used for adding the entry to es_evi->es_evi_vtep_list */
	struct listnode es_evi_listnode;
	struct bgp_evpn_es_vtep *es_vtep;
};

/* A nexthop is created when a path (imported from an EVPN type-2 route)
 * is added to the VRF route table using that nexthop.
 * It is added on first pi reference and removed on last pi deref.
 */
struct bgp_evpn_nh {
	/* backpointer to the VRF */
	struct bgp *bgp_vrf;
	/* nexthop/VTEP IP */
	struct ipaddr ip;
	/* description for easy logging */
	char nh_str[INET6_ADDRSTRLEN];
	struct ethaddr rmac;
	/* pi from which we are pulling the nh RMAC */
	struct bgp_path_info *ref_pi;
	/* List of VRF paths using this nexthop */
	struct list *pi_list;
	uint8_t flags;
#define BGP_EVPN_NH_READY_FOR_ZEBRA (1 << 0)
};

/* multihoming information stored in bgp_master */
#define bgp_mh_info (bm->mh_info)
struct bgp_evpn_mh_info {
	/* RB tree of Ethernet segments (used for EVPN-MH)  */
	struct bgp_es_rb_head es_rb_tree;
	/* List of local ESs */
	struct list *local_es_list;
	/* List of ESs with pending/periodic processing */
	struct list *pend_es_list;
	/* periodic timer for running background consistency checks */
	struct event *t_cons_check;

	/* config knobs for optimizing or interop */
	/* Generate EAD-EVI routes even if the ES is oper-down. This can be
	 * enabled as an optimization to avoid a storm of updates when an ES
	 * link flaps.
	 */
	bool ead_evi_adv_for_down_links;
	/* Enable ES consistency checking */
	bool consistency_checking;
	/* Use L3 NHGs for host routes in symmetric IRB */
	bool host_routes_use_l3nhg;
	/* Some vendors are not generating the EAD-per-EVI route. This knob
	 * can be turned off to activate a remote ES-PE when the EAD-per-ES
	 * route is rxed i.e. not wait on the EAD-per-EVI route
	 */
	bool ead_evi_rx;
#define BGP_EVPN_MH_EAD_EVI_RX_DEF true
	/* Skip EAD-EVI advertisements by turning off this knob */
	bool ead_evi_tx;
#define BGP_EVPN_MH_EAD_EVI_TX_DEF true
	/* If the Local ES is inactive we advertise the MAC-IP without the
	 * L3 ecomm
	 */
	bool suppress_l3_ecomm_on_inactive_es;
	/* Setup EVPN PE nexthops and their RMAC in bgpd */
	bool bgp_evpn_nh_setup;

	/* If global export-rts are configured that is used for sending
	 * sending the ead-per-es route instead of the L2-VNI(s) RTs
	 */
	struct list *ead_es_export_rtl;

	/* Number of EVIs in an ES fragment - used of EAD-per-ES route
	 * construction
	 */
	uint32_t evi_per_es_frag;
};

/****************************************************************************/
static inline int bgp_evpn_is_es_local(struct bgp_evpn_es *es)
{
	return CHECK_FLAG(es->flags, BGP_EVPNES_LOCAL) ? 1 : 0;
}

extern esi_t *zero_esi;
static inline bool bgp_evpn_is_esi_valid(esi_t *esi)
{
	return !!memcmp(esi, zero_esi, sizeof(esi_t));
}

static inline esi_t *bgp_evpn_attr_get_esi(struct attr *attr)
{
	return attr ? &attr->esi : zero_esi;
}

static inline bool bgp_evpn_attr_is_sync(struct attr *attr)
{
	return attr ? !!(attr->es_flags &
		(ATTR_ES_PEER_PROXY | ATTR_ES_PEER_ACTIVE)) : false;
}

static inline uint32_t bgp_evpn_attr_get_sync_seq(struct attr *attr)
{
	return attr ?  attr->mm_sync_seqnum : 0;
}

static inline bool bgp_evpn_attr_is_active_on_peer(struct attr *attr)
{
	return attr ?
		!!(attr->es_flags & ATTR_ES_PEER_ACTIVE) : false;
}

static inline bool bgp_evpn_attr_is_router_on_peer(struct attr *attr)
{
	return attr ?
		!!(attr->es_flags & ATTR_ES_PEER_ROUTER) : false;
}

static inline bool bgp_evpn_attr_is_proxy(struct attr *attr)
{
	return attr ? !!(attr->es_flags & ATTR_ES_PROXY_ADVERT) : false;
}

static inline bool bgp_evpn_attr_is_local_es(struct attr *attr)
{
	return attr ? !!(attr->es_flags & ATTR_ES_IS_LOCAL) : false;
}

static inline bool bgp_evpn_local_es_is_active(struct bgp_evpn_es *es)
{
	return (es->flags & BGP_EVPNES_OPER_UP)
	       && !(es->flags & BGP_EVPNES_BYPASS);
}

/****************************************************************************/
extern int bgp_evpn_es_route_install_uninstall(struct bgp *bgp,
		struct bgp_evpn_es *es, afi_t afi, safi_t safi,
		struct prefix_evpn *evp, struct bgp_path_info *pi,
		int install);
extern void update_type1_routes_for_evi(struct bgp *bgp, struct bgpevpn *vpn);
extern int delete_global_ead_evi_routes(struct bgp *bgp, struct bgpevpn *vpn);
extern int bgp_evpn_mh_route_update(struct bgp *bgp, struct bgp_evpn_es *es,
				    struct bgpevpn *vpn, afi_t afi, safi_t safi,
				    struct bgp_dest *dest, struct attr *attr,
				    struct bgp_path_info **ri,
				    int *route_changed);
int bgp_evpn_type1_route_process(struct peer *peer, afi_t afi, safi_t safi,
		struct attr *attr, uint8_t *pfx, int psize,
		uint32_t addpath_id);
int bgp_evpn_type4_route_process(struct peer *peer, afi_t afi, safi_t safi,
		struct attr *attr, uint8_t *pfx, int psize,
		uint32_t addpath_id);
extern int bgp_evpn_local_es_add(struct bgp *bgp, esi_t *esi,
				 struct in_addr originator_ip, bool oper_up,
				 uint16_t df_pref, bool bypass);
extern int bgp_evpn_local_es_del(struct bgp *bgp, esi_t *esi);
extern int bgp_evpn_local_es_evi_add(struct bgp *bgp, esi_t *esi, vni_t vni);
extern int bgp_evpn_local_es_evi_del(struct bgp *bgp, esi_t *esi, vni_t vni);
extern enum zclient_send_status
bgp_evpn_remote_es_evi_add(struct bgp *bgp, struct bgpevpn *vpn,
			   const struct prefix_evpn *p);
extern enum zclient_send_status
bgp_evpn_remote_es_evi_del(struct bgp *bgp, struct bgpevpn *vpn,
			   const struct prefix_evpn *p);
extern void bgp_evpn_mh_init(void);
extern void bgp_evpn_mh_finish(void);
void bgp_evpn_vni_es_init(struct bgpevpn *vpn);
void bgp_evpn_vni_es_cleanup(struct bgpevpn *vpn);
void bgp_evpn_es_show_esi(struct vty *vty, esi_t *esi, bool uj);
void bgp_evpn_es_show(struct vty *vty, bool uj, bool detail);
void bgp_evpn_es_evi_show_vni(struct vty *vty, vni_t vni,
		bool uj, bool detail);
void bgp_evpn_es_evi_show(struct vty *vty, bool uj, bool detail);
struct bgp_evpn_es *bgp_evpn_es_find(const esi_t *esi);
extern void bgp_evpn_vrf_es_init(struct bgp *bgp_vrf);
extern bool bgp_evpn_is_esi_local_and_non_bypass(esi_t *esi);
extern void bgp_evpn_es_vrf_deref(struct bgp_evpn_es_evi *es_evi);
extern void bgp_evpn_es_vrf_ref(struct bgp_evpn_es_evi *es_evi,
				struct bgp *bgp_vrf);
extern void bgp_evpn_path_mh_info_free(struct bgp_path_mh_info *mh_info);
extern void bgp_evpn_path_es_link(struct bgp_path_info *pi, vni_t vni,
				  esi_t *esi);
extern bool bgp_evpn_path_es_use_nhg(struct bgp *bgp_vrf,
				     struct bgp_path_info *pi, uint32_t *nhg_p);
extern void bgp_evpn_es_vrf_show(struct vty *vty, bool uj,
				 struct bgp_evpn_es *es);
extern void bgp_evpn_es_vrf_show_esi(struct vty *vty, esi_t *esi, bool uj);
extern void bgp_evpn_switch_ead_evi_rx(void);
extern bool bgp_evpn_es_add_l3_ecomm_ok(esi_t *esi);
extern void bgp_evpn_es_vrf_use_nhg(struct bgp *bgp_vrf, esi_t *esi,
				    bool *use_l3nhg, bool *is_l3nhg_active,
				    struct bgp_evpn_es_vrf **es_vrf_p);
extern void bgp_evpn_nh_init(struct bgp *bgp_vrf);
extern void bgp_evpn_nh_finish(struct bgp *bgp_vrf);
extern void bgp_evpn_nh_show(struct vty *vty, bool uj);
extern void bgp_evpn_path_nh_add(struct bgp *bgp_vrf, struct bgp_path_info *pi);
extern void bgp_evpn_path_nh_del(struct bgp *bgp_vrf, struct bgp_path_info *pi);
extern void bgp_evpn_mh_config_ead_export_rt(struct bgp *bgp,
					     struct ecommunity *ecom, bool del);

#endif /* _FRR_BGP_EVPN_MH_H */
