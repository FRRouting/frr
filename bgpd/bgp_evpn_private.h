// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN internal definitions
 * Copyright (C) 2017 Cumulus Networks, Inc.
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

/* EVPN route RD buffer length */
#define BGP_EVPN_PREFIX_RD_LEN 100

/* packet sizes for EVPN routes */
/* Type-1 route should be 25 bytes
 *  RD (8), ESI (10), eth-tag (4), vni (3)
 */
#define BGP_EVPN_TYPE1_PSIZE 25
/* Type-4 route should be either 23 or 35 bytes
 *  RD (8), ESI (10), ip-len (1), ip (4 or 16)
 */
#define BGP_EVPN_TYPE4_V4_PSIZE 23
#define BGP_EVPN_TYPE4_V6_PSIZE 35

static const struct message bgp_evpn_route_type_str[] = { { BGP_EVPN_AD_ROUTE, "AD" },
							  { BGP_EVPN_MAC_IP_ROUTE, "MACIP" },
							  { BGP_EVPN_IMET_ROUTE, "IMET" },
							  { BGP_EVPN_ES_ROUTE, "ES" },
							  { BGP_EVPN_IP_PREFIX_ROUTE, "IP-PREFIX" },
							  { 0 } };

RB_HEAD(bgp_es_evi_rb_head, bgp_evpn_es_evi);
RB_PROTOTYPE(bgp_es_evi_rb_head, bgp_evpn_es_evi, rb_node,
		bgp_es_evi_rb_cmp);
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
	ifindex_t svi_ifindex;
	uint32_t flags;
#define VNI_FLAG_CFGD              0x1  /* VNI is user configured */
#define VNI_FLAG_LIVE              0x2  /* VNI is "live" */
#define VNI_FLAG_RD_CFGD           0x4  /* RD is user configured. */
/* Bits 0x8 and 0x10 are unused. They used to be the
 * VNI_FLAG_{IMPRT,EXPRT}_CFGD flags, which are superseded by the
 * rt_config structure.
 */
/* Attach both L2-VNI and L3-VNI if needed for this VPN */
#define VNI_FLAG_USE_TWO_LABELS 0x20
#define VNI_FLAG_ADD		0x40 /* L2VNI Add */

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
	char *prd_pretty;

	/* Route type 3 field */
	struct ipaddr originator_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* User route-target configuration of this L2VNI */
	struct bgp_evpn_rt_config *rt_config;

	/* Derived route targets: wildcard import (match local admin only),
	 * fully qualified import, fully qualified export
	 */
	struct bgp_evpn_effective_wildcard_rt_slu_head effective_wildcard_import_rts;
	struct bgp_evpn_effective_fq_rt_slu_head effective_fq_import_rts;
	struct bgp_evpn_effective_fq_rt_slu_head effective_fq_export_rts;

	/*
	 * EVPN route that uses gateway IP overlay index as its nexthop
	 * needs to do a recursive lookup.
	 * A remote MAC/IP entry should be present for the gateway IP.
	 * Maintain a hash of the addresses received via remote MAC/IP routes
	 * for efficient gateway IP recursive lookup in this EVI
	 */
	struct hash *remote_ip_hash;

	/* Route tables for EVPN routes for
	 * this VNI. */
	struct bgp_table *ip_table;
	struct bgp_table *mac_table;

	/* RB tree of ES-EVIs */
	struct bgp_es_evi_rb_head es_evi_rb_tree;

	/* List of local ESs */
	struct list *local_es_evi_list;

	struct zebra_l2_vni_item zl2vni;

	enum vxlan_flood_control vxlan_flood_ctrl;

	QOBJ_FIELDS;
};

DECLARE_QOBJ_TYPE(bgpevpn);

DECLARE_LIST(zebra_l2_vni, struct bgpevpn, zl2vni);

/* Mapping of a fully qualified Import RT to VNIs.
 * The fully qualified import RTs of all VNIs are maintained in a hash
 * table with each RT linking to all VNIs that will import routes
 * carrying exactly this RT.
 */
struct bgp_evpn_l2vni_fq_irt_node {
	/* RT */
	struct ecommunity_val rt;

	/* List of VNIs (struct bgpevpn) importing routes matching this RT. */
	struct list *vnis;

	struct bgp_evpn_l2vni_fq_irt_item item;
};

extern int bgp_evpn_l2vni_fq_irt_cmp(const struct bgp_evpn_l2vni_fq_irt_node *irt1,
				     const struct bgp_evpn_l2vni_fq_irt_node *irt2);
extern uint32_t bgp_evpn_l2vni_fq_irt_hash(const struct bgp_evpn_l2vni_fq_irt_node *irt);

DECLARE_HASH(bgp_evpn_l2vni_fq_irt, struct bgp_evpn_l2vni_fq_irt_node, item,
	     bgp_evpn_l2vni_fq_irt_cmp, bgp_evpn_l2vni_fq_irt_hash);

/* Mapping of a wildcard Import RT to VNIs.
 * The wildcard import RTs of all VNIs are maintained in a hash table
 * keyed on the local admin value alone, with each entry linking to all
 * VNIs that will import routes carrying a route target with this local
 * admin value, regardless of the global admin field.
 */
struct bgp_evpn_l2vni_wildcard_irt_node {
	/* local admin value in network byte order */
	uint32_t local_admin_nbo;

	/* List of VNIs (struct bgpevpn) importing routes matching this RT. */
	struct list *vnis;

	struct bgp_evpn_l2vni_wildcard_irt_item item;
};

extern int bgp_evpn_l2vni_wildcard_irt_cmp(const struct bgp_evpn_l2vni_wildcard_irt_node *irt1,
					   const struct bgp_evpn_l2vni_wildcard_irt_node *irt2);
extern uint32_t bgp_evpn_l2vni_wildcard_irt_hash(const struct bgp_evpn_l2vni_wildcard_irt_node *irt);

DECLARE_HASH(bgp_evpn_l2vni_wildcard_irt, struct bgp_evpn_l2vni_wildcard_irt_node, item,
	     bgp_evpn_l2vni_wildcard_irt_cmp, bgp_evpn_l2vni_wildcard_irt_hash);

/* Mapping of a fully qualified Import RT to VRFs.
 * The fully qualified import RTs of all VRFs are maintained in a hash
 * table with each RT linking to all VRFs that will import routes
 * carrying exactly this RT.
 */
struct bgp_evpn_vrf_fq_irt_node {
	/* RT */
	struct ecommunity_val rt;

	/* List of VRFs (struct bgp) importing routes matching this RT. */
	struct list *vrfs;

	struct bgp_evpn_vrf_fq_irt_item item;
};

extern int bgp_evpn_vrf_fq_irt_cmp(const struct bgp_evpn_vrf_fq_irt_node *irt1,
				   const struct bgp_evpn_vrf_fq_irt_node *irt2);
extern uint32_t bgp_evpn_vrf_fq_irt_hash(const struct bgp_evpn_vrf_fq_irt_node *irt);

DECLARE_HASH(bgp_evpn_vrf_fq_irt, struct bgp_evpn_vrf_fq_irt_node, item, bgp_evpn_vrf_fq_irt_cmp,
	     bgp_evpn_vrf_fq_irt_hash);

/* Mapping of a wildcard Import RT to VRFs. See the VNI variant above
 * for the wildcard matching semantics.
 */
struct bgp_evpn_vrf_wildcard_irt_node {
	/* local admin value in network byte order */
	uint32_t local_admin_nbo;

	/* List of VRFs (struct bgp) importing routes matching this RT. */
	struct list *vrfs;

	struct bgp_evpn_vrf_wildcard_irt_item item;
};

extern int bgp_evpn_vrf_wildcard_irt_cmp(const struct bgp_evpn_vrf_wildcard_irt_node *irt1,
					 const struct bgp_evpn_vrf_wildcard_irt_node *irt2);
extern uint32_t bgp_evpn_vrf_wildcard_irt_hash(const struct bgp_evpn_vrf_wildcard_irt_node *irt);

DECLARE_HASH(bgp_evpn_vrf_wildcard_irt, struct bgp_evpn_vrf_wildcard_irt_node, item,
	     bgp_evpn_vrf_wildcard_irt_cmp, bgp_evpn_vrf_wildcard_irt_hash);


/* Direction(s) of a configured EVPN route target. */
enum bgp_evpn_rt_direction {
	RT_TYPE_IMPORT = 1,
	RT_TYPE_EXPORT = 2,
	RT_TYPE_BOTH = 3,
};

/* Type discriminator for user configured route targets */
enum bgp_evpn_cfgd_rt_type {
	/* Wildcard route target, *:<uint32>, e.g. *:98765432 */
	BGP_EVPN_CFGD_RT_TYPE_WILDCARD = 1,
	/* 2-byte AS route target, <AS2>:<uint32>, e.g. 64496:98765432,
	 * BGP extended community type 0x00
	 */
	BGP_EVPN_CFGD_RT_TYPE_AS2 = 2,
	/* IPv4 route target, <IPv4>:<uint16>, e.g. 192.0.2.255:12345,
	 * BGP extended community type 0x01
	 */
	BGP_EVPN_CFGD_RT_TYPE_IP4 = 3,
	/* 4-byte AS route target, <AS4>:<uint16>, e.g. 4200000000:12345,
	 * BGP extended community type 0x02
	 */
	BGP_EVPN_CFGD_RT_TYPE_AS4 = 4,
};

/* User configured wildcard route target */
struct bgp_evpn_cfgd_wildcard_rt {
	uint32_t local_admin;
};

/* User configured 2-byte AS route target */
struct bgp_evpn_cfgd_as2_rt {
	uint16_t as;
	uint32_t local_admin;
};

/* User configured IPv4 route target */
struct bgp_evpn_cfgd_ip4_rt {
	struct in_addr ip;
	uint16_t local_admin;
};

/* User configured 4-byte AS route target */
struct bgp_evpn_cfgd_as4_rt {
	uint32_t as;
	uint16_t local_admin;
};

PREDECL_SORTLIST_UNIQ(bgp_evpn_cfgd_rt_slu);

/* User configured route target, kept in the exact shape the user
 * entered it so that the configuration can be written back verbatim.
 * Used for both L3VNI VRFs and L2VNIs (strictly speaking an L2VNI is
 * an EVI; FRR historically uses the two terms interchangeably).
 */
struct bgp_evpn_cfgd_rt {
	enum bgp_evpn_cfgd_rt_type type;
	union {
		struct bgp_evpn_cfgd_wildcard_rt wildcard_rt;
		struct bgp_evpn_cfgd_as2_rt as2_rt;
		struct bgp_evpn_cfgd_ip4_rt ip4_rt;
		struct bgp_evpn_cfgd_as4_rt as4_rt;
	} payload;

	struct bgp_evpn_cfgd_rt_slu_item slu_item;
};

extern int bgp_evpn_cfgd_rt_cmp(const struct bgp_evpn_cfgd_rt *rt1,
				const struct bgp_evpn_cfgd_rt *rt2);
extern struct bgp_evpn_cfgd_rt *bgp_evpn_cfgd_rt_from_ecom(const struct ecommunity *ecom,
							   bool is_wildcard);
extern struct bgp_evpn_cfgd_rt *bgp_evpn_cfgd_rt_dup(const struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_cfgd_rt_free(struct bgp_evpn_cfgd_rt *cfgd_rt);

DECLARE_SORTLIST_UNIQ(bgp_evpn_cfgd_rt_slu, struct bgp_evpn_cfgd_rt, slu_item,
		      bgp_evpn_cfgd_rt_cmp);

/* Auto route target configuration of one direction */
enum bgp_evpn_autort_cfgd {
	BGP_EVPN_AUTORT_NOT_CFGD = 0, /* default: add if no manual RT */
	BGP_EVPN_AUTORT_ADD_ALWAYS = 1,
};

/* User route target configuration of a L3VNI VRF or L2VNI.
 *
 * "route-target both" is a plain alias for configuring the same route
 * target as import and export at the same time, so only import and
 * export are stored.
 *
 * Wildcard route targets are only valid for import (an advertised route
 * must carry fully qualified route targets), so cfgd_export never
 * contains wildcard entries.
 */
struct bgp_evpn_rt_config {
	enum bgp_evpn_autort_cfgd autort_cfgd_import;
	enum bgp_evpn_autort_cfgd autort_cfgd_export;

	struct bgp_evpn_cfgd_rt_slu_head cfgd_import;
	struct bgp_evpn_cfgd_rt_slu_head cfgd_export;
};

/* Effective (derived) wildcard import route target. Matches routes
 * carrying any route target with this local admin value, regardless of
 * the global admin field.
 */
struct bgp_evpn_effective_wildcard_rt {
	/* local admin value in network byte order (parallel to how it is
	 * laid out in an ecommunity_val)
	 */
	uint32_t local_admin_nbo;

	struct bgp_evpn_effective_wildcard_rt_slu_item slu_item;
};

extern int bgp_evpn_effective_wildcard_rt_cmp(const struct bgp_evpn_effective_wildcard_rt *rt1,
					      const struct bgp_evpn_effective_wildcard_rt *rt2);

DECLARE_SORTLIST_UNIQ(bgp_evpn_effective_wildcard_rt_slu, struct bgp_evpn_effective_wildcard_rt,
		      slu_item, bgp_evpn_effective_wildcard_rt_cmp);

/* Effective (derived) fully qualified route target */
struct bgp_evpn_effective_fq_rt {
	struct ecommunity_val ecom_val;

	struct bgp_evpn_effective_fq_rt_slu_item slu_item;
};

extern int bgp_evpn_effective_fq_rt_cmp(const struct bgp_evpn_effective_fq_rt *rt1,
					const struct bgp_evpn_effective_fq_rt *rt2);

DECLARE_SORTLIST_UNIQ(bgp_evpn_effective_fq_rt_slu, struct bgp_evpn_effective_fq_rt, slu_item,
		      bgp_evpn_effective_fq_rt_cmp);

extern struct bgp_evpn_rt_config *bgp_evpn_rt_config_new(void);
extern void bgp_evpn_rt_config_free(struct bgp_evpn_rt_config *rt_config);

extern void bgp_evpn_format_cfgd_rt(char *buf, size_t buflen,
				    const struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_format_wildcard_rt_local_admin(char *buf, size_t buflen,
						    uint32_t local_admin_nbo);
extern void bgp_evpn_format_fq_rt_ecom_val(char *buf, size_t buflen,
					   const struct ecommunity_val *eval);

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

	/* MAC-VRF Site-of-Origin
	 * - added to all routes exported from L2VNI
	 * - Type-2/3 routes with matching SoO not imported into L2VNI
	 * - Type-2/5 routes with matching SoO not imported into L3VNI
	 */
	struct ecommunity *soo;

	/* PIP feature knob */
	bool advertise_pip;
	/* PIP IP (sys ip) */
	struct ipaddr pip_ip;
	struct ipaddr pip_ip_static;
	/* PIP MAC (sys MAC) */
	struct ethaddr pip_rmac;
	struct ethaddr pip_rmac_static;
	struct ethaddr pip_rmac_zebra;
	bool is_anycast_mac;
};

/* This structure defines an entry in remote_ip_hash */
struct evpn_remote_ip {
	struct ipaddr addr;
	struct list *macip_path_list;
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

static inline struct bgp_evpn_effective_fq_rt_slu_head *
bgpevpn_get_vrf_export_rtl(struct bgpevpn *vpn)
{
	if (!vpn->bgp_vrf)
		return NULL;

	return &vpn->bgp_vrf->effective_fq_export_rts;
}

static inline struct bgp_evpn_effective_fq_rt_slu_head *
bgpevpn_get_vrf_import_rtl(struct bgpevpn *vpn)
{
	if (!vpn->bgp_vrf)
		return NULL;

	return &vpn->bgp_vrf->effective_fq_import_rts;
}

/* Is at least one manual (non-auto) import route target configured for
 * the VRF?
 */
static inline bool bgp_evpn_vrf_has_manual_import_rt_cfgd(struct bgp *bgp_vrf)
{
	struct bgp_evpn_rt_config *rt_config = bgp_vrf->vrf_route_target_config;

	return bgp_evpn_cfgd_rt_slu_count(&rt_config->cfgd_import);
}

/* Is at least one manual (non-auto) export route target configured for
 * the VRF?
 */
static inline bool bgp_evpn_vrf_has_manual_export_rt_cfgd(struct bgp *bgp_vrf)
{
	struct bgp_evpn_rt_config *rt_config = bgp_vrf->vrf_route_target_config;

	return bgp_evpn_cfgd_rt_slu_count(&rt_config->cfgd_export);
}

/* Is the auto import route target explicitly configured for the VRF,
 * e.g. via "route-target import auto"?
 */
static inline bool bgp_evpn_vrf_has_auto_import_rt_cfgd(struct bgp *bgp_vrf)
{
	struct bgp_evpn_rt_config *rt_config = bgp_vrf->vrf_route_target_config;

	return rt_config->autort_cfgd_import == BGP_EVPN_AUTORT_ADD_ALWAYS;
}

/* Is the auto export route target explicitly configured for the VRF,
 * e.g. via "route-target export auto"?
 */
static inline bool bgp_evpn_vrf_has_auto_export_rt_cfgd(struct bgp *bgp_vrf)
{
	struct bgp_evpn_rt_config *rt_config = bgp_vrf->vrf_route_target_config;

	return rt_config->autort_cfgd_export == BGP_EVPN_AUTORT_ADD_ALWAYS;
}

extern void bgp_evpn_es_evi_vrf_ref(struct bgpevpn *vpn);
extern void bgp_evpn_es_evi_vrf_deref(struct bgpevpn *vpn);

static inline void bgpevpn_unlink_from_l3vni(struct bgpevpn *vpn)
{
	/* bail if vpn is not associated to bgp_vrf */
	if (!vpn->bgp_vrf)
		return;

	UNSET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);
	/* During daemon shutdown, VRF EVPN cleanup may already have freed
	 * bgp_vrf->l2vnis before late VNI teardown runs.
	 */
	if (vpn->bgp_vrf->l2vnis)
		listnode_delete(vpn->bgp_vrf->l2vnis, vpn);

	bgp_evpn_es_evi_vrf_deref(vpn);

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

	/* bail if VRF still doesn't exist */
	bgp_vrf = bgp_lookup_by_vrf_id(vpn->tenant_vrf_id);
	if (!bgp_vrf)
		return;

	/* or if there is no l3vni */
	if (!bgp_vrf->l3vni)
		return;

	/* associate the vpn to the bgp_vrf instance */
	vpn->bgp_vrf = bgp_lock(bgp_vrf);
	listnode_add_sort(bgp_vrf->l2vnis, vpn);

	/*
	 * check if we are advertising two labels for this vpn
	 */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY))
		SET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);

	bgp_evpn_es_evi_vrf_ref(vpn);
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

/* Is at least one manual (non-auto) import route target configured for
 * the L2VNI?
 */
static inline int bgp_evpn_l2vni_has_manual_import_rt_cfgd(struct bgpevpn *vpn)
{
	return bgp_evpn_cfgd_rt_slu_count(&vpn->rt_config->cfgd_import);
}

/* Is at least one manual (non-auto) export route target configured for
 * the L2VNI?
 */
static inline int bgp_evpn_l2vni_has_manual_export_rt_cfgd(struct bgpevpn *vpn)
{
	return bgp_evpn_cfgd_rt_slu_count(&vpn->rt_config->cfgd_export);
}

static inline void encode_es_rt_extcomm(struct ecommunity_val *eval,
					struct ethaddr *mac)
{
	memset(eval, 0, sizeof(struct ecommunity_val));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT;
	memcpy(&eval->val[2], mac, ETH_ALEN);
}

static inline void encode_df_elect_extcomm(struct ecommunity_val *eval,
					   uint16_t pref)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_DF_ELECTION;
	eval->val[2] = EVPN_MH_DF_ALG_PREF;
	eval->val[6] = (pref >> 8) & 0xff;
	eval->val[7] = pref & 0xff;
}

static inline void encode_esi_label_extcomm(struct ecommunity_val *eval,
					bool single_active)
{
	memset(eval, 0, sizeof(struct ecommunity_val));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ESI_LABEL;
	if (single_active)
		eval->val[2] |= (1 << 0);
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
					  bool na_flag, bool proxy)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ND;
	if (na_flag)
		eval->val[2] |= ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG;
	if (proxy)
		eval->val[2] |= ECOMMUNITY_EVPN_SUBTYPE_PROXY_FLAG;
}

static inline void ip_prefix_from_type5_prefix(const struct prefix_evpn *evp,
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

static inline bool is_evpn_prefix_default(const struct prefix *evp)
{
	if (evp->family != AF_EVPN)
		return false;

	/*
	 * EVPN default type-5 route
	 * RD:[5]:[0]:[0.0.0.0/0]/352 or RD:[5]:[0]:[::/0]/352
	 */
	if ((evp->u.prefix_evpn.route_type == BGP_EVPN_IP_PREFIX_ROUTE) &&
	    (evp->u.prefix_evpn.prefix_addr.ip_prefix_length == 0))
		return true;

	return false;
}

static inline void ip_prefix_from_type2_prefix(const struct prefix_evpn *evp,
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

static inline void ip_prefix_from_evpn_prefix(const struct prefix_evpn *evp,
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
	memcpy(&p->prefix.macip_addr.ip, ip, sizeof(*ip));
}

static inline void
build_type5_prefix_from_ip_prefix(struct prefix_evpn *evp,
				  const struct prefix *ip_prefix)
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
					   struct ipaddr *originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
	if (IS_IPADDR_V4(originator_ip))
		p->prefix.imet_addr.ip_prefix_length = IPV4_MAX_BITLEN;
	else if (IS_IPADDR_V6(originator_ip))
		p->prefix.imet_addr.ip_prefix_length = IPV6_MAX_BITLEN;
	p->prefix.imet_addr.ip = *originator_ip;
}

static inline void build_evpn_type4_prefix(struct prefix_evpn *p, esi_t *esi,
					   struct ipaddr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_ES_ROUTE;
	/* Set IP prefix length and address based on originator_ip type */
	if (IS_IPADDR_V4(&originator_ip))
		p->prefix.es_addr.ip_prefix_length = IPV4_MAX_BITLEN;
	else if (IS_IPADDR_V6(&originator_ip))
		p->prefix.es_addr.ip_prefix_length = IPV6_MAX_BITLEN;
	else
		p->prefix.es_addr.ip_prefix_length = IPADDR_NONE;

	p->prefix.es_addr.ip = originator_ip;
	memcpy(&p->prefix.es_addr.esi, esi, sizeof(esi_t));
}

static inline void build_evpn_type1_prefix(struct prefix_evpn *p, uint32_t eth_tag, esi_t *esi,
					   struct ipaddr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_AD_ROUTE;
	p->prefix.ead_addr.eth_tag = eth_tag;
	/* Set IP address and type based on originator_ip */
	if (IS_IPADDR_V4(&originator_ip)) {
		SET_IPADDR_V4(&p->prefix.ead_addr.ip);
		IPV4_ADDR_COPY(&p->prefix.ead_addr.ip.ipaddr_v4, &originator_ip.ipaddr_v4);
	} else if (IS_IPADDR_V6(&originator_ip)) {
		SET_IPADDR_V6(&p->prefix.ead_addr.ip);
		IPV6_ADDR_COPY(&p->prefix.ead_addr.ip.ipaddr_v6, &originator_ip.ipaddr_v6);
	} else {
		/* IPADDR_NONE - should not happen, but handle gracefully */
		p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		memset(&p->prefix.ead_addr.ip.ipaddr_v4, 0,
		       sizeof(p->prefix.ead_addr.ip.ipaddr_v4));
	}
	memcpy(&p->prefix.ead_addr.esi, esi, sizeof(esi_t));
}

static inline void evpn_type1_prefix_global_copy(struct prefix_evpn *global_p,
		const struct prefix_evpn *vni_p)
{
	memcpy(global_p, vni_p, sizeof(*global_p));
	/* EAD prefix in global table doesn't include VTEP IP - zero it out
	 * but preserve ipa_type to maintain address family information
	 */
	if (IS_IPADDR_V4(&vni_p->prefix.ead_addr.ip)) {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_V4;
		global_p->prefix.ead_addr.ip.ipaddr_v4.s_addr = INADDR_ANY;
	} else if (IS_IPADDR_V6(&vni_p->prefix.ead_addr.ip)) {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_V6;
		/* Use standard IPv6 "any" address (::) via IN6ADDR_ANY_INIT */
		global_p->prefix.ead_addr.ip.ipaddr_v6 = (struct in6_addr)IN6ADDR_ANY_INIT;
	} else {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		/* ipa_type is IPADDR_NONE, zero everything */
		memset(&global_p->prefix.ead_addr.ip, 0, sizeof(struct ipaddr));
	}
	global_p->prefix.ead_addr.frag_id = 0;
}

/* EAD prefix in the global table doesn't include the VTEP-IP so
 * we need to create a different copy for the VNI
 */
static inline struct prefix_evpn *
evpn_type1_prefix_vni_ip_copy(struct prefix_evpn *vni_p,
			      const struct prefix_evpn *global_p,
			      const struct attr *attr)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	/* Extract originator IP from attr based on nexthop length */
	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4 ||
	    attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV4) {
		/* IPv4 nexthop */
		SET_IPADDR_V4(&vni_p->prefix.ead_addr.ip);
		IPV4_ADDR_COPY(&vni_p->prefix.ead_addr.ip.ipaddr_v4, &attr->nexthop);
	} else if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
		/* IPv6 nexthop - use global address */
		SET_IPADDR_V6(&vni_p->prefix.ead_addr.ip);
		IPV6_ADDR_COPY(&vni_p->prefix.ead_addr.ip.ipaddr_v6, &attr->mp_nexthop_global);
	} else {
		/* IPADDR_NONE - should not happen, but handle gracefully */
		vni_p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		memset(&vni_p->prefix.ead_addr.ip, 0, sizeof(vni_p->prefix.ead_addr.ip));
	}

	return vni_p;
}

static inline void evpn_type2_prefix_global_copy(
	struct prefix_evpn *global_p, const struct prefix_evpn *vni_p,
	const struct ethaddr *mac, const struct ipaddr *ip)
{
	memcpy(global_p, vni_p, sizeof(*global_p));

	if (mac)
		global_p->prefix.macip_addr.mac = *mac;

	if (ip)
		global_p->prefix.macip_addr.ip = *ip;
}

static inline void
evpn_type2_prefix_vni_ip_copy(struct prefix_evpn *vni_p,
			      const struct prefix_evpn *global_p)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	memset(&vni_p->prefix.macip_addr.mac, 0, sizeof(struct ethaddr));
}

static inline void
evpn_type2_prefix_vni_mac_copy(struct prefix_evpn *vni_p,
			       const struct prefix_evpn *global_p)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	memset(&vni_p->prefix.macip_addr.ip, 0, sizeof(struct ipaddr));
}

/* Get MAC of path_info prefix */
static inline struct ethaddr *
evpn_type2_path_info_get_mac(const struct bgp_path_info *local_pi)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	return &local_pi->extra->evpn->vni_info.mac;
}

/* Get IP of path_info prefix */
static inline struct ipaddr *
evpn_type2_path_info_get_ip(const struct bgp_path_info *local_pi)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	return &local_pi->extra->evpn->vni_info.ip;
}

/* Set MAC of path_info prefix */
static inline void evpn_type2_path_info_set_mac(struct bgp_path_info *local_pi,
						const struct ethaddr mac)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	local_pi->extra->evpn->vni_info.mac = mac;
}

/* Set IP of path_info prefix */
static inline void evpn_type2_path_info_set_ip(struct bgp_path_info *local_pi,
					       const struct ipaddr ip)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	local_pi->extra->evpn->vni_info.ip = ip;
}

/* Is the IP empty for the RT's dest? */
static inline bool is_evpn_type2_dest_ipaddr_none(const struct bgp_dest *dest)
{
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);
	return is_evpn_prefix_ipaddr_none(evp);
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

static inline bool bgp_evpn_is_svi_macip_enabled(struct bgpevpn *vpn)
{
	struct bgp *bgp_evpn = NULL;

	bgp_evpn = bgp_get_evpn();

	return (bgp_evpn->evpn_info->advertise_svi_macip ||
		vpn->advertise_svi_macip);
}

static inline bool bgp_evpn_is_path_local(struct bgp *bgp,
		struct bgp_path_info *pi)
{
	return (pi->peer == bgp->peer_self
			&& pi->type == ZEBRA_ROUTE_BGP
			&& pi->sub_type == BGP_ROUTE_STATIC);
}

extern void bgp_evpn_install_uninstall_default_route(struct bgp *bgp_vrf, afi_t afi, safi_t safi,
						     struct bgp_path_info *originator, bool add);
extern void bgp_evpn_l2vni_regenerate_effective_import_rts(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_l2vni_regenerate_effective_export_rts(struct bgp *bgp, struct bgpevpn *vpn);
extern void bgp_evpn_configure_export_rt_for_vrf(struct bgp *bgp_vrf,
						 struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_configure_export_auto_rt_for_vrf(struct bgp *bgp_vrf);
extern void bgp_evpn_unconfigure_export_rt_for_vrf(struct bgp *bgp_vrf,
						   const struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_unconfigure_export_auto_rt_for_vrf(struct bgp *bgp_vrf);
extern void bgp_evpn_configure_import_rt_for_vrf(struct bgp *bgp_vrf,
						 struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_configure_import_auto_rt_for_vrf(struct bgp *bgp_vrf);
extern void bgp_evpn_unconfigure_import_rt_for_vrf(struct bgp *bgp_vrf,
						   const struct bgp_evpn_cfgd_rt *cfgd_rt);
extern void bgp_evpn_unconfigure_import_auto_rt_for_vrf(struct bgp *bgp_vrf);
extern int bgp_evpn_handle_export_rt_change(struct bgp *bgp,
					    struct bgpevpn *vpn);
extern void bgp_evpn_handle_autort_change(struct bgp *bgp);
extern void bgp_evpn_handle_vrf_rd_change(struct bgp *bgp_vrf, int withdraw);
extern void bgp_evpn_handle_rd_change(struct bgp *bgp, struct bgpevpn *vpn,
				      int withdraw);
void bgp_evpn_handle_global_macvrf_soo_change(struct bgp *bgp,
					      struct ecommunity *new_soo);
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
		struct ipaddr *originator_ip,
		vrf_id_t tenant_vrf_id,
		struct in_addr mcast_grp,
		ifindex_t svi_ifindex);
extern void bgp_evpn_free(struct bgp *bgp, struct bgpevpn *vpn);
extern bool bgp_evpn_lookup_l3vni_l2vni_table(vni_t vni);
extern int update_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn);
extern struct bgp_path_info *delete_evpn_route_entry(struct bgp *bgp, afi_t afi, safi_t safi,
						     struct bgp_dest *dest,
						     const struct bgp_path_info *originator,
						     uint32_t addpaht_id);
int vni_list_cmp(void *p1, void *p2);
extern int evpn_route_select_install(struct bgp *bgp, struct bgpevpn *vpn,
				     struct bgp_dest *dest,
				     struct bgp_path_info *pi);
extern struct bgp_dest *
bgp_evpn_global_node_get(struct bgp_table *table, afi_t afi, safi_t safi,
			 const struct prefix_evpn *evp, struct prefix_rd *prd,
			 const struct bgp_path_info *local_pi);
extern struct bgp_dest *bgp_evpn_global_node_lookup(
	struct bgp_table *table, safi_t safi, const struct prefix_evpn *evp,
	struct prefix_rd *prd, const struct bgp_path_info *local_pi);
extern struct bgp_dest *
bgp_evpn_vni_ip_node_get(struct bgp_table *const table,
			 const struct prefix_evpn *evp,
			 const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_ip_node_lookup(const struct bgp_table *const table,
			    const struct prefix_evpn *evp,
			    const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_mac_node_get(struct bgp_table *const table,
			  const struct prefix_evpn *evp,
			  const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_mac_node_lookup(const struct bgp_table *const table,
			     const struct prefix_evpn *evp,
			     const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_node_get(struct bgpevpn *vpn, const struct prefix_evpn *p,
		      const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_node_lookup(const struct bgpevpn *vpn, const struct prefix_evpn *p,
			 const struct bgp_path_info *parent_pi);

extern void bgp_evpn_import_route_in_vrfs(struct bgp_path_info *pi, int import);
extern void bgp_evpn_update_type2_route_entry(struct bgp *bgp,
					      struct bgpevpn *vpn,
					      struct bgp_dest *rn,
					      struct bgp_path_info *local_pi,
					      const char *caller);
extern int bgp_evpn_route_entry_install_if_vrf_match(struct bgp *bgp_vrf,
						     struct bgp_path_info *pi,
						     int install);
extern void bgp_evpn_import_type2_route(struct bgp_path_info *pi, int import);
extern void bgp_evpn_xxport_delete_ecomm(void *val);
extern int bgp_evpn_route_target_cmp(struct ecommunity *ecom1,
				     struct ecommunity *ecom2);
extern void bgp_evpn_handle_deferred_bestpath_for_vnis(struct bgp *bgp, uint16_t cnt);
extern uint16_t bgp_deferred_path_selection(struct bgp *bgp, afi_t afi, safi_t safi,
					    struct bgp_table *table, uint16_t cnt,
					    struct bgpevpn *vpn, bool evpn_select);

#endif /* _BGP_EVPN_PRIVATE_H */
