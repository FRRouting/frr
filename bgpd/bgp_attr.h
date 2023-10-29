// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP attributes.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_ATTR_H
#define _QUAGGA_BGP_ATTR_H

#include "mpls.h"
#include "bgp_attr_evpn.h"
#include "bgpd/bgp_encap_types.h"
#include "srte.h"

/* Simple bit mapping. */
#define BITMAP_NBBY 8

#define SET_BITMAP(MAP, NUM)                                                   \
	SET_FLAG(MAP[(NUM) / BITMAP_NBBY], 1 << ((NUM) % BITMAP_NBBY))

#define CHECK_BITMAP(MAP, NUM)                                                 \
	CHECK_FLAG(MAP[(NUM) / BITMAP_NBBY], 1 << ((NUM) % BITMAP_NBBY))

#define BGP_MED_MAX UINT32_MAX

/* BGP Attribute type range. */
#define BGP_ATTR_TYPE_RANGE     256
#define BGP_ATTR_BITMAP_SIZE    (BGP_ATTR_TYPE_RANGE / BITMAP_NBBY)

/* BGP Attribute flags. */
#define BGP_ATTR_FLAG_OPTIONAL  0x80	/* Attribute is optional. */
#define BGP_ATTR_FLAG_TRANS     0x40	/* Attribute is transitive. */
#define BGP_ATTR_FLAG_PARTIAL   0x20	/* Attribute is partial. */
#define BGP_ATTR_FLAG_EXTLEN    0x10	/* Extended length flag. */

/* BGP attribute header must bigger than 2. */
#define BGP_ATTR_MIN_LEN        3       /* Attribute flag, type length. */
#define BGP_ATTR_DEFAULT_WEIGHT 32768

/* Valid lengths for mp_nexthop_len */
#define BGP_ATTR_NHLEN_IPV4               IPV4_MAX_BYTELEN
#define BGP_ATTR_NHLEN_VPNV4              8+IPV4_MAX_BYTELEN
#define BGP_ATTR_NHLEN_IPV6_GLOBAL        IPV6_MAX_BYTELEN
#define BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL (IPV6_MAX_BYTELEN * 2)
#define BGP_ATTR_NHLEN_VPNV6_GLOBAL       8+IPV6_MAX_BYTELEN
#define BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL ((8+IPV6_MAX_BYTELEN) * 2)

/* Prefix SID types */
#define BGP_PREFIX_SID_LABEL_INDEX     1
#define BGP_PREFIX_SID_IPV6            2
#define BGP_PREFIX_SID_ORIGINATOR_SRGB 3
#define BGP_PREFIX_SID_VPN_SID 4
#define BGP_PREFIX_SID_SRV6_L3_SERVICE 5
#define BGP_PREFIX_SID_SRV6_L2_SERVICE 6

#define BGP_PREFIX_SID_LABEL_INDEX_LENGTH      7
#define BGP_PREFIX_SID_IPV6_LENGTH            19
#define BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH  6
#define BGP_PREFIX_SID_VPN_SID_LENGTH         19

/* SRv6 Service Sub-TLV types */
#define BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO 1
#define BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH 21

/* SRv6 Service Data Sub-Sub-TLV types */
#define BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE 1
#define BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH 6

#define BGP_ATTR_NH_AFI(afi, attr) \
	((afi != AFI_L2VPN) ? afi : \
	((attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4) ? AFI_IP : AFI_IP6))

/* PMSI tunnel types (RFC 6514) */

struct bgp_attr_encap_subtlv {
	struct bgp_attr_encap_subtlv *next; /* for chaining */
	/* Reference count of this attribute. */
	unsigned long refcnt;
	uint16_t type;
	uint16_t length;
	uint8_t value[0]; /* will be extended */
};

#ifdef ENABLE_BGP_VNC
/*
 * old rfp<->rfapi representation
 */
struct bgp_tea_options {
	struct bgp_tea_options *next;
	uint8_t options_count;
	uint16_t options_length; /* each TLV may be 256 in length */
	uint8_t type;
	uint8_t length;
	void *value; /* pointer to data */
};

#endif

enum pta_type {
	PMSI_TNLTYPE_NO_INFO = 0,
	PMSI_TNLTYPE_RSVP_TE_P2MP,
	PMSI_TNLTYPE_MLDP_P2MP,
	PMSI_TNLTYPE_PIM_SSM,
	PMSI_TNLTYPE_PIM_SM,
	PMSI_TNLTYPE_PIM_BIDIR,
	PMSI_TNLTYPE_INGR_REPL,
	PMSI_TNLTYPE_MLDP_MP2MP,
	PMSI_TNLTYPE_MAX = PMSI_TNLTYPE_MLDP_MP2MP
};

/*
 * Prefix-SID type-4
 * SRv6-VPN-SID-TLV
 * draft-dawra-idr-srv6-vpn-04
 */
struct bgp_attr_srv6_vpn {
	unsigned long refcnt;
	uint8_t sid_flags;
	struct in6_addr sid;
};

/*
 * Prefix-SID type-5
 * SRv6-L3VPN-Service-TLV
 * draft-dawra-idr-srv6-vpn-05
 */
struct bgp_attr_srv6_l3vpn {
	unsigned long refcnt;
	uint8_t sid_flags;
	uint16_t endpoint_behavior;
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint8_t transposition_len;
	uint8_t transposition_offset;
};

/* BGP core attribute structure. */
struct attr {
	/* AS Path structure */
	struct aspath *aspath;

	/* Community structure */
	struct community *community;

	/* Reference count of this attribute. */
	unsigned long refcnt;

	/* Flag of attribute is set or not. */
	uint64_t flag;

	/* Apart from in6_addr, the remaining static attributes */
	struct in_addr nexthop;
	uint32_t med;
	uint32_t local_pref;
	ifindex_t nh_ifindex;

	/* Path origin attribute */
	uint8_t origin;

	/* PMSI tunnel type (RFC 6514). */
	enum pta_type pmsi_tnl_type;

	/* has the route-map changed any attribute?
	   Used on the peer outbound side. */
	uint32_t rmap_change_flags;

	/* Multi-Protocol Nexthop, AFI IPv6 */
	struct in6_addr mp_nexthop_global;
	struct in6_addr mp_nexthop_local;

	/* ifIndex corresponding to mp_nexthop_local. */
	ifindex_t nh_lla_ifindex;

	/* Extended Communities attribute. */
	struct ecommunity *ecommunity;

	/* Extended Communities attribute. */
	struct ecommunity *ipv6_ecommunity;

	/* Large Communities attribute. */
	struct lcommunity *lcommunity;

	/* Route-Reflector Cluster attribute */
	struct cluster_list *cluster1;

	/* Unknown transitive attribute. */
	struct transit *transit;

	struct in_addr mp_nexthop_global_in;

	/* Aggregator Router ID attribute */
	struct in_addr aggregator_addr;

	/* Route Reflector Originator attribute */
	struct in_addr originator_id;

	/* Local weight, not actually an attribute */
	uint32_t weight;

	/* Aggregator ASN */
	as_t aggregator_as;

	/* MP Nexthop length */
	uint8_t mp_nexthop_len;

	/* MP Nexthop preference */
	uint8_t mp_nexthop_prefer_global;

	/* Static MAC for EVPN */
	uint8_t sticky;

	/* Flag for default gateway extended community in EVPN */
	uint8_t default_gw;

	/* NA router flag (R-bit) support in EVPN */
	uint8_t router_flag;

	/* ES info */
	uint8_t es_flags;
	/* Path is not "locally-active" on the advertising VTEP. This is
	 * translated into an ARP-ND ECOM.
	 */
#define ATTR_ES_PROXY_ADVERT (1 << 0)
	/* Destination ES is present locally. This flag is set on local
	 * paths and sync paths
	 */
#define ATTR_ES_IS_LOCAL (1 << 1)
	/* There are one or more non-best paths from ES peers. Note that
	 * this flag is only set on the local MAC-IP paths in the VNI
	 * route table (not set in the global routing table). And only
	 * non-proxy advertisements from an ES peer can result in this
	 * flag being set.
	 */
#define ATTR_ES_PEER_ACTIVE (1 << 2)
	/* There are one or more non-best proxy paths from ES peers */
#define ATTR_ES_PEER_PROXY (1 << 3)
	/* An ES peer has router bit set - only applicable if
	 * ATTR_ES_PEER_ACTIVE is set
	 */
#define ATTR_ES_PEER_ROUTER (1 << 4)

	/* These two flags are only set on L3 routes installed in a
	 * VRF as a result of EVPN MAC-IP route
	 * XXX - while splitting up per-family attrs these need to be
	 * classified as non-EVPN
	 */
#define ATTR_ES_L3_NHG_USE (1 << 5)
#define ATTR_ES_L3_NHG_ACTIVE (1 << 6)
#define ATTR_ES_L3_NHG (ATTR_ES_L3_NHG_USE | ATTR_ES_L3_NHG_ACTIVE)

	/* route tag */
	route_tag_t tag;

	/* Label index */
	uint32_t label_index;

	/* MPLS label */
	mpls_label_t label;

	/* SRv6 VPN SID */
	struct bgp_attr_srv6_vpn *srv6_vpn;

	/* SRv6 L3VPN SID */
	struct bgp_attr_srv6_l3vpn *srv6_l3vpn;

	uint16_t encap_tunneltype;		     /* grr */
	struct bgp_attr_encap_subtlv *encap_subtlvs; /* rfc5512 */

#ifdef ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs; /* VNC-specific */
#endif
	/* EVPN */
	struct bgp_route_evpn evpn_overlay;

	/* EVPN MAC Mobility sequence number, if any. */
	uint32_t mm_seqnum;
	/* highest MM sequence number rxed in a MAC-IP route from an
	 * ES peer (this includes both proxy and non-proxy MAC-IP
	 * advertisements from ES peers).
	 * This is only applicable to local paths in the VNI routing
	 * table and derived from other imported/non-best paths.
	 */
	uint32_t mm_sync_seqnum;

	/* EVPN local router-mac */
	struct ethaddr rmac;

	/* Distance as applied by Route map */
	uint8_t distance;

	/* rmap set table */
	uint32_t rmap_table_id;

	/* Link bandwidth value, if any. */
	uint32_t link_bw;

	/* EVPN ES */
	esi_t esi;

	/* SR-TE Color */
	uint32_t srte_color;

	/* EVPN DF preference and algorithm for DF election on local ESs */
	uint16_t df_pref;
	uint8_t df_alg;

	/* Nexthop type */
	enum nexthop_types_t nh_type;

	/* If NEXTHOP_TYPE_BLACKHOLE, then blackhole type */
	enum blackhole_type bh_type;

	/* OTC value if set */
	uint32_t otc;

	/* AIGP Metric */
	uint64_t aigp_metric;
};

/* rmap_change_flags definition */
#define BATTR_RMAP_IPV4_NHOP_CHANGED (1 << 0)
#define BATTR_RMAP_NEXTHOP_PEER_ADDRESS (1 << 1)
#define BATTR_REFLECTED (1 << 2)
#define BATTR_RMAP_NEXTHOP_UNCHANGED (1 << 3)
#define BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED (1 << 4)
#define BATTR_RMAP_IPV6_LL_NHOP_CHANGED (1 << 5)
#define BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED (1 << 6)
#define BATTR_RMAP_LINK_BW_SET (1 << 7)
#define BATTR_RMAP_L3VPN_ACCEPT_GRE (1 << 8)
#define BATTR_RMAP_VPNV4_NHOP_CHANGED (1 << 9)
#define BATTR_RMAP_VPNV6_GLOBAL_NHOP_CHANGED (1 << 10)

/* Router Reflector related structure. */
struct cluster_list {
	unsigned long refcnt;
	int length;
	struct in_addr *list;
};

/* Unknown transit attribute. */
struct transit {
	unsigned long refcnt;
	int length;
	uint8_t *val;
};

/* "(void) 0" will generate a compiler error.  this is a safety check to
 * ensure we're not using a value that exceeds the bit size of attr->flag. */
#define ATTR_FLAG_BIT(X)                                                       \
	__builtin_choose_expr((X) >= 1 && (X) <= 64, 1ULL << ((X)-1), (void)0)

#define BGP_CLUSTER_LIST_LENGTH(attr)                                          \
	(((attr)->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))                 \
		 ? bgp_attr_get_cluster((attr))->length                        \
		 : 0)

enum bgp_attr_parse_ret {
	BGP_ATTR_PARSE_PROCEED = 0,
	BGP_ATTR_PARSE_ERROR = -1,
	BGP_ATTR_PARSE_WITHDRAW = -2,

	/* only used internally, send notify + convert to BGP_ATTR_PARSE_ERROR
	 */
	BGP_ATTR_PARSE_ERROR_NOTIFYPLS = -3,
	BGP_ATTR_PARSE_MISSING_MANDATORY = -4,
};

struct bpacket_attr_vec_arr;

/* Prototypes. */
extern void bgp_attr_init(void);
extern void bgp_attr_finish(void);
extern enum bgp_attr_parse_ret
bgp_attr_parse(struct peer *peer, struct attr *attr, bgp_size_t size,
	       struct bgp_nlri *mp_update, struct bgp_nlri *mp_withdraw);
extern struct attr *bgp_attr_intern(struct attr *attr);
extern void bgp_attr_unintern_sub(struct attr *attr);
extern void bgp_attr_unintern(struct attr **pattr);
extern void bgp_attr_flush(struct attr *attr);
extern struct attr *bgp_attr_default_set(struct attr *attr, struct bgp *bgp,
					 uint8_t origin);
extern struct attr *bgp_attr_aggregate_intern(
	struct bgp *bgp, uint8_t origin, struct aspath *aspath,
	struct community *community, struct ecommunity *ecommunity,
	struct lcommunity *lcommunity, struct bgp_aggregate *aggregate,
	uint8_t atomic_aggregate, const struct prefix *p);
extern bgp_size_t bgp_packet_attribute(
	struct bgp *bgp, struct peer *peer, struct stream *s, struct attr *attr,
	struct bpacket_attr_vec_arr *vecarr, struct prefix *p, afi_t afi,
	safi_t safi, struct peer *from, struct prefix_rd *prd,
	mpls_label_t *label, uint32_t num_labels, bool addpath_capable,
	uint32_t addpath_tx_id, struct bgp_path_info *bpi);
extern void bgp_dump_routes_attr(struct stream *s, struct bgp_path_info *bpi,
				 const struct prefix *p);
extern bool attrhash_cmp(const void *arg1, const void *arg2);
extern unsigned int attrhash_key_make(const void *p);
extern void attr_show_all(struct vty *vty);
extern unsigned long int attr_count(void);
extern unsigned long int attr_unknown_count(void);
extern void bgp_path_attribute_discard_vty(struct vty *vty, struct peer *peer,
					   const char *discard_attrs, bool set);
extern void bgp_path_attribute_withdraw_vty(struct vty *vty, struct peer *peer,
					    const char *withdraw_attrs,
					    bool set);
extern enum bgp_attr_parse_ret bgp_attr_ignore(struct peer *peer, uint8_t type);

/* Cluster list prototypes. */
extern bool cluster_loop_check(struct cluster_list *cluster,
			       struct in_addr originator);

/* Below exported for unit-test purposes only */
struct bgp_attr_parser_args {
	struct peer *peer;
	bgp_size_t length; /* attribute data length; */
	bgp_size_t total;  /* total length, inc header */
	struct attr *attr;
	uint8_t type;
	uint8_t flags;
	uint8_t *startp;
};
extern int bgp_mp_reach_parse(struct bgp_attr_parser_args *args,
			      struct bgp_nlri *mp_update);
extern int bgp_mp_unreach_parse(struct bgp_attr_parser_args *args,
				struct bgp_nlri *mp_withdraw);
extern enum bgp_attr_parse_ret
bgp_attr_prefix_sid(struct bgp_attr_parser_args *args);

extern struct bgp_attr_encap_subtlv *
encap_tlv_dup(struct bgp_attr_encap_subtlv *orig);

extern void bgp_attr_flush_encap(struct attr *attr);

extern void bgp_attr_extcom_tunnel_type(struct attr *attr,
					 bgp_encap_types *tunnel_type);

/**
 * Set of functions to encode MP_REACH_NLRI and MP_UNREACH_NLRI attributes.
 * Typical call sequence is to call _start(), followed by multiple _prefix(),
 * one for each NLRI that needs to be encoded into the UPDATE message, and
 * finally the _end() function.
 */
extern size_t bgp_packet_mpattr_start(struct stream *s, struct peer *peer,
				      afi_t afi, safi_t safi,
				      struct bpacket_attr_vec_arr *vecarr,
				      struct attr *attr);
extern void bgp_packet_mpattr_prefix(struct stream *s, afi_t afi, safi_t safi,
				     const struct prefix *p,
				     const struct prefix_rd *prd,
				     mpls_label_t *label, uint32_t num_labels,
				     bool addpath_capable,
				     uint32_t addpath_tx_id, struct attr *);
extern size_t bgp_packet_mpattr_prefix_size(afi_t afi, safi_t safi,
					    const struct prefix *p);
extern void bgp_packet_mpattr_end(struct stream *s, size_t sizep);

extern size_t bgp_packet_mpunreach_start(struct stream *s, afi_t afi,
					 safi_t safi);
extern void bgp_packet_mpunreach_prefix(
	struct stream *s, const struct prefix *p, afi_t afi, safi_t safi,
	const struct prefix_rd *prd, mpls_label_t *label, uint32_t num_labels,
	bool addpath_capable, uint32_t addpath_tx_id, struct attr *attr);
extern void bgp_packet_mpunreach_end(struct stream *s, size_t attrlen_pnt);

extern enum bgp_attr_parse_ret bgp_attr_nexthop_valid(struct peer *peer,
						      struct attr *attr);

extern uint32_t bgp_attr_get_color(struct attr *attr);

static inline bool bgp_rmap_nhop_changed(uint32_t out_rmap_flags,
					 uint32_t in_rmap_flags)
{
	return ((CHECK_FLAG(out_rmap_flags, BATTR_RMAP_NEXTHOP_PEER_ADDRESS) ||
		 CHECK_FLAG(out_rmap_flags, BATTR_RMAP_NEXTHOP_UNCHANGED) ||
		 CHECK_FLAG(out_rmap_flags, BATTR_RMAP_IPV4_NHOP_CHANGED) ||
		 CHECK_FLAG(out_rmap_flags, BATTR_RMAP_VPNV4_NHOP_CHANGED) ||
		 CHECK_FLAG(out_rmap_flags,
			    BATTR_RMAP_VPNV6_GLOBAL_NHOP_CHANGED) ||
		 CHECK_FLAG(out_rmap_flags,
			    BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED) ||
		 CHECK_FLAG(out_rmap_flags,
			    BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED) ||
		 CHECK_FLAG(out_rmap_flags, BATTR_RMAP_IPV6_LL_NHOP_CHANGED) ||
		 CHECK_FLAG(in_rmap_flags, BATTR_RMAP_NEXTHOP_UNCHANGED))
			? true
			: false);
}

static inline uint32_t mac_mobility_seqnum(struct attr *attr)
{
	return (attr) ? attr->mm_seqnum : 0;
}

static inline enum pta_type bgp_attr_get_pmsi_tnl_type(struct attr *attr)
{
	return attr->pmsi_tnl_type;
}

static inline void bgp_attr_set_pmsi_tnl_type(struct attr *attr,
					      enum pta_type pmsi_tnl_type)
{
	attr->pmsi_tnl_type = pmsi_tnl_type;
}

static inline struct ecommunity *
bgp_attr_get_ecommunity(const struct attr *attr)
{
	return attr->ecommunity;
}

static inline void bgp_attr_set_ecommunity(struct attr *attr,
					   struct ecommunity *ecomm)
{
	attr->ecommunity = ecomm;

	if (ecomm)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));
	else
		UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));
}

static inline struct lcommunity *
bgp_attr_get_lcommunity(const struct attr *attr)
{
	return attr->lcommunity;
}

static inline void bgp_attr_set_lcommunity(struct attr *attr,
					   struct lcommunity *lcomm)
{
	attr->lcommunity = lcomm;

	if (lcomm)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES));
	else
		UNSET_FLAG(attr->flag,
			   ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES));
}

static inline struct community *bgp_attr_get_community(const struct attr *attr)
{
	return attr->community;
}

static inline void bgp_attr_set_community(struct attr *attr,
					  struct community *comm)
{
	attr->community = comm;

	if (comm)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES));
	else
		UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES));
}

static inline struct ecommunity *
bgp_attr_get_ipv6_ecommunity(const struct attr *attr)
{
	return attr->ipv6_ecommunity;
}

static inline void bgp_attr_set_ipv6_ecommunity(struct attr *attr,
						struct ecommunity *ipv6_ecomm)
{
	attr->ipv6_ecommunity = ipv6_ecomm;

	if (ipv6_ecomm)
		SET_FLAG(attr->flag,
			 ATTR_FLAG_BIT(BGP_ATTR_IPV6_EXT_COMMUNITIES));
	else
		UNSET_FLAG(attr->flag,
			   ATTR_FLAG_BIT(BGP_ATTR_IPV6_EXT_COMMUNITIES));
}

static inline struct transit *bgp_attr_get_transit(const struct attr *attr)
{
	return attr->transit;
}

static inline void bgp_attr_set_transit(struct attr *attr,
					struct transit *transit)
{
	attr->transit = transit;
}

static inline uint64_t bgp_attr_get_aigp_metric(const struct attr *attr)
{
	return attr->aigp_metric;
}

static inline void bgp_attr_set_aigp_metric(struct attr *attr, uint64_t aigp)
{
	attr->aigp_metric = aigp;

	if (aigp)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_AIGP));
}

static inline struct cluster_list *bgp_attr_get_cluster(const struct attr *attr)
{
	return attr->cluster1;
}

static inline void bgp_attr_set_cluster(struct attr *attr,
					struct cluster_list *cl)
{
	attr->cluster1 = cl;

	if (cl)
		SET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST));
	else
		UNSET_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST));
}

static inline const struct bgp_route_evpn *
bgp_attr_get_evpn_overlay(const struct attr *attr)
{
	return &attr->evpn_overlay;
}

static inline void bgp_attr_set_evpn_overlay(struct attr *attr,
					     struct bgp_route_evpn *eo)
{
	memcpy(&attr->evpn_overlay, eo, sizeof(struct bgp_route_evpn));
}

static inline struct bgp_attr_encap_subtlv *
bgp_attr_get_vnc_subtlvs(const struct attr *attr)
{
#ifdef ENABLE_BGP_VNC
	return attr->vnc_subtlvs;
#else
	return NULL;
#endif
}

static inline void
bgp_attr_set_vnc_subtlvs(struct attr *attr,
			 struct bgp_attr_encap_subtlv *vnc_subtlvs)
{
#ifdef ENABLE_BGP_VNC
	attr->vnc_subtlvs = vnc_subtlvs;
#endif
}

extern bool route_matches_soo(struct bgp_path_info *pi, struct ecommunity *soo);

#endif /* _QUAGGA_BGP_ATTR_H */
