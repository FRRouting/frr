/* BGP attributes.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_ATTR_H
#define _QUAGGA_BGP_ATTR_H

#include "mpls.h"
#include "bgp_attr_evpn.h"

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

#define BGP_PREFIX_SID_LABEL_INDEX_LENGTH      7
#define BGP_PREFIX_SID_IPV6_LENGTH            19
#define BGP_PREFIX_SID_ORIGINATOR_SRGB_LENGTH  6

/* PMSI tunnel types (RFC 6514) */

struct bgp_attr_encap_subtlv {
	struct bgp_attr_encap_subtlv *next; /* for chaining */
	/* Reference count of this attribute. */
	unsigned long refcnt;
	uint16_t type;
	uint16_t length;
	uint8_t value[0]; /* will be extended */
};

#if ENABLE_BGP_VNC
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

/* Overlay Index Info */
struct overlay_index {
	struct eth_segment_id eth_s_id;
	union gw_addr gw_ip;
};

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

	/* Large Communities attribute. */
	struct lcommunity *lcommunity;

	/* Route-Reflector Cluster attribute */
	struct cluster_list *cluster;

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

	/* route tag */
	route_tag_t tag;

	/* Label index */
	uint32_t label_index;

	/* MPLS label */
	mpls_label_t label;

	uint16_t encap_tunneltype;		     /* grr */
	struct bgp_attr_encap_subtlv *encap_subtlvs; /* rfc5512 */

#if ENABLE_BGP_VNC
	struct bgp_attr_encap_subtlv *vnc_subtlvs; /* VNC-specific */
#endif
	/* EVPN */
	struct overlay_index evpn_overlay;

	/* EVPN MAC Mobility sequence number, if any. */
	uint32_t mm_seqnum;

	/* EVPN local router-mac */
	struct ethaddr rmac;
};

/* rmap_change_flags definition */
#define BATTR_RMAP_IPV4_NHOP_CHANGED (1 << 0)
#define BATTR_RMAP_NEXTHOP_PEER_ADDRESS (1 << 1)
#define BATTR_REFLECTED (1 << 2)
#define BATTR_RMAP_NEXTHOP_UNCHANGED (1 << 3)
#define BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED (1 << 4)
#define BATTR_RMAP_IPV6_LL_NHOP_CHANGED (1 << 5)
#define BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED (1 << 6)

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
		 ? (attr)->cluster->length                                     \
		 : 0)

typedef enum {
	BGP_ATTR_PARSE_PROCEED = 0,
	BGP_ATTR_PARSE_ERROR = -1,
	BGP_ATTR_PARSE_WITHDRAW = -2,

	/* only used internally, send notify + convert to BGP_ATTR_PARSE_ERROR
	   */
	BGP_ATTR_PARSE_ERROR_NOTIFYPLS = -3,
	BGP_ATTR_PARSE_EOR = -4,
} bgp_attr_parse_ret_t;

struct bpacket_attr_vec_arr;

/* Prototypes. */
extern void bgp_attr_init(void);
extern void bgp_attr_finish(void);
extern bgp_attr_parse_ret_t bgp_attr_parse(struct peer *, struct attr *,
					   bgp_size_t, struct bgp_nlri *,
					   struct bgp_nlri *);
extern void bgp_attr_dup(struct attr *, struct attr *);
extern void bgp_attr_undup(struct attr *new, struct attr *old);
extern struct attr *bgp_attr_intern(struct attr *attr);
extern void bgp_attr_unintern_sub(struct attr *);
extern void bgp_attr_unintern(struct attr **);
extern void bgp_attr_flush(struct attr *);
extern struct attr *bgp_attr_default_set(struct attr *attr, uint8_t);
extern struct attr *bgp_attr_aggregate_intern(struct bgp *, uint8_t,
					      struct aspath *,
					      struct community *, int as_set,
					      uint8_t);
extern bgp_size_t bgp_packet_attribute(struct bgp *bgp, struct peer *,
				       struct stream *, struct attr *,
				       struct bpacket_attr_vec_arr *vecarr,
				       struct prefix *, afi_t, safi_t,
				       struct peer *, struct prefix_rd *,
				       mpls_label_t *, uint32_t, int, uint32_t);
extern void bgp_dump_routes_attr(struct stream *, struct attr *,
				 struct prefix *);
extern int attrhash_cmp(const void *, const void *);
extern unsigned int attrhash_key_make(void *);
extern void attr_show_all(struct vty *);
extern unsigned long int attr_count(void);
extern unsigned long int attr_unknown_count(void);

/* Cluster list prototypes. */
extern int cluster_loop_check(struct cluster_list *, struct in_addr);
extern void cluster_unintern(struct cluster_list *);

/* Transit attribute prototypes. */
void transit_unintern(struct transit *);

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
			      struct bgp_nlri *);
extern int bgp_mp_unreach_parse(struct bgp_attr_parser_args *args,
				struct bgp_nlri *);
extern bgp_attr_parse_ret_t
bgp_attr_prefix_sid(int32_t tlength, struct bgp_attr_parser_args *args,
		    struct bgp_nlri *mp_update);

extern struct bgp_attr_encap_subtlv *
encap_tlv_dup(struct bgp_attr_encap_subtlv *orig);

extern void bgp_attr_flush_encap(struct attr *attr);

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
				     struct prefix *p, struct prefix_rd *prd,
				     mpls_label_t *label, uint32_t num_labels,
				     int addpath_encode, uint32_t addpath_tx_id,
				     struct attr *);
extern size_t bgp_packet_mpattr_prefix_size(afi_t afi, safi_t safi,
					    struct prefix *p);
extern void bgp_packet_mpattr_end(struct stream *s, size_t sizep);

extern size_t bgp_packet_mpunreach_start(struct stream *s, afi_t afi,
					 safi_t safi);
extern void bgp_packet_mpunreach_prefix(struct stream *s, struct prefix *p,
					afi_t afi, safi_t safi,
					struct prefix_rd *prd, mpls_label_t *,
					uint32_t, int, uint32_t, struct attr *);
extern void bgp_packet_mpunreach_end(struct stream *s, size_t attrlen_pnt);

static inline int bgp_rmap_nhop_changed(uint32_t out_rmap_flags,
					uint32_t in_rmap_flags)
{
	return ((CHECK_FLAG(out_rmap_flags, BATTR_RMAP_NEXTHOP_PEER_ADDRESS)
		 || CHECK_FLAG(out_rmap_flags, BATTR_RMAP_NEXTHOP_UNCHANGED)
		 || CHECK_FLAG(out_rmap_flags, BATTR_RMAP_IPV4_NHOP_CHANGED)
		 || CHECK_FLAG(out_rmap_flags,
			       BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED)
		 || CHECK_FLAG(out_rmap_flags,
			       BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED)
		 || CHECK_FLAG(out_rmap_flags, BATTR_RMAP_IPV6_LL_NHOP_CHANGED)
		 || CHECK_FLAG(in_rmap_flags, BATTR_RMAP_NEXTHOP_UNCHANGED))
			? 1
			: 0);
}

static inline uint32_t mac_mobility_seqnum(struct attr *attr)
{
	return (attr) ? attr->mm_seqnum : 0;
}

#endif /* _QUAGGA_BGP_ATTR_H */
