// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Extended Communities Attribute.
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#ifndef _QUAGGA_BGP_ECOMMUNITY_H
#define _QUAGGA_BGP_ECOMMUNITY_H

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rpki.h"
#include "bgpd/bgpd.h"

#define ONE_GBPS_BYTES (1000 * 1000 * 1000 / 8)
#define ONE_MBPS_BYTES (1000 * 1000 / 8)
#define ONE_KBPS_BYTES (1000 / 8)

/* Refer to rfc7153 for the IANA registry definitions. These are
 * updated by other standards like rfc7674.
 */
/* High-order octet of the Extended Communities type field.  */
#define ECOMMUNITY_ENCODE_AS                0x00
#define ECOMMUNITY_ENCODE_IP                0x01
#define ECOMMUNITY_ENCODE_AS4               0x02
#define ECOMMUNITY_ENCODE_OPAQUE            0x03
#define ECOMMUNITY_ENCODE_EVPN              0x06
#define ECOMMUNITY_ENCODE_REDIRECT_IP_NH    0x08 /* Flow Spec */
/* Generic Transitive Experimental */
#define ECOMMUNITY_ENCODE_TRANS_EXP         0x80

/* RFC7674 */
#define ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 0x81
#define ECOMMUNITY_EXTENDED_COMMUNITY_PART_3 0x82

/* Non-transitive extended community types. */
#define ECOMMUNITY_ENCODE_AS_NON_TRANS      0x40
#define ECOMMUNITY_ENCODE_IP_NON_TRANS      0x41
#define ECOMMUNITY_ENCODE_AS4_NON_TRANS     0x42
#define ECOMMUNITY_ENCODE_OPAQUE_NON_TRANS  0x43

/* Low-order octet of the Extended Communities type field.  */
/* Note: This really depends on the high-order octet. This means that
 * multiple definitions for the same value are possible.
 */
#define ECOMMUNITY_ORIGIN_VALIDATION_STATE  0x00
#define ECOMMUNITY_ROUTE_TARGET             0x02
#define ECOMMUNITY_SITE_ORIGIN              0x03
#define ECOMMUNITY_LINK_BANDWIDTH           0x04
#define ECOMMUNITY_TRAFFIC_RATE             0x06 /* Flow Spec */
#define ECOMMUNITY_TRAFFIC_ACTION           0x07
#define ECOMMUNITY_REDIRECT_VRF             0x08
#define ECOMMUNITY_TRAFFIC_MARKING          0x09
#define ECOMMUNITY_REDIRECT_IP_NH           0x00
#define ECOMMUNITY_COLOR 0x0b /* RFC9012 - color */

/* from IANA: bgp-extended-communities/bgp-extended-communities.xhtml
 * 0x0c Flow-spec Redirect to IPv4 - draft-ietf-idr-flowspec-redirect
 */
#define ECOMMUNITY_FLOWSPEC_REDIRECT_IPV4   0x0c
/* RFC 8956 */
#define ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6 0x0d

/* https://datatracker.ietf.org/doc/html/draft-li-idr-link-bandwidth-ext-01
 * Sub-type is allocated by IANA, just the draft is not yet updated with the
 * new value.
 */
#define ECOMMUNITY_EXTENDED_LINK_BANDWIDTH 0x0006

/* Low-order octet of the Extended Communities type field for EVPN types */
#define ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY  0x00
#define ECOMMUNITY_EVPN_SUBTYPE_ESI_LABEL    0x01
#define ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT 0x02
#define ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC    0x03
#define ECOMMUNITY_EVPN_SUBTYPE_DF_ELECTION 0x06
#define ECOMMUNITY_EVPN_SUBTYPE_DEF_GW       0x0d
#define ECOMMUNITY_EVPN_SUBTYPE_ND           0x08

#define ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY 0x01

/* DF alg bits - only lower 5 bits are applicable */
#define ECOMMUNITY_EVPN_SUBTYPE_DF_ALG_BITS 0x1f

#define ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG   0x01
#define ECOMMUNITY_EVPN_SUBTYPE_ND_OVERRIDE_FLAG 0x02
#define ECOMMUNITY_EVPN_SUBTYPE_PROXY_FLAG       0x04

#define ECOMMUNITY_EVPN_SUBTYPE_ESI_SA_FLAG (1 << 0) /* single-active */

/* Low-order octet of the Extended Communities type field for OPAQUE types */
#define ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP     0x0c

/* Extended communities attribute string format.  */
#define ECOMMUNITY_FORMAT_ROUTE_MAP            0
#define ECOMMUNITY_FORMAT_COMMUNITY_LIST       1
#define ECOMMUNITY_FORMAT_DISPLAY              2

/* Extended Communities value is eight octet long.  */
#define ECOMMUNITY_SIZE                        8
#define IPV6_ECOMMUNITY_SIZE                  20

/* Extended Community Origin Validation State */
enum ecommunity_origin_validation_states {
	ECOMMUNITY_ORIGIN_VALIDATION_STATE_VALID,
	ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTFOUND,
	ECOMMUNITY_ORIGIN_VALIDATION_STATE_INVALID,
	ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTUSED
};

/* Extended Communities type flag.  */
#define ECOMMUNITY_FLAG_NON_TRANSITIVE      0x40

/* Extended Community readable string length */
#define ECOMMUNITY_STRLEN 64

/* Node Target Extended Communities */
#define ECOMMUNITY_NODE_TARGET 0x09
#define ECOMMUNITY_NODE_TARGET_RESERVED 0

/* Extended Communities attribute.  */
struct ecommunity {
	/* Reference counter.  */
	unsigned long refcnt;

	/* Size of Each Unit of Extended Communities attribute.
	 * to differentiate between IPv6 ext comm and ext comm
	 */
	uint8_t unit_size;

	/* Disable IEEE floating-point encoding for extended community */
	bool disable_ieee_floating;

	/* Size of Extended Communities attribute.  */
	uint32_t size;

	/* Extended Communities value.  */
	uint8_t *val;

	/* Human readable format string.  */
	char *str;
};

struct ecommunity_as {
	as_t as;
	uint32_t val;
};

struct ecommunity_ip {
	struct in_addr ip;
	uint16_t val;
};

struct ecommunity_ip6 {
	struct in6_addr ip;
	uint16_t val;
};

/* Extended community value is eight octet.  */
struct ecommunity_val {
	uint8_t val[ECOMMUNITY_SIZE];
};

/* IPv6 Extended community value is eight octet.  */
struct ecommunity_val_ipv6 {
	uint8_t val[IPV6_ECOMMUNITY_SIZE];
};

#define ecom_length_size(X, Y)    ((X)->size * (Y))

/*
 * Encode BGP Route Target AS:nn.
 */
static inline void encode_route_target_as(as_t as, uint32_t val,
					  struct ecommunity_val *eval,
					  bool trans)
{
	eval->val[0] = ECOMMUNITY_ENCODE_AS;
	if (!trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = ECOMMUNITY_ROUTE_TARGET;
	eval->val[2] = (as >> 8) & 0xff;
	eval->val[3] = as & 0xff;
	eval->val[4] = (val >> 24) & 0xff;
	eval->val[5] = (val >> 16) & 0xff;
	eval->val[6] = (val >> 8) & 0xff;
	eval->val[7] = val & 0xff;
}

/*
 * Encode BGP Route Target IP:nn.
 */
static inline void encode_route_target_ip(struct in_addr *ip, uint16_t val,
					  struct ecommunity_val *eval,
					  bool trans)
{
	eval->val[0] = ECOMMUNITY_ENCODE_IP;
	if (!trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = ECOMMUNITY_ROUTE_TARGET;
	memcpy(&eval->val[2], ip, sizeof(struct in_addr));
	eval->val[6] = (val >> 8) & 0xff;
	eval->val[7] = val & 0xff;
}

/*
 * Encode BGP Route Target AS4:nn.
 */
static inline void encode_route_target_as4(as_t as, uint16_t val,
					   struct ecommunity_val *eval,
					   bool trans)
{
	eval->val[0] = ECOMMUNITY_ENCODE_AS4;
	if (!trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = ECOMMUNITY_ROUTE_TARGET;
	eval->val[2] = (as >> 24) & 0xff;
	eval->val[3] = (as >> 16) & 0xff;
	eval->val[4] = (as >> 8) & 0xff;
	eval->val[5] = as & 0xff;
	eval->val[6] = (val >> 8) & 0xff;
	eval->val[7] = val & 0xff;
}

/* Helper function to convert uint32 to IEEE-754 Floating Point */
static uint32_t uint32_to_ieee_float_uint32(uint32_t u)
{
	union {
		float r;
		uint32_t d;
	} f = {.r = (float)u};

	return f.d;
}

/*
 * Encode BGP Link Bandwidth extended community
 *  bandwidth (bw) is in bytes-per-sec
 */
static inline void encode_lb_extcomm(as_t as, uint64_t bw, bool non_trans,
				     struct ecommunity_val *eval,
				     bool disable_ieee_floating)
{
	uint64_t bandwidth = disable_ieee_floating
				     ? bw
				     : uint32_to_ieee_float_uint32(bw);

	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_AS;
	if (non_trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = ECOMMUNITY_LINK_BANDWIDTH;
	eval->val[2] = (as >> 8) & 0xff;
	eval->val[3] = as & 0xff;
	eval->val[4] = (bandwidth >> 24) & 0xff;
	eval->val[5] = (bandwidth >> 16) & 0xff;
	eval->val[6] = (bandwidth >> 8) & 0xff;
	eval->val[7] = bandwidth & 0xff;
}

/*
 * Encode BGP Link Bandwidth inside IPv6 Extended Community,
 * bandwidth is in bytes per second.
 */
static inline void encode_lb_extended_extcomm(as_t as, uint64_t bandwidth,
					      bool non_trans,
					      struct ecommunity_val_ipv6 *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_AS4;
	if (non_trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = ECOMMUNITY_EXTENDED_LINK_BANDWIDTH;
	eval->val[4] = (bandwidth >> 56) & 0xff;
	eval->val[5] = (bandwidth >> 48) & 0xff;
	eval->val[6] = (bandwidth >> 40) & 0xff;
	eval->val[7] = (bandwidth >> 32) & 0xff;
	eval->val[8] = (bandwidth >> 24) & 0xff;
	eval->val[9] = (bandwidth >> 16) & 0xff;
	eval->val[10] = (bandwidth >> 8) & 0xff;
	eval->val[11] = bandwidth & 0xff;
	eval->val[12] = (as >> 24) & 0xff;
	eval->val[13] = (as >> 16) & 0xff;
	eval->val[14] = (as >> 8) & 0xff;
	eval->val[15] = as & 0xff;
}

static inline void encode_origin_validation_state(enum rpki_states state,
						  struct ecommunity_val *eval)
{
	enum ecommunity_origin_validation_states ovs_state =
		ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTUSED;

	switch (state) {
	case RPKI_VALID:
		ovs_state = ECOMMUNITY_ORIGIN_VALIDATION_STATE_VALID;
		break;
	case RPKI_NOTFOUND:
		ovs_state = ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTFOUND;
		break;
	case RPKI_INVALID:
		ovs_state = ECOMMUNITY_ORIGIN_VALIDATION_STATE_INVALID;
		break;
	case RPKI_NOT_BEING_USED:
		break;
	}

	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_OPAQUE_NON_TRANS;
	eval->val[1] = ECOMMUNITY_ORIGIN_VALIDATION_STATE;
	eval->val[7] = ovs_state;
}

static inline void encode_node_target(struct in_addr *node_id,
				      struct ecommunity_val *eval, bool trans)
{
	/*
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | 0x01 or 0x41 | Sub-Type(0x09) |    Target BGP Identifier      |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | Target BGP Identifier (cont.) |           Reserved            |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_IP;
	if (!trans)
		eval->val[0] |= ECOMMUNITY_ENCODE_IP_NON_TRANS;
	eval->val[1] = ECOMMUNITY_NODE_TARGET;
	memcpy(&eval->val[2], node_id, sizeof(*node_id));
	eval->val[6] = ECOMMUNITY_NODE_TARGET_RESERVED;
	eval->val[7] = ECOMMUNITY_NODE_TARGET_RESERVED;
}

/*
 * Encode BGP Color extended community
 * is's a transitive opaque Extended community (RFC 9012 4.3)
 * flag is set to 0
 * RFC 9012 14.10: No values have currently been registered.
 *            4.3: this field MUST be set to zero by the originator
 *                 and ignored by the receiver;
 *
 */
static inline void encode_color(uint32_t color_id, struct ecommunity_val *eval)
{
	/*
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | 0x03         | Sub-Type(0x0b) |    Flags                      |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |                          Color Value                          |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_OPAQUE;
	eval->val[1] = ECOMMUNITY_COLOR;
	eval->val[2] = 0x00;
	eval->val[3] = 0x00;
	eval->val[4] = (color_id >> 24) & 0xff;
	eval->val[5] = (color_id >> 16) & 0xff;
	eval->val[6] = (color_id >> 8) & 0xff;
	eval->val[7] = color_id & 0xff;
}

extern void ecommunity_init(void);
extern void ecommunity_finish(void);
extern void ecommunity_free(struct ecommunity **);
extern struct ecommunity *ecommunity_parse(uint8_t *, unsigned short,
					   bool disable_ieee_floating);
extern struct ecommunity *ecommunity_parse_ipv6(uint8_t *pnt,
						unsigned short length);
extern struct ecommunity *ecommunity_dup(struct ecommunity *);
extern struct ecommunity *ecommunity_merge(struct ecommunity *,
					   struct ecommunity *);
extern struct ecommunity *ecommunity_uniq_sort(struct ecommunity *);
extern struct ecommunity *ecommunity_intern(struct ecommunity *);
extern bool ecommunity_cmp(const void *arg1, const void *arg2);
extern void ecommunity_unintern(struct ecommunity **ecommunity);
extern unsigned int ecommunity_hash_make(const void *);
extern struct ecommunity *ecommunity_str2com(const char *, int, int);
extern struct ecommunity *ecommunity_str2com_ipv6(const char *str, int type,
						  int keyword_included);
extern char *ecommunity_ecom2str(struct ecommunity *, int, int);
extern bool ecommunity_has_route_target(struct ecommunity *ecom);
extern void ecommunity_strfree(char **s);
extern bool ecommunity_include(struct ecommunity *e1, struct ecommunity *e2);
extern bool ecommunity_match(const struct ecommunity *,
			     const struct ecommunity *);
extern const char *ecommunity_str(struct ecommunity *ecom);
extern struct ecommunity_val *ecommunity_lookup(const struct ecommunity *,
						uint8_t, uint8_t);

extern uint32_t ecommunity_select_color(const struct ecommunity *ecom);
extern bool ecommunity_add_val(struct ecommunity *ecom,
			       struct ecommunity_val *eval,
			       bool unique, bool overwrite);
extern bool ecommunity_add_val_ipv6(struct ecommunity *ecom,
				    struct ecommunity_val_ipv6 *eval,
				    bool unique, bool overwrite);

/* for vpn */
extern struct ecommunity *ecommunity_new(void);
extern bool ecommunity_strip(struct ecommunity *ecom, uint8_t type,
			     uint8_t subtype);
extern struct ecommunity *ecommunity_new(void);
extern bool ecommunity_del_val(struct ecommunity *ecom,
			       struct ecommunity_val *eval);
struct bgp_pbr_entry_action;
extern int ecommunity_fill_pbr_action(struct ecommunity_val *ecom_eval,
				      struct bgp_pbr_entry_action *api,
				      afi_t afi);

extern void bgp_compute_aggregate_ecommunity(
					struct bgp_aggregate *aggregate,
					struct ecommunity *ecommunity);

extern void bgp_compute_aggregate_ecommunity_hash(
					struct bgp_aggregate *aggregate,
					struct ecommunity *ecommunity);
extern void bgp_compute_aggregate_ecommunity_val(
					struct bgp_aggregate *aggregate);
extern void bgp_remove_ecommunity_from_aggregate(
					struct bgp_aggregate *aggregate,
					struct ecommunity *ecommunity);
extern void bgp_remove_ecomm_from_aggregate_hash(
					struct bgp_aggregate *aggregate,
					struct ecommunity *ecommunity);
extern void bgp_aggr_ecommunity_remove(void *arg);
extern const uint8_t *ecommunity_linkbw_present(struct ecommunity *ecom,
						uint64_t *bw);
extern struct ecommunity *
ecommunity_replace_linkbw(as_t as, struct ecommunity *ecom, uint64_t cum_bw,
			  bool disable_ieee_floating, bool extended);

extern bool soo_in_ecom(struct ecommunity *ecom, struct ecommunity *soo);

static inline void ecommunity_strip_rts(struct ecommunity *ecom)
{
	uint8_t subtype = ECOMMUNITY_ROUTE_TARGET;

	ecommunity_strip(ecom, ECOMMUNITY_ENCODE_AS, subtype);
	ecommunity_strip(ecom, ECOMMUNITY_ENCODE_IP, subtype);
	ecommunity_strip(ecom, ECOMMUNITY_ENCODE_AS4, subtype);
}
extern struct ecommunity *
ecommunity_add_origin_validation_state(enum rpki_states rpki_state,
				       struct ecommunity *ecom);
extern struct ecommunity *ecommunity_add_node_target(struct in_addr *node_id,
						     struct ecommunity *old,
						     bool non_trans);
extern bool ecommunity_node_target_match(struct ecommunity *ecomm,
					 struct in_addr *local_id);
#endif /* _QUAGGA_BGP_ECOMMUNITY_H */
