/* BGP Extended Communities Attribute.
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#ifndef _QUAGGA_BGP_ECOMMUNITY_H
#define _QUAGGA_BGP_ECOMMUNITY_H

#include "bgpd/bgp_route.h"
#include "bgpd/bgpd.h"

/* High-order octet of the Extended Communities type field.  */
#define ECOMMUNITY_ENCODE_AS                0x00
#define ECOMMUNITY_ENCODE_IP                0x01
#define ECOMMUNITY_ENCODE_AS4               0x02
#define ECOMMUNITY_ENCODE_OPAQUE            0x03
#define ECOMMUNITY_ENCODE_EVPN              0x06
#define ECOMMUNITY_ENCODE_TRANS_EXP         0x80 /* Flow Spec */
#define ECOMMUNITY_ENCODE_REDIRECT_IP_NH    0x08 /* Flow Spec */
/* RFC7674 */
#define ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 0x81
#define ECOMMUNITY_EXTENDED_COMMUNITY_PART_3 0x82

/* Low-order octet of the Extended Communities type field.  */
#define ECOMMUNITY_ROUTE_TARGET             0x02
#define ECOMMUNITY_SITE_ORIGIN              0x03
#define ECOMMUNITY_TRAFFIC_RATE             0x06 /* Flow Spec */
#define ECOMMUNITY_TRAFFIC_ACTION           0x07
#define ECOMMUNITY_REDIRECT_VRF             0x08
#define ECOMMUNITY_TRAFFIC_MARKING          0x09
#define ECOMMUNITY_REDIRECT_IP_NH           0x00
/* from IANA: bgp-extended-communities/bgp-extended-communities.xhtml
 * 0x0c Flow-spec Redirect to IPv4 - draft-ietf-idr-flowspec-redirect
 */
#define ECOMMUNITY_FLOWSPEC_REDIRECT_IPV4   0x0c

/* Low-order octet of the Extended Communities type field for EVPN types */
#define ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY  0x00
#define ECOMMUNITY_EVPN_SUBTYPE_ESI_LABEL    0x01
#define ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT 0x02
#define ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC    0x03
#define ECOMMUNITY_EVPN_SUBTYPE_DEF_GW       0x0d
#define ECOMMUNITY_EVPN_SUBTYPE_ND           0x08

#define ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY 0x01
#define ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG		0x01
#define ECOMMUNITY_EVPN_SUBTYPE_ND_OVERRIDE_FLAG	0x02

/* Low-order octet of the Extended Communities type field for OPAQUE types */
#define ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP     0x0c

/* Extended communities attribute string format.  */
#define ECOMMUNITY_FORMAT_ROUTE_MAP            0
#define ECOMMUNITY_FORMAT_COMMUNITY_LIST       1
#define ECOMMUNITY_FORMAT_DISPLAY              2

/* Extended Communities value is eight octet long.  */
#define ECOMMUNITY_SIZE                        8

/* Extended Communities type flag.  */
#define ECOMMUNITY_FLAG_NON_TRANSITIVE      0x40

/* Extended Communities attribute.  */
struct ecommunity {
	/* Reference counter.  */
	unsigned long refcnt;

	/* Size of Extended Communities attribute.  */
	int size;

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

/* Extended community value is eight octet.  */
struct ecommunity_val {
	char val[ECOMMUNITY_SIZE];
};

#define ecom_length(X)    ((X)->size * ECOMMUNITY_SIZE)

/*
 * Encode BGP Route Target AS:nn.
 */
static inline void encode_route_target_as(as_t as, uint32_t val,
					  struct ecommunity_val *eval)
{
	eval->val[0] = ECOMMUNITY_ENCODE_AS;
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
static inline void encode_route_target_ip(struct in_addr ip, uint16_t val,
					  struct ecommunity_val *eval)
{
	eval->val[0] = ECOMMUNITY_ENCODE_IP;
	eval->val[1] = ECOMMUNITY_ROUTE_TARGET;
	memcpy(&eval->val[2], &ip, sizeof(struct in_addr));
	eval->val[6] = (val >> 8) & 0xff;
	eval->val[7] = val & 0xff;
}

/*
 * Encode BGP Route Target AS4:nn.
 */
static inline void encode_route_target_as4(as_t as, uint16_t val,
					   struct ecommunity_val *eval)
{
	eval->val[0] = ECOMMUNITY_ENCODE_AS4;
	eval->val[1] = ECOMMUNITY_ROUTE_TARGET;
	eval->val[2] = (as >> 24) & 0xff;
	eval->val[3] = (as >> 16) & 0xff;
	eval->val[4] = (as >> 8) & 0xff;
	eval->val[5] = as & 0xff;
	eval->val[6] = (val >> 8) & 0xff;
	eval->val[7] = val & 0xff;
}

extern void ecommunity_init(void);
extern void ecommunity_finish(void);
extern void ecommunity_free(struct ecommunity **);
extern struct ecommunity *ecommunity_parse(uint8_t *, unsigned short);
extern struct ecommunity *ecommunity_dup(struct ecommunity *);
extern struct ecommunity *ecommunity_merge(struct ecommunity *,
					   struct ecommunity *);
extern struct ecommunity *ecommunity_uniq_sort(struct ecommunity *);
extern struct ecommunity *ecommunity_intern(struct ecommunity *);
extern bool ecommunity_cmp(const void *arg1, const void *arg2);
extern void ecommunity_unintern(struct ecommunity **);
extern unsigned int ecommunity_hash_make(const void *);
extern struct ecommunity *ecommunity_str2com(const char *, int, int);
extern char *ecommunity_ecom2str(struct ecommunity *, int, int);
extern void ecommunity_strfree(char **s);
extern int ecommunity_match(const struct ecommunity *,
			    const struct ecommunity *);
extern char *ecommunity_str(struct ecommunity *);
extern struct ecommunity_val *ecommunity_lookup(const struct ecommunity *,
						uint8_t, uint8_t);
extern int ecommunity_add_val(struct ecommunity *ecom,
			      struct ecommunity_val *eval);

/* for vpn */
extern struct ecommunity *ecommunity_new(void);
extern int ecommunity_add_val(struct ecommunity *, struct ecommunity_val *);
extern int ecommunity_strip(struct ecommunity *ecom, uint8_t type,
			    uint8_t subtype);
extern struct ecommunity *ecommunity_new(void);
extern int ecommunity_del_val(struct ecommunity *ecom,
			      struct ecommunity_val *eval);
struct bgp_pbr_entry_action;
extern int ecommunity_fill_pbr_action(struct ecommunity_val *ecom_eval,
			       struct bgp_pbr_entry_action *api);

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

#endif /* _QUAGGA_BGP_ECOMMUNITY_H */
