/*
 * Copyright 2015, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_ENCAP_TYPES_H
#define _QUAGGA_BGP_ENCAP_TYPES_H

#include "bgpd/bgp_ecommunity.h"

/* from
 * http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#tunnel-types
 */
typedef enum {
	BGP_ENCAP_TYPE_RESERVED = 0,
	BGP_ENCAP_TYPE_L2TPV3_OVER_IP = 1,
	BGP_ENCAP_TYPE_GRE = 2,
	BGP_ENCAP_TYPE_TRANSMIT_TUNNEL_ENDPOINT = 3,
	BGP_ENCAP_TYPE_IPSEC_IN_TUNNEL_MODE = 4,
	BGP_ENCAP_TYPE_IP_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE = 5,
	BGP_ENCAP_TYPE_MPLS_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE = 6,
	BGP_ENCAP_TYPE_IP_IN_IP = 7,
	BGP_ENCAP_TYPE_VXLAN = 8,
	BGP_ENCAP_TYPE_NVGRE = 9,
	BGP_ENCAP_TYPE_MPLS = 10, /* NOTE: Encap SAFI&Attribute not used */
	BGP_ENCAP_TYPE_MPLS_IN_GRE = 11,
	BGP_ENCAP_TYPE_VXLAN_GPE = 12,
	BGP_ENCAP_TYPE_MPLS_IN_UDP = 13,
	BGP_ENCAP_TYPE_PBB
} bgp_encap_types;

typedef enum {
	BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION = 1,
	BGP_ENCAP_SUBTLV_TYPE_PROTO_TYPE = 2,
	BGP_ENCAP_SUBTLV_TYPE_IPSEC_TA = 3,
	BGP_ENCAP_SUBTLV_TYPE_COLOR = 4,
	BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT =
		6 /* speculative, IANA assignment TBD */
} bgp_encap_subtlv_types;

/*
 * Tunnel Encapsulation Attribute subtlvs
 */
struct bgp_tea_subtlv_encap_l2tpv3_over_ip {
	uint32_t sessionid;
	uint8_t cookie_length;
	uint8_t cookie[8];
};

struct bgp_tea_subtlv_encap_gre_key {
	uint32_t gre_key;
};

struct bgp_tea_subtlv_encap_pbb {
	uint32_t flag_isid : 1;
	uint32_t flag_vid : 1;
	uint32_t isid : 24;
	uint16_t vid : 12;
	uint8_t macaddr[6];
};

struct bgp_tea_subtlv_proto_type {
	uint16_t proto; /* ether-type */
};

struct bgp_tea_subtlv_color {
	uint32_t color;
};

/* per draft-rosen-idr-tunnel-encaps */
struct bgp_tea_subtlv_remote_endpoint {
	uint8_t family; /* IPv4 or IPv6 */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip_address;
	as_t as4; /* always 4 bytes */
};

/*
 * This is the length of the value part of the ipsec tunnel authenticator
 * subtlv. Currently we only support the length for authenticator type 1.
 */
#define BGP_ENCAP_SUBTLV_IPSEC_TA_SIZE	20

struct bgp_tea_subtlv_ipsec_ta {
	uint16_t authenticator_type;  /* only type 1 is supported so far */
	uint8_t authenticator_length; /* octets in value field */
	uint8_t value[BGP_ENCAP_SUBTLV_IPSEC_TA_SIZE];
};

/*
 * Subtlv valid flags
 * TBD change names to add "VALID"
 */
#define BGP_TEA_SUBTLV_ENCAP		0x00000001
#define BGP_TEA_SUBTLV_PROTO_TYPE	0x00000002
#define BGP_TEA_SUBTLV_COLOR		0x00000004
#define BGP_TEA_SUBTLV_IPSEC_TA		0x00000008
#define BGP_TEA_SUBTLV_REMOTE_ENDPOINT	0x00000010

#define CHECK_SUBTLV_FLAG(ptr, flag)  CHECK_FLAG((ptr)->valid_subtlvs, (flag))
#define SET_SUBTLV_FLAG(ptr, flag)      SET_FLAG((ptr)->valid_subtlvs, (flag))
#define UNSET_SUBTLV_FLAG(ptr, flag)  UNSET_FLAG((ptr)->valid_subtlvs, (flag))

/*
 * Tunnel Type-specific APIs
 */
struct bgp_encap_type_reserved {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_l2tpv3_over_ip {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_encap_l2tpv3_over_ip st_encap;
	struct bgp_tea_subtlv_proto_type st_proto;	 /* optional */
	struct bgp_tea_subtlv_color st_color;		   /* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_gre {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_encap_gre_key st_encap;      /* optional */
	struct bgp_tea_subtlv_proto_type st_proto;	 /* optional */
	struct bgp_tea_subtlv_color st_color;		   /* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_ip_in_ip {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_proto_type st_proto;	 /* optional */
	struct bgp_tea_subtlv_color st_color;		   /* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_transmit_tunnel_endpoint {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_ipsec_in_tunnel_mode {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_ipsec_ta st_ipsec_ta;	/* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_ipsec_ta st_ipsec_ta;	/* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_ipsec_ta st_ipsec_ta;	/* optional */
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
};

#define VXLAN_ENCAP_MASK_VNID_VALID 0x80000000
#define VXLAN_ENCAP_MASK_MAC_VALID  0x40000000

struct bgp_encap_type_vxlan {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* draft-ietf-idr-tunnel-encaps-02 */
	uint32_t vnid;	/* does not include V and M bit */
	uint8_t *mac_address; /* optional */
};

struct bgp_encap_type_nvgre {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_mpls {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_mpls_in_gre {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_vxlan_gpe {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_mpls_in_udp {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	/* No subtlvs defined in spec? */
};

struct bgp_encap_type_pbb {
	uint32_t valid_subtlvs;
	struct bgp_tea_subtlv_remote_endpoint st_endpoint; /* optional */
	struct bgp_tea_subtlv_encap_pbb st_encap;
};

static inline void encode_encap_extcomm(bgp_encap_types tnl_type,
					struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_OPAQUE;
	eval->val[1] = ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP;
	eval->val[6] = ((tnl_type) >> 8) & 0xff;
	eval->val[7] = (tnl_type)&0xff;
}

#endif /* _QUAGGA_BGP_ENCAP_TYPES_H */
