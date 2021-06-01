/*
 * This is an implementation of RFC4970 Router Information
 * with support of RFC5088 PCE Capabilites announcement
 * and support of draft-ietf-ospf-segment-routing-extensions-18
 * for Segment Routing Capabilities announcement
 *
 *
 * Module name: Router Information
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Copyright (C) 2012 - 2017 Orange Labs http://www.orange.com/
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

#ifndef _ZEBRA_OSPF_ROUTER_INFO_H
#define _ZEBRA_OSPF_ROUTER_INFO_H

/*
 * Opaque LSA's link state ID for Router Information is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |    4   |  MBZ   |........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<Resv'd>|<-- Instance --->|
 *
 *
 * Type:      IANA has assigned '4' for Router Information.
 * MBZ:       Reserved, must be set to zero.
 * Instance:  User may select an arbitrary 16-bit value.
 *
 */

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options | 9,10,11|  A
 * +--------+--------+--------+--------+  |
 * |    4   |   0    |    Instance     |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Type 9,10 or 11 are used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A  TLV part for Router Information;
 * +--------+--------+--------+--------+  |  Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/*
 * Following section defines TLV body parts.
 */

/* Up to now, 11 code points have been assigned to Router Information */
/* Only type 1 Router Capabilities and 6 PCE are supported with this code */
#define RI_IANA_MAX_TYPE		11

/* RFC4970: Router Information Capabilities TLV */ /* Mandatory */
#define RI_TLV_CAPABILITIES		1
#define RI_TLV_CAPABILITIES_SIZE	4
struct ri_tlv_router_cap {
	struct tlv_header header; /* Value length is 4 bytes. */
	uint32_t value;
};

/* Capabilities bits are left align */
#define RI_GRACE_RESTART	0x80000000
#define RI_GRACE_HELPER		0x40000000
#define RI_STUB_SUPPORT		0x20000000
#define RI_TE_SUPPORT		0x10000000
#define RI_P2P_OVER_LAN		0x08000000
#define RI_TE_EXPERIMENTAL	0x04000000

#define RI_TLV_LENGTH		4

/* RFC5088: PCE Capabilities TLV */ /* Optional */
/* RI PCE TLV */
#define RI_TLV_PCE			6

struct ri_tlv_pce {
	struct tlv_header header;
	/* A set of PCE-sub-TLVs will follow. */
};

/* PCE Address Sub-TLV */ /* Mandatory */
#define	RI_PCE_SUBTLV_ADDRESS		1
struct ri_pce_subtlv_address {
	/* Type = 1; Length is 8 (IPv4) or 20 (IPv6) bytes. */
	struct tlv_header header;
#define	PCE_ADDRESS_IPV4_SIZE		8
#define	PCE_ADDRESS_IPV6_SIZE		20
	struct {
		uint16_t type; /* Address type: 1 = IPv4, 2 = IPv6 */
#define	PCE_ADDRESS_IPV4		1
#define	PCE_ADDRESS_IPV6		2
		uint16_t reserved;
		struct in_addr value; /* PCE address */
	} address;
};

/* PCE Path-Scope Sub-TLV */ /* Mandatory */
#define	RI_PCE_SUBTLV_PATH_SCOPE	2
#define	RI_PCE_SUBTLV_PATH_SCOPE_SIZE	4
struct ri_pce_subtlv_path_scope {
	struct tlv_header header; /* Type = 2; Length = 4 bytes. */
	/*
	 * L, R, Rd, S, Sd, Y, PrefL, PrefR, PrefS and PrefY bits:
	 * see RFC5088 page 9
	 */
	uint32_t value;
};

/* PCE Domain Sub-TLV */ /* Optional */
#define	PCE_DOMAIN_TYPE_AREA		1
#define	PCE_DOMAIN_TYPE_AS		2

#define	RI_PCE_SUBTLV_DOMAIN		3
#define	RI_PCE_SUBTLV_DOMAIN_SIZE	8
struct ri_pce_subtlv_domain {
	struct tlv_header header; /* Type = 3; Length = 8 bytes. */
	uint16_t type; /* Domain type: 1 = OSPF Area ID, 2 = AS Number */
	uint16_t reserved;
	uint32_t value;
};

/* PCE Neighbor Sub-TLV */ /* Mandatory if R or S bit is set */
#define RI_PCE_SUBTLV_NEIGHBOR		4
#define RI_PCE_SUBTLV_NEIGHBOR_SIZE	8
struct ri_pce_subtlv_neighbor {
	struct tlv_header header; /* Type = 4; Length = 8 bytes. */
	uint16_t type; /* Domain type: 1 = OSPF Area ID, 2 = AS Number */
	uint16_t reserved;
	uint32_t value;
};

/* PCE Capabilities Flags Sub-TLV */ /* Optional */
#define RI_PCE_SUBTLV_CAP_FLAG		5
#define RI_PCE_SUBTLV_CAP_FLAG_SIZE	4

#define PCE_CAP_GMPLS_LINK		0x0001
#define PCE_CAP_BIDIRECTIONAL		0x0002
#define PCE_CAP_DIVERSE_PATH		0x0004
#define PCE_CAP_LOAD_BALANCE		0x0008
#define PCE_CAP_SYNCHRONIZED		0x0010
#define PCE_CAP_OBJECTIVES		0x0020
#define PCE_CAP_ADDITIVE		0x0040
#define PCE_CAP_PRIORIZATION		0x0080
#define PCE_CAP_MULTIPLE_REQ		0x0100

struct ri_pce_subtlv_cap_flag {
	struct tlv_header header; /* Type = 5; Length = n x 4 bytes. */
	uint32_t value;
};

/* Structure to share flooding scope info for Segment Routing */
struct scope_info {
	uint8_t scope;
	struct list *areas;
};

/* Flags to manage the Router Information LSA. */
#define RIFLG_LSA_INACTIVE		0x0
#define RIFLG_LSA_ENGAGED		0x1
#define RIFLG_LSA_FORCED_REFRESH	0x2

/* Store Router Information PCE TLV and SubTLV in network byte order. */
struct ospf_pce_info {
	bool enabled;
	struct ri_tlv_pce pce_header;
	struct ri_pce_subtlv_address pce_address;
	struct ri_pce_subtlv_path_scope pce_scope;
	struct list *pce_domain;
	struct list *pce_neighbor;
	struct ri_pce_subtlv_cap_flag pce_cap_flag;
};

/*
 * Store Router Information Segment Routing TLV and SubTLV
 * in network byte order
 */
struct ospf_ri_sr_info {
	bool enabled;
	/* Algorithms supported by the node */
	struct ri_sr_tlv_sr_algorithm algo;
	/*
	 * Segment Routing Global Block i.e. label range
	 * Only one range supported in this code
	 */
	struct ri_sr_tlv_sid_label_range srgb;
	/*
	 * Segment Routing Local Block.
	 * Only one block is authorized - see section 3.3
	 */
	struct ri_sr_tlv_sid_label_range srlb;
	/* Maximum SID Depth supported by the node */
	struct ri_sr_tlv_node_msd msd;
};

/* Store area information to flood LSA per area */
struct ospf_ri_area_info {

	uint32_t flags;

	/* area pointer if flooding is Type 10 Null if flooding is AS scope */
	struct ospf_area *area;
};

/* Following structure are internal use only. */
struct ospf_router_info {
	bool enabled;

	uint8_t registered;
	uint8_t scope;
	/* LSA flags are only used when scope is AS flooding */
	uint32_t as_flags;

	/* List of area info to flood RI LSA */
	struct list *area_info;

	/* Store Router Information Capabilities LSA */
	struct ri_tlv_router_cap router_cap;

	/* Store PCE capability LSA */
	struct ospf_pce_info pce_info;

	/* Store SR capability LSA */
	struct ospf_ri_sr_info sr_info;
};

/* Prototypes. */
extern int ospf_router_info_init(void);
extern void ospf_router_info_term(void);
extern void ospf_router_info_finish(void);
extern int ospf_router_info_enable(void);
extern void ospf_router_info_update_sr(bool enable, struct sr_node *self);
extern struct scope_info ospf_router_info_get_flooding_scope(void);
#endif /* _ZEBRA_OSPF_ROUTER_INFO_H */
