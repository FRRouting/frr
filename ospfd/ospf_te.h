/*
 * This is an implementation of RFC3630, RFC5392 & RFC6827
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 *
 * Copyright (C) 2012 Orange Labs
 * http://www.orange.com
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

/* Add support of RFC7471 */
/* Add support of RFC5392 */
/* Add support of RFC6827 (partial) */

#ifndef _ZEBRA_OSPF_MPLS_TE_H
#define _ZEBRA_OSPF_MPLS_TE_H

/*
 * Opaque LSA's link state ID for Traffic Engineering is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |    1   |  MBZ   |........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<Resv'd>|<-- Instance --->|
 *
 *
 * Type:      IANA has assigned '1' for Traffic Engineering.
 * MBZ:       Reserved, must be set to zero.
 * Instance:  User may select an arbitrary 16-bit value.
 *
 */

#define	MAX_LEGAL_TE_INSTANCE_NUM (0xffff)
#define LEGAL_TE_INSTANCE_RANGE(i)  (0 <= (i) && (i) <= 0xffff)

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |   10   |  A
 * +--------+--------+--------+--------+  |
 * |    1   |   0    |    Instance     |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Only type-10 is used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for TE; Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/* Following define the type of TE link regarding the various RFC */
#define STD_TE  	0x01
#define GMPLS   	0x02
#define INTER_AS	0x04
#define PSEUDO_TE	0x08
#define FLOOD_AREA	0x10
#define FLOOD_AS	0x20
#define EMULATED	0x80

#define IS_STD_TE(x)	    (x & STD_TE)
#define IS_PSEUDO_TE(x)		(x & PSEUDO_TE)
#define IS_INTER_AS(x) 		(x & INTER_AS)
#define IS_EMULATED(x)		(x & EMULATED)
#define IS_FLOOD_AREA(x)	(x & FLOOD_AREA)
#define IS_FLOOD_AS(x)		(x & FLOOD_AS)
#define IS_INTER_AS_EMU(x) 	(x & INTER_AS & EMULATED)
#define IS_INTER_AS_AS(x)	(x & INTER_AS & FLOOD_AS)

/* Flags to manage TE Link LSA */
#define LPFLG_LSA_INACTIVE		0x0
#define LPFLG_LSA_ACTIVE		0x1
#define LPFLG_LSA_ENGAGED		0x2
#define LPFLG_LOOKUP_DONE		0x4
#define LPFLG_LSA_FORCED_REFRESH	0x8

/*
 * Following section defines TLV body parts.
 */

/* Router Address TLV */ /* Mandatory */
#define	TE_TLV_ROUTER_ADDR		1
struct te_tlv_router_addr {
	struct tlv_header header; /* Value length is 4 octets. */
	struct in_addr value;
};

/* Link TLV */
#define	TE_TLV_LINK			2
struct te_tlv_link {
	struct tlv_header header;
	/* A set of link-sub-TLVs will follow. */
};

/* Default TE TLV size */
#define TE_LINK_SUBTLV_DEF_SIZE		4

/* Link Type Sub-TLV */ /* Mandatory */
#define	TE_LINK_SUBTLV_LINK_TYPE	1
#define TE_LINK_SUBTLV_TYPE_SIZE	1
struct te_link_subtlv_link_type {
	struct tlv_header header; /* Value length is 1 octet. */
	struct {
#define	LINK_TYPE_SUBTLV_VALUE_PTP	1
#define	LINK_TYPE_SUBTLV_VALUE_MA	2
		uint8_t value;
		uint8_t padding[3];
	} link_type;
};

/* Link Sub-TLV: Link ID */ /* Mandatory */
#define	TE_LINK_SUBTLV_LINK_ID		2
struct te_link_subtlv_link_id {
	struct tlv_header header; /* Value length is 4 octets. */
	struct in_addr value;     /* Same as router-lsa's link-id. */
};

/* Link Sub-TLV: Local Interface IP Address */ /* Optional */
#define	TE_LINK_SUBTLV_LCLIF_IPADDR	3
struct te_link_subtlv_lclif_ipaddr {
	struct tlv_header header; /* Value length is 4 x N octets. */
	struct in_addr value[1];  /* Local IP address(es). */
};

/* Link Sub-TLV: Remote Interface IP Address */ /* Optional */
#define	TE_LINK_SUBTLV_RMTIF_IPADDR	4
struct te_link_subtlv_rmtif_ipaddr {
	struct tlv_header header; /* Value length is 4 x N octets. */
	struct in_addr value[1];  /* Neighbor's IP address(es). */
};

/* Link Sub-TLV: Traffic Engineering Metric */ /* Optional */
#define	TE_LINK_SUBTLV_TE_METRIC	5
struct te_link_subtlv_te_metric {
	struct tlv_header header; /* Value length is 4 octets. */
	uint32_t value;		  /* Link metric for TE purpose. */
};

/* Link Sub-TLV: Maximum Bandwidth */ /* Optional */
#define	TE_LINK_SUBTLV_MAX_BW		6
struct te_link_subtlv_max_bw {
	struct tlv_header header; /* Value length is 4 octets. */
	float value;		  /* bytes/sec */
};

/* Link Sub-TLV: Maximum Reservable Bandwidth */ /* Optional */
#define	TE_LINK_SUBTLV_MAX_RSV_BW	7
struct te_link_subtlv_max_rsv_bw {
	struct tlv_header header; /* Value length is 4 octets. */
	float value;		  /* bytes/sec */
};

/* Link Sub-TLV: Unreserved Bandwidth */ /* Optional */
#define	TE_LINK_SUBTLV_UNRSV_BW		8
#define TE_LINK_SUBTLV_UNRSV_SIZE	32
struct te_link_subtlv_unrsv_bw {
	struct tlv_header header;    /* Value length is 32 octets. */
	float value[MAX_CLASS_TYPE]; /* One for each priority level. */
};

/* Link Sub-TLV: Resource Class/Color */ /* Optional */
#define	TE_LINK_SUBTLV_RSC_CLSCLR	9
struct te_link_subtlv_rsc_clsclr {
	struct tlv_header header; /* Value length is 4 octets. */
	uint32_t value;		  /* Admin. group membership. */
};

/* For RFC6827 */
/* Local and Remote TE Router ID */
#define TE_LINK_SUBTLV_LRRID		10
#define TE_LINK_SUBTLV_LRRID_SIZE	8
struct te_link_subtlv_lrrid {
	struct tlv_header header; /* Value length is 8 octets. */
	struct in_addr local;     /* Local TE Router Identifier */
	struct in_addr remote;    /* Remote TE Router Identifier */
};

/* RFC4203: Link Local/Remote Identifiers */
#define TE_LINK_SUBTLV_LLRI		11
#define TE_LINK_SUBTLV_LLRI_SIZE	8
struct te_link_subtlv_llri {
	struct tlv_header header; /* Value length is 8 octets. */
	uint32_t local;		  /* Link Local Identifier */
	uint32_t remote;	  /* Link Remote Identifier */
};

/* Inter-RA Export Upward sub-TLV (12) and Inter-RA Export Downward sub-TLV (13)
 * (RFC6827bis) are not yet supported */
/* SUBTLV 14-16 (RFC4203) are not yet supported */
/* Bandwidth Constraints sub-TLV (17) (RFC4124) is not yet supported */
/* SUBLV 18-20 are for OSPFv3 TE (RFC5329). see ospf6d */

/* For RFC 5392 */
/* Remote AS Number sub-TLV */
#define TE_LINK_SUBTLV_RAS		21
struct te_link_subtlv_ras {
	struct tlv_header header; /* Value length is 4 octets. */
	uint32_t value;		  /* Remote AS number */
};

/* IPv4 Remote ASBR ID Sub-TLV */
#define TE_LINK_SUBTLV_RIP		22
struct te_link_subtlv_rip {
	struct tlv_header header; /* Value length is 4 octets. */
	struct in_addr value;     /* Remote ASBR IP address */
};

/* SUBTLV 24 is IPv6 Remote ASBR ID (RFC5392). see ospf6d */

/* SUBTLV 23 (RFC5330) and 25 (RFC6001) are not yet supported */

/* SUBTLV 26 (RFC7308) is not yet supported */

/* RFC7471 */
/* Link Sub-TLV: Average Link Delay */ /* Optional */
#define TE_LINK_SUBTLV_AV_DELAY		27
struct te_link_subtlv_av_delay {
	struct tlv_header header; /* Value length is 4 bytes. */
	/*
	 * delay in micro-seconds only 24 bits => 0 ... 16777215
	 * with Anomalous Bit as Upper most bit
	 */
	uint32_t value;
};

/* Link Sub-TLV: Low/High Link Delay */
#define TE_LINK_SUBTLV_MM_DELAY         28
#define TE_LINK_SUBTLV_MM_DELAY_SIZE    8
struct te_link_subtlv_mm_delay {
	struct tlv_header header; /* Value length is 8 bytes. */
	/*
	 * low delay in micro-seconds only 24 bits => 0 ... 16777215
	 * with Anomalous Bit (A) as Upper most bit
	 */
	uint32_t low;
	/* high delay in micro-seconds only 24 bits => 0 ... 16777215 */
	uint32_t high;
};

/* Link Sub-TLV: Link Delay Variation i.e. Jitter */
#define TE_LINK_SUBTLV_DELAY_VAR	29
struct te_link_subtlv_delay_var {
	struct tlv_header header; /* Value length is 4 bytes. */
	/* interval in micro-seconds only 24 bits => 0 ... 16777215 */
	uint32_t value;
};

/* Link Sub-TLV: Routine Unidirectional Link Packet Loss */
#define TE_LINK_SUBTLV_PKT_LOSS		30
struct te_link_subtlv_pkt_loss {
	struct tlv_header header; /* Value length is 4 bytes. */
	/*
	 * in percentage of total traffic only 24 bits (2^24 - 2)
	 * with Anomalous Bit as Upper most bit
	 */
	uint32_t value;
};

/* Link Sub-TLV: Unidirectional Residual Bandwidth */ /* Optional */
#define TE_LINK_SUBTLV_RES_BW		31
struct te_link_subtlv_res_bw {
	struct tlv_header header; /* Value length is 4 bytes. */
	/* bandwidth in IEEE floating point format with units in bytes/second */
	float value;
};

/* Link Sub-TLV: Unidirectional Available Bandwidth */ /* Optional */
#define TE_LINK_SUBTLV_AVA_BW		32
struct te_link_subtlv_ava_bw {
	struct tlv_header header; /* Value length is 4 octets. */
	/* bandwidth in IEEE floating point format with units in bytes/second */
	float value;
};

/* Link Sub-TLV: Unidirectional Utilized Bandwidth */ /* Optional */
#define TE_LINK_SUBTLV_USE_BW           33
struct te_link_subtlv_use_bw {
	struct tlv_header header; /* Value length is 4 octets. */
	/* bandwidth in IEEE floating point format with units in bytes/second */
	float value;
};

#define TE_LINK_SUBTLV_MAX		34      /* Last SUBTLV + 1 */

/* Here are "non-official" architectural constants. */
#define MPLS_TE_MINIMUM_BANDWIDTH	1.0	/* Reasonable? *//* XXX */

/* Mode for Inter-AS Opaque-LSA */
enum inter_as_mode { Off, AS, Area };

struct te_link_subtlv {
	struct tlv_header header;
	union {
		uint32_t link_type;
		struct in_addr link_id;
		struct in_addr lclif;
		struct in_addr rmtif;
		uint32_t te_metric;
		float max_bw;
		float max_rsv_bw;
		float unrsv[8];
		uint32_t rsc_clsclr;
		uint32_t llri[2];
		uint32_t ras;
		struct in_addr rip;
		struct in_addr lrrid[2];
		uint32_t av_delay;
		uint32_t mm_delay;
		uint32_t delay_var;
		uint32_t pkt_loss;
		float res_bw;
		float ava_bw;
		float use_bw;
	} value;
};

/* Following structure are internal use only. */
struct ospf_mpls_te {
	/* Status of MPLS-TE: enable or disbale */
	bool enabled;

	/* RFC5392 */
	enum inter_as_mode inter_as;
	struct in_addr interas_areaid;

	/* List elements are zebra-interfaces (ifp), not ospf-interfaces (oi).
	 */
	struct list *iflist;

	/* Store Router-TLV in network byte order. */
	struct te_tlv_router_addr router_addr;
};

struct mpls_te_link {
	/*
	 * According to MPLS-TE (draft) specification, 24-bit Opaque-ID field
	 * is subdivided into 8-bit "unused" field and 16-bit "instance" field.
	 * In this implementation, each Link-TLV has its own instance.
	 */
	uint32_t instance;

	/* Reference pointer to a Zebra-interface. */
	struct interface *ifp;

	/* Area info in which this MPLS-TE link belongs to. */
	struct ospf_area *area;

	/* Flags to manage this link parameters. */
	uint32_t flags;

	/* Type of MPLS-TE link: RFC3630, RFC5392, RFC5392 emulated, RFC6827 */
	uint8_t type;

	/* Store Link-TLV in network byte order. */
	/* RFC3630 & RFC6827 / RFC 6827 */
	struct te_tlv_link link_header;
	struct te_link_subtlv_link_type link_type;
	struct te_link_subtlv_link_id link_id;
	struct te_link_subtlv_lclif_ipaddr lclif_ipaddr;
	struct te_link_subtlv_rmtif_ipaddr rmtif_ipaddr;
	struct te_link_subtlv_te_metric te_metric;
	struct te_link_subtlv_max_bw max_bw;
	struct te_link_subtlv_max_rsv_bw max_rsv_bw;
	struct te_link_subtlv_unrsv_bw unrsv_bw;
	struct te_link_subtlv_rsc_clsclr rsc_clsclr;
	/* RFC4203 */
	struct te_link_subtlv_llri llri;
	/* RFC5392 */
	struct te_link_subtlv_ras ras;
	struct te_link_subtlv_rip rip;
	/* RFC6827 */
	struct te_link_subtlv_lrrid lrrid;
	/* RFC7471 */
	struct te_link_subtlv_av_delay av_delay;
	struct te_link_subtlv_mm_delay mm_delay;
	struct te_link_subtlv_delay_var delay_var;
	struct te_link_subtlv_pkt_loss pkt_loss;
	struct te_link_subtlv_res_bw res_bw;
	struct te_link_subtlv_ava_bw ava_bw;
	struct te_link_subtlv_use_bw use_bw;

	struct in_addr adv_router;
	struct in_addr id;
};

/* Prototypes. */
extern int ospf_mpls_te_init(void);
extern void ospf_mpls_te_term(void);
extern void ospf_mpls_te_finish(void);
extern struct ospf_mpls_te *get_ospf_mpls_te(void);
extern void ospf_mpls_te_update_if(struct interface *);
extern void ospf_mpls_te_lsa_schedule(struct mpls_te_link *, enum lsa_opcode);
extern void set_linkparams_llri(struct mpls_te_link *, uint32_t, uint32_t);
extern void set_linkparams_lrrid(struct mpls_te_link *, struct in_addr,
				 struct in_addr);

#endif /* _ZEBRA_OSPF_MPLS_TE_H */
