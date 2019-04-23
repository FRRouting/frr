/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305, RFC 5307 and RFC 7810
 *
 *      Copyright (C) 2014 Orange Labs
 *      http://www.orange.com
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

#ifndef _ZEBRA_ISIS_MPLS_TE_H
#define _ZEBRA_ISIS_MPLS_TE_H

/*
 * Traffic Engineering information are transport through LSP:
 *  - Extended IS Reachability          TLV = 22
 *  - Traffic Engineering Router ID     TLV = 134
 *  - Extended IP Reachability          TLV = 135
 *  - Inter-AS Reachability Information TLV = 141
 *
 *  and support following sub-TLV:
 *
 * Name                           Value   Status
 * _________________________________________________
 * Administartive group (color)       3   RFC5305
 * Link Local/Remote Identifiers      4   RFC5307
 * IPv4 interface address             6   RFC5305
 * IPv4 neighbor address              8   RFC5305
 * Maximum link bandwidth             9   RFC5305
 * Reservable link bandwidth         10   RFC5305
 * Unreserved bandwidth              11   RFC5305
 * TE Default metric                 18   RFC5305
 * Link Protection Type              20   RFC5307
 * Interface Switching Capability    21   RFC5307
 * Remote AS number                  24   RFC5316
 * IPv4 Remote ASBR identifier       25   RFC5316
 *
 */

/* NOTE: RFC5316 is not yet supported in this version */

/* Following define the type of TE link regarding the various RFC */
#define STD_TE			0x01
#define GMPLS			0x02
#define INTER_AS 		0x04
#define FLOOD_L1		0x10
#define FLOOD_L2		0x20
#define FLOOD_AS                0x40
#define EMULATED		0x80

#define IS_STD_TE(x) 		(x & STD_TE)
#define IS_INTER_AS(x) 		(x & INTER_AS)
#define IS_EMULATED(x)		(x & EMULATED)
#define IS_FLOOD_L1(x)		(x & FLOOD_L1)
#define IS_FLOOD_L2(x)		(x & FLOOD_L2)
#define IS_FLOOD_AS(x)          (x & FLOOD_AS)
#define IS_INTER_AS_EMU(x) 	(x & INTER_AS & EMULATED)
#define IS_INTER_AS_AS(x)	(x & INTER_AS & FLOOD_AS)

/*
 * Following section defines subTLV (tag, length, value) structures,
 * used for Traffic Engineering.
 */
struct subtlv_header {
	uint8_t type;   /* sub_TLV_XXX type (see above) */
	uint8_t length; /* Value portion only, in byte */
};

#define MAX_SUBTLV_SIZE 256

#define SUBTLV_HDR_SIZE        2  /* (sizeof (struct sub_tlv_header)) */

#define SUBTLV_SIZE(stlvh) 	(SUBTLV_HDR_SIZE + (stlvh)->length)

#define SUBTLV_HDR_TOP(lsph) 	(struct subtlv_header *)((char *)(lsph) + ISIS_LSP_HEADER_SIZE)

#define SUBTLV_HDR_NEXT(stlvh) 	(struct subtlv_header *)((char *)(stlvh) + SUBTLV_SIZE(stlvh))

#define SUBTLV_TYPE(stlvh)     stlvh.header.type
#define SUBTLV_LEN(stlvh)      stlvh.header.length
#define SUBTLV_VAL(stlvh)      stlvh.value
#define SUBTLV_DATA(stlvh)     stlvh + SUBTLV_HDR_SIZE

#define SUBTLV_DEF_SIZE		4

/* Link Sub-TLV: Resource Class/Color - RFC 5305 */
#define TE_SUBTLV_ADMIN_GRP	3
struct te_subtlv_admin_grp {
	struct subtlv_header header; /* Value length is 4 octets. */
	uint32_t value;		     /* Admin. group membership. */
} __attribute__((__packed__));

/* Link Local/Remote Identifiers - RFC 5307 */
#define TE_SUBTLV_LLRI		4
#define TE_SUBTLV_LLRI_SIZE	8
struct te_subtlv_llri {
	struct subtlv_header header; /* Value length is 8 octets. */
	uint32_t local;		     /* Link Local Identifier */
	uint32_t remote;	     /* Link Remote Identifier */
} __attribute__((__packed__));

/* Link Sub-TLV: Local Interface IP Address - RFC 5305 */
#define TE_SUBTLV_LOCAL_IPADDR	6
struct te_subtlv_local_ipaddr {
	struct subtlv_header header; /* Value length is 4 x N octets. */
	struct in_addr value;	/* Local IP address(es). */
} __attribute__((__packed__));

/* Link Sub-TLV: Neighbor Interface IP Address - RFC 5305 */
#define TE_SUBTLV_RMT_IPADDR	8
struct te_subtlv_rmt_ipaddr {
	struct subtlv_header header; /* Value length is 4 x N octets. */
	struct in_addr value;	/* Neighbor's IP address(es). */
} __attribute__((__packed__));

/* Link Sub-TLV: Maximum Bandwidth - RFC 5305 */
#define TE_SUBTLV_MAX_BW	9
struct te_subtlv_max_bw {
	struct subtlv_header header; /* Value length is 4 octets. */
	float value;		     /* bytes/sec */
} __attribute__((__packed__));

/* Link Sub-TLV: Maximum Reservable Bandwidth - RFC 5305 */
#define TE_SUBTLV_MAX_RSV_BW	10
struct te_subtlv_max_rsv_bw {
	struct subtlv_header header; /* Value length is 4 octets. */
	float value;		     /* bytes/sec */
} __attribute__((__packed__));

/* Link Sub-TLV: Unreserved Bandwidth - RFC 5305 */
#define TE_SUBTLV_UNRSV_BW	11
#define TE_SUBTLV_UNRSV_SIZE	32
struct te_subtlv_unrsv_bw {
	struct subtlv_header header; /* Value length is 32 octets. */
	float value[8];		     /* One for each priority level. */
} __attribute__((__packed__));

/* Link Sub-TLV: Traffic Engineering Metric - RFC 5305 */
#define TE_SUBTLV_TE_METRIC	18
#define TE_SUBTLV_TE_METRIC_SIZE    3
struct te_subtlv_te_metric {
	struct subtlv_header header; /* Value length is 4 octets. */
	uint8_t value[3];	    /* Link metric for TE purpose. */
} __attribute__((__packed__));

/* Remote AS Number sub-TLV - RFC5316 */
#define TE_SUBTLV_RAS		24
struct te_subtlv_ras {
	struct subtlv_header header; /* Value length is 4 octets. */
	uint32_t value;		     /* Remote AS number */
} __attribute__((__packed__));

/* IPv4 Remote ASBR ID Sub-TLV - RFC5316 */
#define TE_SUBTLV_RIP		25
struct te_subtlv_rip {
	struct subtlv_header header; /* Value length is 4 octets. */
	struct in_addr value;	/* Remote ASBR IP address */
} __attribute__((__packed__));


/* TE Metric Extensions - RFC 7810 */
/* Link Sub-TLV: Average Link Delay */
#define TE_SUBTLV_AV_DELAY	33
struct te_subtlv_av_delay {
	struct subtlv_header header; /* Value length is 4 bytes. */
	uint32_t value; /* Average delay in micro-seconds only 24 bits => 0 ...
			    16777215
			    with Anomalous Bit (A) as Upper most bit */
} __attribute__((__packed__));

/* Link Sub-TLV: Low/High Link Delay */
#define TE_SUBTLV_MM_DELAY      34
#define TE_SUBTLV_MM_DELAY_SIZE    8
struct te_subtlv_mm_delay {
	struct subtlv_header header; /* Value length is 8 bytes. */
	uint32_t low;  /* low delay in micro-seconds only 24 bits => 0 ...
			   16777215
			   with Anomalous Bit (A) as Upper most bit */
	uint32_t high; /* high delay in micro-seconds only 24 bits => 0 ...
			   16777215 */
} __attribute__((__packed__));

/* Link Sub-TLV: Link Delay Variation i.e. Jitter */
#define TE_SUBTLV_DELAY_VAR     35
struct te_subtlv_delay_var {
	struct subtlv_header header; /* Value length is 4 bytes. */
	uint32_t value; /* interval in micro-seconds only 24 bits => 0 ...
			    16777215 */
} __attribute__((__packed__));

/* Link Sub-TLV: Routine Unidirectional Link Packet Loss */
#define TE_SUBTLV_PKT_LOSS	36
struct te_subtlv_pkt_loss {
	struct subtlv_header header; /* Value length is 4 bytes. */
	uint32_t
		value; /* in percentage of total traffic only 24 bits (2^24 - 2)
			  with Anomalous Bit (A) as Upper most bit */
} __attribute__((__packed__));

/* Link Sub-TLV: Unidirectional Residual Bandwidth */ /* Optional */
#define TE_SUBTLV_RES_BW	37
struct te_subtlv_res_bw {
	struct subtlv_header header; /* Value length is 4 bytes. */
	float value; /* bandwidth in IEEE floating point format with units in
			bytes per second */
} __attribute__((__packed__));

/* Link Sub-TLV: Unidirectional Available Bandwidth */ /* Optional */
#define TE_SUBTLV_AVA_BW	38
struct te_subtlv_ava_bw {
	struct subtlv_header header; /* Value length is 4 octets. */
	float value; /* bandwidth in IEEE floating point format with units in
			bytes per second */
} __attribute__((__packed__));

/* Link Sub-TLV: Unidirectional Utilized Bandwidth */ /* Optional */
#define TE_SUBTLV_USE_BW        39
struct te_subtlv_use_bw {
	struct subtlv_header header; /* Value length is 4 octets. */
	float value; /* bandwidth in IEEE floating point format with units in
			bytes per second */
} __attribute__((__packed__));

#define TE_SUBTLV_MAX		40      /* Last SUBTLV + 1 */

/* Following declaration concerns the MPLS-TE and LINk-TE management */
typedef enum _status_t { disable, enable, learn } status_t;

/* Mode for Inter-AS LSP */ /* TODO: Check how if LSP is flooded in RFC5316 */
typedef enum _interas_mode_t { off, region, as, emulate } interas_mode_t;

#define IS_MPLS_TE(m)    (m.status == enable)
#define IS_CIRCUIT_TE(c) (c->status == enable)

/* Following structure are internal use only. */
struct isis_mpls_te {
	/* Status of MPLS-TE: enable or disable */
	status_t status;

	/* L1, L1-L2, L2-Only */
	uint8_t level;

	/* RFC5316 */
	interas_mode_t inter_as;
	struct in_addr interas_areaid;

	/* Circuit list on which TE are enable */
	struct list *cir_list;

	/* MPLS_TE router ID */
	struct in_addr router_id;
};

extern struct isis_mpls_te isisMplsTE;

struct mpls_te_circuit {

	/* Status of MPLS-TE on this interface */
	status_t status;

	/* Type of MPLS-TE circuit: STD_TE(RFC5305), INTER_AS(RFC5316),
	 * INTER_AS_EMU(RFC5316 emulated) */
	uint8_t type;

	/* Total size of sub_tlvs */
	uint8_t length;

	/* Store subTLV in network byte order. */
	/* RFC5305 */
	struct te_subtlv_admin_grp admin_grp;
	/* RFC5307 */
	struct te_subtlv_llri llri;
	/* RFC5305 */
	struct te_subtlv_local_ipaddr local_ipaddr;
	struct te_subtlv_rmt_ipaddr rmt_ipaddr;
	struct te_subtlv_max_bw max_bw;
	struct te_subtlv_max_rsv_bw max_rsv_bw;
	struct te_subtlv_unrsv_bw unrsv_bw;
	struct te_subtlv_te_metric te_metric;
	/* RFC5316 */
	struct te_subtlv_ras ras;
	struct te_subtlv_rip rip;
	/* RFC7810 */
	struct te_subtlv_av_delay av_delay;
	struct te_subtlv_mm_delay mm_delay;
	struct te_subtlv_delay_var delay_var;
	struct te_subtlv_pkt_loss pkt_loss;
	struct te_subtlv_res_bw res_bw;
	struct te_subtlv_ava_bw ava_bw;
	struct te_subtlv_use_bw use_bw;
};

/* Prototypes. */
void isis_mpls_te_init(void);
struct mpls_te_circuit *mpls_te_circuit_new(void);
struct sbuf;
void mpls_te_print_detail(struct sbuf *buf, int indent, uint8_t *subtlvs,
			  uint8_t subtlv_len);
void set_circuitparams_local_ipaddr(struct mpls_te_circuit *, struct in_addr);
void set_circuitparams_rmt_ipaddr(struct mpls_te_circuit *, struct in_addr);
uint8_t subtlvs_len(struct mpls_te_circuit *);
uint8_t add_te_subtlvs(uint8_t *, struct mpls_te_circuit *);
uint8_t build_te_subtlvs(uint8_t *, struct isis_circuit *);
void isis_link_params_update(struct isis_circuit *, struct interface *);
void isis_mpls_te_update(struct interface *);
void isis_mpls_te_config_write_router(struct vty *);

#endif /* _ZEBRA_ISIS_MPLS_TE_H */
