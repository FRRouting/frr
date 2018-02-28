/*
 * This is an implementation of Segment Routing
 * as per draft draft-ietf-ospf-segment-routing-extensions-24
 *
 * Module name: Segment Routing header definitions
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 *
 * Copyright (C) 2016 - 2018 Orange Labs http://www.orange.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_OSPF_SR_H
#define _FRR_OSPF_SR_H

/* Default Route priority for OSPF Segment Routing */
#define OSPF_SR_PRIORITY_DEFAULT	10

/* macros and constants for segment routing */
#define SET_RANGE_SIZE_MASK             0xffffff00
#define GET_RANGE_SIZE_MASK             0x00ffffff
#define SET_LABEL_MASK                  0xffffff00
#define GET_LABEL_MASK                  0x00ffffff
#define SET_RANGE_SIZE(range_size) ((range_size << 8) & SET_RANGE_SIZE_MASK)
#define GET_RANGE_SIZE(range_size) ((range_size >> 8) & GET_RANGE_SIZE_MASK)
#define SET_LABEL(label) ((label << 8) & SET_LABEL_MASK)
#define GET_LABEL(label) ((label >> 8) & GET_LABEL_MASK)

/* Label range for Adj-SID attribution purpose. Start just right after SRGB */
#define ADJ_SID_MIN                     MPLS_DEFAULT_MAX_SRGB_LABEL
#define ADJ_SID_MAX                     (MPLS_DEFAULT_MAX_SRGB_LABEL + 1000)

#define OSPF_SR_DEFAULT_METRIC		1

/* Segment Routing TLVs as per draft-ietf-ospf-segment-routing-extensions-19 */

/* Segment ID could be a Label (3 bytes) or an Index (4 bytes) */
#define SID_LABEL	3
#define SID_LABEL_SIZE(U) (U - 1)
#define SID_INDEX	4
#define SID_INDEX_SIZE(U) (U)

/* SID/Label Sub TLV - section 2.1 */
#define SUBTLV_SID_LABEL		1
#define SUBTLV_SID_LABEL_SIZE		8
struct subtlv_sid_label {
	/* Length is 3 (20 rightmost bits MPLS label) or 4 (32 bits SID) */
	struct tlv_header header;
	uint32_t value;
};

/*
 * Following section defines Segment Routing TLV (tag, length, value)
 * structures, used in Router Information Opaque LSA.
 */

/* RI SR-Algorithm TLV - section 3.1 */
#define RI_SR_TLV_SR_ALGORITHM          8
struct ri_sr_tlv_sr_algorithm {
	struct tlv_header header;
#define SR_ALGORITHM_SPF         0
#define SR_ALGORITHM_STRICT_SPF  1
#define SR_ALGORITHM_UNSET       255
#define ALGORITHM_COUNT          4
	/* Only 4 algorithms supported in this code */
	uint8_t value[ALGORITHM_COUNT];
};

/* RI SID/Label Range TLV - section 3.2 */
#define RI_SR_TLV_SID_LABEL_RANGE	9
struct ri_sr_tlv_sid_label_range {
	struct tlv_header header;
/* Only 24 upper most bits are significant */
#define SID_RANGE_LABEL_LENGTH	3
	uint32_t size;
	/* A SID/Label sub-TLV will follow. */
	struct subtlv_sid_label lower;
};

/* RI Node/MSD TLV as per draft-ietf-ospf-segment-routing-msd-05 */
#define RI_SR_TLV_NODE_MSD		12
struct ri_sr_tlv_node_msd {
	struct tlv_header header;
	uint8_t subtype; /* always = 1 */
	uint8_t value;
	uint16_t padding;
};

/*
 * Following section defines Segment Routing TLV (tag, length, value)
 * structures, used in Extended Prefix/Link Opaque LSA.
 */

/* Adj-SID and LAN-Ajd-SID subtlvs' flags */
#define EXT_SUBTLV_LINK_ADJ_SID_BFLG	0x80
#define EXT_SUBTLV_LINK_ADJ_SID_VFLG	0x40
#define EXT_SUBTLV_LINK_ADJ_SID_LFLG	0x20
#define EXT_SUBTLV_LINK_ADJ_SID_SFLG	0x10

/* Prefix SID subtlv Flags */
#define EXT_SUBTLV_PREFIX_SID_NPFLG	0x40
#define EXT_SUBTLV_PREFIX_SID_MFLG	0x20
#define EXT_SUBTLV_PREFIX_SID_EFLG	0x10
#define EXT_SUBTLV_PREFIX_SID_VFLG	0x08
#define EXT_SUBTLV_PREFIX_SID_LFLG	0x04

/* SID/Label Binding subtlv Flags */
#define EXT_SUBTLV_SID_BINDING_MFLG	0x80

/* Extended Prefix Range TLV - section 4 */
#define EXT_TLV_PREF_RANGE		2
#define EXT_SUBTLV_PREFIX_RANGE_SIZE	12
struct ext_tlv_prefix_range {
	struct tlv_header header;
	uint8_t pref_length;
	uint8_t af;
	uint16_t range_size;
	uint8_t flags;
	uint8_t reserved[3];
	struct in_addr address;
};

/* Prefix SID Sub-TLV - section 5 */
#define EXT_SUBTLV_PREFIX_SID		2
#define EXT_SUBTLV_PREFIX_SID_SIZE	8
struct ext_subtlv_prefix_sid {
	struct tlv_header header;
	uint8_t flags;
	uint8_t reserved;
	uint8_t mtid;
	uint8_t algorithm;
	uint32_t value;
};

/* Adj-SID Sub-TLV - section 6.1 */
#define EXT_SUBTLV_ADJ_SID		2
#define EXT_SUBTLV_ADJ_SID_SIZE		8
struct ext_subtlv_adj_sid {
	struct tlv_header header;
	uint8_t flags;
	uint8_t reserved;
	uint8_t mtid;
	uint8_t weight;
	uint32_t value;
};

/* LAN Adj-SID Sub-TLV - section 6.2 */
#define EXT_SUBTLV_LAN_ADJ_SID		3
#define EXT_SUBTLV_LAN_ADJ_SID_SIZE	12
struct ext_subtlv_lan_adj_sid {
	struct tlv_header header;
	uint8_t flags;
	uint8_t reserved;
	uint8_t mtid;
	uint8_t weight;
	struct in_addr neighbor_id;
	uint32_t value;
};

/*
 * Following section define structure used to manage Segment Routing
 * information and TLVs / SubTLVs
 */

/* Structure aggregating SRGB info retrieved from an lsa */
struct sr_srgb {
	uint32_t range_size;
	uint32_t lower_bound;
};

/* SID type to make difference between loopback interfaces and others */
enum sid_type { PREF_SID, ADJ_SID, LAN_ADJ_SID };

/* Structure aggregating all OSPF Segment Routing information for the node */
struct ospf_sr_db {
	/* Status of Segment Routing: enable or disable */
	bool enabled;

	/* Ongoing Update following an OSPF SPF */
	bool update;

	/* Flooding Scope: Area = 10 or AS = 11 */
	uint8_t scope;

	/* FRR SR node */
	struct sr_node *self;

	/* List of neighbour SR nodes */
	struct hash *neighbors;

	/* List of SR prefix */
	struct route_table *prefix;

	/* Local SR info announced in Router Info LSA */

	/* Algorithms supported by the node */
	uint8_t algo[ALGORITHM_COUNT];
	/*
	 * Segment Routing Global Block i.e. label range
	 * Only one range supported in this code
	 */
	struct sr_srgb srgb;
	/* Maximum SID Depth supported by the node */
	uint8_t msd;
};

/* Structure aggregating all received SR info from LSAs by node */
struct sr_node {
	struct in_addr adv_router; /* used to identify sender of LSA */
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;

	uint8_t algo[ALGORITHM_COUNT]; /* Algorithms supported by the node */
	/* Segment Routing Global Block i.e. label range */
	struct sr_srgb srgb;
	uint8_t msd; /* Maximum SID Depth */

	/* List of Prefix & Link advertise by this node */
	struct list *ext_prefix; /* For Node SID */
	struct list *ext_link;   /* For Adj and LAN SID */

	/* Pointer to FRR SR-Node or NULL if it is not a neighbor */
	struct sr_node *neighbor;
};


/* Segment Routing - NHLFE info: support IPv4 Only */
struct sr_nhlfe {
	struct prefix_ipv4 prefv4;
	struct in_addr nexthop;
	ifindex_t ifindex;
	mpls_label_t label_in;
	mpls_label_t label_out;
};

/* Structure aggregating all Segment Routing Link information */
/* Link are generally advertised by pair: primary + backup */
struct sr_link {
	struct in_addr adv_router; /* used to identify sender of LSA */
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;

	/* Flags to manage this link parameters. */
	uint8_t flags[2];

	/* Segment Routing ID */
	uint32_t sid[2];
	enum sid_type type;

	/* SR NHLFE for this link */
	struct sr_nhlfe nhlfe[2];

	/* Back pointer to SR Node which advertise this Link */
	struct sr_node *srn;
};

/* Structure aggregating all Segment Routing Prefix information */
struct sr_prefix {
	struct in_addr adv_router; /* used to identify sender of LSA */
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;

	/* Flags to manage this prefix parameters. */
	uint8_t flags;

	/* Segment Routing ID */
	uint32_t sid;
	enum sid_type type;

	/* SR NHLFE for this prefix */
	struct sr_nhlfe nhlfe;

	/* Back pointer to SR Node which advertise this Prefix */
	struct sr_node *srn;

	/*
	 * Pointer to SR Node which is the next hop for this Prefix
	 * or NULL if next hop is the destination of the prefix
	 */
	struct sr_node *nexthop;
};

/* Prototypes definition */
/* Segment Routing initialisation functions */
extern int ospf_sr_init(void);
extern void ospf_sr_term(void);
extern void ospf_sr_finish(void);
/* Segment Routing LSA update & delete functions */
extern void ospf_sr_ri_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ri_lsa_delete(struct ospf_lsa *lsa);
extern void ospf_sr_ext_link_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ext_link_lsa_delete(struct ospf_lsa *lsa);
extern void ospf_sr_ext_prefix_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ext_prefix_lsa_delete(struct ospf_lsa *lsa);
/* Segment Routing configuration functions */
extern uint32_t get_ext_link_label_value(void);
extern void ospf_sr_config_write_router(struct vty *vty);
extern void ospf_sr_update_prefix(struct interface *ifp, struct prefix *p);
/* Segment Routing re-routing function */
extern void ospf_sr_update_timer_add(struct ospf *ospf);
#endif /* _FRR_OSPF_SR_H */
