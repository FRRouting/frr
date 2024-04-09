// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing
 * as per RFC 8665 - OSPF Extensions for Segment Routing
 * and RFC 8476 - Signaling Maximum SID Depth (MSD) Using OSPF
 *
 * Module name: Segment Routing header definitions
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 *
 * Copyright (C) 2016 - 2020 Orange Labs http://www.orange.com
 */

#ifndef _FRR_OSPF_SR_H
#define _FRR_OSPF_SR_H

/* macros and constants for segment routing */
#define SET_RANGE_SIZE_MASK             0xffffff00
#define GET_RANGE_SIZE_MASK             0x00ffffff
#define SET_LABEL_MASK                  0xffffff00
#define GET_LABEL_MASK                  0x00ffffff
#define SET_RANGE_SIZE(range_size) ((range_size << 8) & SET_RANGE_SIZE_MASK)
#define GET_RANGE_SIZE(range_size) ((range_size >> 8) & GET_RANGE_SIZE_MASK)
#define SET_LABEL(label) ((label << 8) & SET_LABEL_MASK)
#define GET_LABEL(label) ((label >> 8) & GET_LABEL_MASK)

/* smallest configurable SRGB / SRLB sizes */
#define MIN_SRLB_SIZE 16
#define MIN_SRGB_SIZE 16

/* Segment Routing TLVs as per RFC 8665 */

/* Segment ID could be a Label (3 bytes) or an Index (4 bytes) */
#define SID_LABEL	3
#define SID_LABEL_SIZE(U) (U - 1)
#define SID_INDEX	4
#define SID_INDEX_SIZE(U) (U)

/* Macro to log debug message */
#define osr_debug(...)                                                         \
	do {                                                                   \
		if (IS_DEBUG_OSPF_SR)                                          \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

/* Macro to check if SR Prefix has no valid route */
#define IS_NO_ROUTE(srp) ((srp->route == NULL) || (srp->route->paths == NULL)  \
			   || list_isempty(srp->route->paths))

/* SID/Label Sub TLV - section 2.1 */
#define SUBTLV_SID_LABEL		1
#define SUBTLV_SID_LABEL_SIZE		4
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

/* RI SID/Label Range TLV used for SRGB & SRLB - section 3.2 & 3.3 */
#define RI_SR_TLV_SRGB_LABEL_RANGE	9
#define RI_SR_TLV_SRLB_LABEL_RANGE	14
#define RI_SR_TLV_LABEL_RANGE_SIZE	12
struct ri_sr_tlv_sid_label_range {
	struct tlv_header header;
/* Only 24 upper most bits are significant */
#define SID_RANGE_LABEL_LENGTH	3
	uint32_t size;
	/* A SID/Label sub-TLV will follow. */
	struct subtlv_sid_label lower;
};

/* RI Node/MSD TLV as per RFC 8476 */
#define RI_SR_TLV_NODE_MSD		12
#define RI_SR_TLV_NODE_MSD_SIZE		4
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
/* Default min and size of SR Global Block label range */
#define DEFAULT_SRGB_LABEL        16000
#define DEFAULT_SRGB_SIZE         8000
#define DEFAULT_SRGB_END (DEFAULT_SRGB_LABEL + DEFAULT_SRGB_SIZE - 1)

/* Default min and size of SR Local Block label range */
#define DEFAULT_SRLB_LABEL        15000
#define DEFAULT_SRLB_SIZE         1000
#define DEFAULT_SRLB_END (DEFAULT_SRLB_LABEL + DEFAULT_SRLB_SIZE - 1)

/* Structure aggregating SR Range Block info retrieved from an lsa */
struct sr_block {
	uint32_t range_size;
	uint32_t lower_bound;
};

/* Segment Routing Global Block allocation */
struct sr_global_block {
	bool reserved;
	uint32_t start;
	uint32_t size;
};

/* Segment Routing Local Block allocation */
struct sr_local_block {
	bool reserved;
	uint32_t start;
	uint32_t end;
	uint32_t current;
	uint32_t max_block;
	uint64_t *used_mark;
};
#define SRLB_BLOCK_SIZE 64

/* SID type to make difference between loopback interfaces and others */
enum sid_type { PREF_SID, LOCAL_SID, ADJ_SID, LAN_ADJ_SID };

/* Status of Segment Routing: Off (Disable), On (Enable), (Up) Started */
enum sr_status { SR_OFF, SR_ON, SR_UP };

/* Structure aggregating all OSPF Segment Routing information for the node */
struct ospf_sr_db {
	/* Status of Segment Routing */
	enum sr_status status;

	/* Flooding Scope: Area = 10 or AS = 11 */
	uint8_t scope;

	/* FRR SR node */
	struct sr_node *self;

	/* List of neighbour SR nodes */
	struct hash *neighbors;

	/* Local SR info announced in Router Info LSA */

	/* Algorithms supported by the node */
	uint8_t algo[ALGORITHM_COUNT];
	/*
	 * Segment Routing Global Block i.e. label range
	 * Only one range supported in this code
	 */
	struct sr_global_block srgb;

	/* Segment Routing Local Block */
	struct sr_local_block srlb;

	/* Maximum SID Depth supported by the node */
	uint8_t msd;

	/* Thread timer to start Label Manager */
	struct event *t_start_lm;
};

/* Structure aggregating all received SR info from LSAs by node */
struct sr_node {
	struct in_addr adv_router; /* used to identify sender of LSA */
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;

	uint8_t algo[ALGORITHM_COUNT]; /* Algorithms supported by the node */
	struct sr_block srgb;          /* Segment Routing Global Block */
	struct sr_block srlb;          /* Segment Routing Local Block */
	uint8_t msd;                   /* Maximum SID Depth */

	/* List of Prefix & Link advertise by this node */
	struct list *ext_prefix; /* For Node SID */
	struct list *ext_link;   /* For Adjacency SID */

	/* Pointer to FRR SR-Node or NULL if it is not a neighbor */
	struct sr_node *neighbor;
};

/* Segment Routing - NHLFE info: support IPv4 Only */
struct sr_nhlfe {
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

	/* Addressed (remote) router id */
	struct in_addr remote_id;

	/* Interface address */
	struct in_addr itf_addr;

	/* Flags to manage this link parameters. */
	uint8_t flags[2];

	/* Segment Routing ID */
	uint32_t sid[2];
	enum sid_type type;

	/* SR NHLFE (Primary + Backup) for this link */
	struct sr_nhlfe nhlfe[2];

	/* Back pointer to SR Node which advertise this Link */
	struct sr_node *srn;
};

/* Structure aggregating all Segment Routing Prefix information */
struct sr_prefix {
	struct in_addr adv_router; /* used to identify sender of LSA */
	/* 24-bit Opaque-ID field value according to RFC 7684 specification */
	uint32_t instance;

	/* Prefix itself */
	struct prefix_ipv4 prefv4;

	/* Flags to manage this prefix parameters. */
	uint8_t flags;

	/* Segment Routing ID */
	uint32_t sid;
	enum sid_type type;

	/* Incoming label for this prefix */
	mpls_label_t label_in;

	/* Back pointer to OSPF Route for remote prefix */
	struct ospf_route *route;

	/* NHLFE for local prefix */
	struct sr_nhlfe nhlfe;

	/* Back pointer to SR Node which advertise this Prefix */
	struct sr_node *srn;
};

/* Prototypes definition */
/* Segment Routing initialisation functions */
extern int ospf_sr_init(void);
extern void ospf_sr_term(void);
extern void ospf_sr_finish(void);
/* Segment Routing label allocation functions */
extern mpls_label_t ospf_sr_local_block_request_label(void);
extern int ospf_sr_local_block_release_label(mpls_label_t label);
/* Segment Routing LSA update & delete functions */
extern void ospf_sr_ri_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ri_lsa_delete(struct ospf_lsa *lsa);
extern void ospf_sr_ext_link_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ext_link_lsa_delete(struct ospf_lsa *lsa);
extern void ospf_sr_ext_prefix_lsa_update(struct ospf_lsa *lsa);
extern void ospf_sr_ext_prefix_lsa_delete(struct ospf_lsa *lsa);
/* Segment Routing Extending Link management */
struct ext_itf;
extern void ospf_sr_ext_itf_add(struct ext_itf *exti);
extern void ospf_sr_ext_itf_delete(struct ext_itf *exti);
/* Segment Routing configuration functions */
extern void ospf_sr_config_write_router(struct vty *vty);
extern void ospf_sr_update_local_prefix(struct interface *ifp,
					struct prefix *p);
/* Segment Routing re-routing function */
extern void ospf_sr_update_task(struct ospf *ospf);

/* Support for TI-LFA */
extern mpls_label_t ospf_sr_get_prefix_sid_by_id(struct in_addr *id);
extern mpls_label_t ospf_sr_get_adj_sid_by_id(struct in_addr *root_id,
					      struct in_addr *neighbor_id);
extern struct sr_node *ospf_sr_node_create(struct in_addr *rid);

#endif /* _FRR_OSPF_SR_H */
