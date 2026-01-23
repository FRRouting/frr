// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State NLRI (RFC 9552)
 * Copyright (C) 2025 Carmine Scarpitta
 */

#ifndef _FRR_BGP_LS_NLRI_H
#define _FRR_BGP_LS_NLRI_H

#include "prefix.h"
#include "bgpd/bgpd.h"

/*
 * ===========================================================================
 * Protocol and NLRI Type Definitions
 * ===========================================================================
 */

/*
 * BGP-LS Protocol-ID values
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#protocol-ids
 */
enum bgp_ls_protocol_id {
	BGP_LS_PROTO_RESERVED = 0, /* Reserved - RFC 9552 */
	BGP_LS_PROTO_ISIS_L1 = 1,  /* IS-IS Level 1 - RFC 9552 */
	BGP_LS_PROTO_ISIS_L2 = 2,  /* IS-IS Level 2 - RFC 9552 */
	BGP_LS_PROTO_OSPFV2 = 3,   /* OSPFv2 - RFC 9552 */
	BGP_LS_PROTO_DIRECT = 4,   /* Direct - RFC 9552 */
	BGP_LS_PROTO_STATIC = 5,   /* Static configuration - RFC 9552 */
	BGP_LS_PROTO_OSPFV3 = 6,   /* OSPFv3 - RFC 9552 */
	BGP_LS_PROTO_BGP = 7,	   /* BGP - RFC 9086 */
};

/*
 * BGP-LS NLRI Types
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#nlri-types
 */
enum bgp_ls_nlri_type {
	BGP_LS_NLRI_TYPE_RESERVED = 0,	  /* Reserved - RFC 9552 */
	BGP_LS_NLRI_TYPE_NODE = 1,	  /* Node NLRI - RFC 9552 */
	BGP_LS_NLRI_TYPE_LINK = 2,	  /* Link NLRI - RFC 9552 */
	BGP_LS_NLRI_TYPE_IPV4_PREFIX = 3, /* IPv4 Topology Prefix NLRI - RFC 9552 */
	BGP_LS_NLRI_TYPE_IPV6_PREFIX = 4, /* IPv6 Topology Prefix NLRI - RFC 9552 */
};

/*
 * ===========================================================================
 * TLV Type Definitions
 * ===========================================================================
 */

/*
 * Node Descriptor TLV Types
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv
 */
enum bgp_ls_node_descriptor_tlv {
	BGP_LS_TLV_LOCAL_NODE_DESC = 256,  /* Local Node Descriptors - RFC 9552, Section 5.2.1.2 */
	BGP_LS_TLV_REMOTE_NODE_DESC = 257, /* Remote Node Descriptors - RFC 9552, Section 5.2.1.3 */
	BGP_LS_TLV_AS_NUMBER = 512,	   /* Autonomous System - RFC 9552, Section 5.2.1.4 */
	BGP_LS_TLV_BGP_LS_ID = 513, /* BGP-LS Identifier (deprecated) - RFC 9552, Section 5.2.1.4 */
	BGP_LS_TLV_OSPF_AREA_ID = 514,	/* OSPF Area-ID - RFC 9552, Section 5.2.1.4 */
	BGP_LS_TLV_IGP_ROUTER_ID = 515, /* IGP Router-ID - RFC 9552, Section 5.2.1.4 */
};

/*
 * Link Descriptor TLV Types
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv
 */
enum bgp_ls_link_descriptor_tlv {
	BGP_LS_TLV_LINK_ID = 258, /* Link Local/Remote Identifiers - RFC 9552, Section 5.2.2 */
	BGP_LS_TLV_IPV4_INTF_ADDR = 259,  /* IPv4 interface address - RFC 9552, Section 5.2.2 */
	BGP_LS_TLV_IPV4_NEIGH_ADDR = 260, /* IPv4 neighbor address - RFC 9552, Section 5.2.2 */
	BGP_LS_TLV_IPV6_INTF_ADDR = 261,  /* IPv6 interface address - RFC 9552, Section 5.2.2 */
	BGP_LS_TLV_IPV6_NEIGH_ADDR = 262, /* IPv6 neighbor address - RFC 9552, Section 5.2.2 */
	BGP_LS_TLV_MT_ID = 263, /* Multi-Topology Identifier - RFC 9552, Section 5.2.2.1 */
};

/*
 * Prefix Descriptor TLV Types
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv
 */
enum bgp_ls_prefix_descriptor_tlv {
	BGP_LS_TLV_OSPF_ROUTE_TYPE = 264, /* OSPF Route Type - RFC 9552, Section 5.2.3.1 */
	BGP_LS_TLV_IP_REACH_INFO = 265, /* IP Reachability Information - RFC 9552, Section 5.2.3.2 */
};

/*
 * OSPF Route Type Values (for TLV 264)
 * RFC 9552, Section 5.2.3.1
 */
enum bgp_ls_ospf_route_type {
	BGP_LS_OSPF_RT_INTRA_AREA = 1, /* Intra-Area */
	BGP_LS_OSPF_RT_INTER_AREA = 2, /* Inter-Area */
	BGP_LS_OSPF_RT_EXTERNAL_1 = 3, /* External Type 1 */
	BGP_LS_OSPF_RT_EXTERNAL_2 = 4, /* External Type 2 */
	BGP_LS_OSPF_RT_NSSA_1 = 5,     /* NSSA Type 1 */
	BGP_LS_OSPF_RT_NSSA_2 = 6,     /* NSSA Type 2 */
};

/*
 * BGP-LS Attribute TLV Types
 * IANA: https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv
 */

/* Node Attribute TLVs (RFC 9552 Section 4.3) */
enum bgp_ls_node_attr_tlv {
	BGP_LS_ATTR_NODE_FLAG_BITS = 1024,  /* Node Flag Bits */
	BGP_LS_ATTR_NODE_NAME = 1026,	    /* Node Name */
	BGP_LS_ATTR_ISIS_AREA_ID = 1027,    /* IS-IS Area Identifier */
	BGP_LS_ATTR_IPV4_ROUTER_ID = 1028,  /* IPv4 Router-ID of Local Node */
	BGP_LS_ATTR_IPV6_ROUTER_ID = 1029,  /* IPv6 Router-ID of Local Node */
	BGP_LS_ATTR_SR_CAPABILITIES = 1034, /* SR Capabilities */
	BGP_LS_ATTR_SR_ALGORITHM = 1035,    /* SR Algorithm */
	BGP_LS_ATTR_SR_LOCAL_BLOCK = 1036,  /* SR Local Block */
	BGP_LS_ATTR_SRMS_PREFERENCE = 1037, /* SRMS Preference */
	BGP_LS_ATTR_NODE_MSD = 1050,	    /* Node MSD */
};

/* Link Attribute TLVs (RFC 9552 Section 4.3) */
enum bgp_ls_link_attr_tlv {
	BGP_LS_ATTR_IPV4_ROUTER_ID_LOCAL = 1028,  /* IPv4 Router-ID of Local Node */
	BGP_LS_ATTR_IPV6_ROUTER_ID_LOCAL = 1029,  /* IPv6 Router-ID of Local Node */
	BGP_LS_ATTR_IPV4_ROUTER_ID_REMOTE = 1030, /* IPv4 Router-ID of Remote Node */
	BGP_LS_ATTR_IPV6_ROUTER_ID_REMOTE = 1031, /* IPv6 Router-ID of Remote Node */
	BGP_LS_ATTR_ADMIN_GROUP = 1088,		  /* Administrative Group (Color) */
	BGP_LS_ATTR_MAX_LINK_BW = 1089,		  /* Maximum Link Bandwidth */
	BGP_LS_ATTR_MAX_RESV_BW = 1090,		  /* Maximum Reservable Link Bandwidth */
	BGP_LS_ATTR_UNRESV_BW = 1091,		  /* Unreserved Bandwidth */
	BGP_LS_ATTR_TE_DEFAULT_METRIC = 1092,	  /* TE Default Metric */
	BGP_LS_ATTR_LINK_PROTECTION_TYPE = 1093,  /* Link Protection Type */
	BGP_LS_ATTR_MPLS_PROTOCOL_MASK = 1094,	  /* MPLS Protocol Mask */
	BGP_LS_ATTR_IGP_METRIC = 1095,		  /* IGP Metric */
	BGP_LS_ATTR_SRLG = 1096,		  /* Shared Risk Link Group */
	BGP_LS_ATTR_OPAQUE_LINK_ATTR = 1097,	  /* Opaque Link Attribute */
	BGP_LS_ATTR_LINK_NAME = 1098,		  /* Link Name */
	BGP_LS_ATTR_ADJ_SID = 1099,		  /* Adjacency SID */
	BGP_LS_ATTR_LAN_ADJ_SID = 1100,		  /* LAN Adjacency SID */
	BGP_LS_ATTR_PEER_NODE_SID = 1101,	  /* PeerNode SID */
	BGP_LS_ATTR_PEER_ADJ_SID = 1102,	  /* PeerAdj SID */
	BGP_LS_ATTR_PEER_SET_SID = 1103,	  /* PeerSet SID */
	BGP_LS_ATTR_LINK_MSD = 1104,		  /* Link MSD */
};

/* Prefix Attribute TLVs (RFC 9552 Section 4.3) */
enum bgp_ls_prefix_attr_tlv {
	BGP_LS_ATTR_IGP_FLAGS = 1152,	       /* IGP Flags */
	BGP_LS_ATTR_ROUTE_TAG = 1153,	       /* Route Tag */
	BGP_LS_ATTR_EXTENDED_TAG = 1154,       /* Extended Tag */
	BGP_LS_ATTR_PREFIX_METRIC = 1155,      /* Prefix Metric */
	BGP_LS_ATTR_OSPF_FWD_ADDR = 1156,      /* OSPF Forwarding Address */
	BGP_LS_ATTR_OPAQUE_PREFIX_ATTR = 1157, /* Opaque Prefix Attribute */
	BGP_LS_ATTR_PREFIX_SID = 1158,	       /* Prefix SID */
	BGP_LS_ATTR_RANGE = 1159,	       /* Range */
	BGP_LS_ATTR_SID_LABEL = 1161,	       /* SID/Label */
	BGP_LS_ATTR_PREFIX_ATTR_FLAGS = 1170,  /* Prefix Attribute Flags */
	BGP_LS_ATTR_SRV6_LOCATOR = 1162,       /* SRv6 Locator */
};

/*
 * ===========================================================================
 * Constants and Macros
 * ===========================================================================
 */

/*
 * TLV Presence Bitmask Macros
 * Used to track which optional TLVs are present in descriptors
 */
#define BGP_LS_TLV_SET(bitmap, bit)   ((bitmap) |= (1U << (bit)))
#define BGP_LS_TLV_CHECK(bitmap, bit) ((bitmap) & (1U << (bit)))
#define BGP_LS_TLV_UNSET(bitmap, bit) ((bitmap) &= ~(1U << (bit)))
#define BGP_LS_TLV_RESET(bitmap)      ((bitmap) = 0)

/* Bit positions for Node Descriptor TLVs */
#define BGP_LS_NODE_DESC_AS_BIT		0
#define BGP_LS_NODE_DESC_BGP_LS_ID_BIT	1
#define BGP_LS_NODE_DESC_OSPF_AREA_BIT	2
#define BGP_LS_NODE_DESC_IGP_ROUTER_BIT 3

/* Bit positions for Link Descriptor TLVs */
#define BGP_LS_LINK_DESC_LINK_ID_BIT	0
#define BGP_LS_LINK_DESC_IPV4_INTF_BIT	1
#define BGP_LS_LINK_DESC_IPV4_NEIGH_BIT 2
#define BGP_LS_LINK_DESC_IPV6_INTF_BIT	3
#define BGP_LS_LINK_DESC_IPV6_NEIGH_BIT 4
#define BGP_LS_LINK_DESC_MT_ID_BIT	5

/* Bit positions for Prefix Descriptor TLVs */
#define BGP_LS_PREFIX_DESC_MT_ID_BIT	  0
#define BGP_LS_PREFIX_DESC_OSPF_ROUTE_BIT 1
#define BGP_LS_PREFIX_DESC_IP_REACH_BIT	  2

/* Maximum number of MT-IDs per descriptor */
#define BGP_LS_MAX_MT_ID 16

/*
 * IGP Router-ID Length Constants (RFC 9552 Section 5.2.1.4)
 */
#define BGP_LS_IGP_ROUTER_ID_OSPF_LEN	     4 /* OSPFv2/v3 non-pseudonode: Router-ID */
#define BGP_LS_IGP_ROUTER_ID_ISIS_LEN	     6 /* IS-IS non-pseudonode: ISO System-ID */
#define BGP_LS_IGP_ROUTER_ID_ISIS_PSEUDO_LEN 7 /* IS-IS pseudonode: System-ID + PSN */
#define BGP_LS_IGP_ROUTER_ID_OSPF_PSEUDO_LEN 8 /* OSPFv2/v3 pseudonode: Router-ID + Interface ID */
#define BGP_LS_IGP_ROUTER_ID_DIRECT_IPV4_LEN IPV4_MAX_BYTELEN /* Direct/Static: IPv4 address */
#define BGP_LS_IGP_ROUTER_ID_DIRECT_IPV6_LEN IPV6_MAX_BYTELEN /* Direct/Static: IPv6 address */
#define BGP_LS_IGP_ROUTER_ID_MIN_SIZE	     BGP_LS_IGP_ROUTER_ID_OSPF_LEN /* Minimum size (4 bytes) */
#define BGP_LS_IGP_ROUTER_ID_MAX_SIZE                                                             \
	BGP_LS_IGP_ROUTER_ID_DIRECT_IPV6_LEN /* Maximum size (16 bytes) */

/*
 * TLV Size Constants (for wire format size calculation)
 */
#define BGP_LS_TLV_HDR_SIZE	4 /* TLV Type (2) + Length (2) */
#define BGP_LS_PROTOCOL_ID_SIZE 1 /* Protocol-ID field */
#define BGP_LS_IDENTIFIER_SIZE	8 /* Identifier field (Instance ID) */
#define BGP_LS_NLRI_HDR_SIZE                                                                      \
	(BGP_LS_PROTOCOL_ID_SIZE + BGP_LS_IDENTIFIER_SIZE) /* Protocol-ID + Identifier */
#define BGP_LS_NLRI_TYPE_SIZE	2			   /* NLRI Type field */
#define BGP_LS_NLRI_LENGTH_SIZE 2			   /* NLRI Length field */
/* Minimum NLRI length: Protocol-ID + Identifier + Node Descriptor TLV header + min descriptor */
#define BGP_LS_NLRI_MIN_LENGTH                                                                    \
	(BGP_LS_PROTOCOL_ID_SIZE + BGP_LS_IDENTIFIER_SIZE + BGP_LS_TLV_HDR_SIZE)
#define BGP_LS_AS_NUMBER_SIZE	    4		     /* AS Number value */
#define BGP_LS_BGP_LS_ID_SIZE	    4		     /* BGP-LS Identifier value */
#define BGP_LS_OSPF_AREA_ID_SIZE    4		     /* OSPF Area-ID value */
#define BGP_LS_LINK_ID_SIZE	    8		     /* Link Local ID (4) + Remote ID (4) */
#define BGP_LS_IPV4_ADDR_SIZE	    IPV4_MAX_BYTELEN /* IPv4 address */
#define BGP_LS_IPV6_ADDR_SIZE	    IPV6_MAX_BYTELEN /* IPv6 address */
#define BGP_LS_OSPF_ROUTE_TYPE_SIZE 1		     /* OSPF Route Type value */
#define BGP_LS_MT_ID_SIZE	    2		     /* Multi-Topology ID (per entry) */
#define BGP_LS_PREFIX_LEN_SIZE	    1		     /* IP prefix length field */

/*
 * IGP Metric can be 1, 2, or 3 bytes
 */
#define BGP_LS_IGP_METRIC_MAX_LEN 3

/*
 * Maximum values for arrays
 */
#define BGP_LS_MAX_SRLG	      64 /* Maximum SRLGs per link */
#define BGP_LS_MAX_UNRESV_BW  8	 /* 8 priority classes */
#define BGP_LS_MAX_ROUTE_TAGS 16 /* Maximum route tags */

/*
 * Bit positions for attribute presence bitmasks
 */

/* Node Attribute Bits */
#define BGP_LS_NODE_ATTR_NODE_FLAGS_BIT	     0
#define BGP_LS_NODE_ATTR_NODE_NAME_BIT	     1
#define BGP_LS_NODE_ATTR_ISIS_AREA_BIT	     2
#define BGP_LS_NODE_ATTR_IPV4_ROUTER_ID_BIT  3
#define BGP_LS_NODE_ATTR_IPV6_ROUTER_ID_BIT  4
#define BGP_LS_NODE_ATTR_SR_CAPABILITIES_BIT 5
#define BGP_LS_NODE_ATTR_SR_ALGORITHM_BIT    6
#define BGP_LS_NODE_ATTR_SR_LOCAL_BLOCK_BIT  7
#define BGP_LS_NODE_ATTR_NODE_MSD_BIT	     8

/* Link Attribute Bits */
#define BGP_LS_LINK_ATTR_IPV4_ROUTER_ID_LOCAL_BIT  0
#define BGP_LS_LINK_ATTR_IPV6_ROUTER_ID_LOCAL_BIT  1
#define BGP_LS_LINK_ATTR_IPV4_ROUTER_ID_REMOTE_BIT 2
#define BGP_LS_LINK_ATTR_IPV6_ROUTER_ID_REMOTE_BIT 3
#define BGP_LS_LINK_ATTR_ADMIN_GROUP_BIT	   4
#define BGP_LS_LINK_ATTR_MAX_LINK_BW_BIT	   5
#define BGP_LS_LINK_ATTR_MAX_RESV_BW_BIT	   6
#define BGP_LS_LINK_ATTR_UNRESV_BW_BIT		   7
#define BGP_LS_LINK_ATTR_TE_METRIC_BIT		   8
#define BGP_LS_LINK_ATTR_LINK_PROTECTION_BIT	   9
#define BGP_LS_LINK_ATTR_MPLS_PROTOCOL_BIT	   10
#define BGP_LS_LINK_ATTR_IGP_METRIC_BIT		   11
#define BGP_LS_LINK_ATTR_SRLG_BIT		   12
#define BGP_LS_LINK_ATTR_LINK_NAME_BIT		   13
#define BGP_LS_LINK_ATTR_ADJ_SID_BIT		   14
#define BGP_LS_LINK_ATTR_LINK_MSD_BIT		   15

/* Prefix Attribute Bits */
#define BGP_LS_PREFIX_ATTR_IGP_FLAGS_BIT     0
#define BGP_LS_PREFIX_ATTR_ROUTE_TAG_BIT     1
#define BGP_LS_PREFIX_ATTR_EXTENDED_TAG_BIT  2
#define BGP_LS_PREFIX_ATTR_PREFIX_METRIC_BIT 3
#define BGP_LS_PREFIX_ATTR_OSPF_FWD_ADDR_BIT 4
#define BGP_LS_PREFIX_ATTR_PREFIX_SID_BIT    5
#define BGP_LS_PREFIX_ATTR_RANGE_BIT	     6
#define BGP_LS_PREFIX_ATTR_SID_LABEL_BIT     7
#define BGP_LS_PREFIX_ATTR_SRV6_LOCATOR_BIT  8

/*
 * Node Flag Bits (TLV 1024)
 * RFC 9552 Section 4.3.1
 */
#define BGP_LS_NODE_FLAG_OVERLOAD 0x80 /* Overload Bit */
#define BGP_LS_NODE_FLAG_ATTACHED 0x40 /* Attached Bit */
#define BGP_LS_NODE_FLAG_EXTERNAL 0x20 /* External Bit */
#define BGP_LS_NODE_FLAG_ABR	  0x10 /* ABR Bit */
#define BGP_LS_NODE_FLAG_ROUTER	  0x08 /* Router Bit */
#define BGP_LS_NODE_FLAG_V6	  0x04 /* V6 Bit */

/*
 * IGP Prefix Flags (TLV 1152)
 * RFC 9552 Section 4.3.4.1
 */
#define BGP_LS_PREFIX_FLAG_DOWN	      0x80 /* IS-IS Down Bit */
#define BGP_LS_PREFIX_FLAG_NO_UNICAST 0x40 /* OSPF No-Unicast Bit */
#define BGP_LS_PREFIX_FLAG_LOCAL      0x20 /* OSPF Local Address Bit */
#define BGP_LS_PREFIX_FLAG_PROPAGATE  0x10 /* OSPF Propagate NSSA Bit */
#define BGP_LS_PREFIX_FLAG_NODE	      0x08 /* Node Prefix Attached Flag */

/*
 * ===========================================================================
 * Descriptor Structures (RFC 9552 Section 5.2)
 * ===========================================================================
 *
 * These structures identify topology elements (nodes, links, prefixes)
 * per RFC 9552 Section 5.2
 */

/*
 * Node Attributes (Type 29 TLVs for Node NLRI)
 * RFC 9552 Section 4.3.1
 */
struct bgp_ls_node_attr {
	uint32_t present_tlvs; /* Bitmask of present TLVs */

	/* Node Flag Bits (TLV 1024) */
	uint8_t node_flags;

	/* Node Name (TLV 1026) */
	char *node_name;

	/* IS-IS Area Identifier (TLV 1027) */
	uint8_t isis_area_id_len;
	uint8_t *isis_area_id;

	/* IPv4 Router-ID (TLV 1028) */
	struct in_addr ipv4_router_id;

	/* IPv6 Router-ID (TLV 1029) */
	struct in6_addr ipv6_router_id;

	/* Multi-Topology IDs (multiple TLVs, same as descriptor) */
	uint8_t mt_id_count;
	uint16_t *mt_id;

	/* Opaque Node Attribute (TLV 1025) */
	uint16_t opaque_len;
	uint8_t *opaque_data;
};

/*
 * Link Attributes (Type 29 TLVs for Link NLRI)
 * RFC 9552 Section 4.3.2
 */
struct bgp_ls_link_attr {
	uint32_t present_tlvs; /* Bitmask of present TLVs */

	/* IPv4/IPv6 Router-IDs (TLVs 1028-1031) */
	struct in_addr ipv4_router_id_local;
	struct in6_addr ipv6_router_id_local;
	struct in_addr ipv4_router_id_remote;
	struct in6_addr ipv6_router_id_remote;

	/* Administrative Group (TLV 1088) */
	uint32_t admin_group;

	/* Maximum Link Bandwidth (TLV 1089) - IEEE floating point */
	float max_link_bw;

	/* Maximum Reservable Bandwidth (TLV 1090) */
	float max_resv_bw;

	/* Unreserved Bandwidth (TLV 1091) - 8 priority levels */
	float unreserved_bw[BGP_LS_MAX_UNRESV_BW];

	/* TE Default Metric (TLV 1092) */
	uint32_t te_metric;

	/* Link Protection Type (TLV 1093) */
	uint16_t link_protection;

	/* MPLS Protocol Mask (TLV 1094) */
	uint8_t mpls_protocol_mask;

	/* IGP Metric (TLV 1095) - Variable length 1-3 bytes */
	uint8_t igp_metric_len;
	uint32_t igp_metric;

	/* Shared Risk Link Group (TLV 1096) */
	uint8_t srlg_count;
	uint32_t *srlg_values;

	/* Link Name (TLV 1098) */
	char *link_name;

	/* Opaque Link Attribute (TLV 1097) */
	uint16_t opaque_len;
	uint8_t *opaque_data;
};

/*
 * Prefix Attributes (Type 29 TLVs for Prefix NLRI)
 * RFC 9552 Section 4.3.4
 */
struct bgp_ls_prefix_attr {
	uint32_t present_tlvs; /* Bitmask of present TLVs */

	/* IGP Flags (TLV 1152) */
	uint8_t igp_flags;

	/* Route Tags (TLV 1153) */
	uint8_t route_tag_count;
	uint32_t *route_tags;

	/* Extended Tags (TLV 1154) */
	uint8_t extended_tag_count;
	uint64_t *extended_tags;

	/* Prefix Metric (TLV 1155) */
	uint32_t prefix_metric;

	/* OSPF Forwarding Address (TLV 1156) */
	struct in_addr ospf_fwd_addr;	/* IPv4 */
	struct in6_addr ospf_fwd_addr6; /* IPv6 */

	/* Opaque Prefix Attribute (TLV 1157) */
	uint16_t opaque_len;
	uint8_t *opaque_data;
};

/*
 * Node Descriptor - Identifies a router/node in the topology
 * RFC 9552, Section 5.2.1
 */
struct bgp_ls_node_descriptor {
	uint16_t present_tlvs;	   /* Bitmask of present TLVs */
	as_t asn;		   /* Autonomous System Number */
	uint32_t bgp_ls_id;	   /* BGP-LS Identifier (deprecated) */
	uint32_t ospf_area_id;	   /* OSPF Area ID */
	uint8_t igp_router_id_len; /* Length of IGP Router ID (4 or 8 bytes) */
	uint8_t igp_router_id[8];  /* IGP Router ID (ISIS or OSPF) */
};

/*
 * Link Descriptor - Identifies a link between two nodes
 * RFC 9552, Section 5.2.2
 */
struct bgp_ls_link_descriptor {
	uint16_t present_tlvs;		 /* Bitmask of present TLVs */
	uint32_t link_local_id;		 /* Link Local Identifier */
	uint32_t link_remote_id;	 /* Link Remote Identifier */
	struct in_addr ipv4_intf_addr;	 /* IPv4 Interface Address */
	struct in_addr ipv4_neigh_addr;	 /* IPv4 Neighbor Address */
	struct in6_addr ipv6_intf_addr;	 /* IPv6 Interface Address */
	struct in6_addr ipv6_neigh_addr; /* IPv6 Neighbor Address */
	uint8_t mt_id_count;		 /* Number of Multi-Topology IDs */
	uint16_t *mt_id;		 /* Multi-Topology IDs */
};

/*
 * Prefix Descriptor - Identifies an IP prefix advertised by a node
 * RFC 9552, Section 5.2.3
 */
struct bgp_ls_prefix_descriptor {
	uint16_t present_tlvs;			     /* Bitmask of present TLVs */
	uint8_t mt_id_count;			     /* Number of Multi-Topology IDs */
	uint16_t *mt_id;			     /* Multi-Topology IDs */
	enum bgp_ls_ospf_route_type ospf_route_type; /* OSPF Route Type */
	struct prefix prefix;			     /* IP prefix (IPv4 or IPv6) */
};

/*
 * ===========================================================================
 * BGP-LS NLRI Structures (RFC 9552 Section 5.2)
 * ===========================================================================
 *
 * These structures represent complete BGP-LS NLRIs as exchanged in UPDATE
 * messages. Each NLRI consists of:
 *   1. Protocol-ID - IGP protocol that originated the information
 *   2. Identifier - 64-bit instance identifier for disambiguation
 *   3. NLRI-specific descriptors that identify the topology element
 */

/*
 * Node NLRI (Type 1) - Identifies a router/node in the topology
 * RFC 9552, Section 5.2
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct bgp_ls_node_nlri {
	enum bgp_ls_protocol_id protocol_id;	  /* IGP protocol */
	uint64_t identifier;			  /* Instance identifier */
	struct bgp_ls_node_descriptor local_node; /* Node identity */
	struct bgp_ls_node_attr *attr;		  /* BGP-LS Attribute (Type 29) */
};

/*
 * Link NLRI (Type 2) - Identifies a link between two nodes
 * RFC 9552, Section 5.2
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Remote Node Descriptors (variable)            //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                  Link Descriptors (variable)                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct bgp_ls_link_nlri {
	enum bgp_ls_protocol_id protocol_id;	   /* IGP protocol */
	uint64_t identifier;			   /* Instance identifier */
	struct bgp_ls_node_descriptor local_node;  /* Source node */
	struct bgp_ls_node_descriptor remote_node; /* Destination node */
	struct bgp_ls_link_descriptor link_desc;   /* Link identity */
	struct bgp_ls_link_attr *attr;		   /* BGP-LS Attribute (Type 29) */
};

/*
 * Prefix NLRI (Type 3/4) - Identifies an IP prefix advertised by a node
 * RFC 9552, Section 5.2
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+
 * |  Protocol-ID  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Identifier                          |
 * |                            (64 bits)                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //               Local Node Descriptors (variable)             //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                Prefix Descriptors (variable)                //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Note: Same structure used for both IPv4 (Type 3) and IPv6 (Type 4)
 *       The prefix_desc.prefix.family field distinguishes between them
 */
struct bgp_ls_prefix_nlri {
	enum bgp_ls_protocol_id protocol_id;	     /* IGP protocol */
	uint64_t identifier;			     /* Instance identifier */
	struct bgp_ls_node_descriptor local_node;    /* Advertising node */
	struct bgp_ls_prefix_descriptor prefix_desc; /* Prefix identity */
	struct bgp_ls_prefix_attr *attr;	     /* BGP-LS Attribute (Type 29) */
};

/*
 * Top-level BGP-LS NLRI structure (RFC 9552 Section 5.2)
 *
 * BGP-LS NLRI encoding in UPDATE message:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * //                   NLRI Value (variable)                     //
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Where:
 *   Type   = NLRI Type (1=Node, 2=Link, 3=IPv4 Prefix, 4=IPv6 Prefix)
 *   Length = Length of NLRI Value in octets
 *   Value  = Type-specific NLRI data (see struct bgp_ls_*_nlri)
 *
 * This structure represents the decoded NLRI after parsing the wire format.
 */
struct bgp_ls_nlri {
	enum bgp_ls_nlri_type nlri_type; /* Discriminator */
	union {
		struct bgp_ls_node_nlri node;	  /* Node NLRI (Type 1) */
		struct bgp_ls_link_nlri link;	  /* Link NLRI (Type 2) */
		struct bgp_ls_prefix_nlri prefix; /* Prefix NLRI (Type 3/4) */
	} nlri_data;
};

#endif /* _FRR_BGP_LS_NLRI_H */
