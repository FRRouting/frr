// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State TLV Serializer/Deserializer header
 * Copyright 2023 6WIND S.A.
 */

#ifndef BGP_LINKSTATE_TLV_H
#define BGP_LINKSTATE_TLV_H

#include "openbsd-tree.h"
#include "prefix.h"

DECLARE_MTYPE(BGP_SUBTLV);

/* RFC7752 Link-State NLRI Protocol-ID values
 *	+-------------+----------------------------------+
 *	| Protocol-ID | NLRI information source protocol |
 *	+-------------+----------------------------------+
 *	|      1      | IS-IS Level 1                    |
 *	|      2      | IS-IS Level 2                    |
 *	|      3      | OSPFv2                           |
 *	|      4      | Direct                           |
 *	|      5      | Static configuration             |
 *	|      6      | OSPFv3                           |
 *	+-------------+----------------------------------+
 */

enum bgp_ls_nlri_proto {
	BGP_LS_NLRI_PROTO_ID_UNKNOWN = 0,
	BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_1 = 1,
	BGP_LS_NLRI_PROTO_ID_IS_IS_LEVEL_2 = 2,
	BGP_LS_NLRI_PROTO_ID_OSPF = 3,
	BGP_LS_NLRI_PROTO_ID_DIRECT = 4,
	BGP_LS_NLRI_PROTO_ID_STATIC = 5,
	BGP_LS_NLRI_PROTO_ID_OSPFv3 = 6,
};

/*
 * List of BGP Link-State TLVs extracted from
 * https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv
 *
 * Retrieved on 2023-01-03
 *
 * The following bash command was used to convert the list:
 * sed -e 's| (.\+)||g' tmp \
 *     | awk -F'\t' '($1 ~ /^[0-9]+$/) {gsub(/(\/|-| |\.)/,"_",$2); printf
 * "\tBGP_LS_TLV_"toupper($2)" = "$1", \/\* "$4" \*\/\n"}' \
 *     | grep -v UNASSIGNED \
 *     | sed -e 's/\[//g;s/\]//g'
 *
 */

enum bgp_linkstate_tlv {
	BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS = 256,  /* RFC7752, Section 3.2.1.2 */
	BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS = 257, /* RFC7752, Section 3.2.1.3 */
	BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS =
		258,				 /* RFC5307, Section 1.1 */
	BGP_LS_TLV_IPV4_INTERFACE_ADDRESS = 259, /* RFC5305, Section 3.2 */
	BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS = 260,  /* RFC5305, Section 3.3 */
	BGP_LS_TLV_IPV6_INTERFACE_ADDRESS = 261, /* RFC6119, Section 4.2 */
	BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS = 262,  /* RFC6119, Section 4.3 */
	BGP_LS_TLV_MULTI_TOPOLOGY_ID = 263,      /* RFC7752, Section 3.2.1.5 */
	BGP_LS_TLV_OSPF_ROUTE_TYPE = 264,	/* RFC7752, Section 3.2.3 */
	BGP_LS_TLV_IP_REACHABILITY_INFORMATION =
		265,			    /* RFC7752, Section 3.2.3 */
	BGP_LS_TLV_NODE_MSD = 266,	  /* RFC8814 */
	BGP_LS_TLV_LINK_MSD = 267,	  /* RFC8814 */
	BGP_LS_TLV_AUTONOMOUS_SYSTEM = 512, /* RFC7752, Section 3.2.1.4 */
	BGP_LS_TLV_BGP_LS_IDENTIFIER = 513, /* RFC7752, Section 3.2.1.4 */
	BGP_LS_TLV_OSPF_AREA_ID = 514,      /* RFC7752, Section 3.2.1.4 */
	BGP_LS_TLV_IGP_ROUTER_ID = 515,     /* RFC7752, Section 3.2.1.4 */
	BGP_LS_TLV_BGP_ROUTER_ID = 516,     /* RFC9086 */
	BGP_LS_TLV_BGP_CONFEDERATION_MEMBER = 517, /* RFC9086 */
	BGP_LS_TLV_SRV6_SID_INFORMATION_TLV =
		518, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_TUNNEL_ID_TLV =
		550,		     /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_LSP_ID_TLV = 551, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_IPV4_6_TUNNEL_HEAD_END_ADDRESS_TLV =
		552, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_IPV4_6_TUNNEL_TAIL_END_ADDRESS_TLV =
		553, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_POLICY_CP_DESCRIPTOR_TLV =
		554, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_MPLS_LOCAL_CROSS_CONNECT_TLV =
		555, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_MPLS_CROSS_CONNECT_INTERFACE_TLV =
		556, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_MPLS_CROSS_CONNECT_FEC_TLV =
		557, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_NODE_FLAG_BITS = 1024,	/* RFC7752, Section 3.3.1.1 */
	BGP_LS_TLV_OPAQUE_NODE_ATTRIBUTE = 1025, /* RFC7752, Section 3.3.1.5 */
	BGP_LS_TLV_NODE_NAME = 1026,		 /* RFC7752, Section 3.3.1.3 */
	BGP_LS_TLV_IS_IS_AREA_IDENTIFIER = 1027, /* RFC7752, Section 3.3.1.2 */
	BGP_LS_TLV_IPV4_ROUTER_ID_OF_LOCAL_NODE =
		1028, /* RFC5305, Section 4.3 */
	BGP_LS_TLV_IPV6_ROUTER_ID_OF_LOCAL_NODE =
		1029, /* RFC6119, Section 4.1 */
	BGP_LS_TLV_IPV4_ROUTER_ID_OF_REMOTE_NODE =
		1030, /* RFC5305, Section 4.3 */
	BGP_LS_TLV_IPV6_ROUTER_ID_OF_REMOTE_NODE =
		1031,				/* RFC6119, Section 4.1 */
	BGP_LS_TLV_S_BFD_DISCRIMINATORS = 1032, /* RFC9247 */
	BGP_LS_TLV_UNASSIGNED = 1033,		/*  */
	BGP_LS_TLV_SR_CAPABILITIES = 1034,      /* RFC9085, Section 2.1.2 */
	BGP_LS_TLV_SR_ALGORITHM = 1035,		/* RFC9085, Section 2.1.3 */
	BGP_LS_TLV_SR_LOCAL_BLOCK = 1036,       /* RFC9085, Section 2.1.4 */
	BGP_LS_TLV_SRMS_PREFERENCE = 1037,      /* RFC9085, Section 2.1.5 */
	BGP_LS_TLV_SRV6_CAPABILITIES_TLV =
		1038, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION =
		1039, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_ANY_AFFINITY =
		1040, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ANY_AFFINITY =
		1041, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_INCLUDE_ALL_AFFINITY =
		1042, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_DEFINITION_FLAGS =
		1043, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_PREFIX_METRIC =
		1044, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_EXCLUDE_SRLG =
		1045, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_FLEXIBLE_ALGORITHM_UNSUPPORTED =
		1046, /* RFC-ietf-idr-bgp-ls-flex-algo-12 */
	BGP_LS_TLV_ADMINISTRATIVE_GROUP = 1088,   /* RFC5305, Section 3.1 */
	BGP_LS_TLV_MAXIMUM_LINK_BANDWIDTH = 1089, /* RFC5305, Section 3.4 */
	BGP_LS_TLV_MAX_RESERVABLE_LINK_BANDWIDTH =
		1090,				  /* RFC5305, Section 3.5 */
	BGP_LS_TLV_UNRESERVED_BANDWIDTH = 1091,   /* RFC5305, Section 3.6 */
	BGP_LS_TLV_TE_DEFAULT_METRIC = 1092,      /* RFC7752, Section 3.3.2.3 */
	BGP_LS_TLV_LINK_PROTECTION_TYPE = 1093,   /* RFC5307, Section 1.2 */
	BGP_LS_TLV_MPLS_PROTOCOL_MASK = 1094,     /* RFC7752, Section 3.3.2.2 */
	BGP_LS_TLV_IGP_METRIC = 1095,		  /* RFC7752, Section 3.3.2.4 */
	BGP_LS_TLV_SHARED_RISK_LINK_GROUP = 1096, /* RFC7752, Section 3.3.2.5 */
	BGP_LS_TLV_OPAQUE_LINK_ATTRIBUTE = 1097,  /* RFC7752, Section 3.3.2.6 */
	BGP_LS_TLV_LINK_NAME = 1098,		  /* RFC7752, Section 3.3.2.7 */
	BGP_LS_TLV_ADJACENCY_SID = 1099,	  /* RFC9085, Section 2.2.1 */
	BGP_LS_TLV_LAN_ADJACENCY_SID = 1100,      /* RFC9085, Section 2.2.2 */
	BGP_LS_TLV_PEERNODE_SID = 1101,		  /* RFC9086 */
	BGP_LS_TLV_PEERADJ_SID = 1102,		  /* RFC9086 */
	BGP_LS_TLV_PEERSET_SID = 1103,		  /* RFC9086 */
	BGP_LS_TLV_RTM_CAPABILITY = 1105,	 /* RFC8169 */
	BGP_LS_TLV_SRV6_END_X_SID_TLV =
		1106, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_IS_IS_SRV6_LAN_END_X_SID_TLV =
		1107, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_OSPFV3_SRV6_LAN_END_X_SID_TLV =
		1108, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_UNIDIRECTIONAL_LINK_DELAY = 1114,		/* RFC8571 */
	BGP_LS_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY = 1115,    /* RFC8571 */
	BGP_LS_TLV_UNIDIRECTIONAL_DELAY_VARIATION = 1116,       /* RFC8571 */
	BGP_LS_TLV_UNIDIRECTIONAL_LINK_LOSS = 1117,		/* RFC8571 */
	BGP_LS_TLV_UNIDIRECTIONAL_RESIDUAL_BANDWIDTH = 1118,    /* RFC8571 */
	BGP_LS_TLV_UNIDIRECTIONAL_AVAILABLE_BANDWIDTH = 1119,   /* RFC8571 */
	BGP_LS_TLV_UNIDIRECTIONAL_UTILIZED_BANDWIDTH = 1120,    /* RFC8571 */
	BGP_LS_TLV_GRACEFUL_LINK_SHUTDOWN_TLV = 1121,		/* RFC8379 */
	BGP_LS_TLV_APPLICATION_SPECIFIC_LINK_ATTRIBUTES = 1122, /* RFC9294 */
	BGP_LS_TLV_IGP_FLAGS = 1152,		  /* RFC7752, Section 3.3.3.1 */
	BGP_LS_TLV_IGP_ROUTE_TAG = 1153,	  /* RFC5130 */
	BGP_LS_TLV_IGP_EXTENDED_ROUTE_TAG = 1154, /* RFC5130 */
	BGP_LS_TLV_PREFIX_METRIC = 1155,	  /* RFC5305 */
	BGP_LS_TLV_OSPF_FORWARDING_ADDRESS = 1156, /* RFC2328 */
	BGP_LS_TLV_OPAQUE_PREFIX_ATTRIBUTE =
		1157,		      /* RFC7752, Section 3.3.3.6 */
	BGP_LS_TLV_PREFIX_SID = 1158, /* RFC9085, Section 2.3.1 */
	BGP_LS_TLV_RANGE = 1159,      /* RFC9085, Section 2.3.5 */
	BGP_LS_TLV_IS_IS_FLOOD_REFLECTION =
		1160, /* draft-ietf-idr-bgp-ls-isis-flood-reflection-02 */
	BGP_LS_TLV_SID_LABEL = 1161, /* RFC9085, Section 2.1.1 */
	BGP_LS_TLV_SRV6_LOCATOR_TLV =
		1162, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_PREFIX_ATTRIBUTES_FLAGS = 1170,  /* RFC9085, Section 2.3.2 */
	BGP_LS_TLV_SOURCE_ROUTER_IDENTIFIER = 1171, /* RFC9085, Section 2.3.3 */
	BGP_LS_TLV_L2_BUNDLE_MEMBER_ATTRIBUTES =
		1172, /* RFC9085, Section 2.2.3 */
	BGP_LS_TLV_EXTENDED_ADMINISTRATIVE_GROUP = 1173, /* RFC9104 */
	BGP_LS_TLV_SOURCE_OSPF_ROUTER_ID = 1174, /* RFC9085, Section 2.3.4 */
	BGP_LS_TLV_MPLS_TE_POLICY_STATE_TLV =
		1200, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_BSID_TLV =
		1201, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_CP_STATE_TLV =
		1202, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_CP_NAME_TLV =
		1203, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_CP_CONSTRAINTS_TLV =
		1204, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_SEGMENT_LIST_TLV =
		1205, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_SEGMENT_SUB_TLV =
		1206, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_SEGMENT_LIST_METRIC_SUB_TLV =
		1207, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_AFFINITY_CONSTRAINT_SUB_TLV =
		1208, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_SRLG_CONSTRAINT_SUB_TLV =
		1209, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_BANDWIDTH_CONSTRAINT_SUB_TLV =
		1210, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_DISJOINT_GROUP_CONSTRAINT_SUB_TLV =
		1211, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SRV6_BSID_TLV =
		1212, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SR_POLICY_NAME_TLV =
		1213, /* draft-ietf-idr-te-lsp-distribution-17 */
	BGP_LS_TLV_SRV6_ENDPOINT_FUNCTION_TLV =
		1250, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_SRV6_BGP_PEER_NODE_SID_TLV =
		1251, /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_SRV6_SID_STRUCTURE_TLV =
		1252,	  /* draft-ietf-idr-bgpls-srv6-ext-08 */
	BGP_LS_TLV_MAX = 1253, /* max TLV value for table size*/
};

struct bgp_ls_tlv_generic {
	uint16_t length;
	uint8_t data[];
};

enum bgp_ls_nlri_node_descr_ig_router_id_size {
	BGP_LS_TLV_IGP_ROUTER_ID_ISIS_NON_PSEUDOWIRE_SIZE = 6,
	BGP_LS_TLV_IGP_ROUTER_ID_ISIS_PSEUDOWIRE_SIZE = 7,
	BGP_LS_TLV_IGP_ROUTER_ID_OSPF_NON_PSEUDOWIRE_SIZE = 4,
	BGP_LS_TLV_IGP_ROUTER_ID_OSPF_PSEUDOWIRE_SIZE = 8,
};

/* local or remote node */
#define BGP_NLRI_TLV_NODE_DESCR_LOCAL_NODE 0x01
#define BGP_NLRI_TLV_NODE_DESCR_REMOTE_NODE 0x02
/* presence of TLV */
#define BGP_NLRI_TLV_NODE_DESCR_AUTONOMOUS_SYSTEM 0x04
#define BGP_NLRI_TLV_NODE_DESCR_BGP_LS_ID 0x08
#define BGP_NLRI_TLV_NODE_DESCR_AREA_ID 0x10
#define BGP_NLRI_TLV_NODE_DESCR_IGP_ROUTER_ID 0x20

struct bgp_ls_nlri_node_descr_tlv {
	/* flags bits determine:
	 * - the type of node: local or remote
	 * - the presence of TLVs
	 */
	uint8_t flags;

	/* value of enum bgp_ls_nlri_node_descr_ig_router_id_size
	 * Use uint8_t instead of enum to save space in struct
	 */
	uint8_t igp_router_id_size;
	uint32_t autonomous_system;
	uint32_t bgp_ls_id;
	uint32_t area_id;
	uint64_t igp_router_id;
};

#define BGP_NLRI_TLV_LINK_DESCR_MT_ID 0x01
#define BGP_NLRI_TLV_LINK_DESCR_LOCAL_REMOTE_ID 0x02
#define BGP_NLRI_TLV_LINK_DESCR_INTERFACE4 0x04
#define BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR4 0x08
#define BGP_NLRI_TLV_LINK_DESCR_INTERFACE6 0x10
#define BGP_NLRI_TLV_LINK_DESCR_NEIGHBOR6 0x20


struct bgp_ls_nlri_link_descr_tlv {
	uint8_t flags;

	uint16_t local_remote_id;
	struct in_addr interface4;
	struct in_addr neighbor4;
	struct in6_addr interface6;
	struct in6_addr neighbor6;
	struct bgp_ls_tlv_generic mtid;
};

#define BGP_NLRI_TLV_PREFIX_DESCR_MT_ID 0x01
#define BGP_NLRI_TLV_PREFIX_DESCR_OSPF_ROUTE_TYPE 0x02
#define BGP_NLRI_TLV_PREFIX_DESCR_IP_REACHABILITY 0x04

struct bgp_ls_nlri_prefix4_descr_tlv {
	uint8_t flags;

	uint8_t ospf_route_type;
	struct in_addr ip_reachability_prefix;
	uint8_t ip_reachability_prefixlen;
	struct bgp_ls_tlv_generic mtid;
};

struct bgp_ls_nlri_prefix6_descr_tlv {
	uint8_t flags;

	uint8_t ospf_route_type;
	struct in6_addr ip_reachability_prefix;
	uint8_t ip_reachability_prefixlen;
	struct bgp_ls_tlv_generic mtid;
};


/*
 * RFC7752 section 3.2
 *
 * +------+---------------------------+
 * | Type | NLRI Type                 |
 * +------+---------------------------+
 * |  1   | Node NLRI                 |
 * |  2   | Link NLRI                 |
 * |  3   | IPv4 Topology Prefix NLRI |
 * |  4   | IPv6 Topology Prefix NLRI |
 * +------+---------------------------+
 */

struct bgp_linkstate_type_node {
	enum bgp_ls_nlri_proto proto;
	uint64_t identifier;
	struct bgp_ls_nlri_node_descr_tlv local_node_descr;
};

struct bgp_linkstate_type_link {
	enum bgp_ls_nlri_proto proto;
	uint64_t identifier;
	struct bgp_ls_nlri_node_descr_tlv local_node_descr;
	struct bgp_ls_nlri_node_descr_tlv remote_node_descr;
	struct bgp_ls_nlri_link_descr_tlv link_descr;
};

struct bgp_linkstate_type_prefix4 {
	enum bgp_ls_nlri_proto proto;
	uint64_t identifier;
	struct bgp_ls_nlri_node_descr_tlv local_node_descr;
	struct bgp_ls_nlri_prefix4_descr_tlv prefix_descr;
};

struct bgp_linkstate_type_prefix6 {
	enum bgp_ls_nlri_proto proto;
	uint64_t identifier;
	struct bgp_ls_nlri_node_descr_tlv local_node_descr;
	struct bgp_ls_nlri_prefix6_descr_tlv prefix_descr;
};

extern int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
				    struct bgp_nlri *packet, int withdraw);
extern char *bgp_linkstate_nlri_prefix_display(char *buf, size_t size,
					       uint16_t nlri_type,
					       void *prefix);
extern void bgp_linkstate_nlri_prefix_json(json_object *json,
					   uint16_t nlri_type, void *prefix);
extern void bgp_nlri_encode_linkstate(struct stream *s, const struct prefix *p);

#endif /* BGP_LINKSTATE_TLV_H */
