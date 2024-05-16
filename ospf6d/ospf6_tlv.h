// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 Type Length Value.
 *
 */

#ifndef OSPF6_TLV_H
#define OSPF6_TLV_H

/*
 * Generic TLV (type, length, value) macros
 */
struct tlv_header {
	uint16_t type;	 /* Type of Value */
	uint16_t length; /* Length of Value portion only, in bytes */
};

#ifdef roundup
#define ROUNDUP(val, gran) roundup(val, gran)
#else /* roundup */
#define ROUNDUP(val, gran) (((val)-1 | (gran)-1) + 1)
#endif /* roundup */

#define TLV_HDR_SIZE (sizeof(struct tlv_header))

#define TLV_BODY_SIZE(tlvh) (ROUNDUP(ntohs((tlvh)->length), sizeof(uint32_t)))

#define TLV_SIZE(tlvh) ((uint32_t)(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh)))

#define TLV_HDR_NEXT(tlvh)                                                     \
	((struct tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh)))

/*
 * RFC 5187 - OSPFv3 Graceful Restart - Grace-LSA
 * Graceful restart predates Extended-LSA TLVs and IANA TLV register.
 */
/* Grace period TLV. */
#define TLV_GRACE_PERIOD_TYPE 1
#define TLV_GRACE_PERIOD_LENGTH 4
struct tlv_grace_period {
	struct tlv_header header;
	uint32_t interval;
};

/* Restart reason TLV. */
#define TLV_GRACE_RESTART_REASON_TYPE 2
#define TLV_GRACE_RESTART_REASON_LENGTH 1
struct tlv_grace_restart_reason {
	struct tlv_header header;
	uint8_t reason;
	uint8_t reserved[3];
};


/*
 * OSPFv3 Extended-LSA TLV Types
 *
 * Ref:
 * Internet Assigned Numbers Authority
 * Open Shortest Path First v3 (OSPFv3) Parameters
 * https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml
 *
 * RFC 8362 - OSPFv3 Link State Advertisement (LSA) Extensibility
 */

#define TLV_ROUTER_LINK_TYPE 1
#define TLV_ROUTER_LINK_LENGTH 16U /* plus Sub-TLVs */
/* fields correspond to struct ospf6_router_lsdesc - RFC 8362 3.2 */
struct tlv_router_link {
	struct tlv_header header;
	uint8_t type;
	uint8_t reserved;
	uint16_t metric; /* output cost */
	uint32_t interface_id;
	uint32_t neighbor_interface_id;
	in_addr_t neighbor_router_id;
};

#define TLV_ATTACHED_ROUTERS_TYPE 2
#define TLV_ATTACHED_ROUTERS_LENGTH 4U /* times adjacent neighbors */
/* fields correspond to struct ospf6_network_lsdesc - RFC 8362 3.3 */
struct tlv_attached_routers {
	struct tlv_header header;
	in_addr_t router_id;
};

#define TLV_INTER_AREA_PREFIX_TYPE 3
#define TLV_INTER_AREA_PREFIX_MIN_LENGTH 4U /* plus prefix, plus Sub-TLVs */
struct tlv_inter_area_prefix {
	struct tlv_header header;
	uint32_t metric; /* of which 8bits must be zero */
	/* followed by ospf6 prefix */
};

#define TLV_INTER_AREA_ROUTER_TYPE 4
#define TLV_INTER_AREA_ROUTER_LENGTH 12U /* plus Sub-TLVs */
struct tlv_inter_area_router {
	struct tlv_header header;
	uint8_t mbz;
	uint8_t options[3];
	uint32_t metric; /* of which 8 bits must be zero */
	uint32_t router_id;
};

#define TLV_EXTERNAL_PREFIX_TYPE 5
#define TLV_EXTERNAL_PREFIX_MIN_LENGTH 4U /* plus Prefix, plus Sub-TLVs */
struct tlv_external_prefix {
	struct tlv_header header;
	uint32_t bits_metric; /* FIXME: first 8 bits unclear in RFC 8362. */
	/* followed by ospf6 prefix */
};

#define TLV_INTRA_AREA_PREFIX_TYPE 6
#define TLV_INTRA_AREA_PREFIX_MIN_LENGTH 4U /* plus Prefix, plus Sub-TLVs */
struct tlv_intra_area_prefix {
	struct tlv_header header;
	uint32_t metric; /* of which 8bits must be zero */
	/* followed by ospf6 prefix */
};

#define TLV_IPV6_LINK_LOCAL_ADDRESS_TYPE 7
#define TLV_IPV6_LINK_LOCAL_ADDRESS_LENGTH 16U /* plus Sub-TLVs */
struct tlv_ipv6_link_local_address {
	struct tlv_header header;
	struct in6_addr addr;
};

#define TLV_IPV4_LINK_LOCAL_ADDRESS_TYPE 8
#define TLV_IPV4_LINK_LOCAL_ADDRESS_LENGTH 4U /* plus Sub-TLVs */
struct tlv_ipv4_link_local_address {
	struct tlv_header header;
	struct in_addr addr;
};

enum ospf6_extended_lsa_tlv_types {
	OSPF6_TLV_RESERVED = 0,
	OSPF6_TLV_ROUTER_LINK = TLV_ROUTER_LINK_TYPE,
	OSPF6_TLV_ATTACHED_ROUTERS = TLV_ATTACHED_ROUTERS_TYPE,
	OSPF6_TLV_INTER_AREA_PREFIX = TLV_INTER_AREA_PREFIX_TYPE,
	OSPF6_TLV_INTER_AREA_ROUTER = TLV_INTER_AREA_ROUTER_TYPE,
	OSPF6_TLV_EXTERNAL_PREFIX = TLV_EXTERNAL_PREFIX_TYPE,
	OSPF6_TLV_INTRA_AREA_PREFIX = TLV_INTRA_AREA_PREFIX_TYPE,
	OSPF6_TLV_IPV6_LL_ADDR = TLV_IPV6_LINK_LOCAL_ADDRESS_TYPE,
	OSPF6_TLV_IPV4_LL_ADDR = TLV_IPV4_LINK_LOCAL_ADDRESS_TYPE,
	/*
	 * when adding new TLVs,
	 * also update tlv_min_size_map[OSPF6_TLV_ENUM_END]
	 */
	OSPF6_TLV_ENUM_END
};

/*
 * OSPFv3 Extended-LSA Sub-TLV Types
 *
 * Ref:
 * Internet Assigned Numbers Authority
 * Open Shortest Path First v3 (OSPFv3) Parameters
 * https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#extended-lsa-sub-tlvs
 *
 * RFC 8362 - OSPFv3 Link State Advertisement (LSA) Extensibility
 */
enum ospf6_extended_lsa_stlv_types {
	OSPF6_STLV_RESERVED = 0,
	OSPF6_STLV_IPV6_FWD_ADDR = 1,
	OSPF6_STLV_IPV4_FWD_ADDR = 2,
	OSPF6_STLV_ROUTE_TAG = 3,
	OSPF6_STLV_PREFIX_SID = 4, /* RFC 8666 */
	OSPF6_STLV_ADJ_SID = 5,
	OSPF6_STLV_LAN_ADJ_SID = 6,
	OSPF6_STLV_SID_LBL = 7,
	OSPF6_STLV_GRACEFUL_LINK_SHUTDOWN = 8,
	OSPF6_STLV_LINK_MSD = 9,
	OSPF6_STLV_LINK_ATTRS = 10,
	OSPF6_STLV_APP_LINK_ATTRS = 11, /* RFC 9492 */
	OSPF6_STLV_SHARED_RISK_LINK_GROUP = 12,
	OSPF6_STLV_UNIDIRECT_LINK_DELAY = 13,
	OSPF6_STLV_UNIDIRECT_MINMAX_LINK_DELAY = 14,
	OSPF6_STLV_UNIDIRECT_DELAY_VARIATION = 15,
	OSPF6_STLV_UNIDIRECT_LOSS = 16,
	OSPF6_STLV_UNIDIRECT_RESID_BW = 17,
	OSPF6_STLV_UNIDIRECT_AVAIL_BW = 18,
	OSPF6_STLV_UNIDIRECT_USED_BW = 19,
	OSPF6_STLV_ADMIN_GROUP = 20,
	OSPF6_STLV_ADMIN_GROUP_EXT = 21,
	OSPF6_STLV_TE_METRIC = 22,
	OSPF6_STLV_MAX_BW = 23,
	OSPF6_STLV_LOCAL_IPV6_ADDR = 24,
	OSPF6_STLV_REMOTE_IPV6_ADDR = 25,
	OSPF6_STLV_FLEX_ALG_PREFIX_METRIC = 26,	      /* RFC 9350 */
	OSPF6_STLV_PREFIX_SOURCE_OSPF_ROUTER_ID = 27, /* RFC 9084 */
	OSPF6_STLV_PREFIX_SOURCE_ROUTER_ADDR = 28,
	OSPF6_STLV_L2_BUNDLE_MEMBER_ATTRS = 29, /* RFC 9356 */
	OSPF6_STLV_SRV6_SID_STRUCTURE = 30,	/* RFC 9513 */
	OSPF6_STLV_SRV6_ENDX_SID = 31,
	OSPF6_STLV_SRV6_LAN_ENDX_SID = 32,
	OSPF6_STLV_FLEX_ALG_ASBR_METRIC = 33,
	OSPF6_STLV_GENERIC_METRIC = 34,
	OSPF6_STLV_IP_ALG_PREFIX_REACH = 35, /* RFC 9502 */
	OSPF6_STLV_IP_FLEX_ALG_ASBR_METRIC = 36
};


#endif /* OSPF6_TLV_H */
