/*
 * IS-IS TLV Serializer/Deserializer
 *
 * Copyright (C) 2015,2017 Christian Franke

 * Copyright (C) 2019 Olivier Dugeon - Orange Labs (for TE and SR)
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef ISIS_TLVS_H
#define ISIS_TLVS_H

#include "openbsd-tree.h"
#include "prefix.h"

DECLARE_MTYPE(ISIS_SUBTLV)

struct lspdb_head;
struct isis_subtlvs;
struct sr_prefix_cfg;

struct isis_area_address;
struct isis_area_address {
	struct isis_area_address *next;

	uint8_t addr[20];
	uint8_t len;
};

struct isis_oldstyle_reach;
struct isis_oldstyle_reach {
	struct isis_oldstyle_reach *next;

	uint8_t id[7];
	uint8_t metric;
};

struct isis_oldstyle_ip_reach;
struct isis_oldstyle_ip_reach {
	struct isis_oldstyle_ip_reach *next;

	uint8_t metric;
	struct prefix_ipv4 prefix;
};

struct isis_lsp_entry;
struct isis_lsp_entry {
	struct isis_lsp_entry *next;

	uint16_t rem_lifetime;
	uint8_t id[8];
	uint16_t checksum;
	uint32_t seqno;

	struct isis_lsp *lsp;
};

struct isis_extended_reach;
struct isis_ext_subtlvs;
struct isis_extended_reach {
	struct isis_extended_reach *next;

	uint8_t id[7];
	uint32_t metric;

	struct isis_ext_subtlvs *subtlvs;
};

struct isis_extended_ip_reach;
struct isis_extended_ip_reach {
	struct isis_extended_ip_reach *next;

	uint32_t metric;
	bool down;
	struct prefix_ipv4 prefix;

	struct isis_subtlvs *subtlvs;
};

struct isis_ipv6_reach;
struct isis_ipv6_reach {
	struct isis_ipv6_reach *next;

	uint32_t metric;
	bool down;
	bool external;

	struct prefix_ipv6 prefix;

	struct isis_subtlvs *subtlvs;
};

struct isis_protocols_supported {
	uint8_t count;
	uint8_t *protocols;
};

#define ISIS_TIER_UNDEFINED 15

struct isis_spine_leaf {
	uint8_t tier;

	bool has_tier;
	bool is_leaf;
	bool is_spine;
	bool is_backup;
};

enum isis_threeway_state {
	ISIS_THREEWAY_DOWN = 2,
	ISIS_THREEWAY_INITIALIZING = 1,
	ISIS_THREEWAY_UP = 0
};

struct isis_threeway_adj {
	enum isis_threeway_state state;
	uint32_t local_circuit_id;
	bool neighbor_set;
	uint8_t neighbor_id[6];
	uint32_t neighbor_circuit_id;
};

/*
 * Segment Routing subTLV's as per
 * draft-ietf-isis-segment-routing-extension-25
 */
#define ISIS_SUBTLV_SRGB_FLAG_I		0x80
#define ISIS_SUBTLV_SRGB_FLAG_V		0x40
#define IS_SR_IPV4(srgb)               (srgb.flags & ISIS_SUBTLV_SRGB_FLAG_I)
#define IS_SR_IPV6(srgb)               (srgb.flags & ISIS_SUBTLV_SRGB_FLAG_V)

/* Structure aggregating SRGB info */
struct isis_srgb {
	uint8_t flags;
	uint32_t range_size;
	uint32_t lower_bound;
};

/* Prefix-SID sub-TLVs flags */
#define ISIS_PREFIX_SID_READVERTISED  0x80
#define ISIS_PREFIX_SID_NODE          0x40
#define ISIS_PREFIX_SID_NO_PHP        0x20
#define ISIS_PREFIX_SID_EXPLICIT_NULL 0x10
#define ISIS_PREFIX_SID_VALUE         0x08
#define ISIS_PREFIX_SID_LOCAL         0x04

struct isis_prefix_sid;
struct isis_prefix_sid {
	struct isis_prefix_sid *next;

	uint8_t flags;
	uint8_t algorithm;
	uint32_t value;
};

/* Adj-SID and LAN-Ajd-SID sub-TLVs flags */
#define EXT_SUBTLV_LINK_ADJ_SID_FFLG	0x80
#define EXT_SUBTLV_LINK_ADJ_SID_BFLG	0x40
#define EXT_SUBTLV_LINK_ADJ_SID_VFLG	0x20
#define EXT_SUBTLV_LINK_ADJ_SID_LFLG	0x10
#define EXT_SUBTLV_LINK_ADJ_SID_SFLG	0x08
#define EXT_SUBTLV_LINK_ADJ_SID_PFLG	0x04

struct isis_adj_sid;
struct isis_adj_sid {
	struct isis_adj_sid *next;

	uint8_t family;
	uint8_t flags;
	uint8_t weight;
	uint32_t sid;
};

struct isis_lan_adj_sid;
struct isis_lan_adj_sid {
	struct isis_lan_adj_sid *next;

	uint8_t family;
	uint8_t flags;
	uint8_t weight;
	uint8_t neighbor_id[ISIS_SYS_ID_LEN];
	uint32_t sid;
};

/* RFC 4971 & RFC 7981 */
#define ISIS_ROUTER_CAP_FLAG_S	0x01
#define ISIS_ROUTER_CAP_FLAG_D	0x02
#define ISIS_ROUTER_CAP_SIZE	5

/* Number of supported algorithm for Segment Routing.
 * Right now only 2 have been standardized:
 *  - 0: SPF
 *  - 1: Strict SPF
 */
#define SR_ALGORITHM_COUNT	2
#define SR_ALGORITHM_SPF	0
#define SR_ALGORITHM_STRICT_SPF	1
#define SR_ALGORITHM_UNSET	255

struct isis_router_cap {
	struct in_addr router_id;
	uint8_t flags;

	/* draft-ietf-segment-routing-extensions-25 */
	struct isis_srgb srgb;
	uint8_t algo[SR_ALGORITHM_COUNT];
	/* RFC 8491 */
#define MSD_TYPE_BASE_MPLS_IMPOSITION  0x01
	uint8_t msd;
};

struct isis_item;
struct isis_item {
	struct isis_item *next;
};

struct isis_lan_neighbor;
struct isis_lan_neighbor {
	struct isis_lan_neighbor *next;

	uint8_t mac[6];
};

struct isis_ipv4_address;
struct isis_ipv4_address {
	struct isis_ipv4_address *next;

	struct in_addr addr;
};

struct isis_ipv6_address;
struct isis_ipv6_address {
	struct isis_ipv6_address *next;

	struct in6_addr addr;
};

struct isis_mt_router_info;
struct isis_mt_router_info {
	struct isis_mt_router_info *next;

	bool overload;
	bool attached;
	uint16_t mtid;
};

struct isis_auth;
struct isis_auth {
	struct isis_auth *next;

	uint8_t type;
	uint8_t length;
	uint8_t value[256];

	uint8_t plength;
	uint8_t passwd[256];

	size_t offset; /* Only valid after packing */
};

struct isis_item_list;
struct isis_item_list {
	struct isis_item *head;
	struct isis_item **tail;

	RB_ENTRY(isis_item_list) mt_tree;
	uint16_t mtid;
	unsigned int count;
};

struct isis_purge_originator {
	bool sender_set;

	uint8_t generator[6];
	uint8_t sender[6];
};

enum isis_auth_result {
	ISIS_AUTH_OK = 0,
	ISIS_AUTH_TYPE_FAILURE,
	ISIS_AUTH_FAILURE,
	ISIS_AUTH_NO_VALIDATOR,
};

RB_HEAD(isis_mt_item_list, isis_item_list);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m,
					 uint16_t mtid);
struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m,
					    uint16_t mtid);

struct isis_tlvs {
	struct isis_item_list isis_auth;
	struct isis_purge_originator *purge_originator;
	struct isis_item_list area_addresses;
	struct isis_item_list oldstyle_reach;
	struct isis_item_list lan_neighbor;
	struct isis_item_list lsp_entries;
	struct isis_item_list extended_reach;
	struct isis_mt_item_list mt_reach;
	struct isis_item_list oldstyle_ip_reach;
	struct isis_protocols_supported protocols_supported;
	struct isis_item_list oldstyle_ip_reach_ext;
	struct isis_item_list ipv4_address;
	struct isis_item_list ipv6_address;
	struct isis_item_list mt_router_info;
	bool mt_router_info_empty;
	struct in_addr *te_router_id;
	struct isis_item_list extended_ip_reach;
	struct isis_mt_item_list mt_ip_reach;
	char *hostname;
	struct isis_item_list ipv6_reach;
	struct isis_mt_item_list mt_ipv6_reach;
	struct isis_threeway_adj *threeway_adj;
	struct isis_router_cap *router_cap;
	struct isis_spine_leaf *spine_leaf;
};

enum isis_tlv_context {
	ISIS_CONTEXT_LSP,
	ISIS_CONTEXT_SUBTLV_NE_REACH,
	ISIS_CONTEXT_SUBTLV_IP_REACH,
	ISIS_CONTEXT_SUBTLV_IPV6_REACH,
	ISIS_CONTEXT_MAX
};

struct isis_subtlvs {
	enum isis_tlv_context context;

	/* draft-baker-ipv6-isis-dst-src-routing-06 */
	struct prefix_ipv6 *source_prefix;
	/* draft-ietf-isis-segment-routing-extensions-25 */
	struct isis_item_list prefix_sids;
};

enum isis_tlv_type {
	/* TLVs code point */
	ISIS_TLV_AREA_ADDRESSES = 1,
	ISIS_TLV_OLDSTYLE_REACH = 2,
	ISIS_TLV_LAN_NEIGHBORS = 6,
	ISIS_TLV_PADDING = 8,
	ISIS_TLV_LSP_ENTRY = 9,
	ISIS_TLV_AUTH = 10,
	ISIS_TLV_PURGE_ORIGINATOR = 13,
	ISIS_TLV_EXTENDED_REACH = 22,

	ISIS_TLV_OLDSTYLE_IP_REACH = 128,
	ISIS_TLV_PROTOCOLS_SUPPORTED = 129,
	ISIS_TLV_OLDSTYLE_IP_REACH_EXT = 130,
	ISIS_TLV_IPV4_ADDRESS = 132,
	ISIS_TLV_TE_ROUTER_ID = 134,
	ISIS_TLV_EXTENDED_IP_REACH = 135,
	ISIS_TLV_DYNAMIC_HOSTNAME = 137,
	ISIS_TLV_SPINE_LEAF_EXT = 150,
	ISIS_TLV_MT_REACH = 222,
	ISIS_TLV_MT_ROUTER_INFO = 229,
	ISIS_TLV_IPV6_ADDRESS = 232,
	ISIS_TLV_MT_IP_REACH = 235,
	ISIS_TLV_IPV6_REACH = 236,
	ISIS_TLV_MT_IPV6_REACH = 237,
	ISIS_TLV_THREE_WAY_ADJ = 240,
	ISIS_TLV_ROUTER_CAPABILITY = 242,
	ISIS_TLV_MAX = 256,

	/* subTLVs code point */
	ISIS_SUBTLV_IPV6_SOURCE_PREFIX = 22,

	/* RFC 5305 & RFC 6119 */
	ISIS_SUBTLV_ADMIN_GRP = 3,
	ISIS_SUBTLV_LOCAL_IPADDR = 6,
	ISIS_SUBTLV_RMT_IPADDR = 8,
	ISIS_SUBTLV_MAX_BW = 9,
	ISIS_SUBTLV_MAX_RSV_BW = 10,
	ISIS_SUBTLV_UNRSV_BW = 11,
	ISIS_SUBTLV_LOCAL_IPADDR6 = 12,
	ISIS_SUBTLV_RMT_IPADDR6 = 13,
	ISIS_SUBTLV_TE_METRIC = 18,

	/* RFC 5307 */
	ISIS_SUBTLV_LLRI = 4,

	/* RFC 5316 */
	ISIS_SUBTLV_RAS = 24,
	ISIS_SUBTLV_RIP = 25,

	/* draft-isis-segment-routing-extension-25 */
	ISIS_SUBTLV_SID_LABEL = 1,
	ISIS_SUBTLV_SID_LABEL_RANGE = 2,
	ISIS_SUBTLV_ALGORITHM = 19,
	ISIS_SUBTLV_NODE_MSD = 23,
	ISIS_SUBTLV_PREFIX_SID = 3,
	ISIS_SUBTLV_ADJ_SID = 31,
	ISIS_SUBTLV_LAN_ADJ_SID = 32,

	/* RFC 7810 */
	ISIS_SUBTLV_AV_DELAY = 33,
	ISIS_SUBTLV_MM_DELAY = 34,
	ISIS_SUBTLV_DELAY_VAR = 35,
	ISIS_SUBTLV_PKT_LOSS = 36,
	ISIS_SUBTLV_RES_BW = 37,
	ISIS_SUBTLV_AVA_BW = 38,
	ISIS_SUBTLV_USE_BW = 39,

	ISIS_SUBTLV_MAX = 40
};

/* subTLVs size for TE and SR */
enum ext_subtlv_size {
	ISIS_SUBTLV_LLRI_SIZE = 8,

	ISIS_SUBTLV_UNRSV_BW_SIZE = 32,
	ISIS_SUBTLV_TE_METRIC_SIZE = 3,
	ISIS_SUBTLV_IPV6_ADDR_SIZE = 16,

	/* draft-isis-segment-routing-extension-25 */
	ISIS_SUBTLV_SID_LABEL_SIZE = 3,
	ISIS_SUBTLV_SID_LABEL_RANGE_SIZE = 9,
	ISIS_SUBTLV_ALGORITHM_SIZE = 4,
	ISIS_SUBTLV_NODE_MSD_SIZE = 2,
	ISIS_SUBTLV_ADJ_SID_SIZE = 5,
	ISIS_SUBTLV_LAN_ADJ_SID_SIZE = 11,
	ISIS_SUBTLV_PREFIX_SID_SIZE = 5,

	ISIS_SUBTLV_MM_DELAY_SIZE = 8,

	ISIS_SUBTLV_HDR_SIZE = 2,
	ISIS_SUBTLV_DEF_SIZE = 4,

	ISIS_SUBTLV_MAX_SIZE = 180
};

/* Macros to manage the optional presence of EXT subTLVs */
#define SET_SUBTLV(s, t) ((s->status) |= (t))
#define UNSET_SUBTLV(s, t) ((s->status) &= ~(t))
#define IS_SUBTLV(s, t) (s->status & t)

#define EXT_DISABLE		0x000000
#define EXT_ADM_GRP		0x000001
#define EXT_LLRI		0x000002
#define EXT_LOCAL_ADDR		0x000004
#define EXT_NEIGH_ADDR		0x000008
#define EXT_LOCAL_ADDR6		0x000010
#define EXT_NEIGH_ADDR6		0x000020
#define EXT_MAX_BW		0x000040
#define EXT_MAX_RSV_BW		0x000080
#define EXT_UNRSV_BW		0x000100
#define EXT_TE_METRIC		0x000200
#define EXT_RMT_AS		0x000400
#define EXT_RMT_IP		0x000800
#define EXT_ADJ_SID		0x001000
#define EXT_LAN_ADJ_SID		0x002000
#define EXT_DELAY		0x004000
#define EXT_MM_DELAY		0x008000
#define EXT_DELAY_VAR		0x010000
#define EXT_PKT_LOSS		0x020000
#define EXT_RES_BW		0x040000
#define EXT_AVA_BW		0x080000
#define EXT_USE_BW		0x100000

/*
 * This structure groups all Extended IS Reachability subTLVs.
 *
 * Each bit of the status field indicates if a subTLVs is valid or not.
 * SubTLVs values use following units:
 *  - Bandwidth in bytes/sec following IEEE format,
 *  - Delay in micro-seconds with only 24 bits significant
 *  - Packet Loss in percentage of total traffic with only 24 bits (2^24 - 2)
 *
 * For Delay and packet Loss, upper bit (A) indicates if the value is
 * normal (0) or anomalous (1).
 */
#define IS_ANORMAL(v) (v & 0x80000000)

struct isis_ext_subtlvs {

	uint32_t status;

	uint32_t adm_group; /* Resource Class/Color - RFC 5305 */
	/* Link Local/Remote Identifiers - RFC 5307 */
	uint32_t local_llri;
	uint32_t remote_llri;
	struct in_addr local_addr; /* Local IP Address - RFC 5305 */
	struct in_addr neigh_addr; /* Neighbor IP Address - RFC 5305 */
	struct in6_addr local_addr6; /* Local IPv6 Address - RFC 6119 */
	struct in6_addr neigh_addr6; /* Neighbor IPv6 Address - RFC 6119 */
	float max_bw; /* Maximum Bandwidth - RFC 5305 */
	float max_rsv_bw; /* Maximum Reservable Bandwidth - RFC 5305 */
	float unrsv_bw[8]; /* Unreserved Bandwidth - RFC 5305 */
	uint32_t te_metric; /* Traffic Engineering Metric - RFC 5305 */
	uint32_t remote_as; /* Remote AS Number sub-TLV - RFC5316 */
	struct in_addr remote_ip; /* IPv4 Remote ASBR ID Sub-TLV - RFC5316 */

	uint32_t delay; /* Average Link Delay  - RFC 8570 */
	uint32_t min_delay; /* Low Link Delay  - RFC 8570 */
	uint32_t max_delay; /* High Link Delay  - RFC 8570 */
	uint32_t delay_var; /* Link Delay Variation i.e. Jitter - RFC 8570 */
	uint32_t pkt_loss; /* Unidirectional Link Packet Loss - RFC 8570 */
	float res_bw; /* Unidirectional Residual Bandwidth - RFC 8570 */
	float ava_bw; /* Unidirectional Available Bandwidth - RFC 8570 */
	float use_bw; /* Unidirectional Utilized Bandwidth - RFC 8570 */

	/* Segment Routing Adjacency & LAN Adjacency Segment ID */
	struct isis_item_list adj_sid;
	struct isis_item_list lan_sid;
};

#define IS_COMPAT_MT_TLV(tlv_type)                                             \
	((tlv_type == ISIS_TLV_MT_REACH) || (tlv_type == ISIS_TLV_MT_IP_REACH) \
	 || (tlv_type == ISIS_TLV_MT_IPV6_REACH))

struct stream;
int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
		   size_t len_pointer, bool pad, bool is_lsp);
void isis_free_tlvs(struct isis_tlvs *tlvs);
struct isis_tlvs *isis_alloc_tlvs(void);
int isis_unpack_tlvs(size_t avail_len, struct stream *stream,
		     struct isis_tlvs **dest, const char **error_log);
const char *isis_format_tlvs(struct isis_tlvs *tlvs);
struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs);
struct list *isis_fragment_tlvs(struct isis_tlvs *tlvs, size_t size);

#define ISIS_EXTENDED_IP_REACH_DOWN 0x80
#define ISIS_EXTENDED_IP_REACH_SUBTLV 0x40

#define ISIS_IPV6_REACH_DOWN 0x80
#define ISIS_IPV6_REACH_EXTERNAL 0x40
#define ISIS_IPV6_REACH_SUBTLV 0x20

#ifndef ISIS_MT_MASK
#define ISIS_MT_MASK           0x0fff
#define ISIS_MT_OL_MASK        0x8000
#define ISIS_MT_AT_MASK        0x4000
#endif

void isis_tlvs_add_auth(struct isis_tlvs *tlvs, struct isis_passwd *passwd);
void isis_tlvs_add_area_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses);
void isis_tlvs_add_lan_neighbors(struct isis_tlvs *tlvs,
				 struct list *neighbors);
void isis_tlvs_set_protocols_supported(struct isis_tlvs *tlvs,
				       struct nlpids *nlpids);
void isis_tlvs_add_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid,
				  bool overload, bool attached);
void isis_tlvs_add_ipv4_address(struct isis_tlvs *tlvs, struct in_addr *addr);
void isis_tlvs_add_ipv4_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses);
void isis_tlvs_add_ipv6_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses);
int isis_tlvs_auth_is_valid(struct isis_tlvs *tlvs, struct isis_passwd *passwd,
			    struct stream *stream, bool is_lsp);
bool isis_tlvs_area_addresses_match(struct isis_tlvs *tlvs,
				    struct list *addresses);
struct isis_adjacency;
void isis_tlvs_to_adj(struct isis_tlvs *tlvs, struct isis_adjacency *adj,
		      bool *changed);
bool isis_tlvs_own_snpa_found(struct isis_tlvs *tlvs, uint8_t *snpa);
void isis_tlvs_add_lsp_entry(struct isis_tlvs *tlvs, struct isis_lsp *lsp);
void isis_tlvs_add_csnp_entries(struct isis_tlvs *tlvs, uint8_t *start_id,
				uint8_t *stop_id, uint16_t num_lsps,
				struct lspdb_head *lspdb,
				struct isis_lsp **last_lsp);
void isis_tlvs_set_dynamic_hostname(struct isis_tlvs *tlvs,
				    const char *hostname);
void isis_tlvs_set_router_capability(struct isis_tlvs *tlvs,
                     const struct isis_router_cap *cap);
void isis_tlvs_set_te_router_id(struct isis_tlvs *tlvs,
				const struct in_addr *id);
void isis_tlvs_add_oldstyle_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint8_t metric);
void isis_tlvs_add_extended_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint32_t metric,
				     bool external, struct sr_prefix_cfg *pcfg);
void isis_tlvs_add_ipv6_reach(struct isis_tlvs *tlvs, uint16_t mtid,
			      struct prefix_ipv6 *dest, uint32_t metric,
			      bool external, struct sr_prefix_cfg *pcfg);
void isis_tlvs_add_ipv6_dstsrc_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				     struct prefix_ipv6 *dest,
				     struct prefix_ipv6 *src,
				     uint32_t metric);
struct isis_ext_subtlvs *isis_alloc_ext_subtlvs(void);
void isis_tlvs_add_adj_sid(struct isis_ext_subtlvs *exts,
			   struct isis_adj_sid *adj);
void isis_tlvs_del_adj_sid(struct isis_ext_subtlvs *exts,
			   struct isis_adj_sid *adj);
void isis_tlvs_add_lan_adj_sid(struct isis_ext_subtlvs *exts,
			       struct isis_lan_adj_sid *lan);
void isis_tlvs_del_lan_adj_sid(struct isis_ext_subtlvs *exts,
			       struct isis_lan_adj_sid *lan);

void isis_tlvs_add_oldstyle_reach(struct isis_tlvs *tlvs, uint8_t *id,
				  uint8_t metric);
void isis_tlvs_add_extended_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				  uint8_t *id, uint32_t metric,
				  struct isis_ext_subtlvs *subtlvs);

const char *isis_threeway_state_name(enum isis_threeway_state state);

void isis_tlvs_add_threeway_adj(struct isis_tlvs *tlvs,
				enum isis_threeway_state state,
				uint32_t local_circuit_id,
				const uint8_t *neighbor_id,
				uint32_t neighbor_circuit_id);

void isis_tlvs_add_spine_leaf(struct isis_tlvs *tlvs, uint8_t tier,
			      bool has_tier, bool is_leaf, bool is_spine,
			      bool is_backup);

struct isis_mt_router_info *
isis_tlvs_lookup_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid);

void isis_tlvs_set_purge_originator(struct isis_tlvs *tlvs,
				    const uint8_t *generator,
				    const uint8_t *sender);
#endif
