/*
 * IS-IS TLV Serializer/Deserializer
 *
 * Copyright (C) 2015,2017 Christian Franke
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
#include "isisd/dict.h"

struct isis_subtlvs;

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
struct isis_extended_reach {
	struct isis_extended_reach *next;

	uint8_t id[7];
	uint32_t metric;

	uint8_t *subtlvs;
	uint8_t subtlv_len;
};

struct isis_extended_ip_reach;
struct isis_extended_ip_reach {
	struct isis_extended_ip_reach *next;

	uint32_t metric;
	bool down;
	struct prefix_ipv4 prefix;
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

RB_HEAD(isis_mt_item_list, isis_item_list);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m,
					 uint16_t mtid);
struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m,
					    uint16_t mtid);

struct isis_tlvs {
	struct isis_item_list isis_auth;
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
};

struct isis_subtlvs {
	/* draft-baker-ipv6-isis-dst-src-routing-06 */
	struct prefix_ipv6 *source_prefix;
};

enum isis_tlv_context {
	ISIS_CONTEXT_LSP,
	ISIS_CONTEXT_SUBTLV_NE_REACH,
	ISIS_CONTEXT_SUBTLV_IP_REACH,
	ISIS_CONTEXT_SUBTLV_IPV6_REACH,
	ISIS_CONTEXT_MAX
};

enum isis_tlv_type {
	ISIS_TLV_AREA_ADDRESSES = 1,
	ISIS_TLV_OLDSTYLE_REACH = 2,
	ISIS_TLV_LAN_NEIGHBORS = 6,
	ISIS_TLV_PADDING = 8,
	ISIS_TLV_LSP_ENTRY = 9,
	ISIS_TLV_AUTH = 10,
	ISIS_TLV_EXTENDED_REACH = 22,

	ISIS_TLV_OLDSTYLE_IP_REACH = 128,
	ISIS_TLV_PROTOCOLS_SUPPORTED = 129,
	ISIS_TLV_OLDSTYLE_IP_REACH_EXT = 130,
	ISIS_TLV_IPV4_ADDRESS = 132,
	ISIS_TLV_TE_ROUTER_ID = 134,
	ISIS_TLV_EXTENDED_IP_REACH = 135,
	ISIS_TLV_DYNAMIC_HOSTNAME = 137,
	ISIS_TLV_MT_REACH = 222,
	ISIS_TLV_MT_ROUTER_INFO = 229,
	ISIS_TLV_IPV6_ADDRESS = 232,
	ISIS_TLV_MT_IP_REACH = 235,
	ISIS_TLV_IPV6_REACH = 236,
	ISIS_TLV_MT_IPV6_REACH = 237,
	ISIS_TLV_THREE_WAY_ADJ = 240,
	ISIS_TLV_MAX = 256,

	ISIS_SUBTLV_IPV6_SOURCE_PREFIX = 22
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
bool isis_tlvs_auth_is_valid(struct isis_tlvs *tlvs, struct isis_passwd *passwd,
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
				dict_t *lspdb, struct isis_lsp **last_lsp);
void isis_tlvs_set_dynamic_hostname(struct isis_tlvs *tlvs,
				    const char *hostname);
void isis_tlvs_set_te_router_id(struct isis_tlvs *tlvs,
				const struct in_addr *id);
void isis_tlvs_add_oldstyle_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint8_t metric);
void isis_tlvs_add_extended_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint32_t metric);
void isis_tlvs_add_ipv6_reach(struct isis_tlvs *tlvs, uint16_t mtid,
			      struct prefix_ipv6 *dest, uint32_t metric);
void isis_tlvs_add_oldstyle_reach(struct isis_tlvs *tlvs, uint8_t *id,
				  uint8_t metric);
void isis_tlvs_add_extended_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				  uint8_t *id, uint32_t metric,
				  uint8_t *subtlvs, uint8_t subtlv_len);

const char *isis_threeway_state_name(enum isis_threeway_state state);

void isis_tlvs_add_threeway_adj(struct isis_tlvs *tlvs,
				enum isis_threeway_state state,
				uint32_t local_circuit_id,
				const uint8_t *neighbor_id,
				uint32_t neighbor_circuit_id);

struct isis_mt_router_info *
isis_tlvs_lookup_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid);
#endif
