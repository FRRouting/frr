/*
 * BGP pbr
 * Copyright (C) 6WIND
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __BGP_PBR_H__
#define __BGP_PBR_H__

#include "nexthop.h"
#include "zclient.h"

/* flowspec case: 0 to 3 actions maximum:
 * 1 redirect
 * 1 set dscp
 * 1 set traffic rate
 */
#define ACTIONS_MAX_NUM 4
enum bgp_pbr_action_enum {
	ACTION_TRAFFICRATE = 1,
	ACTION_TRAFFIC_ACTION = 2,
	ACTION_REDIRECT = 3,
	ACTION_MARKING = 4,
	ACTION_REDIRECT_IP = 5
};

#define TRAFFIC_ACTION_SAMPLE     (1 << 0)
#define TRAFFIC_ACTION_TERMINATE  (1 << 1)
#define TRAFFIC_ACTION_DISTRIBUTE (1 << 2)

#define OPERATOR_COMPARE_LESS_THAN    (1<<1)
#define OPERATOR_COMPARE_GREATER_THAN (1<<2)
#define OPERATOR_COMPARE_EQUAL_TO     (1<<3)
#define OPERATOR_COMPARE_EXACT_MATCH  (1<<4)

#define OPERATOR_UNARY_OR    (1<<1)
#define OPERATOR_UNARY_AND   (1<<2)

/* struct used to store values [0;65535]
 * this can be used for port number of protocol
 */
#define BGP_PBR_MATCH_VAL_MAX 5

struct bgp_pbr_match_val {
	uint16_t value;
	uint8_t compare_operator;
	uint8_t unary_operator;
} bgp_pbr_value_t;

#define FRAGMENT_DONT  1
#define FRAGMENT_IS    2
#define FRAGMENT_FIRST 4
#define FRAGMENT_LAST  8

struct bgp_pbr_fragment_val {
	uint8_t bitmask;
};

struct bgp_pbr_entry_action {
	/* used to store enum bgp_pbr_action_enum enumerate */
	uint8_t action;
	union {
		union {
			uint8_t rate_info[4]; /* IEEE.754.1985 */
			float rate;
		} r __attribute__((aligned(8)));
		struct _pbr_action {
			uint8_t do_sample;
			uint8_t filter;
		} za;
		vrf_id_t redirect_vrf;
		struct _pbr_redirect_ip {
			struct in_addr redirect_ip_v4;
			uint8_t duplicate;
		} zr;
		uint8_t marking_dscp;
	} u __attribute__((aligned(8)));
};

/* BGP Policy Route structure */
struct bgp_pbr_entry_main {
	uint8_t type;
	uint16_t instance;

	uint32_t flags;

	uint8_t message;

	/*
	 * This is an enum but we are going to treat it as a uint8_t
	 * for purpose of encoding/decoding
	 */
	afi_t afi;
	safi_t safi;

#define PREFIX_SRC_PRESENT (1 << 0)
#define PREFIX_DST_PRESENT (1 << 1)
	uint8_t match_bitmask;

	uint8_t match_src_port_num;
	uint8_t match_dst_port_num;
	uint8_t match_port_num;
	uint8_t match_protocol_num;
	uint8_t match_icmp_type_num;
	uint8_t match_icmp_code_num;
	uint8_t match_packet_length_num;
	uint8_t match_dscp_num;
	uint8_t match_tcpflags_num;
	uint8_t match_fragment_num;

	struct prefix src_prefix;
	struct prefix dst_prefix;

#define PROTOCOL_UDP 17
#define PROTOCOL_TCP 6
#define PROTOCOL_ICMP 1
	struct bgp_pbr_match_val protocol[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val src_port[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val dst_port[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val port[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val icmp_type[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val icmp_code[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val packet_length[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val dscp[BGP_PBR_MATCH_VAL_MAX];

	struct bgp_pbr_match_val tcpflags[BGP_PBR_MATCH_VAL_MAX];
	struct bgp_pbr_match_val fragment[BGP_PBR_MATCH_VAL_MAX];

	uint16_t action_num;
	struct bgp_pbr_entry_action actions[ACTIONS_MAX_NUM];

	uint8_t distance;

	uint32_t metric;

	route_tag_t tag;

	uint32_t mtu;

	vrf_id_t vrf_id;
};

struct bgp_pbr_interface {
	RB_ENTRY(bgp_pbr_interface) id_entry;
	char name[INTERFACE_NAMSIZ];
};

RB_HEAD(bgp_pbr_interface_head, bgp_pbr_interface);
RB_PROTOTYPE(bgp_pbr_interface_head, bgp_pbr_interface, id_entry,
	     bgp_pbr_interface_compare);

extern int bgp_pbr_interface_compare(const struct bgp_pbr_interface *a,
				     const struct bgp_pbr_interface *b);

struct bgp_pbr_config {
	struct bgp_pbr_interface_head ifaces_by_name_ipv4;
	bool pbr_interface_any_ipv4;
};

extern struct bgp_pbr_config *bgp_pbr_cfg;

struct bgp_pbr_match {
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];

	/* mapped on enum ipset_type
	 */
	uint32_t type;

	uint32_t flags;

	uint16_t pkt_len_min;
	uint16_t pkt_len_max;
	uint16_t tcp_flags;
	uint16_t tcp_mask_flags;
	uint8_t dscp_value;
	uint8_t fragment;

	vrf_id_t vrf_id;

	/* unique identifier for ipset create transaction
	 */
	uint32_t unique;

	/* unique identifier for iptable add transaction
	 */
	uint32_t unique2;

	bool installed;
	bool install_in_progress;

	bool installed_in_iptable;
	bool install_iptable_in_progress;

	struct hash *entry_hash;

	struct bgp_pbr_action *action;

};

struct bgp_pbr_match_entry {
	struct bgp_pbr_match *backpointer;

	uint32_t unique;

	struct prefix src;
	struct prefix dst;

	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;
	uint8_t proto;

	void *bgp_info;

	bool installed;
	bool install_in_progress;
};

struct bgp_pbr_action {

	/*
	 * The Unique identifier of this specific pbrms
	 */
	uint32_t unique;

	uint32_t fwmark;

	uint32_t table_id;

	float rate;

	/*
	 * nexthop information, or drop information
	 * contains src vrf_id and nh contains dest vrf_id
	 */
	vrf_id_t vrf_id;
	struct nexthop nh;

	bool installed;
	bool install_in_progress;
	uint32_t refcnt;
	struct bgp *bgp;
};

extern struct bgp_pbr_action *bgp_pbr_action_rule_lookup(vrf_id_t vrf_id,
							 uint32_t unique);

extern struct bgp_pbr_match *bgp_pbr_match_ipset_lookup(vrf_id_t vrf_id,
							uint32_t unique);

extern struct bgp_pbr_match_entry *bgp_pbr_match_ipset_entry_lookup(
					    vrf_id_t vrf_id, char *name,
					    uint32_t unique);
extern struct bgp_pbr_match *bgp_pbr_match_iptable_lookup(vrf_id_t vrf_id,
							  uint32_t unique);

extern void bgp_pbr_cleanup(struct bgp *bgp);
extern void bgp_pbr_init(struct bgp *bgp);

extern uint32_t bgp_pbr_action_hash_key(void *arg);
extern int bgp_pbr_action_hash_equal(const void *arg1,
				     const void *arg2);
extern uint32_t bgp_pbr_match_entry_hash_key(void *arg);
extern int bgp_pbr_match_entry_hash_equal(const void *arg1,
					  const void *arg2);
extern uint32_t bgp_pbr_match_hash_key(void *arg);
extern int bgp_pbr_match_hash_equal(const void *arg1,
				    const void *arg2);

void bgp_pbr_print_policy_route(struct bgp_pbr_entry_main *api);

struct bgp_node;
struct bgp_info;
extern void bgp_pbr_update_entry(struct bgp *bgp, struct prefix *p,
				 struct bgp_info *new_select,
				afi_t afi, safi_t safi,
				bool nlri_update);

/* bgp pbr utilities */
extern struct bgp_pbr_interface *pbr_interface_lookup(const char *name);
extern void bgp_pbr_reset(struct bgp *bgp, afi_t afi);
extern struct bgp_pbr_interface *bgp_pbr_interface_lookup(const char *name,
				   struct bgp_pbr_interface_head *head);

#endif /* __BGP_PBR_H__ */
