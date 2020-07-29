/*
 * This is an implementation of Segment Routing for IS-IS as per RFC 8667
 *
 * Copyright (C) 2019 Orange http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
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

#ifndef _FRR_ISIS_SR_H
#define _FRR_ISIS_SR_H

#include "lib/linklist.h"
#include "lib/mpls.h"
#include "lib/nexthop.h"
#include "lib/typesafe.h"

#include "isisd/isis_tlvs.h"

/*
 * Segment Routing information is transported through the following Sub-TLVs:
 *
 * Sub-TLV Name                         Value   TLVs
 * ---------------------------------------------------------------------
 * SID Label				 1
 *
 * Prefix Segment Identifier		 3	135, 235, 236 and 237
 *
 * Adjacency Segment Identifier		31	22, 23, 141, 222 and 223
 * LAN Adjacency Segment Identifier	32	22, 23, 141, 222 and 223
 *
 * Segment Routing Capability		 2	242
 * Segment Routing Algorithm		19	242
 * Node Maximum Stack Depth (MSD)	23	242
 *
 * Sub-TLV definitions, serialization and de-serialization are defined
 * in isis_tlvs.[c,h].
 */

#define SRGB_LOWER_BOUND               16000
#define SRGB_UPPER_BOUND               23999
#define SRLB_LOWER_BOUND               15000
#define SRLB_UPPER_BOUND               15999

/* Segment Routing Data Base (SRDB) RB-Tree structure */
PREDECL_RBTREE_UNIQ(srdb_node)
PREDECL_RBTREE_UNIQ(srdb_node_prefix)
PREDECL_RBTREE_UNIQ(srdb_area_prefix)
PREDECL_RBTREE_UNIQ(srdb_prefix_cfg)

/* Segment Routing Local Block allocation */
struct sr_local_block {
	bool active;
	uint32_t start;
	uint32_t end;
	uint32_t current;
	uint32_t max_block;
	uint64_t *used_mark;
};
#define SRLB_BLOCK_SIZE 64

/* Segment Routing Adjacency-SID type. */
enum sr_adj_type {
	ISIS_SR_ADJ_NORMAL = 0,
	ISIS_SR_LAN_BACKUP,
};

/* Segment Routing Adjacency. */
struct sr_adjacency {
	/* Adjacency type. */
	enum sr_adj_type type;

	/* Adjacency-SID nexthop information. */
	struct {
		int family;
		union g_addr address;
		mpls_label_t label;
	} nexthop;

	/* (LAN-)Adjacency-SID Sub-TLV. */
	union {
		struct isis_adj_sid *adj_sid;
		struct isis_lan_adj_sid *ladj_sid;
	} u;

	/* Back pointer to IS-IS adjacency. */
	struct isis_adjacency *adj;
};

/* Segment Routing Prefix-SID type. */
enum sr_prefix_type {
	ISIS_SR_PREFIX_LOCAL = 0,
	ISIS_SR_PREFIX_REMOTE,
};

/* Segment Routing Nexthop Information. */
struct sr_nexthop_info {
	mpls_label_t label;
	time_t uptime;
};

/* State of Object (SR-Node and SR-Prefix) stored in SRDB */
enum srdb_state {
	SRDB_STATE_VALIDATED = 0,
	SRDB_STATE_NEW,
	SRDB_STATE_MODIFIED,
	SRDB_STATE_UNCHANGED
};

/* Segment Routing Prefix-SID. */
struct sr_prefix {
	/* SRDB RB-tree entries. */
	struct srdb_node_prefix_item node_entry;
	struct srdb_area_prefix_item area_entry;

	/* IP prefix. */
	struct prefix prefix;

	/* SID value, algorithm and flags subTLVs. */
	struct isis_prefix_sid sid;

	/* Input label value. */
	mpls_label_t input_label;

	/* Prefix-SID type. */
	enum sr_prefix_type type;
	union {
		struct {
			/* Information about this local Prefix-SID. */
			struct sr_nexthop_info info;
		} local;
		struct {
			/* Route associated to this remote Prefix-SID. */
			struct isis_route_info *rinfo;
		} remote;
	} u;

	/* Backpointer to Segment Routing node. */
	struct sr_node *srn;

	/* SR-Prefix State used while the LSPDB is being parsed. */
	enum srdb_state state;
};

/* Segment Routing node. */
struct sr_node {
	/* SRDB RB-tree entry. */
	struct srdb_node_item entry;

	/* IS-IS level: ISIS_LEVEL1 or ISIS_LEVEL2. */
	int level;

	/* IS-IS node identifier. */
	uint8_t sysid[ISIS_SYS_ID_LEN];

	/* Segment Routing node capabilities (SRGB, SR Algorithms) subTLVs. */
	struct isis_router_cap cap;

	/* List of Prefix-SIDs advertised by this node. */
	struct srdb_node_prefix_head prefix_sids;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;

	/* SR-Node State used while the LSPDB is being parsed. */
	enum srdb_state state;
};

/* SID type. NOTE: these values must be in sync with the YANG module. */
enum sr_sid_value_type {
	SR_SID_VALUE_TYPE_INDEX = 0,
	SR_SID_VALUE_TYPE_ABSOLUTE = 1,
};

#define IS_SID_VALUE(flag) CHECK_FLAG(flag, ISIS_PREFIX_SID_VALUE)

/* Last Hop Behavior. NOTE: these values must be in sync with the YANG module */
enum sr_last_hop_behavior {
	SR_LAST_HOP_BEHAVIOR_EXP_NULL = 0,
	SR_LAST_HOP_BEHAVIOR_NO_PHP = 1,
	SR_LAST_HOP_BEHAVIOR_PHP = 2,
};

/* Segment Routing Prefix-SID configuration. */
struct sr_prefix_cfg {
	/* SRDB RB-tree entry. */
	struct srdb_prefix_cfg_item entry;

	/* IP prefix. */
	struct prefix prefix;

	/* SID value. */
	uint32_t sid;

	/* SID value type. */
	enum sr_sid_value_type sid_type;

	/* SID last hop behavior. */
	enum sr_last_hop_behavior last_hop_behavior;

	/* Does this Prefix-SID refer to a loopback address (Node-SID)? */
	bool node_sid;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;
};

/* Per-area IS-IS Segment Routing Data Base (SRDB). */
struct isis_sr_db {
	/* Global Operational status of Segment Routing. */
	bool enabled;

	/* Thread timer to start Label Manager */
	struct thread *t_start_lm;

	/* List of local Adjacency-SIDs. */
	struct list *adj_sids;

	/* Segment Routing Node information per IS-IS level. */
	struct srdb_node_head sr_nodes[ISIS_LEVELS];

	/* Segment Routing Prefix-SIDs per IS-IS level. */
	struct srdb_area_prefix_head prefix_sids[ISIS_LEVELS];

	/* Management of SRLB & SRGB allocation */
	struct sr_local_block srlb;
	bool srgb_active;

	/* Area Segment Routing configuration. */
	struct {
		/* Administrative status of Segment Routing. */
		bool enabled;

		/* Segment Routing Global Block lower & upper bound. */
		uint32_t srgb_lower_bound;
		uint32_t srgb_upper_bound;

		/* Segment Routing Local Block lower & upper bound. */
		uint32_t srlb_lower_bound;
		uint32_t srlb_upper_bound;

		/* Maximum SID Depth supported by the node. */
		uint8_t msd;

		/* Prefix-SID mappings. */
		struct srdb_prefix_cfg_head prefix_sids;
	} config;
};

/* Prototypes. */
extern int isis_sr_cfg_srgb_update(struct isis_area *area, uint32_t lower_bound,
				   uint32_t upper_bound);
extern int isis_sr_cfg_srlb_update(struct isis_area *area, uint32_t lower_bound,
				   uint32_t upper_bound);
extern struct sr_prefix_cfg *
isis_sr_cfg_prefix_add(struct isis_area *area, const struct prefix *prefix);
extern void isis_sr_cfg_prefix_del(struct sr_prefix_cfg *pcfg);
extern struct sr_prefix_cfg *
isis_sr_cfg_prefix_find(struct isis_area *area, union prefixconstptr prefix);
extern void isis_sr_prefix_cfg2subtlv(const struct sr_prefix_cfg *pcfg,
				      bool external,
				      struct isis_prefix_sid *psid);
extern void isis_sr_nexthop_update(struct sr_nexthop_info *srnh,
				   mpls_label_t label);
extern void isis_sr_nexthop_reset(struct sr_nexthop_info *srnh);
extern void isis_area_verify_sr(struct isis_area *area);
extern int isis_sr_start(struct isis_area *area);
extern void isis_sr_stop(struct isis_area *area);
extern void isis_sr_area_init(struct isis_area *area);
extern void isis_sr_area_term(struct isis_area *area);
extern void isis_sr_init(void);
extern void isis_sr_term(void);

#endif /* _FRR_ISIS_SR_H */
