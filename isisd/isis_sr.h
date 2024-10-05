// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing for IS-IS as per RFC 8667
 *
 * Copyright (C) 2019 Orange http://www.orange.com
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Contributor: Renato Westphal <renato@opensourcerouting.org> for NetDEF
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
PREDECL_RBTREE_UNIQ(srdb_prefix_cfg);

/*
 * Segment Routing Prefix-SID information.
 *
 * This structure is intended to be embedded inside other structures that
 * might or might not contain Prefix-SID information.
 */
struct isis_sr_psid_info {
	/* Prefix-SID Sub-TLV information. */
	struct isis_prefix_sid sid;

	/* Resolved input/output label. */
	mpls_label_t label;

	/* Indicates whether the Prefix-SID is present or not. */
	bool present;

	uint8_t algorithm;

	struct list *nexthops;
	struct list *nexthops_backup;
};

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
	ISIS_SR_ADJ_BACKUP,
};

/* Segment Routing Adjacency. */
struct sr_adjacency {
	/* Adjacency type. */
	enum sr_adj_type type;

	/* Adjacency-SID input label. */
	mpls_label_t input_label;

	/* Adjacency-SID nexthop information. */
	struct {
		int family;
		union g_addr address;
	} nexthop;

	/* Adjacency-SID TI-LFA backup nexthops. */
	struct list *backup_nexthops;

	/* (LAN-)Adjacency-SID Sub-TLV. */
	union {
		struct isis_adj_sid *adj_sid;
		struct isis_lan_adj_sid *ladj_sid;
	} u;

	/* Back pointer to IS-IS adjacency. */
	struct isis_adjacency *adj;
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

	/* Indicates whether the node flag must be explicitly unset. */
	bool n_flag_clear;

	/* Does this Prefix-SID refer to a loopback address (Node-SID)? */
	bool node_sid;

	/* Backpointer to IS-IS area. */
	struct isis_area *area;

	/* SR Algorithm number */
	uint8_t algorithm;
};

/* Per-area IS-IS Segment Routing Data Base (SRDB). */
struct isis_sr_db {
	/* Global Operational status of Segment Routing. */
	bool enabled;

	/* Thread timer to start Label Manager */
	struct event *t_start_lm;

	/* List of local Adjacency-SIDs. */
	struct list *adj_sids;

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
extern struct isis_sr_block *isis_sr_find_srgb(struct lspdb_head *lspdb,
					       const uint8_t *sysid);
extern mpls_label_t sr_prefix_in_label(struct isis_area *area,
				       struct isis_prefix_sid *psid,
				       bool local);
extern mpls_label_t sr_prefix_out_label(struct lspdb_head *lspdb, int family,
					struct isis_prefix_sid *psid,
					const uint8_t *nh_sysid, bool last_hop);
extern int isis_sr_cfg_srgb_update(struct isis_area *area, uint32_t lower_bound,
				   uint32_t upper_bound);
extern int isis_sr_cfg_srlb_update(struct isis_area *area, uint32_t lower_bound,
				   uint32_t upper_bound);
extern struct sr_prefix_cfg *isis_sr_cfg_prefix_add(struct isis_area *area,
						    const struct prefix *prefix,
						    uint8_t algorithm);
extern void isis_sr_cfg_prefix_del(struct sr_prefix_cfg *pcfg);
extern struct sr_prefix_cfg *
isis_sr_cfg_prefix_find(struct isis_area *area, union prefixconstptr prefix,
			uint8_t algorithm);
extern void isis_sr_prefix_cfg2subtlv(const struct sr_prefix_cfg *pcfg,
				      bool external,
				      struct isis_prefix_sid *psid);
extern void sr_adj_sid_add_single(struct isis_adjacency *adj, int family,
				  bool backup, struct list *nexthops);
extern struct sr_adjacency *isis_sr_adj_sid_find(struct isis_adjacency *adj,
						 int family,
						 enum sr_adj_type type);
extern void isis_area_delete_backup_adj_sids(struct isis_area *area, int level);
extern int sr_if_addr_update(struct interface *ifp);
extern char *sr_op2str(char *buf, size_t size, mpls_label_t label_in,
		       mpls_label_t label_out);
extern int isis_sr_start(struct isis_area *area);
extern void isis_sr_stop(struct isis_area *area);
extern void isis_sr_area_init(struct isis_area *area);
extern void isis_sr_area_term(struct isis_area *area);
extern void isis_sr_init(void);
extern void isis_sr_term(void);

#endif /* _FRR_ISIS_SR_H */
