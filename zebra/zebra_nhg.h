/* Zebra Nexthop Group header.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
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
#ifndef __ZEBRA_NHG_H__
#define __ZEBRA_NHG_H__

#include "zebra/rib.h"
#include "lib/nexthop_group.h"

#include "zebra/zebra_dplane.h"

/* This struct is used exclusively for dataplane
 * interaction via a dataplane context.
 *
 * It is designed to mimic the netlink nexthop_grp
 * struct in include/linux/nexthop.h
 */
struct nh_grp {
	uint32_t id;
	uint8_t weight;
};


struct nhg_hash_entry {
	uint32_t id;
	afi_t afi;
	vrf_id_t vrf_id;
	bool is_kernel_nh;

	struct nexthop_group *nhg;

	/* If this is not a group, it
	 * will be a single nexthop
	 * and must have an interface
	 * associated with it.
	 * Otherwise, this will be null.
	 */
	struct interface *ifp;

	uint32_t refcnt;
	uint32_t dplane_ref;

	uint32_t flags;

	/* Dependency tree for other entries.
	 * For instance a group with two
	 * nexthops will have two dependencies
	 * pointing to those nhg_hash_entries.
	 *
	 * Using a rb tree here to make lookups
	 * faster with ID's.
	 */
	RB_HEAD(nhg_connected_head, nhg_connected) nhg_depends, nhg_dependents;
/*
 * Is this nexthop group valid, ie all nexthops are fully resolved.
 * What is fully resolved?  It's a nexthop that is either self contained
 * and correct( ie no recursive pointer ) or a nexthop that is recursively
 * resolved and correct.
 */
#define NEXTHOP_GROUP_VALID 0x1
/*
 * Has this nexthop group been installed?  At this point in time, this
 * means that the data-plane has been told about this nexthop group
 * and it's possible usage by a route entry.
 */
#define NEXTHOP_GROUP_INSTALLED 0x2
/*
 * Has the nexthop group been queued to be send to the FIB?
 * The NEXTHOP_GROUP_VALID flag should also be set by this point.
 */
#define NEXTHOP_GROUP_QUEUED 0x4
};

/* Abstraction for connected trees */
struct nhg_connected {
	RB_ENTRY(nhg_connected) nhg_entry;
	struct nhg_hash_entry *nhe;
};

RB_PROTOTYPE(nhg_connected_head, nhg_connected, nhg_entry, nhg_connected_cmp);


enum nhg_ctx_op_e {
	NHG_CTX_OP_NONE = 0,
	NHG_CTX_OP_NEW,
	NHG_CTX_OP_DEL,
};

enum nhg_ctx_result {
	NHG_CTX_NONE = 0,
	NHG_CTX_QUEUED,
	NHG_CTX_SUCCESS,
	NHG_CTX_FAILURE,
};

/*
 * Context needed to queue nhg updates on the
 * work queue.
 */
struct nhg_ctx {

	/* Unique ID */
	uint32_t id;

	vrf_id_t vrf_id;
	afi_t afi;
	bool is_kernel_nh;

	/* If its a group array, how many? */
	uint8_t count;

	/* Its either a single nexthop or an array of ID's */
	union {
		struct nexthop nh;
		struct nh_grp grp[MULTIPATH_NUM];
	} u;

	enum nhg_ctx_op_e op;
	enum nhg_ctx_result status;
};


void zebra_nhg_init(void);
void zebra_nhg_terminate(void);

extern void nhg_connected_free(struct nhg_connected *dep);
extern struct nhg_connected *nhg_connected_new(struct nhg_hash_entry *nhe);

/* nhg connected tree direct access functions */
extern void nhg_connected_head_init(struct nhg_connected_head *head);
extern unsigned int
nhg_connected_head_count(const struct nhg_connected_head *head);
extern void nhg_connected_head_free(struct nhg_connected_head *head);
extern bool nhg_connected_head_is_empty(const struct nhg_connected_head *head);
extern void nhg_connected_head_del(struct nhg_connected_head *head,
				   struct nhg_hash_entry *nhe);
extern void nhg_connected_head_add(struct nhg_connected_head *head,
				   struct nhg_hash_entry *nhe);

/**
 * NHE abstracted tree functions.
 * Use these where possible instead of the direct ones access ones.
 */
/* Depends */
extern unsigned int zebra_nhg_depends_count(const struct nhg_hash_entry *nhe);
extern bool zebra_nhg_depends_is_empty(const struct nhg_hash_entry *nhe);
extern void zebra_nhg_depends_del(struct nhg_hash_entry *from,
				  struct nhg_hash_entry *depend);
extern void zebra_nhg_depends_add(struct nhg_hash_entry *to,
				  struct nhg_hash_entry *depend);
extern void zebra_nhg_depends_init(struct nhg_hash_entry *nhe);
/* Dependents */
extern unsigned int
zebra_nhg_dependents_count(const struct nhg_hash_entry *nhe);
extern bool zebra_nhg_dependents_is_empty(const struct nhg_hash_entry *nhe);
extern void zebra_nhg_dependents_del(struct nhg_hash_entry *from,
				     struct nhg_hash_entry *dependent);
extern void zebra_nhg_dependents_add(struct nhg_hash_entry *to,
				     struct nhg_hash_entry *dependent);
extern void zebra_nhg_dependents_init(struct nhg_hash_entry *nhe);


extern struct nhg_hash_entry *zebra_nhg_lookup_id(uint32_t id);
extern int zebra_nhg_insert_id(struct nhg_hash_entry *nhe);

extern uint32_t zebra_nhg_hash_key(const void *arg);
extern uint32_t zebra_nhg_id_key(const void *arg);

extern bool zebra_nhg_hash_equal(const void *arg1, const void *arg2);
extern bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2);

/*
 * Process a context off of a queue.
 * Specifically this should be from
 * the rib meta queue.
 */
extern int nhg_ctx_process(struct nhg_ctx *ctx);

/* Find via kernel nh creation */
extern int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh,
				 struct nh_grp *grp, uint8_t count,
				 vrf_id_t vrf_id, afi_t afi);

/* Find via route creation */
extern struct nhg_hash_entry *zebra_nhg_rib_find(uint32_t id,
						 struct nexthop_group *nhg,
						 vrf_id_t rt_vrf_id,
						 afi_t rt_afi);


void zebra_nhg_free_members(struct nhg_hash_entry *nhe);
void zebra_nhg_free(void *arg);
void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe);
void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe);

extern bool zebra_nhg_id_is_valid(uint32_t id);
void zebra_nhg_set_invalid(struct nhg_hash_entry *nhe);
void zebra_nhg_set_if(struct nhg_hash_entry *nhe, struct interface *ifp);

extern int nexthop_active_update(struct route_node *rn, struct route_entry *re);

void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe);
void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe);

void zebra_nhg_cleanup_tables(void);

/* Forward ref of dplane update context type */
struct zebra_dplane_ctx;
void zebra_nhg_dplane_result(struct zebra_dplane_ctx *ctx);
#endif
