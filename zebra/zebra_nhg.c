/* Zebra Nexthop Group Code.
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
#include <zebra.h>

#include "lib/nexthop.h"
#include "lib/nexthop_group_private.h"
#include "lib/routemap.h"
#include "lib/mpls.h"
#include "lib/jhash.h"
#include "lib/debug.h"

#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_nhg.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_memory.h"
#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra_errors.h"
#include "zebra_dplane.h"
#include "zebra/interface.h"

DEFINE_MTYPE_STATIC(ZEBRA, NHG, "Nexthop Group Entry");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_CONNECTED, "Nexthop Group Connected");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_CTX, "Nexthop Group Context");

static int nhg_connected_cmp(const struct nhg_connected *dep1,
			     const struct nhg_connected *dep2);

RB_GENERATE(nhg_connected_head, nhg_connected, nhg_entry, nhg_connected_cmp);


void nhg_connected_free(struct nhg_connected *dep)
{
	XFREE(MTYPE_NHG_CONNECTED, dep);
}

struct nhg_connected *nhg_connected_new(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *new = NULL;

	new = XCALLOC(MTYPE_NHG_CONNECTED, sizeof(struct nhg_connected));
	new->nhe = nhe;

	return new;
}

void nhg_connected_head_init(struct nhg_connected_head *head)
{
	RB_INIT(nhg_connected_head, head);
}

void nhg_connected_head_free(struct nhg_connected_head *head)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct nhg_connected *tmp = NULL;

	if (!nhg_connected_head_is_empty(head)) {
		RB_FOREACH_SAFE (rb_node_dep, nhg_connected_head, head, tmp) {
			RB_REMOVE(nhg_connected_head, head, rb_node_dep);
			nhg_connected_free(rb_node_dep);
		}
	}
}

unsigned int nhg_connected_head_count(const struct nhg_connected_head *head)
{
	struct nhg_connected *rb_node_dep = NULL;
	unsigned int i = 0;

	RB_FOREACH (rb_node_dep, nhg_connected_head, head) {
		i++;
	}
	return i;
}

bool nhg_connected_head_is_empty(const struct nhg_connected_head *head)
{
	return RB_EMPTY(nhg_connected_head, head);
}

void nhg_connected_head_del(struct nhg_connected_head *head,
			    struct nhg_hash_entry *depend)
{
	struct nhg_connected lookup = {};
	struct nhg_connected *remove = NULL;

	lookup.nhe = depend;

	/* Lookup to find the element, then remove it */
	remove = RB_FIND(nhg_connected_head, head, &lookup);
	remove = RB_REMOVE(nhg_connected_head, head, remove);

	if (remove)
		nhg_connected_free(remove);
}

void nhg_connected_head_add(struct nhg_connected_head *head,
			    struct nhg_hash_entry *depend)
{
	struct nhg_connected *new = NULL;

	new = nhg_connected_new(depend);

	if (new)
		RB_INSERT(nhg_connected_head, head, new);
}

unsigned int zebra_nhg_depends_count(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_head_count(&nhe->nhg_depends);
}

bool zebra_nhg_depends_is_empty(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_head_is_empty(&nhe->nhg_depends);
}

/**
 * zebra_nhg_depends_del() - Delete a dependency from the nhg_hash_entry
 *
 * @from:	Nexthop group hash entry we are deleting from
 * @depend:	Dependency we are deleting
 */
void zebra_nhg_depends_del(struct nhg_hash_entry *from,
			   struct nhg_hash_entry *depend)
{
	nhg_connected_head_del(&from->nhg_depends, depend);
}

/**
 * zebra_nhg_depends_add() - Add a new dependency to the nhg_hash_entry
 *
 * @to:		Nexthop group hash entry we are adding to
 * @depend:	Dependency we are adding
 */
void zebra_nhg_depends_add(struct nhg_hash_entry *to,
			   struct nhg_hash_entry *depend)
{
	nhg_connected_head_add(&to->nhg_depends, depend);
}

/**
 * zebra_nhg_depends_init() - Initialize tree for nhg dependencies
 *
 * @nhe:	Nexthop group hash entry
 */
void zebra_nhg_depends_init(struct nhg_hash_entry *nhe)
{
	nhg_connected_head_init(&nhe->nhg_depends);
}

/* Release this nhe from anything that it depends on */
static void zebra_nhg_depends_release(struct nhg_hash_entry *nhe)
{
	if (!zebra_nhg_depends_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;
		struct nhg_connected *tmp = NULL;

		RB_FOREACH_SAFE (rb_node_dep, nhg_connected_head,
				 &nhe->nhg_depends, tmp) {
			zebra_nhg_dependents_del(rb_node_dep->nhe, nhe);
		}
	}
}

unsigned int zebra_nhg_dependents_count(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_head_count(&nhe->nhg_dependents);
}

bool zebra_nhg_dependents_is_empty(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_head_is_empty(&nhe->nhg_dependents);
}

/**
 * zebra_nhg_dependents_del() - Delete a dependent from the nhg_hash_entry
 *
 * @from:	Nexthop group hash entry we are deleting from
 * @dependent:	Dependent we are deleting
 */
void zebra_nhg_dependents_del(struct nhg_hash_entry *from,
			      struct nhg_hash_entry *dependent)
{
	nhg_connected_head_del(&from->nhg_dependents, dependent);
}

/**
 * zebra_nhg_dependents_add() - Add a new dependent to the nhg_hash_entry
 *
 * @to:		Nexthop group hash entry we are adding to
 * @dependent:	Dependent we are adding
 */
void zebra_nhg_dependents_add(struct nhg_hash_entry *to,
			      struct nhg_hash_entry *dependent)
{
	nhg_connected_head_add(&to->nhg_dependents, dependent);
}

/**
 * zebra_nhg_dependents_init() - Initialize tree for nhg dependents
 *
 * @nhe:	Nexthop group hash entry
 */
void zebra_nhg_dependents_init(struct nhg_hash_entry *nhe)
{
	nhg_connected_head_init(&nhe->nhg_dependents);
}

/* Release this nhe from anything depending on it */
static void zebra_nhg_dependents_release(struct nhg_hash_entry *nhe)
{
	if (!zebra_nhg_dependents_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;
		struct nhg_connected *tmp = NULL;

		RB_FOREACH_SAFE (rb_node_dep, nhg_connected_head,
				 &nhe->nhg_dependents, tmp) {
			zebra_nhg_depends_del(rb_node_dep->nhe, nhe);
		}
	}
}

/**
 * zebra_nhg_lookup_id() - Lookup the nexthop group id in the id table
 *
 * @id:		ID to look for
 *
 * Return:	Nexthop hash entry if found/NULL if not found
 */
struct nhg_hash_entry *zebra_nhg_lookup_id(uint32_t id)
{
	struct nhg_hash_entry lookup = {};

	lookup.id = id;
	return hash_lookup(zrouter.nhgs_id, &lookup);
}

/**
 * zebra_nhg_insert_id() - Insert a nhe into the id hashed table
 *
 * @nhe:	The entry directly from the other table
 *
 * Return:	Result status
 */
int zebra_nhg_insert_id(struct nhg_hash_entry *nhe)
{
	if (hash_lookup(zrouter.nhgs_id, nhe)) {
		flog_err(
			EC_ZEBRA_NHG_TABLE_INSERT_FAILED,
			"Failed inserting NHG id=%u into the ID hash table, entry already exists",
			nhe->id);
		return -1;
	}

	hash_get(zrouter.nhgs_id, nhe, hash_alloc_intern);

	return 0;
}


static void *zebra_nhg_alloc(void *arg)
{
	struct nhg_hash_entry *nhe;
	struct nhg_hash_entry *copy = arg;
	struct nhg_connected *rb_node_dep = NULL;

	nhe = XCALLOC(MTYPE_NHG, sizeof(struct nhg_hash_entry));

	nhe->id = copy->id;
	nhe->nhg_depends = copy->nhg_depends;

	nhe->nhg = nexthop_group_new();
	nexthop_group_copy(nhe->nhg, copy->nhg);

	nhe->vrf_id = copy->vrf_id;
	nhe->afi = copy->afi;
	nhe->refcnt = 0;
	nhe->is_kernel_nh = copy->is_kernel_nh;
	nhe->dplane_ref = zebra_router_get_next_sequence();

	/* Attach backpointer to anything that it depends on */
	zebra_nhg_dependents_init(nhe);
	if (!zebra_nhg_depends_is_empty(nhe)) {
		RB_FOREACH (rb_node_dep, nhg_connected_head,
			    &nhe->nhg_depends) {
			zebra_nhg_dependents_add(rb_node_dep->nhe, nhe);
		}
	}

	/* Add the ifp now if its not a group or recursive and has ifindex */
	if (zebra_nhg_depends_is_empty(nhe) && nhe->nhg->nexthop) {
		struct interface *ifp = NULL;

		switch (nhe->nhg->nexthop->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IFINDEX:
			ifp = if_lookup_by_index(nhe->nhg->nexthop->ifindex,
						 nhe->vrf_id);
			zebra_nhg_set_if(nhe, ifp);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV6:
			break;
		}
	}

	/* Add to id table as well */
	zebra_nhg_insert_id(nhe);

	return nhe;
}

uint32_t zebra_nhg_hash_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;

	uint32_t key = 0x5a351234;

	key = jhash_2words(nhe->vrf_id, nhe->afi, key);

	key = jhash_1word(nexthop_group_hash(nhe->nhg), key);

	return key;
}

uint32_t zebra_nhg_id_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;

	return nhe->id;
}

bool zebra_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	if (!nexthop_group_equal(nhe1->nhg, nhe2->nhg))
		return false;

	return true;
}

bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;

	return nhe1->id == nhe2->id;
}

/**
 * nhg_connected cmp() - Compare the ID's of two connected nhg's
 *
 * @con1:	Connected group entry #1
 * @con2:	Connected group entry #2
 *
 * Return:
 * 	- Negative: #1 < #2
 * 	- Positive: #1 > #2
 * 	- Zero:	    #1 = #2
 *
 * This is used in the nhg RB trees.
 */
static int nhg_connected_cmp(const struct nhg_connected *con1,
			     const struct nhg_connected *con2)
{
	return (con1->nhe->id - con2->nhe->id);
}

static void zebra_nhg_process_grp(struct nexthop_group *nhg,
				  struct nhg_connected_head *depends,
				  struct nh_grp *grp, uint8_t count)
{
	nhg_connected_head_init(depends);

	for (int i = 0; i < count; i++) {
		struct nhg_hash_entry *depend = NULL;
		/* We do not care about nexthop_grp.weight at
		 * this time. But we should figure out
		 * how to adapt this to our code in
		 * the future.
		 */
		depend = zebra_nhg_lookup_id(grp[i].id);
		if (depend) {
			nhg_connected_head_add(depends, depend);
			/*
			 * If this is a nexthop with its own group
			 * dependencies, add them as well. Not sure its
			 * even possible to have a group within a group
			 * in the kernel.
			 */

			copy_nexthops(&nhg->nexthop, depend->nhg->nexthop,
				      NULL);
		} else {
			flog_err(
				EC_ZEBRA_NHG_SYNC,
				"Received Nexthop Group from the kernel with a dependent Nexthop ID (%u) which we do not have in our table",
				grp[i].id);
		}
	}
}


static struct nhg_hash_entry *
zebra_nhg_find(uint32_t id, struct nexthop_group *nhg,
	       struct nhg_connected_head *nhg_depends, vrf_id_t vrf_id,
	       afi_t afi, bool is_kernel_nh)
{
	/* id counter to keep in sync with kernel */
	static uint32_t id_counter = 0;

	struct nhg_hash_entry lookup = {};
	struct nhg_hash_entry *nhe = NULL;

	uint32_t old_id_counter = id_counter;

	if (id > id_counter) {
		/* Increase our counter so we don't try to create
		 * an ID that already exists
		 */
		id_counter = id;
		lookup.id = id;
	} else
		lookup.id = ++id_counter;

	lookup.afi = afi;
	lookup.vrf_id = vrf_id;
	lookup.is_kernel_nh = is_kernel_nh;
	lookup.nhg = nhg;

	if (nhg_depends)
		lookup.nhg_depends = *nhg_depends;

	if (id)
		nhe = zebra_nhg_lookup_id(id);
	else
		nhe = hash_lookup(zrouter.nhgs, &lookup);

	/* If it found an nhe in our tables, this new ID is unused */
	if (nhe)
		id_counter = old_id_counter;

	if (!nhe)
		nhe = hash_get(zrouter.nhgs, &lookup, zebra_nhg_alloc);

	return nhe;
}

/* Find/create a single nexthop */
static struct nhg_hash_entry *zebra_nhg_find_nexthop(uint32_t id,
						     struct nexthop *nh,
						     afi_t afi,
						     bool is_kernel_nh)
{
	struct nexthop_group nhg = {};

	_nexthop_group_add_sorted(&nhg, nh);

	return zebra_nhg_find(id, &nhg, NULL, nh->vrf_id, afi, is_kernel_nh);
}

static struct nhg_ctx *nhg_ctx_new()
{
	struct nhg_ctx *new = NULL;

	new = XCALLOC(MTYPE_NHG_CTX, sizeof(struct nhg_ctx));

	return new;
}

static void nhg_ctx_free(struct nhg_ctx *ctx)
{
	XFREE(MTYPE_NHG_CTX, ctx);
}

static void nhg_ctx_set_status(struct nhg_ctx *ctx, enum nhg_ctx_result status)
{
	ctx->status = status;
}

static enum nhg_ctx_result nhg_ctx_get_status(const struct nhg_ctx *ctx)
{
	return ctx->status;
}

static void nhg_ctx_set_op(struct nhg_ctx *ctx, enum nhg_ctx_op_e op)
{
	ctx->op = op;
}

static enum nhg_ctx_op_e nhg_ctx_get_op(const struct nhg_ctx *ctx)
{
	return ctx->op;
}

static int nhg_ctx_process_new(struct nhg_ctx *ctx)
{
	struct nexthop_group *nhg = NULL;
	struct nhg_connected_head nhg_depends = {};
	struct nhg_hash_entry *nhe = NULL;

	if (ctx->count) {
		nhg = nexthop_group_new();
		zebra_nhg_process_grp(nhg, &nhg_depends, ctx->u.grp,
				      ctx->count);
		nhe = zebra_nhg_find(ctx->id, nhg, &nhg_depends, ctx->vrf_id,
				     ctx->afi, true);
		/* These got copied over in zebra_nhg_alloc() */
		nexthop_group_free_delete(&nhg);
	} else
		nhe = zebra_nhg_find_nexthop(ctx->id, &ctx->u.nh, ctx->afi,
					     ctx->is_kernel_nh);

	if (nhe) {
		if (ctx->id != nhe->id)
			/* Duplicate but with different ID from
			 * the kernel */

			/* The kernel allows duplicate nexthops
			 * as long as they have different IDs.
			 * We are ignoring those to prevent
			 * syncing problems with the kernel
			 * changes.
			 */
			flog_warn(
				EC_ZEBRA_DUPLICATE_NHG_MESSAGE,
				"Nexthop Group with ID (%d) is a duplicate, ignoring",
				ctx->id);
		else {
			/* It actually created a new nhe */
			if (nhe->is_kernel_nh) {
				SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
				SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			}
		}
	} else {
		flog_err(
			EC_ZEBRA_TABLE_LOOKUP_FAILED,
			"Zebra failed to find or create a nexthop hash entry for ID (%u)",
			ctx->id);
		return -1;
	}

	return 0;
}

static void nhg_ctx_process_finish(struct nhg_ctx *ctx)
{
	/*
	 * Just freeing for now, maybe do something more in the future
	 * based on flag.
	 */

	if (ctx)
		nhg_ctx_free(ctx);
}

int nhg_ctx_process(struct nhg_ctx *ctx)
{
	int ret = 0;

	switch (nhg_ctx_get_op(ctx)) {
	case NHG_CTX_OP_NEW:
		ret = nhg_ctx_process_new(ctx);
		break;
	case NHG_CTX_OP_DEL:
	case NHG_CTX_OP_NONE:
		break;
	}

	nhg_ctx_set_status(ctx, (ret ? NHG_CTX_FAILURE : NHG_CTX_SUCCESS));

	nhg_ctx_process_finish(ctx);

	return ret;
}

static int queue_add(struct nhg_ctx *ctx)
{
	/* If its queued or already processed do nothing */
	if (nhg_ctx_get_status(ctx))
		return 0;

	if (rib_queue_nhg_add(ctx)) {
		nhg_ctx_set_status(ctx, NHG_CTX_FAILURE);
		return -1;
	}

	nhg_ctx_set_status(ctx, NHG_CTX_QUEUED);

	return 0;
}

/* Kernel-side, you either get a single new nexthop or a array of ID's */
int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh, struct nh_grp *grp,
			  uint8_t count, vrf_id_t vrf_id, afi_t afi)
{
	// TODO: Can probably put table lookup
	// here before queueing? And if deleted, re-send to kernel?
	// ... Well, if changing the flags it probably needs to be queued
	// still...

	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_new();

	ctx->id = id;
	ctx->vrf_id = vrf_id;
	ctx->afi = afi;
	ctx->is_kernel_nh = true;
	ctx->count = count;

	if (count)
		/* Copy over the array */
		memcpy(&ctx->u.grp, grp, count * sizeof(struct nh_grp));
	else
		ctx->u.nh = *nh;

	nhg_ctx_set_op(ctx, NHG_CTX_OP_NEW);

	if (queue_add(ctx)) {
		nhg_ctx_process_finish(ctx);
		return -1;
	}

	return 0;
}

/* Rib-side, you get a nexthop group struct */
struct nhg_hash_entry *zebra_nhg_rib_find(uint32_t id,
					  struct nexthop_group *nhg,
					  vrf_id_t rt_vrf_id, afi_t rt_afi)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nhg_connected_head nhg_depends = {};
	// Defualt the nhe to the afi and vrf of the route
	afi_t nhg_afi = rt_afi;
	vrf_id_t nhg_vrf_id = rt_vrf_id;

	/* If its a group, create a dependency list */
	if (nhg && nhg->nexthop->next) {
		struct nexthop *nh = NULL;
		struct nexthop lookup = {0};
		struct nhg_hash_entry *depend = NULL;

		nhg_connected_head_init(&nhg_depends);

		for (ALL_NEXTHOPS_PTR(nhg, nh)) {
			lookup = *nh;
			/* Clear it, since its a group */
			lookup.next = NULL;
			/* Use the route afi here, since a single nh */
			depend = zebra_nhg_find_nexthop(0, &lookup, rt_afi,
							false);
			nhg_connected_head_add(&nhg_depends, depend);
		}

		/* change the afi/vrf_id since its a group */
		nhg_afi = AFI_UNSPEC;
		nhg_vrf_id = 0;
	}

	nhe = zebra_nhg_find(id, nhg, &nhg_depends, nhg_vrf_id, nhg_afi, false);

	return nhe;
}

/**
 * zebra_nhg_free_members() - Free all members in the hash entry struct
 *
 * @nhe: Nexthop group hash entry
 *
 * Just use this to free everything but the entry itself.
 */
void zebra_nhg_free_members(struct nhg_hash_entry *nhe)
{
	nexthop_group_free_delete(&nhe->nhg);
	nhg_connected_head_free(&nhe->nhg_depends);
	nhg_connected_head_free(&nhe->nhg_dependents);
}

/**
 * zebra_nhg_free() - Free the nexthop group hash entry
 *
 * arg:	Nexthop group entry to free
 */
void zebra_nhg_free(void *arg)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = (struct nhg_hash_entry *)arg;

	zebra_nhg_free_members(nhe);

	XFREE(MTYPE_NHG, nhe);
}

/**
 * zebra_nhg_release() - Release a nhe from the tables
 *
 * @nhe:	Nexthop group hash entry
 */
static void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	zlog_debug("Releasing nexthop group with ID (%u)", nhe->id);

	/* Remove it from any lists it may be on */
	zebra_nhg_depends_release(nhe);
	zebra_nhg_dependents_release(nhe);
	if (nhe->ifp)
		if_nhg_dependents_del(nhe->ifp, nhe);

	hash_release(zrouter.nhgs, nhe);
	hash_release(zrouter.nhgs_id, nhe);

	zebra_nhg_free(nhe);
}

/**
 * zebra_nhg_decrement_ref() - Decrement the reference count, release if unused
 *
 * @nhe:	Nexthop group hash entry
 *
 * If the counter hits 0 and is not a nexthop group that was created by the
 * kernel, we don't need to have it in our table anymore.
 */
void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe)
{
	nhe->refcnt--;

	if (!zebra_nhg_depends_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;

		RB_FOREACH (rb_node_dep, nhg_connected_head,
			    &nhe->nhg_depends) {
			zebra_nhg_decrement_ref(rb_node_dep->nhe);
		}
	}

	if (!nhe->is_kernel_nh && nhe->refcnt <= 0)
		zebra_nhg_uninstall_kernel(nhe);
}

/**
 * zebra_nhg_increment_ref() - Increment the reference count
 *
 * @nhe:	Nexthop group hash entry
 */
void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe)
{
	nhe->refcnt++;

	if (!zebra_nhg_depends_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;

		RB_FOREACH (rb_node_dep, nhg_connected_head,
			    &nhe->nhg_depends) {
			zebra_nhg_increment_ref(rb_node_dep->nhe);
		}
	}
}

static bool zebra_nhg_is_valid(struct nhg_hash_entry *nhe)
{
	if (nhe->flags & NEXTHOP_GROUP_VALID)
		return true;

	return false;
}

bool zebra_nhg_id_is_valid(uint32_t id)
{
	struct nhg_hash_entry *nhe = NULL;
	bool is_valid = false;

	nhe = zebra_nhg_lookup_id(id);

	if (nhe)
		is_valid = zebra_nhg_is_valid(nhe);

	return is_valid;
}

void zebra_nhg_set_invalid(struct nhg_hash_entry *nhe)
{
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
	/* Assuming uninstalled as well here */
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);

	if (!zebra_nhg_dependents_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;

		RB_FOREACH (rb_node_dep, nhg_connected_head,
			    &nhe->nhg_dependents) {
			zebra_nhg_set_invalid(rb_node_dep->nhe);
		}
	}
}

void zebra_nhg_set_if(struct nhg_hash_entry *nhe, struct interface *ifp)
{
	nhe->ifp = ifp;
	if_nhg_dependents_add(ifp, nhe);
}

static void nexthop_set_resolved(afi_t afi, const struct nexthop *newhop,
				 struct nexthop *nexthop)
{
	struct nexthop *resolved_hop;
	uint8_t num_labels = 0;
	mpls_label_t labels[MPLS_MAX_LABELS];
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	int i = 0;

	resolved_hop = nexthop_new();
	SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);

	resolved_hop->vrf_id = nexthop->vrf_id;
	switch (newhop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		/* If the resolving route specifies a gateway, use it */
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv4 = newhop->gate.ipv4;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
		}
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		resolved_hop->type = newhop->type;
		resolved_hop->gate.ipv6 = newhop->gate.ipv6;

		if (newhop->ifindex) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->ifindex = newhop->ifindex;
		}
		break;
	case NEXTHOP_TYPE_IFINDEX:
		/* If the resolving route is an interface route,
		 * it means the gateway we are looking up is connected
		 * to that interface. (The actual network is _not_ onlink).
		 * Therefore, the resolved route should have the original
		 * gateway as nexthop as it is directly connected.
		 *
		 * On Linux, we have to set the onlink netlink flag because
		 * otherwise, the kernel won't accept the route.
		 */
		resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;
		if (afi == AFI_IP) {
			resolved_hop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			resolved_hop->gate.ipv4 = nexthop->gate.ipv4;
		} else if (afi == AFI_IP6) {
			resolved_hop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			resolved_hop->gate.ipv6 = nexthop->gate.ipv6;
		}
		resolved_hop->ifindex = newhop->ifindex;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		resolved_hop->type = NEXTHOP_TYPE_BLACKHOLE;
		resolved_hop->bh_type = newhop->bh_type;
		break;
	}

	if (newhop->flags & NEXTHOP_FLAG_ONLINK)
		resolved_hop->flags |= NEXTHOP_FLAG_ONLINK;

	/* Copy labels of the resolved route and the parent resolving to it */
	if (newhop->nh_label) {
		for (i = 0; i < newhop->nh_label->num_labels; i++)
			labels[num_labels++] = newhop->nh_label->label[i];
		label_type = newhop->nh_label_type;
	}

	if (nexthop->nh_label) {
		for (i = 0; i < nexthop->nh_label->num_labels; i++)
			labels[num_labels++] = nexthop->nh_label->label[i];

		/* If the parent has labels, use its type */
		label_type = nexthop->nh_label_type;
	}

	if (num_labels)
		nexthop_add_labels(resolved_hop, label_type, num_labels,
				   labels);

	resolved_hop->rparent = nexthop;
	_nexthop_add(&nexthop->resolved, resolved_hop);
}

/* Checks if nexthop we are trying to resolve to is valid */
static bool nexthop_valid_resolve(const struct nexthop *nexthop,
				  const struct nexthop *resolved)
{
	/* Can't resolve to a recursive nexthop */
	if (CHECK_FLAG(resolved->flags, NEXTHOP_FLAG_RECURSIVE))
		return false;

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* If the nexthop we are resolving to does not match the
		 * ifindex for the nexthop the route wanted, its not valid.
		 */
		if (nexthop->ifindex != resolved->ifindex)
			return false;
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	return true;
}

/*
 * Given a nexthop we need to properly recursively resolve
 * the route.  As such, do a table lookup to find and match
 * if at all possible.  Set the nexthop->ifindex as appropriate
 */
static int nexthop_active(afi_t afi, struct route_entry *re,
			  struct nexthop *nexthop, struct route_node *top)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;
	int resolved;
	struct nexthop *newhop;
	struct interface *ifp;
	rib_dest_t *dest;
	struct zebra_vrf *zvrf;

	if ((nexthop->type == NEXTHOP_TYPE_IPV4)
	    || nexthop->type == NEXTHOP_TYPE_IPV6)
		nexthop->ifindex = 0;

	UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
	nexthops_free(nexthop->resolved);
	nexthop->resolved = NULL;
	re->nexthop_mtu = 0;

	/*
	 * If the kernel has sent us a NEW route, then
	 * by golly gee whiz it's a good route.
	 *
	 * If its an already INSTALLED route we have already handled, then the
	 * kernel route's nexthop might have became unreachable
	 * and we have to handle that.
	 */
	if (!CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)
	    && (re->type == ZEBRA_ROUTE_KERNEL
		|| re->type == ZEBRA_ROUTE_SYSTEM))
		return 1;

	/*
	 * Check to see if we should trust the passed in information
	 * for UNNUMBERED interfaces as that we won't find the GW
	 * address in the routing table.
	 * This check should suffice to handle IPv4 or IPv6 routes
	 * sourced from EVPN routes which are installed with the
	 * next hop as the remote VTEP IP.
	 */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)) {
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (!ifp) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Onlink and interface: %u[%u] does not exist",
					__PRETTY_FUNCTION__, nexthop->ifindex,
					nexthop->vrf_id);
			return 0;
		}
		if (connected_is_unnumbered(ifp)) {
			if (if_is_operative(ifp))
				return 1;
			else {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"\t%s: Onlink and interface %s is not operative",
						__PRETTY_FUNCTION__, ifp->name);
				return 0;
			}
		}
		if (!if_is_operative(ifp)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Interface %s is not unnumbered",
					__PRETTY_FUNCTION__, ifp->name);
			return 0;
		}
	}

	/* Make lookup prefix. */
	memset(&p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_PREFIXLEN;
		p.u.prefix4 = nexthop->gate.ipv4;
		break;
	case AFI_IP6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_PREFIXLEN;
		p.u.prefix6 = nexthop->gate.ipv6;
		break;
	default:
		assert(afi != AFI_IP && afi != AFI_IP6);
		break;
	}
	/* Lookup table.  */
	table = zebra_vrf_table(afi, SAFI_UNICAST, nexthop->vrf_id);
	/* get zvrf */
	zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
	if (!table || !zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: Table not found",
				   __PRETTY_FUNCTION__);
		return 0;
	}

	rn = route_node_match(table, (struct prefix *)&p);
	while (rn) {
		route_unlock_node(rn);

		/* Lookup should halt if we've matched against ourselves ('top',
		 * if specified) - i.e., we cannot have a nexthop NH1 is
		 * resolved by a route NH1. The exception is if the route is a
		 * host route.
		 */
		if (top && rn == top)
			if (((afi == AFI_IP) && (rn->p.prefixlen != 32))
			    || ((afi == AFI_IP6) && (rn->p.prefixlen != 128))) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"\t%s: Matched against ourself and prefix length is not max bit length",
						__PRETTY_FUNCTION__);
				return 0;
			}

		/* Pick up selected route. */
		/* However, do not resolve over default route unless explicitly
		 * allowed. */
		if (is_default_prefix(&rn->p)
		    && !rnh_resolve_via_default(zvrf, p.family)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t:%s: Resolved against default route",
					__PRETTY_FUNCTION__);
			return 0;
		}

		dest = rib_dest_from_rnode(rn);
		if (dest && dest->selected_fib
		    && !CHECK_FLAG(dest->selected_fib->status,
				   ROUTE_ENTRY_REMOVED)
		    && dest->selected_fib->type != ZEBRA_ROUTE_TABLE)
			match = dest->selected_fib;

		/* If there is no selected route or matched route is EGP, go up
		   tree. */
		if (!match) {
			do {
				rn = rn->parent;
			} while (rn && rn->info == NULL);
			if (rn)
				route_lock_node(rn);

			continue;
		}

		if (match->type == ZEBRA_ROUTE_CONNECT) {
			/* Directly point connected route. */
			newhop = match->ng->nexthop;
			if (newhop) {
				if (nexthop->type == NEXTHOP_TYPE_IPV4
				    || nexthop->type == NEXTHOP_TYPE_IPV6)
					nexthop->ifindex = newhop->ifindex;
			}
			return 1;
		} else if (CHECK_FLAG(re->flags, ZEBRA_FLAG_ALLOW_RECURSION)) {
			resolved = 0;
			for (ALL_NEXTHOPS_PTR(match->ng, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}
			if (resolved)
				re->nexthop_mtu = match->mtu;
			if (!resolved && IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("\t%s: Recursion failed to find",
					   __PRETTY_FUNCTION__);
			return resolved;
		} else if (re->type == ZEBRA_ROUTE_STATIC) {
			resolved = 0;
			for (ALL_NEXTHOPS_PTR(match->ng, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}
			if (resolved)
				re->nexthop_mtu = match->mtu;

			if (!resolved && IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Static route unable to resolve",
					__PRETTY_FUNCTION__);
			return resolved;
		} else {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
				zlog_debug(
					"\t%s: Route Type %s has not turned on recursion",
					__PRETTY_FUNCTION__,
					zebra_route_string(re->type));
				if (re->type == ZEBRA_ROUTE_BGP
				    && !CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP))
					zlog_debug(
						"\tEBGP: see \"disable-ebgp-connected-route-check\" or \"disable-connected-check\"");
			}
			return 0;
		}
	}
	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("\t%s: Nexthop did not lookup in table",
			   __PRETTY_FUNCTION__);
	return 0;
}

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. The nexthop->ifindex will be updated
 * appropriately as well.  An existing route map can turn
 * (otherwise active) nexthop into inactive, but not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */
static unsigned nexthop_active_check(struct route_node *rn,
				     struct route_entry *re,
				     struct nexthop *nexthop)
{
	struct interface *ifp;
	route_map_result_t ret = RMAP_PERMITMATCH;
	int family;
	char buf[SRCDEST2STR_BUFFER];
	const struct prefix *p, *src_p;
	struct zebra_vrf *zvrf;

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (rn->p.family == AF_INET)
		family = AFI_IP;
	else if (rn->p.family == AF_INET6)
		family = AFI_IP6;
	else
		family = 0;
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (ifp && if_is_operative(ifp))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		family = AFI_IP;
		if (nexthop_active(AFI_IP, re, nexthop, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6:
		family = AFI_IP6;
		if (nexthop_active(AFI_IP6, re, nexthop, rn))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* RFC 5549, v4 prefix with v6 NH */
		if (rn->p.family != AF_INET)
			family = AFI_IP6;
		if (IN6_IS_ADDR_LINKLOCAL(&nexthop->gate.ipv6)) {
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);
			if (ifp && if_is_operative(ifp))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		} else {
			if (nexthop_active(AFI_IP6, re, nexthop, rn))
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			else
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		}
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	default:
		break;
	}
	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: Unable to find a active nexthop",
				   __PRETTY_FUNCTION__);
		return 0;
	}

	/* XXX: What exactly do those checks do? Do we support
	 * e.g. IPv4 routes with IPv6 nexthops or vice versa?
	 */
	if (RIB_SYSTEM_ROUTE(re) || (family == AFI_IP && p->family != AF_INET)
	    || (family == AFI_IP6 && p->family != AF_INET6))
		return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);

	/* The original code didn't determine the family correctly
	 * e.g. for NEXTHOP_TYPE_IFINDEX. Retrieve the correct afi
	 * from the rib_table_info in those cases.
	 * Possibly it may be better to use only the rib_table_info
	 * in every case.
	 */
	if (!family) {
		rib_table_info_t *info;

		info = srcdest_rnode_table_info(rn);
		family = info->afi;
	}

	memset(&nexthop->rmap_src.ipv6, 0, sizeof(union g_addr));

	zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("\t%s: zvrf is NULL", __PRETTY_FUNCTION__);
		return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	/* It'll get set if required inside */
	ret = zebra_route_map_check(family, re->type, re->instance, p, nexthop,
				    zvrf, re->tag);
	if (ret == RMAP_DENYMATCH) {
		if (IS_ZEBRA_DEBUG_RIB) {
			srcdest_rnode2str(rn, buf, sizeof(buf));
			zlog_debug(
				"%u:%s: Filtering out with NH out %s due to route map",
				re->vrf_id, buf,
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
		}
		UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
	return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/*
 * Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag.  If any nexthop is found to toggle the ACTIVE flag,
 * the whole re structure is flagged with ROUTE_ENTRY_CHANGED.
 *
 * Return value is the new number of active nexthops.
 */
int nexthop_active_update(struct route_node *rn, struct route_entry *re)
{
	struct nexthop *nexthop;
	union g_addr prev_src;
	unsigned int prev_active, new_active;
	ifindex_t prev_index;
	uint8_t curr_active = 0;
	afi_t rt_afi = AFI_UNSPEC;

	// TODO: Temporary until we get this function sorted out
	// a little better.
	//
	if (re->nhe_id) {
		struct nhg_hash_entry *nhe = NULL;

		nhe = zebra_nhg_lookup_id(re->nhe_id);

		if (nhe) {
			if (!re->ng) {
				/* This is its first time getting attached */
				zebra_nhg_increment_ref(nhe);
				re->ng = nhe->nhg;
			}

			if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID)) {
				return 1;
			}
		} else
			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Zebra failed to find the nexthop hash entry for id=%u in a route entry",
				re->nhe_id);
	}

	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	for (nexthop = re->ng->nexthop; nexthop; nexthop = nexthop->next) {
		/* No protocol daemon provides src and so we're skipping
		 * tracking it */
		prev_src = nexthop->rmap_src;
		prev_active = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		prev_index = nexthop->ifindex;
		/*
		 * We need to respect the multipath_num here
		 * as that what we should be able to install from
		 * a multipath perpsective should not be a data plane
		 * decision point.
		 */
		new_active = nexthop_active_check(rn, re, nexthop);
		if (new_active
		    && nexthop_group_active_nexthop_num(re->ng)
			       >= zrouter.multipath_num) {
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			new_active = 0;
		}

		if (new_active)
			curr_active++;

		/* Don't allow src setting on IPv6 addr for now */
		if (prev_active != new_active || prev_index != nexthop->ifindex
		    || ((nexthop->type >= NEXTHOP_TYPE_IFINDEX
			 && nexthop->type < NEXTHOP_TYPE_IPV6)
			&& prev_src.ipv4.s_addr
				   != nexthop->rmap_src.ipv4.s_addr)
		    || ((nexthop->type >= NEXTHOP_TYPE_IPV6
			 && nexthop->type < NEXTHOP_TYPE_BLACKHOLE)
			&& !(IPV6_ADDR_SAME(&prev_src.ipv6,
					    &nexthop->rmap_src.ipv6)))
		    || CHECK_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED))
			SET_FLAG(re->status, ROUTE_ENTRY_CHANGED);
	}

	// TODO: Update this when we have this function
	// figured out a little better.
	//
	struct nhg_hash_entry *new_nhe = NULL;

	rt_afi = family2afi(rn->p.family);
	// TODO: Add proto type here

	// TODO: Maybe make this a UPDATE message?
	// Right now we are just creating a new one
	// and deleting the old.
	new_nhe = zebra_nhg_rib_find(0, re->ng, re->vrf_id, rt_afi);

	if (new_nhe && (re->nhe_id != new_nhe->id)) {
		struct nhg_hash_entry *old_nhe =
			zebra_nhg_lookup_id(re->nhe_id);

		/* It should point to the nhe nexthop group now */
		if (re->ng)
			nexthop_group_free_delete(&re->ng);
		re->ng = new_nhe->nhg;
		re->nhe_id = new_nhe->id;

		zebra_nhg_increment_ref(new_nhe);
		if (old_nhe)
			zebra_nhg_decrement_ref(old_nhe);

		if (curr_active) {
			SET_FLAG(new_nhe->flags, NEXTHOP_GROUP_VALID);
			if (!new_nhe->is_kernel_nh)
				zebra_nhg_install_kernel(new_nhe);
		}
	}

	return curr_active;
}

/**
 * zebra_nhg_install_kernel() - Install Nexthop Group hash entry into kernel
 *
 * @nhe:	Nexthop Group hash entry to install
 */
void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe)
{
	if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)
	    && !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		nhe->is_kernel_nh = false;
		int ret = dplane_nexthop_add(nhe);
		switch (ret) {
		case ZEBRA_DPLANE_REQUEST_QUEUED:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
			break;
		case ZEBRA_DPLANE_REQUEST_FAILURE:
			flog_err(
				EC_ZEBRA_DP_INSTALL_FAIL,
				"Failed to install Nexthop ID (%u) into the kernel",
				nhe->id);
			break;
		case ZEBRA_DPLANE_REQUEST_SUCCESS:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			break;
		}
	}
}

/**
 * zebra_nhg_uninstall_kernel() - Uninstall Nexthop Group hash entry into kernel
 *
 * @nhe:	Nexthop Group hash entry to uninstall
 */
void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe)
{
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)) {
		int ret = dplane_nexthop_delete(nhe);
		switch (ret) {
		case ZEBRA_DPLANE_REQUEST_QUEUED:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
			break;
		case ZEBRA_DPLANE_REQUEST_FAILURE:
			flog_err(
				EC_ZEBRA_DP_DELETE_FAIL,
				"Failed to uninstall Nexthop ID (%u) from the kernel",
				nhe->id);
			break;
		case ZEBRA_DPLANE_REQUEST_SUCCESS:
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			zebra_nhg_release(nhe);
			break;
		}
	} else
		zebra_nhg_release(nhe);
}

/**
 * zebra_nhg_uninstall_created() - Uninstall nexthops we created in the kernel
 *
 * @nhe:	Nexthop group hash entry
 */
static void zebra_nhg_uninstall_created(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = (struct nhg_hash_entry *)bucket->data;

	if (nhe && !nhe->is_kernel_nh)
		zebra_nhg_uninstall_kernel(nhe);
}

/**
 * zebra_nhg_cleanup_tables() - Iterate over our tables to uninstall nh's
 * 				we created
 */
void zebra_nhg_cleanup_tables(void)
{
	hash_iterate(zrouter.nhgs, zebra_nhg_uninstall_created, NULL);
}

/**
 * zebra_nhg_dplane_result() - Process dplane result
 *
 * @ctx:	Dataplane context
 */
void zebra_nhg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum zebra_dplane_result status;
	uint32_t id = 0;
	struct nhg_hash_entry *nhe = NULL;

	op = dplane_ctx_get_op(ctx);
	status = dplane_ctx_get_status(ctx);

	id = dplane_ctx_get_nhe_id(ctx);

	nhe = zebra_nhg_lookup_id(id);

	if (nhe) {
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
		if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
			zlog_debug(
				"Nexthop dplane ctx %p, op %s, nexthop ID (%u), result %s",
				ctx, dplane_op2str(op), nhe->id,
				dplane_res2str(status));

		switch (op) {
		case DPLANE_OP_NH_DELETE:
			if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
				UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
				zebra_nhg_release(nhe);
			} else {
				flog_err(
					EC_ZEBRA_DP_DELETE_FAIL,
					"Failed to uninstall Nexthop ID (%u) from the kernel",
					nhe->id);
			}
			break;
		case DPLANE_OP_NH_INSTALL:
		case DPLANE_OP_NH_UPDATE:
			if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
				SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			} else {
				flog_err(
					EC_ZEBRA_DP_INSTALL_FAIL,
					"Failed to install Nexthop ID (%u) into the kernel",
					nhe->id);
				UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			}
			break;
		case DPLANE_OP_ROUTE_INSTALL:
		case DPLANE_OP_ROUTE_UPDATE:
		case DPLANE_OP_ROUTE_DELETE:
		case DPLANE_OP_ROUTE_NOTIFY:
		case DPLANE_OP_LSP_INSTALL:
		case DPLANE_OP_LSP_UPDATE:
		case DPLANE_OP_LSP_DELETE:
		case DPLANE_OP_LSP_NOTIFY:
		case DPLANE_OP_PW_INSTALL:
		case DPLANE_OP_PW_UNINSTALL:
		case DPLANE_OP_SYS_ROUTE_ADD:
		case DPLANE_OP_SYS_ROUTE_DELETE:
		case DPLANE_OP_ADDR_INSTALL:
		case DPLANE_OP_ADDR_UNINSTALL:
		case DPLANE_OP_MAC_INSTALL:
		case DPLANE_OP_MAC_DELETE:
		case DPLANE_OP_NONE:
			break;
		}
	} else
		flog_err(
			EC_ZEBRA_NHG_SYNC,
			"%s operation preformed on Nexthop ID (%u) in the kernel, that we no longer have in our table",
			dplane_op2str(op), id);

	dplane_ctx_fini(&ctx);
}

