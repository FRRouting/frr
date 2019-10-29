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
#include "zebra/zebra_nhg_private.h"
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

/* id counter to keep in sync with kernel */
uint32_t id_counter;

static struct nhg_hash_entry *depends_find(struct nexthop *nh, afi_t afi);
static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend);
static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi);
static struct nhg_hash_entry *
depends_find_id_add(struct nhg_connected_tree_head *head, uint32_t id);
static void depends_decrement_free(struct nhg_connected_tree_head *head);


static void nhg_connected_free(struct nhg_connected *dep)
{
	XFREE(MTYPE_NHG_CONNECTED, dep);
}

static struct nhg_connected *nhg_connected_new(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *new = NULL;

	new = XCALLOC(MTYPE_NHG_CONNECTED, sizeof(struct nhg_connected));
	new->nhe = nhe;

	return new;
}

void nhg_connected_tree_free(struct nhg_connected_tree_head *head)
{
	struct nhg_connected *rb_node_dep = NULL;

	if (!nhg_connected_tree_is_empty(head)) {
		frr_each_safe(nhg_connected_tree, head, rb_node_dep) {
			nhg_connected_tree_del(head, rb_node_dep);
			nhg_connected_free(rb_node_dep);
		}
	}
}

bool nhg_connected_tree_is_empty(const struct nhg_connected_tree_head *head)
{
	return nhg_connected_tree_count(head) ? false : true;
}

struct nhg_connected *
nhg_connected_tree_root(struct nhg_connected_tree_head *head)
{
	return nhg_connected_tree_first(head);
}

void nhg_connected_tree_del_nhe(struct nhg_connected_tree_head *head,
				struct nhg_hash_entry *depend)
{
	struct nhg_connected lookup = {};
	struct nhg_connected *remove = NULL;

	lookup.nhe = depend;

	/* Lookup to find the element, then remove it */
	remove = nhg_connected_tree_find(head, &lookup);
	remove = nhg_connected_tree_del(head, remove);

	if (remove)
		nhg_connected_free(remove);
}

void nhg_connected_tree_add_nhe(struct nhg_connected_tree_head *head,
				struct nhg_hash_entry *depend)
{
	struct nhg_connected *new = NULL;

	new = nhg_connected_new(depend);

	if (new)
		nhg_connected_tree_add(head, new);
}

static void
nhg_connected_tree_decrement_ref(struct nhg_connected_tree_head *head)
{
	struct nhg_connected *rb_node_dep = NULL;

	frr_each_safe(nhg_connected_tree, head, rb_node_dep) {
		zebra_nhg_decrement_ref(rb_node_dep->nhe);
	}
}

static void
nhg_connected_tree_increment_ref(struct nhg_connected_tree_head *head)
{
	struct nhg_connected *rb_node_dep = NULL;

	frr_each(nhg_connected_tree, head, rb_node_dep) {
		zebra_nhg_increment_ref(rb_node_dep->nhe);
	}
}

struct nhg_hash_entry *zebra_nhg_resolve(struct nhg_hash_entry *nhe)
{
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_RECURSIVE)
	    && !zebra_nhg_depends_is_empty(nhe)) {
		nhe = nhg_connected_tree_root(&nhe->nhg_depends)->nhe;
		return zebra_nhg_resolve(nhe);
	}

	return nhe;
}

unsigned int zebra_nhg_depends_count(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_tree_count(&nhe->nhg_depends);
}

bool zebra_nhg_depends_is_empty(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_tree_is_empty(&nhe->nhg_depends);
}

static void zebra_nhg_depends_del(struct nhg_hash_entry *from,
				  struct nhg_hash_entry *depend)
{
	nhg_connected_tree_del_nhe(&from->nhg_depends, depend);
}

static void zebra_nhg_depends_init(struct nhg_hash_entry *nhe)
{
	nhg_connected_tree_init(&nhe->nhg_depends);
}

unsigned int zebra_nhg_dependents_count(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_tree_count(&nhe->nhg_dependents);
}


bool zebra_nhg_dependents_is_empty(const struct nhg_hash_entry *nhe)
{
	return nhg_connected_tree_is_empty(&nhe->nhg_dependents);
}

static void zebra_nhg_dependents_del(struct nhg_hash_entry *from,
				     struct nhg_hash_entry *dependent)
{
	nhg_connected_tree_del_nhe(&from->nhg_dependents, dependent);
}

static void zebra_nhg_dependents_add(struct nhg_hash_entry *to,
				     struct nhg_hash_entry *dependent)
{
	nhg_connected_tree_add_nhe(&to->nhg_dependents, dependent);
}

static void zebra_nhg_dependents_init(struct nhg_hash_entry *nhe)
{
	nhg_connected_tree_init(&nhe->nhg_dependents);
}

/* Release this nhe from anything depending on it */
static void zebra_nhg_dependents_release(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;

	frr_each_safe(nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep) {
		zebra_nhg_depends_del(rb_node_dep->nhe, nhe);
		/* recheck validity of the dependent */
		zebra_nhg_check_valid(rb_node_dep->nhe);
	}
}

/* Release this nhe from anything that it depends on */
static void zebra_nhg_depends_release(struct nhg_hash_entry *nhe)
{
	if (!zebra_nhg_depends_is_empty(nhe)) {
		struct nhg_connected *rb_node_dep = NULL;

		frr_each_safe(nhg_connected_tree, &nhe->nhg_depends,
			       rb_node_dep) {
			zebra_nhg_dependents_del(rb_node_dep->nhe, nhe);
		}
	}
}


struct nhg_hash_entry *zebra_nhg_lookup_id(uint32_t id)
{
	struct nhg_hash_entry lookup = {};

	lookup.id = id;
	return hash_lookup(zrouter.nhgs_id, &lookup);
}

static int zebra_nhg_insert_id(struct nhg_hash_entry *nhe)
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

static void zebra_nhg_set_if(struct nhg_hash_entry *nhe, struct interface *ifp)
{
	nhe->ifp = ifp;
	if_nhg_dependents_add(ifp, nhe);
}

static void
zebra_nhg_connect_depends(struct nhg_hash_entry *nhe,
			  struct nhg_connected_tree_head nhg_depends)
{
	struct nhg_connected *rb_node_dep = NULL;

	/* This has been allocated higher above in the stack. Could probably
	 * re-allocate and free the old stuff but just using the same memory
	 * for now. Otherwise, their might be a time trade-off for repeated
	 * alloc/frees as startup.
	 */
	nhe->nhg_depends = nhg_depends;

	/* Attach backpointer to anything that it depends on */
	zebra_nhg_dependents_init(nhe);
	if (!zebra_nhg_depends_is_empty(nhe)) {
		frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
			zebra_nhg_dependents_add(rb_node_dep->nhe, nhe);
		}
	}

	/* Add the ifp now if its not a group or recursive and has ifindex */
	if (zebra_nhg_depends_is_empty(nhe) && nhe->nhg->nexthop
	    && nhe->nhg->nexthop->ifindex) {
		struct interface *ifp = NULL;

		ifp = if_lookup_by_index(nhe->nhg->nexthop->ifindex,
					 nhe->vrf_id);
		if (ifp)
			zebra_nhg_set_if(nhe, ifp);
		else
			flog_err(
				EC_ZEBRA_IF_LOOKUP_FAILED,
				"Zebra failed to lookup an interface with ifindex=%d in vrf=%u for NHE id=%u",
				nhe->nhg->nexthop->ifindex, nhe->vrf_id,
				nhe->id);
	}
}

static struct nhg_hash_entry *zebra_nhg_copy(struct nhg_hash_entry *copy,
					     uint32_t id)
{
	struct nhg_hash_entry *nhe;

	nhe = XCALLOC(MTYPE_NHG, sizeof(struct nhg_hash_entry));

	nhe->id = id;

	nhe->nhg = nexthop_group_new();
	nexthop_group_copy(nhe->nhg, copy->nhg);

	nhe->vrf_id = copy->vrf_id;
	nhe->afi = copy->afi;
	nhe->type = copy->type ? copy->type : ZEBRA_ROUTE_NHG;
	nhe->refcnt = 0;
	nhe->dplane_ref = zebra_router_get_next_sequence();

	return nhe;
}

/* Allocation via hash handler */
static void *zebra_nhg_hash_alloc(void *arg)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nhg_hash_entry *copy = arg;

	nhe = zebra_nhg_copy(copy, copy->id);

	/* Mark duplicate nexthops in a group at creation time. */
	nexthop_group_mark_duplicates(nhe->nhg);

	zebra_nhg_connect_depends(nhe, copy->nhg_depends);
	zebra_nhg_insert_id(nhe);

	return nhe;
}

uint32_t zebra_nhg_hash_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;

	uint32_t key = 0x5a351234;

	key = jhash_3words(nhe->vrf_id, nhe->afi, nexthop_group_hash(nhe->nhg),
			   key);

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

	/* No matter what if they equal IDs, assume equal */
	if (nhe1->id && nhe2->id && (nhe1->id == nhe2->id))
		return true;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	if (nexthop_group_active_nexthop_num_no_recurse(nhe1->nhg)
	    != nexthop_group_active_nexthop_num_no_recurse(nhe2->nhg))
		return false;

	if (!nexthop_group_equal_no_recurse(nhe1->nhg, nhe2->nhg))
		return false;

	return true;
}

bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;

	return nhe1->id == nhe2->id;
}

static int zebra_nhg_process_grp(struct nexthop_group *nhg,
				 struct nhg_connected_tree_head *depends,
				 struct nh_grp *grp, uint8_t count)
{
	nhg_connected_tree_init(depends);

	for (int i = 0; i < count; i++) {
		struct nhg_hash_entry *depend = NULL;
		/* We do not care about nexthop_grp.weight at
		 * this time. But we should figure out
		 * how to adapt this to our code in
		 * the future.
		 */
		depend = depends_find_id_add(depends, grp[i].id);

		if (!depend) {
			flog_err(
				EC_ZEBRA_NHG_SYNC,
				"Received Nexthop Group from the kernel with a dependent Nexthop ID (%u) which we do not have in our table",
				grp[i].id);
			return -1;
		}

		/*
		 * If this is a nexthop with its own group
		 * dependencies, add them as well. Not sure its
		 * even possible to have a group within a group
		 * in the kernel.
		 */

		copy_nexthops(&nhg->nexthop, depend->nhg->nexthop, NULL);
	}

	return 0;
}

static void handle_recursive_depend(struct nhg_connected_tree_head *nhg_depends,
				    struct nexthop *nh, afi_t afi)
{
	struct nhg_hash_entry *depend = NULL;
	struct nexthop_group resolved_ng = {};

	_nexthop_group_add_sorted(&resolved_ng, nh);

	depend = zebra_nhg_rib_find(0, &resolved_ng, afi);
	depends_add(nhg_depends, depend);
}

static bool zebra_nhg_find(struct nhg_hash_entry **nhe, uint32_t id,
			   struct nexthop_group *nhg,
			   struct nhg_connected_tree_head *nhg_depends,
			   vrf_id_t vrf_id, afi_t afi, int type)
{
	struct nhg_hash_entry lookup = {};

	uint32_t old_id_counter = id_counter;

	bool created = false;
	bool recursive = false;

	/*
	 * If it has an id at this point, we must have gotten it from the kernel
	 */
	lookup.id = id ? id : ++id_counter;

	lookup.type = type ? type : ZEBRA_ROUTE_NHG;
	lookup.nhg = nhg;

	if (lookup.nhg->nexthop->next) {
		/* Groups can have all vrfs and AF's in them */
		lookup.afi = AFI_UNSPEC;
		lookup.vrf_id = 0;
	} else {
		switch (lookup.nhg->nexthop->type) {
		case (NEXTHOP_TYPE_IFINDEX):
		case (NEXTHOP_TYPE_BLACKHOLE):
			/*
			 * This switch case handles setting the afi different
			 * for ipv4/v6 routes. Ifindex/blackhole nexthop
			 * objects cannot be ambiguous, they must be Address
			 * Family specific. If we get here, we will either use
			 * the AF of the route, or the one we got passed from
			 * here from the kernel.
			 */
			lookup.afi = afi;
			break;
		case (NEXTHOP_TYPE_IPV4_IFINDEX):
		case (NEXTHOP_TYPE_IPV4):
			lookup.afi = AFI_IP;
			break;
		case (NEXTHOP_TYPE_IPV6_IFINDEX):
		case (NEXTHOP_TYPE_IPV6):
			lookup.afi = AFI_IP6;
			break;
		}

		lookup.vrf_id = vrf_id;
	}

	if (id)
		(*nhe) = zebra_nhg_lookup_id(id);
	else
		(*nhe) = hash_lookup(zrouter.nhgs, &lookup);

	/* If it found an nhe in our tables, this new ID is unused */
	if (*nhe)
		id_counter = old_id_counter;

	if (!(*nhe)) {
		/* Only hash/lookup the depends if the first lookup
		 * fails to find something. This should hopefully save a
		 * lot of cycles for larger ecmp sizes.
		 */
		if (nhg_depends)
			/* If you don't want to hash on each nexthop in the
			 * nexthop group struct you can pass the depends
			 * directly. Kernel-side we do this since it just looks
			 * them up via IDs.
			 */
			lookup.nhg_depends = *nhg_depends;
		else {
			if (nhg->nexthop->next) {
				zebra_nhg_depends_init(&lookup);

				/* If its a group, create a dependency tree */
				struct nexthop *nh = NULL;

				for (nh = nhg->nexthop; nh; nh = nh->next)
					depends_find_add(&lookup.nhg_depends,
							 nh, afi);
			} else if (CHECK_FLAG(nhg->nexthop->flags,
					      NEXTHOP_FLAG_RECURSIVE)) {
				zebra_nhg_depends_init(&lookup);
				handle_recursive_depend(&lookup.nhg_depends,
							nhg->nexthop->resolved,
							afi);
				recursive = true;
			}
		}

		(*nhe) = hash_get(zrouter.nhgs, &lookup, zebra_nhg_hash_alloc);
		created = true;

		if (recursive)
			SET_FLAG((*nhe)->flags, NEXTHOP_GROUP_RECURSIVE);
	}
	return created;
}

/* Find/create a single nexthop */
static struct nhg_hash_entry *
zebra_nhg_find_nexthop(uint32_t id, struct nexthop *nh, afi_t afi, int type)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nexthop_group nhg = {};

	_nexthop_group_add_sorted(&nhg, nh);

	zebra_nhg_find(&nhe, id, &nhg, NULL, nh->vrf_id, afi, 0);

	return nhe;
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

static uint32_t nhg_ctx_get_id(const struct nhg_ctx *ctx)
{
	return ctx->id;
}

static void nhg_ctx_set_status(struct nhg_ctx *ctx, enum nhg_ctx_status status)
{
	ctx->status = status;
}

static enum nhg_ctx_status nhg_ctx_get_status(const struct nhg_ctx *ctx)
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

static vrf_id_t nhg_ctx_get_vrf_id(const struct nhg_ctx *ctx)
{
	return ctx->vrf_id;
}

static int nhg_ctx_get_type(const struct nhg_ctx *ctx)
{
	return ctx->type;
}

static int nhg_ctx_get_afi(const struct nhg_ctx *ctx)
{
	return ctx->afi;
}

static struct nexthop *nhg_ctx_get_nh(struct nhg_ctx *ctx)
{
	return &ctx->u.nh;
}

static uint8_t nhg_ctx_get_count(const struct nhg_ctx *ctx)
{
	return ctx->count;
}

static struct nh_grp *nhg_ctx_get_grp(struct nhg_ctx *ctx)
{
	return ctx->u.grp;
}

static struct nhg_ctx *nhg_ctx_init(uint32_t id, struct nexthop *nh,
				    struct nh_grp *grp, vrf_id_t vrf_id,
				    afi_t afi, int type, uint8_t count)
{
	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_new();

	ctx->id = id;
	ctx->vrf_id = vrf_id;
	ctx->afi = afi;
	ctx->type = type;
	ctx->count = count;

	if (count)
		/* Copy over the array */
		memcpy(&ctx->u.grp, grp, count * sizeof(struct nh_grp));
	else if (nh)
		ctx->u.nh = *nh;

	return ctx;
}

static bool zebra_nhg_contains_unhashable(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;

	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		if (CHECK_FLAG(rb_node_dep->nhe->flags,
			       NEXTHOP_GROUP_UNHASHABLE))
			return true;
	}

	return false;
}

static void zebra_nhg_set_unhashable(struct nhg_hash_entry *nhe)
{
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_UNHASHABLE);
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);

	flog_warn(
		EC_ZEBRA_DUPLICATE_NHG_MESSAGE,
		"Nexthop Group with ID (%d) is a duplicate, therefore unhashable, ignoring",
		nhe->id);
}

static void zebra_nhg_set_valid(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep;

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);

	frr_each(nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep)
		zebra_nhg_set_valid(rb_node_dep->nhe);
}

static void zebra_nhg_set_invalid(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep;

	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);

	/* Update validity of nexthops depending on it */
	frr_each(nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep)
		zebra_nhg_check_valid(rb_node_dep->nhe);
}

void zebra_nhg_check_valid(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;
	bool valid = false;

	/* If anthing else in the group is valid, the group is valid */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		if (CHECK_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_VALID)) {
			valid = true;
			goto done;
		}
	}

done:
	if (valid)
		zebra_nhg_set_valid(nhe);
	else
		zebra_nhg_set_invalid(nhe);
}


static void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	/* Remove it from any lists it may be on */
	zebra_nhg_depends_release(nhe);
	zebra_nhg_dependents_release(nhe);
	if (nhe->ifp)
		if_nhg_dependents_del(nhe->ifp, nhe);

	/*
	 * If its unhashable, we didn't store it here and have to be
	 * sure we don't clear one thats actually being used.
	 */
	if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_UNHASHABLE))
		hash_release(zrouter.nhgs, nhe);

	hash_release(zrouter.nhgs_id, nhe);
}

static void zebra_nhg_handle_uninstall(struct nhg_hash_entry *nhe)
{
	zebra_nhg_release(nhe);
	zebra_nhg_free(nhe);
}

static void zebra_nhg_handle_install(struct nhg_hash_entry *nhe)
{
	/* Update validity of groups depending on it */
	struct nhg_connected *rb_node_dep;

	frr_each_safe(nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep)
		zebra_nhg_set_valid(rb_node_dep->nhe);
}

/*
 * The kernel/other program has changed the state of a nexthop object we are
 * using.
 */
static void zebra_nhg_handle_kernel_state_change(struct nhg_hash_entry *nhe,
						 bool is_delete)
{
	if (nhe->refcnt) {
		flog_err(
			EC_ZEBRA_NHG_SYNC,
			"Kernel %s a nexthop group with ID (%u) that we are still using for a route, sending it back down",
			(is_delete ? "deleted" : "updated"), nhe->id);

		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
		zebra_nhg_install_kernel(nhe);
	} else
		zebra_nhg_handle_uninstall(nhe);
}

static int nhg_ctx_process_new(struct nhg_ctx *ctx)
{
	struct nexthop_group *nhg = NULL;
	struct nhg_connected_tree_head nhg_depends = {};
	struct nhg_hash_entry *lookup = NULL;
	struct nhg_hash_entry *nhe = NULL;

	uint32_t id = nhg_ctx_get_id(ctx);
	uint8_t count = nhg_ctx_get_count(ctx);
	vrf_id_t vrf_id = nhg_ctx_get_vrf_id(ctx);
	int type = nhg_ctx_get_type(ctx);
	afi_t afi = nhg_ctx_get_afi(ctx);

	lookup = zebra_nhg_lookup_id(id);

	if (lookup) {
		/* This is already present in our table, hence an update
		 * that we did not initate.
		 */
		zebra_nhg_handle_kernel_state_change(lookup, false);
		return 0;
	}

	if (nhg_ctx_get_count(ctx)) {
		nhg = nexthop_group_new();
		if (zebra_nhg_process_grp(nhg, &nhg_depends,
					  nhg_ctx_get_grp(ctx), count)) {
			depends_decrement_free(&nhg_depends);
			nexthop_group_delete(&nhg);
			return -ENOENT;
		}

		if (!zebra_nhg_find(&nhe, id, nhg, &nhg_depends, vrf_id, type,
				    afi))
			depends_decrement_free(&nhg_depends);

		/* These got copied over in zebra_nhg_alloc() */
		nexthop_group_delete(&nhg);
	} else
		nhe = zebra_nhg_find_nexthop(id, nhg_ctx_get_nh(ctx), afi,
					     type);

	if (nhe) {
		if (id != nhe->id) {
			struct nhg_hash_entry *kernel_nhe = NULL;

			/* Duplicate but with different ID from
			 * the kernel
			 */

			/* The kernel allows duplicate nexthops
			 * as long as they have different IDs.
			 * We are ignoring those to prevent
			 * syncing problems with the kernel
			 * changes.
			 *
			 * We maintain them *ONLY* in the ID hash table to
			 * track them and set the flag to indicated
			 * their attributes are unhashable.
			 */

			kernel_nhe = zebra_nhg_copy(nhe, id);
			zebra_nhg_insert_id(kernel_nhe);
			zebra_nhg_set_unhashable(kernel_nhe);
		} else if (zebra_nhg_contains_unhashable(nhe)) {
			/* The group we got contains an unhashable/duplicated
			 * depend, so lets mark this group as unhashable as well
			 * and release it from the non-ID hash.
			 */
			hash_release(zrouter.nhgs, nhe);
			zebra_nhg_set_unhashable(nhe);
		} else {
			/* It actually created a new nhe */
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
		}
	} else {
		flog_err(
			EC_ZEBRA_TABLE_LOOKUP_FAILED,
			"Zebra failed to find or create a nexthop hash entry for ID (%u)",
			id);
		return -1;
	}

	return 0;
}

static int nhg_ctx_process_del(struct nhg_ctx *ctx)
{
	struct nhg_hash_entry *nhe = NULL;
	uint32_t id = nhg_ctx_get_id(ctx);

	nhe = zebra_nhg_lookup_id(id);

	if (!nhe) {
		flog_warn(
			EC_ZEBRA_BAD_NHG_MESSAGE,
			"Kernel delete message received for nexthop group ID (%u) that we do not have in our ID table",
			id);
		return -1;
	}

	zebra_nhg_handle_kernel_state_change(nhe, true);

	return 0;
}

static void nhg_ctx_process_finish(struct nhg_ctx *ctx)
{
	struct nexthop *nh;

	/*
	 * Just freeing for now, maybe do something more in the future
	 * based on flag.
	 */

	if (nhg_ctx_get_count(ctx))
		goto done;

	nh = nhg_ctx_get_nh(ctx);

	nexthop_del_labels(nh);

done:
	nhg_ctx_free(ctx);
}

static int queue_add(struct nhg_ctx *ctx)
{
	/* If its queued or already processed do nothing */
	if (nhg_ctx_get_status(ctx) == NHG_CTX_QUEUED)
		return 0;

	if (rib_queue_nhg_add(ctx)) {
		nhg_ctx_set_status(ctx, NHG_CTX_FAILURE);
		return -1;
	}

	nhg_ctx_set_status(ctx, NHG_CTX_QUEUED);

	return 0;
}

int nhg_ctx_process(struct nhg_ctx *ctx)
{
	int ret = 0;

	switch (nhg_ctx_get_op(ctx)) {
	case NHG_CTX_OP_NEW:
		ret = nhg_ctx_process_new(ctx);
		if (nhg_ctx_get_count(ctx) && ret == -ENOENT
		    && nhg_ctx_get_status(ctx) != NHG_CTX_REQUEUED) {
			/**
			 * We have entered a situation where we are
			 * processing a group from the kernel
			 * that has a contained nexthop which
			 * we have not yet processed.
			 *
			 * Re-enqueue this ctx to be handled exactly one
			 * more time (indicated by the flag).
			 *
			 * By the time we get back to it, we
			 * should have processed its depends.
			 */
			nhg_ctx_set_status(ctx, NHG_CTX_NONE);
			if (queue_add(ctx) == 0) {
				nhg_ctx_set_status(ctx, NHG_CTX_REQUEUED);
				return 0;
			}
		}
		break;
	case NHG_CTX_OP_DEL:
		ret = nhg_ctx_process_del(ctx);
	case NHG_CTX_OP_NONE:
		break;
	}

	nhg_ctx_set_status(ctx, (ret ? NHG_CTX_FAILURE : NHG_CTX_SUCCESS));

	nhg_ctx_process_finish(ctx);

	return ret;
}

/* Kernel-side, you either get a single new nexthop or a array of ID's */
int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh, struct nh_grp *grp,
			  uint8_t count, vrf_id_t vrf_id, afi_t afi, int type,
			  int startup)
{
	struct nhg_ctx *ctx = NULL;

	if (id > id_counter)
		/* Increase our counter so we don't try to create
		 * an ID that already exists
		 */
		id_counter = id;

	ctx = nhg_ctx_init(id, nh, grp, vrf_id, afi, type, count);
	nhg_ctx_set_op(ctx, NHG_CTX_OP_NEW);

	/* Under statup conditions, we need to handle them immediately
	 * like we do for routes. Otherwise, we are going to get a route
	 * with a nhe_id that we have not handled.
	 */
	if (startup)
		return nhg_ctx_process(ctx);

	if (queue_add(ctx)) {
		nhg_ctx_process_finish(ctx);
		return -1;
	}

	return 0;
}

/* Kernel-side, received delete message */
int zebra_nhg_kernel_del(uint32_t id)
{
	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_init(id, NULL, NULL, 0, 0, 0, 0);

	nhg_ctx_set_op(ctx, NHG_CTX_OP_DEL);

	if (queue_add(ctx)) {
		nhg_ctx_process_finish(ctx);
		return -1;
	}

	return 0;
}

/* Some dependency helper functions */
static struct nhg_hash_entry *depends_find(struct nexthop *nh, afi_t afi)
{
	struct nexthop *lookup = NULL;
	struct nhg_hash_entry *nhe = NULL;

	copy_nexthops(&lookup, nh, NULL);

	/* Clear it, in case its a group */
	nexthops_free(lookup->next);
	nexthops_free(lookup->prev);
	lookup->next = NULL;
	lookup->prev = NULL;

	nhe = zebra_nhg_find_nexthop(0, lookup, afi, 0);

	nexthops_free(lookup);

	return nhe;
}

static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend)
{
	nhg_connected_tree_add_nhe(head, depend);
	zebra_nhg_increment_ref(depend);
}

static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi)
{
	struct nhg_hash_entry *depend = NULL;

	depend = depends_find(nh, afi);

	if (depend)
		depends_add(head, depend);

	return depend;
}

static struct nhg_hash_entry *
depends_find_id_add(struct nhg_connected_tree_head *head, uint32_t id)
{
	struct nhg_hash_entry *depend = NULL;

	depend = zebra_nhg_lookup_id(id);

	if (depend)
		depends_add(head, depend);

	return depend;
}

static void depends_decrement_free(struct nhg_connected_tree_head *head)
{
	nhg_connected_tree_decrement_ref(head);
	nhg_connected_tree_free(head);
}

/* Rib-side, you get a nexthop group struct */
struct nhg_hash_entry *
zebra_nhg_rib_find(uint32_t id, struct nexthop_group *nhg, afi_t rt_afi)
{
	struct nhg_hash_entry *nhe = NULL;

	if (!(nhg && nhg->nexthop)) {
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "No nexthop passed to %s", __func__);
		return NULL;
	}

	zebra_nhg_find(&nhe, id, nhg, NULL, nhg->nexthop->vrf_id, rt_afi, 0);

	return nhe;
}

static void zebra_nhg_free_members(struct nhg_hash_entry *nhe)
{
	nexthop_group_delete(&nhe->nhg);
	/* Decrement to remove connection ref */
	nhg_connected_tree_decrement_ref(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_dependents);
}

void zebra_nhg_free(void *arg)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = (struct nhg_hash_entry *)arg;

	if (nhe->refcnt)
		zlog_debug("nhe_id=%u hash refcnt=%d", nhe->id, nhe->refcnt);

	zebra_nhg_free_members(nhe);

	XFREE(MTYPE_NHG, nhe);
}

void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe)
{
	nhe->refcnt--;

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_decrement_ref(&nhe->nhg_depends);

	if (ZEBRA_NHG_CREATED(nhe) && nhe->refcnt <= 0)
		zebra_nhg_uninstall_kernel(nhe);
}

void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe)
{
	nhe->refcnt++;

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_increment_ref(&nhe->nhg_depends);
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
 * if at all possible.  Set the nexthop->ifindex and resolved_id
 * as appropriate
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

			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"\t%s: Onlink and interface %s is not operative",
					__PRETTY_FUNCTION__, ifp->name);
			return 0;
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
		 * allowed.
		 */
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
		 * tree.
		 */
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
 * If it finds a nexthop recursivedly, set the resolved_id
 * to match that nexthop's nhg_hash_entry ID;
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
	struct nexthop_group new_grp = {};
	struct nexthop *nexthop;
	union g_addr prev_src;
	unsigned int prev_active, new_active;
	ifindex_t prev_index;
	uint8_t curr_active = 0;

	afi_t rt_afi = family2afi(rn->p.family);

	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	/* Copy over the nexthops in current state */
	nexthop_group_copy(&new_grp, re->ng);

	for (nexthop = new_grp.nexthop; nexthop; nexthop = nexthop->next) {

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
		new_active =
			nexthop_active_check(rn, re, nexthop);

		if (new_active
		    && nexthop_group_active_nexthop_num(&new_grp)
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

	if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
		struct nhg_hash_entry *new_nhe = NULL;

		new_nhe = zebra_nhg_rib_find(0, &new_grp, rt_afi);

		zebra_nhg_re_update_ref(re, new_nhe);
	}

	if (curr_active) {
		struct nhg_hash_entry *nhe = NULL;

		nhe = zebra_nhg_lookup_id(re->nhe_id);

		if (nhe)
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
		else
			flog_err(
				EC_ZEBRA_TABLE_LOOKUP_FAILED,
				"Active update on NHE id=%u that we do not have in our tables",
				re->nhe_id);
	}

	/*
	 * Do not need these nexthops anymore since they
	 * were either copied over into an nhe or not
	 * used at all.
	 */
	nexthops_free(new_grp.nexthop);
	return curr_active;
}

static void zebra_nhg_re_attach_ref(struct route_entry *re,
				    struct nhg_hash_entry *new)
{
	re->ng = new->nhg;
	re->nhe_id = new->id;

	zebra_nhg_increment_ref(new);
}

int zebra_nhg_re_update_ref(struct route_entry *re, struct nhg_hash_entry *new)
{
	struct nhg_hash_entry *old = NULL;
	int ret = 0;

	if (new == NULL) {
		re->ng = NULL;
		goto done;
	}

	if (re->nhe_id != new->id) {
		old = zebra_nhg_lookup_id(re->nhe_id);

		zebra_nhg_re_attach_ref(re, new);

		if (old)
			zebra_nhg_decrement_ref(old);
	} else if (!re->ng)
		/* This is the first time it's being attached */
		zebra_nhg_re_attach_ref(re, new);

done:
	return ret;
}

/* Convert a nhe into a group array */
uint8_t zebra_nhg_nhe2grp(struct nh_grp *grp, struct nhg_hash_entry *nhe,
			  int max_num)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct nhg_hash_entry *depend = NULL;
	uint8_t i = 0;

	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		bool duplicate = false;

		depend = rb_node_dep->nhe;

		/*
		 * If its recursive, use its resolved nhe in the group
		 */
		if (CHECK_FLAG(depend->flags, NEXTHOP_GROUP_RECURSIVE)) {
			depend = zebra_nhg_resolve(depend);
			if (!depend) {
				flog_err(
					EC_ZEBRA_NHG_FIB_UPDATE,
					"Failed to recursively resolve Nexthop Hash Entry in the group id=%u",
					nhe->id);
				continue;
			}
		}

		/* Check for duplicate IDs, kernel doesn't like that */
		for (int j = 0; j < i; j++) {
			if (depend->id == grp[j].id)
				duplicate = true;
		}

		if (!duplicate) {
			grp[i].id = depend->id;
			/* We aren't using weights for anything right now */
			grp[i].weight = 0;
			i++;
		}

		if (i >= max_num)
			goto done;
	}

done:
	return i;
}

void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;

	/* Resolve it first */
	nhe = zebra_nhg_resolve(nhe);

	/* Make sure all depends are installed/queued */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		zebra_nhg_install_kernel(rb_node_dep->nhe);
	}

	if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)
	    && !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		/* Change its type to us since we are installing it */
		nhe->type = ZEBRA_ROUTE_NHG;

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
			zebra_nhg_handle_install(nhe);
			break;
		}
	}
}

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
			break;
		}
	}

	zebra_nhg_handle_uninstall(nhe);
}

void zebra_nhg_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum zebra_dplane_result status;
	uint32_t id = 0;
	struct nhg_hash_entry *nhe = NULL;

	op = dplane_ctx_get_op(ctx);
	status = dplane_ctx_get_status(ctx);

	id = dplane_ctx_get_nhe_id(ctx);

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		zlog_debug(
			"Nexthop dplane ctx %p, op %s, nexthop ID (%u), result %s",
			ctx, dplane_op2str(op), id, dplane_res2str(status));

	switch (op) {
	case DPLANE_OP_NH_DELETE:
		if (status != ZEBRA_DPLANE_REQUEST_SUCCESS)
			flog_err(
				EC_ZEBRA_DP_DELETE_FAIL,
				"Failed to uninstall Nexthop ID (%u) from the kernel",
				id);
		/* We already free'd the data, nothing to do */
		break;
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
		nhe = zebra_nhg_lookup_id(id);

		if (!nhe) {
			flog_err(
				EC_ZEBRA_NHG_SYNC,
				"%s operation preformed on Nexthop ID (%u) in the kernel, that we no longer have in our table",
				dplane_op2str(op), id);
			break;
		}

		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
		if (status == ZEBRA_DPLANE_REQUEST_SUCCESS) {
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			zebra_nhg_handle_install(nhe);
		} else
			flog_err(
				EC_ZEBRA_DP_INSTALL_FAIL,
				"Failed to install Nexthop ID (%u) into the kernel",
				nhe->id);
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
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NONE:
		break;
	}

	dplane_ctx_fini(&ctx);
}

static void zebra_nhg_sweep_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = (struct nhg_hash_entry *)bucket->data;

	/* If its being ref'd, just let it be uninstalled via a route removal */
	if (ZEBRA_NHG_CREATED(nhe) && nhe->refcnt <= 0)
		zebra_nhg_uninstall_kernel(nhe);
}

void zebra_nhg_sweep_table(struct hash *hash)
{
	hash_iterate(hash, zebra_nhg_sweep_entry, NULL);
}
