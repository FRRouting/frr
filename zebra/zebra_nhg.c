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

/*  */
static bool g_nexthops_enabled = true;
static bool proto_nexthops_only = false;

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi,
					   int type);
static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend);
static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi, int type);
static struct nhg_hash_entry *
depends_find_id_add(struct nhg_connected_tree_head *head, uint32_t id);
static void depends_decrement_free(struct nhg_connected_tree_head *head);

static struct nhg_backup_info *
nhg_backup_copy(const struct nhg_backup_info *orig);

/* Helper function for getting the next allocatable ID */
static uint32_t nhg_get_next_id()
{
	while (1) {
		id_counter++;

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: ID %u checking", __func__, id_counter);

		if (id_counter == ZEBRA_NHG_PROTO_LOWER) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: ID counter wrapped", __func__);

			id_counter = 0;
			continue;
		}

		if (zebra_nhg_lookup_id(id_counter)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: ID already exists", __func__);

			continue;
		}

		break;
	}

	return id_counter;
}

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

struct nhg_hash_entry *
nhg_connected_tree_del_nhe(struct nhg_connected_tree_head *head,
			   struct nhg_hash_entry *depend)
{
	struct nhg_connected lookup = {};
	struct nhg_connected *remove = NULL;
	struct nhg_hash_entry *removed_nhe;

	lookup.nhe = depend;

	/* Lookup to find the element, then remove it */
	remove = nhg_connected_tree_find(head, &lookup);
	if (remove)
		/* Re-returning here just in case this API changes..
		 * the _del list api's are a bit undefined at the moment.
		 *
		 * So hopefully returning here will make it fail if the api
		 * changes to something different than currently expected.
		 */
		remove = nhg_connected_tree_del(head, remove);

	/* If the entry was sucessfully removed, free the 'connected` struct */
	if (remove) {
		removed_nhe = remove->nhe;
		nhg_connected_free(remove);
		return removed_nhe;
	}

	return NULL;
}

/* Assuming UNIQUE RB tree. If this changes, assumptions here about
 * insertion need to change.
 */
struct nhg_hash_entry *
nhg_connected_tree_add_nhe(struct nhg_connected_tree_head *head,
			   struct nhg_hash_entry *depend)
{
	struct nhg_connected *new = NULL;

	new = nhg_connected_new(depend);

	/* On success, NULL will be returned from the
	 * RB code.
	 */
	if (new && (nhg_connected_tree_add(head, new) == NULL))
		return NULL;

	/* If it wasn't successful, it must be a duplicate. We enforce the
	 * unique property for the `nhg_connected` tree.
	 */
	nhg_connected_free(new);

	return depend;
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
			  struct nhg_connected_tree_head *nhg_depends)
{
	struct nhg_connected *rb_node_dep = NULL;

	/* This has been allocated higher above in the stack. Could probably
	 * re-allocate and free the old stuff but just using the same memory
	 * for now. Otherwise, their might be a time trade-off for repeated
	 * alloc/frees as startup.
	 */
	nhe->nhg_depends = *nhg_depends;

	/* Attach backpointer to anything that it depends on */
	zebra_nhg_dependents_init(nhe);
	if (!zebra_nhg_depends_is_empty(nhe)) {
		frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: nhe %p (%u), dep %p (%u)",
					   __func__, nhe, nhe->id,
					   rb_node_dep->nhe,
					   rb_node_dep->nhe->id);

			zebra_nhg_dependents_add(rb_node_dep->nhe, nhe);
		}
	}
}

/* Init an nhe, for use in a hash lookup for example */
void zebra_nhe_init(struct nhg_hash_entry *nhe, afi_t afi,
		    const struct nexthop *nh)
{
	memset(nhe, 0, sizeof(struct nhg_hash_entry));
	nhe->vrf_id = VRF_DEFAULT;
	nhe->type = ZEBRA_ROUTE_NHG;
	nhe->afi = AFI_UNSPEC;

	/* There are some special rules that apply to groups representing
	 * a single nexthop.
	 */
	if (nh && (nh->next == NULL)) {
		switch (nh->type) {
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
			nhe->afi = afi;
			break;
		case (NEXTHOP_TYPE_IPV4_IFINDEX):
		case (NEXTHOP_TYPE_IPV4):
			nhe->afi = AFI_IP;
			break;
		case (NEXTHOP_TYPE_IPV6_IFINDEX):
		case (NEXTHOP_TYPE_IPV6):
			nhe->afi = AFI_IP6;
			break;
		}
	}
}

struct nhg_hash_entry *zebra_nhg_alloc(void)
{
	struct nhg_hash_entry *nhe;

	nhe = XCALLOC(MTYPE_NHG, sizeof(struct nhg_hash_entry));

	return nhe;
}

/*
 * Allocate new nhe and make shallow copy of 'orig'; no
 * recursive info is copied.
 */
struct nhg_hash_entry *zebra_nhe_copy(const struct nhg_hash_entry *orig,
				      uint32_t id)
{
	struct nhg_hash_entry *nhe;

	nhe = zebra_nhg_alloc();

	nhe->id = id;

	nexthop_group_copy(&(nhe->nhg), &(orig->nhg));

	nhe->vrf_id = orig->vrf_id;
	nhe->afi = orig->afi;
	nhe->type = orig->type ? orig->type : ZEBRA_ROUTE_NHG;
	nhe->refcnt = 0;
	nhe->dplane_ref = zebra_router_get_next_sequence();

	/* Copy backup info also, if present */
	if (orig->backup_info)
		nhe->backup_info = nhg_backup_copy(orig->backup_info);

	return nhe;
}

/* Allocation via hash handler */
static void *zebra_nhg_hash_alloc(void *arg)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nhg_hash_entry *copy = arg;

	nhe = zebra_nhe_copy(copy, copy->id);

	/* Mark duplicate nexthops in a group at creation time. */
	nexthop_group_mark_duplicates(&(nhe->nhg));

	zebra_nhg_connect_depends(nhe, &(copy->nhg_depends));

	/* Add the ifp now if it's not a group or recursive and has ifindex */
	if (zebra_nhg_depends_is_empty(nhe) && nhe->nhg.nexthop
	    && nhe->nhg.nexthop->ifindex) {
		struct interface *ifp = NULL;

		ifp = if_lookup_by_index(nhe->nhg.nexthop->ifindex,
					 nhe->nhg.nexthop->vrf_id);
		if (ifp)
			zebra_nhg_set_if(nhe, ifp);
		else
			flog_err(
				EC_ZEBRA_IF_LOOKUP_FAILED,
				"Zebra failed to lookup an interface with ifindex=%d in vrf=%u for NHE id=%u",
				nhe->nhg.nexthop->ifindex,
				nhe->nhg.nexthop->vrf_id, nhe->id);
	}


	return nhe;
}

uint32_t zebra_nhg_hash_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;
	uint32_t key = 0x5a351234;
	uint32_t primary = 0;
	uint32_t backup = 0;

	primary = nexthop_group_hash(&(nhe->nhg));
	if (nhe->backup_info)
		backup = nexthop_group_hash(&(nhe->backup_info->nhe->nhg));

	key = jhash_3words(primary, backup, nhe->type, key);

	key = jhash_2words(nhe->vrf_id, nhe->afi, key);

	return key;
}

uint32_t zebra_nhg_id_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;

	return nhe->id;
}

/* Helper with common nhg/nhe nexthop comparison logic */
static bool nhg_compare_nexthops(const struct nexthop *nh1,
				 const struct nexthop *nh2)
{
	assert(nh1 != NULL && nh2 != NULL);

	/*
	 * We have to check the active flag of each individual one,
	 * not just the overall active_num. This solves the special case
	 * issue of a route with a nexthop group with one nexthop
	 * resolving to itself and thus marking it inactive. If we
	 * have two different routes each wanting to mark a different
	 * nexthop inactive, they need to hash to two different groups.
	 *
	 * If we just hashed on num_active, they would hash the same
	 * which is incorrect.
	 *
	 * ex)
	 *      1.1.1.0/24
	 *           -> 1.1.1.1 dummy1 (inactive)
	 *           -> 1.1.2.1 dummy2
	 *
	 *      1.1.2.0/24
	 *           -> 1.1.1.1 dummy1
	 *           -> 1.1.2.1 dummy2 (inactive)
	 *
	 * Without checking each individual one, they would hash to
	 * the same group and both have 1.1.1.1 dummy1 marked inactive.
	 *
	 */
	if (CHECK_FLAG(nh1->flags, NEXTHOP_FLAG_ACTIVE)
	    != CHECK_FLAG(nh2->flags, NEXTHOP_FLAG_ACTIVE))
		return false;

	if (!nexthop_same(nh1, nh2))
		return false;

	return true;
}

bool zebra_nhg_hash_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;
	struct nexthop *nexthop1;
	struct nexthop *nexthop2;

	/* No matter what if they equal IDs, assume equal */
	if (nhe1->id && nhe2->id && (nhe1->id == nhe2->id))
		return true;

	if (nhe1->type != nhe2->type)
		return false;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	/* Nexthops should be in-order, so we simply compare them in-place */
	for (nexthop1 = nhe1->nhg.nexthop, nexthop2 = nhe2->nhg.nexthop;
	     nexthop1 && nexthop2;
	     nexthop1 = nexthop1->next, nexthop2 = nexthop2->next) {

		if (!nhg_compare_nexthops(nexthop1, nexthop2))
			return false;
	}

	/* Check for unequal list lengths */
	if (nexthop1 || nexthop2)
		return false;

	/* If there's no backup info, comparison is done. */
	if ((nhe1->backup_info == NULL) && (nhe2->backup_info == NULL))
		return true;

	/* Compare backup info also - test the easy things first */
	if (nhe1->backup_info && (nhe2->backup_info == NULL))
		return false;
	if (nhe2->backup_info && (nhe1->backup_info == NULL))
		return false;

	/* Compare number of backups before actually comparing any */
	for (nexthop1 = nhe1->backup_info->nhe->nhg.nexthop,
	     nexthop2 = nhe2->backup_info->nhe->nhg.nexthop;
	     nexthop1 && nexthop2;
	     nexthop1 = nexthop1->next, nexthop2 = nexthop2->next) {
		;
	}

	/* Did we find the end of one list before the other? */
	if (nexthop1 || nexthop2)
		return false;

	/* Have to compare the backup nexthops */
	for (nexthop1 = nhe1->backup_info->nhe->nhg.nexthop,
	     nexthop2 = nhe2->backup_info->nhe->nhg.nexthop;
	     nexthop1 && nexthop2;
	     nexthop1 = nexthop1->next, nexthop2 = nexthop2->next) {

		if (!nhg_compare_nexthops(nexthop1, nexthop2))
			return false;
	}

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

		copy_nexthops(&nhg->nexthop, depend->nhg.nexthop, NULL);
	}

	return 0;
}

static void handle_recursive_depend(struct nhg_connected_tree_head *nhg_depends,
				    struct nexthop *nh, afi_t afi, int type)
{
	struct nhg_hash_entry *depend = NULL;
	struct nexthop_group resolved_ng = {};

	resolved_ng.nexthop = nh;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: head %p, nh %pNHv",
			   __func__, nhg_depends, nh);

	depend = zebra_nhg_rib_find(0, &resolved_ng, afi, type);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%u)",
			   __func__, nh, depend,
			   depend ? depend->id : 0);

	if (depend)
		depends_add(nhg_depends, depend);
}

/*
 * Lookup an nhe in the global hash, using data from another nhe. If 'lookup'
 * has an id value, that's used. Create a new global/shared nhe if not found.
 */
static bool zebra_nhe_find(struct nhg_hash_entry **nhe, /* return value */
			   struct nhg_hash_entry *lookup,
			   struct nhg_connected_tree_head *nhg_depends,
			   afi_t afi)
{
	bool created = false;
	bool recursive = false;
	struct nhg_hash_entry *newnhe, *backup_nhe;
	struct nexthop *nh = NULL;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: id %u, lookup %p, vrf %d, type %d, depends %p",
			   __func__, lookup->id, lookup,
			   lookup->vrf_id, lookup->type,
			   nhg_depends);

	if (lookup->id)
		(*nhe) = zebra_nhg_lookup_id(lookup->id);
	else
		(*nhe) = hash_lookup(zrouter.nhgs, lookup);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: lookup => %p (%u)",
			   __func__, (*nhe),
			   (*nhe) ? (*nhe)->id : 0);

	/* If we found an existing object, we're done */
	if (*nhe)
		goto done;

	/* We're going to create/insert a new nhe:
	 * assign the next global id value if necessary.
	 */
	if (lookup->id == 0)
		lookup->id = nhg_get_next_id();

	if (lookup->id < ZEBRA_NHG_PROTO_LOWER) {
		/*
		 * This is a zebra hashed/owned NHG.
		 *
		 * It goes in HASH and ID table.
		 */
		newnhe = hash_get(zrouter.nhgs, lookup, zebra_nhg_hash_alloc);
		zebra_nhg_insert_id(newnhe);
	} else {
		/*
		 * This is upperproto owned NHG and should not be hashed to.
		 *
		 * It goes in ID table.
		 */
		newnhe =
			hash_get(zrouter.nhgs_id, lookup, zebra_nhg_hash_alloc);
	}

	created = true;

	/* Mail back the new object */
	*nhe = newnhe;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: => created %p (%u)", __func__, newnhe,
			   newnhe->id);

	/* Only hash/lookup the depends if the first lookup
	 * fails to find something. This should hopefully save a
	 * lot of cycles for larger ecmp sizes.
	 */
	if (nhg_depends) {
		/* If you don't want to hash on each nexthop in the
		 * nexthop group struct you can pass the depends
		 * directly. Kernel-side we do this since it just looks
		 * them up via IDs.
		 */
		zebra_nhg_connect_depends(newnhe, nhg_depends);
		goto done;
	}

	/* Prepare dependency relationships if this is not a
	 * singleton nexthop. There are two cases: a single
	 * recursive nexthop, where we need a relationship to the
	 * resolving nexthop; or a group of nexthops, where we need
	 * relationships with the corresponding singletons.
	 */
	zebra_nhg_depends_init(lookup);

	nh = newnhe->nhg.nexthop;

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE))
		SET_FLAG(newnhe->flags, NEXTHOP_GROUP_VALID);

	if (nh->next == NULL && newnhe->id < ZEBRA_NHG_PROTO_LOWER) {
		if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
			/* Single recursive nexthop */
			handle_recursive_depend(&newnhe->nhg_depends,
						nh->resolved, afi,
						newnhe->type);
			recursive = true;
		}
	} else {
		/* Proto-owned are groups by default */
		/* List of nexthops */
		for (nh = newnhe->nhg.nexthop; nh; nh = nh->next) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: depends NH %pNHv %s",
					   __func__, nh,
					   CHECK_FLAG(nh->flags,
						      NEXTHOP_FLAG_RECURSIVE) ?
					   "(R)" : "");

			depends_find_add(&newnhe->nhg_depends, nh, afi,
					 newnhe->type);
		}
	}

	if (recursive)
		SET_FLAG((*nhe)->flags, NEXTHOP_GROUP_RECURSIVE);

	if (zebra_nhg_get_backup_nhg(newnhe) == NULL ||
	    zebra_nhg_get_backup_nhg(newnhe)->nexthop == NULL)
		goto done;

	/* If there are backup nexthops, add them to the backup
	 * depends tree. The rules here are a little different.
	 */
	recursive = false;
	backup_nhe = newnhe->backup_info->nhe;

	nh = backup_nhe->nhg.nexthop;

	/* Singleton recursive NH */
	if (nh->next == NULL &&
	    CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: backup depend NH %pNHv (R)",
				   __func__, nh);

		/* Single recursive nexthop */
		handle_recursive_depend(&backup_nhe->nhg_depends, nh->resolved,
					afi, backup_nhe->type);
		recursive = true;
	} else {
		/* One or more backup NHs */
		for (; nh; nh = nh->next) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: backup depend NH %pNHv %s",
					   __func__, nh,
					   CHECK_FLAG(nh->flags,
						      NEXTHOP_FLAG_RECURSIVE) ?
					   "(R)" : "");

			depends_find_add(&backup_nhe->nhg_depends, nh, afi,
					 backup_nhe->type);
		}
	}

	if (recursive)
		SET_FLAG(backup_nhe->flags, NEXTHOP_GROUP_RECURSIVE);

done:

	return created;
}

/*
 * Lookup or create an nhe, based on an nhg or an nhe id.
 */
static bool zebra_nhg_find(struct nhg_hash_entry **nhe, uint32_t id,
			   struct nexthop_group *nhg,
			   struct nhg_connected_tree_head *nhg_depends,
			   vrf_id_t vrf_id, afi_t afi, int type)
{
	struct nhg_hash_entry lookup = {};
	bool created = false;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: id %u, nhg %p, vrf %d, type %d, depends %p",
			   __func__, id, nhg, vrf_id, type,
			   nhg_depends);

	/* Use a temporary nhe and call into the superset/common code */
	lookup.id = id;
	lookup.type = type ? type : ZEBRA_ROUTE_NHG;
	lookup.nhg = *nhg;

	lookup.vrf_id = vrf_id;
	if (lookup.nhg.nexthop->next) {
		/* Groups can have all vrfs and AF's in them */
		lookup.afi = AFI_UNSPEC;
	} else {
		switch (lookup.nhg.nexthop->type) {
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
	}

	created = zebra_nhe_find(nhe, &lookup, nhg_depends, afi);

	return created;
}

/* Find/create a single nexthop */
static struct nhg_hash_entry *
zebra_nhg_find_nexthop(uint32_t id, struct nexthop *nh, afi_t afi, int type)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nexthop_group nhg = {};
	vrf_id_t vrf_id = !vrf_is_backend_netns() ? VRF_DEFAULT : nh->vrf_id;

	nexthop_group_add_sorted(&nhg, nh);

	zebra_nhg_find(&nhe, id, &nhg, NULL, vrf_id, afi, type);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%u)",
			   __func__, nh, nhe, nhe ? nhe->id : 0);

	return nhe;
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

static struct nhg_ctx *nhg_ctx_new(void)
{
	struct nhg_ctx *new;

	new = XCALLOC(MTYPE_NHG_CTX, sizeof(struct nhg_ctx));

	return new;
}

static void nhg_ctx_free(struct nhg_ctx **ctx)
{
	struct nexthop *nh;

	if (ctx == NULL)
		return;

	assert((*ctx) != NULL);

	if (nhg_ctx_get_count(*ctx))
		goto done;

	nh = nhg_ctx_get_nh(*ctx);

	nexthop_del_labels(nh);

done:
	XFREE(MTYPE_NHG_CTX, *ctx);
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

static void zebra_nhg_release_all_deps(struct nhg_hash_entry *nhe)
{
	/* Remove it from any lists it may be on */
	zebra_nhg_depends_release(nhe);
	zebra_nhg_dependents_release(nhe);
	if (nhe->ifp)
		if_nhg_dependents_del(nhe->ifp, nhe);
}

static void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%u)", __func__, nhe, nhe->id);

	zebra_nhg_release_all_deps(nhe);

	/*
	 * If its not zebra owned, we didn't store it here and have to be
	 * sure we don't clear one thats actually being used.
	 */
	if (ZEBRA_OWNED(nhe))
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

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: id %u, count %d, lookup => %p",
			   __func__, id, count, lookup);

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

		if (!zebra_nhg_find(&nhe, id, nhg, &nhg_depends, vrf_id, afi,
				    type))
			depends_decrement_free(&nhg_depends);

		/* These got copied over in zebra_nhg_alloc() */
		nexthop_group_delete(&nhg);
	} else
		nhe = zebra_nhg_find_nexthop(id, nhg_ctx_get_nh(ctx), afi,
					     type);

	if (!nhe) {
		flog_err(
			EC_ZEBRA_TABLE_LOOKUP_FAILED,
			"Zebra failed to find or create a nexthop hash entry for ID (%u)",
			id);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%u) is new", __func__, nhe, nhe->id);

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);

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

static void nhg_ctx_fini(struct nhg_ctx **ctx)
{
	/*
	 * Just freeing for now, maybe do something more in the future
	 * based on flag.
	 */

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

	nhg_ctx_fini(&ctx);

	return ret;
}

/* Kernel-side, you either get a single new nexthop or a array of ID's */
int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh, struct nh_grp *grp,
			  uint8_t count, vrf_id_t vrf_id, afi_t afi, int type,
			  int startup)
{
	struct nhg_ctx *ctx = NULL;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv, id %u, count %d",
			   __func__, nh, id, (int)count);

	if (id > id_counter && id < ZEBRA_NHG_PROTO_LOWER)
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
		nhg_ctx_fini(&ctx);
		return -1;
	}

	return 0;
}

/* Kernel-side, received delete message */
int zebra_nhg_kernel_del(uint32_t id, vrf_id_t vrf_id)
{
	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_init(id, NULL, NULL, vrf_id, 0, 0, 0);

	nhg_ctx_set_op(ctx, NHG_CTX_OP_DEL);

	if (queue_add(ctx)) {
		nhg_ctx_fini(&ctx);
		return -1;
	}

	return 0;
}

/* Some dependency helper functions */
static struct nhg_hash_entry *depends_find_recursive(const struct nexthop *nh,
						     afi_t afi, int type)
{
	struct nhg_hash_entry *nhe;
	struct nexthop *lookup = NULL;

	lookup = nexthop_dup(nh, NULL);

	nhe = zebra_nhg_find_nexthop(0, lookup, afi, type);

	nexthops_free(lookup);

	return nhe;
}

static struct nhg_hash_entry *depends_find_singleton(const struct nexthop *nh,
						     afi_t afi, int type)
{
	struct nhg_hash_entry *nhe;
	struct nexthop lookup = {};

	/* Capture a snapshot of this single nh; it might be part of a list,
	 * so we need to make a standalone copy.
	 */
	nexthop_copy_no_recurse(&lookup, nh, NULL);

	nhe = zebra_nhg_find_nexthop(0, &lookup, afi, type);

	/* The copy may have allocated labels; free them if necessary. */
	nexthop_del_labels(&lookup);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%u)",
			   __func__, nh, nhe, nhe ? nhe->id : 0);

	return nhe;
}

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi,
					   int type)
{
	struct nhg_hash_entry *nhe = NULL;
	char rbuf[10];

	if (!nh)
		goto done;

	/* We are separating these functions out to increase handling speed
	 * in the non-recursive case (by not alloc/freeing)
	 */
	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
		nhe = depends_find_recursive(nh, afi, type);
		strlcpy(rbuf, "(R)", sizeof(rbuf));
	} else {
		nhe = depends_find_singleton(nh, afi, type);
		rbuf[0] = '\0';
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv %s => %p (%u)",
			   __func__, nh, rbuf,
			   nhe, nhe ? nhe->id : 0);

done:
	return nhe;
}

static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: head %p nh %pNHv",
			   __func__, head, depend->nhg.nexthop);

	/* If NULL is returned, it was successfully added and
	 * needs to have its refcnt incremented.
	 *
	 * Else the NHE is already present in the tree and doesn't
	 * need to increment the refcnt.
	 */
	if (nhg_connected_tree_add_nhe(head, depend) == NULL)
		zebra_nhg_increment_ref(depend);
}

static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi, int type)
{
	struct nhg_hash_entry *depend = NULL;

	depend = depends_find(nh, afi, type);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p",
			   __func__, nh, depend);

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

/* Find an nhe based on a list of nexthops */
struct nhg_hash_entry *zebra_nhg_rib_find(uint32_t id,
					  struct nexthop_group *nhg,
					  afi_t rt_afi, int type)
{
	struct nhg_hash_entry *nhe = NULL;
	vrf_id_t vrf_id;

	/*
	 * CLANG SA is complaining that nexthop may be NULL
	 * Make it happy but this is ridonc
	 */
	assert(nhg->nexthop);
	vrf_id = !vrf_is_backend_netns() ? VRF_DEFAULT : nhg->nexthop->vrf_id;

	zebra_nhg_find(&nhe, id, nhg, NULL, vrf_id, rt_afi, type);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: => nhe %p (%u)",
			   __func__, nhe, nhe ? nhe->id : 0);

	return nhe;
}

/* Find an nhe based on a route's nhe */
struct nhg_hash_entry *
zebra_nhg_rib_find_nhe(struct nhg_hash_entry *rt_nhe, afi_t rt_afi)
{
	struct nhg_hash_entry *nhe = NULL;

	if (!(rt_nhe && rt_nhe->nhg.nexthop)) {
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "No nexthop passed to %s", __func__);
		return NULL;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: rt_nhe %p (%u)", __func__, rt_nhe, rt_nhe->id);

	zebra_nhe_find(&nhe, rt_nhe, NULL, rt_afi);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: => nhe %p (%u)",
			   __func__, nhe, nhe ? nhe->id : 0);

	return nhe;
}

/*
 * Allocate backup nexthop info object. Typically these are embedded in
 * nhg_hash_entry objects.
 */
struct nhg_backup_info *zebra_nhg_backup_alloc(void)
{
	struct nhg_backup_info *p;

	p = XCALLOC(MTYPE_NHG, sizeof(struct nhg_backup_info));

	p->nhe = zebra_nhg_alloc();

	/* Identify the embedded group used to hold the list of backups */
	SET_FLAG(p->nhe->flags, NEXTHOP_GROUP_BACKUP);

	return p;
}

/*
 * Free backup nexthop info object, deal with any embedded allocations
 */
void zebra_nhg_backup_free(struct nhg_backup_info **p)
{
	if (p && *p) {
		if ((*p)->nhe)
			zebra_nhg_free((*p)->nhe);

		XFREE(MTYPE_NHG, (*p));
	}
}

/* Accessor for backup nexthop group */
struct nexthop_group *zebra_nhg_get_backup_nhg(struct nhg_hash_entry *nhe)
{
	struct nexthop_group *p = NULL;

	if (nhe) {
		if (nhe->backup_info && nhe->backup_info->nhe)
			p = &(nhe->backup_info->nhe->nhg);
	}

	return p;
}

/*
 * Helper to return a copy of a backup_info - note that this is a shallow
 * copy, meant to be used when creating a new nhe from info passed in with
 * a route e.g.
 */
static struct nhg_backup_info *
nhg_backup_copy(const struct nhg_backup_info *orig)
{
	struct nhg_backup_info *b;

	b = zebra_nhg_backup_alloc();

	/* Copy list of nexthops */
	nexthop_group_copy(&(b->nhe->nhg), &(orig->nhe->nhg));

	return b;
}

static void zebra_nhg_free_members(struct nhg_hash_entry *nhe)
{
	nexthops_free(nhe->nhg.nexthop);

	zebra_nhg_backup_free(&nhe->backup_info);

	/* Decrement to remove connection ref */
	nhg_connected_tree_decrement_ref(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_dependents);
}

void zebra_nhg_free(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		/* Group or singleton? */
		if (nhe->nhg.nexthop && nhe->nhg.nexthop->next)
			zlog_debug("%s: nhe %p (%u), refcnt %d",
				   __func__, nhe, nhe->id, nhe->refcnt);
		else
			zlog_debug("%s: nhe %p (%u), refcnt %d, NH %pNHv",
				   __func__, nhe, nhe->id, nhe->refcnt,
				   nhe->nhg.nexthop);
	}

	if (nhe->refcnt)
		zlog_debug("nhe_id=%u hash refcnt=%d", nhe->id, nhe->refcnt);

	zebra_nhg_free_members(nhe);

	XFREE(MTYPE_NHG, nhe);
}

void zebra_nhg_hash_free(void *p)
{
	zebra_nhg_free((struct nhg_hash_entry *)p);
}

void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%u) %d => %d",
			   __func__, nhe, nhe->id, nhe->refcnt,
			   nhe->refcnt - 1);

	nhe->refcnt--;

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_decrement_ref(&nhe->nhg_depends);

	if (ZEBRA_NHG_CREATED(nhe) && nhe->refcnt <= 0)
		zebra_nhg_uninstall_kernel(nhe);
}

void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%u) %d => %d",
			   __func__, nhe, nhe->id, nhe->refcnt,
			   nhe->refcnt + 1);

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
		for (i = 0; i < newhop->nh_label->num_labels; i++) {
			/* Be a bit picky about overrunning the local array */
			if (num_labels >= MPLS_MAX_LABELS) {
				if (IS_ZEBRA_DEBUG_NHG || IS_ZEBRA_DEBUG_RIB)
					zlog_debug("%s: too many labels in newhop %pNHv",
						   __func__, newhop);
				break;
			}
			labels[num_labels++] = newhop->nh_label->label[i];
		}
		/* Use the "outer" type */
		label_type = newhop->nh_label_type;
	}

	if (nexthop->nh_label) {
		for (i = 0; i < nexthop->nh_label->num_labels; i++) {
			/* Be a bit picky about overrunning the local array */
			if (num_labels >= MPLS_MAX_LABELS) {
				if (IS_ZEBRA_DEBUG_NHG || IS_ZEBRA_DEBUG_RIB)
					zlog_debug("%s: too many labels in nexthop %pNHv",
						   __func__, nexthop);
				break;
			}
			labels[num_labels++] = nexthop->nh_label->label[i];
		}

		/* If the parent has labels, use its type if
		 * we don't already have one.
		 */
		if (label_type == ZEBRA_LSP_NONE)
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

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p, nexthop %pNHv",
			   __func__, re, nexthop);

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
	 * If the nexthop has been marked as 'onlink' we just need to make
	 * sure the nexthop's interface is known and is operational.
	 */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)) {
		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (!ifp) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("nexthop %pNHv marked onlink but nhif %u doesn't exist",
					   nexthop, nexthop->ifindex);
			return 0;
		}
		if (!if_is_operative(ifp)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("nexthop %pNHv marked onlink but nhif %s is not operational",
					   nexthop, ifp->name);
			return 0;
		}
		return 1;
	}

	if ((top->p.family == AF_INET && top->p.prefixlen == 32
	     && nexthop->gate.ipv4.s_addr == top->p.u.prefix4.s_addr)
	    || (top->p.family == AF_INET6 && top->p.prefixlen == 128
		&& memcmp(&nexthop->gate.ipv6, &top->p.u.prefix6, 16) == 0)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"        :%s: Attempting to install a max prefixlength route through itself",
				__func__);
		return 0;
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
			zlog_debug("        %s: Table not found", __func__);
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
		if (rn == top)
			if (((afi == AFI_IP) && (rn->p.prefixlen != 32))
			    || ((afi == AFI_IP6) && (rn->p.prefixlen != 128))) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"        %s: Matched against ourself and prefix length is not max bit length",
						__func__);
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
					"        :%s: Resolved against default route",
					__func__);
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
			newhop = match->nhe->nhg.nexthop;
			if (newhop) {
				if (nexthop->type == NEXTHOP_TYPE_IPV4
				    || nexthop->type == NEXTHOP_TYPE_IPV6)
					nexthop->ifindex = newhop->ifindex;
			}

			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: CONNECT match %p (%u), newhop %pNHv",
					   __func__, match,
					   match->nhe->id, newhop);

			return 1;
		} else if (CHECK_FLAG(re->flags, ZEBRA_FLAG_ALLOW_RECURSION)) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->nhe->nhg, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug("%s: RECURSIVE match %p (%u), newhop %pNHv",
						   __func__, match,
						   match->nhe->id, newhop);

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}

			if (resolved)
				re->nexthop_mtu = match->mtu;
			else if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"        %s: Recursion failed to find",
					__func__);

			return resolved;
		} else if (re->type == ZEBRA_ROUTE_STATIC) {
			resolved = 0;
			for (ALL_NEXTHOPS(match->nhe->nhg, newhop)) {
				if (!CHECK_FLAG(match->status,
						ROUTE_ENTRY_INSTALLED))
					continue;
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug("%s: STATIC match %p (%u), newhop %pNHv",
						   __func__, match,
						   match->nhe->id, newhop);

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop);
				resolved = 1;
			}
			if (resolved)
				re->nexthop_mtu = match->mtu;

			if (!resolved && IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"        %s: Static route unable to resolve",
					__func__);
			return resolved;
		} else {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
				zlog_debug(
					"        %s: Route Type %s has not turned on recursion",
					__func__, zebra_route_string(re->type));
				if (re->type == ZEBRA_ROUTE_BGP
				    && !CHECK_FLAG(re->flags, ZEBRA_FLAG_IBGP))
					zlog_debug(
						"        EBGP: see \"disable-ebgp-connected-route-check\" or \"disable-connected-check\"");
			}
			return 0;
		}
	}
	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("        %s: Nexthop did not lookup in table",
			   __func__);
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
		/*
		 * If the interface exists and its operative or its a kernel
		 * route and interface is up, its active. We trust kernel routes
		 * to be good.
		 */
		if (ifp
		    && (if_is_operative(ifp)
			|| (if_is_up(ifp)
			    && (re->type == ZEBRA_ROUTE_KERNEL
				|| re->type == ZEBRA_ROUTE_SYSTEM))))
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
			zlog_debug("        %s: Unable to find active nexthop",
				   __func__);
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
		struct rib_table_info *info;

		info = srcdest_rnode_table_info(rn);
		family = info->afi;
	}

	memset(&nexthop->rmap_src.ipv6, 0, sizeof(union g_addr));

	zvrf = zebra_vrf_lookup_by_id(nexthop->vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("        %s: zvrf is NULL", __func__);
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

/* Helper function called after resolution to walk nhg rb trees
 * and toggle the NEXTHOP_GROUP_VALID flag if the nexthop
 * is active on singleton NHEs.
 */
static bool zebra_nhg_set_valid_if_active(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;
	bool valid = false;

	if (!zebra_nhg_depends_is_empty(nhe)) {
		/* Is at least one depend valid? */
		frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
			if (zebra_nhg_set_valid_if_active(rb_node_dep->nhe))
				valid = true;
		}

		goto done;
	}

	/* should be fully resolved singleton at this point */
	if (CHECK_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_ACTIVE))
		valid = true;

done:
	if (valid)
		SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);

	return valid;
}

/*
 * Process a list of nexthops, given the head of the list, determining
 * whether each one is ACTIVE/installable at this time.
 */
static uint32_t nexthop_list_active_update(struct route_node *rn,
					   struct route_entry *re,
					   struct nexthop *nexthop)
{
	union g_addr prev_src;
	unsigned int prev_active, new_active;
	ifindex_t prev_index;
	uint32_t counter = 0;

	/* Process nexthops one-by-one */
	for ( ; nexthop; nexthop = nexthop->next) {

		/* No protocol daemon provides src and so we're skipping
		 * tracking it
		 */
		prev_src = nexthop->rmap_src;
		prev_active = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		prev_index = nexthop->ifindex;
		/*
		 * We need to respect the multipath_num here
		 * as that what we should be able to install from
		 * a multipath perspective should not be a data plane
		 * decision point.
		 */
		new_active =
			nexthop_active_check(rn, re, nexthop);

		if (new_active && counter >= zrouter.multipath_num) {
			struct nexthop *nh;

			/* Set it and its resolved nexthop as inactive. */
			for (nh = nexthop; nh; nh = nh->resolved)
				UNSET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);

			new_active = 0;
		}

		if (new_active)
			counter++;

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

	return counter;
}


static uint32_t proto_nhg_nexthop_active_update(struct nexthop_group *nhg)
{
	struct nexthop *nh;
	uint32_t curr_active = 0;

	/* Assume all active for now */

	for (nh = nhg->nexthop; nh; nh = nh->next) {
		SET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);
		curr_active++;
	}

	return curr_active;
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
	struct nhg_hash_entry *curr_nhe;
	uint32_t curr_active = 0, backup_active = 0;

	if (re->nhe->id >= ZEBRA_NHG_PROTO_LOWER)
		return proto_nhg_nexthop_active_update(&re->nhe->nhg);

	afi_t rt_afi = family2afi(rn->p.family);

	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	/* Make a local copy of the existing nhe, so we don't work on/modify
	 * the shared nhe.
	 */
	curr_nhe = zebra_nhe_copy(re->nhe, re->nhe->id);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p nhe %p (%u), curr_nhe %p",
			   __func__, re, re->nhe, re->nhe->id,
			   curr_nhe);

	/* Clear the existing id, if any: this will avoid any confusion
	 * if the id exists, and will also force the creation
	 * of a new nhe reflecting the changes we may make in this local copy.
	 */
	curr_nhe->id = 0;

	/* Process nexthops */
	curr_active = nexthop_list_active_update(rn, re, curr_nhe->nhg.nexthop);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p curr_active %u", __func__, re,
			   curr_active);

	/* If there are no backup nexthops, we are done */
	if (zebra_nhg_get_backup_nhg(curr_nhe) == NULL)
		goto backups_done;

	backup_active = nexthop_list_active_update(
		rn, re, zebra_nhg_get_backup_nhg(curr_nhe)->nexthop);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p backup_active %u", __func__, re,
			   backup_active);

backups_done:

	/*
	 * Ref or create an nhe that matches the current state of the
	 * nexthop(s).
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
		struct nhg_hash_entry *new_nhe = NULL;

		new_nhe = zebra_nhg_rib_find_nhe(curr_nhe, rt_afi);

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: re %p CHANGED: nhe %p (%u) => new_nhe %p (%u)",
				   __func__, re, re->nhe,
				   re->nhe->id, new_nhe, new_nhe->id);

		route_entry_update_nhe(re, new_nhe);
	}


	/* Walk the NHE depends tree and toggle NEXTHOP_GROUP_VALID
	 * flag where appropriate.
	 */
	if (curr_active)
		zebra_nhg_set_valid_if_active(re->nhe);

	/*
	 * Do not need the old / copied nhe anymore since it
	 * was either copied over into a new nhe or not
	 * used at all.
	 */
	zebra_nhg_free(curr_nhe);
	return curr_active;
}

/* Recursively construct a grp array of fully resolved IDs.
 *
 * This function allows us to account for groups within groups,
 * by converting them into a flat array of IDs.
 *
 * nh_grp is modified at every level of recursion to append
 * to it the next unique, fully resolved ID from the entire tree.
 *
 *
 * Note:
 * I'm pretty sure we only allow ONE level of group within group currently.
 * But making this recursive just in case that ever changes.
 */
static uint8_t zebra_nhg_nhe2grp_internal(struct nh_grp *grp,
					  uint8_t curr_index,
					  struct nhg_hash_entry *nhe,
					  int max_num)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct nhg_hash_entry *depend = NULL;
	uint8_t i = curr_index;

	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		bool duplicate = false;

		if (i >= max_num)
			goto done;

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

		if (!zebra_nhg_depends_is_empty(depend)) {
			/* This is a group within a group */
			i = zebra_nhg_nhe2grp_internal(grp, i, depend, max_num);
		} else {
			if (!CHECK_FLAG(depend->flags, NEXTHOP_GROUP_VALID)) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED
				    || IS_ZEBRA_DEBUG_NHG)
					zlog_debug(
						"%s: Nexthop ID (%u) not valid, not appending to dataplane install group",
						__func__, depend->id);
				continue;
			}

			/* If the nexthop not installed/queued for install don't
			 * put in the ID array.
			 */
			if (!(CHECK_FLAG(depend->flags, NEXTHOP_GROUP_INSTALLED)
			      || CHECK_FLAG(depend->flags,
					    NEXTHOP_GROUP_QUEUED))) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED
				    || IS_ZEBRA_DEBUG_NHG)
					zlog_debug(
						"%s: Nexthop ID (%u) not installed or queued for install, not appending to dataplane install group",
						__func__, depend->id);
				continue;
			}

			/* Check for duplicate IDs, ignore if found. */
			for (int j = 0; j < i; j++) {
				if (depend->id == grp[j].id) {
					duplicate = true;
					break;
				}
			}

			if (duplicate) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED
				    || IS_ZEBRA_DEBUG_NHG)
					zlog_debug(
						"%s: Nexthop ID (%u) is duplicate, not appending to dataplane install group",
						__func__, depend->id);
				continue;
			}

			grp[i].id = depend->id;
			grp[i].weight = depend->nhg.nexthop->weight;
			i++;
		}
	}

	if (nhe->backup_info == NULL || nhe->backup_info->nhe == NULL)
		goto done;

	/* TODO -- For now, we are not trying to use or install any
	 * backup info in this nexthop-id path: we aren't prepared
	 * to use the backups here yet. We're just debugging what we find.
	 */
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: skipping backup nhe",  __func__);

done:
	return i;
}

/* Convert a nhe into a group array */
uint8_t zebra_nhg_nhe2grp(struct nh_grp *grp, struct nhg_hash_entry *nhe,
			  int max_num)
{
	/* Call into the recursive function */
	return zebra_nhg_nhe2grp_internal(grp, 0, nhe, max_num);
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

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID)
	    && (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)
		|| nhe->id >= ZEBRA_NHG_PROTO_LOWER)
	    && !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		/* Change its type to us since we are installing it */
		if (!ZEBRA_NHG_CREATED(nhe))
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

	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL || IS_ZEBRA_DEBUG_NHG_DETAIL)
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
	case DPLANE_OP_BR_PORT_UPDATE:
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

/* Global control to disable use of kernel nexthops, if available. We can't
 * force the kernel to support nexthop ids, of course, but we can disable
 * zebra's use of them, for testing e.g. By default, if the kernel supports
 * nexthop ids, zebra uses them.
 */
void zebra_nhg_enable_kernel_nexthops(bool set)
{
	g_nexthops_enabled = set;
}

bool zebra_nhg_kernel_nexthops_enabled(void)
{
	return g_nexthops_enabled;
}

/*
 * Global control to only use kernel nexthops for protocol created NHGs.
 * There are some use cases where you may not want zebra to implicitly
 * create kernel nexthops for all routes and only create them for NHGs
 * passed down by upper level protos.
 *
 * Default is off.
 */
void zebra_nhg_set_proto_nexthops_only(bool set)
{
	proto_nexthops_only = set;
}

bool zebra_nhg_proto_nexthops_only(void)
{
	return proto_nexthops_only;
}

/* Add NHE from upper level proto */
struct nhg_hash_entry *zebra_nhg_proto_add(uint32_t id, int type,
					   struct nexthop_group *nhg, afi_t afi)
{
	struct nhg_hash_entry lookup;
	struct nhg_hash_entry *new, *old;
	struct nhg_connected *rb_node_dep = NULL;

	zebra_nhe_init(&lookup, afi, nhg->nexthop);
	lookup.nhg.nexthop = nhg->nexthop;
	lookup.id = id;
	lookup.type = type;

	old = zebra_nhg_lookup_id(id);

	if (old) {
		/*
		 * This is a replace, just release NHE from ID for now, The
		 * depends/dependents may still be used in the replacement.
		 */
		hash_release(zrouter.nhgs_id, old);
	}

	new = zebra_nhg_rib_find_nhe(&lookup, afi);

	if (old) {
		/* Now release depends/dependents in old one */
		zebra_nhg_release_all_deps(old);
	}

	if (!new)
		return NULL;

	/* TODO: Assuming valid/onlink for now */
	SET_FLAG(new->flags, NEXTHOP_GROUP_VALID);

	if (!zebra_nhg_depends_is_empty(new)) {
		frr_each (nhg_connected_tree, &new->nhg_depends, rb_node_dep)
			SET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_VALID);
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: %s nhe %p (%u), vrf %d, type %s", __func__,
			   (old ? "replaced" : "added"), new, new->id,
			   new->vrf_id, zebra_route_string(new->type));

	return new;
}

/* Delete NHE from upper level proto */
struct nhg_hash_entry *zebra_nhg_proto_del(uint32_t id)
{
	struct nhg_hash_entry *nhe;

	nhe = zebra_nhg_lookup_id(id);

	if (!nhe) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: id %u, lookup failed", __func__, id);

		return NULL;
	}

	if (nhe->refcnt) {
		/* TODO: should be warn? */
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug("%s: id %u, still being used refcnt %u",
				   __func__, nhe->id, nhe->refcnt);
		return NULL;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: deleted nhe %p (%u), vrf %d, type %s", __func__,
			   nhe, nhe->id, nhe->vrf_id,
			   zebra_route_string(nhe->type));

	return nhe;
}

struct nhg_score_proto_iter {
	int type;
	unsigned long found;
};

static void zebra_nhg_score_proto_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe;
	struct nhg_score_proto_iter *iter;

	nhe = (struct nhg_hash_entry *)bucket->data;
	iter = arg;

	/* Needs to match type and outside zebra ID space */
	if (nhe->type == iter->type && nhe->id >= ZEBRA_NHG_PROTO_LOWER) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug(
				"%s: found nhe %p (%u), vrf %d, type %s after client disconnect",
				__func__, nhe, nhe->id, nhe->vrf_id,
				zebra_route_string(nhe->type));

		/* This should be the last ref if we remove client routes too */
		zebra_nhg_decrement_ref(nhe);
	}
}

/* Remove specific by proto NHGs */
unsigned long zebra_nhg_score_proto(int type)
{
	struct nhg_score_proto_iter iter = {};

	iter.type = type;

	hash_iterate(zrouter.nhgs_id, zebra_nhg_score_proto_entry, &iter);

	return iter.found;
}
