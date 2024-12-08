// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Nexthop Group Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
 */
#include <zebra.h>

#include "lib/nexthop.h"
#include "lib/nexthop_group_private.h"
#include "lib/routemap.h"
#include "lib/mpls.h"
#include "lib/jhash.h"
#include "lib/debug.h"
#include "lib/lib_errors.h"

#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_srte.h"
#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra_errors.h"
#include "zebra_dplane.h"
#include "zebra/interface.h"
#include "zebra/zapi_msg.h"
#include "zebra/rib.h"
#include "zebra/zebra_vxlan.h"

DEFINE_MTYPE_STATIC(ZEBRA, NHG, "Nexthop Group Entry");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_CONNECTED, "Nexthop Group Connected");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_CTX, "Nexthop Group Context");

/* Map backup nexthop indices between two nhes */
struct backup_nh_map_s {
	int map_count;

	struct {
		uint8_t orig_idx;
		uint8_t new_idx;
	} map[MULTIPATH_NUM];
};

/* id counter to keep in sync with kernel */
uint32_t id_counter;

/* Controlled through ui */
static bool g_nexthops_enabled = true;
static bool proto_nexthops_only;
static bool use_recursive_backups = true;

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi, int type,
					   bool from_dplane, bool pic);
static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend);
static struct nhg_hash_entry *depends_find_add(struct nhg_connected_tree_head *head,
					       struct nexthop *nh, afi_t afi, int type,
					       bool from_dplane, bool pic);
static struct nhg_hash_entry *
depends_find_id_add(struct nhg_connected_tree_head *head, uint32_t id);
static void depends_decrement_free(struct nhg_connected_tree_head *head);

static struct nhg_backup_info *
nhg_backup_copy(const struct nhg_backup_info *orig);

/* Helper function for getting the next allocatable ID */
static uint32_t nhg_get_next_id(void)
{
	while (1) {
		id_counter++;

		if (id_counter == ZEBRA_NHG_PROTO_LOWER) {
			id_counter = 0;
			continue;
		}

		if (!zebra_nhg_lookup_id(id_counter))
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
			"Failed inserting NHG %pNG into the ID hash table, entry already exists",
			nhe);
		return -1;
	}

	(void)hash_get(zrouter.nhgs_id, nhe, hash_alloc_intern);

	return 0;
}

static void zebra_nhg_set_if(struct nhg_hash_entry *nhe, struct interface *ifp)
{
	struct zebra_if *zif = (struct zebra_if *)ifp->info;

	nhe->ifp = ifp;
	nhg_connected_tree_add_nhe(&zif->nhg_dependents, nhe);
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
				zlog_debug("%s: nhe %p (%pNG), dep %p (%pNG)",
					   __func__, nhe, nhe, rb_node_dep->nhe,
					   rb_node_dep->nhe);

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
			/*
			 * This switch case handles setting the afi different
			 * for ipv4/v6 routes. Ifindex nexthop
			 * objects cannot be ambiguous, they must be Address
			 * Family specific as that the kernel relies on these
			 * for some reason.  blackholes can be v6 because the
			 * v4 kernel infrastructure allows the usage of v6
			 * blackholes in this case.   if we get here, we will
			 * either use the AF of the route, or the one we got
			 * passed from here from the kernel.
			 */
		case NEXTHOP_TYPE_IFINDEX:
			nhe->afi = afi;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			nhe->afi = AFI_IP6;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			nhe->afi = AFI_IP;
			break;
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IPV6:
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

	/*
	 * This is a special case, Zebra needs to track
	 * whether or not this flag was set on a initial
	 * unresolved NHG
	 */
	if (CHECK_FLAG(orig->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL))
		SET_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL);

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

	/*
	 * Add the ifp now if it's not a group or recursive and has ifindex.
	 *
	 * A proto-owned ID is always a group.
	 */
	if (!PROTO_OWNED(nhe) && nhe->nhg.nexthop && !nhe->nhg.nexthop->next
	    && !nhe->nhg.nexthop->resolved && nhe->nhg.nexthop->ifindex) {
		struct interface *ifp = NULL;

		ifp = if_lookup_by_index(nhe->nhg.nexthop->ifindex,
					 nhe->nhg.nexthop->vrf_id);
		if (ifp)
			zebra_nhg_set_if(nhe, ifp);
		else {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"Failed to lookup an interface with ifindex=%d in vrf=%u for NHE %pNG",
					nhe->nhg.nexthop->ifindex,
					nhe->nhg.nexthop->vrf_id, nhe);
		}
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

	/* If both NHG's have id's then we can just know that
	 * they are either identical or not.  This comparison
	 * is only ever used for hash equality.  NHE's id
	 * is sufficient to distinguish them.  This is especially
	 * true if NHG's are owned by an upper level protocol.
	 */
	if (nhe1->id && nhe2->id) {
		if (nhe1->id == nhe2->id)
			return true;

		return false;
	}

	if (nhe1->type != nhe2->type)
		return false;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	if (nhe1->nhg.nhgr.buckets != nhe2->nhg.nhgr.buckets)
		return false;

	if (nhe1->nhg.nhgr.idle_timer != nhe2->nhg.nhgr.idle_timer)
		return false;

	if (nhe1->nhg.nhgr.unbalanced_timer != nhe2->nhg.nhgr.unbalanced_timer)
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

static int zebra_nhg_process_grp(struct nexthop_group *nhg, struct nhg_connected_tree_head *depends,
				 struct nh_grp *grp, uint16_t count,
				 struct nhg_resilience *resilience)
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

	if (resilience)
		nhg->nhgr = *resilience;

	return 0;
}

static void handle_recursive_depend(struct nhg_connected_tree_head *nhg_depends, struct nexthop *nh,
				    afi_t afi, int type, bool pic)
{
	struct nhg_hash_entry *depend = NULL;
	struct nexthop_group resolved_ng = {};

	resolved_ng.nexthop = nh;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: head %p, nh %pNHv",
			   __func__, nhg_depends, nh);

	depend = zebra_nhg_rib_find(0, &resolved_ng, afi, type, pic);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%u)",
			   __func__, nh, depend,
			   depend ? depend->id : 0);

	if (depend)
		depends_add(nhg_depends, depend);
}

static bool zebra_need_to_create_pic(struct nexthop *nh)
{
	if (!fpm_pic_nexthop)
		return false;
	if (nh && nh->nh_srv6 && nh->nh_srv6->seg6_segs && !sid_zero(nh->nh_srv6->seg6_segs))
		return true;
	return false;
}

/*
 * Lookup an nhe in the global hash, using data from another nhe. If 'lookup'
 * has an id value, that's used. Create a new global/shared nhe if not found.
 */
static bool zebra_nhe_find(struct nhg_hash_entry **nhe, /* return value */
			   struct nhg_hash_entry *lookup,
			   struct nhg_connected_tree_head *nhg_depends, afi_t afi, bool from_dplane,
			   bool pic)
{
	bool created = false;
	bool createdPic = false;
	bool recursive = false;
	struct nhg_hash_entry *newnhe, *backup_nhe, *pic_nhe;
	struct nexthop *nh = NULL;


	if (lookup->id)
		(*nhe) = zebra_nhg_lookup_id(lookup->id);
	else
		(*nhe) = hash_lookup(zrouter.nhgs, lookup);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: id %u, lookup %p, vrf %d, type %d, depends %p%s => Found %p(%pNG)",
			   __func__, lookup->id, lookup, lookup->vrf_id,
			   lookup->type, nhg_depends,
			   (from_dplane ? " (from dplane)" : ""), *nhe, *nhe);

	/* If we found an existing object, we're done */
	if (*nhe)
		goto done;

	/* We're going to create/insert a new nhe:
	 * assign the next global id value if necessary.
	 */
	if (lookup->id == 0)
		lookup->id = nhg_get_next_id();

	if (!from_dplane && lookup->id < ZEBRA_NHG_PROTO_LOWER) {
		/*
		 * This is a zebra hashed/owned NHG.
		 *
		 * It goes in HASH and ID table.
		 */
		newnhe = hash_get(zrouter.nhgs, lookup, zebra_nhg_hash_alloc);
		zebra_nhg_insert_id(newnhe);
	} else {
		/*
		 * This is upperproto owned NHG or one we read in from dataplane
		 * and should not be hashed to.
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
		zlog_debug("%s: => created %p (%pNG)", __func__, newnhe,
			   newnhe);

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
	zebra_nhg_depends_init(newnhe);

	nh = newnhe->nhg.nexthop;

	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE))
		SET_FLAG(newnhe->flags, NEXTHOP_GROUP_VALID);

	if (nh->next == NULL && newnhe->id < ZEBRA_NHG_PROTO_LOWER) {
		if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
			/* Single recursive nexthop */
			handle_recursive_depend(&newnhe->nhg_depends, nh->resolved, afi,
						newnhe->type, pic);
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

			depends_find_add(&newnhe->nhg_depends, nh, afi, newnhe->type, from_dplane,
					 pic);
		}
	}

	if (recursive)
		SET_FLAG(newnhe->flags, NEXTHOP_GROUP_RECURSIVE);

	/* Attach dependent backpointers to singletons */
	zebra_nhg_connect_depends(newnhe, &newnhe->nhg_depends);

	/**
	 * Backup Nexthops
	 */

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
		handle_recursive_depend(&backup_nhe->nhg_depends, nh->resolved, afi,
					backup_nhe->type, pic);
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

			depends_find_add(&backup_nhe->nhg_depends, nh, afi, backup_nhe->type,
					 from_dplane, pic);
		}
	}

	if (recursive)
		SET_FLAG(backup_nhe->flags, NEXTHOP_GROUP_RECURSIVE);

done:
	nh = (*nhe)->nhg.nexthop;
	createdPic = zebra_need_to_create_pic(nh);

	if (createdPic && !pic) {
		zebra_pic_nhe_find(&pic_nhe, *nhe, afi, from_dplane);
		if (pic_nhe && ((*nhe)->pic_nhe) == NULL) {
			(*nhe)->pic_nhe = pic_nhe;
			zebra_nhg_increment_ref(pic_nhe);
		}
	}

	/* Reset time since last update */
	(*nhe)->uptime = monotime(NULL);

	return created;
}

/*find or create pic*/
bool zebra_pic_nhe_find(struct nhg_hash_entry **pic_nhe, /* return value */
			struct nhg_hash_entry *nhe, afi_t afi, bool from_dplane)
{
	bool created = false;
	struct nhg_hash_entry *picnhe;
	struct nexthop *nh = NULL;
	struct nhg_hash_entry pic_nh_lookup = {};
	//struct nexthop *nexthop_tmp;
	struct nexthop *pic_nexthop_tmp;
	bool ret = 0;

	if (nhe->pic_nhe) {
		*pic_nhe = nhe->pic_nhe;
		return false;
	}
	/* Use a temporary nhe to find pic nh */
	pic_nh_lookup.type = ZEBRA_ROUTE_NHG;
	pic_nh_lookup.vrf_id = nhe->vrf_id;
	SET_FLAG(pic_nh_lookup.flags, NEXTHOP_GROUP_PIC_NHT);
	/* the nhg.nexthop is sorted */
	for (nh = nhe->nhg.nexthop; nh; nh = nh->next) {
		if (nh->type == NEXTHOP_TYPE_IFINDEX)
			continue;
		pic_nexthop_tmp = nexthop_dup_no_context(nh, NULL);
		ret = nexthop_group_add_sorted_nodup(&pic_nh_lookup.nhg, pic_nexthop_tmp);
		if (!ret)
			nexthop_free(pic_nexthop_tmp);
	}
	if (pic_nh_lookup.nhg.nexthop == NULL) {
		*pic_nhe = NULL;
		return false;
	}

	if (!zebra_nhg_depends_is_empty(nhe) || pic_nh_lookup.nhg.nexthop->next) {
		/* Groups can have all vrfs and AF's in them */
		pic_nh_lookup.afi = AFI_UNSPEC;
	} else {
		switch (pic_nh_lookup.nhg.nexthop->type) {
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
			pic_nh_lookup.afi = afi;
			break;
		case (NEXTHOP_TYPE_IPV4_IFINDEX):
		case (NEXTHOP_TYPE_IPV4):
			pic_nh_lookup.afi = AFI_IP;
			break;
		case (NEXTHOP_TYPE_IPV6_IFINDEX):
		case (NEXTHOP_TYPE_IPV6):
			pic_nh_lookup.afi = AFI_IP6;
			break;
		}
	}

	created = zebra_nhe_find(&picnhe, &pic_nh_lookup, NULL, afi, from_dplane, true);

	*pic_nhe = picnhe;
	if (pic_nh_lookup.nhg.nexthop)
		nexthops_free(pic_nh_lookup.nhg.nexthop);
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: create PIC nhe id %d for nhe %d", __func__, picnhe->id, nhe->id);
	return created;
}

/*
 * Lookup or create an nhe, based on an nhg or an nhe id.
 */
static bool zebra_nhg_find(struct nhg_hash_entry **nhe, uint32_t id, struct nexthop_group *nhg,
			   struct nhg_connected_tree_head *nhg_depends, vrf_id_t vrf_id, afi_t afi,
			   int type, bool from_dplane, bool pic)
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
	if (nhg_depends || lookup.nhg.nexthop->next) {
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

	created = zebra_nhe_find(nhe, &lookup, nhg_depends, afi, from_dplane, pic);

	return created;
}

/* Find/create a single nexthop */
static struct nhg_hash_entry *zebra_nhg_find_nexthop(uint32_t id, struct nexthop *nh, afi_t afi,
						     int type, bool from_dplane, bool pic)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nexthop_group nhg = {};
	vrf_id_t vrf_id = !vrf_is_backend_netns() ? VRF_DEFAULT : nh->vrf_id;

	nexthop_group_add_sorted(&nhg, nh);

	zebra_nhg_find(&nhe, id, &nhg, NULL, vrf_id, afi, type, from_dplane, pic);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%pNG)", __func__, nh, nhe, nhe);

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

static uint16_t nhg_ctx_get_count(const struct nhg_ctx *ctx)
{
	return ctx->count;
}

static struct nh_grp *nhg_ctx_get_grp(struct nhg_ctx *ctx)
{
	return ctx->u.grp;
}

static struct nhg_resilience *nhg_ctx_get_resilience(struct nhg_ctx *ctx)
{
	return &ctx->resilience;
}

static struct nhg_ctx *nhg_ctx_new(void)
{
	struct nhg_ctx *new;

	new = XCALLOC(MTYPE_NHG_CTX, sizeof(struct nhg_ctx));

	return new;
}

void nhg_ctx_free(struct nhg_ctx **ctx)
{
	struct nexthop *nh;

	if (ctx == NULL)
		return;

	assert((*ctx) != NULL);

	if (nhg_ctx_get_count(*ctx))
		goto done;

	nh = nhg_ctx_get_nh(*ctx);

	nexthop_del_labels(nh);
	nexthop_del_srv6_seg6local(nh);
	nexthop_del_srv6_seg6(nh);

done:
	XFREE(MTYPE_NHG_CTX, *ctx);
}

static struct nhg_ctx *nhg_ctx_init(uint32_t id, struct nexthop *nh, struct nh_grp *grp,
				    vrf_id_t vrf_id, afi_t afi, int type, uint16_t count,
				    struct nhg_resilience *resilience)
{
	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_new();

	ctx->id = id;
	ctx->vrf_id = vrf_id;
	ctx->afi = afi;
	ctx->type = type;
	ctx->count = count;

	if (resilience)
		ctx->resilience = *resilience;

	if (count)
		/* Copy over the array */
		memcpy(&ctx->u.grp, grp, count * sizeof(struct nh_grp));
	else if (nh)
		ctx->u.nh = *nh;

	return ctx;
}

static void zebra_nhg_set_valid(struct nhg_hash_entry *nhe, bool valid)
{
	struct nhg_connected *rb_node_dep;

	if (valid)
		SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
	else {
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);

		/* If we're in shutdown, this interface event needs to clean
		 * up installed NHGs, so don't clear that flag directly.
		 */
		if (!zebra_router_in_shutdown())
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
	}

	/* Update validity of nexthops depending on it */
	frr_each (nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep) {
		if (!valid) {
			/*
			 * Grab the first nexthop from the depending nexthop group
			 * then let's find the nexthop in that group that matches
			 * my individual nexthop and mark it as no longer ACTIVE
			 */
			struct nexthop *nexthop = rb_node_dep->nhe->nhg.nexthop;

			while (nexthop) {
				if (nexthop_same(nexthop, nhe->nhg.nexthop))
					break;

				nexthop = nexthop->next;
			}

			if (nexthop)
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		}
		zebra_nhg_set_valid(rb_node_dep->nhe, valid);
	}
}

void zebra_nhg_check_valid(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;
	bool valid = false;

	/*
	 * If I have other nhe's depending on me, or I have nothing
	 * I am depending on then this is a
	 * singleton nhe so set this nexthops flag as appropriate.
	 */
	if (nhg_connected_tree_count(&nhe->nhg_depends) ||
	    nhg_connected_tree_count(&nhe->nhg_dependents) == 0) {
		UNSET_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_FIB);
		UNSET_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	/* If anthing else in the group is valid, the group is valid */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		if (CHECK_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_VALID)) {
			valid = true;
			break;
		}
	}

	zebra_nhg_set_valid(nhe, valid);
}

static void zebra_nhg_release_all_deps(struct nhg_hash_entry *nhe)
{
	/* Remove it from any lists it may be on */
	zebra_nhg_depends_release(nhe);
	zebra_nhg_dependents_release(nhe);
	if (nhe->ifp) {
		struct zebra_if *zif = nhe->ifp->info;

		nhg_connected_tree_del_nhe(&zif->nhg_dependents, nhe);
	}
}

static void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG)", __func__, nhe, nhe);

	zebra_nhg_release_all_deps(nhe);

	/*
	 * If its not zebra owned, we didn't store it here and have to be
	 * sure we don't clear one thats actually being used.
	 */
	if (nhe->id < ZEBRA_NHG_PROTO_LOWER)
		hash_release(zrouter.nhgs, nhe);

	hash_release(zrouter.nhgs_id, nhe);
}

static void zebra_nhg_handle_uninstall(struct nhg_hash_entry *nhe)
{
	zebra_nhg_release(nhe);
	zebra_nhg_free(nhe);
}

static void zebra_nhg_handle_install(struct nhg_hash_entry *nhe, bool install)
{
	/* Update validity of groups depending on it */
	struct nhg_connected *rb_node_dep;

	frr_each_safe (nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep) {
		zebra_nhg_set_valid(rb_node_dep->nhe, true);
		/* install dependent NHG into kernel */
		if (install) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"%s nh id %u (flags 0x%x) associated dependent NHG %pNG install",
					__func__, nhe->id, nhe->flags,
					rb_node_dep->nhe);
			zebra_nhg_install_kernel(rb_node_dep->nhe,
						 ZEBRA_ROUTE_MAX);
		}
	}
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
			"Kernel %s a nexthop group with ID (%pNG) that we are still using for a route, sending it back down",
			(is_delete ? "deleted" : "updated"), nhe);

		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
		zebra_nhg_install_kernel(nhe, ZEBRA_ROUTE_MAX);
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
	uint16_t count = nhg_ctx_get_count(ctx);
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
					  nhg_ctx_get_grp(ctx), count,
					  nhg_ctx_get_resilience(ctx))) {
			depends_decrement_free(&nhg_depends);
			nexthop_group_delete(&nhg);
			return -ENOENT;
		}

		if (!zebra_nhg_find(&nhe, id, nhg, &nhg_depends, vrf_id, afi, type, true, false))
			depends_decrement_free(&nhg_depends);

		/* These got copied over in zebra_nhg_alloc() */
		nexthop_group_delete(&nhg);
	} else
		nhe = zebra_nhg_find_nexthop(id, nhg_ctx_get_nh(ctx), afi, type, true, false);

	if (!nhe) {
		flog_err(
			EC_ZEBRA_TABLE_LOOKUP_FAILED,
			"Zebra failed to find or create a nexthop hash entry for ID (%u)",
			id);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG) is new", __func__, nhe, nhe);

	/*
	 * If daemon nhg from the kernel, add a refcnt here to indicate the
	 * daemon owns it.
	 */
	if (PROTO_OWNED(nhe))
		zebra_nhg_increment_ref(nhe);

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

	if (rib_queue_nhg_ctx_add(ctx)) {
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
		break;
	case NHG_CTX_OP_NONE:
		break;
	}

	nhg_ctx_set_status(ctx, (ret ? NHG_CTX_FAILURE : NHG_CTX_SUCCESS));

	nhg_ctx_fini(&ctx);

	return ret;
}

/* Kernel-side, you either get a single new nexthop or a array of ID's */
int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh, struct nh_grp *grp, uint16_t count,
			  vrf_id_t vrf_id, afi_t afi, int type, int startup,
			  struct nhg_resilience *nhgr)
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

	ctx = nhg_ctx_init(id, nh, grp, vrf_id, afi, type, count, nhgr);
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

	ctx = nhg_ctx_init(id, NULL, NULL, vrf_id, 0, 0, 0, NULL);

	nhg_ctx_set_op(ctx, NHG_CTX_OP_DEL);

	if (queue_add(ctx)) {
		nhg_ctx_fini(&ctx);
		return -1;
	}

	return 0;
}

/* Some dependency helper functions */
static struct nhg_hash_entry *depends_find_recursive(const struct nexthop *nh, afi_t afi, int type,
						     bool pic)
{
	struct nhg_hash_entry *nhe;
	struct nexthop *lookup = NULL;

	lookup = nexthop_dup(nh, NULL);

	nhe = zebra_nhg_find_nexthop(0, lookup, afi, type, false, pic);

	nexthops_free(lookup);

	return nhe;
}

static struct nhg_hash_entry *depends_find_singleton(const struct nexthop *nh, afi_t afi, int type,
						     bool from_dplane, bool pic)
{
	struct nhg_hash_entry *nhe;
	struct nexthop lookup = {};

	/* Capture a snapshot of this single nh; it might be part of a list,
	 * so we need to make a standalone copy.
	 */
	nexthop_copy_no_recurse(&lookup, nh, NULL);

	/*
	 * So this is to intentionally cause the singleton nexthop
	 * to be created with a weight of 1.
	 */
	lookup.weight = 1;
	nhe = zebra_nhg_find_nexthop(0, &lookup, afi, type, from_dplane, pic);

	/* The copy may have allocated labels; free them if necessary. */
	nexthop_del_labels(&lookup);
	nexthop_del_srv6_seg6local(&lookup);
	nexthop_del_srv6_seg6(&lookup);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%pNG)", __func__, nh, nhe, nhe);

	return nhe;
}

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi, int type,
					   bool from_dplane, bool pic)
{
	struct nhg_hash_entry *nhe = NULL;

	if (!nh)
		goto done;

	/* We are separating these functions out to increase handling speed
	 * in the non-recursive case (by not alloc/freeing)
	 */
	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE))
		nhe = depends_find_recursive(nh, afi, type, pic);
	else
		nhe = depends_find_singleton(nh, afi, type, from_dplane, pic);


	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		zlog_debug("%s: nh %pNHv %s => %p (%pNG)", __func__, nh,
			   CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE) ? "(R)"
									 : "",
			   nhe, nhe);
	}

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

static struct nhg_hash_entry *depends_find_add(struct nhg_connected_tree_head *head,
					       struct nexthop *nh, afi_t afi, int type,
					       bool from_dplane, bool pic)
{
	struct nhg_hash_entry *depend = NULL;

	depend = depends_find(nh, afi, type, from_dplane, pic);

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
struct nhg_hash_entry *zebra_nhg_rib_find(uint32_t id, struct nexthop_group *nhg, afi_t rt_afi,
					  int type, bool pic)
{
	struct nhg_hash_entry *nhe = NULL;
	vrf_id_t vrf_id;

	/*
	 * CLANG SA is complaining that nexthop may be NULL
	 * Make it happy but this is ridonc
	 */
	assert(nhg->nexthop);
	vrf_id = !vrf_is_backend_netns() ? VRF_DEFAULT : nhg->nexthop->vrf_id;

	zebra_nhg_find(&nhe, id, nhg, NULL, vrf_id, rt_afi, type, false, pic);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: => nhe %p (%pNG)", __func__, nhe, nhe);

	return nhe;
}

/* Find an nhe based on a route's nhe */
struct nhg_hash_entry *
zebra_nhg_rib_find_nhe(struct nhg_hash_entry *rt_nhe, afi_t rt_afi)
{
	struct nhg_hash_entry *nhe = NULL;

	if (!rt_nhe) {
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "No nhg_hash_entry passed to %s", __func__);
		return NULL;
	}

	if (!rt_nhe->nhg.nexthop) {
		flog_err(EC_ZEBRA_TABLE_LOOKUP_FAILED,
			 "No nexthop passed to %s", __func__);
		return NULL;
	}

	zebra_nhe_find(&nhe, rt_nhe, NULL, rt_afi, false, false);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: rt_nhe %p(%pNG) => nhe %p(%pNG)", __func__,
			   rt_nhe, rt_nhe, nhe, nhe);

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
	if (nhe->pic_nhe)
		zebra_nhg_decrement_ref(nhe->pic_nhe);
	nhe->pic_nhe = NULL;
	nhg_connected_tree_free(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_dependents);
}

void zebra_nhg_free(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		/* Group or singleton? */
		if (nhe->nhg.nexthop && nhe->nhg.nexthop->next)
			zlog_debug("%s: nhe %p (%pNG), refcnt %d", __func__,
				   nhe, nhe, nhe->refcnt);
		else
			zlog_debug("%s: nhe %p (%pNG), refcnt %d, NH %pNHv",
				   __func__, nhe, nhe, nhe->refcnt,
				   nhe->nhg.nexthop);
	}

	EVENT_OFF(nhe->timer);

	zebra_nhg_free_members(nhe);

	XFREE(MTYPE_NHG, nhe);
}

/*
 * Let's just drop the memory associated with each item
 */
void zebra_nhg_hash_free(void *p)
{
	struct nhg_hash_entry *nhe = p;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		/* Group or singleton? */
		if (nhe->nhg.nexthop && nhe->nhg.nexthop->next)
			zlog_debug("%s: nhe %p (%u), refcnt %d", __func__, nhe,
				   nhe->id, nhe->refcnt);
		else
			zlog_debug("%s: nhe %p (%pNG), refcnt %d, NH %pNHv",
				   __func__, nhe, nhe, nhe->refcnt,
				   nhe->nhg.nexthop);
	}

	EVENT_OFF(nhe->timer);

	nexthops_free(nhe->nhg.nexthop);

	XFREE(MTYPE_NHG, nhe);
}

/*
 * On cleanup there are nexthop groups that have not
 * been resolved at all( a nhe->id of 0 ).  As such
 * zebra needs to clean up the memory associated with
 * those entries.
 */
void zebra_nhg_hash_free_zero_id(struct hash_bucket *b, void *arg)
{
	struct nhg_hash_entry *nhe = b->data;
	struct nhg_connected *dep;

	while ((dep = nhg_connected_tree_pop(&nhe->nhg_depends))) {
		if (dep->nhe->id == 0)
			zebra_nhg_hash_free(dep->nhe);

		nhg_connected_free(dep);
	}

	while ((dep = nhg_connected_tree_pop(&nhe->nhg_dependents)))
		nhg_connected_free(dep);

	if (nhe->backup_info && nhe->backup_info->nhe->id == 0) {
		while ((dep = nhg_connected_tree_pop(
				&nhe->backup_info->nhe->nhg_depends)))
			nhg_connected_free(dep);

		zebra_nhg_hash_free(nhe->backup_info->nhe);

		XFREE(MTYPE_NHG, nhe->backup_info);
	}
}

static void zebra_nhg_timer(struct event *thread)
{
	struct nhg_hash_entry *nhe = EVENT_ARG(thread);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("Nexthop Timer for nhe: %pNG", nhe);

	if (nhe->refcnt == 1)
		zebra_nhg_decrement_ref(nhe);
}

void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG) %d => %d", __func__, nhe, nhe,
			   nhe->refcnt, nhe->refcnt - 1);

	nhe->refcnt--;

	if (!zebra_router_in_shutdown() && nhe->refcnt <= 0 &&
	    CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) &&
	    !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_KEEP_AROUND)) {
		nhe->refcnt = 1;
		SET_FLAG(nhe->flags, NEXTHOP_GROUP_KEEP_AROUND);
		event_add_timer(zrouter.master, zebra_nhg_timer, nhe,
				zrouter.nhg_keep, &nhe->timer);
		return;
	}

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_decrement_ref(&nhe->nhg_depends);

	if (ZEBRA_NHG_CREATED(nhe) && nhe->refcnt <= 0)
		zebra_nhg_uninstall_kernel(nhe);
}

void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG) %d => %d", __func__, nhe, nhe,
			   nhe->refcnt, nhe->refcnt + 1);

	nhe->refcnt++;

	if (event_is_scheduled(nhe->timer)) {
		EVENT_OFF(nhe->timer);
		nhe->refcnt--;
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_KEEP_AROUND);
	}

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_increment_ref(&nhe->nhg_depends);
}

static struct nexthop *nexthop_set_resolved(afi_t afi,
					    const struct nexthop *newhop,
					    struct nexthop *nexthop,
					    struct zebra_sr_policy *policy)
{
	struct nexthop *resolved_hop;
	uint8_t num_labels = 0;
	mpls_label_t labels[MPLS_MAX_LABELS];
	enum lsp_types_t label_type = ZEBRA_LSP_NONE;
	int i = 0;

	resolved_hop = nexthop_new();
	SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ACTIVE);

	resolved_hop->vrf_id = nexthop->vrf_id;

	/* Using weighted ECMP, we should respect the weight and use
	 * the same value for non-recursive next-hop.
	 */
	resolved_hop->weight = nexthop->weight;

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

	if (CHECK_FLAG(newhop->flags, NEXTHOP_FLAG_ONLINK))
		SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_ONLINK);

	/* Copy labels of the resolved route and the parent resolving to it */
	if (policy) {
		int label_num = 0;

		/*
		 * Don't push the first SID if the corresponding action in the
		 * LFIB is POP.
		 */
		if (!newhop->nh_label || !newhop->nh_label->num_labels
		    || newhop->nh_label->label[0] == MPLS_LABEL_IMPLICIT_NULL)
			label_num = 1;

		for (; label_num < policy->segment_list.label_num; label_num++)
			labels[num_labels++] =
				policy->segment_list.labels[label_num];
		label_type = policy->segment_list.type;
	} else if (newhop->nh_label) {
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

	if (nexthop->nh_srv6) {
		if (nexthop->nh_srv6->seg6local_action !=
		    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
			nexthop_add_srv6_seg6local(resolved_hop,
						   nexthop->nh_srv6
							   ->seg6local_action,
						   &nexthop->nh_srv6
							    ->seg6local_ctx);
		if (nexthop->nh_srv6->seg6_segs)
			nexthop_add_srv6_seg6(resolved_hop,
					      &nexthop->nh_srv6->seg6_segs->seg[0],
					      nexthop->nh_srv6->seg6_segs
						      ->num_segs);
	}

	resolved_hop->rparent = nexthop;
	_nexthop_add(&nexthop->resolved, resolved_hop);

	return resolved_hop;
}

/* Checks if nexthop we are trying to resolve to is valid */
static bool nexthop_valid_resolve(const struct nexthop *nexthop,
				  const struct nexthop *resolved)
{
	/* Can't resolve to a recursive nexthop */
	if (CHECK_FLAG(resolved->flags, NEXTHOP_FLAG_RECURSIVE))
		return false;

	/* Must be ACTIVE */
	if (!CHECK_FLAG(resolved->flags, NEXTHOP_FLAG_ACTIVE))
		return false;

	/* Must not be duplicate */
	if (CHECK_FLAG(resolved->flags, NEXTHOP_FLAG_DUPLICATE))
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
 * Downstream VNI and Single VXlan device check.
 *
 * If it has nexthop VNI labels at this point it must be D-VNI allocated
 * and all the nexthops have to be on an SVD.
 *
 * If SVD is not available, mark as inactive.
 */
static bool nexthop_set_evpn_dvni_svd(vrf_id_t re_vrf_id,
				      struct nexthop *nexthop)
{
	if (!is_vrf_l3vni_svd_backed(re_vrf_id)) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
			struct vrf *vrf = vrf_lookup_by_id(re_vrf_id);

			zlog_debug(
				"nexthop %pNHv D-VNI but route's vrf %s(%u) doesn't use SVD",
				nexthop, VRF_LOGNAME(vrf), re_vrf_id);
		}

		return false;
	}

	nexthop->ifindex = get_l3vni_vxlan_ifindex(re_vrf_id);
	nexthop->vrf_id = 0;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("nexthop %pNHv using SVD", nexthop);

	return true;
}

/*
 * Given a nexthop we need to properly recursively resolve
 * the route.  As such, do a table lookup to find and match
 * if at all possible.  Set the nexthop->ifindex and resolved_id
 * as appropriate
 */
static int resolve_backup_nexthops(const struct nexthop *nexthop,
				   const struct nhg_hash_entry *nhe,
				   struct nexthop *resolved,
				   struct nhg_hash_entry *resolve_nhe,
				   struct backup_nh_map_s *map)
{
	int i, j, idx;
	const struct nexthop *bnh;
	struct nexthop *nh, *newnh;
	mpls_label_t labels[MPLS_MAX_LABELS];
	uint8_t num_labels;

	assert(nexthop->backup_num <= NEXTHOP_MAX_BACKUPS);

	/* Locate backups from the original nexthop's backup index and nhe */
	for (i = 0; i < nexthop->backup_num; i++) {
		idx = nexthop->backup_idx[i];

		/* Do we already know about this particular backup? */
		for (j = 0; j < map->map_count; j++) {
			if (map->map[j].orig_idx == idx)
				break;
		}

		if (j < map->map_count) {
			resolved->backup_idx[resolved->backup_num] =
				map->map[j].new_idx;
			resolved->backup_num++;

			SET_FLAG(resolved->flags, NEXTHOP_FLAG_HAS_BACKUP);

			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("%s: found map idx orig %d, new %d",
					   __func__, map->map[j].orig_idx,
					   map->map[j].new_idx);

			continue;
		}

		/* We can't handle any new map entries at this point. */
		if (map->map_count == MULTIPATH_NUM)
			break;

		/* Need to create/copy a new backup */
		bnh = nhe->backup_info->nhe->nhg.nexthop;
		for (j = 0; j < idx; j++) {
			if (bnh == NULL)
				break;
			bnh = bnh->next;
		}

		/* Whoops - bad index in the nexthop? */
		if (bnh == NULL)
			continue;

		if (resolve_nhe->backup_info == NULL)
			resolve_nhe->backup_info = zebra_nhg_backup_alloc();

		/* Update backup info in the resolving nexthop and its nhe */
		newnh = nexthop_dup_no_recurse(bnh, NULL);

		/* We may need some special handling for mpls labels: the new
		 * backup needs to carry the recursive nexthop's labels,
		 * if any: they may be vrf labels e.g.
		 * The original/inner labels are in the stack of 'resolve_nhe',
		 * if that is longer than the stack in 'nexthop'.
		 */
		if (newnh->nh_label && resolved->nh_label &&
		    nexthop->nh_label) {
			if (resolved->nh_label->num_labels >
			    nexthop->nh_label->num_labels) {
				/* Prepare new label stack */
				num_labels = 0;
				for (j = 0; j < newnh->nh_label->num_labels;
				     j++) {
					labels[j] = newnh->nh_label->label[j];
					num_labels++;
				}

				/* Include inner labels */
				for (j = nexthop->nh_label->num_labels;
				     j < resolved->nh_label->num_labels;
				     j++) {
					labels[num_labels] =
						resolved->nh_label->label[j];
					num_labels++;
				}

				/* Replace existing label stack in the backup */
				nexthop_del_labels(newnh);
				nexthop_add_labels(newnh, bnh->nh_label_type,
						   num_labels, labels);
			}
		}

		/* Need to compute the new backup index in the new
		 * backup list, and add to map struct.
		 */
		j = 0;
		nh = resolve_nhe->backup_info->nhe->nhg.nexthop;
		if (nh) {
			while (nh->next) {
				nh = nh->next;
				j++;
			}

			nh->next = newnh;
			j++;

		} else	/* First one */
			resolve_nhe->backup_info->nhe->nhg.nexthop = newnh;

		/* Capture index */
		resolved->backup_idx[resolved->backup_num] = j;
		resolved->backup_num++;

		SET_FLAG(resolved->flags, NEXTHOP_FLAG_HAS_BACKUP);

		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("%s: added idx orig %d, new %d",
				   __func__, idx, j);

		/* Update map/cache */
		map->map[map->map_count].orig_idx = idx;
		map->map[map->map_count].new_idx = j;
		map->map_count++;
	}

	return 0;
}

/*
 * So this nexthop resolution has decided that a connected route
 * is the correct choice.  At this point in time if FRR has multiple
 * connected routes that all point to the same prefix one will be
 * selected, *but* the particular interface may not be the one
 * that the nexthop points at.  Let's look at all the available
 * connected routes on this node and if any of them auto match
 * the routes nexthops ifindex that is good enough for a match
 *
 * This code is depending on the fact that a nexthop->ifindex is 0
 * if it is not known, if this assumption changes, yummy!
 * Additionally a ifindx of 0 means figure it out for us.
 */
static struct route_entry *
zebra_nhg_connected_ifindex(struct route_node *rn, struct route_entry *match,
			    int32_t curr_ifindex)
{
	struct nexthop *newhop = match->nhe->nhg.nexthop;
	struct route_entry *re;

	assert(newhop); /* What a kick in the patooey */

	if (curr_ifindex == 0)
		return match;

	if (curr_ifindex == newhop->ifindex)
		return match;

	/*
	 * At this point we know that this route is matching a connected
	 * but there are possibly a bunch of connected routes that are
	 * alive that should be considered as well.  So let's iterate over
	 * all the re's and see if they are connected as well and maybe one
	 * of those ifindexes match as well.
	 */
	RNODE_FOREACH_RE (rn, re) {
		if (re->type != ZEBRA_ROUTE_CONNECT &&
		    re->type != ZEBRA_ROUTE_LOCAL)
			continue;

		if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
			continue;

		/*
		 * zebra has a connected route that is not removed
		 * let's test if it is good
		 */
		newhop = re->nhe->nhg.nexthop;
		assert(newhop);
		if (curr_ifindex == newhop->ifindex)
			return re;
	}

	return match;
}

/*
 * Given a nexthop we need to properly recursively resolve,
 * do a table lookup to find and match if at all possible.
 * Set the nexthop->ifindex and resolution info as appropriate.
 */
static int nexthop_active(struct nexthop *nexthop, struct nhg_hash_entry *nhe,
			  const struct prefix *top, int type, uint32_t flags,
			  uint32_t *pmtu, vrf_id_t vrf_id)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *match = NULL;
	int resolved;
	struct zebra_nhlfe *nhlfe;
	struct nexthop *newhop;
	struct interface *ifp;
	rib_dest_t *dest;
	struct zebra_vrf *zvrf;
	struct in_addr local_ipv4;
	struct in_addr *ipv4;
	afi_t afi = AFI_IP;

	/* Reset some nexthop attributes that we'll recompute if necessary */
	if ((nexthop->type == NEXTHOP_TYPE_IPV4)
	    || (nexthop->type == NEXTHOP_TYPE_IPV6))
		nexthop->ifindex = 0;

	UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
	nexthops_free(nexthop->resolved);
	nexthop->resolved = NULL;

	/*
	 * Set afi based on nexthop type.
	 * Some nexthop types get special handling, possibly skipping
	 * the normal processing.
	 */
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:

		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		/* If the interface exists and its operative, it's active */
		if (ifp && (if_is_operative(ifp)))
			return 1;
		else
			return 0;
		break;

	case NEXTHOP_TYPE_IPV6_IFINDEX:
		afi = AFI_IP6;

		if (IN6_IS_ADDR_LINKLOCAL(&nexthop->gate.ipv6)) {
			ifp = if_lookup_by_index(nexthop->ifindex,
						 nexthop->vrf_id);
			if (ifp && if_is_operative(ifp))
				return 1;
			else
				return 0;
		}
		break;

	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		afi = AFI_IP;
		break;
	case NEXTHOP_TYPE_IPV6:
		afi = AFI_IP6;
		break;

	case NEXTHOP_TYPE_BLACKHOLE:
		return 1;
	}

	/*
	 * If the nexthop has been marked as 'onlink' we just need to make
	 * sure the nexthop's interface is known and is operational.
	 */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK)) {
		/* DVNI/SVD Checks for EVPN routes */
		if (nexthop->nh_label &&
		    nexthop->nh_label_type == ZEBRA_LSP_EVPN &&
		    !nexthop_set_evpn_dvni_svd(vrf_id, nexthop))
			return 0;

		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);
		if (!ifp) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("nexthop %pNHv marked onlink but nhif %u doesn't exist",
					   nexthop, nexthop->ifindex);
			return 0;
		}
		if (!if_is_operative(ifp)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("nexthop %pNHv marked onlink but nhif %s is not operational",
					   nexthop, ifp->name);
			return 0;
		}
		return 1;
	}

	/* Validation for ipv4 mapped ipv6 nexthop. */
	if (IS_MAPPED_IPV6(&nexthop->gate.ipv6)) {
		afi = AFI_IP;
		ipv4 = &local_ipv4;
		ipv4_mapped_ipv6_to_ipv4(&nexthop->gate.ipv6, ipv4);
	} else {
		ipv4 = &nexthop->gate.ipv4;
	}

	/* Processing for nexthops with SR 'color' attribute, using
	 * the corresponding SR policy object.
	 */
	if (nexthop->srte_color) {
		struct ipaddr endpoint = {0};
		struct zebra_sr_policy *policy;

		switch (afi) {
		case AFI_IP:
			endpoint.ipa_type = IPADDR_V4;
			endpoint.ipaddr_v4 = *ipv4;
			break;
		case AFI_IP6:
			endpoint.ipa_type = IPADDR_V6;
			endpoint.ipaddr_v6 = nexthop->gate.ipv6;
			break;
		case AFI_UNSPEC:
		case AFI_L2VPN:
		case AFI_MAX:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address-family: %u", __func__,
				 afi);
			exit(1);
		}

		policy = zebra_sr_policy_find(nexthop->srte_color, &endpoint);
		if (policy && policy->status == ZEBRA_SR_POLICY_UP) {
			resolved = 0;
			frr_each_safe (nhlfe_list, &policy->lsp->nhlfe_list,
				       nhlfe) {
				if (!CHECK_FLAG(nhlfe->flags,
						NHLFE_FLAG_SELECTED)
				    || CHECK_FLAG(nhlfe->flags,
						  NHLFE_FLAG_DELETED))
					continue;
				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, nhlfe->nexthop,
						     nexthop, policy);
				resolved = 1;
			}
			if (resolved)
				return 1;
		}
	}

	/* Make lookup prefix. */
	memset(&p, 0, sizeof(struct prefix));
	switch (afi) {
	case AFI_IP:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = *ipv4;
		break;
	case AFI_IP6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = nexthop->gate.ipv6;
		break;
	case AFI_UNSPEC:
	case AFI_L2VPN:
	case AFI_MAX:
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
		if (prefix_same(&rn->p, top))
			if (((afi == AFI_IP)
			     && (rn->p.prefixlen != IPV4_MAX_BITLEN))
			    || ((afi == AFI_IP6)
				&& (rn->p.prefixlen != IPV6_MAX_BITLEN))) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"        %s: Matched against ourself and prefix length is not max bit length",
						__func__);
				goto continue_up_tree;
			}

		/* Pick up selected route. */
		/* However, do not resolve over default route unless explicitly
		 * allowed.
		 */
		if (is_default_prefix(&rn->p)
		    && !rnh_resolve_via_default(zvrf, p.family)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug("        :%s: %pFX Resolved against default route",
					   __func__, &p);
			return 0;
		}

		dest = rib_dest_from_rnode(rn);
		if (dest && dest->selected_fib &&
		    (!CHECK_FLAG(dest->selected_fib->status,
				 ROUTE_ENTRY_REMOVED) ||
		     CHECK_FLAG(dest->selected_fib->status,
				ROUTE_ENTRY_ROUTE_REPLACING)) &&
		    dest->selected_fib->type != ZEBRA_ROUTE_TABLE)
			match = dest->selected_fib;

		/* If there is no selected route or matched route is EGP, go up
		 * tree.
		 */

		/* If the candidate match's type is considered "connected",
		 * we consider it first.
		 */
		if (match && (RIB_CONNECTED_ROUTE(match) ||
			      (RIB_SYSTEM_ROUTE(match) && RSYSTEM_ROUTE(type)))) {
			match = zebra_nhg_connected_ifindex(rn, match,
							    nexthop->ifindex);

			newhop = match->nhe->nhg.nexthop;
			if (nexthop->type == NEXTHOP_TYPE_IPV4) {
				nexthop->ifindex = newhop->ifindex;
				nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			} else if (nexthop->type == NEXTHOP_TYPE_IPV6) {
				nexthop->ifindex = newhop->ifindex;
				nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			} else if (nexthop->ifindex != newhop->ifindex) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"%s: %pNHv given ifindex does not match nexthops ifindex found: %pNHv",
						__func__, nexthop, newhop);
				goto continue_up_tree;
			}

			/* NHRP special case: need to indicate onlink */
			if (match->type == ZEBRA_ROUTE_NHRP)
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK);

			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"%s: CONNECT match %p (%pNG), newhop %pNHv",
					__func__, match, match->nhe, newhop);

			return 1;
		} else if (match && CHECK_FLAG(flags, ZEBRA_FLAG_ALLOW_RECURSION)) {
			struct nexthop_group *nhg;
			struct nexthop *resolver;
			struct backup_nh_map_s map = {};

			resolved = 0;

			/*
			 * Only useful if installed or being Route Replacing
			 * Why Being Route Replaced as well?
			 * Imagine a route A and route B( that depends on A )
			 * for recursive resolution and A already exists in the
			 * zebra rib.  If zebra receives the routes
			 * for resolution at aproximately the same time in the [
			 * B, A ] order on the workQ.  If this happens then
			 * normal route resolution will happen and B will be
			 * resolved successfully and then A will be resolved
			 * successfully. Now imagine the reversed order [A, B].
			 * A will be resolved and then scheduled for installed
			 * (Thus not having the ROUTE_ENTRY_INSTALLED flag ).  B
			 * will then get resolved and fail to be installed
			 * because the original below test.  Let's `loosen` this
			 * up a tiny bit and allow the
			 * ROUTE_ENTRY_ROUTE_REPLACING flag ( that is set when a
			 * Route Replace operation is being initiated on A now )
			 * to now satisfy this situation.  This will allow
			 * either order in the workQ to work properly.
			 */
			if (!CHECK_FLAG(match->status, ROUTE_ENTRY_INSTALLED) &&
			    !CHECK_FLAG(match->status,
					ROUTE_ENTRY_ROUTE_REPLACING)) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"%s: match %p (%pNG) not installed or being Route Replaced",
						__func__, match, match->nhe);

				if (CHECK_FLAG(match->status,
					       ROUTE_ENTRY_QUEUED))
					goto continue_up_tree;

				goto done_with_match;
			}

			/* Examine installed nexthops; note that there
			 * may not be any installed primary nexthops if
			 * only backups are installed.
			 */
			nhg = rib_get_fib_nhg(match);
			for (ALL_NEXTHOPS_PTR(nhg, newhop)) {
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug(
						"%s: RECURSIVE match %p (%pNG), newhop %pNHv",
						__func__, match, match->nhe,
						newhop);

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				resolver = nexthop_set_resolved(afi, newhop,
								nexthop, NULL);
				resolved = 1;

				/* If there are backup nexthops, capture
				 * that info with the resolving nexthop.
				 */
				if (resolver && newhop->backup_num > 0) {
					resolve_backup_nexthops(newhop,
								match->nhe,
								resolver, nhe,
								&map);
				}
			}

			/* Examine installed backup nexthops, if any. There
			 * are only installed backups *if* there is a
			 * dedicated fib list. The UI can also control use
			 * of backups for resolution.
			 */
			nhg = rib_get_fib_backup_nhg(match);
			if (!use_recursive_backups ||
			    nhg == NULL || nhg->nexthop == NULL)
				goto done_with_match;

			for (ALL_NEXTHOPS_PTR(nhg, newhop)) {
				if (!nexthop_valid_resolve(nexthop, newhop))
					continue;

				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug(
						"%s: RECURSIVE match backup %p (%pNG), newhop %pNHv",
						__func__, match, match->nhe,
						newhop);

				SET_FLAG(nexthop->flags,
					 NEXTHOP_FLAG_RECURSIVE);
				nexthop_set_resolved(afi, newhop, nexthop,
						     NULL);
				resolved = 1;
			}

done_with_match:
			/* Capture resolving mtu */
			if (resolved) {
				if (pmtu)
					*pmtu = match->mtu;

			} else {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED)
					zlog_debug(
						"        %s: Recursion failed to find while looking at %pRN",
						__func__, rn);
				goto continue_up_tree;
			}

			return 1;
		} else if (IS_ZEBRA_DEBUG_RIB_DETAILED) {
			zlog_debug(
				"        %s: Route Type %s has not turned on recursion %pRN failed to match",
				__func__, zebra_route_string(type), rn);
			if (type == ZEBRA_ROUTE_BGP
			    && !CHECK_FLAG(flags, ZEBRA_FLAG_IBGP))
				zlog_debug(
					"        EBGP: see \"disable-ebgp-connected-route-check\" or \"disable-connected-check\"");
		}

	continue_up_tree:
		/*
		 * If there is no selected route or matched route is EGP, go up
		 * tree.
		 */
		do {
			rn = rn->parent;
		} while (rn && rn->info == NULL);
		if (rn)
			route_lock_node(rn);
	}

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug("        %s: Nexthop did not lookup in table",
			   __func__);
	return 0;
}

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. The nexthop->ifindex will be updated
 * appropriately as well.
 *
 * An existing route map can turn an otherwise active nexthop into inactive,
 * but not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */
static unsigned nexthop_active_check(struct route_node *rn,
				     struct route_entry *re,
				     struct nexthop *nexthop,
				     struct nhg_hash_entry *nhe)
{
	route_map_result_t ret = RMAP_PERMITMATCH;
	afi_t family;
	const struct prefix *p, *src_p;
	struct zebra_vrf *zvrf;
	uint32_t mtu = 0;
	vrf_id_t vrf_id;

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (rn->p.family == AF_INET)
		family = AFI_IP;
	else if (rn->p.family == AF_INET6)
		family = AFI_IP6;
	else
		family = AF_UNSPEC;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p, nexthop %pNHv", __func__, re, nexthop);

	vrf_id = zvrf_id(rib_dest_vrf(rib_dest_from_rnode(rn)));

	/*
	 * If this is a kernel route, then if the interface is *up* then
	 * by golly gee whiz it's a good route.
	 */
	if (re->type == ZEBRA_ROUTE_KERNEL || re->type == ZEBRA_ROUTE_SYSTEM) {
		struct interface *ifp;

		ifp = if_lookup_by_index(nexthop->ifindex, nexthop->vrf_id);

		if (ifp && ifp->vrf->vrf_id == vrf_id && if_is_up(ifp)) {
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			goto skip_check;
		}
	}

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		if (nexthop_active(nexthop, nhe, &rn->p, re->type, re->flags,
				   &mtu, vrf_id))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		family = AFI_IP;
		if (nexthop_active(nexthop, nhe, &rn->p, re->type, re->flags,
				   &mtu, vrf_id))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* RFC 5549, v4 prefix with v6 NH */
		if (rn->p.family != AF_INET)
			family = AFI_IP6;

		if (nexthop_active(nexthop, nhe, &rn->p, re->type, re->flags,
				   &mtu, vrf_id))
			SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		else
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		break;
	default:
		break;
	}

skip_check:

	if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("        %s: Unable to find active nexthop",
				   __func__);
		return 0;
	}

	/* Capture recursive nexthop mtu.
	 * TODO -- the code used to just reset the re's value to zero
	 * for each nexthop, and then jam any resolving route's mtu value in,
	 * whether or not that was zero, or lt/gt any existing value? The
	 * way this is used appears to be as a floor value, so let's try
	 * using it that way here.
	 */
	if (mtu > 0) {
		if (re->nexthop_mtu == 0 || re->nexthop_mtu > mtu)
			re->nexthop_mtu = mtu;
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
	if (family == 0) {
		struct rib_table_info *info;

		info = srcdest_rnode_table_info(rn);
		family = info->afi;
	}

	memset(&nexthop->rmap_src.ipv6, 0, sizeof(union g_addr));

	zvrf = zebra_vrf_lookup_by_id(re->vrf_id);
	if (!zvrf) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug("        %s: zvrf is NULL", __func__);
		return CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	/* It'll get set if required inside */
	ret = zebra_route_map_check(family, re, p, nexthop, zvrf);
	if (ret == RMAP_DENYMATCH) {
		if (IS_ZEBRA_DEBUG_RIB) {
			zlog_debug(
				"%u:%pRN: Filtering out with NH %pNHv due to route map",
				re->vrf_id, rn, nexthop);
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

/* Checks if the first nexthop is EVPN. If not, early return.
 *
 * This is used to determine if there is a mismatch between l3VNI
 * of the route's vrf and the nexthops in use's VNI labels.
 *
 * If there is a mismatch, we keep the labels as these MUST be DVNI nexthops.
 *
 * IF there is no mismatch, we remove the labels and handle the routes as
 * we have traditionally with evpn.
 */
static bool nexthop_list_set_evpn_dvni(struct route_entry *re,
				       struct nexthop_group *nhg)
{
	struct nexthop *nexthop;
	vni_t re_vrf_vni;
	vni_t nh_vni;
	bool use_dvni = false;

	nexthop = nhg->nexthop;

	if (!nexthop->nh_label || nexthop->nh_label_type != ZEBRA_LSP_EVPN)
		return false;

	re_vrf_vni = get_l3vni_vni(re->vrf_id);

	for (; nexthop; nexthop = nexthop->next) {
		if (!nexthop->nh_label ||
		    nexthop->nh_label_type != ZEBRA_LSP_EVPN)
			continue;

		nh_vni = label2vni(&nexthop->nh_label->label[0]);

		if (nh_vni != re_vrf_vni)
			use_dvni = true;
	}

	/* Using traditional way, no VNI encap - remove labels */
	if (!use_dvni) {
		for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next)
			nexthop_del_labels(nexthop);
	}

	return use_dvni;
}

/*
 * Process a list of nexthops, given an nhe, determining
 * whether each one is ACTIVE/installable at this time.
 */
static uint32_t nexthop_list_active_update(struct route_node *rn,
					   struct route_entry *re,
					   struct nhg_hash_entry *nhe,
					   bool is_backup)
{
	union g_addr prev_src;
	unsigned int prev_active, new_active;
	ifindex_t prev_index;
	uint32_t counter = 0;
	struct nexthop *nexthop;
	struct nexthop_group *nhg = &nhe->nhg;
	bool vni_removed = false;

	nexthop = nhg->nexthop;

	/* Init recursive nh mtu */
	re->nexthop_mtu = 0;

	/* Handler for dvni evpn nexthops. Has to be done at nhg level */
	vni_removed = !nexthop_list_set_evpn_dvni(re, nhg);

	/* Process nexthops one-by-one */
	for ( ; nexthop; nexthop = nexthop->next) {

		/* No protocol daemon provides src and so we're skipping
		 * tracking it
		 */
		prev_src = nexthop->rmap_src;
		prev_active = CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		prev_index = nexthop->ifindex;

		/* Include the containing nhe for primary nexthops: if there's
		 * recursive resolution, we capture the backup info also.
		 */
		new_active =
			nexthop_active_check(rn, re, nexthop,
					     (is_backup ? NULL : nhe));

		/*
		 * We need to respect the multipath_num here
		 * as that what we should be able to install from
		 * a multipath perspective should not be a data plane
		 * decision point.
		 */
		if (new_active && counter >= zrouter.multipath_num) {
			struct nexthop *nh;

			/* Set it and its resolved nexthop as inactive. */
			for (nh = nexthop; nh; nh = nh->resolved)
				UNSET_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE);

			new_active = 0;
		}

		if (new_active)
			counter++;

		/* Check for changes to the nexthop - set ROUTE_ENTRY_CHANGED */
		if (prev_active != new_active ||
		    prev_index != nexthop->ifindex ||
		    ((nexthop->type >= NEXTHOP_TYPE_IFINDEX &&
		      nexthop->type < NEXTHOP_TYPE_IPV6) &&
		     prev_src.ipv4.s_addr != nexthop->rmap_src.ipv4.s_addr) ||
		    ((nexthop->type >= NEXTHOP_TYPE_IPV6 &&
		      nexthop->type < NEXTHOP_TYPE_BLACKHOLE) &&
		     !(IPV6_ADDR_SAME(&prev_src.ipv6,
				      &nexthop->rmap_src.ipv6))) ||
		    CHECK_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED) ||
		    vni_removed)
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
 * This function takes the start of two comparable nexthops from two different
 * nexthop groups and walks them to see if they can be considered the same
 * or not.  This is being used to determine if zebra should reuse a nhg
 * from the old_re to the new_re, when an interface goes down and the
 * new nhg sent down from the upper level protocol would resolve to it
 */
static bool zebra_nhg_nexthop_compare(const struct nexthop *nhop,
				      const struct nexthop *old_nhop,
				      const struct route_node *rn)
{
	bool same = true;

	while (nhop && old_nhop) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: %pRN Comparing %pNHvv(%u) to old: %pNHvv(%u)",
				   __func__, rn, nhop, nhop->flags, old_nhop,
				   old_nhop->flags);
		if (!CHECK_FLAG(old_nhop->flags, NEXTHOP_FLAG_ACTIVE)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: %pRN Old is not active going to the next one",
					   __func__, rn);
			old_nhop = old_nhop->next;
			continue;
		}

		if (nexthop_same(nhop, old_nhop)) {
			struct nexthop *new_recursive, *old_recursive;

			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: %pRN New and old are same, continuing search",
					   __func__, rn);

			new_recursive = nhop->resolved;
			old_recursive = old_nhop->resolved;

			while (new_recursive && old_recursive) {
				if (!nexthop_same(new_recursive, old_recursive)) {
					same = false;
					break;
				}

				new_recursive = new_recursive->next;
				old_recursive = old_recursive->next;
			}

			if (new_recursive)
				same = false;
			else if (old_recursive) {
				while (old_recursive) {
					if (CHECK_FLAG(old_recursive->flags,
						       NEXTHOP_FLAG_ACTIVE))
						break;
					old_recursive = old_recursive->next;
				}

				if (old_recursive)
					same = false;
			}

			if (!same)
				break;

			nhop = nhop->next;
			old_nhop = old_nhop->next;
			continue;
		} else {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s:%pRN They are not the same, stopping using new nexthop entry",
					   __func__, rn);
			same = false;
			break;
		}
	}

	if (nhop)
		same = false;
	else if (old_nhop) {
		while (old_nhop) {
			if (CHECK_FLAG(old_nhop->flags, NEXTHOP_FLAG_ACTIVE))
				break;
			old_nhop = old_nhop->next;
		}

		if (old_nhop)
			same = false;
	}

	return same;
}

static struct nhg_hash_entry *zebra_nhg_rib_compare_old_nhe(
	const struct route_node *rn, const struct route_entry *re,
	struct nhg_hash_entry *new_nhe, struct nhg_hash_entry *old_nhe)
{
	struct nexthop *nhop, *old_nhop;
	bool same = true;
	struct vrf *vrf = vrf_lookup_by_id(re->vrf_id);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		char straddr[PREFIX_STRLEN];

		prefix2str(&rn->p, straddr, sizeof(straddr));
		zlog_debug("%s: %pRN new id: %u old id: %u", __func__, rn,
			   new_nhe->id, old_nhe->id);
		zlog_debug("%s: %pRN NEW", __func__, rn);
		for (ALL_NEXTHOPS(new_nhe->nhg, nhop))
			route_entry_dump_nh(re, straddr, vrf, nhop);

		zlog_debug("%s: %pRN OLD", __func__, rn);
		for (ALL_NEXTHOPS(old_nhe->nhg, nhop))
			route_entry_dump_nh(re, straddr, vrf, nhop);
	}

	nhop = new_nhe->nhg.nexthop;
	old_nhop = old_nhe->nhg.nexthop;

	same = zebra_nhg_nexthop_compare(nhop, old_nhop, rn);

	if (same) {
		struct nexthop_group *bnhg, *old_bnhg;

		bnhg = zebra_nhg_get_backup_nhg(new_nhe);
		old_bnhg = zebra_nhg_get_backup_nhg(old_nhe);

		if (bnhg || old_bnhg) {
			if (bnhg && !old_bnhg)
				same = false;
			else if (!bnhg && old_bnhg)
				same = false;
			else
				same = zebra_nhg_nexthop_compare(bnhg->nexthop,
								 old_bnhg->nexthop,
								 rn);
		}
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s:%pRN They are %sthe same, using the %s nhg entry",
			   __func__, rn, same ? "" : "not ",
			   same ? "old" : "new");

	if (same)
		return old_nhe;
	else
		return new_nhe;
}

/*
 * Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag.  If any nexthop is found to toggle the ACTIVE flag,
 * the whole re structure is flagged with ROUTE_ENTRY_CHANGED.
 *
 * Return value is the new number of active nexthops.
 */
int nexthop_active_update(struct route_node *rn, struct route_entry *re,
			  struct route_entry *old_re)
{
	struct nhg_hash_entry *curr_nhe;
	uint32_t curr_active = 0, backup_active = 0;

	if (PROTO_OWNED(re->nhe))
		return proto_nhg_nexthop_active_update(&re->nhe->nhg);

	afi_t rt_afi = family2afi(rn->p.family);

	UNSET_FLAG(re->status, ROUTE_ENTRY_CHANGED);

	/* Make a local copy of the existing nhe, so we don't work on/modify
	 * the shared nhe.
	 */
	curr_nhe = zebra_nhe_copy(re->nhe, re->nhe->id);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p nhe %p (%pNG), curr_nhe %p", __func__, re,
			   re->nhe, re->nhe, curr_nhe);

	/* Clear the existing id, if any: this will avoid any confusion
	 * if the id exists, and will also force the creation
	 * of a new nhe reflecting the changes we may make in this local copy.
	 */
	curr_nhe->id = 0;

	/* Process nexthops */
	curr_active = nexthop_list_active_update(rn, re, curr_nhe, false);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p curr_active %u", __func__, re,
			   curr_active);

	/* If there are no backup nexthops, we are done */
	if (zebra_nhg_get_backup_nhg(curr_nhe) == NULL)
		goto backups_done;

	backup_active = nexthop_list_active_update(
		rn, re, curr_nhe->backup_info->nhe, true /*is_backup*/);

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

		if (old_re && old_re->type == re->type &&
		    old_re->instance == re->instance)
			new_nhe = zebra_nhg_rib_compare_old_nhe(rn, re, new_nhe,
								old_re->nhe);

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug(
				"%s: re %p CHANGED: nhe %p (%pNG) => new_nhe %p (%pNG)",
				__func__, re, re->nhe, re->nhe, new_nhe,
				new_nhe);

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
static uint16_t zebra_nhg_nhe2grp_internal(struct nh_grp *grp, uint16_t curr_index,
					   struct nhg_hash_entry *nhe,
					   struct nhg_hash_entry *original, int max_num)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct nhg_hash_entry *depend = NULL;
	struct nexthop *nexthop;
	uint16_t i = curr_index;

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
					"Failed to recursively resolve Nexthop Hash Entry in the group id=%pNG",
					nhe);
				continue;
			}
		}

		if (!zebra_nhg_depends_is_empty(depend)) {
			/* This is a group within a group */
			i = zebra_nhg_nhe2grp_internal(grp, i, depend, nhe,
						       max_num);
		} else {
			bool found;

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

			/*
			 * So we need to create the nexthop group with
			 * the appropriate weights.  The nexthops weights
			 * are stored in the fully resolved nexthops for
			 * the nhg so we need to find the appropriate
			 * nexthop associated with this and set the weight
			 * appropriately
			 */
			found = false;
			for (ALL_NEXTHOPS_PTR(&original->nhg, nexthop)) {
				if (CHECK_FLAG(nexthop->flags,
					       NEXTHOP_FLAG_RECURSIVE))
					continue;

				if (nexthop_cmp_no_weight(depend->nhg.nexthop,
							  nexthop) != 0)
					continue;

				found = true;
				break;
			}

			if (!found) {
				if (IS_ZEBRA_DEBUG_RIB_DETAILED ||
				    IS_ZEBRA_DEBUG_NHG)
					zlog_debug("%s: Nexthop ID (%u) unable to find nexthop in Nexthop Gropu Entry, something is terribly wrong",
						   __func__, depend->id);
				continue;
			}
			grp[i].id = depend->id;
			grp[i].weight = nexthop->weight;
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
uint16_t zebra_nhg_nhe2grp(struct nh_grp *grp, struct nhg_hash_entry *nhe, int max_num)
{
	/* Call into the recursive function */
	return zebra_nhg_nhe2grp_internal(grp, 0, nhe, nhe, max_num);
}

void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe, uint8_t type)
{
	struct nhg_connected *rb_node_dep = NULL;
	enum zebra_dplane_result ret;

	/* Resolve it first */
	nhe = zebra_nhg_resolve(nhe);

	if (zebra_nhg_set_valid_if_active(nhe)) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: valid flag set for nh %pNG", __func__,
				   nhe);
	}

	if ((type != ZEBRA_ROUTE_CONNECT && type != ZEBRA_ROUTE_LOCAL &&
	     type != ZEBRA_ROUTE_KERNEL) &&
	    CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL)) {
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL);
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
	}

	/* Make sure all depends are installed/queued */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		zebra_nhg_install_kernel(rb_node_dep->nhe, type);
	}
	if (nhe->pic_nhe)
		zebra_nhg_install_kernel(nhe->pic_nhe, ZEBRA_ROUTE_MAX);

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID) &&
	    (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) ||
	     CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL)) &&
	    !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		/* Change its type to us since we are installing it */
		if (!ZEBRA_NHG_CREATED(nhe))
			nhe->type = ZEBRA_ROUTE_NHG;

		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_PIC_NHT))
			ret = dplane_pic_nh_add(nhe);
		else
			ret = dplane_nexthop_add(nhe);

		switch (ret) {
		case ZEBRA_DPLANE_REQUEST_QUEUED:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
			break;
		case ZEBRA_DPLANE_REQUEST_FAILURE:
			flog_err(
				EC_ZEBRA_DP_INSTALL_FAIL,
				"Failed to install Nexthop ID (%pNG) into the kernel",
				nhe);
			break;
		case ZEBRA_DPLANE_REQUEST_SUCCESS:
			break;
		}
	}
}

void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe)
{
	enum zebra_dplane_result ret;

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)) {
		if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_PIC_NHT) || !nhe->pic_nhe)
			ret = dplane_nexthop_delete(nhe);
		else
			ret = dplane_pic_nh_delete(nhe);

		switch (ret) {
		case ZEBRA_DPLANE_REQUEST_QUEUED:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
			break;
		case ZEBRA_DPLANE_REQUEST_FAILURE:
			flog_err(
				EC_ZEBRA_DP_DELETE_FAIL,
				"Failed to uninstall Nexthop ID (%pNG) from the kernel",
				nhe);
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

	if (op == DPLANE_OP_NH_DELETE || op == DPLANE_OP_PIC_NH_DELETE) {
		if (status != ZEBRA_DPLANE_REQUEST_SUCCESS)
			flog_err(
				EC_ZEBRA_DP_DELETE_FAIL,
				"Failed to uninstall Nexthop ID (%u) from the kernel",
				id);

		/* We already free'd the data, nothing to do */
	} else if (op == DPLANE_OP_NH_INSTALL || op == DPLANE_OP_NH_UPDATE ||
		   op == DPLANE_OP_PIC_NH_INSTALL || op == DPLANE_OP_PIC_NH_UPDATE) {
		nhe = zebra_nhg_lookup_id(id);

		if (!nhe) {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug("%s operation performed on Nexthop ID (%u) in the kernel, that we no longer have in our table",
					   dplane_op2str(op), id);

			return;
		}

		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL);
		switch (status) {
		case ZEBRA_DPLANE_REQUEST_SUCCESS:
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			zebra_nhg_handle_install(nhe, true);

			/* If daemon nhg, send it an update */
			if (PROTO_OWNED(nhe))
				zsend_nhg_notify(nhe->type, nhe->zapi_instance,
						 nhe->zapi_session, nhe->id,
						 ZAPI_NHG_INSTALLED);
			break;
		case ZEBRA_DPLANE_REQUEST_FAILURE:
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
			/* If daemon nhg, send it an update */
			if (PROTO_OWNED(nhe))
				zsend_nhg_notify(nhe->type, nhe->zapi_instance,
						 nhe->zapi_session, nhe->id,
						 ZAPI_NHG_FAIL_INSTALL);

			if (!(zebra_nhg_proto_nexthops_only() &&
			      !PROTO_OWNED(nhe)))
				flog_err(
					EC_ZEBRA_DP_INSTALL_FAIL,
					"Failed to install Nexthop (%pNG) into the kernel",
					nhe);
			break;
		case ZEBRA_DPLANE_REQUEST_QUEUED:
			flog_err(EC_ZEBRA_DP_INVALID_RC,
				 "Dplane returned an invalid result code for a result from the dplane for %pNG into the kernel",
				 nhe);
			break;
		}
	}
}

static int zebra_nhg_sweep_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = NULL;

	nhe = (struct nhg_hash_entry *)bucket->data;

	/*
	 * same logic as with routes.
	 *
	 * If older than startup time, we know we read them in from the
	 * kernel and have not gotten and update for them since startup
	 * from an upper level proto.
	 */
	if (zrouter.startup_time < nhe->uptime)
		return HASHWALK_CONTINUE;

	/*
	 * If it's proto-owned and not being used by a route, remove it since
	 * we haven't gotten an update about it from the proto since startup.
	 * This means that either the config for it was removed or the daemon
	 * didn't get started. This handles graceful restart & retain scenario.
	 */
	if (PROTO_OWNED(nhe) && nhe->refcnt == 1) {
		zebra_nhg_decrement_ref(nhe);
		return HASHWALK_ABORT;
	}

	/*
	 * If its being ref'd by routes, just let it be uninstalled via a route
	 * removal.
	 */
	if (ZEBRA_NHG_CREATED(nhe) && nhe->refcnt <= 0) {
		zebra_nhg_uninstall_kernel(nhe);
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

void zebra_nhg_sweep_table(struct hash *hash)
{
	uint32_t count;

	/*
	 * Yes this is extremely odd.  Effectively nhg's have
	 * other nexthop groups that depend on them and when you
	 * remove them, you can have other entries blown up.
	 * our hash code does not work with deleting multiple
	 * entries at a time and will possibly cause crashes
	 * So what to do?  Whenever zebra_nhg_sweep_entry
	 * deletes an entry it will return HASHWALK_ABORT,
	 * cause that deletion might have triggered more.
	 * then we can just keep sweeping this table
	 * until nothing more is found to do.
	 */
	do {
		count = hashcount(hash);
		hash_walk(hash, zebra_nhg_sweep_entry, NULL);
	} while (count != hashcount(hash));
}

static void zebra_nhg_mark_keep_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;

	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
}

/*
 * When we are shutting down and we have retain mode enabled
 * in zebra the process is to mark each vrf that it's
 * routes should not be deleted.  The problem with that
 * is that shutdown actually free's up memory which
 * causes the nexthop group's ref counts to go to zero
 * we need a way to subtly tell the system to not remove
 * the nexthop groups from the kernel at the same time.
 * The easiest just looks like that we should not mark
 * the nhg's as installed any more and when the ref count
 * goes to zero we'll attempt to delete and do nothing
 */
void zebra_nhg_mark_keep(void)
{
	hash_iterate(zrouter.nhgs_id, zebra_nhg_mark_keep_entry, NULL);
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

/* Global control for use of activated backups for recursive resolution. */
void zebra_nhg_set_recursive_use_backups(bool set)
{
	use_recursive_backups = set;
}

bool zebra_nhg_recursive_use_backups(void)
{
	return use_recursive_backups;
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
					   uint16_t instance, uint32_t session,
					   struct nexthop_group *nhg, afi_t afi)
{
	struct nhg_hash_entry lookup;
	struct nhg_hash_entry *new, *old;
	struct nhg_connected *rb_node_dep = NULL;
	struct nexthop *newhop;
	bool replace = false;
	int ret = 0;

	if (!nhg->nexthop) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug("%s: id %u, no nexthops passed to add",
				   __func__, id);
		return NULL;
	}


	/* Set nexthop list as active, since they wont go through rib
	 * processing.
	 *
	 * Assuming valid/onlink for now.
	 *
	 * Once resolution is figured out, we won't need this!
	 */
	for (ALL_NEXTHOPS_PTR(nhg, newhop)) {
		if (CHECK_FLAG(newhop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"%s: id %u, backup nexthops not supported",
					__func__, id);
			return NULL;
		}

		if (newhop->type == NEXTHOP_TYPE_BLACKHOLE) {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"%s: id %u, blackhole nexthop not supported",
					__func__, id);
			return NULL;
		}

		if (newhop->type == NEXTHOP_TYPE_IFINDEX) {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"%s: id %u, nexthop without gateway not supported",
					__func__, id);
			return NULL;
		}

		if (!newhop->ifindex) {
			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"%s: id %u, nexthop without ifindex is not supported",
					__func__, id);
			return NULL;
		}
		SET_FLAG(newhop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	zebra_nhe_init(&lookup, afi, nhg->nexthop);
	lookup.nhg.nexthop = nhg->nexthop;
	lookup.nhg.nhgr = nhg->nhgr;
	lookup.id = id;
	lookup.type = type;

	old = zebra_nhg_lookup_id(id);

	if (old) {
		/*
		 * This is a replace, just release NHE from ID for now, The
		 * depends/dependents may still be used in the replacement so
		 * we don't touch them other than to remove their refs to their
		 * old parent.
		 */
		replace = true;
		hash_release(zrouter.nhgs_id, old);

		/* Free all the things */
		zebra_nhg_release_all_deps(old);
	}

	new = zebra_nhg_rib_find_nhe(&lookup, afi);

	zebra_nhg_increment_ref(new);

	/* Capture zapi client info */
	new->zapi_instance = instance;
	new->zapi_session = session;

	zebra_nhg_set_valid_if_active(new);

	zebra_nhg_install_kernel(new, ZEBRA_ROUTE_MAX);

	if (old) {
		/*
		 * Check to handle recving DEL while routes still in use then
		 * a replace.
		 *
		 * In this case we would have decremented the refcnt already
		 * but set the FLAG here. Go ahead and increment once to fix
		 * the misordering we have been sent.
		 */
		if (CHECK_FLAG(old->flags, NEXTHOP_GROUP_PROTO_RELEASED))
			zebra_nhg_increment_ref(old);

		ret = rib_handle_nhg_replace(old, new);
		if (ret)
			/*
			 * if ret > 0, some previous re->nhe has freed the
			 * address to which old_entry is pointing. Hence mark
			 * the old NHE as NULL
			 */
			old = NULL;
		else {
			/* We have to decrement its singletons
			 * because some might not exist in NEW.
			 */
			if (!zebra_nhg_depends_is_empty(old)) {
				frr_each (nhg_connected_tree, &old->nhg_depends,
					  rb_node_dep)
					zebra_nhg_decrement_ref(
						rb_node_dep->nhe);
			}

			/* Dont call the dec API, we dont want to uninstall the ID */
			old->refcnt = 0;
			EVENT_OFF(old->timer);
			zebra_nhg_free(old);
			old = NULL;
		}
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: %s nhe %p (%u), vrf %d, type %s", __func__,
			   (replace ? "replaced" : "added"), new, new->id,
			   new->vrf_id, zebra_route_string(new->type));

	return new;
}

/* Delete NHE from upper level proto, caller must decrement ref */
struct nhg_hash_entry *zebra_nhg_proto_del(uint32_t id, int type)
{
	struct nhg_hash_entry *nhe;

	nhe = zebra_nhg_lookup_id(id);

	if (!nhe) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug("%s: id %u, lookup failed", __func__, id);

		return NULL;
	}

	if (type != nhe->type) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: id %u, type %s mismatch, sent by %s, ignoring",
				__func__, id, zebra_route_string(nhe->type),
				zebra_route_string(type));
		return NULL;
	}

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_PROTO_RELEASED)) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug("%s: id %u, already released", __func__, id);

		return NULL;
	}

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_PROTO_RELEASED);

	if (nhe->refcnt > 1) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug(
				"%s: %pNG, still being used by routes refcnt %u",
				__func__, nhe, nhe->refcnt);
		return nhe;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: deleted nhe %p (%pNG), vrf %d, type %s",
			   __func__, nhe, nhe, nhe->vrf_id,
			   zebra_route_string(nhe->type));

	return nhe;
}

struct nhg_score_proto_iter {
	int type;
	struct list *found;
};

static void zebra_nhg_score_proto_entry(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe;
	struct nhg_score_proto_iter *iter;

	nhe = (struct nhg_hash_entry *)bucket->data;
	iter = arg;

	/* Needs to match type and outside zebra ID space */
	if (nhe->type == iter->type && PROTO_OWNED(nhe)) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug(
				"%s: found nhe %p (%pNG), vrf %d, type %s after client disconnect",
				__func__, nhe, nhe, nhe->vrf_id,
				zebra_route_string(nhe->type));

		/* Add to removal list */
		listnode_add(iter->found, nhe);
	}
}

/* Remove specific by proto NHGs */
unsigned long zebra_nhg_score_proto(int type)
{
	struct nhg_hash_entry *nhe;
	struct nhg_score_proto_iter iter = {};
	struct listnode *ln;
	unsigned long count;

	iter.type = type;
	iter.found = list_new();

	/* Find matching entries to remove */
	hash_iterate(zrouter.nhgs_id, zebra_nhg_score_proto_entry, &iter);

	/* Now remove them */
	for (ALL_LIST_ELEMENTS_RO(iter.found, ln, nhe)) {
		/*
		 * This should be the last ref if we remove client routes too,
		 * and thus should remove and free them.
		 */
		if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_PROTO_RELEASED))
			zebra_nhg_decrement_ref(nhe);
		else {

			/* protocol sends explicit delete of nhg, the
			 * nhe->refcount is decremented in zread_nhg_del()
			 */
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"%s: nhe %u (%p) refcount %u already decremented in zread_nhg_del",
					__func__, nhe->id, nhe, nhe->refcnt);
		}
	}

	count = iter.found->count;
	list_delete(&iter.found);

	return count;
}

printfrr_ext_autoreg_p("NG", printfrr_nhghe);
static ssize_t printfrr_nhghe(struct fbuf *buf, struct printfrr_eargs *ea,
			      const void *ptr)
{
	const struct nhg_hash_entry *nhe = ptr;
	const struct nhg_connected *dep;
	ssize_t ret = 0;

	if (!nhe)
		return bputs(buf, "[NULL]");

	ret += bprintfrr(buf, "%u[", nhe->id);
	if (nhe->ifp)
		ret += printfrr_nhs(buf, nhe->nhg.nexthop);
	else {
		int count = zebra_nhg_depends_count(nhe);

		frr_each (nhg_connected_tree_const, &nhe->nhg_depends, dep) {
			ret += bprintfrr(buf, "%u", dep->nhe->id);
			if (count > 1)
				ret += bputs(buf, "/");
			count--;
		}
	}

	ret += bputs(buf, "]");
	return ret;
}

/*
 * On interface add the nexthop that resolves to this intf needs
 * a re-install. There are following scenarios when the nexthop group update
 * gets skipped:
 * 1. When upper level protocol sends removal of NHG, there is
 * timer running to keep NHG for 180 seconds, during this interval, same route
 * with same set of nexthops installation is given , the same NHG is used
 * but since NHG is not reinstalled on interface address add, it is not aware
 * in Dplan/Kernel.
 * 2. Due to a quick port flap due to interface add and delete
 * to be processed in same queue one after another. Zebra believes that
 * there is no change in nhg in this case. Hence this re-install will
 * make sure the nexthop group gets updated to Dplan/Kernel.
 */
void zebra_interface_nhg_reinstall(struct interface *ifp)
{
	struct nhg_connected *rb_node_dep = NULL;
	struct zebra_if *zif = ifp->info;
	struct nexthop *nh;

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug(
			"%s: Installing interface %s associated NHGs into kernel",
			__func__, ifp->name);

	frr_each (nhg_connected_tree, &zif->nhg_dependents, rb_node_dep) {
		nh = rb_node_dep->nhe->nhg.nexthop;
		if (zebra_nhg_set_valid_if_active(rb_node_dep->nhe)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"%s: Setting the valid flag for nhe %pNG, interface: %s",
					__func__, rb_node_dep->nhe, ifp->name);
		}

		/* Check for singleton NHG associated to interface */
		if (!nexthop_is_blackhole(nh) &&
		    zebra_nhg_depends_is_empty(rb_node_dep->nhe)) {
			struct nhg_connected *rb_node_dependent;

			if (IS_ZEBRA_DEBUG_NHG)
				zlog_debug(
					"%s install nhe %pNG nh type %u flags 0x%x",
					__func__, rb_node_dep->nhe, nh->type,
					rb_node_dep->nhe->flags);
			zebra_nhg_install_kernel(rb_node_dep->nhe,
						 ZEBRA_ROUTE_MAX);

			/* Don't need to modify dependents if installed */
			if (CHECK_FLAG(rb_node_dep->nhe->flags,
				       NEXTHOP_GROUP_INSTALLED))
				continue;

			/* mark dependent uninstalled; when interface associated
			 * singleton is installed, install dependent
			 */
			frr_each_safe (nhg_connected_tree,
				       &rb_node_dep->nhe->nhg_dependents,
				       rb_node_dependent) {
				struct nexthop *nhop_dependent =
					rb_node_dependent->nhe->nhg.nexthop;

				while (nhop_dependent &&
				       !nexthop_same(nhop_dependent, nh))
					nhop_dependent = nhop_dependent->next;

				if (nhop_dependent)
					SET_FLAG(nhop_dependent->flags,
						 NEXTHOP_FLAG_ACTIVE);

				if (IS_ZEBRA_DEBUG_NHG)
					zlog_debug("%s dependent nhe %pNG Setting Reinstall flag",
						   __func__,
						   rb_node_dependent->nhe);
				SET_FLAG(rb_node_dependent->nhe->flags,
					 NEXTHOP_GROUP_REINSTALL);
			}
		}
	}
}
