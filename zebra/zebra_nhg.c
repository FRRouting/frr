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
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_trace.h"

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

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi,
					   int type, bool from_dplane);
static void depends_add(struct nhg_connected_tree_head *head,
			struct nhg_hash_entry *depend);
static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi, int type, bool from_dplane);
static struct nhg_hash_entry *
depends_find_id_add(struct nhg_connected_tree_head *head, uint32_t id);
static void depends_decrement_free(struct nhg_connected_tree_head *head);

static struct nhg_backup_info *
nhg_backup_copy(const struct nhg_backup_info *orig);

const char *zebra_nhg_afi2str(struct nhg_hash_entry *nhe)
{
	if (nhe->afi == AFI_UNSPEC)
		return "No AFI";

	return afi2str(nhe->afi);
}

/* Helper function for getting the next allocatable ID */
static uint32_t nhg_get_next_id(void)
{
	while (1) {
		id_counter++;

		if (id_counter == ZEBRA_NHG_PROTO_LOWER) {
			frrtrace(1, frr_zebra, zebra_nhg_id_counter_wrapped, id_counter);
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

	/* If the entry was successfully removed, free the 'connected` struct */
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

			frrtrace(2, frr_zebra, zebra_nhg_dep, nhe->id, rb_node_dep->nhe->id);
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
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s Creating the nhe %u (%p) re-tree", __func__, nhe->id, nhe);

	nhe_re_tree_init(&nhe->re_head);

	zebra_nhg_tracker_init(nhe);

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
	if (!PROTO_OWNED(nhe) && (ZEBRA_NHG_IS_SINGLETON(nhe) && nhe->nhg.nexthop->ifindex &&
				  !CHECK_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_RECURSIVE))) {
		struct interface *ifp = NULL;

		ifp = if_lookup_by_index(nhe->nhg.nexthop->ifindex,
					 nhe->nhg.nexthop->vrf_id);
		if (ifp)
			zebra_nhg_set_if(nhe, ifp);
		else {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"Failed to lookup an interface with ifindex=%d in vrf=%u for NHE %pNG",
					nhe->nhg.nexthop->ifindex,
					nhe->nhg.nexthop->vrf_id, nhe);

			frrtrace(1, frr_zebra, zebra_nhg_intf_lkup_failed, nhe);
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
bool nhg_compare_nexthops(const struct nexthop *nh1, const struct nexthop *nh2)
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
	     nexthop1 = nexthop_next(nexthop1), nexthop2 = nexthop_next(nexthop2)) {
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
	     nexthop1 = nexthop_next(nexthop1), nexthop2 = nexthop_next(nexthop2)) {
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
		uint16_t weight;
		struct nhg_hash_entry *depend = NULL;

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
		weight = depend->nhg.nexthop->weight;
		depend->nhg.nexthop->weight = grp[i].weight;
		copy_nexthops(&nhg->nexthop, depend->nhg.nexthop, NULL);
		depend->nhg.nexthop->weight = weight;
	}

	if (resilience)
		nhg->nhgr = *resilience;

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
			   afi_t afi, bool from_dplane)
{
	bool created = false;
	bool recursive = false;
	struct nhg_hash_entry *newnhe, *backup_nhe;
	struct nexthop *nh = NULL;

	/*
	 * Apply the global resilience to zebra-owned multipath groups, before
	 * the lookup since resilience is part of the hash key. Skip dataplane
	 * and proto-owned groups, and never override existing resilience.
	 */
	if (!from_dplane && lookup->id < ZEBRA_NHG_PROTO_LOWER &&
	    zrouter.nhg_resilience.buckets && lookup->nhg.nhgr.buckets == 0 &&
	    (nhg_depends || (lookup->nhg.nexthop && lookup->nhg.nexthop->next)))
		lookup->nhg.nhgr = zrouter.nhg_resilience;

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
					 newnhe->type, from_dplane);
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
	if (ZEBRA_NHG_IS_SINGLETON(backup_nhe) && CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
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
					 backup_nhe->type, from_dplane);
		}
	}

	if (recursive)
		SET_FLAG(backup_nhe->flags, NEXTHOP_GROUP_RECURSIVE);

done:
	/* Reset time since last update */
	(*nhe)->uptime = monotime(NULL);
	return created;
}

/*
 * Lookup or create an nhe, based on an nhg or an nhe id.
 */
static bool zebra_nhg_find(struct nhg_hash_entry **nhe, uint32_t id,
			   struct nexthop_group *nhg,
			   struct nhg_connected_tree_head *nhg_depends,
			   vrf_id_t vrf_id, afi_t afi, int type,
			   bool from_dplane)
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

	created = zebra_nhe_find(nhe, &lookup, nhg_depends, afi, from_dplane);

	return created;
}

/* Find/create a single nexthop */
static struct nhg_hash_entry *zebra_nhg_find_nexthop(uint32_t id,
						     struct nexthop *nh,
						     afi_t afi, int type,
						     bool from_dplane)
{
	struct nhg_hash_entry *nhe = NULL;
	struct nexthop_group nhg = {};
	vrf_id_t vrf_id = !vrf_is_backend_netns() ? VRF_DEFAULT : nh->vrf_id;

	nexthop_group_add_sorted(&nhg, nh);

	zebra_nhg_find(&nhe, id, &nhg, NULL, vrf_id, afi, type, from_dplane);

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

static bool nhg_ctx_get_startup(const struct nhg_ctx *ctx)
{
	return ctx->startup;
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
				    struct nhg_resilience *resilience, bool startup)
{
	struct nhg_ctx *ctx = NULL;

	ctx = nhg_ctx_new();

	ctx->id = id;
	ctx->vrf_id = vrf_id;
	ctx->afi = afi;
	ctx->type = type;
	ctx->count = count;
	ctx->startup = startup;

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
	bool dependent_valid = valid;

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
		dependent_valid = valid;
		if (!valid) {
			/*
			 * Grab the first nexthop from the depending nexthop group
			 * then let's find the nexthop in that group that matches
			 * my individual nexthop and mark it as no longer ACTIVE
			 */
			struct nexthop *nexthop = rb_node_dep->nhe->nhg.nexthop;

			while (nexthop) {
				if (nexthop_same_no_weight(nexthop, nhe->nhg.nexthop)) {
					/* Invalid Nexthop */
					UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
				} else {
					/*
					 * If other nexthops in the nexthop
					 * group are valid then we can continue
					 * to use this nexthop group as valid
					 */
					if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
						dependent_valid = true;
				}
				nexthop = nexthop->next;
			}
		}
		zebra_nhg_set_valid(rb_node_dep->nhe, dependent_valid);
	}
}

void zebra_nhg_check_valid(struct nhg_hash_entry *nhe)
{
	struct nhg_connected *rb_node_dep = NULL;
	bool valid = false;

	/* Singleton means it has no depends and has only dependents */
	if (ZEBRA_NHG_IS_SINGLETON(nhe)) {
		UNSET_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_FIB);
		UNSET_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}

	/* If anything else in the group is valid, the group is valid */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		if (CHECK_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_VALID)) {
			valid = true;
			break;
		}
	}

	zebra_nhg_set_valid(nhe, valid);

	/*
	 * Create tracker now - all the parent NHGs are updated with the valid state.
	 * Walk transitive dependents - catches recursively-dependent NHGs and
	 * creates trackers wherever required.
	 */
	if (ZEBRA_NHG_IS_SINGLETON(nhe))
		zebra_nhg_tracker_create_for_event(nhe, nhe->nhg.nexthop->ifindex,
						   NHG_TRACKER_EVENT_INTF_DOWN);
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

/*
 * Rebuild nhg_depends from the NHE's current nexthop list.
 * Called after replacing an NHE's nexthop group content in-place
 * (e.g. during tracker NHG rework).  Releases old dependency edges
 * and rebuilds them from the new nexthop list.
 */
void zebra_nhg_rebuild_depends(struct nhg_hash_entry *nhe)
{
	struct nexthop *nh;
	struct nhg_connected *rb_node_dep;
	uint32_t i;

	/*
	 * Drain refcount contributions from old singletons.
	 * E.g. group with 10 REs: each old singleton got +11 total.
	 * The loop drains the 10 cascade increments; the subsequent
	 * depends_decrement_free drains the 1 creation increment.
	 */
	uint32_t old_dep_count = nhg_connected_tree_count(&nhe->nhg_depends);

	for (i = 0; i < nhe->refcnt; i++)
		nhg_connected_tree_decrement_ref(&nhe->nhg_depends);

	zebra_nhg_depends_release(nhe);
	depends_decrement_free(&nhe->nhg_depends);

	/* Re-init the depends tree (nhg_dependents is NOT touched —
	 * other NHGs that depend on us must keep their backpointers).
	 */
	zebra_nhg_depends_init(nhe);

	nh = nhe->nhg.nexthop;
	if (!nh)
		return;

	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_RECURSIVE);

	if (nh->next == NULL && nhe->id < ZEBRA_NHG_PROTO_LOWER) {
		if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
			handle_recursive_depend(&nhe->nhg_depends, nh->resolved, nhe->afi,
						nhe->type);
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_RECURSIVE);
		}
	} else {
		for (ALL_NEXTHOPS(nhe->nhg, nh))
			depends_find_add(&nhe->nhg_depends, nh, nhe->afi, nhe->type, false);
	}

	/*
	 * Wire backpointers from new dependencies to this NHE.
	 * Note: zebra_nhg_connect_depends() — it reinitializes
	 * nhg_dependents which would wipe backpointers from other NHGs
	 * that depend on us.  Instead, manually add backpointers.
	 */
	frr_each (nhg_connected_tree, &nhe->nhg_depends, rb_node_dep)
		zebra_nhg_dependents_add(rb_node_dep->nhe, nhe);

	/*
	 * Fill cascade increments on new singletons.
	 * depends_find_add already gave each new singleton +1 (via
	 * depends_add->zebra_nhg_increment_ref) for the creation
	 * increment. The loop adds nhe->refcnt more to cover the
	 * cascade contribution (one per RE on this group).
	 *
	 * E.g. group with 10 REs: each new singleton needs +11 total
	 * (+1 creation + 10 cascade).  depends_add gave +1, loop
	 * gives +10.
	 */
	for (i = 0; i < nhe->refcnt; i++)
		nhg_connected_tree_increment_ref(&nhe->nhg_depends);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u (refcnt %d) rebuilt depends: old %u -> new %zu (drained/filled %d+1 per singleton)",
			   __func__, nhe->id, nhe->refcnt, old_dep_count,
			   nhg_connected_tree_count(&nhe->nhg_depends), nhe->refcnt);

	frrtrace(6, frr_zebra, nhg_rework, "rebuild-depends", nhe->id, nhe->refcnt, old_dep_count,
		 nhg_connected_tree_count(&nhe->nhg_depends), 0);
}

/*
 * Build backup_nhe->nhg_depends from its nexthop list, creating or referencing
 * a singleton dep per backup nexthop.  Required after nhg_backup_copy(), which
 * copies only the nexthop list and leaves the depends tree empty.
 */
static void zebra_nhg_backup_build_depends(struct nhg_hash_entry *backup_nhe, afi_t afi)
{
	struct nexthop *nh = backup_nhe->nhg.nexthop;

	if (!nh)
		return;

	if (ZEBRA_NHG_IS_SINGLETON(backup_nhe) && CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)) {
		handle_recursive_depend(&backup_nhe->nhg_depends, nh->resolved, afi,
					backup_nhe->type);
		SET_FLAG(backup_nhe->flags, NEXTHOP_GROUP_RECURSIVE);
	} else {
		for (; nh; nh = nh->next)
			depends_find_add(&backup_nhe->nhg_depends, nh, afi, backup_nhe->type,
					 false);
	}

	frrtrace(6, frr_zebra, nhg_rework, "backup-build-depends", backup_nhe->id, 0, 0,
		 nhg_connected_tree_count(&backup_nhe->nhg_depends), 0);
}

/*
 * Rework in-place: release nhe from the content hash. The id-hash entry is
 * untouched so nhe's id stays reserved.
 */
void zebra_nhg_rework_content_release(struct nhg_hash_entry *nhe)
{
	hash_release(zrouter.nhgs, nhe);
}

/*
 * Rework in-place: mutate — free nhe's old nexthop list, copy
 * source_nhe's nexthop list, rebuild nhg_depends, migrate backup_info,
 * and update the ifp binding for singletons.
 * Caller must ensure nhe is currently OUT of the content hash.
 */
void zebra_nhg_rework_content_mutate(struct nhg_hash_entry *nhe, struct nhg_hash_entry *source_nhe)
{
	nexthops_free(nhe->nhg.nexthop);
	nhe->nhg.nexthop = NULL;

	nexthop_group_copy(&nhe->nhg, &source_nhe->nhg);

	/* Mark duplicate NH here to keep FIB nexthop accounting identical to the
	 * normal resolution path.
	 */
	nexthop_group_mark_duplicates(&nhe->nhg);

	zebra_nhg_rebuild_depends(nhe);

	/* Migrate backup_info to match source_nhe.
	 * Teardown is just zebra_nhg_backup_free which decrements each old
	 * backup-dep's refcnt -- no backpointers to clear (none were wired).
	 */
	if (nhe->backup_info)
		zebra_nhg_backup_free(&nhe->backup_info);

	if (source_nhe->backup_info) {
		/* nhg_backup_copy copies only the nexthop list;
		 * the depends tree must be built separately using zebra_nhg_backup_build_depends
		 */
		nhe->backup_info = nhg_backup_copy(source_nhe->backup_info);
		zebra_nhg_backup_build_depends(nhe->backup_info->nhe, nhe->afi);
	}

	/*
	 * Update interface pointer for singletons.  The new nexthop
	 * may use a different interface than the old one.  Remove from
	 * old zif->nhg_dependents and add to new.
	 */
	if (!PROTO_OWNED(nhe) && ZEBRA_NHG_IS_SINGLETON(nhe) && nhe->nhg.nexthop->ifindex &&
	    !CHECK_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_RECURSIVE)) {
		struct interface *new_ifp;

		new_ifp = if_lookup_by_index(nhe->nhg.nexthop->ifindex, nhe->nhg.nexthop->vrf_id);
		if (new_ifp && new_ifp != nhe->ifp) {
			if (nhe->ifp) {
				struct zebra_if *old_zif = nhe->ifp->info;

				nhg_connected_tree_del_nhe(&old_zif->nhg_dependents, nhe);
			}
			zebra_nhg_set_if(nhe, new_ifp);
		}
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u reworked (refcnt %d flags 0x%x depends %zu backup %s) <- source NHG %u",
			   __func__, nhe->id, nhe->refcnt, nhe->flags,
			   nhg_connected_tree_count(&nhe->nhg_depends),
			   nhe->backup_info ? "yes" : "no", source_nhe->id);

	frrtrace(6, frr_zebra, nhg_rework, "rework-mutate", nhe->id, nhe->refcnt, 0,
		 nhg_connected_tree_count(&nhe->nhg_depends), source_nhe->id);
}

/*
 * Rework in-place: rehash — re-insert nhe into the content hash after
 * its content has been mutated.
 */
void zebra_nhg_rework_content_rehash(struct nhg_hash_entry *nhe)
{
	struct nhg_hash_entry *result;

	result = hash_get(zrouter.nhgs, nhe, hash_alloc_intern);
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: input NHG %u (ptr=%p flags=0x%x) -> hash_get NHG %u (ptr=%p flags=0x%x) inserted=%d",
			   __func__, nhe->id, nhe, nhe->flags, result ? result->id : 0, result,
			   result ? result->flags : 0, (result == nhe) ? 1 : 0);

	frrtrace(5, frr_zebra, nhg_hash_reinsert, "nhg-tracker-rehash", nhe->id,
		 result ? result->id : 0, (result == nhe) ? 1 : 0, nhe->flags);
}

/*
 * Rework an NHG in-place: replace nhe's content with source_nhe's content.
 * This is the single-call wrapper; callers that need to keep nhe out
 * of the content hash across a separate processing window (e.g.during the
 * tracker flush) should call the three primitives directly.
 */
void zebra_nhg_rework_in_place(struct nhg_hash_entry *nhe, struct nhg_hash_entry *source_nhe)
{
	zebra_nhg_rework_content_release(nhe);
	zebra_nhg_rework_content_mutate(nhe, source_nhe);
	zebra_nhg_rework_content_rehash(nhe);
}

/*
 * Hash walk callback: find NHGs whose content matches ctx->target.
 *
 * zebra_nhg_hash_equal short-circuits when both IDs are non-zero
 * (different IDs -> "not equal").  The caller sets target->id = 0
 * so the comparison falls through to actual content matching.
 */
static void nhg_dup_find_cb(struct hash_bucket *bucket, void *arg)
{
	struct nhg_hash_entry *nhe = bucket->data;
	struct nhg_dup_walk_ctx *ctx = arg;

	if (nhe == ctx->target)
		return;

	if (!zebra_nhg_hash_equal(nhe, ctx->target))
		return;

	if (ctx->count >= ctx->capacity) {
		ctx->capacity = ctx->capacity ? ctx->capacity * 2 : 8;
		ctx->dups = XREALLOC(MTYPE_NHG, ctx->dups, ctx->capacity * sizeof(*ctx->dups));
	}
	ctx->dups[ctx->count++] = nhe;
}

/*
 * Migrate all REs from a loser NHG to the winner.
 * Iterates the loser's re_head directly.
 * frr_each_safe pre-fetches the next element, so it is safe even though
 * route_entry_update_nhe removes the RE from loser->re_head during the loop body.
 *
 * For each RE:
 *  1. route_entry_update_nhe switches re->nhe to the winner (moves
 *     the RE between re_head trees, updates refcounts).
 *  2. rib_install_kernel with old=NULL sends RTM_NEWROUTE.
 * After all REs are migrated, the loser's refcount drops and the
 * existing keep-around timer cleans it up.
 */
static void nhg_consolidate_migrate_loser(struct nhg_hash_entry *loser,
					  struct nhg_hash_entry *winner)
{
	uint32_t migrated = 0;
	struct route_entry *re;

	frr_each_safe (nhe_re_tree, &loser->re_head, re) {
		/*
		 * Skip REs owned by an active tracker — the tracker's
		 * phase 1/2 ack tracking uses re->nhe and the parent
		 * NHG ID; switching the NHG now would break it.
		 */
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_TRACKER |
						   ROUTE_ENTRY_NHG_TRACKER_FLUSH_BATCH |
						   ROUTE_ENTRY_NHG_TRACKER_WINNER))
			continue;

		route_entry_update_nhe(re, winner);

		/* Include QUEUED so freshly-released winners (QUEUED but not yet installed)
		 * still get a fresh ROUTE_INSTALL enqueued on the winner NHG here.
		 */
		if (re->rn && CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED | ROUTE_ENTRY_QUEUED)) {
			rib_install_kernel(re->rn, re, NULL);
		} else {
			frrtrace(5, frr_zebra, nhg_migrate, "migrate-skip", loser->id, winner->id,
				 re->status, 0);
		}

		migrated++;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u -> %u: migrated %u routes", __func__, loser->id, winner->id,
			   migrated);

	frrtrace(5, frr_zebra, nhg_migrate, "migrated", loser->id, winner->id, 0, migrated);
}

static void zebra_nhg_consolidate_event_handler(struct event *event)
{
	struct nhg_hash_entry *nhe = EVENT_ARG(event);
	struct nhg_dup_walk_ctx ctx = {};
	struct nhg_hash_entry *winner = NULL;
	struct nhg_hash_entry *dup;
	uint32_t winner_re_count = 0;
	uint32_t saved_id;
	uint32_t i;
	uint32_t skipped = 0;
	uint32_t re_count;
	bool nhe_busy;

	if (zebra_router_in_shutdown())
		return;

	saved_id = nhe->id;
	nhe->id = 0;
	ctx.target = nhe;
	hash_iterate(zrouter.nhgs, nhg_dup_find_cb, &ctx);
	nhe->id = saved_id;

	/*
	 * If nhe itself is busy, abort this consolidation round entirely.
	 * nhe keeps its DUPLICATE flag set. pending_winners-hit-zero or
	 * tracker_flush_batch_finish will re-fire consolidation on this nhe.
	 */
	nhe_busy = (nhg_event_tracker_list_count(&nhe->tracker_list) > 0 ||
		    nhe->tracker_pending_winners > 0);

	if (nhe_busy) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: NHG %u busy (trackers=%zu pending_winners=%u); skipping consolidation, DUPLICATE retained",
				   __func__, nhe->id,
				   nhg_event_tracker_list_count(&nhe->tracker_list),
				   nhe->tracker_pending_winners);

		frrtrace(5, frr_zebra, nhg_consolidate_busy, "consolidate-busy", nhe->id, 0,
			 (uint32_t)nhg_event_tracker_list_count(&nhe->tracker_list),
			 nhe->tracker_pending_winners);
		XFREE(MTYPE_NHG, ctx.dups);
		return;
	}

	/* Pick winner among nhe + non-busy dups by re_count
	 * Busy dups are skipped silently. their own triggers will re-fire later.
	 */
	winner = nhe;
	winner_re_count = nhe_re_tree_count(&nhe->re_head);

	for (i = 0; i < ctx.count; i++) {
		dup = ctx.dups[i];

		if (nhg_event_tracker_list_count(&dup->tracker_list) > 0 ||
		    dup->tracker_pending_winners > 0) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: NHG %u skipping busy dup NHG %u (trackers=%zu pending_winners=%u)",
					   __func__, nhe->id, dup->id,
					   nhg_event_tracker_list_count(&dup->tracker_list),
					   dup->tracker_pending_winners);

			frrtrace(5, frr_zebra, nhg_consolidate_busy, "consolidate-skip-dup",
				 nhe->id, dup->id,
				 (uint32_t)nhg_event_tracker_list_count(&dup->tracker_list),
				 dup->tracker_pending_winners);
			ctx.dups[i] = NULL;
			skipped++;
			continue;
		}

		/* Non-busy: candidate for winner selection. */
		re_count = nhe_re_tree_count(&dup->re_head);
		if (re_count > winner_re_count ||
		    (re_count == winner_re_count && dup->id < winner->id)) {
			winner = dup;
			winner_re_count = re_count;
		}
	}

	if (ctx.count - skipped == 0) {
		/*
		 * No non-busy dups paired with nhe.  Either there are
		 * genuinely no dups, or all dups are busy.  Either way we
		 * clear DUPLICATE on nhe — busy dups carry their own
		 * DUPLICATE + triggers, and will find nhe via hash walk
		 * when they re-fire.
		 */
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: NHG %u no mergeable duplicate this round (dups found=%u, busy=%u%s) - clearing DUPLICATE",
				   __func__, nhe->id, ctx.count, skipped,
				   ctx.count == 0 ? ", none exist" : "");

		frrtrace(6, frr_zebra, nhg_consolidate, "consolidate-none", nhe->id, 0, ctx.count,
			 skipped, 0);
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE);
		XFREE(MTYPE_NHG, ctx.dups);
		return;
	}

	/*
	 * Migrate each non-busy loser NHG's routes to the winner.
	 *
	 * For each installed RE on the loser, switch re->nhe to the
	 * winner and call rib_install_kernel(rn, re, NULL) to send
	 * RTM_NEWROUTE with the winner's NHG ID to the kernel.
	 *
	 * nhe is migrated separately first since it isn't in ctx.dups[];
	 * then walk ctx.dups[] for every non-skipped, non-winner dup.
	 */
	if (nhe != winner) {
		zlog_info("%s: migrating NHG %u -> winner NHG %u", __func__, nhe->id, winner->id);
		nhg_consolidate_migrate_loser(nhe, winner);
	}

	for (i = 0; i < ctx.count; i++) {
		if (ctx.dups[i] == NULL || ctx.dups[i] == winner)
			continue;
		zlog_info("%s: migrating NHG %u -> winner NHG %u", __func__, ctx.dups[i]->id,
			  winner->id);
		nhg_consolidate_migrate_loser(ctx.dups[i], winner);
	}

	/* Clear DUPLICATE on nhe and the winner. */
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u consolidation done: winner NHG %u (dups found=%u skipped busy=%u winner re_count=%u)",
			   __func__, nhe->id, winner->id, ctx.count, skipped, winner_re_count);

	frrtrace(6, frr_zebra, nhg_consolidate, "consolidate-done", nhe->id, winner->id, ctx.count,
		 skipped, winner_re_count);
	UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE);
	UNSET_FLAG(winner->flags, NEXTHOP_GROUP_DUPLICATE);

	XFREE(MTYPE_NHG, ctx.dups);
}

void zebra_nhg_mark_duplicate(struct nhg_hash_entry *nhe)
{
	if (!nhe || CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE))
		return;

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE);
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u has content-duplicate in the hash, consolidation will fire once winners drain",
			   __func__, nhe->id);

	frrtrace(4, frr_zebra, nhg_state, "mark-duplicate", nhe->id, nhe->flags, nhe->refcnt);
}

/*
 * Mark an old/installed NHG as a reuse-target.
 */
void zebra_nhg_mark_reuse(struct nhg_hash_entry *nhe)
{
	if (!nhe || CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE))
		return;

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: NHG %u marked as reuse-target", __func__, nhe->id);

	frrtrace(4, frr_zebra, nhg_state, "mark-reuse", nhe->id, nhe->flags, nhe->refcnt);
}

/* Schedule the consolidation event for nhe */
void zebra_nhg_schedule_consolidate(struct nhg_hash_entry *nhe)
{
	if (!nhe)
		return;
#ifdef NHG_TRK_VERBOSE_LOG
	zlog_info("pw-trk: schedule_consolidate NHG %u (dup=%d pending_winners=%u)", nhe->id,
		  CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_DUPLICATE) ? 1 : 0,
		  nhe->tracker_pending_winners);
#endif
	event_add_event(zrouter.master, zebra_nhg_consolidate_event_handler, nhe, 0,
			&nhe->consolidation_event);
}

static void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG)", __func__, nhe, nhe);

	frrtrace(4, frr_zebra, nhg_state, "nhg-release", nhe->id, nhe->flags, nhe->refcnt);

	zebra_nhg_release_all_deps(nhe);

	/*
	 * If its not zebra owned, we didn't store it here and have to be
	 * sure we don't clear one that's actually being used.
	 */
	if (nhe->id < ZEBRA_NHG_PROTO_LOWER)
		hash_release(zrouter.nhgs, nhe);

	hash_release(zrouter.nhgs_id, nhe);
}

static void zebra_nhg_handle_uninstall(struct nhg_hash_entry *nhe)
{
	zebra_nhg_release(nhe);

	/* Release bitmap bit only for stale FDB entries read from kernel
	 * at startup. Normal FDB entries have their bitmap managed by
	 * the EVPN-MH layer (zebra_evpn_nhid_free).
	 */
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_STALE_FDB))
		zebra_evpn_mh_release_stale_nhid(nhe->id);

	zebra_nhg_free(nhe);
}

static void nhg_handle_install_one(struct nhg_connected *node)
{
	struct nhg_connected *rb_node_indirect_dep = NULL;

	frr_each_safe (nhg_connected_tree, &node->nhe->nhg_dependents,
		       rb_node_indirect_dep) {
		SET_FLAG(rb_node_indirect_dep->nhe->flags,
			 NEXTHOP_GROUP_REINSTALL);

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s nh id %u (flags 0x%x) associated dependents NHG %pNG (flags 0x%x) Re-install",
				   __func__, node->nhe->id,
				   node->nhe->flags,
				   rb_node_indirect_dep->nhe,
				   rb_node_indirect_dep->nhe->flags);

		/*
		 * Defer kernel install if any tracker exists on this NHG.
		 * The tracker flow handles the install.
		 */
		if (nhg_event_tracker_list_count(&rb_node_indirect_dep->nhe->tracker_list) == 0) {
			frrtrace(4, frr_zebra, nhg_install_dep, "install-indirect-dep",
				 rb_node_indirect_dep->nhe->id, rb_node_indirect_dep->nhe->flags,
				 node->nhe->id);
			zebra_nhg_install_kernel(rb_node_indirect_dep->nhe, ZEBRA_ROUTE_MAX);
		}
	}

}

static void zebra_nhg_handle_install(struct nhg_hash_entry *nhe, bool install)
{
	/* Update validity of groups depending on it */
	struct nhg_connected *rb_node_dep;

	frr_each_safe (nhg_connected_tree, &nhe->nhg_dependents, rb_node_dep) {
		zebra_nhg_set_valid(rb_node_dep->nhe, true);
		/* install dependent NHG into kernel */
		if (install) {
			if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) &&
			    CHECK_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_RECURSIVE)) {
				nhg_handle_install_one(rb_node_dep);
			}

			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"%s nh id %u (flags 0x%x) associated dependent NHG %pNG install",
					__func__, nhe->id, nhe->flags,
					rb_node_dep->nhe);

			/*
			 * Defer kernel install if this dependent has an
			 * active tracker; the tracker flush will drive
			 * installation with the reworked NHG state.
			 */
			if (nhg_event_tracker_list_count(&rb_node_dep->nhe->tracker_list) > 0) {
				frrtrace(4, frr_zebra, nhg_install_dep, "reinstall-dep",
					 rb_node_dep->nhe->id, rb_node_dep->nhe->flags, nhe->id);
				SET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_REINSTALL);
			} else
				zebra_nhg_install_kernel(rb_node_dep->nhe, ZEBRA_ROUTE_MAX);
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
	bool startup = nhg_ctx_get_startup(ctx);

	lookup = zebra_nhg_lookup_id(id);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: id %u, count %d, lookup => %p",
			   __func__, id, count, lookup);

	if (lookup) {
		/* This is already present in our table, hence an update
		 * that we did not initiate.
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

		if (!zebra_nhg_find(&nhe, id, nhg, &nhg_depends, vrf_id, afi,
				    type, true))
			depends_decrement_free(&nhg_depends);

		/* These got copied over in zebra_nhg_alloc() */
		nexthop_group_delete(&nhg);
	} else
		nhe = zebra_nhg_find_nexthop(id, nhg_ctx_get_nh(ctx), afi, type,
					     true);

	if (!nhe) {
		flog_err(
			EC_ZEBRA_TABLE_LOOKUP_FAILED,
			"Zebra failed to find or create a nexthop hash entry for ID (%u)",
			id);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nhe %p (%pNG) is new", __func__, nhe, nhe);

	frrtrace(1, frr_zebra, nhg_ctx_process_new_nhe, id);

	SET_FLAG(nhe->flags, NEXTHOP_GROUP_RECEIVED_FROM_EXTERNAL);
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_VALID);
	SET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);

	/*
	 * On startup Zebra is creating the nexthop group cache entry
	 * after the router has it's startup time set.  This is because
	 * the process of grabbing routes and nexthops is now *after*
	 * the dataplane starts up, which is after the routers startup
	 * time is set.  So let's just cheat a tiny bit on the time
	 * and set the nexthop group hash entry startup time to be
	 * slightly before the zrouter.startup_time.  Then graceful
	 * restart sweeping will work properly for these nexthop entries
	 */
	if (startup) {
		nhe->uptime = zrouter.startup_time - 1;
		/* tag stale FDB NH/NHG and reserve its bitmap bit; sweep
		 * releases the bit via zebra_evpn_mh_release_stale_nhid()
		 */
		if (zebra_evpn_mh_is_fdb_nh(id)) {
			SET_FLAG(nhe->flags, NEXTHOP_GROUP_STALE_FDB);
			zebra_evpn_mh_reserve_stale_nhid(id);
		}
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

	ctx = nhg_ctx_init(id, nh, grp, vrf_id, afi, type, count, nhgr, startup);
	nhg_ctx_set_op(ctx, NHG_CTX_OP_NEW);

	/* Under startup conditions, we need to handle them immediately
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

	ctx = nhg_ctx_init(id, NULL, NULL, vrf_id, 0, 0, 0, NULL, false);

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

	nhe = zebra_nhg_find_nexthop(0, lookup, afi, type, false);

	nexthops_free(lookup);

	return nhe;
}

static struct nhg_hash_entry *depends_find_singleton(const struct nexthop *nh,
						     afi_t afi, int type,
						     bool from_dplane)
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
	nhe = zebra_nhg_find_nexthop(0, &lookup, afi, type, from_dplane);

	/* The copy may have allocated labels; free them if necessary. */
	nexthop_del_labels(&lookup);
	nexthop_del_srv6_seg6local(&lookup);
	nexthop_del_srv6_seg6(&lookup);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: nh %pNHv => %p (%pNG)", __func__, nh, nhe, nhe);

	return nhe;
}

static struct nhg_hash_entry *depends_find(const struct nexthop *nh, afi_t afi,
					   int type, bool from_dplane)
{
	struct nhg_hash_entry *nhe = NULL;

	if (!nh)
		goto done;

	/* We are separating these functions out to increase handling speed
	 * in the non-recursive case (by not alloc/freeing)
	 */
	if (CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE))
		nhe = depends_find_recursive(nh, afi, type);
	else
		nhe = depends_find_singleton(nh, afi, type, from_dplane);


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

static struct nhg_hash_entry *
depends_find_add(struct nhg_connected_tree_head *head, struct nexthop *nh,
		 afi_t afi, int type, bool from_dplane)
{
	struct nhg_hash_entry *depend = NULL;

	depend = depends_find(nh, afi, type, from_dplane);

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

	zebra_nhg_find(&nhe, id, nhg, NULL, vrf_id, rt_afi, type, false);

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

	zebra_nhe_find(&nhe, rt_nhe, NULL, rt_afi, false);

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
	nhg_connected_tree_free(&nhe->nhg_depends);
	nhg_connected_tree_free(&nhe->nhg_dependents);

	zebra_nhg_tracker_fini(nhe);
}

void zebra_nhg_free(struct nhg_hash_entry *nhe)
{
	if (IS_ZEBRA_DEBUG_NHG_DETAIL) {
		if (ZEBRA_NHG_IS_SINGLETON(nhe))
			zlog_debug("%s: nhe %p (%pNG), refcnt %d, NH %pNHv",
				   __func__, nhe, nhe, nhe->refcnt,
				   nhe->nhg.nexthop);
		else
			zlog_debug("%s: nhe %p (%pNG) flags (0x%x), refcnt %d", __func__, nhe, nhe,
				   nhe->flags, nhe->refcnt);
	}

	event_cancel(&nhe->timer);
	event_cancel(&nhe->consolidation_event);

	if (nhe->id)
		frrtrace(1, frr_zebra, zebra_nhg_free_nhe_refcount, nhe);

	/*
	 * Since the nhe->re_tree is in line with the refcount, all the re entries
	 * should have been deleted at this point in time.
	 */
	assert(!nhe_re_tree_count(&nhe->re_head));
	nhe_re_tree_fini(&nhe->re_head);
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
		if (ZEBRA_NHG_IS_SINGLETON(nhe))
			zlog_debug("%s: nhe %p (%pNG), refcnt %d, NH %pNHv",
				   __func__, nhe, nhe, nhe->refcnt,
				   nhe->nhg.nexthop);
		else
			zlog_debug("%s: nhe %p (%u), refcnt %d", __func__, nhe, nhe->id,
				   nhe->refcnt);
	}

	event_cancel(&nhe->timer);

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

static void zebra_nhg_timer(struct event *event)
{
	struct nhg_hash_entry *nhe = EVENT_ARG(event);

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
	    (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) ||
	     CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) &&
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
		event_cancel(&nhe->timer);
		nhe->refcnt--;
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_KEEP_AROUND);
	}

	if (!zebra_nhg_depends_is_empty(nhe))
		nhg_connected_tree_increment_ref(&nhe->nhg_depends);
}

static struct nexthop *nexthop_set_resolved(afi_t afi, const struct nexthop *newhop,
					    struct nexthop *nexthop,
					    struct zebra_sr_policy *policy, uint32_t flags)
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
	if (CHECK_FLAG(flags, ZEBRA_FLAG_USE_RECURSIVE_WEIGHT))
		resolved_hop->weight = newhop->weight;
	else
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
			nexthop_add_srv6_seg6(resolved_hop, &nexthop->nh_srv6->seg6_segs->seg[0],
					      nexthop->nh_srv6->seg6_segs->num_segs,
					      nexthop->nh_srv6->seg6_segs->encap_behavior);
	}

	/* Handle evpn nexthop - capture that info also */
	if (CHECK_FLAG(newhop->flags, NEXTHOP_FLAG_EVPN)) {
		resolved_hop->nh_encap_type = newhop->nh_encap_type;
		memcpy(&(resolved_hop->rmac), &(newhop->rmac), ETH_ALEN);
		SET_FLAG(resolved_hop->flags, NEXTHOP_FLAG_EVPN);
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
		case AFI_BGP_LS:
		case AFI_MAX:
			flog_err(EC_LIB_DEVELOPMENT,
				 "%s: unknown address-family: %u", __func__,
				 afi);
			frr_exit_with_buffer_flush(1);
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
				nexthop_set_resolved(afi, nhlfe->nexthop, nexthop, policy, flags);
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
	case AFI_BGP_LS:
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

		/*
		 * Lookup should not care about the prefix being the same
		 * for a cross vrf nexthop.
		 * Lookup should halt if we've matched against ourselves ('top',
		 * if specified) - i.e., we cannot have a nexthop NH1 is
		 * resolved by a route NH1. The exception is if the route is a
		 * host route.
		 */
		if (vrf_id == nexthop->vrf_id && prefix_same(&rn->p, top))
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
			 * for resolution at approximately the same time in the [
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
				resolver = nexthop_set_resolved(afi, newhop, nexthop, NULL, flags);
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

		if (ifp && ifp->vrf->vrf_id == vrf_id && if_is_up(ifp) && if_is_operative(ifp)) {
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
		/* Route-map denied a NH. This RE can no longer reuse the old NHG. */
		UNSET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
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
	if (CHECK_FLAG(nhe->nhg.nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
		struct interface *ifp = if_lookup_by_index(nhe->nhg.nexthop->ifindex, nhe->vrf_id);

		if (!ifp || !if_is_operative(ifp))
			valid = false;
		else
			valid = true;
	}

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
		if (new_active && counter >= zrouter.zav.multipath_num) {
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

void nexthop_vrf_update(struct route_node *rn, struct route_entry *re, vrf_id_t vrf_id)
{
	struct nhg_hash_entry *curr_nhe, *new_nhe;
	afi_t rt_afi = family2afi(rn->p.family);
	struct nexthop *nexthop;

	/* vrf_id is part of the re_head RB key.
	 * Remove old key, change, re-add to keep the tree ordered.
	 */
	nhe_add_or_del_re_tree(re->nhe, re, __func__, true);

	re->vrf_id = vrf_id;

	nhe_add_or_del_re_tree(re->nhe, re, __func__, false);

	/* Make a local copy of the existing nhe, so we don't work on/modify
	 * the shared nhe.
	 */
	curr_nhe = zebra_nhe_copy(re->nhe, re->nhe->id);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p nhe %p (%pNG), curr_nhe %p", __func__, re, re->nhe, re->nhe,
			   curr_nhe);

	/* Clear the existing id, if any: this will avoid any confusion
	 * if the id exists, and will also force the creation
	 * of a new nhe reflecting the changes we may make in this local copy.
	 */
	curr_nhe->id = 0;

	curr_nhe->vrf_id = vrf_id;
	for (ALL_NEXTHOPS(curr_nhe->nhg, nexthop)) {
		if (!nexthop->ifindex)
			/* change VRF ID of nexthop without interfaces
			 * (eg. blackhole)
			 */
			nexthop->vrf_id = vrf_id;
	}

	if (zebra_nhg_get_backup_nhg(curr_nhe)) {
		for (ALL_NEXTHOPS(curr_nhe->backup_info->nhe->nhg, nexthop)) {
			if (!nexthop->ifindex)
				/* change VRF ID of nexthop without interfaces
				 * (eg. blackhole)
				 */
				nexthop->vrf_id = vrf_id;
		}
	}

	/*
	 * Ref or create an nhe that matches the current state of the
	 * nexthop(s).
	 */
	new_nhe = zebra_nhg_rib_find_nhe(curr_nhe, rt_afi);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p CHANGED: nhe %p (%pNG) => new_nhe %p (%pNG)", __func__, re,
			   re->nhe, re->nhe, new_nhe, new_nhe);

	route_entry_update_nhe(re, new_nhe);

	/*
	 * Do not need the old / copied nhe anymore since it
	 * was either copied over into a new nhe or not
	 * used at all.
	 */
	zebra_nhg_free(curr_nhe);
}

/*
 * Compare an incoming (protocol) nexthop list against a reference nexthop
 * list to decide whether they represent the same NHG, for the NHG tracker.
 *
 * Both lists are kept sorted, so the walk is lockstep.  The incoming list is
 * unresolved (no ACTIVE flags), so gateways are compared with
 * nexthop_same_no_ifindex() - an unresolved incoming NH (IPV4) still matches
 * its resolved installed form (IPV4_IFINDEX).
 *
 * skip_inactive_old selects the two comparison cases:
 *   false : reference is an unresolved snapshot (ECMP-change event); compare
 *           element-wise, any leftover on either side => differ.
 *   true  : reference is a resolved/installed NHG; skip its inactive members
 *           (down/unusable) and compare the incoming set against the active
 *           members only.  A recursive NH's top-level ACTIVE flag already
 *           summarizes its resolution, so gateway-level compare suffices.
 */
bool zebra_nhg_nexthop_compare(const struct nexthop *nhop, const struct nexthop *old_nhop,
			       const struct route_node *rn, bool skip_inactive_old)
{
	bool same = true;

	if (nhop == old_nhop)
		return true;

	while (nhop && old_nhop) {
		/* An inactive installed NH is "extra" - skip it and
		 * keep the incoming NH for the next comparison.
		 */
		if (skip_inactive_old && !CHECK_FLAG(old_nhop->flags, NEXTHOP_FLAG_ACTIVE)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: %pRN old %pNHvv inactive, skipping", __func__, rn,
					   old_nhop);
			old_nhop = old_nhop->next;
			continue;
		}

		if (!nexthop_same_no_ifindex(nhop, old_nhop)) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: %pRN %pNHvv != old %pNHvv, differ", __func__, rn,
					   nhop, old_nhop);
			same = false;
			break;
		}

		nhop = nhop->next;
		old_nhop = old_nhop->next;
	}

	/* Leftover incoming NHs => differ. */
	if (nhop) {
		same = false;
	} else if (old_nhop) {
		if (skip_inactive_old) {
			/* Only leftover ACTIVE old NHs mean the sets differ. */
			while (old_nhop) {
				if (CHECK_FLAG(old_nhop->flags, NEXTHOP_FLAG_ACTIVE)) {
					same = false;
					break;
				}
				old_nhop = old_nhop->next;
			}
		} else {
			/* Any leftover reference NH means the sets differ. */
			same = false;
		}
	}

	return same;
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
	uint16_t resolved_active __attribute__((unused)) = 0;
	uint16_t incoming_count __attribute__((unused)) = 0;
	struct nhg_hash_entry *curr_nhe, *remove;
	struct nhg_hash_entry *parent_nhe = NULL;
	struct nexthop *nhop;
	bool is_tracker_winner;
	bool shape_differs, route_map_ok, reuse_ok;
	bool first_winner;
	uint32_t curr_active = 0, backup_active = 0;

	if (PROTO_OWNED(re->nhe) ||
	    CHECK_FLAG(re->nhe->flags, NEXTHOP_GROUP_RECEIVED_FROM_EXTERNAL))
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

	/*
	 * Tracker-winner detection: phase 2 sets ROUTE_ENTRY_NHG_TRACKER_WINNER
	 * on released winners (and fired silent REs).  parent_nhe is the
	 * previously-installed NHG carrying the tracker context.
	 * NHG reuse is done here for all the winner REs coming from tracker,
	 * and this is driven by the first winner RE.
	 * is_tracker_winner gates id-lock, counter decrement, and (for the
	 * first winner RE) the in-place rework + mark_duplicate.
	 */
	is_tracker_winner = CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
	if (is_tracker_winner && old_re && old_re->nhe)
		parent_nhe = old_re->nhe;

	/*
	 * Force content-only lookup in zebra_nhg_rib_find_nhe below.  For
	 * tracker winners we may overwrite this with parent_nhe->id later so
	 * the lookup lands deterministically on parent_nhe.
	 */
	curr_nhe->id = 0;

	/* Process nexthops */
	curr_active = nexthop_list_active_update(rn, re, curr_nhe, false);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p (%pRN) curr_active %u nhe %u (flags 0x%x) status 0x%x tracker_winner %d parent_nhe %u (flags 0x%x) old_re %p old_nhe %u (flags 0x%x)",
			   __func__, re, rn, curr_active, re->nhe ? re->nhe->id : 0,
			   re->nhe ? re->nhe->flags : 0, re->status, is_tracker_winner ? 1 : 0,
			   parent_nhe ? parent_nhe->id : 0, parent_nhe ? parent_nhe->flags : 0,
			   old_re, (old_re && old_re->nhe) ? old_re->nhe->id : 0,
			   (old_re && old_re->nhe) ? old_re->nhe->flags : 0);

	/* If there are no backup nexthops, we are done */
	if (zebra_nhg_get_backup_nhg(curr_nhe) == NULL)
		goto backups_done;

	backup_active = nexthop_list_active_update(
		rn, re, curr_nhe->backup_info->nhe, true /*is_backup*/);

	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		zlog_debug("%s: re %p (%pRN) backup_active %u nhe %u (flags 0x%x) status 0x%x parent_nhe %u (flags 0x%x) old_re %p old_nhe %u (flags 0x%x)",
			   __func__, re, rn, backup_active, re->nhe ? re->nhe->id : 0,
			   re->nhe ? re->nhe->flags : 0, re->status,
			   parent_nhe ? parent_nhe->id : 0, parent_nhe ? parent_nhe->flags : 0,
			   old_re, (old_re && old_re->nhe) ? old_re->nhe->id : 0,
			   (old_re && old_re->nhe) ? old_re->nhe->flags : 0);

backups_done:

	/*
	 * Tracker-winner handling.  When this RE was released as a winner
	 * by tracker phase 2 (ROUTE_ENTRY_NHG_TRACKER_WINNER), the resolver
	 * runs the following per-RE work:
	 *
	 *  - Route-map check against parent_nhe.
	 *  - For the FIRST winner only (parent_nhe still has TRACKER_REUSE):
	 *    do the in-place rework so parent_nhe ends up carrying the
	 *    resolved winner content, and mark_duplicate if another content-
	 *    equal NHG already exists in the hash.
	 *  - For ALL winners (first and subsequent): lock curr_nhe->id to
	 *    parent_nhe->id so the subsequent rib_find_nhe lands on parent_nhe
	 *    by ID.
	 *  - Always: clear the WINNER flag, decrement
	 *    parent_nhe->tracker_pending_winners, and when the counter
	 *    reaches 0 with DUPLICATE set, schedule the consolidation event.
	 */
	if (parent_nhe) {
		first_winner = CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);

		for (nhop = curr_nhe->nhg.nexthop; nhop; nhop = nhop->next) {
			incoming_count++;
			if (CHECK_FLAG(nhop->flags, NEXTHOP_FLAG_ACTIVE))
				resolved_active++;
		}

		shape_differs = (ZEBRA_NHG_IS_SINGLETON(parent_nhe) !=
				 ZEBRA_NHG_IS_SINGLETON(curr_nhe));
		/*
		 * WINNER survives resolution unless a route-map denied a NH on this RE.
		 * RE still has WINNER means this RE is eligible to reuse the old NHG.
		 */
		route_map_ok = CHECK_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
		reuse_ok = route_map_ok && !shape_differs;

		if (first_winner) {
			if (!route_map_ok) {
				/*
				 * Route-map denied some NHs for this RE only;
				 * leave REUSE set so another winner (without
				 * the route-map issue) can still trigger the rework
				 * todo: logged for testing. remove this log.
				 */
				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug("%s: NHG reuse skipped for old NHG %u (active=%u != incoming=%u), route-map mismatch -- leaving REUSE for another winner",
						   __func__, parent_nhe->id, resolved_active,
						   incoming_count);

				frrtrace(4, frr_zebra, nhg_reuse, "reuse-skip-rmap",
					 parent_nhe->id, resolved_active, incoming_count);
			} else if (shape_differs) {
				/*
				 * Kernel rejects in-place RTM_NEWNEXTHOP across
				 * singleton<->group changes.  Clear REUSE+
				 * REINSTALL so subsequent winners don't id-lock
				 * onto a not-yet-reworked parent_nhe.
				 * todo: remove this check once zebra handles this limitation.
				 */
#ifdef NHG_TRK_VERBOSE_LOG
				zlog_info("%s: NHG reuse skipped for old NHG %u: shape mismatch (parent_singleton=%d curr_singleton=%d)",
					  __func__, parent_nhe->id,
					  ZEBRA_NHG_IS_SINGLETON(parent_nhe) ? 1 : 0,
					  ZEBRA_NHG_IS_SINGLETON(curr_nhe) ? 1 : 0);
#endif
				UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);
				UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_REINSTALL);
			} else {
				/*
				 * Look up resolved content in the NHG hash:
				 *  - found == parent_nhe: fast-path, skip rework.
				 *  - found == other content-equal NHG: rework
				 *    parent (preserving its id) + mark_duplicate
				 *    so consolidation merges them once all
				 *    winners attach.
				 *  - found == NULL: rework parent so it becomes
				 *    the unique carrier of resolved content.
				 */
				struct nhg_hash_entry *found = hash_lookup(zrouter.nhgs, curr_nhe);

				if (found == parent_nhe) {
					if (IS_ZEBRA_DEBUG_NHG_DETAIL)
						zlog_debug("%s: NHG reuse fast-path: parent NHG %u already holds resolved content (active=%u incoming=%u)",
							   __func__, parent_nhe->id,
							   resolved_active, incoming_count);

					frrtrace(4, frr_zebra, nhg_reuse, "reuse-fastpath",
						 parent_nhe->id, resolved_active, incoming_count);
					UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);
				} else {
					if (IS_ZEBRA_DEBUG_NHG_DETAIL)
						zlog_debug("%s: NHG reuse: copying resolved state onto old NHG %u (active=%u incoming=%u)",
							   __func__, parent_nhe->id,
							   resolved_active, incoming_count);

					frrtrace(4, frr_zebra, nhg_reuse, "reuse-copy",
						 parent_nhe->id, resolved_active, incoming_count);
					zebra_nhg_rework_in_place(parent_nhe, curr_nhe);
					UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);
					if (found && found != parent_nhe)
						zebra_nhg_mark_duplicate(parent_nhe);
				}
			}
		}

		/*
		 * Id-lock for ALL winners that pass the reuse checks. This makes
		 * the subsequent rib_find_nhe land on parent_nhe by ID lookup.
		 */
		if (reuse_ok)
			curr_nhe->id = parent_nhe->id;

		/* Counter bookkeeping for ALL winners (including shape/route-map skips). */
		UNSET_FLAG(re->status, ROUTE_ENTRY_NHG_TRACKER_WINNER);
		if (parent_nhe->tracker_pending_winners > 0)
			parent_nhe->tracker_pending_winners--;

		if (parent_nhe->tracker_pending_winners == 0) {
			/* All winners drained: clear REUSE+REINSTALL and, when
			 * this NHG is a content-duplicate, schedule consolidation.
			 */
			if (CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE)) {
				UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_TRACKER_REUSE);
				UNSET_FLAG(parent_nhe->flags, NEXTHOP_GROUP_REINSTALL);
			}
			if (CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_DUPLICATE))
				zebra_nhg_schedule_consolidate(parent_nhe);
		}

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: winner drained %pRN parent NHG %u -> pending_winners=%u (reuse_ok=%d locked_id=%u dup=%d)",
				   __func__, rn, parent_nhe->id,
				   parent_nhe->tracker_pending_winners, reuse_ok ? 1 : 0,
				   curr_nhe->id,
				   CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_DUPLICATE) ? 1 : 0);

		frrtrace(6, frr_zebra, nhg_winner, "winner-drained", parent_nhe->id,
			 parent_nhe->tracker_pending_winners, reuse_ok ? 1 : 0, curr_nhe->id,
			 CHECK_FLAG(parent_nhe->flags, NEXTHOP_GROUP_DUPLICATE) ? 1 : 0);
	} else if (is_tracker_winner) {
		/*
		 * Winner with no installed peer (old_re NULL): parent_nhe
		 * unresolved, so pending_winners is not decremented here.
		 */
		frrtrace(6, frr_zebra, nhg_re_change, "tracker-winner-no-peer",
			 re->nhe ? re->nhe->id : 0, 0, re->status, re->nhe ? re->nhe->flags : 0, 0);
	}

	/*
	 * Ref or create an nhe that matches the current state of the
	 * nexthop(s).
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_CHANGED)) {
		struct nhg_hash_entry *new_nhe = NULL;

		new_nhe = zebra_nhg_rib_find_nhe(curr_nhe, rt_afi);

		remove = new_nhe;

		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: re %p (%pRN) CHANGED status 0x%x tracker_winner %d: old nhe %u (%pNG) flags 0x%x => new_nhe %u (%pNG) flags 0x%x refcnt %d, parent_nhe %u (flags 0x%x)",
				   __func__, re, rn, re->status, is_tracker_winner ? 1 : 0,
				   re->nhe ? re->nhe->id : 0, re->nhe,
				   re->nhe ? re->nhe->flags : 0, new_nhe ? new_nhe->id : 0,
				   new_nhe, new_nhe ? new_nhe->flags : 0,
				   new_nhe ? new_nhe->refcnt : 0, parent_nhe ? parent_nhe->id : 0,
				   parent_nhe ? parent_nhe->flags : 0);

		frrtrace(6, frr_zebra, nhg_re_change, "re-changed", re->nhe ? re->nhe->id : 0,
			 new_nhe ? new_nhe->id : 0, re->status, re->nhe ? re->nhe->flags : 0,
			 new_nhe ? new_nhe->flags : 0);

		/*
		 * if the results from zebra_nhg_rib_find_nhe is being
		 * dropped and it was generated in that function
		 * (refcnt of 0) then we know we can clean it up
		 */
		if (remove && remove != new_nhe && remove != re->nhe && remove->refcnt == 0)
			zebra_nhg_handle_uninstall(remove);

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

				frrtrace(1, frr_zebra, zebra_nhg_nhe2grp_internal_failure,
					 depend->id);
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

				frrtrace(1, frr_zebra, zebra_nhg_nhe2grp_internal_failure,
					 depend->id);
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
					zlog_debug("%s: Nexthop ID (%u) unable to find nexthop in Nexthop Group Entry, something is terribly wrong",
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

	/* Resolve it first */
	nhe = zebra_nhg_resolve(nhe);

	if (zebra_nhg_set_valid_if_active(nhe)) {
		if (IS_ZEBRA_DEBUG_NHG_DETAIL)
			zlog_debug("%s: valid flag set for nh %pNG flags (0x%x)", __func__, nhe,
				   nhe->flags);
	}

	if ((type != ZEBRA_ROUTE_CONNECT && type != ZEBRA_ROUTE_LOCAL &&
	     type != ZEBRA_ROUTE_KERNEL) &&
	    CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL)) {
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL);
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED);
		UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
	}

	/* Make sure all depends are installed/queued */
	frr_each(nhg_connected_tree, &nhe->nhg_depends, rb_node_dep) {
		zebra_nhg_install_kernel(rb_node_dep->nhe, type);
	}

	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_VALID) &&
	    (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) ||
	     CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_REINSTALL)) &&
	    !CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		/* Change its type to us since we are installing it */
		if (!ZEBRA_NHG_CREATED(nhe)) {
			nhe->type = ZEBRA_ROUTE_NHG;
			frrtrace(2, frr_zebra, zebra_nhg_install_kernel, nhe, 1);
		} else
			frrtrace(2, frr_zebra, zebra_nhg_install_kernel, nhe, 2);

		enum zebra_dplane_result ret = dplane_nexthop_add(nhe);

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
			flog_err(EC_ZEBRA_DP_INVALID_RC,
				 "DPlane returned an invalid result code for attempt of installation of %pNG into the kernel",
				 nhe);
			break;
		}
	}
}

void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe)
{
	/*
	 * Clearly if the nexthop group is installed we should
	 * remove it.  Additionally If the nexthop is already
	 * QUEUED for installation, we should also just send
	 * a deletion down as well.  We cannot necessarily pluck
	 * the installation out of the queue ( since it may have
	 * already been acted on, but not processed yet in the
	 * main pthread ).
	 */
	if (CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED) ||
	    CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED)) {
		int ret = dplane_nexthop_delete(nhe);

		frrtrace(2, frr_zebra, zebra_nhg_uninstall_kernel, nhe, ret);
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

	frrtrace(3, frr_zebra, zebra_nhg_dplane_result, op, id, status);

	if (op == DPLANE_OP_NH_DELETE) {
		if (status != ZEBRA_DPLANE_REQUEST_SUCCESS)
			flog_err(
				EC_ZEBRA_DP_DELETE_FAIL,
				"Failed to uninstall Nexthop ID (%u) from the kernel",
				id);

		/* We already free'd the data, nothing to do */
	} else if (op == DPLANE_OP_NH_INSTALL || op == DPLANE_OP_NH_UPDATE) {
		nhe = zebra_nhg_lookup_id(id);

		if (!nhe) {
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
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
			/*
			 * With a request failure it is unknown what we now know
			 * this is because Zebra has lost track of whether or not
			 * any previous versions of this NHG are in the kernel
			 * or even what those versions were.  So at this point
			 * we cannot unset the INSTALLED flag.
			 */
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
	bool *stale_sweep = (bool *)arg;

	nhe = (struct nhg_hash_entry *)bucket->data;

	/*
	 * We are in the zebra shutdown path and all the NHGs would have been
	 * cleaned up by now. Check if any NHG is still present in the hash and
	 * it has timer running. If yes, we need to uninstall it from kernel as
	 * it was meant to be uninstalled after the timer expires.
	 * This is required to avoid stale NHG in kernel as it is not being
	 * referenced by anyone.
	 */
	if (stale_sweep && *stale_sweep) {
		if (event_is_scheduled(nhe->timer)) {
			zebra_nhg_decrement_ref(nhe);
			return HASHWALK_ABORT;
		}
		return HASHWALK_CONTINUE;
	}

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
	 *
	 * zebra_nhg_decrement_ref may trigger KEEP_AROUND which keeps the entry
	 * in the hash (refcnt reset to 1, timer started) in that case the
	 * hash is unmodified and the walk can safely continue to process
	 * remaining proto-owned entries in the same pass.
	 */
	if (PROTO_OWNED(nhe) && nhe->refcnt == 1) {
		uint32_t id = nhe->id;

		zebra_nhg_decrement_ref(nhe);
		/* Entry still in hash (KEEP_AROUND) safe to continue.
		 * Entry freed hash may be modified, must abort.
		 */
		if (zebra_nhg_lookup_id(id))
			return HASHWALK_CONTINUE;
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

void zebra_nhg_sweep_table(struct hash *hash, bool stale_sweep)
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
		hash_walk(hash, zebra_nhg_sweep_entry, &stale_sweep);
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

/* Global control to make zebra-created multipath groups resilient. */
void zebra_nhg_set_resilience(uint16_t buckets, uint32_t idle_timer,
			      uint32_t unbalanced_timer)
{
	zrouter.nhg_resilience.buckets = buckets;
	zrouter.nhg_resilience.idle_timer = idle_timer;
	zrouter.nhg_resilience.unbalanced_timer = unbalanced_timer;
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

	if (!new) {
		if (IS_ZEBRA_DEBUG_NHG)
			zlog_debug("%s: zebra_nhg_rib_find_nhe failed for id %u", __func__, id);
		return NULL;
	}

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
			event_cancel(&old->timer);
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
		/*
		 * If this nhe has 'initial delay' flag set, we should not install this
		 * in kernel in case of any interface events. Zebra created this entry
		 * while processing the kernel/connected routes, just to pretend
		 * the successful kernel install of this NHG
		 */
		if (CHECK_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL))
			continue;
		/*
		 * The nexthop associated with this was set as !ACTIVE
		 * so we need to turn it back to active when we get to
		 * this point again
		 */
		SET_FLAG(rb_node_dep->nhe->nhg.nexthop->flags, NEXTHOP_FLAG_ACTIVE);
		nh = rb_node_dep->nhe->nhg.nexthop;

		if (zebra_nhg_set_valid_if_active(rb_node_dep->nhe)) {
			frrtrace(3, frr_zebra, zebra_interface_nhg_reinstall, ifp,
				 rb_node_dep->nhe, 1);
			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug("%s: Setting the valid flag for nhe %pNG flags (0x%x), interface: %s",
					   __func__, rb_node_dep->nhe, rb_node_dep->nhe->flags,
					   ifp->name);
		}

		/* Check for singleton NHG associated to interface */
		if (!nexthop_is_blackhole(nh) && ZEBRA_NHG_IS_SINGLETON(rb_node_dep->nhe)) {
			struct nhg_connected *rb_node_dependent;

			if (IS_ZEBRA_DEBUG_NHG_DETAIL)
				zlog_debug(
					"%s install nhe %pNG nh type %u flags 0x%x",
					__func__, rb_node_dep->nhe, nh->type,
					rb_node_dep->nhe->flags);

			/*
			 * If this singleton has an active tracker, defer
			 * kernel install to the tracker's flush path.
			 * Set REINSTALL so install_kernel will re-queue it
			 * when the tracker completes.
			 */
			if (nhg_event_tracker_list_count(&rb_node_dep->nhe->tracker_list) > 0)
				SET_FLAG(rb_node_dep->nhe->flags, NEXTHOP_GROUP_REINSTALL);
			else
				zebra_nhg_install_kernel(rb_node_dep->nhe, ZEBRA_ROUTE_MAX);

			/* Don't need to modify dependents if installed */
			if (CHECK_FLAG(rb_node_dep->nhe->flags,
				       NEXTHOP_GROUP_INSTALLED))
				goto create_tracker;

			/* mark dependent uninstalled; when interface associated
			 * singleton is installed, install dependent
			 */
			frr_each_safe (nhg_connected_tree,
				       &rb_node_dep->nhe->nhg_dependents,
				       rb_node_dependent) {
				struct nexthop *nhop_dependent =
					rb_node_dependent->nhe->nhg.nexthop;

				while (nhop_dependent && !nexthop_same_no_weight(nhop_dependent, nh))
					nhop_dependent = nhop_dependent->next;

				if (nhop_dependent) {
					SET_FLAG(nhop_dependent->flags,
						 NEXTHOP_FLAG_ACTIVE);
				}

				if (IS_ZEBRA_DEBUG_NHG_DETAIL)
					zlog_debug("%s dependent nhe (%pNG) flags (0x%x) Setting Reinstall flag",
						   __func__, rb_node_dependent->nhe,
						   rb_node_dependent->nhe->flags);

				SET_FLAG(rb_node_dependent->nhe->flags,
					 NEXTHOP_GROUP_REINSTALL);
				frrtrace(3, frr_zebra, zebra_interface_nhg_reinstall, ifp,
					 rb_node_dependent->nhe, 2);
			}
		}

create_tracker:
		/*
		 * Create tracker now - all the parent NHGs are updated with the valid state.
		 * Walk transitive dependents - catches recursively-dependent NHGs and
		 * creates trackers wherever required.
		 */
		zebra_nhg_tracker_create_for_event(rb_node_dep->nhe, ifp->ifindex,
						   NHG_TRACKER_EVENT_INTF_UP);
	}
}

/* Format NHG flags into a comma-separated string for display */
void dump_nhg_flags(uint32_t flags, char *buf, size_t len)
{
	bool first = true;

	if (!buf || len == 0)
		return;

	buf[0] = '\0';

	if (CHECK_FLAG(flags, NEXTHOP_GROUP_VALID)) {
		strlcat(buf, "Valid", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_INSTALLED)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Installed", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_QUEUED)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Queued", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_RECURSIVE)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Recursive", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_REINSTALL)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Reinstall", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_BACKUP)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Backup", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_PROTO_RELEASED)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Proto Released", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_KEEP_AROUND)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Keep Around", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_FPM)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "FPM", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_INITIAL_DELAY_INSTALL)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Initial Delay", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_TRACKER_REUSE)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Tracker NHG Reuse", len);
		first = false;
	}
	if (CHECK_FLAG(flags, NEXTHOP_GROUP_DUPLICATE)) {
		if (!first)
			strlcat(buf, ", ", len);
		strlcat(buf, "Duplicate", len);
	}
}
