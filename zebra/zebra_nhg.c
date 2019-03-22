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

DEFINE_MTYPE_STATIC(ZEBRA, NHG, "Nexthop Group Entry");
DEFINE_MTYPE_STATIC(ZEBRA, NHG_DEPENDS, "Nexthop Group Entry Depends");

/**
 * nhg_depend_add() - Add a new dependency to the nhg_hash_entry
 *
 * @nhg_depend:	List we are adding the dependency to
 * @depends:		Dependency we are adding
 *
 * Return:		Newly created nhg_depend
 */
struct nhg_depend *nhg_depend_add(struct list *nhg_depends,
				  struct nhg_hash_entry *depend)
{
	struct nhg_depend *nhg_dp = NULL;

	nhg_dp = nhg_depend_new();
	nhg_dp->nhe = depend;

	listnode_add(nhg_depends, nhg_dp);
	return nhg_dp;
}

/**
 * nhg_depend_new() - Allocate a new nhg_depend struct
 *
 * Return:	Allocated nhg_depend struct
 */
struct nhg_depend *nhg_depend_new(void)
{
	return XCALLOC(MTYPE_NHG_DEPENDS, sizeof(struct nhg_depend));
}

/**
 * nhg_depend_free() - Free the nhg_depend struct
 */
void nhg_depend_free(struct nhg_depend *depends)
{
	XFREE(MTYPE_NHG_DEPENDS, depends);
}

/**
 * nhg_depend_new_list() - Allocate a new list for nhg_depends
 *
 * Return:	Allocated nhg_depend list
 */
struct list *nhg_depend_new_list()
{
	struct list *nhg_depends = NULL;

	nhg_depends = list_new();
	nhg_depends->del = (void (*)(void *))nhg_depend_free;

	return nhg_depends;
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
	struct nhg_hash_entry lookup = {0};

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
	/* lock for getiing and setting the id */
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	/* id counter to keep in sync with kernel */
	static uint32_t id_counter = 0;
	struct nhg_hash_entry *nhe;
	struct nhg_hash_entry *copy = arg;

	nhe = XCALLOC(MTYPE_NHG, sizeof(struct nhg_hash_entry));

	pthread_mutex_lock(&lock); /* Lock, set the id counter from kernel */
	if (copy->id) {
		/* This is from the kernel if it has an id */
		if (copy->id > id_counter) {
			/* Increase our counter so we don't try to create
			 * an ID that already exists
			 */
			id_counter = copy->id;
		}
		nhe->id = copy->id;
	} else {
		nhe->id = ++id_counter;
	}
	pthread_mutex_unlock(&lock);

	nhe->nhg_depends = NULL;
	nhe->nhg.nexthop = NULL;

	if (copy->nhg_depends) {
		nhe->nhg_depends = copy->nhg_depends;
		/* These have already been allocated when
		 * building the dependency list
		 */
		nhe->nhg = copy->nhg;
	} else {
		nexthop_group_copy(&nhe->nhg, &copy->nhg);
	}

	nhe->vrf_id = copy->vrf_id;
	nhe->afi = copy->afi;
	nhe->refcnt = 0;
	nhe->is_kernel_nh = false;
	nhe->dplane_ref = zebra_router_get_next_sequence();
	nhe->ifp = NULL;


	/* Add to id table as well */
	zebra_nhg_insert_id(nhe);


	return nhe;
}

static uint32_t zebra_nhg_hash_key_nexthop_group(struct nexthop_group *nhg)
{
	struct nexthop *nh;
	uint32_t i;
	uint32_t key = 0;

	/*
	 * We are not interested in hashing over any recursively
	 * resolved nexthops
	 */
	for (nh = nhg->nexthop; nh; nh = nh->next) {
		key = jhash_1word(nh->type, key);
		key = jhash_2words(nh->vrf_id, nh->nh_label_type, key);
		/* gate and blackhole are together in a union */
		key = jhash(&nh->gate, sizeof(nh->gate), key);
		key = jhash(&nh->src, sizeof(nh->src), key);
		key = jhash(&nh->rmap_src, sizeof(nh->rmap_src), key);
		if (nh->nh_label) {
			for (i = 0; i < nh->nh_label->num_labels; i++)
				key = jhash_1word(nh->nh_label->label[i], key);
		}
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		case NEXTHOP_TYPE_IFINDEX:
			key = jhash_1word(nh->ifindex, key);
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV6:
			break;
		}
	}
	return key;
}

uint32_t zebra_nhg_hash_key(const void *arg)
{
	const struct nhg_hash_entry *nhe = arg;

	int key = 0x5a351234;

	key = jhash_2words(nhe->vrf_id, nhe->afi, key);

	key = jhash_1word(zebra_nhg_hash_key_nexthop_group(&nhe->nhg), key);

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
	struct nexthop *nh1, *nh2;
	uint32_t nh_count = 0;

	if (nhe1->vrf_id != nhe2->vrf_id)
		return false;

	if (nhe1->afi != nhe2->afi)
		return false;

	/*
	 * Again we are not interested in looking at any recursively
	 * resolved nexthops.  Top level only
	 */
	for (nh1 = nhe1->nhg.nexthop; nh1; nh1 = nh1->next) {
		uint32_t inner_nh_count = 0;
		for (nh2 = nhe2->nhg.nexthop; nh2; nh2 = nh2->next) {
			if (inner_nh_count == nh_count) {
				break;
			}
			inner_nh_count++;
		}

		if (!nexthop_same(nh1, nh2))
			return false;

		nh_count++;
	}

	return true;
}

bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2)
{
	const struct nhg_hash_entry *nhe1 = arg1;
	const struct nhg_hash_entry *nhe2 = arg2;

	return nhe1->id == nhe2->id;
}

/**
 * zebra_nhg_find() - Find the zebra nhg in our table, or create it
 *
 * @nhg:	Nexthop group we lookup with
 * @vrf_id:	VRF id
 * @afi:	Address Family type
 * @id:		ID we lookup with, 0 means its from us and we need to give it
 * 		an ID, otherwise its from the kernel as we use the ID it gave
 * 		us.
 * @dep_info:	Array of nexthop dependency info (ID/weight)
 * @dep_count:	Count for the number of nexthop dependencies
 *
 * Return:	Hash entry found or created
 *
 * The nhg and n_grp are fundementally the same thing (a group of nexthops).
 * We are just using the nhg representation with routes and the n_grp
 * is what the kernel gives us (a list of IDs). Our nhg_hash_entry
 * will contain both.
 *
 * nhg_hash_entry example:
 *
 * 	nhe:
 * 		->nhg:
 * 			.nexthop->nexthop->nexthop
 * 		->nhg_depends:
 * 			.nhe->nhe->nhe
 *
 * Routes will use the nhg directly, and any updating of nexthops
 * we have to do or flag setting, we use the nhg_depends.
 *
 */
struct nhg_hash_entry *zebra_nhg_find(struct nexthop_group *nhg,
				      vrf_id_t vrf_id, afi_t afi, uint32_t id,
				      struct list *nhg_depends, int dep_count)
{
	struct nhg_hash_entry lookup = {0};
	struct nhg_hash_entry *nhe = NULL;

	lookup.id = id;
	lookup.vrf_id = vrf_id;
	lookup.afi = afi;
	lookup.nhg = nhg;
	lookup.nhg_depends = nhg_depends;

	if (id)
		nhe = zebra_nhg_lookup_id(id);
	else
		nhe = hash_lookup(zrouter.nhgs, &lookup);

	if (!nhe) {
		nhe = hash_get(zrouter.nhgs, &lookup, zebra_nhg_alloc);
	} else {
		zebra_nhg_free_group_depends(nhg, nhg_depends);
	}

	return nhe;
}

/**
 * zebra_nhg_free_group_depends() - Helper function for freeing nexthop_group
 * 				    struct and depends
 *
 * @nhg:		Nexthop group
 * @nhg_depends:	Nexthop group hash entry dependency list
 */
void zebra_nhg_free_group_depends(struct nexthop_group *nhg,
				  struct list *nhg_depends)
{
	if (nhg_depends)
		list_delete(&nhg_depends);
	if (nhg) {
		if (nhg->nexthop)
			nexthops_free(nhg->nexthop);
		nexthop_group_delete(&nhg);
	}
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
	zebra_nhg_free_group_depends(nhe->nhg, nhe->nhg_depends);
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

	if (nhe->nhg_depends)
		list_delete(&nhe->nhg_depends);

	nexthops_free(nhe->nhg.nexthop);

	XFREE(MTYPE_NHG, nhe);
}

/**
 * zebra_nhg_release() - Release a nhe from the tables
 *
 * @nhe:	Nexthop group hash entry
 */
void zebra_nhg_release(struct nhg_hash_entry *nhe)
{
	if (nhe->refcnt)
		flog_err(
			EC_ZEBRA_NHG_SYNC,
			"Releasing a nexthop group with ID (%u) that we are still using for a route",
			nhe->id);

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

	if (!nhe->is_kernel_nh && nhe->refcnt <= 0) {
		zebra_nhg_uninstall_kernel(nhe);
	}

	// re->ng = NULL;
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

	return curr_active;
}

/**
 * zebra_nhg_install_kernel() - Install Nexthop Group hash entry into kernel
 *
 * @nhe:	Nexthop Group hash entry to install
 */
void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe)
{
	if (!CHECK_FLAG(nhe->flags, NEXTHOP_GROUP_INSTALLED)) {
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
			break;
		}
	}
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

	id = dplane_ctx_get_nhe(ctx)->id;
	nhe = zebra_nhg_lookup_id(id);

	if (nhe) {
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
			UNSET_FLAG(nhe->flags, NEXTHOP_GROUP_QUEUED);
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
		dplane_ctx_fini(&ctx);

	} else {
		flog_err(
			EC_ZEBRA_NHG_SYNC,
			"%s operation preformed on Nexthop ID (%u) in the kernel, that we no longer have in our table",
			dplane_op2str(op), id);
	}
}

