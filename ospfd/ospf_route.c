// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF routing table.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "linklist.h"
#include "log.h"
#include "if.h"
#include "command.h"
#include "sockunion.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"

const char *ospf_path_type_name(int path_type)
{
	switch (path_type) {
	case OSPF_PATH_INTRA_AREA:
		return "Intra-Area";
	case OSPF_PATH_INTER_AREA:
		return "Inter-Area";
	case OSPF_PATH_TYPE1_EXTERNAL:
		return "External-1";
	case OSPF_PATH_TYPE2_EXTERNAL:
		return "External-2";
	default:
		return "Unknown";
	}
}

struct ospf_route *ospf_route_new(void)
{
	struct ospf_route *new;

	new = XCALLOC(MTYPE_OSPF_ROUTE, sizeof(struct ospf_route));

	new->paths = list_new();
	new->paths->del = (void (*)(void *))ospf_path_free;

	return new;
}

void ospf_route_free(struct ospf_route *or)
{
	if (or->paths)
		list_delete(& or->paths);

	XFREE(MTYPE_OSPF_ROUTE, or);
}

struct ospf_path *ospf_path_new(void)
{
	struct ospf_path *new;

	new = XCALLOC(MTYPE_OSPF_PATH, sizeof(struct ospf_path));

	return new;
}

static struct ospf_path *ospf_path_dup(struct ospf_path *path)
{
	struct ospf_path *new;
	int memsize;

	new = ospf_path_new();
	memcpy(new, path, sizeof(struct ospf_path));

	/* optional TI-LFA backup paths */
	if (path->srni.backup_label_stack) {
		memsize = sizeof(struct mpls_label_stack)
			  + (sizeof(mpls_label_t)
			     * path->srni.backup_label_stack->num_labels);
		new->srni.backup_label_stack =
			XCALLOC(MTYPE_OSPF_PATH, memsize);
		memcpy(new->srni.backup_label_stack,
		       path->srni.backup_label_stack, memsize);
	}

	return new;
}

void ospf_path_free(struct ospf_path *op)
{
	/* optional TI-LFA backup paths */
	if (op->srni.backup_label_stack)
		XFREE(MTYPE_OSPF_PATH, op->srni.backup_label_stack);

	XFREE(MTYPE_OSPF_PATH, op);
}

void ospf_route_delete(struct ospf *ospf, struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;

	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL) {
			if (or->type == OSPF_DESTINATION_NETWORK)
				ospf_zebra_delete(
					ospf, (struct prefix_ipv4 *)&rn->p, or);
			else if (or->type == OSPF_DESTINATION_DISCARD)
				ospf_zebra_delete_discard(
					ospf, (struct prefix_ipv4 *)&rn->p);
		}
}

void ospf_route_table_free(struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;

	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL) {
			ospf_route_free(or);

			rn->info = NULL;
			route_unlock_node(rn);
		}

	route_table_finish(rt);
}

/* If a prefix exists in the new routing table, then return 1,
   otherwise return 0. Since the ZEBRA-RIB does an implicit
   withdraw, it is not necessary to send a delete, an add later
   will act like an implicit delete. */
static int ospf_route_exist_new_table(struct route_table *rt,
				      struct prefix_ipv4 *prefix)
{
	struct route_node *rn;

	assert(rt);
	assert(prefix);

	rn = route_node_lookup(rt, (struct prefix *)prefix);
	if (!rn) {
		return 0;
	}
	route_unlock_node(rn);

	if (!rn->info) {
		return 0;
	}

	return 1;
}

static int ospf_route_backup_path_same(struct sr_nexthop_info *srni1,
				       struct sr_nexthop_info *srni2)
{
	struct mpls_label_stack *ls1, *ls2;
	uint8_t label_count;

	ls1 = srni1->backup_label_stack;
	ls2 = srni2->backup_label_stack;

	if (!ls1 && !ls2)
		return 1;

	if ((ls1 && !ls2) || (!ls1 && ls2))
		return 0;

	if (ls1->num_labels != ls2->num_labels)
		return 0;

	for (label_count = 0; label_count < ls1->num_labels; label_count++) {
		if (ls1->label[label_count] != ls2->label[label_count])
			return 0;
	}

	if (!IPV4_ADDR_SAME(&srni1->backup_nexthop, &srni2->backup_nexthop))
		return 0;

	return 1;
}

/* If a prefix and a nexthop match any route in the routing table,
   then return 1, otherwise return 0. */
int ospf_route_match_same(struct route_table *rt, struct prefix_ipv4 *prefix,
			  struct ospf_route *newor)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct ospf_path *op;
	struct ospf_path *newop;
	struct listnode *n1;
	struct listnode *n2;

	if (!rt || !prefix)
		return 0;

	rn = route_node_lookup(rt, (struct prefix *)prefix);
	if (!rn || !rn->info)
		return 0;

	route_unlock_node(rn);

	or = rn->info;
	if (or->type == newor->type && or->cost == newor->cost) {
		if (or->changed)
			return 0;

		if (or->type == OSPF_DESTINATION_NETWORK) {
			if (or->paths->count != newor->paths->count)
				return 0;

			/* Check each path. */
			for (n1 = listhead(or->paths),
			    n2 = listhead(newor->paths);
			     n1 && n2; n1 = listnextnode_unchecked(n1),
			    n2 = listnextnode_unchecked(n2)) {
				op = listgetdata(n1);
				newop = listgetdata(n2);

				if (!IPV4_ADDR_SAME(&op->nexthop,
						    &newop->nexthop))
					return 0;
				if (op->ifindex != newop->ifindex)
					return 0;

				/* check TI-LFA backup paths */
				if (!ospf_route_backup_path_same(&op->srni,
								 &newop->srni))
					return 0;
			}
			return 1;
		} else if (prefix_same(&rn->p, (struct prefix *)prefix))
			return 1;
	}
	return 0;
}

/* delete routes generated from AS-External routes if there is a inter/intra
 * area route
 */
static void ospf_route_delete_same_ext(struct ospf *ospf,
				       struct route_table *external_routes,
				       struct route_table *routes)
{
	struct route_node *rn, *ext_rn;

	if ((external_routes == NULL) || (routes == NULL))
		return;

	/* Remove deleted routes */
	for (rn = route_top(routes); rn; rn = route_next(rn)) {
		if (rn && rn->info) {
			struct prefix_ipv4 *p = (struct prefix_ipv4 *)(&rn->p);
			if ((ext_rn = route_node_lookup(external_routes,
							(struct prefix *)p))) {
				if (ext_rn->info) {
					ospf_zebra_delete(ospf, p,
							  ext_rn->info);
					ospf_route_free(ext_rn->info);
					ext_rn->info = NULL;
				}
				route_unlock_node(ext_rn);
			}
		}
	}
}

/* rt: Old, cmprt: New */
static void ospf_route_delete_uniq(struct ospf *ospf, struct route_table *rt,
				   struct route_table *cmprt)
{
	struct route_node *rn;
	struct ospf_route * or ;

	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL)
			if (or->path_type == OSPF_PATH_INTRA_AREA ||
			    or->path_type == OSPF_PATH_INTER_AREA) {
				if (or->type == OSPF_DESTINATION_NETWORK) {
					if (!ospf_route_exist_new_table(
						    cmprt,
						    (struct prefix_ipv4 *)&rn
							    ->p))
						ospf_zebra_delete(
							ospf,
							(struct prefix_ipv4
								 *)&rn->p,
							or);
				} else if (or->type == OSPF_DESTINATION_DISCARD)
					if (!ospf_route_exist_new_table(
						    cmprt,
						    (struct prefix_ipv4 *)&rn
							    ->p))
						ospf_zebra_delete_discard(
							ospf,
							(struct prefix_ipv4
								 *)&rn->p);
			}
}

/* Install routes to table. */
void ospf_route_install(struct ospf *ospf, struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;

	/* rt contains new routing table, new_table contains an old one.
	   updating pointers */
	if (ospf->old_table)
		ospf_route_table_free(ospf->old_table);

	ospf->old_table = ospf->new_table;
	ospf->new_table = rt;

	/* Delete old routes. */
	if (ospf->old_table)
		ospf_route_delete_uniq(ospf, ospf->old_table, rt);
	if (ospf->old_external_route)
		ospf_route_delete_same_ext(ospf, ospf->old_external_route, rt);

	/* Install new routes. */
	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL) {
			if (or->type == OSPF_DESTINATION_NETWORK) {
				if (!ospf_route_match_same(
					    ospf->old_table,
					    (struct prefix_ipv4 *)&rn->p, or))
					ospf_zebra_add(
						ospf,
						(struct prefix_ipv4 *)&rn->p,
						or);
			} else if (or->type == OSPF_DESTINATION_DISCARD)
				if (!ospf_route_match_same(
					    ospf->old_table,
					    (struct prefix_ipv4 *)&rn->p, or))
					ospf_zebra_add_discard(
						ospf,
						(struct prefix_ipv4 *)&rn->p);
		}
}

/* RFC2328 16.1. (4). For "router". */
void ospf_intra_add_router(struct route_table *rt, struct vertex *v,
			   struct ospf_area *area, bool add_only)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct prefix_ipv4 p;
	struct router_lsa *lsa;

	if (IS_DEBUG_OSPF_EVENT) {
		if (!add_only)
			zlog_debug("%s: Start", __func__);
		else
			zlog_debug("%s: REACHRUN: Start", __func__);
	}
	lsa = (struct router_lsa *)v->lsa;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: LS ID: %pI4", __func__, &lsa->header.id);

	if (!add_only) {
		if (!OSPF_IS_AREA_BACKBONE(area))
			ospf_vl_up_check(area, lsa->header.id, v);

		if (!CHECK_FLAG(lsa->flags, ROUTER_LSA_SHORTCUT))
			area->shortcut_capability = 0;

		/* If the newly added vertex is an area border router or AS
		   boundary router, a routing table entry is added whose
		   destination type is "router". */
		if (!IS_ROUTER_LSA_BORDER(lsa) &&
		    !IS_ROUTER_LSA_EXTERNAL(lsa)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: this router is neither ASBR nor ABR, skipping it",
					__func__);
			return;
		}

		/* Update ABR and ASBR count in this area. */
		if (IS_ROUTER_LSA_BORDER(lsa))
			area->abr_count++;
		if (IS_ROUTER_LSA_EXTERNAL(lsa))
			area->asbr_count++;
	}

	/* The Options field found in the associated router-LSA is copied
	   into the routing table entry's Optional capabilities field. Call
	   the newly added vertex Router X. */
	or = ospf_route_new();

	or->id = v->id;
	or->u.std.area_id = area->area_id;
	or->u.std.external_routing = area->external_routing;
	or->path_type = OSPF_PATH_INTRA_AREA;
	or->cost = v->distance;
	or->type = OSPF_DESTINATION_ROUTER;
	or->u.std.origin = (struct lsa_header *)lsa;
	or->u.std.options = lsa->header.options;
	or->u.std.flags = lsa->flags;

	/* If Router X is the endpoint of one of the calculating router's
	   virtual links, and the virtual link uses Area A as Transit area:
	   the virtual link is declared up, the IP address of the virtual
	   interface is set to the IP address of the outgoing interface
	   calculated above for Router X, and the virtual neighbor's IP
	   address is set to Router X's interface address (contained in
	   Router X's router-LSA) that points back to the root of the
	   shortest- path tree; equivalently, this is the interface that
	   points back to Router X's parent vertex on the shortest-path tree
	   (similar to the calculation in Section 16.1.1). */

	p.family = AF_INET;
	p.prefix = v->id;
	p.prefixlen = IPV4_MAX_BITLEN;
	apply_mask_ipv4(&p);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: talking about %pFX", __func__, &p);

	rn = route_node_get(rt, (struct prefix *)&p);

	/* Note that we keep all routes to ABRs and ASBRs, not only the best */
	if (rn->info == NULL)
		rn->info = list_new();
	else
		route_unlock_node(rn);

	ospf_route_copy_nexthops_from_vertex(area, or, v);

	listnode_add(rn->info, or);

	if (IS_DEBUG_OSPF_EVENT) {
		if (!add_only)
			zlog_debug("%s: Stop", __func__);
		else
			zlog_debug("%s: REACHRUN: Stop", __func__);
	}
}

/* RFC2328 16.1. (4).  For transit network. */
void ospf_intra_add_transit(struct route_table *rt, struct vertex *v,
			    struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct prefix_ipv4 p;
	struct network_lsa *lsa;

	lsa = (struct network_lsa *)v->lsa;

	/* If the newly added vertex is a transit network, the routing table
	   entry for the network is located.  The entry's Destination ID is
	   the IP network number, which can be obtained by masking the
	   Vertex ID (Link State ID) with its associated subnet mask (found
	   in the body of the associated network-LSA). */
	p.family = AF_INET;
	p.prefix = v->id;
	p.prefixlen = ip_masklen(lsa->mask);
	apply_mask_ipv4(&p);

	rn = route_node_get(rt, (struct prefix *)&p);

	/* If the routing table entry already exists (i.e., there is already
	   an intra-area route to the destination installed in the routing
	   table), multiple vertices have mapped to the same IP network.
	   For example, this can occur when a new Designated Router is being
	   established.  In this case, the current routing table entry
	   should be overwritten if and only if the newly found path is just
	   as short and the current routing table entry's Link State Origin
	   has a smaller Link State ID than the newly added vertex' LSA. */
	if (rn->info) {
		struct ospf_route *cur_or;

		route_unlock_node(rn);
		cur_or = rn->info;

		if (v->distance > cur_or->cost
		    || IPV4_ADDR_CMP(&cur_or->u.std.origin->id, &lsa->header.id)
			       > 0)
			return;

		ospf_route_free(rn->info);
	}

	or = ospf_route_new();

	or->id = v->id;
	or->u.std.area_id = area->area_id;
	or->u.std.external_routing = area->external_routing;
	or->path_type = OSPF_PATH_INTRA_AREA;
	or->cost = v->distance;
	or->type = OSPF_DESTINATION_NETWORK;
	or->u.std.origin = (struct lsa_header *)lsa;

	ospf_route_copy_nexthops_from_vertex(area, or, v);

	rn->info = or ;
}

/* RFC2328 16.1. second stage. */
void ospf_intra_add_stub(struct route_table *rt, struct router_lsa_link *link,
			 struct vertex *v, struct ospf_area *area,
			 int parent_is_root, int lsa_pos)
{
	uint32_t cost;
	struct route_node *rn;
	struct ospf_route * or ;
	struct prefix_ipv4 p;
	struct router_lsa *lsa;
	struct ospf_interface *oi = NULL;
	struct ospf_path *path;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Start", __func__);

	lsa = (struct router_lsa *)v->lsa;

	p.family = AF_INET;
	p.prefix = link->link_id;
	p.prefixlen = ip_masklen(link->link_data);
	apply_mask_ipv4(&p);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: processing route to %pFX", __func__, &p);

	/* (1) Calculate the distance D of stub network from the root.  D is
	   equal to the distance from the root to the router vertex
	   (calculated in stage 1), plus the stub network link's advertised
	   cost. */
	cost = v->distance + ntohs(link->m[0].metric);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: calculated cost is %d + %d = %d", __func__,
			   v->distance, ntohs(link->m[0].metric), cost);

	/* PtP links with /32 masks adds host routes to remote, directly
	 * connected hosts, see RFC 2328, 12.4.1.1, Option 1.
	 * Such routes can just be ignored for the sake of tidyness.
	 */
	if (parent_is_root && link->link_data.s_addr == 0xffffffff
	    && ospf_if_lookup_by_local_addr(area->ospf, NULL, link->link_id)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: ignoring host route %pI4/32 to self.",
				   __func__, &link->link_id);
		return;
	}

	rn = route_node_get(rt, (struct prefix *)&p);

	/* Lookup current routing table. */
	if (rn->info) {
		struct ospf_route *cur_or;

		route_unlock_node(rn);

		cur_or = rn->info;

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: another route to the same prefix found with cost %u",
				__func__, cur_or->cost);

		/* Compare this distance to the current best cost to the stub
		   network.  This is done by looking up the stub network's
		   current routing table entry.  If the calculated distance D is
		   larger, go on to examine the next stub network link in the
		   LSA. */
		if (cost > cur_or->cost) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: old route is better, exit",
					   __func__);
			return;
		}

		/* (2) If this step is reached, the stub network's routing table
		   entry must be updated.  Calculate the set of next hops that
		   would result from using the stub network link.  This
		   calculation is shown in Section 16.1.1; input to this
		   calculation is the destination (the stub network) and the
		   parent vertex (the router vertex). If the distance D is the
		   same as the current routing table cost, simply add this set
		   of next hops to the routing table entry's list of next hops.
		   In this case, the routing table already has a Link State
		   Origin.  If this Link State Origin is a router-LSA whose Link
		   State ID is smaller than V's Router ID, reset the Link State
		   Origin to V's router-LSA. */

		if (cost == cur_or->cost) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: routes are equal, merge",
					   __func__);

			ospf_route_copy_nexthops_from_vertex(area, cur_or, v);

			if (IPV4_ADDR_CMP(&cur_or->u.std.origin->id,
					  &lsa->header.id)
			    < 0)
				cur_or->u.std.origin = (struct lsa_header *)lsa;
			return;
		}

		/* Otherwise D is smaller than the routing table cost.
		   Overwrite the current routing table entry by setting the
		   routing table entry's cost to D, and by setting the entry's
		   list of next hops to the newly calculated set.  Set the
		   routing table entry's Link State Origin to V's router-LSA.
		   Then go on to examine the next stub network link. */

		if (cost < cur_or->cost) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: new route is better, set it",
					   __func__);

			cur_or->cost = cost;

			list_delete_all_node(cur_or->paths);

			ospf_route_copy_nexthops_from_vertex(area, cur_or, v);

			cur_or->u.std.origin = (struct lsa_header *)lsa;
			return;
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: installing new route", __func__);

	or = ospf_route_new();

	or->id = v->id;
	or->u.std.area_id = area->area_id;
	or->u.std.external_routing = area->external_routing;
	or->path_type = OSPF_PATH_INTRA_AREA;
	or->cost = cost;
	or->type = OSPF_DESTINATION_NETWORK;
	or->u.std.origin = (struct lsa_header *)lsa;

	/* Nexthop is depend on connection type. */
	if (v != area->spf) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: this network is on remote router",
				   __func__);
		ospf_route_copy_nexthops_from_vertex(area, or, v);
	} else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: this network is on this router",
				   __func__);

		/*
		 * Only deal with interface data when we
		 * don't do a dry run
		 */
		if (!area->spf_dry_run)
			oi = ospf_if_lookup_by_lsa_pos(area, lsa_pos);

		if (oi || area->spf_dry_run) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: the lsa pos is %d", __func__,
					   lsa_pos);

			path = ospf_path_new();
			path->nexthop.s_addr = INADDR_ANY;

			if (oi) {
				path->ifindex = oi->ifp->ifindex;
				if (CHECK_FLAG(oi->connected->flags,
					       ZEBRA_IFA_UNNUMBERED))
					path->unnumbered = 1;
			}

			listnode_add(or->paths, path);
		} else {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: where's the interface ?",
					   __func__);
		}
	}

	rn->info = or ;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
}

static const char *const ospf_path_type_str[] = {
	"unknown-type", "intra-area", "inter-area", "type1-external",
	"type2-external"
};

void ospf_route_table_dump(struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct listnode *pnode;
	struct ospf_path *path;

	zlog_debug("========== OSPF routing table ==========");
	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL) {
			if (or->type == OSPF_DESTINATION_NETWORK) {
				zlog_debug("N %-18pFX %-15pI4 %s %d", &rn->p,
					   &or->u.std.area_id,
					   ospf_path_type_str[or->path_type],
					   or->cost);
				for (ALL_LIST_ELEMENTS_RO(or->paths, pnode,
							  path))
					zlog_debug("  -> %pI4",
						   &path->nexthop);
			} else
				zlog_debug("R %-18pI4 %-15pI4 %s %d",
					   &rn->p.u.prefix4,
					   &or->u.std.area_id,
					   ospf_path_type_str[or->path_type],
					   or->cost);
		}
	zlog_debug("========================================");
}

void ospf_router_route_table_dump(struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route *or;
	struct listnode *node;

	zlog_debug("========== OSPF routing table ==========");
	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node, or)) {
			assert(or->type == OSPF_DESTINATION_ROUTER);
			zlog_debug("R %-18pI4 %-15pI4 %s %d", &rn->p.u.prefix4,
				   &or->u.std.area_id,
				   ospf_path_type_str[or->path_type], or->cost);
		}
	}
	zlog_debug("========================================");
}

/* This is 16.4.1 implementation.
   o Intra-area paths using non-backbone areas are always the most preferred.
   o The other paths, intra-area backbone paths and inter-area paths,
     are of equal preference. */
static int ospf_asbr_route_cmp(struct ospf *ospf, struct ospf_route *r1,
			       struct ospf_route *r2)
{
	uint8_t r1_type, r2_type;

	r1_type = r1->path_type;
	r2_type = r2->path_type;

	/* r1/r2 itself is backbone, and it's Inter-area path. */
	if (OSPF_IS_AREA_ID_BACKBONE(r1->u.std.area_id))
		r1_type = OSPF_PATH_INTER_AREA;
	if (OSPF_IS_AREA_ID_BACKBONE(r2->u.std.area_id))
		r2_type = OSPF_PATH_INTER_AREA;

	return (r1_type - r2_type);
}

/* Compare two routes.
 ret <  0 -- r1 is better.
 ret == 0 -- r1 and r2 are the same.
 ret >  0 -- r2 is better. */
int ospf_route_cmp(struct ospf *ospf, struct ospf_route *r1,
		   struct ospf_route *r2)
{
	int ret = 0;

	/* Path types of r1 and r2 are not the same. */
	if ((ret = (r1->path_type - r2->path_type)))
		return ret;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Route[Compare]: Path types are the same.");
	/* Path types are the same, compare any cost. */
	switch (r1->path_type) {
	case OSPF_PATH_INTRA_AREA:
	case OSPF_PATH_INTER_AREA:
		break;
	case OSPF_PATH_TYPE1_EXTERNAL:
		if (!CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
			ret = ospf_asbr_route_cmp(ospf, r1->u.ext.asbr,
						  r2->u.ext.asbr);
			if (ret != 0)
				return ret;
		}
		break;
	case OSPF_PATH_TYPE2_EXTERNAL:
		if ((ret = (r1->u.ext.type2_cost - r2->u.ext.type2_cost)))
			return ret;

		if (!CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
			ret = ospf_asbr_route_cmp(ospf, r1->u.ext.asbr,
						  r2->u.ext.asbr);
			if (ret != 0)
				return ret;
		}
		break;
	}

	/* Anyway, compare the costs. */
	return (r1->cost - r2->cost);
}

static int ospf_path_exist(struct list *plist, struct in_addr nexthop,
			   struct ospf_interface *oi)
{
	struct listnode *node, *nnode;
	struct ospf_path *path;

	for (ALL_LIST_ELEMENTS(plist, node, nnode, path))
		if (IPV4_ADDR_SAME(&path->nexthop, &nexthop)
		    && path->ifindex == oi->ifp->ifindex)
			return 1;

	return 0;
}

void ospf_route_copy_nexthops_from_vertex(struct ospf_area *area,
					  struct ospf_route *to,
					  struct vertex *v)
{
	struct listnode *node;
	struct ospf_path *path;
	struct vertex_nexthop *nexthop;
	struct vertex_parent *vp;
	struct ospf_interface *oi = NULL;

	assert(to->paths);

	for (ALL_LIST_ELEMENTS_RO(v->parents, node, vp)) {
		nexthop = vp->nexthop;

		/*
		 * Only deal with interface data when we
		 * don't do a dry run
		 */
		if (!area->spf_dry_run)
			oi = ospf_if_lookup_by_lsa_pos(area, nexthop->lsa_pos);

		if ((oi && !ospf_path_exist(to->paths, nexthop->router, oi))
		    || area->spf_dry_run) {
			path = ospf_path_new();
			path->nexthop = nexthop->router;
			path->adv_router = v->id;

			if (oi) {
				path->ifindex = oi->ifp->ifindex;
				if (CHECK_FLAG(oi->connected->flags,
					       ZEBRA_IFA_UNNUMBERED))
					path->unnumbered = 1;
			}

			listnode_add(to->paths, path);
		}
	}
}

struct ospf_path *ospf_path_lookup(struct list *plist, struct ospf_path *path)
{
	struct listnode *node;
	struct ospf_path *op;

	for (ALL_LIST_ELEMENTS_RO(plist, node, op)) {
		if (!IPV4_ADDR_SAME(&op->nexthop, &path->nexthop))
			continue;
		if (!IPV4_ADDR_SAME(&op->adv_router, &path->adv_router))
			continue;
		if (op->ifindex != path->ifindex)
			continue;
		return op;
	}
	return NULL;
}

void ospf_route_copy_nexthops(struct ospf_route *to, struct list *from)
{
	struct listnode *node, *nnode;
	struct ospf_path *path;

	assert(to->paths);

	for (ALL_LIST_ELEMENTS(from, node, nnode, path))
		/* The same routes are just discarded. */
		if (!ospf_path_lookup(to->paths, path))
			listnode_add(to->paths, ospf_path_dup(path));
}

void ospf_route_subst_nexthops(struct ospf_route *to, struct list *from)
{

	list_delete_all_node(to->paths);
	ospf_route_copy_nexthops(to, from);
}

void ospf_route_subst(struct route_node *rn, struct ospf_route *new_or,
		      struct ospf_route *over)
{
	route_lock_node(rn);
	ospf_route_free(rn->info);

	ospf_route_copy_nexthops(new_or, over->paths);
	rn->info = new_or;
	route_unlock_node(rn);
}

void ospf_route_add(struct route_table *rt, struct prefix_ipv4 *p,
		    struct ospf_route *new_or, struct ospf_route *over)
{
	struct route_node *rn;

	rn = route_node_get(rt, (struct prefix *)p);

	ospf_route_copy_nexthops(new_or, over->paths);

	if (rn->info) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: something's wrong !", __func__);
		route_unlock_node(rn);
		return;
	}

	rn->info = new_or;
}

void ospf_prune_unreachable_networks(struct route_table *rt)
{
	struct route_node *rn, *next;
	struct ospf_route * or ;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Pruning unreachable networks");

	for (rn = route_top(rt); rn; rn = next) {
		next = route_next(rn);
		if (rn->info != NULL) {
			or = rn->info;
			if (listcount(or->paths) == 0) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug("Pruning route to %pFX",
						   &rn->p);

				ospf_route_free(or);
				rn->info = NULL;
				route_unlock_node(rn);
			}
		}
	}
}

void ospf_prune_unreachable_routers(struct route_table *rtrs)
{
	struct route_node *rn, *next;
	struct ospf_route * or ;
	struct listnode *node, *nnode;
	struct list *paths;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Pruning unreachable routers");

	for (rn = route_top(rtrs); rn; rn = next) {
		next = route_next(rn);
		if ((paths = rn->info) == NULL)
			continue;

		for (ALL_LIST_ELEMENTS(paths, node, nnode, or)) {
			if (listcount(or->paths) == 0) {
				if (IS_DEBUG_OSPF_EVENT) {
					zlog_debug("Pruning route to rtr %pI4",
						   &rn->p.u.prefix4);
					zlog_debug(
						"               via area %pI4",
						&or->u.std.area_id);
				}

				/* Unset the DNA flag on lsa, if the router
				 * which generated this lsa is no longer
				 * reachabele.
				 */
				(CHECK_FLAG(or->u.std.origin->ls_age,
					    DO_NOT_AGE))
					? UNSET_FLAG(or->u.std.origin->ls_age,
						     DO_NOT_AGE)
					: 0;

				listnode_delete(paths, or);
				ospf_route_free(or);
			}
		}

		if (listcount(paths) == 0) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("Pruning router node %pI4",
					   &rn->p.u.prefix4);

			list_delete(&paths);
			rn->info = NULL;
			route_unlock_node(rn);
		}
	}
}

int ospf_add_discard_route(struct ospf *ospf, struct route_table *rt,
			   struct ospf_area *area, struct prefix_ipv4 *p,
			   bool nssa)
{
	struct route_node *rn;
	struct ospf_route * or, *new_or;

	rn = route_node_get(rt, (struct prefix *)p);

	if (rn == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: router installation error", __func__);
		return 0;
	}

	if (rn->info) /* If the route to the same destination is found */
	{
		route_unlock_node(rn);

		or = rn->info;

		if (!nssa && or->path_type == OSPF_PATH_INTRA_AREA) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: an intra-area route exists",
					   __func__);
			return 0;
		}

		if (or->type == OSPF_DESTINATION_DISCARD) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: discard entry already installed",
					__func__);
			return 0;
		}

		ospf_route_free(rn->info);
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: adding %pFX", __func__, p);

	new_or = ospf_route_new();
	new_or->type = OSPF_DESTINATION_DISCARD;
	new_or->id.s_addr = INADDR_ANY;
	new_or->cost = 0;
	new_or->u.std.area_id = area->area_id;
	new_or->u.std.external_routing = area->external_routing;
	if (nssa)
		new_or->path_type = OSPF_PATH_TYPE2_EXTERNAL;
	else
		new_or->path_type = OSPF_PATH_INTER_AREA;
	rn->info = new_or;

	ospf_zebra_add_discard(ospf, p);

	return 1;
}

void ospf_delete_discard_route(struct ospf *ospf, struct route_table *rt,
			       struct prefix_ipv4 *p, bool nssa)
{
	struct route_node *rn;
	struct ospf_route * or ;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: deleting %pFX", __func__, p);

	rn = route_node_lookup(rt, (struct prefix *)p);

	if (rn == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: no route found", __func__);
		return;
	}

	or = rn->info;

	if (!nssa && or->path_type == OSPF_PATH_INTRA_AREA) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: an intra-area route exists", __func__);
		return;
	}

	if (or->type != OSPF_DESTINATION_DISCARD) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: not a discard entry", __func__);
		return;
	}

	/* free the route entry and the route node */
	ospf_route_free(rn->info);

	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);

	/* remove the discard entry from the rib */
	ospf_zebra_delete_discard(ospf, p);

	return;
}
