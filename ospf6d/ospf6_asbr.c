// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "command.h"
#include "vty.h"
#include "routemap.h"
#include "table.h"
#include "plist.h"
#include "frrevent.h"
#include "frrstr.h"
#include "linklist.h"
#include "lib/northbound_cli.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_message.h"
#include "ospf6_spf.h"

#include "ospf6_top.h"
#include "ospf6d.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_intra.h"
#include "ospf6_flood.h"
#include "ospf6_nssa.h"
#include "ospf6d.h"
#include "ospf6_spf.h"
#include "ospf6_nssa.h"
#include "ospf6_gr.h"
#include "lib/json.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_EXTERNAL_INFO, "OSPF6 ext. info");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_DIST_ARGS,     "OSPF6 Distribute arguments");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_REDISTRIBUTE, "OSPF6 Redistribute arguments");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_EXTERNAL_RT_AGGR, "OSPF6 ASBR Summarisation");

static void ospf6_asbr_redistribute_set(struct ospf6 *ospf6, int type);
static void ospf6_asbr_redistribute_unset(struct ospf6 *ospf6,
					  struct ospf6_redist *red, int type);

#include "ospf6d/ospf6_asbr_clippy.c"

unsigned char conf_debug_ospf6_asbr = 0;

#define ZROUTE_NAME(x) zebra_route_string(x)

/* Originate Type-5 and Type-7 LSA */
static struct ospf6_lsa *ospf6_originate_type5_type7_lsas(
						struct ospf6_route *route,
						struct ospf6 *ospf6)
{
	struct ospf6_lsa *lsa;
	struct listnode *lnode;
	struct ospf6_area *oa = NULL;

	lsa = ospf6_as_external_lsa_originate(route, ospf6);

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, lnode, oa)) {
		if (IS_AREA_NSSA(oa))
			ospf6_nssa_lsa_originate(route, oa, true);
	}

	return lsa;
}

/* AS External LSA origination */
struct ospf6_lsa *ospf6_as_external_lsa_originate(struct ospf6_route *route,
					    struct ospf6 *ospf6)
{
	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *lsa;
	struct ospf6_external_info *info = route->route_option;

	struct ospf6_as_external_lsa *as_external_lsa;
	caddr_t p;

	if (ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return NULL;
	}

	if (IS_OSPF6_DEBUG_ASBR || IS_OSPF6_DEBUG_ORIGINATE(AS_EXTERNAL))
		zlog_debug("Originate AS-External-LSA for %pFX",
			   &route->prefix);

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	as_external_lsa = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
		lsa_header);
	p = (caddr_t)((caddr_t)as_external_lsa
		      + sizeof(struct ospf6_as_external_lsa));

	/* Fill AS-External-LSA */
	/* Metric type */
	if (route->path.metric_type == 2)
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);
	else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);

	/* forwarding address */
	if (!IN6_IS_ADDR_UNSPECIFIED(&info->forwarding))
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);
	else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);

	/* external route tag */
	if (info->tag)
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T);
	else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T);

	/* Set metric */
	OSPF6_ASBR_METRIC_SET(as_external_lsa, route->path.cost);

	/* prefixlen */
	as_external_lsa->prefix.prefix_length = route->prefix.prefixlen;

	/* PrefixOptions */
	as_external_lsa->prefix.prefix_options = route->prefix_options;

	/* don't use refer LS-type */
	as_external_lsa->prefix.prefix_refer_lstype = htons(0);

	/* set Prefix */
	memcpy(p, &route->prefix.u.prefix6,
	       OSPF6_PREFIX_SPACE(route->prefix.prefixlen));
	ospf6_prefix_apply_mask(&as_external_lsa->prefix);
	p += OSPF6_PREFIX_SPACE(route->prefix.prefixlen);

	/* Forwarding address */
	if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F)) {
		memcpy(p, &info->forwarding, sizeof(struct in6_addr));
		p += sizeof(struct in6_addr);
	}

	/* External Route Tag */
	if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T)) {
		route_tag_t network_order = htonl(info->tag);

		memcpy(p, &network_order, sizeof(network_order));
		p += sizeof(network_order);
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	lsa_header->id = route->path.origin.id;
	lsa_header->adv_router = ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, ospf6->lsdb);
	lsa_header->length = htons((caddr_t)p - (caddr_t)lsa_header);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_process(lsa, ospf6);

	return lsa;
}

void ospf6_orig_as_external_lsa(struct event *thread)
{
	struct ospf6_interface *oi;
	struct ospf6_lsa *lsa;
	uint32_t type, adv_router;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	if (oi->state == OSPF6_INTERFACE_DOWN)
		return;
	if (IS_AREA_NSSA(oi->area) || IS_AREA_STUB(oi->area))
		return;

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	adv_router = oi->area->ospf6->router_id;
	for (ALL_LSDB_TYPED_ADVRTR(oi->area->ospf6->lsdb, type, adv_router,
				   lsa)) {
		if (IS_OSPF6_DEBUG_ASBR)
			zlog_debug(
				"%s: Send update of AS-External LSA %s seq 0x%x",
				__func__, lsa->name,
				ntohl(lsa->header->seqnum));

		ospf6_flood_interface(NULL, lsa, oi);
	}
}

static route_tag_t ospf6_as_external_lsa_get_tag(struct ospf6_lsa *lsa)
{
	struct ospf6_as_external_lsa *external;
	ptrdiff_t tag_offset;
	route_tag_t network_order;

	if (!lsa)
		return 0;

	external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
		lsa->header);

	if (!CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_T))
		return 0;

	tag_offset = sizeof(*external)
		     + OSPF6_PREFIX_SPACE(external->prefix.prefix_length);
	if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F))
		tag_offset += sizeof(struct in6_addr);

	memcpy(&network_order, (caddr_t)external + tag_offset,
	       sizeof(network_order));
	return ntohl(network_order);
}

void ospf6_asbr_update_route_ecmp_path(struct ospf6_route *old,
				       struct ospf6_route *route,
				       struct ospf6 *ospf6)
{
	struct ospf6_route *old_route, *next_route;
	struct ospf6_path *ecmp_path, *o_path = NULL;
	struct listnode *anode, *anext;
	struct listnode *nnode, *rnode, *rnext;
	struct ospf6_nexthop *nh, *rnh;
	bool route_found = false;

	/* check for old entry match with new route origin,
	 * delete old entry.
	 */
	for (old_route = old; old_route; old_route = next_route) {
		bool route_updated = false;

		next_route = old_route->next;

		/* The route linked-list is grouped in batches of prefix.
		 * If the new prefix is not the same as the one of interest
		 * then we have walked over the end of the batch and so we
		 * should break rather than continuing unnecessarily.
		 */
		if (!ospf6_route_is_same(old_route, route))
			break;
		if (old_route->path.type != route->path.type)
			continue;

		/* Current and New route has same origin,
		 * delete old entry.
		 */
		for (ALL_LIST_ELEMENTS(old_route->paths, anode, anext,
				       o_path)) {
			/* Check old route path and route has same
			 * origin.
			 */
			if (o_path->area_id != route->path.area_id
			    || !ospf6_ls_origin_same(o_path, &route->path))
				continue;

			/* Cost is not same then delete current path */
			if ((o_path->cost == route->path.cost)
			    && (o_path->u.cost_e2 == route->path.u.cost_e2))
				continue;

			if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)) {
				zlog_debug(
					"%s: route %pFX cost old %u new %u is not same, replace route",
					__func__, &old_route->prefix, o_path->cost,
					route->path.cost);
			}

			/* Remove selected current rout path's nh from
			 * effective nh list.
			 */
			for (ALL_LIST_ELEMENTS_RO(o_path->nh_list, nnode, nh)) {
				for (ALL_LIST_ELEMENTS(old_route->nh_list,
						       rnode, rnext, rnh)) {
					if (!ospf6_nexthop_is_same(rnh, nh))
						continue;
					listnode_delete(old_route->nh_list,
							rnh);
					ospf6_nexthop_delete(rnh);
				}
			}

			listnode_delete(old_route->paths, o_path);
			ospf6_path_free(o_path);
			route_updated = true;

			/* Current route's path (adv_router info) is similar
			 * to route being added.
			 * Replace current route's path with paths list head.
			 * Update FIB with effective NHs.
			 */
			if (listcount(old_route->paths)) {
				for (ALL_LIST_ELEMENTS(old_route->paths,
						anode, anext, o_path)) {
					ospf6_merge_nexthops(
						old_route->nh_list,
						o_path->nh_list);
				}
				/* Update RIB/FIB with effective
				 * nh_list
				 */
				if (ospf6->route_table->hook_add)
					(*ospf6->route_table->hook_add)(
						old_route);

				if (old_route->path.origin.id
					    == route->path.origin.id
				    && old_route->path.origin.adv_router
					       == route->path.origin
							  .adv_router) {
					struct ospf6_path *h_path;

					h_path = (struct ospf6_path *)
						listgetdata(listhead(
							old_route->paths));
					old_route->path.origin.type =
						h_path->origin.type;
					old_route->path.origin.id =
						h_path->origin.id;
					old_route->path.origin.adv_router =
						h_path->origin.adv_router;
				}
			} else {
				if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)) {
					zlog_debug(
						"%s: route %pFX old cost %u new cost %u, delete old entry.",
						__func__, &old_route->prefix,
						old_route->path.cost,
						route->path.cost);
				}
				if (old == old_route)
					old = next_route;
				ospf6_route_remove(old_route,
						   ospf6->route_table);
			}
		}
		if (route_updated)
			break;
	}

	/* Add new route */
	for (old_route = old; old_route; old_route = old_route->next) {

		/* The route linked-list is grouped in batches of prefix.
		 * If the new prefix is not the same as the one of interest
		 * then we have walked over the end of the batch and so we
		 * should break rather than continuing unnecessarily.
		 */
		if (!ospf6_route_is_same(old_route, route))
			break;
		if (old_route->path.type != route->path.type)
			continue;

		/* Old Route and New Route have Equal Cost, Merge NHs */
		if ((old_route->path.cost == route->path.cost)
		    && (old_route->path.u.cost_e2 == route->path.u.cost_e2)) {

			if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)) {
				zlog_debug(
					"%s: old route %pFX path  cost %u e2 %u",
					__func__, &old_route->prefix,
					old_route->path.cost,
					old_route->path.u.cost_e2);
			}
			route_found = true;
			/* check if this path exists already in
			 * route->paths list, if so, replace nh_list
			 * from asbr_entry.
			 */
			for (ALL_LIST_ELEMENTS_RO(old_route->paths, anode,
						  o_path)) {
				if (o_path->area_id == route->path.area_id
				    && ospf6_ls_origin_same(o_path, &route->path))
					break;
			}
			/* If path is not found in old_route paths's list,
			 * add a new path to route paths list and merge
			 * nexthops in route->path->nh_list.
			 * Otherwise replace existing path's nh_list.
			 */
			if (o_path == NULL) {
				ecmp_path = ospf6_path_dup(&route->path);

				/* Add a nh_list to new ecmp path */
				ospf6_copy_nexthops(ecmp_path->nh_list,
						    route->nh_list);

				/* Add the new path to route's path list */
				listnode_add_sort(old_route->paths, ecmp_path);

				if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL)) {
					zlog_debug(
						"%s: route %pFX another path added with nh %u, effective paths %u nh %u",
						__func__, &route->prefix,
						listcount(ecmp_path->nh_list),
						old_route->paths ? listcount(
							old_route->paths)
								 : 0,
						listcount(old_route->nh_list));
				}
			} else {
				list_delete_all_node(o_path->nh_list);
				ospf6_copy_nexthops(o_path->nh_list,
						    route->nh_list);
			}

			/* Reset nexthop lists, rebuild from brouter table
			 * for each adv. router.
			 */
			list_delete_all_node(old_route->nh_list);

			for (ALL_LIST_ELEMENTS_RO(old_route->paths, anode,
						  o_path)) {
				struct ospf6_route *asbr_entry;

				asbr_entry = ospf6_route_lookup(
							&o_path->ls_prefix,
							ospf6->brouter_table);
				if (asbr_entry == NULL) {
					if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
						zlog_debug(
							"%s: ls_prfix %pFX asbr_entry not found.",
							__func__,
							&old_route->prefix);
					continue;
				}
				ospf6_route_merge_nexthops(old_route,
							   asbr_entry);
			}

			if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
				zlog_debug(
					"%s: route %pFX with effective paths %u nh %u",
					__func__, &route->prefix,
					old_route->paths
						? listcount(old_route->paths)
						: 0,
					old_route->nh_list
						? listcount(old_route->nh_list)
						: 0);

			/* Update RIB/FIB */
			if (ospf6->route_table->hook_add)
				(*ospf6->route_table->hook_add)(old_route);

			/* Delete the new route its info added to existing
			 * route.
			 */
			ospf6_route_delete(route);

			break;
		}
	}

	if (!route_found) {
		/* Add new route to existing node in ospf6 route table. */
		ospf6_route_add(route, ospf6->route_table);
	}
}

/* Check if the forwarding address is local address */
static int ospf6_ase_forward_address_check(struct ospf6 *ospf6,
					   struct in6_addr *fwd_addr)
{
	struct listnode *anode, *node;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct interface *ifp;
	struct connected *c;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, anode, oa)) {
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, node, oi)) {
			if (!if_is_operative(oi->interface)
			    || oi->type == OSPF_IFTYPE_VIRTUALLINK)
				continue;

			ifp = oi->interface;
			frr_each (if_connected, ifp->connected, c) {
				if (IPV6_ADDR_SAME(&c->address->u.prefix6,
						   fwd_addr))
					return 0;
			}
		}
	}

	return 1;
}

void ospf6_asbr_lsa_add(struct ospf6_lsa *lsa)
{
	struct ospf6_as_external_lsa *external;
	struct prefix asbr_id;
	struct ospf6_route *asbr_entry, *route, *old = NULL;
	struct ospf6_path *path;
	struct ospf6 *ospf6;
	int type;
	struct ospf6_area *oa = NULL;
	struct prefix fwd_addr;
	ptrdiff_t offset;

	type = ntohs(lsa->header->type);
	oa = lsa->lsdb->data;

	external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
		lsa->header);

	if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
		zlog_debug("Calculate AS-External route for %s", lsa->name);

	ospf6 = ospf6_get_by_lsdb(lsa);

	if (lsa->header->adv_router == ospf6->router_id) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("Ignore self-originated AS-External-LSA");
		return;
	}

	if (OSPF6_ASBR_METRIC(external) == OSPF_LS_INFINITY) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("Ignore LSA with LSInfinity Metric");
		return;
	}

	if (CHECK_FLAG(external->prefix.prefix_options,
		       OSPF6_PREFIX_OPTION_NU)) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("Ignore LSA with NU bit set Metric");
		return;
	}

	ospf6_linkstate_prefix(lsa->header->adv_router, htonl(0), &asbr_id);
	asbr_entry = ospf6_route_lookup(&asbr_id, ospf6->brouter_table);
	if (asbr_entry == NULL) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("ASBR entry not found: %pFX", &asbr_id);
		return;
	} else {
		/* The router advertising external LSA can be ASBR or ABR */
		if (!CHECK_FLAG(asbr_entry->path.router_bits,
				OSPF6_ROUTER_BIT_E)) {
			if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
				zlog_debug(
					"External bit reset ASBR route entry : %pFX",
					&asbr_id);
			return;
		}

		/*
		 * RFC 3101 - Section 2.5:
		 * "For a Type-7 LSA the matching routing table entry must
		 * specify an intra-area path through the LSA's originating
		 * NSSA".
		 */
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7
		    && (asbr_entry->path.area_id != oa->area_id
			|| asbr_entry->path.type != OSPF6_PATH_TYPE_INTRA)) {
			if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
				zlog_debug(
					"Intra-area route to NSSA ASBR not found: %pFX",
					&asbr_id);
			return;
		}
	}

	/*
	 * RFC 3101 - Section 2.5:
	 * "If the destination is a Type-7 default route (destination ID =
	 * DefaultDestination) and one of the following is true, then do
	 * nothing with this LSA and consider the next in the list:
	 *
	 *  o  The calculating router is a border router and the LSA has
	 *     its P-bit clear.  Appendix E describes a technique
	 *     whereby an NSSA border router installs a Type-7 default
	 *     LSA without propagating it.
	 *
	 *  o  The calculating router is a border router and is
	 *     suppressing the import of summary routes as Type-3
	 *     summary-LSAs".
	 */
	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7
	    && external->prefix.prefix_length == 0
	    && CHECK_FLAG(ospf6->flag, OSPF6_FLAG_ABR)
	    && (CHECK_FLAG(external->prefix.prefix_options,
			   OSPF6_PREFIX_OPTION_P)
		|| oa->no_summary)) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("Skipping Type-7 default route");
		return;
	}

	/* Check the forwarding address */
	if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F)) {
		offset = sizeof(*external)
			 + OSPF6_PREFIX_SPACE(external->prefix.prefix_length);
		memset(&fwd_addr, 0, sizeof(fwd_addr));
		fwd_addr.family = AF_INET6;
		fwd_addr.prefixlen = IPV6_MAX_BITLEN;
		memcpy(&fwd_addr.u.prefix6, (caddr_t)external + offset,
		       sizeof(struct in6_addr));

		if (!IN6_IS_ADDR_UNSPECIFIED(&fwd_addr.u.prefix6)) {
			if (!ospf6_ase_forward_address_check(
				    ospf6, &fwd_addr.u.prefix6)) {
				if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
					zlog_debug(
						"Fwd address %pFX is local address",
						&fwd_addr);
				return;
			}

			/* Find the forwarding entry */
			asbr_entry = ospf6_route_lookup_bestmatch(
				&fwd_addr, ospf6->route_table);
			if (asbr_entry == NULL) {
				if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
					zlog_debug(
						"Fwd address not found: %pFX",
						&fwd_addr);
				return;
			}
		}
	}

	route = ospf6_route_create(ospf6);
	route->type = OSPF6_DEST_TYPE_NETWORK;
	route->prefix.family = AF_INET6;
	route->prefix.prefixlen = external->prefix.prefix_length;
	ospf6_prefix_in6_addr(&route->prefix.u.prefix6, external,
			      &external->prefix);
	route->prefix_options = external->prefix.prefix_options;

	route->path.area_id = asbr_entry->path.area_id;
	route->path.origin.type = lsa->header->type;
	route->path.origin.id = lsa->header->id;
	route->path.origin.adv_router = lsa->header->adv_router;
	memcpy(&route->path.ls_prefix, &asbr_id, sizeof(struct prefix));

	if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_E)) {
		route->path.type = OSPF6_PATH_TYPE_EXTERNAL2;
		route->path.metric_type = 2;
		route->path.cost = asbr_entry->path.cost;
		route->path.u.cost_e2 = OSPF6_ASBR_METRIC(external);
	} else {
		route->path.type = OSPF6_PATH_TYPE_EXTERNAL1;
		route->path.metric_type = 1;
		route->path.cost =
			asbr_entry->path.cost + OSPF6_ASBR_METRIC(external);
		route->path.u.cost_e2 = 0;
	}

	route->path.tag = ospf6_as_external_lsa_get_tag(lsa);

	ospf6_route_copy_nexthops(route, asbr_entry);

	path = ospf6_path_dup(&route->path);
	ospf6_copy_nexthops(path->nh_list, asbr_entry->nh_list);
	listnode_add_sort(route->paths, path);


	if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
		zlog_debug(
			"%s: %s %u route add %pFX cost %u(%u) nh %u", __func__,
			(type == OSPF6_LSTYPE_AS_EXTERNAL) ? "AS-External"
							   : "NSSA",
			(route->path.type == OSPF6_PATH_TYPE_EXTERNAL1) ? 1 : 2,
			&route->prefix, route->path.cost, route->path.u.cost_e2,
			listcount(route->nh_list));

	if (type == OSPF6_LSTYPE_AS_EXTERNAL)
		old = ospf6_route_lookup(&route->prefix, ospf6->route_table);
	else if (type == OSPF6_LSTYPE_TYPE_7)
		old = ospf6_route_lookup(&route->prefix, oa->route_table);
	if (!old) {
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("%s: Adding new route", __func__);
		/* Add the new route to ospf6 instance route table. */
		if (type == OSPF6_LSTYPE_AS_EXTERNAL)
			ospf6_route_add(route, ospf6->route_table);
		/* Add the route to the area route table */
		else if (type == OSPF6_LSTYPE_TYPE_7) {
			ospf6_route_add(route, oa->route_table);
		}
	} else {
		/* RFC 2328 16.4 (6)
		 * ECMP: Keep new equal preference path in current
		 * route's path list, update zebra with new effective
		 * list along with addition of ECMP path.
		 */
		if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL))
			zlog_debug("%s : old route %pFX cost %u(%u) nh %u",
				   __func__, &route->prefix, route->path.cost,
				   route->path.u.cost_e2,
				   listcount(route->nh_list));
		ospf6_asbr_update_route_ecmp_path(old, route, ospf6);
	}
}

void ospf6_asbr_lsa_remove(struct ospf6_lsa *lsa,
			   struct ospf6_route *asbr_entry)
{
	struct ospf6_as_external_lsa *external;
	struct prefix prefix;
	struct ospf6_route *route, *nroute, *route_to_del;
	struct ospf6_area *oa = NULL;
	struct ospf6 *ospf6;
	int type;
	bool debug = false;

	external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
		lsa->header);

	if (IS_OSPF6_DEBUG_EXAMIN(AS_EXTERNAL) || (IS_OSPF6_DEBUG_NSSA))
		debug = true;

	ospf6 = ospf6_get_by_lsdb(lsa);
	type = ntohs(lsa->header->type);

	if (type == OSPF6_LSTYPE_TYPE_7) {
		if (debug)
			zlog_debug("%s: Withdraw  Type 7 route for %s",
				   __func__, lsa->name);
		oa = lsa->lsdb->data;
	} else {
		if (debug)
			zlog_debug("%s: Withdraw AS-External route for %s",
				   __func__, lsa->name);

		if (ospf6_check_and_set_router_abr(ospf6))
			oa = ospf6->backbone;
		else
			oa = listnode_head(ospf6->area_list);
	}

	if (oa == NULL) {
		if (debug)
			zlog_debug("%s: Invalid area", __func__);
		return;
	}

	if (lsa->header->adv_router == oa->ospf6->router_id) {
		if (debug)
			zlog_debug("Ignore self-originated AS-External-LSA");
		return;
	}

	route_to_del = ospf6_route_create(ospf6);
	route_to_del->type = OSPF6_DEST_TYPE_NETWORK;
	route_to_del->prefix.family = AF_INET6;
	route_to_del->prefix.prefixlen = external->prefix.prefix_length;
	ospf6_prefix_in6_addr(&route_to_del->prefix.u.prefix6, external,
			      &external->prefix);

	route_to_del->path.origin.type = lsa->header->type;
	route_to_del->path.origin.id = lsa->header->id;
	route_to_del->path.origin.adv_router = lsa->header->adv_router;

	if (asbr_entry) {
		route_to_del->path.area_id = asbr_entry->path.area_id;
		if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_E)) {
			route_to_del->path.type = OSPF6_PATH_TYPE_EXTERNAL2;
			route_to_del->path.metric_type = 2;
			route_to_del->path.cost = asbr_entry->path.cost;
			route_to_del->path.u.cost_e2 =
				OSPF6_ASBR_METRIC(external);
		} else {
			route_to_del->path.type = OSPF6_PATH_TYPE_EXTERNAL1;
			route_to_del->path.metric_type = 1;
			route_to_del->path.cost = asbr_entry->path.cost
						  + OSPF6_ASBR_METRIC(external);
			route_to_del->path.u.cost_e2 = 0;
		}
	}

	memset(&prefix, 0, sizeof(struct prefix));
	prefix.family = AF_INET6;
	prefix.prefixlen = external->prefix.prefix_length;
	ospf6_prefix_in6_addr(&prefix.u.prefix6, external, &external->prefix);

	if (type == OSPF6_LSTYPE_TYPE_7)
		route = ospf6_route_lookup(&prefix, oa->route_table);
	else
		route = ospf6_route_lookup(&prefix, oa->ospf6->route_table);

	if (route == NULL) {
		if (debug)
			zlog_debug("AS-External route %pFX not found", &prefix);
		ospf6_route_delete(route_to_del);
		return;
	}

	if (debug)
		zlog_debug(
			"%s: Current route %pFX cost %u e2 %u, route to del cost %u e2 %u",
			__func__, &prefix, route->path.cost, route->path.u.cost_e2,
			route_to_del->path.cost, route_to_del->path.u.cost_e2);

	for (ospf6_route_lock(route);
	     route && ospf6_route_is_prefix(&prefix, route); route = nroute) {
		nroute = ospf6_route_next(route);

		if (route->type != OSPF6_DEST_TYPE_NETWORK)
			continue;

		/* Route has multiple ECMP paths, remove matching
		 * path. Update current route's effective nh list
		 * after removal of one of the path.
		 */
		if (listcount(route->paths) > 1) {
			struct listnode *anode, *anext;
			struct listnode *nnode, *rnode, *rnext;
			struct ospf6_nexthop *nh, *rnh;
			struct ospf6_path *o_path;
			bool nh_updated = false;

			/* Iterate all paths of route to find maching with LSA
			 * remove from route path list. If route->path is same,
			 * replace from paths list.
			 */
			for (ALL_LIST_ELEMENTS(route->paths, anode, anext,
					       o_path)) {
				if ((o_path->origin.type != lsa->header->type)
				    || (o_path->origin.adv_router
					!= lsa->header->adv_router)
				    || (o_path->origin.id != lsa->header->id))
					continue;

				/* Compare LSA cost with current
				 * route info.
				 */
				if (asbr_entry
				    && (o_path->cost != route_to_del->path.cost
					|| o_path->u.cost_e2
						   != route_to_del->path.u
							      .cost_e2)) {
					if (IS_OSPF6_DEBUG_EXAMIN(
						    AS_EXTERNAL)) {
						zlog_debug(
							"%s: route %pFX to delete is not same, cost %u del cost %u. skip",
							__func__, &prefix,
							route->path.cost,
							route_to_del->path
								.cost);
					}
					continue;
				}

				if (debug) {
					zlog_debug(
						"%s: route %pFX path found with cost %u nh %u to remove.",
						__func__, &prefix, route->path.cost,
						listcount(o_path->nh_list));
				}

				/* Remove found path's nh_list from
				 * the route's nh_list.
				 */
				for (ALL_LIST_ELEMENTS_RO(o_path->nh_list,
							  nnode, nh)) {
					for (ALL_LIST_ELEMENTS(route->nh_list,
							       rnode, rnext,
							       rnh)) {
						if (!ospf6_nexthop_is_same(rnh,
									   nh))
							continue;
						listnode_delete(route->nh_list,
								rnh);
						ospf6_nexthop_delete(rnh);
					}
				}
				/* Delete the path from route's path list */
				listnode_delete(route->paths, o_path);
				ospf6_path_free(o_path);
				nh_updated = true;
			}

			if (nh_updated) {
				/* Iterate all paths and merge nexthop,
				 * unlesss any of the nexthop similar to
				 * ones deleted as part of path deletion.
				 */

				for (ALL_LIST_ELEMENTS(route->paths, anode,
						       anext, o_path)) {
					ospf6_merge_nexthops(route->nh_list,
							     o_path->nh_list);
				}

				if (debug) {
					zlog_debug(
						"%s: AS-External %u route %pFX update paths %u nh %u",
						__func__,
						(route->path.type
						 == OSPF6_PATH_TYPE_EXTERNAL1)
							? 1
							: 2,
						&route->prefix, listcount(route->paths),
						route->nh_list ? listcount(
							route->nh_list)
							       : 0);
				}

				if (listcount(route->paths)) {
					/* Update RIB/FIB with effective
					 * nh_list
					 */
					if (oa->ospf6->route_table->hook_add)
						(*oa->ospf6->route_table
							  ->hook_add)(route);

					/* route's primary path is similar
					 * to LSA, replace route's primary
					 * path with route's paths list head.
					 */
					if ((route->path.origin.id ==
					    lsa->header->id) &&
					    (route->path.origin.adv_router
						 == lsa->header->adv_router)) {
						struct ospf6_path *h_path;

						h_path = (struct ospf6_path *)
						listgetdata(
							listhead(route->paths));
						route->path.origin.type =
							h_path->origin.type;
						route->path.origin.id =
							h_path->origin.id;
						route->path.origin.adv_router =
						h_path->origin.adv_router;
					}
				} else {
					if (type == OSPF6_LSTYPE_TYPE_7)
						ospf6_route_remove(
							route, oa->route_table);
					else
						ospf6_route_remove(
							route,
							oa->ospf6->route_table);
				}
			}
			continue;

		} else {
			/* Compare LSA origin and cost with current route info.
			 * if any check fails skip del this route node.
			 */
			if (asbr_entry
			    && (!ospf6_route_is_same_origin(route, route_to_del)
				|| (route->path.type != route_to_del->path.type)
				|| (route->path.cost != route_to_del->path.cost)
				|| (route->path.u.cost_e2
				    != route_to_del->path.u.cost_e2))) {
				if (debug) {
					zlog_debug(
						"%s: route %pFX to delete is not same, cost %u del cost %u. skip",
						__func__, &prefix, route->path.cost,
						route_to_del->path.cost);
				}
				continue;
			}

			if ((route->path.origin.type != lsa->header->type)
			    || (route->path.origin.adv_router
				!= lsa->header->adv_router)
			    || (route->path.origin.id != lsa->header->id))
				continue;
		}
		if (debug) {
			zlog_debug(
				"%s: AS-External %u route remove %pFX cost %u(%u) nh %u",
				__func__,
				route->path.type == OSPF6_PATH_TYPE_EXTERNAL1
					? 1
					: 2,
				&route->prefix, route->path.cost, route->path.u.cost_e2,
				listcount(route->nh_list));
		}
		if (type == OSPF6_LSTYPE_TYPE_7)
			ospf6_route_remove(route, oa->route_table);
		else
			ospf6_route_remove(route, oa->ospf6->route_table);
	}
	if (route != NULL)
		ospf6_route_unlock(route);

	ospf6_route_delete(route_to_del);
}

void ospf6_asbr_lsentry_add(struct ospf6_route *asbr_entry, struct ospf6 *ospf6)
{
	struct ospf6_lsa *lsa;
	uint16_t type;
	uint32_t router;

	if (!CHECK_FLAG(asbr_entry->flag, OSPF6_ROUTE_BEST)) {
		char buf[16];
		inet_ntop(AF_INET, &ADV_ROUTER_IN_PREFIX(&asbr_entry->prefix),
			  buf, sizeof(buf));
		zlog_info("ignore non-best path: lsentry %s add", buf);
		return;
	}

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	router = ospf6_linkstate_prefix_adv_router(&asbr_entry->prefix);
	for (ALL_LSDB_TYPED_ADVRTR(ospf6->lsdb, type, router, lsa)) {
		if (!OSPF6_LSA_IS_MAXAGE(lsa))
			ospf6_asbr_lsa_add(lsa);
	}
}

void ospf6_asbr_lsentry_remove(struct ospf6_route *asbr_entry,
			       struct ospf6 *ospf6)
{
	struct ospf6_lsa *lsa;
	uint16_t type;
	uint32_t router;

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	router = ospf6_linkstate_prefix_adv_router(&asbr_entry->prefix);
	for (ALL_LSDB_TYPED_ADVRTR(ospf6->lsdb, type, router, lsa))
		ospf6_asbr_lsa_remove(lsa, asbr_entry);
}


/* redistribute function */
static void ospf6_asbr_routemap_set(struct ospf6_redist *red,
				    const char *mapname)
{
	if (ROUTEMAP_NAME(red)) {
		route_map_counter_decrement(ROUTEMAP(red));
		free(ROUTEMAP_NAME(red));
	}

	ROUTEMAP_NAME(red) = strdup(mapname);
	ROUTEMAP(red) = route_map_lookup_by_name(mapname);
	route_map_counter_increment(ROUTEMAP(red));
}

static void ospf6_asbr_routemap_unset(struct ospf6_redist *red)
{
	if (ROUTEMAP_NAME(red))
		free(ROUTEMAP_NAME(red));

	route_map_counter_decrement(ROUTEMAP(red));

	ROUTEMAP_NAME(red) = NULL;
	ROUTEMAP(red) = NULL;
}

static void ospf6_asbr_routemap_update_timer(struct event *thread)
{
	struct ospf6 *ospf6 = EVENT_ARG(thread);
	struct ospf6_redist *red;
	int type;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red = ospf6_redist_lookup(ospf6, type, 0);

		if (!red)
			continue;

		if (!CHECK_FLAG(red->flag, OSPF6_IS_RMAP_CHANGED))
			continue;

		if (ROUTEMAP_NAME(red))
			ROUTEMAP(red) =
				route_map_lookup_by_name(ROUTEMAP_NAME(red));

		if (ROUTEMAP(red)) {
			if (IS_OSPF6_DEBUG_ASBR)
				zlog_debug(
					"%s: route-map %s update, reset redist %s",
					__func__, ROUTEMAP_NAME(red),
					ZROUTE_NAME(type));

			ospf6_zebra_no_redistribute(type, ospf6->vrf_id);
			ospf6_zebra_redistribute(type, ospf6->vrf_id);
		}

		UNSET_FLAG(red->flag, OSPF6_IS_RMAP_CHANGED);
	}
}

void ospf6_asbr_distribute_list_update(struct ospf6 *ospf6,
				       struct ospf6_redist *red)
{
	SET_FLAG(red->flag, OSPF6_IS_RMAP_CHANGED);

	if (event_is_scheduled(ospf6->t_distribute_update))
		return;

	if (IS_OSPF6_DEBUG_ASBR)
		zlog_debug("%s: trigger redistribute reset thread", __func__);

	event_add_timer_msec(master, ospf6_asbr_routemap_update_timer, ospf6,
			     OSPF_MIN_LS_INTERVAL, &ospf6->t_distribute_update);
}

void ospf6_asbr_routemap_update(const char *mapname)
{
	int type;
	struct listnode *node, *nnode;
	struct ospf6 *ospf6 = NULL;
	struct ospf6_redist *red;

	if (om6 == NULL)
		return;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
			red = ospf6_redist_lookup(ospf6, type, 0);
			if (!red || (ROUTEMAP_NAME(red) == NULL))
				continue;
			ROUTEMAP(red) =
				route_map_lookup_by_name(ROUTEMAP_NAME(red));

			if (mapname == NULL
			    || strcmp(ROUTEMAP_NAME(red), mapname))
				continue;
			if (ROUTEMAP(red)) {
				if (IS_OSPF6_DEBUG_ASBR)
					zlog_debug(
							"%s: route-map %s update, reset redist %s",
							__func__,
							mapname,
							ZROUTE_NAME(
								type));

				route_map_counter_increment(ROUTEMAP(red));
				ospf6_asbr_distribute_list_update(ospf6, red);
			} else {
				/*
				* if the mapname matches a
				* route-map on ospf6 but the
				* map doesn't exist, it is
				* being deleted. flush and then
				* readvertise
				*/
				if (IS_OSPF6_DEBUG_ASBR)
					zlog_debug(
							"%s: route-map %s deleted, reset redist %s",
							__func__,
							mapname,
							ZROUTE_NAME(
								type));
				ospf6_asbr_redistribute_unset(ospf6, red, type);
				ospf6_asbr_routemap_set(red, mapname);
				ospf6_asbr_redistribute_set(ospf6, type);
			}
		}
	}
}

static void ospf6_asbr_routemap_event(const char *name)
{
	int type;
	struct listnode *node, *nnode;
	struct ospf6 *ospf6;
	struct ospf6_redist *red;

	if (om6 == NULL)
		return;
	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
			red = ospf6_redist_lookup(ospf6, type, 0);
			if (red && ROUTEMAP_NAME(red)
			    && (strcmp(ROUTEMAP_NAME(red), name) == 0))
				ospf6_asbr_distribute_list_update(ospf6, red);
		}
	}
}

int ospf6_asbr_is_asbr(struct ospf6 *o)
{
	return (o->external_table->count || IS_OSPF6_ASBR(o));
}

struct ospf6_redist *ospf6_redist_lookup(struct ospf6 *ospf6, int type,
					 unsigned short instance)
{
	struct list *red_list;
	struct listnode *node;
	struct ospf6_redist *red;

	red_list = ospf6->redist[type];
	if (!red_list)
		return (NULL);

	for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
		if (red->instance == instance)
			return red;

	return NULL;
}

static struct ospf6_redist *ospf6_redist_add(struct ospf6 *ospf6, int type,
					     uint8_t instance)
{
	struct ospf6_redist *red;

	red = ospf6_redist_lookup(ospf6, type, instance);
	if (red)
		return red;

	if (!ospf6->redist[type])
		ospf6->redist[type] = list_new();

	red = XCALLOC(MTYPE_OSPF6_REDISTRIBUTE, sizeof(struct ospf6_redist));
	red->instance = instance;
	red->dmetric.type = -1;
	red->dmetric.value = -1;
	ROUTEMAP_NAME(red) = NULL;
	ROUTEMAP(red) = NULL;

	listnode_add(ospf6->redist[type], red);
	ospf6->redistribute++;

	return red;
}

static void ospf6_redist_del(struct ospf6 *ospf6, struct ospf6_redist *red,
			     int type)
{
	if (red) {
		listnode_delete(ospf6->redist[type], red);
		if (!ospf6->redist[type]->count) {
			list_delete(&ospf6->redist[type]);
		}
		XFREE(MTYPE_OSPF6_REDISTRIBUTE, red);
		ospf6->redistribute--;
	}
}

/*Set the status of the ospf instance to ASBR based on the status parameter,
 * rechedule SPF calculation, originate router LSA*/
void ospf6_asbr_status_update(struct ospf6 *ospf6, int status)
{
	struct listnode *lnode, *lnnode;
	struct ospf6_area *oa;

	zlog_info("ASBR[%s:Status:%d]: Update", ospf6->name, status);

	if (status) {
		if (IS_OSPF6_ASBR(ospf6)) {
			zlog_info("ASBR[%s:Status:%d]: Already ASBR",
				  ospf6->name, status);
			return;
		}
		SET_FLAG(ospf6->flag, OSPF6_FLAG_ASBR);
	} else {
		if (!IS_OSPF6_ASBR(ospf6)) {
			zlog_info("ASBR[%s:Status:%d]: Already non ASBR",
				  ospf6->name, status);
			return;
		}
		UNSET_FLAG(ospf6->flag, OSPF6_FLAG_ASBR);
	}

	/* Transition from/to status ASBR, schedule timer. */
	ospf6_spf_schedule(ospf6, OSPF6_SPF_FLAGS_ASBR_STATUS_CHANGE);

	/* Reoriginate router LSA for all areas */
	for (ALL_LIST_ELEMENTS(ospf6->area_list, lnode, lnnode, oa))
		OSPF6_ROUTER_LSA_SCHEDULE(oa);
}

static void ospf6_asbr_redistribute_set(struct ospf6 *ospf6, int type)
{
	ospf6_zebra_redistribute(type, ospf6->vrf_id);

	++ospf6->redist_count;
	ospf6_asbr_status_update(ospf6, ospf6->redist_count);
}

static void ospf6_asbr_redistribute_unset(struct ospf6 *ospf6,
					  struct ospf6_redist *red, int type)
{
	struct ospf6_route *route;
	struct ospf6_external_info *info;

	ospf6_zebra_no_redistribute(type, ospf6->vrf_id);

	for (route = ospf6_route_head(ospf6->external_table); route;
	     route = ospf6_route_next(route)) {
		info = route->route_option;
		if (info->type != type)
			continue;

		ospf6_asbr_redistribute_remove(info->type, 0, &route->prefix,
					       ospf6);
	}

	ospf6_asbr_routemap_unset(red);
	--ospf6->redist_count;
	ospf6_asbr_status_update(ospf6, ospf6->redist_count);
}

/* When an area is unstubified, flood all the external LSAs in the area */
void ospf6_asbr_send_externals_to_area(struct ospf6_area *oa)
{
	struct ospf6_lsa *lsa, *lsanext;

	for (ALL_LSDB(oa->ospf6->lsdb, lsa, lsanext)) {
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL) {
			if (IS_OSPF6_DEBUG_ASBR)
				zlog_debug("%s: Flooding AS-External LSA %s",
					   __func__, lsa->name);

			ospf6_flood_area(NULL, lsa, oa);
		}
	}
}

/* When an area is stubified, remove all the external LSAs in the area */
void ospf6_asbr_remove_externals_from_area(struct ospf6_area *oa)
{
	struct ospf6_lsa *lsa, *lsanext;
	struct listnode *node, *nnode;
	struct ospf6_area *area;
	struct ospf6 *ospf6 = oa->ospf6;
	const struct route_node *iterend;

	/* skip if router is in other non-stub/non-NSSA areas */
	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area))
		if (!IS_AREA_STUB(area) && !IS_AREA_NSSA(area))
			return;

	/* if router is only in a stub area then purge AS-External LSAs */
	iterend = ospf6_lsdb_head(ospf6->lsdb, 0, 0, 0, &lsa);
	while (lsa != NULL) {
		assert(lsa->lock > 1);
		lsanext = ospf6_lsdb_next(iterend, lsa);
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL)
			ospf6_lsdb_remove(lsa, ospf6->lsdb);
		lsa = lsanext;
	}
}

static struct ospf6_external_aggr_rt *
ospf6_external_aggr_match(struct ospf6 *ospf6, struct prefix *p)
{
	struct route_node *node;

	node = route_node_match(ospf6->rt_aggr_tbl, p);
	if (node == NULL)
		return NULL;

	if (IS_OSPF6_DEBUG_AGGR) {
		struct ospf6_external_aggr_rt *ag = node->info;
		zlog_debug("%s: Matching aggregator found.prefix: %pFX Aggregator %pFX",
			__func__,
			p,
			&ag->p);
	}

	route_unlock_node(node);

	return node->info;
}

static void ospf6_external_lsa_fwd_addr_set(struct ospf6 *ospf6,
					    const struct in6_addr *nexthop,
					    struct in6_addr *fwd_addr)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct prefix nh;

	/* Initialize forwarding address to zero. */
	memset(fwd_addr, 0, sizeof(*fwd_addr));

	vrf = vrf_lookup_by_id(ospf6->vrf_id);
	if (!vrf)
		return;

	nh.family = AF_INET6;
	nh.u.prefix6 = *nexthop;
	nh.prefixlen = IPV6_MAX_BITLEN;

	/*
	 * Use the route's nexthop as the forwarding address if it meets the
	 * following conditions:
	 * - It's a global address.
	 * - The associated nexthop interface is OSPF-enabled.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(nexthop) || IN6_IS_ADDR_LINKLOCAL(nexthop))
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct ospf6_interface *oi = ifp->info;
		struct connected *connected;

		if (!oi || CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE))
			continue;

		frr_each (if_connected, ifp->connected, connected) {
			if (connected->address->family != AF_INET6)
				continue;
			if (IN6_IS_ADDR_LINKLOCAL(&connected->address->u.prefix6))
				continue;
			if (!prefix_match(connected->address, &nh))
				continue;

			*fwd_addr = *nexthop;
			return;
		}
	}
}

void ospf6_asbr_redistribute_add(int type, ifindex_t ifindex,
				 struct prefix *prefix, unsigned int nexthop_num,
				 const struct in6_addr *nexthop, route_tag_t tag,
				 struct ospf6 *ospf6, uint32_t metric)
{
	route_map_result_t ret;
	struct ospf6_route troute;
	struct ospf6_external_info tinfo;
	struct ospf6_route *route, *match;
	struct ospf6_external_info *info;
	struct ospf6_redist *red;

	red = ospf6_redist_lookup(ospf6, type, 0);

	if (!red)
		return;

	if ((type != DEFAULT_ROUTE)
	    && !ospf6_zebra_is_redistribute(type, ospf6->vrf_id))
		return;

	memset(&troute, 0, sizeof(troute));
	memset(&tinfo, 0, sizeof(tinfo));

	if (IS_OSPF6_DEBUG_ASBR)
		zlog_debug("Redistribute %pFX (%s)", prefix,
			   type == DEFAULT_ROUTE
				   ? "default-information-originate"
				   : ZROUTE_NAME(type));

	/* if route-map was specified but not found, do not advertise */
	if (ROUTEMAP_NAME(red)) {
		if (ROUTEMAP(red) == NULL)
			ospf6_asbr_routemap_update(NULL);
		if (ROUTEMAP(red) == NULL) {
			zlog_warn(
				"route-map \"%s\" not found, suppress redistributing",
				ROUTEMAP_NAME(red));
			return;
		}
	}

	/* apply route-map */
	if (ROUTEMAP(red)) {
		troute.route_option = &tinfo;
		troute.ospf6 = ospf6;
		troute.path.redistribute_cost = metric;
		tinfo.ifindex = ifindex;
		tinfo.tag = tag;

		ret = route_map_apply(ROUTEMAP(red), prefix, &troute);
		if (ret == RMAP_DENYMATCH) {
			if (IS_OSPF6_DEBUG_ASBR)
				zlog_debug("Denied by route-map \"%s\"",
					   ROUTEMAP_NAME(red));
			ospf6_asbr_redistribute_remove(type, ifindex, prefix,
						       ospf6);
			return;
		}
	}

	match = ospf6_route_lookup(prefix, ospf6->external_table);
	if (match) {
		info = match->route_option;
		/* copy result of route-map */
		if (ROUTEMAP(red)) {
			if (troute.path.metric_type)
				match->path.metric_type =
					troute.path.metric_type;
			else
				match->path.metric_type =
					metric_type(ospf6, type, 0);
			if (troute.path.cost)
				match->path.cost = troute.path.cost;
			else
				match->path.cost = metric_value(ospf6, type, 0);

			if (!IN6_IS_ADDR_UNSPECIFIED(&tinfo.forwarding))
				memcpy(&info->forwarding, &tinfo.forwarding,
				       sizeof(struct in6_addr));
			info->tag = tinfo.tag;
		} else {
			/* If there is no route-map, simply update the tag and
			 * metric fields
			 */
			match->path.metric_type = metric_type(ospf6, type, 0);
			match->path.cost = metric_value(ospf6, type, 0);
			info->tag = tag;
		}

		info->type = type;

		if (nexthop_num && nexthop) {
			ospf6_route_add_nexthop(match, ifindex, nexthop);
			ospf6_external_lsa_fwd_addr_set(ospf6, nexthop,
							&info->forwarding);
		} else
			ospf6_route_add_nexthop(match, ifindex, NULL);

		match->path.origin.id = htonl(info->id);
		ospf6_handle_external_lsa_origination(ospf6, match, prefix);

		ospf6_asbr_status_update(ospf6, ospf6->redistribute);

		return;
	}

	/* create new entry */
	route = ospf6_route_create(ospf6);
	route->type = OSPF6_DEST_TYPE_NETWORK;
	prefix_copy(&route->prefix, prefix);

	info = (struct ospf6_external_info *)XCALLOC(
		MTYPE_OSPF6_EXTERNAL_INFO, sizeof(struct ospf6_external_info));
	route->route_option = info;

	/* copy result of route-map */
	if (ROUTEMAP(red)) {
		if (troute.path.metric_type)
			route->path.metric_type = troute.path.metric_type;
		else
			route->path.metric_type = metric_type(ospf6, type, 0);
		if (troute.path.cost)
			route->path.cost = troute.path.cost;
		else
			route->path.cost = metric_value(ospf6, type, 0);
		if (!IN6_IS_ADDR_UNSPECIFIED(&tinfo.forwarding))
			memcpy(&info->forwarding, &tinfo.forwarding,
			       sizeof(struct in6_addr));
		info->tag = tinfo.tag;
	} else {
		/* If there is no route-map, simply update the tag and metric
		 * fields
		 */
		route->path.metric_type = metric_type(ospf6, type, 0);
		route->path.cost = metric_value(ospf6, type, 0);
		info->tag = tag;
	}

	info->type = type;
	if (nexthop_num && nexthop) {
		ospf6_route_add_nexthop(route, ifindex, nexthop);
		ospf6_external_lsa_fwd_addr_set(ospf6, nexthop,
						&info->forwarding);
	} else
		ospf6_route_add_nexthop(route, ifindex, NULL);

	route = ospf6_route_add(route, ospf6->external_table);
	ospf6_handle_external_lsa_origination(ospf6, route, prefix);

	ospf6_asbr_status_update(ospf6, ospf6->redistribute);

}

static void ospf6_asbr_external_lsa_remove_by_id(struct ospf6 *ospf6,
					 uint32_t id)
{
	struct ospf6_lsa *lsa;

	lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
				htonl(id), ospf6->router_id, ospf6->lsdb);
	if (!lsa)
		return;

	ospf6_external_lsa_purge(ospf6, lsa);

}

static void
ospf6_link_route_to_aggr(struct ospf6_external_aggr_rt *aggr,
			struct ospf6_route *rt)
{
	(void)hash_get(aggr->match_extnl_hash, rt, hash_alloc_intern);
	rt->aggr_route = aggr;
}

static void
ospf6_asbr_summary_remove_lsa_and_route(struct ospf6 *ospf6,
					struct ospf6_external_aggr_rt *aggr)
{

	/* Send a Max age LSA if it is already originated.*/
	if (!CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED))
		return;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Flushing Aggregate route (%pFX)",
				__func__,
				&aggr->p);

	ospf6_asbr_external_lsa_remove_by_id(ospf6, aggr->id);

	if (aggr->route) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug(
				"%s: Remove the blackhole route",
				__func__);

		ospf6_zebra_route_update_remove(aggr->route, ospf6);
		if (aggr->route->route_option)
			XFREE(MTYPE_OSPF6_EXTERNAL_INFO,
			      aggr->route->route_option);
		ospf6_route_delete(aggr->route);
		aggr->route = NULL;
	}

	aggr->id = 0;
	/* Unset the Origination flag */
	UNSET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED);
}

static void
ospf6_unlink_route_from_aggr(struct ospf6 *ospf6,
			     struct ospf6_external_aggr_rt *aggr,
			     struct ospf6_route *rt)
{
	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Unlinking external route(%pFX) from aggregator(%pFX), external route count:%ld",
					__func__,
					&rt->prefix,
					&aggr->p,
					OSPF6_EXTERNAL_RT_COUNT(aggr));

	hash_release(aggr->match_extnl_hash, rt);
	rt->aggr_route = NULL;

	/* Flush the aggregate route if matching
	 * external route count becomes zero.
	 */
	if (!OSPF6_EXTERNAL_RT_COUNT(aggr))
		ospf6_asbr_summary_remove_lsa_and_route(ospf6, aggr);
}

void ospf6_asbr_redistribute_remove(int type, ifindex_t ifindex,
				    struct prefix *prefix, struct ospf6 *ospf6)
{
	struct ospf6_route *match;
	struct ospf6_external_info *info = NULL;

	match = ospf6_route_lookup(prefix, ospf6->external_table);
	if (match == NULL) {
		if (IS_OSPF6_DEBUG_ASBR)
			zlog_debug("No such route %pFX to withdraw", prefix);
		return;
	}

	info = match->route_option;
	assert(info);

	if (info->type != type) {
		if (IS_OSPF6_DEBUG_ASBR)
			zlog_debug("Original protocol mismatch: %pFX", prefix);
		return;
	}

	/* This means aggregation on this route was not done, hence remove LSA
	 * if any originated for this prefix
	 */
	if (!match->aggr_route)
		ospf6_asbr_external_lsa_remove_by_id(ospf6, info->id);
	else
		ospf6_unlink_route_from_aggr(ospf6, match->aggr_route, match);

	if (IS_OSPF6_DEBUG_ASBR)
		zlog_debug("Removing route from external table %pFX",
			   prefix);

	ospf6_route_remove(match, ospf6->external_table);
	XFREE(MTYPE_OSPF6_EXTERNAL_INFO, info);

	ospf6_asbr_status_update(ospf6, ospf6->redistribute);
}

DEFPY (ospf6_redistribute,
       ospf6_redistribute_cmd,
       "redistribute " FRR_REDIST_STR_OSPF6D "[{metric (0-16777214)|metric-type (1-2)$metric_type|route-map RMAP_NAME$rmap_str}]",
       "Redistribute\n"
       FRR_REDIST_HELP_STR_OSPF6D
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Route map name\n")
{
	int type;
	struct ospf6_redist *red;
	int idx_protocol = 1;
	char *proto = argv[idx_protocol]->text;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	type = proto_redistnum(AFI_IP6, proto);
	if (type < 0)
		return CMD_WARNING_CONFIG_FAILED;

	if (!metric_str)
		metric = -1;
	if (!metric_type_str)
		metric_type = -1;

	red = ospf6_redist_lookup(ospf6, type, 0);
	if (!red) {
		red = ospf6_redist_add(ospf6, type, 0);
	} else {
		/* Check if nothing has changed. */
		if (red->dmetric.value == metric
		    && red->dmetric.type == metric_type
		    && ((!ROUTEMAP_NAME(red) && !rmap_str)
			|| (ROUTEMAP_NAME(red) && rmap_str
			    && strmatch(ROUTEMAP_NAME(red), rmap_str))))
			return CMD_SUCCESS;

		ospf6_asbr_redistribute_unset(ospf6, red, type);
	}

	red->dmetric.value = metric;
	red->dmetric.type = metric_type;
	if (rmap_str)
		ospf6_asbr_routemap_set(red, rmap_str);
	else
		ospf6_asbr_routemap_unset(red);
	ospf6_asbr_redistribute_set(ospf6, type);

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute,
       no_ospf6_redistribute_cmd,
       "no redistribute " FRR_REDIST_STR_OSPF6D "[{metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       NO_STR
       "Redistribute\n"
       FRR_REDIST_HELP_STR_OSPF6D
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Route map name\n")
{
	int type;
	struct ospf6_redist *red;
	int idx_protocol = 2;
	char *proto = argv[idx_protocol]->text;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	type = proto_redistnum(AFI_IP6, proto);
	if (type < 0)
		return CMD_WARNING_CONFIG_FAILED;

	red = ospf6_redist_lookup(ospf6, type, 0);
	if (!red)
		return CMD_SUCCESS;

	ospf6_asbr_redistribute_unset(ospf6, red, type);
	ospf6_redist_del(ospf6, red, type);

	return CMD_SUCCESS;
}

int ospf6_redistribute_config_write(struct vty *vty, struct ospf6 *ospf6)
{
	int type;
	struct ospf6_redist *red;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red = ospf6_redist_lookup(ospf6, type, 0);
		if (!red)
			continue;
		if (type == ZEBRA_ROUTE_OSPF6)
			continue;

		vty_out(vty, " redistribute %s", ZROUTE_NAME(type));
		if (red->dmetric.value >= 0)
			vty_out(vty, " metric %d", red->dmetric.value);
		if (red->dmetric.type == 1)
			vty_out(vty, " metric-type 1");
		if (ROUTEMAP_NAME(red))
			vty_out(vty, " route-map %s", ROUTEMAP_NAME(red));
		vty_out(vty, "\n");
	}

	return 0;
}

static void ospf6_redistribute_show_config(struct vty *vty, struct ospf6 *ospf6,
					   json_object *json_array,
					   json_object *json, bool use_json)
{
	int type;
	int nroute[ZEBRA_ROUTE_MAX];
	int total;
	struct ospf6_route *route;
	struct ospf6_external_info *info;
	json_object *json_route;
	struct ospf6_redist *red;

	total = 0;
	memset(nroute, 0, sizeof(nroute));
	for (route = ospf6_route_head(ospf6->external_table); route;
	     route = ospf6_route_next(route)) {
		info = route->route_option;
		nroute[info->type]++;
		total++;
	}

	if (!use_json)
		vty_out(vty, "Redistributing External Routes from:\n");

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {

		red = ospf6_redist_lookup(ospf6, type, 0);

		if (!red)
			continue;
		if (type == ZEBRA_ROUTE_OSPF6)
			continue;

		if (use_json) {
			json_route = json_object_new_object();
			json_object_string_add(json_route, "routeType",
					       ZROUTE_NAME(type));
			json_object_int_add(json_route, "numberOfRoutes",
					    nroute[type]);
			json_object_boolean_add(json_route,
						"routeMapNamePresent",
						ROUTEMAP_NAME(red));
		}

		if (ROUTEMAP_NAME(red)) {
			if (use_json) {
				json_object_string_add(json_route,
						       "routeMapName",
						       ROUTEMAP_NAME(red));
				json_object_boolean_add(json_route,
							"routeMapFound",
							ROUTEMAP(red));
			} else
				vty_out(vty,
					"    %d: %s with route-map \"%s\"%s\n",
					nroute[type], ZROUTE_NAME(type),
					ROUTEMAP_NAME(red),
					(ROUTEMAP(red) ? ""
						       : " (not found !)"));
		} else {
			if (!use_json)
				vty_out(vty, "    %d: %s\n", nroute[type],
					ZROUTE_NAME(type));
		}

		if (use_json)
			json_object_array_add(json_array, json_route);
	}
	if (use_json) {
		json_object_object_add(json, "redistributedRoutes", json_array);
		json_object_int_add(json, "totalRoutes", total);
	} else
		vty_out(vty, "Total %d routes\n", total);
}

static void ospf6_redistribute_default_set(struct ospf6 *ospf6, int originate)
{
	struct prefix_ipv6 p = {};
	struct in6_addr nexthop = {};
	int cur_originate = ospf6->default_originate;

	p.family = AF_INET6;
	p.prefixlen = 0;

	ospf6->default_originate = originate;

	switch (cur_originate) {
	case DEFAULT_ORIGINATE_NONE:
		break;
	case DEFAULT_ORIGINATE_ZEBRA:
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
					     zclient, AFI_IP6, ospf6->vrf_id);
		ospf6_asbr_redistribute_remove(DEFAULT_ROUTE, 0,
					       (struct prefix *)&p, ospf6);

		break;
	case DEFAULT_ORIGINATE_ALWAYS:
		ospf6_asbr_redistribute_remove(DEFAULT_ROUTE, 0,
					       (struct prefix *)&p, ospf6);
		break;
	}

	switch (originate) {
	case DEFAULT_ORIGINATE_NONE:
		break;
	case DEFAULT_ORIGINATE_ZEBRA:
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
					     zclient, AFI_IP6, ospf6->vrf_id);

		break;
	case DEFAULT_ORIGINATE_ALWAYS:
		ospf6_asbr_redistribute_add(DEFAULT_ROUTE, 0,
					    (struct prefix *)&p, 0, &nexthop, 0,
					    ospf6, 0);
		break;
	}
}

/* Default Route originate. */
DEFPY (ospf6_default_route_originate,
       ospf6_default_route_originate_cmd,
       "default-information originate [{always$always|metric (0-16777214)$mval|metric-type (1-2)$mtype|route-map RMAP_NAME$rtmap}]",
       "Control distribution of default route\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPFv3 default metric\n"
       "OSPFv3 metric\n"
       "OSPFv3 metric type for default routes\n"
       "Set OSPFv3 External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int default_originate = DEFAULT_ORIGINATE_ZEBRA;
	struct ospf6_redist *red;
	bool sameRtmap = false;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	int cur_originate = ospf6->default_originate;

	red = ospf6_redist_add(ospf6, DEFAULT_ROUTE, 0);

	if (always != NULL)
		default_originate = DEFAULT_ORIGINATE_ALWAYS;

	if (mval_str == NULL)
		mval = -1;

	if (mtype_str == NULL)
		mtype = -1;

	/* To check if user is providing same route map */
	if ((!rtmap && !ROUTEMAP_NAME(red)) ||
	    (rtmap && ROUTEMAP_NAME(red) &&
	     (strcmp(rtmap, ROUTEMAP_NAME(red)) == 0)))
		sameRtmap = true;

	/* Don't allow if the same lsa is already originated. */
	if ((sameRtmap) && (red->dmetric.type == mtype)
	    && (red->dmetric.value == mval)
	    && (cur_originate == default_originate))
		return CMD_SUCCESS;

	/* Updating Metric details */
	red->dmetric.type = mtype;
	red->dmetric.value = mval;

	/* updating route map details */
	if (rtmap)
		ospf6_asbr_routemap_set(red, rtmap);
	else
		ospf6_asbr_routemap_unset(red);

	ospf6_redistribute_default_set(ospf6, default_originate);
	return CMD_SUCCESS;
}

DEFPY (no_ospf6_default_information_originate,
       no_ospf6_default_information_originate_cmd,
       "no default-information originate [{always|metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       NO_STR
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPFv3 default metric\n"
       "OSPFv3 metric\n"
       "OSPFv3 metric type for default routes\n"
       "Set OSPFv3 External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	struct ospf6_redist *red;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	red = ospf6_redist_lookup(ospf6, DEFAULT_ROUTE, 0);
	if (!red)
		return CMD_SUCCESS;

	ospf6_asbr_routemap_unset(red);
	ospf6_redist_del(ospf6, red, DEFAULT_ROUTE);

	ospf6_redistribute_default_set(ospf6, DEFAULT_ORIGINATE_NONE);
	return CMD_SUCCESS;
}

/* Routemap Functions */
static enum route_map_cmd_result_t
ospf6_routemap_rule_match_address_prefixlist(void *rule,
					     const struct prefix *prefix,

					     void *object)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (plist == NULL)
		return RMAP_NOMATCH;

	return (prefix_list_apply(plist, prefix) == PREFIX_DENY ? RMAP_NOMATCH
								: RMAP_MATCH);
}

static void *
ospf6_routemap_rule_match_address_prefixlist_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void ospf6_routemap_rule_match_address_prefixlist_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		ospf6_routemap_rule_match_address_prefixlist_cmd = {
	"ipv6 address prefix-list",
	ospf6_routemap_rule_match_address_prefixlist,
	ospf6_routemap_rule_match_address_prefixlist_compile,
	ospf6_routemap_rule_match_address_prefixlist_free,
};

/* `match interface IFNAME' */
/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
ospf6_routemap_rule_match_interface(void *rule, const struct prefix *prefix,
				    void *object)
{
	struct interface *ifp;
	struct ospf6_route *route;
	struct ospf6_external_info *ei;

	route = object;
	ei = route->route_option;
	ifp = if_lookup_by_name((char *)rule, route->ospf6->vrf_id);

	if (ifp != NULL && ei->ifindex == ifp->ifindex)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map `interface' match statement.  `arg' should be
   interface name. */
static void *ospf6_routemap_rule_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `interface' value. */
static void ospf6_routemap_rule_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for interface matching. */
static const struct route_map_rule_cmd
		ospf6_routemap_rule_match_interface_cmd = {
	"interface",
	ospf6_routemap_rule_match_interface,
	ospf6_routemap_rule_match_interface_compile,
	ospf6_routemap_rule_match_interface_free
};

/* Match function for matching route tags */
static enum route_map_cmd_result_t
ospf6_routemap_rule_match_tag(void *rule, const struct prefix *p, void *object)
{
	route_tag_t *tag = rule;
	struct ospf6_route *route = object;
	struct ospf6_external_info *info = route->route_option;

	if (info->tag == *tag)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static const struct route_map_rule_cmd
		ospf6_routemap_rule_match_tag_cmd = {
	"tag",
	ospf6_routemap_rule_match_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

static enum route_map_cmd_result_t
ospf6_routemap_rule_set_metric_type(void *rule, const struct prefix *prefix,
				    void *object)
{
	char *metric_type = rule;
	struct ospf6_route *route = object;

	if (strcmp(metric_type, "type-2") == 0)
		route->path.metric_type = 2;
	else
		route->path.metric_type = 1;

	return RMAP_OKAY;
}

static void *ospf6_routemap_rule_set_metric_type_compile(const char *arg)
{
	if (strcmp(arg, "type-2") && strcmp(arg, "type-1"))
		return NULL;
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void ospf6_routemap_rule_set_metric_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		ospf6_routemap_rule_set_metric_type_cmd = {
	"metric-type",
	ospf6_routemap_rule_set_metric_type,
	ospf6_routemap_rule_set_metric_type_compile,
	ospf6_routemap_rule_set_metric_type_free,
};

struct ospf6_metric {
	enum { metric_increment, metric_decrement, metric_absolute } type;
	bool used;
	uint32_t metric;
};

static enum route_map_cmd_result_t
ospf6_routemap_rule_set_metric(void *rule, const struct prefix *prefix,
			       void *object)
{
	struct ospf6_metric *metric;
	struct ospf6_route *route;

	/* Fetch routemap's rule information. */
	metric = rule;
	route = object;

	/* Set metric out value. */
	if (!metric->used)
		return RMAP_OKAY;

	if (route->path.redistribute_cost > OSPF6_EXT_PATH_METRIC_MAX)
		route->path.redistribute_cost = OSPF6_EXT_PATH_METRIC_MAX;

	if (metric->type == metric_increment) {
		route->path.cost = route->path.redistribute_cost +
				   metric->metric;

		/* Check overflow */
		if (route->path.cost > OSPF6_EXT_PATH_METRIC_MAX ||
		    route->path.cost < metric->metric)
			route->path.cost = OSPF6_EXT_PATH_METRIC_MAX;
	} else if (metric->type == metric_decrement) {
		route->path.cost = route->path.redistribute_cost -
				   metric->metric;

		/* Check overflow */
		if (route->path.cost == 0 ||
		    route->path.cost > route->path.redistribute_cost)
			route->path.cost = 1;
	} else if (metric->type == metric_absolute)
		route->path.cost = metric->metric;

	return RMAP_OKAY;
}

static void *ospf6_routemap_rule_set_metric_compile(const char *arg)
{
	struct ospf6_metric *metric;

	metric = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*metric));
	metric->used = false;

	if (all_digit(arg))
		metric->type = metric_absolute;

	if ((arg[0] == '+') && all_digit(arg + 1)) {
		metric->type = metric_increment;
		arg++;
	}

	if ((arg[0] == '-') && all_digit(arg + 1)) {
		metric->type = metric_decrement;
		arg++;
	}

	metric->metric = strtoul(arg, NULL, 10);

	if (metric->metric > OSPF6_EXT_PATH_METRIC_MAX)
		metric->metric = OSPF6_EXT_PATH_METRIC_MAX;

	if (metric->metric)
		metric->used = true;

	return metric;
}

static void ospf6_routemap_rule_set_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		ospf6_routemap_rule_set_metric_cmd = {
	"metric",
	ospf6_routemap_rule_set_metric,
	ospf6_routemap_rule_set_metric_compile,
	ospf6_routemap_rule_set_metric_free,
};

static enum route_map_cmd_result_t
ospf6_routemap_rule_set_forwarding(void *rule, const struct prefix *prefix,
				   void *object)
{
	char *forwarding = rule;
	struct ospf6_route *route = object;
	struct ospf6_external_info *info = route->route_option;

	if (inet_pton(AF_INET6, forwarding, &info->forwarding) != 1) {
		memset(&info->forwarding, 0, sizeof(struct in6_addr));
		return RMAP_ERROR;
	}

	return RMAP_OKAY;
}

static void *ospf6_routemap_rule_set_forwarding_compile(const char *arg)
{
	struct in6_addr a;
	if (inet_pton(AF_INET6, arg, &a) != 1)
		return NULL;
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void ospf6_routemap_rule_set_forwarding_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		ospf6_routemap_rule_set_forwarding_cmd = {
	"forwarding-address",
	ospf6_routemap_rule_set_forwarding,
	ospf6_routemap_rule_set_forwarding_compile,
	ospf6_routemap_rule_set_forwarding_free,
};

static enum route_map_cmd_result_t
ospf6_routemap_rule_set_tag(void *rule, const struct prefix *p, void *object)
{
	route_tag_t *tag = rule;
	struct ospf6_route *route = object;
	struct ospf6_external_info *info = route->route_option;

	info->tag = *tag;
	return RMAP_OKAY;
}

static const struct route_map_rule_cmd ospf6_routemap_rule_set_tag_cmd = {
	"tag",
	ospf6_routemap_rule_set_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

/* add "set metric-type" */
DEFUN_YANG (ospf6_routemap_set_metric_type, ospf6_routemap_set_metric_type_cmd,
      "set metric-type <type-1|type-2>",
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
	char *ext = argv[2]->text;

	const char *xpath =
		"./set-action[action='frr-ospf-route-map:metric-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-ospf-route-map:metric-type", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ext);
	return nb_cli_apply_changes(vty, NULL);
}

/* delete "set metric-type" */
DEFUN_YANG (ospf6_routemap_no_set_metric_type, ospf6_routemap_no_set_metric_type_cmd,
      "no set metric-type [<type-1|type-2>]",
      NO_STR
      SET_STR
      "Type of metric for destination routing protocol\n"
      "OSPF[6] external type 1 metric\n"
      "OSPF[6] external type 2 metric\n")
{
	const char *xpath =
		"./set-action[action='frr-ospf-route-map:metric-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* add "set forwarding-address" */
DEFUN_YANG (ospf6_routemap_set_forwarding, ospf6_routemap_set_forwarding_cmd,
      "set forwarding-address X:X::X:X",
      "Set value\n"
      "Forwarding Address\n"
      "IPv6 Address\n")
{
	int idx_ipv6 = 2;
	const char *xpath =
		"./set-action[action='frr-ospf6-route-map:forwarding-address']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-ospf6-route-map:ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_ipv6]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

/* delete "set forwarding-address" */
DEFUN_YANG (ospf6_routemap_no_set_forwarding, ospf6_routemap_no_set_forwarding_cmd,
      "no set forwarding-address [X:X::X:X]",
      NO_STR
      "Set value\n"
      "Forwarding Address\n"
      "IPv6 Address\n")
{
	const char *xpath =
		"./set-action[action='frr-ospf6-route-map:forwarding-address']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void ospf6_routemap_init(void)
{
	route_map_init();

	route_map_add_hook(ospf6_asbr_routemap_update);
	route_map_delete_hook(ospf6_asbr_routemap_update);
	route_map_event_hook(ospf6_asbr_routemap_event);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_set_tag_hook(generic_set_add);
	route_map_no_set_tag_hook(generic_set_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_match_ipv6_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_address_prefix_list_hook(generic_match_delete);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_install_match(
		&ospf6_routemap_rule_match_address_prefixlist_cmd);
	route_map_install_match(&ospf6_routemap_rule_match_interface_cmd);
	route_map_install_match(&ospf6_routemap_rule_match_tag_cmd);

	route_map_install_set(&ospf6_routemap_rule_set_metric_type_cmd);
	route_map_install_set(&ospf6_routemap_rule_set_metric_cmd);
	route_map_install_set(&ospf6_routemap_rule_set_forwarding_cmd);
	route_map_install_set(&ospf6_routemap_rule_set_tag_cmd);

	/* ASE Metric Type (e.g. Type-1/Type-2) */
	install_element(RMAP_NODE, &ospf6_routemap_set_metric_type_cmd);
	install_element(RMAP_NODE, &ospf6_routemap_no_set_metric_type_cmd);

	/* ASE Metric */
	install_element(RMAP_NODE, &ospf6_routemap_set_forwarding_cmd);
	install_element(RMAP_NODE, &ospf6_routemap_no_set_forwarding_cmd);
}


/* Display functions */
static char *ospf6_as_external_lsa_get_prefix_str(struct ospf6_lsa *lsa,
						  char *buf, int buflen,
						  int pos)
{
	struct ospf6_as_external_lsa *external;
	struct in6_addr in6;
	int prefix_length = 0;
	char tbuf[16];

	if (lsa) {
		external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
			lsa->header);

		if (pos == 0) {
			ospf6_prefix_in6_addr(&in6, external,
					      &external->prefix);
			prefix_length = external->prefix.prefix_length;
		} else {
			in6 = *((struct in6_addr
					 *)((caddr_t)external
					    + sizeof(struct
						     ospf6_as_external_lsa)
					    + OSPF6_PREFIX_SPACE(
						      external->prefix
							      .prefix_length)));
		}
		if (buf) {
			inet_ntop(AF_INET6, &in6, buf, buflen);
			if (prefix_length) {
				snprintf(tbuf, sizeof(tbuf), "/%d",
					 prefix_length);
				strlcat(buf, tbuf, buflen);
			}
		}
	}
	return (buf);
}

static int ospf6_as_external_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
				      json_object *json_obj, bool use_json)
{
	struct ospf6_as_external_lsa *external;
	char buf[64];

	assert(lsa->header);
	external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
		lsa->header);

	/* bits */
	snprintf(buf, sizeof(buf), "%c%c%c",
		 (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_E) ? 'E'
								      : '-'),
		 (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F) ? 'F'
								      : '-'),
		 (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_T) ? 'T'
								      : '-'));

	if (use_json) {
		json_object_string_add(json_obj, "bits", buf);
		json_object_int_add(json_obj, "metric",
				    (unsigned long)OSPF6_ASBR_METRIC(external));
		ospf6_prefix_options_printbuf(external->prefix.prefix_options,
					      buf, sizeof(buf));
		json_object_string_add(json_obj, "prefixOptions", buf);
		json_object_int_add(
			json_obj, "referenceLsType",
			ntohs(external->prefix.prefix_refer_lstype));
		json_object_string_add(json_obj, "prefix",
				       ospf6_as_external_lsa_get_prefix_str(
					       lsa, buf, sizeof(buf), 0));

		/* Forwarding-Address */
		json_object_boolean_add(
			json_obj, "forwardingAddressPresent",
			CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F));
		if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F))
			json_object_string_add(
				json_obj, "forwardingAddress",
				ospf6_as_external_lsa_get_prefix_str(
					lsa, buf, sizeof(buf), 1));

		/* Tag */
		json_object_boolean_add(
			json_obj, "tagPresent",
			CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_T));
		if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_T))
			json_object_int_add(json_obj, "tag",
					    ospf6_as_external_lsa_get_tag(lsa));
	} else {
		vty_out(vty, "     Bits: %s\n", buf);
		vty_out(vty, "     Metric: %5lu\n",
			(unsigned long)OSPF6_ASBR_METRIC(external));

		ospf6_prefix_options_printbuf(external->prefix.prefix_options,
					      buf, sizeof(buf));
		vty_out(vty, "     Prefix Options: %s\n", buf);

		vty_out(vty, "     Referenced LSType: %d\n",
			ntohs(external->prefix.prefix_refer_lstype));

		vty_out(vty, "     Prefix: %s\n",
			ospf6_as_external_lsa_get_prefix_str(lsa, buf,
							     sizeof(buf), 0));

		/* Forwarding-Address */
		if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_F)) {
			vty_out(vty, "     Forwarding-Address: %s\n",
				ospf6_as_external_lsa_get_prefix_str(
					lsa, buf, sizeof(buf), 1));
		}

		/* Tag */
		if (CHECK_FLAG(external->bits_metric, OSPF6_ASBR_BIT_T)) {
			vty_out(vty, "     Tag: %" ROUTE_TAG_PRI "\n",
				ospf6_as_external_lsa_get_tag(lsa));
		}
	}

	return 0;
}

static void ospf6_asbr_external_route_show(struct vty *vty,
					   struct ospf6_route *route,
					   json_object *json_array,
					   bool use_json)
{
	struct ospf6_external_info *info = route->route_option;
	char prefix[PREFIX2STR_BUFFER], id[16], forwarding[64];
	uint32_t tmp_id;
	json_object *json_route;
	char route_type[2];

	prefix2str(&route->prefix, prefix, sizeof(prefix));
	tmp_id = ntohl(info->id);
	inet_ntop(AF_INET, &tmp_id, id, sizeof(id));
	if (!IN6_IS_ADDR_UNSPECIFIED(&info->forwarding))
		inet_ntop(AF_INET6, &info->forwarding, forwarding,
			  sizeof(forwarding));
	else
		snprintf(forwarding, sizeof(forwarding), ":: (ifindex %d)",
			 ospf6_route_get_first_nh_index(route));

	if (use_json) {
		json_route = json_object_new_object();
		snprintf(route_type, sizeof(route_type), "%c",
			 zebra_route_char(info->type));
		json_object_string_add(json_route, "routeType", route_type);
		json_object_string_add(json_route, "destination", prefix);
		json_object_string_add(json_route, "id", id);
		json_object_int_add(json_route, "metricType",
				    route->path.metric_type);
		json_object_int_add(
			json_route, "routeCost",
			(unsigned long)(route->path.metric_type == 2
						? route->path.u.cost_e2
						: route->path.cost));
		json_object_string_add(json_route, "forwarding", forwarding);

		json_object_array_add(json_array, json_route);
	} else

		vty_out(vty, "%c %-32pFX %-15s type-%d %5lu %s\n",
			zebra_route_char(info->type), &route->prefix, id,
			route->path.metric_type,
			(unsigned long)(route->path.metric_type == 2
						? route->path.u.cost_e2
						: route->path.cost),
			forwarding);
}

DEFUN(show_ipv6_ospf6_redistribute, show_ipv6_ospf6_redistribute_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] redistribute [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "redistributing External information\n" JSON_STR)
{
	struct ospf6_route *route;
	struct ospf6 *ospf6 = NULL;
	json_object *json = NULL;
	bool uj = use_json(argc, argv);
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	json_object *json_array_routes = NULL;
	json_object *json_array_redistribute = NULL;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj) {
		json = json_object_new_object();
		json_array_routes = json_object_new_array();
		json_array_redistribute = json_object_new_array();
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf
		    || ((ospf6->name == NULL && vrf_name == NULL)
			|| (ospf6->name && vrf_name
			    && strcmp(ospf6->name, vrf_name) == 0))) {
			ospf6_redistribute_show_config(
				vty, ospf6, json_array_redistribute, json, uj);

			for (route = ospf6_route_head(ospf6->external_table);
			     route; route = ospf6_route_next(route)) {
				ospf6_asbr_external_route_show(
					vty, route, json_array_routes, uj);
			}

			if (uj) {
				json_object_object_add(json, "routes",
						       json_array_routes);
				vty_json(vty, json);
			}

			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static struct ospf6_lsa_handler as_external_handler = {
	.lh_type = OSPF6_LSTYPE_AS_EXTERNAL,
	.lh_name = "AS-External",
	.lh_short_name = "ASE",
	.lh_show = ospf6_as_external_lsa_show,
	.lh_get_prefix_str = ospf6_as_external_lsa_get_prefix_str,
	.lh_debug = 0};

static struct ospf6_lsa_handler nssa_external_handler = {
	.lh_type = OSPF6_LSTYPE_TYPE_7,
	.lh_name = "NSSA",
	.lh_short_name = "Type7",
	.lh_show = ospf6_as_external_lsa_show,
	.lh_get_prefix_str = ospf6_as_external_lsa_get_prefix_str,
	.lh_debug = 0};

void ospf6_asbr_init(void)
{
	ospf6_routemap_init();

	ospf6_install_lsa_handler(&as_external_handler);
	ospf6_install_lsa_handler(&nssa_external_handler);

	install_element(VIEW_NODE, &show_ipv6_ospf6_redistribute_cmd);

	install_element(OSPF6_NODE, &ospf6_default_route_originate_cmd);
	install_element(OSPF6_NODE,
			&no_ospf6_default_information_originate_cmd);
	install_element(OSPF6_NODE, &ospf6_redistribute_cmd);
	install_element(OSPF6_NODE, &no_ospf6_redistribute_cmd);
}

void ospf6_asbr_redistribute_disable(struct ospf6 *ospf6)
{
	int type;
	struct ospf6_redist *red;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red = ospf6_redist_lookup(ospf6, type, 0);
		if (!red)
			continue;
		if (type == ZEBRA_ROUTE_OSPF6)
			continue;
		ospf6_asbr_redistribute_unset(ospf6, red, type);
		ospf6_redist_del(ospf6, red, type);
	}
	red = ospf6_redist_lookup(ospf6, DEFAULT_ROUTE, 0);
	if (red) {
		ospf6_asbr_routemap_unset(red);
		ospf6_redist_del(ospf6, red, type);
		ospf6_redistribute_default_set(ospf6, DEFAULT_ORIGINATE_NONE);
	}
}

void ospf6_asbr_redistribute_reset(struct ospf6 *ospf6)
{
	int type;
	struct ospf6_redist *red;
	char buf[RMAP_NAME_MAXLEN];

	for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
		buf[0] = '\0';
		if (type == ZEBRA_ROUTE_OSPF6)
			continue;
		red = ospf6_redist_lookup(ospf6, type, 0);
		if (!red)
			continue;

		if (type == DEFAULT_ROUTE) {
			ospf6_redistribute_default_set(
				ospf6, ospf6->default_originate);
			continue;
		}
		if (ROUTEMAP_NAME(red))
			strlcpy(buf, ROUTEMAP_NAME(red), sizeof(buf));

		ospf6_asbr_redistribute_unset(ospf6, red, type);
		if (buf[0])
			ospf6_asbr_routemap_set(red, buf);
		ospf6_asbr_redistribute_set(ospf6, type);
	}
}

void ospf6_asbr_terminate(void)
{
	/* Cleanup route maps */
	route_map_finish();
}

DEFUN (debug_ospf6_asbr,
       debug_ospf6_asbr_cmd,
       "debug ospf6 asbr",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ASBR function\n"
      )
{
	OSPF6_DEBUG_ASBR_ON();
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_asbr,
       no_debug_ospf6_asbr_cmd,
       "no debug ospf6 asbr",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 ASBR function\n"
      )
{
	OSPF6_DEBUG_ASBR_OFF();
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_asbr(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_ASBR)
		vty_out(vty, "debug ospf6 asbr\n");
	return 0;
}

static void ospf6_default_originate_write(struct vty *vty, struct ospf6 *o)
{
	struct ospf6_redist *red;

	vty_out(vty, " default-information originate");
	if (o->default_originate == DEFAULT_ORIGINATE_ALWAYS)
		vty_out(vty, " always");

	red = ospf6_redist_lookup(o, DEFAULT_ROUTE, 0);
	if (red == NULL) {
		vty_out(vty, "\n");
		return;
	}

	if (red->dmetric.value >= 0)
		vty_out(vty, " metric %d", red->dmetric.value);

	if (red->dmetric.type >= 0)
		vty_out(vty, " metric-type %d", red->dmetric.type);

	if (ROUTEMAP_NAME(red))
		vty_out(vty, " route-map %s", ROUTEMAP_NAME(red));

	vty_out(vty, "\n");
}

int ospf6_distribute_config_write(struct vty *vty, struct ospf6 *o)
{
	if (o == NULL)
		return 0;

	/* Print default originate configuration. */
	if (o->default_originate != DEFAULT_ORIGINATE_NONE)
		ospf6_default_originate_write(vty, o);

	return 0;
}

void install_element_ospf6_debug_asbr(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_asbr_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_asbr_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_asbr_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_asbr_cmd);
}

/* ASBR Summarisation */
void ospf6_fill_aggr_route_details(struct ospf6 *ospf6,
				   struct ospf6_external_aggr_rt *aggr)
{
	struct ospf6_route *rt_aggr = aggr->route;
	struct ospf6_external_info *ei_aggr = rt_aggr->route_option;

	rt_aggr->prefix = aggr->p;
	ei_aggr->tag = aggr->tag;
	ei_aggr->type = 0;
	ei_aggr->id = aggr->id;

	/* When metric is not configured, apply the default metric */
	rt_aggr->path.cost = ((aggr->metric == -1) ?
				DEFAULT_DEFAULT_METRIC
				: (unsigned int)(aggr->metric));
	rt_aggr->path.metric_type = aggr->mtype;

	rt_aggr->path.origin.id = htonl(aggr->id);
}

static void
ospf6_summary_add_aggr_route_and_blackhole(struct ospf6 *ospf6,
					   struct ospf6_external_aggr_rt *aggr)
{
	struct ospf6_route *rt_aggr;
	struct ospf6_route *old_rt = NULL;
	struct ospf6_external_info *info;

	/* Check if a route is already present. */
	if (aggr->route)
		old_rt = aggr->route;

	/* Create summary route and save it. */
	rt_aggr = ospf6_route_create(ospf6);
	rt_aggr->type = OSPF6_DEST_TYPE_NETWORK;
	/* Needed to install route while calling zebra api */
	SET_FLAG(rt_aggr->flag, OSPF6_ROUTE_BEST);

	info = XCALLOC(MTYPE_OSPF6_EXTERNAL_INFO, sizeof(*info));
	rt_aggr->route_option = info;
	aggr->route = rt_aggr;

	/* Prepare the external_info for aggregator
	 * Fill all the details which will get advertised
	 */
	ospf6_fill_aggr_route_details(ospf6, aggr);

	/* Add next-hop to Null interface. */
	ospf6_add_route_nexthop_blackhole(rt_aggr);

	/* Free the old route, if any. */
	if (old_rt) {
		ospf6_zebra_route_update_remove(old_rt, ospf6);

		if (old_rt->route_option)
			XFREE(MTYPE_OSPF6_EXTERNAL_INFO, old_rt->route_option);

		ospf6_route_delete(old_rt);
	}

	ospf6_zebra_route_update_add(rt_aggr, ospf6);
}

static void ospf6_originate_new_aggr_lsa(struct ospf6 *ospf6,
					 struct ospf6_external_aggr_rt *aggr)
{
	struct prefix prefix_id;
	struct ospf6_lsa *lsa = NULL;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Originate new aggregate route(%pFX)", __func__,
			   &aggr->p);

	aggr->id = ospf6->external_id++;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug(
			"Advertise AS-External Id:%pI4 prefix %pFX metric %u",
			&prefix_id.u.prefix4, &aggr->p, aggr->metric);

	ospf6_summary_add_aggr_route_and_blackhole(ospf6, aggr);

	/* Originate summary LSA */
	lsa = ospf6_originate_type5_type7_lsas(aggr->route, ospf6);
	if (lsa) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: Set the origination bit for aggregator",
					__func__);
		SET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED);
	}
}

static void
ospf6_aggr_handle_advertise_change(struct ospf6 *ospf6,
		struct ospf6_external_aggr_rt *aggr)
{
	/* Check if advertise option modified. */
	if (CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE)) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: Don't originate the summary address,It is configured to not-advertise.",
					__func__);
		ospf6_asbr_summary_remove_lsa_and_route(ospf6, aggr);

		return;
	}

	/* There are no routes present under this aggregation config, hence
	 * nothing to originate here
	 */
	if (OSPF6_EXTERNAL_RT_COUNT(aggr) == 0) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: No routes present under this aggregation",
					__func__);
		return;
	}

	if (!CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED)) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: Now it is advertisable",
					__func__);

		ospf6_originate_new_aggr_lsa(ospf6, aggr);

		return;
	}
}

static void
ospf6_originate_summary_lsa(struct ospf6 *ospf6,
			    struct ospf6_external_aggr_rt *aggr,
			    struct ospf6_route *rt)
{
	struct ospf6_lsa *lsa = NULL, *aggr_lsa = NULL;
	struct ospf6_external_info *info = NULL;
	struct ospf6_external_aggr_rt *old_aggr;
	struct ospf6_as_external_lsa *external;
	struct ospf6_route *rt_aggr = NULL;
	route_tag_t tag = 0;
	unsigned int metric = 0;
	int mtype;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Prepare to originate Summary route(%pFX)",
			   __func__, &aggr->p);

	/* This case to handle when the overlapping aggregator address
	 * is available. Best match will be considered.So need to delink
	 * from old aggregator and link to the new aggr.
	 */
	if (rt->aggr_route) {
		if (rt->aggr_route != aggr) {
			old_aggr = rt->aggr_route;
			ospf6_unlink_route_from_aggr(ospf6, old_aggr, rt);
		}
	}

	/* Add the external route to hash table */
	ospf6_link_route_to_aggr(aggr, rt);

	/* The key for ID field is a running number and not prefix */
	info = rt->route_option;
	assert(info);
	if (info->id)
		lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
					htonl(info->id), ospf6->router_id,
					ospf6->lsdb);

	aggr_lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
				htonl(aggr->id), ospf6->router_id, ospf6->lsdb);

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Aggr LSA ID: %d flags %x.",
		   __func__, aggr->id, aggr->aggrflags);
	/* Don't originate external LSA,
	 * If it is configured not to advertise.
	 */
	if (CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE)) {
		/* If it is already originated as external LSA,
		 * But, it is configured not to advertise then
		 * flush the originated external lsa.
		 */
		if (lsa) {
			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s: Purge the external LSA %s.",
					   __func__, lsa->name);
			ospf6_external_lsa_purge(ospf6, lsa);
			info->id = 0;
			rt->path.origin.id = 0;
		}

		if (aggr_lsa) {
			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s: Purge the aggr external LSA %s.",
					   __func__, lsa->name);
			ospf6_asbr_summary_remove_lsa_and_route(ospf6, aggr);
		}

		UNSET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED);

		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: Don't originate the summary address,It is configured to not-advertise.",
				__func__);
		return;
	}

	/* Summary route already originated,
	 * So, Do nothing.
	 */
	if (CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED)) {
		if (!aggr_lsa) {
			zlog_warn(
				"%s: Could not refresh/originate %pFX",
						__func__,
						&aggr->p);
			/* Remove the assert later */
			assert(aggr_lsa);
			return;
		}

		external = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
			aggr_lsa->header);
		metric = (unsigned long)OSPF6_ASBR_METRIC(external);
		tag = ospf6_as_external_lsa_get_tag(aggr_lsa);
		mtype = CHECK_FLAG(external->bits_metric,
				   OSPF6_ASBR_BIT_E) ? 2 : 1;

		/* Prepare the external_info for aggregator */
		ospf6_fill_aggr_route_details(ospf6, aggr);
		rt_aggr = aggr->route;
		/* If tag/metric/metric-type modified , then re-originate the
		 * route with modified tag/metric/metric-type details.
		 */
		if ((tag != aggr->tag)
		    || (metric != (unsigned int)rt_aggr->path.cost)
		    || (mtype != aggr->mtype)) {

			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug(
					"%s: Routetag(old:%d new:%d)/Metric(o:%u,n:%u)/mtype(o:%d n:%d) modified,So refresh the summary route.(%pFX)",
					__func__, tag, aggr->tag,
					metric,
					aggr->metric,
					mtype, aggr->mtype,
					&aggr->p);

			aggr_lsa = ospf6_originate_type5_type7_lsas(aggr->route,
								    ospf6);
			if (aggr_lsa)
				SET_FLAG(aggr->aggrflags,
					OSPF6_EXTERNAL_AGGRT_ORIGINATED);
		}

		return;
	}

	/* If the external route prefix same as aggregate route
	 * and if external route is already originated as TYPE-5
	 * then just update the aggr info and remove the route info
	 */
	if (lsa && prefix_same(&aggr->p, &rt->prefix)) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug(
				"%s: Route prefix is same as aggr so no need to re-originate LSA(%pFX)",
				__PRETTY_FUNCTION__, &aggr->p);

		aggr->id = info->id;
		info->id = 0;
		rt->path.origin.id = 0;

		ospf6_summary_add_aggr_route_and_blackhole(ospf6, aggr);

		SET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED);

		return;
	}

	ospf6_originate_new_aggr_lsa(ospf6, aggr);
}

static void ospf6_aggr_handle_external_info(void *data)
{
	struct ospf6_route *rt = (struct ospf6_route *)data;
	struct ospf6_external_aggr_rt *aggr = NULL;
	struct ospf6_lsa *lsa = NULL;
	struct ospf6_external_info *info;
	struct ospf6 *ospf6 = NULL;

	rt->aggr_route = NULL;

	rt->to_be_processed = true;

	if (IS_OSPF6_DEBUG_ASBR || IS_OSPF6_DEBUG_ORIGINATE(AS_EXTERNAL))
		zlog_debug("%s: Handle external route for origination/refresh (%pFX)",
					__func__,
					&rt->prefix);

	ospf6 = rt->ospf6;
	assert(ospf6);

	aggr = ospf6_external_aggr_match(ospf6,
					&rt->prefix);
	if (aggr) {
		ospf6_originate_summary_lsa(ospf6, aggr, rt);
		return;
	}

	info = rt->route_option;
	if (info->id) {
		lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
					htonl(info->id), ospf6->router_id,
					ospf6->lsdb);
		if (lsa) {
			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s: LSA found, refresh it",
					   __func__);
			EVENT_OFF(lsa->refresh);
			event_add_event(master, ospf6_lsa_refresh, lsa, 0,
					&lsa->refresh);
			return;
		}
	}

	info->id  = ospf6->external_id++;
	rt->path.origin.id = htonl(info->id);

	(void)ospf6_originate_type5_type7_lsas(rt, ospf6);
}

void ospf6_asbr_summary_config_delete(struct ospf6 *ospf6,
				      struct route_node *rn)
{
	struct ospf6_external_aggr_rt *aggr = rn->info;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Deleting Aggregate route (%pFX)",
						__func__,
						&aggr->p);

	ospf6_asbr_summary_remove_lsa_and_route(ospf6, aggr);

	rn->info = NULL;
	route_unlock_node(rn);
}

static int
ospf6_handle_external_aggr_modify(struct ospf6 *ospf6,
				  struct ospf6_external_aggr_rt *aggr)
{
	struct ospf6_lsa *lsa = NULL;
	struct ospf6_as_external_lsa *asel = NULL;
	struct ospf6_route *rt_aggr;
	unsigned int metric = 0;
	route_tag_t tag = 0;
	int mtype;

	lsa = ospf6_lsdb_lookup(
		htons(OSPF6_LSTYPE_AS_EXTERNAL),
		htonl(aggr->id), ospf6->router_id,
		ospf6->lsdb);
	if (!lsa) {
		zlog_warn(
			"%s: Could not refresh/originate %pFX",
			__func__,
			&aggr->p);

		return OSPF6_FAILURE;
	}

	asel = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(lsa->header);
	metric = (unsigned long)OSPF6_ASBR_METRIC(asel);
	tag = ospf6_as_external_lsa_get_tag(lsa);
	mtype = CHECK_FLAG(asel->bits_metric,
			   OSPF6_ASBR_BIT_E) ? 2 : 1;

	/* Fill all the details for advertisement */
	ospf6_fill_aggr_route_details(ospf6, aggr);
	rt_aggr = aggr->route;
	/* If tag/metric/metric-type modified , then
	 * re-originate the route with modified
	 * tag/metric/metric-type details.
	 */
	if ((tag != aggr->tag)
	    || (metric
		!= (unsigned int)rt_aggr->path.cost)
	    || (mtype
		!= aggr->mtype)) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug(
			"%s: Changed tag(old:%d new:%d)/metric(o:%u n:%d)/mtype(o:%d n:%d),So refresh the summary route.(%pFX)",
			__func__, tag,
			aggr->tag,
			metric,
			(unsigned int)rt_aggr->path.cost,
			mtype, aggr->mtype,
			&aggr->p);

		(void)ospf6_originate_type5_type7_lsas(
					aggr->route,
					ospf6);
	}

	return OSPF6_SUCCESS;
}

static void ospf6_handle_external_aggr_update(struct ospf6 *ospf6)
{
	struct route_node *rn = NULL;
	int ret;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Process modified aggregators.", __func__);

	for (rn = route_top(ospf6->rt_aggr_tbl); rn; rn = route_next(rn)) {
		struct ospf6_external_aggr_rt *aggr;

		if (!rn->info)
			continue;

		aggr = rn->info;

		if (aggr->action == OSPF6_ROUTE_AGGR_DEL) {
			aggr->action = OSPF6_ROUTE_AGGR_NONE;
			ospf6_asbr_summary_config_delete(ospf6, rn);

			hash_clean_and_free(&aggr->match_extnl_hash,
					    ospf6_aggr_handle_external_info);

			XFREE(MTYPE_OSPF6_EXTERNAL_RT_AGGR, aggr);

		} else if (aggr->action == OSPF6_ROUTE_AGGR_MODIFY) {

			aggr->action = OSPF6_ROUTE_AGGR_NONE;

			/* Check if tag/metric/metric-type modified */
			if (CHECK_FLAG(aggr->aggrflags,
				OSPF6_EXTERNAL_AGGRT_ORIGINATED)
			    && !CHECK_FLAG(aggr->aggrflags,
				OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE)) {

				ret = ospf6_handle_external_aggr_modify(ospf6,
									aggr);
				if (ret == OSPF6_FAILURE)
					continue;
			}

			/* Advertise option modified ?
			 * If so, handled it here.
			 */
			ospf6_aggr_handle_advertise_change(ospf6, aggr);
		}
	}
}

static void ospf6_aggr_unlink_external_info(void *data)
{
	struct ospf6_route *rt = (struct ospf6_route *)data;

	rt->aggr_route = NULL;

	rt->to_be_processed = true;
}

void ospf6_external_aggregator_free(struct ospf6_external_aggr_rt *aggr)
{
	hash_clean_and_free(&aggr->match_extnl_hash,
			    ospf6_aggr_unlink_external_info);

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Release the aggregator Address(%pFX)",
						__func__,
						&aggr->p);

	XFREE(MTYPE_OSPF6_EXTERNAL_RT_AGGR, aggr);
}

static void
ospf6_delete_all_marked_aggregators(struct ospf6 *ospf6)
{
	struct route_node *rn = NULL;
	struct ospf6_external_aggr_rt *aggr;

	/* Loop through all the aggregators, Delete all aggregators
	 * which are marked as DELETE. Set action to NONE for remaining
	 * aggregators
	 */
	for (rn = route_top(ospf6->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		aggr = rn->info;

		if (aggr->action != OSPF6_ROUTE_AGGR_DEL) {
			aggr->action = OSPF6_ROUTE_AGGR_NONE;
			continue;
		}
		ospf6_asbr_summary_config_delete(ospf6, rn);
		ospf6_external_aggregator_free(aggr);
	}
}

static void ospf6_handle_exnl_rt_after_aggr_del(struct ospf6 *ospf6,
					       struct ospf6_route *rt)
{
	struct ospf6_lsa *lsa;

	/* Process only marked external routes.
	 * These routes were part of a deleted
	 * aggregator.So, originate now.
	 */
	if (!rt->to_be_processed)
		return;

	rt->to_be_processed = false;

	lsa = ospf6_find_external_lsa(ospf6, &rt->prefix);

	if (lsa) {
		EVENT_OFF(lsa->refresh);
		event_add_event(master, ospf6_lsa_refresh, lsa, 0,
				&lsa->refresh);
	} else {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: Originate external route(%pFX)",
				__func__,
				&rt->prefix);

		(void)ospf6_originate_type5_type7_lsas(rt, ospf6);
	}
}

static void ospf6_handle_aggregated_exnl_rt(struct ospf6 *ospf6,
					   struct ospf6_external_aggr_rt *aggr,
					   struct ospf6_route *rt)
{
	struct ospf6_lsa *lsa;
	struct ospf6_as_external_lsa *ext_lsa;
	struct ospf6_external_info *info;

	/* Handling the case where the external route prefix
	 * and aggegate prefix is same
	 * If same don't flush the originated external LSA.
	 */
	if (prefix_same(&aggr->p, &rt->prefix)) {
		if (IS_OSPF6_DEBUG_AGGR)
			zlog_debug("%s: External Route prefix same as Aggregator(%pFX), so don't flush.",
				__func__,
				&rt->prefix);

		return;
	}

	info = rt->route_option;
	assert(info);

	lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
				htonl(info->id), ospf6->router_id, ospf6->lsdb);
	if (lsa) {
		ext_lsa = (struct ospf6_as_external_lsa *)ospf6_lsa_header_end(
			lsa->header);

		if (rt->prefix.prefixlen != ext_lsa->prefix.prefix_length)
			return;

		ospf6_external_lsa_purge(ospf6, lsa);

		/* Resetting the ID of route */
		rt->path.origin.id = 0;
		info->id = 0;
	}
}

static void
ospf6_handle_external_aggr_add(struct ospf6 *ospf6)
{
	struct ospf6_route *rt = NULL;
	struct ospf6_external_info *ei = NULL;
	struct ospf6_external_aggr_rt *aggr;

	/* Delete all the aggregators which are marked as
	 * OSPF6_ROUTE_AGGR_DEL.
	 */
	ospf6_delete_all_marked_aggregators(ospf6);

	for (rt = ospf6_route_head(ospf6->external_table); rt;
		rt = ospf6_route_next(rt)) {
		ei = rt->route_option;
		if (ei == NULL)
			continue;

		if (is_default_prefix(&rt->prefix))
			continue;

		aggr = ospf6_external_aggr_match(ospf6,
					&rt->prefix);

		/* If matching aggregator found, Add
		 * the external route refrenace to the
		 * aggregator and originate the aggr
		 * route if it is advertisable.
		 * flush the external LSA if it is
		 * already originated for this external
		 * prefix.
		 */
		if (aggr) {
			ospf6_originate_summary_lsa(ospf6, aggr, rt);

			/* All aggregated external rts
			 * are handled here.
			 */
			ospf6_handle_aggregated_exnl_rt(
				ospf6, aggr, rt);
			continue;
		}

		/* External routes which are only out
		 * of aggregation will be handled here.
		 */
		ospf6_handle_exnl_rt_after_aggr_del(
					ospf6, rt);
	}
}

static void ospf6_asbr_summary_process(struct event *thread)
{
	struct ospf6 *ospf6 = EVENT_ARG(thread);
	int operation = 0;

	operation = ospf6->aggr_action;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: operation:%d",
				__func__,
				operation);

	switch (operation) {
	case OSPF6_ROUTE_AGGR_ADD:
		ospf6_handle_external_aggr_add(ospf6);
		break;
	case OSPF6_ROUTE_AGGR_DEL:
	case OSPF6_ROUTE_AGGR_MODIFY:
		ospf6_handle_external_aggr_update(ospf6);
		break;
	default:
		break;
	}
}

static void
ospf6_start_asbr_summary_delay_timer(struct ospf6 *ospf6,
			struct ospf6_external_aggr_rt *aggr,
			ospf6_aggr_action_t operation)
{
	aggr->action = operation;

	if (event_is_scheduled(ospf6->t_external_aggr)) {
		if (ospf6->aggr_action == OSPF6_ROUTE_AGGR_ADD) {

			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s: Not required to restart timer,set is already added.",
					__func__);
			return;
		}

		if (operation == OSPF6_ROUTE_AGGR_ADD) {
			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s, Restarting Aggregator delay timer.",
							__func__);
			EVENT_OFF(ospf6->t_external_aggr);
		}
	}

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Start Aggregator delay timer %u(in seconds).",
			   __func__, ospf6->aggr_delay_interval);

	ospf6->aggr_action = operation;
	event_add_timer(master, ospf6_asbr_summary_process, ospf6,
			ospf6->aggr_delay_interval, &ospf6->t_external_aggr);
}

int ospf6_asbr_external_rt_advertise(struct ospf6 *ospf6,
				struct prefix *p)
{
	struct route_node *rn;
	struct ospf6_external_aggr_rt *aggr;

	rn = route_node_lookup(ospf6->rt_aggr_tbl, p);
	if (!rn)
		return OSPF6_INVALID;

	aggr = rn->info;

	route_unlock_node(rn);

	if (!CHECK_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE))
		return OSPF6_INVALID;

	UNSET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE);

	if (!OSPF6_EXTERNAL_RT_COUNT(aggr))
		return OSPF6_SUCCESS;

	ospf6_start_asbr_summary_delay_timer(ospf6, aggr,
					     OSPF6_ROUTE_AGGR_MODIFY);

	return OSPF6_SUCCESS;
}

int ospf6_external_aggr_delay_timer_set(struct ospf6 *ospf6, uint16_t interval)
{
	ospf6->aggr_delay_interval = interval;

	return OSPF6_SUCCESS;
}

static unsigned int ospf6_external_rt_hash_key(const void *data)
{
	const struct ospf6_route *rt = data;
	unsigned int key = 0;

	key = prefix_hash_key(&rt->prefix);
	return key;
}

static bool ospf6_external_rt_hash_cmp(const void *d1, const void *d2)
{
	const struct ospf6_route *rt1 = d1;
	const struct ospf6_route *rt2 = d2;

	return prefix_same(&rt1->prefix, &rt2->prefix);
}

static struct ospf6_external_aggr_rt *
ospf6_external_aggr_new(struct prefix *p)
{
	struct ospf6_external_aggr_rt *aggr;

	aggr = XCALLOC(MTYPE_OSPF6_EXTERNAL_RT_AGGR,
		       sizeof(struct ospf6_external_aggr_rt));

	prefix_copy(&aggr->p, p);
	aggr->metric = -1;
	aggr->mtype = DEFAULT_METRIC_TYPE;
	aggr->match_extnl_hash = hash_create(ospf6_external_rt_hash_key,
					     ospf6_external_rt_hash_cmp,
					     "Ospf6 external route hash");
	return aggr;
}

static void ospf6_external_aggr_add(struct ospf6 *ospf6,
		struct ospf6_external_aggr_rt *aggr)
{
	struct route_node *rn;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("%s: Adding Aggregate route to Aggr table (%pFX)",
					__func__,
					&aggr->p);

	rn = route_node_get(ospf6->rt_aggr_tbl, &aggr->p);
	if (rn->info)
		route_unlock_node(rn);
	else
		rn->info = aggr;
}

int ospf6_asbr_external_rt_no_advertise(struct ospf6 *ospf6,
				struct prefix *p)
{
	struct ospf6_external_aggr_rt *aggr;
	route_tag_t tag = 0;

	aggr = ospf6_external_aggr_config_lookup(ospf6, p);
	if (aggr) {
		if (CHECK_FLAG(aggr->aggrflags,
			OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE))
			return OSPF6_SUCCESS;

		SET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE);

		aggr->tag = tag;
		aggr->metric = -1;

		if (!OSPF6_EXTERNAL_RT_COUNT(aggr))
			return OSPF6_SUCCESS;

		ospf6_start_asbr_summary_delay_timer(ospf6, aggr,
			OSPF6_ROUTE_AGGR_MODIFY);
	} else {
		aggr = ospf6_external_aggr_new(p);

		if (!aggr)
			return OSPF6_FAILURE;

		SET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE);
		ospf6_external_aggr_add(ospf6, aggr);
		ospf6_start_asbr_summary_delay_timer(ospf6, aggr,
					OSPF6_ROUTE_AGGR_ADD);
	}

	return OSPF6_SUCCESS;
}

struct ospf6_external_aggr_rt *
ospf6_external_aggr_config_lookup(struct ospf6 *ospf6, struct prefix *p)
{
	struct route_node *rn;

	rn = route_node_lookup(ospf6->rt_aggr_tbl, p);
	if (rn) {
		route_unlock_node(rn);
		return rn->info;
	}

	return NULL;
}


int ospf6_external_aggr_config_set(struct ospf6 *ospf6, struct prefix *p,
				      route_tag_t tag, int metric, int mtype)
{
	struct ospf6_external_aggr_rt *aggregator;

	aggregator = ospf6_external_aggr_config_lookup(ospf6, p);

	if (aggregator) {
		if (CHECK_FLAG(aggregator->aggrflags,
			       OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE))
			UNSET_FLAG(aggregator->aggrflags,
				   OSPF6_EXTERNAL_AGGRT_NO_ADVERTISE);
		else if ((aggregator->tag == tag)
			 && (aggregator->metric == metric)
			 && (aggregator->mtype == mtype))
			return OSPF6_SUCCESS;

		aggregator->tag = tag;
		aggregator->metric = metric;
		aggregator->mtype = mtype;

		ospf6_start_asbr_summary_delay_timer(ospf6, aggregator,
					 OSPF6_ROUTE_AGGR_MODIFY);
	} else {
		aggregator = ospf6_external_aggr_new(p);
		if (!aggregator)
			return OSPF6_FAILURE;

		aggregator->tag = tag;
		aggregator->metric = metric;
		aggregator->mtype = mtype;

		ospf6_external_aggr_add(ospf6, aggregator);
		ospf6_start_asbr_summary_delay_timer(ospf6, aggregator,
						OSPF6_ROUTE_AGGR_ADD);
	}

	return OSPF6_SUCCESS;
}

int ospf6_external_aggr_config_unset(struct ospf6 *ospf6,
					struct prefix *p)
{
	struct route_node *rn;
	struct ospf6_external_aggr_rt *aggr;

	rn = route_node_lookup(ospf6->rt_aggr_tbl, p);
	if (!rn)
		return OSPF6_INVALID;

	aggr = rn->info;

	route_unlock_node(rn);

	if (!OSPF6_EXTERNAL_RT_COUNT(aggr)) {
		ospf6_asbr_summary_config_delete(ospf6, rn);
		ospf6_external_aggregator_free(aggr);
		return OSPF6_SUCCESS;
	}

	ospf6_start_asbr_summary_delay_timer(ospf6, aggr,
				OSPF6_ROUTE_AGGR_DEL);

	return OSPF6_SUCCESS;
}

void ospf6_handle_external_lsa_origination(struct ospf6 *ospf6,
					       struct ospf6_route *rt,
					       struct prefix *p)
{

	struct ospf6_external_aggr_rt *aggr;
	struct ospf6_external_info *info;
	struct prefix prefix_id;

	if (!is_default_prefix(p)) {
		aggr = ospf6_external_aggr_match(ospf6,
						p);

		if (aggr) {

			if (IS_OSPF6_DEBUG_AGGR)
				zlog_debug("%s: Send Aggregate LSA (%pFX)",
				__func__,
				&aggr->p);

			ospf6_originate_summary_lsa(
				ospf6, aggr, rt);

			/* Handling the case where the
			 * external route prefix
			 * and aggegate prefix is same
			 * If same don't flush the
			 * originated
			 * external LSA.
			 */
			ospf6_handle_aggregated_exnl_rt(
					ospf6, aggr, rt);
			return;
		}
	}

	info = rt->route_option;

	/* When the info->id = 0, it means it is being originated for the
	 * first time.
	 */
	if (!info->id) {
		info->id = ospf6->external_id++;
	} else {
		prefix_id.family = AF_INET;
		prefix_id.prefixlen = 32;
		prefix_id.u.prefix4.s_addr = htonl(info->id);
	}

	rt->path.origin.id = htonl(info->id);

	if (IS_OSPF6_DEBUG_ASBR) {
		zlog_debug("Advertise new AS-External Id:%pI4 prefix %pFX metric %u",
			   &prefix_id.u.prefix4, p, rt->path.metric_type);
	}

	ospf6_originate_type5_type7_lsas(rt, ospf6);

}

void ospf6_unset_all_aggr_flag(struct ospf6 *ospf6)
{
	struct route_node *rn = NULL;
	struct ospf6_external_aggr_rt *aggr;

	if (IS_OSPF6_DEBUG_AGGR)
		zlog_debug("Unset the origination bit for all aggregator");

	/* Resetting the running external ID counter so that the origination
	 * of external LSAs starts from the beginning 0.0.0.1
	 */
	ospf6->external_id = OSPF6_EXT_INIT_LS_ID;

	for (rn = route_top(ospf6->rt_aggr_tbl); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		aggr = rn->info;

		UNSET_FLAG(aggr->aggrflags, OSPF6_EXTERNAL_AGGRT_ORIGINATED);
	}
}
