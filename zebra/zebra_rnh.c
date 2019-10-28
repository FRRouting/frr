/* Zebra next hop tracking code
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"
#include "vrf.h"

#include "zebra/zebra_router.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/interface.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_errors.h"

DEFINE_MTYPE_STATIC(ZEBRA, RNH, "Nexthop tracking object")

static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn);
static void copy_state(struct rnh *rnh, struct route_entry *re,
		       struct route_node *rn);
static int compare_state(struct route_entry *r1, struct route_entry *r2);
static int send_client(struct rnh *rnh, struct zserv *client, rnh_type_t type,
		       vrf_id_t vrf_id);
static void print_rnh(struct route_node *rn, struct vty *vty);
static int zebra_client_cleanup_rnh(struct zserv *client);

void zebra_rnh_init(void)
{
	hook_register(zserv_client_close, zebra_client_cleanup_rnh);
}

static inline struct route_table *get_rnh_table(vrf_id_t vrfid, afi_t afi,
						rnh_type_t type)
{
	struct zebra_vrf *zvrf;
	struct route_table *t = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrfid);
	if (zvrf)
		switch (type) {
		case RNH_NEXTHOP_TYPE:
			t = zvrf->rnh_table[afi];
			break;
		case RNH_IMPORT_CHECK_TYPE:
			t = zvrf->import_check_table[afi];
			break;
		}

	return t;
}

char *rnh_str(struct rnh *rnh, char *buf, int size)
{
	prefix2str(&(rnh->node->p), buf, size);
	return buf;
}

static void zebra_rnh_remove_from_routing_table(struct rnh *rnh)
{
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	struct route_table *table = zvrf->table[rnh->afi][SAFI_UNICAST];
	struct route_node *rn;
	rib_dest_t *dest;

	if (!table)
		return;

	rn = route_node_match(table, &rnh->resolved_route);
	if (!rn)
		return;

	if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
		char buf[PREFIX_STRLEN];
		char buf1[PREFIX_STRLEN];

		zlog_debug("%s: %u:%s removed from tracking on %s",
			   __PRETTY_FUNCTION__, rnh->vrf_id,
			   prefix2str(&rnh->node->p, buf, sizeof(buf)),
			   srcdest_rnode2str(rn, buf1, sizeof(buf)));
	}

	dest = rib_dest_from_rnode(rn);
	rnh_list_del(&dest->nht, rnh);
	route_unlock_node(rn);
}

static void zebra_rnh_store_in_routing_table(struct rnh *rnh)
{
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	struct route_table *table = zvrf->table[rnh->afi][SAFI_UNICAST];
	struct route_node *rn;
	rib_dest_t *dest;

	rn = route_node_match(table, &rnh->resolved_route);
	if (!rn)
		return;

	if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
		char buf[PREFIX_STRLEN];
		char buf1[PREFIX_STRLEN];

		zlog_debug("%s: %u:%s added for tracking on %s",
			   __PRETTY_FUNCTION__, rnh->vrf_id,
			   prefix2str(&rnh->node->p, buf, sizeof(buf)),
			   srcdest_rnode2str(rn, buf1, sizeof(buf)));
	}

	dest = rib_dest_from_rnode(rn);
	rnh_list_add_tail(&dest->nht, rnh);
	route_unlock_node(rn);
}

struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid, rnh_type_t type,
			  bool *exists)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh *rnh = NULL;
	char buf[PREFIX2STR_BUFFER];
	afi_t afi = family2afi(p->family);

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(p, buf, sizeof(buf));
		zlog_debug("%u: Add RNH %s type %s", vrfid, buf,
			   rnh_type2str(type));
	}
	table = get_rnh_table(vrfid, afi, type);
	if (!table) {
		prefix2str(p, buf, sizeof(buf));
		flog_warn(EC_ZEBRA_RNH_NO_TABLE,
			  "%u: Add RNH %s type %s - table not found", vrfid,
			  buf, rnh_type2str(type));
		exists = false;
		return NULL;
	}

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(table, p);

	if (!rn->info) {
		rnh = XCALLOC(MTYPE_RNH, sizeof(struct rnh));

		/*
		 * The resolved route is already 0.0.0.0/0 or
		 * 0::0/0 due to the calloc right above, but
		 * we should set the family so that future
		 * comparisons can just be done
		 */
		rnh->resolved_route.family = p->family;
		rnh->client_list = list_new();
		rnh->vrf_id = vrfid;
		rnh->type = type;
		rnh->seqno = 0;
		rnh->afi = afi;
		rnh->zebra_pseudowire_list = list_new();
		route_lock_node(rn);
		rn->info = rnh;
		rnh->node = rn;
		*exists = false;

		zebra_rnh_store_in_routing_table(rnh);
	} else
		*exists = true;

	route_unlock_node(rn);
	return (rn->info);
}

struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid, rnh_type_t type)
{
	struct route_table *table;
	struct route_node *rn;

	table = get_rnh_table(vrfid, family2afi(PREFIX_FAMILY(p)), type);
	if (!table)
		return NULL;

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup route node.*/
	rn = route_node_lookup(table, p);
	if (!rn)
		return NULL;

	route_unlock_node(rn);
	return (rn->info);
}

void zebra_free_rnh(struct rnh *rnh)
{
	struct zebra_vrf *zvrf;
	struct route_table *table;

	zebra_rnh_remove_from_routing_table(rnh);
	rnh->flags |= ZEBRA_NHT_DELETED;
	list_delete(&rnh->client_list);
	list_delete(&rnh->zebra_pseudowire_list);

	zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	table = zvrf->table[family2afi(rnh->resolved_route.family)][SAFI_UNICAST];

	if (table) {
		struct route_node *rern;

		rern = route_node_match(table, &rnh->resolved_route);
		if (rern) {
			rib_dest_t *dest;

			route_unlock_node(rern);

			dest = rib_dest_from_rnode(rern);
			rnh_list_del(&dest->nht, rnh);
		}
	}
	free_state(rnh->vrf_id, rnh->state, rnh->node);
	XFREE(MTYPE_RNH, rnh);
}

static void zebra_delete_rnh(struct rnh *rnh, rnh_type_t type)
{
	struct route_node *rn;

	if (!list_isempty(rnh->client_list)
	    || !list_isempty(rnh->zebra_pseudowire_list))
		return;

	if ((rnh->flags & ZEBRA_NHT_DELETED) || !(rn = rnh->node))
		return;

	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("%u: Del RNH %s type %s", rnh->vrf_id,
			   rnh_str(rnh, buf, sizeof(buf)), rnh_type2str(type));
	}

	zebra_free_rnh(rnh);
	rn->info = NULL;
	route_unlock_node(rn);
}

/*
 * This code will send to the registering client
 * the looked up rnh.
 * For a rnh that was created, there is no data
 * so it will send an empty nexthop group
 * If rnh exists then we know it has been evaluated
 * and as such it will have a resolved rnh.
 */
void zebra_add_rnh_client(struct rnh *rnh, struct zserv *client,
			  rnh_type_t type, vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("%u: Client %s registers for RNH %s type %s", vrf_id,
			   zebra_route_string(client->proto),
			   rnh_str(rnh, buf, sizeof(buf)), rnh_type2str(type));
	}
	if (!listnode_lookup(rnh->client_list, client))
		listnode_add(rnh->client_list, client);

	/*
	 * We always need to respond with known information,
	 * currently multiple daemons expect this behavior
	 */
	send_client(rnh, client, type, vrf_id);
}

void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client,
			     rnh_type_t type)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("Client %s unregisters for RNH %s type %s",
			   zebra_route_string(client->proto),
			   rnh_str(rnh, buf, sizeof(buf)), rnh_type2str(type));
	}
	listnode_delete(rnh->client_list, client);
	zebra_delete_rnh(rnh, type);
}

/* XXX move this utility function elsewhere? */
static void addr2hostprefix(int af, const union g_addr *addr,
			    struct prefix *prefix)
{
	switch (af) {
	case AF_INET:
		prefix->family = AF_INET;
		prefix->prefixlen = IPV4_MAX_BITLEN;
		prefix->u.prefix4 = addr->ipv4;
		break;
	case AF_INET6:
		prefix->family = AF_INET6;
		prefix->prefixlen = IPV6_MAX_BITLEN;
		prefix->u.prefix6 = addr->ipv6;
		break;
	default:
		memset(prefix, 0, sizeof(*prefix));
		zlog_warn("%s: unknown address family %d", __func__, af);
		break;
	}
}

void zebra_register_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw)
{
	struct prefix nh;
	struct rnh *rnh;
	bool exists;
	struct zebra_vrf *zvrf;

	zvrf = vrf_info_lookup(vrf_id);
	if (!zvrf)
		return;

	addr2hostprefix(pw->af, &pw->nexthop, &nh);
	rnh = zebra_add_rnh(&nh, vrf_id, RNH_NEXTHOP_TYPE, &exists);
	if (rnh && !listnode_lookup(rnh->zebra_pseudowire_list, pw)) {
		listnode_add(rnh->zebra_pseudowire_list, pw);
		pw->rnh = rnh;
		zebra_evaluate_rnh(zvrf, family2afi(pw->af), 1,
				   RNH_NEXTHOP_TYPE, &nh);
	}
}

void zebra_deregister_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw)
{
	struct rnh *rnh;

	rnh = pw->rnh;
	if (!rnh)
		return;

	listnode_delete(rnh->zebra_pseudowire_list, pw);
	pw->rnh = NULL;

	zebra_delete_rnh(rnh, RNH_NEXTHOP_TYPE);
}

/* Clear the NEXTHOP_FLAG_RNH_FILTERED flags on all nexthops
 */
static void zebra_rnh_clear_nexthop_rnh_filters(struct route_entry *re)
{
	struct nexthop *nexthop;

	if (re) {
		for (nexthop = re->ng->nexthop; nexthop;
		     nexthop = nexthop->next) {
			UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_RNH_FILTERED);
		}
	}
}

/* Apply the NHT route-map for a client to the route (and nexthops)
 * resolving a NH.
 */
static int zebra_rnh_apply_nht_rmap(afi_t afi, struct zebra_vrf *zvrf,
				    struct route_node *prn,
				    struct route_entry *re, int proto)
{
	int at_least_one = 0;
	struct nexthop *nexthop;
	route_map_result_t ret;

	if (prn && re) {
		for (nexthop = re->ng->nexthop; nexthop;
		     nexthop = nexthop->next) {
			ret = zebra_nht_route_map_check(
				afi, proto, &prn->p, zvrf, re, nexthop);
			if (ret != RMAP_DENYMATCH)
				at_least_one++; /* at least one valid NH */
			else {
				SET_FLAG(nexthop->flags,
						NEXTHOP_FLAG_RNH_FILTERED);
			}
		}
	}
	return (at_least_one);
}

/*
 * Determine appropriate route (RE entry) resolving a tracked BGP route
 * for BGP route for import.
 */
static struct route_entry *
zebra_rnh_resolve_import_entry(struct zebra_vrf *zvrf, afi_t afi,
			       struct route_node *nrn, struct rnh *rnh,
			       struct route_node **prn)
{
	struct route_table *route_table;
	struct route_node *rn;
	struct route_entry *re;

	*prn = NULL;

	route_table = zvrf->table[afi][SAFI_UNICAST];
	if (!route_table) // unexpected
		return NULL;

	rn = route_node_match(route_table, &nrn->p);
	if (!rn)
		return NULL;

	/* Unlock route node - we don't need to lock when walking the tree. */
	route_unlock_node(rn);

	if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH)
	    && !prefix_same(&nrn->p, &rn->p))
		return NULL;

	if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
		char buf[PREFIX_STRLEN];
		char buf1[PREFIX_STRLEN];

		zlog_debug("%s: %u:%s Resolved Import Entry to %s",
			   __PRETTY_FUNCTION__, rnh->vrf_id,
			   prefix2str(&rnh->node->p, buf, sizeof(buf)),
			   srcdest_rnode2str(rn, buf1, sizeof(buf)));
	}

	/* Identify appropriate route entry. */
	RNODE_FOREACH_RE (rn, re) {
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)
		    && CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)
		    && !CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED)
		    && (re->type != ZEBRA_ROUTE_BGP))
			break;
	}

	if (re)
		*prn = rn;

	if (!re && IS_ZEBRA_DEBUG_NHT_DETAILED)
		zlog_debug("\tRejected due to removed or is a bgp route");

	return re;
}

/*
 * See if a tracked route entry for import (by BGP) has undergone any
 * change, and if so, notify the client.
 */
static void zebra_rnh_eval_import_check_entry(struct zebra_vrf *zvrf, afi_t afi,
					      int force, struct route_node *nrn,
					      struct rnh *rnh,
					      struct route_node *prn,
					      struct route_entry *re)
{
	int state_changed = 0;
	struct zserv *client;
	char bufn[INET6_ADDRSTRLEN];
	struct listnode *node;

	zebra_rnh_remove_from_routing_table(rnh);
	if (prn) {
		prefix_copy(&rnh->resolved_route, &prn->p);
	} else {
		int family = rnh->resolved_route.family;

		memset(&rnh->resolved_route.family, 0, sizeof(struct prefix));
		rnh->resolved_route.family = family;
	}
	zebra_rnh_store_in_routing_table(rnh);

	if (re && (rnh->state == NULL)) {
		if (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED))
			state_changed = 1;
	} else if (!re && (rnh->state != NULL))
		state_changed = 1;

	if (compare_state(re, rnh->state)) {
		copy_state(rnh, re, nrn);
		state_changed = 1;
	}

	if (state_changed || force) {
		if (IS_ZEBRA_DEBUG_NHT) {
			prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
			zlog_debug("%u:%s: Route import check %s %s",
				   zvrf->vrf->vrf_id,
				   bufn, rnh->state ? "passed" : "failed",
				   state_changed ? "(state changed)" : "");
		}
		/* state changed, notify clients */
		for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
			send_client(rnh, client,
				    RNH_IMPORT_CHECK_TYPE, zvrf->vrf->vrf_id);
		}
	}
}

/*
 * Notify clients registered for this nexthop about a change.
 */
static void zebra_rnh_notify_protocol_clients(struct zebra_vrf *zvrf, afi_t afi,
					      struct route_node *nrn,
					      struct rnh *rnh,
					      struct route_node *prn,
					      struct route_entry *re)
{
	struct listnode *node;
	struct zserv *client;
	char bufn[INET6_ADDRSTRLEN];
	char bufp[INET6_ADDRSTRLEN];
	int num_resolving_nh;

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
		if (prn && re) {
			srcdest_rnode2str(prn, bufp, INET6_ADDRSTRLEN);
			zlog_debug("%u:%s: NH resolved over route %s",
				   zvrf->vrf->vrf_id, bufn, bufp);
		} else
			zlog_debug("%u:%s: NH has become unresolved",
				   zvrf->vrf->vrf_id, bufn);
	}

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
		if (prn && re) {
			/* Apply route-map for this client to route resolving
			 * this
			 * nexthop to see if it is filtered or not.
			 */
			zebra_rnh_clear_nexthop_rnh_filters(re);
			num_resolving_nh = zebra_rnh_apply_nht_rmap(
				afi, zvrf, prn, re, client->proto);
			if (num_resolving_nh)
				rnh->filtered[client->proto] = 0;
			else
				rnh->filtered[client->proto] = 1;

			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug(
					"%u:%s: Notifying client %s about NH %s",
					zvrf->vrf->vrf_id, bufn,
					zebra_route_string(client->proto),
					num_resolving_nh
						? ""
						: "(filtered by route-map)");
		} else {
			rnh->filtered[client->proto] = 0;
			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug(
					"%u:%s: Notifying client %s about NH (unreachable)",
					zvrf->vrf->vrf_id, bufn,
					zebra_route_string(client->proto));
		}

		send_client(rnh, client, RNH_NEXTHOP_TYPE, zvrf->vrf->vrf_id);
	}

	if (re)
		zebra_rnh_clear_nexthop_rnh_filters(re);
}

/*
 * Utility to determine whether a candidate nexthop is useable. We make this
 * check in a couple of places, so this is a single home for the logic we
 * use.
 */
static bool rnh_nexthop_valid(const struct route_entry *re,
			      const struct nexthop *nh)
{
	return (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)
		&& CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE)
		&& !CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RECURSIVE)
		&& !CHECK_FLAG(nh->flags, NEXTHOP_FLAG_DUPLICATE)
		&& !CHECK_FLAG(nh->flags, NEXTHOP_FLAG_RNH_FILTERED));
}

/*
 * Determine appropriate route (route entry) resolving a tracked
 * nexthop.
 */
static struct route_entry *
zebra_rnh_resolve_nexthop_entry(struct zebra_vrf *zvrf, afi_t afi,
				struct route_node *nrn, struct rnh *rnh,
				struct route_node **prn)
{
	struct route_table *route_table;
	struct route_node *rn;
	struct route_entry *re;
	struct nexthop *nexthop;

	*prn = NULL;

	route_table = zvrf->table[afi][SAFI_UNICAST];
	if (!route_table)
		return NULL;

	rn = route_node_match(route_table, &nrn->p);
	if (!rn)
		return NULL;

	/* Unlock route node - we don't need to lock when walking the tree. */
	route_unlock_node(rn);

	/* While resolving nexthops, we may need to walk up the tree from the
	 * most-specific match. Do similar logic as in zebra_rib.c
	 */
	while (rn) {
		if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
			char buf[PREFIX_STRLEN];
			char buf1[PREFIX_STRLEN];

			zlog_debug("%s: %u:%s Possible Match to %s",
				   __PRETTY_FUNCTION__, rnh->vrf_id,
				   prefix2str(&rnh->node->p, buf, sizeof(buf)),
				   srcdest_rnode2str(rn, buf1, sizeof(buf)));
		}

		/* Do not resolve over default route unless allowed &&
		 * match route to be exact if so specified
		 */
		if (is_default_prefix(&rn->p)
		    && !rnh_resolve_via_default(zvrf, rn->p.family)) {
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug(
					"\tNot allowed to resolve through default prefix");
			return NULL;
		}

		/* Identify appropriate route entry. */
		RNODE_FOREACH_RE (rn, re) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"\tRoute Entry %s removed",
						zebra_route_string(re->type));
				continue;
			}
			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"\tRoute Entry %s !selected",
						zebra_route_string(re->type));
				continue;
			}

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"\tRoute Entry %s queued",
						zebra_route_string(re->type));
				continue;
			}

			/* Just being SELECTED isn't quite enough - must
			 * have an installed nexthop to be useful.
			 */
			for (ALL_NEXTHOPS_PTR(re->ng, nexthop)) {
				if (rnh_nexthop_valid(re, nexthop))
					break;
			}

			if (nexthop == NULL) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"\tRoute Entry %s no nexthops",
						zebra_route_string(re->type));
				continue;
			}

			if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)) {
				if ((re->type == ZEBRA_ROUTE_CONNECT)
				    || (re->type == ZEBRA_ROUTE_STATIC))
					break;
				if (re->type == ZEBRA_ROUTE_NHRP) {

					for (nexthop = re->ng->nexthop; nexthop;
					     nexthop = nexthop->next)
						if (nexthop->type
						    == NEXTHOP_TYPE_IFINDEX)
							break;
					if (nexthop)
						break;
				}
			} else
				break;
		}

		/* Route entry found, we're done; else, walk up the tree. */
		if (re) {
			*prn = rn;
			return re;
		}

		if (!CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
			rn = rn->parent;
		else {
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug(
					"\tNexthop must be connected, cannot recurse up");
			return NULL;
		}
	}

	return NULL;
}

static void zebra_rnh_process_pseudowires(vrf_id_t vrfid, struct rnh *rnh)
{
	struct zebra_pw *pw;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rnh->zebra_pseudowire_list, node, pw))
		zebra_pw_update(pw);
}

/*
 * See if a tracked nexthop entry has undergone any change, and if so,
 * take appropriate action; this involves notifying any clients and/or
 * scheduling dependent static routes for processing.
 */
static void zebra_rnh_eval_nexthop_entry(struct zebra_vrf *zvrf, afi_t afi,
					 int force, struct route_node *nrn,
					 struct rnh *rnh,
					 struct route_node *prn,
					 struct route_entry *re)
{
	int state_changed = 0;

	/* If we're resolving over a different route, resolution has changed or
	 * the resolving route has some change (e.g., metric), there is a state
	 * change.
	 */
	zebra_rnh_remove_from_routing_table(rnh);
	if (!prefix_same(&rnh->resolved_route, prn ? &prn->p : NULL)) {
		if (prn)
			prefix_copy(&rnh->resolved_route, &prn->p);
		else {
			/*
			 * Just quickly store the family of the resolved
			 * route so that we can reset it in a second here
			 */
			int family = rnh->resolved_route.family;

			memset(&rnh->resolved_route, 0, sizeof(struct prefix));
			rnh->resolved_route.family = family;
		}

		copy_state(rnh, re, nrn);
		state_changed = 1;
	} else if (compare_state(re, rnh->state)) {
		copy_state(rnh, re, nrn);
		state_changed = 1;
	}
	zebra_rnh_store_in_routing_table(rnh);

	if (state_changed || force) {
		/* NOTE: Use the "copy" of resolving route stored in 'rnh' i.e.,
		 * rnh->state.
		 */
		/* Notify registered protocol clients. */
		zebra_rnh_notify_protocol_clients(zvrf, afi, nrn, rnh, prn,
						  rnh->state);

		/* Process pseudowires attached to this nexthop */
		zebra_rnh_process_pseudowires(zvrf->vrf->vrf_id, rnh);
	}
}

/* Evaluate one tracked entry */
static void zebra_rnh_evaluate_entry(struct zebra_vrf *zvrf, afi_t afi,
				     int force, rnh_type_t type,
				     struct route_node *nrn)
{
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;
	char bufn[INET6_ADDRSTRLEN];

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
		zlog_debug("%u:%s: Evaluate RNH, type %s %s", zvrf->vrf->vrf_id,
			   bufn, rnh_type2str(type), force ? "(force)" : "");
	}

	rnh = nrn->info;

	/* Identify route entry (RE) resolving this tracked entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		re = zebra_rnh_resolve_import_entry(zvrf, afi, nrn, rnh, &prn);
	else
		re = zebra_rnh_resolve_nexthop_entry(zvrf, afi, nrn, rnh, &prn);

	/* If the entry cannot be resolved and that is also the existing state,
	 * there is nothing further to do.
	 */
	if (!re && rnh->state == NULL && !force)
		return;

	/* Process based on type of entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		zebra_rnh_eval_import_check_entry(zvrf, afi, force, nrn, rnh,
						  prn, re);
	else
		zebra_rnh_eval_nexthop_entry(zvrf, afi, force, nrn, rnh, prn,
					     re);
}

/*
 * Clear the ROUTE_ENTRY_NEXTHOPS_CHANGED flag
 * from the re entries.
 *
 * Please note we are doing this *after* we have
 * notified the world about each nexthop as that
 * we can have a situation where one re entry
 * covers multiple nexthops we are interested in.
 */
static void zebra_rnh_clear_nhc_flag(struct zebra_vrf *zvrf, afi_t afi,
				     rnh_type_t type, struct route_node *nrn)
{
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	rnh = nrn->info;

	/* Identify route entry (RIB) resolving this tracked entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		re = zebra_rnh_resolve_import_entry(zvrf, afi, nrn, rnh,
						    &prn);
	else
		re = zebra_rnh_resolve_nexthop_entry(zvrf, afi, nrn, rnh,
						     &prn);

	if (re)
		UNSET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);
}

/* Evaluate all tracked entries (nexthops or routes for import into BGP)
 * of a particular VRF and address-family or a specific prefix.
 */
void zebra_evaluate_rnh(struct zebra_vrf *zvrf, afi_t afi, int force,
			rnh_type_t type, struct prefix *p)
{
	struct route_table *rnh_table;
	struct route_node *nrn;

	rnh_table = get_rnh_table(zvrf->vrf->vrf_id, afi, type);
	if (!rnh_table) // unexpected
		return;

	if (p) {
		/* Evaluating a specific entry, make sure it exists. */
		nrn = route_node_lookup(rnh_table, p);
		if (nrn && nrn->info)
			zebra_rnh_evaluate_entry(zvrf, afi, force, type, nrn);

		if (nrn)
			route_unlock_node(nrn);
	} else {
		/* Evaluate entire table. */
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_evaluate_entry(zvrf, afi, force, type,
							 nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_clear_nhc_flag(zvrf, afi, type, nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
	}
}

void zebra_print_rnh_table(vrf_id_t vrfid, afi_t afi, struct vty *vty,
			   rnh_type_t type, struct prefix *p)
{
	struct route_table *table;
	struct route_node *rn;

	table = get_rnh_table(vrfid, afi, type);
	if (!table) {
		if (IS_ZEBRA_DEBUG_NHT)
			zlog_debug("print_rnhs: rnh table not found");
		return;
	}

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		if (p && !prefix_match(&rn->p, p))
			continue;

		if (rn->info)
			print_rnh(rn, vty);
	}
}

/**
 * free_state - free up the re structure associated with the rnh.
 */
static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn)
{
	if (!re)
		return;

	/* free RE and nexthops */
	nexthop_group_delete(&re->ng);
	XFREE(MTYPE_RE, re);
}

static void copy_state(struct rnh *rnh, struct route_entry *re,
		       struct route_node *rn)
{
	struct route_entry *state;

	if (rnh->state) {
		free_state(rnh->vrf_id, rnh->state, rn);
		rnh->state = NULL;
	}

	if (!re)
		return;

	state = XCALLOC(MTYPE_RE, sizeof(struct route_entry));
	state->type = re->type;
	state->distance = re->distance;
	state->metric = re->metric;
	state->vrf_id = re->vrf_id;
	state->status = re->status;
	state->ng = nexthop_group_new();

	route_entry_copy_nexthops(state, re->ng->nexthop);
	rnh->state = state;
}

static int compare_state(struct route_entry *r1, struct route_entry *r2)
{
	if (!r1 && !r2)
		return 0;

	if ((!r1 && r2) || (r1 && !r2))
		return 1;

	if (r1->distance != r2->distance)
		return 1;

	if (r1->metric != r2->metric)
		return 1;

	if (nexthop_group_nexthop_num(r1->ng)
	    != nexthop_group_nexthop_num(r2->ng))
		return 1;

	if (nexthop_group_hash(r1->ng) != nexthop_group_hash(r2->ng))
		return 1;

	return 0;
}

static int send_client(struct rnh *rnh, struct zserv *client, rnh_type_t type,
		       vrf_id_t vrf_id)
{
	struct stream *s;
	struct route_entry *re;
	unsigned long nump;
	uint8_t num;
	struct nexthop *nh;
	struct route_node *rn;
	int cmd = (type == RNH_IMPORT_CHECK_TYPE) ? ZEBRA_IMPORT_CHECK_UPDATE
						  : ZEBRA_NEXTHOP_UPDATE;

	rn = rnh->node;
	re = rnh->state;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, vrf_id);

	stream_putw(s, rn->p.family);
	switch (rn->p.family) {
	case AF_INET:
		stream_putc(s, rn->p.prefixlen);
		stream_put_in_addr(s, &rn->p.u.prefix4);
		break;
	case AF_INET6:
		stream_putc(s, rn->p.prefixlen);
		stream_put(s, &rn->p.u.prefix6, IPV6_MAX_BYTELEN);
		break;
	default:
		flog_err(EC_ZEBRA_RNH_UNKNOWN_FAMILY,
			 "%s: Unknown family (%d) notification attempted\n",
			 __FUNCTION__, rn->p.family);
		break;
	}
	if (re) {
		stream_putc(s, re->type);
		stream_putw(s, re->instance);
		stream_putc(s, re->distance);
		stream_putl(s, re->metric);
		num = 0;
		nump = stream_get_endp(s);
		stream_putc(s, 0);
		for (ALL_NEXTHOPS_PTR(re->ng, nh))
			if (rnh_nexthop_valid(re, nh)) {
				stream_putl(s, nh->vrf_id);
				stream_putc(s, nh->type);
				switch (nh->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					stream_put_in_addr(s, &nh->gate.ipv4);
					stream_putl(s, nh->ifindex);
					break;
				case NEXTHOP_TYPE_IFINDEX:
					stream_putl(s, nh->ifindex);
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					stream_put(s, &nh->gate.ipv6, 16);
					stream_putl(s, nh->ifindex);
					break;
				default:
					/* do nothing */
					break;
				}
				if (nh->nh_label) {
					stream_putc(s,
						    nh->nh_label->num_labels);
					if (nh->nh_label->num_labels)
						stream_put(
							s,
							&nh->nh_label->label[0],
							nh->nh_label->num_labels
								* sizeof(mpls_label_t));
				} else
					stream_putc(s, 0);
				num++;
			}
		stream_putc_at(s, nump, num);
	} else {
		stream_putc(s, 0); // type
		stream_putw(s, 0); // instance
		stream_putc(s, 0); // distance
		stream_putl(s, 0); // metric
		stream_putc(s, 0); // nexthops
	}
	stream_putw_at(s, 0, stream_get_endp(s));

	client->nh_last_upd_time = monotime(NULL);
	client->last_write_cmd = cmd;
	return zserv_send_message(client, s);
}

static void print_nh(struct nexthop *nexthop, struct vty *vty)
{
	char buf[BUFSIZ];
	struct zebra_ns *zns = zebra_ns_lookup(nexthop->vrf_id);

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, " via %s", inet_ntoa(nexthop->gate.ipv4));
		if (nexthop->ifindex)
			vty_out(vty, ", %s",
				ifindex2ifname_per_ns(zns, nexthop->ifindex));
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, " %s",
			inet_ntop(AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
		if (nexthop->ifindex)
			vty_out(vty, ", via %s",
				ifindex2ifname_per_ns(zns, nexthop->ifindex));
		break;
	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty, " is directly connected, %s",
			ifindex2ifname_per_ns(zns, nexthop->ifindex));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		vty_out(vty, " is directly connected, Null0");
		break;
	default:
		break;
	}
	vty_out(vty, "\n");
}

static void print_rnh(struct route_node *rn, struct vty *vty)
{
	struct rnh *rnh;
	struct nexthop *nexthop;
	struct listnode *node;
	struct zserv *client;
	char buf[BUFSIZ];

	rnh = rn->info;
	vty_out(vty, "%s%s\n",
		inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
		CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED) ? "(Connected)"
							    : "");
	if (rnh->state) {
		vty_out(vty, " resolved via %s\n",
			zebra_route_string(rnh->state->type));
		for (nexthop = rnh->state->ng->nexthop; nexthop;
		     nexthop = nexthop->next)
			print_nh(nexthop, vty);
	} else
		vty_out(vty, " unresolved%s\n",
			CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)
				? "(Connected)"
				: "");

	vty_out(vty, " Client list:");
	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client))
		vty_out(vty, " %s(fd %d)%s", zebra_route_string(client->proto),
			client->sock,
			rnh->filtered[client->proto] ? "(filtered)" : "");
	if (!list_isempty(rnh->zebra_pseudowire_list))
		vty_out(vty, " zebra[pseudowires]");
	vty_out(vty, "\n");
}

static int zebra_cleanup_rnh_client(vrf_id_t vrf_id, afi_t afi,
				    struct zserv *client, rnh_type_t type)
{
	struct route_table *ntable;
	struct route_node *nrn;
	struct rnh *rnh;

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug("%u: Client %s RNH cleanup for family %s type %s",
			   vrf_id, zebra_route_string(client->proto),
			   afi2str(afi), rnh_type2str(type));

	ntable = get_rnh_table(vrf_id, afi, type);
	if (!ntable) {
		zlog_debug("cleanup_rnh_client: rnh table not found");
		return -1;
	}

	for (nrn = route_top(ntable); nrn; nrn = route_next(nrn)) {
		if (!nrn->info)
			continue;

		rnh = nrn->info;
		zebra_remove_rnh_client(rnh, client, type);
	}
	return 1;
}

/* Cleanup registered nexthops (across VRFs) upon client disconnect. */
static int zebra_client_cleanup_rnh(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		if (zvrf) {
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP, client,
						 RNH_NEXTHOP_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP6, client,
						 RNH_NEXTHOP_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP, client,
						 RNH_IMPORT_CHECK_TYPE);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP6, client,
						 RNH_IMPORT_CHECK_TYPE);
		}
	}

	return 0;
}

int rnh_resolve_via_default(struct zebra_vrf *zvrf, int family)
{
	if (((family == AF_INET) && zvrf->zebra_rnh_ip_default_route)
	    || ((family == AF_INET6) && zvrf->zebra_rnh_ipv6_default_route))
		return 1;
	else
		return 0;
}
