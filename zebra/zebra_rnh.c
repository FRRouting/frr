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

static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn);
static void copy_state(struct rnh *rnh, struct route_entry *re,
		       struct route_node *rn);
#define lookup_rnh_table(v, f)                                                 \
	({                                                                     \
		struct zebra_vrf *zvrf;                                        \
		struct route_table *t = NULL;                                  \
		zvrf = zebra_vrf_lookup_by_id(v);                              \
		if (zvrf)                                                      \
			t = zvrf->rnh_table[family2afi(f)];                    \
		t;                                                             \
	})

static int compare_state(struct route_entry *r1, struct route_entry *r2);
static int send_client(struct rnh *rnh, struct zserv *client, rnh_type_t type,
		       vrf_id_t vrf_id);
static void print_rnh(struct route_node *rn, struct vty *vty);

int zebra_rnh_ip_default_route = 0;
int zebra_rnh_ipv6_default_route = 0;

static inline struct route_table *get_rnh_table(vrf_id_t vrfid, int family,
						rnh_type_t type)
{
	struct zebra_vrf *zvrf;
	struct route_table *t = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrfid);
	if (zvrf)
		switch (type) {
		case RNH_NEXTHOP_TYPE:
			t = zvrf->rnh_table[family2afi(family)];
			break;
		case RNH_IMPORT_CHECK_TYPE:
			t = zvrf->import_check_table[family2afi(family)];
			break;
		}

	return t;
}

char *rnh_str(struct rnh *rnh, char *buf, int size)
{
	prefix2str(&(rnh->node->p), buf, size);
	return buf;
}

struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid, rnh_type_t type)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh *rnh = NULL;
	char buf[PREFIX2STR_BUFFER];

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(p, buf, sizeof(buf));
		zlog_debug("%u: Add RNH %s type %d", vrfid, buf, type);
	}
	table = get_rnh_table(vrfid, PREFIX_FAMILY(p), type);
	if (!table) {
		prefix2str(p, buf, sizeof(buf));
		zlog_warn("%u: Add RNH %s type %d - table not found", vrfid,
			  buf, type);
		return NULL;
	}

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(table, p);

	if (!rn->info) {
		rnh = XCALLOC(MTYPE_RNH, sizeof(struct rnh));
		rnh->client_list = list_new();
		rnh->vrf_id = vrfid;
		rnh->zebra_static_route_list = list_new();
		rnh->zebra_pseudowire_list = list_new();
		route_lock_node(rn);
		rn->info = rnh;
		rnh->node = rn;
	}

	route_unlock_node(rn);
	return (rn->info);
}

struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid, rnh_type_t type)
{
	struct route_table *table;
	struct route_node *rn;

	table = get_rnh_table(vrfid, PREFIX_FAMILY(p), type);
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
	rnh->flags |= ZEBRA_NHT_DELETED;
	list_delete_and_null(&rnh->client_list);
	list_delete_and_null(&rnh->zebra_static_route_list);
	list_delete_and_null(&rnh->zebra_pseudowire_list);
	free_state(rnh->vrf_id, rnh->state, rnh->node);
	XFREE(MTYPE_RNH, rnh);
}

void zebra_delete_rnh(struct rnh *rnh, rnh_type_t type)
{
	struct route_node *rn;

	if (!rnh || (rnh->flags & ZEBRA_NHT_DELETED) || !(rn = rnh->node))
		return;

	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("%u: Del RNH %s type %d", rnh->vrf_id,
			   rnh_str(rnh, buf, sizeof(buf)), type);
	}

	zebra_free_rnh(rnh);
	rn->info = NULL;
	route_unlock_node(rn);
}

void zebra_add_rnh_client(struct rnh *rnh, struct zserv *client,
			  rnh_type_t type, vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("%u: Client %s registers for RNH %s type %d", vrf_id,
			   zebra_route_string(client->proto),
			   rnh_str(rnh, buf, sizeof(buf)), type);
	}
	if (!listnode_lookup(rnh->client_list, client)) {
		listnode_add(rnh->client_list, client);
		send_client(rnh, client, type,
			    vrf_id); // Pending: check if its needed
	}
}

void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client,
			     rnh_type_t type)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		char buf[PREFIX2STR_BUFFER];
		zlog_debug("Client %s unregisters for RNH %s type %d",
			   zebra_route_string(client->proto),
			   rnh_str(rnh, buf, sizeof(buf)), type);
	}
	listnode_delete(rnh->client_list, client);
	if (list_isempty(rnh->client_list)
	    && list_isempty(rnh->zebra_static_route_list)
	    && list_isempty(rnh->zebra_pseudowire_list))
		zebra_delete_rnh(rnh, type);
}

void zebra_register_rnh_static_nh(vrf_id_t vrf_id, struct prefix *nh,
				  struct route_node *static_rn)
{
	struct rnh *rnh;

	rnh = zebra_add_rnh(nh, vrf_id, RNH_NEXTHOP_TYPE);
	if (rnh && !listnode_lookup(rnh->zebra_static_route_list, static_rn)) {
		listnode_add(rnh->zebra_static_route_list, static_rn);
	}
}

void zebra_deregister_rnh_static_nh(vrf_id_t vrf_id, struct prefix *nh,
				    struct route_node *static_rn)
{
	struct rnh *rnh;

	rnh = zebra_lookup_rnh(nh, vrf_id, RNH_NEXTHOP_TYPE);
	if (!rnh || (rnh->flags & ZEBRA_NHT_DELETED))
		return;

	listnode_delete(rnh->zebra_static_route_list, static_rn);

	if (list_isempty(rnh->client_list)
	    && list_isempty(rnh->zebra_static_route_list)
	    && list_isempty(rnh->zebra_pseudowire_list))
		zebra_delete_rnh(rnh, RNH_NEXTHOP_TYPE);
}

void zebra_deregister_rnh_static_nexthops(vrf_id_t vrf_id,
					  struct nexthop *nexthop,
					  struct route_node *rn)
{
	struct nexthop *nh;
	struct prefix nh_p;

	for (nh = nexthop; nh; nh = nh->next) {
		switch (nh->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			nh_p.family = AF_INET;
			nh_p.prefixlen = IPV4_MAX_BITLEN;
			nh_p.u.prefix4 = nh->gate.ipv4;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			nh_p.family = AF_INET6;
			nh_p.prefixlen = IPV6_MAX_BITLEN;
			nh_p.u.prefix6 = nh->gate.ipv6;
			break;
		/*
		 * Not sure what really to do here, we are not
		 * supposed to have either of these for NHT
		 * and the code has no way to know what prefix
		 * to use.  So I'm going to just continue
		 * for the moment, which is preferable to
		 * what is currently happening which is a
		 * CRASH and BURN.
		 * Some simple testing shows that we
		 * are not leaving slag around for these
		 * skipped static routes.  Since
		 * they don't appear to be installed
		 */
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_BLACKHOLE:
			continue;
			break;
		}
		zebra_deregister_rnh_static_nh(vrf_id, &nh_p, rn);
	}
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

	addr2hostprefix(pw->af, &pw->nexthop, &nh);
	rnh = zebra_add_rnh(&nh, vrf_id, RNH_NEXTHOP_TYPE);
	if (rnh && !listnode_lookup(rnh->zebra_pseudowire_list, pw)) {
		listnode_add(rnh->zebra_pseudowire_list, pw);
		pw->rnh = rnh;
		zebra_evaluate_rnh(vrf_id, pw->af, 1, RNH_NEXTHOP_TYPE, &nh);
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

	if (list_isempty(rnh->client_list)
	    && list_isempty(rnh->zebra_static_route_list)
	    && list_isempty(rnh->zebra_pseudowire_list))
		zebra_delete_rnh(rnh, RNH_NEXTHOP_TYPE);
}

/* Apply the NHT route-map for a client to the route (and nexthops)
 * resolving a NH.
 */
static int zebra_rnh_apply_nht_rmap(int family, struct route_node *prn,
				    struct route_entry *re, int proto)
{
	int at_least_one = 0;
	int rmap_family; /* Route map has diff AF family enum */
	struct nexthop *nexthop;
	int ret;

	rmap_family = (family == AF_INET) ? AFI_IP : AFI_IP6;

	if (prn && re) {
		for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next) {
			ret = zebra_nht_route_map_check(rmap_family, proto,
							&prn->p, re, nexthop);
			if (ret != RMAP_DENYMATCH) {
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
				at_least_one++; /* at least one valid NH */
			} else {
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
			}
		}
	}
	return (at_least_one);
}

/*
 * Determine appropriate route (RE entry) resolving a tracked BGP route
 * for BGP route for import.
 */
static
struct route_entry *zebra_rnh_resolve_import_entry(vrf_id_t vrfid,
						   int family,
						   struct route_node *nrn,
						   struct rnh *rnh,
						   struct route_node **prn)
{
	struct route_table *route_table;
	struct route_node *rn;
	struct route_entry *re;

	*prn = NULL;

	route_table = zebra_vrf_table(family2afi(family), SAFI_UNICAST, vrfid);
	if (!route_table) // unexpected
		return NULL;

	rn = route_node_match(route_table, &nrn->p);
	if (!rn)
		return NULL;

	/* Unlock route node - we don't need to lock when walking the tree. */
	route_unlock_node(rn);

	if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_EXACT_MATCH) &&
	     !prefix_same(&nrn->p, &rn->p))
		return NULL;

	/* Identify appropriate route entry. */
	RNODE_FOREACH_RE(rn, re) {
		if (!CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED) &&
		    CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED) &&
		    (re->type != ZEBRA_ROUTE_BGP))
			break;
	}

	if (re)
		*prn = rn;
	return re;
}

/*
 * See if a tracked route entry for import (by BGP) has undergone any
 * change, and if so, notify the client.
 */
static void zebra_rnh_eval_import_check_entry(vrf_id_t vrfid, int family,
					      int force, struct route_node *nrn,
					      struct rnh *rnh,
					      struct route_entry *re)
{
	int state_changed = 0;
	struct zserv *client;
	char bufn[INET6_ADDRSTRLEN];
	struct listnode *node;
	struct nexthop *nexthop;

	if (re && (rnh->state == NULL)) {
		for (ALL_NEXTHOPS(re->nexthop, nexthop))
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)) {
				state_changed = 1;
				break;
			}
	} else if (!re && (rnh->state != NULL))
		state_changed = 1;

	if (compare_state(re, rnh->state))
		copy_state(rnh, re, nrn);

	if (state_changed || force) {
		if (IS_ZEBRA_DEBUG_NHT) {
			prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
			zlog_debug("%u:%s: Route import check %s %s\n", vrfid,
				   bufn, rnh->state ? "passed" : "failed",
				   state_changed ? "(state changed)" : "");
		}
		/* state changed, notify clients */
		for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
			send_client(rnh, client, RNH_IMPORT_CHECK_TYPE, vrfid);
		}
	}
}

/*
 * Notify clients registered for this nexthop about a change.
 */
static void zebra_rnh_notify_protocol_clients(vrf_id_t vrfid, int family,
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
			prefix2str(&prn->p, bufp, INET6_ADDRSTRLEN);
			zlog_debug("%u:%s: NH resolved over route %s", vrfid,
				   bufn, bufp);
		} else
			zlog_debug("%u:%s: NH has become unresolved", vrfid,
				   bufn);
	}

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
		if (prn && re) {
			/* Apply route-map for this client to route resolving
			 * this
			 * nexthop to see if it is filtered or not.
			 */
			num_resolving_nh = zebra_rnh_apply_nht_rmap(
				family, prn, re, client->proto);
			if (num_resolving_nh)
				rnh->filtered[client->proto] = 0;
			else
				rnh->filtered[client->proto] = 1;

			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug(
					"%u:%s: Notifying client %s about NH %s",
					vrfid, bufn,
					zebra_route_string(client->proto),
					num_resolving_nh
						? ""
						: "(filtered by route-map)");
		} else {
			rnh->filtered[client->proto] = 0;
			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug(
					"%u:%s: Notifying client %s about NH (unreachable)",
					vrfid, bufn,
					zebra_route_string(client->proto));
		}

		send_client(rnh, client, RNH_NEXTHOP_TYPE, vrfid);
	}
}

static void zebra_rnh_process_static_routes(vrf_id_t vrfid, int family,
					    struct route_node *nrn,
					    struct rnh *rnh,
					    struct route_node *prn,
					    struct route_entry *re)
{
	struct listnode *node;
	int num_resolving_nh = 0;
	struct route_node *static_rn;
	struct route_entry *sre;
	struct nexthop *nexthop;
	char bufn[INET6_ADDRSTRLEN];
	char bufp[INET6_ADDRSTRLEN];
	char bufs[INET6_ADDRSTRLEN];

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
		if (prn)
			prefix2str(&prn->p, bufp, INET6_ADDRSTRLEN);
	}

	if (prn && re) {
		/* Apply route-map for "static" to route resolving this
		 * nexthop to see if it is filtered or not.
		 */
		num_resolving_nh = zebra_rnh_apply_nht_rmap(family, prn, re,
							    ZEBRA_ROUTE_STATIC);
		if (num_resolving_nh)
			rnh->filtered[ZEBRA_ROUTE_STATIC] = 0;
		else
			rnh->filtered[ZEBRA_ROUTE_STATIC] = 1;
	} else
		rnh->filtered[ZEBRA_ROUTE_STATIC] = 0;

	/* Evaluate each static route associated with this nexthop. */
	for (ALL_LIST_ELEMENTS_RO(rnh->zebra_static_route_list, node,
				  static_rn)) {
		RNODE_FOREACH_RE (static_rn, sre) {
			if (sre->type != ZEBRA_ROUTE_STATIC)
				continue;

			/* Set the filter flag for the correct nexthop - static
			 * route may
			 * be having multiple. We care here only about
			 * registered nexthops.
			 */
			for (nexthop = sre->nexthop; nexthop;
			     nexthop = nexthop->next) {
				switch (nexthop->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					if (nexthop->gate.ipv4.s_addr
					    == nrn->p.u.prefix4.s_addr) {
						if (num_resolving_nh)
							UNSET_FLAG(
								nexthop->flags,
								NEXTHOP_FLAG_FILTERED);
						else
							SET_FLAG(
								nexthop->flags,
								NEXTHOP_FLAG_FILTERED);
					}
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:

					if (memcmp(&nexthop->gate.ipv6,
						   &nrn->p.u.prefix6, 16)
					    == 0) {
						if (num_resolving_nh)
							UNSET_FLAG(
								nexthop->flags,
								NEXTHOP_FLAG_FILTERED);
						else
							SET_FLAG(
								nexthop->flags,
								NEXTHOP_FLAG_FILTERED);
					}
					break;
				default:
					break;
				}
			}

			if (IS_ZEBRA_DEBUG_NHT) {
				prefix2str(&static_rn->p, bufs,
					   INET6_ADDRSTRLEN);
				if (prn && re)
					zlog_debug(
						"%u:%s: NH change %s, scheduling static route %s",
						vrfid, bufn,
						num_resolving_nh
							? ""
							: "(filtered by route-map)",
						bufs);
				else
					zlog_debug(
						"%u:%s: NH unreachable, scheduling static route %s",
						vrfid, bufn, bufs);
			}

			SET_FLAG(sre->status, ROUTE_ENTRY_CHANGED);
			SET_FLAG(sre->status, ROUTE_ENTRY_NEXTHOPS_CHANGED);
		}

		rib_queue_add(static_rn);
	}
}

/*
 * Determine appropriate route (route entry) resolving a tracked
 * nexthop.
 */
static struct route_entry *zebra_rnh_resolve_nexthop_entry(vrf_id_t vrfid,
						     int family,
						     struct route_node *nrn,
						     struct rnh *rnh,
						     struct route_node **prn)
{
	struct route_table *route_table;
	struct route_node *rn;
	struct route_entry *re;

	*prn = NULL;

	route_table = zebra_vrf_table(family2afi(family), SAFI_UNICAST, vrfid);
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
		/* Do not resolve over default route unless allowed &&
		 * match route to be exact if so specified
		 */
		if (is_default_prefix(&rn->p) &&
		    !nh_resolve_via_default(rn->p.family))
			return NULL;

		/* Identify appropriate route entry. */
		RNODE_FOREACH_RE(rn, re) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
				continue;
			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED))
				continue;

			if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)) {
				if ((re->type == ZEBRA_ROUTE_CONNECT)
				    || (re->type == ZEBRA_ROUTE_STATIC))
					break;
				if (re->type == ZEBRA_ROUTE_NHRP) {
					struct nexthop *nexthop;

					for (nexthop = re->nexthop;
					     nexthop;
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

		if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED))
			rn = rn->parent;
		else
			return NULL;
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
static void zebra_rnh_eval_nexthop_entry(vrf_id_t vrfid, int family, int force,
					 struct route_node *nrn,
					 struct rnh *rnh,
					 struct route_node *prn,
					 struct route_entry *re)
{
	int state_changed = 0;

	/* If we're resolving over a different route, resolution has changed or
	 * the resolving route has some change (e.g., metric), there is a state
	 * change.
	 */
	if (!prefix_same(&rnh->resolved_route, &prn->p)) {
		if (prn)
			prefix_copy(&rnh->resolved_route, &prn->p);
		else
			memset(&rnh->resolved_route, 0, sizeof(struct prefix));

		copy_state(rnh, re, nrn);
		state_changed = 1;
	} else if (compare_state(re, rnh->state)) {
		copy_state(rnh, re, nrn);
		state_changed = 1;
	}

	if (state_changed || force) {
		/* NOTE: Use the "copy" of resolving route stored in 'rnh' i.e.,
		 * rnh->state.
		 */
		/* Notify registered protocol clients. */
		zebra_rnh_notify_protocol_clients(vrfid, family, nrn, rnh, prn,
						  rnh->state);

		/* Process static routes attached to this nexthop */
		zebra_rnh_process_static_routes(vrfid, family, nrn, rnh, prn,
						rnh->state);

		/* Process pseudowires attached to this nexthop */
		zebra_rnh_process_pseudowires(vrfid, rnh);
	}
}

/* Evaluate one tracked entry */
static void zebra_rnh_evaluate_entry(vrf_id_t vrfid, int family, int force,
				     rnh_type_t type, struct route_node *nrn)
{
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;
	char bufn[INET6_ADDRSTRLEN];

	if (IS_ZEBRA_DEBUG_NHT) {
		prefix2str(&nrn->p, bufn, INET6_ADDRSTRLEN);
		zlog_debug("%u:%s: Evaluate RNH, type %d %s", vrfid, bufn, type,
			   force ? "(force)" : "");
	}

	rnh = nrn->info;

	/* Identify route entry (RE) resolving this tracked entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		re = zebra_rnh_resolve_import_entry(vrfid, family, nrn,
						    rnh, &prn);
	else
		re = zebra_rnh_resolve_nexthop_entry(vrfid, family, nrn, rnh,
						     &prn);

	/* If the entry cannot be resolved and that is also the existing state,
	 * there is nothing further to do.
	 */
	if (!re && rnh->state == NULL && !force)
		return;

	/* Process based on type of entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		zebra_rnh_eval_import_check_entry(vrfid, family, force, nrn,
						  rnh, re);
	else
		zebra_rnh_eval_nexthop_entry(vrfid, family, force, nrn, rnh,
					     prn, re);
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
static void zebra_rnh_clear_nhc_flag(vrf_id_t vrfid, int family,
				     rnh_type_t type, struct route_node *nrn)
{
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	rnh = nrn->info;

	/* Identify route entry (RIB) resolving this tracked entry. */
	if (type == RNH_IMPORT_CHECK_TYPE)
		re = zebra_rnh_resolve_import_entry(vrfid, family, nrn,
						    rnh, &prn);
	else
		re = zebra_rnh_resolve_nexthop_entry(vrfid, family, nrn, rnh,
						     &prn);

	if (re) {
		UNSET_FLAG(re->status, ROUTE_ENTRY_NEXTHOPS_CHANGED);
		UNSET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);
	}
}

/* Evaluate all tracked entries (nexthops or routes for import into BGP)
 * of a particular VRF and address-family or a specific prefix.
 */
void zebra_evaluate_rnh(vrf_id_t vrfid, int family, int force, rnh_type_t type,
			struct prefix *p)
{
	struct route_table *rnh_table;
	struct route_node *nrn;

	rnh_table = get_rnh_table(vrfid, family, type);
	if (!rnh_table) // unexpected
		return;

	if (p) {
		/* Evaluating a specific entry, make sure it exists. */
		nrn = route_node_lookup(rnh_table, p);
		if (nrn && nrn->info)
			zebra_rnh_evaluate_entry(vrfid, family, force, type,
						 nrn);

		if (nrn)
			route_unlock_node(nrn);
	} else {
		/* Evaluate entire table. */
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_evaluate_entry(vrfid, family, force,
							 type, nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_clear_nhc_flag(vrfid, family, type,
							 nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
	}
}

void zebra_print_rnh_table(vrf_id_t vrfid, int af, struct vty *vty,
			   rnh_type_t type)
{
	struct route_table *table;
	struct route_node *rn;

	table = get_rnh_table(vrfid, af, type);
	if (!table) {
		zlog_debug("print_rnhs: rnh table not found\n");
		return;
	}

	for (rn = route_top(table); rn; rn = route_next(rn))
		if (rn->info)
			print_rnh(rn, vty);
}

int zebra_cleanup_rnh_client(vrf_id_t vrf_id, int family, struct zserv *client,
			     rnh_type_t type)
{
	struct route_table *ntable;
	struct route_node *nrn;
	struct rnh *rnh;

	if (IS_ZEBRA_DEBUG_NHT)
		zlog_debug("%u: Client %s RNH cleanup for family %d type %d",
			   vrf_id, zebra_route_string(client->proto), family,
			   type);

	ntable = get_rnh_table(vrf_id, family, type);
	if (!ntable) {
		zlog_debug("cleanup_rnh_client: rnh table not found\n");
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

/**
 * free_state - free up the re structure associated with the rnh.
 */
static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn)
{

	if (!re)
		return;

	/* free RE and nexthops */
	zebra_deregister_rnh_static_nexthops(vrf_id, re->nexthop, rn);
	nexthops_free(re->nexthop);
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
	state->nh_vrf_id = re->vrf_id;

	route_entry_copy_nexthops(state, re->nexthop);
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

	if (r1->nexthop_num != r2->nexthop_num)
		return 1;

	if (CHECK_FLAG(r1->status, ROUTE_ENTRY_NEXTHOPS_CHANGED)
	    || CHECK_FLAG(r1->status, ROUTE_ENTRY_LABELS_CHANGED))
		return 1;

	return 0;
}

static int send_client(struct rnh *rnh, struct zserv *client, rnh_type_t type,
		       vrf_id_t vrf_id)
{
	struct stream *s;
	struct route_entry *re;
	unsigned long nump;
	u_char num;
	struct nexthop *nexthop;
	struct route_node *rn;
	int cmd = (type == RNH_IMPORT_CHECK_TYPE) ? ZEBRA_IMPORT_CHECK_UPDATE
						  : ZEBRA_NEXTHOP_UPDATE;

	rn = rnh->node;
	re = rnh->state;

	/* Get output stream. */
	s = client->obuf;
	stream_reset(s);

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
		zlog_err("%s: Unknown family (%d) notification attempted\n",
			 __FUNCTION__, rn->p.family);
		break;
	}
	if (re) {
		stream_putc(s, re->distance);
		stream_putl(s, re->metric);
		num = 0;
		nump = stream_get_endp(s);
		stream_putc(s, 0);
		for (nexthop = re->nexthop; nexthop; nexthop = nexthop->next)
			if ((CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)
			     || CHECK_FLAG(nexthop->flags,
					   NEXTHOP_FLAG_RECURSIVE))
			    && CHECK_FLAG(nexthop->flags,
					  NEXTHOP_FLAG_ACTIVE)) {
				stream_putc(s, nexthop->type);
				switch (nexthop->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					stream_put_in_addr(s,
							   &nexthop->gate.ipv4);
					stream_putl(s, nexthop->ifindex);
					break;
				case NEXTHOP_TYPE_IFINDEX:
					stream_putl(s, nexthop->ifindex);
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					stream_put(s, &nexthop->gate.ipv6, 16);
					stream_putl(s, nexthop->ifindex);
					break;
				default:
					/* do nothing */
					break;
				}
				num++;
			}
		stream_putc_at(s, nump, num);
	} else {
		stream_putc(s, 0); // distance
		stream_putl(s, 0); // metric
		stream_putc(s, 0); // nexthops
	}
	stream_putw_at(s, 0, stream_get_endp(s));

	client->nh_last_upd_time = monotime(NULL);
	client->last_write_cmd = cmd;
	return zebra_server_send_message(client);
}

static void print_nh(struct nexthop *nexthop, struct vty *vty)
{
	char buf[BUFSIZ];
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

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
		for (nexthop = rnh->state->nexthop; nexthop;
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
	if (!list_isempty(rnh->zebra_static_route_list))
		vty_out(vty, " zebra%s",
			rnh->filtered[ZEBRA_ROUTE_STATIC] ? "(filtered)" : "");
	if (!list_isempty(rnh->zebra_pseudowire_list))
		vty_out(vty, " zebra[pseudowires]");
	vty_out(vty, "\n");
}
