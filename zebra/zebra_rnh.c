// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra next hop tracking code
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "zebra/zebra_memory.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "frrevent.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "nexthop.h"
#include "vrf.h"
#include "jhash.h"

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
#include "zebra/zebra_srte.h"
#include "zebra/interface.h"
#include "zebra/zebra_errors.h"

DEFINE_MTYPE_STATIC(ZEBRA, RNH, "Nexthop tracking object");
DEFINE_MTYPE_STATIC(ZEBRA, RNH_CONTAINER, "RNH container for per-client tracking");

/* Container for multiple rnh structures per prefix.
 * This is stored in route_node->info in the rnh_table.
 * This structure is private to zebra_rnh.c.
 */
struct rnh_container {
	/* Hash table of rnh structures, keyed by client */
	struct rnh_rbtree_head rnh_rbtree;
};

static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn);
static void copy_state(struct rnh *rnh, const struct route_entry *re,
		       struct route_node *rn);
static bool compare_state(struct route_entry *r1, struct route_entry *r2);
static void print_rnh(struct route_node *rn, struct vty *vty,
		      json_object *json);
static int zebra_client_cleanup_rnh(struct zserv *client);

/* Sentinel client value for pseudowire RNHs (which don't have a real client) */
static struct zserv pseudowire_client_sentinel;
#define PSEUDOWIRE_CLIENT (&pseudowire_client_sentinel)

/* Hash comparison function for rnh */
static int rnh_rbtree_cmp(const struct rnh *rnh1, const struct rnh *rnh2)
{
	uint8_t proto1, proto2;

	/* Handle pseudowire sentinel */
	if (rnh1->client == PSEUDOWIRE_CLIENT)
		proto1 = UINT8_MAX;
	else
		proto1 = rnh1->client->proto;

	if (rnh2->client == PSEUDOWIRE_CLIENT)
		proto2 = UINT8_MAX;
	else
		proto2 = rnh2->client->proto;

	if (proto1 != proto2)
		return (proto1 < proto2) ? -1 : 1;

	return rnh1->client->instance - rnh2->client->instance;
}

/* Declare the hash implementation - this stays private to zebra_rnh.c */
DECLARE_RBTREE_UNIQ(rnh_rbtree, struct rnh, rnh_rbtree_item, rnh_rbtree_cmp);

void zebra_rnh_init(void)
{
	hook_register(zserv_client_close, zebra_client_cleanup_rnh);
}

static inline struct route_table *get_rnh_table(vrf_id_t vrfid, afi_t afi,
						safi_t safi)
{
	struct zebra_vrf *zvrf;
	struct route_table *t = NULL;

	zvrf = zebra_vrf_lookup_by_id(vrfid);
	if (zvrf) {
		if (safi == SAFI_UNICAST)
			t = zvrf->rnh_table[afi];
		else if (safi == SAFI_MULTICAST)
			t = zvrf->rnh_table_multicast[afi];
	}

	return t;
}

static void zebra_rnh_remove_from_routing_table(struct rnh *rnh)
{
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	struct route_table *table;
	struct route_node *rn;
	rib_dest_t *dest;

	if (!zvrf)
		return;

	table = zvrf->table[rnh->afi][rnh->safi];
	if (!table)
		return;

	rn = route_node_match(table, &rnh->resolved_route);
	if (!rn)
		return;

	if (IS_ZEBRA_DEBUG_NHT_DETAILED)
		zlog_debug("%s: %s(%u):%pRN removed from tracking on %pRN",
			   __func__, VRF_LOGNAME(zvrf->vrf), rnh->vrf_id,
			   rnh->node, rn);

	dest = rib_dest_from_rnode(rn);
	rnh_list_del(&dest->nht, rnh);
	route_unlock_node(rn);
}

static void zebra_rnh_store_in_routing_table(struct rnh *rnh)
{
	struct zebra_vrf *zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	struct route_table *table;
	struct route_node *rn;
	rib_dest_t *dest;

	if (!zvrf)
		return;

	table = zvrf->table[rnh->afi][rnh->safi];
	if (!table)
		return;

	rn = route_node_match(table, &rnh->resolved_route);
	if (!rn)
		return;

	if (IS_ZEBRA_DEBUG_NHT_DETAILED)
		zlog_debug("%s: %s(%u):%pRN added for tracking on %pRN",
			   __func__, VRF_LOGNAME(zvrf->vrf), rnh->vrf_id,
			   rnh->node, rn);

	dest = rib_dest_from_rnode(rn);
	rnh_list_add_tail(&dest->nht, rnh);
	route_unlock_node(rn);
}

struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi, struct zserv *client,
			  bool *exists)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh *rnh = NULL;
	struct rnh_container *rnhc = NULL;
	struct rnh lookup;
	afi_t afi = family2afi(p->family);

	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(vrfid);

		zlog_debug("%s(%u): Add RNH %pFX for safi: %u, client: %s", VRF_LOGNAME(vrf), vrfid,
			   p, safi, client ? zebra_route_string(client->proto) : "pseudowire");
	}

	table = get_rnh_table(vrfid, afi, safi);
	if (!table) {
		struct vrf *vrf = vrf_lookup_by_id(vrfid);

		flog_warn(EC_ZEBRA_RNH_NO_TABLE,
			  "%s(%u): Add RNH %pFX - table not found",
			  VRF_LOGNAME(vrf), vrfid, p);
		*exists = false;
		return NULL;
	}

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup (or add) route node.*/
	rn = route_node_get(table, p);

	if (!rn->info) {
		/* Create a new container for this prefix */
		rnhc = XCALLOC(MTYPE_RNH_CONTAINER, sizeof(struct rnh_container));
		rnh_rbtree_init(&rnhc->rnh_rbtree);
		rn->info = rnhc;
		route_lock_node(rn);
	} else {
		rnhc = rn->info;
	}

	/* Use sentinel client for pseudowires (NULL client pointer) */
	struct zserv *lookup_client = client ? client : PSEUDOWIRE_CLIENT;

	/* Now look for an existing rnh for this client */
	lookup.client = lookup_client;
	rnh = rnh_rbtree_find(&rnhc->rnh_rbtree, &lookup);

	if (rnh) {
		*exists = true;
	} else {
		/* Create new rnh for this client */
		rnh = XCALLOC(MTYPE_RNH, sizeof(struct rnh));

		/*
		 * The resolved route is already 0.0.0.0/0 or
		 * 0::0/0 due to the calloc right above, but
		 * we should set the family so that future
		 * comparisons can just be done
		 */
		rnh->resolved_route.family = p->family;
		rnh->client = lookup_client;
		rnh->vrf_id = vrfid;
		rnh->seqno = 0;
		rnh->afi = afi;
		rnh->safi = safi;
		rnh->zebra_pseudowire_list = list_new();
		rnh->node = rn;
		rnh->filtered = false;
		*exists = false;

		/* Add to hash */
		rnh_rbtree_add(&rnhc->rnh_rbtree, rnh);

		zebra_rnh_store_in_routing_table(rnh);
	}

	route_unlock_node(rn);
	return rnh;
}

struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi, struct zserv *client)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh_container *rnhc;
	struct rnh lookup;

	table = get_rnh_table(vrfid, family2afi(PREFIX_FAMILY(p)), safi);
	if (!table)
		return NULL;

	/* Make it sure prefixlen is applied to the prefix. */
	apply_mask(p);

	/* Lookup route node.*/
	rn = route_node_lookup(table, p);
	if (!rn)
		return NULL;

	route_unlock_node(rn);

	rnhc = rn->info;
	if (!rnhc)
		return NULL;

	/* Use sentinel client for pseudowires (NULL client pointer) */
	struct zserv *lookup_client = client ? client : PSEUDOWIRE_CLIENT;

	/* Find the rnh for this specific client */
	lookup.client = lookup_client;
	return rnh_rbtree_find(&rnhc->rnh_rbtree, &lookup);
}

void zebra_free_rnh(struct rnh *rnh)
{
	struct zebra_vrf *zvrf;
	struct route_table *table;

	zebra_rnh_remove_from_routing_table(rnh);
	rnh->flags |= ZEBRA_NHT_DELETED;
	list_delete(&rnh->zebra_pseudowire_list);

	zvrf = zebra_vrf_lookup_by_id(rnh->vrf_id);
	if (zvrf) {
		table = zvrf->table[family2afi(rnh->resolved_route.family)][rnh->safi];

		if (table) {
			struct route_node *rern;

			rern = route_node_match(table, &rnh->resolved_route);
			if (rern) {
				rib_dest_t *dest;

				dest = rib_dest_from_rnode(rern);
				rnh_list_del(&dest->nht, rnh);
				route_unlock_node(rern);
			}
		}
	}
	free_state(rnh->vrf_id, rnh->state, rnh->node);
	XFREE(MTYPE_RNH, rnh);
}

static void zebra_delete_rnh(struct rnh *rnh)
{
	struct route_node *rn;
	struct rnh_container *rnhc;

	if (!list_isempty(rnh->zebra_pseudowire_list))
		return;

	if ((rnh->flags & ZEBRA_NHT_DELETED) || !(rn = rnh->node))
		return;

	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(rnh->vrf_id);

		zlog_debug("%s(%u): Del RNH %pRN for client %s", VRF_LOGNAME(vrf), rnh->vrf_id,
			   rnh->node,
			   rnh->client ? zebra_route_string(rnh->client->proto) : "pseudowire");
	}

	/* Remove from hash */
	rnhc = rn->info;
	if (rnhc && rnh->client)
		rnh_rbtree_del(&rnhc->rnh_rbtree, rnh);

	zebra_free_rnh(rnh);

	/* If hash is now empty, free the container */
	if (rnhc && rnh_rbtree_count(&rnhc->rnh_rbtree) == 0) {
		rnh_rbtree_fini(&rnhc->rnh_rbtree);
		XFREE(MTYPE_RNH_CONTAINER, rnhc);
		rn->info = NULL;
		route_unlock_node(rn);
	} else if (!rnhc)
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
			  vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);

		zlog_debug("%s(%u): Client %s registers for RNH %pRN",
			   VRF_LOGNAME(vrf), vrf_id,
			   zebra_route_string(client->proto), rnh->node);
	}

	/* Each rnh now has a single client, so just verify it matches */
	assert(rnh->client == client);

	/*
	 * We always need to respond with known information,
	 * currently multiple daemons expect this behavior
	 */
	zebra_send_rnh_update(rnh, client, vrf_id, 0);
}

void zebra_remove_rnh_client(struct rnh *rnh, struct zserv *client)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(rnh->vrf_id);

		zlog_debug("Client %s unregisters for RNH %s(%u)%pRN",
			   zebra_route_string(client->proto), VRF_LOGNAME(vrf),
			   vrf ? vrf->vrf_id : rnh->vrf_id, rnh->node);
	}

	/* Verify this is the right client */
	if (rnh->client != client) {
		flog_err(EC_ZEBRA_RNH_NO_TABLE, "Attempt to remove wrong client from rnh");
		return;
	}

	zebra_delete_rnh(rnh);
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

void zebra_register_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw,
				   bool *nht_exists)
{
	struct prefix nh;
	struct rnh *rnh;
	bool exists;
	struct zebra_vrf *zvrf;

	*nht_exists = false;

	zvrf = zebra_vrf_lookup_by_id(vrf_id);
	if (!zvrf)
		return;

	addr2hostprefix(pw->af, &pw->nexthop, &nh);
	/* Pseudowires use NULL client */
	rnh = zebra_add_rnh(&nh, vrf_id, SAFI_UNICAST, NULL, &exists);
	if (!rnh)
		return;

	if (!listnode_lookup(rnh->zebra_pseudowire_list, pw)) {
		listnode_add(rnh->zebra_pseudowire_list, pw);
		pw->rnh = rnh;
		zebra_evaluate_rnh(zvrf, family2afi(pw->af), 1, &nh,
				   SAFI_UNICAST);
	} else
		*nht_exists = true;
}

void zebra_deregister_rnh_pseudowire(vrf_id_t vrf_id, struct zebra_pw *pw)
{
	struct rnh *rnh;

	rnh = pw->rnh;
	if (!rnh)
		return;

	listnode_delete(rnh->zebra_pseudowire_list, pw);
	pw->rnh = NULL;

	zebra_delete_rnh(rnh);
}

int zebra_rnh_iterate_prefix(struct prefix *p, vrf_id_t vrfid, safi_t safi, rnh_iter_cb cb,
			     void *ctx)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh_container *rnhc;
	struct rnh *rnh;
	int count = 0;
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	table = get_rnh_table(vrfid, afi, safi);
	if (!table)
		return 0;

	apply_mask(p);
	rn = route_node_lookup(table, p);
	if (!rn)
		return 0;

	rnhc = rn->info;
	route_unlock_node(rn);

	if (!rnhc)
		return 0;

	/* Iterate through all RNHs in the container */
	frr_each (rnh_rbtree, &rnhc->rnh_rbtree, rnh) {
		count++;
		if (cb(rnh, ctx) != 0)
			break;
	}

	return count;
}

/* Clear the NEXTHOP_FLAG_RNH_FILTERED flags on all nexthops
 */
static void zebra_rnh_clear_nexthop_rnh_filters(struct route_entry *re)
{
	struct nexthop *nexthop;

	if (re) {
		for (nexthop = re->nhe->nhg.nexthop; nexthop;
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
		for (nexthop = re->nhe->nhg.nexthop; nexthop;
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
 * Notify the client for this RNH about a change.
 */
static void zebra_rnh_notify_protocol_clients(struct zebra_vrf *zvrf, afi_t afi,
					      struct route_node *nrn,
					      struct rnh *rnh,
					      struct route_node *prn,
					      struct route_entry *re)
{
	struct zserv *client;
	int num_resolving_nh;

	client = rnh->client;
	if (!client)
		return;

	if (IS_ZEBRA_DEBUG_NHT) {
		if (prn && re) {
			zlog_debug("%s(%u):%pRN: NH resolved over route %pRN for client %s",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id, nrn, prn,
				   zebra_route_string(client->proto));
		} else
			zlog_debug("%s(%u):%pRN: NH has become unresolved for client %s",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id, nrn,
				   zebra_route_string(client->proto));
	}

	if (prn && re) {
		/* Apply route-map for this client to route resolving
		 * this nexthop to see if it is filtered or not.
		 */
		zebra_rnh_clear_nexthop_rnh_filters(re);
		num_resolving_nh = zebra_rnh_apply_nht_rmap(afi, zvrf, prn, re, client->proto);
		if (num_resolving_nh)
			rnh->filtered = false;
		else
			rnh->filtered = true;

		if (IS_ZEBRA_DEBUG_NHT)
			zlog_debug("%s(%u):%pRN: Notifying client %s about NH %s",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id, nrn,
				   zebra_route_string(client->proto),
				   num_resolving_nh ? "" : "(filtered by route-map)");
	} else {
		rnh->filtered = false;
		if (IS_ZEBRA_DEBUG_NHT)
			zlog_debug("%s(%u):%pRN: Notifying client %s about NH (unreachable)",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id, nrn,
				   zebra_route_string(client->proto));
	}

	zebra_send_rnh_update(rnh, client, zvrf->vrf->vrf_id, 0);

	if (re)
		zebra_rnh_clear_nexthop_rnh_filters(re);
}

/*
 * Utility to determine whether a candidate nexthop is useable. We make this
 * check in a couple of places, so this is a single home for the logic we
 * use.
 */

static const int RNH_INVALID_NH_FLAGS = (NEXTHOP_FLAG_RECURSIVE |
					 NEXTHOP_FLAG_DUPLICATE |
					 NEXTHOP_FLAG_RNH_FILTERED);

bool rnh_nexthop_valid(const struct route_entry *re, const struct nexthop *nh)
{
	return (CHECK_FLAG(re->status, ROUTE_ENTRY_INSTALLED)
		&& CHECK_FLAG(nh->flags, NEXTHOP_FLAG_ACTIVE)
		&& !CHECK_FLAG(nh->flags, RNH_INVALID_NH_FLAGS));
}

/*
 * Determine whether an re's nexthops are valid for tracking.
 */
static bool rnh_check_re_nexthops(const struct route_entry *re,
				  const struct rnh *rnh)
{
	bool ret = false;
	const struct nexthop *nexthop = NULL;

	/* Check route's nexthops */
	for (ALL_NEXTHOPS(re->nhe->nhg, nexthop)) {
		if (rnh_nexthop_valid(re, nexthop))
			break;
	}

	/* Check backup nexthops, if any. */
	if (nexthop == NULL && re->nhe->backup_info &&
	    re->nhe->backup_info->nhe) {
		for (ALL_NEXTHOPS(re->nhe->backup_info->nhe->nhg, nexthop)) {
			if (rnh_nexthop_valid(re, nexthop))
				break;
		}
	}

	if (nexthop == NULL) {
		if (IS_ZEBRA_DEBUG_NHT_DETAILED)
			zlog_debug(
				"        Route Entry %s no nexthops",
				zebra_route_string(re->type));

		goto done;
	}

	/*
	 * Some special checks if registration asked for them.
	 * LOCAL routes are by their definition not CONNECTED
	 * and as such should not be considered here
	 */
	if (CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)) {
		if ((re->type == ZEBRA_ROUTE_CONNECT) ||
		    (re->type == ZEBRA_ROUTE_STATIC))
			ret = true;
		if (re->type == ZEBRA_ROUTE_NHRP) {

			for (nexthop = re->nhe->nhg.nexthop;
			     nexthop;
			     nexthop = nexthop->next)
				if (nexthop->type == NEXTHOP_TYPE_IFINDEX)
					break;
			if (nexthop)
				ret = true;
		}
	} else {
		ret = true;
	}

done:
	return ret;
}

/*
 * Determine appropriate route (route entry) resolving a tracked
 * nexthop.
 */
static struct route_entry *
zebra_rnh_resolve_nexthop_entry(struct zebra_vrf *zvrf, afi_t afi,
				struct route_node *nrn, const struct rnh *rnh,
				struct route_node **prn)
{
	struct route_table *route_table;
	struct route_node *rn;
	struct route_entry *re;

	*prn = NULL;

	route_table = zvrf->table[afi][rnh->safi];
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
		if (IS_ZEBRA_DEBUG_NHT_DETAILED)
			zlog_debug("%s: %s(%u):%pRN Possible Match to %pRN",
				   __func__, VRF_LOGNAME(zvrf->vrf),
				   rnh->vrf_id, rnh->node, rn);

		/* Do not resolve over default route unless allowed &&
		 * match route to be exact if so specified
		 */
		if (is_default_prefix(&rn->p)
		    && (!CHECK_FLAG(rnh->flags, ZEBRA_NHT_RESOLVE_VIA_DEFAULT)
			&& !rnh_resolve_via_default(zvrf, rn->p.family))) {
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug(
					"        Not allowed to resolve through default prefix: rnh->resolve_via_default: %u",
					CHECK_FLAG(
						rnh->flags,
						ZEBRA_NHT_RESOLVE_VIA_DEFAULT));
			return NULL;
		}

		/* Identify appropriate route entry. */
		RNODE_FOREACH_RE (rn, re) {
			if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"        Route Entry %s removed",
						zebra_route_string(re->type));
				continue;
			}
			if (!CHECK_FLAG(re->flags, ZEBRA_FLAG_SELECTED) &&
			    !CHECK_FLAG(re->flags, ZEBRA_FLAG_FIB_OVERRIDE)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"        Route Entry %s !selected",
						zebra_route_string(re->type));
				continue;
			}

			if (CHECK_FLAG(re->status, ROUTE_ENTRY_QUEUED)) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug(
						"        Route Entry %s queued",
						zebra_route_string(re->type));
				continue;
			}

			/* Just being SELECTED isn't quite enough - must
			 * have an installed nexthop to be useful.
			 */
			if (rnh_check_re_nexthops(re, rnh))
				break;
		}

		/* Route entry found, we're done; else, walk up the tree. */
		if (re) {
			*prn = rn;
			return re;
		} else {
			/* Resolve the nexthop recursively by finding matching
			 * route with lower prefix length
			 */
			rn = rn->parent;
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

/* Evaluate one tracked entry (can be multiple RNHs per prefix now) */
static void zebra_rnh_evaluate_entry(struct zebra_vrf *zvrf, afi_t afi,
				     int force, struct route_node *nrn)
{
	struct rnh_container *rnhc;
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	if (IS_ZEBRA_DEBUG_NHT) {
		zlog_debug("%s(%u):%pRN: Evaluate RNH, %s", VRF_LOGNAME(zvrf->vrf),
			   zvrf->vrf ? zvrf->vrf->vrf_id : 0, nrn, force ? "(force)" : "");
	}

	rnhc = nrn->info;
	if (!rnhc)
		return;

	/* Iterate through all RNHs for this prefix */
	frr_each (rnh_rbtree, &rnhc->rnh_rbtree, rnh) {
		/* Identify route entry (RE) resolving this tracked entry. */
		re = zebra_rnh_resolve_nexthop_entry(zvrf, afi, nrn, rnh, &prn);

		/* If the entry cannot be resolved and that is also the existing state,
		 * there is nothing further to do.
		 */
		if (!re && rnh->state == NULL && !force)
			continue;

		/* Process based on type of entry. */
		zebra_rnh_eval_nexthop_entry(zvrf, afi, force, nrn, rnh, prn, re);
	}
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
				     struct route_node *nrn)
{
	struct rnh_container *rnhc;
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	rnhc = nrn->info;
	if (!rnhc)
		return;

	/* Just need to check one rnh since they all resolve to the same route */
	rnh = rnh_rbtree_first(&rnhc->rnh_rbtree);
	if (!rnh)
		return;

	/* Identify route entry (RIB) resolving this tracked entry. */
	re = zebra_rnh_resolve_nexthop_entry(zvrf, afi, nrn, rnh, &prn);

	if (re)
		UNSET_FLAG(re->status, ROUTE_ENTRY_LABELS_CHANGED);
}

/* Evaluate all tracked entries (nexthops or routes for import into BGP)
 * of a particular VRF and address-family or a specific prefix.
 */
void zebra_evaluate_rnh(struct zebra_vrf *zvrf, afi_t afi, int force,
			const struct prefix *p, safi_t safi)
{
	struct route_table *rnh_table;
	struct route_node *nrn;

	rnh_table = get_rnh_table(zvrf->vrf->vrf_id, afi, safi);
	if (!rnh_table)
		return;

	if (p) {
		/* Evaluating a specific entry, make sure it exists. */
		nrn = route_node_lookup(rnh_table, p);
		if (nrn && nrn->info)
			zebra_rnh_evaluate_entry(zvrf, afi, force, nrn);

		if (nrn)
			route_unlock_node(nrn);
	} else {
		/* Evaluate entire table. */
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_evaluate_entry(zvrf, afi, force, nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
		nrn = route_top(rnh_table);
		while (nrn) {
			if (nrn->info)
				zebra_rnh_clear_nhc_flag(zvrf, afi, nrn);
			nrn = route_next(nrn); /* this will also unlock nrn */
		}
	}
}

void zebra_print_rnh_table(vrf_id_t vrfid, afi_t afi, safi_t safi,
			   struct vty *vty, const struct prefix *p,
			   json_object *json)
{
	struct route_table *table;
	struct route_node *rn;

	table = get_rnh_table(vrfid, afi, safi);
	if (!table) {
		if (IS_ZEBRA_DEBUG_NHT)
			zlog_debug("print_rnhs: rnh table not found");
		return;
	}

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		if (p && !prefix_match(&rn->p, p))
			continue;

		if (rn->info)
			print_rnh(rn, vty, json);
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
	zebra_nhg_free(re->nhe);
	zebra_rib_route_entry_free(re);
}

/**
 * zebra_rnh_node_cleanup - cleanup RNH container and all RNHs in a route node
 *
 * This is called during RNH table deletion (e.g., VRF deletion).
 * It properly handles the new rnh_container structure.
 */
void zebra_rnh_node_cleanup(struct route_node *node)
{
	struct rnh_container *rnhc;
	struct rnh *rnh;

	if (!node->info)
		return;

	rnhc = node->info;

	frr_each_safe (rnh_rbtree, &rnhc->rnh_rbtree, rnh) {
		rnh_rbtree_del(&rnhc->rnh_rbtree, rnh);

		/* Mark as deleted to avoid recursive cleanup attempts */
		rnh->flags |= ZEBRA_NHT_DELETED;

		/* MUST remove from routing table dest->nht lists first! */
		zebra_rnh_remove_from_routing_table(rnh);

		/* Clean up RNH resources */
		list_delete(&rnh->zebra_pseudowire_list);
		free_state(rnh->vrf_id, rnh->state, rnh->node);
		XFREE(MTYPE_RNH, rnh);
	}

	/* Clean up the container */
	rnh_rbtree_fini(&rnhc->rnh_rbtree);
	XFREE(MTYPE_RNH_CONTAINER, rnhc);
	node->info = NULL;
}

static void copy_state(struct rnh *rnh, const struct route_entry *re,
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

	state->nhe = zebra_nhe_copy(re->nhe, 0);

	rnh->state = state;
}

/*
 * Locate the next primary nexthop, used when comparing current rnh info with
 * an updated route.
 */
static struct nexthop *next_valid_primary_nh(struct route_entry *re,
					     struct nexthop *nh)
{
	struct nexthop_group *nhg;

	/* Default path: no special handling, just using the 'installed'
	 * primary nexthops and the common validity test.
	 */
	if (nh == NULL) {
		nhg = rib_get_fib_nhg(re);
		nh = nhg->nexthop;
	} else
		nh = nexthop_next(nh);

	while (nh) {
		if (rnh_nexthop_valid(re, nh))
			break;
		else
			nh = nexthop_next(nh);
	}

	return nh;
}

/*
 * Compare two route_entries' nexthops. Account for backup nexthops
 * and for the 'fib' nexthop lists, if present.
 */
static bool compare_valid_nexthops(struct route_entry *r1,
				   struct route_entry *r2)
{
	bool matched_p = false;
	struct nexthop *nh1, *nh2;

	/* Start with the primary nexthops */

	nh1 = next_valid_primary_nh(r1, NULL);
	nh2 = next_valid_primary_nh(r2, NULL);

	while (1) {
		/* Find any differences in the nexthop lists */

		if (nh1 && nh2) {
			/* Any difference is a no-match */
			if (nexthop_cmp(nh1, nh2) != 0) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug("%s: nh1: %pNHv, nh2: %pNHv differ",
						   __func__, nh1, nh2);
				goto done;
			}

		} else if (nh1 || nh2) {
			/* One list has more valid nexthops than the other */
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%s: nh1 %s, nh2 %s", __func__,
					   nh1 ? "non-NULL" : "NULL",
					   nh2 ? "non-NULL" : "NULL");
			goto done;
		} else
			break; /* Done with both lists */

		nh1 = next_valid_primary_nh(r1, nh1);
		nh2 = next_valid_primary_nh(r2, nh2);
	}

	/* Well, it's a match */
	matched_p = true;

done:

	if (IS_ZEBRA_DEBUG_NHT_DETAILED)
		zlog_debug("%s: %smatched",
			   __func__, (matched_p ? "" : "NOT "));

	return matched_p;
}

/* Returns 'false' if no difference. */
static bool compare_state(struct route_entry *r1,
			  struct route_entry *r2)
{
	if (!r1 && !r2)
		return false;

	if ((!r1 && r2) || (r1 && !r2))
		return true;

	if (r1->type != r2->type)
		return true;

	if (r1->distance != r2->distance)
		return true;

	if (r1->metric != r2->metric)
		return true;

	if (!compare_valid_nexthops(r1, r2))
		return true;

	return false;
}

int zebra_send_rnh_update(struct rnh *rnh, struct zserv *client,
			  vrf_id_t vrf_id, uint32_t srte_color)
{
	struct stream *s = NULL;
	struct route_entry *re;
	unsigned long nump;
	uint16_t num;
	struct nexthop *nh;
	struct route_node *rn;
	int ret;
	uint32_t message = 0;

	rn = rnh->node;
	re = rnh->state;

	/* Get output stream. */
	s = stream_new_expandable(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_NEXTHOP_UPDATE, vrf_id);

	/* Message flags. */
	if (srte_color)
		SET_FLAG(message, ZAPI_MESSAGE_SRTE);
	stream_putl(s, message);

	/*
	 * Put what we were told to match against
	 */
	stream_putw(s, rnh->safi);
	stream_putw(s, rn->p.family);
	stream_putc(s, rn->p.prefixlen);
	switch (rn->p.family) {
	case AF_INET:
		stream_put_in_addr(s, &rn->p.u.prefix4);
		break;
	case AF_INET6:
		stream_put(s, &rn->p.u.prefix6, IPV6_MAX_BYTELEN);
		break;
	default:
		flog_err(EC_ZEBRA_RNH_UNKNOWN_FAMILY,
			 "%s: Unknown family (%d) notification attempted",
			 __func__, rn->p.family);
		goto failure;
	}

	/*
	 * What we matched against
	 */
	stream_putw(s, rnh->resolved_route.family);
	stream_putc(s, rnh->resolved_route.prefixlen);
	switch (rnh->resolved_route.family) {
	case AF_INET:
		stream_put_in_addr(s, &rnh->resolved_route.u.prefix4);
		break;
	case AF_INET6:
		stream_put(s, &rnh->resolved_route.u.prefix6, IPV6_MAX_BYTELEN);
		break;
	default:
		flog_err(EC_ZEBRA_RNH_UNKNOWN_FAMILY,
			 "%s: Unknown family (%d) notification attempted",
			 __func__, rn->p.family);
		goto failure;
	}

	if (srte_color)
		stream_putl(s, srte_color);

	if (re) {
		struct zapi_nexthop znh;
		struct nexthop_group *nhg;

		stream_putc(s, re->type);
		stream_putw(s, re->instance);
		stream_putc(s, re->distance);
		stream_putl(s, re->metric);
		num = 0;
		nump = stream_get_endp(s);
		stream_putw(s, 0);

		nhg = rib_get_fib_nhg(re);
		for (ALL_NEXTHOPS_PTR(nhg, nh))
			if (rnh_nexthop_valid(re, nh)) {
				zapi_nexthop_from_nexthop(&znh, nh);
				ret = zapi_nexthop_encode(s, &znh, 0, message);
				if (ret < 0)
					goto failure;

				num++;
			}

		stream_putw_at(s, nump, num);
	} else {
		stream_putc(s, 0); // type
		stream_putw(s, 0); // instance
		stream_putc(s, 0); // distance
		stream_putl(s, 0); // metric
		stream_putw(s, 0); // nexthops
	}
	stream_putw_at(s, 0, stream_get_endp(s));

	client->nh_last_upd_time = monotime(NULL);
	return zserv_send_message(client, s);

failure:

	stream_free(s);
	return -1;
}


/*
 * Render a nexthop into a json object; the caller allocates and owns
 * the json object memory.
 */
void show_nexthop_json_helper(json_object *json_nexthop,
			      const struct nexthop *nexthop,
			      const struct route_node *rn,
			      const struct route_entry *re)
{
	bool display_vrfid = false;
	uint8_t rn_family;

	if ((re == NULL || nexthop->vrf_id != re->vrf_id) && nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		display_vrfid = true;

	if (rn)
		rn_family = rn->p.family;
	else
		rn_family = AF_UNSPEC;

	nexthop_json_helper(json_nexthop, nexthop, display_vrfid, rn_family);
}

/*
 * Helper for nexthop output, used in the 'show ip route' path
 */
void show_route_nexthop_helper(struct vty *vty, const struct route_node *rn,
			       const struct route_entry *re,
			       const struct nexthop *nexthop)
{
	bool display_vrfid = false;
	uint8_t rn_family;

	if ((re == NULL || nexthop->vrf_id != re->vrf_id) && nexthop->type != NEXTHOP_TYPE_BLACKHOLE)
		display_vrfid = true;

	if (rn)
		rn_family = rn->p.family;
	else
		rn_family = AF_UNSPEC;

	nexthop_vty_helper(vty, nexthop, display_vrfid, rn_family);
}

static void print_rnh(struct route_node *rn, struct vty *vty, json_object *json)
{
	struct rnh_container *rnhc;
	struct rnh *rnh, *compare_rnh;
	struct nexthop *nexthop;
	struct zserv *client;
	char buf[BUFSIZ];
	char flags_buf[64];
	json_object *json_nht = NULL;
	json_object *json_resolutions = NULL;
	json_object *json_resolution = NULL;
	json_object *json_client_array = NULL;
	json_object *json_client = NULL;
	json_object *json_nexthop_array = NULL;
	json_object *json_nexthop = NULL;
	bool first_resolution = true;

	rnhc = rn->info;
	if (!rnhc)
		return;

	/* Build prefix string */
	snprintf(buf, sizeof(buf), "%s",
		 inet_ntop(rn->p.family, &rn->p.u.prefix, flags_buf, sizeof(flags_buf)));

	if (json) {
		json_nht = json_object_new_object();
		json_resolutions = json_object_new_array();
		json_object_object_add(json, buf, json_nht);
		json_object_object_add(json_nht, "resolutions", json_resolutions);
	} else {
		vty_out(vty, "%s\n", buf);
	}

	/* Group clients by their resolution.
	 * Different clients can resolve to different prefixes due to
	 * different flags (CONNECTED, RESOLVE_VIA_DEFAULT, etc.)
	 */
	frr_each (rnh_rbtree, &rnhc->rnh_rbtree, rnh) {
		bool already_shown = false;
		bool first_client = true;

		/* Check if we already displayed this resolution */
		frr_each (rnh_rbtree, &rnhc->rnh_rbtree, compare_rnh) {
			if (compare_rnh == rnh)
				break;

			/* Same resolution if same state and resolved_route */
			if (compare_rnh->state == rnh->state &&
			    prefix_same(&compare_rnh->resolved_route, &rnh->resolved_route)) {
				already_shown = true;
				break;
			}
		}

		if (already_shown)
			continue;

		/* Show resolution details for this group */
		if (json) {
			json_resolution = json_object_new_object();
			json_nexthop_array = json_object_new_array();
			json_client_array = json_object_new_array();
			json_object_array_add(json_resolutions, json_resolution);
			json_object_object_add(json_resolution, "clientList", json_client_array);
			json_object_object_add(json_resolution, "nexthops", json_nexthop_array);
		}

		if (rnh->state) {
			if (json) {
				json_object_string_add(json_resolution, "resolvedProtocol",
						       zebra_route_string(rnh->state->type));
				json_object_string_addf(json_resolution, "prefix", "%pFX",
							&rnh->resolved_route);
			} else {
				if (!first_resolution)
					vty_out(vty, "\n");
				vty_out(vty, " resolved via %s, prefix %pFX\n",
					zebra_route_string(rnh->state->type), &rnh->resolved_route);
				first_resolution = false;
			}

			for (nexthop = rnh->state->nhe->nhg.nexthop; nexthop;
			     nexthop = nexthop->next) {
				if (json) {
					json_nexthop = json_object_new_object();
					json_object_array_add(json_nexthop_array, json_nexthop);
					show_nexthop_json_helper(json_nexthop, nexthop, rn, NULL);
				} else {
					show_route_nexthop_helper(vty, rn, NULL, nexthop);
					vty_out(vty, "\n");
				}
			}
		} else {
			if (json)
				json_object_boolean_add(json_resolution, "unresolved", true);
			else {
				if (!first_resolution)
					vty_out(vty, "\n");
				vty_out(vty, " unresolved\n");
				first_resolution = false;
			}
		}

		/* Show client list for this resolution group */
		if (!json)
			vty_out(vty, " Client list:");

		/* Iterate again to find all clients with same resolution */
		frr_each (rnh_rbtree, &rnhc->rnh_rbtree, compare_rnh) {
			client = compare_rnh->client;

			/* Only show clients that match this resolution */
			if (!(compare_rnh->state == rnh->state &&
			      prefix_same(&compare_rnh->resolved_route, &rnh->resolved_route)))
				continue;

			/* Skip pseudowire sentinel client in client list */
			if (client == PSEUDOWIRE_CLIENT) {
				/* But do show pseudowires if attached */
				if (!json && !list_isempty(compare_rnh->zebra_pseudowire_list)) {
					vty_out(vty, "%szebra[pseudowires]",
						first_client ? " " : " ");
					first_client = false;
				}
				if (json && !list_isempty(compare_rnh->zebra_pseudowire_list))
					json_object_boolean_true_add(json_resolution,
								     "zebraPseudowires");
				continue;
			}

			if (json) {
				json_client = json_object_new_object();
				json_object_array_add(json_client_array, json_client);

				if (client) {
					json_object_string_add(json_client, "protocol",
							       zebra_route_string(client->proto));
					json_object_int_add(json_client, "socket", client->sock);
					json_object_boolean_add(json_client, "filtered",
								compare_rnh->filtered);
					json_object_boolean_add(json_client, "nhtConnected",
								CHECK_FLAG(compare_rnh->flags,
									   ZEBRA_NHT_CONNECTED));
					json_object_boolean_add(json_client, "nhtResolveViaDefault",
								CHECK_FLAG(compare_rnh->flags,
									   ZEBRA_NHT_RESOLVE_VIA_DEFAULT));
				}
			} else {
				if (client) {
					char flags_str[32] = "";

					/* Build flag string */
					if (CHECK_FLAG(compare_rnh->flags, ZEBRA_NHT_CONNECTED))
						strlcat(flags_str, ",Connected", sizeof(flags_str));
					if (CHECK_FLAG(compare_rnh->flags,
						       ZEBRA_NHT_RESOLVE_VIA_DEFAULT))
						strlcat(flags_str, ",ResolveViaDefault",
							sizeof(flags_str));
					if (compare_rnh->filtered)
						strlcat(flags_str, ",filtered", sizeof(flags_str));

					/* Remove leading comma if present */
					const char *display_flags = flags_str[0] == ','
									    ? flags_str + 1
									    : flags_str;

					vty_out(vty, "%s%s(fd %d)%s%s%s", first_client ? " " : " ",
						zebra_route_string(client->proto), client->sock,
						display_flags[0] ? "(" : "", display_flags,
						display_flags[0] ? ")" : "");
					first_client = false;
				}
			}
		}

		if (!json)
			vty_out(vty, "\n");
	}
}

static int zebra_cleanup_rnh_client(vrf_id_t vrf_id, afi_t afi, safi_t safi,
				    struct zserv *client)
{
	struct route_table *ntable;
	struct route_node *nrn;
	struct rnh_container *rnhc;
	struct rnh *rnh;

	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);

		zlog_debug("%s(%u): Client %s RNH cleanup for family %s",
			   VRF_LOGNAME(vrf), vrf_id,
			   zebra_route_string(client->proto), afi2str(afi));
	}

	ntable = get_rnh_table(vrf_id, afi, safi);
	if (!ntable) {
		zlog_debug("cleanup_rnh_client: rnh table not found");
		return -1;
	}

	for (nrn = route_top(ntable); nrn; nrn = route_next(nrn)) {
		if (!nrn->info)
			continue;

		rnhc = nrn->info;

		/* Find the rnh for this client and remove it */
		frr_each_safe (rnh_rbtree, &rnhc->rnh_rbtree, rnh) {
			if (rnh->client == client)
				zebra_remove_rnh_client(rnh, client);
		}
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
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP,
						 SAFI_UNICAST, client);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP,
						 SAFI_MULTICAST, client);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP6,
						 SAFI_UNICAST, client);
			zebra_cleanup_rnh_client(zvrf_id(zvrf), AFI_IP6,
						 SAFI_MULTICAST, client);
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
