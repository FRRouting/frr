// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra next hop tracking code
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include "frrevent.h"
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
#include "zebra/zebra_srte.h"
#include "zebra/interface.h"
#include "zebra/zebra_errors.h"

DEFINE_MTYPE_STATIC(ZEBRA, RNH, "Nexthop tracking object");

/* UI controls whether to notify about changes that only involve backup
 * nexthops. Default is to notify all changes.
 */
static bool rnh_hide_backups;

static void free_state(vrf_id_t vrf_id, struct route_entry *re,
		       struct route_node *rn);
static void copy_state(struct rnh *rnh, const struct route_entry *re,
		       struct route_node *rn);
static bool compare_state(struct route_entry *r1, struct route_entry *r2);
static void print_rnh(struct route_node *rn, struct vty *vty,
		      json_object *json);
static int zebra_client_cleanup_rnh(struct zserv *client);

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
	struct route_table *table = zvrf->table[rnh->afi][rnh->safi];
	struct route_node *rn;
	rib_dest_t *dest;

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
	struct route_table *table = zvrf->table[rnh->afi][rnh->safi];
	struct route_node *rn;
	rib_dest_t *dest;

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

struct rnh *zebra_add_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi,
			  bool *exists)
{
	struct route_table *table;
	struct route_node *rn;
	struct rnh *rnh = NULL;
	afi_t afi = family2afi(p->family);

	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(vrfid);

		zlog_debug("%s(%u): Add RNH %pFX for safi: %u",
			   VRF_LOGNAME(vrf), vrfid, p, safi);
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
		rnh->seqno = 0;
		rnh->afi = afi;
		rnh->safi = safi;
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

struct rnh *zebra_lookup_rnh(struct prefix *p, vrf_id_t vrfid, safi_t safi)
{
	struct route_table *table;
	struct route_node *rn;

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
	table = zvrf->table[family2afi(rnh->resolved_route.family)][rnh->safi];

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

static void zebra_delete_rnh(struct rnh *rnh)
{
	struct route_node *rn;

	if (!list_isempty(rnh->client_list)
	    || !list_isempty(rnh->zebra_pseudowire_list))
		return;

	if ((rnh->flags & ZEBRA_NHT_DELETED) || !(rn = rnh->node))
		return;

	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(rnh->vrf_id);

		zlog_debug("%s(%u): Del RNH %pRN", VRF_LOGNAME(vrf),
			   rnh->vrf_id, rnh->node);
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
			  vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_NHT) {
		struct vrf *vrf = vrf_lookup_by_id(vrf_id);

		zlog_debug("%s(%u): Client %s registers for RNH %pRN",
			   VRF_LOGNAME(vrf), vrf_id,
			   zebra_route_string(client->proto), rnh->node);
	}
	if (!listnode_lookup(rnh->client_list, client))
		listnode_add(rnh->client_list, client);

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
			   vrf->vrf_id, rnh->node);
	}
	listnode_delete(rnh->client_list, client);
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
	rnh = zebra_add_rnh(&nh, vrf_id, SAFI_UNICAST, &exists);
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
	int num_resolving_nh;

	if (IS_ZEBRA_DEBUG_NHT) {
		if (prn && re) {
			zlog_debug("%s(%u):%pRN: NH resolved over route %pRN",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id,
				   nrn, prn);
		} else
			zlog_debug("%s(%u):%pRN: NH has become unresolved",
				   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id,
				   nrn);
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
					"%s(%u):%pRN: Notifying client %s about NH %s",
					VRF_LOGNAME(zvrf->vrf),
					zvrf->vrf->vrf_id, nrn,
					zebra_route_string(client->proto),
					num_resolving_nh
						? ""
						: "(filtered by route-map)");
		} else {
			rnh->filtered[client->proto] = 0;
			if (IS_ZEBRA_DEBUG_NHT)
				zlog_debug(
					"%s(%u):%pRN: Notifying client %s about NH (unreachable)",
					VRF_LOGNAME(zvrf->vrf),
					zvrf->vrf->vrf_id, nrn,
					zebra_route_string(client->proto));
		}

		zebra_send_rnh_update(rnh, client, zvrf->vrf->vrf_id, 0);
	}

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

/* Evaluate one tracked entry */
static void zebra_rnh_evaluate_entry(struct zebra_vrf *zvrf, afi_t afi,
				     int force, struct route_node *nrn)
{
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	if (IS_ZEBRA_DEBUG_NHT) {
		zlog_debug("%s(%u):%pRN: Evaluate RNH, %s",
			   VRF_LOGNAME(zvrf->vrf), zvrf->vrf->vrf_id, nrn,
			   force ? "(force)" : "");
	}

	rnh = nrn->info;

	/* Identify route entry (RE) resolving this tracked entry. */
	re = zebra_rnh_resolve_nexthop_entry(zvrf, afi, nrn, rnh, &prn);

	/* If the entry cannot be resolved and that is also the existing state,
	 * there is nothing further to do.
	 */
	if (!re && rnh->state == NULL && !force)
		return;

	/* Process based on type of entry. */
	zebra_rnh_eval_nexthop_entry(zvrf, afi, force, nrn, rnh, prn, re);
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
	struct rnh *rnh;
	struct route_entry *re;
	struct route_node *prn;

	rnh = nrn->info;

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
	if (!rnh_table) // unexpected
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
	XFREE(MTYPE_RE, re);
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

	/* Copy the 'fib' nexthops also, if present - we want to capture
	 * the true installed nexthops.
	 */
	if (re->fib_ng.nexthop)
		nexthop_group_copy(&state->fib_ng, &re->fib_ng);
	if (re->fib_backup_ng.nexthop)
		nexthop_group_copy(&state->fib_backup_ng, &re->fib_backup_ng);

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
	struct nexthop *bnh;
	int i, idx;
	bool default_path = true;

	/* Fib backup ng present: some backups are installed,
	 * and we're configured for special handling if there are backups.
	 */
	if (rnh_hide_backups && (re->fib_backup_ng.nexthop != NULL))
		default_path = false;

	/* Default path: no special handling, just using the 'installed'
	 * primary nexthops and the common validity test.
	 */
	if (default_path) {
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

	/* Hide backup activation/switchover events.
	 *
	 * If we've had a switchover, an inactive primary won't be in
	 * the fib list at all - the 'fib' list could even be empty
	 * in the case where no primary is installed. But we want to consider
	 * those primaries "valid" if they have an activated backup nh.
	 *
	 * The logic is something like:
	 * if (!fib_nhg)
	 *     // then all primaries are installed
	 * else
	 *     for each primary in re nhg
	 *         if in fib_nhg
	 *             primary is installed
	 *         else if a backup is installed
	 *             primary counts as installed
	 *         else
	 *             primary !installed
	 */

	/* Start with the first primary */
	if (nh == NULL)
		nh = re->nhe->nhg.nexthop;
	else
		nh = nexthop_next(nh);

	while (nh) {

		if (IS_ZEBRA_DEBUG_NHT_DETAILED)
			zlog_debug("%s: checking primary NH %pNHv",
				   __func__, nh);

		/* If this nexthop is in the fib list, it's installed */
		nhg = rib_get_fib_nhg(re);

		for (bnh = nhg->nexthop; bnh; bnh = nexthop_next(bnh)) {
			if (nexthop_cmp(nh, bnh) == 0)
				break;
		}

		if (bnh != NULL) {
			/* Found the match */
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%s:     NH in fib list", __func__);
			break;
		}

		/* Else if this nexthop's backup is installed, it counts */
		nhg = rib_get_fib_backup_nhg(re);
		bnh = nhg->nexthop;

		for (idx = 0; bnh != NULL; idx++) {
			/* If we find an active backup nh for this
			 * primary, we're done;
			 */
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%s: checking backup %pNHv [%d]",
					   __func__, bnh, idx);

			if (!CHECK_FLAG(bnh->flags, NEXTHOP_FLAG_ACTIVE))
				continue;

			for (i = 0; i < nh->backup_num; i++) {
				/* Found a matching activated backup nh */
				if (nh->backup_idx[i] == idx) {
					if (IS_ZEBRA_DEBUG_NHT_DETAILED)
						zlog_debug("%s: backup %d activated",
							   __func__, i);

					goto done;
				}
			}

			/* Note that we're not recursing here if the
			 * backups are recursive: the primary's index is
			 * only valid in the top-level backup list.
			 */
			bnh = bnh->next;
		}

		/* Try the next primary nexthop */
		nh = nexthop_next(nh);
	}

done:

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
	struct nexthop_group *nhg1, *nhg2;
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

	/* If configured, don't compare installed backup state - we've
	 * accounted for that with the primaries above.
	 *
	 * But we do want to compare the routes' backup info,
	 * in case the owning route has changed the backups -
	 * that change we do want to report.
	 */
	if (rnh_hide_backups) {
		uint32_t hash1 = 0, hash2 = 0;

		if (r1->nhe->backup_info)
			hash1 = nexthop_group_hash(
				&r1->nhe->backup_info->nhe->nhg);

		if (r2->nhe->backup_info)
			hash2 = nexthop_group_hash(
				&r2->nhe->backup_info->nhe->nhg);

		if (IS_ZEBRA_DEBUG_NHT_DETAILED)
			zlog_debug("%s: backup hash1 %#x, hash2 %#x",
				   __func__, hash1, hash2);

		if (hash1 != hash2)
			goto done;
		else
			goto finished;
	}

	/* The test for the backups is slightly different: the only installed
	 * backups will be in the 'fib' list.
	 */
	nhg1 = rib_get_fib_backup_nhg(r1);
	nhg2 = rib_get_fib_backup_nhg(r2);

	nh1 = nhg1->nexthop;
	nh2 = nhg2->nexthop;

	while (1) {
		/* Find each backup list's next valid nexthop */
		while ((nh1 != NULL) && !rnh_nexthop_valid(r1, nh1))
			nh1 = nexthop_next(nh1);

		while ((nh2 != NULL) && !rnh_nexthop_valid(r2, nh2))
			nh2 = nexthop_next(nh2);

		if (nh1 && nh2) {
			/* Any difference is a no-match */
			if (nexthop_cmp(nh1, nh2) != 0) {
				if (IS_ZEBRA_DEBUG_NHT_DETAILED)
					zlog_debug("%s: backup nh1: %pNHv, nh2: %pNHv differ",
						   __func__, nh1, nh2);
				goto done;
			}

			nh1 = nexthop_next(nh1);
			nh2 = nexthop_next(nh2);
		} else if (nh1 || nh2) {
			/* One list has more valid nexthops than the other */
			if (IS_ZEBRA_DEBUG_NHT_DETAILED)
				zlog_debug("%s: backup nh1 %s, nh2 %s",
					   __func__,
					   nh1 ? "non-NULL" : "NULL",
					   nh2 ? "non-NULL" : "NULL");
			goto done;
		} else
			break; /* Done with both lists */
	}

finished:

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
	uint8_t num;
	struct nexthop *nh;
	struct route_node *rn;
	int ret;
	uint32_t message = 0;

	rn = rnh->node;
	re = rnh->state;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

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
		stream_putc(s, 0);

		nhg = rib_get_fib_nhg(re);
		for (ALL_NEXTHOPS_PTR(nhg, nh))
			if (rnh_nexthop_valid(re, nh)) {
				zapi_nexthop_from_nexthop(&znh, nh);
				ret = zapi_nexthop_encode(s, &znh, 0, message);
				if (ret < 0)
					goto failure;

				num++;
			}

		nhg = rib_get_fib_backup_nhg(re);
		if (nhg) {
			for (ALL_NEXTHOPS_PTR(nhg, nh))
				if (rnh_nexthop_valid(re, nh)) {
					zapi_nexthop_from_nexthop(&znh, nh);
					ret = zapi_nexthop_encode(
						s, &znh, 0 /* flags */,
						0 /* message */);
					if (ret < 0)
						goto failure;

					num++;
				}
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

	if (re == NULL || nexthop->vrf_id != re->vrf_id)
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

	if (re == NULL || nexthop->vrf_id != re->vrf_id)
		display_vrfid = true;

	if (rn)
		rn_family = rn->p.family;
	else
		rn_family = AF_UNSPEC;

	nexthop_vty_helper(vty, nexthop, display_vrfid, rn_family);
}

static void print_rnh(struct route_node *rn, struct vty *vty, json_object *json)
{
	struct rnh *rnh;
	struct nexthop *nexthop;
	struct listnode *node;
	struct zserv *client;
	char buf[BUFSIZ];
	json_object *json_nht = NULL;
	json_object *json_client_array = NULL;
	json_object *json_client = NULL;
	json_object *json_nexthop_array = NULL;
	json_object *json_nexthop = NULL;

	rnh = rn->info;

	if (json) {
		json_nht = json_object_new_object();
		json_nexthop_array = json_object_new_array();
		json_client_array = json_object_new_array();

		json_object_object_add(
			json,
			inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
			json_nht);
		json_object_boolean_add(
			json_nht, "nhtConnected",
			CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED));
		json_object_object_add(json_nht, "clientList",
				       json_client_array);
		json_object_object_add(json_nht, "nexthops",
				       json_nexthop_array);
	} else {
		vty_out(vty, "%s%s\n",
			inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
			CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)
				? "(Connected)"
				: "");
	}

	if (rnh->state) {
		if (json)
			json_object_string_add(
				json_nht, "resolvedProtocol",
				zebra_route_string(rnh->state->type));
		else
			vty_out(vty, " resolved via %s\n",
				zebra_route_string(rnh->state->type));

		for (nexthop = rnh->state->nhe->nhg.nexthop; nexthop;
		     nexthop = nexthop->next) {
			if (json) {
				json_nexthop = json_object_new_object();
				json_object_array_add(json_nexthop_array,
						      json_nexthop);
				show_nexthop_json_helper(json_nexthop, nexthop,
							 rn, NULL);
			} else {
				show_route_nexthop_helper(vty, rn, NULL,
							  nexthop);
				vty_out(vty, "\n");
			}
		}
	} else {
		if (json)
			json_object_boolean_add(
				json_nht, "unresolved",
				CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED));
		else
			vty_out(vty, " unresolved%s\n",
				CHECK_FLAG(rnh->flags, ZEBRA_NHT_CONNECTED)
					? "(Connected)"
					: "");
	}

	if (!json)
		vty_out(vty, " Client list:");

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
		if (json) {
			json_client = json_object_new_object();
			json_object_array_add(json_client_array, json_client);

			json_object_string_add(
				json_client, "protocol",
				zebra_route_string(client->proto));
			json_object_int_add(json_client, "socket",
					    client->sock);
			json_object_string_add(json_client, "protocolFiltered",
					       (rnh->filtered[client->proto]
							? "(filtered)"
							: "none"));
		} else {
			vty_out(vty, " %s(fd %d)%s",
				zebra_route_string(client->proto), client->sock,
				rnh->filtered[client->proto] ? "(filtered)"
							     : "");
		}
	}

	if (!list_isempty(rnh->zebra_pseudowire_list)) {
		if (json)
			json_object_boolean_true_add(json_nht,
						     "zebraPseudowires");
		else
			vty_out(vty, " zebra[pseudowires]");
	}

	if (!json)
		vty_out(vty, "\n");
}

static int zebra_cleanup_rnh_client(vrf_id_t vrf_id, afi_t afi, safi_t safi,
				    struct zserv *client)
{
	struct route_table *ntable;
	struct route_node *nrn;
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

		rnh = nrn->info;
		zebra_remove_rnh_client(rnh, client);
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

/*
 * UI control to avoid notifications if backup nexthop status changes
 */
void rnh_set_hide_backups(bool hide_p)
{
	rnh_hide_backups = hide_p;
}

bool rnh_get_hide_backups(void)
{
	return rnh_hide_backups;
}
