// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound configuration callbacks.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "if.h"
#include "lib/bfd.h"
#include "libospf.h"
#include "prefix.h"
#include "table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_zebra.h"

/*
 * RFC 9129 ietf-ospf area-type identityref values. Accept both the bare
 * identity name and the module-qualified form so callers do not depend on the
 * exact libyang serialisation context used for this dnode.
 */
#define OSPF_AREA_TYPE_NORMAL "normal-area"
#define OSPF_AREA_TYPE_STUB   "stub-area"
#define OSPF_AREA_TYPE_NSSA   "nssa-area"

static bool ospf_area_type_is(const char *val, const char *name)
{
	if (!val)
		return false;
	if (!strcmp(val, name))
		return true;
	if (strncmp(val, "ietf-ospf:", strlen("ietf-ospf:")) == 0)
		return !strcmp(val + strlen("ietf-ospf:"), name);
	return false;
}

static bool ospfd_ietf_ospf_type_is(const char *val)
{
	return val && (!strcmp(val, "ospfv2") ||
		       !strcmp(val, "ietf-ospf:ospfv2"));
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 *
 * Keep the IETF routing protocol list present in the local candidate whenever
 * the legacy `router ospf` CLI creates the daemon instance directly. Child
 * commands converted to RFC 9129 leaves, such as explicit-router-id, then have
 * a real parent list entry to modify during the pending NB commit.
 */
int ospfd_ietf_routing_control_plane_protocol_create(struct nb_cb_create_args *args)
{
	const char *type;
	const char *name;
	bool created = false;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!ospfd_ietf_ospf_type_is(type))
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!name)
		name = VRF_DEFAULT_NAME;

	ospf_get(ospf_instance, name, &created);

	return NB_OK;
}

int ospfd_ietf_routing_control_plane_protocol_destroy(struct nb_cb_destroy_args *args)
{
	const char *type;
	const char *name;
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!ospfd_ietf_ospf_type_is(type))
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!name)
		name = VRF_DEFAULT_NAME;

	ospf = ospfd_ietf_ospf_lookup_instance(name);
	if (!ospf)
		return NB_OK;

	if (ospf->gr_info.restart_support)
		ospf_gr_nvm_delete(ospf);
	ospf_finish(ospf);

	return NB_OK;
}

/*
 * Look up the OSPF instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
 *
 * mgmtd's predicate-aware dispatch (mgmt_be_xpath_prefix) routes only
 * control-plane-protocol[type='ietf-ospf:ospfv2'] entries to ospfd. In
 * daemon-instance mode, each ospfd backend also registers its own `name`
 * predicate, so the instance-name check is handled at the dispatch layer
 * and not repeated here.
 *
 * Returns NULL when no FRR-side OSPF instance exists for the named
 * control-plane-protocol; the caller should treat the configuration as a
 * no-op until the instance is created (today: via `router ospf`).
 */
static struct ospf *ospfd_ietf_ospf_instance_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *cpp;
	const char *name;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (!cpp)
		return NULL;

	name = yang_dnode_get_string(cpp, "name");
	return ospfd_ietf_ospf_lookup_instance(name);
}

/*
 * Resolve the OSPF instance for create / modify callbacks. Per-leaf callbacks
 * route through this so mgmtd cannot accept a commit whose APPLY phase would
 * be a silent no-op.
 *
 * Returns:
 *   NB_OK + *ospf_out set      -- proceed.
 *   NB_OK + *ospf_out == NULL  -- APPLY-phase race tolerated (the instance
 *                                 vanished between VALIDATE and APPLY).
 *                                 Caller should bail out cleanly.
 *   NB_ERR_INCONSISTENCY       -- VALIDATE rejected the commit.
 */
static int ospfd_ietf_ospf_resolve_instance(const struct lyd_node *dnode, enum nb_event event,
					    char *errmsg, size_t errmsg_len, struct ospf **ospf_out)
{
	struct ospf *ospf;

	ospf = ospfd_ietf_ospf_instance_from_dnode(dnode);
	*ospf_out = ospf;
	if (ospf)
		return NB_OK;

	if (event == NB_EV_VALIDATE) {
		const struct lyd_node *cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");

		snprintf(errmsg, errmsg_len,
			 "OSPF instance '%s' is not configured (use 'router ospf' first)",
			 cpp ? yang_dnode_get_string(cpp, "name") : "?");
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
}


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/explicit-router-id
 */
int ospfd_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr router_id;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	ospf->router_id_static = router_id;
	ospf_router_id_update(ospf);

	return NB_OK;
}

int ospfd_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;

	ospf->router_id_static.s_addr = INADDR_ANY;
	ospf_router_id_update(ospf);

	return NB_OK;
}

/*
 * Walk up from a dnode within the areas/area subtree to extract the
 * area-id key. Returns 0 on success, -1 on failure.
 */
static int ospfd_ietf_ospf_area_id_from_dnode(const struct lyd_node *dnode, struct in_addr *area_id)
{
	const struct lyd_node *area_node;
	const char *area_id_str;

	area_node = yang_dnode_get_parent(dnode, "area");
	if (!area_node)
		return -1;

	area_id_str = yang_dnode_get_string(area_node, "area-id");
	if (inet_pton(AF_INET, area_id_str, area_id) != 1)
		return -1;
	return 0;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 *
 * area-id key is an RFC 9129 area-id-type, which serialises as A.B.C.D.
 * ospf_area_get (the FRR-internal lookup-or-create). Areas are deliberately
 * not anchored on the running dnode: legacy-compatible cleanup such as
 * deleting area-type can free an otherwise empty area while the YANG area list
 * node remains present.
 */
int ospfd_ietf_ospf_areas_area_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr area_id;
	const char *area_id_str;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area_id_str = yang_dnode_get_string(args->dnode, "area-id");
	if (inet_pton(AF_INET, area_id_str, &area_id) != 1)
		return NB_ERR_VALIDATION;

	(void)ospf_area_get(ospf, area_id);

	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct in_addr area_id;
	const char *area_id_str;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;

	area_id_str = yang_dnode_get_string(args->dnode, "area-id");
	if (inet_pton(AF_INET, area_id_str, &area_id) != 1)
		return NB_ERR_VALIDATION;

	/*
	 * Reset every area attr back to FRR defaults so
	 * ospf_area_check_free's precondition (external_routing == DEFAULT,
	 * no_summary == 0, default_cost == 1, no ranges) can match. Per-leaf
	 * destroy isn't dispatched for leaves with YANG defaults (area-type
	 * defaults to normal-area), so we mirror those resets here.
	 */
	ospf_area_stub_unset(ospf, area_id);
	ospf_area_nssa_unset(ospf, area_id);
	ospf_area_no_summary_unset(ospf, area_id);
	{
		struct ospf_area *area;
		struct route_node *rn;
		struct prefix_ipv4 p;

		area = ospf_area_lookup_by_area_id(ospf, area_id);
		if (area) {
			struct route_node *next;

			area->default_cost = 1;

			/*
			 * Drop any area ranges before the check_free below;
			 * ospf_area_check_free requires area->ranges->top to
			 * be NULL.
			 *
			 * Snapshot the prefix BEFORE calling route_next: for
			 * radix glue nodes (rn->info == NULL, held only by the
			 * iterator at lock = 1) route_next unlocks rn to 0 and
			 * frees it, so any rn->p access afterwards is a
			 * use-after-free. Skip glue nodes outright; only data
			 * nodes (rn->info != NULL) have a stored lock that keeps
			 * rn alive after route_next.
			 */
			for (rn = route_top(area->ranges); rn; rn = next) {
				if (!rn->info) {
					next = route_next(rn);
					continue;
				}
				p.family = AF_INET;
				p.prefix = rn->p.u.prefix4;
				p.prefixlen = rn->p.prefixlen;
				next = route_next(rn);
				ospf_area_range_unset(ospf, area, area->ranges, &p);
			}
		}
	}

	ospf_area_check_free(ospf, area_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/area-type
 *
 * Map the RFC 9129 identityref values to FRR's area type setters:
 *   normal-area -> ospf_area_stub_unset + ospf_area_nssa_unset (back to DEFAULT)
 *   stub-area   -> ospf_area_stub_set
 *   nssa-area   -> ospf_area_nssa_set
 */
int ospfd_ietf_ospf_areas_area_type_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr area_id;
	const char *type;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len, "malformed area-id");
		return NB_ERR_VALIDATION;
	}

	type = yang_dnode_get_string(args->dnode, NULL);

	/*
	 * Reject stub / NSSA conversions at VALIDATE when the area has
	 * virtual links traversing it. ospf_area_{stub,nssa}_set return 0
	 * for this case but a deferred APPLY-phase NB_ERR_INCONSISTENCY is
	 * logged-and-dropped by mgmtd, leaving the YANG datastore recording
	 * stub-area/nssa-area while ospfd keeps running the area as normal
	 * -- a persistent invisible split between the two planes. Look up
	 * the area only if it already exists; atomic-create transactions
	 * cannot have virtual links yet so are tolerated by falling through
	 * to APPLY.
	 */
	if (ospf_area_type_is(type, OSPF_AREA_TYPE_STUB) ||
	    ospf_area_type_is(type, OSPF_AREA_TYPE_NSSA)) {
		struct ospf_area *area = ospf_area_lookup_by_area_id(ospf, area_id);

		if (area && ospf_area_vlink_count(ospf, area) &&
		    args->event == NB_EV_VALIDATE) {
			snprintf(args->errmsg, args->errmsg_len,
				 "area %pI4 has virtual links traversing it; remove them before converting to %s",
				 &area_id, type);
			return NB_ERR_VALIDATION;
		}
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (ospf_area_type_is(type, OSPF_AREA_TYPE_NORMAL)) {
		ospf_area_stub_unset(ospf, area_id);
		ospf_area_nssa_unset(ospf, area_id);
	} else if (ospf_area_type_is(type, OSPF_AREA_TYPE_STUB)) {
		struct ospf_area *area = ospf_area_lookup_by_area_id(ospf, area_id);
		bool was_stub = area && area->external_routing == OSPF_AREA_STUB;

		ospf_area_nssa_unset(ospf, area_id);
		if (!ospf_area_stub_set(ospf, area_id))
			return NB_ERR_INCONSISTENCY;
		/*
		 * Stub areas don't carry AS-external LSAs; purge any
		 * lingering ones from when the area was non-stub. The
		 * legacy CLI did this explicitly after stub_set, so we
		 * replicate it here to keep CLI- and YANG-driven paths
		 * semantically identical.
		 */
		if (!was_stub)
			ospf_flush_lsa_from_area(ospf, area_id, OSPF_AS_EXTERNAL_LSA);
	} else if (ospf_area_type_is(type, OSPF_AREA_TYPE_NSSA)) {
		ospf_area_stub_unset(ospf, area_id);
		if (!ospf_area_nssa_set(ospf, area_id))
			return NB_ERR_INCONSISTENCY;
	} else {
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/summary
 *
 * RFC 9129 inverts FRR's no_summary flag: summary=true means summary LSAs
 * ARE injected (the default for a stub area), summary=false means they're
 * suppressed (totally stubby).
 */
int ospfd_ietf_ospf_areas_area_summary_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr area_id;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ospf_area_no_summary_unset(ospf, area_id);
	else
		ospf_area_no_summary_set(ospf, area_id);

	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_summary_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct in_addr area_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	/*
	 * summary has no YANG default; destroy means the operator removed the
	 * explicit setting. Revert to FRR's natural default (summary LSAs on).
	 */
	ospf_area_no_summary_unset(ospf, area_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/default-cost
 *
 * The YANG `when` clause restricts this leaf to stub or NSSA areas; the
 * modify callback still defensively checks external_routing and returns
 * NB_ERR_VALIDATION on misuse rather than silently mutating an
 * inappropriate area.
 */
int ospfd_ietf_ospf_areas_area_default_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct in_addr area_id;
	struct ospf_area *area;
	struct prefix_ipv4 p = {
		.family = AF_INET,
		.prefix.s_addr = OSPF_DEFAULT_DESTINATION,
		.prefixlen = 0,
	};

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len, "malformed area-id");
		return NB_ERR_VALIDATION;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * Defer the area-existence and area-type checks to APPLY: at
	 * VALIDATE the area may be in the same candidate transaction as
	 * this leaf (atomic stub-area + default-cost commit), so
	 * ospf_area_lookup_by_area_id would return NULL even though the
	 * area-create APPLY runs first within the same transaction. RFC
	 * 9129's `when` clause on default-cost (restricts to stub / NSSA
	 * in the candidate datastore) is the authoritative area-type
	 * cross-leaf check; libyang enforces it before any callback
	 * fires. The check here is defensive at APPLY time only:
	 * silently no-op if the area is gone, defensively skip the
	 * mutation on a normal area (shouldn't happen, but matches the
	 * "logged and dropped" APPLY-error semantics).
	 */
	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;
	if (area->external_routing == OSPF_AREA_DEFAULT)
		return NB_OK;

	area->default_cost = yang_dnode_get_uint32(args->dnode, NULL);
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);

	return NB_OK;
}

/*
 * Walk up from a dnode within the area/interfaces/interface subtree to
 * extract the interface name. Returns NULL if the parent list entry
 * cannot be found (the schema guarantees it under areas/area, so this
 * is purely defensive).
 */
static const char *ospfd_ietf_ospf_interface_name_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *iface_node;

	iface_node = yang_dnode_get_parent(dnode, "interface");
	if (!iface_node)
		return NULL;
	return yang_dnode_get_string(iface_node, "name");
}

/*
 * Resolve a YANG per-interface dnode to the FRR-side struct interface in
 * the OSPF instance's VRF. ietf-interfaces names are unqualified for
 * vrf-lite mode and ":<vrf>:<name>" qualified under netns backend (the
 * same convention zebra uses to populate /ietf-interfaces:interfaces).
 * Returns NULL if no matching interface exists, which the caller treats
 * as NB_OK (no-op apply).
 */
static struct interface *ospfd_ietf_ospf_interface_from_dnode(const struct ospf *ospf,
							      const struct lyd_node *dnode)
{
	const char *name;

	name = ospfd_ietf_ospf_interface_name_from_dnode(dnode);
	if (!name)
		return NULL;
	return if_lookup_by_name(name, ospf->vrf_id);
}

static bool ospfd_ietf_ospf_area_has_interface(const struct lyd_node *area_node,
					       const char *ifname)
{
	const struct lyd_node *interfaces_node;
	const struct lyd_node *iface_node;

	interfaces_node = yang_dnode_get(area_node, "interfaces");
	if (!interfaces_node)
		return false;

	LY_LIST_FOR (lyd_child(interfaces_node), iface_node) {
		const char *name;

		if (strcmp(iface_node->schema->name, "interface"))
			continue;

		name = yang_dnode_get_string(iface_node, "name");
		if (name && !strcmp(name, ifname))
			return true;
	}

	return false;
}

static int ospfd_ietf_ospf_validate_interface_area_unique(const struct lyd_node *dnode,
							  const char *ifname, char *errmsg,
							  size_t errmsg_len)
{
	const struct lyd_node *area_node;
	const struct lyd_node *areas_node;
	const struct lyd_node *other_area_node;
	const char *area_id;

	area_node = yang_dnode_get_parent(dnode, "area");
	if (!area_node)
		return NB_OK;
	areas_node = yang_dnode_get_parent(area_node, "areas");
	if (!areas_node)
		return NB_OK;

	/*
	 * Walk the candidate subtree directly rather than synthesising an XPath
	 * predicate from the interface name. Interface names are external strings;
	 * avoiding XPath quoting keeps validation simple and exact.
	 */
	area_id = yang_dnode_get_string(area_node, "area-id");
	LY_LIST_FOR (lyd_child(areas_node), other_area_node) {
		const char *other_area_id;

		if (other_area_node == area_node ||
		    strcmp(other_area_node->schema->name, "area"))
			continue;
		if (!ospfd_ietf_ospf_area_has_interface(other_area_node, ifname))
			continue;

		other_area_id = yang_dnode_get_string(other_area_node, "area-id");
		snprintf(errmsg, errmsg_len,
			 "interface '%s' is configured under multiple OSPF areas (%s and %s)",
			 ifname, area_id, other_area_id);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * VALIDATE-rejecting variant for per-interface create / modify callbacks.
 * frr-deviations-ietf-routing-ospf keeps the RFC 9129 interface-name
 * leafref but sets require-instance false so configuration can be emitted
 * ahead of interface plumbing. This helper performs the FRR daemon-side
 * existence check, returning NB_ERR_VALIDATION at VALIDATE when the
 * interface is not present in the OSPF instance's VRF.
 *
 * Returns:
 *   NB_OK + *ifp_out set      -- proceed.
 *   NB_OK + *ifp_out == NULL  -- APPLY-phase race tolerated.
 *   NB_ERR_VALIDATION         -- VALIDATE rejected.
 */
static int ospfd_ietf_ospf_resolve_interface(const struct ospf *ospf, const struct lyd_node *dnode,
					     enum nb_event event, char *errmsg, size_t errmsg_len,
					     struct interface **ifp_out)
{
	struct interface *ifp;

	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, dnode);
	*ifp_out = ifp;
	if (ifp)
		return NB_OK;

	if (event == NB_EV_VALIDATE) {
		const struct lyd_node *iface_node = yang_dnode_get_parent(dnode, "interface");

		snprintf(errmsg, errmsg_len, "interface '%s' is not present in vrf-id %u",
			 iface_node ? yang_dnode_get_string(iface_node, "name") : "?",
			 ospf->vrf_id);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static bool ospfd_ietf_ospf_ensure_if_info(struct interface *ifp)
{
	if (!IF_OSPF_IF_INFO(ifp) && ospf_if_new_hook(ifp) != 0)
		return false;

	return IF_OSPF_IF_INFO(ifp) && IF_DEF_PARAMS(ifp);
}

static void ospfd_ietf_ospf_nbr_timer_update(struct interface *ifp)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;
		if (oi)
			ospf_nbr_timer_update(oi);
	}
}

static void ospfd_ietf_ospf_priority_update(struct interface *ifp)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;
		if (!oi)
			continue;

		if (PRIORITY(oi) == OSPF_IF_PARAM(oi, priority))
			continue;

		PRIORITY(oi) = OSPF_IF_PARAM(oi, priority);
		OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);
	}
}

int ospfd_ietf_ospf_areas_area_default_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct in_addr area_id;
	struct ospf_area *area;
	struct prefix_ipv4 p = {
		.family = AF_INET,
		.prefix.s_addr = OSPF_DEFAULT_DESTINATION,
		.prefixlen = 0,
	};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	area->default_cost = 1;
	if (area->external_routing != OSPF_AREA_DEFAULT)
		ospf_abr_announce_network_to_area(&p, area->default_cost, area);

	return NB_OK;
}


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 *
 * RFC 9129 keys the interface entry by name with the area as the
 * structural parent: creating the entry assigns the interface to that
 * area. This is the same semantic as the legacy `ip ospf area X`
 * per-interface command, but expressed through the area-centric YANG
 * shape rather than the interface-centric CLI shape.
 *
 * One interface, one area. VALIDATE rejects a candidate that contains
 * the same interface entry under more than one area, matching FRR's
 * OSPF interface model and the legacy CLI's "Must remove previous
 * area/address config before changing ospf area" restriction.
 *
 * Per-address overrides (`ip ospf area X A.B.C.D`) have no RFC 9129
 * counterpart and stay reachable only via the legacy CLI on the
 * direct-mutation path. The YANG-managed default-params attachment
 * is the canonical one for newly-emitted config.
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr area_id;
	int format = OSPF_AREA_ID_FMT_DOTTEDQUAD;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event == NB_EV_VALIDATE) {
		ret = ospfd_ietf_ospf_validate_interface_area_unique(
			args->dnode, ifp->name, args->errmsg, args->errmsg_len);
		if (ret != NB_OK)
			return ret;
	}

	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, if_area);
	params->if_area = area_id;
	params->if_area_id_fmt = format;

	ospf_interface_area_set(ospf, ifp);

	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr area_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, if_area))
		return NB_OK;

	/*
	 * Mirror the legacy `no ip ospf area` semantics exactly: only clear
	 * the area binding.  Per-interface attrs (cost, hello-interval,
	 * dead-interval, etc.) are intentionally preserved across area
	 * changes -- operators rely on `no ip ospf area` /
	 * `ip ospf area <new>` to re-bind without losing tuning.
	 */
	UNSET_IF_PARAM(params, if_area);
	ospf_interface_area_unset(ospf, ifp);
	ospf_area_check_free(ospf, area_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/cost
 *
 * Maps to the per-interface output cost via IF_DEF_PARAMS. The YANG
 * model is strictly per-interface, so we always mutate the default
 * params -- the legacy per-address overrides reachable through
 * `ip ospf cost N A.B.C.D` remain on the direct-mutation path.
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, output_cost_cmd);
	/* ospf-link-metric is uint16; widen on store into output_cost_cmd. */
	params->output_cost_cmd = yang_dnode_get_uint16(args->dnode, NULL);

	ospf_if_recalculate_output_cost(ifp);

	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, output_cost_cmd))
		return NB_OK;

	UNSET_IF_PARAM(params, output_cost_cmd);
	ospf_if_recalculate_output_cost(ifp);

	return NB_OK;
}

/*
 * Per-interface uint16/uint8/boolean leaves under
 * /ietf-routing:routing/.../ospf/areas/area/interfaces/interface.
 *
 * All of them mutate IF_DEF_PARAMS only. The YANG model is strictly
 * per-interface; legacy per-address overrides (e.g. `ip ospf hello-interval N A.B.C.D`)
 * remain accessible only via the legacy CLI direct-mutation path.
 */

/* XPath: .../interface/hello-interval */
int ospfd_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;
	uint16_t seconds;
	struct in_addr addr = { .s_addr = 0L };

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	seconds = yang_dnode_get_uint16(args->dnode, NULL);
	if (params->v_hello == seconds)
		return NB_OK;

	SET_IF_PARAM(params, v_hello);
	params->v_hello = seconds;

	/*
	 * Mirror the legacy `ip ospf hello-interval` side effect: if the
	 * operator hasn't explicitly set dead-interval, derive it from the
	 * hello (RFC 4062 recommends roughly 4x). The YANG dead-interval
	 * `must` clause (dead > hello) is enforced by libyang at commit.
	 */
	if (!params->is_v_wait_set) {
		SET_IF_PARAM(params, v_wait);
		params->v_wait = 4 * seconds;
		ospfd_ietf_ospf_nbr_timer_update(ifp);
	}

	ospf_reset_hello_timer(ifp, addr, false);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = 0L };

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, v_hello))
		return NB_OK;

	UNSET_IF_PARAM(params, v_hello);
	params->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;

	/*
	 * Mirror the legacy `no ip ospf hello-interval` (ospf_hello_unset_apply
	 * in ospf_vty.c): when dead-interval was never explicitly set, reset
	 * v_wait back to the protocol default AND clear its CONFIGURED flag,
	 * not just rewrite the value. Earlier versions used SET_IF_PARAM here,
	 * which left v_wait marked as explicitly configured -- the same
	 * numerical default (4 * 10 == 40) but a divergent flag state from
	 * the legacy path, which could surface if other code consults
	 * OSPF_IF_PARAM_CONFIGURED(params, v_wait) without also checking
	 * is_v_wait_set.
	 */
	if (!params->is_v_wait_set) {
		UNSET_IF_PARAM(params, v_wait);
		params->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
		ospfd_ietf_ospf_nbr_timer_update(ifp);
	}

	ospf_reset_hello_timer(ifp, addr, false);
	return NB_OK;
}

/* XPath: .../interface/dead-interval */
int ospfd_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, v_wait);
	params->v_wait = yang_dnode_get_uint16(args->dnode, NULL);
	params->is_v_wait_set = true;
	ospfd_ietf_ospf_nbr_timer_update(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, v_wait);
	params->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	params->is_v_wait_set = false;
	UNSET_IF_PARAM(params, fast_hello);
	params->fast_hello = OSPF_FAST_HELLO_DEFAULT;

	ospfd_ietf_ospf_nbr_timer_update(ifp);
	return NB_OK;
}

/* XPath: .../interface/retransmit-interval */
int ospfd_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, retransmit_interval);
	params->retransmit_interval = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, retransmit_interval);
	params->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;
	return NB_OK;
}

/* XPath: .../interface/priority */
int ospfd_ietf_ospf_areas_area_interfaces_interface_priority_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, priority);
	params->priority = yang_dnode_get_uint8(args->dnode, NULL);
	ospfd_ietf_ospf_priority_update(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_priority_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, priority);
	params->priority = OSPF_ROUTER_PRIORITY_DEFAULT;
	ospfd_ietf_ospf_priority_update(ifp);
	return NB_OK;
}

/* XPath: .../interface/mtu-ignore */
int ospfd_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, mtu_ignore);
	params->mtu_ignore = yang_dnode_get_bool(args->dnode, NULL) ? 1 : 0;
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, mtu_ignore);
	params->mtu_ignore = 0;
	return NB_OK;
}

/* XPath: .../interface/transmit-delay */
int ospfd_ietf_ospf_areas_area_interfaces_interface_transmit_delay_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	SET_IF_PARAM(params, transmit_delay);
	params->transmit_delay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_transmit_delay_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, transmit_delay);
	params->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;
	return NB_OK;
}

/*
 * Helper for areas/area/ranges/range list and per-leaf callbacks:
 * walk up to the range list entry, extract the prefix key, narrow to
 * struct prefix_ipv4. Returns 0 on success, -1 if the dnode shape is
 * unexpected or the prefix isn't IPv4.
 */
static int ospfd_ietf_ospf_range_prefix_from_dnode(const struct lyd_node *dnode,
						   struct prefix_ipv4 *p)
{
	const struct lyd_node *range_node;
	struct prefix pref;

	range_node = yang_dnode_get_parent(dnode, "range");
	if (!range_node)
		return -1;

	yang_dnode_get_prefix(&pref, range_node, "prefix");
	if (pref.family != AF_INET)
		return -1;

	memset(p, 0, sizeof(*p));
	p->family = AF_INET;
	p->prefixlen = pref.prefixlen;
	p->prefix = pref.u.prefix4;
	return 0;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/ranges/range
 *
 * RFC 9129's ranges/range list lives under address-family-area-config
 * and is keyed by prefix. List create sets up the FRR-side range entry
 * with advertise=true (FRR's default, matching the legacy
 * `area X range A.B.C.D/M` form without an explicit not-advertise).
 * advertise and cost leaves can then mutate per-range state.
 *
 * The legacy `area X range A.B.C.D/M substitute A.B.C.D/M` form is FRR
 * specific and has no RFC 9129 counterpart; it stays reachable only
 * via the legacy CLI direct-mutation path.
 */
int ospfd_ietf_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;
	int ret;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;

	area = ospf_area_get(ospf, area_id);
	ospf_area_range_set(ospf, area, area->ranges, &p, OSPF_AREA_RANGE_ADVERTISE, false);

	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	ospf_area_range_unset(ospf, area, area->ranges, &p);
	ospf_area_check_free(ospf, area_id);
	return NB_OK;
}

/* XPath: .../ranges/range/advertise */
int ospfd_ietf_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;
	int advertise;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	advertise = yang_dnode_get_bool(args->dnode, NULL) ? OSPF_AREA_RANGE_ADVERTISE : 0;
	ospf_area_range_set(ospf, area, area->ranges, &p, advertise, false);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_ranges_range_advertise_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	/* No YANG default; revert to FRR's natural default (advertise on). */
	ospf_area_range_set(ospf, area, area->ranges, &p, OSPF_AREA_RANGE_ADVERTISE, false);
	return NB_OK;
}

/* XPath: .../ranges/range/cost */
int ospfd_ietf_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	ospf_area_range_cost_set(ospf, area, area->ranges, &p,
				 yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospfd_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_OK;

	/* "no explicit cost" -> the auto-cost path takes over. */
	ospf_area_range_cost_set(ospf, area, area->ranges, &p, OSPF_AREA_RANGE_COST_UNSPEC);
	return NB_OK;
}

/*
 * XPath: .../interface/interface-type
 *
 * RFC 9129's interface-type enumeration maps onto FRR's OSPF_IFTYPE_*
 * macros. The legacy `ip ospf network` DEFUN also supports FRR-specific
 * modifiers (dmvpn, delay-reflood, non-broadcast) that have no RFC 9129
 * counterpart; those stay reachable only through the legacy CLI.
 * The YANG modify clears any previously-set FRR modifiers so the
 * resulting state is the canonical RFC-9129-shaped one.
 */
static int ospf_iftype_from_yang(const char *val)
{
	if (!strcmp(val, "broadcast"))
		return OSPF_IFTYPE_BROADCAST;
	if (!strcmp(val, "non-broadcast"))
		return OSPF_IFTYPE_NBMA;
	if (!strcmp(val, "point-to-multipoint"))
		return OSPF_IFTYPE_POINTOMULTIPOINT;
	if (!strcmp(val, "point-to-point"))
		return OSPF_IFTYPE_POINTOPOINT;
	return -1;
}

static void ospf_apply_interface_type(struct interface *ifp, int new_type)
{
	struct ospf_if_params *params;
	struct route_node *rn;
	int old_type;
	uint8_t old_ptp_dmvpn;
	uint8_t old_p2mp_delay_reflood;
	uint8_t old_p2mp_non_broadcast;

	if (!ospfd_ietf_ospf_ensure_if_info(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	old_type = params->type;
	old_ptp_dmvpn = params->ptp_dmvpn;
	old_p2mp_delay_reflood = params->p2mp_delay_reflood;
	old_p2mp_non_broadcast = params->p2mp_non_broadcast;

	/* RFC 9129 has no FRR-specific modifiers; reset them. */
	params->ptp_dmvpn = 0;
	params->p2mp_delay_reflood = OSPF_P2MP_DELAY_REFLOOD_DEFAULT;
	params->p2mp_non_broadcast = OSPF_P2MP_NON_BROADCAST_DEFAULT;
	params->type = new_type;
	params->type_cfg = true;
	SET_IF_PARAM(params, type);

	if (params->type == old_type && params->ptp_dmvpn == old_ptp_dmvpn &&
	    params->p2mp_delay_reflood == old_p2mp_delay_reflood &&
	    params->p2mp_non_broadcast == old_p2mp_non_broadcast)
		return;

	if (!IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;
		oi->type = params->type;
		oi->ptp_dmvpn = params->ptp_dmvpn;
		oi->p2mp_delay_reflood = params->p2mp_delay_reflood;
		oi->p2mp_non_broadcast = params->p2mp_non_broadcast;

		if (oi->type != old_type || oi->ptp_dmvpn != old_ptp_dmvpn ||
		    oi->p2mp_non_broadcast != old_p2mp_non_broadcast) {
			if (oi->state > ISM_Down) {
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}
		}
	}
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_interface_type_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	const char *val;
	int type;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	/*
	 * Loopback interfaces have a fixed OSPF type. Use if_is_loopback,
	 * the kernel-flag-based check from libfrr, rather than inspecting
	 * IF_DEF_PARAMS(ifp)->type, which is an OSPF-internal classification
	 * that is unset until the interface is first picked up by OSPF and
	 * therefore returns the wrong answer for a brand-new loopback that
	 * config arrives on before the network statement runs.
	 */
	if (if_is_loopback(ifp)) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "cannot set interface-type on loopback interface %s", ifp->name);
		return args->event == NB_EV_VALIDATE ? NB_ERR_VALIDATION : NB_OK;
	}

	val = yang_dnode_get_string(args->dnode, NULL);
	type = ospf_iftype_from_yang(val);
	if (type < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "unsupported interface-type enum '%s'", val);
		return NB_ERR_VALIDATION;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_apply_interface_type(ifp, type);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_interface_type_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	if (!ospfd_ietf_ospf_ensure_if_info(ifp))
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, type))
		return NB_OK;

	UNSET_IF_PARAM(params, type);
	params->type_cfg = false;
	/*
	 * Without an explicit setting, ospfd will re-derive the type from
	 * the underlying kernel interface on the next state recompute. The
	 * cleanest way to trigger that here is to flap any existing
	 * ospf_interface objects.
	 */
	{
		struct route_node *rn;

		if (!IF_OIFS(ifp))
			return NB_OK;

		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (oi && oi->state > ISM_Down) {
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}
		}
	}
	return NB_OK;
}

/*
 * XPath: .../interface/passive
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_passive_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = INADDR_ANY };
	uint8_t newval;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	newval = yang_dnode_get_bool(args->dnode, NULL) ? OSPF_IF_PASSIVE : OSPF_IF_ACTIVE;
	ospf_passive_interface_update(ifp, params, addr, newval);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_passive_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = INADDR_ANY };

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, passive_interface))
		return NB_OK;
	/* Revert to FRR's natural default (active). */
	ospf_passive_interface_update(ifp, params, addr, OSPF_IF_ACTIVE);
	UNSET_IF_PARAM(params, passive_interface);
	return NB_OK;
}

/*
 * Per-instance preference (admin distance) leaves.
 *
 * RFC 9129's preference container is a `choice` between three scopes:
 *   case single-value   -> leaf all (one distance for everything)
 *   case multi-values/detail -> leaf intra-area, leaf inter-area
 *   case multi-values/coarse -> leaf internal (both intra+inter), leaf external
 * Plus leaf external in both multi-values branches.
 *
 * FRR's ospf struct has distance_all (single) and distance_intra/
 * distance_inter/distance_external (multi). Setting any "multi"
 * leaf to non-zero implicitly forces the multi-values choice;
 * mgmtd's libyang validation handles the choice-arm exclusivity at
 * commit time. Every modify ends with ospf_restart_spf so the new
 * distances reflect in the next SPF result.
 */

/* XPath: .../ospf/preference/all */
int ospfd_ietf_ospf_preference_all_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint8_t distance;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf->distance_all == distance)
		return NB_OK;
	ospf->distance_all = distance;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_preference_all_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (!ospf->distance_all)
		return NB_OK;
	ospf->distance_all = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/* XPath: .../ospf/preference/intra-area */
int ospfd_ietf_ospf_preference_intra_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint8_t distance;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf->distance_intra == distance)
		return NB_OK;
	ospf->distance_intra = distance;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_preference_intra_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (!ospf->distance_intra)
		return NB_OK;
	ospf->distance_intra = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/* XPath: .../ospf/preference/inter-area */
int ospfd_ietf_ospf_preference_inter_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint8_t distance;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf->distance_inter == distance)
		return NB_OK;
	ospf->distance_inter = distance;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_preference_inter_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (!ospf->distance_inter)
		return NB_OK;
	ospf->distance_inter = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/* XPath: .../ospf/preference/internal -- coarse-mode shorthand: both intra & inter to the same value. */
int ospfd_ietf_ospf_preference_internal_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint8_t distance;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf->distance_intra == distance && ospf->distance_inter == distance)
		return NB_OK;
	ospf->distance_intra = distance;
	ospf->distance_inter = distance;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_preference_internal_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (!ospf->distance_intra && !ospf->distance_inter)
		return NB_OK;
	ospf->distance_intra = 0;
	ospf->distance_inter = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/* XPath: .../ospf/preference/external */
int ospfd_ietf_ospf_preference_external_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint8_t distance;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf->distance_external == distance)
		return NB_OK;
	ospf->distance_external = distance;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_preference_external_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (!ospf->distance_external)
		return NB_OK;
	ospf->distance_external = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/*
 * XPath: .../ospf/spf-control/paths
 *
 * Per-instance maximum ECMP paths.  Mirrors the legacy `maximum-paths
 * N` CLI.  RFC 9129 types `paths` as uint16 (range 1..65535), so FRR's
 * configured MULTIPATH_NUM cap (typically 16..64) fits trivially.  The
 * destroy callback restores FRR's "no maximum-paths" semantics
 * (MULTIPATH_NUM), not RFC 9129's absent YANG default.
 */
int ospfd_ietf_ospf_spf_control_paths_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint16_t paths;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event == NB_EV_VALIDATE) {
		paths = yang_dnode_get_uint16(args->dnode, NULL);
		if (paths > MULTIPATH_NUM) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maximum-paths exceeds platform max %u",
				 MULTIPATH_NUM);
			return NB_ERR_INCONSISTENCY;
		}
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	paths = yang_dnode_get_uint16(args->dnode, NULL);
	if (ospf->max_multipath == paths)
		return NB_OK;
	ospf->max_multipath = paths;
	ospf_restart_spf(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_spf_control_paths_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
			return NB_ERR_VALIDATION;
		return NB_OK;
	if (ospf->max_multipath == MULTIPATH_NUM)
		return NB_OK;
	ospf->max_multipath = MULTIPATH_NUM;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/*
 * XPath: .../ospf/mpls/ldp/igp-sync
 *
 * Per-instance MPLS LDP/IGP sync toggle.  Mirrors the legacy
 * `mpls ldp-sync` / `no mpls ldp-sync` CLI.  Enabling registers the
 * opaque LDP-IGP zclient handlers and walks all point-to-point OSPF
 * interfaces in the default VRF to start sync; disabling unwinds via
 * `ospf_ldp_sync_gbl_exit`, which clears the flag, resets the
 * holddown timer, and tears down the per-interface state.  FRR's
 * LDP/IGP sync is restricted to the default VRF, mirroring the
 * legacy CLI's `ldp-sync only runs on DEFAULT VRF` precondition.
 */
int ospfd_ietf_ospf_mpls_ldp_igp_sync_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct vrf *vrf;
	struct interface *ifp;
	int ret;
	bool enable;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event == NB_EV_VALIDATE) {
		if (ospf->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ldp-sync only runs on DEFAULT VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	if (enable) {
		if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
			return NB_OK;
		zclient_register_opaque(ospf_zclient,
					LDP_IGP_SYNC_IF_STATE_UPDATE);
		zclient_register_opaque(ospf_zclient,
					LDP_IGP_SYNC_ANNOUNCE_UPDATE);
		SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		vrf = vrf_lookup_by_id(ospf->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_enable(ospf, ifp);
	} else {
		ospf_ldp_sync_gbl_exit(ospf, true);
	}
	return NB_OK;
}

int ospfd_ietf_ospf_mpls_ldp_igp_sync_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ospf_ldp_sync_gbl_exit(ospf, true);
	return NB_OK;
}

/*
 * XPath: .../ospf/stub-router/always
 *
 * Presence container that mirrors the legacy
 * `max-metric router-lsa administrative` CLI (RFC 6987 unconditional
 * stub router).  The intermediate `choice trigger` YANG node is not
 * a data-tree node, so the data path skips it (RFC 7950 sec 7.9.2).
 * Create sets `OSPF_AREA_ADMIN_STUB_ROUTED` on every existing area
 * and arms the `stub_router_admin_set` flag so later-created areas
 * inherit the property; destroy unwinds, preserving any startup-
 * timer-driven stub state already in flight.
 */
int ospfd_ietf_ospf_stub_router_always_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;
	int ret;
	struct listnode *ln;
	struct ospf_area *area;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		SET_FLAG(area->stub_router_state, OSPF_AREA_ADMIN_STUB_ROUTED);
		if (!CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED))
			ospf_router_lsa_update_area(area);
	}
	ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_SET;
	return NB_OK;
}

int ospfd_ietf_ospf_stub_router_always_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct listnode *ln;
	struct ospf_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		UNSET_FLAG(area->stub_router_state, OSPF_AREA_ADMIN_STUB_ROUTED);
		/* Don't trample on the start-up stub timer */
		if (CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED)
		    && !area->t_stub_router) {
			UNSET_FLAG(area->stub_router_state,
				   OSPF_AREA_IS_STUB_ROUTED);
			ospf_router_lsa_update_area(area);
		}
	}
	ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET;
	return NB_OK;
}

/*
 * Reorigninate the Router-LSA (and Network-LSA when DR) on every OSPF
 * interface attached to `ifp`, mirroring the legacy `ip ospf
 * prefix-suppression` DEFPY's per-interface fan-out so the LSA contents
 * track the flag change immediately.
 */
static void ospfd_ietf_ospf_prefix_suppression_lsa_update(struct interface *ifp)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi && oi->state > ISM_Down) {
			(void)ospf_router_lsa_update_area(oi->area);
			if (oi->state == ISM_DR)
				ospf_network_lsa_update(oi);
		}
	}
}

/*
 * XPath: .../interface/prefix-suppression
 *
 * Per-interface prefix-suppression flag (RFC 6860).  Mirrors the
 * legacy `ip ospf prefix-suppression` CLI's whole-interface form
 * (per-address overrides stay on the legacy direct path because RFC
 * 9129 doesn't model them).  Toggling the flag reoriginates the
 * Router-LSA on every adjacency, plus the Network-LSA on any
 * interface where this router is the DR.
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_prefix_suppression_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	struct interface *ifp;
	struct ospf_if_params *params;
	bool old_value, new_value;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (!ospfd_ietf_ospf_ensure_if_info(ifp))
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	old_value = params->prefix_suppression;
	new_value = yang_dnode_get_bool(args->dnode, NULL);
	if (new_value != OSPF_PREFIX_SUPPRESSION_DEFAULT)
		SET_IF_PARAM(params, prefix_suppression);
	else
		UNSET_IF_PARAM(params, prefix_suppression);
	params->prefix_suppression = new_value;
	if (old_value != new_value)
		ospfd_ietf_ospf_prefix_suppression_lsa_update(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_prefix_suppression_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	bool old_value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	if (!ospfd_ietf_ospf_ensure_if_info(ifp))
		return NB_OK;

	params = IF_DEF_PARAMS(ifp);
	old_value = params->prefix_suppression;
	UNSET_IF_PARAM(params, prefix_suppression);
	params->prefix_suppression = OSPF_PREFIX_SUPPRESSION_DEFAULT;
	if (old_value != OSPF_PREFIX_SUPPRESSION_DEFAULT)
		ospfd_ietf_ospf_prefix_suppression_lsa_update(ifp);
	return NB_OK;
}

/*
 * XPath: .../ospf/auto-cost/enabled
 *
 * RFC 9129 models interface auto-cost as a two-leaf container -- an
 * `enabled` boolean and the `reference-bandwidth` value gated by
 * `when "../enabled = 'true'"`.  FRR has no on/off switch: it always
 * computes interface cost from `reference-bandwidth / interface
 * speed` when the operator hasn't set an explicit per-interface cost.
 *
 * Modify with `true` is a no-op (FRR is always in this state).  Modify
 * with `false` is rejected at NB_EV_VALIDATE -- FRR can't honour
 * `enabled=false` without losing the cost computation that drives
 * every other interface metric.  The destroy callback is also a
 * no-op since the deviation file declares `default "true"` so the
 * leaf is always present and the `when` clause on
 * `reference-bandwidth` is always satisfied.
 */
int ospfd_ietf_ospf_auto_cost_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	bool enabled;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE) {
		if (!enabled) {
			snprintf(args->errmsg, args->errmsg_len,
				 "FRR auto-cost cannot be disabled; "
				 "set per-interface 'ip ospf cost' instead");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	return NB_OK;
}

int ospfd_ietf_ospf_auto_cost_enabled_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	/* Deviation pins enabled to "true"; FRR has no off-switch. */
	return NB_OK;
}

/*
 * XPath: .../ospf/auto-cost/reference-bandwidth
 *
 * Per-instance reference bandwidth used by the auto-cost computation.
 * Mirrors the legacy `auto-cost reference-bandwidth N` CLI.  RFC 9129
 * units are Mbits; FRR stores the same units in `ospf->ref_bandwidth`
 * (despite the `Kbps` comment in ospfd.h -- both CLI and computation
 * treat the value as Mbits/s, see ospf_if_recalculate_output_cost).
 */
int ospfd_ietf_ospf_auto_cost_reference_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct vrf *vrf;
	struct interface *ifp;
	int ret;
	uint32_t refbw;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	refbw = yang_dnode_get_uint32(args->dnode, NULL);
	if (ospf->ref_bandwidth == refbw)
		return NB_OK;
	ospf->ref_bandwidth = refbw;
	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_recalculate_output_cost(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_auto_cost_reference_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct vrf *vrf;
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospf->ref_bandwidth == OSPF_DEFAULT_REF_BANDWIDTH)
		return NB_OK;
	ospf->ref_bandwidth = OSPF_DEFAULT_REF_BANDWIDTH;
	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_recalculate_output_cost(ifp);
	return NB_OK;
}

/*
 * XPath: .../ospf/mpls/te-rid/ipv4-router-id
 *
 * RFC 9129's MPLS-TE Router-ID maps onto FRR's per-process global
 * `OspfMplsTE.router_addr`.  The legacy `mpls-te router-address`
 * CLI is process-wide and rejected outside the default VRF; this
 * callback mirrors that constraint.  The actual mutation +
 * Opaque-LSA reorigination lives in `ospf_mpls_te_apply_router_addr`
 * so the CLI shim and the YANG path share identical behaviour.
 */
int ospfd_ietf_ospf_mpls_te_rid_ipv4_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct in_addr value;
	int ret;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event == NB_EV_VALIDATE) {
		if (ospf->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "mpls-te router-address only runs on DEFAULT VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&value, args->dnode, NULL);
	ospf_mpls_te_apply_router_addr(value);
	return NB_OK;
}

int ospfd_ietf_ospf_mpls_te_rid_ipv4_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	if (ospf->vrf_id != VRF_DEFAULT)
		return NB_OK;
	ospf_mpls_te_clear_router_addr();
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/enabled
 *
 * RFC 9129's graceful-restart enable flag.  Maps onto FRR's per-
 * instance `ospf->gr_info.restart_support` and the matching
 * zebra/nvm bookkeeping in `ospf_gr_restart_support_enable` /
 * `_disable`.  Disable is rejected at NB_EV_VALIDATE if a GR
 * preparation is in flight -- the legacy CLI rejects the same way.
 * The `restart-interval` leaf is a sibling and is intentionally
 * not touched here; see the `restart_interval` callback below.
 */
int ospfd_ietf_ospf_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	bool enabled;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	enabled = yang_dnode_get_bool(args->dnode, NULL);

	if (args->event == NB_EV_VALIDATE) {
		if (!enabled && ospf->gr_info.prepare_in_progress) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Graceful Restart preparation in progress");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (enabled)
		ospf_gr_restart_support_enable(ospf);
	else
		(void)ospf_gr_restart_support_disable(ospf);
	return NB_OK;
}

int ospfd_ietf_ospf_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	(void)ospf_gr_restart_support_disable(ospf);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/restart-interval
 *
 * Per-instance grace period.  Modify sets the value and, when GR is
 * currently enabled, refreshes the zebra stale-route timer.  Destroy
 * restores the RFC default (120s, which also matches FRR's
 * `OSPF_DFLT_GRACE_INTERVAL`).
 */
int ospfd_ietf_ospf_graceful_restart_restart_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;
	uint16_t period;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	period = yang_dnode_get_uint16(args->dnode, NULL);
	ospf_gr_set_grace_period(ospf, period);
	return NB_OK;
}

int ospfd_ietf_ospf_graceful_restart_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;

	ospf_gr_set_grace_period(ospf, OSPF_DFLT_GRACE_INTERVAL);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/helper-enabled
 *
 * RFC 9129's global helper-mode flag.  Maps onto FRR's
 * `ospf->is_helper_supported`.  The legacy `graceful-restart helper
 * enable [A.B.C.D]` CLI conflates this global with a per-router-id
 * enable list; the YANG model has no per-router-id concept, so the
 * northbound only touches the global flag and the legacy CLI keeps
 * the per-router-id form on its direct mutation path.
 */
int ospfd_ietf_ospf_graceful_restart_helper_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_gr_helper_support_set(ospf, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int ospfd_ietf_ospf_graceful_restart_helper_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ospf_gr_helper_support_set(ospf, false);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/helper-strict-lsa-checking
 *
 * Strict-LSA-check on the helper.  FRR defaults to true; the running
 * config writer only emits `no graceful-restart helper strict-lsa-
 * checking` when the value is false, so leaving the leaf unset
 * matches FRR's default behaviour.  Destroy restores the default.
 */
int ospfd_ietf_ospf_graceful_restart_helper_strict_lsa_checking_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_gr_helper_lsa_check_set(ospf, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int ospfd_ietf_ospf_graceful_restart_helper_strict_lsa_checking_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ospf_gr_helper_lsa_check_set(
		ospf,
		yang_get_default_bool(
			"%s/graceful-restart/helper-strict-lsa-checking",
			OSPFD_IETF_OSPF_XPATH));
	return NB_OK;
}

/*
 * RFC 9129 `bfd-types:client-cfg-parms` uses microsecond units for the
 * timer leaves; FRR stores milliseconds internally (see
 * lib/bfd.c:1120-1125 where bfdd multiplies by 1000 again for the
 * protocol).  Operators expect to write whole-millisecond values via
 * YANG, so reject non-multiples of 1000 microseconds at VALIDATE and
 * convert at APPLY.  Range checks mirror the legacy CLI grammar:
 * 50..60000 ms.
 */
#define OSPFD_IETF_BFD_MIN_INTERVAL_US (50UL * 1000)
#define OSPFD_IETF_BFD_MAX_INTERVAL_US (60000UL * 1000)

static int ospfd_ietf_bfd_validate_interval_us(uint32_t us, const char *leaf, char *errmsg,
					       size_t errmsg_len)
{
	if (us % 1000 != 0) {
		snprintf(errmsg, errmsg_len,
			 "FRR BFD %s must be a whole millisecond (multiple of 1000 us); got %u",
			 leaf, us);
		return NB_ERR_VALIDATION;
	}
	if (us < OSPFD_IETF_BFD_MIN_INTERVAL_US || us > OSPFD_IETF_BFD_MAX_INTERVAL_US) {
		snprintf(errmsg, errmsg_len,
			 "FRR BFD %s must be %u..%u us (50..60000 ms); got %u", leaf,
			 (unsigned int)OSPFD_IETF_BFD_MIN_INTERVAL_US,
			 (unsigned int)OSPFD_IETF_BFD_MAX_INTERVAL_US, us);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * XPath: .../ospf/areas/area/interfaces/interface/bfd/enabled
 *
 * Presence-style toggle that maps onto FRR's `bfd_config` allocation.
 * `true` calls `ospf_interface_enable_bfd(ifp, quick=false)` (allocates
 * the struct with FRR defaults) followed by `ospf_interface_bfd_apply`
 * to push the session.  `false` / destroy calls
 * `ospf_interface_disable_bfd` which frees the struct and removes
 * every BFD session bound to the interface.  FRR's quick-establishment
 * flag has no YANG counterpart and stays on the legacy direct path.
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	int ret;
	bool enabled;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;
	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	params = IF_DEF_PARAMS(ifp);
	if (enabled) {
		ospf_interface_enable_bfd(ifp, false);
		ospf_interface_bfd_apply(ifp);
	} else if (params->bfd_config) {
		ospf_interface_disable_bfd(ifp, params);
	}
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	params = IF_DEF_PARAMS(ifp);
	if (params->bfd_config)
		ospf_interface_disable_bfd(ifp, params);
	return NB_OK;
}

/*
 * XPath: .../ospf/areas/area/interfaces/interface/bfd/local-multiplier
 *
 * Maps to `bfd_config->detection_multiplier`.  Type is `multiplier`
 * (uint8 1..255) in ietf-bfd-types; FRR's CLI accepts the same range.
 * Setting this leaf only makes sense once `bfd_config` exists, so the
 * callback creates it via the shared helper (mirroring the legacy
 * `ip ospf bfd N N N` form which also implies enable).
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	int ret;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;
	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_interface_enable_bfd(ifp, false);
	params = IF_DEF_PARAMS(ifp);
	params->bfd_config->detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config)
		return NB_OK;
	params->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}

/*
 * XPath: .../ospf/areas/area/interfaces/interface/bfd/desired-min-tx-interval
 *
 * RFC unit is microseconds; FRR stores milliseconds.  Reject values
 * that are not whole milliseconds, and clamp the range to FRR's CLI
 * grammar (50..60000 ms).
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	int ret;
	uint32_t us;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;
	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	us = yang_dnode_get_uint32(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE)
		return ospfd_ietf_bfd_validate_interval_us(us, "desired-min-tx-interval",
							   args->errmsg, args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_interface_enable_bfd(ifp, false);
	params = IF_DEF_PARAMS(ifp);
	params->bfd_config->min_tx = us / 1000;
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config)
		return NB_OK;
	params->bfd_config->min_tx = BFD_DEF_MIN_TX;
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}

/*
 * XPath: .../ospf/areas/area/interfaces/interface/bfd/required-min-rx-interval
 *
 * Companion to desired-min-tx-interval.  Same unit conversion + range.
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;
	int ret;
	uint32_t us;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;
	ret = ospfd_ietf_ospf_resolve_interface(ospf, args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	us = yang_dnode_get_uint32(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE)
		return ospfd_ietf_bfd_validate_interval_us(us, "required-min-rx-interval",
							   args->errmsg, args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf_interface_enable_bfd(ifp, false);
	params = IF_DEF_PARAMS(ifp);
	params->bfd_config->min_rx = us / 1000;
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}

int ospfd_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct interface *ifp;
	struct ospf_if_params *params;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf = ospfd_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf)
		return NB_OK;
	ifp = ospfd_ietf_ospf_interface_from_dnode(ospf, args->dnode);
	if (!ifp)
		return NB_OK;
	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config)
		return NB_OK;
	params->bfd_config->min_rx = BFD_DEF_MIN_RX;
	ospf_interface_bfd_apply(ifp);
	return NB_OK;
}
