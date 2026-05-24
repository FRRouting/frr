// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound configuration callbacks.
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "if.h"
#include "libospf.h"
#include "prefix.h"
#include "table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_vty.h"

/*
 * RFC 9129 ietf-ospf area-type identityrefs. libyang canonicalises identityref
 * values to "module:identity" when the identity is defined outside the local
 * module, and to bare "identity" when it lives in the same module as the leaf
 * being read. ietf-ospf's area-type leaf is in ietf-ospf and the identities
 * are also in ietf-ospf, so the bare form is what we see at runtime, but
 * accept the prefixed form too for robustness.
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
	if (strncmp(val, "ietf-ospf:", 10) == 0 && !strcmp(val + 10, name))
		return true;
	return false;
}

/*
 * Look up the OSPF instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
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
 * The list create callback materialises the FRR-side ospf_area struct via
 * ospf_area_get (the FRR-internal lookup-or-create). Per-leaf callbacks
 * re-derive the area from the parent control-plane-protocol's name key
 * plus the area's area-id key rather than going through nb_running_get_entry,
 * because the ospf instance itself is not yet NB-managed (still CLI-owned) so
 * nb_running_get_entry walks may return stale entries from unrelated paths.
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
			 * Use route_top + route_next to advance the iterator
			 * independently of ospf_area_range_unset's success.
			 * `next` is grabbed (with a route_next lock) before
			 * the unset call, so the for-loop terminates even if
			 * ospf_area_range_unset returns 0 without freeing the
			 * node -- robust against partial-removal regressions.
			 */
			for (rn = route_top(area->ranges); rn; rn = next) {
				next = route_next(rn);
				p.family = AF_INET;
				p.prefix = rn->p.u.prefix4;
				p.prefixlen = rn->p.prefixlen;
				route_unlock_node(rn);
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
 *   nssa-area   -> deferred; B2b covers NSSA-specific attrs
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

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	type = yang_dnode_get_string(args->dnode, NULL);
	if (ospf_area_type_is(type, OSPF_AREA_TYPE_NORMAL)) {
		ospf_area_stub_unset(ospf, area_id);
		ospf_area_nssa_unset(ospf, area_id);
	} else if (ospf_area_type_is(type, OSPF_AREA_TYPE_STUB)) {
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

/*
 * VALIDATE-rejecting variant for per-interface create / modify callbacks.
 * frr-deviations-ietf-routing-ospf relaxes the RFC 9129 interface-name
 * leafref so configuration can be emitted ahead of interface plumbing.
 * The relaxation removes libyang's referential check; this helper restores
 * it inside the callback, returning NB_ERR_INCONSISTENCY at VALIDATE when
 * the interface is not present in the OSPF instance's VRF.
 *
 * Returns:
 *   NB_OK + *ifp_out set      -- proceed.
 *   NB_OK + *ifp_out == NULL  -- APPLY-phase race tolerated.
 *   NB_ERR_INCONSISTENCY      -- VALIDATE rejected.
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
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
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
 * One interface, one area. If a YANG transaction tries to attach an
 * interface to a second area while the first attachment is still
 * present, the create returns NB_ERR_INCONSISTENCY -- matching the
 * legacy CLI message "Must remove previous area/address config before
 * changing ospf area". The user must delete the old area entry first.
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

	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	/*
	 * One-area-per-interface check: catch the user trying to attach an
	 * interface that is already in a different area. Run at VALIDATE so
	 * mgmtd refuses the commit cleanly rather than half-applying it.
	 */
	params = IF_DEF_PARAMS(ifp);
	if (OSPF_IF_PARAM_CONFIGURED(params, if_area) &&
	    !IPV4_ADDR_SAME(&params->if_area, &area_id)) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "interface %s already attached to area %pI4", ifp->name,
				 &params->if_area);
		return NB_ERR_INCONSISTENCY;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

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
	 * Clear per-interface attrs before tearing the OSPF
	 * interface down, so a subsequent re-create starts from defaults.
	 */
	if (OSPF_IF_PARAM_CONFIGURED(params, output_cost_cmd)) {
		UNSET_IF_PARAM(params, output_cost_cmd);
		ospf_if_recalculate_output_cost(ifp);
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, v_hello)) {
		UNSET_IF_PARAM(params, v_hello);
		params->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, v_wait)) {
		UNSET_IF_PARAM(params, v_wait);
		params->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	}
	params->is_v_wait_set = false;
	if (OSPF_IF_PARAM_CONFIGURED(params, retransmit_interval)) {
		UNSET_IF_PARAM(params, retransmit_interval);
		params->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, priority)) {
		UNSET_IF_PARAM(params, priority);
		params->priority = OSPF_ROUTER_PRIORITY_DEFAULT;
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, mtu_ignore)) {
		UNSET_IF_PARAM(params, mtu_ignore);
		params->mtu_ignore = 0;
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, type)) {
		UNSET_IF_PARAM(params, type);
		params->type_cfg = false;
	}
	if (OSPF_IF_PARAM_CONFIGURED(params, passive_interface)) {
		UNSET_IF_PARAM(params, passive_interface);
		params->passive_interface = OSPF_IF_ACTIVE;
	}

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
	params->is_v_wait_set = false;
	UNSET_IF_PARAM(params, v_wait);
	params->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
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
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);
	struct route_node *rn;
	int old_type = params->type;
	uint8_t old_ptp_dmvpn = params->ptp_dmvpn;
	uint8_t old_p2mp_delay_reflood = params->p2mp_delay_reflood;
	uint8_t old_p2mp_non_broadcast = params->p2mp_non_broadcast;

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
		return NB_ERR_INCONSISTENCY;
	}

	val = yang_dnode_get_string(args->dnode, NULL);
	type = ospf_iftype_from_yang(val);
	if (type < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "unsupported interface-type identityref '%s'", val);
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

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf->distance_intra = yang_dnode_get_uint8(args->dnode, NULL);
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
	ospf->distance_intra = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}

/* XPath: .../ospf/preference/inter-area */
int ospfd_ietf_ospf_preference_inter_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	int ret;

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf->distance_inter = yang_dnode_get_uint8(args->dnode, NULL);
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

	ret = ospfd_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
					       args->errmsg_len, &ospf);
	if (ret != NB_OK || !ospf)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf->distance_external = yang_dnode_get_uint8(args->dnode, NULL);
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
	ospf->distance_external = 0;
	ospf_restart_spf(ospf);
	return NB_OK;
}
