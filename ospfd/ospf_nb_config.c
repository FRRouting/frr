// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound configuration callbacks.
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "libospf.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_nb.h"

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

		area = ospf_area_lookup_by_area_id(ospf, area_id);
		if (area)
			area->default_cost = 1;
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

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospfd_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NB_ERR_INCONSISTENCY;
	if (area->external_routing == OSPF_AREA_DEFAULT)
		return NB_ERR_VALIDATION;

	area->default_cost = yang_dnode_get_uint32(args->dnode, NULL);
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);

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
