// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound configuration callbacks.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "if.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_route.h"
#include "ospf6_nb.h"
#include "ospf6_nssa.h"

/*
 * RFC 9129 ietf-ospf area-type identityrefs. Accept both bare and
 * module-qualified forms; see the matching helper in ospfd/ospf_nb_config.c.
 */
#define OSPF6_AREA_TYPE_NORMAL "normal-area"
#define OSPF6_AREA_TYPE_STUB   "stub-area"
#define OSPF6_AREA_TYPE_NSSA   "nssa-area"

static bool ospf6_area_type_is(const char *val, const char *name)
{
	if (!val)
		return false;
	if (!strcmp(val, name))
		return true;
	if (strncmp(val, "ietf-ospf:", strlen("ietf-ospf:")) == 0)
		return !strcmp(val + strlen("ietf-ospf:"), name);
	return false;
}

/*
 * Look up the OSPFv3 instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
 *
 * mgmtd's predicate-aware dispatch (mgmt_be_xpath_prefix) routes only
 * control-plane-protocol[type='ietf-ospf:ospfv3'] entries to ospf6d, so
 * the type check is handled at the dispatch layer and not repeated here.
 *
 * Returns NULL when no FRR-side OSPFv3 instance exists for the named
 * control-plane-protocol; the caller should treat the configuration as a
 * no-op until the instance is created (today: via `router ospf6`).
 */
static struct ospf6 *ospf6d_ietf_ospf_instance_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *cpp;
	const char *name;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (!cpp)
		return NULL;

	name = yang_dnode_get_string(cpp, "name");
	return ospf6d_ietf_ospf_lookup_instance(name);
}

/*
 * Resolve the OSPFv3 instance for create / modify callbacks. See the OSPFv2
 * equivalent in ospfd/ospf_nb_config.c for the rationale; APPLY-phase
 * tolerance preserves commit progress if the instance is torn down
 * mid-transaction. Returns NB_OK + *ospf6_out set on success, NB_OK + NULL
 * for the APPLY-race case, NB_ERR_INCONSISTENCY when VALIDATE rejects.
 */
static int ospf6d_ietf_ospf_resolve_instance(const struct lyd_node *dnode, enum nb_event event,
					     char *errmsg, size_t errmsg_len,
					     struct ospf6 **ospf6_out)
{
	struct ospf6 *ospf6;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(dnode);
	*ospf6_out = ospf6;
	if (ospf6)
		return NB_OK;

	if (event == NB_EV_VALIDATE) {
		const struct lyd_node *cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");

		snprintf(errmsg, errmsg_len,
			 "OSPFv3 instance '%s' is not configured (use 'router ospf6' first)",
			 cpp ? yang_dnode_get_string(cpp, "name") : "?");
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
}


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/explicit-router-id
 */
int ospf6d_ietf_ospf_explicit_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct in_addr router_id;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	/* ospf6d stores router IDs as network-byte-order uint32_t values. */
	ospf6->router_id_static = router_id.s_addr;

	if (ospf6_router_id_update(ospf6, false))
		ospf6_process_reset(ospf6);

	return NB_OK;
}

int ospf6d_ietf_ospf_explicit_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;

	ospf6->router_id_static = 0;

	if (ospf6_router_id_update(ospf6, false))
		ospf6_process_reset(ospf6);

	return NB_OK;
}

/*
 * Walk up from a dnode within the areas/area subtree to extract the
 * area-id key. Returns 0 on success, -1 on failure. ospf6d stores area
 * IDs as network-byte-order uint32_t.
 */
static int ospf6d_ietf_ospf_area_id_from_dnode(const struct lyd_node *dnode, uint32_t *area_id)
{
	const struct lyd_node *area_node;
	const char *area_id_str;
	struct in_addr addr;

	area_node = yang_dnode_get_parent(dnode, "area");
	if (!area_node)
		return -1;

	area_id_str = yang_dnode_get_string(area_node, "area-id");
	if (inet_pton(AF_INET, area_id_str, &addr) != 1)
		return -1;
	*area_id = addr.s_addr;
	return 0;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 *
 * Mirrors the OSPFv2 area pilot. ospf6_area_create takes a display format;
 * areas declared through YANG always use the dotted-quad form because that
 * is how rt-types:area-id-type serialises. Areas are deliberately not
 * anchored on the running dnode: legacy-compatible cleanup such as deleting
 * area-type can free an otherwise empty area while the YANG area list node
 * remains present.
 */
int ospf6d_ietf_ospf_areas_area_create(struct nb_cb_create_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *area;
	uint32_t area_id;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		(void)ospf6_area_create(area_id, ospf6, OSPF6_AREA_FMT_DOTTEDQUAD);

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *area;
	uint32_t area_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;

	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		return NB_OK;

	/*
	 * Reset every area attr back to defaults so
	 * ospf6_area_no_config_delete can actually free the area. Per-leaf
	 * destroy isn't dispatched for area-type (it has a YANG default), so
	 * the cleanup is centralised here.
	 */
	ospf6_area_stub_unset(ospf6, area);
	ospf6_area_nssa_unset(ospf6, area);
	ospf6_area_no_summary_unset(ospf6, area);

	ospf6_area_no_config_delete(area);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/area-type
 *
 * No virtual-link VALIDATE guard here, in contrast to the OSPFv2 sibling
 * in ospfd/ospf_nb_config.c. ospf6_area_stub_set / ospf6_area_nssa_set
 * unconditionally return 1 -- they have no failure mode -- so there is no
 * deferred-APPLY-error class to push earlier. Adding a defensive guard
 * would be a no-op today and would invite drift if ospf6d ever gains a
 * matching restriction; the right place to add one is alongside such a
 * restriction in the v3 helpers, not preemptively here.
 */
int ospf6d_ietf_ospf_areas_area_type_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *area;
	uint32_t area_id;
	const char *type;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	/*
	 * Idempotent at APPLY: if the area was torn down between VALIDATE
	 * and APPLY, silently no-op rather than returning
	 * NB_ERR_INCONSISTENCY (which mgmtd would log-and-drop anyway, and
	 * which diverged from the OSPFv2 callback's behaviour where the
	 * area helpers handle missing areas internally).
	 */
	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		return NB_OK;

	type = yang_dnode_get_string(args->dnode, NULL);
	if (ospf6_area_type_is(type, OSPF6_AREA_TYPE_NORMAL)) {
		ospf6_area_stub_unset(ospf6, area);
		ospf6_area_nssa_unset(ospf6, area);
	} else if (ospf6_area_type_is(type, OSPF6_AREA_TYPE_STUB)) {
		ospf6_area_nssa_unset(ospf6, area);
		if (!ospf6_area_stub_set(ospf6, area))
			return NB_ERR_INCONSISTENCY;
	} else if (ospf6_area_type_is(type, OSPF6_AREA_TYPE_NSSA)) {
		ospf6_area_stub_unset(ospf6, area);
		if (!ospf6_area_nssa_set(ospf6, area))
			return NB_ERR_INCONSISTENCY;
	} else {
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/summary
 *
 * Same inverted semantics as the OSPFv2 side: summary=true means summary
 * LSAs are injected, summary=false means totally stubby.
 *
 * NOTE: RFC 9129 also defines areas/area/default-cost. ospf6d has no
 * per-area stub default-cost knob, so that leaf is intentionally
 * unimplemented here; setting it through YANG against an ospf6 instance
 * is rejected by mgmtd as "no backend handles this path". This matches
 * FRR's existing v3 CLI surface (which has no `area X default-cost`
 * equivalent) and is a pre-existing v2/v3 feature gap, not introduced
 * by this conversion.
 */
int ospf6d_ietf_ospf_areas_area_summary_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *area;
	uint32_t area_id;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ospf6_area_no_summary_unset(ospf6, area);
	else
		ospf6_area_no_summary_set(ospf6, area);

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_summary_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *area;
	uint32_t area_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		return NB_OK;

	ospf6_area_no_summary_unset(ospf6, area);

	return NB_OK;
}

/*
 * Walk up from a dnode within the area/interfaces/interface subtree to
 * extract the interface name. NULL on schema-shape failure (defensive).
 */
static const char *ospf6d_ietf_ospf_interface_name_from_dnode(const struct lyd_node *dnode)
{
	const struct lyd_node *iface_node;

	iface_node = yang_dnode_get_parent(dnode, "interface");
	if (!iface_node)
		return NULL;
	return yang_dnode_get_string(iface_node, "name");
}

static struct interface *ospf6d_ietf_ospf_interface_from_dnode(const struct ospf6 *ospf6,
							       const struct lyd_node *dnode)
{
	const char *name;

	name = ospf6d_ietf_ospf_interface_name_from_dnode(dnode);
	if (!name)
		return NULL;
	return if_lookup_by_name(name, ospf6->vrf_id);
}

static bool ospf6d_ietf_ospf_area_has_interface(const struct lyd_node *area_node,
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

static int ospf6d_ietf_ospf_validate_interface_area_unique(const struct lyd_node *dnode,
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
		if (!ospf6d_ietf_ospf_area_has_interface(other_area_node, ifname))
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
static int ospf6d_ietf_ospf_resolve_interface(const struct ospf6 *ospf,
					      const struct lyd_node *dnode, enum nb_event event,
					      char *errmsg, size_t errmsg_len,
					      struct interface **ifp_out)
{
	struct interface *ifp;

	ifp = ospf6d_ietf_ospf_interface_from_dnode(ospf, dnode);
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


/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 *
 * Same area-keyed model as the OSPFv2 side. One interface, one area:
 * VALIDATE rejects a candidate that contains the same interface under
 * more than one area, matching FRR's OSPFv3 interface model and the
 * legacy ipv6_ospf6_area "already attached to Area X" restriction.
 */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_create(struct nb_cb_create_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;
	uint32_t area_id;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	ret = ospf6d_ietf_ospf_resolve_interface(ospf6, args->dnode, args->event, args->errmsg,
						 args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event == NB_EV_VALIDATE) {
		ret = ospf6d_ietf_ospf_validate_interface_area_unique(
			args->dnode, ifp->name, args->errmsg, args->errmsg_len);
		if (ret != NB_OK)
			return ret;
	}

	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi = (struct ospf6_interface *)ifp->info;
	if (!oi)
		oi = ospf6_interface_create(ifp);

	oi->area_id = area_id;
	oi->area_id_format = OSPF6_AREA_FMT_DOTTEDQUAD;

	if (!oi->area)
		ospf6_interface_start(oi);

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct interface *ifp;
	struct ospf6_interface *oi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;

	ifp = ospf6d_ietf_ospf_interface_from_dnode(ospf6, args->dnode);
	if (!ifp)
		return NB_OK;

	oi = (struct ospf6_interface *)ifp->info;
	if (!oi)
		return NB_OK;

	/*
	 * Future B3 leaves on this interface should clear their state here
	 * before the area detach so reattach starts from defaults. For B3a
	 * we have cost only, and it lives on oi itself and is reset by the
	 * recalculate-from-bandwidth path triggered after stop.
	 */
	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);
	ospf6_interface_stop(oi);
	oi->area_id = 0;
	oi->area_id_format = OSPF6_AREA_FMT_UNSET;

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/cost
 */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;
	uint32_t cost;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	ret = ospf6d_ietf_ospf_resolve_interface(ospf6, args->dnode, args->event, args->errmsg,
						 args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi = (struct ospf6_interface *)ifp->info;
	if (!oi)
		return NB_OK;

	/* ospf-link-metric is uint16; widen into oi->cost (uint32_t). */
	cost = yang_dnode_get_uint16(args->dnode, NULL);
	SET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);
	if (oi->cost == cost)
		return NB_OK;
	oi->cost = cost;
	ospf6_interface_force_recalculate_cost(oi);

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct interface *ifp;
	struct ospf6_interface *oi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	ifp = ospf6d_ietf_ospf_interface_from_dnode(ospf6, args->dnode);
	if (!ifp)
		return NB_OK;

	oi = (struct ospf6_interface *)ifp->info;
	if (!oi)
		return NB_OK;

	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);
	ospf6_interface_recalculate_cost(oi);

	return NB_OK;
}
