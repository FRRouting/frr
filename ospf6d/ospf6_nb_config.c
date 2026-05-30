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

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_abr.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_route.h"
#include "ospf6_tlv.h"
#include "ospf6_gr.h"
#include "ospf6_bfd.h"
#include "ospf6_auth_trailer.h"
#include "ospf6_nb.h"
#include "ospf6_nssa.h"

#include "lib/bfd.h"

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

static bool ospf6d_ietf_ospf_type_is(const char *val)
{
	return val && (!strcmp(val, "ospfv3") ||
		       !strcmp(val, "ietf-ospf:ospfv3"));
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 *
 * Keep the IETF routing protocol list present in the local candidate whenever
 * the legacy `router ospf6` CLI creates the daemon instance directly. Child
 * commands converted to RFC 9129 leaves, such as explicit-router-id, then have
 * a real parent list entry to modify during the pending NB commit.
 */
int ospf6d_ietf_routing_control_plane_protocol_create(struct nb_cb_create_args *args)
{
	const char *type;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!ospf6d_ietf_ospf_type_is(type))
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!name)
		name = VRF_DEFAULT_NAME;

	if (!ospf6d_ietf_ospf_lookup_instance(name))
		ospf6_instance_create(name);

	return NB_OK;
}

int ospf6d_ietf_routing_control_plane_protocol_destroy(struct nb_cb_destroy_args *args)
{
	const char *type;
	const char *name;
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!ospf6d_ietf_ospf_type_is(type))
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!name)
		name = VRF_DEFAULT_NAME;

	ospf6 = ospf6d_ietf_ospf_lookup_instance(name);
	if (!ospf6)
		return NB_OK;

	if (ospf6->gr_info.restart_support)
		ospf6_gr_nvm_delete(ospf6);
	ospf6_delete(&ospf6);

	return NB_OK;
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

	/*
	 * Drop any area ranges; ospf6_area_no_config_delete inspects
	 * range_table->count and refuses to free if non-zero.  Use the
	 * head-then-remove drain pattern -- same shape as the post-fix
	 * ospf6_route_remove_all -- so the loop stays safe if a future
	 * `hook_remove` is ever attached to range_table.
	 */
	{
		struct ospf6_route *range;
		bool abr = ospf6_check_and_set_router_abr(area->ospf6);

		while ((range = ospf6_route_head(area->range_table)) != NULL) {
			if (abr) {
				SET_FLAG(range->flag, OSPF6_ROUTE_REMOVE);
				ospf6_schedule_abr_task(area->ospf6);
			}
			ospf6_route_remove(range, area->range_table);
			ospf6_route_unlock(range);
		}
	}

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
	 * Reset every per-interface attr to its compile-time
	 * default so a subsequent re-create starts clean. The cost field
	 * is restored by ospf6_interface_recalculate_cost after we drop
	 * the NOAUTOCOST flag.
	 */
	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_NOAUTOCOST);
	UNSET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
	oi->hello_interval = OSPF6_INTERFACE_HELLO_INTERVAL;
	oi->dead_interval = OSPF6_INTERFACE_DEAD_INTERVAL;
	oi->rxmt_interval = OSPF6_INTERFACE_RXMT_INTERVAL;
	oi->priority = OSPF6_INTERFACE_PRIORITY;
	oi->mtu_ignore = 0;
	oi->type_cfg = false;
	oi->type = ospf6_default_iftype(ifp);
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

/*
 * Per-interface uint16/uint8/boolean leaves for OSPFv3.
 *
 * ospf6d stores per-interface state directly on struct ospf6_interface
 * rather than via a parallel "default params" struct, so each modify
 * just writes the field and (where needed) re-arms whatever timer or
 * SPF the change should provoke. destroy reverts to the FRR-side
 * compile-time default.
 */

/* XPath: .../interface/hello-interval */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->hello_interval = yang_dnode_get_uint16(args->dnode, NULL);
	/*
	 * Reschedule the next hello immediately so the new interval takes
	 * effect within the current hello cycle rather than after one full
	 * old-interval delay. Mirrors the legacy `ipv6 ospf6 hello-interval`
	 * direct-mutation path.
	 */
	ospf6_hello_reschedule(oi);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_hello_interval_destroy(
	struct nb_cb_destroy_args *args)
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

	oi->hello_interval = OSPF6_INTERFACE_HELLO_INTERVAL;
	ospf6_hello_reschedule(oi);
	return NB_OK;
}

/* XPath: .../interface/dead-interval */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->dead_interval = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_dead_interval_destroy(
	struct nb_cb_destroy_args *args)
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

	oi->dead_interval = OSPF6_INTERFACE_DEAD_INTERVAL;
	return NB_OK;
}

/* XPath: .../interface/retransmit-interval */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->rxmt_interval = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_retransmit_interval_destroy(
	struct nb_cb_destroy_args *args)
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

	oi->rxmt_interval = OSPF6_INTERFACE_RXMT_INTERVAL;
	return NB_OK;
}

/* XPath: .../interface/priority */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->priority = yang_dnode_get_uint8(args->dnode, NULL);
	/*
	 * Re-run DR election immediately so the new priority is reflected
	 * in the next hello without waiting for the current DR/BDR state
	 * to time out. Mirrors the legacy `ipv6 ospf6 priority` direct-
	 * mutation path.
	 */
	ospf6_priority_recompute(oi);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_priority_destroy(struct nb_cb_destroy_args *args)
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

	oi->priority = OSPF6_INTERFACE_PRIORITY;
	ospf6_priority_recompute(oi);
	return NB_OK;
}

/* XPath: .../interface/mtu-ignore */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->mtu_ignore = yang_dnode_get_bool(args->dnode, NULL) ? 1 : 0;
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_mtu_ignore_destroy(
	struct nb_cb_destroy_args *args)
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

	oi->mtu_ignore = 0;
	return NB_OK;
}

/* XPath: .../interface/transmit-delay */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_transmit_delay_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;

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

	oi->transdelay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_transmit_delay_destroy(
	struct nb_cb_destroy_args *args)
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

	oi->transdelay = OSPF6_INTERFACE_TRANSDELAY;
	return NB_OK;
}

/*
 * Helper for areas/area/ranges/range callbacks: extract the prefix
 * key as struct prefix (libyang gives us the full prefix, callers narrow
 * to ipv6 since this is the ospf6d side). Returns 0 on success.
 */
static int ospf6d_ietf_ospf_range_prefix_from_dnode(const struct lyd_node *dnode, struct prefix *p)
{
	const struct lyd_node *range_node;

	range_node = yang_dnode_get_parent(dnode, "range");
	if (!range_node)
		return -1;

	yang_dnode_get_prefix(p, range_node, "prefix");
	if (p->family != AF_INET6)
		return -1;
	return 0;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/ranges/range
 *
 * v3 area ranges live as ospf6_route entries in oa->range_table with
 * type=OSPF6_DEST_TYPE_RANGE. The route abstraction is the public API
 * (there is no ospf6_area_range_set helper), so the callback inlines
 * the same sequence the legacy `area X range PREFIX` DEFUN uses:
 * create-or-lookup the route, set advertise flag and cost, add to the
 * table, schedule ABR.
 */
int ospf6d_ietf_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;

	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		oa = ospf6_area_create(area_id, ospf6, OSPF6_AREA_FMT_DOTTEDQUAD);

	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range) {
		range = ospf6_route_create(ospf6);
		range->type = OSPF6_DEST_TYPE_RANGE;
		range->prefix = p;
		range->path.area_id = oa->area_id;
		range->path.cost = OSPF_AREA_RANGE_COST_UNSPEC;
		range->path.u.cost_config = OSPF_AREA_RANGE_COST_UNSPEC;
		ospf6_route_add(range, oa->range_table);
	}

	if (ospf6_check_and_set_router_abr(ospf6))
		ospf6_schedule_abr_task(ospf6);

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;

	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		return NB_OK;
	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range)
		return NB_OK;

	if (ospf6_check_and_set_router_abr(oa->ospf6)) {
		SET_FLAG(range->flag, OSPF6_ROUTE_REMOVE);
		ospf6_schedule_abr_task(oa->ospf6);
	}
	ospf6_route_remove(range, oa->range_table);
	ospf6_area_no_config_delete(oa);
	return NB_OK;
}

/* XPath: .../ranges/range/advertise */
int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		return NB_OK;
	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
	else
		SET_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);

	if (ospf6_check_and_set_router_abr(ospf6))
		ospf6_schedule_abr_task(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_ranges_range_advertise_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		return NB_OK;
	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range)
		return NB_OK;

	/* Revert to FRR's natural default (advertise on). */
	UNSET_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
	if (ospf6_check_and_set_router_abr(ospf6))
		ospf6_schedule_abr_task(ospf6);
	return NB_OK;
}

/* XPath: .../ranges/range/cost */
int ospf6d_ietf_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		return NB_OK;
	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range)
		return NB_OK;

	range->path.u.cost_config = yang_dnode_get_uint32(args->dnode, NULL);
	if (ospf6_check_and_set_router_abr(ospf6))
		ospf6_schedule_abr_task(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;
	uint32_t area_id;
	struct prefix p;
	struct ospf6_route *range;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (ospf6d_ietf_ospf_area_id_from_dnode(args->dnode, &area_id) < 0)
		return NB_ERR_VALIDATION;
	if (ospf6d_ietf_ospf_range_prefix_from_dnode(args->dnode, &p) < 0)
		return NB_ERR_VALIDATION;
	oa = ospf6_area_lookup(area_id, ospf6);
	if (!oa)
		return NB_OK;
	range = ospf6_route_lookup(&p, oa->range_table);
	if (!range)
		return NB_OK;

	range->path.u.cost_config = OSPF_AREA_RANGE_COST_UNSPEC;
	if (ospf6_check_and_set_router_abr(ospf6))
		ospf6_schedule_abr_task(ospf6);
	return NB_OK;
}

/*
 * XPath: .../interface/interface-type (OSPFv3)
 *
 * RFC 9129 declares broadcast, non-broadcast, point-to-multipoint,
 * point-to-point and hybrid. ospf6d's `ipv6 ospf6 network` CLI only
 * accepts broadcast, point-to-point, and point-to-multipoint; NBMA and
 * hybrid have no v3 surface and are rejected here. The legacy DEFUN
 * triggers a full interface_down/up cycle on type change; the NB
 * callback follows the same pattern via event_execute.
 */
static int ospf6_iftype_from_yang(const char *val)
{
	if (!strcmp(val, "broadcast"))
		return OSPF_IFTYPE_BROADCAST;
	if (!strcmp(val, "point-to-point"))
		return OSPF_IFTYPE_POINTOPOINT;
	if (!strcmp(val, "point-to-multipoint"))
		return OSPF_IFTYPE_POINTOMULTIPOINT;
	return -1;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_modify(
	struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;
	const char *val;
	int type;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	ret = ospf6d_ietf_ospf_resolve_interface(ospf6, args->dnode, args->event, args->errmsg,
						 args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	/*
	 * Loopback interfaces have a fixed OSPF type. Reject at VALIDATE
	 * before we touch the struct ospf6_interface or trigger any flap.
	 * Use if_is_loopback rather than checking oi->type, because oi might
	 * not be allocated yet (the per-interface attachment may arrive
	 * before any ospf6 area binding) and oi->type would be unset.
	 */
	if (if_is_loopback(ifp)) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "cannot set interface-type on loopback interface %s", ifp->name);
		return args->event == NB_EV_VALIDATE ? NB_ERR_VALIDATION : NB_OK;
	}

	/*
	 * Reject unsupported enum values at VALIDATE. ospf6d only accepts
	 * broadcast / point-to-point / point-to-multipoint; the YANG model
	 * also declares non-broadcast and hybrid which ospf6d cannot
	 * implement.
	 */
	val = yang_dnode_get_string(args->dnode, NULL);
	type = ospf6_iftype_from_yang(val);
	if (type < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "unsupported interface-type enum '%s' for ospf6", val);
		return NB_ERR_VALIDATION;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi = (struct ospf6_interface *)ifp->info;
	if (!oi)
		oi = ospf6_interface_create(ifp);

	oi->type_cfg = true;
	if (oi->type == type)
		return NB_OK;

	oi->type = type;
	event_execute(master, interface_down, oi, 0, NULL);
	event_execute(master, interface_up, oi, 0, NULL);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_interface_type_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct interface *ifp;
	struct ospf6_interface *oi;
	uint8_t type;

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

	oi->type_cfg = false;
	type = ospf6_default_iftype(ifp);
	if (oi->type == type)
		return NB_OK;

	oi->type = type;
	event_execute(master, interface_down, oi, 0, NULL);
	event_execute(master, interface_up, oi, 0, NULL);
	return NB_OK;
}

/*
 * XPath: .../interface/passive (OSPFv3)
 */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	struct interface *ifp;
	struct ospf6_interface *oi;
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;
	bool passive;

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
		oi = ospf6_interface_create(ifp);

	passive = yang_dnode_get_bool(args->dnode, NULL);

	if (passive) {
		SET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
		event_cancel(&oi->thread_send_hello);
		event_cancel(&oi->thread_sso);
		for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
			event_cancel(&on->inactivity_timer);
			event_add_event(master, inactivity_timer, on, 0, NULL);
		}
	} else {
		UNSET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
		event_cancel(&oi->thread_send_hello);
		event_cancel(&oi->thread_sso);
		if (!if_is_loopback(oi->interface))
			event_add_timer(master, ospf6_hello_send, oi, 0, &oi->thread_send_hello);
	}
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_passive_destroy(struct nb_cb_destroy_args *args)
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

	/* Revert to FRR's natural default (active). */
	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE)) {
		UNSET_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE);
		event_cancel(&oi->thread_send_hello);
		event_cancel(&oi->thread_sso);
		if (!if_is_loopback(oi->interface))
			event_add_timer(master, ospf6_hello_send, oi, 0, &oi->thread_send_hello);
	}
	return NB_OK;
}

/*
 * Per-instance preference (admin distance) leaves, v3.
 *
 * Same mapping as ospfd: distance_all (single scope), distance_intra/
 * distance_inter/distance_external (multi-values scope), with a
 * "coarse" alias `internal` covering both intra and inter.
 *
 * ospf6d's struct ospf6 has the same distance_* fields as ospfd's
 * struct ospf, so the callbacks are identical in shape. We trigger an
 * SPF restart via ospf6_restart_spf so the new distances take effect.
 */

/* XPath: .../ospf/preference/all */
int ospf6d_ietf_ospf_preference_all_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint8_t distance;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf6->distance_all == distance)
		return NB_OK;
	ospf6->distance_all = distance;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_preference_all_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (!ospf6->distance_all)
		return NB_OK;
	ospf6->distance_all = 0;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

/* XPath: .../ospf/preference/intra-area */
int ospf6d_ietf_ospf_preference_intra_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint8_t distance;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf6->distance_intra == distance)
		return NB_OK;
	ospf6->distance_intra = distance;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_preference_intra_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (!ospf6->distance_intra)
		return NB_OK;
	ospf6->distance_intra = 0;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

/* XPath: .../ospf/preference/inter-area */
int ospf6d_ietf_ospf_preference_inter_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint8_t distance;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf6->distance_inter == distance)
		return NB_OK;
	ospf6->distance_inter = distance;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_preference_inter_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (!ospf6->distance_inter)
		return NB_OK;
	ospf6->distance_inter = 0;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

/* XPath: .../ospf/preference/internal */
int ospf6d_ietf_ospf_preference_internal_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint8_t distance;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf6->distance_intra == distance && ospf6->distance_inter == distance)
		return NB_OK;
	ospf6->distance_intra = distance;
	ospf6->distance_inter = distance;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_preference_internal_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (!ospf6->distance_intra && !ospf6->distance_inter)
		return NB_OK;
	ospf6->distance_intra = 0;
	ospf6->distance_inter = 0;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

/* XPath: .../ospf/preference/external */
int ospf6d_ietf_ospf_preference_external_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint8_t distance;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	if (ospf6->distance_external == distance)
		return NB_OK;
	ospf6->distance_external = distance;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_preference_external_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (!ospf6->distance_external)
		return NB_OK;
	ospf6->distance_external = 0;
	ospf6_restart_spf(ospf6);
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
int ospf6d_ietf_ospf_spf_control_paths_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint16_t paths;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
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
	if (ospf6->max_multipath == paths)
		return NB_OK;
	ospf6->max_multipath = paths;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_spf_control_paths_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
			return NB_ERR_VALIDATION;
		return NB_OK;
	if (ospf6->max_multipath == MULTIPATH_NUM)
		return NB_OK;
	ospf6->max_multipath = MULTIPATH_NUM;
	ospf6_restart_spf(ospf6);
	return NB_OK;
}

/*
 * XPath: .../ospf/auto-cost/enabled
 *
 * See the ospfd companion comment.  ospf6d shares FRR's "always-on
 * auto-cost" semantics: there's no on/off switch, so modify=true is a
 * no-op, modify=false is rejected at validate, and destroy is a no-op
 * because the deviation file pins the leaf's default to "true".
 */
int ospf6d_ietf_ospf_auto_cost_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	bool enabled;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE) {
		if (!enabled) {
			snprintf(args->errmsg, args->errmsg_len,
				 "FRR auto-cost cannot be disabled; "
				 "set per-interface 'ipv6 ospf6 cost' instead");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	return NB_OK;
}

/*
 * XPath: .../ospf/auto-cost/reference-bandwidth
 *
 * Per-instance reference bandwidth for the auto-cost computation.
 * Mirrors the legacy `auto-cost reference-bandwidth N` CLI; RFC 9129
 * units are Mbits, matching FRR's ospf6->ref_bandwidth.  Destroy
 * restores `OSPF6_REFERENCE_BANDWIDTH`.
 */
int ospf6d_ietf_ospf_auto_cost_reference_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct listnode *i, *j;
	int ret;
	uint32_t refbw;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	refbw = yang_dnode_get_uint32(args->dnode, NULL);
	if (ospf6->ref_bandwidth == refbw)
		return NB_OK;
	ospf6->ref_bandwidth = refbw;
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			ospf6_interface_recalculate_cost(oi);
	return NB_OK;
}

int ospf6d_ietf_ospf_auto_cost_reference_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_area *oa;
	struct ospf6_interface *oi;
	struct listnode *i, *j;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	if (ospf6->ref_bandwidth == OSPF6_REFERENCE_BANDWIDTH)
		return NB_OK;
	ospf6->ref_bandwidth = OSPF6_REFERENCE_BANDWIDTH;
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			ospf6_interface_recalculate_cost(oi);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/enabled
 *
 * Companion to the ospfd callback above.  Same semantics: shared
 * helper in `ospf6_gr_restart_support_{enable,disable}`, validate-
 * time rejection when a GR prepare is in flight, sibling
 * `restart-interval` leaf is not touched here.
 */
int ospf6d_ietf_ospf_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	bool enabled;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	enabled = yang_dnode_get_bool(args->dnode, NULL);

	if (args->event == NB_EV_VALIDATE) {
		if (!enabled && ospf6->gr_info.prepare_in_progress) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Graceful Restart preparation in progress");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (enabled)
		ospf6_gr_restart_support_enable(ospf6);
	else
		(void)ospf6_gr_restart_support_disable(ospf6);
	return NB_OK;
}

int ospf6d_ietf_ospf_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	(void)ospf6_gr_restart_support_disable(ospf6);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/restart-interval
 *
 * Per-instance grace period.  Destroy restores the RFC default (120s,
 * which also matches FRR's `OSPF6_DFLT_GRACE_INTERVAL`).
 */
int ospf6d_ietf_ospf_graceful_restart_restart_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;
	uint16_t period;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	period = yang_dnode_get_uint16(args->dnode, NULL);
	ospf6_gr_set_grace_period(ospf6, period);
	return NB_OK;
}

int ospf6d_ietf_ospf_graceful_restart_restart_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;

	ospf6_gr_set_grace_period(ospf6, OSPF6_DFLT_GRACE_INTERVAL);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/helper-enabled
 *
 * Companion to the ospfd callback above; same per-router-id caveat.
 */
int ospf6d_ietf_ospf_graceful_restart_helper_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6_gr_helper_support_set(ospf6, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int ospf6d_ietf_ospf_graceful_restart_helper_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	ospf6_gr_helper_support_set(ospf6, false);
	return NB_OK;
}

/*
 * XPath: .../ospf/graceful-restart/helper-strict-lsa-checking
 *
 * Same semantics as ospfd: default-true, FRR's writer only emits a
 * line when the value is false.
 */
int ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	int ret;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ospf6_gr_helper_lsacheck_set(ospf6, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int ospf6d_ietf_ospf_graceful_restart_helper_strict_lsa_checking_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf6 *ospf6;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	ospf6 = ospf6d_ietf_ospf_instance_from_dnode(args->dnode);
	if (!ospf6)
		return NB_OK;
	ospf6_gr_helper_lsacheck_set(
		ospf6,
		yang_get_default_bool(
			"%s/graceful-restart/helper-strict-lsa-checking",
			OSPF6D_IETF_OSPF_XPATH));
	return NB_OK;
}

/*
 * RFC 9129 BFD timer leaves: see the ospfd companion notes.  FRR's v3
 * `bfd_config` is embedded in `ospf6_interface`, no allocation needed;
 * a session refresh is achieved via `ospf6_bfd_reg_dereg_all_nbr(oi,
 * true)`.  Disable tears every session down.
 */
#define OSPF6D_IETF_BFD_MIN_INTERVAL_US (50UL * 1000)
#define OSPF6D_IETF_BFD_MAX_INTERVAL_US (60000UL * 1000)

static int ospf6d_ietf_bfd_validate_interval_us(uint32_t us, const char *leaf, char *errmsg,
						size_t errmsg_len)
{
	if (us % 1000 != 0) {
		snprintf(errmsg, errmsg_len,
			 "FRR BFD %s must be a whole millisecond (multiple of 1000 us); got %u",
			 leaf, us);
		return NB_ERR_VALIDATION;
	}
	if (us < OSPF6D_IETF_BFD_MIN_INTERVAL_US || us > OSPF6D_IETF_BFD_MAX_INTERVAL_US) {
		snprintf(errmsg, errmsg_len,
			 "FRR BFD %s must be %u..%u us (50..60000 ms); got %u", leaf,
			 (unsigned int)OSPF6D_IETF_BFD_MIN_INTERVAL_US,
			 (unsigned int)OSPF6D_IETF_BFD_MAX_INTERVAL_US, us);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * Resolve the OSPFv3 interface for a per-interface BFD callback.
 * Returns NB_OK + *oi_out set on success, NB_OK + NULL when the
 * interface or its OSPFv3 state does not exist (callers should bail
 * out cleanly).
 */
static int ospf6d_ietf_bfd_resolve_oi(struct nb_cb_modify_args *args, struct ospf6 *ospf6,
				      struct ospf6_interface **oi_out)
{
	struct interface *ifp;
	int ret;

	ret = ospf6d_ietf_ospf_resolve_interface(ospf6, args->dnode, args->event, args->errmsg,
						 args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp) {
		*oi_out = NULL;
		return ret;
	}
	*oi_out = ifp->info;
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_interface *oi;
	int ret;
	bool enabled;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;
	ret = ospf6d_ietf_bfd_resolve_oi(args, ospf6, &oi);
	if (ret != NB_OK || !oi)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (enabled) {
		if (!oi->bfd_config.enabled) {
			oi->bfd_config.detection_multiplier = BFD_DEF_DETECT_MULT;
			oi->bfd_config.min_rx = BFD_DEF_MIN_RX;
			oi->bfd_config.min_tx = BFD_DEF_MIN_TX;
		}
		oi->bfd_config.enabled = true;
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	} else if (oi->bfd_config.enabled) {
		oi->bfd_config.enabled = false;
		ospf6_bfd_reg_dereg_all_nbr(oi, false);
	}
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_interface *oi;
	int ret;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;
	ret = ospf6d_ietf_bfd_resolve_oi(args, ospf6, &oi);
	if (ret != NB_OK || !oi)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi->bfd_config.detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_local_multiplier_destroy(struct nb_cb_destroy_args *args)
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
	oi = ifp->info;
	if (!oi)
		return NB_OK;
	oi->bfd_config.detection_multiplier = BFD_DEF_DETECT_MULT;
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_interface *oi;
	int ret;
	uint32_t us;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;
	ret = ospf6d_ietf_bfd_resolve_oi(args, ospf6, &oi);
	if (ret != NB_OK || !oi)
		return ret;

	us = yang_dnode_get_uint32(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE)
		return ospf6d_ietf_bfd_validate_interval_us(us, "desired-min-tx-interval",
							    args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi->bfd_config.min_tx = us / 1000;
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_desired_min_tx_interval_destroy(struct nb_cb_destroy_args *args)
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
	oi = ifp->info;
	if (!oi)
		return NB_OK;
	oi->bfd_config.min_tx = BFD_DEF_MIN_TX;
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct ospf6_interface *oi;
	int ret;
	uint32_t us;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;
	ret = ospf6d_ietf_bfd_resolve_oi(args, ospf6, &oi);
	if (ret != NB_OK || !oi)
		return ret;

	us = yang_dnode_get_uint32(args->dnode, NULL);
	if (args->event == NB_EV_VALIDATE)
		return ospf6d_ietf_bfd_validate_interval_us(us, "required-min-rx-interval",
							    args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	oi->bfd_config.min_rx = us / 1000;
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_bfd_required_min_rx_interval_destroy(struct nb_cb_destroy_args *args)
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
	oi = ifp->info;
	if (!oi)
		return NB_OK;
	oi->bfd_config.min_rx = BFD_DEF_MIN_RX;
	if (oi->bfd_config.enabled)
		ospf6_bfd_reg_dereg_all_nbr(oi, true);
	return NB_OK;
}

/*
 * RFC 9129's `authentication/ospfv3-key-chain` lives under
 * `choice ospfv3-auth-trailer / case auth-key-chain`.  Maps onto
 * FRR's per-interface `oi->at_data.keychain` and the
 * OSPF6_AUTH_TRAILER_KEYCHAIN flag, mirroring `ipv6 ospf6
 * authentication keychain X` exactly (see
 * ospf6_interface.c:3438-3470).  Rejects at NB_EV_VALIDATE if the
 * interface already carries a MANUAL_KEY -- matches the legacy CLI's
 * mutually-exclusive lock.  Other authentication leaves (explicit
 * key-id / key / crypto-algo, OSPFv3 IPsec SA, OSPFv2-only leaves)
 * are marked not-supported via deviation.
 */
static int ospf6d_ietf_ospf_authentication_ospfv3_key_chain_validate(struct interface *ifp,
								     char *errmsg,
								     size_t errmsg_len)
{
	struct ospf6_interface *oi = ifp->info;

	if (oi && CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_MANUAL_KEY)) {
		snprintf(errmsg, errmsg_len,
			 "Manual key configured on %s; remove it before configuring a key chain",
			 ifp->name);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_modify(struct nb_cb_modify_args *args)
{
	struct ospf6 *ospf6;
	struct interface *ifp;
	struct ospf6_interface *oi;
	int ret;

	ret = ospf6d_ietf_ospf_resolve_instance(args->dnode, args->event, args->errmsg,
						args->errmsg_len, &ospf6);
	if (ret != NB_OK || !ospf6)
		return ret;
	ret = ospf6d_ietf_ospf_resolve_interface(ospf6, args->dnode, args->event, args->errmsg,
						 args->errmsg_len, &ifp);
	if (ret != NB_OK || !ifp)
		return ret;

	oi = ifp->info;
	if (args->event == NB_EV_VALIDATE)
		return ospf6d_ietf_ospf_authentication_ospfv3_key_chain_validate(ifp, args->errmsg,
										 args->errmsg_len);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!oi)
		oi = ospf6_interface_create(ifp);
	SET_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN);
	if (oi->at_data.keychain)
		XFREE(MTYPE_OSPF6_AUTH_KEYCHAIN, oi->at_data.keychain);
	oi->at_data.keychain = XSTRDUP(MTYPE_OSPF6_AUTH_KEYCHAIN,
				       yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int ospf6d_ietf_ospf_areas_area_interfaces_interface_authentication_ospfv3_key_chain_destroy(struct nb_cb_destroy_args *args)
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
	oi = ifp->info;
	if (!oi || !CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN))
		return NB_OK;
	if (oi->at_data.keychain)
		XFREE(MTYPE_OSPF6_AUTH_KEYCHAIN, oi->at_data.keychain);
	oi->at_data.flags = 0;
	return NB_OK;
}
