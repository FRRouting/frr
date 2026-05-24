// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound configuration callbacks.
 */

#include <zebra.h>

#include "northbound.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_route.h"
#include "ospf6_nb.h"
#include "ospf6_nssa.h"

/*
 * RFC 9129 ietf-ospf area-type identityrefs. See the matching helper in
 * ospfd/ospf_nb_config.c for the canonicalisation rationale.
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
	if (strncmp(val, "ietf-ospf:", 10) == 0 && !strcmp(val + 10, name))
		return true;
	return false;
}

/*
 * Look up the OSPFv3 instance corresponding to an ietf-ospf config dnode.
 * Walks up to the parent control-plane-protocol list entry to read the
 * instance name, then resolves it through the shared helper.
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
 * is how rt-types:area-id-type serialises.
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

	area = ospf6_area_lookup(area_id, ospf6);
	if (!area)
		return NB_ERR_INCONSISTENCY;

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
		return NB_ERR_INCONSISTENCY;

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
