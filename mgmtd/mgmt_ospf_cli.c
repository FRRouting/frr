// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmtd RFC 9129 OSPF CLI rendering.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "northbound.h"
#include "northbound_cli.h"
#include "vrf.h"

#define MGMT_IETF_ROUTING_CP_XPATH                                             \
	"/ietf-routing:routing/control-plane-protocols/control-plane-protocol"
#define MGMT_IETF_OSPF_XPATH MGMT_IETF_ROUTING_CP_XPATH "/ietf-ospf:ospf"

enum mgmt_ospf_cli_type {
	MGMT_OSPF_CLI_NONE,
	MGMT_OSPF_CLI_V2,
	MGMT_OSPF_CLI_V3,
};

static bool mgmt_ospf_identity_is(const char *value, const char *identity)
{
	const char *suffix;

	if (!value)
		return false;
	if (!strcmp(value, identity))
		return true;

	suffix = strrchr(value, ':');
	return suffix && !strcmp(suffix + 1, identity);
}

static enum mgmt_ospf_cli_type
mgmt_ospf_cli_type_from_protocol(const struct lyd_node *cpp)
{
	const char *type;

	if (!cpp)
		return MGMT_OSPF_CLI_NONE;

	type = yang_dnode_get_string(cpp, "type");
	if (mgmt_ospf_identity_is(type, "ospfv2"))
		return MGMT_OSPF_CLI_V2;
	if (mgmt_ospf_identity_is(type, "ospfv3"))
		return MGMT_OSPF_CLI_V3;

	return MGMT_OSPF_CLI_NONE;
}

static enum mgmt_ospf_cli_type mgmt_ospf_cli_type(const struct lyd_node *dnode)
{
	return mgmt_ospf_cli_type_from_protocol(
		yang_dnode_get_parent(dnode, "control-plane-protocol"));
}

static bool mgmt_ospf_cli_show_dnode(const struct lyd_node *dnode,
				     bool show_defaults)
{
	return show_defaults || !yang_dnode_is_default(dnode, NULL);
}

static bool mgmt_ospf_cli_name_is_instance(const char *name)
{
	if (!name || !*name)
		return false;

	for (; *name; name++) {
		if (*name < '0' || *name > '9')
			return false;
	}

	return true;
}

static void mgmt_ietf_routing_control_plane_protocol_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	enum mgmt_ospf_cli_type type = mgmt_ospf_cli_type_from_protocol(dnode);
	const char *name;

	if (type == MGMT_OSPF_CLI_NONE)
		return;

	vty_out(vty, "!\n");

	switch (type) {
	case MGMT_OSPF_CLI_V2:
		name = yang_dnode_get_string(dnode, "name");
		if (!strcmp(name, VRF_DEFAULT_NAME))
			vty_out(vty, "router ospf\n");
		else if (mgmt_ospf_cli_name_is_instance(name))
			vty_out(vty, "router ospf %s\n", name);
		else
			vty_out(vty, "router ospf vrf %s\n", name);
		break;
	case MGMT_OSPF_CLI_V3:
		name = yang_dnode_get_string(dnode, "name");
		if (!strcmp(name, VRF_DEFAULT_NAME))
			vty_out(vty, "router ospf6\n");
		else
			vty_out(vty, "router ospf6 vrf %s\n", name);
		break;
	case MGMT_OSPF_CLI_NONE:
		break;
	}
}

static void mgmt_ietf_routing_control_plane_protocol_cli_show_end(
	struct vty *vty, const struct lyd_node *dnode)
{
	if (mgmt_ospf_cli_type_from_protocol(dnode) != MGMT_OSPF_CLI_NONE)
		vty_out(vty, "exit\n");
}

static void mgmt_ietf_ospf_explicit_router_id_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	switch (mgmt_ospf_cli_type(dnode)) {
	case MGMT_OSPF_CLI_V2:
		vty_out(vty, " ospf router-id %s\n",
			yang_dnode_get_string(dnode, NULL));
		break;
	case MGMT_OSPF_CLI_V3:
		vty_out(vty, " ospf6 router-id %s\n",
			yang_dnode_get_string(dnode, NULL));
		break;
	case MGMT_OSPF_CLI_NONE:
		break;
	}
}

static void mgmt_ietf_ospf_preference_cli_show(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *distance_cmd = NULL;
	const struct lyd_node *child;
	const struct lyd_node *external;
	const struct lyd_node *inter;
	const struct lyd_node *intra;

	switch (mgmt_ospf_cli_type(dnode)) {
	case MGMT_OSPF_CLI_V2:
		distance_cmd = "distance ospf";
		break;
	case MGMT_OSPF_CLI_V3:
		distance_cmd = "distance ospf6";
		break;
	case MGMT_OSPF_CLI_NONE:
		break;
	}
	if (!distance_cmd)
		return;

	child = yang_dnode_get(dnode, "all");
	if (child && mgmt_ospf_cli_show_dnode(child, show_defaults)) {
		vty_out(vty, " distance %u\n",
			yang_dnode_get_uint8(child, NULL));
		return;
	}

	child = yang_dnode_get(dnode, "internal");
	if (child && mgmt_ospf_cli_show_dnode(child, show_defaults)) {
		/* RFC 9129 `internal` is FRR's coarse intra/inter form. */
		vty_out(vty, " %s intra-area %u inter-area %u", distance_cmd,
			yang_dnode_get_uint8(child, NULL),
			yang_dnode_get_uint8(child, NULL));
		child = yang_dnode_get(dnode, "external");
		if (child && mgmt_ospf_cli_show_dnode(child, show_defaults))
			vty_out(vty, " external %u",
				yang_dnode_get_uint8(child, NULL));
		vty_out(vty, "\n");
		return;
	}

	intra = yang_dnode_get(dnode, "intra-area");
	inter = yang_dnode_get(dnode, "inter-area");
	external = yang_dnode_get(dnode, "external");
	if ((!intra || !mgmt_ospf_cli_show_dnode(intra, show_defaults)) &&
	    (!inter || !mgmt_ospf_cli_show_dnode(inter, show_defaults)) &&
	    (!external || !mgmt_ospf_cli_show_dnode(external, show_defaults)))
		return;

	vty_out(vty, " %s", distance_cmd);
	if (intra && mgmt_ospf_cli_show_dnode(intra, show_defaults))
		vty_out(vty, " intra-area %u",
			yang_dnode_get_uint8(intra, NULL));
	if (inter && mgmt_ospf_cli_show_dnode(inter, show_defaults))
		vty_out(vty, " inter-area %u",
			yang_dnode_get_uint8(inter, NULL));
	if (external && mgmt_ospf_cli_show_dnode(external, show_defaults))
		vty_out(vty, " external %u",
			yang_dnode_get_uint8(external, NULL));
	vty_out(vty, "\n");
}

static void mgmt_ietf_ospf_spf_control_paths_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (mgmt_ospf_cli_type(dnode) == MGMT_OSPF_CLI_NONE ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty, " maximum-paths %u\n",
		yang_dnode_get_uint16(dnode, NULL));
}

static void mgmt_ietf_ospf_mpls_ldp_igp_sync_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (mgmt_ospf_cli_type(dnode) != MGMT_OSPF_CLI_V2 ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults) ||
	    !yang_dnode_get_bool(dnode, NULL))
		return;

	vty_out(vty, " mpls ldp-sync\n");
}

static void mgmt_ietf_ospf_stub_router_always_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (mgmt_ospf_cli_type(dnode) != MGMT_OSPF_CLI_V2 ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty, " max-metric router-lsa administrative\n");
}

static void mgmt_ietf_ospf_auto_cost_reference_bandwidth_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (mgmt_ospf_cli_type(dnode) == MGMT_OSPF_CLI_NONE ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	if (mgmt_ospf_cli_type(dnode) == MGMT_OSPF_CLI_V2)
		vty_out(vty,
			"! Important: ensure reference bandwidth is consistent across all routers\n");
	vty_out(vty, " auto-cost reference-bandwidth %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

static void mgmt_ietf_ospf_graceful_restart_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *child;
	enum mgmt_ospf_cli_type type = mgmt_ospf_cli_type(dnode);

	if (type == MGMT_OSPF_CLI_NONE)
		return;

	child = yang_dnode_get(dnode, "enabled");
	if (child && mgmt_ospf_cli_show_dnode(child, show_defaults) &&
	    yang_dnode_get_bool(child, NULL)) {
		child = yang_dnode_get(dnode, "restart-interval");
		if (child && mgmt_ospf_cli_show_dnode(child, show_defaults))
			vty_out(vty, " graceful-restart grace-period %u\n",
				yang_dnode_get_uint16(child, NULL));
		else
			vty_out(vty, " graceful-restart\n");
	}

	child = yang_dnode_get(dnode, "helper-enabled");
	if (child && mgmt_ospf_cli_show_dnode(child, show_defaults) &&
	    yang_dnode_get_bool(child, NULL))
		vty_out(vty, " graceful-restart helper enable\n");

	child = yang_dnode_get(dnode, "helper-strict-lsa-checking");
	if (child && mgmt_ospf_cli_show_dnode(child, show_defaults) &&
	    !yang_dnode_get_bool(child, NULL)) {
		if (type == MGMT_OSPF_CLI_V2)
			vty_out(vty,
				" no graceful-restart helper strict-lsa-checking\n");
		else
			vty_out(vty,
				" graceful-restart helper lsa-check-disable\n");
	}
}

static void mgmt_ietf_ospf_areas_area_area_type_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *area;
	const struct lyd_node *summary;
	const char *area_id;
	const char *type;
	const char *type_cmd = NULL;

	if (mgmt_ospf_cli_type(dnode) == MGMT_OSPF_CLI_NONE ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	type = yang_dnode_get_string(dnode, NULL);
	if (mgmt_ospf_identity_is(type, "stub-area"))
		type_cmd = "stub";
	else if (mgmt_ospf_identity_is(type, "nssa-area"))
		type_cmd = "nssa";
	if (!type_cmd)
		return;

	area = yang_dnode_get_parent(dnode, "area");
	if (!area)
		return;

	area_id = yang_dnode_get_string(area, "area-id");
	if (!area_id)
		return;

	vty_out(vty, " area %s %s", area_id, type_cmd);
	summary = yang_dnode_get(area, "summary");
	if (summary && mgmt_ospf_cli_show_dnode(summary, show_defaults) &&
	    !yang_dnode_get_bool(summary, NULL))
		vty_out(vty, " no-summary");
	vty_out(vty, "\n");
}

static void mgmt_ietf_ospf_areas_area_default_cost_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *area;
	const char *area_id;

	if (mgmt_ospf_cli_type(dnode) != MGMT_OSPF_CLI_V2 ||
	    !mgmt_ospf_cli_show_dnode(dnode, show_defaults))
		return;

	area = yang_dnode_get_parent(dnode, "area");
	if (!area)
		return;

	area_id = yang_dnode_get_string(area, "area-id");
	if (!area_id)
		return;

	vty_out(vty, " area %s default-cost %u\n", area_id,
		yang_dnode_get_uint32(dnode, NULL));
}

static void mgmt_ietf_ospf_areas_area_ranges_range_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *advertise;
	const struct lyd_node *area;
	const struct lyd_node *cost;
	const char *area_id;
	const char *prefix;

	if (mgmt_ospf_cli_type(dnode) == MGMT_OSPF_CLI_NONE)
		return;

	area = yang_dnode_get_parent(dnode, "area");
	if (!area)
		return;

	area_id = yang_dnode_get_string(area, "area-id");
	prefix = yang_dnode_get_string(dnode, "prefix");
	if (!area_id || !prefix)
		return;

	vty_out(vty, " area %s range %s", area_id, prefix);

	advertise = yang_dnode_get(dnode, "advertise");
	if (advertise && mgmt_ospf_cli_show_dnode(advertise, show_defaults) &&
	    !yang_dnode_get_bool(advertise, NULL)) {
		vty_out(vty, " not-advertise\n");
		return;
	}

	cost = yang_dnode_get(dnode, "cost");
	if (cost && mgmt_ospf_cli_show_dnode(cost, show_defaults))
		vty_out(vty, " cost %u", yang_dnode_get_uint32(cost, NULL));
	vty_out(vty, "\n");
}

/* clang-format off */
static const char *const ietf_ospf_features[] = {
	"auto-cost",
	"bfd",
	"explicit-router-id",
	"graceful-restart",
	"key-chain",
	"ldp-igp-sync",
	"max-ecmp",
	"mtu-ignore",
	"ospfv3-authentication-trailer",
	"prefix-suppression",
	"stub-router",
	"te-rid",
	NULL,
};

const struct frr_yang_module_info ietf_routing_ospf_cli_info = {
	.name = "ietf-routing",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = MGMT_IETF_ROUTING_CP_XPATH,
			.cbs = {
				.cli_show =
					mgmt_ietf_routing_control_plane_protocol_cli_show,
				.cli_show_end =
					mgmt_ietf_routing_control_plane_protocol_cli_show_end,
			},
		},
		{
			.xpath = NULL,
		},
	},
};

const struct frr_yang_module_info ietf_ospf_cli_info = {
	.name = "ietf-ospf",
	.features = (const char **)ietf_ospf_features,
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/explicit-router-id",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_explicit_router_id_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/preference",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_preference_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/spf-control/paths",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_spf_control_paths_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/mpls/ldp/igp-sync",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_mpls_ldp_igp_sync_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/stub-router/always",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_stub_router_always_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH
				 "/auto-cost/reference-bandwidth",
			.cbs = {
				.cli_show =
					mgmt_ietf_ospf_auto_cost_reference_bandwidth_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/graceful-restart",
			.cbs = {
				.cli_show = mgmt_ietf_ospf_graceful_restart_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/areas/area/area-type",
			.cbs = {
				.cli_show =
					mgmt_ietf_ospf_areas_area_area_type_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/areas/area/default-cost",
			.cbs = {
				.cli_show =
					mgmt_ietf_ospf_areas_area_default_cost_cli_show,
			},
		},
		{
			.xpath = MGMT_IETF_OSPF_XPATH "/areas/area/ranges/range",
			.cbs = {
				.cli_show =
					mgmt_ietf_ospf_areas_area_ranges_range_cli_show,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
