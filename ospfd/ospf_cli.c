// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound CLI rendering.
 * Copyright (C) 2026  Eric Parsonage
 *
 * These callbacks are daemon-local.  mgmtd uses separate unified callbacks
 * for the safe router-level subset because ospfd and ospf6d implement the
 * same ietf-ospf schema nodes there and mgmtd must inspect the
 * control-plane-protocol type key before choosing v2 or v3 CLI spelling.
 */

#include <zebra.h>

#include "northbound_cli.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_nb.h"

static bool ospfd_cli_show_dnode(const struct lyd_node *dnode,
				 bool show_defaults)
{
	return show_defaults || !yang_dnode_is_default(dnode, NULL);
}

static bool ospfd_cli_identity_is(const char *value, const char *identity)
{
	const char *suffix;

	if (!value)
		return false;
	if (!strcmp(value, identity))
		return true;

	suffix = strrchr(value, ':');
	return suffix && !strcmp(suffix + 1, identity);
}

void ospfd_ietf_ospf_cli_show_config(struct vty *vty, const struct ospf *ospf)
{
	char xpath[XPATH_MAXLEN];
	struct lyd_node *dnode;
	int len;

	len = ospfd_ietf_routing_protocol_xpath(xpath, sizeof(xpath), ospf);
	if (len < 0 || (size_t)len >= sizeof(xpath))
		return;
	if (strlcat(xpath, "/ietf-ospf:ospf", sizeof(xpath)) >= sizeof(xpath))
		return;

	dnode = yang_dnode_get(running_config->dnode, xpath);
	if (dnode)
		nb_cli_show_dnode_cmds(vty, dnode, false);
}

void ospfd_ietf_ospf_explicit_router_id_cli_show(struct vty *vty,
						 const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (!ospfd_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty, " ospf router-id %s\n", yang_dnode_get_string(dnode, NULL));
}

void ospfd_ietf_ospf_preference_cli_show(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults)
{
	const struct lyd_node *child;
	const struct lyd_node *external;
	const struct lyd_node *inter;
	const struct lyd_node *intra;

	child = yang_dnode_get(dnode, "all");
	if (child && ospfd_cli_show_dnode(child, show_defaults)) {
		vty_out(vty, " distance %u\n",
			yang_dnode_get_uint8(child, NULL));
		return;
	}

	child = yang_dnode_get(dnode, "internal");
	if (child && ospfd_cli_show_dnode(child, show_defaults)) {
		/* RFC 9129 `internal` is FRR's coarse intra/inter form. */
		vty_out(vty, " distance ospf intra-area %u inter-area %u",
			yang_dnode_get_uint8(child, NULL),
			yang_dnode_get_uint8(child, NULL));
		child = yang_dnode_get(dnode, "external");
		if (child && ospfd_cli_show_dnode(child, show_defaults))
			vty_out(vty, " external %u",
				yang_dnode_get_uint8(child, NULL));
		vty_out(vty, "\n");
		return;
	}

	intra = yang_dnode_get(dnode, "intra-area");
	inter = yang_dnode_get(dnode, "inter-area");
	external = yang_dnode_get(dnode, "external");
	if ((!intra || !ospfd_cli_show_dnode(intra, show_defaults)) &&
	    (!inter || !ospfd_cli_show_dnode(inter, show_defaults)) &&
	    (!external || !ospfd_cli_show_dnode(external, show_defaults)))
		return;

	vty_out(vty, " distance ospf");
	if (intra && ospfd_cli_show_dnode(intra, show_defaults))
		vty_out(vty, " intra-area %u",
			yang_dnode_get_uint8(intra, NULL));
	if (inter && ospfd_cli_show_dnode(inter, show_defaults))
		vty_out(vty, " inter-area %u",
			yang_dnode_get_uint8(inter, NULL));
	if (external && ospfd_cli_show_dnode(external, show_defaults))
		vty_out(vty, " external %u",
			yang_dnode_get_uint8(external, NULL));
	vty_out(vty, "\n");
}

void ospfd_ietf_ospf_spf_control_paths_cli_show(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!ospfd_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty, " maximum-paths %u\n", yang_dnode_get_uint16(dnode, NULL));
}

void ospfd_ietf_ospf_mpls_ldp_igp_sync_cli_show(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!ospfd_cli_show_dnode(dnode, show_defaults) ||
	    !yang_dnode_get_bool(dnode, NULL))
		return;

	vty_out(vty, " mpls ldp-sync\n");
}

void ospfd_ietf_ospf_stub_router_always_cli_show(struct vty *vty,
						 const struct lyd_node *dnode,
						 bool show_defaults)
{
	if (!ospfd_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty, " max-metric router-lsa administrative\n");
}

void ospfd_ietf_ospf_auto_cost_reference_bandwidth_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!ospfd_cli_show_dnode(dnode, show_defaults))
		return;

	vty_out(vty,
		"! Important: ensure reference bandwidth is consistent across all routers\n");
	vty_out(vty, " auto-cost reference-bandwidth %u\n",
		yang_dnode_get_uint32(dnode, NULL));
}

void ospfd_ietf_ospf_graceful_restart_cli_show(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	const struct lyd_node *child;

	child = yang_dnode_get(dnode, "enabled");
	if (child && ospfd_cli_show_dnode(child, show_defaults) &&
	    yang_dnode_get_bool(child, NULL)) {
		child = yang_dnode_get(dnode, "restart-interval");
		if (child && ospfd_cli_show_dnode(child, show_defaults))
			vty_out(vty, " graceful-restart grace-period %u\n",
				yang_dnode_get_uint16(child, NULL));
		else
			vty_out(vty, " graceful-restart\n");
	}

	child = yang_dnode_get(dnode, "helper-enabled");
	if (child && ospfd_cli_show_dnode(child, show_defaults) &&
	    yang_dnode_get_bool(child, NULL))
		vty_out(vty, " graceful-restart helper enable\n");

	child = yang_dnode_get(dnode, "helper-strict-lsa-checking");
	if (child && ospfd_cli_show_dnode(child, show_defaults) &&
	    !yang_dnode_get_bool(child, NULL))
		vty_out(vty, " no graceful-restart helper strict-lsa-checking\n");
}

void ospfd_ietf_ospf_areas_area_area_type_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *area;
	const struct lyd_node *summary;
	const char *area_id;
	const char *type;
	const char *type_cmd = NULL;

	if (!ospfd_cli_show_dnode(dnode, show_defaults))
		return;

	type = yang_dnode_get_string(dnode, NULL);
	if (ospfd_cli_identity_is(type, "stub-area"))
		type_cmd = "stub";
	/*
	 * NSSA CLI is still daemon-local direct mutation, so keep daemon-local
	 * NSSA rendering in the existing writer until that command is converted.
	 */
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
	if (summary && ospfd_cli_show_dnode(summary, show_defaults) &&
	    !yang_dnode_get_bool(summary, NULL))
		vty_out(vty, " no-summary");
	vty_out(vty, "\n");
}

void ospfd_ietf_ospf_areas_area_default_cost_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *area;
	const char *area_id;

	if (!ospfd_cli_show_dnode(dnode, show_defaults))
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

void ospfd_ietf_ospf_areas_area_ranges_range_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *advertise;
	const struct lyd_node *area;
	const struct lyd_node *cost;
	const char *area_id;
	const char *prefix;

	area = yang_dnode_get_parent(dnode, "area");
	if (!area)
		return;

	area_id = yang_dnode_get_string(area, "area-id");
	prefix = yang_dnode_get_string(dnode, "prefix");
	if (!area_id || !prefix)
		return;

	vty_out(vty, " area %s range %s", area_id, prefix);

	advertise = yang_dnode_get(dnode, "advertise");
	if (advertise && ospfd_cli_show_dnode(advertise, show_defaults) &&
	    !yang_dnode_get_bool(advertise, NULL)) {
		vty_out(vty, " not-advertise\n");
		return;
	}

	cost = yang_dnode_get(dnode, "cost");
	if (cost && ospfd_cli_show_dnode(cost, show_defaults))
		vty_out(vty, " cost %u", yang_dnode_get_uint32(cost, NULL));
	vty_out(vty, "\n");
}
