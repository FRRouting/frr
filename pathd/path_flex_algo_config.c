/* Flex-algo config candidate paths
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "memory.h"
#include "zapi_fae.h"
#include "vty.h"
#include "pathd/path_flex_algo.h"

#include "pathd/path_flex_algo_config_clippy.c"

/* clang-format off */
const struct frr_yang_module_info frr_pathd_flexalgo_info = {
	.name = "frr-pathd-flexalgo",
	.nodes = {
		  {
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults",
			.cbs = {
				.cli_show = cli_show_flex_algo_igp_defaults,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults/protocol",

			.cbs = {
				.modify = pathd_srte_flex_algo_default_protocol_modify,
				.destroy = pathd_srte_flex_algo_default_protocol_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults/vrf",

			.cbs = {
				.modify = pathd_srte_flex_algo_default_vrf_modify,
				.destroy = pathd_srte_flex_algo_default_vrf_destroy,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults/instance",

			.cbs = {
				.destroy = pathd_srte_flex_algo_default_instance_destroy,
				.modify = pathd_srte_flex_algo_default_instance_modify,
			}
		},
		{
			.xpath = "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults/isis-area-tag",

			.cbs = {
				.destroy = pathd_srte_flex_algo_default_isis_area_tag_destroy,
				.modify = pathd_srte_flex_algo_default_isis_area_tag_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/* clang-format off */
DEFPY(debug_fa_ready,
	debug_fa_ready_cmd,
	"debug fa-ready [not$not] igp <isis|ospf>$igp [vrf VRF$vrf] [area-tag AREA$area z-area-id (0-4294967295)$z_area_id]",
	"debug\n"
	"flex-algo ready message\n"
	"Not ready\n"
	"Specify IGP\n"
	"igp is isis\n"
	"igp is ospf\n"
	"Specify VRF\n"
	"vrf name\n"
	"Specify isis area-tag\n"
	"area-tag string\n"
	"Specify zebra area ID\n"
	"area-id number\n")
{
	uint8_t proto = ZEBRA_ROUTE_ALL;
	struct vrf *v;
	int rc;

	if (!strcmp(igp, "isis"))
		proto = ZEBRA_ROUTE_ISIS;
	else {
		vty_out(vty, "igp protocol %s not supported\n", igp);
		return CMD_SUCCESS;
	}

	if (!vrf)
		vrf = "default";
	v = vrf_lookup_by_name(vrf);

	rc = path_zebra_debug_send_fae_ready(
		(not? false: true), proto,
		(v? v->vrf_id: VRF_DEFAULT), area, z_area_id);

	vty_out(vty, "path_zebra_debug_send_fae_ready returned %d\n", rc);

	return CMD_SUCCESS;
}

DEFPY(debug_fa_update,
	debug_fa_update_cmd,
	"debug fa-update igp <isis|ospf>$igp [vrf VRF$vrf] [z-area-id (0-4294967295)$z_area_id] endpoint <A.B.C.D|X:X::X:X>$endpoint algorithm (128-255)$algorithm (1-4294967295) ...",
	"debug\n"
	"flex-algo update message\n"
	"Specify IGP\n"
	"igp is isis\n"
	"igp is ospf\n"
	"Specify VRF\n"
	"vrf name\n"
	"Specify isis z-area-id\n"
	"z-area-id number\n"
	"Specify endpoint\n"
	"IPv4 endpoint address\n"
	"IPv6 endpoint address\n"
	"Specify algorithm\n"
	"algorithm number\n"
	"list of space-separated labels\n"
	)
{
	uint8_t proto = ZEBRA_ROUTE_ALL;
	struct vrf *v;
	struct zapi_srte_tunnel sid_list;
	int rc;

	if (!strcmp(igp, "isis"))
		proto = ZEBRA_ROUTE_ISIS;
	else {
		vty_out(vty, "igp protocol %s not supported\n", igp);
		return CMD_SUCCESS;
	}

	if (!vrf)
		vrf = "default";
	v = vrf_lookup_by_name(vrf);

	/*
	 * endpoint
	 */
	struct ipaddr ipa_endpoint;

	if (str2ipaddr(endpoint_str, &ipa_endpoint)) {
		vty_out(vty, "Error: can't parse endpoint IP address \"%s\"\n",
			endpoint_str);
		return CMD_SUCCESS;
	}

	int idx_algorithm = 1;
	int idx_sidlist;
	int label_num;

	if (!argv_find(argv, argc, "algorithm", &idx_algorithm)) {
		vty_out(vty, "Error: can't locate \"algorithm\" keyword\n");
		return CMD_SUCCESS;
	}
	idx_sidlist = idx_algorithm + 2;
	label_num = argc - idx_sidlist;

	if (label_num < 0) {
		vty_out(vty, "Error: Invalid label number (have %d)\n",
			label_num);
		return CMD_SUCCESS;
	} else if (label_num > MPLS_MAX_LABELS) {
		vty_out(vty, "Error: too many labels (have %d, max %d)\n",
			label_num, MPLS_MAX_LABELS);
		return CMD_SUCCESS;
	}

	memset(&sid_list, 0, sizeof(sid_list));
	sid_list.label_num = (uint8_t)label_num;
	/* maybe: if label_num is 0, set special label */
	for (unsigned int i = 0; i < (unsigned int)label_num; ++i) {
		unsigned long val;
		char *end;

		val = strtoul(argv[idx_sidlist + i]->arg, &end, 10);
		if (*end) {
			vty_out(vty, "Error: invalid SID\n");
			return CMD_SUCCESS;
		}

		sid_list.labels[i] = val;
	}

	/*
	 * Look up z_area_id in flex algo igp table based on area string
	 */
	if (ZEBRA_ROUTE_ISIS == proto) {
		if (!z_area_id_str) {
			vty_out(vty, "Error: missing z-area-id\n");
			return CMD_SUCCESS;
		}
	}

	rc = path_zebra_debug_send_fae_update(
		proto,
		(v? v->vrf_id: VRF_DEFAULT), z_area_id,
		&ipa_endpoint, (uint8_t)algorithm, &sid_list);

	vty_out(vty, "path_zebra_debug_send_fae_update returned %d\n", rc);

	return CMD_SUCCESS;
}

/* version with no SID-list */
ALIAS(debug_fa_update,
	debug_fa_update_empty_cmd,
	"debug fa-update igp <isis|ospf>$igp [vrf VRF$vrf] [area-tag AREA$area] endpoint <A.B.C.D|X:X::X:X>$endpoint algorithm (128-255)$algorithm",
	"debug\n"
	"flex-algo update message\n"
	"Specify IGP\n"
	"igp is isis\n"
	"igp is ospf\n"
	"Specify VRF\n"
	"vrf name\n"
	"Specify isis area-tag\n"
	"area-tag string\n"
	"Specify endpoint\n"
	"IPv4 endpoint address\n"
	"IPv6 endpoint address\n"
	"Specify algorithm\n"
	"algorithm number\n"
	)

DEFPY(debug_flex_algo_show_igp,
	debug_flex_algo_show_igp_cmd,
	"debug flex-algo show igp",
	"debug\n"
	"flex-algo\n"
	"show\n"
	"IGP table\n"
	)
{
	fa_vty_igp_show_all(vty);
	return CMD_SUCCESS;
}

DEFPY(debug_flex_algo_show_endpoint,
	debug_flex_algo_show_endpoint_cmd,
	"debug flex-algo show endpoint [detail]$detail",
	"debug\n"
	"flex-algo\n"
	"Show\n"
	"endpoint table\n"
	"detailed listing\n"
	)
{
	fa_vty_endpoint_show_all(vty, !!detail);
	return CMD_SUCCESS;
}

DEFPY(debug_flex_algo_show_igp_defaults,
	debug_flex_algo_show_igp_defaults_cmd,
	"debug flex-algo show igp-defaults",
	"debug\n"
	"flex-algo\n"
	"Show\n"
	"IGP defaults for flex-algo candidate paths\n"
	)
{
	fa_vty_igp_defaults_show(vty);
	return CMD_SUCCESS;
}

/*
 * instance and vrf default to 0, but area-tag is mandatory for isis.
 * The idea here is that for other igp protocols (e.g., ospf), the
 * developer will define another CLI command
 * "flex-algo igp-defaults protocol ospf ..." with whatever ospf-specific
 * syntax might be needed.
 */
#define _X_ID "/frr-pathd:pathd/frr-pathd:srte/frr-pathd-flexalgo:flex-algo/igp-defaults/"
DEFPY(flex_algo_igp_defaults_isis,
      flex_algo_igp_defaults_isis_cmd,
      "[no] flex-algo igp-defaults protocol isis [instance (0-65535)$inst] [vrf VRF$vrf] area-tag AREA$area",
      NO_STR
      "Flex-algo\n"
      "IGP defaults\n"
      "Specify IGP source\n"
      "IGP is isis\n"
      "Specify IGP daemon instance\n"
      "instance number\n"
      "Specify IGP vrf\n"
      "vrf name\n"
      "Specify isis area tag\n"
      "area tag string\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, _X_ID "protocol", NB_OP_DESTROY, 0);
		nb_cli_enqueue_change(vty, _X_ID "instance", NB_OP_DESTROY, 0);
		nb_cli_enqueue_change(vty, _X_ID "vrf", NB_OP_DESTROY, 0);
		nb_cli_enqueue_change(vty, _X_ID "isis-area-tag",
			NB_OP_DESTROY, 0);
	} else {
		nb_cli_enqueue_change(vty, _X_ID "protocol", NB_OP_MODIFY,
			"isis");
		if (inst_str)
			nb_cli_enqueue_change(vty, _X_ID "instance",
				NB_OP_MODIFY, inst_str);
		if (vrf)
			nb_cli_enqueue_change(vty, _X_ID "vrf",
				NB_OP_MODIFY, vrf);
		nb_cli_enqueue_change(vty, _X_ID "isis-area-tag", NB_OP_MODIFY, area);
	}
	return nb_cli_apply_changes(vty, _X_ID);
}

DEFUN(no_flex_algo_igp_defaults_isis,
      no_flex_algo_igp_defaults_isis_cmd,
      "no flex-algo igp-defaults",
      NO_STR
      "Flex-algo\n"
      "IGP defaults\n")
{
	nb_cli_enqueue_change(vty, _X_ID "protocol", NB_OP_DESTROY, 0);
	nb_cli_enqueue_change(vty, _X_ID "instance", NB_OP_DESTROY, 0);
	nb_cli_enqueue_change(vty, _X_ID "vrf", NB_OP_DESTROY, 0);
	nb_cli_enqueue_change(vty, _X_ID "isis-area-tag", NB_OP_DESTROY, 0);
	return nb_cli_apply_changes(vty, _X_ID);
}
#undef _X_ID
/* clang-format on */

void cli_show_flex_algo_igp_defaults(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	const char *proto_str;
	const char *vrf_str;
	uint16_t instance;

	proto_str = yang_dnode_get_string(dnode, "./protocol");
	vty_out(vty, "  flex-algo igp-defaults protocol %s", proto_str);

	if (yang_dnode_exists(dnode, "./vrf")) {
		vrf_str = yang_dnode_get_string(dnode, "./vrf");
		if (strcmp(vrf_str, "default") || show_defaults)
			vty_out(vty, " vrf %s", vrf_str);
	}

	if (yang_dnode_exists(dnode, "./instance")) {
		instance = yang_dnode_get_uint16(dnode, "./instance");
		if (instance || show_defaults)
			vty_out(vty, " instance %u", instance);
	}

	if (!strcmp(proto_str, "isis")) {
		const char *area_str;

		area_str = yang_dnode_get_string(dnode, "./isis-area-tag");
		vty_out(vty, " area-tag %s", (area_str ? area_str : "\"\""));
	}
	vty_out(vty, "\n");
}

/* cli initialisation */
void path_flex_algo_cli_init(void)
{
	install_element(ENABLE_NODE, &debug_fa_ready_cmd);
	install_element(ENABLE_NODE, &debug_fa_update_cmd);
	install_element(ENABLE_NODE, &debug_fa_update_empty_cmd);
	install_element(ENABLE_NODE, &debug_flex_algo_show_igp_cmd);
	install_element(ENABLE_NODE, &debug_flex_algo_show_endpoint_cmd);
	install_element(ENABLE_NODE, &debug_flex_algo_show_igp_defaults_cmd);
	install_element(SR_TRAFFIC_ENG_NODE, &flex_algo_igp_defaults_isis_cmd);
	install_element(SR_TRAFFIC_ENG_NODE,
			&no_flex_algo_igp_defaults_isis_cmd);
}

/* northbound config API */

/*
 * XPath: /frr-pathd:pathd/srte/flex-algo/defaults/protocol
 */
int pathd_srte_flex_algo_default_protocol_modify(struct nb_cb_modify_args *args)
{
	const char *type;
	int igp_protocol;
	int rc;

	switch (args->event) {
	case NB_EV_VALIDATE:
		type = yang_dnode_get_string(args->dnode, NULL);
		igp_protocol = proto_name2num(type);
		if (igp_protocol < 0) {
			zlog_warn("%s: invalid protocol: %s", __func__, type);
			return NB_ERR_VALIDATION;
		}
		if (fa_check_default_igp_proto(igp_protocol)) {
			zlog_warn("%s: disallowed protocol: %s", __func__,
				  type);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	type = yang_dnode_get_string(args->dnode, NULL);
	igp_protocol = proto_name2num(type);

	rc = fa_set_default_igp_proto((uint8_t)(igp_protocol & 0xff));
	if (rc) {
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pathd_srte_flex_algo_default_protocol_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	(void)fa_set_default_igp_proto(ZEBRA_ROUTE_ISIS);
	return NB_OK;
}

int pathd_srte_flex_algo_default_vrf_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	struct vrf *vrf;
	int rc;

	switch (args->event) {
	case NB_EV_VALIDATE:
		name = yang_dnode_get_string(args->dnode, NULL);
		vrf = vrf_lookup_by_name(name);
		if (!vrf) {
			zlog_warn("%s: invalid vrf name: %s", __func__, name);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	name = yang_dnode_get_string(args->dnode, NULL);
	vrf = vrf_lookup_by_name(name);
	if (!vrf) {
		return NB_ERR_INCONSISTENCY;
	}

	rc = fa_set_default_igp_vrf_id(vrf->vrf_id);
	if (rc) {
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pathd_srte_flex_algo_default_vrf_destroy(struct nb_cb_destroy_args *args)

{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	(void)fa_set_default_igp_vrf_id(VRF_DEFAULT);
	return NB_OK;
}

int pathd_srte_flex_algo_default_instance_modify(struct nb_cb_modify_args *args)
{
	uint16_t instance;
	int rc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	instance = yang_dnode_get_uint16(args->dnode, NULL);

	rc = fa_set_default_igp_instance(instance);
	if (rc) {
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pathd_srte_flex_algo_default_instance_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	(void)fa_set_default_igp_instance(0);
	return NB_OK;
}

int pathd_srte_flex_algo_default_isis_area_tag_modify(
	struct nb_cb_modify_args *args)
{
	const char *name;
	int rc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	name = yang_dnode_get_string(args->dnode, NULL);

	rc = fa_set_default_igp_isis_area_tag(name);
	if (rc) {
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int pathd_srte_flex_algo_default_isis_area_tag_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	(void)fa_set_default_igp_isis_area_tag("");
	return NB_OK;
}
